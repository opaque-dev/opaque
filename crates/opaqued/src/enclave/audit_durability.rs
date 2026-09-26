//! Durability barriers for operation dispatch and successful disclosure.
use super::{Enclave, EnclaveError};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;

impl Enclave {
    /// Flush the configured sinks off the executor. Cancellation cannot free a
    /// worker's permit while it still owns a blocking durability wait.
    pub(crate) async fn confirm_audit(&self, dispatched: bool) -> Result<(), EnclaveError> {
        static WORKERS: OnceLock<Arc<Semaphore>> = OnceLock::new();
        let unavailable = || {
            EnclaveError::Internal(if dispatched {
                "audit durability unavailable after dispatch; outcome unknown to the caller. Inspect the task receipt or operation audit before further action".into()
            } else {
                "audit durability unavailable; next operation was not dispatched. Inspect existing task receipts for earlier effects".into()
            })
        };
        let permit = WORKERS
            .get_or_init(|| Arc::new(Semaphore::new(64)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| unavailable())?;
        let sink = self.audit.clone();
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            sink.flush(Duration::from_secs(5))
        });
        tokio::time::timeout(Duration::from_secs(6), worker)
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())
    }
}
