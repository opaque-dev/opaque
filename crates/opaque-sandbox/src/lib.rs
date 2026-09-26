#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Sandbox orchestrator for `sandbox.exec` operations.
//!
//! The `SandboxExecutor` implements `OperationHandler` and coordinates:
//! 1. Loading the execution profile
//! 2. Resolving secret references
//! 3. Dispatching to the platform-specific sandbox (Linux or macOS)
//! 4. Streaming output frames back to the client
//! 5. Emitting audit events
//! 6. Cleaning up secret memory after execution

mod custody;
pub mod execve_hook;
pub mod resolve;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;
use opaque_core::profile::{self, ExecProfile};
use opaque_core::proto::ExecFrame;
use tokio::sync::mpsc;

use opaque_core::operation_handler::{OperationHandler, PreparedOperation, render_argv};
use opaque_core::resolver::SecretResolver;
use opaque_core::secret::SecretValue;
use resolve::{CompositeResolver, resolve_all};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Errors from direct (unsandboxed) execution.
#[derive(Debug, thiserror::Error)]
pub enum DirectExecError {
    #[error("configuration error: {0}")]
    Configuration(String),

    #[error("execution error: {0}")]
    Execution(String),
}

/// Builds the set of provider secret resolvers to wire into the
/// [`CompositeResolver`] used for each `sandbox.exec` request.
///
/// This crate cannot name concrete provider resolver types (that would
/// recreate the providers-vs-sandbox cycle the crate split exists to avoid),
/// so the composition root — `opaqued`'s `main.rs`, via its
/// `default_secret_resolvers()` — supplies this as a plain `fn` pointer to
/// [`SandboxExecutor::new`]. It is re-invoked on every `sandbox.exec` call
/// (rather than cached at construction time) to preserve the exact resolver
/// set that a fresh `CompositeResolver::new(default_secret_resolvers())`
/// would have produced before the crate split.
pub type ResolverFactory = fn() -> Vec<Box<dyn SecretResolver>>;

/// The sandbox executor handles `sandbox.exec` operations.
///
/// It loads profiles, resolves secrets, dispatches to the platform sandbox,
/// and returns the exit code. Output streaming is handled via the exec
/// frame channel stored in the operation request's params.
pub struct SandboxExecutor {
    audit: Arc<dyn AuditSink>,
    resolver_factory: ResolverFactory,
}

impl fmt::Debug for SandboxExecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxExecutor").finish()
    }
}

impl SandboxExecutor {
    /// `resolver_factory` is the composition root's provider-resolver
    /// builder (e.g. `opaqued::default_secret_resolvers`), invoked fresh for
    /// every `sandbox.exec` request. See [`ResolverFactory`].
    pub fn new(audit: Arc<dyn AuditSink>, resolver_factory: ResolverFactory) -> Self {
        Self {
            audit,
            resolver_factory,
        }
    }

    /// Load and validate a profile by name.
    fn load_profile(name: &str) -> Result<ExecProfile, String> {
        profile::load_named_profile(name)
            .map_err(|e| format!("failed to load profile '{name}': {e}"))
    }

    /// Resolve all secret references in the profile.
    fn resolve_secrets(
        profile: &ExecProfile,
        resolver_factory: ResolverFactory,
    ) -> Result<HashMap<String, SecretValue>, String> {
        let resolver = CompositeResolver::new(resolver_factory());
        resolve_all(&profile.secrets, &resolver)
            .map_err(|e| format!("secret resolution failed: {e}"))
    }

    /// Build the combined environment for the sandbox (secrets + literal env).
    ///
    /// Extracts the string value from each `SecretValue` for injection into the
    /// child process environment. The `SecretValue`s remain alive (and will be
    /// zeroed on drop) in the caller's `resolved_secrets` map.
    fn build_env(
        profile: &ExecProfile,
        resolved_secrets: &HashMap<String, SecretValue>,
    ) -> HashMap<String, String> {
        let mut env = HashMap::with_capacity(profile.env.len() + resolved_secrets.len());

        // Literal env vars first.
        for (key, value) in &profile.env {
            env.insert(key.clone(), value.clone());
        }

        // Resolved secrets (overwrite if conflict — secrets take precedence).
        for (key, secret) in resolved_secrets {
            if let Some(s) = secret.as_str() {
                env.insert(key.clone(), s.to_owned());
            }
        }

        env
    }
}

/// The execution profile is owned by the action, but only its digest enters
/// authorization. Literal environment values never become review/audit fields.
#[derive(Serialize)]
struct SandboxAction {
    version: &'static str,
    profile_name: String,
    command: Vec<String>,
    profile_sha256: String,
    #[serde(skip)]
    profile: ExecProfile,
}

fn profile_digest(profile: &ExecProfile) -> Result<String, String> {
    let mut canonical =
        serde_json::to_value(profile).map_err(|_| "cannot encode sandbox profile")?;
    canonical.sort_all_objects();
    let bytes = serde_json::to_vec(&canonical).map_err(|_| "cannot encode sandbox profile")?;
    let mut hash = Sha256::new();
    hash.update(b"opaque:sandbox:profile:v1\0");
    hash.update(bytes);
    Ok(format!("{:x}", hash.finalize()))
}

impl OperationHandler for SandboxExecutor {
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        self.prepare_with_loader(request, Self::load_profile)
    }
}

impl SandboxExecutor {
    fn prepare_with_loader<'a>(
        &'a self,
        request: &OperationRequest,
        load: impl FnOnce(&str) -> Result<ExecProfile, String>,
    ) -> Result<PreparedOperation<'a>, String> {
        if request.operation != "sandbox.exec" {
            return Err("unknown sandbox operation".into());
        }
        let params = request
            .params
            .as_object()
            .ok_or("sandbox params must be an object")?;
        if params
            .keys()
            .any(|key| !matches!(key.as_str(), "profile" | "command"))
        {
            return Err("unknown sandbox parameter".into());
        }
        let profile_name = params
            .get("profile")
            .and_then(|value| value.as_str())
            .ok_or("missing 'profile' parameter")?
            .to_owned();
        if profile_name.is_empty()
            || !profile_name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
        {
            return Err("invalid profile name".into());
        }
        let command: Vec<String> = params
            .get("command")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .ok_or("missing or invalid 'command' parameter")?;
        if command.is_empty() {
            return Err("command must not be empty".into());
        }
        if command[0].is_empty() || command.iter().any(|value| value.contains('\0')) {
            return Err("invalid command argument".into());
        }
        let profile = load(&profile_name)?;
        profile::validate_profile(&profile, Some(&profile_name))
            .map_err(|_| "invalid sandbox profile")?;
        if profile.env.values().any(|value| value.contains('\0'))
            || profile.secrets.values().any(|value| value.contains('\0'))
        {
            return Err("invalid NUL in sandbox environment or secret reference".into());
        }
        let profile_sha256 = profile_digest(&profile)?;
        let secret_refs = profile.secrets.values().cloned().collect();
        let target = HashMap::from([
            ("profile".into(), profile_name.clone()),
            ("command".into(), render_argv(&command)),
            ("profile_sha256".into(), profile_sha256.clone()),
        ]);
        let action = SandboxAction {
            version: "sandbox.exec.v1",
            profile_name,
            command,
            profile_sha256,
            profile,
        };
        let request_id = request.request_id;
        let audit = self.audit.clone();
        let resolver_factory = self.resolver_factory;
        PreparedOperation::new(action, target, secret_refs, move |action| async move {
            let SandboxAction {
                profile_name,
                command,
                profile,
                ..
            } = action;
            // Decide how the workload will be contained before any secret is
            // resolved: a host with no usable sandbox strategy fails closed
            // here, and the audit events below name the strategy chosen.
            let plan = SandboxPlan::for_profile(&profile)?;
            let sandbox_label = plan.label();

            // Resolve secret references.
            let resolved_secrets = Self::resolve_secrets(&profile, resolver_factory)?;

            // Emit SecretResolved audit events (one per secret, without the value).
            for env_name in resolved_secrets.keys() {
                let event = AuditEvent::new(AuditEventKind::SecretResolved)
                    .with_request_id(request_id)
                    .with_operation("sandbox.exec")
                    .with_outcome("resolved")
                    .with_detail(format!("profile={profile_name} env_name={env_name}"));
                audit.emit(event);
            }

            // Build combined environment.
            let env = Self::build_env(&profile, &resolved_secrets);

            // Arbitrary argv and working paths can contain secret bytes that
            // pattern redaction cannot recognize. Record only bounded metadata;
            // the canonical approval still binds the complete requested action.
            let sandbox_event = AuditEvent::new(AuditEventKind::SandboxCreated)
                .with_request_id(request_id)
                .with_operation("sandbox.exec")
                .with_outcome("created")
                .with_detail(format!(
                    "profile={profile_name} argument_count={} sandbox={sandbox_label}",
                    command.len(),
                ));
            audit.emit(sandbox_event);

            // Create the frame channel for streaming.
            //
            // IMPORTANT: Drain this concurrently while the sandbox runs. If we
            // only collect after completion, the bounded channel can fill up
            // and deadlock output tasks that are awaiting `send()`.
            let (tx, rx) = mpsc::channel::<ExecFrame>(64);

            // Drain in the same owned future as execution. No plaintext output
            // copies or detached collector survive cancellation.
            let (exit_code, s) = summarize_execution(
                execute_platform_sandbox(&plan, &profile, command, env, tx),
                rx,
            )
            .await?;

            // Emit SandboxCompleted audit event, naming the strategy that
            // actually contained the workload.
            let completed_event = AuditEvent::new(AuditEventKind::SandboxCompleted)
                .with_request_id(request_id)
                .with_operation("sandbox.exec")
                .with_outcome(if exit_code == 0 { "success" } else { "failed" })
                .with_detail(format!(
                    "profile={profile_name} exit_code={exit_code} sandbox={sandbox_label}"
                ));
            audit.emit(completed_event);

            let truncated = s.stdout_len > 64 * 1024 || s.stderr_len > 64 * 1024;

            // SECURITY (C2): never return captured stdout/stderr *content* to the
            // caller. The child runs with plaintext secrets in its environment and
            // the caller chooses argv, so any secret it prints would leak straight
            // to the client (and thus the LLM). Only lengths and metadata are
            // returned. A human-only live-output view is tracked as follow-up work.
            Ok(serde_json::json!({
                "exit_code": exit_code,
                "duration_ms": s.duration_ms,
                "stdout_length": s.stdout_len,
                "stderr_length": s.stderr_len,
                "truncated": truncated,
            }))
        })
    }
}

#[derive(Debug, Default)]
struct FrameSummary {
    stdout_len: u64,
    stderr_len: u64,
    duration_ms: u64,
}

async fn summarize_execution(
    execution: impl Future<Output = Result<i32, String>>,
    frames: mpsc::Receiver<ExecFrame>,
) -> Result<(i32, FrameSummary), String> {
    tokio::try_join!(execution, async { Ok(summarize_frames(frames).await) })
}

async fn summarize_frames(mut frames: mpsc::Receiver<ExecFrame>) -> FrameSummary {
    let mut summary = FrameSummary::default();
    while let Some(frame) = frames.recv().await {
        match frame {
            ExecFrame::Output { stream, data } => match stream {
                opaque_core::proto::ExecStream::Stdout => {
                    summary.stdout_len = summary.stdout_len.saturating_add(data.len() as u64);
                }
                opaque_core::proto::ExecStream::Stderr => {
                    summary.stderr_len = summary.stderr_len.saturating_add(data.len() as u64);
                }
            },
            ExecFrame::ExecCompleted { duration_ms, .. } => {
                summary.duration_ms = duration_ms;
                break;
            }
            _ => {}
        }
    }
    summary
}

/// Execute a command without platform sandbox, but with environment sanitization.
///
/// Clears inherited environment, sets restricted PATH and HOME, injects only
/// the profile's env vars, and enforces timeouts. OPAQUE_SOCK is never set.
pub async fn execute_direct(
    command: &[String],
    env: HashMap<String, String>,
    timeout_secs: u64,
    max_output_bytes: usize,
    tx: mpsc::Sender<ExecFrame>,
    working_dir: Option<&std::path::Path>,
) -> Result<i32, DirectExecError> {
    use tokio::io::AsyncReadExt;
    use tokio::process::Command;

    if command.is_empty() {
        return Err(DirectExecError::Configuration("empty command".into()));
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    // Clear environment completely.
    cmd.env_clear();

    // Restricted PATH — no user-specific dirs.
    cmd.env("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin");
    cmd.env("HOME", "/tmp");

    // Inject profile env vars, but never OPAQUE_SOCK.
    for (k, v) in &env {
        if k != "OPAQUE_SOCK" {
            cmd.env(k, v);
        }
    }

    // Set working directory if provided.
    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.process_group(0).kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| DirectExecError::Execution(format!("spawn failed: {e}")))?;

    let pid = child.id().unwrap_or(0);
    let mut custody = custody::ProcessCustody::new(pid);
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);
    custody::send_frame(&tx, ExecFrame::ExecStarted { pid }, deadline)
        .await
        .map_err(|error| DirectExecError::Execution(error.to_string()))?;

    let start = std::time::Instant::now();
    let mut total_bytes = 0usize;

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| DirectExecError::Execution("stdout not piped".into()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| DirectExecError::Execution("stderr not piped".into()))?;

    let mut stdout_buf = vec![0u8; 16384];
    let mut stderr_buf = vec![0u8; 16384];
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut process_exit = None;

    let exit_code = loop {
        if stdout_done
            && stderr_done
            && let Some(code) = process_exit
        {
            break code;
        }
        tokio::select! {
            _ = tx.closed() => return Err(DirectExecError::Execution("execution consumer disconnected".into())),
            result = stdout.read(&mut stdout_buf), if !stdout_done => {
                match result {
                    Ok(0) => stdout_done = true,
                    Ok(n) => {
                        total_bytes += n;
                        if total_bytes <= max_output_bytes
                            && let Ok(s) = String::from_utf8(stdout_buf[..n].to_vec()) {
                                custody::send_frame(&tx, ExecFrame::Output {
                                    stream: opaque_core::proto::ExecStream::Stdout, data: s,
                                }, deadline).await.map_err(|error| DirectExecError::Execution(error.to_string()))?;
                            }
                    }
                    Err(e) => {
                        tracing::warn!("stdout read error: {e}");
                        stdout_done = true;
                    }
                }
            }
            result = stderr.read(&mut stderr_buf), if !stderr_done => {
                match result {
                    Ok(0) => stderr_done = true,
                    Ok(n) => {
                        total_bytes += n;
                        if total_bytes <= max_output_bytes
                            && let Ok(s) = String::from_utf8(stderr_buf[..n].to_vec()) {
                                custody::send_frame(&tx, ExecFrame::Output {
                                    stream: opaque_core::proto::ExecStream::Stderr, data: s,
                                }, deadline).await.map_err(|error| DirectExecError::Execution(error.to_string()))?;
                            }
                    }
                    Err(e) => {
                        tracing::warn!("stderr read error: {e}");
                        stderr_done = true;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                tracing::warn!("execute_direct: timeout after {timeout_secs}s, killing process");
                custody.kill_group();
                let _ = child.kill().await;
                let duration_ms = start.elapsed().as_millis() as u64;
                custody::send_frame(&tx, ExecFrame::ExecCompleted { exit_code: -1, duration_ms }, custody::completion_deadline()).await
                    .map_err(|error| DirectExecError::Execution(error.to_string()))?;
                return Ok(-1);
            }
            status = custody.wait(&mut child), if process_exit.is_none() => {
                match status {
                    Ok(s) => process_exit = Some(s.code().unwrap_or(-1)),
                    Err(e) => return Err(DirectExecError::Execution(format!("wait failed: {e}"))),
                }
            }
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    custody::send_frame(
        &tx,
        ExecFrame::ExecCompleted {
            exit_code,
            duration_ms,
        },
        custody::completion_deadline(),
    )
    .await
    .map_err(|error| DirectExecError::Execution(error.to_string()))?;

    Ok(exit_code)
}

/// How a `sandbox.exec` will be contained on this host.
///
/// Decided before the `sandbox.created` audit event so the event can name the
/// strategy, and before any secret is resolved so a host with no usable
/// sandbox never sees plaintext. On Linux the decision is the probed
/// capability set (bubblewrap, Landlock, seccomp, user namespaces) turned
/// into a [`linux::SandboxStrategy`]; a host without a namespace wrapper is
/// refused here, before anything is spawned.
#[derive(Debug)]
enum SandboxPlan {
    /// `sandbox = false`: environment sanitization only.
    Direct,
    #[cfg(target_os = "linux")]
    Linux(linux::SandboxStrategy),
    #[cfg(target_os = "macos")]
    Seatbelt,
}

impl SandboxPlan {
    fn for_profile(profile: &ExecProfile) -> Result<Self, String> {
        if !profile.sandbox {
            return Ok(Self::Direct);
        }
        Self::platform_default()
    }

    #[cfg(target_os = "linux")]
    fn platform_default() -> Result<Self, String> {
        let caps = linux::SandboxCapabilities::detect();
        caps.log_capabilities();
        Self::from_capabilities(&caps)
    }

    /// The Linux plan for an already-probed host: the strongest strategy the
    /// capabilities support, or the refusal that stops the exec before any
    /// secret is resolved.
    #[cfg(target_os = "linux")]
    fn from_capabilities(caps: &linux::SandboxCapabilities) -> Result<Self, String> {
        linux::SandboxStrategy::select(caps)
            .map(Self::Linux)
            .map_err(|e| format!("linux sandbox unavailable: {e}"))
    }

    #[cfg(target_os = "macos")]
    fn platform_default() -> Result<Self, String> {
        Ok(Self::Seatbelt)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn platform_default() -> Result<Self, String> {
        Err("sandbox execution is not supported on this platform".into())
    }

    /// Label recorded in the audit trail: `none` for direct execution,
    /// `seatbelt` on macOS, or the Linux strategy actually selected such as
    /// `bubblewrap+landlock+seccomp` or `unshare+seccomp`.
    fn label(&self) -> String {
        match self {
            Self::Direct => "none".into(),
            #[cfg(target_os = "linux")]
            Self::Linux(strategy) => strategy.name(),
            #[cfg(target_os = "macos")]
            Self::Seatbelt => "seatbelt".into(),
        }
    }
}

/// Dispatch to the platform-specific sandbox executor according to `plan`.
///
/// [`SandboxPlan::Direct`] bypasses the platform sandbox and uses
/// `execute_direct()` instead (environment sanitization only).
async fn execute_platform_sandbox(
    plan: &SandboxPlan,
    profile: &ExecProfile,
    command: Vec<String>,
    env: HashMap<String, String>,
    tx: mpsc::Sender<ExecFrame>,
) -> Result<i32, String> {
    match plan {
        SandboxPlan::Direct => {
            tracing::info!(
                profile = %profile.name,
                "sandbox disabled for profile, using direct execution"
            );
            execute_direct(
                &command,
                env,
                profile.limits.timeout_secs,
                profile.limits.max_output_bytes,
                tx,
                Some(&profile.project_dir),
            )
            .await
            .map_err(|e| format!("direct execution failed: {e}"))
        }

        #[cfg(target_os = "linux")]
        SandboxPlan::Linux(strategy) => {
            let config = linux::LinuxSandboxConfig {
                command,
                env,
                project_dir: profile.project_dir.clone(),
                extra_read_paths: profile.extra_read_paths.clone(),
                network_allow: profile.network.allow.clone(),
                timeout_secs: profile.limits.timeout_secs,
                max_output_bytes: profile.limits.max_output_bytes,
            };
            linux::execute_with_strategy(config, strategy, tx)
                .await
                .map_err(|e| format!("linux sandbox failed: {e}"))
        }

        #[cfg(target_os = "macos")]
        SandboxPlan::Seatbelt => {
            let config = macos::MacOSSandboxConfig {
                command,
                env,
                project_dir: profile.project_dir.clone(),
                extra_read_paths: profile.extra_read_paths.clone(),
                network_allow: profile.network.allow.clone(),
                timeout_secs: profile.limits.timeout_secs,
                max_output_bytes: profile.limits.max_output_bytes,
            };
            macos::execute(config, tx)
                .await
                .map_err(|e| format!("macos sandbox failed: {e}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {

    #[tokio::test]
    async fn prepared_execution_reports_only_bounded_metadata_for_failed_large_output() {
        let directory = tempfile::tempdir().unwrap();
        for stderr in [false, true] {
            let audit = Arc::new(InMemoryAuditEmitter::new());
            let executor = SandboxExecutor::new(audit.clone(), Vec::new);
            let mut profile = test_profile();
            profile.sandbox = false;
            profile.project_dir = directory.path().into();
            profile.limits.max_output_bytes = 200_000;
            let command = if stderr {
                "head -c 65537 /dev/zero | tr '\\000' x >&2; exit 7"
            } else {
                "head -c 65537 /dev/zero | tr '\\000' x; exit 7"
            };
            let request = sandbox_request(
                serde_json::json!({"profile":profile.name,"command":["/bin/sh","-c",command]}),
            );
            let result = executor
                .prepare_with_loader(&request, |_| Ok(profile))
                .unwrap()
                .execute()
                .await
                .unwrap();
            assert_eq!(result["exit_code"], 7);
            assert_eq!(result["truncated"], true);
            assert_eq!(
                result[if stderr {
                    "stderr_length"
                } else {
                    "stdout_length"
                }],
                65_537
            );
            assert!(result.get("stdout").is_none() && result.get("stderr").is_none());
            assert!(
                audit
                    .events()
                    .iter()
                    .any(|e| e.kind == AuditEventKind::SandboxCompleted
                        && e.outcome.as_deref() == Some("failed"))
            );
            // Both sandbox events name the containment that was used.
            for kind in [
                AuditEventKind::SandboxCreated,
                AuditEventKind::SandboxCompleted,
            ] {
                assert!(
                    audit.events().iter().any(|e| e.kind == kind
                        && e.detail
                            .as_deref()
                            .is_some_and(|detail| detail.contains("sandbox=none"))),
                    "sandbox audit events must carry sandbox=none for a direct run"
                );
            }
        }
    }

    #[test]
    fn sandbox_plan_labels_direct_execution_as_none() {
        let mut profile = test_profile();
        profile.sandbox = false;
        let plan = SandboxPlan::for_profile(&profile).unwrap();
        assert!(matches!(plan, SandboxPlan::Direct));
        assert_eq!(plan.label(), "none");
    }

    /// PROPERTY (Linux): with the platform sandbox on, the executor either
    /// contains the workload under the probed strategy and names it in both
    /// sandbox audit events, or refuses explicitly with no `sandbox.created`
    /// event at all. It never reports a sandbox that did not exist.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_executor_names_the_strategy_or_refuses_before_any_sandbox_event() {
        let directory = tempfile::tempdir().unwrap();
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit.clone(), Vec::new);
        let mut profile = test_profile();
        profile.sandbox = true;
        profile.project_dir = directory.path().into();
        let request = sandbox_request(
            serde_json::json!({"profile":profile.name,"command":["/bin/sh","-c","exit 0"]}),
        );
        let result = executor
            .prepare_with_loader(&request, |_| Ok(profile))
            .unwrap()
            .execute()
            .await;
        let created: Vec<String> = audit
            .events()
            .iter()
            .filter(|e| e.kind == AuditEventKind::SandboxCreated)
            .filter_map(|e| e.detail.clone())
            .collect();
        match linux::SandboxStrategy::select(&linux::SandboxCapabilities::detect()) {
            Ok(strategy) => {
                let label = format!("sandbox={}", strategy.name());
                assert!(created.iter().any(|d| d.contains(&label)), "{created:?}");
                match result {
                    Ok(value) => {
                        assert_eq!(value["exit_code"], 0);
                        assert!(
                            audit.events().iter().any(|e| {
                                e.kind == AuditEventKind::SandboxCompleted
                                    && e.detail.as_deref().is_some_and(|d| d.contains(&label))
                            }),
                            "sandbox.completed must name {label}"
                        );
                    }
                    // The wrapper exists but this host cannot run it (for
                    // example a container without CAP_SYS_ADMIN).
                    Err(error) => assert!(
                        error.contains("linux sandbox failed"),
                        "unexpected failure shape: {error}"
                    ),
                }
            }
            Err(_) => {
                let error = result.expect_err("no wrapper on this host must refuse the exec");
                assert!(
                    error.contains("linux sandbox unavailable")
                        && error.contains("no sandbox strategy available"),
                    "{error}"
                );
                assert!(created.is_empty(), "refused exec must not claim a sandbox");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sandbox_plan_follows_the_probed_capabilities() {
        let caps =
            |bubblewrap: bool, landlock: bool, user_namespaces: bool| linux::SandboxCapabilities {
                bubblewrap,
                bubblewrap_evidence: if bubblewrap {
                    "ok".into()
                } else {
                    "bwrap is not on PATH".into()
                },
                landlock,
                landlock_evidence: "lsm=landlock-listed abi=v7".into(),
                seccomp: true,
                user_namespaces,
                user_namespaces_evidence: if user_namespaces {
                    "ok".into()
                } else {
                    "unshare probe exit status: 1: unshare: unshare failed".into()
                },
            };
        assert_eq!(
            SandboxPlan::from_capabilities(&caps(true, true, true))
                .unwrap()
                .label(),
            "bubblewrap+landlock+seccomp"
        );
        // Landlock missing: explicit failover, named in the label.
        assert_eq!(
            SandboxPlan::from_capabilities(&caps(false, false, true))
                .unwrap()
                .label(),
            "unshare+seccomp"
        );
        // No namespace wrapper: refused before anything runs.
        let refusal = SandboxPlan::from_capabilities(&caps(false, true, false)).unwrap_err();
        assert!(
            refusal.starts_with("linux sandbox unavailable: ")
                && refusal.contains("no sandbox strategy available")
                && refusal.contains("bwrap is not on PATH"),
            "{refusal}"
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn platform_dispatch_obeys_detected_seatbelt_capability_without_unsandboxed_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let mut profile = test_profile();
        profile.sandbox = true;
        profile.project_dir = dir.path().into();
        let (tx, mut rx) = mpsc::channel(16);
        let plan = SandboxPlan::for_profile(&profile).unwrap();
        assert_eq!(plan.label(), "seatbelt");
        let result = execute_platform_sandbox(
            &plan,
            &profile,
            vec!["/usr/bin/true".into()],
            HashMap::new(),
            tx,
        )
        .await;
        if macos::MacOSSandboxCapabilities::detect().sandbox_exec_works {
            assert_eq!(result.unwrap(), 0);
        } else {
            assert!(result.is_err());
        }
        let mut started = false;
        while let Some(frame) = rx.recv().await {
            if matches!(frame, ExecFrame::ExecStarted { .. }) {
                started = true;
            }
        }
        assert_eq!(
            started,
            macos::MacOSSandboxCapabilities::detect().sandbox_exec_works
        );
    }

    #[test]
    fn invalid_profile_inputs_never_resolve_or_authorize_execution() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor =
            SandboxExecutor::new(audit.clone(), || panic!("must not resolve invalid input"));
        for input in [
            serde_json::json!(null),
            serde_json::json!({"profile":"","command":["true"]}),
        ] {
            assert!(
                executor
                    .prepare_with_loader(&sandbox_request(input), |_| panic!("must not load"))
                    .is_err()
            );
        }
        let mut request = sandbox_request(serde_json::json!({"profile":"test","command":["true"]}));
        request.operation = "sandbox.other".into();
        assert!(
            executor
                .prepare_with_loader(&request, |_| panic!("must not load"))
                .is_err()
        );
        request.operation = "sandbox.exec".into();
        for secret in [false, true] {
            let mut profile = test_profile();
            if secret {
                profile
                    .secrets
                    .insert("TOKEN".into(), "env:BAD\0REF".into());
            } else {
                profile.env.insert("TOKEN".into(), "BAD\0VALUE".into());
            }
            assert!(
                executor
                    .prepare_with_loader(&request, |_| Ok(profile))
                    .is_err()
            );
        }
        let mut profile = test_profile();
        profile.env.insert("TOKEN".into(), "literal".into());
        let values = HashMap::from([("TOKEN".into(), SecretValue::new(vec![0xff]))]);
        assert_eq!(
            SandboxExecutor::build_env(&profile, &values)["TOKEN"],
            "literal"
        );
        assert!(audit.events().is_empty());
    }

    #[tokio::test]
    async fn direct_output_enforces_byte_budget_utf8_and_reserved_environment() {
        use opaque_core::proto::ExecStream;
        let dir = tempfile::tempdir().unwrap();
        for (script, limit, expected) in [
            (
                "printf stdout; printf stderr >&2; test -z \"${OPAQUE_SOCK+x}\"; exit 7",
                64,
                vec![
                    (ExecStream::Stdout, "stdout"),
                    (ExecStream::Stderr, "stderr"),
                ],
            ),
            ("printf too-long", 0, vec![]),
            ("printf too-long >&2", 0, vec![]),
            ("printf '\\377'", 64, vec![]),
            ("printf '\\377' >&2", 64, vec![]),
        ] {
            let (tx, mut rx) = mpsc::channel(32);
            let code = execute_direct(
                &["/bin/sh".into(), "-c".into(), script.into()],
                HashMap::from([("OPAQUE_SOCK".into(), "must-not-inherit".into())]),
                5,
                limit,
                tx,
                Some(dir.path()),
            )
            .await
            .unwrap();
            assert_eq!(code, if expected.is_empty() { 0 } else { 7 });
            let mut outputs = vec![];
            while let Some(frame) = rx.recv().await {
                if let ExecFrame::Output { stream, data } = frame {
                    outputs.push((stream, data));
                }
            }
            assert_eq!(outputs.len(), expected.len());
            for (stream, data) in expected {
                assert!(
                    outputs
                        .iter()
                        .any(|actual| actual.0 == stream && actual.1 == data)
                );
            }
        }
        let (tx, _rx) = mpsc::channel(1);
        assert!(matches!(
            execute_direct(&[], HashMap::new(), 1, 1, tx, None).await,
            Err(DirectExecError::Configuration(_))
        ));
    }

    #[tokio::test]
    async fn frame_summary_accepts_closed_producer_without_completion_fabrication() {
        let (tx, rx) = mpsc::channel(1);
        tx.send(ExecFrame::Output {
            stream: opaque_core::proto::ExecStream::Stderr,
            data: "failure".into(),
        })
        .await
        .unwrap();
        drop(tx);
        let summary = summarize_frames(rx).await;
        assert_eq!(summary.stderr_len, 7);
        assert_eq!(summary.stdout_len, 0);
        assert_eq!(summary.duration_ms, 0);
    }
    use super::*;

    #[tokio::test]
    async fn output_summary_counts_unicode_across_capture_boundaries_without_copies() {
        let (tx, rx) = mpsc::channel(2);
        let output = format!("{}é🙂", "a".repeat(65535));
        let expected = output.len() as u64;
        let producer = async move {
            for stream in [
                opaque_core::proto::ExecStream::Stdout,
                opaque_core::proto::ExecStream::Stderr,
            ] {
                tx.send(ExecFrame::Output {
                    stream,
                    data: output.clone(),
                })
                .await
                .unwrap();
            }
            tx.send(ExecFrame::ExecCompleted {
                exit_code: 0,
                duration_ms: 17,
            })
            .await
            .unwrap();
        };
        let (_, summary) = tokio::join!(producer, summarize_frames(rx));
        assert_eq!(summary.stdout_len, expected);
        assert_eq!(summary.stderr_len, expected);
        assert_eq!(summary.duration_ms, 17);
    }

    use std::path::PathBuf;

    use opaque_core::audit::InMemoryAuditEmitter;
    use opaque_core::operation::{ClientIdentity, ClientType};
    use uuid::Uuid;

    fn test_profile() -> ExecProfile {
        ExecProfile {
            name: "test".into(),
            description: None,
            sandbox: true,
            project_dir: PathBuf::from("/tmp"),
            extra_read_paths: vec![],
            network: opaque_core::profile::NetworkConfig { allow: vec![] },
            secrets: HashMap::new(),
            env: HashMap::from([("RUST_LOG".into(), "info".into())]),
            limits: opaque_core::profile::LimitsConfig {
                timeout_secs: 60,
                max_output_bytes: 1024,
            },
        }
    }

    #[test]
    fn build_env_combines_secrets_and_literals() {
        use opaque_core::secret::SecretValue;
        let profile = test_profile();
        let mut secrets = HashMap::new();
        secrets.insert(
            "API_KEY".into(),
            SecretValue::from_string("secret_value".into()),
        );

        let env = SandboxExecutor::build_env(&profile, &secrets);
        assert_eq!(env.get("RUST_LOG").unwrap(), "info");
        assert_eq!(env.get("API_KEY").unwrap(), "secret_value");
    }

    #[test]
    fn build_env_secrets_override_literals() {
        use opaque_core::secret::SecretValue;
        let mut profile = test_profile();
        profile
            .env
            .insert("SHARED_KEY".into(), "literal_value".into());

        let mut secrets = HashMap::new();
        secrets.insert(
            "SHARED_KEY".into(),
            SecretValue::from_string("secret_value".into()),
        );

        let env = SandboxExecutor::build_env(&profile, &secrets);
        assert_eq!(env.get("SHARED_KEY").unwrap(), "secret_value");
    }

    #[test]
    fn sandbox_executor_debug_format() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit, Vec::new);
        let debug = format!("{executor:?}");
        assert!(debug.contains("SandboxExecutor"));
    }

    #[tokio::test]
    async fn missing_profile_param_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit, Vec::new);

        let request = OperationRequest {
            principal: None,
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
                workload: None,
            },
            client_type: ClientType::Human,
            operation: "sandbox.exec".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({}),
            workspace: None,
        };

        let result = executor.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'profile'"));
    }

    #[tokio::test]
    async fn missing_command_param_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit, Vec::new);

        let request = OperationRequest {
            principal: None,
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
                workload: None,
            },
            client_type: ClientType::Human,
            operation: "sandbox.exec".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({"profile": "test"}),
            workspace: None,
        };

        let result = executor.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing or invalid 'command'"));
    }

    #[tokio::test]
    async fn empty_command_rejected() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit, Vec::new);

        let request = OperationRequest {
            principal: None,
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
                workload: None,
            },
            client_type: ClientType::Human,
            operation: "sandbox.exec".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params: serde_json::json!({"profile": "test", "command": []}),
            workspace: None,
        };

        let result = executor.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("command must not be empty"));
    }

    #[test]
    fn sandbox_response_omits_output_content() {
        // SECURITY (C2): the daemon response must carry only lengths + metadata,
        // never stdout/stderr *content* — returning content would leak secrets the
        // command printed to the calling client. This mirrors the response built in
        // execute_platform_sandbox above; keep the two in sync.
        let response = serde_json::json!({
            "exit_code": 0,
            "duration_ms": 150_u64,
            "stdout_length": 18_u64,
            "stderr_length": 0_u64,
            "truncated": false,
        });

        let obj = response.as_object().unwrap();
        assert!(obj.contains_key("exit_code"));
        assert!(obj.contains_key("duration_ms"));
        assert!(
            !obj.contains_key("stdout"),
            "stdout content must never be returned to the caller"
        );
        assert!(
            !obj.contains_key("stderr"),
            "stderr content must never be returned to the caller"
        );
        assert!(obj.contains_key("stdout_length"));
        assert!(obj.contains_key("stderr_length"));
        assert!(obj.contains_key("truncated"));
    }

    fn sandbox_request(params: serde_json::Value) -> OperationRequest {
        OperationRequest {
            principal: None,
            request_id: Uuid::new_v4(),
            client_identity: ClientIdentity {
                uid: 501,
                gid: 20,
                pid: Some(1234),
                exe_path: None,
                exe_sha256: None,
                codesign_team_id: None,
                workload: None,
            },
            client_type: ClientType::Human,
            operation: "sandbox.exec".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params,
            workspace: None,
        }
    }

    #[test]
    fn preparation_validates_argv_before_profile_loading_or_resolution() {
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit.clone(), || panic!("must not resolve"));
        for params in [
            serde_json::json!({"profile":"test","command":["/bin/echo"],"extra":true}),
            serde_json::json!({"profile":"test","command":["/bin/echo",1]}),
            serde_json::json!({"profile":"test","command":["/bin/echo","bad\u{0}arg"]}),
            serde_json::json!({"profile":"../test","command":["/bin/echo"]}),
            serde_json::json!({"profile":"test","command":[""]}),
        ] {
            assert!(
                executor
                    .prepare_with_loader(&sandbox_request(params), |_| panic!(
                        "must not load invalid action"
                    ))
                    .is_err()
            );
        }
        assert!(audit.events().is_empty());
    }

    #[test]
    fn profile_digest_is_stable_and_binds_all_execution_configuration() {
        let mut original = test_profile();
        original.env = HashMap::from([
            ("A".into(), "private-literal".into()),
            ("B".into(), "second".into()),
        ]);
        let mut reordered = original.clone();
        reordered.env = HashMap::from([
            ("B".into(), "second".into()),
            ("A".into(), "private-literal".into()),
        ]);
        assert_eq!(
            profile_digest(&original).unwrap(),
            profile_digest(&reordered).unwrap()
        );
        let original_digest = profile_digest(&original).unwrap();
        let mut variants = vec![];
        let mut next = original.clone();
        next.sandbox = !next.sandbox;
        variants.push(next);
        let mut next = original.clone();
        next.network.allow.push("fixture.invalid:443".into());
        variants.push(next);
        let mut next = original.clone();
        next.env.insert("A".into(), "different".into());
        variants.push(next);
        let mut next = original.clone();
        next.secrets
            .insert("TOKEN".into(), "env:FIXTURE_TOKEN".into());
        variants.push(next);
        let mut next = original.clone();
        next.limits.timeout_secs += 1;
        variants.push(next);
        let mut next = original.clone();
        next.project_dir = "/different".into();
        variants.push(next);
        for profile in variants {
            assert_ne!(original_digest, profile_digest(&profile).unwrap());
        }

        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor =
            SandboxExecutor::new(audit.clone(), || panic!("must not resolve during prepare"));
        original
            .secrets
            .insert("TOKEN".into(), "env:FIXTURE_TOKEN".into());
        let request = sandbox_request(
            serde_json::json!({"profile":original.name,"command":["/bin/echo","a b"]}),
        );
        let prepared = executor
            .prepare_with_loader(&request, |_| Ok(original.clone()))
            .unwrap();
        assert_eq!(prepared.secret_ref_names(), ["env:FIXTURE_TOKEN"]);
        assert_eq!(prepared.target()["command"], r#"["/bin/echo","a b"]"#);
        assert_eq!(
            prepared.target()["profile_sha256"],
            profile_digest(&original).unwrap()
        );
        assert!(!prepared.params().to_string().contains("private-literal"));
        assert!(prepared.params().get("profile").is_none());
        assert!(audit.events().is_empty());
    }

    #[tokio::test]
    async fn prepared_executor_uses_owned_profile_after_file_and_request_change() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.toml");
        let content = format!(
            r#"
[profile]
name = "snapshot"
sandbox = false
project_dir = {:?}
[env]
MARKER = "DO_NOT_SHOW_THIS_VALUE"
[limits]
timeout_secs = 3
max_output_bytes = 1024
"#,
            directory.path().display().to_string()
        );
        std::fs::write(&path, &content).unwrap();
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let executor = SandboxExecutor::new(audit.clone(), Vec::new);
        let mut request = sandbox_request(serde_json::json!({
            "profile":"snapshot", "command":["/bin/sh","-c","test ${#MARKER} -eq 22"]
        }));
        let mut loads = 0;
        let prepared = executor
            .prepare_with_loader(&request, |name| {
                loads += 1;
                profile::load_profile(&std::fs::read_to_string(&path).unwrap(), Some(name))
                    .map_err(|e| e.to_string())
            })
            .unwrap();
        assert_eq!(loads, 1);
        assert!(audit.events().is_empty());
        assert!(
            !prepared
                .params()
                .to_string()
                .contains("DO_NOT_SHOW_THIS_VALUE")
        );
        std::fs::write(&path, content.replace("DO_NOT_SHOW_THIS_VALUE", "changed")).unwrap();
        std::fs::remove_file(&path).unwrap();
        request.params["command"] = serde_json::json!(["/usr/bin/false"]);
        let result = prepared.execute().await.unwrap();
        assert_eq!(result["exit_code"], 0);
        assert_eq!(loads, 1);
    }

    #[test]
    fn long_and_distinct_argv_keep_their_exact_canonical_rendering() {
        let executor = SandboxExecutor::new(Arc::new(InMemoryAuditEmitter::new()), Vec::new);
        let mut requests = vec![];
        for command in [
            serde_json::json!(["/bin/echo", "a b"]),
            serde_json::json!(["/bin/echo", "a", "b"]),
            serde_json::json!(["/bin/echo", "x".repeat(8192)]),
        ] {
            let request = sandbox_request(serde_json::json!({"profile":"test","command":command}));
            requests.push(
                executor
                    .prepare_with_loader(&request, |_| Ok(test_profile()))
                    .unwrap(),
            );
        }
        assert_ne!(
            requests[0].target()["command"],
            requests[1].target()["command"]
        );
        assert!(requests[2].target()["command"].len() > 8192);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod lifecycle_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn completion_and_execution_errors_do_not_wait_for_unrelated_sender_clones() {
        let (tx, rx) = mpsc::channel(2);
        tx.send(ExecFrame::ExecCompleted {
            exit_code: -1,
            duration_ms: 23,
        })
        .await
        .unwrap();
        let (exit, summary) = tokio::time::timeout(
            Duration::from_millis(100),
            summarize_execution(async { Ok(-1) }, rx),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(exit, -1);
        assert_eq!(summary.duration_ms, 23);
        assert!(tx.is_closed());
        let (tx, rx) = mpsc::channel(2);
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            summarize_execution(async { Err("platform failure".into()) }, rx),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err(), "platform failure");
        assert!(tx.is_closed());
    }

    #[tokio::test]
    async fn output_activity_and_closed_pipes_do_not_extend_direct_execution_deadline() {
        for script in [
            "while :; do printf x; sleep 0.01; done",
            "exec 1>&- 2>&-; sleep 30",
        ] {
            let (tx, rx) = mpsc::channel(64);
            let command = ["/bin/sh".into(), "-c".into(), script.into()];
            let execution = execute_direct(&command, HashMap::new(), 1, 1024, tx, None);
            let (result, _) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(execution, summarize_frames(rx))
            })
            .await
            .expect("the original deadline must cover output and child wait");
            assert_eq!(result.unwrap(), -1);
        }
    }

    #[tokio::test]
    async fn cancelling_direct_execution_reaps_the_owned_process() {
        let (tx, mut rx) = mpsc::channel(4);
        let invocation = tokio::spawn(async move {
            execute_direct(
                &["/bin/sleep".into(), "30".into()],
                HashMap::new(),
                30,
                1024,
                tx,
                None,
            )
            .await
        });
        let ExecFrame::ExecStarted { pid } = rx.recv().await.unwrap() else {
            panic!("missing start");
        };
        invocation.abort();
        assert!(invocation.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            // SAFETY: signal zero observes only this disposable fixture PID.
            while unsafe { libc::kill(pid as i32, 0) } == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled child must be killed and reaped");
    }

    #[tokio::test]
    async fn direct_leader_exit_kills_descendants_holding_inherited_pipes() {
        let (tx, rx) = mpsc::channel(4);
        let command = [
            "/bin/sh".into(),
            "-c".into(),
            "sleep 30 & printf done; exit 0".into(),
        ];
        let (result, summary) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                execute_direct(&command, HashMap::new(), 30, 1024, tx, None),
                summarize_frames(rx)
            )
        })
        .await
        .expect("leader exit must terminate descendants and drain their pipes promptly");
        assert_eq!(result.unwrap(), 0);
        assert_eq!(summary.stdout_len, 4);
    }

    #[tokio::test]
    async fn disconnected_direct_consumer_terminates_quiet_child() {
        let (tx, mut rx) = mpsc::channel(4);
        let invocation = tokio::spawn(async move {
            execute_direct(
                &["/bin/sleep".into(), "30".into()],
                HashMap::new(),
                30,
                1024,
                tx,
                None,
            )
            .await
        });
        let ExecFrame::ExecStarted { pid } = rx.recv().await.unwrap() else {
            panic!("missing start")
        };
        drop(rx);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), invocation)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert_process_reaped(pid).await;
    }

    #[tokio::test]
    async fn backpressured_direct_output_preserves_execution_deadline() {
        let (tx, mut rx) = mpsc::channel(1);
        let invocation = tokio::spawn(async move {
            execute_direct(
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf output; sleep 30".into(),
                ],
                HashMap::new(),
                1,
                1024,
                tx,
                None,
            )
            .await
        });
        // ExecStarted fills the channel; the first output blocks its sender.
        let error = tokio::time::timeout(Duration::from_secs(3), invocation)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("frame delivery timed out"));
        let ExecFrame::ExecStarted { pid } = rx.recv().await.unwrap() else {
            panic!("missing start")
        };
        assert_process_reaped(pid).await;
    }

    async fn assert_process_reaped(pid: u32) {
        tokio::time::timeout(Duration::from_secs(2), async {
            // SAFETY: signal zero observes only this disposable fixture PID.
            while unsafe { libc::kill(pid as i32, 0) } == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("owned child must be killed and reaped");
    }
}
