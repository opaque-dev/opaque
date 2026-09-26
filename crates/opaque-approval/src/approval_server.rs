//! Local HTTPS approval server for paired mobile devices.
//!
//! The server listens on localhost with a self-signed TLS certificate
//! and advertises itself via mDNS (Bonjour) as `_opaque-approval._tcp`.
//! Paired devices connect to fetch pending approval challenges and submit
//! signed decisions; new devices complete pairing here.
//!
//! Trust model:
//! - **Pairing** (`POST /pair`): authenticated by the one-time nonce from the
//!   QR payload (5-minute TTL, single use). Returns the device id plus a
//!   per-device bearer token (shown once; stored hashed).
//! - **Notice feed**: `/notifications/pending` requires a separate read-only
//!   notification credential and returns opaque references only.
//! - **Device transport auth**: other authenticated routes require
//!   `Authorization: Bearer <token>` + `X-Opaque-Device: <device_id>`, and
//!   the token must match THAT device's stored hash. This is coarse gating
//!   only — it decides who may see and submit, never who approved.
//! - **Decisions** (`POST /approvals/{id}/respond`): the Ed25519 signature
//!   over the challenge + decision tag is verified against the pairing store
//!   BEFORE anything is relayed. What crosses into the daemon is the
//!   VERIFIED device record, never client-supplied identity.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::extract::{Json, Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::pairing::PairingManager;
use crate::pairing::store::PairedDevice;
mod scope;
mod workstation;
pub use scope::{PendingScopeReviews, ScopeReviewKey, ScopeReviewService, ScopeReviewServiceError};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("TLS setup failed: {0}")]
    TlsSetup(String),

    #[error("certificate generation failed: {0}")]
    CertGeneration(String),

    #[error("server bind failed: {0}")]
    Bind(String),

    #[error("mDNS registration failed: {0}")]
    MdnsRegistration(String),
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Configuration for the approval server.
#[derive(Debug, Clone)]
pub struct ApprovalServerConfig {
    /// Address to bind to (default: 127.0.0.1:0 for auto port selection).
    pub bind_addr: SocketAddr,
    /// TLS certificate (DER-encoded).
    pub tls_cert_der: Vec<u8>,
    /// TLS private key (PKCS8 DER-encoded).
    pub tls_key_der: Vec<u8>,
    /// Approval timeout in seconds (default: 60).
    pub timeout_secs: u64,
}

/// A challenge shown to a paired device. `challenge_data` carries the JSON of
/// the `pairing::challenge::ApprovalChallenge` the device must sign (together
/// with its decision tag — see `pairing::challenge::decision_bytes`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub request_id: String,
    pub operation: String,
    pub target: String,
    pub client_identity: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub challenge_data: String,
}

/// The decision on an approval challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

/// Body submitted by the device on the respond endpoint.
#[derive(Debug, Deserialize)]
pub struct RespondBody {
    pub decision: ApprovalDecision,
    /// Ed25519 signature over the decision bytes, hex-encoded.
    pub signature: String,
    pub device_id: String,
}

/// Body submitted on the pair endpoint.
#[derive(Debug, Deserialize)]
pub struct PairBody {
    /// One-time nonce from the QR payload.
    pub nonce: String,
    /// Device's Ed25519 public key, hex-encoded (32 bytes).
    pub device_public_key: String,
    /// Human-readable device name.
    pub device_name: String,
}

/// Response to a successful pairing.
#[derive(Debug, Serialize, Deserialize)]
pub struct PairResponse {
    pub device_id: String,
    pub server_id: String,
    /// Per-device bearer token — shown exactly once, stored hashed.
    pub token: String,
}

/// A decision whose signature HAS been verified against the pairing store.
/// The only thing the server ever relays inward.
#[derive(Debug, Clone)]
pub struct VerifiedDeviceDecision {
    pub approve: bool,
    pub device: PairedDevice,
    pub workstation_receipt: Option<opaque_core::workstation::SignedWorkstationReceipt>,
}

/// Pending approval entry (internal).
#[derive(Debug)]
struct PendingApproval {
    challenge: ApprovalChallenge,
    /// The signable form of the challenge, kept server-side so verification
    /// uses exactly what was issued (never client-echoed fields).
    pairing_challenge: crate::pairing::challenge::ApprovalChallenge,
    response_tx: oneshot::Sender<VerifiedDeviceDecision>,
    created_at: Instant,
    timeout: Duration,
}

/// JSON returned by GET /approvals/pending.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingApprovalsResponse {
    pub approvals: Vec<ApprovalChallenge>,
}

/// JSON returned by GET /health.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

pub(crate) struct ServerState {
    pending: Mutex<HashMap<String, PendingApproval>>,
    pairing: Arc<PairingManager>,
    timeout: Duration,
    workstation_pending: std::sync::Mutex<HashMap<String, workstation::PendingWorkstation>>,
    remote: Option<Arc<crate::remote::RemoteApprovals>>,
    scope_reviews: Option<Arc<dyn ScopeReviewService>>,
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerState")
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Cloneable handle for submitting challenges to a running (or about to run)
/// approval server. Held by the paired-device factor verifier.
#[derive(Clone, Debug)]
pub struct ApprovalServerHandle {
    state: Arc<ServerState>,
}

impl ApprovalServerHandle {
    /// Submit a challenge for approval and get a receiver for the VERIFIED
    /// response. The challenge expires after the configured timeout.
    pub async fn submit_challenge(
        &self,
        challenge: ApprovalChallenge,
        pairing_challenge: crate::pairing::challenge::ApprovalChallenge,
    ) -> oneshot::Receiver<VerifiedDeviceDecision> {
        let (tx, rx) = oneshot::channel();
        let entry = PendingApproval {
            challenge: challenge.clone(),
            pairing_challenge,
            response_tx: tx,
            created_at: Instant::now(),
            timeout: self.state.timeout,
        };
        let mut pending = self.state.pending.lock().await;
        pending.insert(challenge.request_id.clone(), entry);
        rx
    }

    /// The configured approval timeout.
    pub fn timeout(&self) -> Duration {
        self.state.timeout
    }
}

/// Test hook: pop one pending approval, handing back its signable challenge
/// and response sender — what the HTTP respond path does, minus HTTP.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn test_take_pending(
    handle: &ApprovalServerHandle,
) -> Option<(
    crate::pairing::challenge::ApprovalChallenge,
    oneshot::Sender<VerifiedDeviceDecision>,
)> {
    let mut pending = handle.state.pending.lock().await;
    let key = pending.keys().next()?.clone();
    let entry = pending.remove(&key)?;
    Some((entry.pairing_challenge, entry.response_tx))
}

// ---------------------------------------------------------------------------
// TLS certificate generation + persistence
// ---------------------------------------------------------------------------

/// Generated TLS identity with the certificate fingerprint for pairing.
#[derive(Debug, Clone)]
pub struct TlsIdentity {
    /// DER-encoded certificate bytes.
    pub cert_der: Vec<u8>,
    /// PKCS8 DER-encoded private key bytes.
    pub key_der: Vec<u8>,
    /// SHA-256 fingerprint of the certificate (hex-encoded).
    pub fingerprint: String,
    /// PEM-encoded certificate (for display/storage).
    pub cert_pem: String,
}

/// Generate a self-signed Ed25519 TLS certificate for the approval server.
pub fn generate_self_signed_cert() -> Result<TlsIdentity, ServerError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .map_err(|e| ServerError::CertGeneration(e.to_string()))?;

    let mut params = CertificateParams::new(vec!["localhost".into()])
        .map_err(|e| ServerError::CertGeneration(e.to_string()))?;
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("Opaque Approval Server".into()),
    );

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ServerError::CertGeneration(e.to_string()))?;

    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_der = key_pair.serialize_der();

    // SHA-256 fingerprint of the DER certificate.
    let mut hasher = Sha256::new();
    hasher.update(&cert_der);
    let fingerprint = hex::encode(hasher.finalize());

    Ok(TlsIdentity {
        cert_der,
        key_der,
        fingerprint,
        cert_pem,
    })
}

/// Load the persisted TLS identity from `<dir>/approval_server.{key,cert}`,
/// creating it on first use.
///
/// Persistence is not an optimization: paired devices pin the certificate
/// fingerprint from the QR payload, so a regenerated-per-start certificate
/// would break every existing pairing on restart. Both files live in the
/// daemon's custody set.
pub fn load_or_create_tls_identity(dir: &Path) -> Result<TlsIdentity, ServerError> {
    let key_path = dir.join("approval_server.key");
    let cert_path = dir.join("approval_server.cert");

    if key_path.exists() && cert_path.exists() {
        let key_der = std::fs::read(&key_path)
            .map_err(|e| ServerError::TlsSetup(format!("read {}: {e}", key_path.display())))?;
        let cert_der = std::fs::read(&cert_path)
            .map_err(|e| ServerError::TlsSetup(format!("read {}: {e}", cert_path.display())))?;
        let mut hasher = Sha256::new();
        hasher.update(&cert_der);
        let fingerprint = hex::encode(hasher.finalize());
        return Ok(TlsIdentity {
            cert_der,
            key_der,
            fingerprint,
            cert_pem: String::new(), // only needed at generation time
        });
    }

    let identity = generate_self_signed_cert()?;
    write_private(&key_path, &identity.key_der)
        .map_err(|e| ServerError::TlsSetup(format!("write {}: {e}", key_path.display())))?;
    write_private(&cert_path, &identity.cert_der)
        .map_err(|e| ServerError::TlsSetup(format!("write {}: {e}", cert_path.display())))?;
    Ok(identity)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

// Inline hex encoding to avoid adding a `hex` dependency.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd-length hex string".into());
        }
        // Slice only ASCII: a byte-even Unicode string may contain a code
        // point spanning the two-byte boundary and must not panic a handler.
        if !s.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid hex string".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex at position {i}: {e}"))
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ApprovalServer
// ---------------------------------------------------------------------------

/// Local HTTPS approval server for paired mobile devices.
pub struct ApprovalServer {
    state: Arc<ServerState>,
    config: ApprovalServerConfig,
}

impl ApprovalServer {
    /// Create a new approval server bound to the given pairing manager.
    pub fn new(
        config: ApprovalServerConfig,
        pairing: Arc<PairingManager>,
    ) -> Result<Self, ServerError> {
        let state = Arc::new(ServerState {
            pending: Mutex::new(HashMap::new()),
            pairing,
            timeout: Duration::from_secs(config.timeout_secs),
            workstation_pending: std::sync::Mutex::new(HashMap::new()),
            remote: None,
            scope_reviews: None,
        });

        Ok(Self { state, config })
    }

    /// Attach durable remote routing before exposing a handle or starting.
    pub fn with_remote(mut self, remote: Arc<crate::remote::RemoteApprovals>) -> Self {
        Arc::get_mut(&mut self.state)
            .expect("remote routing configured before server use")
            .remote = Some(remote);
        self
    }

    /// Attach host-owned scope review authority before exposing a handle/start.
    pub fn with_scope_reviews(mut self, service: Arc<dyn ScopeReviewService>) -> Self {
        Arc::get_mut(&mut self.state)
            .expect("scope reviews configured before server use")
            .scope_reviews = Some(service);
        self
    }

    /// Handle for submitting challenges (usable before and after `start`).
    pub fn handle(&self) -> ApprovalServerHandle {
        ApprovalServerHandle {
            state: self.state.clone(),
        }
    }

    /// Start the server in a background task. Returns the join handle and the
    /// actual bound address (useful when port 0 is used for auto-selection).
    pub async fn start(self) -> Result<(JoinHandle<()>, SocketAddr), ServerError> {
        let tls_config = build_tls_config(&self.config.tls_cert_der, &self.config.tls_key_der)?;

        let app = build_router(self.state.clone());

        let listener = tokio::net::TcpListener::bind(self.config.bind_addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| ServerError::Bind(e.to_string()))?;

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        let state = self.state.clone();
        let timeout = state.timeout;

        let handle = tokio::spawn(async move {
            // Spawn a background task to expire timed-out approvals.
            let expiry_state = state.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    expire_pending(&expiry_state, timeout).await;
                }
            });

            // A remote peer must not block other approvers by opening a TCP
            // socket and withholding its TLS handshake. Bound concurrent
            // connections and apply the handshake timeout inside each task.
            let connections = Arc::new(tokio::sync::Semaphore::new(128));
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!("approval server accept error: {e}");
                        continue;
                    }
                };

                let Ok(permit) = connections.clone().try_acquire_owned() else {
                    continue;
                };
                let tls_acceptor = tls_acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let tls_stream = match tokio::time::timeout(
                        Duration::from_secs(10),
                        tls_acceptor.accept(stream),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(error)) => {
                            warn!("TLS handshake failed: {error}");
                            return;
                        }
                        Err(_) => return,
                    };
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper_util::service::TowerToHyperService::new(app.into_service());
                    if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, service)
                    .await
                    {
                        warn!("connection error: {e}");
                    }
                });
            }
        });

        info!("approval server listening on {local_addr}");
        Ok((handle, local_addr))
    }

    /// Get a reference to the shared state (for testing).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn state(&self) -> &Arc<ServerState> {
        &self.state
    }
}

// ---------------------------------------------------------------------------
// TLS configuration
// ---------------------------------------------------------------------------

fn build_tls_config(cert_der: &[u8], key_der: &[u8]) -> Result<rustls::ServerConfig, ServerError> {
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::TlsSetup(e.to_string()))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

fn build_router(state: Arc<ServerState>) -> Router {
    Router::new()
        .merge(workstation::routes())
        .merge(scope::routes())
        .route(
            "/notifications/pending",
            get(workstation::notice_feed_handler),
        )
        .route("/health", get(health_handler))
        .route("/pair", post(pair_handler))
        .route("/approvals/pending", get(pending_handler))
        .route("/approvals/{request_id}/respond", post(respond_handler))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
    })
}

/// Complete a pairing. Authenticated by the one-time QR nonce, not a bearer
/// token (the device has no token yet — this is where it gets one).
async fn pair_handler(
    State(state): State<Arc<ServerState>>,
    Json(body): Json<PairBody>,
) -> Result<Json<PairResponse>, StatusCode> {
    let key_bytes = hex::decode(&body.device_public_key).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Attribution rides the pairing SESSION (captured when the ceremony was
    // started by an authenticated human), never completion time.
    let (device, token) = state
        .pairing
        .complete_pairing(&body.nonce, &key_bytes, &body.device_name)
        .map_err(|e| {
            warn!("pairing attempt failed: {e}");
            match e {
                crate::pairing::PairingError::Expired => StatusCode::GONE,
                crate::pairing::PairingError::InvalidNonce
                | crate::pairing::PairingError::SessionConsumed => StatusCode::UNAUTHORIZED,
                _ => StatusCode::BAD_REQUEST,
            }
        })?;

    info!(
        device_id = %device.device_id,
        device_name = %device.name,
        paired_by = device.paired_by.as_deref().unwrap_or("(no identity)"),
        "device paired"
    );

    Ok(Json(PairResponse {
        device_id: device.device_id,
        server_id: state.pairing.server_id().to_owned(),
        token,
    }))
}

async fn pending_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Json<PendingApprovalsResponse>, StatusCode> {
    let device_id = validate_auth(&state, &headers)?;
    if state.pairing.workstation_device(&device_id).is_ok() {
        return Err(StatusCode::FORBIDDEN);
    }

    let pending = state.pending.lock().await;
    let approvals: Vec<ApprovalChallenge> = pending.values().map(|p| p.challenge.clone()).collect();

    Ok(Json(PendingApprovalsResponse { approvals }))
}

async fn respond_handler(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    AxumPath(request_id): AxumPath<String>,
    Json(body): Json<RespondBody>,
) -> Result<StatusCode, StatusCode> {
    let auth_device = validate_auth(&state, &headers)?;

    // The transport identity and the claimed signer must agree — a device
    // may not submit under another device's name even with a valid token.
    if auth_device != body.device_id {
        return Err(StatusCode::FORBIDDEN);
    }

    let approve = matches!(body.decision, ApprovalDecision::Approve);
    let signature = hex::decode(&body.signature).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Verify FIRST, against the server-side copy of the challenge, without
    // consuming the pending entry: a garbage signature must not burn the
    // approval for the legitimate responder.
    let pairing_challenge = {
        let pending = state.pending.lock().await;
        let entry = pending.get(&request_id).ok_or(StatusCode::NOT_FOUND)?;
        if entry.created_at.elapsed() > entry.timeout {
            return Err(StatusCode::GONE);
        }
        entry.pairing_challenge.clone()
    };

    let device = state
        .pairing
        .verify_approval(&pairing_challenge, &signature, &body.device_id, approve)
        .map_err(|e| {
            warn!(
                device_id = %body.device_id,
                request_id = %request_id,
                "approval response REJECTED: signature did not verify: {e}"
            );
            StatusCode::FORBIDDEN
        })?;

    // Only now consume the entry and relay the verified decision.
    let entry = {
        let mut pending = state.pending.lock().await;
        pending.remove(&request_id).ok_or(StatusCode::NOT_FOUND)?
    };

    info!(
        device_id = %device.device_id,
        device_name = %device.name,
        request_id = %request_id,
        approve,
        "device decision verified"
    );

    let _ = entry.response_tx.send(VerifiedDeviceDecision {
        approve,
        device,
        workstation_receipt: None,
    });

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Auth validation
// ---------------------------------------------------------------------------

/// Validate the per-device bearer token. Returns the authenticated device id.
fn validate_auth(state: &ServerState, headers: &HeaderMap) -> Result<String, StatusCode> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let device_id = headers
        .get("x-opaque-device")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !state.pairing.verify_device_token(device_id, token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(device_id.to_owned())
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

async fn expire_pending(state: &ServerState, _timeout: Duration) {
    let mut pending = state.pending.lock().await;
    pending.retain(|_id, entry| entry.created_at.elapsed() <= entry.timeout);
}

// ---------------------------------------------------------------------------
// mDNS advertisement
// ---------------------------------------------------------------------------

/// Advertise the approval server via mDNS/Bonjour.
///
/// Returns the `ServiceDaemon` handle (drop to stop advertising).
pub fn advertise_mdns(port: u16, fingerprint: &str) -> Result<mdns_sd::ServiceDaemon, ServerError> {
    let mdns =
        mdns_sd::ServiceDaemon::new().map_err(|e| ServerError::MdnsRegistration(e.to_string()))?;

    let service_type = "_opaque-approval._tcp.local.";
    let instance_name = "opaqued";

    let mut properties = HashMap::new();
    properties.insert("fingerprint".to_string(), fingerprint.to_string());

    let service_info = mdns_sd::ServiceInfo::new(
        service_type,
        instance_name,
        "localhost.",
        "",
        port,
        properties,
    )
    .map_err(|e| ServerError::MdnsRegistration(e.to_string()))?;

    mdns.register(service_info)
        .map_err(|e| ServerError::MdnsRegistration(e.to_string()))?;

    info!("mDNS: advertising {service_type} on port {port}");

    Ok(mdns)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::pairing::challenge::decision_bytes;
    use crate::pairing::store::DeviceStore;
    use ed25519_dalek::{Signer, SigningKey};
    use std::net::{IpAddr, Ipv4Addr};

    /// A paired device driven by the test: real Ed25519 key, real token.
    struct TestDevice {
        device_id: String,
        token: String,
        signing_key: SigningKey,
    }

    struct TestRig {
        server: ApprovalServer,
        identity: TlsIdentity,
        pairing: Arc<PairingManager>,
        device: TestDevice,
        _dir: tempfile::TempDir,
    }

    /// Build a server over a REAL pairing manager with one REALLY paired
    /// device — tests exercise the exact verification path production uses.
    fn test_rig() -> TestRig {
        test_rig_with_timeout(60)
    }

    fn test_rig_with_timeout(timeout_secs: u64) -> TestRig {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let identity = generate_self_signed_cert().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(dir.path().join("devices.json"), vec![7u8; 32]);
        let server_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let pairing = Arc::new(PairingManager::new(
            "server-test-1".into(),
            server_key,
            0,
            store,
        ));

        let (_qr, nonce) = pairing.generate_qr_payload(Some("hum_pairer".into()));
        let device_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let (device, token) = pairing
            .complete_pairing(&nonce, device_key.verifying_key().as_bytes(), "Test iPhone")
            .unwrap();
        // Complete the fingerprint-confirmation ceremony the rig's tests
        // assume; the pre-confirmation quarantine has its own test.
        pairing.confirm_device(&device.device_id).unwrap();

        let config = ApprovalServerConfig {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            tls_cert_der: identity.cert_der.clone(),
            tls_key_der: identity.key_der.clone(),
            timeout_secs,
        };
        let server = ApprovalServer::new(config, pairing.clone()).unwrap();

        TestRig {
            server,
            identity,
            pairing,
            device: TestDevice {
                device_id: device.device_id,
                token,
                signing_key: device_key,
            },
            _dir: dir,
        }
    }

    /// Build a reqwest client that accepts the self-signed cert.
    fn test_client(identity: &TlsIdentity) -> reqwest::Client {
        let cert = reqwest::tls::Certificate::from_der(&identity.cert_der).unwrap();
        reqwest::Client::builder()
            .add_root_certificate(cert)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
    }

    /// Submit a wire+pairing challenge pair for `request_id`.
    async fn submit(
        rig: &TestRig,
        request_id: &str,
    ) -> (
        oneshot::Receiver<VerifiedDeviceDecision>,
        crate::pairing::challenge::ApprovalChallenge,
    ) {
        let pairing_challenge = rig.pairing.create_challenge(request_id, "test operation");
        let wire = ApprovalChallenge {
            request_id: request_id.into(),
            operation: "github.set_actions_secret".into(),
            target: "org/repo".into(),
            client_identity: "test-client".into(),
            created_at: 1000,
            expires_at: 2000,
            challenge_data: serde_json::to_string(&pairing_challenge).unwrap(),
        };
        let rx = rig
            .server
            .handle()
            .submit_challenge(wire, pairing_challenge.clone())
            .await;
        (rx, pairing_challenge)
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[tokio::test]
    async fn test_server_binds_to_localhost() {
        let rig = test_rig();
        let (_handle, addr) = rig.server.start().await.unwrap();

        assert!(
            addr.ip().is_loopback(),
            "server must bind to loopback, got {addr}"
        );
    }

    #[tokio::test]
    async fn test_server_uses_self_signed_tls() {
        let identity = generate_self_signed_cert().unwrap();

        // Fingerprint should be a 64-char hex string (SHA-256).
        assert_eq!(identity.fingerprint.len(), 64);
        assert!(identity.fingerprint.chars().all(|c| c.is_ascii_hexdigit()));

        // PEM should start with certificate header.
        assert!(identity.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));

        // DER should be non-empty.
        assert!(!identity.cert_der.is_empty());
    }

    #[tokio::test]
    async fn test_tls_identity_persists_for_fingerprint_stability() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_tls_identity(dir.path()).unwrap();
        let second = load_or_create_tls_identity(dir.path()).unwrap();
        assert_eq!(
            first.fingerprint, second.fingerprint,
            "paired devices pin the fingerprint — it must survive restarts"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("approval_server.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn test_pending_approval_endpoint() {
        let rig = test_rig();
        let (_rx, _pc) = submit(&rig, "req-1").await;

        let (device_id, token) = (rig.device.device_id.clone(), rig.device.token.clone());
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);

        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let body: PendingApprovalsResponse = resp.json().await.unwrap();
        assert_eq!(body.approvals.len(), 1);
        assert_eq!(body.approvals[0].request_id, "req-1");
        // The challenge_data carries the signable pairing challenge.
        let pc: crate::pairing::challenge::ApprovalChallenge =
            serde_json::from_str(&body.approvals[0].challenge_data).unwrap();
        assert_eq!(pc.request_id, "req-1");
    }

    #[tokio::test]
    async fn test_signed_approve_is_verified_and_relayed() {
        let rig = test_rig();
        let (rx, pc) = submit(&rig, "req-approve").await;

        let sig = rig.device.signing_key.sign(&decision_bytes(&pc, true));
        let (device_id, token) = (rig.device.device_id.clone(), rig.device.token.clone());
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);

        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-approve/respond",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .json(&serde_json::json!({
                "decision": "approve",
                "signature": hex_encode(&sig.to_bytes()),
                "device_id": device_id,
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);

        let verified = rx.await.unwrap();
        assert!(verified.approve);
        assert_eq!(verified.device.device_id, device_id);
        assert_eq!(verified.device.paired_by.as_deref(), Some("hum_pairer"));
    }

    #[tokio::test]
    async fn test_forged_signature_is_rejected_and_entry_survives() {
        let rig = test_rig();
        let (rx, pc) = submit(&rig, "req-forged").await;

        // Signature from a key that was never paired.
        let interloper = SigningKey::generate(&mut rand::rngs::OsRng);
        let sig = interloper.sign(&decision_bytes(&pc, true));

        let (device_id, token) = (rig.device.device_id.clone(), rig.device.token.clone());
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);

        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-forged/respond",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .json(&serde_json::json!({
                "decision": "approve",
                "signature": hex_encode(&sig.to_bytes()),
                "device_id": device_id,
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 403, "forged signature must be refused");

        // The pending entry survives a forged attempt: the legitimate device
        // can still respond.
        let good = rig.device.signing_key.sign(&decision_bytes(&pc, true));
        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-forged/respond",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .json(&serde_json::json!({
                "decision": "approve",
                "signature": hex_encode(&good.to_bytes()),
                "device_id": device_id,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(rx.await.unwrap().approve);
    }

    #[tokio::test]
    async fn test_signed_reject_cannot_be_flipped_to_approve() {
        let rig = test_rig();
        let (rx, pc) = submit(&rig, "req-flip").await;

        // The device signs a REJECT…
        let reject_sig = rig.device.signing_key.sign(&decision_bytes(&pc, false));
        let (device_id, token) = (rig.device.device_id.clone(), rig.device.token.clone());
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);

        // …and a relay tries to submit that signature as an APPROVE.
        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-flip/respond",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .json(&serde_json::json!({
                "decision": "approve",
                "signature": hex_encode(&reject_sig.to_bytes()),
                "device_id": device_id,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "decision flip must fail verification");

        // Submitted honestly as the reject it is, it verifies and relays.
        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-flip/respond",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .json(&serde_json::json!({
                "decision": "reject",
                "signature": hex_encode(&reject_sig.to_bytes()),
                "device_id": device_id,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert!(!rx.await.unwrap().approve);
    }

    #[tokio::test]
    async fn test_unauthenticated_request_rejected() {
        let rig = test_rig();
        let (device_id, token) = (rig.device.device_id.clone(), rig.device.token.clone());
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);
        let url = format!("https://127.0.0.1:{}/approvals/pending", addr.port());

        // No Authorization header.
        let resp = client.get(&url).send().await.unwrap();
        assert_eq!(resp.status(), 401);

        // Valid header shape but wrong token.
        let resp = client
            .get(&url)
            .header("Authorization", "Bearer wrong-token")
            .header("X-Opaque-Device", &device_id)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // Right token but no device header (token belongs to no one).
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // Right token, WRONG device id: per-device binding must hold.
        let resp = client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", "some-other-device")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);

        // Malformed header (no Bearer prefix).
        let resp = client
            .get(&url)
            .header("Authorization", token)
            .header("X-Opaque-Device", &device_id)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_pair_endpoint_pairs_and_returns_token() {
        let rig = test_rig();
        let (nonce_qr, nonce) = rig.pairing.generate_qr_payload(None);
        assert_eq!(nonce_qr.nonce, nonce);

        let new_device_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);

        let resp = client
            .post(format!("https://127.0.0.1:{}/pair", addr.port()))
            .json(&serde_json::json!({
                "nonce": nonce,
                "device_public_key": hex_encode(new_device_key.verifying_key().as_bytes()),
                "device_name": "Second Phone",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let pair: PairResponse = resp.json().await.unwrap();
        assert_eq!(pair.server_id, "server-test-1");
        assert!(!pair.token.is_empty());

        // QUARANTINE: completing /pair proves only nonce possession, so the
        // fresh token must NOT authenticate until a human confirms the key
        // fingerprint out-of-band.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {}", pair.token))
            .header("X-Opaque-Device", &pair.device_id)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            401,
            "unconfirmed device must not authenticate"
        );

        rig.pairing.confirm_device(&pair.device_id).unwrap();

        // Confirmed: the token now works for authenticated routes.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {}", pair.token))
            .header("X-Opaque-Device", &pair.device_id)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // A replayed nonce is refused.
        let resp = client
            .post(format!("https://127.0.0.1:{}/pair", addr.port()))
            .json(&serde_json::json!({
                "nonce": nonce,
                "device_public_key": hex_encode(new_device_key.verifying_key().as_bytes()),
                "device_name": "Sneaky Re-pair",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[tokio::test]
    async fn test_approval_timeout() {
        // Very short timeout: 1 second.
        let rig = test_rig_with_timeout(1);
        let (_rx, _pc) = submit(&rig, "req-timeout").await;

        let (device_id, token) = (rig.device.device_id.clone(), rig.device.token.clone());
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);

        // Wait for the challenge to expire.
        tokio::time::sleep(Duration::from_secs(2)).await;

        // The expired challenge should be reaped by the background task.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .send()
            .await
            .unwrap();

        let body: PendingApprovalsResponse = resp.json().await.unwrap();
        assert!(
            body.approvals.is_empty(),
            "expired approval should have been reaped"
        );
    }

    #[tokio::test]
    async fn test_concurrent_approvals() {
        let rig = test_rig();

        let mut receivers = Vec::new();
        let mut pairing_challenges = Vec::new();
        for i in 0..5 {
            let (rx, pc) = submit(&rig, &format!("req-{i}")).await;
            receivers.push(rx);
            pairing_challenges.push(pc);
        }

        let (device_id, token) = (rig.device.device_id.clone(), rig.device.token.clone());
        let signing_key = rig.device.signing_key.clone();
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);

        // Verify all are pending.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .send()
            .await
            .unwrap();
        let body: PendingApprovalsResponse = resp.json().await.unwrap();
        assert_eq!(body.approvals.len(), 5);

        // Approve req-0, reject req-1, each properly signed.
        let approve_sig = signing_key.sign(&decision_bytes(&pairing_challenges[0], true));
        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-0/respond",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .json(&serde_json::json!({
                "decision": "approve",
                "signature": hex_encode(&approve_sig.to_bytes()),
                "device_id": device_id,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let reject_sig = signing_key.sign(&decision_bytes(&pairing_challenges[1], false));
        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/req-1/respond",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .json(&serde_json::json!({
                "decision": "reject",
                "signature": hex_encode(&reject_sig.to_bytes()),
                "device_id": device_id,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // Verify remaining pending count.
        let resp = client
            .get(format!(
                "https://127.0.0.1:{}/approvals/pending",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .send()
            .await
            .unwrap();
        let body: PendingApprovalsResponse = resp.json().await.unwrap();
        assert_eq!(body.approvals.len(), 3);

        // Verify the responses.
        let r0 = receivers.remove(0).await.unwrap();
        assert!(r0.approve);
        let r1 = receivers.remove(0).await.unwrap();
        assert!(!r1.approve);
    }

    #[tokio::test]
    async fn test_mdns_advertisement() {
        let fingerprint = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        // Just verify the function doesn't panic and returns Ok.
        // Actual mDNS discovery is hard to test in CI, but we verify
        // the service daemon is created and registration doesn't error.
        let result = advertise_mdns(12345, fingerprint);
        match result {
            Ok(mdns) => {
                // Shutdown cleanly.
                let _ = mdns.shutdown();
            }
            Err(ServerError::MdnsRegistration(e)) => {
                // mDNS may fail in CI environments without a network stack.
                // This is acceptable — log and pass.
                eprintln!("mDNS not available in this environment: {e}");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn test_port_selection() {
        let rig = test_rig();
        let (_handle, addr) = rig.server.start().await.unwrap();

        // The assigned port should be non-zero.
        assert_ne!(addr.port(), 0, "OS should have assigned a real port");

        // And it should be on loopback.
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let rig = test_rig();
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);

        let resp = client
            .get(format!("https://127.0.0.1:{}/health", addr.port()))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200);
        let body: HealthResponse = resp.json().await.unwrap();
        assert_eq!(body.status, "ok");
    }

    #[tokio::test]
    async fn test_respond_nonexistent_request() {
        let rig = test_rig();
        let (device_id, token) = (rig.device.device_id.clone(), rig.device.token.clone());
        let (_handle, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);

        let resp = client
            .post(format!(
                "https://127.0.0.1:{}/approvals/nonexistent/respond",
                addr.port()
            ))
            .header("Authorization", format!("Bearer {token}"))
            .header("X-Opaque-Device", &device_id)
            .json(&serde_json::json!({
                "decision": "approve",
                "signature": "00",
                "device_id": device_id,
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 404);
    }

    #[test]
    fn state_debug_does_not_leak() {
        // ServerState's Debug must not print tokens or keys.
        let dir = tempfile::tempdir().unwrap();
        let store = DeviceStore::new(dir.path().join("d.json"), vec![1u8; 32]);
        let pairing = Arc::new(PairingManager::new(
            "s".into(),
            SigningKey::generate(&mut rand::rngs::OsRng),
            0,
            store,
        ));
        let state = ServerState {
            remote: None,
            scope_reviews: None,
            pending: Mutex::new(HashMap::new()),
            pairing,
            timeout: Duration::from_secs(60),
            workstation_pending: std::sync::Mutex::new(HashMap::new()),
        };
        let dbg = format!("{state:?}");
        assert!(dbg.contains("timeout"));
    }

    #[tokio::test]
    async fn malformed_signature_text_and_foreign_device_preserve_pending_round() {
        let rig = test_rig();
        let (receiver, challenge) = submit(&rig, "req-text-guard").await;
        let state = rig.server.state.clone();
        let (server, addr) = rig.server.start().await.unwrap();
        let client = test_client(&rig.identity);
        let url = format!(
            "https://127.0.0.1:{}/approvals/req-text-guard/respond",
            addr.port()
        );
        for signature in ["0", "gg", "€€", "a€", "🛑", "１２"] {
            let response = client.post(&url).header("Authorization",format!("Bearer {}",rig.device.token)).header("X-Opaque-Device",&rig.device.device_id)
                .json(&serde_json::json!({"decision":"approve","device_id":rig.device.device_id,"signature":signature})).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{signature}");
            assert!(state.pending.lock().await.contains_key("req-text-guard"));
        }
        let signed = hex_encode(
            &rig.device
                .signing_key
                .sign(&decision_bytes(&challenge, true))
                .to_bytes(),
        );
        let response = client.post(&url).header("Authorization",format!("Bearer {}",rig.device.token)).header("X-Opaque-Device",&rig.device.device_id)
            .json(&serde_json::json!({"decision":"approve","device_id":"foreign-device","signature":signed})).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(state.pending.lock().await.contains_key("req-text-guard"));
        let response = client.post(&url).header("Authorization",format!("Bearer {}",rig.device.token)).header("X-Opaque-Device",&rig.device.device_id)
            .json(&serde_json::json!({"decision":"approve","device_id":rig.device.device_id,"signature":signed})).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(receiver.await.unwrap().approve);
        assert!(!state.pending.lock().await.contains_key("req-text-guard"));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn expired_round_is_gone_before_signature_verification_and_is_not_consumed() {
        let rig = test_rig();
        let (_receiver, _challenge) = submit(&rig, "expired").await;
        rig.server
            .state
            .pending
            .lock()
            .await
            .get_mut("expired")
            .unwrap()
            .created_at = Instant::now() - Duration::from_secs(61);
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", rig.device.token).parse().unwrap(),
        );
        headers.insert("x-opaque-device", rig.device.device_id.parse().unwrap());
        assert_eq!(
            respond_handler(
                State(rig.server.state.clone()),
                headers,
                AxumPath("expired".into()),
                Json(RespondBody {
                    device_id: rig.device.device_id,
                    decision: ApprovalDecision::Approve,
                    signature: "00".repeat(64)
                })
            )
            .await
            .unwrap_err(),
            StatusCode::GONE
        );
        assert!(
            rig.server
                .state
                .pending
                .lock()
                .await
                .contains_key("expired")
        );
    }
}
