//! Audit event model and emission.
//!
//! Every operation, approval, and policy decision emits structured audit events.
//! Events carry correlation IDs ([`request_id`], [`approval_id`], [`event_id`])
//! for end-to-end tracing.
//!
//! Secret values NEVER appear in audit events.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use hmac::{Hmac, Mac};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::operation::{ClientIdentity, ClientType, OperationSafety};
use crate::policy::PolicyDecision;

pub mod checkpoint;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Audit event kind
// ---------------------------------------------------------------------------

/// The kind of event recorded by the daemon's audit sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    /// A new operation request was received by the daemon.
    RequestReceived,

    /// The policy engine denied the request.
    PolicyDenied,

    /// An approval is required before the operation can proceed.
    ApprovalRequired,

    /// An approval challenge was presented to the user.
    ApprovalPresented,

    /// The user granted approval.
    ApprovalGranted,

    /// The user denied approval (or it timed out).
    ApprovalDenied,

    /// The operation handler has started execution.
    OperationStarted,

    /// The operation completed successfully.
    OperationSucceeded,

    /// The operation failed.
    OperationFailed,

    /// A provider fetch (secret retrieval) has started.
    ProviderFetchStarted,

    /// A provider fetch has completed.
    ProviderFetchFinished,

    /// A request was rate-limited.
    RateLimited,

    /// An approval lease was reused (FirstUse within TTL).
    LeaseHit,

    /// A sandbox environment was created for command execution.
    SandboxCreated,

    /// A sandboxed command execution completed.
    SandboxCompleted,

    /// A secret reference was resolved (value never logged).
    SecretResolved,

    /// Audit events were dropped due to channel backpressure.
    AuditDropped,

    /// An execve was evaluated against policy.
    ExecveChecked,

    /// An execve was allowed (either by policy or cached lease).
    ExecveAllowed,

    /// An execve was denied by policy.
    ExecveDenied,

    /// An execve requires human approval before proceeding.
    ExecvePrompted,

    /// A human completed OIDC login and a login session was created.
    IdentityLoginSucceeded,

    /// An OIDC login attempt failed (bad token, domain not allowed, …).
    IdentityLoginFailed,

    /// A human login session was revoked by logout.
    IdentityLogout,

    /// A principal's role assignments were changed.
    IdentityRoleChanged,

    /// A delegation (agent session bound to a principal) was issued.
    DelegationIssued,

    /// A delegation was revoked before expiry.
    DelegationRevoked,

    /// Startup report of the daemon's trust-domain posture: whether the
    /// service-account split is enforced and what custody violations exist.
    TrustDomainPosture,

    /// A signed federation policy bundle was verified and applied.
    FederationBundleApplied,

    /// A federation bundle was refused (rollback, version reuse, bad
    /// signature at refresh time).
    FederationBundleRejected,

    /// The export pump's independent detector flagged an integrity anomaly
    /// (e.g. an operation succeeded without its required approval being
    /// granted in the chain).
    AuditAlert,

    /// The listener attested a workload before dispatching its request.
    WorkloadAttested,

    /// Workload attestation failed or a caller tried to assert its identity.
    WorkloadAttestationDenied,
}

impl fmt::Display for AuditEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::RequestReceived => "request.received",
            Self::PolicyDenied => "policy.denied",
            Self::ApprovalRequired => "approval.required",
            Self::ApprovalPresented => "approval.presented",
            Self::ApprovalGranted => "approval.granted",
            Self::ApprovalDenied => "approval.denied",
            Self::OperationStarted => "operation.started",
            Self::OperationSucceeded => "operation.succeeded",
            Self::OperationFailed => "operation.failed",
            Self::ProviderFetchStarted => "provider.fetch.started",
            Self::ProviderFetchFinished => "provider.fetch.finished",
            Self::RateLimited => "rate.limited",
            Self::LeaseHit => "lease.hit",
            Self::SandboxCreated => "sandbox.created",
            Self::SandboxCompleted => "sandbox.completed",
            Self::SecretResolved => "secret.resolved",
            Self::AuditDropped => "audit.dropped",
            Self::ExecveChecked => "execve.checked",
            Self::ExecveAllowed => "execve.allowed",
            Self::ExecveDenied => "execve.denied",
            Self::ExecvePrompted => "execve.prompted",
            Self::IdentityLoginSucceeded => "identity.login.succeeded",
            Self::IdentityLoginFailed => "identity.login.failed",
            Self::IdentityLogout => "identity.logout",
            Self::IdentityRoleChanged => "identity.role.changed",
            Self::DelegationIssued => "delegation.issued",
            Self::DelegationRevoked => "delegation.revoked",
            Self::TrustDomainPosture => "trust_domain.posture",
            Self::FederationBundleApplied => "federation.bundle_applied",
            Self::FederationBundleRejected => "federation.bundle_rejected",
            Self::AuditAlert => "audit.alert",
            Self::WorkloadAttested => "workload.attested",
            Self::WorkloadAttestationDenied => "workload.attestation_denied",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for AuditEventKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "request.received" => Ok(Self::RequestReceived),
            "policy.denied" => Ok(Self::PolicyDenied),
            "approval.required" => Ok(Self::ApprovalRequired),
            "approval.presented" => Ok(Self::ApprovalPresented),
            "approval.granted" => Ok(Self::ApprovalGranted),
            "approval.denied" => Ok(Self::ApprovalDenied),
            "operation.started" => Ok(Self::OperationStarted),
            "operation.succeeded" => Ok(Self::OperationSucceeded),
            "operation.failed" => Ok(Self::OperationFailed),
            "provider.fetch.started" => Ok(Self::ProviderFetchStarted),
            "provider.fetch.finished" => Ok(Self::ProviderFetchFinished),
            "rate.limited" => Ok(Self::RateLimited),
            "lease.hit" => Ok(Self::LeaseHit),
            "sandbox.created" => Ok(Self::SandboxCreated),
            "sandbox.completed" => Ok(Self::SandboxCompleted),
            "secret.resolved" => Ok(Self::SecretResolved),
            "audit.dropped" => Ok(Self::AuditDropped),
            "execve.checked" => Ok(Self::ExecveChecked),
            "execve.allowed" => Ok(Self::ExecveAllowed),
            "execve.denied" => Ok(Self::ExecveDenied),
            "execve.prompted" => Ok(Self::ExecvePrompted),
            "identity.login.succeeded" => Ok(Self::IdentityLoginSucceeded),
            "identity.login.failed" => Ok(Self::IdentityLoginFailed),
            "identity.logout" => Ok(Self::IdentityLogout),
            "identity.role.changed" => Ok(Self::IdentityRoleChanged),
            "delegation.issued" => Ok(Self::DelegationIssued),
            "delegation.revoked" => Ok(Self::DelegationRevoked),
            "trust_domain.posture" => Ok(Self::TrustDomainPosture),
            "federation.bundle_applied" => Ok(Self::FederationBundleApplied),
            "federation.bundle_rejected" => Ok(Self::FederationBundleRejected),
            "audit.alert" => Ok(Self::AuditAlert),
            "workload.attested" => Ok(Self::WorkloadAttested),
            "workload.attestation_denied" => Ok(Self::WorkloadAttestationDenied),
            _ => Err(format!("unknown audit event kind: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Audit error type
// ---------------------------------------------------------------------------

/// Errors from the SQLite audit backend.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Client summary (safe for audit)
// ---------------------------------------------------------------------------

/// Audit-safe snapshot of the verified principal/delegation context attached
/// to a request (Phase 1 identity substrate).
///
/// Plain strings by design: audit rows are historical records, stable across
/// releases. `sub_roles` is the role set the delegating principal held AT THE
/// TIME of the request (roles are mutable; the snapshot preserves why a
/// decision was made).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalSummary {
    /// Principal the operation was performed on behalf of.
    pub sub: String,
    /// Display label for `sub` (email for humans, `service:<name>`).
    pub sub_label: String,
    /// Roles `sub` held at request time.
    #[serde(default)]
    pub sub_roles: Vec<String>,
    /// Acting agent workload principal.
    pub act: String,
    /// Display label for `act` (e.g. `agent:claude-code`).
    pub act_label: String,
    /// Access mode of the delegation (delegated / autonomous / break_glass).
    pub mode: String,
    /// Delegation session id.
    pub jti: String,
    /// Team namespaces under the applied federation bundle (empty when no
    /// bundle governs; omitted from JSON when empty so pre-federation records
    /// keep their exact serialized shape).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_teams: Vec<String>,
}

impl From<&crate::identity::PrincipalContext> for PrincipalSummary {
    fn from(ctx: &crate::identity::PrincipalContext) -> Self {
        Self {
            sub: ctx.sub.as_str().to_owned(),
            sub_label: ctx.sub_label.clone(),
            sub_roles: ctx
                .sub_roles
                .iter()
                .map(|r| r.as_str().to_owned())
                .collect(),
            act: ctx.act.as_str().to_owned(),
            act_label: ctx.act_label.clone(),
            mode: ctx.mode.as_str().to_owned(),
            jti: ctx.jti.clone(),
            sub_teams: ctx.sub_teams.clone(),
        }
    }
}

/// How an approval's approver identity was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproverSource {
    /// Local OS biometric/password prompt passed while the named principal
    /// held the active login session. Presence is cryptographically proven
    /// (device owner); the *name* is session-bound, not signature-bound.
    LocalBioSession,
    /// A paired device's Ed25519 signature over the approval challenge was
    /// verified against the pairing store. Signature-bound: only recorded by
    /// the paired-device factor verifier, never from relayed, unverified
    /// device ids.
    PairedDevice,
    /// An enrolled workstation key signed the full review and decision. The
    /// broker trusts workstation custody; this is not biometric attestation.
    PairedWorkstation,
    /// A FIDO2/WebAuthn assertion (hardware key or passkey) over the approval
    /// challenge was verified against the stored credential. Signature-bound.
    Fido2,
    /// Linux polkit authorized the approval; the named account is the
    /// authenticated session user reported by the approval helper.
    /// Account-verified (polkit checked credentials), not signature-bound.
    PolkitAccount,
    /// The insecure auto-approve test backend granted it. Never a person.
    InsecureAutoApprove,
}

impl fmt::Display for ApproverSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalBioSession => write!(f, "local_bio_session"),
            Self::PairedDevice => write!(f, "paired_device"),
            Self::PairedWorkstation => write!(f, "paired_workstation"),
            Self::Fido2 => write!(f, "fido2"),
            Self::PolkitAccount => write!(f, "polkit_account"),
            Self::InsecureAutoApprove => write!(f, "insecure_auto_approve"),
        }
    }
}

/// The identity that confirmed an out-of-band approval, recorded in the audit
/// chain (`approver_json` column, covered by the record HMAC).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverIdentity {
    /// Approving principal id (`hum_…`), or a device id for paired devices.
    pub principal_id: String,
    /// Display label at approval time.
    pub label: String,
    /// How this identity was established.
    pub source: ApproverSource,
}

/// A summary of the client identity, safe for inclusion in audit events.
/// Does not contain secrets or full hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSummary {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
    pub exe_path: Option<String>,
    /// Truncated hash prefix (first 16 hex chars) for identification without
    /// full disclosure.
    pub exe_sha256_prefix: Option<String>,
    pub codesign_team_id: Option<String>,
    pub client_type: ClientType,
    /// Verified principal/delegation context, when the request carried one.
    /// `skip_serializing_if` keeps identity-less rows byte-identical to
    /// pre-Phase-1 rows, so existing chain hashes keep verifying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalSummary>,
}

impl ClientSummary {
    /// Attach the verified principal context to this summary.
    pub fn with_principal(mut self, ctx: &crate::identity::PrincipalContext) -> Self {
        self.principal = Some(PrincipalSummary::from(ctx));
        self
    }
}

impl From<(&ClientIdentity, ClientType)> for ClientSummary {
    fn from((id, ct): (&ClientIdentity, ClientType)) -> Self {
        Self {
            uid: id.uid,
            gid: id.gid,
            pid: id.pid,
            exe_path: id
                .exe_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            exe_sha256_prefix: id
                .exe_sha256
                .as_ref()
                .map(|h| crate::validate::truncate_utf8(h, 16).to_owned()),
            codesign_team_id: id.codesign_team_id.clone(),
            client_type: ct,
            principal: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Target summary (safe for audit)
// ---------------------------------------------------------------------------

/// A summary of the operation target, safe for audit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetSummary {
    /// Key-value pairs describing the target (e.g. repo, cluster, namespace).
    pub fields: std::collections::HashMap<String, String>,
}

impl TargetSummary {
    /// Create a sanitized target summary by scrubbing URLs and redacting
    /// secret patterns in all values.
    pub fn sanitized(target: &std::collections::HashMap<String, String>) -> Self {
        let patterns = crate::sanitize::SecretPatterns::compile();
        let fields = target
            .iter()
            .map(|(k, v)| {
                let scrubbed = crate::sanitize::scrub_urls(v);
                let redacted = patterns.redact(&scrubbed);
                (k.clone(), redacted)
            })
            .collect();
        Self { fields }
    }
}

// ---------------------------------------------------------------------------
// Workspace summary (safe for audit)
// ---------------------------------------------------------------------------

/// A summary of the workspace context, safe for inclusion in audit events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSummary {
    /// Git remote URL.
    pub remote_url: Option<String>,
    /// Current branch name.
    pub branch: Option<String>,
    /// Whether the working tree is dirty.
    pub dirty: bool,
}

impl WorkspaceSummary {
    /// Create a sanitized workspace summary, stripping userinfo from the
    /// remote URL.
    pub fn sanitized(ws: &crate::operation::WorkspaceContext) -> Self {
        Self {
            remote_url: ws
                .remote_url
                .as_deref()
                .map(crate::validate::InputValidator::sanitize_url),
            branch: ws.branch.clone(),
            dirty: ws.dirty,
        }
    }
}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

/// A structured audit event.
///
/// See `docs/audit-analytics.md` for inspection and custody boundaries.
/// Secret values NEVER appear here.
#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub event_id: Uuid,

    /// Monotonically increasing sequence number assigned by the emitter.
    pub sequence_number: u64,

    /// UTC timestamp in milliseconds since epoch.
    pub ts_utc_ms: i64,

    /// Event severity level.
    pub level: AuditLevel,

    /// The kind of event.
    pub kind: AuditEventKind,

    /// Correlation: end-to-end request identifier.
    pub request_id: Option<Uuid>,

    /// Correlation: approval request identifier (may differ per step-up).
    pub approval_id: Option<Uuid>,

    /// Client summary.
    pub client: Option<ClientSummary>,

    /// Operation name (e.g. `"github.set_actions_secret"`).
    pub operation: Option<String>,

    /// Operation safety classification.
    pub safety: Option<OperationSafety>,

    /// Target summary.
    pub target: Option<TargetSummary>,

    /// Outcome string: `"ok"`, `"denied"`, `"error"`.
    pub outcome: Option<String>,

    /// Latency in milliseconds (approval latency, operation latency, etc.).
    pub latency_ms: Option<i64>,

    /// Secret variable names referenced (never values).
    pub secret_names: Vec<String>,

    /// Policy decision summary (for policy events).
    pub policy_decision: Option<String>,

    /// Human-readable detail message (sanitized).
    pub detail: Option<String>,

    /// Workspace summary (git repo/branch info).
    pub workspace: Option<WorkspaceSummary>,

    /// SHA-256 content hash of the operation request (for approval binding).
    /// Not secret — safe for display and audit.
    pub request_hash: Option<String>,

    /// Who confirmed the approval (approval events only). Persisted in its
    /// own chained column so tampering with attribution is detectable.
    pub approver: Option<ApproverIdentity>,
}

// Custom Debug to avoid any accidental leakage.
impl fmt::Debug for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditEvent")
            .field("event_id", &self.event_id)
            .field("sequence_number", &self.sequence_number)
            .field("kind", &self.kind)
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .field("outcome", &self.outcome)
            .field("latency_ms", &self.latency_ms)
            .field("request_hash", &self.request_hash)
            .finish()
    }
}

/// Severity level for audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    Info,
    Warn,
    Error,
}

impl fmt::Display for AuditLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warn => write!(f, "warn"),
            Self::Error => write!(f, "error"),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditEvent builder
// ---------------------------------------------------------------------------

impl AuditEvent {
    /// Create a new audit event with the given kind. Timestamps and event_id
    /// are set automatically.
    pub fn new(kind: AuditEventKind) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();

        Self {
            event_id: Uuid::new_v4(),
            sequence_number: 0,
            ts_utc_ms: now.as_millis() as i64,
            level: default_level_for_kind(kind),
            kind,
            request_id: None,
            approval_id: None,
            client: None,
            operation: None,
            safety: None,
            target: None,
            outcome: None,
            latency_ms: None,
            secret_names: vec![],
            policy_decision: None,
            detail: None,
            workspace: None,
            request_hash: None,
            approver: None,
        }
    }

    /// Set the sequence number.
    pub fn with_sequence_number(mut self, seq: u64) -> Self {
        self.sequence_number = seq;
        self
    }

    /// Set the approver identity (approval events).
    pub fn with_approver(mut self, approver: ApproverIdentity) -> Self {
        self.approver = Some(approver);
        self
    }

    /// Set the request correlation ID.
    pub fn with_request_id(mut self, id: Uuid) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Set the approval correlation ID.
    pub fn with_approval_id(mut self, id: Uuid) -> Self {
        self.approval_id = Some(id);
        self
    }

    /// Set the client summary.
    pub fn with_client(mut self, client: ClientSummary) -> Self {
        self.client = Some(client);
        self
    }

    /// Set the operation name.
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Set the safety classification.
    pub fn with_safety(mut self, safety: OperationSafety) -> Self {
        self.safety = Some(safety);
        self
    }

    /// Set the target summary.
    pub fn with_target(mut self, target: TargetSummary) -> Self {
        self.target = Some(target);
        self
    }

    /// Set the outcome.
    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    /// Set the latency.
    pub fn with_latency_ms(mut self, ms: i64) -> Self {
        self.latency_ms = Some(ms);
        self
    }

    /// Set secret names.
    pub fn with_secret_names(mut self, names: Vec<String>) -> Self {
        self.secret_names = names;
        self
    }

    /// Set policy decision summary.
    pub fn with_policy_decision(mut self, decision: &PolicyDecision) -> Self {
        self.policy_decision = Some(format!("{decision}"));
        self
    }

    /// Set a detail message.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Override the level.
    pub fn with_level(mut self, level: AuditLevel) -> Self {
        self.level = level;
        self
    }

    /// Set the workspace summary.
    pub fn with_workspace(mut self, workspace: WorkspaceSummary) -> Self {
        self.workspace = Some(workspace);
        self
    }

    /// Set the request content hash (for approval binding).
    pub fn with_request_hash(mut self, hash: impl Into<String>) -> Self {
        self.request_hash = Some(hash.into());
        self
    }
}

/// Default severity level based on event kind.
fn default_level_for_kind(kind: AuditEventKind) -> AuditLevel {
    match kind {
        AuditEventKind::PolicyDenied
        | AuditEventKind::ApprovalDenied
        | AuditEventKind::RateLimited
        | AuditEventKind::AuditDropped
        | AuditEventKind::IdentityLoginFailed
        | AuditEventKind::WorkloadAttestationDenied
        | AuditEventKind::ExecveDenied => AuditLevel::Warn,
        AuditEventKind::OperationFailed => AuditLevel::Error,
        _ => AuditLevel::Info,
    }
}

// ---------------------------------------------------------------------------
// Audit emitter trait
// ---------------------------------------------------------------------------

/// Trait for emitting audit events.
///
/// Implementations should be non-blocking. For I/O-bound backends (SQLite,
/// network), buffer events internally and flush asynchronously.
///
/// This is the primary interface used by the enclave.
pub trait AuditSink: Send + Sync + fmt::Debug {
    /// Emit an audit event. Must not block the caller.
    fn emit(&self, event: AuditEvent);

    /// Block until previously emitted events are durably recorded.
    ///
    /// Emission is asynchronous, so a process that exits immediately after
    /// recording a security-relevant event (a refused policy bundle, a
    /// fail-closed startup) would otherwise lose it: `std::process::exit`
    /// runs no destructors, and the writer thread dies mid-flight. Call this
    /// before any deliberate exit that follows an `emit`. A successful result
    /// means all prior events committed; timeout, storage failure or dropped
    /// events are explicit errors. Synchronous sinks return success by default.
    fn flush(&self, _timeout: std::time::Duration) -> Result<(), AuditFlushError> {
        Ok(())
    }
}

/// A flush never reports success after the sink has lost an event. Failure is
/// sticky for the lifetime of that sink, even when subsequent writes succeed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditFlushError {
    #[error("audit flush timed out before all accepted events were committed")]
    Timeout,
    #[error("audit persistence failed: {0}")]
    Storage(String),
    #[error("audit sink is closed")]
    Closed,
    #[error("audit events were lost due to channel backpressure")]
    Backpressure,
}

// ---------------------------------------------------------------------------
// In-memory audit emitter (for testing)
// ---------------------------------------------------------------------------

/// Internal state for `InMemoryAuditEmitter`.
#[derive(Debug)]
struct InMemoryAuditState {
    events: Vec<AuditEvent>,
    next_sequence: u64,
}

/// An in-memory audit emitter that stores events in a `Vec` behind a mutex.
/// Assigns monotonically increasing sequence numbers. Useful for testing.
#[derive(Debug, Clone)]
pub struct InMemoryAuditEmitter {
    state: std::sync::Arc<std::sync::Mutex<InMemoryAuditState>>,
}

impl InMemoryAuditEmitter {
    /// Create a new empty emitter.
    pub fn new() -> Self {
        Self {
            state: std::sync::Arc::new(std::sync::Mutex::new(InMemoryAuditState {
                events: Vec::new(),
                next_sequence: 0,
            })),
        }
    }

    /// Retrieve a snapshot of all emitted events.
    pub fn events(&self) -> Vec<AuditEvent> {
        self.state
            .lock()
            .expect("audit mutex poisoned")
            .events
            .clone()
    }

    /// Number of emitted events.
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("audit mutex poisoned")
            .events
            .len()
    }

    /// Whether any events have been emitted.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clear all stored events.
    pub fn clear(&self) {
        let mut state = self.state.lock().expect("audit mutex poisoned");
        state.events.clear();
    }

    /// Get events of a specific kind.
    pub fn events_of_kind(&self, kind: AuditEventKind) -> Vec<AuditEvent> {
        self.state
            .lock()
            .expect("audit mutex poisoned")
            .events
            .iter()
            .filter(|e| e.kind == kind)
            .cloned()
            .collect()
    }
}

impl Default for InMemoryAuditEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for InMemoryAuditEmitter {
    fn emit(&self, mut event: AuditEvent) {
        let mut state = self.state.lock().expect("audit mutex poisoned");
        event.sequence_number = state.next_sequence;
        state.next_sequence += 1;
        state.events.push(event);
    }
}

// ---------------------------------------------------------------------------
// Tracing audit emitter (logs events via tracing)
// ---------------------------------------------------------------------------

/// An audit emitter that logs events via the `tracing` crate.
/// Assigns monotonically increasing sequence numbers.
#[derive(Debug)]
pub struct TracingAuditEmitter {
    next_sequence: AtomicU64,
}

impl TracingAuditEmitter {
    /// Create a new tracing audit emitter.
    pub fn new() -> Self {
        Self {
            next_sequence: AtomicU64::new(0),
        }
    }
}

impl Default for TracingAuditEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for TracingAuditEmitter {
    fn emit(&self, mut event: AuditEvent) {
        event.sequence_number = self.next_sequence.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            event_id = %event.event_id,
            sequence_number = event.sequence_number,
            kind = %event.kind,
            request_id = ?event.request_id,
            operation = ?event.operation,
            outcome = ?event.outcome,
            latency_ms = ?event.latency_ms,
            "audit event"
        );
    }
}

// ---------------------------------------------------------------------------
// SQLite audit sink (persistent storage)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tamper-evident hash chain
// ---------------------------------------------------------------------------

/// Genesis value the first audit record chains from.
const CHAIN_GENESIS: &str = "opaque-audit-chain-genesis-v1";

/// The persisted columns bound into each record's chain hash, in a fixed order.
/// Insert, verify, and backfill all reference this list so the canonical form
/// they hash is identical.
const CHAIN_COLUMNS: &str = "event_id, sequence_number, ts_utc_ms, level, kind, \
request_id, approval_id, client_json, operation, safety, target_json, outcome, \
latency_ms, secret_names, policy_decision, detail, workspace_json, request_hash";

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Path to the HMAC key file that seals the audit chain, derived from the database
/// path (sibling file with a `.hmac` extension).
fn hmac_key_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("hmac")
}

/// Load the audit chain HMAC key, creating it (0600) on first use.
///
/// SECURITY: this key authenticates the tamper-evident chain. At rest it is a 0600
/// file beside the database, so a process running as the daemon's own uid can read
/// it. At a shared uid the chain is therefore tamper-*evident* (it detects casual,
/// partial, or non-key-holder tampering) but not tamper-*proof* against an adversary
/// that also reads the key. Under the trust-domain split
/// (`[trust_domain] enforce = true`), the key is part of the daemon's custody set —
/// unreadable at the agent's uid and ownership-verified at every startup — which
/// closes that gap; see docs/deployment.md.
fn load_or_create_hmac_key(db_path: &Path) -> Result<[u8; 32], AuditError> {
    Ok(crate::keyfile::load_or_create_key_file(&hmac_key_path(
        db_path,
    ))?)
}

fn load_hmac_key(db_path: &Path) -> Result<[u8; 32], AuditError> {
    crate::keyfile::load_key_file(&hmac_key_path(db_path))?
        .ok_or_else(|| AuditError::Other("audit chain key is missing".into()))
}

/// Deterministic, order-fixed serialization of the persisted fields. `None` renders
/// empty; the field count is fixed so empties are unambiguous. Unit separators
/// (`0x1f`) prevent field-boundary ambiguity.
#[allow(clippy::too_many_arguments)]
fn canonical_record(
    event_id: &str,
    sequence_number: i64,
    ts_utc_ms: i64,
    level: &str,
    kind: &str,
    request_id: Option<&str>,
    approval_id: Option<&str>,
    client_json: Option<&str>,
    operation: Option<&str>,
    safety: Option<&str>,
    target_json: Option<&str>,
    outcome: Option<&str>,
    latency_ms: Option<i64>,
    secret_names: Option<&str>,
    policy_decision: Option<&str>,
    detail: Option<&str>,
    workspace_json: Option<&str>,
    request_hash: Option<&str>,
) -> String {
    let seq = sequence_number.to_string();
    let ts = ts_utc_ms.to_string();
    let lat = latency_ms.map(|v| v.to_string()).unwrap_or_default();
    fn f(o: Option<&str>) -> &str {
        o.unwrap_or("")
    }
    [
        event_id,
        &seq,
        &ts,
        level,
        kind,
        f(request_id),
        f(approval_id),
        f(client_json),
        f(operation),
        f(safety),
        f(target_json),
        f(outcome),
        &lat,
        f(secret_names),
        f(policy_decision),
        f(detail),
        f(workspace_json),
        f(request_hash),
    ]
    .join("\u{1f}")
}

/// Presence-versioned canon extension (Phase 1): fields added AFTER the
/// original 18 are appended to the canonical record ONLY when non-empty.
///
/// - Pre-Phase-1 rows (field absent/NULL) keep their original 18-field canon,
///   so their stored `record_hash` values keep verifying with NO backfill —
///   and therefore no window in which a re-anchor could absorb prior
///   tampering.
/// - Any tampering permutation still changes the canon and is detected:
///   setting the field on an old row appends a 19th segment; NULLing it on a
///   new row removes one; editing it changes the bytes.
/// - Unambiguous by construction: the 18th field (`request_hash`) is
///   hex-or-empty and can never contain the `0x1f` separator, so an 18-field
///   canon can never collide with a 19-field one.
fn append_optional_chained_field(canon: &mut String, value: Option<&str>) {
    if let Some(v) = value
        && !v.is_empty()
    {
        canon.push('\u{1f}');
        canon.push_str(v);
    }
}

/// `HMAC-SHA256(key, prev_hash ‖ RS ‖ canonical_record)`, hex-encoded.
fn chain_hash(key: &[u8; 32], prev_hash: &str, canon: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(prev_hash.as_bytes());
    mac.update(b"\x1e");
    mac.update(canon.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

/// Read the chained fields from a row starting at column `base` and return the
/// canonical record string. `has_approver` says whether the caller's SELECT
/// included the `approver_json` column at position `base + 18` (databases
/// created before Phase 1 don't have it).
fn canon_from_row(
    row: &rusqlite::Row,
    base: usize,
    has_approver: bool,
) -> rusqlite::Result<String> {
    let s = |i: usize| -> rusqlite::Result<Option<String>> { row.get(base + i) };
    let event_id: String = row.get(base)?;
    let sequence_number: i64 = row.get(base + 1)?;
    let ts_utc_ms: i64 = row.get(base + 2)?;
    let level: String = row.get(base + 3)?;
    let kind: String = row.get(base + 4)?;
    let request_id = s(5)?;
    let approval_id = s(6)?;
    let client_json = s(7)?;
    let operation = s(8)?;
    let safety = s(9)?;
    let target_json = s(10)?;
    let outcome = s(11)?;
    let latency_ms: Option<i64> = row.get(base + 12)?;
    let secret_names = s(13)?;
    let policy_decision = s(14)?;
    let detail = s(15)?;
    let workspace_json = s(16)?;
    let request_hash = s(17)?;
    // Column 18 (approver_json) exists only on migrated/new databases; the
    // caller's SELECT list says whether it is present.
    let approver_json = if has_approver { s(18)? } else { None };
    let mut canon = canonical_record(
        &event_id,
        sequence_number,
        ts_utc_ms,
        &level,
        &kind,
        request_id.as_deref(),
        approval_id.as_deref(),
        client_json.as_deref(),
        operation.as_deref(),
        safety.as_deref(),
        target_json.as_deref(),
        outcome.as_deref(),
        latency_ms,
        secret_names.as_deref(),
        policy_decision.as_deref(),
        detail.as_deref(),
        workspace_json.as_deref(),
        request_hash.as_deref(),
    );
    append_optional_chained_field(&mut canon, approver_json.as_deref());
    Ok(canon)
}

/// Authenticate the tail with a separate HMAC domain, committed with its rows.
/// This protects against database-only suffix/head edits. Restoring an older
/// coherent database and authentic head still requires an independent checkpoint.
fn set_chain_head(
    conn: &rusqlite::Connection,
    key: &[u8; 32],
    last_hash: &str,
    last_sequence: i64,
) -> rusqlite::Result<()> {
    let authenticator = head_signature(key, last_hash, last_sequence);
    conn.execute(
        "INSERT INTO chain_head (id, last_hash, last_sequence, format_version, authenticator) VALUES (0, ?1, ?2, 1, ?3)
         ON CONFLICT(id) DO UPDATE SET last_hash=?1, last_sequence=?2, format_version=1, authenticator=?3",
        rusqlite::params![last_hash, last_sequence, authenticator],
    )?;
    Ok(())
}

fn head_signature(key: &[u8; 32], hash: &str, sequence: i64) -> String {
    chain_hash(
        key,
        "opaque-audit-tail-head-v1",
        &format!("{sequence}\x1f{hash}"),
    )
}

/// Result of verifying the audit hash chain.
#[derive(Debug, Clone)]
pub struct ChainVerification {
    /// True if every record's stored hash matches the recomputed chain.
    pub ok: bool,
    /// Number of records verified before a break (or the total, if `ok`).
    pub records_checked: u64,
    /// Sequence number of the first record whose hash did not match.
    pub first_bad_sequence: Option<u64>,
    /// Human-readable detail when the chain is broken.
    pub detail: Option<String>,
}

/// Verify the tamper-evident hash chain over the audit log at `db_path`.
///
/// Verifies row authenticators, retention boundary and authenticated tail head.
/// Database-only edits cannot forge a new head without the separate HMAC key.
/// The broker UID/host administrator remain trusted. An older intact snapshot
/// requires independent retained high-water evidence; this is not rollback proof.
/// Legacy unauthenticated heads require an explicit independently pinned upgrade.
pub fn verify_audit_chain(db_path: &Path) -> Result<ChainVerification, AuditError> {
    let key = load_hmac_key(db_path)?;
    let mut conn =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    // A snapshot spans the boundary, records and tail checks, including when
    // a writer commits or retention removes a prefix during verification.
    let tx = conn.transaction()?;
    verify_audit_connection(&tx, &key, false)
}

fn table_exists(conn: &rusqlite::Connection, name: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 COLLATE NOCASE)",
        [name],
        |row| row.get(0),
    )
}

fn boundary_signature(
    key: &[u8; 32],
    hash: &str,
    sequence: i64,
    high_watermark: i64,
    rowid: i64,
) -> String {
    chain_hash(
        key,
        "opaque-audit-retention-boundary-v1",
        &format!("{sequence}\x1f{high_watermark}\x1f{rowid}\x1f{hash}"),
    )
}

/// The last legitimately pruned record remains the predecessor of the first
/// retained record. Its signature distinguishes retention from an arbitrary
/// deletion of the front of the log; survivor hashes never change.
fn retention_boundary(
    conn: &rusqlite::Connection,
    key: &[u8; 32],
) -> Result<Option<(String, i64)>, AuditError> {
    if !table_exists(conn, "retention_boundary")? {
        return Ok(None);
    }
    let boundary: Option<(String, i64, i64, i64, String)> = conn.query_row(
        "SELECT previous_hash, previous_sequence, sequence_high_watermark, previous_rowid, authenticator FROM retention_boundary WHERE id=0",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional()?;
    match boundary {
        Some((hash, sequence, high_watermark, rowid, signature)) => {
            if sequence < 0
                || high_watermark < sequence
                || rowid <= 0
                || signature != boundary_signature(key, &hash, sequence, high_watermark, rowid)
            {
                return Err(AuditError::Other(
                    "audit retention boundary authentication failed".into(),
                ));
            }
            Ok(Some((hash, sequence)))
        }
        None => Ok(None),
    }
}

fn verify_audit_connection(
    conn: &rusqlite::Connection,
    key: &[u8; 32],
    allow_legacy_missing_head: bool,
) -> Result<ChainVerification, AuditError> {
    let broken = |count, sequence, detail| ChainVerification {
        ok: false,
        records_checked: count,
        first_bad_sequence: sequence,
        detail: Some(detail),
    };
    // Metadata is a singleton contract, not an extensible table. Authenticate
    // exactly the row that startup/retention may use, and reject side effects on
    // these tables before any maintenance or legacy upgrade can write them.
    // The documented audit_events FTS triggers are unaffected.
    for table in ["chain_head", "retention_boundary"] {
        if !table_exists(conn, table)? {
            continue;
        }
        let mut statement = conn.prepare(&format!("SELECT id FROM {table} LIMIT 2"))?;
        let ids = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() > 1 || ids.first().is_some_and(|id| *id != 0) {
            return Ok(broken(
                0,
                None,
                format!("audit {table} metadata must contain only the singleton id=0 row"),
            ));
        }
        let has_triggers: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='trigger' AND tbl_name=?1 COLLATE NOCASE)",
            [table],
            |row| row.get(0),
        )?;
        if has_triggers {
            return Ok(broken(
                0,
                None,
                format!("audit {table} metadata does not permit triggers"),
            ));
        }
    }
    let boundary = match retention_boundary(conn, key) {
        Ok(boundary) => boundary,
        Err(AuditError::Other(detail)) => return Ok(broken(0, None, detail)),
        Err(error) => return Err(error),
    };
    let (mut prev, mut tail_sequence) = match boundary {
        Some((hash, sequence)) => (hash, Some(sequence)),
        None => (CHAIN_GENESIS.to_owned(), None),
    };
    // Presence-versioned fields keep pre-approver rows valid without re-signing.
    let has_approver = conn
        .prepare("SELECT approver_json FROM audit_events LIMIT 0")
        .is_ok();
    let sql = if has_approver {
        format!(
            "SELECT {CHAIN_COLUMNS}, approver_json, record_hash FROM audit_events ORDER BY rowid ASC"
        )
    } else {
        format!("SELECT {CHAIN_COLUMNS}, record_hash FROM audit_events ORDER BY rowid ASC")
    };
    let stored_idx = if has_approver { 19 } else { 18 };
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let canon = canon_from_row(row, 0, has_approver)?;
        let seq: i64 = row.get(1)?;
        let stored: Option<String> = row.get(stored_idx)?;
        let expected = chain_hash(key, &prev, &canon);
        match stored {
            Some(hash) if hash == expected && seq >= 0 => {
                prev = hash;
                tail_sequence = Some(seq);
                count += 1;
            }
            _ => {
                return Ok(broken(
                    count,
                    Some(seq.max(0) as u64),
                    format!(
                        "audit chain broken at record {} (sequence {seq})",
                        count + 1
                    ),
                ));
            }
        }
    }
    let authenticated = conn
        .prepare("SELECT format_version, authenticator FROM chain_head LIMIT 0")
        .is_ok();
    if !authenticated && !allow_legacy_missing_head {
        return Ok(broken(
            count,
            tail_sequence.map(|n| n as u64),
            "legacy audit head requires independently pinned offline upgrade".into(),
        ));
    }
    let head: Option<(String, i64)> = if table_exists(conn, "chain_head")? {
        conn.query_row(
            "SELECT last_hash,last_sequence FROM chain_head WHERE id=0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
    } else {
        None
    };
    if authenticated {
        let authentication: Option<(i64, String)> = conn
            .query_row(
                "SELECT format_version,authenticator FROM chain_head WHERE id=0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if !matches!((&head,&authentication), (Some((hash,sequence)),Some((1,signature))) if signature == &head_signature(key,hash,*sequence))
        {
            return Ok(broken(
                count,
                tail_sequence.map(|n| n as u64),
                "audit tail head authentication failed".into(),
            ));
        }
    }
    match head {
        Some((hash, sequence)) if hash == prev && sequence == tail_sequence.unwrap_or(-1) => {}
        None if allow_legacy_missing_head => {}
        _ => {
            return Ok(broken(
                count,
                tail_sequence.map(|n| n as u64),
                "audit log truncated or tail anchor altered".into(),
            ));
        }
    }
    Ok(ChainVerification {
        ok: true,
        records_checked: count,
        first_bad_sequence: None,
        detail: None,
    })
}

fn require_valid_chain(
    conn: &rusqlite::Connection,
    key: &[u8; 32],
    allow_legacy_missing_head: bool,
) -> Result<(), AuditError> {
    let verification = verify_audit_connection(conn, key, allow_legacy_missing_head)?;
    if !verification.ok {
        return Err(AuditError::Other(
            verification
                .detail
                .unwrap_or_else(|| "audit chain integrity failure".into()),
        ));
    }
    Ok(())
}

const SCHEMA_SQL: &str = "\
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    sequence_number INTEGER NOT NULL,
    ts_utc_ms INTEGER NOT NULL,
    level TEXT NOT NULL,
    kind TEXT NOT NULL,
    request_id TEXT,
    approval_id TEXT,
    client_json TEXT,
    operation TEXT,
    safety TEXT,
    target_json TEXT,
    outcome TEXT,
    latency_ms INTEGER,
    secret_names TEXT,
    policy_decision TEXT,
    detail TEXT,
    workspace_json TEXT,
    request_hash TEXT,
    approver_json TEXT,
    record_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_ts ON audit_events(ts_utc_ms);
CREATE INDEX IF NOT EXISTS idx_sequence ON audit_events(sequence_number);
CREATE INDEX IF NOT EXISTS idx_kind ON audit_events(kind);
CREATE INDEX IF NOT EXISTS idx_operation ON audit_events(operation);
CREATE INDEX IF NOT EXISTS idx_request_id ON audit_events(request_id);
CREATE VIRTUAL TABLE IF NOT EXISTS audit_events_fts USING fts5(search_text);
CREATE TRIGGER IF NOT EXISTS audit_events_ai AFTER INSERT ON audit_events BEGIN
    INSERT INTO audit_events_fts(rowid, search_text)
    VALUES(
        new.rowid,
        trim(
            coalesce(new.kind, '') || ' ' ||
            coalesce(new.operation, '') || ' ' ||
            coalesce(new.outcome, '') || ' ' ||
            coalesce(new.detail, '') || ' ' ||
            coalesce(new.target_json, '') || ' ' ||
            coalesce(new.secret_names, '') || ' ' ||
            coalesce(new.request_id, '')
        )
    );
END;
CREATE TRIGGER IF NOT EXISTS audit_events_ad AFTER DELETE ON audit_events BEGIN
    DELETE FROM audit_events_fts WHERE rowid = old.rowid;
END;
CREATE TABLE IF NOT EXISTS retention_boundary (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    previous_hash TEXT NOT NULL,
    previous_sequence INTEGER NOT NULL,
    sequence_high_watermark INTEGER NOT NULL,
    previous_rowid INTEGER NOT NULL,
    authenticator TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chain_head (
    id INTEGER PRIMARY KEY CHECK (id = 0),
    last_hash TEXT NOT NULL,
    last_sequence INTEGER NOT NULL,
    format_version INTEGER NOT NULL CHECK(format_version=1),
    authenticator TEXT NOT NULL
);
";

#[cfg(test)]
const RETENTION_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(not(test))]
const RETENTION_CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

/// A persistent audit sink backed by SQLite.
///
/// Events are sent through a bounded channel and written by a dedicated
/// background thread to avoid blocking the enclave pipeline.
struct WriterState {
    sender: Option<std::sync::mpsc::SyncSender<AuditEvent>>,
    next_sequence: u64,
    accepted: u64,
    settled: u64,
    failure: Option<AuditFlushError>,
    stopped: bool,
}

type WriterProgress = std::sync::Arc<(std::sync::Mutex<WriterState>, std::sync::Condvar)>;

pub struct SqliteAuditSink {
    progress: WriterProgress,
    /// Drops not yet represented by a successfully queued synthetic event.
    dropped_count: std::sync::Arc<AtomicU64>,
    shutdown_lock: std::sync::Mutex<()>,
    writer_handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    drop_monitor_handle: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    writer_pause: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    monitor_stop: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    sanitizer: crate::sanitize::Sanitizer,
}

impl fmt::Debug for SqliteAuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.progress.0.lock().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("SqliteAuditSink")
            .field("next_sequence", &state.next_sequence)
            .field("failure", &state.failure)
            .field("dropped_count", &self.dropped_count.load(Ordering::Relaxed))
            .finish()
    }
}

/// Serialize queue publication and sequence allocation. The writer and flush
/// observe the same accepted-event count; synthetic events use this path too.
fn enqueue_event(progress: &WriterProgress, mut event: AuditEvent) -> Result<(), AuditFlushError> {
    let (lock, cvar) = &**progress;
    let mut state = lock.lock().unwrap_or_else(|p| p.into_inner());
    event.sequence_number = state.next_sequence;
    let result = match &state.sender {
        Some(sender) => sender.try_send(event).map_err(|error| match error {
            std::sync::mpsc::TrySendError::Full(_) => AuditFlushError::Backpressure,
            std::sync::mpsc::TrySendError::Disconnected(_) => AuditFlushError::Closed,
        }),
        None => Err(AuditFlushError::Closed),
    };
    match &result {
        Ok(()) => {
            state.accepted += 1;
            state.next_sequence += 1;
        }
        Err(error) => {
            state.failure.get_or_insert_with(|| error.clone());
        }
    }
    cvar.notify_all();
    result
}

impl SqliteAuditSink {
    /// Open (or create) the audit database at `db_path`.
    ///
    /// Verifies existing evidence before any maintenance, migrates historical
    /// schemas atomically, and prunes the expired insertion-order prefix.
    /// A corrupt established chain prevents the sink from opening.
    pub fn new(db_path: PathBuf, retention_days: u64) -> Result<Self, AuditError> {
        Self::new_with_capacity(db_path, retention_days, 4096)
    }

    /// Open (or create) the audit database with a custom channel capacity.
    ///
    /// The `capacity` parameter controls the bounded channel size. In production
    /// use [`Self::new`] which defaults to 4096.
    pub(crate) fn new_with_capacity(
        db_path: PathBuf,
        retention_days: u64,
        capacity: usize,
    ) -> Result<Self, AuditError> {
        // Ensure parent directory exists, owner-only. `create_dir_all` uses
        // the process umask (0755 typically); the audit database's directory
        // is custody material, and on a fresh state dir the daemon's custody
        // pass has already run by the time we get here.
        if let Some(parent) = db_path.parent() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                if !parent.exists() {
                    std::fs::DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(parent)?;
                }
            }
            #[cfg(not(unix))]
            std::fs::create_dir_all(parent)?;
        }

        let mut conn = rusqlite::Connection::open(&db_path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o600))?;
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;

        // Schema migration, verification and pruning share a writer transaction.
        // Never delete or re-sign evidence before checking the existing chain.
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let had_events = table_exists(&tx, "audit_events")?;
        let had_head = table_exists(&tx, "chain_head")?;
        let had_fts = table_exists(&tx, "audit_events_fts")?;
        if had_events
            && tx
                .prepare("SELECT record_hash FROM audit_events LIMIT 0")
                .is_err()
        {
            return Err(AuditError::Other("unchained legacy audit cannot be authenticated automatically; preserve it separately and enroll a new stream".into()));
        }
        if (had_events || had_head)
            && tx
                .prepare("SELECT format_version,authenticator FROM chain_head LIMIT 0")
                .is_err()
        {
            return Err(AuditError::Other(
                "legacy audit head requires independently pinned offline upgrade".into(),
            ));
        }
        let hmac_key = if had_events || had_head {
            load_hmac_key(&db_path)?
        } else {
            load_or_create_hmac_key(&db_path)?
        };
        tx.execute_batch(SCHEMA_SQL)?;
        if tx
            .prepare("SELECT approver_json FROM audit_events LIMIT 0")
            .is_err()
        {
            tx.execute("ALTER TABLE audit_events ADD COLUMN approver_json TEXT", [])?;
        }
        if !had_events && !had_head {
            set_chain_head(&tx, &hmac_key, CHAIN_GENESIS, -1)?;
        }
        require_valid_chain(&tx, &hmac_key, false)?;
        Self::prune_verified_prefix(&tx, retention_days, &hmac_key)?;
        // Populate FTS only when introducing the index, not on every restart.
        if !had_fts {
            tx.execute(
                "INSERT OR IGNORE INTO audit_events_fts(rowid, search_text)
                 SELECT rowid, trim(coalesce(kind, '') || ' ' || coalesce(operation, '') || ' ' ||
                    coalesce(outcome, '') || ' ' || coalesce(detail, '') || ' ' ||
                    coalesce(target_json, '') || ' ' || coalesce(secret_names, '') || ' ' ||
                    coalesce(request_id, '')) FROM audit_events",
                [],
            )?;
        }
        let next_sequence: u64 = tx.query_row(
            "SELECT COALESCE(MAX(sequence_number), -1) + 1 FROM (
                SELECT sequence_number FROM audit_events UNION ALL SELECT last_sequence FROM chain_head WHERE id=0
                UNION ALL SELECT sequence_high_watermark FROM retention_boundary WHERE id=0
             )", [], |row| row.get(0),
        )?;
        let last_hash = tx
            .query_row("SELECT last_hash FROM chain_head WHERE id=0", [], |row| {
                row.get(0)
            })
            .optional()?
            .unwrap_or_else(|| CHAIN_GENESIS.to_owned());
        tx.commit()?;

        let (sender, receiver) = std::sync::mpsc::sync_channel::<AuditEvent>(capacity);
        let progress = std::sync::Arc::new((
            std::sync::Mutex::new(WriterState {
                sender: Some(sender),
                next_sequence,
                accepted: 0,
                settled: 0,
                failure: None,
                stopped: false,
            }),
            std::sync::Condvar::new(),
        ));
        let writer_pause =
            std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let writer_pause_clone = writer_pause.clone();
        let writer_progress = progress.clone();
        let writer_handle = std::thread::Builder::new()
            .name("audit-writer".into())
            .spawn(move || {
                Self::writer_loop(
                    conn,
                    receiver,
                    &writer_pause_clone,
                    retention_days,
                    hmac_key,
                    last_hash,
                    &writer_progress,
                );
            })
            .map_err(|error| {
                AuditError::Other(format!("failed to spawn writer thread: {error}"))
            })?;
        let dropped_count = std::sync::Arc::new(AtomicU64::new(0));
        let monitor_stop =
            std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        // Construct the owner before starting another thread. If the monitor
        // cannot start, Drop closes the queue and joins the existing writer.
        let sink = Self {
            progress,
            dropped_count,
            shutdown_lock: std::sync::Mutex::new(()),
            writer_handle: std::sync::Mutex::new(Some(writer_handle)),
            drop_monitor_handle: std::sync::Mutex::new(None),
            writer_pause,
            monitor_stop,
            sanitizer: crate::sanitize::Sanitizer::new(),
        };
        let monitor_progress = sink.progress.clone();
        let monitor_dropped = sink.dropped_count.clone();
        let monitor_stop = sink.monitor_stop.clone();
        let handle = std::thread::Builder::new()
            .name("audit-drop-monitor".into())
            .spawn(move || {
                Self::drop_monitor_loop(monitor_progress, monitor_dropped, monitor_stop);
            })
            .map_err(|error| {
                AuditError::Other(format!("failed to spawn drop monitor thread: {error}"))
            })?;
        *sink
            .drop_monitor_handle
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(handle);
        Ok(sink)
    }

    /// Returns the number of audit events dropped due to channel backpressure.
    ///
    /// This value is suitable for health checks and monitoring (e.g. `opaque doctor`).
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Pause the writer thread (for testing only). Events sent while paused
    /// will accumulate in the channel and eventually be dropped.
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn pause_writer(&self) {
        let (lock, _cvar) = &*self.writer_pause;
        let mut paused = lock.lock().expect("pause lock poisoned");
        *paused = true;
    }

    /// Resume the writer thread (for testing only).
    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn resume_writer(&self) {
        let (lock, cvar) = &*self.writer_pause;
        let mut paused = lock.lock().expect("pause lock poisoned");
        *paused = false;
        cvar.notify_all();
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub(crate) fn flush_dropped_events(&self) {
        Self::report_drops(&self.progress, &self.dropped_count);
    }

    fn report_drops(progress: &WriterProgress, dropped_count: &AtomicU64) {
        let count = dropped_count.swap(0, Ordering::SeqCst);
        if count == 0 {
            return;
        }
        let event = AuditEvent::new(AuditEventKind::AuditDropped)
            .with_detail(format!(
                "{count} audit events dropped due to channel backpressure"
            ))
            .with_level(AuditLevel::Warn);
        if enqueue_event(progress, event).is_err() {
            // An unqueued report must not erase knowledge of the loss.
            dropped_count.fetch_add(count, Ordering::SeqCst);
        }
    }

    fn drop_monitor_loop(
        progress: WriterProgress,
        dropped_count: std::sync::Arc<AtomicU64>,
        stop: std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    ) {
        let (lock, cvar) = &*stop;
        loop {
            let guard = lock.lock().unwrap_or_else(|p| p.into_inner());
            // Check the predicate before sleeping: close may precede thread start.
            let (guard, _) = cvar
                .wait_timeout_while(guard, std::time::Duration::from_secs(60), |stopped| {
                    !*stopped
                })
                .unwrap_or_else(|p| p.into_inner());
            if *guard {
                return;
            }
            drop(guard);
            Self::report_drops(&progress, &dropped_count);
        }
    }

    fn writer_loop(
        mut conn: rusqlite::Connection,
        receiver: std::sync::mpsc::Receiver<AuditEvent>,
        pause: &std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        retention_days: u64,
        key: [u8; 32],
        mut last_hash: String,
        progress: &WriterProgress,
    ) {
        let mut batch = Vec::with_capacity(256);
        let mut next_retention_cleanup = std::time::Instant::now() + RETENTION_CLEANUP_INTERVAL;
        loop {
            let wait = next_retention_cleanup.saturating_duration_since(std::time::Instant::now());
            match receiver.recv_timeout(wait) {
                Ok(event) => {
                    let (lock, cvar) = &**pause;
                    let paused = lock.lock().unwrap_or_else(|p| p.into_inner());
                    drop(
                        cvar.wait_while(paused, |paused| *paused)
                            .unwrap_or_else(|p| p.into_inner()),
                    );
                    batch.push(event);
                    while batch.len() < 256 {
                        match receiver.try_recv() {
                            Ok(event) => batch.push(event),
                            Err(_) => break,
                        }
                    }
                    let result = Self::insert_batch(&conn, &batch, &key, &mut last_hash);
                    let (lock, cvar) = &**progress;
                    let mut state = lock.lock().unwrap_or_else(|p| p.into_inner());
                    if let Err(error) = result {
                        tracing::error!("audit writer insert failed: {error}");
                        state
                            .failure
                            .get_or_insert_with(|| AuditFlushError::Storage(error.to_string()));
                    }
                    // Settled is not committed: a failed batch is recorded in
                    // failure and every later flush must report that loss.
                    state.settled += batch.len() as u64;
                    cvar.notify_all();
                    batch.clear();
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if std::time::Instant::now() >= next_retention_cleanup {
                if let Err(error) = Self::run_retention_cleanup(&mut conn, retention_days, &key) {
                    tracing::error!("audit retention maintenance failed: {error}");
                    let (lock, cvar) = &**progress;
                    lock.lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .failure
                        .get_or_insert_with(|| AuditFlushError::Storage(error.to_string()));
                    cvar.notify_all();
                }
                next_retention_cleanup = std::time::Instant::now() + RETENTION_CLEANUP_INTERVAL;
            }
        }
        let (lock, cvar) = &**progress;
        lock.lock().unwrap_or_else(|p| p.into_inner()).stopped = true;
        cvar.notify_all();
    }

    fn retention_cutoff_ms(retention_days: u64) -> i64 {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let retention_ms = u128::from(retention_days) * 86_400_000;
        now.saturating_sub(retention_ms).min(i64::MAX as u128) as i64
    }

    fn run_retention_cleanup(
        conn: &mut rusqlite::Connection,
        retention_days: u64,
        key: &[u8; 32],
    ) -> Result<usize, AuditError> {
        if retention_days == 0 {
            return Ok(0);
        }
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        require_valid_chain(&tx, key, false)?;
        let deleted = Self::prune_verified_prefix(&tx, retention_days, key)?;
        tx.commit()?;
        Ok(deleted)
    }

    /// Prune only the expired insertion-order prefix. Clock regressions can
    /// leave an older timestamp after a live record; preserving that row until
    /// the prefix expires is preferable to rewriting authenticated history.
    fn prune_verified_prefix(
        conn: &rusqlite::Transaction<'_>,
        retention_days: u64,
        key: &[u8; 32],
    ) -> Result<usize, AuditError> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = Self::retention_cutoff_ms(retention_days);
        let mut last_expired = None;
        // Historical writers allocated sequences before enqueueing, allowing
        // insertion order to differ from sequence order. Preserve every pruned
        // prefix's maximum so a restart cannot reuse one of those numbers.
        let mut high_watermark: i64 = conn
            .query_row(
                "SELECT sequence_high_watermark FROM retention_boundary WHERE id=0",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(-1);
        {
            let mut statement = conn.prepare("SELECT rowid, ts_utc_ms, record_hash, sequence_number FROM audit_events ORDER BY rowid")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                if row.get::<_, i64>(1)? >= cutoff {
                    break;
                }
                high_watermark = high_watermark.max(row.get::<_, i64>(3)?);
                last_expired = Some((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ));
            }
        }
        let Some((rowid, hash, sequence)) = last_expired else {
            return Ok(0);
        };
        conn.execute(
            "INSERT INTO retention_boundary(id, previous_hash, previous_sequence, sequence_high_watermark, previous_rowid, authenticator) VALUES(0, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET previous_hash=excluded.previous_hash,
             previous_sequence=excluded.previous_sequence, sequence_high_watermark=excluded.sequence_high_watermark,
             previous_rowid=excluded.previous_rowid, authenticator=excluded.authenticator",
            rusqlite::params![hash, sequence, high_watermark, rowid, boundary_signature(key, &hash, sequence, high_watermark, rowid)],
        )?;
        Ok(conn.execute("DELETE FROM audit_events WHERE rowid <= ?1", [rowid])?)
    }

    /// Insert a batch of events within a single transaction.
    fn insert_batch(
        conn: &rusqlite::Connection,
        events: &[AuditEvent],
        key: &[u8; 32],
        last_hash: &mut String,
    ) -> Result<(), rusqlite::Error> {
        // Reserve the writer before reading the rowid snapshot. A deferred
        // read-to-write upgrade can return SQLITE_BUSY without consulting the
        // busy handler, losing an accepted batch during transient contention.
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        let mut candidate_hash = last_hash.clone();
        // Export transports persist rowid cursors. SQLite reuses rowid 1 when
        // a table becomes empty, so allocate beyond the authenticated pruned
        // prefix as well as the surviving tail. Both queries are indexed.
        let existing_rowid: i64 = tx.query_row(
            "SELECT COALESCE(MAX(rowid), 0) FROM audit_events",
            [],
            |row| row.get(0),
        )?;
        let pruned_rowid: i64 = tx
            .query_row(
                "SELECT previous_rowid FROM retention_boundary WHERE id=0",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let mut next_rowid = existing_rowid.max(pruned_rowid);
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO audit_events (
                    event_id, sequence_number, ts_utc_ms, level, kind,
                    request_id, approval_id, client_json, operation, safety,
                    target_json, outcome, latency_ms, secret_names,
                    policy_decision, detail, workspace_json, request_hash,
                    approver_json, record_hash, rowid
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
            )?;

            let mut last_seq: Option<i64> = None;
            for event in events {
                let client_json = event
                    .client
                    .as_ref()
                    .and_then(|c| serde_json::to_string(c).ok());
                let target_json = event
                    .target
                    .as_ref()
                    .and_then(|t| serde_json::to_string(t).ok());
                let safety_str = event.safety.as_ref().map(|s| format!("{s:?}"));
                let secret_names_str = if event.secret_names.is_empty() {
                    None
                } else {
                    Some(event.secret_names.join(","))
                };
                let workspace_json = event
                    .workspace
                    .as_ref()
                    .and_then(|w| serde_json::to_string(w).ok());
                let approver_json = event
                    .approver
                    .as_ref()
                    .and_then(|a| serde_json::to_string(a).ok());

                // Chain this record to the current head over its canonical form.
                let event_id = event.event_id.to_string();
                let level = event.level.to_string();
                let kind = event.kind.to_string();
                let request_id = event.request_id.map(|u| u.to_string());
                let approval_id = event.approval_id.map(|u| u.to_string());
                let mut canon = canonical_record(
                    &event_id,
                    event.sequence_number as i64,
                    event.ts_utc_ms,
                    &level,
                    &kind,
                    request_id.as_deref(),
                    approval_id.as_deref(),
                    client_json.as_deref(),
                    event.operation.as_deref(),
                    safety_str.as_deref(),
                    target_json.as_deref(),
                    event.outcome.as_deref(),
                    event.latency_ms,
                    secret_names_str.as_deref(),
                    event.policy_decision.as_deref(),
                    event.detail.as_deref(),
                    workspace_json.as_deref(),
                    event.request_hash.as_deref(),
                );
                append_optional_chained_field(&mut canon, approver_json.as_deref());
                let record_hash = chain_hash(key, &candidate_hash, &canon);
                next_rowid = next_rowid.checked_add(1).ok_or_else(|| {
                    rusqlite::Error::InvalidParameterName("audit rowid exhausted".into())
                })?;

                let changed = stmt.execute(rusqlite::params![
                    event_id,
                    event.sequence_number,
                    event.ts_utc_ms,
                    level,
                    kind,
                    request_id,
                    approval_id,
                    client_json,
                    event.operation,
                    safety_str,
                    target_json,
                    event.outcome,
                    event.latency_ms,
                    secret_names_str,
                    event.policy_decision,
                    event.detail,
                    workspace_json,
                    event.request_hash,
                    approver_json,
                    record_hash,
                    next_rowid,
                ])?;
                // Every accepted event needs its own persisted row. Reused IDs
                // fail explicitly, including retries: no distinct payload may
                // be mistaken for an already durable event.
                if changed != 1 {
                    return Err(rusqlite::Error::InvalidParameterName(
                        "audit event was not inserted".into(),
                    ));
                }
                candidate_hash = record_hash;
                last_seq = Some(event.sequence_number as i64);
            }
            // Record the tail anchor in the same transaction so verification can
            // detect truncation of the newest records.
            if let Some(seq) = last_seq {
                set_chain_head(&tx, key, &candidate_hash, seq)?;
            }
        }
        tx.commit()?;
        *last_hash = candidate_hash;
        Ok(())
    }

    /// Stop accepting events, drain the queue, and join both owned threads.
    /// Repeated or concurrent calls are safe. Persistence failures remain
    /// visible after close, including failures that happened before shutdown.
    pub fn close(&self) -> Result<(), AuditFlushError> {
        let _shutdown = self.shutdown_lock.lock().unwrap_or_else(|p| p.into_inner());
        {
            let (lock, cvar) = &*self.monitor_stop;
            *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
            cvar.notify_all();
        }
        if let Some(handle) = self
            .drop_monitor_handle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            && handle.join().is_err()
        {
            self.record_thread_failure("audit drop monitor panicked");
        }
        // The shared state owns the only sender; taking it disconnects the
        // channel even while emit/flush callers retain references to the sink.
        self.progress
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .sender
            .take();
        {
            let (lock, cvar) = &*self.writer_pause;
            *lock.lock().unwrap_or_else(|p| p.into_inner()) = false;
            cvar.notify_all();
        }
        if let Some(handle) = self
            .writer_handle
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            && handle.join().is_err()
        {
            self.record_thread_failure("audit writer panicked");
        }
        self.flush(std::time::Duration::ZERO)
    }

    fn record_thread_failure(&self, message: &str) {
        let (lock, cvar) = &*self.progress;
        lock.lock()
            .unwrap_or_else(|p| p.into_inner())
            .failure
            .get_or_insert_with(|| AuditFlushError::Storage(message.into()));
        cvar.notify_all();
    }
}

impl AuditSink for SqliteAuditSink {
    fn emit(&self, mut event: AuditEvent) {
        if let Some(ref detail) = event.detail {
            event.detail = Some(
                self.sanitizer
                    .redact_audit_text(detail, crate::sanitize::RedactionLevel::Human),
            );
        }
        if let Err(error) = enqueue_event(&self.progress, event) {
            if error == AuditFlushError::Backpressure {
                self.dropped_count.fetch_add(1, Ordering::Relaxed);
            }
            tracing::warn!(%error, "audit event was not accepted");
        }
    }

    fn flush(&self, timeout: std::time::Duration) -> Result<(), AuditFlushError> {
        let started = std::time::Instant::now();
        let (lock, cvar) = &*self.progress;
        let mut state = lock.lock().unwrap_or_else(|p| p.into_inner());
        let target = state.accepted;
        loop {
            if state.settled >= target {
                return state.failure.clone().map_or(Ok(()), Err);
            }
            if state.stopped {
                return Err(state.failure.clone().unwrap_or(AuditFlushError::Closed));
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(AuditFlushError::Timeout);
            }
            let (guard, _) = cvar
                .wait_timeout(state, remaining)
                .unwrap_or_else(|p| p.into_inner());
            state = guard;
        }
    }
}

impl Drop for SqliteAuditSink {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            tracing::error!(%error, "audit sink closed without complete durability");
        }
    }
}

// ---------------------------------------------------------------------------
// Audit filter & query
// ---------------------------------------------------------------------------

/// Filter criteria for querying audit events from the SQLite database.
pub struct AuditFilter {
    /// Filter by event kind.
    pub kind: Option<AuditEventKind>,
    /// Filter by operation name.
    pub operation: Option<String>,
    /// Only events after this timestamp (ms since epoch).
    pub since_ms: Option<i64>,
    /// Maximum number of events to return.
    pub limit: usize,
    /// Filter by request correlation ID.
    pub request_id: Option<Uuid>,
    /// Filter by outcome value (e.g. "allowed", "denied", "error").
    pub outcome: Option<String>,
    /// Full-text search over sanitized event text (kind/operation/outcome/detail/targets).
    pub text_query: Option<String>,
}

impl Default for AuditFilter {
    fn default() -> Self {
        Self {
            kind: None,
            operation: None,
            since_ms: None,
            limit: 50,
            request_id: None,
            outcome: None,
            text_query: None,
        }
    }
}

/// Query audit events from a SQLite database file.
///
/// Opens the database read-only and returns matching events ordered by
/// timestamp descending (most recent first).
pub fn query_audit_db(db_path: &Path, filter: &AuditFilter) -> Result<Vec<AuditEvent>, AuditError> {
    let conn = rusqlite::Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    let mut sql = String::from("SELECT audit_events.* FROM audit_events");
    if filter.text_query.is_some() {
        sql.push_str(" JOIN audit_events_fts ON audit_events_fts.rowid = audit_events.rowid");
    }
    sql.push_str(" WHERE 1=1");
    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(ref kind) = filter.kind {
        sql.push_str(" AND kind = ?");
        param_values.push(Box::new(kind.to_string()));
    }
    if let Some(ref op) = filter.operation {
        sql.push_str(" AND operation = ?");
        param_values.push(Box::new(op.clone()));
    }
    if let Some(since) = filter.since_ms {
        sql.push_str(" AND ts_utc_ms >= ?");
        param_values.push(Box::new(since));
    }
    if let Some(ref rid) = filter.request_id {
        sql.push_str(" AND request_id = ?");
        param_values.push(Box::new(rid.to_string()));
    }
    if let Some(ref outcome) = filter.outcome {
        sql.push_str(" AND outcome = ?");
        param_values.push(Box::new(outcome.clone()));
    }
    if let Some(ref text_query) = filter.text_query {
        sql.push_str(" AND audit_events_fts MATCH ?");
        param_values.push(Box::new(text_query.clone()));
    }

    sql.push_str(" ORDER BY audit_events.ts_utc_ms DESC LIMIT ?");
    param_values.push(Box::new(filter.limit as i64));

    let params: Vec<&dyn rusqlite::types::ToSql> =
        param_values.iter().map(|b| b.as_ref()).collect();

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params.as_slice(), row_to_audit_event)?;

    let mut events = Vec::new();
    for row in rows {
        events.push(row?);
    }
    Ok(events)
}

/// Reconstruct an `AuditEvent` from a database row.
fn row_to_audit_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEvent> {
    let event_id_str: String = row.get("event_id")?;
    let event_id = Uuid::parse_str(&event_id_str).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })?;

    let sequence_number: u64 = row.get("sequence_number")?;
    let ts_utc_ms: i64 = row.get("ts_utc_ms")?;

    let level_str: String = row.get("level")?;
    let level = match level_str.as_str() {
        "info" => AuditLevel::Info,
        "warn" => AuditLevel::Warn,
        "error" => AuditLevel::Error,
        _ => AuditLevel::Info,
    };

    let kind_str: String = row.get("kind")?;
    let kind: AuditEventKind = kind_str.parse().map_err(|e: String| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(AuditError::Other(e)),
        )
    })?;

    let request_id: Option<String> = row.get("request_id")?;
    let request_id = request_id.and_then(|s| Uuid::parse_str(&s).ok());

    let approval_id: Option<String> = row.get("approval_id")?;
    let approval_id = approval_id.and_then(|s| Uuid::parse_str(&s).ok());

    let client_json: Option<String> = row.get("client_json")?;
    let client: Option<ClientSummary> = client_json.and_then(|s| serde_json::from_str(&s).ok());

    let operation: Option<String> = row.get("operation")?;

    let safety_str: Option<String> = row.get("safety")?;
    let safety = safety_str.and_then(|s| match s.as_str() {
        "Safe" => Some(OperationSafety::Safe),
        "SensitiveOutput" => Some(OperationSafety::SensitiveOutput),
        "Reveal" => Some(OperationSafety::Reveal),
        _ => None,
    });

    let target_json: Option<String> = row.get("target_json")?;
    let target: Option<TargetSummary> = target_json.and_then(|s| serde_json::from_str(&s).ok());

    let outcome: Option<String> = row.get("outcome")?;
    let latency_ms: Option<i64> = row.get("latency_ms")?;

    let secret_names_str: Option<String> = row.get("secret_names")?;
    let secret_names = secret_names_str
        .map(|s| s.split(',').map(|part| part.to_owned()).collect())
        .unwrap_or_default();

    let policy_decision: Option<String> = row.get("policy_decision")?;
    let detail: Option<String> = row.get("detail")?;

    let workspace_json: Option<String> = row.get("workspace_json")?;
    let workspace: Option<WorkspaceSummary> =
        workspace_json.and_then(|s| serde_json::from_str(&s).ok());

    let request_hash: Option<String> = row.get("request_hash")?;

    // Absent on databases created before Phase 1 — treat missing column as None.
    let approver: Option<ApproverIdentity> = row
        .get::<_, Option<String>>("approver_json")
        .unwrap_or(None)
        .and_then(|s| serde_json::from_str(&s).ok());

    Ok(AuditEvent {
        event_id,
        sequence_number,
        ts_utc_ms,
        level,
        kind,
        request_id,
        approval_id,
        client,
        operation,
        safety,
        target,
        outcome,
        latency_ms,
        secret_names,
        policy_decision,
        detail,
        workspace,
        request_hash,
        approver,
    })
}

// ---------------------------------------------------------------------------
// Multi-sink fan-out
// ---------------------------------------------------------------------------

/// Fans out audit events to multiple sinks.
pub struct MultiAuditSink {
    sinks: Vec<std::sync::Arc<dyn AuditSink>>,
}

impl MultiAuditSink {
    /// Create a new multi-sink that dispatches to all provided sinks.
    pub fn new(sinks: Vec<std::sync::Arc<dyn AuditSink>>) -> Self {
        Self { sinks }
    }
}

impl fmt::Debug for MultiAuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiAuditSink")
            .field("sink_count", &self.sinks.len())
            .finish()
    }
}

impl AuditSink for MultiAuditSink {
    fn emit(&self, event: AuditEvent) {
        for sink in &self.sinks {
            sink.emit(event.clone());
        }
    }

    fn flush(&self, timeout: std::time::Duration) -> Result<(), AuditFlushError> {
        let started = std::time::Instant::now();
        let mut failure = None;
        for sink in &self.sinks {
            if let Err(error) = sink.flush(timeout.saturating_sub(started.elapsed())) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::operation::{ApprovalRequirement, ClientIdentity, ClientType, OperationSafety};

    #[test]
    fn audit_event_builder() {
        let event = AuditEvent::new(AuditEventKind::RequestReceived)
            .with_request_id(Uuid::new_v4())
            .with_operation("github.set_actions_secret")
            .with_outcome("ok")
            .with_latency_ms(42);

        assert_eq!(event.kind, AuditEventKind::RequestReceived);
        assert_eq!(
            event.operation.as_deref(),
            Some("github.set_actions_secret")
        );
        assert_eq!(event.outcome.as_deref(), Some("ok"));
        assert_eq!(event.latency_ms, Some(42));
        assert_eq!(event.level, AuditLevel::Info);
    }

    #[test]
    fn audit_event_kind_display() {
        assert_eq!(
            format!("{}", AuditEventKind::RequestReceived),
            "request.received"
        );
        assert_eq!(
            format!("{}", AuditEventKind::ApprovalGranted),
            "approval.granted"
        );
        assert_eq!(
            format!("{}", AuditEventKind::OperationFailed),
            "operation.failed"
        );
    }

    #[test]
    fn default_levels() {
        assert_eq!(
            default_level_for_kind(AuditEventKind::PolicyDenied),
            AuditLevel::Warn
        );
        assert_eq!(
            default_level_for_kind(AuditEventKind::OperationFailed),
            AuditLevel::Error
        );
        assert_eq!(
            default_level_for_kind(AuditEventKind::OperationSucceeded),
            AuditLevel::Info
        );
        assert_eq!(
            default_level_for_kind(AuditEventKind::LeaseHit),
            AuditLevel::Info
        );
    }

    #[test]
    fn in_memory_emitter() {
        let emitter = InMemoryAuditEmitter::new();
        assert!(emitter.is_empty());

        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        emitter.emit(AuditEvent::new(AuditEventKind::PolicyDenied));
        emitter.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));

        assert_eq!(emitter.len(), 3);
        assert_eq!(
            emitter.events_of_kind(AuditEventKind::PolicyDenied).len(),
            1
        );

        emitter.clear();
        assert!(emitter.is_empty());
    }

    #[test]
    fn client_summary_from_identity() {
        let id = ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/test".into()),
            exe_sha256: Some(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
            ),
            codesign_team_id: Some("TEAM123".into()),
            workload: None,
        };
        let summary = ClientSummary::from((&id, ClientType::Agent));
        assert_eq!(summary.uid, 501);
        assert_eq!(
            summary.exe_sha256_prefix.as_deref(),
            Some("abcdef0123456789")
        );
        assert_eq!(summary.codesign_team_id.as_deref(), Some("TEAM123"));
    }

    #[test]
    fn audit_event_debug_is_safe() {
        let event = AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_detail("some detail with password=hunter2");
        let dbg = format!("{event:?}");
        // Debug impl only shows selected fields, not detail.
        assert!(!dbg.contains("hunter2"));
    }

    #[test]
    fn all_event_kind_display() {
        let kinds = vec![
            (AuditEventKind::RequestReceived, "request.received"),
            (AuditEventKind::PolicyDenied, "policy.denied"),
            (AuditEventKind::ApprovalRequired, "approval.required"),
            (AuditEventKind::ApprovalPresented, "approval.presented"),
            (AuditEventKind::ApprovalGranted, "approval.granted"),
            (AuditEventKind::ApprovalDenied, "approval.denied"),
            (AuditEventKind::OperationStarted, "operation.started"),
            (AuditEventKind::OperationSucceeded, "operation.succeeded"),
            (AuditEventKind::OperationFailed, "operation.failed"),
            (
                AuditEventKind::ProviderFetchStarted,
                "provider.fetch.started",
            ),
            (
                AuditEventKind::ProviderFetchFinished,
                "provider.fetch.finished",
            ),
            (AuditEventKind::RateLimited, "rate.limited"),
            (AuditEventKind::LeaseHit, "lease.hit"),
            (AuditEventKind::SandboxCreated, "sandbox.created"),
            (AuditEventKind::SandboxCompleted, "sandbox.completed"),
            (AuditEventKind::SecretResolved, "secret.resolved"),
            (AuditEventKind::AuditDropped, "audit.dropped"),
            (AuditEventKind::ExecveChecked, "execve.checked"),
            (AuditEventKind::ExecveAllowed, "execve.allowed"),
            (AuditEventKind::ExecveDenied, "execve.denied"),
            (AuditEventKind::ExecvePrompted, "execve.prompted"),
            (AuditEventKind::WorkloadAttested, "workload.attested"),
            (
                AuditEventKind::WorkloadAttestationDenied,
                "workload.attestation_denied",
            ),
        ];
        for (kind, expected) in kinds {
            assert_eq!(format!("{kind}"), expected);
            assert_eq!(expected.parse::<AuditEventKind>().unwrap(), kind);
        }
    }

    #[test]
    fn all_audit_level_display() {
        assert_eq!(format!("{}", AuditLevel::Info), "info");
        assert_eq!(format!("{}", AuditLevel::Warn), "warn");
        assert_eq!(format!("{}", AuditLevel::Error), "error");
    }

    #[test]
    fn audit_event_all_builder_methods() {
        let id = Uuid::new_v4();
        let approval_id = Uuid::new_v4();
        let summary = ClientSummary {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/test".into()),
            exe_sha256_prefix: Some("aabb".into()),
            codesign_team_id: None,
            client_type: ClientType::Agent,
            principal: None,
        };
        let target = TargetSummary {
            fields: {
                let mut m = std::collections::HashMap::new();
                m.insert("repo".into(), "org/repo".into());
                m
            },
        };
        let event = AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_request_id(id)
            .with_approval_id(approval_id)
            .with_client(summary)
            .with_operation("test.op")
            .with_safety(OperationSafety::Safe)
            .with_target(target)
            .with_outcome("ok")
            .with_latency_ms(100)
            .with_secret_names(vec!["SECRET".into()])
            .with_detail("test detail");

        assert_eq!(event.request_id, Some(id));
        assert_eq!(event.approval_id, Some(approval_id));
        assert!(event.client.is_some());
        assert_eq!(event.operation.as_deref(), Some("test.op"));
        assert_eq!(event.safety, Some(OperationSafety::Safe));
        assert!(event.target.is_some());
        assert_eq!(event.outcome.as_deref(), Some("ok"));
        assert_eq!(event.latency_ms, Some(100));
        assert_eq!(event.secret_names, vec!["SECRET"]);
        assert_eq!(event.detail.as_deref(), Some("test detail"));
    }

    #[test]
    fn audit_event_with_level_override() {
        let event =
            AuditEvent::new(AuditEventKind::OperationSucceeded).with_level(AuditLevel::Error);
        assert_eq!(event.level, AuditLevel::Error);
    }

    #[test]
    fn audit_event_with_policy_decision() {
        let decision = PolicyDecision {
            allowed: false,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            budget: None,
            require_distinct_approver: false,
            matched_rule: Some("deny-rule".into()),
            denial_reason: Some("denied".into()),
        };
        let event = AuditEvent::new(AuditEventKind::PolicyDenied).with_policy_decision(&decision);
        assert!(event.policy_decision.is_some());
        let pd = event.policy_decision.unwrap();
        assert!(pd.contains("DENY"));
    }

    #[test]
    fn client_summary_no_hash() {
        let id = ClientIdentity {
            uid: 501,
            gid: 20,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        };
        let summary = ClientSummary::from((&id, ClientType::Human));
        assert!(summary.exe_sha256_prefix.is_none());
        assert!(summary.pid.is_none());
        assert!(summary.exe_path.is_none());
    }

    #[test]
    fn client_summary_short_hash() {
        let id = ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1),
            exe_path: None,
            exe_sha256: Some("abcdef01".into()),
            codesign_team_id: None,
            workload: None,
        };
        let summary = ClientSummary::from((&id, ClientType::Agent));
        assert_eq!(summary.exe_sha256_prefix.as_deref(), Some("abcdef01"));
    }

    #[test]
    fn in_memory_emitter_events_of_kind_empty() {
        let emitter = InMemoryAuditEmitter::new();
        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        let policy_events = emitter.events_of_kind(AuditEventKind::PolicyDenied);
        assert!(policy_events.is_empty());
    }

    #[test]
    fn in_memory_emitter_default() {
        let emitter = InMemoryAuditEmitter::default();
        assert!(emitter.is_empty());
    }

    #[test]
    fn target_summary_default() {
        let target = TargetSummary::default();
        assert!(target.fields.is_empty());
    }

    #[test]
    fn tracing_emitter_does_not_panic() {
        let emitter = TracingAuditEmitter::new();
        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        emitter.emit(
            AuditEvent::new(AuditEventKind::OperationFailed)
                .with_operation("test.op")
                .with_outcome("error")
                .with_latency_ms(5),
        );
    }

    #[test]
    fn sequence_numbers_monotonic() {
        let emitter = InMemoryAuditEmitter::new();
        for _ in 0..10 {
            emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        }
        let events = emitter.events();
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.sequence_number, i as u64);
        }
    }

    #[test]
    fn sequence_starts_at_zero() {
        let emitter = InMemoryAuditEmitter::new();
        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        let events = emitter.events();
        assert_eq!(events[0].sequence_number, 0);
    }

    #[test]
    fn sequence_in_debug() {
        let event = AuditEvent::new(AuditEventKind::RequestReceived).with_sequence_number(42);
        let dbg = format!("{event:?}");
        assert!(dbg.contains("sequence_number: 42"));
    }

    #[test]
    fn rate_limited_kind_display() {
        assert_eq!(format!("{}", AuditEventKind::RateLimited), "rate.limited");
    }

    #[test]
    fn rate_limited_default_level() {
        assert_eq!(
            default_level_for_kind(AuditEventKind::RateLimited),
            AuditLevel::Warn
        );
    }

    #[test]
    fn audit_event_with_request_hash() {
        let event = AuditEvent::new(AuditEventKind::ApprovalRequired)
            .with_request_hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        assert_eq!(
            event.request_hash.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        );
    }

    #[test]
    fn audit_event_debug_shows_request_hash() {
        let event =
            AuditEvent::new(AuditEventKind::ApprovalGranted).with_request_hash("deadbeef01234567");
        let dbg = format!("{event:?}");
        assert!(dbg.contains("request_hash"));
        assert!(dbg.contains("deadbeef01234567"));
    }

    #[test]
    fn tracing_emitter_assigns_sequence_numbers() {
        let emitter = TracingAuditEmitter::new();
        emitter.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        emitter.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));
        // We can't inspect the events directly from TracingAuditEmitter,
        // but we can verify the counter advanced.
        assert_eq!(
            emitter
                .next_sequence
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    // -- Sanitized constructor tests --

    #[test]
    fn target_summary_redacts_jwt_in_value() {
        let mut target = std::collections::HashMap::new();
        target.insert("repo".into(), "org/myrepo".into());
        target.insert(
            "header".into(),
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U".into(),
        );
        let summary = TargetSummary::sanitized(&target);
        assert_eq!(summary.fields["repo"], "org/myrepo");
        assert!(!summary.fields["header"].contains("eyJ"));
        assert!(summary.fields["header"].contains("[REDACTED:"));
    }

    #[test]
    fn target_summary_redacts_credential_url() {
        let mut target = std::collections::HashMap::new();
        target.insert(
            "endpoint".into(),
            "https://admin:secret@db.example.com/mydb".into(),
        );
        let summary = TargetSummary::sanitized(&target);
        assert!(!summary.fields["endpoint"].contains("admin:secret"));
        assert!(summary.fields["endpoint"].contains("[URL:REDACTED]"));
    }

    #[test]
    fn workspace_summary_strips_userinfo() {
        use crate::operation::WorkspaceContext;
        use std::path::PathBuf;
        let ws = WorkspaceContext {
            repo_root: PathBuf::from("/tmp/repo"),
            remote_url: Some("https://user:pass@github.com/org/repo.git".into()),
            branch: Some("main".into()),
            head_sha: None,
            dirty: false,
            workspace_verified: false,
        };
        let summary = WorkspaceSummary::sanitized(&ws);
        let url = summary.remote_url.unwrap();
        assert!(!url.contains("user:pass"));
        assert_eq!(url, "https://github.com/org/repo.git");
        assert_eq!(summary.branch.as_deref(), Some("main"));
    }

    // -- AuditEventKind FromStr tests --

    #[test]
    fn audit_event_kind_from_str_roundtrip() {
        let kinds = vec![
            AuditEventKind::RequestReceived,
            AuditEventKind::PolicyDenied,
            AuditEventKind::ApprovalRequired,
            AuditEventKind::ApprovalPresented,
            AuditEventKind::ApprovalGranted,
            AuditEventKind::ApprovalDenied,
            AuditEventKind::OperationStarted,
            AuditEventKind::OperationSucceeded,
            AuditEventKind::OperationFailed,
            AuditEventKind::ProviderFetchStarted,
            AuditEventKind::ProviderFetchFinished,
            AuditEventKind::RateLimited,
            AuditEventKind::LeaseHit,
            AuditEventKind::SandboxCreated,
            AuditEventKind::SandboxCompleted,
            AuditEventKind::SecretResolved,
            AuditEventKind::AuditDropped,
            AuditEventKind::ExecveChecked,
            AuditEventKind::ExecveAllowed,
            AuditEventKind::ExecveDenied,
            AuditEventKind::ExecvePrompted,
        ];
        for kind in kinds {
            let s = format!("{kind}");
            let parsed: AuditEventKind = s.parse().unwrap();
            assert_eq!(parsed, kind);
        }
    }

    #[test]
    fn audit_event_kind_from_str_unknown() {
        let result = "nonexistent.kind".parse::<AuditEventKind>();
        assert!(result.is_err());
    }

    // -- SqliteAuditSink tests --

    fn temp_db_path() -> PathBuf {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        dir.join(format!("opaque-test-audit-{}.db", Uuid::new_v4()))
    }

    fn make_test_event(kind: AuditEventKind) -> AuditEvent {
        AuditEvent::new(kind)
            .with_operation("test.op")
            .with_outcome("ok")
            .with_latency_ms(42)
    }

    #[test]
    fn sqlite_sink_schema_creation() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        drop(sink);

        // Verify schema exists by opening read-only and querying.
        let conn = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_sink_emit_and_query() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        let req_id = Uuid::new_v4();
        let event = make_test_event(AuditEventKind::RequestReceived)
            .with_request_id(req_id)
            .with_secret_names(vec!["SECRET_A".into(), "SECRET_B".into()])
            .with_detail("test detail");
        sink.emit(event);

        let event2 = make_test_event(AuditEventKind::OperationSucceeded)
            .with_request_id(req_id)
            .with_safety(OperationSafety::Safe);
        sink.emit(event2);

        // Drop to flush and join writer thread.
        drop(sink);

        let filter = AuditFilter::default();
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 2);

        // Most recent first.
        assert_eq!(events[0].kind, AuditEventKind::OperationSucceeded);
        assert_eq!(events[1].kind, AuditEventKind::RequestReceived);
        assert_eq!(events[1].operation.as_deref(), Some("test.op"));
        assert_eq!(events[1].secret_names, vec!["SECRET_A", "SECRET_B"]);
        assert_eq!(events[1].detail.as_deref(), Some("test detail"));
        assert_eq!(events[0].safety, Some(OperationSafety::Safe));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_filter_by_kind() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        sink.emit(make_test_event(AuditEventKind::RequestReceived));
        sink.emit(make_test_event(AuditEventKind::PolicyDenied));
        sink.emit(make_test_event(AuditEventKind::OperationSucceeded));
        drop(sink);

        let filter = AuditFilter {
            kind: Some(AuditEventKind::PolicyDenied),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, AuditEventKind::PolicyDenied);

        let _ = std::fs::remove_file(&db_path);
    }

    // -- Tamper-evident hash chain --

    #[test]
    fn audit_chain_verifies_clean_log() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(make_test_event(AuditEventKind::RequestReceived));
        sink.emit(make_test_event(AuditEventKind::OperationStarted));
        sink.emit(make_test_event(AuditEventKind::OperationSucceeded));
        drop(sink); // flush + join writer

        let v = verify_audit_chain(&db_path).unwrap();
        assert!(v.ok, "clean log should verify: {:?}", v.detail);
        assert_eq!(v.records_checked, 3);
        assert!(v.first_bad_sequence.is_none());

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[cfg(unix)]
    #[test]
    fn audit_database_is_created_owner_only() {
        // REGRESSION (found by attestation posture reporting): SQLite created
        // audit.db with the process umask (0644). The daemon's custody check
        // runs before the file exists, so under trust_domain.enforce a fresh
        // state dir left the audit log readable at the agent's uid.
        use std::os::unix::fs::PermissionsExt;

        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(make_test_event(AuditEventKind::RequestReceived));
        drop(sink); // flush + WAL checkpoint

        let mode = std::fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "audit database must be owner-only, got {mode:o}"
        );

        // WAL/SHM siblings inherit the main file's mode — assert no group or
        // world access leaked through them either.
        for suffix in ["-wal", "-shm"] {
            let sibling = PathBuf::from(format!("{}{suffix}", db_path.display()));
            if let Ok(meta) = std::fs::metadata(&sibling) {
                let mode = meta.permissions().mode() & 0o077;
                assert_eq!(
                    mode,
                    0,
                    "{} grants access beyond the owner",
                    sibling.display()
                );
            }
        }

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[test]
    fn flush_makes_emitted_events_durable_before_exit() {
        // REGRESSION (found by the federation e2e on Linux): a daemon that
        // records a security-relevant refusal and then exits lost the event,
        // because emission is asynchronous and process exit runs no
        // destructors. flush() must make it durable without dropping.
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(
            make_test_event(AuditEventKind::FederationBundleRejected)
                .with_outcome("rollback_refused"),
        );
        sink.flush(std::time::Duration::from_secs(5)).unwrap();

        // Read with a SEPARATE connection while the sink is still alive.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let outcome: String = conn
            .query_row(
                "SELECT outcome FROM audit_events WHERE kind = 'federation.bundle_rejected'",
                [],
                |r| r.get(0),
            )
            .expect("flushed event must be readable before the sink is dropped");
        assert_eq!(outcome, "rollback_refused");
        drop(conn);
        drop(sink);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[test]
    fn audit_chain_survives_daemon_restart() {
        // REGRESSION (found by the trust-domain e2e): the sink used to reset
        // its sequence counter to 0 on every open, so a restarted daemon
        // wrote duplicate sequence numbers into the chain and verification —
        // which orders by sequence — read the log as scrambled.
        let db_path = temp_db_path();

        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(make_test_event(AuditEventKind::RequestReceived));
        sink.emit(make_test_event(AuditEventKind::OperationSucceeded));
        drop(sink); // daemon shutdown

        // Daemon restart: a fresh sink over the same database.
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(make_test_event(AuditEventKind::RequestReceived));
        sink.emit(make_test_event(AuditEventKind::OperationSucceeded));
        drop(sink);

        // Sequences must be strictly increasing across the restart…
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let seqs: Vec<i64> = conn
            .prepare("SELECT sequence_number FROM audit_events ORDER BY rowid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(seqs, vec![0, 1, 2, 3], "restart must resume numbering");
        drop(conn);

        // …and the chain must verify end to end.
        let v = verify_audit_chain(&db_path).unwrap();
        assert!(v.ok, "restarted log must verify: {:?}", v.detail);
        assert_eq!(v.records_checked, 4);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[test]
    fn audit_chain_detects_row_tamper() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(make_test_event(AuditEventKind::RequestReceived).with_outcome("ok"));
        sink.emit(make_test_event(AuditEventKind::PolicyDenied).with_outcome("denied"));
        sink.emit(make_test_event(AuditEventKind::OperationSucceeded).with_outcome("ok"));
        drop(sink);

        // Tamper: rewrite a denial to look successful, leaving record_hash untouched.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "UPDATE audit_events SET outcome = 'ok' WHERE outcome = 'denied'",
                [],
            )
            .unwrap();
        }

        let v = verify_audit_chain(&db_path).unwrap();
        assert!(!v.ok, "tampered log must fail verification");
        assert!(v.first_bad_sequence.is_some());

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[test]
    fn audit_chain_detects_row_deletion() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(make_test_event(AuditEventKind::RequestReceived));
        sink.emit(make_test_event(AuditEventKind::PolicyDenied));
        sink.emit(make_test_event(AuditEventKind::OperationSucceeded));
        drop(sink);

        // Delete the middle record — the following record no longer chains.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("DELETE FROM audit_events WHERE kind = 'policy.denied'", [])
                .unwrap();
        }

        let v = verify_audit_chain(&db_path).unwrap();
        assert!(!v.ok, "deletion must be detected");

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[test]
    fn retention_zero_keeps_all() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        let sink = SqliteAuditSink::new(path.clone(), 0).unwrap();
        let mut event = make_test_event(AuditEventKind::RequestReceived);
        event.ts_utc_ms = 1;
        sink.emit(event);
        sink.close().unwrap();
        let key = load_hmac_key(&path).unwrap();
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            SqliteAuditSink::run_retention_cleanup(&mut conn, 0, &key).unwrap(),
            0
        );
        assert_eq!(
            SqliteAuditSink::run_retention_cleanup(&mut conn, 1, &key).unwrap(),
            1
        );
        assert!(verify_audit_chain(&path).unwrap().ok);
    }

    #[test]
    fn retention_refuses_to_reauthenticate_a_deleted_prefix() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        let sink = SqliteAuditSink::new(path.clone(), 0).unwrap();
        for _ in 0..3 {
            sink.emit(make_test_event(AuditEventKind::RequestReceived));
        }
        sink.close().unwrap();
        let key = load_hmac_key(&path).unwrap();
        let mut conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "DELETE FROM audit_events WHERE rowid=(SELECT MIN(rowid) FROM audit_events)",
            [],
        )
        .unwrap();
        assert!(!verify_audit_chain(&path).unwrap().ok);
        assert!(SqliteAuditSink::run_retention_cleanup(&mut conn, 1, &key).is_err());
        assert!(SqliteAuditSink::new(path.clone(), 1).is_err());
        assert!(!verify_audit_chain(&path).unwrap().ok);
    }

    #[test]
    fn audit_chain_detects_tail_truncation() {
        // Deleting the newest records leaves a valid shorter chain, which the chain
        // walk alone cannot catch — the head anchor detects it.
        let db_path = temp_db_path();
        {
            let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
            sink.emit(make_test_event(AuditEventKind::RequestReceived));
            sink.emit(make_test_event(AuditEventKind::OperationStarted));
            sink.emit(make_test_event(AuditEventKind::OperationSucceeded));
            drop(sink);
        }
        // Attacker truncates the newest record.
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "DELETE FROM audit_events WHERE rowid = (SELECT MAX(rowid) FROM audit_events)",
                [],
            )
            .unwrap();
        }
        let v = verify_audit_chain(&db_path).unwrap();
        assert!(
            !v.ok,
            "tail truncation must be detected via the head anchor"
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[test]
    fn sqlite_query_filter_by_operation() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        sink.emit(AuditEvent::new(AuditEventKind::RequestReceived).with_operation("github.sync"));
        sink.emit(AuditEvent::new(AuditEventKind::RequestReceived).with_operation("k8s.apply"));
        drop(sink);

        let filter = AuditFilter {
            operation: Some("github.sync".into()),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation.as_deref(), Some("github.sync"));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_filter_by_text_query() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        sink.emit(
            AuditEvent::new(AuditEventKind::OperationSucceeded)
                .with_operation("github.set_actions_secret")
                .with_outcome("ok")
                .with_detail("repo=acme/api secret=DATABASE_URL"),
        );
        sink.emit(
            AuditEvent::new(AuditEventKind::OperationSucceeded)
                .with_operation("sandbox.exec")
                .with_outcome("ok")
                .with_detail("command=ls"),
        );
        drop(sink);

        let filter = AuditFilter {
            text_query: Some("acme".into()),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].operation.as_deref(),
            Some("github.set_actions_secret")
        );

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_filter_by_request_id() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        let target_id = Uuid::new_v4();
        sink.emit(make_test_event(AuditEventKind::RequestReceived).with_request_id(target_id));
        sink.emit(make_test_event(AuditEventKind::RequestReceived).with_request_id(Uuid::new_v4()));
        drop(sink);

        let filter = AuditFilter {
            request_id: Some(target_id),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].request_id, Some(target_id));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_filter_by_since_ms() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        // Emit events — they'll all have "now" timestamps.
        sink.emit(make_test_event(AuditEventKind::RequestReceived));
        drop(sink);

        let now_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        // Since in the future — should return nothing.
        let filter = AuditFilter {
            since_ms: Some(now_ms + 60_000),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert!(events.is_empty());

        // Since in the past — should return everything.
        let filter = AuditFilter {
            since_ms: Some(now_ms - 60_000),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_query_limit() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        for _ in 0..10 {
            sink.emit(make_test_event(AuditEventKind::RequestReceived));
        }
        drop(sink);

        let filter = AuditFilter {
            limit: 3,
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 3);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn sqlite_retention_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        let sink = SqliteAuditSink::new(path.clone(), 0).unwrap();
        let mut event = make_test_event(AuditEventKind::RequestReceived);
        event.ts_utc_ms = 1000;
        sink.emit(event);
        sink.close().unwrap();
        let reopened = SqliteAuditSink::new(path.clone(), 90).unwrap();
        reopened.close().unwrap();
        assert!(
            query_audit_db(&path, &AuditFilter::default())
                .unwrap()
                .is_empty()
        );
        assert!(verify_audit_chain(&path).unwrap().ok);
    }

    #[test]
    fn sqlite_retention_cleanup_runs_periodically_while_running() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        let sink = SqliteAuditSink::new(path.clone(), 90).unwrap();
        let mut event = make_test_event(AuditEventKind::RequestReceived);
        event.ts_utc_ms = 1000;
        sink.emit(event);
        sink.flush(std::time::Duration::from_secs(5)).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if query_audit_db(&path, &AuditFilter::default())
                .unwrap()
                .is_empty()
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "periodic cleanup did not run"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        sink.close().unwrap();
        assert!(verify_audit_chain(&path).unwrap().ok);
    }

    #[test]
    fn sqlite_sink_with_client_and_target() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        let client = ClientSummary {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/test".into()),
            exe_sha256_prefix: Some("aabb".into()),
            codesign_team_id: None,
            client_type: ClientType::Human,
            principal: None,
        };
        let target = TargetSummary {
            fields: {
                let mut m = std::collections::HashMap::new();
                m.insert("repo".into(), "org/repo".into());
                m
            },
        };
        let workspace = WorkspaceSummary {
            remote_url: Some("https://github.com/org/repo.git".into()),
            branch: Some("main".into()),
            dirty: false,
        };

        let event = AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_client(client)
            .with_target(target)
            .with_workspace(workspace)
            .with_request_hash("abcdef");
        sink.emit(event);
        drop(sink);

        let filter = AuditFilter::default();
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(events.len(), 1);

        let e = &events[0];
        let c = e.client.as_ref().unwrap();
        assert_eq!(c.uid, 501);
        assert_eq!(c.client_type, ClientType::Human);
        let t = e.target.as_ref().unwrap();
        assert_eq!(t.fields["repo"], "org/repo");
        let w = e.workspace.as_ref().unwrap();
        assert_eq!(w.branch.as_deref(), Some("main"));
        assert_eq!(e.request_hash.as_deref(), Some("abcdef"));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn audit_filter_defaults() {
        let filter = AuditFilter::default();
        assert!(filter.kind.is_none());
        assert!(filter.operation.is_none());
        assert!(filter.since_ms.is_none());
        assert_eq!(filter.limit, 50);
        assert!(filter.request_id.is_none());
        assert!(filter.text_query.is_none());
    }

    // -- MultiAuditSink tests --

    #[test]
    fn multi_sink_fans_out() {
        let a = std::sync::Arc::new(InMemoryAuditEmitter::new());
        let b = std::sync::Arc::new(InMemoryAuditEmitter::new());
        let multi = MultiAuditSink::new(vec![
            a.clone() as std::sync::Arc<dyn AuditSink>,
            b.clone() as std::sync::Arc<dyn AuditSink>,
        ]);

        multi.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        multi.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));

        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn multi_sink_debug() {
        let multi = MultiAuditSink::new(vec![]);
        let dbg = format!("{multi:?}");
        assert!(dbg.contains("MultiAuditSink"));
        assert!(dbg.contains("sink_count: 0"));
    }

    #[test]
    fn sqlite_sink_debug() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("SqliteAuditSink"));
        drop(sink);
        let _ = std::fs::remove_file(&db_path);
    }

    // -- AuditError tests --

    #[test]
    fn audit_error_display() {
        let err = AuditError::Other("test error".into());
        assert_eq!(format!("{err}"), "test error");

        let io_err = AuditError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        assert!(format!("{io_err}").contains("not found"));
    }

    #[test]
    fn sqlite_sink_sanitizes_detail() {
        // P0-4: The SqliteAuditSink must sanitize the detail field
        // before persisting to prevent secret leakage in the audit DB.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("sanitize_test.db");
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        let secret_detail =
            "command=[\"/bin/sh\", \"-c\", \"echo ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"]";
        let event = AuditEvent::new(AuditEventKind::OperationSucceeded)
            .with_detail(secret_detail.to_owned());
        sink.emit(event);
        drop(sink);

        // Query the DB directly to verify the detail was sanitized.
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let detail: String = conn
            .query_row(
                "SELECT detail FROM audit_events WHERE detail IS NOT NULL LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert!(
            !detail.contains("ghp_ABCDEF"),
            "audit detail should not contain the raw GitHub PAT"
        );
        assert!(
            detail.contains("[REDACTED:github_token]"),
            "audit detail should contain redaction marker"
        );
    }

    // -- Dropped event accounting tests (P2 security fix) --

    #[test]
    fn dropped_counter_starts_at_zero() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        assert_eq!(sink.dropped_count(), 0);
        drop(sink);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn dropped_counter_increments_on_full_channel() {
        let db_path = temp_db_path();
        // Use a tiny channel (capacity=2) so we can easily overflow it.
        let sink = SqliteAuditSink::new_with_capacity(db_path.clone(), 90, 2).unwrap();

        // Pause the writer so it cannot drain the channel.
        sink.pause_writer();

        // Emit 10 events — the first 2 fill the channel, the remaining 8 should be dropped.
        for _ in 0..10 {
            sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        }

        assert!(
            sink.dropped_count() > 0,
            "expected dropped_count > 0, got {}",
            sink.dropped_count()
        );

        sink.resume_writer();
        drop(sink);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn dropped_count_returns_correct_value() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new_with_capacity(db_path.clone(), 90, 1).unwrap();

        sink.pause_writer();

        // With capacity 1: writer holds 1 event (from recv), channel holds 1,
        // remaining 8 out of 10 are dropped.
        for _ in 0..10 {
            sink.emit(AuditEvent::new(AuditEventKind::OperationSucceeded));
        }

        // At least 8 should be dropped (writer holds 1, channel holds 1, 8 overflow).
        assert!(
            sink.dropped_count() >= 8,
            "expected dropped_count >= 8, got {}",
            sink.dropped_count()
        );

        sink.resume_writer();
        drop(sink);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn normal_operation_no_drops() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        // Emit a small number of events — writer should keep up.
        for _ in 0..5 {
            sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        }

        // Give the writer a moment to drain.
        std::thread::sleep(std::time::Duration::from_millis(50));

        assert_eq!(
            sink.dropped_count(),
            0,
            "no events should be dropped under normal load"
        );

        drop(sink);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn audit_dropped_event_kind_exists() {
        // The AuditDropped kind should exist and round-trip through Display/FromStr.
        let kind = AuditEventKind::AuditDropped;
        let s = format!("{kind}");
        assert_eq!(s, "audit.dropped");
        let parsed: AuditEventKind = s.parse().unwrap();
        assert_eq!(parsed, AuditEventKind::AuditDropped);
    }

    #[test]
    fn audit_dropped_default_level_is_warn() {
        assert_eq!(
            default_level_for_kind(AuditEventKind::AuditDropped),
            AuditLevel::Warn
        );
    }

    #[test]
    fn synthetic_audit_dropped_event_emitted_with_count() {
        let db_path = temp_db_path();
        // Use capacity=2 so we can overflow, but still have room for the
        // synthetic event after the writer drains.
        let sink = SqliteAuditSink::new_with_capacity(db_path.clone(), 90, 2).unwrap();

        sink.pause_writer();

        // Overflow the channel to create drops.
        for _ in 0..10 {
            sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        }

        let dropped_before = sink.dropped_count();
        assert!(dropped_before > 0);

        // Resume writer and wait for it to drain the channel.
        sink.resume_writer();
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Manually trigger the periodic flush of the dropped counter.
        sink.flush_dropped_events();

        // After flushing, the counter should reset to 0.
        assert_eq!(
            sink.dropped_count(),
            0,
            "counter should reset after synthetic event emission"
        );

        // Give writer time to persist the synthetic event.
        std::thread::sleep(std::time::Duration::from_millis(200));
        drop(sink);

        // Query the DB for the synthetic AuditDropped event.
        let filter = AuditFilter {
            kind: Some(AuditEventKind::AuditDropped),
            ..Default::default()
        };
        let events = query_audit_db(&db_path, &filter).unwrap();
        assert_eq!(
            events.len(),
            1,
            "should have exactly one AuditDropped event"
        );

        let dropped_event = &events[0];
        assert_eq!(dropped_event.kind, AuditEventKind::AuditDropped);
        assert_eq!(dropped_event.level, AuditLevel::Warn);

        // The detail should contain the dropped count.
        let detail = dropped_event.detail.as_deref().unwrap();
        assert!(
            detail.contains(&dropped_before.to_string()),
            "detail should contain the dropped count ({dropped_before}), got: {detail}"
        );

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn counter_resets_after_synthetic_event() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new_with_capacity(db_path.clone(), 90, 1).unwrap();

        sink.pause_writer();

        // Create some drops.
        for _ in 0..5 {
            sink.emit(AuditEvent::new(AuditEventKind::RequestReceived));
        }
        assert!(sink.dropped_count() > 0);

        sink.resume_writer();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let state = sink.progress.0.lock().unwrap();
            if state.settled == state.accepted {
                break;
            }
            drop(state);
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // The report can now be queued, so resetting its pending count is safe.
        sink.flush_dropped_events();
        assert_eq!(sink.dropped_count(), 0);

        // Create more drops.
        sink.pause_writer();
        for _ in 0..3 {
            sink.emit(AuditEvent::new(AuditEventKind::OperationFailed));
        }

        // The counter should reflect only the new drops, not old ones.
        let new_count = sink.dropped_count();
        assert!(
            new_count > 0 && new_count <= 3,
            "counter should only reflect new drops, got {new_count}"
        );

        sink.resume_writer();
        drop(sink);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn dropped_count_health_accessor() {
        // Verify dropped_count is publicly accessible for health/metrics.
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();

        // This tests the public API surface — dropped_count() must be pub.
        let count: u64 = sink.dropped_count();
        assert_eq!(count, 0);

        drop(sink);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn execve_audit_events_serialize() {
        // Verify that all execve audit event kinds serialize and deserialize correctly.
        let kinds = vec![
            AuditEventKind::ExecveChecked,
            AuditEventKind::ExecveAllowed,
            AuditEventKind::ExecveDenied,
            AuditEventKind::ExecvePrompted,
        ];
        for kind in kinds {
            let event = AuditEvent::new(kind)
                .with_operation("sandbox.execve_check")
                .with_outcome("allow")
                .with_detail("executable=/usr/bin/git args=[push, origin, main] cwd=/home/user sandbox_id=codex-abc");
            let json = serde_json::to_string(&event).unwrap();
            let deserialized: AuditEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.kind, kind);
            assert_eq!(
                deserialized.operation.as_deref(),
                Some("sandbox.execve_check")
            );
            assert!(
                deserialized
                    .detail
                    .as_ref()
                    .unwrap()
                    .contains("/usr/bin/git")
            );
        }

        // Verify default levels.
        assert_eq!(
            default_level_for_kind(AuditEventKind::ExecveChecked),
            AuditLevel::Info
        );
        assert_eq!(
            default_level_for_kind(AuditEventKind::ExecveAllowed),
            AuditLevel::Info
        );
        assert_eq!(
            default_level_for_kind(AuditEventKind::ExecveDenied),
            AuditLevel::Warn
        );
        assert_eq!(
            default_level_for_kind(AuditEventKind::ExecvePrompted),
            AuditLevel::Info
        );
    }

    // -- Phase 1: approver identity + presence-versioned canon --------------

    fn test_approver() -> ApproverIdentity {
        ApproverIdentity {
            principal_id: "hum_0123456789abcdef0123456789abcdef".into(),
            label: "dev@example.com".into(),
            source: ApproverSource::LocalBioSession,
        }
    }

    /// Build a database exactly the way a pre-Phase-1 daemon did: no
    /// approver_json column, rows hashed over the original 18-field canon.
    fn seed_pre_phase1_db(db_path: &Path, rows: usize) {
        let conn = rusqlite::Connection::open(db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE audit_events (
                event_id TEXT PRIMARY KEY,
                sequence_number INTEGER NOT NULL,
                ts_utc_ms INTEGER NOT NULL,
                level TEXT NOT NULL,
                kind TEXT NOT NULL,
                request_id TEXT, approval_id TEXT, client_json TEXT,
                operation TEXT, safety TEXT, target_json TEXT, outcome TEXT,
                latency_ms INTEGER, secret_names TEXT, policy_decision TEXT,
                detail TEXT, workspace_json TEXT, request_hash TEXT,
                record_hash TEXT
            );
            CREATE TABLE chain_head (
                id INTEGER PRIMARY KEY CHECK (id = 0),
                last_hash TEXT NOT NULL,
                last_sequence INTEGER NOT NULL
            );",
        )
        .unwrap();
        let key = load_or_create_hmac_key(db_path).unwrap();
        let mut prev = CHAIN_GENESIS.to_string();
        for i in 0..rows {
            let event_id = Uuid::new_v4().to_string();
            let canon = canonical_record(
                &event_id,
                i as i64,
                1_000 + i as i64,
                "info",
                "request.received",
                None,
                None,
                None,
                Some("legacy.op"),
                None,
                None,
                Some("ok"),
                None,
                None,
                None,
                None,
                None,
                None,
            );
            let h = chain_hash(&key, &prev, &canon);
            conn.execute(
                "INSERT INTO audit_events (event_id, sequence_number, ts_utc_ms,
                    level, kind, operation, outcome, record_hash)
                 VALUES (?1, ?2, ?3, 'info', 'request.received', 'legacy.op', 'ok', ?4)",
                rusqlite::params![event_id, i as i64, 1_000 + i as i64, h],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO chain_head (id, last_hash, last_sequence) VALUES (0, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET last_hash = ?1, last_sequence = ?2",
                rusqlite::params![h, i as i64],
            )
            .unwrap();
            prev = h;
        }
    }

    #[test]
    fn approver_rows_chain_and_roundtrip() {
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(make_test_event(AuditEventKind::ApprovalGranted).with_approver(test_approver()));
        sink.emit(make_test_event(AuditEventKind::OperationSucceeded));
        drop(sink);

        let v = verify_audit_chain(&db_path).unwrap();
        assert!(v.ok, "chain with approver rows must verify: {:?}", v.detail);

        let events = query_audit_db(&db_path, &AuditFilter::default()).unwrap();
        let approved = events
            .iter()
            .find(|e| e.kind == AuditEventKind::ApprovalGranted)
            .unwrap();
        let approver = approved.approver.as_ref().expect("approver stored");
        assert_eq!(approver.label, "dev@example.com");
        assert_eq!(approver.source, ApproverSource::LocalBioSession);
        assert!(
            events
                .iter()
                .find(|e| e.kind == AuditEventKind::OperationSucceeded)
                .unwrap()
                .approver
                .is_none()
        );

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[test]
    fn pre_phase1_db_verifies_and_extends_without_backfill() {
        let db_path = temp_db_path();
        seed_pre_phase1_db(&db_path, 3);

        // An unauthenticated legacy head cannot be silently blessed at startup.
        assert!(!verify_audit_chain(&db_path).unwrap().ok);
        assert!(SqliteAuditSink::new(db_path.clone(), 0).is_err());
        let trusted_pin = crate::evidence_checkpoint::sha256(
            &checkpoint::inspect_legacy_export(&db_path).unwrap(),
        );
        checkpoint::upgrade_legacy_head(&db_path, &trusted_pin).unwrap();
        let v = verify_audit_chain(&db_path).unwrap();
        assert!(v.ok);
        assert_eq!(v.records_checked, 3);

        // Snapshot old hashes, then open with the new sink (migrates: adds
        // the approver column, must NOT rewrite existing record hashes).
        let old_hashes: Vec<String> = {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            let mut stmt = conn
                .prepare("SELECT record_hash FROM audit_events ORDER BY rowid")
                .unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };

        let sink = SqliteAuditSink::new(db_path.clone(), 0).unwrap();
        sink.emit(make_test_event(AuditEventKind::ApprovalGranted).with_approver(test_approver()));
        drop(sink);

        let new_hashes: Vec<String> = {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            let mut stmt = conn
                .prepare("SELECT record_hash FROM audit_events ORDER BY rowid LIMIT 3")
                .unwrap();
            stmt.query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(
            old_hashes, new_hashes,
            "migration must not rewrite pre-existing record hashes (no backfill)"
        );

        // Mixed chain (3 legacy rows + 1 approver row) verifies end to end.
        let v = verify_audit_chain(&db_path).unwrap();
        assert!(v.ok, "mixed old/new chain must verify: {:?}", v.detail);
        assert_eq!(v.records_checked, 4);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[test]
    fn tampered_approver_detected_in_all_permutations() {
        // Permutation 1: edit the approver on a new row.
        let db_path = temp_db_path();
        let sink = SqliteAuditSink::new(db_path.clone(), 90).unwrap();
        sink.emit(make_test_event(AuditEventKind::ApprovalGranted).with_approver(test_approver()));
        drop(sink);
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "UPDATE audit_events SET approver_json =
                    replace(approver_json, 'dev@example.com', 'evil@example.com')",
                [],
            )
            .unwrap();
        }
        assert!(
            !verify_audit_chain(&db_path).unwrap().ok,
            "edited approver must break the chain"
        );

        // Permutation 2: strip the approver from that row (NULL it out).
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute("UPDATE audit_events SET approver_json = NULL", [])
                .unwrap();
        }
        assert!(
            !verify_audit_chain(&db_path).unwrap().ok,
            "removed approver must break the chain"
        );
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));

        // Permutation 3: inject an approver into a legacy (pre-Phase-1) row
        // after the column migration.
        let db_path = temp_db_path();
        seed_pre_phase1_db(&db_path, 2);
        let trusted_pin = crate::evidence_checkpoint::sha256(
            &checkpoint::inspect_legacy_export(&db_path).unwrap(),
        );
        checkpoint::upgrade_legacy_head(&db_path, &trusted_pin).unwrap();
        let sink = SqliteAuditSink::new(db_path.clone(), 0).unwrap();
        drop(sink); // migration only
        {
            let conn = rusqlite::Connection::open(&db_path).unwrap();
            conn.execute(
                "UPDATE audit_events SET approver_json = '{\"principal_id\":\"hum_x\",\
                 \"label\":\"fake\",\"source\":\"local_bio_session\"}'
                 WHERE sequence_number = 0",
                [],
            )
            .unwrap();
        }
        assert!(
            !verify_audit_chain(&db_path).unwrap().ok,
            "approver injected into a legacy row must break the chain"
        );
        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(hmac_key_path(&db_path));
    }

    #[test]
    fn client_summary_principal_serde_compat() {
        // Old client_json (no principal key) still deserializes.
        let old = r#"{"uid":501,"gid":20,"pid":1,"exe_path":null,
            "exe_sha256_prefix":null,"codesign_team_id":null,"client_type":"agent"}"#;
        let summary: ClientSummary = serde_json::from_str(old).unwrap();
        assert!(summary.principal.is_none());

        // Without a principal the serialized form has no principal key at all
        // (byte-stability for the chain).
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("principal"));

        // With a principal it roundtrips.
        use crate::identity::{AccessMode, PrincipalContext, PrincipalId};
        let ctx = PrincipalContext {
            sub: PrincipalId::parse("hum_0123456789abcdef0123456789abcdef").unwrap(),
            sub_label: "dev@example.com".into(),
            sub_roles: [crate::identity::Role::Operator].into_iter().collect(),
            sub_teams: vec![],
            act: PrincipalId::parse("agt_0123456789abcdef0123456789abcdef").unwrap(),
            act_label: "agent:claude-code".into(),
            mode: AccessMode::Delegated,
            jti: "sess-1".into(),
            human_session_id: None,
        };
        let with = summary.with_principal(&ctx);
        let json = serde_json::to_string(&with).unwrap();
        let back: ClientSummary = serde_json::from_str(&json).unwrap();
        let p = back.principal.unwrap();
        assert_eq!(p.sub_label, "dev@example.com");
        assert_eq!(p.mode, "delegated");
        assert_eq!(p.sub_roles, vec!["operator"]);
    }

    #[test]
    fn retention_preserves_chain_with_approver_rows() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        let sink = SqliteAuditSink::new(path.clone(), 0).unwrap();
        let mut expired =
            make_test_event(AuditEventKind::ApprovalGranted).with_approver(test_approver());
        expired.ts_utc_ms = 1000;
        sink.emit(expired);
        sink.emit(
            make_test_event(AuditEventKind::OperationSucceeded).with_approver(test_approver()),
        );
        sink.close().unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        let old_hash: String = conn
            .query_row(
                "SELECT record_hash FROM audit_events WHERE sequence_number=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let reopened = SqliteAuditSink::new(path.clone(), 1).unwrap();
        reopened
            .emit(make_test_event(AuditEventKind::ApprovalGranted).with_approver(test_approver()));
        reopened.close().unwrap();
        let survivor_hash: String = conn
            .query_row(
                "SELECT record_hash FROM audit_events WHERE sequence_number=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            old_hash, survivor_hash,
            "retention must not re-sign surviving records"
        );
        let verification = verify_audit_chain(&path).unwrap();
        assert!(verification.ok, "{:?}", verification.detail);
        assert_eq!(verification.records_checked, 2);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[path = "audit/regression_tests.rs"]
mod regression_tests;
