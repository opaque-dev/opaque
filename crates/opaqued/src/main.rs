#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use bytes::Bytes;
use futures_util::StreamExt;
use opaque_core::audit::{
    AuditEvent, AuditEventKind, AuditSink, ClientSummary, MultiAuditSink, SqliteAuditSink,
    TracingAuditEmitter,
};
use opaque_core::execve_map::{ExecveDefault, ExecveMapper, ExecveRule};
use opaque_core::identity::{
    AccessMode, PrincipalContext, PrincipalId, now_unix, verify_delegation_token,
};
use opaque_core::operation::{
    ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationDef,
    OperationRegistry, OperationRequest, OperationSafety,
};
use opaque_core::peer::peer_info_from_fd;
use opaque_core::policy::{
    PolicyEngine, PolicyRule, codesign_team_id_is_platform_enforceable,
    known_human_client_platform_warnings, platform_policy_warnings,
};
use opaque_core::proto::{Request, Response};
use opaque_core::socket::{
    bind_unix_listener_private, ensure_socket_parent_dir, socket_path_for_client,
    validate_path_chain,
};
use opaque_core::validate::InputValidator;
use serde::Deserialize;
use tokio::net::{UnixListener, UnixStream};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, warn};
use uuid::Uuid;

/// Name of the daemon token file written next to the socket.
const DAEMON_TOKEN_FILENAME: &str = "daemon.token";

mod agent_session;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod agent_session_contract_tests;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod approver_rpc_tests;
mod authority_policy;
mod connection;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod connection_flow_tests;
mod enclave;
mod identity;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod main_contract_tests;
mod mcp_gateway;
mod provisioning_api;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod provisioning_api_tests;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod resource_authority_provisioning_tests;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod role_authority_tests;
mod rpc_wrappers;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod scope_rpc_tests;
mod scope_runtime;
mod trust_domain;
mod workspace_process;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod workspace_verification_tests;

// `task_api`, `task_store`, `ssh`, `resource_authority`, and `inference`
// moved to the `opaque-bounded-work` crate (the daemon's task-ledger/
// SSH-execution/inference-brokering surface). `resource_authority`'s former
// inline `#[cfg(test)] mod provisioning_tests` moved with it conceptually
// but not literally: it needed the real `identity::IdentityRuntime`, which
// stays here, so it now lives in this crate as
// `resource_authority_provisioning_tests` above (declared here rather than
// nested in a moved file, same wiring pattern as `provisioning_api_tests`).

use workspace_process::WorkspaceCommandExt;

use std::future::Future;
use std::pin::Pin;

use enclave::{Enclave, NativeApprovalGate};
use opaque_core::approval_gate::ApprovalGate;
use opaque_core::enclave_facade::EnclaveFacade;
use opaque_core::operation_handler::OperationHandler;

// ---------------------------------------------------------------------------
// Daemon configuration
// ---------------------------------------------------------------------------

/// Daemon configuration loaded from `~/.opaque/config.toml`.
#[derive(Debug, Clone, Deserialize, Default)]
struct DaemonConfig {
    /// Operator-pinned AuthorityPolicy; mutually exclusive with scope_workflow.
    #[serde(default)]
    authority_policy: Option<authority_policy::Config>,
    /// Opt-in fixed support-case workflow; requires sealed isolated identity custody.
    #[serde(default)]
    scope_workflow: Option<scope_runtime::Config>,
    /// Signed third-party MCP registry and broker-owned credential bindings.
    #[serde(default)]
    mcp: Option<opaque_bounded_work::mcp::Config>,
    /// One immutable tenant per independently isolated broker installation.
    #[serde(default)]
    tenant: Option<opaque_tenant::tenant::TenantConfig>,
    /// Sealed, operator-selected model and public source profile.
    #[serde(default)]
    inference: Option<opaque_bounded_work::inference::InferenceProfileConfig>,
    /// One operator-pinned host operation using a Vault SSH signing role.
    #[serde(default)]
    ssh: Option<opaque_bounded_work::ssh::SshProfileConfig>,
    /// Opt-in fixed-manifest publishing; existing single-write rules keep their floor.
    #[serde(default)]
    enable_task_grants: bool,

    /// Trusted state location for isolated installations and dogfood runs.
    #[serde(default)]
    data_dir: Option<PathBuf>,
    /// Known human client executables. If a connecting client matches any
    /// entry, it is classified as `Human`; otherwise it defaults to `Agent`.
    #[serde(default)]
    known_human_clients: Vec<HumanClientEntry>,

    /// Policy rules loaded from config. Deny-all default when empty.
    #[serde(default)]
    rules: Vec<PolicyRule>,

    /// Audit log retention in days. Defaults to 90 if not specified.
    #[serde(default)]
    audit_retention_days: Option<u64>,

    /// When true, clients classified as `Agent` must present a valid
    /// per-session token in the handshake.
    #[serde(default)]
    enforce_agent_sessions: bool,

    /// Default TTL for agent sessions in seconds.
    #[serde(default)]
    agent_session_ttl_secs: Option<u64>,

    /// When true, the daemon refuses to start if the config is not sealed.
    /// Production deployments should set this to `true`.
    #[serde(default)]
    require_seal: bool,

    /// Execve-to-operation mapping rules for external sandbox policy hooks.
    #[serde(default)]
    execve_rules: Vec<ExecveRule>,

    /// Default decision for execve requests that do not match any rule.
    #[serde(default)]
    execve_default: ExecveDefault,

    /// Identity substrate (`[identity]`): OIDC login, principals, roles.
    /// Absent = identity features disabled (Phase 0 behavior).
    #[serde(default)]
    identity: Option<identity::IdentityConfig>,
    /// Recognize old provisioning configuration solely to reject a silent
    /// downgrade to unmanaged identity after component extraction.
    #[serde(default, rename = "scim")]
    legacy_scim: Option<serde::de::IgnoredAny>,
    #[serde(default)]
    lifecycle: Option<identity::lifecycle::LifecycleConfig>,
    #[serde(default)]
    fleet: Option<opaque_federation_runtime::fleet::reporter::ReporterConfig>,
    #[serde(default)]
    resource_authority: Option<opaque_bounded_work::resource_authority::ResourceAuthorityConfig>,
    /// Explicitly scoped, human-authorized IdP provisioning mandates.
    #[serde(default)]
    provisioning: Option<identity::provisioning::ProvisioningConfig>,

    /// Approval backend: `"native"` (default — OS biometric/polkit prompt) or
    /// `"insecure_auto_approve"` (tests/e2e ONLY; additionally requires the
    /// environment variable `OPAQUE_INSECURE_AUTO_APPROVE=1` at startup, and
    /// announces itself with an Error-level audit event).
    #[serde(default)]
    approval_backend: Option<String>,

    /// Public keys authorized by the trusted operator to review whole tasks.
    #[serde(default)]
    workstation_approvers: Vec<opaque_approval::pairing::WorkstationApproverConfig>,
    /// Durable signed review decisions and minimal collaboration notifications.
    #[serde(default)]
    remote_approvals: Option<opaque_approval::remote::RemoteApprovalConfig>,

    /// Downgrades receipt provenance for an automated signing fixture. This
    /// does not bypass any enrollment, signature, expiry or policy check.
    #[serde(default)]
    workstation_test_mode: bool,

    /// Trust-domain enforcement (`[trust_domain]`): the service-account split
    /// that turns the audit/seal/delegation guarantees from tamper-evidence
    /// into tamper-prevention. Absent = shared-uid developer mode (audited,
    /// not enforced).
    #[serde(default)]
    trust_domain: TrustDomainConfig,

    /// Approval factor settings (`[approval]`): which out-of-band factors are
    /// live beyond the local prompt.
    #[serde(default)]
    approval: ApprovalFactorsConfig,

    /// Federation (`[federation]`): signed policy bundles from an org.
    #[serde(default)]
    federation: opaque_federation_runtime::federation::FederationConfig,

    /// SIEM export (`[export]`): stream the audit chain off the box.
    #[serde(default)]
    export: opaque_federation_runtime::export::ExportConfig,

    /// Continuous attestation (`[attestation]`): periodic posture reports and
    /// verify-before-trust key release.
    #[serde(default)]
    attestation: opaque_federation_runtime::attest::AttestationConfig,
}

/// `[approval]` — out-of-band approval factor configuration.
#[derive(Debug, Clone, Deserialize, Default)]
struct ApprovalFactorsConfig {
    /// Session creation requires full review, locally or on a paired workstation.
    #[serde(default)]
    session_factor: Option<ApprovalFactor>,

    /// Enable the second-device factor: starts the local HTTPS approval
    /// server (+ mDNS) where paired devices fetch and sign challenges.
    #[serde(default)]
    second_device: bool,

    /// Bind address for the approval server. Defaults to `127.0.0.1:7381`;
    /// `127.0.0.1:0` picks a free port.
    #[serde(default)]
    server_bind: Option<String>,

    /// Seconds a device has to answer a challenge (default 60).
    #[serde(default)]
    timeout_secs: Option<u64>,

    /// Enable the FIDO2/passkey factor: hardware keys and platform passkeys
    /// registered with the daemon can approve operations. Assertion
    /// verification is daemon-side; the authenticator ceremony runs in the
    /// client that drives the key.
    #[serde(default)]
    fido2: bool,

    /// WebAuthn relying-party id for FIDO2 (default "opaque.local").
    #[serde(default)]
    fido2_rp_id: Option<String>,
}

impl ApprovalFactorsConfig {
    fn validated_session_factor(&self) -> Result<ApprovalFactor, String> {
        match self.session_factor.unwrap_or(ApprovalFactor::LocalBio) {
            factor @ (ApprovalFactor::LocalBio | ApprovalFactor::PairedWorkstation) => Ok(factor),
            _ => Err("approval.session_factor requires local_bio or paired_workstation".into()),
        }
    }
}

/// `[trust_domain]` — settings for running the daemon as a principal distinct
/// from the agents it polices.
#[derive(Debug, Clone, Deserialize, Default)]
struct TrustDomainConfig {
    /// When true the daemon fails closed at startup unless every custody file
    /// (audit db + chain key, identity db + signing key, config + seal,
    /// pairing store, profiles) is exclusively owned by the daemon's own uid,
    /// and refuses connections from peers running *as* the daemon uid
    /// (nothing legitimate runs as the service account except the daemon).
    #[serde(default)]
    enforce: bool,

    /// Drop privileges to this user at startup when launched as root (the
    /// non-systemd path; under systemd prefer `User=`/`Group=` in the unit).
    #[serde(default)]
    run_as: Option<String>,

    /// Group granted connect access to the socket + read access to the
    /// daemon token in enforce mode. Clients must be members. Without it the
    /// socket keeps owner-only permissions, which at a split uid means no
    /// client can connect — so enforce mode requires it.
    #[serde(default)]
    socket_group: Option<String>,

    /// Explicit socket path for split deployments (e.g. `/run/opaque/opaqued.sock`).
    /// Trusted because it comes from the sealed, custody-verified config —
    /// unlike `$OPAQUE_SOCK`, which the daemon deliberately ignores.
    #[serde(default)]
    socket_path: Option<PathBuf>,

    /// Permit running enforce mode as uid 0. Off by default: a root daemon
    /// cannot be protected from a root agent, and the split loses meaning.
    /// Container entrypoints that cannot set a runAsUser may opt in.
    #[serde(default)]
    allow_root: bool,
}

/// A single entry in the known human clients allowlist.
#[derive(Debug, Clone, Deserialize)]
struct HumanClientEntry {
    /// Human-readable label (for logging).
    name: String,

    /// Glob pattern matched against the exe path.
    exe_path: Option<String>,

    /// Exact SHA-256 hex digest of the executable (case-insensitive).
    exe_sha256: Option<String>,

    /// Exact macOS code-signing Team ID.
    codesign_team_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Daemon state
// ---------------------------------------------------------------------------

/// Build a version string that includes the git SHA: `0.1.0+abc1234`.
const fn version_string() -> &'static str {
    concat!(env!("CARGO_PKG_VERSION"), "+", env!("OPAQUE_GIT_SHA"))
}

/// Flags the daemon answers without starting: returns the exit code to stop
/// with, or `None` to carry on into startup. Unrecognized arguments are left
/// alone — the daemon's real configuration is the config file, and the one
/// other flag it reads is scanned for separately at the point it applies.
fn handle_immediate_flags<I: IntoIterator<Item = String>>(args: I) -> Option<i32> {
    for arg in args {
        match arg.as_str() {
            "--version" | "-V" => {
                println!("opaqued {}", version_string());
                return Some(0);
            }
            "--help" | "-h" => {
                print!("{}", usage_text());
                return Some(0);
            }
            _ => {}
        }
    }
    None
}

/// What `opaqued --help` prints. Deliberately short: the daemon takes almost
/// no arguments, because everything that matters is policy, and policy belongs
/// in a sealed config file rather than in a command line an agent could shape.
fn usage_text() -> String {
    format!(
        "opaqued {version}
The Opaque daemon: policy, approvals, execution, and the audit chain.

USAGE:
    opaqued [OPTIONS]

OPTIONS:
    --allow-unsealed    Start even though the config carries no valid seal.
                        Refused outright when trust-domain enforcement is on.
    -V, --version       Print the version and exit
    -h, --help          Print this help and exit

ENVIRONMENT:
    OPAQUE_CONFIG       Config path (default: ~/.opaque/config.toml)
    XDG_RUNTIME_DIR     Where the socket and daemon token are placed
    RUST_LOG            Log filter (default: info)

Docs: https://opaque.info/
",
        version = version_string()
    )
}

struct DaemonState {
    scope_workflow: Option<Arc<scope_runtime::Runtime>>,
    mcp: Option<Arc<opaque_bounded_work::mcp::Gateway>>,
    /// Immutable attestor binding installed by the Unix listener after privilege drop.
    workload_attestor: opaque_federation_runtime::workload_attest::ListenerAttestor,
    tenant: Option<opaque_tenant::tenant::TenantBoundary>,
    enclave: Arc<Enclave>,
    tasks: Option<Arc<opaque_bounded_work::task_store::TaskStore>>,
    audit: Arc<dyn AuditSink>,
    config: DaemonConfig,
    version: &'static str,
    /// Hex-encoded 32-byte CSPRNG token for handshake authentication.
    daemon_token: String,
    /// Active wrapper sessions keyed by session id.
    agent_sessions: Arc<tokio::sync::RwLock<HashMap<String, AgentSession>>>,
    /// Semaphore to limit maximum concurrent connections.
    connection_semaphore: Arc<tokio::sync::Semaphore>,
    /// Identity runtime, present when `[identity]` is configured.
    identity: Option<Arc<identity::IdentityRuntime>>,
    /// Pairing manager, present when `[approval] second_device` is enabled.
    pairing: Option<Arc<opaque_approval::pairing::PairingManager>>,
    /// Bound address of the approval server, when running.
    approval_server_addr: Option<std::net::SocketAddr>,
    /// FIDO2 approval coordination, present when `[approval] fido2` is enabled.
    fido2: Option<Arc<opaque_approval::factors::Fido2Approvals>>,
    provisioning_challenges: opaque_tenant::provisioning_api::Challenges,
    /// Applied federation bundle context (org, version, teams).
    federation: Arc<opaque_federation_runtime::federation::FederationStatus>,
    /// Attestation service (posture reports; always present).
    attestation: Arc<opaque_federation_runtime::attest::AttestationService>,
}

#[derive(Debug, Clone)]
struct AgentSession {
    session_id: String,
    token: String,
    created_by_uid: u32,
    expires_at: SystemTime,
    label: Option<String>,
    /// Principal binding for this session when identity is configured.
    /// `None` for legacy (pre-identity) hex-token sessions.
    delegation: Option<SessionDelegation>,
}

/// The delegation a session token was minted under. The authoritative copy of
/// these claims is the signed token + the `delegations` store row; this is the
/// in-memory binding used to re-validate liveness on every request.
#[derive(Debug, Clone)]
struct SessionDelegation {
    jti: String,
    sub: PrincipalId,
    act: PrincipalId,
    mode: AccessMode,
    human_session_id: Option<String>,
}

// ---------------------------------------------------------------------------
// EnclaveFacade: the narrow kernel-facing seam `opaque_core` exposes for
// transport/dispatch code (`task_api.rs`, the `github` RPC convenience
// wrapper, and this file's own `provisioning_api.rs`) that either has moved
// out of this binary crate already or depends on this trait to call back
// into it. `provisioning_api.rs`'s RPC dispatch stays here — it is
// irreducibly coupled to the concrete `identity::IdentityRuntime`/
// `DaemonConfig` (see `opaque_tenant::provisioning_api`'s doc comment) — but
// still goes through this trait for `request_control_approval`/
// `resolve_principal_context` so its shared, daemon-state-free half can live
// in `opaque-tenant`. Implemented for `DaemonState` rather than `Enclave`
// alone because `resolve_principal_context` needs `agent_sessions`/
// `identity`/`federation`, which only `DaemonState` owns; the other methods
// simply delegate to the concrete `Enclave`.
// ---------------------------------------------------------------------------

impl EnclaveFacade for DaemonState {
    fn preflight_task(
        &self,
        request: &mut OperationRequest,
        manifest: &opaque_core::task::TaskManifest,
    ) -> Result<(), String> {
        self.enclave.preflight_task(request, manifest)
    }

    fn preflight_task_observation(
        &self,
        base: &OperationRequest,
        manifest: &opaque_core::task::TaskManifest,
    ) -> Result<(), String> {
        self.enclave.preflight_task_observation(base, manifest)
    }

    fn execute(
        &self,
        request: OperationRequest,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = opaque_core::sanitize::SanitizedResponse<
                        opaque_core::sanitize::Sanitized,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(self.enclave.execute(request))
    }

    fn swap_policy(&self, policy: PolicyEngine) -> usize {
        self.enclave.swap_policy(policy)
    }

    fn request_control_approval<'a>(
        &'a self,
        identity: &'a ClientIdentity,
        client_type: ClientType,
        operation_label: &'a str,
        action_description: &'a str,
        reason: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<opaque_core::audit::ApproverIdentity>, String>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.enclave
                .request_control_approval(
                    identity,
                    client_type,
                    operation_label,
                    action_description,
                    reason,
                )
                .await
                .map_err(|e| e.to_string())
        })
    }

    /// Resolve the verified principal context bound to an agent session.
    ///
    /// Promoted from the free function of the same name that used to live
    /// here; every existing call site keeps calling the free function below,
    /// which now just delegates to this trait method.
    fn resolve_principal_context<'a>(
        &'a self,
        session_id: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PrincipalContext>, String>> + Send + 'a>> {
        Box::pin(async move {
            let Some(sid) = session_id else {
                return Ok(None);
            };
            let delegation = {
                let sessions = self.agent_sessions.read().await;
                match sessions.get(sid) {
                    Some(s) if s.expires_at > SystemTime::now() => s.delegation.clone(),
                    Some(_) => return Err("agent session expired".into()),
                    None => return Err("agent session no longer exists".into()),
                }
            };
            let Some(d) = delegation else {
                return Ok(None);
            };
            let Some(rt) = self.identity.as_ref() else {
                return Err("delegated session without an identity runtime".into());
            };

            let now = now_unix();

            let row = rt
                .store
                .get_delegation(&d.jti)
                .map_err(|e| format!("delegation lookup failed: {e}"))?
                .ok_or("delegation record missing")?;
            if row.revoked_at.is_some() {
                return Err("delegation revoked".into());
            }
            if row.expires_at <= now {
                return Err("delegation expired".into());
            }

            let sub_principal = rt
                .store
                .get_principal(&d.sub)
                .map_err(|e| format!("principal lookup failed: {e}"))?
                .ok_or("delegating principal missing")?;
            if sub_principal.disabled {
                return Err("delegating principal disabled".into());
            }
            if !rt.principal_permitted(&sub_principal) {
                return Err(
                    "delegating principal is no longer permitted by identity policy".into(),
                );
            }
            let act_principal = rt
                .store
                .get_principal(&d.act)
                .map_err(|e| format!("principal lookup failed: {e}"))?
                .ok_or("agent principal missing")?;
            if act_principal.disabled {
                return Err("agent principal disabled".into());
            }

            // Delegated / break-glass access is only as alive as the human login
            // session it was granted under.
            if matches!(d.mode, AccessMode::Delegated | AccessMode::BreakGlass) {
                let hs_id = d
                    .human_session_id
                    .as_deref()
                    .ok_or("delegation missing its human session binding")?;
                let hs = rt
                    .store
                    .get_human_session(hs_id)
                    .map_err(|e| format!("session lookup failed: {e}"))?
                    .ok_or("human login session missing")?;
                if hs.revoked_at.is_some() {
                    return Err("human login session revoked".into());
                }
                if hs.expires_at <= now {
                    return Err("human login session expired".into());
                }
                if hs.idp_issuer != rt.config.issuer {
                    return Err("human login session issuer is no longer permitted".into());
                }
                if hs.principal_id != d.sub {
                    return Err("human login session does not match the delegation".into());
                }
            }

            // Team membership comes from the applied federation bundle, resolved
            // daemon-side per request (bundle refresh takes effect immediately).
            let sub_teams = self.federation.teams_of(&sub_principal.display_label());

            Ok(Some(PrincipalContext {
                sub: d.sub.clone(),
                sub_label: sub_principal.display_label(),
                sub_roles: sub_principal.roles.clone(),
                sub_teams,
                act: d.act.clone(),
                act_label: act_principal.display_label(),
                mode: d.mode,
                jti: d.jti.clone(),
                human_session_id: d.human_session_id.clone(),
            }))
        })
    }

    /// Re-verify a workspace claim. Delegates to the free function of the
    /// same name below, which owns the actual bounded-subprocess machinery
    /// (`workspace_process.rs`) — this trait method exists purely so
    /// `opaque-bounded-work`'s `task_api` can invoke it as a live TOCTOU
    /// recheck without depending on `opaqued` directly.
    fn verify_workspace<'a>(
        &'a self,
        claimed: &'a opaque_core::operation::WorkspaceContext,
        client_pid: Option<i32>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(verify_workspace(claimed, client_pid))
    }
}

/// A bare `Enclave` also implements the facade directly, for composition-root
/// code that runs before a `DaemonState` exists — the federation bundle
/// bootstrap (`opaque_federation_runtime::federation::BundleApplier`) applies the initial bundle while
/// only `Arc<Enclave>` is in scope, well before `DaemonState` is built.
///
/// Every method mirrors an inherent `Enclave` method one-for-one (the same
/// ones `DaemonState`'s impl above delegates to via `self.enclave.X(...)`),
/// except `resolve_principal_context`, which needs `DaemonState`-owned
/// agent-session/identity/federation state that a bare `Enclave` does not
/// have; that one fails loudly instead of silently returning `Ok(None)`; the
/// federation bootstrap never calls it.
impl EnclaveFacade for Enclave {
    fn preflight_task(
        &self,
        request: &mut OperationRequest,
        manifest: &opaque_core::task::TaskManifest,
    ) -> Result<(), String> {
        Enclave::preflight_task(self, request, manifest)
    }

    fn preflight_task_observation(
        &self,
        base: &OperationRequest,
        manifest: &opaque_core::task::TaskManifest,
    ) -> Result<(), String> {
        Enclave::preflight_task_observation(self, base, manifest)
    }

    fn execute(
        &self,
        request: OperationRequest,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = opaque_core::sanitize::SanitizedResponse<
                        opaque_core::sanitize::Sanitized,
                    >,
                > + Send
                + '_,
        >,
    > {
        Box::pin(Enclave::execute(self, request))
    }

    fn swap_policy(&self, policy: PolicyEngine) -> usize {
        Enclave::swap_policy(self, policy)
    }

    fn request_control_approval<'a>(
        &'a self,
        identity: &'a ClientIdentity,
        client_type: ClientType,
        operation_label: &'a str,
        action_description: &'a str,
        reason: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<opaque_core::audit::ApproverIdentity>, String>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Enclave::request_control_approval(
                self,
                identity,
                client_type,
                operation_label,
                action_description,
                reason,
            )
            .await
            .map_err(|e| e.to_string())
        })
    }

    fn resolve_principal_context<'a>(
        &'a self,
        _session_id: Option<&'a str>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<PrincipalContext>, String>> + Send + 'a>> {
        Box::pin(async move {
            Err(
                "resolve_principal_context is unavailable on a bare Enclave facade; it needs \
                 DaemonState-owned agent-session/identity/federation state"
                    .to_string(),
            )
        })
    }

    fn verify_workspace<'a>(
        &'a self,
        claimed: &'a opaque_core::operation::WorkspaceContext,
        client_pid: Option<i32>,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        // Same free function as DaemonState's impl above; this method needs
        // no DaemonState-owned state, so unlike resolve_principal_context it
        // isn't a fails-loudly stub.
        Box::pin(verify_workspace(claimed, client_pid))
    }
}

// `default_secret_resolvers()` used to live here (main.rs is the crate's
// composition root); it has been promoted to `opaque_providers` because it
// has zero opaqued-specific dependencies (pure provider-client wiring from
// env vars) and, after the `opaque-bounded-work` extraction, is needed by
// `ssh.rs`/`inference/mod.rs` (now in `opaque-bounded-work`) in addition to
// this file and `opaque_sandbox::SandboxExecutor::new`'s `ResolverFactory`
// fn pointer — `opaque-providers` is the only non-circular common home for
// all three call sites (`opaqued`, `opaque-bounded-work`, and transitively
// `opaque-sandbox` all already depend on it).

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    // The Linux sandbox re-invokes this binary inside bwrap/unshare as the
    // helper that restricts itself and execs the workload. That role is
    // decided on argv[1] before anything else, so a workload argument such
    // as `--help` can never be mistaken for the daemon's own flags.
    #[cfg(target_os = "linux")]
    opaque_sandbox::linux::maybe_run_helper();

    // Answered before anything else starts. `opaqued --version` used to fall
    // through to a full daemon start — binding the socket, verifying custody,
    // taking the PID lock — which is a startling way to find out what you just
    // installed.
    if let Some(code) = handle_immediate_flags(std::env::args().skip(1)) {
        std::process::exit(code);
    }

    init_tracing();

    // Say what sandbox.exec will do on this host before the first request,
    // with the kernel evidence behind it (issue #121: a missing layer must be
    // visible at startup, not discovered as an unexplained exec failure).
    #[cfg(target_os = "linux")]
    opaque_sandbox::linux::log_startup_capabilities();

    // Process-wide rustls provider, installed once up front: the approval
    // server builds a rustls ServerConfig directly, which PANICS if no
    // default provider exists (only reqwest's internal TLS picks one on its
    // own). Err just means something installed it earlier — fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Config is loaded before the async runtime starts because two decisions
    // depend on it while the process is still genuinely single-threaded: the
    // privilege drop (setuid + env repoint must not race other threads) and
    // the socket path for split deployments.
    let config_path = resolve_config_path();
    let config = load_config(&config_path);

    if let Some(user) = config.trust_domain.run_as.clone() {
        if unsafe { libc::geteuid() } == 0 {
            if let Err(e) = trust_domain::drop_privileges(&user) {
                eprintln!("opaqued: privilege drop failed: {e}");
                std::process::exit(1);
            }
        } else {
            info!("trust_domain.run_as set but not starting as root — already dropped, ignoring");
        }
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("opaqued: failed to start runtime: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = runtime.block_on(run(config, config_path)) {
        eprintln!("opaqued: {e}");
        std::process::exit(1);
    }
}

/// Resolve the daemon config path.
///
/// `$OPAQUE_CONFIG` wins when set. Otherwise root reads the system location
/// `/etc/opaque/config.toml` (a root launch precedes a `run_as` drop, and the
/// service account's config must not live in root's home), and a normal user
/// reads `~/.opaque/config.toml`.
fn resolve_config_path() -> PathBuf {
    if let Ok(p) = std::env::var("OPAQUE_CONFIG") {
        return PathBuf::from(p);
    }
    if unsafe { libc::geteuid() } == 0 {
        return PathBuf::from("/etc/opaque/config.toml");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".opaque").join("config.toml")
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Load daemon config from the resolved config path (see [`resolve_config_path`]).
fn load_config(path: &Path) -> DaemonConfig {
    match std::fs::read_to_string(path) {
        Ok(contents) => match toml_edit::de::from_str::<DaemonConfig>(&contents) {
            Ok(mut config) => {
                // Filter out empty human client entries that would match everything.
                let before = config.known_human_clients.len();
                config.known_human_clients.retain(|entry| {
                    let has_criteria = entry.exe_path.is_some()
                        || entry.exe_sha256.is_some()
                        || entry.codesign_team_id.is_some();
                    if !has_criteria {
                        warn!(
                            "ignoring known_human_clients entry '{}': no matching criteria specified",
                            entry.name
                        );
                    }
                    has_criteria
                });
                let filtered = before - config.known_human_clients.len();
                if filtered > 0 {
                    warn!("{filtered} empty human client entries removed from config");
                }
                // Unknown role names in [rules.identity] never match (fail
                // closed) — surface the typo instead of silently denying.
                for rule in &config.rules {
                    if let Some(roles) = &rule.identity.roles {
                        for role in roles {
                            if role.parse::<opaque_core::identity::Role>().is_err() {
                                warn!(
                                    "policy rule '{}' names unknown role {role:?} — \
                                     this rule will never match",
                                    rule.name
                                );
                            }
                        }
                    }
                }
                // N1: a rule can require a client-identity field this
                // platform's connection attestor never populates
                // (codesign_team_id off macOS). Such a rule still loads. It
                // simply never matches a real client, so this warns rather
                // than refusing the load.
                for warning in platform_policy_warnings(
                    &config.rules,
                    codesign_team_id_is_platform_enforceable(),
                ) {
                    warn!("{warning}");
                }
                // N1: the same gap applies to known_human_clients entries.
                // Such an entry still loads. It simply never classifies a
                // connection as human, so this warns rather than refusing
                // the load.
                for warning in known_human_client_platform_warnings(
                    config
                        .known_human_clients
                        .iter()
                        .map(|entry| (entry.name.as_str(), entry.codesign_team_id.is_some())),
                    codesign_team_id_is_platform_enforceable(),
                ) {
                    warn!("{warning}");
                }
                info!(
                    "loaded config from {} ({} known human clients, {} policy rules)",
                    path.display(),
                    config.known_human_clients.len(),
                    config.rules.len(),
                );
                config
            }
            Err(e) => {
                // SECURITY: an unparseable config must be FATAL, never a
                // silent fall-through to defaults. Defaults mean
                // trust_domain.enforce=false, require_seal=false, no policy
                // rules — one typo would quietly dissolve every protection
                // the operator wrote down. A config that exists but cannot
                // be honored stops the daemon.
                eprintln!(
                    "opaqued: refusing to start: config {} exists but failed to parse: {e}",
                    path.display()
                );
                std::process::exit(1);
            }
        },
        Err(_) => {
            info!("no config file at {}, using defaults", path.display());
            DaemonConfig::default()
        }
    }
}

/// Verify the config seal on daemon startup.
///
/// - **Verified** (keyed): proceed normally.
/// - **VerifiedLegacy** (unkeyed): forgeable by anyone who can write the seal
///   file — warn in shared-uid mode, hard stop under `trust_domain.enforce`.
/// - **Unsealed**: no seal found — warn and continue (backward compatible),
///   unless `require_seal` demands one.
/// - **KeyMissing**: keyed seal whose key vanished — hard stop (custody break).
/// - **Tampered**: seal exists but doesn't match — hard stop.
fn verify_config_seal(
    config_path: &Path,
    require_seal: bool,
    allow_unsealed: bool,
    enforce: bool,
    file_only: bool,
) -> std::io::Result<()> {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let seal_file = config_dir.join("config.seal");

    if file_only {
        check_seal_file_only(
            config_path,
            &seal_file,
            require_seal,
            allow_unsealed,
            enforce,
        )
    } else {
        check_seal(
            config_path,
            &seal_file,
            require_seal,
            allow_unsealed,
            enforce,
        )
    }
}

/// The legacy default shared installation retains its keychain fallback.
/// Every explicitly isolated installation verifies only its own seal and key.
fn config_uses_file_seal(config: &DaemonConfig, config_path: &Path, home: &Path) -> bool {
    config.data_dir.is_some()
        || config.tenant.is_some()
        || config.trust_domain.enforce
        || config_path != home.join(".opaque/config.toml")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod seal_scope_tests {
    use super::*;
    #[test]
    fn scoped_installations_use_local_seals_and_preserve_required_custody() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path();
        let mut config = DaemonConfig::default();
        let default = home.join(".opaque/config.toml");
        assert!(!config_uses_file_seal(&config, &default, home));
        let path = home.join("config.toml");
        assert!(config_uses_file_seal(&config, &path, home));
        config.data_dir = Some(home.join("state"));
        assert!(config_uses_file_seal(&config, &default, home));
        config.data_dir = None;
        config.trust_domain.enforce = true;
        assert!(config_uses_file_seal(&config, &default, home));
        std::fs::write(&path, b"fixture config").unwrap();
        assert!(verify_config_seal(&path, true, false, true, true).is_err());
        let seal = home.join("config.seal");
        let key_path = opaque_core::seal::seal_key_path(&seal);
        let key = [73u8; 32];
        std::fs::write(&key_path, key).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            &seal,
            opaque_core::seal::compute_seal_keyed(b"fixture config", &key),
        )
        .unwrap();
        assert!(verify_config_seal(&path, true, false, true, true).is_ok());
        std::fs::write(&path, b"tampered config").unwrap();
        assert!(verify_config_seal(&path, true, true, true, true).is_err());
        std::fs::write(&path, b"fixture config").unwrap();
        std::fs::remove_file(&key_path).unwrap();
        assert!(verify_config_seal(&path, false, true, true, true).is_err());
        std::fs::write(&seal, opaque_core::seal::compute_seal(b"fixture config")).unwrap();
        assert!(verify_config_seal(&path, true, false, true, true).is_err());
    }
}

/// Core seal-check logic, separated from env-var resolution for testability.
///
/// Uses keychain + file verification in production. Tests should call
/// `check_seal_file_only` to avoid dependence on system keychain state.
fn check_seal(
    config_path: &Path,
    seal_file: &Path,
    require_seal: bool,
    allow_unsealed: bool,
    enforce: bool,
) -> std::io::Result<()> {
    // If config doesn't exist, nothing to verify (load_config handles defaults).
    if !config_path.exists() {
        return Ok(());
    }

    let config_bytes = std::fs::read(config_path)?;
    let status = opaque_core::seal::verify_seal(&config_bytes, seal_file)
        .map_err(|e| std::io::Error::other(format!("config seal check failed: {e}")))?;
    evaluate_seal_status(status, require_seal, allow_unsealed, enforce)
}

/// File-only verification for independently custodied installations.
/// The global OS keychain entry belongs only to the default shared installation;
/// it cannot supply authority for another tenant or explicit config location.
fn check_seal_file_only(
    config_path: &Path,
    seal_file: &Path,
    require_seal: bool,
    allow_unsealed: bool,
    enforce: bool,
) -> std::io::Result<()> {
    if !config_path.exists() {
        return Ok(());
    }

    let config_bytes = std::fs::read(config_path)?;
    let status = opaque_core::seal::verify_seal_from_file(&config_bytes, seal_file)
        .map_err(|e| std::io::Error::other(format!("config seal check failed: {e}")))?;
    evaluate_seal_status(status, require_seal, allow_unsealed, enforce)
}

/// Shared policy over a seal verification outcome (see [`verify_config_seal`]).
fn evaluate_seal_status(
    status: opaque_core::seal::SealStatus,
    require_seal: bool,
    allow_unsealed: bool,
    enforce: bool,
) -> std::io::Result<()> {
    use opaque_core::seal::SealStatus;

    match status {
        SealStatus::Verified => {
            info!("config seal verified (keyed)");
        }
        SealStatus::VerifiedLegacy => {
            if enforce {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "config carries a legacy UNKEYED seal, which any config writer can \
                     forge — trust_domain.enforce requires the keyed seal. \
                     Re-seal with 'opaque setup --seal'.",
                ));
            }
            warn!(
                "config seal is the legacy unkeyed format (drift detection only) — \
                 re-seal with 'opaque setup --seal' to upgrade to the keyed seal"
            );
        }
        SealStatus::Unsealed => {
            if require_seal && !allow_unsealed {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "config is unsealed but require_seal is enabled. \
                     Seal your config with 'opaque setup --seal' or \
                     start the daemon with '--allow-unsealed' for development use.",
                ));
            }
            if allow_unsealed {
                warn!("config is unsealed — continuing because --allow-unsealed was passed");
            } else {
                warn!("config is unsealed — run 'opaque setup --seal' to protect it");
            }
        }
        SealStatus::KeyMissing => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "config has a keyed seal but the seal key (config.seal.key) is missing — \
                 the custody of the seal is broken. Restore the key, or re-seal with \
                 'opaque setup --reset' then 'opaque setup --seal'.",
            ));
        }
        SealStatus::Tampered { .. } => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "config seal broken — config.toml was modified after sealing. \
                 Run 'opaque setup --reset' to unseal, then reconfigure.",
            ));
        }
    }

    Ok(())
}

/// Generate a 32-byte CSPRNG hex token for daemon authentication.
fn generate_daemon_token() -> String {
    let mut buf = [0u8; 32];
    getrandom::fill(&mut buf).expect("failed to generate random bytes");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Write the daemon token to `<socket_dir>/daemon.token` with mode 0600.
fn write_daemon_token(socket: &Path, token: &str) -> std::io::Result<PathBuf> {
    let token_path = socket
        .parent()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "socket path has no parent directory",
            )
        })?
        .join(DAEMON_TOKEN_FILENAME);
    std::fs::write(&token_path, token.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(token_path)
}

/// Minimal no-op operation handler for end-to-end testing of the enclave pipeline.
#[derive(Debug)]
struct NoopHandler;

impl OperationHandler for NoopHandler {
    fn prepare<'a>(
        &'a self,
        request: &OperationRequest,
    ) -> Result<opaque_core::operation_handler::PreparedOperation<'a>, String> {
        if !request.params.is_null()
            && !request
                .params
                .as_object()
                .is_some_and(|params| params.is_empty())
        {
            return Err("test.noop takes no parameters".into());
        }
        opaque_core::operation_handler::PreparedOperation::new(
            serde_json::json!({"action":"test.noop.v1"}),
            HashMap::new(),
            vec![],
            |_| async { Ok(serde_json::json!({"status":"ok"})) },
        )
    }
}

/// Disable core dumps to prevent secret material from being written to disk.
///
/// Called early in daemon startup, before any secrets are loaded.
fn init_memory_safety() {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        if ret == 0 {
            info!("core dumps disabled (PR_SET_DUMPABLE=0)");
        } else {
            warn!("failed to disable core dumps via PR_SET_DUMPABLE");
        }
    }
    #[cfg(target_os = "macos")]
    {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        if ret == 0 {
            info!("core dumps disabled (RLIMIT_CORE=0)");
        } else {
            warn!("failed to disable core dumps via RLIMIT_CORE");
        }
    }
}

/// Complete operation inventory shared by startup and coverage regressions.
fn operation_registry() -> std::io::Result<OperationRegistry> {
    let mut registry = OperationRegistry::new();
    registry
        .register(OperationDef {
            name: "test.noop".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "No-op test operation".into(),
            params_schema: None,
            allowed_target_keys: vec![],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "sandbox.exec".into(),
            // SECURITY (C2): SensitiveOutput re-engages the enclave + policy gates
            // that deny agent access unless a rule explicitly allows it. Restored
            // after 2fd20b8 re-added stdout/stderr without restoring the class.
            safety: OperationSafety::SensitiveOutput,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Execute a command in a sandboxed environment".into(),
            params_schema: None,
            allowed_target_keys: vec!["profile".into(), "command".into(), "profile_sha256".into()],
            secret_ref_param_keys: vec!["profile".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "github.set_actions_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Actions repository secret".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["repo", "secret_name", "value_ref"],
                "properties": {
                    "repo": {"type": "string"},
                    "secret_name": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "github_token_ref": {"type": "string"},
                    "environment": {"type": "string"}
                }
            })),
            allowed_target_keys: vec![
                "repo".into(),
                "secret_name".into(),
                "environment".into(),
                "scope".into(),
                "scope_kind".into(),
                "github_api_url".into(),
            ],
            secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "github.set_codespaces_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Codespaces secret (user or repo level)".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["secret_name", "value_ref"],
                "properties": {
                    "secret_name": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "repo": {"type": "string"},
                    "github_token_ref": {"type": "string"},
                    "selected_repository_ids": {"type": "array", "items": {"type": "integer"}}
                }
            })),
            allowed_target_keys: vec![
                "repo".into(),
                "secret_name".into(),
                "scope".into(),
                "scope_kind".into(),
                "visibility".into(),
                "selected_repository_ids".into(),
                "github_api_url".into(),
            ],
            secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "github.set_dependabot_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Dependabot repository secret".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["repo", "secret_name", "value_ref"],
                "properties": {
                    "repo": {"type": "string"},
                    "secret_name": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "github_token_ref": {"type": "string"}
                }
            })),
            allowed_target_keys: vec![
                "repo".into(),
                "secret_name".into(),
                "scope".into(),
                "scope_kind".into(),
                "github_api_url".into(),
            ],
            secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "github.set_org_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitHub Actions organization secret".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["org", "secret_name", "value_ref"],
                "properties": {
                    "org": {"type": "string"},
                    "secret_name": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "github_token_ref": {"type": "string"},
                    "visibility": {"type": "string", "enum": ["all", "private", "selected"]},
                    "selected_repository_ids": {"type": "array", "items": {"type": "integer"}}
                }
            })),
            allowed_target_keys: vec![
                "org".into(),
                "secret_name".into(),
                "scope".into(),
                "scope_kind".into(),
                "visibility".into(),
                "selected_repository_ids".into(),
                "github_api_url".into(),
            ],
            secret_ref_param_keys: vec!["value_ref".into(), "github_token_ref".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "github.list_secrets".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List GitHub secret names for a repository, environment, or org".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "scope": {"type": "string", "enum": ["actions", "codespaces", "dependabot", "org"]},
                    "repo": {"type": "string"},
                    "org": {"type": "string"},
                    "environment": {"type": "string"},
                    "github_token_ref": {"type": "string"}
                }
            })),
            allowed_target_keys: vec!["repo".into(), "org".into(), "environment".into(), "scope".into(), "scope_kind".into(), "github_api_url".into()],
            secret_ref_param_keys: vec!["github_token_ref".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "github.delete_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Delete a GitHub secret from a repository, environment, or org".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["secret_name"],
                "properties": {
                    "scope": {"type": "string", "enum": ["actions", "codespaces", "dependabot", "org"]},
                    "secret_name": {"type": "string"},
                    "repo": {"type": "string"},
                    "org": {"type": "string"},
                    "environment": {"type": "string"},
                    "github_token_ref": {"type": "string"}
                }
            })),
            allowed_target_keys: vec!["repo".into(), "org".into(), "environment".into(), "secret_name".into(), "scope".into(), "scope_kind".into(), "github_api_url".into()],
            secret_ref_param_keys: vec!["github_token_ref".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "gitlab.set_ci_variable".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Set a GitLab CI/CD variable for a project".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["project", "key", "value_ref"],
                "properties": {
                    "project": {"type": "string"},
                    "key": {"type": "string"},
                    "value_ref": {"type": "string"},
                    "gitlab_token_ref": {"type": "string"},
                    "environment_scope": {"type": "string"},
                    "protected": {"type": "boolean"},
                    "masked": {"type": "boolean"},
                    "raw": {"type": "boolean"},
                    "variable_type": {"type": "string", "enum": ["env_var", "file"]}
                }
            })),
            allowed_target_keys: vec![
                "project".into(),
                "key".into(),
                "environment_scope".into(),
                "protected".into(),
                "masked".into(),
                "raw".into(),
                "variable_type".into(),
                "gitlab_api_url".into(),
            ],
            secret_ref_param_keys: vec!["value_ref".into(), "gitlab_token_ref".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "onepassword.list_vaults".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List available 1Password vaults".into(),
            params_schema: None,
            allowed_target_keys: vec![
                "onepassword_backend".into(),
                "onepassword_api_url".into(),
                "onepassword_cli_path".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "onepassword.read_field".into(),
            safety: OperationSafety::Reveal,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Read a single field value from a 1Password item".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["vault", "item", "field"],
                "properties": {
                    "vault": {"type": "string"},
                    "item": {"type": "string"},
                    "field": {"type": "string"}
                }
            })),
            allowed_target_keys: vec![
                "vault".into(),
                "item".into(),
                "field".into(),
                "onepassword_backend".into(),
                "onepassword_api_url".into(),
                "onepassword_cli_path".into(),
            ],
            secret_ref_param_keys: vec!["onepassword:{vault}/{item}/{field}".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "onepassword.list_items".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List items in a 1Password vault".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["vault"],
                "properties": { "vault": {"type": "string"} }
            })),
            allowed_target_keys: vec![
                "vault".into(),
                "onepassword_backend".into(),
                "onepassword_api_url".into(),
                "onepassword_cli_path".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "bitwarden.list_projects".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List available Bitwarden Secrets Manager projects".into(),
            params_schema: None,
            allowed_target_keys: vec![
                "bitwarden_api_url".into(),
                "bitwarden_identity_url".into(),
                "bitwarden_cli_sha256".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "bitwarden.list_secrets".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List secrets in a Bitwarden Secrets Manager project".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "properties": { "project": {"type": "string"} }
            })),
            allowed_target_keys: vec![
                "project".into(),
                "bitwarden_api_url".into(),
                "bitwarden_identity_url".into(),
                "bitwarden_cli_sha256".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "bitwarden.read_secret".into(),
            safety: OperationSafety::Reveal,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Read a secret value from Bitwarden Secrets Manager".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["secret_id"],
                "properties": { "secret_id": {"type": "string"} }
            })),
            allowed_target_keys: vec![
                "secret_id".into(),
                "bitwarden_api_url".into(),
                "bitwarden_identity_url".into(),
                "bitwarden_cli_sha256".into(),
            ],
            secret_ref_param_keys: vec!["secret_id".into()],
        })
        .map_err(std::io::Error::other)?;

    for operation in opaque_providers::gcp::operations()
        .into_iter()
        .chain(opaque_providers::azure::operations())
    {
        registry
            .register(operation)
            .map_err(std::io::Error::other)?;
    }

    // AWS STS operations
    registry
        .register(OperationDef {
            name: "aws.get_caller_identity".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Get the AWS caller identity (account, ARN, user ID)".into(),
            params_schema: None,
            allowed_target_keys: vec![
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "aws.assume_role".into(),
            safety: OperationSafety::SensitiveOutput,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Assume an AWS IAM role and get temporary credentials".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["role_arn"],
                "properties": {
                    "role_arn": {"type": "string"},
                    "session_name": {"type": "string"}
                }
            })),
            allowed_target_keys: vec![
                "role_arn".into(),
                "session_name".into(),
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    // AWS Secrets Manager operations
    registry
        .register(OperationDef {
            name: "aws.list_secrets".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List AWS Secrets Manager secret names".into(),
            params_schema: None,
            allowed_target_keys: vec![
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "aws.get_secret_value".into(),
            safety: OperationSafety::Reveal,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Read a secret value from AWS Secrets Manager".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["secret_id"],
                "properties": { "secret_id": {"type": "string"} }
            })),
            allowed_target_keys: vec![
                "secret_id".into(),
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec!["secret_id".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "aws.create_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Create a new secret in AWS Secrets Manager".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["name", "value"],
                "properties": {
                    "name": {"type": "string"},
                    "value": {"type": "string"},
                    "description": {"type": "string"}
                }
            })),
            allowed_target_keys: vec![
                "name".into(),
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "aws.put_secret_value".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Update an existing AWS Secrets Manager secret value".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["secret_id", "value"],
                "properties": {
                    "secret_id": {"type": "string"},
                    "value": {"type": "string"}
                }
            })),
            allowed_target_keys: vec![
                "secret_id".into(),
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "aws.delete_secret".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Schedule an AWS Secrets Manager secret for deletion".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["secret_id"],
                "properties": { "secret_id": {"type": "string"} }
            })),
            allowed_target_keys: vec![
                "secret_id".into(),
                "force_delete_without_recovery".into(),
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    // AWS SSM Parameter Store operations
    registry
        .register(OperationDef {
            name: "aws.get_parameter".into(),
            safety: OperationSafety::Reveal,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Read a parameter from AWS SSM Parameter Store".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["name"],
                "properties": { "name": {"type": "string"} }
            })),
            allowed_target_keys: vec![
                "name".into(),
                "with_decryption".into(),
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec!["name".into()],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "aws.put_parameter".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Write a parameter to AWS SSM Parameter Store".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["name", "value"],
                "properties": {
                    "name": {"type": "string"},
                    "value": {"type": "string"},
                    "type": {"type": "string"},
                    "overwrite": {"type": "boolean"}
                }
            })),
            allowed_target_keys: vec![
                "name".into(),
                "type".into(),
                "overwrite".into(),
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "aws.get_parameters_by_path".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::FirstUse,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "List parameters under a path in AWS SSM Parameter Store".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": {"type": "string"},
                    "with_decryption": {"type": "boolean"}
                }
            })),
            allowed_target_keys: vec![
                "path".into(),
                "with_decryption".into(),
                "recursive".into(),
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "aws.delete_parameter".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Always,
            default_factors: vec![ApprovalFactor::LocalBio],
            description: "Delete a parameter from AWS SSM Parameter Store".into(),
            params_schema: Some(serde_json::json!({
                "type": "object",
                "required": ["name"],
                "properties": { "name": {"type": "string"} }
            })),
            allowed_target_keys: vec![
                "name".into(),
                "aws_region".into(),
                "aws_backend".into(),
                "aws_api_url".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    // Sandbox execve policy hook operations.
    registry
        .register(OperationDef {
            name: "sandbox.execve_check".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Never,
            default_factors: vec![],
            description: "Evaluate an execve against policy".into(),
            params_schema: None,
            allowed_target_keys: vec![
                "executable".into(),
                "command".into(),
                "cwd".into(),
                "sandbox_id".into(),
                "env_keys".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(OperationDef {
            name: "sandbox.execve_approve".into(),
            safety: OperationSafety::Safe,
            default_approval: ApprovalRequirement::Never,
            default_factors: vec![],
            description: "Complete an execve approval".into(),
            params_schema: None,
            allowed_target_keys: vec![
                "approval_id".into(),
                "decision".into(),
                "lease_for_pattern".into(),
                "command".into(),
                "sandbox_id".into(),
                "pattern".into(),
            ],
            secret_ref_param_keys: vec![],
        })
        .map_err(std::io::Error::other)?;

    registry
        .register(enclave::mcp_operation())
        .map_err(std::io::Error::other)?;
    registry
        .register(enclave::task_operation())
        .map_err(std::io::Error::other)?;
    for operation in enclave::release_task_operations()
        .into_iter()
        .chain(enclave::inference_task_operations())
        .chain(enclave::ssh_task_operations())
    {
        registry
            .register(operation)
            .map_err(std::io::Error::other)?;
    }
    Ok(registry)
}

/// Outcome of the H-8 macOS startup session preflight (see
/// [`local_auth_preflight`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionAuthPreflight {
    /// This deployment never needs the session to authenticate locally:
    /// either the session factor is an out-of-band one (`paired_workstation`,
    /// on the way to `fido2`/`ios_faceid` for individual operations), or
    /// `trust_domain.enforce` is on and pairs with those out-of-band factors
    /// by design (see docs/deployment.md, "Approval factors in split mode").
    NotGated,
    /// `local_bio` is the configured session factor, trust-domain enforcement
    /// is off, and the probe confirms this session can authenticate locally.
    GatedOk,
    /// `local_bio` is the configured session factor, trust-domain enforcement
    /// is off, and the probe says this session never can: fail closed.
    Fatal,
}

/// Pure gating decision for the H-8 preflight, kept free of I/O so the full
/// truth table is unit-testable without a real GUI session: `probe` is the
/// (possibly injected) outcome of the `canEvaluatePolicy` capability check.
fn session_auth_preflight_decision(
    local_bio_configured: bool,
    trust_domain_enforced: bool,
    probe: Result<(), opaque_native_approval::ApprovalError>,
) -> SessionAuthPreflight {
    if !local_bio_configured || trust_domain_enforced {
        return SessionAuthPreflight::NotGated;
    }
    match probe {
        Ok(()) => SessionAuthPreflight::GatedOk,
        Err(_) => SessionAuthPreflight::Fatal,
    }
}

/// H-8: refuse to start when this session is configured to require local
/// biometric/password approval (`approval.session_factor` defaults to
/// `local_bio`) but can never satisfy it — e.g. a LaunchDaemon or SSH session
/// with no window server. Split deployments and out-of-band session factors
/// are exempt: see docs/deployment.md, "Session Detection (Daemon Startup)".
/// The existing per-prompt fail-closed check (`canEvaluatePolicy` on every
/// approval) is unaffected by this startup-only gate.
fn local_auth_preflight(
    session_factor: ApprovalFactor,
    trust_domain_enforced: bool,
    probe: Result<(), opaque_native_approval::ApprovalError>,
) -> std::io::Result<()> {
    match session_auth_preflight_decision(
        session_factor == ApprovalFactor::LocalBio,
        trust_domain_enforced,
        probe,
    ) {
        SessionAuthPreflight::Fatal => Err(std::io::Error::other(
            "opaqued refuses to start: this session cannot complete local device \
             authentication (canEvaluatePolicy failed), and approval.session_factor \
             is local_bio with trust_domain.enforce off. Run opaqued as a LaunchAgent \
             inside an active GUI session, set approval.session_factor to \
             paired_workstation, or enable trust_domain.enforce with an out-of-band \
             factor for a split deployment. See docs/deployment.md.",
        )),
        SessionAuthPreflight::NotGated | SessionAuthPreflight::GatedOk => Ok(()),
    }
}

async fn run(config: DaemonConfig, config_path: PathBuf) -> std::io::Result<()> {
    if config.scope_workflow.is_some() && config.authority_policy.is_some() {
        return Err(std::io::Error::other(
            "scope_workflow and authority_policy cannot coexist",
        ));
    }
    if config.legacy_scim.is_some() {
        return Err(std::io::Error::other(
            "legacy [scim] configuration requires explicit migration to the managed lifecycle adapter; refusing unmanaged startup",
        ));
    }
    init_memory_safety();

    let session_approval_factor = config
        .approval
        .validated_session_factor()
        .map_err(|message| std::io::Error::new(std::io::ErrorKind::InvalidInput, message))?;
    local_auth_preflight(
        session_approval_factor,
        config.trust_domain.enforce,
        opaque_native_approval::session_supports_local_authentication(),
    )?;

    // --- Trust domain: verify custody BEFORE opening or creating any state ---
    let td = &config.trust_domain;
    if td.enforce {
        if unsafe { libc::geteuid() } == 0 && !td.allow_root {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "trust_domain.enforce with euid 0: a root daemon cannot be protected from a \
                 root agent. Run as a dedicated service account (systemd User=, run_as, or a \
                 container runAsUser) — or set trust_domain.allow_root = true to override.",
            ));
        }
        if td.socket_group.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "trust_domain.enforce requires trust_domain.socket_group: with the socket \
                 owner-only and the daemon under its own uid, no client could ever connect. \
                 Create a client group (e.g. groupadd opaque-clients) and name it here.",
            ));
        }
    }
    // Resolve the client group before touching the filesystem so a typo'd
    // group name fails the startup, not the post-bind chgrp — and verify the
    // daemon can actually assign it (non-root owners may chgrp only to their
    // own supplementary groups).
    let socket_gid = td
        .socket_group
        .as_deref()
        .map(trust_domain::resolve_gid)
        .transpose()?;
    if let (Some(gid), Some(label)) = (socket_gid, td.socket_group.as_deref()) {
        trust_domain::require_socket_group_membership(gid, label)?;
    }

    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let state_dir = config
        .data_dir
        .clone()
        .unwrap_or_else(|| home.join(".opaque"));
    if !state_dir.is_absolute() {
        return Err(std::io::Error::other("data_dir must be an absolute path"));
    }
    if config.data_dir.is_some() {
        validate_path_chain(&state_dir)?;
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir.join("approval"))?;
    }

    // Materialize the state directory owner-only BEFORE verifying custody:
    // otherwise a fresh install has nothing to check here, and whichever
    // subsystem creates it later does so with the process umask (0755) —
    // leaving the custody root group/world-traversable until the next
    // restart, which is exactly the window enforcement is meant to close.
    {
        if !state_dir.exists() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&state_dir)?;
        }
    }

    let custody_violations =
        trust_domain::startup_custody_check_at(td.enforce, &home, &config_path, &state_dir)?;

    // Check if --allow-unsealed was passed on the command line.
    let allow_unsealed = std::env::args().any(|a| a == "--allow-unsealed");

    // Verify config seal before proceeding.
    verify_config_seal(
        &config_path,
        config.require_seal,
        allow_unsealed,
        td.enforce,
        config_uses_file_seal(&config, &config_path, &home),
    )?;

    // Bind custody before any identity, ledger, or provider state is opened.
    validate_tenant_startup(&config, &state_dir).map_err(std::io::Error::other)?;
    let tenant = config
        .tenant
        .as_ref()
        .map(|tenant_config| {
            opaque_tenant::tenant::TenantBoundary::open(tenant_config, &state_dir, td.enforce)
        })
        .transpose()
        .map_err(std::io::Error::other)?;
    let inference_profile = config
        .inference
        .as_ref()
        .map(|profile| {
            let boundary = tenant
                .as_ref()
                .ok_or("inference requires a tenant-bound broker")?;
            profile.bind(boundary.binding())
        })
        .transpose()
        .map_err(std::io::Error::other)?;

    let ssh_profile = config
        .ssh
        .as_ref()
        .map(|profile| {
            let boundary = tenant
                .as_ref()
                .ok_or("SSH requires a tenant-bound broker")?;
            profile.bind(boundary.binding())
        })
        .transpose()
        .map_err(std::io::Error::other)?;

    // --- Socket surface ---
    // Split deployments name an explicit socket path in the sealed config
    // (e.g. /run/opaque/opaqued.sock); the daemon still never trusts
    // $OPAQUE_SOCK from the environment.
    let socket = td
        .socket_path
        .clone()
        .or_else(|| {
            config
                .data_dir
                .as_ref()
                .map(|dir| dir.join("run/opaqued.sock"))
        })
        .unwrap_or_else(|| socket_path_for_client(false));
    ensure_socket_parent_dir(&socket)?;

    // Validate no symlinks in the path chain before writing anything into
    // it: the pid file, the stale-socket handling, and the bind below all
    // trust this chain.
    validate_path_chain(&socket)?;

    // Acquire PID file lock before anything else.
    let pid_path = socket
        .parent()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "socket path has no parent directory",
            )
        })?
        .join("opaqued.pid");
    let _pid_guard = PidFileGuard::acquire(pid_path)?;

    if socket.exists() {
        match UnixStream::connect(&socket).await {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("socket already in use: {}", socket.display()),
                ));
            }
            Err(_) => {
                // Stale socket file.
                tokio::fs::remove_file(&socket).await?;
            }
        }
    }

    // SECURITY (C-6): bind under a temporary 0o177 umask so the socket file
    // is 0600 from birth; it never exists with a mode any other process
    // could connect through. Split deployments widen it to the client group
    // only after the full surface is prepared (apply_socket_group below).
    let listener = {
        let std_listener = bind_unix_listener_private(&socket)?;
        std_listener.set_nonblocking(true)?;
        UnixListener::from_std(std_listener)?
    };
    let workload_attestor =
        opaque_federation_runtime::workload_attest::ListenerAttestor::unix_listener();
    lock_down_socket_path(&socket)?;
    let _socket_guard = SocketGuard::new(socket.clone());

    // Generate and write daemon token for handshake authentication.
    let daemon_token = generate_daemon_token();
    let token_path = write_daemon_token(&socket, &daemon_token)?;
    info!("daemon token written to {}", token_path.display());

    // Open the cross-domain surface last: everything above was created
    // owner-only, and only now does the client group gain access to exactly
    // the socket dir (0750), the socket (0660), and the token (0640).
    if let Some(gid) = socket_gid {
        let socket_dir = socket.parent().expect("checked above");
        trust_domain::apply_socket_group(socket_dir, &socket, &token_path, gid)?;
        info!(
            "socket surface opened to group {} (gid {gid})",
            td.socket_group.as_deref().unwrap_or("?"),
        );
    }

    info!("listening on {}", socket.display());

    let registry = operation_registry()?;
    let policy = PolicyEngine::with_rules(config.rules.clone());
    info!("policy engine loaded with {} rules", policy.rule_count());

    let tracing_sink: Arc<dyn AuditSink> = Arc::new(TracingAuditEmitter::new());
    let audit_db_path = state_dir.join("audit.db");
    let tasks = if config.enable_task_grants {
        Some(Arc::new(
            match tenant.as_ref() {
                Some(boundary) => opaque_bounded_work::task_store::TaskStore::open_for_tenant(
                    &state_dir.join("tasks.db"),
                    Some(boundary.binding().clone()),
                ),
                None => {
                    opaque_bounded_work::task_store::TaskStore::open(&state_dir.join("tasks.db"))
                }
            }
            .map_err(|e| std::io::Error::other(format!("task ledger unavailable: {e}")))?,
        ))
    } else {
        None
    };
    let retention_days = config.audit_retention_days.unwrap_or(90);
    let sqlite_sink: Arc<dyn AuditSink> = Arc::new(
        SqliteAuditSink::new(audit_db_path.clone(), retention_days)
            .map_err(|e| std::io::Error::other(format!("failed to open audit database: {e}")))?,
    );
    info!(
        "audit database at {} (retention: {} days)",
        audit_db_path.display(),
        retention_days
    );

    // Recheck the read-only verification path before accepting requests. The
    // sink also verifies before migration/retention. Integrity failures stop
    // startup; operators must preserve and investigate the original evidence.
    match opaque_core::audit::verify_audit_chain(&audit_db_path) {
        Ok(v) if v.ok => {
            info!("audit chain verified ({} records)", v.records_checked);
        }
        Ok(v) => {
            return Err(std::io::Error::other(format!(
                "audit chain integrity failure: {}",
                v.detail.as_deref().unwrap_or("chain mismatch")
            )));
        }
        Err(e) => {
            return Err(std::io::Error::other(format!(
                "could not verify audit chain at startup: {e}"
            )));
        }
    }
    let audit: Arc<dyn AuditSink> = Arc::new(MultiAuditSink::new(vec![tracing_sink, sqlite_sink]));

    // Record the trust-domain posture in the tamper-evident chain itself, so
    // "was the split enforced at the time?" is answerable from the audit log.
    {
        let enforced = config.trust_domain.enforce;
        let detail = if custody_violations.is_empty() {
            format!(
                "trust domain {}: custody clean",
                if enforced { "ENFORCED" } else { "not enforced" }
            )
        } else {
            format!(
                "trust domain not enforced: {} custody violation(s) — {}",
                custody_violations.len(),
                custody_violations
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        };
        let level = if enforced && custody_violations.is_empty() {
            opaque_core::audit::AuditLevel::Info
        } else {
            opaque_core::audit::AuditLevel::Warn
        };
        audit.emit(
            AuditEvent::new(AuditEventKind::TrustDomainPosture)
                .with_operation("daemon_startup")
                .with_outcome(if enforced { "enforced" } else { "shared_uid" })
                .with_level(level)
                .with_detail(detail),
        );
    }

    if identity::lifecycle::persisted_lifecycle(&state_dir).map_err(std::io::Error::other)?
        && (config.lifecycle.is_none()
            || !config
                .identity
                .as_ref()
                .is_some_and(|identity| identity.required))
    {
        return Err(std::io::Error::other(
            "persisted managed lifecycle requires lifecycle and required identity configuration; explicit offline migration required",
        ));
    }

    // Identity substrate (Phase 1): initialize when `[identity]` is present.
    // A broken identity config fails the daemon only when `required = true`
    // (fail closed where identity gates operations); otherwise it degrades to
    // identity-disabled with a loud warning.
    let identity_runtime = match config.identity.clone() {
        None => None,
        Some(id_config) => {
            let required = id_config.required;
            let state_dir = audit_db_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            match identity::IdentityRuntime::initialize(id_config, &state_dir) {
                Ok(rt) => Some(Arc::new(rt.with_audit(audit.clone()))),
                Err(e) if required => {
                    return Err(std::io::Error::other(format!(
                        "identity is required but failed to initialize: {e}"
                    )));
                }
                Err(e) => {
                    tracing::error!(
                        "identity disabled: failed to initialize identity runtime: {e}"
                    );
                    None
                }
            }
        }
    };

    if config.lifecycle.is_none()
        && identity_runtime.as_ref().is_some_and(|runtime| {
            runtime
                .store
                .lifecycle_revision()
                .map_or(true, |revision| revision > 0)
        })
    {
        return Err(std::io::Error::other(
            "persisted managed lifecycle requires its configured ingress; explicit offline migration required",
        ));
    }
    let _lifecycle_listener = if let Some(lifecycle_config) = config.lifecycle.clone() {
        if !config.require_seal || !td.enforce {
            return Err(std::io::Error::other(
                "Managed lifecycle requires sealed configuration and isolated tenant custody",
            ));
        }
        let runtime = identity_runtime
            .clone()
            .ok_or_else(|| std::io::Error::other("Managed lifecycle requires identity"))?;
        let binding = tenant
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Managed lifecycle requires a tenant binding"))?
            .binding()
            .clone();
        Some(
            identity::lifecycle::start(lifecycle_config, runtime, binding, &state_dir)
                .await
                .map_err(std::io::Error::other)?,
        )
    } else {
        None
    };

    provisioning_api::initialize(
        &config,
        identity_runtime.as_deref(),
        tenant.as_ref().map(|t| t.binding()),
    )
    .map_err(std::io::Error::other)?;

    let resource_authority = config
        .resource_authority
        .clone()
        .map(|resource_config| {
            let runtime = identity_runtime.clone().ok_or_else(|| {
                std::io::Error::other("resource authority requires broker identity")
            })?;
            let authority = opaque_bounded_work::resource_authority::ResourceAuthority::new(
                resource_config,
                runtime as Arc<dyn opaque_bounded_work::resource_authority::IdentityAuthority>,
                tenant.as_ref().map(|boundary| boundary.binding()),
                config.provisioning.is_some(),
            )
            .map_err(std::io::Error::other)?;
            let listener = authority.bind()?;
            Ok::<_, std::io::Error>((authority, listener))
        })
        .transpose()?;

    let sandbox_executor = opaque_sandbox::SandboxExecutor::new(
        audit.clone(),
        opaque_providers::default_secret_resolvers,
    );

    // Execve policy hook handlers.
    let execve_mapper = Arc::new(ExecveMapper::new(
        config.execve_rules.clone(),
        config.execve_default.clone(),
    ));
    info!(
        "execve mapper loaded with {} rules (default: {:?})",
        execve_mapper.rule_count(),
        config.execve_default.decision,
    );
    let (execve_check_handler, execve_approve_handler) =
        opaque_sandbox::execve_hook::create_execve_handlers(audit.clone(), execve_mapper);

    let github_actions_handler = opaque_providers::github::GitHubHandler::new(audit.clone())
        .map_err(std::io::Error::other)?;
    let github_codespaces_handler = opaque_providers::github::GitHubHandler::new(audit.clone())
        .map_err(std::io::Error::other)?;
    let github_dependabot_handler = opaque_providers::github::GitHubHandler::new(audit.clone())
        .map_err(std::io::Error::other)?;
    let github_org_handler = opaque_providers::github::GitHubHandler::new(audit.clone())
        .map_err(std::io::Error::other)?;
    let github_list_handler = opaque_providers::github::GitHubHandler::new(audit.clone())
        .map_err(std::io::Error::other)?;
    let github_delete_handler = opaque_providers::github::GitHubHandler::new(audit.clone())
        .map_err(std::io::Error::other)?;
    let gitlab_handler = opaque_providers::gitlab::GitLabHandler::new(audit.clone())
        .map_err(std::io::Error::other)?;

    // 1Password handler: prefer Connect Server URL, fall back to `op` CLI.
    let onepassword_connect_url =
        std::env::var(opaque_providers::onepassword::client::CONNECT_URL_ENV).unwrap_or_default();

    let mut enclave_builder = Enclave::builder()
        .task_grants_enabled(tasks.is_some())
        .inference_profile(inference_profile)
        .ssh_profile(ssh_profile)
        .session_approval_factor(session_approval_factor)
        .registry(registry)
        .policy(policy)
        .handler("test.noop", Box::new(NoopHandler))
        .handler("sandbox.exec", Box::new(sandbox_executor))
        .handler("sandbox.execve_check", Box::new(execve_check_handler))
        .handler("sandbox.execve_approve", Box::new(execve_approve_handler))
        .handler(
            "github.set_actions_secret",
            Box::new(github_actions_handler),
        )
        .handler(
            "github.set_codespaces_secret",
            Box::new(github_codespaces_handler),
        )
        .handler(
            "github.set_dependabot_secret",
            Box::new(github_dependabot_handler),
        )
        .handler("github.set_org_secret", Box::new(github_org_handler))
        .handler("github.list_secrets", Box::new(github_list_handler))
        .handler("github.delete_secret", Box::new(github_delete_handler))
        .handler("gitlab.set_ci_variable", Box::new(gitlab_handler));

    if let Some(runtime) = identity_runtime.clone() {
        enclave_builder =
            enclave_builder.task_authority_guard(Arc::new(move |requester, authorize| {
                runtime.with_dispatch_authority(requester, None, authorize)
            }));
    }

    if !onepassword_connect_url.is_empty() {
        // Connect Server backend (self-hosted REST API).
        let op_list_vaults_handler = opaque_providers::onepassword::OnePasswordHandler::new(
            audit.clone(),
            &onepassword_connect_url,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let op_list_items_handler = opaque_providers::onepassword::OnePasswordHandler::new(
            audit.clone(),
            &onepassword_connect_url,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let op_read_field_handler = opaque_providers::onepassword::OnePasswordHandler::new(
            audit.clone(),
            &onepassword_connect_url,
        )
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        enclave_builder = enclave_builder
            .handler("onepassword.list_vaults", Box::new(op_list_vaults_handler))
            .handler("onepassword.list_items", Box::new(op_list_items_handler))
            .handler("onepassword.read_field", Box::new(op_read_field_handler));
        info!(
            "1Password handler enabled via Connect Server ({})",
            onepassword_connect_url
        );
    } else if let Ok(cli) = opaque_providers::onepassword::op_cli::OpCliClient::new() {
        // `op` CLI backend (desktop app + biometric auth).
        let op_list_vaults_handler =
            opaque_providers::onepassword::OnePasswordHandler::from_cli(audit.clone(), cli.clone());
        let op_list_items_handler =
            opaque_providers::onepassword::OnePasswordHandler::from_cli(audit.clone(), cli.clone());
        let op_read_field_handler =
            opaque_providers::onepassword::OnePasswordHandler::from_cli(audit.clone(), cli);
        enclave_builder = enclave_builder
            .handler("onepassword.list_vaults", Box::new(op_list_vaults_handler))
            .handler("onepassword.list_items", Box::new(op_list_items_handler))
            .handler("onepassword.read_field", Box::new(op_read_field_handler));
        info!("1Password handler enabled via op CLI");
    } else {
        info!("1Password handler disabled (no Connect URL or op CLI found)");
    }

    // The official bws CLI performs authentication and secret decryption.
    let bitwarden_url = std::env::var(opaque_providers::bitwarden::client::BITWARDEN_URL_ENV)
        .unwrap_or_else(|_| opaque_providers::bitwarden::client::DEFAULT_BASE_URL.to_owned());
    for operation in [
        "bitwarden.list_projects",
        "bitwarden.list_secrets",
        "bitwarden.read_secret",
    ] {
        match opaque_providers::bitwarden::BitwardenHandler::new(audit.clone(), &bitwarden_url) {
            Ok(handler) => enclave_builder = enclave_builder.handler(operation, Box::new(handler)),
            Err(error) => {
                info!("Bitwarden handler disabled: {error}");
                break;
            }
        }
    }

    // Production AWS uses official SigV4 and service wire protocols.
    match opaque_providers::aws::client::AwsClient::from_env() {
        Ok(Some(aws_client)) => {
            for op in [
                "aws.get_caller_identity",
                "aws.assume_role",
                "aws.list_secrets",
                "aws.get_secret_value",
                "aws.create_secret",
                "aws.put_secret_value",
                "aws.delete_secret",
                "aws.get_parameter",
                "aws.put_parameter",
                "aws.get_parameters_by_path",
                "aws.delete_parameter",
            ] {
                enclave_builder = enclave_builder.handler(
                    op,
                    Box::new(opaque_providers::aws::AwsHandler::new(
                        audit.clone(),
                        aws_client.clone(),
                    )),
                );
            }
            info!("AWS handler enabled ({})", aws_client.backend());
        }
        Ok(None) => info!("AWS handler disabled (set OPAQUE_AWS_REGION)"),
        Err(error) => {
            return Err(std::io::Error::other(format!(
                "invalid AWS configuration: {error}"
            )));
        }
    }

    match opaque_providers::gcp::client::GcpSecretManagerClient::from_env() {
        Ok(Some(client)) => {
            for operation in opaque_providers::gcp::operations() {
                enclave_builder = enclave_builder.handler(
                    &operation.name,
                    Box::new(opaque_providers::gcp::GcpHandler::from_client(
                        audit.clone(),
                        client.clone(),
                    )),
                );
            }
            info!("GCP Secret Manager handler enabled");
        }
        Ok(None) => info!("GCP Secret Manager handler disabled (see docs/gcp.md)"),
        Err(error) => {
            return Err(std::io::Error::other(format!(
                "invalid GCP configuration: {error}"
            )));
        }
    }
    match opaque_providers::azure::client::AzureKeyVaultClient::from_env() {
        Ok(Some(client)) => {
            for operation in opaque_providers::azure::operations() {
                enclave_builder = enclave_builder.handler(
                    &operation.name,
                    Box::new(opaque_providers::azure::AzureHandler::from_client(
                        audit.clone(),
                        client.clone(),
                    )),
                );
            }
            info!("Azure Key Vault handler enabled");
        }
        Ok(None) => info!("Azure Key Vault handler disabled (see docs/azure.md)"),
        Err(error) => {
            return Err(std::io::Error::other(format!(
                "invalid Azure configuration: {error}"
            )));
        }
    }

    // Approval backend selection. The insecure auto-approve backend exists
    // only so e2e tests can run headless: it demands BOTH the config value and
    // an explicit environment marker, refuses to start on a partial attempt
    // (no silent fallback in either direction), and announces itself loudly.
    let auto_approve_env = std::env::var("OPAQUE_INSECURE_AUTO_APPROVE")
        .ok()
        .as_deref()
        == Some("1");
    let backend = select_approval_backend(config.approval_backend.as_deref(), auto_approve_env)
        .map_err(std::io::Error::other)?;
    // Second-device factor: pairing manager + approval server, when enabled.
    // Constructed before the gate so the registry can hold the verifier, and
    // stashed in DaemonState for the device_* control methods.
    let mut scope_workflow: Option<Arc<scope_runtime::Runtime>> = None;
    let mut pairing_manager: Option<Arc<opaque_approval::pairing::PairingManager>> = None;
    let mut approval_server_addr: Option<std::net::SocketAddr> = None;
    let mut second_device_verifier: Option<(
        Arc<opaque_approval::pairing::PairingManager>,
        opaque_approval::approval_server::ApprovalServerHandle,
    )> = None;
    if config.approval.second_device
        || !config.workstation_approvers.is_empty()
        || config.remote_approvals.is_some()
        || config.scope_workflow.is_some()
        || config.authority_policy.is_some()
    {
        let state_dir = audit_db_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        // Daemon pairing signing key (custody set) — server_id derives from
        // its public key, so both are stable across restarts.
        let pairing_key =
            identity::keys::load_or_create_signing_key(&state_dir.join("pairing.key"))?;
        let server_id = {
            let pk = pairing_key.verifying_key();
            let hex: String = pk.as_bytes()[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            format!("opq-{hex}")
        };

        // Device store integrity key beside the store (custody set).
        let store_path = config
            .data_dir
            .as_ref()
            .map(|dir| dir.join("approval/paired_devices.json"))
            .unwrap_or_else(opaque_approval::pairing::store::DeviceStore::default_path);
        if let Some(parent) = store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let store_hmac =
            opaque_core::keyfile::load_or_create_key_file(&store_path.with_extension("hmac"))?;

        let bind: std::net::SocketAddr = config
            .approval
            .server_bind
            .as_deref()
            .unwrap_or("127.0.0.1:7381")
            .parse()
            .map_err(|e| std::io::Error::other(format!("approval.server_bind invalid: {e}")))?;

        let store =
            opaque_approval::pairing::store::DeviceStore::new(store_path, store_hmac.to_vec());
        let pm = Arc::new(opaque_approval::pairing::PairingManager::new(
            server_id,
            pairing_key,
            bind.port(),
            store,
        ));
        for approver in &config.workstation_approvers {
            pm.enroll_workstation(approver)
                .map_err(std::io::Error::other)?;
        }

        let remote = config
            .remote_approvals
            .clone()
            .map(|remote_config| {
                if !config.enable_task_grants || backend != ApprovalBackendKind::Native {
                    return Err("remote approvals require native bounded-task approval".to_owned());
                }
                if !config.require_seal
                    || !td.enforce
                    || !config.identity.as_ref().is_some_and(|id| id.required)
                {
                    return Err(
                        "remote approvals require sealed isolated custody and required identity"
                            .to_owned(),
                    );
                }
                let runtime = identity_runtime
                    .clone()
                    .ok_or("remote approvals require identity")?;
                let boundary = tenant
                    .as_ref()
                    .ok_or("remote approvals require an isolated tenant")?;
                let resolution_runtime = runtime.clone();
                let resolver: opaque_approval::remote::ReviewerResolver =
                    Arc::new(move |principal, role| {
                        let principal = opaque_core::identity::PrincipalId::parse(principal)
                            .map_err(|_| "invalid remote reviewer principal")?;
                        let role = role
                            .parse::<opaque_core::identity::Role>()
                            .map_err(|_| "invalid remote reviewer role")?;
                        resolution_runtime.reviewer_eligibility(&principal, role)
                    });
                let authority_guard: opaque_approval::remote::ReviewerAuthorityGuard =
                    Arc::new(move |requester, principal, role, epoch, authorize| {
                        let principal = opaque_core::identity::PrincipalId::parse(principal)
                            .map_err(|_| "invalid reviewer principal")?;
                        let role = role
                            .parse::<opaque_core::identity::Role>()
                            .map_err(|_| "invalid reviewer role")?;
                        runtime.with_dispatch_authority(
                            requester,
                            Some((&principal, role, epoch)),
                            authorize,
                        )
                    });
                opaque_approval::remote::RemoteApprovals::open(
                    remote_config,
                    &state_dir.join("remote-approvals.db"),
                    boundary.binding().clone(),
                    pm.clone(),
                    resolver,
                    authority_guard,
                )
            })
            .transpose()
            .map_err(std::io::Error::other)?;

        if config.scope_workflow.is_some() || config.authority_policy.is_some() {
            if backend != ApprovalBackendKind::Native
                || !config.require_seal
                || !td.enforce
                || !config
                    .identity
                    .as_ref()
                    .is_some_and(|identity| identity.required)
            {
                return Err(std::io::Error::other(
                    "scope workflow requires native approval, required identity, and sealed isolated custody",
                ));
            }
            let boundary = tenant
                .as_ref()
                .ok_or_else(|| std::io::Error::other("scope workflow requires tenant isolation"))?;
            let runtime = identity_runtime
                .clone()
                .ok_or_else(|| std::io::Error::other("scope workflow requires identity"))?;
            let workflow_config = authority_policy::resolve(
                config.scope_workflow.clone(),
                config.authority_policy.as_ref(),
                boundary.binding(),
            )
            .map_err(std::io::Error::other)?
            .ok_or_else(|| std::io::Error::other("scope workflow unavailable"))?;
            scope_workflow = Some(Arc::new(
                scope_runtime::Runtime::open(
                    workflow_config,
                    boundary.binding(),
                    &state_dir,
                    runtime,
                    pm.clone(),
                )
                .map_err(std::io::Error::other)?,
            ));
        }

        // TLS identity persists so paired devices' fingerprint pin survives
        // restarts (custody set).
        let tls = opaque_approval::approval_server::load_or_create_tls_identity(&state_dir)
            .map_err(std::io::Error::other)?;
        let fingerprint = tls.fingerprint.clone();

        let server = opaque_approval::approval_server::ApprovalServer::new(
            opaque_approval::approval_server::ApprovalServerConfig {
                bind_addr: bind,
                tls_cert_der: tls.cert_der,
                tls_key_der: tls.key_der,
                timeout_secs: config.approval.timeout_secs.unwrap_or(60),
            },
            pm.clone(),
        )
        .map_err(std::io::Error::other)?;
        let server = if let Some(remote) = &remote {
            server.with_remote(remote.clone())
        } else {
            server
        };
        let server = if let Some(workflow) = &scope_workflow {
            server.with_scope_reviews(workflow.clone())
        } else {
            server
        };
        let server_handle = server.handle();

        let (_join, addr) = server
            .start()
            .await
            .map_err(|e| std::io::Error::other(format!("approval server failed to start: {e}")))?;
        pm.set_port(addr.port());
        approval_server_addr = Some(addr);

        // mDNS is convenience discovery — never fatal.
        match opaque_approval::approval_server::advertise_mdns(addr.port(), &fingerprint) {
            Ok(mdns) => {
                // Keep advertising for the daemon's lifetime.
                std::mem::forget(mdns);
            }
            Err(e) => warn!("mDNS advertisement unavailable: {e}"),
        }

        info!(
            "second-device approval factor live on {addr} (fingerprint {})",
            &fingerprint[..16]
        );
        pairing_manager = Some(pm);

        // Stash the handle for the verifier registration below.
        second_device_verifier = Some((pairing_manager.clone().expect("just set"), server_handle));
    }

    // FIDO2/passkey factor: daemon-side verification over the socket; the
    // authenticator ceremony runs in whatever client drives the key.
    let mut fido2_approvals: Option<Arc<opaque_approval::factors::Fido2Approvals>> = None;
    if config.approval.fido2 {
        let store_path = config
            .data_dir
            .as_ref()
            .map(|dir| dir.join("approval/fido2_credentials.json"))
            .unwrap_or_else(opaque_approval::fido2::Fido2CredentialStore::default_path);
        if let Some(parent) = store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let store_hmac =
            opaque_core::keyfile::load_or_create_key_file(&store_path.with_extension("hmac"))?;
        let store =
            opaque_approval::fido2::Fido2CredentialStore::new(store_path, store_hmac.to_vec());
        let rp_id = config
            .approval
            .fido2_rp_id
            .clone()
            .unwrap_or_else(|| "opaque.local".into());
        let manager = opaque_approval::fido2::Fido2Manager::new(
            store,
            Box::new(opaque_approval::fido2::NoLocalTransport),
            rp_id,
        );
        let approvals = Arc::new(opaque_approval::factors::Fido2Approvals::new(
            manager,
            std::time::Duration::from_secs(config.approval.timeout_secs.unwrap_or(60)),
        ));
        info!(
            "FIDO2/passkey approval factor enabled ({} credential(s) registered)",
            approvals.list_credentials().map(|c| c.len()).unwrap_or(0)
        );
        fido2_approvals = Some(approvals);
    }

    let mut registered_factors: Vec<String> = Vec::new();
    let approval_gate: Box<dyn ApprovalGate> = match backend {
        ApprovalBackendKind::Native => {
            let mut registry = opaque_approval::factors::FactorRegistry::new();

            // Local factor, with login-session approver binding when identity
            // is configured.
            let resolver = identity_runtime.clone().map(|rt| {
                Arc::new(move || {
                    rt.current_human_principal()
                        .filter(|p| !p.disabled)
                        .map(|p| opaque_core::audit::ApproverIdentity {
                            principal_id: p.id.as_str().to_owned(),
                            label: p.display_label(),
                            source: opaque_core::audit::ApproverSource::LocalBioSession,
                        })
                }) as opaque_approval::factors::ApproverResolver
            });
            registry.register(Arc::new(opaque_approval::factors::LocalBioVerifier::new(
                resolver,
            )));

            if let Some((pm, handle)) = second_device_verifier.clone() {
                if config.approval.second_device {
                    registry.register(Arc::new(
                        opaque_approval::factors::PairedDeviceVerifier::new(
                            pm.clone(),
                            handle.clone(),
                        ),
                    ));
                }
                if !config.workstation_approvers.is_empty() {
                    registry.register(Arc::new(
                        opaque_approval::factors::PairedWorkstationVerifier::new(pm, handle),
                    ));
                }
            }

            if let Some(approvals) = fido2_approvals.clone() {
                registry.register(Arc::new(opaque_approval::factors::Fido2Verifier::new(
                    approvals,
                )));
            }

            registered_factors = registry
                .available_factors()
                .iter()
                .map(|f| f.to_string())
                .collect();
            info!(factors = ?registered_factors, "approval factors registered");
            Box::new(NativeApprovalGate::with_registry(registry))
        }
        ApprovalBackendKind::InsecureAutoApprove => {
            tracing::error!(
                "INSECURE AUTO-APPROVE BACKEND ACTIVE — every approval will be granted \
                 without human interaction. Test use only."
            );
            audit.emit(
                AuditEvent::new(AuditEventKind::ApprovalGranted)
                    .with_operation("daemon_startup")
                    .with_outcome("insecure_backend_active")
                    .with_level(opaque_core::audit::AuditLevel::Error)
                    .with_approver(enclave::InsecureAutoApproveGate::approver())
                    .with_detail("INSECURE AUTO-APPROVE BACKEND ACTIVE \u{2014} test use only"),
            );
            Box::new(enclave::InsecureAutoApproveGate)
        }
    };

    let enclave = enclave_builder
        .approval_gate(approval_gate)
        .audit(audit.clone())
        .build()
        .map_err(std::io::Error::other)?;
    let enclave = Arc::new(enclave);

    // Detector runs locally even when no off-box export is configured.
    {
        let pump = opaque_federation_runtime::export::ExportPump::new(
            config.export.clone(),
            audit_db_path.clone(),
            opaque_federation_runtime::export::cursor_path(&home),
            audit.clone(),
        )
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("[export] configuration invalid (fail closed): {e}"),
            )
        })?;
        tokio::spawn(pump.run());
    }

    // --- Federation: signed policy bundles ---
    let federation_status =
        Arc::new(opaque_federation_runtime::federation::FederationStatus::default());
    if config.federation.configured() {
        let fed = &config.federation;
        let anchors = fed.anchors()?;
        if anchors.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "[federation] has a bundle source but no trust_anchors — an unverifiable \
                 bundle can never be applied",
            ));
        }
        let applier = opaque_federation_runtime::federation::BundleApplier {
            anchors,
            state_file: opaque_federation_runtime::federation::state_path(&home),
            enclave: enclave.clone(),
            status: federation_status.clone(),
            audit: audit.clone(),
        };

        // Initial load. Under require_bundle any failure (fetch, signature,
        // rollback, expiry) refuses startup; otherwise the daemon starts on
        // local [[rules]] and the refresh task keeps trying.
        match applier.load_and_apply(fed, true).await {
            Ok(()) => {}
            Err(e) if fed.require_bundle => {
                // The rejection was just audited; emission is asynchronous and
                // the process is about to exit without running destructors, so
                // make the security event durable before leaving.
                if let Err(error) = audit.flush(std::time::Duration::from_secs(5)) {
                    tracing::error!(%error, "federation rejection could not be durably audited");
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "federation.require_bundle is on and no valid bundle could be \
                         applied (fail closed): {e}"
                    ),
                ));
            }
            Err(e) => {
                warn!(
                    "federation bundle not applied at startup ({e}) — running on local \
                     [[rules]] until a refresh succeeds"
                );
            }
        }

        // Refresh task (0 disables).
        let refresh_secs = fed.refresh_secs.unwrap_or(300);
        if refresh_secs > 0 {
            let fed = fed.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tick.tick().await; // consume the immediate first tick
                loop {
                    tick.tick().await;
                    if let Err(e) = applier.load_and_apply(&fed, false).await {
                        warn!("federation refresh failed: {e}");
                    }
                }
            });
        }
    }

    // --- Continuous attestation ---
    let attestation = Arc::new(opaque_federation_runtime::attest::AttestationService::new(
        opaque_federation_runtime::attest::load_or_create_key_in(&state_dir)?,
        home.clone(),
        config_path.clone(),
        audit_db_path.clone(),
        version_string().to_owned(),
        config.trust_domain.enforce,
        registered_factors.clone(),
        federation_status.clone(),
    ));
    info!(
        attestation_key = %attestation.public_key_hex(),
        "attestation service ready (enroll this key with your verifier)"
    );
    attestation.record_posture(&audit, "startup");
    if let Some(fleet_config) = config.fleet.clone() {
        if !config.require_seal || !td.enforce {
            return Err(std::io::Error::other(
                "fleet reporter requires sealed isolated tenant custody",
            ));
        }
        let binding = tenant
            .as_ref()
            .ok_or_else(|| std::io::Error::other("fleet reporter requires a tenant binding"))?
            .binding()
            .clone();
        let reporter = opaque_federation_runtime::fleet::reporter::Reporter::new(
            fleet_config,
            binding,
            attestation.clone(),
            &state_dir,
        )
        .map_err(std::io::Error::other)?;
        tokio::spawn(reporter.run());
    }

    // Verify-before-trust: prove posture to the verifier before it releases
    // custody material. A refusal is loud but not fatal — the daemon keeps
    // running on the key material it already holds.
    if let Some(url) = config.attestation.key_release_url.clone() {
        match opaque_federation_runtime::attest::KeyReleaseClient::new(
            url,
            config.attestation.key_release_authorization.clone(),
        ) {
            Ok(client) => match client.release(&attestation).await {
                Ok(material) => info!(
                    bytes = material.len(),
                    "verifier released key material after attesting posture"
                ),
                Err(e) => warn!("attestation key release did not complete: {e}"),
            },
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("[attestation] key_release_url invalid: {e}"),
                ));
            }
        }
    }

    let attestation_interval = config.attestation.interval_secs.unwrap_or(900);
    if attestation_interval > 0 {
        tokio::spawn(
            attestation
                .clone()
                .run_periodic(audit.clone(), attestation_interval),
        );
    }

    let mcp = mcp_gateway::initialize(
        &config,
        &state_dir,
        tenant.as_ref().map(|t| t.binding()).cloned(),
    )?;
    let state = Arc::new(DaemonState {
        scope_workflow,
        mcp,
        workload_attestor,
        tenant,
        enclave,
        tasks,
        audit: audit.clone(),
        config,
        version: version_string(),
        daemon_token,
        agent_sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        connection_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
        identity: identity_runtime,
        pairing: pairing_manager,
        approval_server_addr,
        fido2: fido2_approvals,
        provisioning_challenges: opaque_tenant::provisioning_api::Challenges::default(),
        federation: federation_status,
        attestation,
    });

    // Shutdown coordination: watch channel + active connection counter.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    if let Some((authority, listener)) = resource_authority {
        tokio::spawn(authority.serve(listener, shutdown_rx.clone()));
    }
    let active_connections = Arc::new(AtomicUsize::new(0));

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown requested (ctrl-c)");
                break;
            }
            _ = sigterm.recv() => {
                info!("shutdown requested (sigterm)");
                break;
            }
            res = listener.accept() => {
                let (stream, _addr) = res?;
                let permit = match state.connection_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("max connections reached (64), rejecting");
                        drop(stream);
                        continue;
                    }
                };
                let state = state.clone();
                let conn_shutdown_rx = shutdown_rx.clone();
                let guard = connection::Guard::new(active_connections.clone(), permit);
                tokio::spawn(async move {
                    let _connection = guard;
                    if let Err(e) = handle_conn(state, stream, conn_shutdown_rx).await {
                        warn!("connection error: {e}");
                    }
                });
            }
        }
    }

    // Graceful drain: signal all connections to stop accepting new requests.
    let _ = shutdown_tx.send(true);
    let drain_deadline = std::time::Duration::from_secs(5);
    info!("draining active connections (up to 5s)...");
    let drain_start = std::time::Instant::now();
    while active_connections.load(Ordering::SeqCst) > 0 && drain_start.elapsed() < drain_deadline {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let remaining = active_connections.load(Ordering::SeqCst);
    if remaining > 0 {
        warn!("{remaining} connections still active after drain timeout");
    } else {
        info!("all connections drained");
    }

    Ok(())
}

/// Truncate a client-supplied string before echoing it in an error message.
/// Prevents secret-length content from being reflected back in error responses.
fn truncate_for_error(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_owned()
    } else {
        format!("{}...", opaque_core::validate::truncate_utf8(s, max_len))
    }
}

fn lock_down_socket_path(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
}

impl SocketGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// PID file guard (advisory flock)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PidFileGuard {
    _file: std::fs::File, // Keep file open to hold flock
    path: PathBuf,
}

impl PidFileGuard {
    fn acquire(path: PathBuf) -> std::io::Result<Self> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)?;
        // Acquire exclusive advisory lock (non-blocking).
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "daemon already running (PID file locked)",
                ));
            }
        }
        write!(file, "{}", std::process::id())?;
        file.flush()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { _file: file, path })
    }
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Per-connection rate limiter
// ---------------------------------------------------------------------------

struct ConnectionRateLimiter {
    timestamps: std::collections::VecDeque<std::time::Instant>,
    burst: usize,
    sustained_per_sec: f64,
}

impl ConnectionRateLimiter {
    fn new(burst: usize, sustained_per_sec: f64) -> Self {
        Self {
            timestamps: std::collections::VecDeque::new(),
            burst,
            sustained_per_sec,
        }
    }

    fn check(&mut self) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(1);
        // Remove timestamps older than 1 second.
        while let Some(&front) = self.timestamps.front() {
            if now.duration_since(front) > window {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
        // Check sustained rate (requests in last second).
        if self.timestamps.len() >= self.sustained_per_sec as usize {
            return false;
        }
        // Check burst.
        if self.timestamps.len() >= self.burst {
            return false;
        }
        self.timestamps.push_back(now);
        true
    }
}

// ---------------------------------------------------------------------------
// Client identity & type derivation
// ---------------------------------------------------------------------------

/// Derive the client type from the client identity and daemon config.
///
/// The daemon NEVER trusts a self-declared `client_type` from request params.
/// Instead, it matches the verified peer identity against the configured
/// `known_human_clients` allowlist. If no entry matches, the client is
/// classified as `Agent` (safer — more restrictive).
/// Revoke delegation records for ended sessions and audit each revocation.
/// In-memory removal closes connections; durable rows also govern final task
/// dispatch. A failed write retains a local identity fence and must not be
/// acknowledged as a successful durable revocation.
fn revoke_delegations(
    state: &DaemonState,
    identity: &ClientIdentity,
    client_type: ClientType,
    delegations: &[SessionDelegation],
) -> Result<(), ()> {
    let Some(rt) = state.identity.as_ref() else {
        return Ok(());
    };
    let mut failed = false;
    for d in delegations {
        match rt.store.revoke_delegation(&d.jti) {
            Ok(true) => {
                state.audit.emit(
                    AuditEvent::new(AuditEventKind::DelegationRevoked)
                        .with_operation("agent_session_end")
                        .with_client(ClientSummary::from((identity, client_type)))
                        .with_outcome("revoked")
                        .with_detail(format!("jti={} mode={} sub={}", d.jti, d.mode, d.sub)),
                );
            }
            Ok(false) => {}
            Err(e) => {
                failed = true;
                warn!("failed to revoke delegation record: {e}");
                emit_daemon_method_audit(
                    state,
                    AuditEventKind::OperationFailed,
                    "agent_session_end",
                    identity,
                    client_type,
                    "revocation_failed",
                    None,
                );
            }
        }
    }
    if failed { Err(()) } else { Ok(()) }
}

/// Build the full session review from trusted authority and bounded display hints.
fn session_approval_reason(
    tenant: Option<&opaque_core::tenant::TenantBinding>,
    uid: u32,
    ttl_secs: u64,
    delegation: Option<&(AccessMode, opaque_core::identity::Principal)>,
    label: Option<&str>,
) -> String {
    // Authority is always first and comes from verified runtime state. Labels
    // are separate, single-line display hints and cannot hide these fields.
    let mut reason = tenant.map_or_else(
        || "Tenant: unbound local broker\n".to_owned(),
        opaque_core::tenant::TenantBinding::approval_context,
    );
    reason.push_str(&format!(
        "Peer UID: {uid}\nSession lifetime: {ttl_secs} seconds\n"
    ));
    if let Some((mode, principal)) = delegation {
        reason.push_str(&format!(
            "Subject principal: {}\nAccess mode: {mode}\n",
            principal.id
        ));
    } else {
        reason.push_str("Subject principal: none (legacy local session)\nAccess mode: legacy\n");
    }
    let display_label = |value: &str, limit: usize| {
        let filtered: String = value.chars().filter(|c| {
            !c.is_control()
                && !matches!(*c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        }).take(limit.saturating_add(1)).collect();
        enclave::sanitize_for_display(&filtered, limit)
    };
    if let Some((_, principal)) = delegation {
        reason.push_str(&format!(
            "Subject display label: {}\n",
            display_label(&principal.display_label(), 128)
        ));
    }
    if let Some(label) = label {
        reason.push_str(&format!(
            "Requested session label: {}\n",
            display_label(label, 96)
        ));
    }
    reason
}

/// Derive an agent workload tool name for the `act` principal: prefer the
/// client-supplied label, else the client executable's basename, else
/// "agent" — sanitized to the identity charset (`[A-Za-z0-9._-]`, max 64).
fn derive_agent_tool_name(label: Option<&str>, identity: &ClientIdentity) -> String {
    let raw = label
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            identity
                .exe_path
                .as_ref()
                .and_then(|p| p.file_name())
                .map(|f| f.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "agent".into());
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    let cleaned = cleaned.trim_matches('-');
    if cleaned.is_empty() {
        "agent".into()
    } else {
        cleaned.to_owned()
    }
}

fn derive_client_type(identity: &ClientIdentity, config: &DaemonConfig) -> ClientType {
    for entry in &config.known_human_clients {
        if entry_matches(identity, entry) {
            return ClientType::Human;
        }
    }
    ClientType::Agent
}

/// Check if a client identity matches a human client allowlist entry.
/// All specified fields must match; absent fields are treated as "any".
/// An entry with NO fields specified matches nothing — this prevents a
/// misconfigured empty entry from classifying every client as Human.
fn entry_matches(identity: &ClientIdentity, entry: &HumanClientEntry) -> bool {
    // Reject entries that specify no matching criteria at all.
    if entry.exe_path.is_none() && entry.exe_sha256.is_none() && entry.codesign_team_id.is_none() {
        return false;
    }

    if let Some(ref pattern) = entry.exe_path {
        match &identity.exe_path {
            Some(exe) => {
                let path_str = exe.to_string_lossy();
                if !glob_match::glob_match(pattern, &path_str) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref expected_hash) = entry.exe_sha256 {
        match &identity.exe_sha256 {
            Some(actual) => {
                if !actual.eq_ignore_ascii_case(expected_hash) {
                    return false;
                }
            }
            None => return false,
        }
    }

    if let Some(ref expected_team) = entry.codesign_team_id {
        match &identity.codesign_team_id {
            Some(actual) => {
                if actual != expected_team {
                    return false;
                }
            }
            None => return false,
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Workspace verification
// ---------------------------------------------------------------------------

/// Create a `Command` with a minimal, hardened environment.
///
/// Clears all inherited env vars and sets only a restricted PATH to prevent
/// binary injection. Also prevents git from reading system/user config or
/// prompting for credentials.
fn safe_command(bin: &str) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin);
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/usr/local/bin:/bin");
    cmd.env("LC_ALL", "C");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1");
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.env("GIT_OPTIONAL_LOCKS", "0");
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    cmd
}

/// Read the current working directory of a process by PID.
fn read_client_cwd(pid: i32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
    }

    #[cfg(target_os = "macos")]
    {
        read_client_cwd_macos(pid)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "macos")]
fn read_client_cwd_macos(pid: i32) -> Option<PathBuf> {
    // Use lsof to get the cwd of a process on macOS.
    let output = safe_command("/usr/sbin/lsof")
        .args(["-a", "-p", &pid.to_string(), "-d", "cwd", "-Fn"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // lsof output format: "p<pid>\nn<path>"
    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix('n') {
            return Some(PathBuf::from(path));
        }
    }
    None
}

/// Blocking workspace verification logic.
///
/// Verifies that the claimed workspace context is consistent with the client's
/// actual process state. Runs external `git` commands.
///
/// Checks:
/// - Client's cwd is within the claimed repo_root (fail-closed if unreadable)
/// - `git rev-parse --show-toplevel` in repo_root matches
/// - Claimed remote_url matches actual `git remote get-url origin` (fail-closed if git fails)
/// - Claimed branch matches actual `git rev-parse --abbrev-ref HEAD` (fail-closed if git fails)
fn verify_workspace_blocking(
    claimed: &opaque_core::operation::WorkspaceContext,
    client_pid: Option<i32>,
) -> Result<(), String> {
    // Verify client cwd is within claimed repo_root.
    // Fail-closed: if we cannot determine the client cwd, we reject.
    if let Some(pid) = client_pid {
        match read_client_cwd(pid) {
            Some(cwd) => {
                let repo_root = claimed
                    .repo_root
                    .canonicalize()
                    .unwrap_or(claimed.repo_root.clone());
                let cwd = cwd.canonicalize().unwrap_or(cwd);
                if !cwd.starts_with(&repo_root) {
                    return Err(format!(
                        "client cwd {} is not within claimed repo_root {}",
                        cwd.display(),
                        repo_root.display(),
                    ));
                }
            }
            None => {
                return Err(format!(
                    "cannot read cwd for pid {pid}: workspace verification requires readable cwd"
                ));
            }
        }
    }

    // Verify git toplevel matches.
    let toplevel = workspace_git_read_command()
        .args([
            "-C",
            &claimed.repo_root.to_string_lossy(),
            "rev-parse",
            "--show-toplevel",
        ])
        .workspace_output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if !toplevel.status.success() {
        return Err(format!(
            "{} is not a git repository",
            claimed.repo_root.display()
        ));
    }
    let actual_root = String::from_utf8_lossy(&toplevel.stdout).trim().to_string();
    let actual_root = PathBuf::from(&actual_root)
        .canonicalize()
        .unwrap_or(PathBuf::from(&actual_root));
    let claimed_root = claimed
        .repo_root
        .canonicalize()
        .unwrap_or(claimed.repo_root.clone());
    if actual_root != claimed_root {
        return Err(format!(
            "git toplevel {} does not match claimed repo_root {}",
            actual_root.display(),
            claimed_root.display(),
        ));
    }

    // Verify remote URL if claimed.
    // Fail-closed: if git remote command fails, deny the request.
    if let Some(ref claimed_url) = claimed.remote_url {
        let remote = workspace_git_read_command()
            .args([
                "-C",
                &claimed.repo_root.to_string_lossy(),
                "remote",
                "get-url",
                "origin",
            ])
            .workspace_output()
            .map_err(|e| format!("failed to get remote url: {e}"))?;
        if !remote.status.success() {
            return Err(
                "git remote get-url origin failed: cannot verify claimed remote_url".to_string(),
            );
        }
        let actual_url = String::from_utf8_lossy(&remote.stdout).trim().to_string();
        if InputValidator::sanitize_url(&actual_url) != *claimed_url {
            // Sanitize URLs before embedding in error messages to strip
            // embedded credentials (e.g. https://token@host/...).
            let safe_claimed = InputValidator::sanitize_url(claimed_url);
            let safe_actual = InputValidator::sanitize_url(&actual_url);
            return Err(format!(
                "claimed remote_url '{}' does not match actual '{}'",
                safe_claimed, safe_actual,
            ));
        }
    }

    // Verify branch if claimed.
    // Fail-closed: if git branch command fails, deny the request.
    if let Some(ref claimed_branch) = claimed.branch {
        let branch = workspace_git_read_command()
            .args([
                "-C",
                &claimed.repo_root.to_string_lossy(),
                "rev-parse",
                "--abbrev-ref",
                "HEAD",
            ])
            .workspace_output()
            .map_err(|e| format!("failed to get branch: {e}"))?;
        if !branch.status.success() {
            return Err(
                "git rev-parse --abbrev-ref HEAD failed: cannot verify claimed branch".to_string(),
            );
        }
        let actual_branch = String::from_utf8_lossy(&branch.stdout).trim().to_string();
        if actual_branch != *claimed_branch {
            return Err(format!(
                "claimed branch '{}' does not match actual '{}'",
                claimed_branch, actual_branch,
            ));
        }
    }

    let snapshot = WorkspaceGitSnapshot::capture(&claimed.repo_root)?;
    if claimed
        .head_sha
        .as_ref()
        .is_some_and(|expected| expected != &snapshot.head)
    {
        return Err("workspace HEAD changed".into());
    }
    if snapshot.is_dirty()? != claimed.dirty {
        return Err("workspace dirty state differs from the supplied context".into());
    }
    Ok(())
}

/// Repository metadata plumbing may read untrusted Git data, but may never
/// invoke a transport/credential helper or lazy-fetch missing objects.
fn workspace_git_read_command() -> std::process::Command {
    let mut command = safe_command("git");
    command
        .stdin(std::process::Stdio::null())
        .arg("--no-pager")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ]);
    command
}

/// Status runs with broker-owned metadata, never the mutable repository's
/// config. Enumerating then overriding filter names is unsafe: a new name can
/// be added after enumeration and executed by Git under the daemon account.
struct WorkspaceGitSnapshot {
    directory: tempfile::TempDir,
    worktree: PathBuf,
    objects: PathBuf,
    head: String,
    safe_config: Vec<(String, String)>,
}

impl WorkspaceGitSnapshot {
    fn capture(worktree: &std::path::Path) -> Result<Self, String> {
        let unavailable = || "workspace metadata cannot be verified safely".to_owned();
        let read_git = |args: &[&str]| -> Result<Vec<u8>, String> {
            let output = workspace_git_read_command()
                .arg("-C")
                .arg(worktree)
                .args(args)
                .workspace_output_with_limit(128 * 1024)
                .map_err(|_| unavailable())?;
            if !output.status.success() || output.stdout.len() > 128 * 1024 {
                return Err(unavailable());
            }
            Ok(output.stdout)
        };
        let text_git = |args: &[&str]| -> Result<String, String> {
            String::from_utf8(read_git(args)?)
                .map(|s| s.trim_end_matches('\n').to_owned())
                .map_err(|_| unavailable())
        };
        let head = text_git(&["rev-parse", "--verify", "HEAD"])?;
        if head.len() != 40
            || !head.bytes().all(|c| c.is_ascii_hexdigit())
            || text_git(&["rev-parse", "--show-object-format"])? != "sha1"
        {
            return Err("workspace HEAD or object format is unsupported".into());
        }
        let index = PathBuf::from(text_git(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "index",
        ])?);
        let objects = PathBuf::from(text_git(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects",
        ])?);
        if !index.is_absolute() || !objects.is_absolute() || !objects.is_dir() {
            return Err(unavailable());
        }
        let config = read_git(&["config", "--includes", "--null", "--list"])?;
        let mut safe_config = Vec::new();
        for entry in config.split(|b| *b == 0).filter(|entry| !entry.is_empty()) {
            let entry = std::str::from_utf8(entry).map_err(|_| unavailable())?;
            let (key, value) = entry.split_once('\n').unwrap_or((entry, "true"));
            let key = key.to_ascii_lowercase();
            if matches!(
                key.as_str(),
                "core.sparsecheckout" | "core.sparsecheckoutcone" | "index.sparse"
            ) && !matches!(value, "false" | "no" | "off" | "0")
            {
                return Err("sparse workspaces cannot be verified safely".into());
            }
            if matches!(key.as_str(), "core.attributesfile" | "core.excludesfile") {
                return Err("external workspace attribute or exclude files are unsupported".into());
            }
            // Only built-in conversion/stat settings are copied. In particular,
            // there are no filter.*, include.*, remote.*, extensions.*, fsmonitor,
            // hooks, credential helpers, alternate commands or shell programs.
            if matches!(
                key.as_str(),
                "core.filemode"
                    | "core.ignorecase"
                    | "core.symlinks"
                    | "core.precomposeunicode"
                    | "core.autocrlf"
                    | "core.eol"
                    | "core.safecrlf"
                    | "core.checkstat"
                    | "core.trustctime"
            ) {
                if value.len() > 32 || !value.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return Err(unavailable());
                }
                safe_config.push((key, value.to_owned()));
            }
        }
        let directory = tempfile::Builder::new()
            .prefix("opaque-workspace-")
            .tempdir()
            .map_err(|_| unavailable())?;
        std::fs::create_dir(directory.path().join("refs")).map_err(|_| unavailable())?;
        std::fs::create_dir(directory.path().join("objects")).map_err(|_| unavailable())?;
        std::fs::create_dir(directory.path().join("info")).map_err(|_| unavailable())?;
        std::fs::write(directory.path().join("HEAD"), format!("{head}\n"))
            .map_err(|_| unavailable())?;
        std::fs::write(
            directory.path().join("config"),
            "[core]\nrepositoryformatversion = 0\nbare = false\n",
        )
        .map_err(|_| unavailable())?;
        Self::copy_metadata(&index, &directory.path().join("index"), 64 * 1024 * 1024)?;
        for name in ["exclude", "attributes"] {
            let relative = format!("info/{name}");
            let source = PathBuf::from(text_git(&[
                "rev-parse",
                "--path-format=absolute",
                "--git-path",
                &relative,
            ])?);
            Self::copy_metadata(&source, &directory.path().join(relative), 128 * 1024)?;
        }
        let snapshot = Self {
            directory,
            worktree: worktree.to_path_buf(),
            objects,
            head,
            safe_config,
        };
        snapshot.rebuild_index()?;
        Ok(snapshot)
    }

    fn copy_metadata(
        source: &std::path::Path,
        destination: &std::path::Path,
        limit: u64,
    ) -> Result<(), String> {
        use std::io::Read;
        use std::os::unix::fs::OpenOptionsExt;
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(source)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("workspace metadata unavailable".into()),
        };
        let metadata = file
            .metadata()
            .map_err(|_| "workspace metadata unavailable")?;
        if !metadata.is_file() || metadata.len() > limit {
            return Err("workspace metadata exceeds supported limits".into());
        }
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "workspace metadata unavailable")?;
        if bytes.len() as u64 > limit {
            return Err("workspace metadata exceeds supported limits".into());
        }
        std::fs::write(destination, bytes)
            .map_err(|_| "workspace metadata snapshot unavailable".into())
    }

    fn command(&self) -> std::process::Command {
        let mut command = workspace_git_read_command();
        command
            .arg("--no-pager")
            .arg(format!("--git-dir={}", self.directory.path().display()))
            .arg(format!("--work-tree={}", self.worktree.display()))
            .arg("-C")
            .arg(&self.worktree)
            .env("GIT_OBJECT_DIRECTORY", &self.objects)
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.ignorestat=false",
            ]);
        for (key, value) in &self.safe_config {
            command.arg("-c").arg(format!("{key}={value}"));
        }
        command
    }

    fn rebuild_index(&self) -> Result<(), String> {
        let flags = self
            .command()
            .args(["ls-files", "-v", "-z"])
            .workspace_output()
            .map_err(|_| "workspace index unavailable")?;
        if !flags.status.success()
            || flags
                .stdout
                .split(|b| *b == 0)
                .filter(|entry| !entry.is_empty())
                .any(|entry| entry[0].is_ascii_lowercase() || entry[0] == b'S')
        {
            return Err(
                "assume-unchanged, split or sparse workspace indexes are unsupported".into(),
            );
        }
        let entries = self
            .command()
            .args(["ls-files", "--stage", "--sparse", "-z"])
            .workspace_output()
            .map_err(|_| "workspace index unavailable")?;
        if !entries.status.success() || entries.stdout.len() > 16 * 1024 * 1024 {
            return Err("workspace index is unsupported or unavailable".into());
        }
        for entry in entries
            .stdout
            .split(|b| *b == 0)
            .filter(|entry| !entry.is_empty())
        {
            let header = entry
                .split(|b| *b == b'\t')
                .next()
                .ok_or("invalid workspace index")?;
            let header = std::str::from_utf8(header).map_err(|_| "invalid workspace index")?;
            let fields: Vec<_> = header.split(' ').collect();
            if fields.len() != 3
                || !matches!(fields[0], "100644" | "100755" | "120000" | "160000")
                || fields[1].len() != 40
                || !fields[1].bytes().all(|b| b.is_ascii_hexdigit())
                || !matches!(fields[2], "0" | "1" | "2" | "3")
            {
                return Err("workspace index entry is unsupported".into());
            }
        }
        let input = self.directory.path().join("index-entries");
        let rebuilt = self.directory.path().join("rebuilt-index");
        std::fs::write(&input, entries.stdout)
            .map_err(|_| "workspace index snapshot unavailable")?;
        let empty = self
            .command()
            .env("GIT_INDEX_FILE", &rebuilt)
            .args(["read-tree", "--empty"])
            .workspace_output()
            .map_err(|_| "workspace index snapshot unavailable")?;
        if !empty.status.success() {
            return Err("workspace index snapshot unavailable".into());
        }
        let result = self
            .command()
            .env("GIT_INDEX_FILE", &rebuilt)
            .args(["update-index", "-z", "--index-info"])
            .stdin(std::fs::File::open(input).map_err(|_| "workspace index snapshot unavailable")?)
            .workspace_output()
            .map_err(|_| "workspace index snapshot unavailable")?;
        if !result.status.success() {
            return Err("workspace index snapshot unavailable".into());
        }
        std::fs::rename(rebuilt, self.directory.path().join("index"))
            .map_err(|_| "workspace index snapshot unavailable".into())
    }

    fn reject_external_filters(&self) -> Result<(), String> {
        // check-attr reads attributes but never executes their filter programs.
        // A late filter remains harmless because this Git directory has no
        // corresponding filter configuration, even if worktree files race.
        let files = self
            .command()
            .args([
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ])
            .workspace_output()
            .map_err(|_| "workspace index unavailable")?;
        if !files.status.success() || files.stdout.len() > 16 * 1024 * 1024 {
            return Err("workspace index is unsupported or unavailable".into());
        }
        let paths = self.directory.path().join("checked-paths");
        std::fs::write(&paths, files.stdout)
            .map_err(|_| "workspace attribute check unavailable")?;
        let input =
            std::fs::File::open(paths).map_err(|_| "workspace attribute check unavailable")?;
        let attributes = self
            .command()
            .args(["check-attr", "-z", "--stdin", "filter"])
            .stdin(input)
            .workspace_output()
            .map_err(|_| "workspace attribute check unavailable")?;
        if !attributes.status.success() || attributes.stdout.len() > 64 * 1024 * 1024 {
            return Err("workspace attributes unavailable".into());
        }
        let fields: Vec<_> = attributes.stdout.split(|b| *b == 0).collect();
        if fields.last() != Some(&b"".as_slice()) || (fields.len() - 1) % 3 != 0 {
            return Err("workspace attributes unavailable".into());
        }
        if fields[..fields.len() - 1]
            .chunks_exact(3)
            .any(|entry| entry[2] != b"unspecified" && entry[2] != b"unset")
        {
            return Err("workspaces using external Git filters cannot be verified safely".into());
        }
        Ok(())
    }

    fn is_dirty(&self) -> Result<bool, String> {
        self.reject_external_filters()?;
        let status = self
            .command()
            .args([
                "status",
                "--porcelain",
                "--untracked-files=normal",
                "--ignore-submodules=all",
            ])
            .workspace_output()
            .map_err(|_| "could not verify workspace state")?;
        if !status.status.success() {
            return Err("could not verify workspace state".into());
        }
        self.reject_external_filters()?;
        Ok(!status.stdout.is_empty())
    }
}

/// Async wrapper around `verify_workspace_blocking` that offloads the
/// bounded subprocess calls to a Tokio blocking thread.
async fn verify_workspace(
    claimed: &opaque_core::operation::WorkspaceContext,
    client_pid: Option<i32>,
) -> Result<(), String> {
    let claimed = claimed.clone();
    tokio::task::spawn_blocking(move || verify_workspace_blocking(&claimed, client_pid))
        .await
        .map_err(|e| format!("workspace verification task failed: {e}"))?
}

/// Parse, sanitize, and verify a request's optional `workspace` claim.
///
/// Moved here from `opaque_bounded_work::task_api` (previously
/// `task_api::verified_workspace`): it calls `verify_workspace` above,
/// kernel-side machinery `opaque-bounded-work` must not reach back into.
/// `handle_request` now computes this once per request for every method
/// whose params may carry a `workspace` claim, and passes the result down —
/// see the call site above.
async fn verified_workspace(
    params: &serde_json::Value,
    identity: &ClientIdentity,
) -> Result<Option<opaque_core::operation::WorkspaceContext>, String> {
    let Some(value) = params.get("workspace").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let mut workspace: opaque_core::operation::WorkspaceContext =
        serde_json::from_value(value.clone()).map_err(|_| "invalid workspace context")?;
    if identity.pid.is_none() {
        return Err("workspace peer pid is unavailable".into());
    }
    if let Some(url) = &workspace.remote_url {
        workspace.remote_url = Some(InputValidator::sanitize_url(url));
    }
    workspace.workspace_verified = false;
    verify_workspace(&workspace, identity.pid)
        .await
        .map_err(|_| "workspace verification failed")?;
    workspace.workspace_verified = true;
    Ok(Some(workspace))
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_conn(
    state: Arc<DaemonState>,
    stream: UnixStream,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    let peer = peer_info_from_fd(fd).ok();
    // Peer-uid gate, mode-aware. Shared-uid mode admits only the daemon's own
    // uid (multi-user protection). The enforced split refuses exactly that
    // uid: nothing legitimate runs as the service account except the daemon,
    // so a same-uid peer inside the trust domain is a breach, and everyone
    // else is gated by socket-group membership + the daemon token.
    if let Some(info) = &peer {
        let daemon_uid = state.workload_attestor.daemon_effective_uid();
        let enforce = state.config.trust_domain.enforce;
        if !trust_domain::peer_uid_allowed(info.uid, daemon_uid, enforce) {
            warn!(
                "peer uid {} refused ({}), rejecting connection",
                info.uid,
                if enforce {
                    "runs as the daemon's own service account"
                } else {
                    "does not match daemon uid"
                }
            );
            return Ok(());
        }
    }

    let Some((identity, workload)) = attest_connection(&state, peer.as_ref()) else {
        return Ok(());
    };

    // Derive client type once per connection — never from request params.
    let client_type = derive_client_type(&identity, &state.config);

    if let Some(ref peer) = peer {
        info!(
            "client connected uid={} gid={} pid={:?} type={:?}",
            peer.uid, peer.gid, peer.pid, client_type
        );
    } else {
        info!("client connected (peer creds unavailable) type={client_type:?}");
    }

    let codec = LengthDelimitedCodec::builder()
        .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
        .new_codec();
    let mut framed = Framed::new(stream, codec);

    // --- Handshake: first frame must be a valid daemon token ---
    let handshake = match connection::read_handshake(&mut framed, &mut shutdown_rx).await? {
        Some(frame) => {
            if serde_json::from_slice::<serde_json::Value>(&frame).is_ok_and(|value| {
                opaque_federation_runtime::workload_attest::has_identity_claim(&value)
            }) {
                emit_daemon_method_audit(
                    &state,
                    AuditEventKind::WorkloadAttestationDenied,
                    "connection.handshake",
                    &identity,
                    client_type,
                    "identity_claim_forbidden",
                    Some(workload_audit_detail(&workload)),
                );
                return Ok(());
            }
            validate_handshake(&frame, &state.daemon_token)
        }
        _ => None,
    };

    let Some(handshake) = handshake else {
        // Close silently — no error detail to prevent oracle attacks.
        warn!("handshake failed, closing connection");
        return Ok(());
    };

    let session_id = match handshake_session(
        &state,
        handshake.session_token.as_deref(),
        client_type,
        identity.uid,
    )
    .await
    {
        Ok(id) => id,
        Err(()) => {
            warn!("required or supplied session token invalid, closing connection");
            return Ok(());
        }
    };

    // Split into read/write halves so we can detect client disconnect during
    // request processing. When the client disconnects, the in-flight request
    // future is dropped, which releases any held resources (including the
    // approval semaphore). This implements the US-009 requirement:
    // "Approval semaphore is released when the requesting client disconnects."
    let (mut sink, mut reader) = framed.split();

    // Per-connection rate limiter: burst of 10, sustained 2 req/s.
    let mut rate_limiter = ConnectionRateLimiter::new(10, 2.0);

    loop {
        // Stop accepting new requests when shutdown is signaled.
        if *shutdown_rx.borrow() {
            info!("shutdown signaled, closing connection");
            break;
        }

        // Idle timeout: disconnect clients that send no frames for 30 seconds.
        let next_frame = tokio::select! {
            frame = tokio::time::timeout(std::time::Duration::from_secs(30), reader.next()) => frame,
            _ = shutdown_rx.changed() => {
                info!("shutdown signaled, closing connection");
                break;
            }
        };

        match next_frame {
            Ok(Some(Ok(frame))) => {
                let value: serde_json::Value = match serde_json::from_slice(&frame) {
                    Ok(value) => value,
                    Err(_) => {
                        let resp = Response::err(None, "bad_json", "invalid JSON request");
                        connection::send(
                            &mut sink,
                            Bytes::from(serde_json::to_vec(&resp).map_err(std::io::Error::other)?),
                        )
                        .await?;
                        continue;
                    }
                };
                // Claimed identities consume the same budget as other requests,
                // so repeated refusals cannot bypass the audit flood limit.
                if !rate_limiter.check() {
                    warn!("rate limit exceeded for connection");
                    let resp = Response::err(
                        value.get("id").and_then(serde_json::Value::as_u64),
                        "rate_limited",
                        "too many requests",
                    );
                    let out = serde_json::to_vec(&resp).map_err(std::io::Error::other)?;
                    connection::send(&mut sink, Bytes::from(out)).await?;
                    continue;
                }
                if opaque_federation_runtime::workload_attest::has_identity_claim(&value) {
                    emit_daemon_method_audit(
                        &state,
                        AuditEventKind::WorkloadAttestationDenied,
                        "request.attest",
                        &identity,
                        client_type,
                        "identity_claim_forbidden",
                        Some(workload_audit_detail(&workload)),
                    );
                    let resp = Response::err(
                        value.get("id").and_then(serde_json::Value::as_u64),
                        "identity_claim_forbidden",
                        "workload identity is established by the listener",
                    );
                    connection::send(
                        &mut sink,
                        Bytes::from(serde_json::to_vec(&resp).map_err(std::io::Error::other)?),
                    )
                    .await?;
                    continue;
                }
                // Decode the original frame so duplicate envelope fields still
                // fail closed instead of being overwritten by Value parsing.
                let req: Request = match serde_json::from_slice(&frame) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("bad JSON from client: {e}");
                        let resp = Response::err(None, "bad_json", "invalid JSON request");
                        let bytes = serde_json::to_vec(&resp)
                            .unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                        let _ = connection::send(&mut sink, Bytes::from(bytes)).await;
                        continue;
                    }
                };

                // Session TTL enforcement for wrapped agents.
                if state.config.enforce_agent_sessions && client_type == ClientType::Agent {
                    let active = if let Some(ref sid) = session_id {
                        let sessions = state.agent_sessions.read().await;
                        sessions.get(sid).is_some_and(|s| {
                            s.created_by_uid == identity.uid && s.expires_at > SystemTime::now()
                        })
                    } else {
                        false
                    };
                    if !active {
                        warn!("agent session expired or revoked, closing connection");
                        break;
                    }
                }

                // Never log params (may contain secrets due to client bugs).
                emit_daemon_method_audit(
                    &state,
                    AuditEventKind::WorkloadAttested,
                    &req.method,
                    &identity,
                    client_type,
                    "attested",
                    Some(workload_audit_detail(&workload)),
                );
                // Task work is bounded by its durable expiry (at most one hour).
                // Native review plus several provider calls may exceed the
                // ordinary request timeout; cancellation still seals the ledger.
                // Race against client disconnect so the approval semaphore is
                // released immediately when the requesting client goes away.
                let req_id = req.id;
                let timeout_secs = if req.method == "task_run" { 3600 } else { 120 };
                let resp = tokio::select! {
                    r = tokio::time::timeout(
                        std::time::Duration::from_secs(timeout_secs),
                        handle_request(&state, req, &identity, client_type, session_id.as_deref()),
                    ) => {
                        match r {
                            Ok(r) => r,
                            Err(_) => {
                                warn!(timeout_secs, "request timed out");
                                Response::err(Some(req_id), "timeout", "request timed out")
                            }
                        }
                    }
                    _ = reader.next() => {
                        // Client disconnected or sent data during request processing.
                        // Dropping the handle_request future releases the approval
                        // semaphore permit via RAII if one was held.
                        info!("client disconnected during request processing");
                        break;
                    }
                };
                let out = serde_json::to_vec(&resp).map_err(std::io::Error::other)?;
                connection::send(&mut sink, Bytes::from(out)).await?;
            }
            Ok(Some(Err(e))) => {
                warn!("bad frame from client: {e}");
                let resp = Response::err(None, "bad_frame", "malformed frame");
                let bytes = serde_json::to_vec(&resp)
                    .unwrap_or_else(|_| b"{\"error\":\"encode\"}".to_vec());
                let _ = connection::send(&mut sink, Bytes::from(bytes)).await;
                return Err(e);
            }
            Ok(None) => break, // Client disconnected
            Err(_) => {
                info!("idle timeout, closing connection");
                break;
            }
        }
    }

    Ok(())
}

/// Validate the handshake frame from a client.
///
/// Expected format: `{"handshake":"v1","daemon_token":"<hex>"}`
#[derive(Debug, Clone)]
struct HandshakePayload {
    session_token: Option<String>,
}

fn validate_handshake(frame: &[u8], expected_token: &str) -> Option<HandshakePayload> {
    #[derive(Deserialize)]
    struct Handshake {
        handshake: String,
        daemon_token: String,
        #[serde(default)]
        session_token: Option<String>,
    }

    let value: serde_json::Value = serde_json::from_slice(frame).ok()?;
    if opaque_federation_runtime::workload_attest::has_identity_claim(&value) {
        return None;
    }
    let hs: Handshake = match serde_json::from_slice(frame) {
        Ok(h) => h,
        Err(_) => return None,
    };

    if hs.handshake != "v1" {
        return None;
    }

    // Constant-time comparison to prevent timing attacks.
    if !constant_time_eq(hs.daemon_token.as_bytes(), expected_token.as_bytes()) {
        return None;
    }

    Some(HandshakePayload {
        session_token: hs.session_token.filter(|s| !s.trim().is_empty()),
    })
}

/// Existing chained detail column carries the new evidence; no historical
/// audit serialization or fingerprint changes. Never include caller claims.
fn workload_audit_detail(workload: &opaque_core::workload::WorkloadIdentity) -> String {
    serde_json::json!({
        "attestor": workload.source.as_str(),
        "strength": workload.strength,
        "selector_count": workload.selectors.len(),
    })
    .to_string()
}

fn attest_connection(
    state: &DaemonState,
    peer: Option<&opaque_core::peer::PeerInfo>,
) -> Option<(ClientIdentity, opaque_core::workload::WorkloadIdentity)> {
    let (identity, workload) = state.workload_attestor.attest(peer);
    if workload.is_attested() {
        return Some((identity, workload));
    }
    state.audit.emit(
        AuditEvent::new(AuditEventKind::WorkloadAttestationDenied)
            .with_operation("connection.attest")
            .with_outcome("attestation_unavailable")
            .with_detail(workload_audit_detail(&workload)),
    );
    warn!("workload attestation unavailable, rejecting connection");
    None
}

/// Constant-time byte comparison (prevents timing side channels).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn system_time_to_unix_ms(ts: SystemTime) -> i64 {
    ts.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn emit_daemon_method_audit(
    state: &DaemonState,
    kind: AuditEventKind,
    method: &str,
    identity: &ClientIdentity,
    client_type: ClientType,
    outcome: &str,
    detail: Option<String>,
) {
    let mut event = AuditEvent::new(kind)
        .with_operation(method)
        .with_client(ClientSummary::from((identity, client_type)))
        .with_outcome(outcome);
    if let Some(detail) = detail {
        event = event.with_detail(detail);
    }
    state.audit.emit(event);
}

async fn validate_agent_session_token(
    state: &DaemonState,
    token: &str,
    uid: u32,
) -> Option<String> {
    // Delegation tokens carry signed claims: verify the signature and expiry
    // BEFORE consulting the session table. A token that parses as a delegation
    // token but fails verification is rejected outright — the constant-time
    // store match below is the liveness check, not the authenticity check.
    if token.starts_with("opqd1.") {
        let rt = state.identity.as_ref()?;
        let key = rt.signing.verifying_key();
        if let Err(e) = verify_delegation_token(token, &key, now_unix()) {
            warn!("delegation token rejected: {e}");
            return None;
        }
    }

    let now = SystemTime::now();
    let mut sessions = state.agent_sessions.write().await;
    // Expire old sessions opportunistically.
    sessions.retain(|_, s| s.expires_at > now);

    sessions.values().find_map(|session| {
        if session.created_by_uid == uid
            && constant_time_eq(session.token.as_bytes(), token.as_bytes())
        {
            Some(session.session_id.clone())
        } else {
            None
        }
    })
}

/// Classification cannot erase a credential's delegation. An allowlisted CLI
/// running inside a service wrapper must retain the verified service context;
/// supplying a bad token never falls back to an ambient human login.
async fn handshake_session(
    state: &DaemonState,
    token: Option<&str>,
    client_type: ClientType,
    uid: u32,
) -> Result<Option<String>, ()> {
    match token {
        Some(token) => validate_agent_session_token(state, token, uid)
            .await
            .map(Some)
            .ok_or(()),
        None if state.config.enforce_agent_sessions && client_type == ClientType::Agent => Err(()),
        None => Ok(None),
    }
}

/// Methods that build an `OperationRequest` and enter the enclave. These are
/// the requests that carry (and, under `identity.required`, must carry) a
/// verified principal context. Introspection and identity methods are exempt.
/// Which approval backend the daemon should use, or a hard startup error.
///
/// The insecure auto-approve backend demands BOTH the config value and the
/// `OPAQUE_INSECURE_AUTO_APPROVE=1` environment marker; every partial or
/// mismatched combination is a loud refusal, never a silent fallback.
#[derive(Debug, PartialEq, Eq)]
enum ApprovalBackendKind {
    Native,
    InsecureAutoApprove,
}

fn select_approval_backend(
    config_backend: Option<&str>,
    auto_approve_env: bool,
) -> Result<ApprovalBackendKind, String> {
    match config_backend.unwrap_or("native") {
        "native" => {
            if auto_approve_env {
                return Err(
                    "OPAQUE_INSECURE_AUTO_APPROVE=1 is set but approval_backend is not \
                     'insecure_auto_approve' — refusing to start with a half-enabled insecure \
                     backend; unset the variable or set approval_backend"
                        .into(),
                );
            }
            Ok(ApprovalBackendKind::Native)
        }
        "insecure_auto_approve" => {
            if !auto_approve_env {
                return Err(
                    "approval_backend = 'insecure_auto_approve' additionally requires \
                     OPAQUE_INSECURE_AUTO_APPROVE=1 in the daemon environment — refusing to start"
                        .into(),
                );
            }
            Ok(ApprovalBackendKind::InsecureAutoApprove)
        }
        other => Err(format!(
            "unknown approval_backend {other:?} (expected 'native' or 'insecure_auto_approve')"
        )),
    }
}

fn validate_tenant_startup(
    config: &DaemonConfig,
    state_dir: &std::path::Path,
) -> Result<(), String> {
    if config.tenant.is_none()
        && [
            opaque_tenant::tenant::BINDING_FILE,
            opaque_tenant::tenant::LOCK_FILE,
        ]
        .iter()
        .any(|name| std::fs::symlink_metadata(state_dir.join(name)).is_ok())
    {
        return Err("tenant-bound custody requires its tenant configuration".into());
    }
    if (config.inference.is_some() || config.ssh.is_some())
        && (config.tenant.is_none()
            || !config.enable_task_grants
            || !config
                .identity
                .as_ref()
                .is_some_and(|identity| identity.required && !identity.allowed_subjects.is_empty()))
    {
        return Err("tenant inference and SSH require task grants and identity.required=true with explicit identity.allowed_subjects membership".into());
    }
    Ok(())
}

fn is_operation_method(method: &str) -> bool {
    if method.starts_with("identity.provisioning.") || method.starts_with("scope_") {
        return true;
    }
    matches!(
        method,
        "execute"
            | "github"
            | "gitlab"
            | "onepassword"
            | "bitwarden"
            | "exec"
            | "task_plan"
            | "task_plan_inference"
            | "task_plan_ssh"
            | "mcp_call"
            | "mcp_catalog"
            | "mcp_get"
            | "mcp_revoke"
            | "task_run"
            | "task_get"
            | "task_list"
            | "task_revoke"
            | "task_reconcile"
            | "identity.role_set"
    )
}

/// Re-validate the delegation behind an agent session and build the verified
/// [`PrincipalContext`] for this request.
///
/// Runs on EVERY operation request (like the agent-session TTL re-check), so
/// revocation, human-session expiry, and principal disablement take effect
/// mid-connection:
///
/// - `Ok(None)` — the session carries no delegation (identity not configured,
///   or a legacy hex-token session): nothing to attach.
/// - `Ok(Some(ctx))` — the delegation is live; `sub_roles` are resolved fresh
///   from the store so role edits apply immediately.
/// - `Err(reason)` — the session HAS a delegation that is no longer valid
///   (fail closed: the caller must reject operation requests).
///
/// Thin wrapper kept so the many existing call sites (in this file and in
/// `task_api.rs`/`provisioning_api.rs`) don't need to change; the real logic
/// now lives in `<DaemonState as EnclaveFacade>::resolve_principal_context`
/// so it is reachable through the trait by code that only has `&dyn
/// EnclaveFacade`, not a concrete `&DaemonState`.
async fn resolve_principal_context(
    state: &DaemonState,
    session_id: Option<&str>,
) -> Result<Option<PrincipalContext>, String> {
    <DaemonState as EnclaveFacade>::resolve_principal_context(state, session_id).await
}

async fn handle_request(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
) -> Response {
    // Resolve the verified principal context for operation-executing requests.
    // Fails closed: a session whose delegation has died (revoked, expired
    // human login, disabled principal) can no longer execute anything, even
    // though the connection itself stays up for introspection methods.
    let principal_ctx = if is_operation_method(&req.method) {
        match resolve_principal_context(state, session_id).await {
            Ok(ctx) => ctx,
            Err(reason) => {
                warn!("rejecting {}: delegation invalid: {reason}", req.method);
                return Response::err(
                    Some(req.id),
                    "delegation_invalid",
                    "the delegation behind this agent session is no longer valid",
                );
            }
        }
    } else {
        None
    };

    // `identity.required`: agent operations must carry a verified delegation.
    // Enforced on operation methods only — introspection, login, and session
    // management stay reachable so an agent can be pointed at `opaque login`.
    if is_operation_method(&req.method)
        && client_type == ClientType::Agent
        && state.identity.as_ref().is_some_and(|rt| rt.config.required)
        && principal_ctx.is_none()
    {
        return Response::err(
            Some(req.id),
            "identity_required",
            "this daemon requires agent operations to run under a delegation — \
             run `opaque login`, then wrap the agent with `opaque agent run`",
        );
    }

    if req.method.starts_with("scope_") {
        return scope_runtime::handle(state, req, principal_ctx).await;
    }

    if req.method.starts_with("identity.provisioning.") {
        return provisioning_api::handle(
            state,
            req,
            identity,
            client_type,
            session_id,
            principal_ctx,
        )
        .await;
    }

    // Computed once, up front, for every method whose params may carry a
    // `workspace` claim: the `github`/`gitlab`/`onepassword`/`bitwarden`/
    // `exec` family (via `wrapper_workspace` below) and the fixed-manifest
    // task-planning family (`task_get`/`task_list`/`task_revoke` never look
    // at `workspace`, so they are deliberately excluded — matching exactly
    // which methods reached this check before `task_api` moved to
    // `opaque-bounded-work`). `verified_workspace` (defined below, next to
    // the `verify_workspace` machinery it wraps) used to live in
    // `task_api.rs`; it moved here because it calls this file's kernel-side
    // `verify_workspace`/`workspace_process.rs`, which `opaque-bounded-work`
    // must not reach back into.
    let verified_workspace = if matches!(
        req.method.as_str(),
        "github"
            | "gitlab"
            | "onepassword"
            | "bitwarden"
            | "exec"
            | "task_plan"
            | "task_plan_inference"
            | "task_plan_ssh"
            | "mcp_call"
            | "task_run"
            | "task_reconcile"
    ) {
        verified_workspace(&req.params, identity).await
    } else {
        Ok(None)
    };
    // `github`/`gitlab`/`onepassword`/`bitwarden`/`exec` want the unwrapped
    // value with one uniform, immediate failure response (unchanged
    // behavior). The fixed-manifest task family instead gets the `Result`
    // passed straight through to `task_api::handle`, which funnels a
    // verification failure into its own `"task_unavailable"` error the same
    // way it always has — preserving that pre-move behavior exactly rather
    // than switching it to this uniform response too.
    let wrapper_workspace = if matches!(
        req.method.as_str(),
        "github" | "gitlab" | "onepassword" | "bitwarden" | "exec"
    ) {
        match &verified_workspace {
            Ok(workspace) => workspace.clone(),
            Err(_) => {
                return Response::err(
                    Some(req.id),
                    "workspace_verification_failed",
                    "workspace verification failed",
                );
            }
        }
    } else {
        None
    };

    match req.method.as_str() {
        "mcp_catalog" | "mcp_call" | "mcp_get" | "mcp_revoke" => {
            mcp_gateway::handle(
                state,
                req,
                identity,
                client_type,
                session_id,
                principal_ctx,
                verified_workspace,
            )
            .await
        }
        "task_plan"
        | "task_plan_inference"
        | "task_plan_ssh"
        | "task_run"
        | "task_get"
        | "task_list"
        | "task_revoke"
        | "task_reconcile" => {
            let insecure_auto_approve = state.config.approval_backend.as_deref()
                == Some("insecure_auto_approve")
                || state.config.workstation_test_mode;
            let kernel = opaque_bounded_work::task_api::TaskApiKernel {
                facade: state,
                enclave: state.enclave.as_ref(),
                tasks: state.tasks.as_deref(),
                tenant: state.tenant.as_ref(),
                has_identity: state.identity.is_some(),
                audit: state.audit.as_ref(),
                insecure_auto_approve,
            };
            opaque_bounded_work::task_api::handle(
                &kernel,
                &req,
                identity,
                client_type,
                session_id,
                principal_ctx,
                verified_workspace,
            )
            .await
        }
        "ping" => Response::ok(
            req.id,
            serde_json::json!({ "ok": true, "api_version": opaque_core::API_VERSION }),
        ),
        "operations" => Response::ok(
            req.id,
            serde_json::json!({
                "mode": "live", "operations": mcp_gateway::operation_catalog(state),
            }),
        ),
        "version" => {
            let federation = state.federation.current().map(|a| {
                serde_json::json!({
                    "org": a.org,
                    "bundle_version": a.version,
                    "bundle_digest": &a.digest[..16.min(a.digest.len())],
                })
            });
            Response::ok(
                req.id,
                serde_json::json!({
                    "version": state.version,
                    "api_version": opaque_core::API_VERSION,
                    "federation": federation,
                    "approval_backend": state.config.approval_backend.as_deref().unwrap_or("native"),
                    "workstation_test_mode": state.config.workstation_test_mode,
                    "task_grants_enabled": state.tasks.is_some(),
                    "trust_domain_enforced": state.config.trust_domain.enforce,
                }),
            )
        }
        "whoami" => {
            let identity_required = state.identity.as_ref().is_some_and(|rt| rt.config.required);
            // Agent clients get minimal info to prevent reconnaissance.
            // Human clients get the full dump for debugging identity matching,
            // plus the logged-in principal when a login session is active.
            let payload = match client_type {
                ClientType::Human => {
                    let logged_in = state
                        .identity
                        .as_ref()
                        .and_then(|rt| rt.current_identity_json());
                    serde_json::json!({
                        "uid": identity.uid,
                        "gid": identity.gid,
                        "pid": identity.pid,
                        "exe_path": identity.exe_path.as_ref().map(|p| p.display().to_string()),
                        "exe_sha256": identity.exe_sha256,
                        "client_type": client_type,
                        "agent_session_id": session_id,
                        "identity": logged_in,
                        "identity_required": identity_required,
                    })
                }
                ClientType::Agent => serde_json::json!({
                    "uid": identity.uid,
                    "client_type": client_type,
                    "agent_session_id": session_id,
                    "identity_required": identity_required,
                }),
            };
            Response::ok(req.id, payload)
        }
        "identity.login_start" => {
            let Some(rt) = state.identity.as_ref() else {
                return Response::err(
                    Some(req.id),
                    "identity_not_configured",
                    "no [identity] section in the daemon config",
                );
            };
            match rt.login_start().await {
                Ok(started) => Response::ok(
                    req.id,
                    serde_json::json!({
                        "attempt_id": started.attempt_id,
                        "auth_url": started.auth_url,
                        "expires_in_secs": started.expires_in_secs,
                    }),
                ),
                Err(e) => {
                    warn!("identity.login_start failed: {e}");
                    Response::err(
                        Some(req.id),
                        "login_failed",
                        "could not start a login attempt (is the identity provider reachable?)",
                    )
                }
            }
        }
        "identity.login_status" => {
            let Some(rt) = state.identity.as_ref() else {
                return Response::err(
                    Some(req.id),
                    "identity_not_configured",
                    "no [identity] section in the daemon config",
                );
            };
            let attempt_id = req.params.get("attempt_id").and_then(|v| v.as_str());
            let Some(attempt_id) = attempt_id.and_then(|s| Uuid::parse_str(s).ok()) else {
                return Response::err(Some(req.id), "invalid_params", "attempt_id must be a UUID");
            };
            match rt.login_status(&attempt_id.to_string()) {
                None => Response::err(
                    Some(req.id),
                    "unknown_attempt",
                    "unknown or expired login attempt",
                ),
                Some(identity::login::AttemptOutcome::Pending) => {
                    Response::ok(req.id, serde_json::json!({ "status": "pending" }))
                }
                Some(identity::login::AttemptOutcome::Done { .. }) => Response::ok(
                    req.id,
                    serde_json::json!({
                        "status": "complete",
                        "identity": rt.current_identity_json(),
                    }),
                ),
                Some(identity::login::AttemptOutcome::Failed { reason }) => Response::ok(
                    req.id,
                    serde_json::json!({ "status": "failed", "reason": reason }),
                ),
            }
        }
        "identity.logout" => {
            let Some(rt) = state.identity.as_ref() else {
                return Response::err(
                    Some(req.id),
                    "identity_not_configured",
                    "no [identity] section in the daemon config",
                );
            };
            // Capture who is logging out BEFORE revoking their session.
            let label = rt
                .current_human_principal()
                .map(|p| p.display_label())
                .unwrap_or_else(|| "none".into());
            match rt.store.revoke_all_human_sessions() {
                Ok(revoked) => {
                    info!("identity.logout revoked {revoked} human session(s)");
                    state.audit.emit(
                        AuditEvent::new(AuditEventKind::IdentityLogout)
                            .with_operation("identity.logout")
                            .with_client(ClientSummary::from((identity, client_type)))
                            .with_outcome("ok")
                            .with_detail(format!("revoked={revoked} current_principal={label}")),
                    );
                    Response::ok(req.id, serde_json::json!({ "revoked": revoked }))
                }
                Err(e) => {
                    warn!("identity.logout failed: {e}");
                    Response::err(Some(req.id), "internal", "failed to revoke sessions")
                }
            }
        }
        "identity.principal_list" => {
            let Some(rt) = state.identity.as_ref() else {
                return Response::err(
                    Some(req.id),
                    "identity_not_configured",
                    "no [identity] section in the daemon config",
                );
            };
            // Once any human is registered, listing requires an active login
            // session (bootstrap-phase listing stays open so the first login
            // can be verified). Client classification is NOT a gate here.
            let humans = rt.store.count_humans().unwrap_or(0);
            if humans > 0 && rt.current_human_principal().is_none() {
                return Response::err(
                    Some(req.id),
                    "not_authorized",
                    "an active login session is required (run `opaque login`)",
                );
            }
            match rt.store.list_principals() {
                Ok(principals) => {
                    let list: Vec<serde_json::Value> = principals
                        .iter()
                        .map(|p| {
                            serde_json::json!({
                                "id": p.id.as_str(),
                                "kind": match &p.kind {
                                    opaque_core::identity::PrincipalKind::Human { .. } => "human",
                                    opaque_core::identity::PrincipalKind::Agent { .. } => "agent",
                                    opaque_core::identity::PrincipalKind::Service { .. } => "service",
                                },
                                "label": p.display_label(),
                                "roles": p.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                                "disabled": p.disabled,
                                "created_at": p.created_at,
                                "last_seen": p.last_seen,
                            })
                        })
                        .collect();
                    Response::ok(req.id, serde_json::json!({ "principals": list }))
                }
                Err(e) => {
                    warn!("identity.principal_list failed: {e}");
                    Response::err(Some(req.id), "internal", "failed to list principals")
                }
            }
        }
        "identity.role_set" => {
            identity::handle_role_set(state, req, identity, client_type, principal_ctx, session_id)
                .await
        }
        "identity.delegation_list" => {
            let Some(rt) = state.identity.as_ref() else {
                return Response::err(
                    Some(req.id),
                    "identity_not_configured",
                    "no [identity] section in the daemon config",
                );
            };
            // Same shape as principal_list: open during bootstrap, then
            // restricted to an active admin/auditor login session.
            let humans = rt.store.count_humans().unwrap_or(0);
            if humans > 0
                && !(rt.current_human_has_role(opaque_core::identity::Role::Admin)
                    || rt.current_human_has_role(opaque_core::identity::Role::Auditor))
            {
                return Response::err(
                    Some(req.id),
                    "not_authorized",
                    "listing delegations requires an active admin or auditor login session",
                );
            }
            match rt.store.list_delegations() {
                Ok(delegations) => {
                    let label_of = |id: &PrincipalId| -> String {
                        rt.store
                            .get_principal(id)
                            .ok()
                            .flatten()
                            .map(|p| p.display_label())
                            .unwrap_or_else(|| id.as_str().to_owned())
                    };
                    let list: Vec<serde_json::Value> = delegations
                        .iter()
                        .map(|d| {
                            serde_json::json!({
                                "jti": d.jti,
                                "sub": d.sub_principal.as_str(),
                                "sub_label": label_of(&d.sub_principal),
                                "act": d.act_principal.as_str(),
                                "act_label": label_of(&d.act_principal),
                                "mode": d.mode.as_str(),
                                "human_session_id": d.human_session_id,
                                "approved_by": d.approved_by.as_ref().map(|p| p.as_str().to_owned()),
                                "created_at": d.created_at,
                                "expires_at": d.expires_at,
                                "revoked_at": d.revoked_at,
                            })
                        })
                        .collect();
                    Response::ok(req.id, serde_json::json!({ "delegations": list }))
                }
                Err(e) => {
                    warn!("identity.delegation_list failed: {e}");
                    Response::err(Some(req.id), "internal", "failed to list delegations")
                }
            }
        }
        "agent_session_start" => {
            agent_session::handle_start(state, req, identity, client_type).await
        }
        "agent_session_end" => agent_session::handle_end(state, req, identity, client_type).await,
        "agent_session_list" => agent_session::handle_list(state, req, identity, client_type).await,
        "leases" => {
            // NOTE (software-first): no longer gated on client classification
            // (audit-only at a shared uid). Read-only lease metadata; a sound
            // restriction from a co-resident agent needs the separate-uid split.
            let leases = state.enclave.active_leases();
            Response::ok(
                req.id,
                serde_json::json!({
                    "count": leases.len(),
                    "leases": leases,
                }),
            )
        }
        "device_pair_start" => {
            let Some(pm) = &state.pairing else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "second-device approvals are not enabled — set [approval] \
                     second_device = true in the daemon config",
                );
            };

            // SECURITY: pairing begins the addition of a new APPROVER channel,
            // so it needs a fresh out-of-band approval. The QR nonce this
            // returns is deliberately weak authority: whatever completes /pair
            // with it lands QUARANTINED until the fingerprint ceremony.
            if let Err(e) = state
                .enclave
                .request_control_approval(
                    identity,
                    client_type,
                    "device_pair_start",
                    "Begin pairing a new approver device",
                    "the paired device gains approval authority only after you \
                     confirm its key fingerprint",
                )
                .await
            {
                emit_daemon_method_audit(
                    state,
                    AuditEventKind::OperationFailed,
                    "device_pair_start",
                    identity,
                    client_type,
                    "permission_denied",
                    Some(format!("pairing start not approved: {e}")),
                );
                return Response::err(
                    Some(req.id),
                    "permission_denied",
                    "starting a device pairing requires out-of-band approval",
                );
            }

            // Attribution captured NOW, at ceremony start: this is the
            // principal whose phone this is supposed to become, and the one
            // SoD will treat as the device's approver identity.
            let initiated_by = state.identity.as_ref().and_then(|rt| {
                rt.current_human_principal()
                    .filter(|p| !p.disabled)
                    .map(|p| p.id.as_str().to_owned())
            });
            let (payload, _nonce) = pm.generate_qr_payload(initiated_by);
            emit_daemon_method_audit(
                state,
                AuditEventKind::OperationSucceeded,
                "device_pair_start",
                identity,
                client_type,
                "pairing_session_created",
                Some(format!("expires_at={}", payload.expires_at)),
            );
            Response::ok(
                req.id,
                serde_json::json!({
                    "qr_payload": payload,
                    "server_addr": state.approval_server_addr.map(|a| a.to_string()),
                }),
            )
        }
        "device_list" => {
            let Some(pm) = &state.pairing else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "second-device approvals are not enabled",
                );
            };
            match pm.list_devices() {
                Ok(devices) => {
                    let rows: Vec<serde_json::Value> = devices
                        .iter()
                        .map(|d| {
                            serde_json::json!({
                                "device_id": d.device_id,
                                "name": d.name,
                                "fingerprint": d.key_fingerprint(),
                                "paired_at": d.paired_at,
                                "last_seen": d.last_seen,
                                "revoked": d.revoked,
                                "confirmed": d.confirmed,
                                "paired_by": d.paired_by,
                            })
                        })
                        .collect();
                    Response::ok(
                        req.id,
                        serde_json::json!({ "count": rows.len(), "devices": rows }),
                    )
                }
                Err(e) => Response::err(
                    Some(req.id),
                    "internal",
                    format!("device store unavailable: {e}"),
                ),
            }
        }
        "device_pair_confirm" => {
            let Some(pm) = &state.pairing else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "second-device approvals are not enabled",
                );
            };
            let device_id = req
                .params
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if device_id.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'device_id'");
            }
            let device = match pm.list_devices() {
                Ok(devices) => match devices.into_iter().find(|d| d.device_id == device_id) {
                    Some(d) => d,
                    None => {
                        return Response::err(Some(req.id), "not_found", "no such device");
                    }
                },
                Err(e) => {
                    return Response::err(
                        Some(req.id),
                        "internal",
                        format!("device store unavailable: {e}"),
                    );
                }
            };

            // SECURITY: this approval prompt IS the anti-hijack ceremony. The
            // human compares the fingerprint below with the one their phone
            // displays; a device paired by anything else (an agent racing the
            // nonce with its own key) shows a fingerprint the phone does not.
            let reason = format!(
                "device \"{}\" key fingerprint {}  — CONFIRM ONLY IF YOUR DEVICE \
                 SHOWS THE SAME FINGERPRINT",
                enclave::sanitize_for_display(&device.name, 64),
                device.key_fingerprint()
            );
            if let Err(e) = state
                .enclave
                .request_control_approval(
                    identity,
                    client_type,
                    "device_pair_confirm",
                    "Grant approval authority to a paired device",
                    &reason,
                )
                .await
            {
                emit_daemon_method_audit(
                    state,
                    AuditEventKind::OperationFailed,
                    "device_pair_confirm",
                    identity,
                    client_type,
                    "permission_denied",
                    Some(format!("device confirmation not approved: {e}")),
                );
                return Response::err(
                    Some(req.id),
                    "permission_denied",
                    "confirming a device requires out-of-band approval",
                );
            }

            match pm.confirm_device(device_id) {
                Ok(confirmed) => {
                    emit_daemon_method_audit(
                        state,
                        AuditEventKind::OperationSucceeded,
                        "device_pair_confirm",
                        identity,
                        client_type,
                        "device_confirmed",
                        Some(format!(
                            "device_id={} fingerprint={}",
                            confirmed.device_id,
                            confirmed.key_fingerprint()
                        )),
                    );
                    Response::ok(
                        req.id,
                        serde_json::json!({
                            "device_id": confirmed.device_id,
                            "name": confirmed.name,
                            "confirmed": true,
                        }),
                    )
                }
                Err(e) => Response::err(
                    Some(req.id),
                    "internal",
                    format!("confirmation failed: {e}"),
                ),
            }
        }
        "device_revoke" => {
            let Some(pm) = &state.pairing else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "second-device approvals are not enabled",
                );
            };
            let device_id = req
                .params
                .get("device_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if device_id.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'device_id'");
            }
            // Revocation removes approval authority — the safe direction, so
            // it is not approval-gated (an emergency kill must never wait on
            // the very factor being killed). Audited with the client identity.
            match pm.revoke_device(device_id) {
                Ok(()) => {
                    emit_daemon_method_audit(
                        state,
                        AuditEventKind::OperationSucceeded,
                        "device_revoke",
                        identity,
                        client_type,
                        "device_revoked",
                        Some(format!("device_id={device_id}")),
                    );
                    Response::ok(
                        req.id,
                        serde_json::json!({ "device_id": device_id, "revoked": true }),
                    )
                }
                Err(e) => Response::err(Some(req.id), "not_found", format!("{e}")),
            }
        }
        "attestation_report" => {
            // Read-only posture proof. Deliberately NOT approval-gated: a
            // verifier or auditor must be able to ask an unhealthy daemon
            // for its posture, and the report's contents are the daemon's
            // own state, never secrets. Freshness and authenticity come from
            // the caller's nonce and the signature.
            let nonce = req
                .params
                .get("nonce")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if nonce.len() < 16
                || nonce.len() > 128
                || !nonce.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Response::err(
                    Some(req.id),
                    "bad_request",
                    "'nonce' must be 16-128 hex characters (caller-chosen, anti-replay)",
                );
            }
            match state.attestation.report(&nonce) {
                Ok(report) => {
                    emit_daemon_method_audit(
                        state,
                        AuditEventKind::OperationSucceeded,
                        "attestation_report",
                        identity,
                        client_type,
                        "report_issued",
                        None,
                    );
                    Response::ok(
                        req.id,
                        serde_json::json!({
                            "report": report,
                            "attestation_key": state.attestation.public_key_hex(),
                        }),
                    )
                }
                Err(e) => Response::err(Some(req.id), "internal", e),
            }
        }
        "fido2_register_start" => {
            let Some(f2) = &state.fido2 else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "FIDO2 approvals are not enabled — set [approval] fido2 = true",
                );
            };
            // Registering a credential adds an APPROVER — approval-gated,
            // like device pairing. (This simplified flow verifies UP + RP +
            // key, not attestation chains; the human approval here is the
            // authorization anchor for the new credential.)
            if let Err(e) = state
                .enclave
                .request_control_approval(
                    identity,
                    client_type,
                    "fido2_register_start",
                    "Register a FIDO2 hardware key / passkey as an approver",
                    "the credential completing this registration will be able to \
                     approve operations",
                )
                .await
            {
                emit_daemon_method_audit(
                    state,
                    AuditEventKind::OperationFailed,
                    "fido2_register_start",
                    identity,
                    client_type,
                    "permission_denied",
                    Some(format!("registration not approved: {e}")),
                );
                return Response::err(
                    Some(req.id),
                    "permission_denied",
                    "registering a FIDO2 credential requires out-of-band approval",
                );
            }
            match f2.register_begin() {
                Ok((challenge, rp_id)) => {
                    emit_daemon_method_audit(
                        state,
                        AuditEventKind::OperationSucceeded,
                        "fido2_register_start",
                        identity,
                        client_type,
                        "registration_challenge_issued",
                        None,
                    );
                    Response::ok(
                        req.id,
                        serde_json::json!({ "challenge": challenge, "rp_id": rp_id }),
                    )
                }
                Err(e) => Response::err(Some(req.id), "internal", e),
            }
        }
        "fido2_register_complete" => {
            let Some(f2) = &state.fido2 else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "FIDO2 approvals are not enabled",
                );
            };
            let label = req
                .params
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("hardware key");
            let response: opaque_approval::fido2::Fido2RegistrationResponse = match req
                .params
                .get("response")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
            {
                Some(r) => r,
                None => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        "missing or malformed 'response' (registration payload)",
                    );
                }
            };
            match f2.register_complete(&response, &enclave::sanitize_for_display(label, 64)) {
                Ok(credential) => {
                    emit_daemon_method_audit(
                        state,
                        AuditEventKind::OperationSucceeded,
                        "fido2_register_complete",
                        identity,
                        client_type,
                        "credential_registered",
                        Some(format!(
                            "credential_id={} label={}",
                            credential
                                .credential_id
                                .chars()
                                .take(12)
                                .collect::<String>(),
                            credential.label
                        )),
                    );
                    Response::ok(
                        req.id,
                        serde_json::json!({
                            "credential_id": credential.credential_id,
                            "label": credential.label,
                        }),
                    )
                }
                Err(e) => {
                    emit_daemon_method_audit(
                        state,
                        AuditEventKind::OperationFailed,
                        "fido2_register_complete",
                        identity,
                        client_type,
                        "registration_rejected",
                        Some(e.clone()),
                    );
                    Response::err(Some(req.id), "invalid_registration", e)
                }
            }
        }
        "fido2_list" => {
            let Some(f2) = &state.fido2 else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "FIDO2 approvals are not enabled",
                );
            };
            match f2.list_credentials() {
                Ok(creds) => {
                    let rows: Vec<serde_json::Value> = creds
                        .iter()
                        .map(|c| {
                            serde_json::json!({
                                "credential_id": c.credential_id,
                                "label": c.label,
                                "created_at": c.created_at.to_rfc3339(),
                                "counter": c.counter,
                            })
                        })
                        .collect();
                    Response::ok(
                        req.id,
                        serde_json::json!({ "count": rows.len(), "credentials": rows }),
                    )
                }
                Err(e) => Response::err(
                    Some(req.id),
                    "internal",
                    format!("credential store unavailable: {e}"),
                ),
            }
        }
        "fido2_remove" => {
            let Some(f2) = &state.fido2 else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "FIDO2 approvals are not enabled",
                );
            };
            let credential_id = req
                .params
                .get("credential_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if credential_id.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'credential_id'");
            }
            // Like device_revoke: removing an approver is the safe direction.
            if let (Some(rt), Some(tenant)) = (&state.identity, &state.tenant)
                && let Err(error) =
                    rt.store
                        .revoke_by_credential(tenant.binding(), credential_id, now_unix())
            {
                return Response::err(Some(req.id), "revocation_failed", error);
            }
            match f2.remove_credential(credential_id) {
                Ok(removed) => {
                    emit_daemon_method_audit(
                        state,
                        AuditEventKind::OperationSucceeded,
                        "fido2_remove",
                        identity,
                        client_type,
                        "credential_removed",
                        Some(format!("label={}", removed.label)),
                    );
                    Response::ok(
                        req.id,
                        serde_json::json!({ "credential_id": credential_id, "removed": true }),
                    )
                }
                Err(e) => Response::err(Some(req.id), "not_found", format!("{e}")),
            }
        }
        "fido2_pending" => {
            let Some(f2) = &state.fido2 else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "FIDO2 approvals are not enabled",
                );
            };
            let rounds: Vec<serde_json::Value> = f2
                .pending_rounds()
                .into_iter()
                .map(|(request_id, challenge, rp_id, allowed)| {
                    serde_json::json!({
                        "request_id": request_id,
                        "challenge": challenge,
                        "rp_id": rp_id,
                        "allowed_credentials": allowed,
                    })
                })
                .collect();
            Response::ok(
                req.id,
                serde_json::json!({ "count": rounds.len(), "rounds": rounds }),
            )
        }
        "fido2_respond" => {
            let Some(f2) = &state.fido2 else {
                return Response::err(
                    Some(req.id),
                    "factor_disabled",
                    "FIDO2 approvals are not enabled",
                );
            };
            let request_id = req
                .params
                .get("request_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if request_id.is_empty() {
                return Response::err(Some(req.id), "bad_request", "missing 'request_id'");
            }
            let assertion: opaque_approval::fido2::Fido2Assertion = match req
                .params
                .get("assertion")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
            {
                Some(a) => a,
                None => {
                    return Response::err(
                        Some(req.id),
                        "bad_request",
                        "missing or malformed 'assertion'",
                    );
                }
            };
            match f2.respond(request_id, &assertion) {
                Ok(verified) => {
                    emit_daemon_method_audit(
                        state,
                        AuditEventKind::OperationSucceeded,
                        "fido2_respond",
                        identity,
                        client_type,
                        "assertion_verified",
                        Some(format!("label={}", verified.credential.label)),
                    );
                    Response::ok(req.id, serde_json::json!({ "verified": true }))
                }
                Err(e) => {
                    emit_daemon_method_audit(
                        state,
                        AuditEventKind::OperationFailed,
                        "fido2_respond",
                        identity,
                        client_type,
                        "assertion_rejected",
                        Some(e.clone()),
                    );
                    Response::err(Some(req.id), "invalid_assertion", e)
                }
            }
        }
        "execute" => {
            rpc_wrappers::handle_execute(state, req, identity, client_type, principal_ctx).await
        }
        "github" => {
            opaque_providers::github::handle_github_rpc(
                &req,
                state,
                identity,
                client_type,
                principal_ctx.as_ref(),
                wrapper_workspace.clone(),
            )
            .await
        }
        "gitlab" => {
            rpc_wrappers::handle_gitlab(
                state,
                req,
                identity,
                client_type,
                principal_ctx,
                wrapper_workspace,
            )
            .await
        }
        "onepassword" => {
            rpc_wrappers::handle_onepassword(
                state,
                req,
                identity,
                client_type,
                principal_ctx,
                wrapper_workspace,
            )
            .await
        }
        "bitwarden" => {
            rpc_wrappers::handle_bitwarden(
                state,
                req,
                identity,
                client_type,
                principal_ctx,
                wrapper_workspace,
            )
            .await
        }
        "exec" => {
            rpc_wrappers::handle_exec(
                state,
                req,
                identity,
                client_type,
                principal_ctx,
                wrapper_workspace,
            )
            .await
        }
        _ => Response::err(Some(req.id), "unknown_method", "unknown method"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    #[test]
    fn every_registered_operation_has_an_explicit_generic_or_task_contract() {
        // A new registration must extend this reviewed inventory and its real
        // preparer/transport tests; it cannot inherit raw-request execution.
        let families: &[(&str, &[&str])] = &[
            (
                "github",
                &[
                    "set_actions_secret",
                    "set_codespaces_secret",
                    "set_dependabot_secret",
                    "set_org_secret",
                    "list_secrets",
                    "delete_secret",
                ],
            ),
            ("gitlab", &["set_ci_variable"]),
            ("onepassword", &["list_vaults", "list_items", "read_field"]),
            (
                "gcp",
                &[
                    "get_secret",
                    "list_secrets",
                    "create_secret",
                    "add_secret_version",
                ],
            ),
            (
                "azure",
                &[
                    "get_secret",
                    "list_secrets",
                    "set_secret",
                    "list_keys",
                    "list_certificates",
                ],
            ),
            (
                "bitwarden",
                &["list_projects", "list_secrets", "read_secret"],
            ),
            (
                "aws",
                &[
                    "get_caller_identity",
                    "assume_role",
                    "list_secrets",
                    "get_secret_value",
                    "create_secret",
                    "put_secret_value",
                    "delete_secret",
                    "get_parameter",
                    "put_parameter",
                    "get_parameters_by_path",
                    "delete_parameter",
                ],
            ),
            ("sandbox", &["exec", "execve_check", "execve_approve"]),
            ("test", &["noop"]),
        ];
        let mut expected: std::collections::BTreeSet<_> = families
            .iter()
            .flat_map(|(family, actions)| {
                actions
                    .iter()
                    .map(move |action| format!("{family}.{action}"))
            })
            .collect();
        assert_eq!(expected.len(), 37);
        expected.extend(
            [enclave::task_operation()]
                .into_iter()
                .chain(enclave::release_task_operations())
                .chain(enclave::inference_task_operations())
                .chain(enclave::ssh_task_operations())
                .map(|def| def.name),
        );
        // MCP uses its dedicated, durably accounted invocation runner. It
        // must remain explicitly reviewed here, with an unlowerable local
        // approval floor, rather than inheriting a generic raw handler.
        let mcp = enclave::mcp_operation();
        assert_eq!(mcp.name, "mcp.call");
        assert_eq!(mcp.default_approval, ApprovalRequirement::Always);
        assert_eq!(mcp.default_factors, vec![ApprovalFactor::LocalBio]);
        assert!(expected.insert(mcp.name));
        let registry = operation_registry().unwrap();
        let actual: std::collections::BTreeSet<_> =
            registry.iter().map(|def| def.name.clone()).collect();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 46);
        // Raw secret bytes must never be cataloged as reference names.
        assert!(
            registry
                .iter()
                .all(|def| !def.secret_ref_param_keys.iter().any(|key| key == "value"))
        );
    }

    fn test_identity() -> ClientIdentity {
        ClientIdentity {
            uid: 501,
            gid: 20,
            pid: Some(1234),
            exe_path: Some("/usr/bin/claude-code".into()),
            exe_sha256: Some("aabbccdd".into()),
            codesign_team_id: None,
            workload: None,
        }
    }

    fn entry_with_path(name: &str, pattern: &str) -> HumanClientEntry {
        HumanClientEntry {
            name: name.into(),
            exe_path: Some(pattern.into()),
            exe_sha256: None,
            codesign_team_id: None,
        }
    }

    #[test]
    fn derive_client_type_matches_by_path() {
        let config = DaemonConfig {
            known_human_clients: vec![entry_with_path("claude", "/usr/bin/claude*")],
            ..Default::default()
        };
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Human);
    }

    #[test]
    fn derive_client_type_matches_by_hash() {
        let config = DaemonConfig {
            known_human_clients: vec![HumanClientEntry {
                name: "claude".into(),
                exe_path: None,
                exe_sha256: Some("AABBCCDD".into()), // case-insensitive
                codesign_team_id: None,
            }],
            ..Default::default()
        };
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Human);
    }

    #[test]
    fn derive_client_type_defaults_to_agent() {
        let config = DaemonConfig {
            known_human_clients: vec![entry_with_path("vscode", "/usr/bin/code*")],
            ..Default::default()
        };
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Agent);
    }

    #[test]
    fn config_empty_all_agents() {
        let config = DaemonConfig::default();
        let id = test_identity();
        assert_eq!(derive_client_type(&id, &config), ClientType::Agent);
    }

    #[test]
    fn entry_matches_codesign_team_id() {
        let entry = HumanClientEntry {
            name: "xcode".into(),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: Some("TEAM123".into()),
        };
        let mut id = test_identity();
        id.codesign_team_id = Some("TEAM123".into());
        assert!(entry_matches(&id, &entry));

        id.codesign_team_id = Some("OTHER".into());
        assert!(!entry_matches(&id, &entry));

        id.codesign_team_id = None;
        assert!(!entry_matches(&id, &entry));
    }

    #[test]
    fn entry_matches_multi_criteria_all_must_match() {
        // When both exe_path and exe_sha256 are specified, both must match.
        let entry = HumanClientEntry {
            name: "strict".into(),
            exe_path: Some("/usr/bin/claude*".into()),
            exe_sha256: Some("aabbccdd".into()),
            codesign_team_id: None,
        };

        // Both match → ok.
        let id = test_identity();
        assert!(entry_matches(&id, &entry));

        // Path matches, hash doesn't → reject.
        let mut id2 = test_identity();
        id2.exe_sha256 = Some("different".into());
        assert!(!entry_matches(&id2, &entry));

        // Hash matches, path doesn't → reject.
        let mut id3 = test_identity();
        id3.exe_path = Some("/opt/bin/other".into());
        assert!(!entry_matches(&id3, &entry));
    }

    #[test]
    fn entry_matches_empty_entry_rejects_all() {
        let empty = HumanClientEntry {
            name: "empty".into(),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        };
        let id = test_identity();
        assert!(!entry_matches(&id, &empty));
    }

    #[test]
    fn entry_matches_identity_missing_exe_path() {
        let entry = entry_with_path("cli", "/usr/bin/claude*");
        let mut id = test_identity();
        id.exe_path = None;
        assert!(!entry_matches(&id, &entry));
    }

    #[test]
    fn entry_matches_identity_missing_hash() {
        let entry = HumanClientEntry {
            name: "hash-only".into(),
            exe_path: None,
            exe_sha256: Some("aabbccdd".into()),
            codesign_team_id: None,
        };
        let mut id = test_identity();
        id.exe_sha256 = None;
        assert!(!entry_matches(&id, &entry));
    }

    #[test]
    fn handshake_valid_accepted() {
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v1",
            "daemon_token": token,
        }))
        .unwrap();
        assert!(validate_handshake(&frame, token).is_some());
    }

    #[test]
    fn handshake_invalid_token_rejected() {
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v1",
            "daemon_token": "wrong_token",
        }))
        .unwrap();
        assert!(validate_handshake(&frame, "correct_token").is_none());
    }

    #[test]
    fn handshake_missing_fields_rejected() {
        let frame = serde_json::to_vec(&serde_json::json!({"handshake": "v1"})).unwrap();
        assert!(validate_handshake(&frame, "token").is_none());
    }

    #[test]
    fn handshake_wrong_version_rejected() {
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v99",
            "daemon_token": "token",
        }))
        .unwrap();
        assert!(validate_handshake(&frame, "token").is_none());
    }

    #[test]
    fn handshake_garbage_rejected() {
        assert!(validate_handshake(b"not json at all", "token").is_none());
    }

    #[test]
    fn handshake_with_session_token_roundtrip() {
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let frame = serde_json::to_vec(&serde_json::json!({
            "handshake": "v1",
            "daemon_token": token,
            "session_token": "session_123",
        }))
        .unwrap();
        let hs = validate_handshake(&frame, token).expect("handshake should parse");
        assert_eq!(hs.session_token.as_deref(), Some("session_123"));
    }

    #[test]
    fn generate_daemon_token_is_64_hex_chars() {
        let token = generate_daemon_token();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_daemon_token_is_unique() {
        let t1 = generate_daemon_token();
        let t2 = generate_daemon_token();
        assert_ne!(t1, t2);
    }

    #[test]
    fn write_daemon_token_creates_file() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_path = dir.join("opaqued.sock");
        let token = "test_token_hex";
        let token_path = write_daemon_token(&socket_path, token).unwrap();
        assert_eq!(token_path, dir.join(DAEMON_TOKEN_FILENAME));
        let contents = std::fs::read_to_string(&token_path).unwrap();
        assert_eq!(contents, token);

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = token_path.metadata().unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
        }

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Peer-uid gating (both modes) is covered by trust_domain::peer_uid_allowed
    // unit tests; the connection-level wiring is exercised by the daemon e2e
    // tests, which connect from the same uid in shared mode.

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hi", b"hello"));
    }

    #[test]
    fn safe_command_has_minimal_env() {
        let cmd = safe_command("echo");
        let envs: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        assert_eq!(
            envs.get("PATH").map(|s| s.as_str()),
            Some("/usr/bin:/usr/local/bin:/bin")
        );
        assert_eq!(envs.get("LC_ALL").map(|s| s.as_str()), Some("C"));
        assert_eq!(
            envs.get("GIT_TERMINAL_PROMPT").map(|s| s.as_str()),
            Some("0")
        );
        assert_eq!(
            envs.get("GIT_CONFIG_NOSYSTEM").map(|s| s.as_str()),
            Some("1")
        );
        assert_eq!(
            envs.get("GIT_CONFIG_GLOBAL").map(|s| s.as_str()),
            Some("/dev/null")
        );
        // Should not contain common env vars that would be inherited.
        assert!(!envs.contains_key("USER"));
        assert!(!envs.contains_key("SHELL"));
    }

    #[test]
    fn safe_command_blocks_git_config() {
        let cmd = safe_command("git");
        let envs: HashMap<String, String> = cmd
            .get_envs()
            .filter_map(|(k, v)| {
                Some((
                    k.to_string_lossy().into_owned(),
                    v?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        // GIT_CONFIG_NOSYSTEM prevents reading /etc/gitconfig.
        assert_eq!(
            envs.get("GIT_CONFIG_NOSYSTEM").map(|s| s.as_str()),
            Some("1")
        );
        // The global config override prevents reading user git configuration.
        assert_eq!(
            envs.get("GIT_CONFIG_GLOBAL").map(|s| s.as_str()),
            Some("/dev/null")
        );
    }

    #[test]
    fn empty_entry_does_not_match() {
        let entry = HumanClientEntry {
            name: "empty".into(),
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
        };
        let id = test_identity();
        assert!(!entry_matches(&id, &entry));
    }

    #[test]
    fn config_rejects_empty_human_client_entry() {
        let toml_str = r#"
[[known_human_clients]]
name = "empty-entry"

[[known_human_clients]]
name = "valid-entry"
exe_path = "/usr/bin/claude*"
"#;
        let mut config: DaemonConfig = toml_edit::de::from_str(toml_str).unwrap();
        assert_eq!(config.known_human_clients.len(), 2);

        // Simulate the filtering that load_config() performs.
        config.known_human_clients.retain(|entry| {
            entry.exe_path.is_some()
                || entry.exe_sha256.is_some()
                || entry.codesign_team_id.is_some()
        });
        assert_eq!(config.known_human_clients.len(), 1);
        assert_eq!(
            config.known_human_clients[0].exe_path.as_deref(),
            Some("/usr/bin/claude*")
        );
    }

    #[test]
    fn config_toml_roundtrip() {
        let toml_str = r#"
[[known_human_clients]]
name = "claude-code"
exe_path = "/usr/bin/claude*"

[[known_human_clients]]
name = "vscode"
exe_sha256 = "deadbeef"
"#;
        let config: DaemonConfig = toml_edit::de::from_str(toml_str).unwrap();
        assert_eq!(config.known_human_clients.len(), 2);
        assert_eq!(
            config.known_human_clients[0].exe_path.as_deref(),
            Some("/usr/bin/claude*")
        );
        assert_eq!(
            config.known_human_clients[1].exe_sha256.as_deref(),
            Some("deadbeef")
        );
    }

    // -----------------------------------------------------------------------
    // PID file tests
    // -----------------------------------------------------------------------

    #[test]
    fn pid_file_acquire_creates_file_with_pid() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-pid-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_path = dir.join("opaqued.pid");

        let guard = PidFileGuard::acquire(pid_path.clone()).unwrap();
        let contents = std::fs::read_to_string(&pid_path).unwrap();
        assert_eq!(contents, format!("{}", std::process::id()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = pid_path.metadata().unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
        }

        drop(guard);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_file_double_acquire_fails() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-pid-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_path = dir.join("opaqued.pid");

        let _guard1 = PidFileGuard::acquire(pid_path.clone()).unwrap();
        let result = PidFileGuard::acquire(pid_path.clone());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        assert!(err.to_string().contains("daemon already running"));

        drop(_guard1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_file_cleaned_up_on_drop() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-pid-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_path = dir.join("opaqued.pid");

        let guard = PidFileGuard::acquire(pid_path.clone()).unwrap();
        assert!(pid_path.exists());
        drop(guard);
        assert!(!pid_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pid_file_reacquire_after_drop() {
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join(format!("opaque-pid-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid_path = dir.join("opaqued.pid");

        let guard1 = PidFileGuard::acquire(pid_path.clone()).unwrap();
        drop(guard1);
        // Should succeed after first guard is dropped.
        let _guard2 = PidFileGuard::acquire(pid_path.clone()).unwrap();

        drop(_guard2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------
    // Rate limiter tests
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiter_allows_burst() {
        let mut rl = ConnectionRateLimiter::new(5, 10.0);
        for _ in 0..5 {
            assert!(rl.check());
        }
    }

    #[test]
    fn rate_limiter_rejects_above_burst() {
        let mut rl = ConnectionRateLimiter::new(3, 10.0);
        assert!(rl.check());
        assert!(rl.check());
        assert!(rl.check());
        // 4th should be rejected (burst = 3).
        assert!(!rl.check());
    }

    #[test]
    fn rate_limiter_rejects_above_sustained() {
        // sustained_per_sec = 2 means max 2 requests in the 1s window.
        let mut rl = ConnectionRateLimiter::new(10, 2.0);
        assert!(rl.check());
        assert!(rl.check());
        // 3rd should be rejected (sustained = 2).
        assert!(!rl.check());
    }

    // -----------------------------------------------------------------------
    // api_version tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ping_includes_api_version() {
        let state = make_test_state();
        let req = Request {
            id: 1,
            method: "ping".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        let result = resp.result.unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["api_version"], opaque_core::API_VERSION);
    }

    #[tokio::test]
    async fn version_includes_api_version() {
        let state = make_test_state();
        let req = Request {
            id: 2,
            method: "version".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        let result = resp.result.unwrap();
        assert!(result["version"].is_string());
        assert_eq!(result["api_version"], opaque_core::API_VERSION);
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let state = make_test_state();
        let req = Request {
            id: 3,
            method: "nonexistent".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, "unknown_method");
    }

    #[tokio::test]
    async fn agent_session_start_succeeds_with_approval() {
        // Software-first: session creation is gated on out-of-band approval, not on
        // client classification — an agent whose request is approved succeeds.
        let state = make_test_state();
        let req = Request {
            id: 4,
            method: "agent_session_start".into(),
            params: serde_json::json!({}),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Agent, None).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("result expected");
        assert!(result.get("session_id").and_then(|v| v.as_str()).is_some());
        assert!(
            result
                .get("session_token")
                .and_then(|v| v.as_str())
                .is_some()
        );
    }

    #[tokio::test]
    async fn agent_session_start_denied_without_approval() {
        // When approval is not granted (no human present, or an agent that cannot
        // satisfy it), session creation is denied regardless of classification —
        // this is what stops an agent minting its own session.
        let state = make_denying_test_state();
        let req = Request {
            id: 5,
            method: "agent_session_start".into(),
            params: serde_json::json!({}),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Agent, None).await;
        let err = resp.error.expect("expected permission denial");
        assert_eq!(err.code, "permission_denied");
    }

    #[tokio::test]
    async fn agent_session_list_allowed_for_local_callers() {
        // Software-first: listing is no longer gated on classification (audit-only
        // at a shared uid); it is scoped to the caller's own uid and hides tokens.
        let state = make_test_state();
        let req = Request {
            id: 6,
            method: "agent_session_list".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Agent, None).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("result expected");
        assert!(result.get("sessions").and_then(|v| v.as_array()).is_some());
    }

    #[tokio::test]
    async fn agent_session_list_filters_to_calling_uid_and_hides_token() {
        let state = make_test_state();
        let now = SystemTime::now();

        state.agent_sessions.write().await.insert(
            "s-own-active".into(),
            AgentSession {
                session_id: "s-own-active".into(),
                token: "tok-own-active".into(),
                created_by_uid: 501,
                expires_at: now + std::time::Duration::from_secs(600),
                label: Some("own-active".into()),
                delegation: None,
            },
        );
        state.agent_sessions.write().await.insert(
            "s-own-expired".into(),
            AgentSession {
                session_id: "s-own-expired".into(),
                token: "tok-own-expired".into(),
                created_by_uid: 501,
                expires_at: now - std::time::Duration::from_secs(1),
                label: Some("own-expired".into()),
                delegation: None,
            },
        );
        state.agent_sessions.write().await.insert(
            "s-other-active".into(),
            AgentSession {
                session_id: "s-other-active".into(),
                token: "tok-other-active".into(),
                created_by_uid: 777,
                expires_at: now + std::time::Duration::from_secs(600),
                label: Some("other-active".into()),
                delegation: None,
            },
        );

        let req = Request {
            id: 7,
            method: "agent_session_list".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("result expected");
        assert_eq!(result.get("count").and_then(|v| v.as_u64()), Some(1));

        let sessions = result
            .get("sessions")
            .and_then(|v| v.as_array())
            .expect("sessions array expected");
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].get("session_id").and_then(|v| v.as_str()),
            Some("s-own-active")
        );
        assert!(
            sessions[0].get("session_token").is_none(),
            "session token must never be returned"
        );

        // Expired entry should be removed during list.
        assert!(
            state
                .agent_sessions
                .read()
                .await
                .get("s-own-expired")
                .is_none()
        );
    }

    #[tokio::test]
    async fn agent_session_end_all_revokes_only_calling_uid_sessions() {
        let state = make_test_state();
        let now = SystemTime::now();

        state.agent_sessions.write().await.insert(
            "s-own-1".into(),
            AgentSession {
                session_id: "s-own-1".into(),
                token: "tok-own-1".into(),
                created_by_uid: 501,
                expires_at: now + std::time::Duration::from_secs(300),
                label: Some("own-1".into()),
                delegation: None,
            },
        );
        state.agent_sessions.write().await.insert(
            "s-own-2".into(),
            AgentSession {
                session_id: "s-own-2".into(),
                token: "tok-own-2".into(),
                created_by_uid: 501,
                expires_at: now + std::time::Duration::from_secs(300),
                label: Some("own-2".into()),
                delegation: None,
            },
        );
        state.agent_sessions.write().await.insert(
            "s-other".into(),
            AgentSession {
                session_id: "s-other".into(),
                token: "tok-other".into(),
                created_by_uid: 777,
                expires_at: now + std::time::Duration::from_secs(300),
                label: Some("other".into()),
                delegation: None,
            },
        );

        let req = Request {
            id: 8,
            method: "agent_session_end".into(),
            params: serde_json::json!({ "all": true }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let result = resp.result.expect("result expected");
        assert_eq!(result.get("status").and_then(|v| v.as_str()), Some("ended"));
        assert_eq!(result.get("all").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(result.get("ended_count").and_then(|v| v.as_u64()), Some(2));

        let sessions = state.agent_sessions.read().await;
        assert!(!sessions.contains_key("s-own-1"));
        assert!(!sessions.contains_key("s-own-2"));
        assert!(sessions.contains_key("s-other"));
    }

    #[tokio::test]
    async fn agent_session_end_all_rejects_mixed_mode_with_session_id() {
        let state = make_test_state();
        let req = Request {
            id: 9,
            method: "agent_session_end".into(),
            params: serde_json::json!({
                "all": true,
                "session_id": "s1",
            }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        let err = resp.error.expect("expected bad_request");
        assert_eq!(err.code, "bad_request");
        assert!(err.message.contains("cannot combine 'all'"));
    }

    #[tokio::test]
    async fn agent_session_start_emits_audit_event() {
        let audit = Arc::new(opaque_core::audit::InMemoryAuditEmitter::new());
        let state = make_test_state_with_audit(audit.clone());
        let req = Request {
            id: 10,
            method: "agent_session_start".into(),
            params: serde_json::json!({
                "label": "codex",
                "ttl_secs": 120,
            }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);

        let events = audit.events_of_kind(AuditEventKind::OperationSucceeded);
        assert!(events.iter().any(|e| {
            e.operation.as_deref() == Some("agent_session_start")
                && e.outcome.as_deref() == Some("started")
        }));
    }

    #[tokio::test]
    async fn agent_session_end_all_emits_audit_event() {
        let audit = Arc::new(opaque_core::audit::InMemoryAuditEmitter::new());
        let state = make_test_state_with_audit(audit.clone());
        state.agent_sessions.write().await.insert(
            "s-own-1".into(),
            AgentSession {
                session_id: "s-own-1".into(),
                token: "tok-own-1".into(),
                created_by_uid: 501,
                expires_at: SystemTime::now() + std::time::Duration::from_secs(300),
                label: Some("own-1".into()),
                delegation: None,
            },
        );

        let req = Request {
            id: 11,
            method: "agent_session_end".into(),
            params: serde_json::json!({ "all": true }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);

        let events = audit.events_of_kind(AuditEventKind::OperationSucceeded);
        assert!(events.iter().any(|e| {
            e.operation.as_deref() == Some("agent_session_end")
                && e.outcome.as_deref() == Some("ended_all")
        }));
    }

    #[tokio::test]
    async fn validate_agent_session_token_uid_scoped() {
        let state = make_test_state();
        let session = AgentSession {
            session_id: "s1".into(),
            token: "tok1".into(),
            created_by_uid: 501,
            expires_at: SystemTime::now() + std::time::Duration::from_secs(300),
            label: Some("test".into()),
            delegation: None,
        };
        state
            .agent_sessions
            .write()
            .await
            .insert(session.session_id.clone(), session);

        let ok = validate_agent_session_token(&state, "tok1", 501).await;
        assert_eq!(ok.as_deref(), Some("s1"));

        let wrong_uid = validate_agent_session_token(&state, "tok1", 502).await;
        assert!(wrong_uid.is_none());
    }

    #[tokio::test]
    async fn enforce_agent_sessions_rejects_unwrapped_and_allows_session_token() {
        let mut state = make_test_state();
        state.config.enforce_agent_sessions = true;

        let uid = unsafe { libc::getuid() } as u32;
        state.agent_sessions.write().await.insert(
            "session-1".into(),
            AgentSession {
                session_id: "session-1".into(),
                token: "token-1".into(),
                created_by_uid: uid,
                expires_at: SystemTime::now() + std::time::Duration::from_secs(60),
                label: Some("test".into()),
                delegation: None,
            },
        );

        let state = Arc::new(state);
        let codec = || {
            LengthDelimitedCodec::builder()
                .max_frame_length(opaque_core::MAX_FRAME_LENGTH)
                .new_codec()
        };

        // Unwrapped agent-style request: handshake has daemon token only.
        let (client_stream, server_stream) = UnixStream::pair().expect("unix pair");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_task = tokio::spawn(handle_conn(state.clone(), server_stream, shutdown_rx));
        let mut client = Framed::new(client_stream, codec());

        let direct_hs = serde_json::json!({
            "handshake": "v1",
            "daemon_token": "test_token",
        });
        client
            .send(Bytes::from(
                serde_json::to_vec(&direct_hs).expect("serialize handshake"),
            ))
            .await
            .expect("send handshake");

        let ping = Request {
            id: 1,
            method: "ping".into(),
            params: serde_json::Value::Null,
        };
        let _ = client
            .send(Bytes::from(
                serde_json::to_vec(&ping).expect("serialize ping"),
            ))
            .await;

        match tokio::time::timeout(std::time::Duration::from_secs(1), client.next()).await {
            Ok(None) | Ok(Some(Err(_))) => {}
            Ok(Some(Ok(frame))) => panic!("unexpected frame on rejected connection: {frame:?}"),
            Err(_) => panic!("timed out waiting for rejected connection to close"),
        }

        drop(client);
        let direct_result = tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
            .await
            .expect("server task timeout")
            .expect("server task join");
        assert!(direct_result.is_ok(), "server error: {direct_result:?}");

        // Wrapped agent-style request: includes valid session token.
        let (client_stream, server_stream) = UnixStream::pair().expect("unix pair");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server_task = tokio::spawn(handle_conn(state.clone(), server_stream, shutdown_rx));
        let mut client = Framed::new(client_stream, codec());

        let wrapped_hs = serde_json::json!({
            "handshake": "v1",
            "daemon_token": "test_token",
            "session_token": "token-1",
        });
        client
            .send(Bytes::from(
                serde_json::to_vec(&wrapped_hs).expect("serialize handshake"),
            ))
            .await
            .expect("send handshake");
        client
            .send(Bytes::from(
                serde_json::to_vec(&ping).expect("serialize ping"),
            ))
            .await
            .expect("send ping");

        let frame = tokio::time::timeout(std::time::Duration::from_secs(1), client.next())
            .await
            .expect("timed out waiting for ping response")
            .expect("connection closed unexpectedly")
            .expect("frame read failed");
        let resp: Response = serde_json::from_slice(&frame).expect("response decode");
        assert!(
            resp.error.is_none(),
            "unexpected daemon error: {:?}",
            resp.error
        );
        assert_eq!(
            resp.result
                .as_ref()
                .and_then(|r| r.get("ok"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );

        drop(client);
        let wrapped_result = tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
            .await
            .expect("server task timeout")
            .expect("server task join");
        assert!(wrapped_result.is_ok(), "server error: {wrapped_result:?}");
    }

    // -----------------------------------------------------------------------
    // Request timeout test
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn request_timeout_produces_timeout_response() {
        tokio::time::pause();
        let slow_future = async {
            tokio::time::sleep(std::time::Duration::from_secs(200)).await;
            Response::ok(1, serde_json::json!({"ok": true}))
        };
        let req_id = 42u64;
        let resp =
            match tokio::time::timeout(std::time::Duration::from_secs(120), slow_future).await {
                Ok(r) => r,
                Err(_) => Response::err(Some(req_id), "timeout", "request timed out"),
            };
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, "timeout");
        assert_eq!(resp.id, Some(42));
    }

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Test approval gate returning a fixed decision, so session-approval paths can
    /// be exercised without a real biometric prompt.
    #[derive(Debug)]
    struct TestApprovalGate {
        approve: bool,
    }

    impl ApprovalGate for TestApprovalGate {
        fn request_approval(
            &self,
            _approval_id: uuid::Uuid,
            _request: &opaque_core::operation::OperationRequest,
            _factors: &[opaque_core::operation::ApprovalFactor],
            _description: &str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<opaque_core::approval_gate::ApprovalOutcome, String>,
                    > + Send
                    + '_,
            >,
        > {
            let approve = self.approve;
            Box::pin(async move {
                Ok(if approve {
                    opaque_core::approval_gate::ApprovalOutcome::approved_anonymous()
                } else {
                    opaque_core::approval_gate::ApprovalOutcome::denied()
                })
            })
        }
    }

    pub(crate) fn build_test_state(audit: Arc<dyn AuditSink>, approve: bool) -> DaemonState {
        let registry = OperationRegistry::new();
        let policy = PolicyEngine::with_rules(vec![]);
        let enclave = Enclave::builder()
            .registry(registry)
            .policy(policy)
            .approval_gate(Box::new(TestApprovalGate { approve }))
            .audit(audit.clone())
            .build()
            .unwrap();
        DaemonState {
            scope_workflow: None,
            mcp: None,
            workload_attestor:
                opaque_federation_runtime::workload_attest::ListenerAttestor::unix_listener(),
            tenant: None,
            enclave: Arc::new(enclave),
            tasks: None,
            audit,
            config: DaemonConfig::default(),
            version: version_string(),
            daemon_token: "test_token".into(),
            agent_sessions: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            connection_semaphore: Arc::new(tokio::sync::Semaphore::new(64)),
            identity: None,
            pairing: None,
            approval_server_addr: None,
            fido2: None,
            provisioning_challenges: opaque_tenant::provisioning_api::Challenges::default(),
            federation: Arc::new(
                opaque_federation_runtime::federation::FederationStatus::default(),
            ),
            attestation: Arc::new(opaque_federation_runtime::attest::AttestationService::new(
                ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
                PathBuf::from("/nonexistent"),
                PathBuf::from("/nonexistent/config.toml"),
                PathBuf::from("/nonexistent/audit.db"),
                "test".into(),
                false,
                vec![],
                Arc::new(opaque_federation_runtime::federation::FederationStatus::default()),
            )),
        }
    }

    #[tokio::test]
    async fn supplied_sessions_retain_authority_for_allowlisted_cli_clients() {
        let audit = Arc::new(opaque_core::audit::InMemoryAuditEmitter::new());
        let mut state = build_test_state(audit, true);
        state.config.enforce_agent_sessions = true;
        state.agent_sessions.write().await.insert(
            "session".into(),
            AgentSession {
                session_id: "session".into(),
                token: "fixture-session-token".into(),
                created_by_uid: 42,
                expires_at: SystemTime::now() + std::time::Duration::from_secs(60),
                label: None,
                delegation: None,
            },
        );
        for client in [ClientType::Human, ClientType::Agent] {
            assert_eq!(
                handshake_session(&state, Some("fixture-session-token"), client, 42)
                    .await
                    .unwrap(),
                Some("session".into())
            );
            assert!(
                handshake_session(&state, Some("fixture-session-token"), client, 43)
                    .await
                    .is_err()
            );
            assert!(
                handshake_session(&state, Some("invalid"), client, 42)
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            handshake_session(&state, None, ClientType::Human, 42)
                .await
                .unwrap(),
            None
        );
        assert!(
            handshake_session(&state, None, ClientType::Agent, 42)
                .await
                .is_err()
        );
        state.agent_sessions.write().await.clear();
        assert!(
            handshake_session(&state, Some("fixture-session-token"), ClientType::Human, 42)
                .await
                .is_err()
        );
    }

    #[test]
    fn tenant_configuration_cannot_be_removed_from_initialized_custody() {
        for marker in [
            opaque_tenant::tenant::BINDING_FILE,
            opaque_tenant::tenant::LOCK_FILE,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let config = DaemonConfig::default();
            assert!(validate_tenant_startup(&config, directory.path()).is_ok());
            std::fs::write(directory.path().join(marker), b"existing tenant lineage").unwrap();
            assert!(validate_tenant_startup(&config, directory.path()).is_err());
            std::fs::remove_file(directory.path().join(marker)).unwrap();
            std::os::unix::fs::symlink(
                directory.path().join("absent"),
                directory.path().join(marker),
            )
            .unwrap();
            assert!(validate_tenant_startup(&config, directory.path()).is_err());
        }
    }

    fn make_test_state_with_audit(audit: Arc<dyn AuditSink>) -> DaemonState {
        build_test_state(audit, true)
    }

    #[test]
    fn workload_attestation_absence_refuses_dispatch_and_is_audited() {
        let audit = Arc::new(opaque_core::audit::InMemoryAuditEmitter::new());
        let state = make_test_state_with_audit(audit.clone());
        assert!(attest_connection(&state, None).is_none());
        let events = audit.events_of_kind(AuditEventKind::WorkloadAttestationDenied);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].outcome.as_deref(),
            Some("attestation_unavailable")
        );
        let detail: serde_json::Value =
            serde_json::from_str(events[0].detail.as_deref().unwrap()).unwrap();
        assert_eq!(detail["attestor"], "peercred");
        assert_eq!(detail["strength"], "none");
        assert_eq!(detail["selector_count"], 0);
    }

    fn make_denying_test_state() -> DaemonState {
        build_test_state(Arc::new(TracingAuditEmitter::new()), false)
    }

    fn make_test_state() -> DaemonState {
        let audit: Arc<dyn AuditSink> = Arc::new(TracingAuditEmitter::new());
        make_test_state_with_audit(audit)
    }

    /// Test state with an identity runtime (no live IdP — discovery is lazy).
    fn make_test_state_with_identity() -> (tempfile::TempDir, DaemonState) {
        let (dir, state, _audit) = make_test_state_with_identity_audit();
        (dir, state)
    }

    /// As above, but the daemon audit sink AND the identity runtime share an
    /// in-memory emitter so lifecycle events can be asserted.
    fn make_test_state_with_identity_audit() -> (
        tempfile::TempDir,
        DaemonState,
        Arc<opaque_core::audit::InMemoryAuditEmitter>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let config = identity::IdentityConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "opaque-cli".into(),
            audience: None,
            redirect_port: None,
            session_ttl_secs: None,
            allowed_email_domains: vec![],
            allowed_subjects: vec![],
            required: false,
            service_principals: vec![],
            persona: None,
        };
        let emitter = Arc::new(opaque_core::audit::InMemoryAuditEmitter::new());
        let runtime = identity::IdentityRuntime::initialize(config, dir.path())
            .unwrap()
            .with_audit(emitter.clone());
        let mut state = build_test_state(emitter.clone(), true);
        state.identity = Some(Arc::new(runtime));
        (dir, state, emitter)
    }

    #[test]
    fn approval_backend_selection_fails_closed() {
        use ApprovalBackendKind::*;
        // Default and explicit native without the env marker.
        assert_eq!(select_approval_backend(None, false).unwrap(), Native);
        assert_eq!(
            select_approval_backend(Some("native"), false).unwrap(),
            Native
        );
        // Env marker set but backend not selected → refuse.
        assert!(select_approval_backend(None, true).is_err());
        assert!(select_approval_backend(Some("native"), true).is_err());
        // Insecure backend requested without the env marker → refuse.
        assert!(select_approval_backend(Some("insecure_auto_approve"), false).is_err());
        // Both present → activate.
        assert_eq!(
            select_approval_backend(Some("insecure_auto_approve"), true).unwrap(),
            InsecureAutoApprove
        );
        // Unknown value → refuse.
        assert!(select_approval_backend(Some("nope"), false).is_err());
    }

    #[tokio::test]
    async fn logout_emits_identity_logout_event() {
        let (_dir, state, audit) = make_test_state_with_identity_audit();
        let rt = state.identity.as_ref().unwrap();
        // Bootstrap a human + active session.
        let p = rt
            .store
            .upsert_human(
                "https://idp.example.com",
                "u1",
                Some("dev@example.com"),
                None,
                &Default::default(),
            )
            .unwrap();
        rt.store
            .create_human_session(&p.id, 3600, "https://idp.example.com")
            .unwrap();
        let req = Request {
            id: 1,
            method: "identity.logout".into(),
            params: serde_json::json!({}),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_none());
        assert!(
            audit
                .events()
                .iter()
                .any(|e| e.kind == AuditEventKind::IdentityLogout),
            "logout must emit an IdentityLogout audit event"
        );
    }

    #[tokio::test]
    async fn role_set_emits_role_changed_event() {
        let (_dir, state, audit) = make_test_state_with_identity_audit();
        let rt = state.identity.as_ref().unwrap();
        // Bootstrap admin with an active session, plus a target principal.
        let admin = rt
            .store
            .upsert_human(
                "https://idp.example.com",
                "admin",
                Some("admin@example.com"),
                None,
                &[opaque_core::identity::Role::Admin].into_iter().collect(),
            )
            .unwrap();
        rt.store
            .create_human_session(&admin.id, 3600, "https://idp.example.com")
            .unwrap();
        let target = rt.store.upsert_service("ci").unwrap();
        let req = Request {
            id: 1,
            method: "identity.role_set".into(),
            params: serde_json::json!({
                "principal_id": target.id.as_str(),
                "roles": ["operator"],
            }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_none(), "role_set failed: {:?}", resp.error);
        assert!(
            audit
                .events()
                .iter()
                .any(|e| e.kind == AuditEventKind::IdentityRoleChanged),
            "role_set must emit an IdentityRoleChanged audit event"
        );
    }

    // -----------------------------------------------------------------------
    // Identity method tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn identity_methods_error_when_not_configured() {
        let state = make_test_state();
        for method in [
            "identity.login_start",
            "identity.login_status",
            "identity.logout",
            "identity.principal_list",
            "identity.role_set",
        ] {
            let req = Request {
                id: 1,
                method: method.into(),
                params: serde_json::json!({}),
            };
            let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
            assert_eq!(
                resp.error.expect("error expected").code,
                "identity_not_configured",
                "method {method}"
            );
        }
    }

    #[tokio::test]
    async fn whoami_reports_identity_absent_when_unconfigured() {
        let state = make_test_state();
        let req = Request {
            id: 1,
            method: "whoami".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        let result = resp.result.unwrap();
        assert_eq!(result["identity"], serde_json::Value::Null);
        assert_eq!(result["identity_required"], false);
    }

    #[tokio::test]
    async fn whoami_reports_logged_in_identity() {
        let (_dir, state) = make_test_state_with_identity();
        let rt = state.identity.as_ref().unwrap();
        let principal = rt
            .store
            .upsert_human(
                "https://idp.example.com",
                "u-1",
                Some("dev@example.com"),
                None,
                &std::collections::BTreeSet::from([
                    opaque_core::identity::Role::Admin,
                    opaque_core::identity::Role::Operator,
                ]),
            )
            .unwrap();
        rt.store
            .create_human_session(&principal.id, 3600, "https://idp.example.com")
            .unwrap();

        let req = Request {
            id: 1,
            method: "whoami".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        let result = resp.result.unwrap();
        assert_eq!(result["identity"]["email"], "dev@example.com");
        assert_eq!(result["identity"]["principal_id"], principal.id.as_str());

        // Agent whoami stays reduced: no identity object, but the flag is there.
        let req = Request {
            id: 2,
            method: "whoami".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Agent, None).await;
        let result = resp.result.unwrap();
        assert!(result.get("identity").is_none());
        assert_eq!(result["identity_required"], false);
        assert!(result.get("exe_path").is_none());
    }

    #[tokio::test]
    async fn principal_list_open_during_bootstrap_then_session_gated() {
        let (_dir, state) = make_test_state_with_identity();

        // Bootstrap phase (no humans yet): listing is allowed.
        let req = Request {
            id: 1,
            method: "identity.principal_list".into(),
            params: serde_json::json!({}),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_none());

        // Register a human but no active session → gated.
        let rt = state.identity.as_ref().unwrap();
        rt.store
            .upsert_human(
                "https://idp.example.com",
                "u-1",
                None,
                None,
                &std::collections::BTreeSet::new(),
            )
            .unwrap();
        let req = Request {
            id: 2,
            method: "identity.principal_list".into(),
            params: serde_json::json!({}),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert_eq!(resp.error.expect("gated").code, "not_authorized");
    }

    #[tokio::test]
    async fn ambient_admin_login_cannot_authorize_agent_role_changes_without_approval() {
        let (_directory, mut state) = make_test_state_with_identity();
        state.enclave = build_test_state(state.audit.clone(), false).enclave;
        let runtime = state.identity.as_ref().unwrap();
        let admin = runtime
            .store
            .upsert_human(
                "https://idp.example.com",
                "role-admin",
                None,
                None,
                &std::collections::BTreeSet::from([opaque_core::identity::Role::Admin]),
            )
            .unwrap();
        runtime
            .store
            .create_human_session(&admin.id, 3600, "https://idp.example.com")
            .unwrap();
        let target = runtime
            .store
            .upsert_human(
                "https://idp.example.com",
                "role-target",
                None,
                None,
                &std::collections::BTreeSet::from([opaque_core::identity::Role::Operator]),
            )
            .unwrap();
        let request = Request {
            id: 1,
            method: "identity.role_set".into(),
            params: serde_json::json!({"principal_id": target.id, "roles": ["admin", "operator"]}),
        };
        let response =
            handle_request(&state, request, &test_identity(), ClientType::Agent, None).await;
        assert_eq!(response.error.unwrap().code, "permission_denied");
        assert_eq!(
            runtime
                .store
                .get_principal(&target.id)
                .unwrap()
                .unwrap()
                .roles,
            target.roles
        );
    }

    #[tokio::test]
    async fn role_set_requires_admin_session_and_guards_last_admin() {
        let (_dir, state) = make_test_state_with_identity();
        let rt = state.identity.as_ref().unwrap().clone();
        let admin = rt
            .store
            .upsert_human(
                "https://idp.example.com",
                "u-admin",
                Some("admin@example.com"),
                None,
                &std::collections::BTreeSet::from([
                    opaque_core::identity::Role::Admin,
                    opaque_core::identity::Role::Operator,
                ]),
            )
            .unwrap();

        // No active session → not authorized.
        let req = Request {
            id: 1,
            method: "identity.role_set".into(),
            params: serde_json::json!({
                "principal_id": admin.id.as_str(),
                "roles": ["operator"],
            }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert_eq!(resp.error.expect("gated").code, "not_authorized");

        // With an admin session: dropping the last admin's admin role fails.
        rt.store
            .create_human_session(&admin.id, 3600, "https://idp.example.com")
            .unwrap();
        let req = Request {
            id: 2,
            method: "identity.role_set".into(),
            params: serde_json::json!({
                "principal_id": admin.id.as_str(),
                "roles": ["operator"],
            }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert_eq!(resp.error.expect("guarded").code, "last_admin");

        // Granting roles to a second principal works and is visible.
        let second = rt
            .store
            .upsert_human(
                "https://idp.example.com",
                "u-2",
                None,
                None,
                &std::collections::BTreeSet::new(),
            )
            .unwrap();
        let req = Request {
            id: 3,
            method: "identity.role_set".into(),
            params: serde_json::json!({
                "principal_id": second.id.as_str(),
                "roles": ["approver", "operator"],
            }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_none(), "{:?}", resp.error);
        let roles = resp.result.unwrap()["roles"].clone();
        let roles: Vec<String> = serde_json::from_value(roles).unwrap();
        assert_eq!(roles, vec!["approver".to_string(), "operator".to_string()]);

        // Unknown role name rejected.
        let req = Request {
            id: 4,
            method: "identity.role_set".into(),
            params: serde_json::json!({
                "principal_id": second.id.as_str(),
                "roles": ["root"],
            }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert_eq!(resp.error.expect("invalid role").code, "invalid_params");
    }

    #[tokio::test]
    async fn logout_revokes_sessions() {
        let (_dir, state) = make_test_state_with_identity();
        let rt = state.identity.as_ref().unwrap();
        let p = rt
            .store
            .upsert_human(
                "https://idp.example.com",
                "u-1",
                None,
                None,
                &std::collections::BTreeSet::new(),
            )
            .unwrap();
        rt.store
            .create_human_session(&p.id, 3600, "https://idp.example.com")
            .unwrap();
        assert!(rt.current_identity_json().is_some());

        let req = Request {
            id: 1,
            method: "identity.logout".into(),
            params: serde_json::json!({}),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert_eq!(resp.result.unwrap()["revoked"], 1);
        assert!(rt.current_identity_json().is_none());
    }

    #[tokio::test]
    async fn login_status_requires_uuid_attempt_id() {
        let (_dir, state) = make_test_state_with_identity();
        let req = Request {
            id: 1,
            method: "identity.login_status".into(),
            params: serde_json::json!({ "attempt_id": "../../etc/passwd" }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert_eq!(resp.error.expect("rejected").code, "invalid_params");

        let req = Request {
            id: 2,
            method: "identity.login_status".into(),
            params: serde_json::json!({ "attempt_id": Uuid::new_v4().to_string() }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert_eq!(resp.error.expect("unknown").code, "unknown_attempt");
    }

    // -----------------------------------------------------------------------
    // Seal enforcement tests
    // -----------------------------------------------------------------------

    /// Helper: create a temp dir with a config.toml and optionally a (keyed,
    /// current-format) seal + key beside it.
    fn setup_seal_test(
        config_content: &str,
        sealed: bool,
    ) -> (tempfile::TempDir, PathBuf, PathBuf) {
        use opaque_core::seal;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let seal_file = dir.path().join("config.seal");
        std::fs::write(&config_path, config_content).unwrap();
        if sealed {
            let key = seal::load_or_create_seal_key(&seal_file).unwrap();
            let value = seal::compute_seal_keyed(config_content.as_bytes(), &key);
            std::fs::write(&seal_file, &value).unwrap();
        }
        (dir, config_path, seal_file)
    }

    #[test]
    fn seal_require_true_and_sealed_succeeds() {
        let (_dir, config_path, seal_file) = setup_seal_test("[daemon]\n", true);
        // The keyed seal satisfies both shared-uid and enforce mode.
        let result = check_seal_file_only(&config_path, &seal_file, true, false, false);
        assert!(
            result.is_ok(),
            "sealed config with require_seal=true should succeed"
        );
        let result = check_seal_file_only(&config_path, &seal_file, true, false, true);
        assert!(
            result.is_ok(),
            "keyed seal should satisfy trust_domain.enforce too"
        );
    }

    #[test]
    fn seal_legacy_unkeyed_warns_in_shared_mode_but_fails_enforce() {
        use opaque_core::seal;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let seal_file = dir.path().join("config.seal");
        let content = "[daemon]\n";
        std::fs::write(&config_path, content).unwrap();
        // Legacy bare-hex seal, as written by pre-trust-domain builds.
        std::fs::write(&seal_file, seal::compute_seal(content.as_bytes())).unwrap();

        let result = check_seal_file_only(&config_path, &seal_file, true, false, false);
        assert!(
            result.is_ok(),
            "legacy seal remains accepted in shared mode"
        );

        let result = check_seal_file_only(&config_path, &seal_file, true, false, true);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("UNKEYED"),
            "enforce-mode refusal must explain the legacy seal problem: {err}"
        );
    }

    #[test]
    fn seal_keyed_with_missing_key_fails_closed() {
        use opaque_core::seal;
        let (_dir, config_path, seal_file) = setup_seal_test("[daemon]\n", true);
        std::fs::remove_file(seal::seal_key_path(&seal_file)).unwrap();

        let result = check_seal_file_only(&config_path, &seal_file, false, false, false);
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("seal key"),
            "key-missing refusal must name the missing key: {err}"
        );
    }

    #[test]
    fn seal_require_true_and_unsealed_fails() {
        let (_dir, config_path, seal_file) = setup_seal_test("[daemon]\n", false);
        let result = check_seal_file_only(&config_path, &seal_file, true, false, false);
        assert!(
            result.is_err(),
            "unsealed config with require_seal=true should fail"
        );
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        let msg = err.to_string();
        assert!(
            msg.contains("require_seal"),
            "error should mention require_seal, got: {msg}"
        );
        assert!(
            msg.contains("opaque setup --seal"),
            "error should suggest 'opaque setup --seal', got: {msg}"
        );
        assert!(
            msg.contains("--allow-unsealed"),
            "error should suggest --allow-unsealed, got: {msg}"
        );
    }

    #[test]
    fn seal_require_true_allow_unsealed_succeeds() {
        let (_dir, config_path, seal_file) = setup_seal_test("[daemon]\n", false);
        let result = check_seal_file_only(&config_path, &seal_file, true, true, false);
        assert!(
            result.is_ok(),
            "unsealed config with require_seal=true + allow_unsealed should succeed"
        );
    }

    #[test]
    fn seal_require_false_default_unsealed_succeeds() {
        let (_dir, config_path, seal_file) = setup_seal_test("[daemon]\n", false);
        let result = check_seal_file_only(&config_path, &seal_file, false, false, false);
        assert!(
            result.is_ok(),
            "unsealed config with require_seal=false should succeed (backward compat)"
        );
    }

    #[test]
    fn seal_config_without_require_seal_defaults_false() {
        // A config TOML without `require_seal` should deserialize with default false.
        let toml_str = r#"
            enforce_agent_sessions = true
        "#;
        let config: DaemonConfig = toml_edit::de::from_str(toml_str).unwrap();
        assert!(
            !config.require_seal,
            "require_seal should default to false for backward compatibility"
        );
    }

    #[test]
    fn seal_config_with_require_seal_true() {
        let toml_str = r#"
            require_seal = true
            enforce_agent_sessions = false
        "#;
        let config: DaemonConfig = toml_edit::de::from_str(toml_str).unwrap();
        assert!(
            config.require_seal,
            "require_seal should be true when explicitly set"
        );
    }

    #[test]
    fn seal_tampered_always_fails_regardless_of_flags() {
        // Create sealed config, then modify the config content (tamper).
        use opaque_core::seal;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let seal_file = dir.path().join("config.seal");

        let original = "[daemon]\n";
        std::fs::write(&config_path, original).unwrap();
        let seal_hash = seal::compute_seal(original.as_bytes());
        std::fs::write(&seal_file, &seal_hash).unwrap();

        // Now tamper: change config but leave seal unchanged.
        std::fs::write(&config_path, "[daemon]\nrequire_seal = true\n").unwrap();

        // Should fail with require_seal=false.
        let result = check_seal_file_only(&config_path, &seal_file, false, false, false);
        assert!(result.is_err(), "tampered config should always fail");
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);

        // Should fail even with allow_unsealed=true.
        let result = check_seal_file_only(&config_path, &seal_file, false, true, false);
        assert!(
            result.is_err(),
            "tampered config should fail even with allow_unsealed"
        );
    }

    #[test]
    fn seal_no_config_file_always_ok() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("nonexistent.toml");
        let seal_file = dir.path().join("config.seal");

        // Even with require_seal=true, if there's no config file it's OK.
        let result = check_seal_file_only(&config_path, &seal_file, true, false, false);
        assert!(
            result.is_ok(),
            "missing config file should not cause seal failure"
        );
    }

    #[test]
    fn truncate_for_error_short_string() {
        assert_eq!(truncate_for_error("abc", 64), "abc");
    }

    #[test]
    fn truncate_for_error_exact_length() {
        let s = "a".repeat(64);
        assert_eq!(truncate_for_error(&s, 64), s);
    }

    #[test]
    fn truncate_for_error_long_string() {
        let s = "a".repeat(100);
        let result = truncate_for_error(&s, 64);
        assert_eq!(result.len(), 67); // 64 + "..."
        assert!(result.ends_with("..."));
    }

    // -----------------------------------------------------------------------
    // Stage C: delegation minting + enforcement
    // -----------------------------------------------------------------------

    use opaque_core::identity::{AccessMode, Role};

    /// Identity-enabled test state with `required` toggled and a logged-in
    /// human (admin+operator) so delegated mints succeed by default.
    fn identity_state(required: bool) -> (tempfile::TempDir, DaemonState) {
        let dir = tempfile::tempdir().unwrap();
        let config = identity::IdentityConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "opaque-cli".into(),
            audience: None,
            redirect_port: None,
            session_ttl_secs: None,
            allowed_email_domains: vec![],
            allowed_subjects: vec![],
            required,
            persona: None,
            service_principals: vec![identity::ServicePrincipalConfig {
                name: "ci".into(),
                roles: vec!["operator".into()],
            }],
        };
        let runtime = identity::IdentityRuntime::initialize(config, dir.path()).unwrap();
        let mut state = make_test_state();
        state.identity = Some(Arc::new(runtime));
        (dir, state)
    }

    /// Log a human in (bootstrap admin) and return their principal id.
    fn login_human(state: &DaemonState) -> PrincipalId {
        let rt = state.identity.as_ref().unwrap();
        let p = rt
            .store
            .upsert_human(
                "https://idp.example.com",
                "u-1",
                Some("dev@example.com"),
                Some("Dev"),
                &std::collections::BTreeSet::from([Role::Admin, Role::Operator]),
            )
            .unwrap();
        rt.store
            .create_human_session(&p.id, 3600, "https://idp.example.com")
            .unwrap();
        p.id
    }

    async fn start_session(state: &DaemonState, params: serde_json::Value) -> Response {
        let req = Request {
            id: 1,
            method: "agent_session_start".into(),
            params,
        };
        handle_request(state, req, &test_identity(), ClientType::Agent, None).await
    }

    #[tokio::test]
    async fn mint_delegated_happy_path_returns_principal_and_opqd1_token() {
        let (_d, state) = identity_state(false);
        login_human(&state);
        let resp = start_session(&state, serde_json::json!({})).await;
        assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
        let r = resp.result.unwrap();
        assert!(
            r["session_token"].as_str().unwrap().starts_with("opqd1."),
            "expected a delegation token"
        );
        assert_eq!(r["mode"], "delegated");
        assert_eq!(r["on_behalf_of_label"], "dev@example.com");
        assert!(r["on_behalf_of"].as_str().unwrap().starts_with("hum_"));
    }

    #[tokio::test]
    async fn mint_delegated_without_login_fails_closed() {
        let (_d, state) = identity_state(false);
        let resp = start_session(&state, serde_json::json!({})).await;
        assert_eq!(resp.error.expect("should fail").code, "login_required");
    }

    #[tokio::test]
    async fn mint_break_glass_unavailable() {
        let (_d, state) = identity_state(false);
        login_human(&state);
        let resp = start_session(&state, serde_json::json!({ "mode": "break_glass" })).await;
        assert_eq!(
            resp.error.expect("should fail").code,
            "break_glass_unavailable"
        );
    }

    #[tokio::test]
    async fn mint_autonomous_happy_and_unknown_service() {
        let (_d, state) = identity_state(false);
        // Known service principal (declared in identity_state config).
        let ok = start_session(
            &state,
            serde_json::json!({ "mode": "autonomous", "service": "ci" }),
        )
        .await;
        assert!(ok.error.is_none(), "unexpected: {:?}", ok.error);
        let r = ok.result.unwrap();
        assert_eq!(r["mode"], "autonomous");
        assert!(r["on_behalf_of"].as_str().unwrap().starts_with("svc_"));

        // Unknown service principal.
        let bad = start_session(
            &state,
            serde_json::json!({ "mode": "autonomous", "service": "nope" }),
        )
        .await;
        assert_eq!(
            bad.error.expect("should fail").code,
            "unknown_service_principal"
        );
    }

    #[tokio::test]
    async fn mint_autonomous_does_not_require_login() {
        // Autonomous mode is for unattended operation — no human session.
        let (_d, state) = identity_state(true);
        let resp = start_session(
            &state,
            serde_json::json!({ "mode": "autonomous", "service": "ci" }),
        )
        .await;
        assert!(resp.error.is_none(), "unexpected: {:?}", resp.error);
    }

    #[test]
    fn agent_tool_name_sanitization() {
        let id = test_identity();
        // Label wins, sanitized to the identity charset.
        assert_eq!(
            derive_agent_tool_name(Some("Claude Code!!"), &id),
            "Claude-Code"
        );
        // Empty/whitespace label → exe basename.
        assert_eq!(derive_agent_tool_name(Some("   "), &id), "claude-code");
        assert_eq!(derive_agent_tool_name(None, &id), "claude-code");
        // No exe path and no label → "agent".
        let bare = ClientIdentity {
            uid: 1,
            gid: 1,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        };
        assert_eq!(derive_agent_tool_name(None, &bare), "agent");
        // Pure punctuation label collapses to "agent", never empty.
        assert_eq!(derive_agent_tool_name(Some("///"), &bare), "agent");
    }

    #[test]
    fn session_approval_factor_config_requires_full_review() {
        assert_eq!(
            ApprovalFactorsConfig::default()
                .validated_session_factor()
                .unwrap(),
            ApprovalFactor::LocalBio
        );
        for factor in [ApprovalFactor::LocalBio, ApprovalFactor::PairedWorkstation] {
            let config = ApprovalFactorsConfig {
                session_factor: Some(factor),
                ..Default::default()
            };
            assert_eq!(config.validated_session_factor().unwrap(), factor);
        }
        for factor in [ApprovalFactor::IosFaceId, ApprovalFactor::Fido2] {
            let config = ApprovalFactorsConfig {
                session_factor: Some(factor),
                ..Default::default()
            };
            assert!(config.validated_session_factor().is_err());
        }
        let config: DaemonConfig =
            toml_edit::de::from_str("[approval]\nsession_factor = 'paired_workstation'\n").unwrap();
        assert_eq!(
            config.approval.validated_session_factor().unwrap(),
            ApprovalFactor::PairedWorkstation
        );
    }

    /// H-8: exhaustive truth table for the pure startup-preflight decision.
    /// (local_bio configured?) x (trust-domain enforced?) x (probe ok/err).
    #[test]
    fn session_auth_preflight_decision_covers_the_full_truth_table() {
        let ok = || Ok(());
        let err = || Err(opaque_native_approval::ApprovalError::Unavailable);

        // local_bio not configured: never gated, regardless of enforcement
        // or probe outcome (paired_workstation/fido2/ios_faceid deployments
        // never need this session to authenticate locally).
        assert_eq!(
            session_auth_preflight_decision(false, false, ok()),
            SessionAuthPreflight::NotGated
        );
        assert_eq!(
            session_auth_preflight_decision(false, false, err()),
            SessionAuthPreflight::NotGated
        );
        assert_eq!(
            session_auth_preflight_decision(false, true, ok()),
            SessionAuthPreflight::NotGated
        );
        assert_eq!(
            session_auth_preflight_decision(false, true, err()),
            SessionAuthPreflight::NotGated
        );

        // local_bio configured, trust-domain enforced: still never gated —
        // split deployments pair with out-of-band factors by design.
        assert_eq!(
            session_auth_preflight_decision(true, true, ok()),
            SessionAuthPreflight::NotGated
        );
        assert_eq!(
            session_auth_preflight_decision(true, true, err()),
            SessionAuthPreflight::NotGated
        );

        // local_bio configured, trust-domain NOT enforced: gated on the
        // probe. This is the only pair of cases that consults it at all.
        assert_eq!(
            session_auth_preflight_decision(true, false, ok()),
            SessionAuthPreflight::GatedOk
        );
        assert_eq!(
            session_auth_preflight_decision(true, false, err()),
            SessionAuthPreflight::Fatal
        );
    }

    #[test]
    fn local_auth_preflight_rejects_only_the_gated_failing_case() {
        // The exact scenario the daemon hits at startup: default config
        // (local_bio, trust_domain.enforce absent/false) parsed from real
        // TOML, with a failing probe injected in place of the real
        // canEvaluatePolicy call.
        let config: DaemonConfig = toml_edit::de::from_str("").unwrap();
        assert!(!config.trust_domain.enforce);
        let session_factor = config.approval.validated_session_factor().unwrap();
        assert_eq!(session_factor, ApprovalFactor::LocalBio);

        let error = local_auth_preflight(
            session_factor,
            config.trust_domain.enforce,
            Err(opaque_native_approval::ApprovalError::Unavailable),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cannot complete local device"));
        assert!(error.to_string().contains("docs/deployment.md"));

        // A successful probe under the same config proceeds.
        assert!(local_auth_preflight(session_factor, config.trust_domain.enforce, Ok(())).is_ok());

        // An out-of-band session factor proceeds even with a failing probe.
        let split: DaemonConfig =
            toml_edit::de::from_str("[approval]\nsession_factor = 'paired_workstation'\n").unwrap();
        let split_factor = split.approval.validated_session_factor().unwrap();
        assert!(
            local_auth_preflight(
                split_factor,
                split.trust_domain.enforce,
                Err(opaque_native_approval::ApprovalError::Unavailable)
            )
            .is_ok()
        );

        // An enforced trust domain proceeds even with local_bio and a
        // failing probe: split deployments pair with out-of-band factors.
        let enforced: DaemonConfig = toml_edit::de::from_str(
            "[trust_domain]\nenforce = true\nsocket_group = 'opaque-clients'\n",
        )
        .unwrap();
        assert!(
            local_auth_preflight(
                ApprovalFactor::LocalBio,
                enforced.trust_domain.enforce,
                Err(opaque_native_approval::ApprovalError::Unavailable)
            )
            .is_ok()
        );
    }

    #[test]
    fn session_approval_reason_preserves_authority_before_bounded_labels() {
        let (_directory, state) = identity_state(false);
        let principal_id = login_human(&state);
        let principal = state
            .identity
            .as_ref()
            .unwrap()
            .store
            .get_principal(&principal_id)
            .unwrap()
            .unwrap();
        let tenant = opaque_core::tenant::TenantBinding::new(
            opaque_core::tenant::TenantId::parse("tenant-a").unwrap(),
            Uuid::parse_str("b173e800-52ee-48f1-9bd8-a45487988089").unwrap(),
        )
        .unwrap();
        let label = format!("\n\r\u{061c}\u{200e}\u{202e}{}", "界".repeat(20_000));
        let reason = session_approval_reason(
            Some(&tenant),
            42,
            600,
            Some(&(AccessMode::Delegated, principal)),
            Some(&label),
        );
        assert!(reason.starts_with(&tenant.approval_context()));
        assert!(reason.contains("Peer UID: 42\nSession lifetime: 600 seconds\n"));
        let authority = format!("Subject principal: {principal_id}\nAccess mode: delegated\n");
        assert!(reason.contains(&authority));
        assert!(
            reason.find(&authority).unwrap() < reason.find("Requested session label:").unwrap()
        );
        assert!(!reason.contains(['\r', '\u{061c}', '\u{200e}', '\u{202e}']));
        assert!(reason.len() < 1024);
        assert_eq!(reason.lines().count(), 8);
    }

    /// Drive a mint, then return (state, session_id, token) for enforcement tests.
    async fn mint_delegated(state: &DaemonState) -> (String, String) {
        let resp = start_session(state, serde_json::json!({})).await;
        let r = resp.result.unwrap();
        (
            r["session_id"].as_str().unwrap().to_owned(),
            r["session_token"].as_str().unwrap().to_owned(),
        )
    }

    #[tokio::test]
    async fn resolve_context_reflects_live_delegation() {
        let (_d, state) = identity_state(false);
        let sub = login_human(&state);
        let (sid, _tok) = mint_delegated(&state).await;
        let ctx = resolve_principal_context(&state, Some(&sid))
            .await
            .unwrap()
            .expect("context expected");
        assert_eq!(ctx.sub, sub);
        assert_eq!(ctx.mode, AccessMode::Delegated);
        assert!(ctx.sub_roles.contains(&Role::Operator));
        assert_eq!(ctx.sub_label, "dev@example.com");
    }

    #[tokio::test]
    async fn identity_membership_changes_reject_persisted_human_authority() {
        for change in ["subject", "issuer", "domain"] {
            let (directory, mut state) = identity_state(false);
            login_human(&state);
            let (sid, _) = mint_delegated(&state).await;
            let mut config = state.identity.as_ref().unwrap().config.clone();
            match change {
                "subject" => config.allowed_subjects = vec!["different-member".into()],
                "issuer" => config.issuer = "https://different.example.com".into(),
                _ => config.allowed_email_domains = vec!["different.example.com".into()],
            }
            // Reopen the same persisted identity store with revised trusted
            // configuration. No session/principal rows are deleted as a crutch.
            state.identity = Some(Arc::new(
                identity::IdentityRuntime::initialize(config, directory.path()).unwrap(),
            ));
            let runtime = state.identity.as_ref().unwrap();
            assert!(runtime.store.current_human_session().unwrap().is_some());
            assert!(runtime.current_human_principal().is_none());
            assert!(runtime.current_identity_json().is_none());
            assert!(!runtime.current_human_has_role(Role::Admin));
            assert!(
                resolve_principal_context(&state, Some(&sid)).await.is_err(),
                "{change} must invalidate the live authority fence"
            );
            let response = start_session(&state, serde_json::json!({})).await;
            assert_eq!(
                response.error.unwrap().code,
                "login_required",
                "{change} must forbid fresh minting from a persisted session"
            );
        }
    }

    #[tokio::test]
    async fn identity_membership_changes_reject_persisted_service_authority() {
        for invalid_roles in [false, true] {
            let (directory, mut state) = identity_state(false);
            let response = start_session(
                &state,
                serde_json::json!({"mode":"autonomous", "service":"ci"}),
            )
            .await;
            let sid = response.result.unwrap()["session_id"]
                .as_str()
                .unwrap()
                .to_owned();
            let mut config = state.identity.as_ref().unwrap().config.clone();
            if invalid_roles {
                config.service_principals[0].roles = vec!["unrecognized-role".into()];
            } else {
                config.service_principals.clear();
            }
            state.identity = Some(Arc::new(
                identity::IdentityRuntime::initialize(config, directory.path()).unwrap(),
            ));
            assert!(
                state
                    .identity
                    .as_ref()
                    .unwrap()
                    .store
                    .get_service_by_name("ci")
                    .unwrap()
                    .is_some(),
                "test must retain the stale principal row"
            );
            assert!(resolve_principal_context(&state, Some(&sid)).await.is_err());
            let response = start_session(
                &state,
                serde_json::json!({"mode":"autonomous", "service":"ci"}),
            )
            .await;
            assert_eq!(response.error.unwrap().code, "unknown_service_principal");
        }
    }

    #[tokio::test]
    async fn identity_membership_is_rechecked_after_session_approval() {
        struct DisableDuringApproval {
            runtime: Arc<identity::IdentityRuntime>,
            principal: PrincipalId,
        }
        impl std::fmt::Debug for DisableDuringApproval {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("DisableDuringApproval")
            }
        }
        impl ApprovalGate for DisableDuringApproval {
            fn request_approval(
                &self,
                _: Uuid,
                _: &OperationRequest,
                _: &[ApprovalFactor],
                _: &str,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<opaque_core::approval_gate::ApprovalOutcome, String>,
                        > + Send
                        + '_,
                >,
            > {
                Box::pin(async move {
                    self.runtime
                        .store
                        .set_disabled(&self.principal, true)
                        .unwrap();
                    Ok(opaque_core::approval_gate::ApprovalOutcome::approved_anonymous())
                })
            }
        }
        let (_directory, mut state) = identity_state(false);
        let principal = login_human(&state);
        state.enclave = Arc::new(
            Enclave::builder()
                .registry(OperationRegistry::new())
                .policy(PolicyEngine::with_rules(vec![]))
                .approval_gate(Box::new(DisableDuringApproval {
                    runtime: state.identity.as_ref().unwrap().clone(),
                    principal,
                }))
                .audit(state.audit.clone())
                .build()
                .unwrap(),
        );
        let response = start_session(&state, serde_json::json!({})).await;
        assert_eq!(response.error.unwrap().code, "identity_not_permitted");
        assert!(state.agent_sessions.read().await.is_empty());
    }

    #[tokio::test]
    async fn revoked_delegation_fails_closed() {
        let (_d, state) = identity_state(false);
        login_human(&state);
        let (sid, _tok) = mint_delegated(&state).await;
        state
            .identity
            .as_ref()
            .unwrap()
            .store
            .revoke_delegation(&sid)
            .unwrap();
        let err = resolve_principal_context(&state, Some(&sid)).await;
        assert!(err.is_err(), "revoked delegation must fail closed");
    }

    #[tokio::test]
    async fn expired_human_session_kills_delegated_ops() {
        let (_d, state) = identity_state(false);
        login_human(&state);
        let (sid, _tok) = mint_delegated(&state).await;
        // Revoke the human session mid-flight.
        state
            .identity
            .as_ref()
            .unwrap()
            .store
            .revoke_all_human_sessions()
            .unwrap();
        let err = resolve_principal_context(&state, Some(&sid)).await;
        assert!(
            err.is_err(),
            "delegated op must die when the human session ends"
        );
    }

    #[tokio::test]
    async fn disabled_principal_fails_closed() {
        let (_d, state) = identity_state(false);
        let sub = login_human(&state);
        let (sid, _tok) = mint_delegated(&state).await;
        // Disable the delegating principal.
        state
            .identity
            .as_ref()
            .unwrap()
            .store
            .set_disabled(&sub, true)
            .unwrap();
        let err = resolve_principal_context(&state, Some(&sid)).await;
        assert!(err.is_err(), "disabled principal must fail closed");
    }

    #[tokio::test]
    async fn expired_wrapper_session_fails_live_context_check() {
        let (_directory, state) = identity_state(false);
        login_human(&state);
        let (sid, _) = mint_delegated(&state).await;
        state
            .agent_sessions
            .write()
            .await
            .get_mut(&sid)
            .unwrap()
            .expires_at = std::time::UNIX_EPOCH;
        assert_eq!(
            resolve_principal_context(&state, Some(&sid))
                .await
                .unwrap_err(),
            "agent session expired"
        );
        // Legacy sessions also have a live TTL, even without a delegation.
        state
            .agent_sessions
            .write()
            .await
            .get_mut(&sid)
            .unwrap()
            .delegation = None;
        assert!(resolve_principal_context(&state, Some(&sid)).await.is_err());
    }

    #[tokio::test]
    async fn disabled_acting_agent_fails_live_context_check() {
        let (_directory, state) = identity_state(false);
        login_human(&state);
        let (sid, _) = mint_delegated(&state).await;
        let context = resolve_principal_context(&state, Some(&sid))
            .await
            .unwrap()
            .unwrap();
        let store = &state.identity.as_ref().unwrap().store;
        assert!(
            store
                .get_delegation(&context.jti)
                .unwrap()
                .unwrap()
                .revoked_at
                .is_none()
        );
        store.set_disabled(&context.act, true).unwrap();
        assert!(store.get_principal(&context.act).unwrap().unwrap().disabled);
        // The lifecycle trigger revokes existing delegations in the same
        // transaction as disabling their acting principal. Live resolution
        // therefore rejects the persisted revocation before checking the
        // principal's disabled flag.
        let revoked_at = store
            .get_delegation(&context.jti)
            .unwrap()
            .unwrap()
            .revoked_at;
        assert!(revoked_at.is_some());
        assert_eq!(
            resolve_principal_context(&state, Some(&sid))
                .await
                .unwrap_err(),
            "delegation revoked"
        );
        // Re-enabling the principal cannot resurrect an old delegated grant.
        store.set_disabled(&context.act, false).unwrap();
        assert!(!store.get_principal(&context.act).unwrap().unwrap().disabled);
        assert_eq!(
            store
                .get_delegation(&context.jti)
                .unwrap()
                .unwrap()
                .revoked_at,
            revoked_at
        );
        assert_eq!(
            resolve_principal_context(&state, Some(&sid))
                .await
                .unwrap_err(),
            "delegation revoked"
        );
    }

    #[test]
    fn workspace_verification_checks_dirty_and_head_without_executing_filters() {
        use opaque_core::operation::WorkspaceContext;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let git = |args: &[&str]| {
            let output = safe_command("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        git(&["init", "-q"]);
        git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "initial",
        ]);
        let mut workspace = WorkspaceContext {
            repo_root: root.clone(),
            remote_url: None,
            branch: None,
            head_sha: Some(git(&["rev-parse", "HEAD"])),
            dirty: false,
            workspace_verified: false,
        };
        assert!(verify_workspace_blocking(&workspace, None).is_ok());
        std::fs::write(root.join("changed.txt"), "changed").unwrap();
        assert!(
            verify_workspace_blocking(&workspace, None)
                .unwrap_err()
                .contains("dirty")
        );
        workspace.dirty = true;
        assert!(verify_workspace_blocking(&workspace, None).is_ok());
        workspace.head_sha = Some("0000000000000000000000000000000000000000".into());
        assert!(
            verify_workspace_blocking(&workspace, None)
                .unwrap_err()
                .contains("HEAD")
        );
        workspace.head_sha = None;
        let marker = root.join("filter-executed");
        std::fs::write(root.join(".gitattributes"), "*.txt filter=unsafe\n").unwrap();
        git(&[
            "config",
            "filter.unsafe.clean",
            &format!("touch {}", marker.display()),
        ]);
        git(&[
            "config",
            "core.fsmonitor",
            &format!("touch {}", marker.display()),
        ]);
        assert!(
            verify_workspace_blocking(&workspace, None)
                .unwrap_err()
                .contains("external Git filters")
        );
        assert!(
            !marker.exists(),
            "workspace verification must not execute repository programs"
        );
    }

    #[test]
    fn workspace_snapshot_late_filter_cannot_execute_broker_commands() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let git = |args: &[&str]| {
            let result = safe_command("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        };
        git(&["init", "-q"]);
        std::fs::write(root.join("tracked"), "before\n").unwrap();
        git(&["add", "tracked"]);
        git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "initial",
        ]);
        let snapshot = WorkspaceGitSnapshot::capture(&root).unwrap();
        assert!(!snapshot.is_dirty().unwrap());
        snapshot.reject_external_filters().unwrap();
        // The attack lands after config capture AND the attribute precheck.
        let marker = root.join("filter-executed");
        git(&[
            "config",
            "filter.late.clean",
            &format!("touch {}", marker.display()),
        ]);
        git(&[
            "config",
            "core.fsmonitor",
            &format!("touch {}", marker.display()),
        ]);
        std::fs::write(root.join(".gitattributes"), "tracked filter=late\n").unwrap();
        std::fs::write(root.join("tracked"), "after!\n").unwrap();
        let status = snapshot
            .command()
            .args([
                "status",
                "--porcelain",
                "--untracked-files=normal",
                "--ignore-submodules=all",
            ])
            .output()
            .unwrap();
        assert!(status.status.success());
        assert!(
            !marker.exists(),
            "status must not discover the changed original config"
        );
        assert!(
            snapshot
                .is_dirty()
                .unwrap_err()
                .contains("external Git filters")
        );
        assert!(!marker.exists());
    }

    #[test]
    fn workspace_snapshot_preserves_builtin_eol_staging_and_linked_worktree_semantics() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        let git = |root: &std::path::Path, args: &[&str]| {
            let result = safe_command("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        };
        git(&root, &["init", "-q"]);
        git(&root, &["config", "core.autocrlf", "true"]);
        std::fs::write(root.join("tracked.txt"), "before\r\n").unwrap();
        git(&root, &["add", "tracked.txt"]);
        git(
            &root,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "initial",
            ],
        );
        assert!(
            !WorkspaceGitSnapshot::capture(&root)
                .unwrap()
                .is_dirty()
                .unwrap()
        );
        std::fs::write(root.join("tracked.txt"), "after!\r\n").unwrap();
        assert!(
            WorkspaceGitSnapshot::capture(&root)
                .unwrap()
                .is_dirty()
                .unwrap()
        );
        git(&root, &["add", "tracked.txt"]);
        assert!(
            WorkspaceGitSnapshot::capture(&root)
                .unwrap()
                .is_dirty()
                .unwrap(),
            "staged change must remain dirty"
        );
        git(
            &root,
            &["update-index", "--assume-unchanged", "tracked.txt"],
        );
        assert!(WorkspaceGitSnapshot::capture(&root).is_err());
        git(
            &root,
            &["update-index", "--no-assume-unchanged", "tracked.txt"],
        );
        let linked = directory.path().join("linked");
        git(
            &root,
            &[
                "worktree",
                "add",
                "--detach",
                linked.to_str().unwrap(),
                "HEAD",
            ],
        );
        assert!(
            !WorkspaceGitSnapshot::capture(&linked)
                .unwrap()
                .is_dirty()
                .unwrap()
        );
    }

    #[test]
    fn workspace_metadata_fifo_is_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("index");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a valid, owned temporary pathname and mode is private.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(
            WorkspaceGitSnapshot::copy_metadata(&fifo, &directory.path().join("copy"), 1024)
                .is_err()
        );
    }

    #[test]
    fn workspace_snapshot_ignorestat_cannot_hide_changed_content() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let git = |args: &[&str]| {
            let result = safe_command("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        };
        git(&["init", "-q"]);
        std::fs::write(root.join("tracked"), "before\n").unwrap();
        git(&["add", "tracked"]);
        git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "initial",
        ]);
        // The source index is ordinary; copying this configuration while
        // rebuilding it would silently set CE_VALID on every tracked entry.
        git(&["config", "core.ignorestat", "true"]);
        let snapshot = WorkspaceGitSnapshot::capture(&root).unwrap();
        assert!(!snapshot.is_dirty().unwrap());
        std::fs::write(root.join("tracked"), "after!\n").unwrap();
        assert!(
            snapshot.is_dirty().unwrap(),
            "repository ignorestat must not hide changed content"
        );
    }

    #[tokio::test]
    async fn identity_required_blocks_undelegated_execute_but_not_ping() {
        let (_d, state) = identity_state(true);
        // Agent execute without a delegation → identity_required.
        let exec = Request {
            id: 1,
            method: "execute".into(),
            params: serde_json::json!({ "operation": "noop.test" }),
        };
        let resp = handle_request(&state, exec, &test_identity(), ClientType::Agent, None).await;
        assert_eq!(resp.error.expect("blocked").code, "identity_required");

        // ping is always reachable.
        let ping = Request {
            id: 2,
            method: "ping".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, ping, &test_identity(), ClientType::Agent, None).await;
        assert!(resp.error.is_none());

        // whoami is reachable (so an agent can be told to log in).
        let who = Request {
            id: 3,
            method: "whoami".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, who, &test_identity(), ClientType::Agent, None).await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn identity_required_does_not_block_human() {
        // Humans are not agents — identity.required targets agent workloads.
        let (_d, state) = identity_state(true);
        let exec = Request {
            id: 1,
            method: "execute".into(),
            params: serde_json::json!({ "operation": "noop.test" }),
        };
        let resp = handle_request(&state, exec, &test_identity(), ClientType::Human, None).await;
        // Reaches the enclave (unknown op → not identity_required).
        assert!(
            resp.error.is_none() || resp.error.as_ref().unwrap().code != "identity_required",
            "human must not be identity-gated"
        );
    }

    #[tokio::test]
    async fn policy_require_principal_gates_by_delegation() {
        use opaque_core::operation::{
            ApprovalRequirement, OperationDef, OperationRegistry, OperationSafety,
        };
        use opaque_core::policy::{IdentityMatch, PolicyEngine, PolicyRule};

        // A rule that only allows delegated requests carrying a principal.
        let rule = PolicyRule {
            name: "delegated-only".into(),
            client: Default::default(),
            operation_pattern: "noop.*".into(),
            target: Default::default(),
            workspace: Default::default(),
            secret_names: Default::default(),
            allow: true,
            client_types: vec![],
            identity: IdentityMatch {
                require_principal: Some(true),
                ..Default::default()
            },
            approval: Default::default(),
        };
        let mut registry = OperationRegistry::new();
        registry
            .register(OperationDef {
                name: "noop.test".into(),
                safety: OperationSafety::Safe,
                default_approval: ApprovalRequirement::Never,
                default_factors: vec![],
                description: "test".into(),
                params_schema: None,
                allowed_target_keys: vec![],
                secret_ref_param_keys: vec![],
            })
            .unwrap();
        let engine = PolicyEngine::with_rules(vec![rule]);

        use opaque_core::identity::{PrincipalContext, PrincipalId, PrincipalKind};
        let ctx = PrincipalContext {
            sub: PrincipalId::generate(&PrincipalKind::Human {
                iss: "https://idp.example.com".into(),
                sub: "u".into(),
                email: None,
                name: None,
            }),
            sub_label: "u".into(),
            sub_roles: Default::default(),
            sub_teams: vec![],
            act: PrincipalId::generate(&PrincipalKind::Agent { tool: "x".into() }),
            act_label: "agent:x".into(),
            mode: AccessMode::Delegated,
            jti: "j".into(),
            human_session_id: None,
        };

        let mut req = OperationRequest {
            principal: None,
            request_id: Uuid::new_v4(),
            client_identity: test_identity(),
            client_type: ClientType::Agent,
            operation: "noop.test".into(),
            target: HashMap::new(),
            secret_ref_names: vec![],
            created_at: SystemTime::now(),
            expires_at: None,
            params: serde_json::Value::Null,
            workspace: None,
        };
        // No principal → denied.
        assert!(!engine.evaluate(&req, OperationSafety::Safe).allowed);
        // With a verified principal → allowed.
        req.principal = Some(ctx);
        assert!(engine.evaluate(&req, OperationSafety::Safe).allowed);
    }

    #[tokio::test]
    async fn delegation_list_gated_and_shaped() {
        let (_d, state) = identity_state(false);
        login_human(&state);
        mint_delegated(&state).await;

        let req = Request {
            id: 1,
            method: "identity.delegation_list".into(),
            params: serde_json::Value::Null,
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Human, None).await;
        assert!(resp.error.is_none(), "unexpected: {:?}", resp.error);
        let list = resp.result.unwrap();
        let arr = list["delegations"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["mode"], "delegated");
        assert_eq!(arr[0]["sub_label"], "dev@example.com");
        assert!(arr[0]["jti"].is_string());
    }

    #[tokio::test]
    async fn end_session_revokes_delegation() {
        let (_d, state) = identity_state(false);
        login_human(&state);
        let (sid, _tok) = mint_delegated(&state).await;
        let req = Request {
            id: 1,
            method: "agent_session_end".into(),
            params: serde_json::json!({ "session_id": sid }),
        };
        let resp = handle_request(&state, req, &test_identity(), ClientType::Agent, None).await;
        assert!(resp.error.is_none());
        // The store row is now revoked.
        let rec = state
            .identity
            .as_ref()
            .unwrap()
            .store
            .get_delegation(&sid)
            .unwrap()
            .unwrap();
        assert!(rec.revoked_at.is_some());
    }

    #[tokio::test]
    async fn legacy_hex_token_path_unchanged_without_identity() {
        // No [identity] configured: minting yields a hex token, no principal.
        let state = make_test_state();
        let resp = start_session(&state, serde_json::json!({})).await;
        assert!(resp.error.is_none());
        let r = resp.result.unwrap();
        let tok = r["session_token"].as_str().unwrap();
        assert!(
            !tok.starts_with("opqd1."),
            "legacy path must use hex tokens"
        );
        assert!(r.get("mode").is_none(), "no delegation metadata expected");
    }
}
