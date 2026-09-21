//! Phase 1 identity substrate — daemon side.
//!
//! Wires the core principal model (`opaque_core::identity`) into the daemon:
//! a persistent identity store (SQLite), an Ed25519 delegation signing key,
//! a hand-rolled OIDC relying party (discovery + PKCE + JWKS verification),
//! and the browser-login attempt lifecycle.
//!
//! Trust model reminder: agents drive the same CLI binary humans use, so
//! nothing a client process sends is proof of humanity. The proof of a human
//! is the browser/IdP authentication step — the authorization code lands on a
//! daemon-owned loopback listener and is exchanged and verified entirely
//! inside the daemon. The CLI only ever sees an authorization URL to display
//! and an attempt id to poll.

pub mod keys;
pub mod lifecycle;
pub mod login;
pub mod oidc;
pub mod persona;
pub mod provisioning;
pub mod store;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod runtime_contract_tests;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod service_startup_contract_tests;

use std::path::Path;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, ClientSummary};
use opaque_core::identity::{PrincipalContext, Role, roles_from_string};
use opaque_core::operation::{ClientIdentity, ClientType};
use opaque_core::proto::{Request, Response};
use serde::Deserialize;
use tracing::{info, warn};

use login::LoginAttempts;
use oidc::OidcClient;
pub use persona::PersonaConfig;
use store::IdentityStore;

use crate::DaemonState;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `[identity]` section of the daemon config.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    /// OIDC issuer URL (https, or loopback http for tests).
    pub issuer: String,

    /// OAuth client id registered at the IdP (public client, PKCE).
    pub client_id: String,

    /// Expected `aud` of ID tokens. Defaults to `client_id`.
    #[serde(default)]
    pub audience: Option<String>,

    /// Fixed loopback redirect port. Defaults to an ephemeral port
    /// (RFC 8252 §7.3); set this if the IdP requires an exact redirect URI.
    #[serde(default)]
    pub redirect_port: Option<u16>,

    /// Human login session TTL in seconds (default 12h, clamped 5m..=7d).
    #[serde(default)]
    pub session_ttl_secs: Option<u64>,

    /// When non-empty, only emails under these domains may log in.
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,

    /// Exact issuer-local subjects admitted by trusted operator configuration.
    /// This is a membership boundary, evaluated before account bootstrap.
    #[serde(default)]
    pub allowed_subjects: Vec<String>,

    /// When true, agent operations will require a valid delegation bound to
    /// an authenticated principal (enforced from Stage C onward).
    #[serde(default)]
    pub required: bool,

    /// Opt-in verified IdP groups and fresh authentication for provisioning.
    /// New humans receive no implicit roles while this is enabled.
    #[serde(default)]
    pub persona: Option<PersonaConfig>,

    /// Config-declared service principals for autonomous operation.
    #[serde(default)]
    pub service_principals: Vec<ServicePrincipalConfig>,
}

/// One config-declared service principal.
#[derive(Debug, Clone, Deserialize)]
pub struct ServicePrincipalConfig {
    /// Service name (charset-limited; see `opaque_core::identity`).
    pub name: String,
    /// Roles granted to the service principal (e.g. `["operator"]`).
    #[serde(default)]
    pub roles: Vec<String>,
}

impl IdentityConfig {
    /// Expected audience for ID tokens.
    pub fn audience(&self) -> &str {
        self.audience.as_deref().unwrap_or(&self.client_id)
    }

    /// Human session TTL, defaulted and clamped.
    pub fn session_ttl_secs(&self) -> u64 {
        self.session_ttl_secs.unwrap_or(43_200).clamp(300, 604_800)
    }

    /// Validate semantic invariants (issuer shape, client id present).
    pub fn validate(&self) -> Result<(), String> {
        // Reuse the core issuer rules by validating a synthetic human kind.
        let probe = opaque_core::identity::PrincipalKind::Human {
            iss: self.issuer.clone(),
            sub: "probe".into(),
            email: None,
            name: None,
        };
        probe
            .validate()
            .map_err(|e| format!("invalid [identity] issuer: {e}"))?;
        if self.issuer.ends_with('/') {
            return Err("invalid [identity] issuer: must not end with '/'".into());
        }
        if self.client_id.trim().is_empty() {
            return Err("invalid [identity] client_id: empty".into());
        }
        if self.allowed_subjects.iter().any(|subject| {
            subject.is_empty() || subject.len() > 255 || subject.chars().any(char::is_control)
        }) {
            return Err("invalid [identity] allowed_subjects".into());
        }
        if let Some(persona) = &self.persona {
            persona.validate()?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

/// Live identity state hung off `DaemonState` when `[identity]` is configured.
pub struct IdentityRuntime {
    pub config: IdentityConfig,
    pub store: IdentityStore,
    /// Delegation-token signing key.
    pub signing: ed25519_dalek::SigningKey,
    /// Shared HTTP client for IdP traffic.
    pub http: reqwest::Client,
    /// Cached OIDC discovery + JWKS state (populated on first login).
    pub(crate) oidc: tokio::sync::Mutex<Option<Arc<OidcClient>>>,
    /// Pending browser-login attempts.
    pub(crate) attempts: LoginAttempts,
    /// Audit sink for identity lifecycle events (login/logout/role changes).
    /// `None` only in unit tests; the daemon always wires it.
    pub(crate) audit: Option<Arc<dyn opaque_core::audit::AuditSink>>,
}

impl IdentityRuntime {
    /// Admission remains live after login. Persisted sessions/principals must
    /// not preserve membership removed from the current broker configuration.
    pub fn principal_permitted(&self, principal: &opaque_core::identity::Principal) -> bool {
        use opaque_core::identity::PrincipalKind;
        if principal.disabled {
            return false;
        }
        match &principal.kind {
            PrincipalKind::Human {
                iss, sub, email, ..
            } => {
                iss == &self.config.issuer
                    && (self.config.allowed_subjects.is_empty()
                        || self.config.allowed_subjects.contains(sub))
                    && (self.config.allowed_email_domains.is_empty()
                        || email
                            .as_deref()
                            .and_then(|email| email.rsplit_once('@'))
                            .is_some_and(|(_, domain)| {
                                self.config
                                    .allowed_email_domains
                                    .iter()
                                    .any(|allowed| domain.eq_ignore_ascii_case(allowed))
                            }))
            }
            PrincipalKind::Service { name } => self.config.service_principals.iter().any(|entry| {
                entry.name == *name && roles_from_string(&entry.roles.join(",")).is_ok()
            }),
            PrincipalKind::Agent { .. } => false,
        }
    }

    /// Current trusted reviewer authority. The epoch changes on lifecycle and
    /// role changes; callers must compare the captured epoch at acceptance and
    /// again at dispatch. Labels and notification payloads are not identity.
    pub fn reviewer_eligibility(
        &self,
        id: &opaque_core::identity::PrincipalId,
        role: Role,
    ) -> Result<u64, String> {
        let epoch = self.store.authority_epoch(id)?;
        self.with_reviewer_authority(id, role, epoch, &mut || Ok(()))?;
        Ok(epoch)
    }

    /// Hold identity lifecycle writer exclusion through a synchronous dispatch
    /// fence. Lock order is identity -> task; callbacks must not re-enter identity.
    pub fn with_reviewer_authority(
        &self,
        id: &opaque_core::identity::PrincipalId,
        role: Role,
        expected_epoch: u64,
        authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.with_dispatch_authority(None, Some((id, role, expected_epoch)), authorize)
    }

    /// Atomically validate requester and reviewer under one identity lock.
    /// This closes lifecycle removal races at the durable dispatch boundary;
    /// prior asynchronous checks still validate workload/workspace/policy context.
    pub fn with_dispatch_authority(
        &self,
        requester: Option<&PrincipalContext>,
        reviewer: Option<(&opaque_core::identity::PrincipalId, Role, u64)>,
        authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        self.with_scope_authority(requester, None, reviewer, authorize)
    }

    /// Scope issuance/use also checks the current subject while holding the
    /// same identity writer fence as delegation and reviewer revocation.
    pub fn with_scope_authority(
        &self,
        requester: Option<&PrincipalContext>,
        subject: Option<&opaque_core::identity::PrincipalId>,
        reviewer: Option<(&opaque_core::identity::PrincipalId, Role, u64)>,
        authorize: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let conn = self.store.lock();
        let read_principal = |id: &opaque_core::identity::PrincipalId| {
            conn.query_row(
                "SELECT id,kind,iss,sub,email,display_name,tool,service_name,roles,created_at,last_seen,disabled FROM principals WHERE id=?1",
                [id.as_str()], store::row_to_principal,
            ).map_err(|_|"principal unavailable".to_string())
        };
        let now = opaque_core::identity::now_unix();
        if let Some(id) = subject {
            let principal = read_principal(id)?;
            if !self.principal_permitted(&principal) || !principal.has_role(Role::Operator) {
                return Err("scope subject is no longer an eligible operator".into());
            }
        }
        if let Some(context) = requester {
            if self.store.delegation_revocation_failed(&context.jti) {
                return Err("requester delegation revocation could not be persisted".into());
            }
            let principal = read_principal(&context.sub)?;
            let actor = read_principal(&context.act)?;
            if !self.principal_permitted(&principal)
                || actor.disabled
                || principal.roles != context.sub_roles
            {
                return Err("requester authority changed before dispatch".into());
            }
            let live: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM delegations WHERE jti=?1 AND sub_principal=?2 AND act_principal=?3 AND mode=?4 AND revoked_at IS NULL AND expires_at>?5 AND human_session_id IS ?6)",
                rusqlite::params![context.jti,context.sub.as_str(),context.act.as_str(),context.mode.as_str(),now,context.human_session_id],|row|row.get(0),
            ).map_err(|_|"requester delegation unavailable")?;
            if !live {
                return Err("requester delegation revoked or expired".into());
            }
            if matches!(
                context.mode,
                opaque_core::identity::AccessMode::Delegated
                    | opaque_core::identity::AccessMode::BreakGlass
            ) {
                let session = context
                    .human_session_id
                    .as_deref()
                    .ok_or("requester login binding unavailable")?;
                let live: bool = conn.query_row(
                    "SELECT EXISTS(SELECT 1 FROM human_sessions WHERE id=?1 AND principal_id=?2 AND idp_issuer=?3 AND revoked_at IS NULL AND expires_at>?4)",
                    rusqlite::params![session,context.sub.as_str(),self.config.issuer,now],|row|row.get(0),
                ).map_err(|_|"requester login unavailable")?;
                if !live {
                    return Err("requester login revoked or expired".into());
                }
            }
        }
        if let Some((id, role, expected_epoch)) = reviewer {
            let principal = read_principal(id)?;
            let epoch: u64 = conn
                .query_row(
                    "SELECT epoch FROM identity_authority_epochs WHERE principal_id=?1",
                    [id.as_str()],
                    |row| row.get(0),
                )
                .map_err(|_| "reviewer authority unavailable")?;
            if !id.is_human()
                || !self.principal_permitted(&principal)
                || !principal.has_role(role)
                || epoch != expected_epoch
            {
                return Err("reviewer authority changed before dispatch".into());
            }
        }
        authorize()
    }

    /// Initialize the identity runtime: validate config, open the store,
    /// load or create the signing key, and upsert config-declared service
    /// principals. `state_dir` is `~/.opaque` (the audit.db directory).
    pub fn initialize(config: IdentityConfig, state_dir: &Path) -> Result<Self, String> {
        config.validate()?;

        let store = IdentityStore::open(&state_dir.join("identity.db"))
            .map_err(|e| format!("failed to open identity store: {e}"))?;
        // Every startup, including disabled persona mode, changes the durable
        // evidence generation when claim semantics/freshness policy changes.
        store.sync_persona_policy(config.persona.as_ref())?;
        let signing = keys::load_or_create_signing_key(&state_dir.join("identity.key"))
            .map_err(|e| format!("failed to load identity signing key: {e}"))?;

        // Upsert service principals from config. Invalid entries are skipped
        // with a warning — a config typo must not take the daemon down. Any
        // persistence failure must abort startup rather than publish stale roles.
        for sp in &config.service_principals {
            let roles = match roles_from_string(&sp.roles.join(",")) {
                Ok(r) => r,
                Err(e) => {
                    warn!(
                        "skipping service principal '{}': invalid roles: {e}",
                        sp.name
                    );
                    continue;
                }
            };
            let kind = opaque_core::identity::PrincipalKind::Service {
                name: sp.name.clone(),
            };
            if let Err(e) = kind.validate() {
                warn!("skipping service principal '{}': {e}", sp.name);
                continue;
            }
            let principal = store
                .upsert_service(&sp.name)
                .map_err(|e| format!("failed to persist service principal '{}': {e}", sp.name))?;
            store
                .set_roles(&principal.id, &roles)
                .map_err(|e| format!("failed to persist roles for service '{}': {e}", sp.name))?;
        }

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| format!("failed to build http client: {e}"))?;

        info!(
            "identity runtime initialized (issuer: {}, {} service principals, required: {})",
            config.issuer,
            config.service_principals.len(),
            config.required,
        );

        Ok(Self {
            config,
            store,
            signing,
            http,
            oidc: tokio::sync::Mutex::new(None),
            attempts: LoginAttempts::default(),
            audit: None,
        })
    }

    /// Attach the daemon's audit sink for identity lifecycle events.
    pub fn with_audit(mut self, sink: Arc<dyn opaque_core::audit::AuditSink>) -> Self {
        self.audit = Some(sink);
        self
    }

    /// Emit an identity lifecycle audit event (no-op without a sink).
    pub(crate) fn emit_audit(&self, event: opaque_core::audit::AuditEvent) {
        if let Some(sink) = &self.audit {
            sink.emit(event);
        }
    }

    /// Discovery, cached after the first successful fetch.
    pub(crate) async fn oidc_client(&self) -> Result<Arc<OidcClient>, String> {
        let mut guard = self.oidc.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }
        let client = OidcClient::discover(
            &self.config.issuer,
            self.config.client_id.clone(),
            self.config.audience().to_owned(),
            self.http.clone(),
        )
        .await?;
        let client = Arc::new(client);
        *guard = Some(client.clone());
        Ok(client)
    }

    /// The `identity` object for `whoami` / `identity.login_status` payloads:
    /// the current (latest active) human session, or `None` when logged out.
    pub fn current_identity_json(&self) -> Option<serde_json::Value> {
        let session = self.store.current_human_session().ok().flatten()?;
        let principal = self
            .store
            .get_principal(&session.principal_id)
            .ok()
            .flatten()?;
        if session.idp_issuer != self.config.issuer || !self.principal_permitted(&principal) {
            return None;
        }
        Some(serde_json::json!({
            "principal_id": principal.id.as_str(),
            "label": principal.display_label(),
            "email": match &principal.kind {
                opaque_core::identity::PrincipalKind::Human { email, .. } => email.clone(),
                _ => None,
            },
            "roles": principal.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            "session_id": session.id,
            "session_expires_at_utc_ms": session.expires_at * 1000,
            "issuer": session.idp_issuer,
        }))
    }

    /// The principal behind the current active human session, if any.
    pub fn current_human_principal(&self) -> Option<opaque_core::identity::Principal> {
        let session = self.store.current_human_session().ok().flatten()?;
        if session.idp_issuer != self.config.issuer {
            return None;
        }
        self.store
            .get_principal(&session.principal_id)
            .ok()
            .flatten()
            .filter(|principal| self.principal_permitted(principal))
    }

    /// True when the current human session's principal holds `role`.
    pub fn current_human_has_role(&self, role: Role) -> bool {
        self.current_human_principal()
            .is_some_and(|p| !p.disabled && p.has_role(role))
    }
}

/// `resource_authority.rs` moved to `opaque-bounded-work`, which cannot name
/// `IdentityRuntime` (this crate has no `lib.rs`, and `identity/` stays
/// here regardless — see that module's doc comment). This implements the
/// narrow trait it defines instead, the same "opaqued implements a trait
/// the extracted crate defines" direction as
/// `opaque_bounded_work::task_facade::BoundedWorkFacade for Enclave`.
impl opaque_bounded_work::resource_authority::IdentityAuthority for IdentityRuntime {
    fn config_issuer(&self) -> &str {
        &self.config.issuer
    }

    fn config_required(&self) -> bool {
        self.config.required
    }

    fn persona_max_age_secs(&self) -> Option<u64> {
        self.config.persona.as_ref().map(|p| p.max_age_secs)
    }

    fn principal_permitted(&self, principal: &opaque_core::identity::Principal) -> bool {
        IdentityRuntime::principal_permitted(self, principal)
    }

    fn get_human_by_subject(
        &self,
        issuer: &str,
        subject: &str,
    ) -> Result<Option<opaque_core::identity::Principal>, String> {
        self.store.get_human_by_subject(issuer, subject)
    }

    fn resource_token_revoked(
        &self,
        issuer: &str,
        audience: &str,
        jti: &str,
    ) -> Result<bool, String> {
        self.store.resource_token_revoked(issuer, audience, jti)
    }

    fn revoke_resource_token(
        &self,
        issuer: &str,
        audience: &str,
        jti: &str,
        expires_at: i64,
    ) -> Result<(), String> {
        self.store
            .revoke_resource_token(issuer, audience, jti, expires_at)
    }

    fn authorize_scopes(
        &self,
        binding: &opaque_core::tenant::TenantBinding,
        recipient: &opaque_core::identity::PrincipalId,
        now: i64,
        persona_max_age_secs: u64,
    ) -> Result<std::collections::BTreeSet<String>, String> {
        self.store
            .authorize_scopes(binding, recipient, now, persona_max_age_secs, |p| {
                self.principal_permitted(p)
            })
    }

    fn emit_audit(&self, event: opaque_core::audit::AuditEvent) {
        IdentityRuntime::emit_audit(self, event)
    }
}

// ---------------------------------------------------------------------------
// RPC handlers
// ---------------------------------------------------------------------------

/// `identity.role_set`: change a principal's roles, gated on a fresh
/// out-of-band admin approval, a last-admitted-admin lockout guard, and a
/// TOCTOU recheck of both the acting admin's and target's state after the
/// approval completes (membership/roles can change while the human is
/// reviewing).
///
/// Extracted verbatim out of `main.rs`'s `handle_request` dispatch (pure
/// structural move, no behavior change) — this arm alone was ~195 inline
/// lines, by far the thickest `identity.*` method (contrast
/// `identity.login_start`'s ~27-line clean delegate, left inline in
/// `main.rs`).
pub async fn handle_role_set(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    principal_ctx: Option<PrincipalContext>,
    session_id: Option<&str>,
) -> Response {
    let Some(rt) = state.identity.as_ref() else {
        return Response::err(
            Some(req.id),
            "identity_not_configured",
            "no [identity] section in the daemon config",
        );
    };
    // An ambient admin login is only a prerequisite. It never permits
    // another socket holder to mutate roles without fresh approval.
    let acting_admin = rt
        .current_human_principal()
        .filter(|principal| principal.has_role(opaque_core::identity::Role::Admin));
    let Some(acting_admin) = acting_admin else {
        return Response::err(
            Some(req.id),
            "not_authorized",
            "role changes require an active admin login session",
        );
    };
    if principal_ctx.as_ref().is_some_and(|context| {
        !context
            .sub_roles
            .contains(&opaque_core::identity::Role::Admin)
    }) {
        return Response::err(
            Some(req.id),
            "not_authorized",
            "delegated role changes require an admin subject",
        );
    }
    let principal_id = req
        .params
        .get("principal_id")
        .and_then(|v| v.as_str())
        .and_then(|s| opaque_core::identity::PrincipalId::parse(s).ok());
    let Some(principal_id) = principal_id else {
        return Response::err(
            Some(req.id),
            "invalid_params",
            "principal_id must be a valid principal id",
        );
    };
    let roles_param = req.params.get("roles").and_then(|v| v.as_array());
    let Some(roles_param) = roles_param else {
        return Response::err(
            Some(req.id),
            "invalid_params",
            "roles must be an array of role names",
        );
    };
    let roles_csv = roles_param
        .iter()
        .map(|v| v.as_str())
        .collect::<Option<Vec<_>>>();
    let Some(roles_csv) = roles_csv else {
        return Response::err(
            Some(req.id),
            "invalid_params",
            "every role must be a role name",
        );
    };
    let roles_csv = roles_csv.join(",");
    let roles = match opaque_core::identity::roles_from_string(&roles_csv) {
        Ok(r) => r,
        Err(e) => {
            return Response::err(Some(req.id), "invalid_params", e.to_string());
        }
    };
    // Only an admitted, enabled human can administer roles through
    // this flow. Service roles and removed members cannot satisfy the
    // lockout guard. The store repeats this under its writer lock.
    let eligible_admin = |principal: &opaque_core::identity::Principal| {
        matches!(
            &principal.kind,
            opaque_core::identity::PrincipalKind::Human { .. }
        ) && principal.has_role(opaque_core::identity::Role::Admin)
            && rt.principal_permitted(principal)
    };
    let current_eligible_admin_count = || {
        rt.store
            .list_principals()
            .map(|principals| {
                principals
                    .iter()
                    .filter(|principal| eligible_admin(principal))
                    .count()
            })
            .unwrap_or(0)
    };
    let target = rt.store.get_principal(&principal_id).ok().flatten();
    let target_is_admin = target.as_ref().is_some_and(eligible_admin);
    if target_is_admin
        && !roles.contains(&opaque_core::identity::Role::Admin)
        && current_eligible_admin_count() <= 1
    {
        return Response::err(
            Some(req.id),
            "last_admin",
            "cannot remove the admin role from the last admitted human admin",
        );
    }
    let old_roles = target
        .as_ref()
        .map(|p| opaque_core::identity::roles_to_string(&p.roles))
        .unwrap_or_default();
    let tenant_context = state
        .tenant
        .as_ref()
        .map(|tenant| tenant.binding().approval_context())
        .unwrap_or_default();
    let review = format!(
        "Change principal roles\n{tenant_context}Acting admin: {}\nTarget principal: {}\nPrevious roles: [{}]\nApproved replacement roles: [{}]",
        acting_admin.id,
        principal_id,
        old_roles,
        opaque_core::identity::roles_to_string(&roles)
    );
    if state
        .enclave
        .request_control_approval(
            identity,
            client_type,
            "identity.role_set",
            &review,
            "This changes the principal's authorization. Apply exactly this replacement role set.",
        )
        .await
        .is_err()
    {
        return Response::err(
            Some(req.id),
            "permission_denied",
            "role changes require fresh out-of-band admin approval",
        );
    }
    if crate::resolve_principal_context(state, session_id)
        .await
        .ok()
        .as_ref()
        != Some(&principal_ctx)
    {
        return Response::err(
            Some(req.id),
            "authority_changed",
            "delegation changed during role approval",
        );
    }
    if rt.current_human_principal().is_none_or(|current| {
        current.id != acting_admin.id || !current.has_role(opaque_core::identity::Role::Admin)
    }) || rt
        .store
        .get_principal(&principal_id)
        .ok()
        .flatten()
        .is_none_or(|current| opaque_core::identity::roles_to_string(&current.roles) != old_roles)
        || (target_is_admin
            && !roles.contains(&opaque_core::identity::Role::Admin)
            && current_eligible_admin_count() <= 1)
    {
        return Response::err(
            Some(req.id),
            "authority_changed",
            "identity authority changed during approval; request a fresh review",
        );
    }
    match rt.store.set_reviewed_roles(
        &acting_admin.id,
        &principal_id,
        &old_roles,
        &roles,
        |principal| rt.principal_permitted(principal),
    ) {
        Ok(()) => {
            info!(
                "roles updated for {principal_id}: [{}]",
                opaque_core::identity::roles_to_string(&roles)
            );
            let acting_admin = rt
                .current_human_principal()
                .map(|p| p.display_label())
                .unwrap_or_else(|| "bootstrap".into());
            state.audit.emit(
                AuditEvent::new(AuditEventKind::IdentityRoleChanged)
                    .with_operation("identity.role_set")
                    .with_client(ClientSummary::from((identity, client_type)))
                    .with_outcome("ok")
                    .with_detail(format!(
                        "principal={principal_id} roles: [{old_roles}] -> [{}] by={acting_admin}",
                        opaque_core::identity::roles_to_string(&roles)
                    )),
            );
            match rt.store.get_principal(&principal_id) {
                Ok(Some(p)) => Response::ok(
                    req.id,
                    serde_json::json!({
                        "id": p.id.as_str(),
                        "label": p.display_label(),
                        "roles": p.roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
                    }),
                ),
                _ => Response::ok(req.id, serde_json::json!({ "updated": true })),
            }
        }
        Err(e) => Response::err(Some(req.id), "invalid_params", e),
    }
}
