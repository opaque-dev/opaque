//! Policy engine: allowlist-based authorization for operation requests.
//!
//! The policy engine evaluates every [`OperationRequest`] against a set of
//! [`PolicyRule`]s. The default behaviour is **deny-all** unless a rule
//! explicitly allows the request.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::identity::{AccessMode, PrincipalContext, Role};
use crate::operation::{
    ApprovalFactor, ApprovalRequirement, ClientIdentity, ClientType, OperationRequest,
    OperationSafety, WorkspaceContext,
};
use crate::workload::{AttestationStrength, AttestorId, Selector};

// ---------------------------------------------------------------------------
// Client match pattern
// ---------------------------------------------------------------------------

/// Pattern for matching a client identity. All present fields must match.
/// Absent (None) fields are treated as "any".
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientMatch {
    /// Match on UID.
    pub uid: Option<u32>,

    /// Glob pattern on executable path (e.g. `"/Applications/Claude Code*"`).
    pub exe_path: Option<String>,

    /// Exact match on executable SHA-256.
    pub exe_sha256: Option<String>,

    /// Exact match on macOS code signature Team ID.
    pub codesign_team_id: Option<String>,

    /// Exact trusted listener attestor. A request cannot select its own attestor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestor: Option<AttestorId>,

    /// Minimum achieved attestation strength; no caller claims are accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_attestation: Option<AttestationStrength>,

    /// Every selector must be present exactly in the trusted observation set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub selectors: Vec<Selector>,
}

impl ClientMatch {
    /// Returns `true` if the given identity matches this pattern.
    pub fn matches(&self, identity: &ClientIdentity) -> bool {
        if self.attestor.is_some() || self.min_attestation.is_some() || !self.selectors.is_empty() {
            let Some(workload) = identity
                .workload
                .as_ref()
                .filter(|value| value.is_attested())
            else {
                return false;
            };
            if self
                .attestor
                .as_ref()
                .is_some_and(|expected| expected != &workload.source)
                || self
                    .min_attestation
                    .is_some_and(|minimum| workload.strength < minimum)
                || self
                    .selectors
                    .iter()
                    .any(|selector| !workload.selectors.contains(selector))
            {
                return false;
            }
        }
        if let Some(uid) = self.uid
            && identity.uid != uid
        {
            return false;
        }

        if let Some(ref pattern) = self.exe_path {
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

        if let Some(ref expected_hash) = self.exe_sha256 {
            match &identity.exe_sha256 {
                Some(actual) => {
                    if !actual.eq_ignore_ascii_case(expected_hash) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if let Some(ref expected_team) = self.codesign_team_id {
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
}

/// Whether the current platform's connection attestor can ever populate
/// `codesign_team_id` for a real client. Mirrors the platform gate on
/// `opaque_federation_runtime::workload_attest::signing_team_for_peer`, which
/// resolves a macOS code-signing Team ID from the kernel-verified peer audit
/// token and has no equivalent elsewhere. `uid`, `exe_path` and `exe_sha256`
/// are populated on every supported platform, so they need no such check.
pub fn codesign_team_id_is_platform_enforceable() -> bool {
    cfg!(target_os = "macos")
}

/// True when a client-identity constraint requiring `codesign_team_id`
/// cannot be satisfied by a real client on this platform. The one-field
/// decision every N1 caller reduces to: a policy rule's `ClientMatch`, a
/// `known_human_clients` entry, or any future caller all just need to know
/// whether they name the field and whether this platform can enforce it.
fn codesign_requirement_is_unenforceable(
    requires_codesign_team_id: bool,
    codesign_enforceable: bool,
) -> bool {
    requires_codesign_team_id && !codesign_enforceable
}

/// Rules whose [`ClientMatch`] requires `codesign_team_id` although the
/// current platform can never populate it for a real client (N1): such a
/// rule loads without error but can never match, an accepted-but-unenforced
/// constraint rather than a visible one. Pure over `codesign_enforceable` so
/// the decision is unit-testable independent of the host platform running
/// the test; production callers pass
/// [`codesign_team_id_is_platform_enforceable`].
pub fn unenforceable_client_identity_rules(
    rules: &[PolicyRule],
    codesign_enforceable: bool,
) -> Vec<(&PolicyRule, &'static str)> {
    rules
        .iter()
        .filter(|rule| {
            codesign_requirement_is_unenforceable(
                rule.client.codesign_team_id.is_some(),
                codesign_enforceable,
            )
        })
        .map(|rule| (rule, "codesign_team_id"))
        .collect()
}

/// The shared sentence behind every N1 warning: names what kind of thing
/// (`kind`) requires `field`, by `name`, states the consequence, and points
/// at the fields this platform does populate. Every caller routes through
/// this one format string so the wording cannot drift between them.
fn unenforceable_field_warning(kind: &str, name: &str, field: &str, consequence: &str) -> String {
    format!(
        "{kind} {name:?} requires {field}, which this platform cannot populate \
         for a real client. {consequence} Pin the caller with exe_sha256 or \
         exe_path on this platform instead."
    )
}

/// Operator-facing text for one unenforceable client-identity constraint on
/// a policy rule: names the rule and the field, and points at the fields
/// this platform does populate.
pub fn client_identity_platform_warning(rule_name: &str, field: &str) -> String {
    unenforceable_field_warning(
        "policy rule",
        rule_name,
        field,
        "The rule will never match.",
    )
}

/// Warning strings for every rule in `rules` that requires a client-identity
/// field this platform cannot enforce. Empty when there is nothing to warn
/// about. Shared by the CLI policy-check path, the daemon's config-load
/// path, and the federation bundle-apply path, so all three phrase the same
/// condition identically.
pub fn platform_policy_warnings(rules: &[PolicyRule], codesign_enforceable: bool) -> Vec<String> {
    unenforceable_client_identity_rules(rules, codesign_enforceable)
        .into_iter()
        .map(|(rule, field)| client_identity_platform_warning(&rule.name, field))
        .collect()
}

/// Names of `known_human_clients` entries requiring `codesign_team_id`
/// although the current platform can never populate it for a real client
/// (N1). The one-field adapter for [`unenforceable_client_identity_rules`]:
/// `HumanClientEntry` lives in the daemon crate, not here, so callers adapt
/// each entry into a `(name, requires_codesign_team_id)` pair before calling
/// this. Pure over `codesign_enforceable` for the same reason as its rule
/// counterpart: unit-testable independent of the host platform.
pub fn unenforceable_codesign_entries<'a>(
    entries: impl IntoIterator<Item = (&'a str, bool)>,
    codesign_enforceable: bool,
) -> Vec<&'a str> {
    entries
        .into_iter()
        .filter(|&(_, requires_codesign)| {
            codesign_requirement_is_unenforceable(requires_codesign, codesign_enforceable)
        })
        .map(|(name, _)| name)
        .collect()
}

/// Operator-facing text for one `known_human_clients` entry that requires
/// `codesign_team_id` although this platform cannot populate it: names the
/// entry, states that it can never classify a connection as human, and
/// points at the fields this platform does populate.
pub fn known_human_client_platform_warning(entry_name: &str) -> String {
    unenforceable_field_warning(
        "known_human_clients entry",
        entry_name,
        "codesign_team_id",
        "The entry will never classify a client as human.",
    )
}

/// Warning strings for every `known_human_clients` entry (adapted to
/// `(name, requires_codesign_team_id)` pairs by the caller) that requires a
/// field this platform cannot enforce. Empty when there is nothing to warn
/// about. The `known_human_clients` counterpart to [`platform_policy_warnings`].
pub fn known_human_client_platform_warnings<'a>(
    entries: impl IntoIterator<Item = (&'a str, bool)>,
    codesign_enforceable: bool,
) -> Vec<String> {
    unenforceable_codesign_entries(entries, codesign_enforceable)
        .into_iter()
        .map(known_human_client_platform_warning)
        .collect()
}

// ---------------------------------------------------------------------------
// Identity match pattern (Phase 1 identity substrate)
// ---------------------------------------------------------------------------

/// Constraints on the verified principal/delegation context of a request.
/// All absent (`None`) fields mean "any". If ANY constraint is set and the
/// request carries no principal context, the rule does not match (fail
/// closed) — an identity-constrained rule can never be satisfied by an
/// unidentified request.
///
/// This is how "effective permission = agent ∩ human" is expressed: the
/// `roles` constraint is checked against the DELEGATOR (`sub`) — the human
/// (or service principal) the agent acts on behalf of — so an agent session
/// can never exceed what its delegating principal holds.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityMatch {
    /// Require a verified principal context to be present at all.
    pub require_principal: Option<bool>,

    /// Delegating principal: exact principal id (`hum_…`/`svc_…`) or
    /// case-insensitive display label (email for humans, `service:<name>`).
    pub principal: Option<String>,

    /// Roles the delegating principal must ALL hold (resolved from the
    /// identity store at request time). Unknown role names never match.
    pub roles: Option<Vec<String>>,

    /// Access modes this rule applies to (delegated / autonomous / break_glass).
    pub access_modes: Option<Vec<AccessMode>>,

    /// Team namespaces (from the applied federation bundle) the delegating
    /// principal must belong to — ANY-of. Fails closed for requests without
    /// a principal, and for principals in none of the listed teams (including
    /// when no bundle is applied, since then nobody has teams).
    pub teams: Option<Vec<String>>,
}

impl IdentityMatch {
    /// True when no identity constraint is configured.
    pub fn is_empty(&self) -> bool {
        self.require_principal.is_none()
            && self.principal.is_none()
            && self.roles.is_none()
            && self.access_modes.is_none()
            && self.teams.is_none()
    }

    /// Returns `true` if the given principal context satisfies this pattern.
    pub fn matches(&self, ctx: Option<&PrincipalContext>) -> bool {
        if self.is_empty() {
            return true;
        }
        // Any constraint present demands a verified context (fail closed).
        // `require_principal = false` is "no requirement", not "must be absent".
        let Some(ctx) = ctx else {
            return self.require_principal == Some(false)
                && self.principal.is_none()
                && self.roles.is_none()
                && self.access_modes.is_none()
                && self.teams.is_none();
        };

        if let Some(ref expected) = self.principal {
            let id_match = ctx.sub.as_str() == expected;
            let label_match = ctx.sub_label.eq_ignore_ascii_case(expected);
            if !id_match && !label_match {
                return false;
            }
        }

        if let Some(ref required) = self.roles {
            for name in required {
                match name.parse::<Role>() {
                    Ok(role) if ctx.sub_roles.contains(&role) => {}
                    // Unknown role names and missing roles both fail closed.
                    _ => return false,
                }
            }
        }

        if let Some(ref modes) = self.access_modes
            && !modes.contains(&ctx.mode)
        {
            return false;
        }

        if let Some(ref teams) = self.teams {
            // ANY-of: the delegator must sit in at least one listed team.
            // An empty rule list can never match (a misconfigured constraint
            // fails closed rather than waving everyone through).
            let hit = teams.iter().any(|t| {
                ctx.sub_teams
                    .iter()
                    .any(|have| have.eq_ignore_ascii_case(t))
            });
            if !hit {
                return false;
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Target match pattern
// ---------------------------------------------------------------------------

/// Pattern for matching operation target fields. Each entry is a field name
/// mapped to a glob pattern. All present entries must match.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetMatch {
    /// Map of target field name to glob pattern.
    /// e.g. `{ "repo": "org/*", "environment": "prod*" }`.
    pub fields: std::collections::HashMap<String, String>,
}

impl TargetMatch {
    /// Returns `true` if the given target map matches all patterns.
    pub fn matches(&self, target: &std::collections::HashMap<String, String>) -> bool {
        for (field, pattern) in &self.fields {
            match target.get(field) {
                Some(value) => {
                    if !glob_match::glob_match(pattern, value) {
                        return false;
                    }
                }
                // If the target does not have the required field, no match.
                None => return false,
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Workspace match pattern
// ---------------------------------------------------------------------------

/// Pattern for matching git workspace context. When a rule has workspace
/// constraints, requests without workspace context are denied.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceMatch {
    /// Glob pattern for the git remote URL (e.g. `"*github.com:org/*"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_url_pattern: Option<String>,

    /// Glob pattern for the branch name (e.g. `"main"`, `"release/*"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch_pattern: Option<String>,

    /// If true, deny requests from dirty (uncommitted changes) workspaces.
    #[serde(default)]
    pub require_clean: bool,
}

impl WorkspaceMatch {
    /// Returns `true` if the workspace context (or lack thereof) matches.
    ///
    /// - No constraints + no workspace = match (backward compat)
    /// - No constraints + workspace present = match (backward compat)
    /// - Constraints + no workspace = deny
    /// - Constraints + unverified workspace = deny (fail-closed)
    /// - Constraints + verified workspace = check each field via glob
    /// - `require_clean && dirty = deny`
    pub fn matches(&self, workspace: Option<&WorkspaceContext>) -> bool {
        let has_constraints = self.remote_url_pattern.is_some()
            || self.branch_pattern.is_some()
            || self.require_clean;

        match (has_constraints, workspace) {
            // No constraints, no workspace — backward compat match.
            (false, None) => true,
            // No constraints, workspace present — match.
            (false, Some(_)) => true,
            // Constraints but no workspace — deny.
            (true, None) => false,
            // Constraints + workspace — check each.
            (true, Some(ws)) => {
                // Fail-closed: workspace constraints require verified workspace state.
                // If the daemon could not verify the claimed workspace (cwd unreadable,
                // git commands failed, etc.), the workspace_verified flag is false and
                // the rule must not match.
                if !ws.workspace_verified {
                    return false;
                }

                if let Some(ref pattern) = self.remote_url_pattern {
                    match &ws.remote_url {
                        Some(url) => {
                            if !glob_match::glob_match(pattern, url) {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }

                if let Some(ref pattern) = self.branch_pattern {
                    match &ws.branch {
                        Some(branch) => {
                            if !glob_match::glob_match(pattern, branch) {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }

                if self.require_clean && ws.dirty {
                    return false;
                }

                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Secret name match pattern
// ---------------------------------------------------------------------------

/// Pattern for matching secret ref names referenced in an operation request.
/// Constrains which secrets a policy rule permits, preventing "secret
/// transporter" attacks where a client with access to one operation can
/// reference any secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretNameMatch {
    /// Glob patterns for allowed secret ref names. Empty = match any.
    #[serde(default)]
    pub patterns: Vec<String>,
}

impl SecretNameMatch {
    /// Returns `true` if all secret ref names match at least one pattern.
    /// An empty pattern list matches any set of names (backward compat).
    /// A non-empty pattern list requires at least one secret ref name —
    /// empty `secret_ref_names` fails closed when patterns are specified.
    pub fn matches(&self, secret_ref_names: &[String]) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        if secret_ref_names.is_empty() {
            return false;
        }
        secret_ref_names.iter().all(|name| {
            self.patterns
                .iter()
                .any(|p| glob_match::glob_match(p, name))
        })
    }
}

// ---------------------------------------------------------------------------
// Approval configuration within a rule
// ---------------------------------------------------------------------------

/// Approval configuration attached to a policy rule.
///
/// Defaults to `require: Never, factors: []` — suitable for deny rules
/// where approval is irrelevant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalConfig {
    /// When approval is required.
    #[serde(default)]
    pub require: ApprovalRequirement,

    /// Acceptable approval factors (any-of).
    #[serde(default)]
    pub factors: Vec<ApprovalFactor>,

    /// Lease duration after approval (for `FirstUse`).
    #[serde(
        default,
        with = "optional_duration_secs",
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_ttl: Option<Duration>,

    /// If true, the approval is consumed after a single use.
    #[serde(default)]
    pub one_time: bool,

    /// Total attempts authorized by one first-use approval, including the
    /// approving request. Exhaustion denies reuse until expiry or revocation.
    /// Absent preserves the legacy unlimited-within-TTL behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<u32>,

    /// Break-glass segregation of duties: the approver must be a different
    /// principal than the one the operation is performed on behalf of
    /// (`sub`). Fails closed when the request carries no principal context
    /// or the approver identity is unknown. Requires an approval mode other
    /// than `never` — the enclave rejects the combination as misconfigured.
    #[serde(default)]
    pub require_distinct_approver: bool,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            require: ApprovalRequirement::Never,
            factors: vec![],
            lease_ttl: None,
            one_time: false,
            budget: None,
            require_distinct_approver: false,
        }
    }
}

mod optional_duration_secs {
    use std::time::Duration;

    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(dur: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match dur {
            Some(d) => serializer.serialize_u64(d.as_secs()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<u64> = Option::deserialize(deserializer)?;
        Ok(opt.map(Duration::from_secs))
    }
}

// ---------------------------------------------------------------------------
// Policy rule
// ---------------------------------------------------------------------------

/// A single policy rule. Rules are evaluated in order; the first matching rule
/// determines the decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable rule name (for audit/logging).
    pub name: String,

    /// Client match pattern. Defaults to "match any" when omitted.
    #[serde(default)]
    pub client: ClientMatch,

    /// Glob pattern on operation name (e.g. `"github.*"`).
    pub operation_pattern: String,

    /// Target field constraints.
    #[serde(default)]
    pub target: TargetMatch,

    /// Workspace (git repo/branch) constraints.
    #[serde(default)]
    pub workspace: WorkspaceMatch,

    /// Secret ref name constraints (glob patterns).
    #[serde(default)]
    pub secret_names: SecretNameMatch,

    /// Whether this rule allows the matched request.
    #[serde(default = "default_true")]
    pub allow: bool,

    /// What client types this rule applies to.
    /// If empty, applies to all client types.
    #[serde(default)]
    pub client_types: Vec<ClientType>,

    /// Principal/delegation constraints (Phase 1 identity substrate).
    /// Defaults to "match any" when omitted.
    #[serde(default)]
    pub identity: IdentityMatch,

    /// Approval configuration (required factors, lease, one-time).
    /// Defaults to no approval required (suitable for deny rules).
    #[serde(default)]
    pub approval: ApprovalConfig,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Known TOML keys
// ---------------------------------------------------------------------------
//
// serde ignores keys it does not know (only `[rules.client]` denies them), so
// a mistyped or misplaced key is silently inert. These lists let
// `opaque policy check` report such keys. A unit test keeps each list in step
// with its struct: it serializes a fully populated value written as an
// exhaustive struct literal, so adding a field fails to compile until the
// list is updated.

impl PolicyRule {
    /// Keys a `[[rules]]` table accepts.
    pub const FIELDS: &'static [&'static str] = &[
        "name",
        "client",
        "operation_pattern",
        "target",
        "workspace",
        "secret_names",
        "allow",
        "client_types",
        "identity",
        "approval",
    ];
}

impl ClientMatch {
    /// Keys a `[rules.client]` table accepts.
    pub const FIELDS: &'static [&'static str] = &[
        "uid",
        "exe_path",
        "exe_sha256",
        "codesign_team_id",
        "attestor",
        "min_attestation",
        "selectors",
    ];
}

impl TargetMatch {
    /// Keys a `[rules.target]` table accepts.
    pub const FIELDS: &'static [&'static str] = &["fields"];
}

impl WorkspaceMatch {
    /// Keys a `[rules.workspace]` table accepts.
    pub const FIELDS: &'static [&'static str] =
        &["remote_url_pattern", "branch_pattern", "require_clean"];
}

impl SecretNameMatch {
    /// Keys a `[rules.secret_names]` table accepts.
    pub const FIELDS: &'static [&'static str] = &["patterns"];
}

impl IdentityMatch {
    /// Keys a `[rules.identity]` table accepts.
    pub const FIELDS: &'static [&'static str] = &[
        "require_principal",
        "principal",
        "roles",
        "access_modes",
        "teams",
    ];
}

impl ApprovalConfig {
    /// Keys a `[rules.approval]` table accepts.
    pub const FIELDS: &'static [&'static str] = &[
        "require",
        "factors",
        "lease_ttl",
        "one_time",
        "budget",
        "require_distinct_approver",
    ];
}

impl PolicyRule {
    /// Check whether this rule matches the given request.
    fn matches(&self, request: &OperationRequest) -> bool {
        // Client type filter.
        if !self.client_types.is_empty() && !self.client_types.contains(&request.client_type) {
            return false;
        }

        // Client identity match.
        if !self.client.matches(&request.client_identity) {
            return false;
        }

        // Principal/delegation constraints.
        if !self.identity.matches(request.principal.as_ref()) {
            return false;
        }

        // Operation name glob.
        if !glob_match::glob_match(&self.operation_pattern, &request.operation) {
            return false;
        }

        // Target constraints.
        if !self.target.matches(&request.target) {
            return false;
        }

        // Workspace constraints.
        if !self.workspace.matches(request.workspace.as_ref()) {
            return false;
        }

        // Secret ref name constraints.
        if !self.secret_names.matches(&request.secret_ref_names) {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Policy decision
// ---------------------------------------------------------------------------

/// The result of evaluating a request against the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Whether the request is allowed.
    pub allowed: bool,

    /// If allowed, the set of required approval factors.
    pub required_factors: Vec<ApprovalFactor>,

    /// Approval requirement mode.
    pub approval_requirement: ApprovalRequirement,

    /// Lease TTL granted after approval.
    #[serde(
        default,
        with = "optional_duration_secs",
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_ttl: Option<Duration>,

    /// If true, the approval is consumed after one use.
    pub one_time: bool,

    /// Total attempts covered by a first-use approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<u32>,

    /// If true, the approver must differ from the request's `sub` principal.
    #[serde(default)]
    pub require_distinct_approver: bool,

    /// Name of the rule that matched (for audit).
    pub matched_rule: Option<String>,

    /// Human-readable reason for denial (if denied).
    pub denial_reason: Option<String>,
}

impl PolicyDecision {
    /// Construct a deny decision.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            budget: None,
            require_distinct_approver: false,
            matched_rule: None,
            denial_reason: Some(reason.into()),
        }
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.allowed {
            write!(f, "ALLOW")?;
            if let Some(ref rule) = self.matched_rule {
                write!(f, " (rule={rule})")?;
            }
        } else {
            write!(f, "DENY")?;
            if let Some(ref reason) = self.denial_reason {
                write!(f, ": {reason}")?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Policy engine
// ---------------------------------------------------------------------------

/// Error type for policy engine operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PolicyError {
    #[error("policy evaluation failed: {0}")]
    EvaluationFailed(String),
}

/// The policy engine holds an ordered list of rules and evaluates requests
/// against them. Default behaviour is **deny-all**.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Create a policy engine with no rules (deny-all).
    pub fn new() -> Self {
        Self { rules: vec![] }
    }

    /// Create a policy engine from a list of rules.
    pub fn with_rules(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    /// Add a rule to the engine.
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Stable digest of the complete ordered effective rule set. Conversion
    /// through JSON values orders object keys without changing rule order.
    pub fn digest(&self) -> Result<String, serde_json::Error> {
        use sha2::{Digest, Sha256};
        let value = serde_json::to_value(&self.rules)?;
        let mut hash = Sha256::new();
        hash.update(b"opaque.effective-policy.v1\0");
        hash.update(serde_json::to_vec(&value)?);
        Ok(crate::workstation::hex(&hash.finalize()))
    }

    /// Evaluate a request against the policy rules.
    ///
    /// Agent `REVEAL` requests are denied before matching. `SENSITIVE_OUTPUT`
    /// approval is clamped by the enclave; classification alone is not presence.
    pub fn evaluate(&self, request: &OperationRequest, safety: OperationSafety) -> PolicyDecision {
        use opaque_policy_kernel::{Decision, RuleFacts};

        let decision = opaque_policy_kernel::evaluate(
            request.client_type == ClientType::Agent,
            safety == OperationSafety::Reveal,
            self.rules.iter().map(|rule| RuleFacts {
                matches: rule.matches(request),
                allow: rule.allow,
                first_use: rule.approval.require == ApprovalRequirement::FirstUse,
                budget: rule.approval.budget,
            }),
        );
        match decision {
            Decision::AgentRevealDenied => {
                PolicyDecision::deny("REVEAL operations are never permitted for agent clients")
            }
            Decision::RuleDenied(index) => {
                let rule = &self.rules[index];
                PolicyDecision {
                    matched_rule: Some(rule.name.clone()),
                    ..PolicyDecision::deny(format!("denied by rule: {}", rule.name))
                }
            }
            Decision::InvalidBudget => {
                PolicyDecision::deny("approval budget requires first_use and a positive count")
            }
            Decision::Allow(index) => {
                let rule = &self.rules[index];
                PolicyDecision {
                    allowed: true,
                    required_factors: rule.approval.factors.clone(),
                    approval_requirement: rule.approval.require,
                    lease_ttl: rule.approval.lease_ttl,
                    one_time: rule.approval.one_time,
                    budget: rule.approval.budget,
                    require_distinct_approver: rule.approval.require_distinct_approver,
                    matched_rule: Some(rule.name.clone()),
                    denial_reason: None,
                }
            }
            Decision::DefaultDenied => {
                PolicyDecision::deny("no matching policy rule (default deny)")
            }
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::collections::HashMap;
    use std::time::SystemTime;

    use uuid::Uuid;

    use std::time::Duration;

    use super::*;
    use crate::operation::{ClientIdentity, ClientType, OperationRequest};

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

    fn test_request(operation: &str, client_type: ClientType) -> OperationRequest {
        OperationRequest {
            request_id: Uuid::new_v4(),
            client_identity: test_identity(),
            client_type,
            operation: operation.into(),
            target: {
                let mut m = HashMap::new();
                m.insert("repo".into(), "org/myrepo".into());
                m
            },
            secret_ref_names: vec!["JWT".into()],
            created_at: SystemTime::now(),
            expires_at: None,
            params: serde_json::Value::Null,
            workspace: None,
            principal: None,
        }
    }

    fn workload_identity(strength: AttestationStrength) -> crate::workload::WorkloadIdentity {
        crate::workload::WorkloadIdentity {
            source: "peercred".to_owned().try_into().unwrap(),
            strength,
            selectors: ["peercred:uid:501", "peercred:exe_path:/usr/bin/claude-code"]
                .into_iter()
                .map(|value| value.parse().unwrap())
                .collect(),
        }
    }

    #[test]
    fn workload_constraints_require_trusted_exact_selectors_source_and_strength() {
        let matcher: ClientMatch = serde_json::from_value(serde_json::json!({
            "uid": 501,
            "attestor": "peercred",
            "min_attestation": "medium",
            "selectors": ["peercred:uid:501", "peercred:exe_path:/usr/bin/claude-code"]
        }))
        .unwrap();
        let mut identity = test_identity();
        assert!(!matcher.matches(&identity));
        identity.workload = Some(workload_identity(AttestationStrength::Weak));
        assert!(!matcher.matches(&identity));
        identity.workload = Some(workload_identity(AttestationStrength::Medium));
        assert!(matcher.matches(&identity));
        identity.workload.as_mut().unwrap().source = "other".to_owned().try_into().unwrap();
        assert!(!matcher.matches(&identity));
        identity.workload = Some(workload_identity(AttestationStrength::Strong));
        identity
            .workload
            .as_mut()
            .unwrap()
            .selectors
            .remove(&"peercred:exe_path:/usr/bin/claude-code".parse().unwrap());
        assert!(!matcher.matches(&identity));
        let wildcard: ClientMatch = serde_json::from_value(serde_json::json!({
            "selectors": ["peercred:uid:*"]
        }))
        .unwrap();
        assert!(
            !wildcard.matches(&identity),
            "selectors are literal, never globs"
        );
    }

    #[test]
    fn workload_policy_fails_closed_without_attestation_even_for_none_floor() {
        let matcher: ClientMatch = serde_json::from_value(serde_json::json!({
            "min_attestation": "none"
        }))
        .unwrap();
        let mut identity = test_identity();
        assert!(!matcher.matches(&identity));
        identity.workload = Some(crate::workload::WorkloadIdentity::unavailable(
            "peercred".to_owned().try_into().unwrap(),
        ));
        assert!(!matcher.matches(&identity));
        identity.workload = Some(workload_identity(AttestationStrength::Weak));
        assert!(matcher.matches(&identity));
    }

    #[test]
    fn workload_claims_cannot_survive_client_identity_deserialization() {
        let mut identity = test_identity();
        identity.workload = Some(workload_identity(AttestationStrength::Strong));
        let mut wire = serde_json::to_value(&identity).unwrap();
        assert!(wire.get("workload").is_none());
        wire["workload"] = serde_json::to_value(identity.workload.unwrap()).unwrap();
        let decoded: ClientIdentity = serde_json::from_value(wire).unwrap();
        assert!(decoded.workload.is_none());
        let matcher: ClientMatch = serde_json::from_value(serde_json::json!({
            "min_attestation": "weak"
        }))
        .unwrap();
        assert!(!matcher.matches(&decoded));
        assert!(
            serde_json::from_value::<ClientMatch>(serde_json::json!({
                "agent_instance": "caller-chosen"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ClientMatch>(serde_json::json!({
                "min_attestation": "hardware"
            }))
            .is_err()
        );
    }

    #[test]
    fn workload_reaches_policy_evaluation_and_changes_approval_content_hash() {
        let mut rule = allow_rule();
        rule.client.min_attestation = Some(AttestationStrength::Medium);
        let engine = PolicyEngine::with_rules(vec![rule]);
        let mut request = test_request("github.list_secrets", ClientType::Agent);
        let absent_hash = request.content_hash();
        assert!(!engine.evaluate(&request, OperationSafety::Safe).allowed);
        request.client_identity.workload = Some(workload_identity(AttestationStrength::Medium));
        assert!(engine.evaluate(&request, OperationSafety::Safe).allowed);
        let approved_hash = request.content_hash();
        assert_ne!(approved_hash, absent_hash);
        request.client_identity.workload.as_mut().unwrap().strength = AttestationStrength::Weak;
        assert!(!engine.evaluate(&request, OperationSafety::Safe).allowed);
        assert_ne!(request.content_hash(), approved_hash);
        request.client_identity.workload = Some(workload_identity(AttestationStrength::Medium));
        request
            .client_identity
            .workload
            .as_mut()
            .unwrap()
            .selectors
            .insert("peercred:codesign_team_id:TEAM123".parse().unwrap());
        assert_ne!(request.content_hash(), approved_hash);
    }

    fn allow_rule() -> PolicyRule {
        PolicyRule {
            name: "allow-claude-github".into(),
            client: ClientMatch {
                uid: Some(501),
                exe_path: Some("/usr/bin/claude*".into()),
                ..Default::default()
            },
            operation_pattern: "github.*".into(),
            target: TargetMatch {
                fields: {
                    let mut m = HashMap::new();
                    m.insert("repo".into(), "org/*".into());
                    m
                },
            },
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![ClientType::Agent, ClientType::Human],
            identity: IdentityMatch::default(),
            approval: ApprovalConfig {
                require: ApprovalRequirement::Always,
                factors: vec![ApprovalFactor::LocalBio],
                lease_ttl: None,
                one_time: true,
                budget: None,
                require_distinct_approver: false,
            },
        }
    }

    #[test]
    fn default_deny() {
        let engine = PolicyEngine::new();
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
        assert!(decision.denial_reason.unwrap().contains("default deny"));
    }

    #[test]
    fn matching_rule_allows() {
        let engine = PolicyEngine::with_rules(vec![allow_rule()]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(decision.allowed);
        assert_eq!(decision.required_factors, vec![ApprovalFactor::LocalBio]);
        assert!(decision.one_time);
    }

    #[test]
    fn reveal_denied_for_agents() {
        let engine = PolicyEngine::with_rules(vec![allow_rule()]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Reveal);
        assert!(!decision.allowed);
        assert!(decision.denial_reason.unwrap().contains("REVEAL"));
    }

    #[test]
    fn sensitive_output_not_gated_on_classification_in_policy() {
        // Software-first (C1): SensitiveOutput is no longer denied at the policy
        // layer for a caller merely because of its classification. A matching allow
        // rule permits it here; the enclave separately clamps SensitiveOutput to
        // mandatory out-of-band approval (enclave::execute), which is the sound
        // presence signal at a shared uid.
        let mut rule = allow_rule();
        rule.client_types = vec![]; // applies to all classifications
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::SensitiveOutput);
        assert!(decision.allowed);
    }

    #[test]
    fn sensitive_output_allowed_when_agent_explicit() {
        let rule = allow_rule(); // already has Agent in client_types
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::SensitiveOutput);
        assert!(decision.allowed);
    }

    #[test]
    fn client_match_uid_mismatch() {
        let mut rule = allow_rule();
        rule.client.uid = Some(999);
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }

    #[test]
    fn target_mismatch_denies() {
        let engine = PolicyEngine::with_rules(vec![allow_rule()]);
        let mut req = test_request("github.set_actions_secret", ClientType::Human);
        req.target.insert("repo".into(), "other-org/repo".into());
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }

    #[test]
    fn explicit_deny_rule() {
        let mut rule = allow_rule();
        rule.allow = false;
        rule.name = "deny-rule".into();
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
        assert!(decision.denial_reason.unwrap().contains("deny-rule"));
    }

    #[test]
    fn policy_decision_display() {
        let allow = PolicyDecision {
            allowed: true,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            budget: None,
            require_distinct_approver: false,
            matched_rule: Some("test-rule".into()),
            denial_reason: None,
        };
        assert_eq!(format!("{allow}"), "ALLOW (rule=test-rule)");

        let deny = PolicyDecision::deny("no rule matched");
        assert!(format!("{deny}").starts_with("DENY"));
    }

    #[test]
    fn client_match_exe_sha256_mismatch() {
        let cm = ClientMatch {
            exe_sha256: Some("expected_hash".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.exe_sha256 = Some("different_hash".into());
        assert!(!cm.matches(&id));
    }

    #[test]
    fn client_match_exe_sha256_none() {
        let cm = ClientMatch {
            exe_sha256: Some("expected_hash".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.exe_sha256 = None;
        assert!(!cm.matches(&id));
    }

    #[test]
    fn client_match_codesign_mismatch() {
        let cm = ClientMatch {
            codesign_team_id: Some("TEAM_A".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.codesign_team_id = Some("TEAM_B".into());
        assert!(!cm.matches(&id));
    }

    #[test]
    fn client_match_codesign_none() {
        let cm = ClientMatch {
            codesign_team_id: Some("TEAM_A".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.codesign_team_id = None;
        assert!(!cm.matches(&id));
    }

    /// N1: a rule naming `client`, with every other field at its default.
    fn client_rule(name: &str, client: ClientMatch) -> PolicyRule {
        PolicyRule {
            name: name.into(),
            client,
            operation_pattern: "*".into(),
            target: TargetMatch::default(),
            workspace: WorkspaceMatch::default(),
            secret_names: SecretNameMatch::default(),
            allow: true,
            client_types: vec![],
            identity: IdentityMatch::default(),
            approval: ApprovalConfig::default(),
        }
    }

    #[test]
    fn unenforceable_client_identity_rules_flags_codesign_only_when_unenforceable() {
        let rules = vec![
            client_rule(
                "requires-team",
                ClientMatch {
                    codesign_team_id: Some("TEAM_A".into()),
                    ..Default::default()
                },
            ),
            client_rule(
                "requires-exe",
                ClientMatch {
                    exe_sha256: Some("deadbeef".into()),
                    exe_path: Some("/usr/bin/claude*".into()),
                    ..Default::default()
                },
            ),
            client_rule("requires-nothing", ClientMatch::default()),
        ];

        // Enforceable (macOS): nothing is flagged, regardless of what any
        // rule requires.
        assert!(unenforceable_client_identity_rules(&rules, true).is_empty());

        // Not enforceable: only the codesign_team_id rule is flagged, by
        // name, and exe_sha256/exe_path rules are left alone (they ARE
        // populated on every platform).
        let flagged = unenforceable_client_identity_rules(&rules, false);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].0.name, "requires-team");
        assert_eq!(flagged[0].1, "codesign_team_id");
    }

    #[test]
    fn client_identity_platform_warning_names_the_rule_field_and_alternative() {
        let warning = client_identity_platform_warning("requires-team", "codesign_team_id");
        assert!(warning.contains("requires-team"));
        assert!(warning.contains("codesign_team_id"));
        assert!(warning.contains("exe_sha256"));
        assert!(warning.contains("exe_path"));
        assert!(warning.contains("never match"));
    }

    #[test]
    fn platform_policy_warnings_is_empty_when_enforceable_or_nothing_to_flag() {
        let team_rule = client_rule(
            "requires-team",
            ClientMatch {
                codesign_team_id: Some("TEAM_A".into()),
                ..Default::default()
            },
        );
        assert!(platform_policy_warnings(std::slice::from_ref(&team_rule), true).is_empty());

        let exe_rule = client_rule(
            "requires-exe",
            ClientMatch {
                exe_sha256: Some("deadbeef".into()),
                ..Default::default()
            },
        );
        assert!(platform_policy_warnings(std::slice::from_ref(&exe_rule), false).is_empty());

        let warnings = platform_policy_warnings(std::slice::from_ref(&team_rule), false);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("requires-team"));
        assert!(warnings[0].contains("codesign_team_id"));
    }

    /// N1: the `known_human_clients` one-field adapter, exhaustive over
    /// (requires codesign_team_id?) x (platform enforceable?).
    #[test]
    fn unenforceable_codesign_entries_flags_only_the_unenforceable_ones() {
        let entries = [
            ("requires-team", true),
            ("requires-exe", false),
            ("requires-nothing", false),
        ];

        // Enforceable (macOS): nothing is flagged, regardless of what any
        // entry requires.
        assert!(unenforceable_codesign_entries(entries, true).is_empty());

        // Not enforceable: only the entry that actually requires
        // codesign_team_id is flagged, by name.
        assert_eq!(
            unenforceable_codesign_entries(entries, false),
            ["requires-team"]
        );
    }

    #[test]
    fn known_human_client_platform_warning_names_the_entry_and_alternative() {
        let warning = known_human_client_platform_warning("requires-team");
        assert!(warning.contains("requires-team"));
        assert!(warning.contains("codesign_team_id"));
        assert!(warning.contains("exe_sha256"));
        assert!(warning.contains("exe_path"));
        assert!(warning.contains("never classify"));
    }

    #[test]
    fn known_human_client_platform_warnings_is_empty_when_enforceable_or_nothing_to_flag() {
        let entries = [("requires-team", true), ("requires-exe", false)];

        assert!(known_human_client_platform_warnings(entries, true).is_empty());
        assert!(known_human_client_platform_warnings([entries[1]], false).is_empty());

        let warnings = known_human_client_platform_warnings(entries, false);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("requires-team"));
        assert!(warnings[0].contains("codesign_team_id"));
    }

    #[test]
    fn client_match_exe_path_none() {
        let cm = ClientMatch {
            exe_path: Some("/usr/bin/*".into()),
            ..Default::default()
        };
        let mut id = test_identity();
        id.exe_path = None;
        assert!(!cm.matches(&id));
    }

    #[test]
    fn client_match_all_none() {
        let cm = ClientMatch::default();
        let id = test_identity();
        assert!(cm.matches(&id));
    }

    #[test]
    fn target_match_empty_matches_all() {
        let tm = TargetMatch::default();
        let mut target = HashMap::new();
        target.insert("repo".into(), "anything".into());
        assert!(tm.matches(&target));
    }

    #[test]
    fn target_match_missing_field() {
        let tm = TargetMatch {
            fields: {
                let mut m = HashMap::new();
                m.insert("repo".into(), "org/*".into());
                m
            },
        };
        let target = HashMap::new();
        assert!(!tm.matches(&target));
    }

    #[test]
    fn policy_engine_add_rule_and_count() {
        let mut engine = PolicyEngine::new();
        assert_eq!(engine.rule_count(), 0);
        engine.add_rule(allow_rule());
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn policy_engine_default() {
        let engine = PolicyEngine::default();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn client_type_filter_mismatch() {
        let mut rule = allow_rule();
        rule.client_types = vec![ClientType::Human];
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }

    #[test]
    fn operation_pattern_mismatch() {
        let engine = PolicyEngine::with_rules(vec![allow_rule()]);
        let req = test_request("k8s.set_secret", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }

    #[test]
    fn reveal_allowed_for_human() {
        let mut rule = allow_rule();
        rule.operation_pattern = "*".into();
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("secret.reveal", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::Reveal);
        assert!(decision.allowed);
    }

    #[test]
    fn human_sensitive_output_allowed() {
        let mut rule = allow_rule();
        rule.client_types = vec![ClientType::Human];
        let engine = PolicyEngine::with_rules(vec![rule]);
        let req = test_request("github.set_actions_secret", ClientType::Human);
        let decision = engine.evaluate(&req, OperationSafety::SensitiveOutput);
        assert!(decision.allowed);
    }

    #[test]
    fn policy_decision_display_no_rule() {
        let decision = PolicyDecision {
            allowed: true,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            budget: None,
            require_distinct_approver: false,
            matched_rule: None,
            denial_reason: None,
        };
        assert_eq!(format!("{decision}"), "ALLOW");
    }

    #[test]
    fn policy_decision_display_deny_no_reason() {
        let decision = PolicyDecision {
            allowed: false,
            required_factors: vec![],
            approval_requirement: ApprovalRequirement::Never,
            lease_ttl: None,
            one_time: false,
            budget: None,
            require_distinct_approver: false,
            matched_rule: None,
            denial_reason: None,
        };
        assert_eq!(format!("{decision}"), "DENY");
    }

    #[test]
    fn approval_config_serde_with_lease_ttl() {
        let config = ApprovalConfig {
            require: ApprovalRequirement::FirstUse,
            factors: vec![ApprovalFactor::LocalBio],
            lease_ttl: Some(Duration::from_secs(300)),
            one_time: false,
            budget: None,
            require_distinct_approver: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        let roundtripped: ApprovalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped.lease_ttl, Some(Duration::from_secs(300)));
    }

    #[test]
    fn approval_config_serde_without_lease_ttl() {
        let config = ApprovalConfig {
            require: ApprovalRequirement::Always,
            factors: vec![],
            lease_ttl: None,
            one_time: true,
            budget: None,
            require_distinct_approver: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("lease_ttl"));
        let roundtripped: ApprovalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped.lease_ttl, None);
        assert!(roundtripped.one_time);
    }

    // -- Workspace match tests --

    fn test_workspace() -> WorkspaceContext {
        WorkspaceContext {
            repo_root: "/home/user/project".into(),
            remote_url: Some("git@github.com:org/repo.git".into()),
            branch: Some("main".into()),
            head_sha: Some("abc123".into()),
            dirty: false,
            workspace_verified: true,
        }
    }

    #[test]
    fn workspace_match_empty_matches_all() {
        let wm = WorkspaceMatch::default();
        assert!(wm.matches(None));
        assert!(wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_remote_url_pattern() {
        let wm = WorkspaceMatch {
            remote_url_pattern: Some("*github.com:org/*".into()),
            ..Default::default()
        };
        assert!(wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_remote_url_mismatch() {
        let wm = WorkspaceMatch {
            remote_url_pattern: Some("*gitlab.com:org/*".into()),
            ..Default::default()
        };
        assert!(!wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_branch_pattern() {
        let wm = WorkspaceMatch {
            branch_pattern: Some("main".into()),
            ..Default::default()
        };
        assert!(wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_branch_mismatch() {
        let wm = WorkspaceMatch {
            branch_pattern: Some("release/*".into()),
            ..Default::default()
        };
        assert!(!wm.matches(Some(&test_workspace())));
    }

    #[test]
    fn workspace_match_require_clean_dirty_fails() {
        let wm = WorkspaceMatch {
            require_clean: true,
            ..Default::default()
        };
        let mut ws = test_workspace();
        ws.dirty = true;
        assert!(!wm.matches(Some(&ws)));
    }

    #[test]
    fn workspace_match_require_clean_clean_passes() {
        let wm = WorkspaceMatch {
            require_clean: true,
            ..Default::default()
        };
        let ws = test_workspace(); // dirty = false
        assert!(wm.matches(Some(&ws)));
    }

    #[test]
    fn workspace_match_no_ws_with_constraints_fails() {
        let wm = WorkspaceMatch {
            remote_url_pattern: Some("*".into()),
            ..Default::default()
        };
        assert!(!wm.matches(None));
    }

    #[test]
    fn workspace_match_no_ws_no_constraints_passes() {
        let wm = WorkspaceMatch::default();
        assert!(wm.matches(None));
    }

    #[test]
    fn policy_rule_with_workspace_constraint() {
        let mut rule = allow_rule();
        rule.workspace = WorkspaceMatch {
            remote_url_pattern: Some("*github.com:org/*".into()),
            branch_pattern: Some("main".into()),
            require_clean: false,
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        // Request with matching workspace.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.workspace = Some(test_workspace());
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(decision.allowed);

        // Request without workspace — denied.
        let req2 = test_request("github.set_actions_secret", ClientType::Agent);
        let decision2 = engine.evaluate(&req2, OperationSafety::Safe);
        assert!(!decision2.allowed);
    }

    // -- SecretNameMatch tests --

    #[test]
    fn secret_name_empty_allows_any() {
        let snm = SecretNameMatch::default();
        assert!(snm.matches(&["ANY_SECRET".into(), "OTHER".into()]));
        assert!(snm.matches(&[]));
    }

    #[test]
    fn secret_name_exact() {
        let snm = SecretNameMatch {
            patterns: vec!["JWT".into()],
        };
        assert!(snm.matches(&["JWT".into()]));
        assert!(!snm.matches(&["AWS_KEY".into()]));
    }

    #[test]
    fn secret_name_glob() {
        let snm = SecretNameMatch {
            patterns: vec!["db/*".into()],
        };
        assert!(snm.matches(&["db/password".into()]));
        assert!(snm.matches(&["db/username".into()]));
        assert!(!snm.matches(&["aws/key".into()]));
    }

    #[test]
    fn secret_name_rejects_unmatched() {
        let snm = SecretNameMatch {
            patterns: vec!["JWT".into()],
        };
        assert!(!snm.matches(&["JWT".into(), "UNALLOWED_SECRET".into()]));
    }

    #[test]
    fn secret_name_multiple_patterns() {
        let snm = SecretNameMatch {
            patterns: vec!["JWT".into(), "AWS_*".into()],
        };
        assert!(snm.matches(&["JWT".into()]));
        assert!(snm.matches(&["AWS_ACCESS_KEY".into()]));
        assert!(snm.matches(&["JWT".into(), "AWS_SECRET".into()]));
        assert!(!snm.matches(&["GH_TOKEN".into()]));
    }

    #[test]
    fn secret_name_all_refs_must_match() {
        let snm = SecretNameMatch {
            patterns: vec!["allowed_*".into()],
        };
        // All refs match
        assert!(snm.matches(&["allowed_one".into(), "allowed_two".into()]));
        // One ref doesn't match
        assert!(!snm.matches(&["allowed_one".into(), "forbidden".into()]));
    }

    #[test]
    fn policy_with_secret_constraint() {
        let mut rule = allow_rule();
        rule.secret_names = SecretNameMatch {
            patterns: vec!["JWT".into(), "GH_*".into()],
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        // Request with JWT — allowed.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(decision.allowed);
    }

    #[test]
    fn policy_denies_unlisted_secret() {
        let mut rule = allow_rule();
        rule.secret_names = SecretNameMatch {
            patterns: vec!["ONLY_THIS".into()],
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        // Request has "JWT" which doesn't match "ONLY_THIS".
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
        assert!(
            decision
                .denial_reason
                .as_ref()
                .unwrap()
                .contains("default deny")
        );
    }

    #[test]
    fn secret_name_match_empty_refs_fails_closed() {
        // P0-3: When patterns are specified but secret_ref_names is empty,
        // matches() must return false (fail-closed).
        let matcher = SecretNameMatch {
            patterns: vec!["CI_*".into()],
        };
        assert!(!matcher.matches(&[]));
    }

    #[test]
    fn secret_name_match_empty_patterns_matches_anything() {
        // Empty patterns means "no constraint" — should match any refs.
        let matcher = SecretNameMatch { patterns: vec![] };
        assert!(matcher.matches(&[]));
        assert!(matcher.matches(&["FOO".into()]));
    }

    #[test]
    fn secret_name_match_populated_refs_still_works() {
        let matcher = SecretNameMatch {
            patterns: vec!["CI_*".into()],
        };
        assert!(matcher.matches(&["CI_TOKEN".into()]));
        assert!(!matcher.matches(&["DB_PASSWORD".into()]));
    }

    #[test]
    fn policy_denies_empty_secret_refs_when_rule_has_patterns() {
        // P0-3: A policy rule with secret_names patterns should reject
        // requests that don't declare any secret refs.
        let mut rule = allow_rule();
        rule.secret_names = SecretNameMatch {
            patterns: vec!["CI_*".into()],
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.secret_ref_names = vec![]; // Empty — should fail closed.
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(!decision.allowed);
    }

    // -- Workspace verification fail-closed tests (P1 security fix) --

    fn test_workspace_verified() -> WorkspaceContext {
        // A workspace context with workspace_verified = true (daemon confirmed git state).
        WorkspaceContext {
            repo_root: "/home/user/project".into(),
            remote_url: Some("git@github.com:org/repo.git".into()),
            branch: Some("main".into()),
            head_sha: Some("abc123".into()),
            dirty: false,
            workspace_verified: true,
        }
    }

    fn test_workspace_unverified() -> WorkspaceContext {
        // A workspace context where verification could not be completed.
        WorkspaceContext {
            repo_root: "/home/user/project".into(),
            remote_url: Some("git@github.com:org/repo.git".into()),
            branch: Some("main".into()),
            head_sha: Some("abc123".into()),
            dirty: false,
            workspace_verified: false,
        }
    }

    #[test]
    fn workspace_match_unverified_with_constraints_denied() {
        // When a workspace rule has constraints (remote_url_pattern), an unverified
        // workspace must NOT match — fail closed.
        let wm = WorkspaceMatch {
            remote_url_pattern: Some("*github.com:org/*".into()),
            ..Default::default()
        };
        let ws = test_workspace_unverified();
        assert!(!wm.matches(Some(&ws)));
    }

    #[test]
    fn workspace_match_unverified_without_constraints_passes() {
        // When a workspace rule has NO constraints, verification status is irrelevant.
        let wm = WorkspaceMatch::default();
        let ws = test_workspace_unverified();
        assert!(wm.matches(Some(&ws)));
    }

    #[test]
    fn workspace_match_verified_matching_remote_allowed() {
        let wm = WorkspaceMatch {
            remote_url_pattern: Some("*github.com:org/*".into()),
            ..Default::default()
        };
        let ws = test_workspace_verified();
        assert!(wm.matches(Some(&ws)));
    }

    #[test]
    fn workspace_match_verified_nonmatching_remote_denied() {
        let wm = WorkspaceMatch {
            remote_url_pattern: Some("*gitlab.com:other/*".into()),
            ..Default::default()
        };
        let ws = test_workspace_verified();
        assert!(!wm.matches(Some(&ws)));
    }

    #[test]
    fn workspace_match_unverified_with_branch_constraint_denied() {
        let wm = WorkspaceMatch {
            branch_pattern: Some("main".into()),
            ..Default::default()
        };
        let ws = test_workspace_unverified();
        assert!(!wm.matches(Some(&ws)));
    }

    #[test]
    fn workspace_match_unverified_with_require_clean_denied() {
        let wm = WorkspaceMatch {
            require_clean: true,
            ..Default::default()
        };
        let ws = test_workspace_unverified();
        assert!(!wm.matches(Some(&ws)));
    }

    #[test]
    fn policy_workspace_constraint_unverified_denied() {
        // End-to-end: a policy rule with workspace constraints should deny
        // a request that has an unverified workspace, even if all other
        // fields match.
        let mut rule = allow_rule();
        rule.workspace = WorkspaceMatch {
            remote_url_pattern: Some("*github.com:org/*".into()),
            branch_pattern: Some("main".into()),
            require_clean: false,
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.workspace = Some(test_workspace_unverified());
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(
            !decision.allowed,
            "unverified workspace must be denied when constraints exist"
        );
    }

    #[test]
    fn policy_workspace_constraint_verified_allowed() {
        // End-to-end: verified workspace with matching constraints -> allowed.
        let mut rule = allow_rule();
        rule.workspace = WorkspaceMatch {
            remote_url_pattern: Some("*github.com:org/*".into()),
            branch_pattern: Some("main".into()),
            require_clean: false,
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.workspace = Some(test_workspace_verified());
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(
            decision.allowed,
            "verified matching workspace must be allowed"
        );
    }

    #[test]
    fn policy_no_workspace_constraints_ignores_verification() {
        // When a rule has NO workspace constraints, verification status
        // is irrelevant — backward compatible.
        let rule = allow_rule(); // default WorkspaceMatch (no constraints)
        let engine = PolicyEngine::with_rules(vec![rule]);

        // Unverified workspace still passes because rule has no constraints.
        let mut req = test_request("github.set_actions_secret", ClientType::Agent);
        req.workspace = Some(test_workspace_unverified());
        let decision = engine.evaluate(&req, OperationSafety::Safe);
        assert!(
            decision.allowed,
            "no workspace constraints => verification irrelevant"
        );

        // No workspace at all also passes.
        let req2 = test_request("github.set_actions_secret", ClientType::Agent);
        let decision2 = engine.evaluate(&req2, OperationSafety::Safe);
        assert!(
            decision2.allowed,
            "no workspace constraints => None workspace ok"
        );
    }

    // -- identity match (Phase 1) ------------------------------------------

    use crate::identity::{AccessMode, PrincipalContext, PrincipalId, PrincipalKind, Role};
    use std::collections::BTreeSet;

    fn test_principal_ctx(mode: AccessMode, roles: &[Role]) -> PrincipalContext {
        let sub = match mode {
            AccessMode::Autonomous => {
                PrincipalId::generate(&PrincipalKind::Service { name: "ci".into() })
            }
            _ => PrincipalId::generate(&PrincipalKind::Human {
                iss: "https://idp.example.com".into(),
                sub: "u1".into(),
                email: Some("dev@example.com".into()),
                name: None,
            }),
        };
        PrincipalContext {
            sub,
            sub_label: "dev@example.com".into(),
            sub_roles: roles.iter().copied().collect::<BTreeSet<_>>(),
            sub_teams: vec![],
            act: PrincipalId::generate(&PrincipalKind::Agent {
                tool: "claude-code".into(),
            }),
            act_label: "agent:claude-code".into(),
            mode,
            jti: "sess-1".into(),
            human_session_id: Some("hses_x".into()),
        }
    }

    #[test]
    fn identity_match_empty_matches_anything() {
        let m = IdentityMatch::default();
        assert!(m.matches(None));
        assert!(m.matches(Some(&test_principal_ctx(
            AccessMode::Delegated,
            &[Role::Operator]
        ))));
    }

    #[test]
    fn identity_constrained_rule_fails_closed_without_principal() {
        let m = IdentityMatch {
            require_principal: Some(true),
            ..Default::default()
        };
        assert!(!m.matches(None));
        assert!(m.matches(Some(&test_principal_ctx(AccessMode::Delegated, &[]))));

        // Any other constraint also demands a context.
        let m2 = IdentityMatch {
            roles: Some(vec!["operator".into()]),
            ..Default::default()
        };
        assert!(!m2.matches(None));
    }

    #[test]
    fn identity_roles_require_all_and_unknown_fails_closed() {
        let ctx = test_principal_ctx(AccessMode::Delegated, &[Role::Operator, Role::Approver]);
        let ok = IdentityMatch {
            roles: Some(vec!["operator".into(), "approver".into()]),
            ..Default::default()
        };
        assert!(ok.matches(Some(&ctx)));

        let missing = IdentityMatch {
            roles: Some(vec!["operator".into(), "admin".into()]),
            ..Default::default()
        };
        assert!(!missing.matches(Some(&ctx)));

        let unknown = IdentityMatch {
            roles: Some(vec!["root".into()]),
            ..Default::default()
        };
        assert!(!unknown.matches(Some(&ctx)));
    }

    #[test]
    fn identity_principal_matches_id_or_label() {
        let ctx = test_principal_ctx(AccessMode::Delegated, &[Role::Operator]);
        let by_id = IdentityMatch {
            principal: Some(ctx.sub.as_str().to_string()),
            ..Default::default()
        };
        assert!(by_id.matches(Some(&ctx)));

        let by_label = IdentityMatch {
            principal: Some("DEV@example.com".into()),
            ..Default::default()
        };
        assert!(by_label.matches(Some(&ctx)));

        let wrong = IdentityMatch {
            principal: Some("other@example.com".into()),
            ..Default::default()
        };
        assert!(!wrong.matches(Some(&ctx)));
    }

    #[test]
    fn identity_teams_any_of_and_fail_closed() {
        let m = IdentityMatch {
            teams: Some(vec!["platform".into(), "ml-infra".into()]),
            ..Default::default()
        };

        // No principal at all: fail closed.
        assert!(!m.matches(None));

        // Principal with no teams (no bundle applied): fail closed.
        let ctx = test_principal_ctx(AccessMode::Delegated, &[Role::Operator]);
        assert!(!m.matches(Some(&ctx)));

        // Member of one listed team (ANY-of): match, case-insensitively.
        let mut ctx_team = ctx.clone();
        ctx_team.sub_teams = vec!["Platform".into()];
        assert!(m.matches(Some(&ctx_team)));

        // Member of only unlisted teams: no match.
        let mut ctx_other = ctx.clone();
        ctx_other.sub_teams = vec!["frontend".into()];
        assert!(!m.matches(Some(&ctx_other)));

        // An EMPTY rule team list can never match (misconfiguration fails
        // closed rather than waving everyone through).
        let empty = IdentityMatch {
            teams: Some(vec![]),
            ..Default::default()
        };
        assert!(!empty.matches(Some(&ctx_team)));
    }

    #[test]
    fn identity_access_mode_filter() {
        let delegated = test_principal_ctx(AccessMode::Delegated, &[Role::Operator]);
        let autonomous = test_principal_ctx(AccessMode::Autonomous, &[Role::Operator]);
        let m = IdentityMatch {
            access_modes: Some(vec![AccessMode::Delegated]),
            ..Default::default()
        };
        assert!(m.matches(Some(&delegated)));
        assert!(!m.matches(Some(&autonomous)));
    }

    #[test]
    fn rule_with_identity_constraint_gates_requests() {
        let mut rule = allow_rule();
        rule.identity = IdentityMatch {
            roles: Some(vec!["operator".into()]),
            ..Default::default()
        };
        let engine = PolicyEngine::with_rules(vec![rule]);

        // No principal context: identity-constrained rule can't match →
        // default deny.
        let req = test_request("github.set_actions_secret", ClientType::Agent);
        assert!(!engine.evaluate(&req, OperationSafety::Safe).allowed);

        // Delegator holds the role → allowed.
        let mut req2 = test_request("github.set_actions_secret", ClientType::Agent);
        req2.principal = Some(test_principal_ctx(AccessMode::Delegated, &[Role::Operator]));
        assert!(engine.evaluate(&req2, OperationSafety::Safe).allowed);

        // Delegator lacks the role (agent ∩ human = ∅) → denied.
        let mut req3 = test_request("github.set_actions_secret", ClientType::Agent);
        req3.principal = Some(test_principal_ctx(AccessMode::Delegated, &[Role::Auditor]));
        assert!(!engine.evaluate(&req3, OperationSafety::Safe).allowed);
    }

    #[test]
    fn identity_match_toml_roundtrip_and_back_compat() {
        // Existing policy TOML without an identity block still parses.
        let toml = r#"
            name = "legacy"
            operation_pattern = "github.*"
        "#;
        let rule: PolicyRule = toml_edit::de::from_str(toml).unwrap();
        assert!(rule.identity.is_empty());

        // New identity block parses with typed access modes.
        let toml2 = r#"
            name = "identity-gated"
            operation_pattern = "github.*"
            [identity]
            require_principal = true
            roles = ["operator"]
            access_modes = ["delegated", "break_glass"]
        "#;
        let rule2: PolicyRule = toml_edit::de::from_str(toml2).unwrap();
        assert_eq!(rule2.identity.require_principal, Some(true));
        assert_eq!(
            rule2.identity.access_modes,
            Some(vec![AccessMode::Delegated, AccessMode::BreakGlass])
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod known_key_tests {
    use super::*;
    use std::collections::BTreeSet;

    fn keys(value: &impl Serialize) -> BTreeSet<String> {
        serde_json::to_value(value)
            .unwrap()
            .as_object()
            .expect("struct serializes to an object")
            .keys()
            .cloned()
            .collect()
    }

    fn listed(fields: &[&str]) -> BTreeSet<String> {
        fields.iter().map(|f| f.to_string()).collect()
    }

    /// Exhaustive struct literals: adding a field to any matcher is a
    /// compile error here until the FIELDS list that `opaque policy check`
    /// reads is updated too.
    #[test]
    fn field_lists_match_the_structs_they_describe() {
        let client = ClientMatch {
            uid: Some(501),
            exe_path: Some("/usr/bin/claude*".into()),
            exe_sha256: Some("deadbeef".into()),
            codesign_team_id: Some("TEAM".into()),
            attestor: Some(AttestorId::try_from("listener".to_string()).unwrap()),
            min_attestation: Some(AttestationStrength::Weak),
            selectors: vec![Selector::new("k8s", "ns", "default").unwrap()],
        };
        assert_eq!(keys(&client), listed(ClientMatch::FIELDS));

        let target = TargetMatch {
            fields: [("repo".to_string(), "org/*".to_string())]
                .into_iter()
                .collect(),
        };
        assert_eq!(keys(&target), listed(TargetMatch::FIELDS));

        let workspace = WorkspaceMatch {
            remote_url_pattern: Some("*github.com:org/*".into()),
            branch_pattern: Some("main".into()),
            require_clean: true,
        };
        assert_eq!(keys(&workspace), listed(WorkspaceMatch::FIELDS));

        let secret_names = SecretNameMatch {
            patterns: vec!["GH_*".into()],
        };
        assert_eq!(keys(&secret_names), listed(SecretNameMatch::FIELDS));

        let identity = IdentityMatch {
            require_principal: Some(true),
            principal: Some("hum_x".into()),
            roles: Some(vec!["admin".into()]),
            access_modes: Some(vec![AccessMode::Delegated]),
            teams: Some(vec!["platform".into()]),
        };
        assert_eq!(keys(&identity), listed(IdentityMatch::FIELDS));

        let approval = ApprovalConfig {
            require: ApprovalRequirement::FirstUse,
            factors: vec![ApprovalFactor::LocalBio],
            lease_ttl: Some(Duration::from_secs(300)),
            one_time: true,
            budget: Some(3),
            require_distinct_approver: true,
        };
        assert_eq!(keys(&approval), listed(ApprovalConfig::FIELDS));

        let rule = PolicyRule {
            name: "fixture".into(),
            client,
            operation_pattern: "github.*".into(),
            target,
            workspace,
            secret_names,
            allow: true,
            client_types: vec![ClientType::Agent],
            identity,
            approval,
        };
        assert_eq!(keys(&rule), listed(PolicyRule::FIELDS));
    }
}
