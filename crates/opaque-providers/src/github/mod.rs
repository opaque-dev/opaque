//! GitHub provider integration.
//!
//! Implements secret-setting operations across all GitHub secret scopes:
//! - `github.set_actions_secret` — repo-level and environment Actions secrets
//! - `github.set_codespaces_secret` — user-level and repo-level Codespaces secrets
//! - `github.set_dependabot_secret` — repo-level Dependabot secrets
//! - `github.set_org_secret` — org-level Actions secrets
//!
//! All scopes use the same NaCl sealed-box encryption. The handler dispatches
//! by operation name and delegates to a shared `set_secret_flow()` helper.

pub mod client;
pub mod crypto;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod prepared_tests;
pub mod release;
mod rpc;
mod task;
pub mod workflow;

pub use release::{
    dispatch_staging_release, plan_staging_release, prepare_staging_release,
    reconcile_staging_release,
};
pub use rpc::handle_github_rpc;
pub use task::{execute_task_action, plan_task_manifest, prepare_task_manifest};

#[cfg(test)]
static TEST_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

use std::fmt;
use std::sync::Arc;

use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink};
use opaque_core::operation::OperationRequest;

use opaque_core::profile::ALLOWED_REF_SCHEMES;

use crate::internal_resolve::CompositeResolver;
use opaque_core::operation_handler::{OperationHandler, PreparedOperation};
use opaque_core::resolver::SecretResolver;

use client::{GitHubClient, SecretScope};
use crypto::encrypt_secret;

/// Default keychain ref for the GitHub PAT when not specified by the caller.
/// Override with the `OPAQUE_GITHUB_TOKEN_REF` environment variable to use a
/// different keychain entry or ref scheme for the GitHub personal access token.
const DEFAULT_GITHUB_TOKEN_REF: &str = "keychain:opaque/github-pat";

/// Environment variable to override the default GitHub PAT ref.
const GITHUB_TOKEN_REF_ENV: &str = "OPAQUE_GITHUB_TOKEN_REF";

/// The GitHub secret handler.
///
/// Handles all GitHub secret-setting operations. A single `GitHubHandler` instance
/// is registered for each operation name; it dispatches by `request.operation`.
pub struct GitHubHandler {
    audit: Arc<dyn AuditSink>,
    client: GitHubClient,
}

impl fmt::Debug for GitHubHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubHandler").finish()
    }
}

impl GitHubHandler {
    pub fn new(audit: Arc<dyn AuditSink>) -> Result<Self, String> {
        Ok(Self {
            audit,
            client: GitHubClient::new().map_err(|e| e.to_string())?,
        })
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[allow(dead_code)]
    pub fn with_client(audit: Arc<dyn AuditSink>, client: GitHubClient) -> Self {
        Self { audit, client }
    }
}

/// Validate that a repo string is in `owner/repo` format.
fn validate_repo(repo: &str) -> Result<(&str, &str), String> {
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| "repo must be in 'owner/repo' format".to_string())?;

    if owner.is_empty() || name.is_empty() {
        return Err("repo owner and name must be non-empty".into());
    }

    // Reject additional slashes.
    if name.contains('/') {
        return Err("repo must be in 'owner/repo' format (no extra slashes)".into());
    }

    validate_org_name(owner)?;
    if name.len() > 100
        || matches!(name, "." | "..")
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err("repo name contains invalid path characters".into());
    }
    Ok((owner, name))
}

/// Validate that a secret name matches GitHub's requirements.
fn validate_secret_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("secret_name must be non-empty".into());
    }

    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("secret_name must contain only alphanumeric characters and underscores".into());
    }

    // GitHub requires names to not start with GITHUB_ or a digit.
    if name.starts_with("GITHUB_") {
        return Err("secret_name must not start with GITHUB_".into());
    }

    if name.starts_with(|c: char| c.is_ascii_digit()) {
        return Err("secret_name must not start with a digit".into());
    }

    Ok(())
}

/// Validate that a value_ref uses a known scheme.
fn validate_value_ref(ref_str: &str) -> Result<(), String> {
    if ALLOWED_REF_SCHEMES.iter().any(|p| ref_str.starts_with(p)) {
        Ok(())
    } else {
        Err(format!(
            "value_ref must start with a known scheme ({ALLOWED_REF_SCHEMES:?}), got: '{ref_str}'"
        ))
    }
}

/// Validate a GitHub environment name.
/// Must be 1-255 chars, alphanumeric / hyphens / underscores / dots.
fn validate_environment_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("environment name must be non-empty".into());
    }
    if matches!(name, "." | "..") {
        return Err("environment name must not be a path traversal segment".into());
    }
    if name.len() > 255 {
        return Err("environment name must be at most 255 characters".into());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(
            "environment name must contain only alphanumeric characters, hyphens, underscores, and dots".into(),
        );
    }
    Ok(())
}

/// Validate a GitHub organization name.
/// Must be 1-39 chars, alphanumeric / hyphens, cannot start/end with hyphen.
fn validate_org_name(org: &str) -> Result<(), String> {
    if org.is_empty() {
        return Err("org name must be non-empty".into());
    }
    if org.len() > 39 {
        return Err("org name must be at most 39 characters".into());
    }
    if !org.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("org name must contain only alphanumeric characters and hyphens".into());
    }
    if org.starts_with('-') || org.ends_with('-') {
        return Err("org name must not start or end with a hyphen".into());
    }
    Ok(())
}

/// Shared secret-setting flow used by all sub-handlers.
///
/// Steps: resolve secret → resolve token → audit → get public key → encrypt → PUT → audit.
/// Returns a sanitized JSON response. Never includes secret values or ciphertext.
#[allow(clippy::too_many_arguments)]
async fn set_secret_flow(
    client: &GitHubClient,
    audit: &Arc<dyn AuditSink>,
    request_id: uuid::Uuid,
    scope: &SecretScope<'_>,
    secret_name: &str,
    value_ref: &str,
    github_token_ref: &str,
    operation_name: &str,
    extra_body: Option<&serde_json::Value>,
) -> Result<serde_json::Value, String> {
    // 1. Resolve secret value and GitHub PAT.
    let resolver = CompositeResolver::new(crate::internal_resolve::default_secret_resolvers());

    let secret_value = resolver
        .resolve(value_ref)
        .map_err(|e| format!("failed to resolve value_ref: {e}"))?;
    secret_value.mlock();

    audit.emit(
        AuditEvent::new(AuditEventKind::SecretResolved)
            .with_request_id(request_id)
            .with_operation(operation_name)
            .with_outcome("resolved")
            .with_detail(format!(
                "ref_scheme={}",
                value_ref.split(':').next().unwrap_or("unknown")
            )),
    );

    let github_token = resolver
        .resolve(github_token_ref)
        .map_err(|e| format!("failed to resolve github_token_ref: {e}"))?;
    github_token.mlock();

    let github_token_str = github_token
        .as_str()
        .ok_or_else(|| "github token is not valid UTF-8".to_string())?;

    audit.emit(
        AuditEvent::new(AuditEventKind::SecretResolved)
            .with_request_id(request_id)
            .with_operation(operation_name)
            .with_outcome("resolved")
            .with_detail("ref_scheme=github_token"),
    );

    // 2. Fetch public key for the target scope.
    audit.emit(
        AuditEvent::new(AuditEventKind::ProviderFetchStarted)
            .with_request_id(request_id)
            .with_operation(operation_name)
            .with_detail(format!("endpoint=public_key {}", scope.display_target())),
    );

    let pk_resp = client
        .get_public_key_scoped(github_token_str, scope)
        .await
        .map_err(|e| format!("failed to get public key: {e}"))?;

    // 3. Encrypt the secret.
    let encrypted_value = encrypt_secret(secret_value.as_bytes(), &pk_resp.key)
        .map_err(|e| format!("encryption failed: {e}"))?;

    // 4. Set the secret via API.
    let set_result = client
        .set_secret_scoped(
            github_token_str,
            scope,
            secret_name,
            &encrypted_value,
            &pk_resp.key_id,
            extra_body,
        )
        .await
        .map_err(|e| format!("failed to set secret: {e}"))?;

    let status = match set_result {
        client::SetSecretResponse::Created => "created",
        client::SetSecretResponse::Updated => "updated",
    };

    audit.emit(
        AuditEvent::new(AuditEventKind::ProviderFetchFinished)
            .with_request_id(request_id)
            .with_operation(operation_name)
            .with_outcome(status)
            .with_detail(format!(
                "{} secret_name={secret_name}",
                scope.display_target()
            )),
    );

    // 5. Build sanitized response — NEVER the secret value or ciphertext.
    let mut resp = serde_json::json!({
        "status": status,
        "secret_name": secret_name,
    });

    match scope {
        SecretScope::RepoActions { owner, repo }
        | SecretScope::CodespacesRepo { owner, repo }
        | SecretScope::Dependabot { owner, repo } => {
            resp["repo"] = serde_json::Value::String(format!("{owner}/{repo}"));
        }
        SecretScope::EnvActions {
            owner,
            repo,
            environment,
        } => {
            resp["repo"] = serde_json::Value::String(format!("{owner}/{repo}"));
            resp["environment"] = serde_json::Value::String(environment.to_string());
        }
        SecretScope::CodespacesUser => {
            resp["scope"] = serde_json::Value::String("user".into());
        }
        SecretScope::OrgActions { org } => {
            resp["org"] = serde_json::Value::String(org.to_string());
        }
    }

    Ok(resp)
}

/// Token reference selection is frozen before policy or provider access.
fn resolve_github_token_ref(explicit: Option<String>) -> Result<String, String> {
    let reference = explicit
        .or_else(|| std::env::var(GITHUB_TOKEN_REF_ENV).ok())
        .unwrap_or_else(|| DEFAULT_GITHUB_TOKEN_REF.to_owned());
    validate_value_ref(&reference)?;
    Ok(reference)
}

fn parse_params<T: serde::de::DeserializeOwned>(params: &serde_json::Value) -> Result<T, String> {
    // Keep parse diagnostics bounded and never echo an untrusted parameter value.
    serde_json::from_value(params.clone()).map_err(|error| {
        let message = error.to_string();
        if let Some(field) = message
            .strip_prefix("missing field `")
            .and_then(|s| s.strip_suffix('`'))
        {
            format!("missing '{field}' parameter")
        } else {
            "invalid GitHub parameters (unexpected field or incorrect type)".to_owned()
        }
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionsInput {
    repo: String,
    secret_name: String,
    value_ref: String,
    environment: Option<String>,
    github_token_ref: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DependabotInput {
    repo: String,
    secret_name: String,
    value_ref: String,
    github_token_ref: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CodespacesInput {
    secret_name: String,
    value_ref: String,
    repo: Option<String>,
    selected_repository_ids: Option<Vec<i64>>,
    github_token_ref: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrgInput {
    org: String,
    secret_name: String,
    value_ref: String,
    visibility: Option<String>,
    selected_repository_ids: Option<Vec<i64>>,
    github_token_ref: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ListInput {
    scope: Option<String>,
    repo: Option<String>,
    org: Option<String>,
    environment: Option<String>,
    github_token_ref: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteInput {
    secret_name: String,
    scope: Option<String>,
    repo: Option<String>,
    org: Option<String>,
    environment: Option<String>,
    github_token_ref: Option<String>,
}

/// Only valid scope combinations can reach an execution closure.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PreparedScope {
    RepoActions {
        owner: String,
        repo: String,
    },
    EnvActions {
        owner: String,
        repo: String,
        environment: String,
    },
    CodespacesUser,
    CodespacesRepo {
        owner: String,
        repo: String,
    },
    Dependabot {
        owner: String,
        repo: String,
    },
    OrgActions {
        org: String,
    },
}

impl PreparedScope {
    fn borrowed(&self) -> SecretScope<'_> {
        match self {
            Self::RepoActions { owner, repo } => SecretScope::RepoActions { owner, repo },
            Self::EnvActions {
                owner,
                repo,
                environment,
            } => SecretScope::EnvActions {
                owner,
                repo,
                environment,
            },
            Self::CodespacesUser => SecretScope::CodespacesUser,
            Self::CodespacesRepo { owner, repo } => SecretScope::CodespacesRepo { owner, repo },
            Self::Dependabot { owner, repo } => SecretScope::Dependabot { owner, repo },
            Self::OrgActions { org } => SecretScope::OrgActions { org },
        }
    }

    fn target(&self) -> std::collections::HashMap<String, String> {
        let (scope, scope_kind) = match self {
            Self::RepoActions { .. } => ("actions", "repository"),
            Self::EnvActions { .. } => ("actions", "environment"),
            Self::CodespacesUser => ("codespaces", "user"),
            Self::CodespacesRepo { .. } => ("codespaces", "repository"),
            Self::Dependabot { .. } => ("dependabot", "repository"),
            Self::OrgActions { .. } => ("org", "organization"),
        };
        let mut target = std::collections::HashMap::from([
            ("scope".into(), scope.into()),
            ("scope_kind".into(), scope_kind.into()),
        ]);
        match self {
            Self::RepoActions { owner, repo }
            | Self::CodespacesRepo { owner, repo }
            | Self::Dependabot { owner, repo } => {
                target.insert("repo".into(), format!("{owner}/{repo}"));
            }
            Self::EnvActions {
                owner,
                repo,
                environment,
            } => {
                target.insert("repo".into(), format!("{owner}/{repo}"));
                target.insert("environment".into(), environment.clone());
            }
            Self::OrgActions { org } => {
                target.insert("org".into(), org.clone());
            }
            Self::CodespacesUser => {}
        }
        target
    }
}

fn prepare_scope(
    scope: Option<String>,
    repo: Option<String>,
    org: Option<String>,
    environment: Option<String>,
) -> Result<PreparedScope, String> {
    let scope = scope.as_deref().unwrap_or("actions");
    if (scope != "org" && org.is_some())
        || (scope == "org" && repo.is_some())
        || (scope != "actions" && environment.is_some())
    {
        return Err("competing or irrelevant GitHub scope parameters".into());
    }
    if scope == "org" {
        let org = org.ok_or("missing 'org' parameter")?;
        validate_org_name(&org)?;
        return Ok(PreparedScope::OrgActions { org });
    }
    if !matches!(scope, "actions" | "codespaces" | "dependabot") {
        return Err(
            "unknown scope: expected 'actions', 'codespaces', 'dependabot', or 'org'".into(),
        );
    }
    if scope == "codespaces" && repo.is_none() {
        return Ok(PreparedScope::CodespacesUser);
    }
    let repo = repo.ok_or("missing 'repo' parameter")?;
    let (owner, repo) = validate_repo(&repo)?;
    let (owner, repo) = (owner.to_owned(), repo.to_owned());
    match scope {
        "actions" => match environment {
            Some(environment) => {
                validate_environment_name(&environment)?;
                Ok(PreparedScope::EnvActions {
                    owner,
                    repo,
                    environment,
                })
            }
            None => Ok(PreparedScope::RepoActions { owner, repo }),
        },
        "codespaces" => Ok(PreparedScope::CodespacesRepo { owner, repo }),
        "dependabot" => Ok(PreparedScope::Dependabot { owner, repo }),
        _ => unreachable!("validated scope"),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn parse_scope(params: &serde_json::Value) -> Result<PreparedScope, String> {
    let input: ListInput = parse_params(params)?;
    prepare_scope(input.scope, input.repo, input.org, input.environment)
}

#[derive(serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SecretEffect {
    Set {
        secret_name: String,
        value_ref: String,
        audience: Option<SecretAudience>,
    },
    List,
    Delete {
        secret_name: String,
    },
}

#[derive(serde::Serialize)]
struct SecretAudience {
    #[serde(skip_serializing_if = "Option::is_none")]
    visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_repository_ids: Option<Vec<i64>>,
}

#[derive(serde::Serialize)]
struct GitHubAction {
    github_api_url: String,
    scope: PreparedScope,
    github_token_ref: String,
    effect: SecretEffect,
}

fn prepare_audience(
    visibility: Option<String>,
    ids: Option<Vec<i64>>,
) -> Result<SecretAudience, String> {
    if visibility
        .as_deref()
        .is_some_and(|v| !matches!(v, "all" | "private" | "selected"))
    {
        return Err("visibility must be 'all', 'private', or 'selected'".into());
    }
    if visibility.as_deref().is_some_and(|v| v != "selected") && ids.is_some() {
        return Err("selected_repository_ids requires selected visibility".into());
    }
    if visibility.as_deref() == Some("selected") && ids.is_none() {
        return Err("selected visibility requires explicit selected_repository_ids".into());
    }
    let mut ids = ids;
    if let Some(ids) = &mut ids {
        if ids.iter().any(|id| *id <= 0) {
            return Err("selected_repository_ids must contain positive integer IDs".into());
        }
        // GitHub treats this audience as a set. Execution consumes the same ordering.
        ids.sort_unstable();
        ids.dedup();
    }
    Ok(SecretAudience {
        visibility,
        selected_repository_ids: ids,
    })
}

impl OperationHandler for GitHubHandler {
    fn prepare<'a>(&'a self, request: &OperationRequest) -> Result<PreparedOperation<'a>, String> {
        let (scope, token_ref, effect) = match request.operation.as_str() {
            "github.set_actions_secret" => {
                let input: ActionsInput = parse_params(&request.params)?;
                (
                    prepare_scope(None, Some(input.repo), None, input.environment)?,
                    input.github_token_ref,
                    SecretEffect::Set {
                        secret_name: input.secret_name,
                        value_ref: input.value_ref,
                        audience: None,
                    },
                )
            }
            "github.set_dependabot_secret" => {
                let input: DependabotInput = parse_params(&request.params)?;
                (
                    prepare_scope(Some("dependabot".into()), Some(input.repo), None, None)?,
                    input.github_token_ref,
                    SecretEffect::Set {
                        secret_name: input.secret_name,
                        value_ref: input.value_ref,
                        audience: None,
                    },
                )
            }
            "github.set_codespaces_secret" => {
                let input: CodespacesInput = parse_params(&request.params)?;
                if input.repo.is_some() && input.selected_repository_ids.is_some() {
                    return Err(
                        "selected_repository_ids is only valid for user Codespaces secrets".into(),
                    );
                }
                let audience = if input.repo.is_none() {
                    Some(prepare_audience(None, input.selected_repository_ids)?)
                } else {
                    None
                };
                (
                    prepare_scope(Some("codespaces".into()), input.repo, None, None)?,
                    input.github_token_ref,
                    SecretEffect::Set {
                        secret_name: input.secret_name,
                        value_ref: input.value_ref,
                        audience,
                    },
                )
            }
            "github.set_org_secret" => {
                let input: OrgInput = parse_params(&request.params)?;
                let audience = prepare_audience(
                    Some(input.visibility.unwrap_or_else(|| "private".into())),
                    input.selected_repository_ids,
                )?;
                (
                    prepare_scope(Some("org".into()), None, Some(input.org), None)?,
                    input.github_token_ref,
                    SecretEffect::Set {
                        secret_name: input.secret_name,
                        value_ref: input.value_ref,
                        audience: Some(audience),
                    },
                )
            }
            "github.list_secrets" => {
                let input: ListInput = parse_params(&request.params)?;
                (
                    prepare_scope(input.scope, input.repo, input.org, input.environment)?,
                    input.github_token_ref,
                    SecretEffect::List,
                )
            }
            "github.delete_secret" => {
                let input: DeleteInput = parse_params(&request.params)?;
                (
                    prepare_scope(input.scope, input.repo, input.org, input.environment)?,
                    input.github_token_ref,
                    SecretEffect::Delete {
                        secret_name: input.secret_name,
                    },
                )
            }
            other => return Err(format!("unknown GitHub operation: {other}")),
        };
        let mut target = scope.target();
        target.insert("github_api_url".into(), self.client.base_url().to_owned());
        let github_token_ref = resolve_github_token_ref(token_ref)?;
        let mut refs = vec![github_token_ref.clone()];
        match &effect {
            SecretEffect::Set {
                secret_name,
                value_ref,
                audience,
            } => {
                validate_secret_name(secret_name)?;
                validate_value_ref(value_ref)?;
                target.insert("secret_name".into(), secret_name.clone());
                refs.push(value_ref.clone());
                if let Some(audience) = audience {
                    if let Some(visibility) = &audience.visibility {
                        target.insert("visibility".into(), visibility.clone());
                    }
                    if let Some(ids) = &audience.selected_repository_ids {
                        target.insert(
                            "selected_repository_ids".into(),
                            serde_json::to_string(ids).map_err(|_| "invalid audience")?,
                        );
                    } else if audience.visibility.is_none() {
                        // Omitted user Codespaces audience retains the API's
                        // existing/default behavior; do not revoke it by inventing [].
                        target.insert(
                            "selected_repository_ids".into(),
                            "preserve_or_provider_default".into(),
                        );
                    }
                }
            }
            SecretEffect::Delete { secret_name } => {
                validate_secret_name(secret_name)?;
                target.insert("secret_name".into(), secret_name.clone());
            }
            SecretEffect::List => {}
        }
        let action = GitHubAction {
            github_api_url: self.client.base_url().to_owned(),
            scope,
            github_token_ref,
            effect,
        };
        let request_id = request.request_id;
        let operation = request.operation.clone();
        PreparedOperation::new(action, target, refs, move |action| async move {
            self.execute_prepared(request_id, &operation, action).await
        })
    }
}

impl GitHubHandler {
    async fn execute_prepared(
        &self,
        request_id: uuid::Uuid,
        operation: &str,
        action: GitHubAction,
    ) -> Result<serde_json::Value, String> {
        let scope = action.scope.borrowed();
        if let SecretEffect::Set {
            secret_name,
            value_ref,
            audience,
        } = &action.effect
        {
            let extra = audience
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| "invalid audience")?;
            return set_secret_flow(
                &self.client,
                &self.audit,
                request_id,
                &scope,
                secret_name,
                value_ref,
                &action.github_token_ref,
                operation,
                extra.as_ref(),
            )
            .await;
        }
        let resolver = CompositeResolver::new(crate::internal_resolve::default_secret_resolvers());
        let token = resolver
            .resolve(&action.github_token_ref)
            .map_err(|e| format!("failed to resolve github_token_ref: {e}"))?;
        token.mlock();
        let token = token.as_str().ok_or("github token is not valid UTF-8")?;
        self.audit.emit(
            AuditEvent::new(AuditEventKind::ProviderFetchStarted)
                .with_request_id(request_id)
                .with_operation(operation)
                .with_detail(scope.display_target()),
        );
        let (result, outcome) = match &action.effect {
            SecretEffect::List => {
                let response = self
                    .client
                    .list_secrets_scoped(token, &scope)
                    .await
                    .map_err(|e| format!("failed to list secrets: {e}"))?;
                let secrets: Vec<_> = response.secrets.into_iter().map(|secret| serde_json::json!({
                    "name": secret.name, "created_at": secret.created_at, "updated_at": secret.updated_at,
                })).collect();
                (
                    serde_json::json!({"total_count": response.total_count, "secrets": secrets}),
                    "ok",
                )
            }
            SecretEffect::Delete { secret_name } => {
                self.client
                    .delete_secret_scoped(token, &scope, secret_name)
                    .await
                    .map_err(|e| format!("failed to delete secret: {e}"))?;
                let mut response =
                    serde_json::json!({"status": "deleted", "secret_name": secret_name});
                for (key, value) in action.scope.target() {
                    if matches!(key.as_str(), "repo" | "org" | "environment") {
                        response[key] = value.into();
                    }
                }
                if matches!(scope, SecretScope::CodespacesUser) {
                    response["scope"] = "user".into();
                }
                (response, "deleted")
            }
            SecretEffect::Set { .. } => unreachable!("set completed before token-only flow"),
        };
        self.audit.emit(
            AuditEvent::new(AuditEventKind::ProviderFetchFinished)
                .with_request_id(request_id)
                .with_operation(operation)
                .with_outcome(outcome)
                .with_detail(scope.display_target()),
        );
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn validate_repo_valid() {
        let (owner, name) = validate_repo("myorg/myrepo").unwrap();
        assert_eq!(owner, "myorg");
        assert_eq!(name, "myrepo");
    }

    #[test]
    fn validate_repo_no_slash() {
        assert!(validate_repo("noslash").is_err());
    }

    #[test]
    fn validate_repo_empty_parts() {
        assert!(validate_repo("/repo").is_err());
        assert!(validate_repo("owner/").is_err());
    }

    #[test]
    fn validate_repo_extra_slashes() {
        assert!(validate_repo("owner/repo/extra").is_err());
    }

    #[test]
    fn validate_secret_name_valid() {
        assert!(validate_secret_name("MY_SECRET").is_ok());
        assert!(validate_secret_name("AWS_ACCESS_KEY_ID").is_ok());
        assert!(validate_secret_name("token").is_ok());
    }

    #[test]
    fn validate_secret_name_empty() {
        assert!(validate_secret_name("").is_err());
    }

    #[test]
    fn validate_secret_name_invalid_chars() {
        assert!(validate_secret_name("my-secret").is_err());
        assert!(validate_secret_name("my.secret").is_err());
        assert!(validate_secret_name("my secret").is_err());
    }

    #[test]
    fn validate_secret_name_github_prefix() {
        assert!(validate_secret_name("GITHUB_TOKEN").is_err());
    }

    #[test]
    fn validate_secret_name_digit_prefix() {
        assert!(validate_secret_name("1SECRET").is_err());
    }

    #[test]
    fn validate_value_ref_valid() {
        assert!(validate_value_ref("env:MY_VAR").is_ok());
        assert!(validate_value_ref("keychain:opaque/my-token").is_ok());
        assert!(validate_value_ref("profile:prod:AWS_KEY").is_ok());
    }

    #[test]
    fn validate_value_ref_invalid() {
        assert!(validate_value_ref("literal:foo").is_err());
        assert!(validate_value_ref("raw-value").is_err());
        assert!(validate_value_ref("").is_err());
    }

    // -----------------------------------------------------------------------
    // Environment name validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_environment_name_valid() {
        assert!(validate_environment_name("production").is_ok());
        assert!(validate_environment_name("staging-1").is_ok());
        assert!(validate_environment_name("test_env.v2").is_ok());
    }

    #[test]
    fn validate_environment_name_empty() {
        assert!(validate_environment_name("").is_err());
    }

    #[test]
    fn validate_environment_name_too_long() {
        let long = "a".repeat(256);
        assert!(validate_environment_name(&long).is_err());
        // 255 chars should be fine.
        let max = "a".repeat(255);
        assert!(validate_environment_name(&max).is_ok());
    }

    #[test]
    fn validate_environment_name_invalid_chars() {
        assert!(validate_environment_name("prod env").is_err());
        assert!(validate_environment_name("prod/env").is_err());
        assert!(validate_environment_name("prod@env").is_err());
    }

    // -----------------------------------------------------------------------
    // Org name validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_org_name_valid() {
        assert!(validate_org_name("myorg").is_ok());
        assert!(validate_org_name("my-org").is_ok());
        assert!(validate_org_name("org123").is_ok());
    }

    #[test]
    fn validate_org_name_empty() {
        assert!(validate_org_name("").is_err());
    }

    #[test]
    fn validate_org_name_too_long() {
        let long = "a".repeat(40);
        assert!(validate_org_name(&long).is_err());
        let max = "a".repeat(39);
        assert!(validate_org_name(&max).is_ok());
    }

    #[test]
    fn validate_org_name_invalid_chars() {
        assert!(validate_org_name("my_org").is_err());
        assert!(validate_org_name("my.org").is_err());
        assert!(validate_org_name("my org").is_err());
    }

    #[test]
    fn validate_org_name_leading_trailing_hyphen() {
        assert!(validate_org_name("-org").is_err());
        assert!(validate_org_name("org-").is_err());
    }

    // -----------------------------------------------------------------------
    // Handler tests
    // -----------------------------------------------------------------------

    #[test]
    fn github_handler_debug() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.blocking_lock();
        let handler = GitHubHandler::new(audit).unwrap();
        let debug = format!("{handler:?}");
        assert!(debug.contains("GitHubHandler"));
    }

    fn make_request(operation: &str, params: serde_json::Value) -> OperationRequest {
        use opaque_core::operation::{ClientIdentity, ClientType};
        OperationRequest {
            principal: None,
            request_id: uuid::Uuid::new_v4(),
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
            operation: operation.into(),
            target: std::collections::HashMap::new(),
            secret_ref_names: vec![],
            created_at: std::time::SystemTime::now(),
            expires_at: None,
            params,
            workspace: None,
        }
    }

    // --- Actions secret tests ---

    #[tokio::test]
    async fn missing_repo_param_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request("github.set_actions_secret", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'repo'"));
    }

    #[tokio::test]
    async fn missing_secret_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.set_actions_secret",
            serde_json::json!({"repo": "owner/repo"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_name'"));
    }

    #[tokio::test]
    async fn raw_value_ref_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.set_actions_secret",
            serde_json::json!({
                "repo": "owner/repo",
                "secret_name": "MY_SECRET",
                "value_ref": "raw-value-not-a-ref"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("known scheme"));
    }

    #[tokio::test]
    async fn invalid_repo_format_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.set_actions_secret",
            serde_json::json!({
                "repo": "noslash",
                "secret_name": "MY_SECRET",
                "value_ref": "env:MY_VAR"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("owner/repo"));
    }

    #[tokio::test]
    async fn invalid_environment_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.set_actions_secret",
            serde_json::json!({
                "repo": "owner/repo",
                "secret_name": "MY_SECRET",
                "value_ref": "env:MY_VAR",
                "environment": "invalid env!"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("environment name"));
    }

    // --- Codespaces secret tests ---

    #[tokio::test]
    async fn codespaces_missing_secret_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request("github.set_codespaces_secret", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_name'"));
    }

    #[tokio::test]
    async fn codespaces_missing_value_ref_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.set_codespaces_secret",
            serde_json::json!({"secret_name": "MY_SECRET"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'value_ref'"));
    }

    // --- Dependabot secret tests ---

    #[tokio::test]
    async fn dependabot_missing_repo_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.set_dependabot_secret",
            serde_json::json!({
                "secret_name": "NPM_TOKEN",
                "value_ref": "env:NPM_TOKEN"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'repo'"));
    }

    // --- Org secret tests ---

    #[tokio::test]
    async fn org_secret_missing_org_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.set_org_secret",
            serde_json::json!({
                "secret_name": "ORG_TOKEN",
                "value_ref": "env:TOKEN"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'org'"));
    }

    #[tokio::test]
    async fn org_secret_invalid_org_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.set_org_secret",
            serde_json::json!({
                "org": "-bad-org-",
                "secret_name": "MY_SECRET",
                "value_ref": "env:TOKEN"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("org name"));
    }

    #[tokio::test]
    async fn org_secret_invalid_visibility_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.set_org_secret",
            serde_json::json!({
                "org": "myorg",
                "secret_name": "MY_SECRET",
                "value_ref": "env:TOKEN",
                "visibility": "invalid"
            }),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("visibility"));
    }

    // --- Unknown operation test ---

    #[tokio::test]
    async fn unknown_operation_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request("github.unknown_op", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown GitHub operation"));
    }

    // --- parse_scope tests ---

    #[test]
    fn parse_scope_default_actions() {
        let params = serde_json::json!({"repo": "owner/repo"});
        let prepared_scope = parse_scope(&params).unwrap();
        let scope = prepared_scope.borrowed();
        assert_eq!(
            scope,
            SecretScope::RepoActions {
                owner: "owner",
                repo: "repo"
            }
        );
    }

    #[test]
    fn parse_scope_actions_with_environment() {
        let params = serde_json::json!({"repo": "owner/repo", "environment": "production"});
        let prepared_scope = parse_scope(&params).unwrap();
        let scope = prepared_scope.borrowed();
        assert_eq!(
            scope,
            SecretScope::EnvActions {
                owner: "owner",
                repo: "repo",
                environment: "production"
            }
        );
    }

    #[test]
    fn parse_scope_codespaces_user() {
        let params = serde_json::json!({"scope": "codespaces"});
        let prepared_scope = parse_scope(&params).unwrap();
        let scope = prepared_scope.borrowed();
        assert_eq!(scope, SecretScope::CodespacesUser);
    }

    #[test]
    fn parse_scope_codespaces_repo() {
        let params = serde_json::json!({"scope": "codespaces", "repo": "owner/repo"});
        let prepared_scope = parse_scope(&params).unwrap();
        let scope = prepared_scope.borrowed();
        assert_eq!(
            scope,
            SecretScope::CodespacesRepo {
                owner: "owner",
                repo: "repo"
            }
        );
    }

    #[test]
    fn parse_scope_dependabot() {
        let params = serde_json::json!({"scope": "dependabot", "repo": "owner/repo"});
        let prepared_scope = parse_scope(&params).unwrap();
        let scope = prepared_scope.borrowed();
        assert_eq!(
            scope,
            SecretScope::Dependabot {
                owner: "owner",
                repo: "repo"
            }
        );
    }

    #[test]
    fn parse_scope_dependabot_missing_repo() {
        let params = serde_json::json!({"scope": "dependabot"});
        assert!(parse_scope(&params).is_err());
    }

    #[test]
    fn parse_scope_org() {
        let params = serde_json::json!({"scope": "org", "org": "myorg"});
        let prepared_scope = parse_scope(&params).unwrap();
        let scope = prepared_scope.borrowed();
        assert_eq!(scope, SecretScope::OrgActions { org: "myorg" });
    }

    #[test]
    fn parse_scope_org_missing_org() {
        let params = serde_json::json!({"scope": "org"});
        assert!(parse_scope(&params).is_err());
    }

    #[test]
    fn parse_scope_unknown() {
        let params = serde_json::json!({"scope": "invalid"});
        assert!(parse_scope(&params).is_err());
    }

    // --- list_secrets handler tests ---

    #[tokio::test]
    async fn list_secrets_missing_repo_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request("github.list_secrets", serde_json::json!({}));
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'repo'"));
    }

    #[tokio::test]
    async fn list_secrets_invalid_scope_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.list_secrets",
            serde_json::json!({"scope": "invalid"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown scope"));
    }

    // --- delete_secret handler tests ---

    #[tokio::test]
    async fn delete_secret_missing_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.delete_secret",
            serde_json::json!({"repo": "owner/repo"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'secret_name'"));
    }

    #[tokio::test]
    async fn delete_secret_invalid_name_rejected() {
        use opaque_core::audit::InMemoryAuditEmitter;
        let audit = Arc::new(InMemoryAuditEmitter::new());
        let _environment = TEST_ENV_LOCK.lock().await;
        let handler = GitHubHandler::new(audit).unwrap();
        let request = make_request(
            "github.delete_secret",
            serde_json::json!({"repo": "owner/repo", "secret_name": "GITHUB_TOKEN"}),
        );
        let result = handler.execute(&request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("GITHUB_"));
    }
}
