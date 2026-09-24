//! Offline commands: no IPC, config writes, seals, approval, grants or ledger I/O.
use clap::Subcommand;
use opaque_core::authority_policy::{self as policy, *};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
#[derive(Debug, Subcommand)]
pub enum Action {
    /// Validate YAML/JSON and print its canonical digest and bound identity.
    Validate { file: PathBuf },
    /// Print canonical policy JSON and digest; this creates no authority.
    Compile { file: PathBuf },
    /// Print the portable strict JSON Schema.
    Schema,
    /// Convert existing scope_workflow TOML to manifest JSON on stdout only.
    Migrate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        tenant_ref: String,
        #[arg(long)]
        connector_ref: String,
        #[arg(long)]
        reviewer_ref: String,
    },
}
pub fn run(action: &Action) -> Result<Value, String> {
    match action {
        Action::Validate { file } => {
            let compiled = policy::read(file)?;
            Ok(
                json!({"schemaVersion":1,"valid":true,"digest":compiled.digest,"identity":compiled.identity}),
            )
        }
        Action::Compile { file } => {
            serde_json::to_value(policy::read(file)?).map_err(|_| "policy encoding failed".into())
        }
        Action::Schema => Ok(policy::json_schema()),
        Action::Migrate {
            config,
            name,
            namespace,
            tenant_ref,
            connector_ref,
            reviewer_ref,
        } => {
            let bytes = policy::read_bounded(config, 1024 * 1024)?;
            let text = std::str::from_utf8(&bytes).map_err(|_| "config must be UTF-8")?;
            let config: Value = toml_edit::de::from_str(text).map_err(|_| "invalid config TOML")?;
            if config.get("authority_policy").is_some() {
                return Err("migration refuses an existing authority_policy binding".into());
            }
            let legacy: Legacy = serde_json::from_value(
                config
                    .get("scope_workflow")
                    .ok_or("scope_workflow configuration missing")?
                    .clone(),
            )
            .map_err(|_| "invalid or unsupported scope_workflow configuration")?;
            legacy.check()?;
            let manifest = AuthorityPolicy {
                api_version: API_VERSION.into(),
                kind: KIND.into(),
                metadata: Metadata {
                    name: name.clone(),
                    namespace: namespace.clone(),
                },
                spec: Spec {
                    tenant_ref: tenant_ref.clone(),
                    connector_ref: connector_ref.clone(),
                    mode: Mode::Enforce,
                    evaluators: vec![],
                    authority: Authority {
                        operation: OPERATION.into(),
                        allowed_statuses: legacy.allowed_statuses,
                        max_resources: legacy.max_resources,
                        max_attempts: legacy.max_attempts,
                        max_duration: format!("{}s", legacy.max_scope_seconds),
                    },
                    approval: Approval {
                        scope: ScopeApproval::Required,
                        action: if legacy.exact_action {
                            ActionApproval::EveryAction
                        } else {
                            ActionApproval::WithinApprovedScope
                        },
                        reviewer_ref: reviewer_ref.clone(),
                    },
                },
            }
            .compile()?;
            serde_json::to_value(manifest.policy).map_err(|_| "policy encoding failed".into())
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Legacy {
    profile: LegacyProfile,
    reviewer_id: String,
    reviewer_public_key: String,
    #[serde(default = "generation")]
    generation: u64,
    #[serde(default = "duration")]
    max_scope_seconds: i64,
    #[serde(default = "attempts")]
    max_attempts: u64,
    #[serde(default = "resources")]
    max_resources: u32,
    #[serde(default = "yes")]
    exact_action: bool,
    allowed_statuses: Vec<Status>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProfile {
    endpoint: String,
    token_file: PathBuf,
    #[serde(default)]
    ca_certificate_file: Option<PathBuf>,
}
fn generation() -> u64 {
    1
}
fn duration() -> i64 {
    3600
}
fn attempts() -> u64 {
    100
}
fn resources() -> u32 {
    100
}
fn yes() -> bool {
    true
}
impl Legacy {
    fn check(&self) -> Result<(), String> {
        if self.generation == 0
            || self.profile.endpoint.is_empty()
            || !self.profile.token_file.is_absolute()
            || self
                .profile
                .ca_certificate_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || !opaque_core::identity::PrincipalId::parse(&self.reviewer_id)
                .is_ok_and(|p| p.is_human())
            || self.reviewer_public_key.len() != 64
            || !self
                .reviewer_public_key
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(
                "legacy local connector/reviewer/generation configuration is invalid".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
