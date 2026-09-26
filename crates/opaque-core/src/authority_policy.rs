//! Offline deployment policy, never a grant or a source of authenticated identity.
//! Canonical identity and bounds must be pinned in trusted broker configuration.
mod parse;
mod schema;
pub use schema::json_schema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

pub const API_VERSION: &str = "policy.opaque.dev/v1alpha1";
pub const KIND: &str = "AuthorityPolicy";
pub const MAX_BYTES: usize = 64 * 1024;
pub const OPERATION: &str = "support.case.setStatus";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityPolicy {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: Spec,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    pub namespace: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Spec {
    pub tenant_ref: String,
    pub connector_ref: String,
    pub authority: Authority,
    pub approval: Approval,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub evaluators: Vec<serde_json::Value>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    #[default]
    Enforce,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authority {
    pub operation: String,
    pub allowed_statuses: Vec<Status>,
    pub max_resources: u32,
    pub max_attempts: u64,
    pub max_duration: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Closed,
    Open,
    Resolved,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Approval {
    pub scope: ScopeApproval,
    #[serde(default)]
    pub action: ActionApproval,
    pub reviewer_ref: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeApproval {
    Required,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionApproval {
    #[default]
    EveryAction,
    WithinApprovedScope,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Identity {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub tenant_ref: String,
    pub connector_ref: String,
    pub reviewer_ref: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledPolicy {
    pub schema_version: u32,
    pub digest: String,
    pub identity: Identity,
    pub policy: AuthorityPolicy,
}

/// Parse once with explicit structural limits before typed deserialization.
/// YAML aliases, anchors, explicit tags, duplicate keys and multiple documents
/// are rejected, including JSON objects with duplicate keys.
pub fn compile(bytes: &[u8]) -> Result<CompiledPolicy, String> {
    let value = parse::document(bytes)?;
    let policy: AuthorityPolicy = serde_json::from_value(value).map_err(
        |_| "invalid AuthorityPolicy shape, field or enum value (Shadow is unsupported)",
    )?;
    policy.compile()
}
pub fn read(path: &Path) -> Result<CompiledPolicy, String> {
    compile(&read_bounded(path, MAX_BYTES)?)
}
/// O_NONBLOCK ensures a FIFO cannot stall an offline command or broker startup.
/// Symlinks are supported for immutable Kubernetes projected volumes; content
/// identity, not the symlink path, is pinned by the broker.
pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot open policy input")?;
    if !file
        .metadata()
        .map_err(|_| "cannot inspect policy input")?
        .is_file()
    {
        return Err("policy input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read policy input")?;
    if bytes.len() > limit {
        return Err("policy input exceeds byte limit".into());
    }
    Ok(bytes)
}
impl AuthorityPolicy {
    pub fn compile(mut self) -> Result<CompiledPolicy, String> {
        if self.api_version != API_VERSION || self.kind != KIND {
            return Err("unsupported AuthorityPolicy version or kind".into());
        }
        for value in [
            &self.metadata.name,
            &self.metadata.namespace,
            &self.spec.tenant_ref,
            &self.spec.connector_ref,
            &self.spec.approval.reviewer_ref,
        ] {
            reference(value)?;
        }
        if self.spec.authority.operation != OPERATION || !self.spec.evaluators.is_empty() {
            return Err("unsupported operation or evaluator requirement".into());
        }
        let a = &mut self.spec.authority;
        if !(1..=100).contains(&a.max_resources)
            || !(1..=10000).contains(&a.max_attempts)
            || a.allowed_statuses.is_empty()
            || a.allowed_statuses.len() > 3
        {
            return Err("authority bounds exceed supported limits".into());
        }
        a.allowed_statuses.sort();
        if a.allowed_statuses.windows(2).any(|w| w[0] == w[1]) {
            return Err("duplicate allowed status".into());
        }
        a.max_duration = format!("{}s", duration_seconds(&a.max_duration)?);
        let identity = Identity {
            api_version: self.api_version.clone(),
            kind: self.kind.clone(),
            name: self.metadata.name.clone(),
            namespace: self.metadata.namespace.clone(),
            tenant_ref: self.spec.tenant_ref.clone(),
            connector_ref: self.spec.connector_ref.clone(),
            reviewer_ref: self.spec.approval.reviewer_ref.clone(),
        };
        let mut hash = Sha256::new();
        hash.update(b"opaque.authority-policy.v1\0");
        let mut canonical = serde_json::to_value(&self).map_err(|_| "policy encoding failed")?;
        canonical.sort_all_objects();
        hash.update(serde_json::to_vec(&canonical).map_err(|_| "policy encoding failed")?);
        Ok(CompiledPolicy {
            schema_version: 1,
            digest: format!("{:x}", hash.finalize()),
            identity,
            policy: self,
        })
    }
}
pub fn duration_seconds(value: &str) -> Result<i64, String> {
    let error = || "maxDuration must be a positive whole s/m/h duration up to 24h".to_owned();
    if value.len() < 2 || value.len() > 8 {
        return Err(error());
    }
    let (number, multiplier) = if let Some(n) = value.strip_suffix('s') {
        (n, 1)
    } else if let Some(n) = value.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = value.strip_suffix('h') {
        (n, 3600)
    } else {
        return Err(error());
    };
    if !number.bytes().all(|b| b.is_ascii_digit()) || number.starts_with('0') {
        return Err(error());
    }
    let seconds = number
        .parse::<i64>()
        .map_err(|_| error())?
        .checked_mul(multiplier)
        .ok_or_else(error)?;
    if !(1..=86400).contains(&seconds) {
        return Err(error());
    }
    Ok(seconds)
}
fn reference(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
    {
        return Err("policy names and references must be DNS labels of at most 63 bytes".into());
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
