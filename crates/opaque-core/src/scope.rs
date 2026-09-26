//! Versioned finite authority contracts for trusted hosts.
//!
//! These types do not authenticate a caller, verify an approval signature, or
//! authorize an existing task/MCP operation. A host must verify current identity,
//! policy, issuance and review receipts at the execution boundary. No natural
//! language, evaluator confidence, or analytics projection grants permission.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const VERSION: u16 = 1;
pub const MAX_RESOURCES: usize = 4096;
pub const MAX_DEPTH: u8 = 8;
const MAX_FIELDS: usize = 32;
const MAX_VALUES: usize = 64;
const MAX_CHECKS: usize = 32;
const MAX_BYTES: usize = 512 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("unsupported scope contract version")]
    Version,
    #[error("invalid or unbounded scope contract")]
    Invalid,
    #[error("child expands or changes its parent's authority")]
    NotSubset,
    #[error("action is outside its scope")]
    OutOfScope,
    #[error("missing, stale, or mismatched authorization evidence")]
    Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityOwner {
    pub tenant_id: String,
    pub broker_id: String,
    pub generation: String,
}

impl AuthorityOwner {
    pub fn validate(&self) -> Result<(), ScopeError> {
        id(&self.tenant_id)?;
        id(&self.broker_id)?;
        id(&self.generation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldConstraint {
    pub field: String,
    pub allowed_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldValue {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinimumApproval {
    /// Only an explicitly qualified contract may use issuance as its minimum.
    ScopeIssuance,
    ExactAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorRequirement {
    pub check_id: String,
    pub contract_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRequirements {
    pub policy_digest: String,
    pub minimum_approval: MinimumApproval,
    pub evaluator_checks: Vec<EvaluatorRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeGrant {
    pub schema_version: u16,
    pub scope_id: String,
    pub root_id: String,
    pub parent_id: Option<String>,
    pub owner: AuthorityOwner,
    pub issuer: String,
    pub subject: String,
    pub operation: String,
    pub provider_profile_digest: String,
    pub resources: Vec<String>,
    pub fields: Vec<FieldConstraint>,
    pub not_before: i64,
    pub expires_at: i64,
    pub delegations_remaining: u8,
    pub max_charged_attempts: u64,
    pub max_distinct_resources: u32,
    pub requirements: ScopeRequirements,
    pub issuance_receipt_digest: String,
}

impl ScopeGrant {
    pub fn canonicalized(&self) -> Result<Self, ScopeError> {
        version(self.schema_version)?;
        self.owner.validate()?;
        for value in [
            &self.scope_id,
            &self.root_id,
            &self.issuer,
            &self.subject,
            &self.operation,
        ] {
            id(value)?;
        }
        if let Some(parent) = &self.parent_id {
            id(parent)?;
            if parent == &self.scope_id || self.root_id == self.scope_id {
                return Err(ScopeError::Invalid);
            }
        } else if self.root_id != self.scope_id {
            return Err(ScopeError::Invalid);
        }
        digest(&self.provider_profile_digest)?;
        digest(&self.issuance_receipt_digest)?;
        digest(&self.requirements.policy_digest)?;
        if self.not_before < 0
            || self.expires_at <= self.not_before
            || self.delegations_remaining > MAX_DEPTH
            || self.max_charged_attempts == 0
            || self.max_charged_attempts > i64::MAX as u64
            || self.max_distinct_resources == 0
            || self.resources.is_empty()
            || self.resources.len() > MAX_RESOURCES
            || self.max_distinct_resources as usize > self.resources.len()
            || self.fields.is_empty()
            || self.fields.len() > MAX_FIELDS
            || self.requirements.evaluator_checks.len() > MAX_CHECKS
        {
            return Err(ScopeError::Invalid);
        }
        let mut result = self.clone();
        for resource in &result.resources {
            id(resource)?;
        }
        result.resources.sort();
        unique(result.resources.iter().map(String::as_str))?;
        for field in &mut result.fields {
            id(&field.field)?;
            if field.allowed_values.is_empty() || field.allowed_values.len() > MAX_VALUES {
                return Err(ScopeError::Invalid);
            }
            for value in &field.allowed_values {
                bounded_value(value)?;
            }
            field.allowed_values.sort();
            unique(field.allowed_values.iter().map(String::as_str))?;
        }
        result.fields.sort_by(|a, b| a.field.cmp(&b.field));
        unique(result.fields.iter().map(|f| f.field.as_str()))?;
        for check in &result.requirements.evaluator_checks {
            id(&check.check_id)?;
            digest(&check.contract_digest)?;
        }
        result
            .requirements
            .evaluator_checks
            .sort_by(|a, b| a.check_id.cmp(&b.check_id));
        unique(
            result
                .requirements
                .evaluator_checks
                .iter()
                .map(|c| c.check_id.as_str()),
        )?;
        encoded(&result)?;
        Ok(result)
    }

    pub fn digest(&self) -> Result<String, ScopeError> {
        hash("opaque.scope.grant.v1", &self.canonicalized()?)
    }

    pub fn validate_child_of(&self, parent: &Self) -> Result<(), ScopeError> {
        let child = self.canonicalized()?;
        let parent = parent.canonicalized()?;
        let subset = child.parent_id.as_deref() == Some(parent.scope_id.as_str())
            && child.root_id == parent.root_id
            && child.owner == parent.owner
            && child.issuer == parent.subject
            && child.operation == parent.operation
            && child.provider_profile_digest == parent.provider_profile_digest
            && child.not_before >= parent.not_before
            && child.expires_at <= parent.expires_at
            && parent.delegations_remaining > 0
            && child.delegations_remaining < parent.delegations_remaining
            && child.max_charged_attempts <= parent.max_charged_attempts
            && child.max_distinct_resources <= parent.max_distinct_resources
            && child.requirements.policy_digest == parent.requirements.policy_digest
            && !(parent.requirements.minimum_approval == MinimumApproval::ExactAction
                && child.requirements.minimum_approval != MinimumApproval::ExactAction)
            && child
                .resources
                .iter()
                .all(|r| parent.resources.binary_search(r).is_ok())
            && child.fields.iter().all(|field| {
                parent.fields.iter().any(|p| {
                    p.field == field.field
                        && field
                            .allowed_values
                            .iter()
                            .all(|v| p.allowed_values.binary_search(v).is_ok())
                })
            })
            && parent
                .requirements
                .evaluator_checks
                .iter()
                .all(|c| child.requirements.evaluator_checks.contains(c));
        if subset {
            Ok(())
        } else {
            Err(ScopeError::NotSubset)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedAction {
    pub schema_version: u16,
    pub action_id: String,
    pub request_id: String,
    pub scope_id: String,
    pub scope_digest: String,
    pub owner: AuthorityOwner,
    pub subject: String,
    pub operation: String,
    pub provider_profile_digest: String,
    pub resource: String,
    pub resource_version: String,
    pub fields: Vec<FieldValue>,
    pub evidence_digest: String,
}

impl PreparedAction {
    pub fn canonicalized(&self) -> Result<Self, ScopeError> {
        version(self.schema_version)?;
        self.owner.validate()?;
        for value in [
            &self.action_id,
            &self.request_id,
            &self.scope_id,
            &self.subject,
            &self.operation,
            &self.resource,
        ] {
            id(value)?;
        }
        bounded_value(&self.resource_version)?;
        if self.resource_version.is_empty()
            || self.fields.is_empty()
            || self.fields.len() > MAX_FIELDS
        {
            return Err(ScopeError::Invalid);
        }
        for value in [
            &self.scope_digest,
            &self.provider_profile_digest,
            &self.evidence_digest,
        ] {
            digest(value)?;
        }
        let mut result = self.clone();
        for field in &result.fields {
            id(&field.field)?;
            bounded_value(&field.value)?;
        }
        result.fields.sort_by(|a, b| a.field.cmp(&b.field));
        unique(result.fields.iter().map(|f| f.field.as_str()))?;
        encoded(&result)?;
        Ok(result)
    }

    pub fn digest(&self) -> Result<String, ScopeError> {
        hash("opaque.scope.action.v1", &self.canonicalized()?)
    }

    pub fn validate_for(&self, scope: &ScopeGrant) -> Result<(), ScopeError> {
        let action = self.canonicalized()?;
        let scope = scope.canonicalized()?;
        if action.scope_id != scope.scope_id
            || action.scope_digest != scope.digest()?
            || action.owner != scope.owner
            || action.subject != scope.subject
            || action.operation != scope.operation
            || action.provider_profile_digest != scope.provider_profile_digest
            || scope.resources.binary_search(&action.resource).is_err()
            || !action.fields.iter().all(|f| {
                scope
                    .fields
                    .iter()
                    .any(|s| s.field == f.field && s.allowed_values.binary_search(&f.value).is_ok())
            })
        {
            return Err(ScopeError::OutOfScope);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewBinding {
    pub schema_version: u16,
    pub case_id: String,
    pub case_revision: u64,
    pub action_id: String,
    pub action_digest: String,
    pub scope_digest: String,
    pub evidence_digest: String,
    pub policy_digest: String,
    pub round_id: String,
    pub decision_receipt_digest: String,
    pub expires_at: i64,
}

impl ReviewBinding {
    pub fn validate(&self) -> Result<(), ScopeError> {
        version(self.schema_version)?;
        for value in [&self.case_id, &self.action_id, &self.round_id] {
            id(value)?;
        }
        for value in [
            &self.action_digest,
            &self.scope_digest,
            &self.evidence_digest,
            &self.policy_digest,
            &self.decision_receipt_digest,
        ] {
            digest(value)?;
        }
        if self.case_revision == 0 || self.expires_at <= 0 {
            return Err(ScopeError::Invalid);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ScopeError> {
        self.validate()?;
        hash("opaque.scope.review-binding.v1", self)
    }
}

/// A host-verified receipt reference, never an evaluator-supplied permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorReceipt {
    pub check_id: String,
    pub contract_digest: String,
    pub receipt_digest: String,
    pub action_digest: String,
    pub evidence_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionEvidence {
    pub schema_version: u16,
    pub policy_digest: String,
    pub scope_digest: String,
    pub action_digest: String,
    pub authority_revision: u64,
    pub evaluated_at: i64,
    pub expires_at: i64,
    pub review: Option<ReviewBinding>,
    pub evaluators: Vec<EvaluatorReceipt>,
}

impl AdmissionEvidence {
    pub fn validate_for(
        &self,
        scope: &ScopeGrant,
        action: &PreparedAction,
        now: i64,
    ) -> Result<(), ScopeError> {
        version(self.schema_version)?;
        action.validate_for(scope)?;
        if self.policy_digest != scope.requirements.policy_digest
            || self.scope_digest != scope.digest()?
            || self.action_digest != action.digest()?
            || self.authority_revision == 0
            || self.evaluated_at < 0
            || self.evaluated_at > now
            || self.expires_at <= now
            || self.expires_at > scope.expires_at
            || self.evaluators.len() > MAX_CHECKS
        {
            return Err(ScopeError::Evidence);
        }
        if let Some(review) = &self.review {
            review.validate()?;
            if review.action_id != action.action_id
                || review.action_digest != self.action_digest
                || review.scope_digest != self.scope_digest
                || review.evidence_digest != action.evidence_digest
                || review.policy_digest != self.policy_digest
                || review.expires_at <= now
                || review.expires_at > scope.expires_at
            {
                return Err(ScopeError::Evidence);
            }
        } else if scope.requirements.minimum_approval == MinimumApproval::ExactAction {
            return Err(ScopeError::Evidence);
        }
        unique(self.evaluators.iter().map(|e| e.check_id.as_str()))?;
        for receipt in &self.evaluators {
            id(&receipt.check_id)?;
            digest(&receipt.contract_digest)?;
            digest(&receipt.receipt_digest)?;
            if receipt.action_digest != self.action_digest
                || receipt.evidence_digest != action.evidence_digest
            {
                return Err(ScopeError::Evidence);
            }
        }
        if !scope.requirements.evaluator_checks.iter().all(|check| {
            self.evaluators
                .iter()
                .any(|e| e.check_id == check.check_id && e.contract_digest == check.contract_digest)
        }) {
            return Err(ScopeError::Evidence);
        }
        Ok(())
    }
}

fn version(value: u16) -> Result<(), ScopeError> {
    if value == VERSION {
        Ok(())
    } else {
        Err(ScopeError::Version)
    }
}
fn id(value: &str) -> Result<(), ScopeError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-/".contains(&b))
    {
        Err(ScopeError::Invalid)
    } else {
        Ok(())
    }
}
fn bounded_value(value: &str) -> Result<(), ScopeError> {
    if value.len() > 1024 || value.chars().any(char::is_control) {
        Err(ScopeError::Invalid)
    } else {
        Ok(())
    }
}
fn digest(value: &str) -> Result<(), ScopeError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Err(ScopeError::Invalid)
    } else {
        Ok(())
    }
}
fn unique<'a>(values: impl Iterator<Item = &'a str>) -> Result<(), ScopeError> {
    let mut seen = BTreeSet::new();
    if values.into_iter().all(|value| seen.insert(value)) {
        Ok(())
    } else {
        Err(ScopeError::Invalid)
    }
}
fn encoded(value: &impl Serialize) -> Result<Vec<u8>, ScopeError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ScopeError::Invalid)?;
    if bytes.len() > MAX_BYTES {
        Err(ScopeError::Invalid)
    } else {
        Ok(bytes)
    }
}
fn hash(domain: &str, value: &impl Serialize) -> Result<String, ScopeError> {
    let mut hash = Sha256::new();
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(encoded(value)?);
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
