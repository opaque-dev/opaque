//! Versioned scope-issuance and exact-action review protocol.
//!
//! Broker signatures authenticate the review source against an independently
//! enrolled broker key. Reviewer signatures prove key possession and bind the
//! complete review; they do not remotely prove a human-presence ceremony.
//! Historical receipts do not establish current authority or remaining budget.

use crate::scope::{AuthorityOwner, FieldValue, PreparedAction, ScopeGrant};
use crate::workstation::{decode_hex, hex, verify_signature};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERSION: u16 = 1;
pub const MAX_REVIEW_BYTES: usize = 120 * 1024;
/// Leave room for the pending-list wrapper inside the workstation's 256 KiB cap.
pub const MAX_SIGNED_REVIEW_BYTES: usize = 250 * 1024;
pub const MAX_RECEIPT_BYTES: usize = 256 * 1024;
pub const MAX_ROUND_SECONDS: i64 = 300;
pub const EMPTY_RECEIPT_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReviewError {
    #[error("invalid or unsupported scope review contract")]
    Invalid,
    #[error("review deadline expired or not yet valid")]
    Expired,
    #[error("scope review signature or independently enrolled key mismatch")]
    Signature,
    #[error("scope review authority or exact subject changed")]
    Binding,
}
pub type Result<T> = std::result::Result<T, ReviewError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAuthority {
    pub owner: AuthorityOwner,
    pub requester_id: String,
    pub reviewer_id: String,
    pub device_id: String,
    pub reviewer_public_key: String,
    pub required_role: String,
    pub policy_digest: String,
    pub authority_epoch: u64,
    pub enrollment_epoch: u64,
}

impl ReviewAuthority {
    pub fn validate(&self) -> Result<()> {
        self.owner.validate().map_err(|_| ReviewError::Invalid)?;
        for value in [
            &self.requester_id,
            &self.reviewer_id,
            &self.device_id,
            &self.required_role,
        ] {
            identifier(value)?;
        }
        digest(&self.reviewer_public_key)?;
        digest(&self.policy_digest)?;
        ed25519_dalek::VerifyingKey::from_bytes(
            &decode_hex::<32>(&self.reviewer_public_key).map_err(|_| ReviewError::Invalid)?,
        )
        .map_err(|_| ReviewError::Invalid)?;
        if self.requester_id == self.reviewer_id
            || self.authority_epoch == 0
            || self.enrollment_epoch == 0
        {
            return Err(ReviewError::Binding);
        }
        Ok(())
    }
}

/// Typed provider state acquired by the trusted host. The signature authenticates
/// what the host presented, not the independent truth of a provider's response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvidence {
    pub provider_profile_digest: String,
    pub resource: String,
    pub resource_version: String,
    pub fields: Vec<FieldValue>,
}

impl ReviewEvidence {
    pub fn canonicalized(&self) -> Result<Self> {
        digest(&self.provider_profile_digest)?;
        identifier(&self.resource)?;
        if self.resource_version.is_empty()
            || self.resource_version.len() > 1024
            || self.resource_version.chars().any(char::is_control)
            || self.fields.is_empty()
            || self.fields.len() > 32
        {
            return Err(ReviewError::Invalid);
        }
        for field in &self.fields {
            identifier(&field.field)?;
            if field.value.len() > 1024 || field.value.chars().any(char::is_control) {
                return Err(ReviewError::Invalid);
            }
        }
        let mut result = self.clone();
        result.fields.sort_by(|a, b| a.field.cmp(&b.field));
        if result
            .fields
            .windows(2)
            .any(|pair| pair[0].field == pair[1].field)
        {
            return Err(ReviewError::Invalid);
        }
        Ok(result)
    }

    pub fn digest(&self) -> Result<String> {
        hash("opaque.scope.review-evidence.v1", &self.canonicalized()?)
    }

    fn validate_for(&self, action: &PreparedAction) -> Result<()> {
        if self.canonicalized()? != *self
            || self.provider_profile_digest != action.provider_profile_digest
            || self.resource != action.resource
            || self.resource_version != action.resource_version
            || self.digest()? != action.evidence_digest
        {
            return Err(ReviewError::Binding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewSubject {
    /// A canonical draft with the receipt field set to EMPTY_RECEIPT_DIGEST.
    ScopeIssuance { draft: ScopeGrant },
    ExactAction {
        scope: ScopeGrant,
        action: Box<PreparedAction>,
        case_id: String,
        case_revision: u64,
        #[serde(default)]
        evidence: Option<ReviewEvidence>,
    },
}

impl ReviewSubject {
    pub fn issuance(scope: &ScopeGrant) -> Result<Self> {
        let mut draft = scope.canonicalized().map_err(|_| ReviewError::Invalid)?;
        draft.issuance_receipt_digest = EMPTY_RECEIPT_DIGEST.into();
        Ok(Self::ScopeIssuance { draft })
    }

    pub fn exact_action(
        scope: &ScopeGrant,
        action: &PreparedAction,
        case_id: String,
        case_revision: u64,
    ) -> Result<Self> {
        let scope = scope.canonicalized().map_err(|_| ReviewError::Invalid)?;
        let action = action.canonicalized().map_err(|_| ReviewError::Invalid)?;
        action
            .validate_for(&scope)
            .map_err(|_| ReviewError::Binding)?;
        identifier(&case_id)?;
        if case_revision == 0 {
            return Err(ReviewError::Invalid);
        }
        Ok(Self::ExactAction {
            scope,
            action: Box::new(action),
            case_id,
            case_revision,
            evidence: None,
        })
    }

    pub fn exact_action_with_evidence(
        scope: &ScopeGrant,
        action: &PreparedAction,
        case_id: String,
        case_revision: u64,
        evidence: ReviewEvidence,
    ) -> Result<Self> {
        let evidence = evidence.canonicalized()?;
        evidence.validate_for(action)?;
        let mut subject = Self::exact_action(scope, action, case_id, case_revision)?;
        if let Self::ExactAction {
            evidence: target, ..
        } = &mut subject
        {
            *target = Some(evidence);
        }
        Ok(subject)
    }

    pub fn validate_for(&self, authority: &ReviewAuthority) -> Result<()> {
        authority.validate()?;
        match self {
            Self::ScopeIssuance { draft } => {
                if draft.issuance_receipt_digest != EMPTY_RECEIPT_DIGEST
                    || &draft.canonicalized().map_err(|_| ReviewError::Invalid)? != draft
                    || draft.owner != authority.owner
                    || draft.issuer != authority.requester_id
                    || draft.requirements.policy_digest != authority.policy_digest
                {
                    return Err(ReviewError::Binding);
                }
            }
            Self::ExactAction {
                scope,
                action,
                case_id,
                case_revision,
                evidence,
            } => {
                identifier(case_id)?;
                if *case_revision == 0
                    || &scope.canonicalized().map_err(|_| ReviewError::Invalid)? != scope
                    || &action.canonicalized().map_err(|_| ReviewError::Invalid)? != action.as_ref()
                    || scope.owner != authority.owner
                    || action.subject != authority.requester_id
                    || scope.requirements.policy_digest != authority.policy_digest
                {
                    return Err(ReviewError::Binding);
                }
                action
                    .validate_for(scope)
                    .map_err(|_| ReviewError::Binding)?;
                if let Some(evidence) = evidence {
                    evidence.validate_for(action)?;
                }
            }
        }
        Ok(())
    }

    pub fn scope(&self) -> &ScopeGrant {
        match self {
            Self::ScopeIssuance { draft } => draft,
            Self::ExactAction { scope, .. } => scope,
        }
    }
}

/// Commitment to canonical grant content excluding ONLY issuance_receipt_digest.
/// The signed issuance receipt is subsequently put into that excluded field and
/// the ordinary ScopeGrant::digest then binds the complete finalized grant.
pub fn issuance_commitment(scope: &ScopeGrant) -> Result<String> {
    let canonical = scope.canonicalized().map_err(|_| ReviewError::Invalid)?;
    let mut value = serde_json::to_value(canonical).map_err(|_| ReviewError::Invalid)?;
    value
        .as_object_mut()
        .ok_or(ReviewError::Invalid)?
        .remove("issuance_receipt_digest");
    hash("opaque.scope.unsigned-issuance.v1", &value)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewDocument {
    pub schema_version: u16,
    pub round_id: String,
    pub nonce: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub authority: ReviewAuthority,
    pub subject: ReviewSubject,
    /// Complete deterministic text, regenerated and compared by verification.
    pub review_text: String,
}

impl ReviewDocument {
    pub fn new(
        round_id: String,
        nonce: String,
        created_at: i64,
        expires_at: i64,
        authority: ReviewAuthority,
        subject: ReviewSubject,
    ) -> Result<Self> {
        let mut document = Self {
            schema_version: VERSION,
            round_id,
            nonce,
            created_at,
            expires_at,
            authority,
            subject,
            review_text: String::new(),
        };
        document.review_text = document.render()?;
        document.validate_at(created_at)?;
        Ok(document)
    }

    fn render(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Display<'a> {
            protocol: &'static str,
            round_id: &'a str,
            nonce: &'a str,
            created_at: i64,
            expires_at: i64,
            authority: &'a ReviewAuthority,
            subject: &'a ReviewSubject,
            issuance_commitment: Option<String>,
        }
        let commitment = match &self.subject {
            ReviewSubject::ScopeIssuance { draft } => Some(issuance_commitment(draft)?),
            _ => None,
        };
        let value = Display {
            protocol: "opaque.scope.review.v1",
            round_id: &self.round_id,
            nonce: &self.nonce,
            created_at: self.created_at,
            expires_at: self.expires_at,
            authority: &self.authority,
            subject: &self.subject,
            issuance_commitment: commitment,
        };
        let text = serde_json::to_string_pretty(&value).map_err(|_| ReviewError::Invalid)?;
        if text.len() > MAX_REVIEW_BYTES || text.chars().any(|c| {
            (c.is_control() && c != '\n' && c != '\t')
                || matches!(c as u32, 0x061c | 0x200e..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069)
        }) {
            return Err(ReviewError::Invalid);
        }
        Ok(text)
    }

    pub fn validate_at(&self, now: i64) -> Result<()> {
        if self.schema_version != VERSION
            || uuid::Uuid::parse_str(&self.round_id).is_err()
            || digest(&self.nonce).is_err()
            || self.created_at < 0
            || self
                .expires_at
                .checked_sub(self.created_at)
                .is_none_or(|ttl| !(1..=MAX_ROUND_SECONDS).contains(&ttl))
        {
            return Err(ReviewError::Invalid);
        }
        self.subject.validate_for(&self.authority)?;
        if self.expires_at > self.subject.scope().expires_at {
            return Err(ReviewError::Binding);
        }
        if self.review_text.len() > MAX_REVIEW_BYTES || self.review_text != self.render()? {
            return Err(ReviewError::Binding);
        }
        if now < self.created_at || now >= self.expires_at {
            return Err(ReviewError::Expired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReview {
    pub schema_version: u16,
    pub document: ReviewDocument,
    pub broker_public_key: String,
    pub signature: String,
}

impl SignedReview {
    pub fn sign(document: ReviewDocument, key: &SigningKey) -> Result<Self> {
        document.validate_at(document.created_at)?;
        let signature = hex(&key
            .sign(&bytes("opaque.scope.broker-review.v1", &document)?)
            .to_bytes());
        let result = Self {
            schema_version: VERSION,
            document,
            broker_public_key: hex(key.verifying_key().as_bytes()),
            signature,
        };
        bounded_wire(&result, MAX_SIGNED_REVIEW_BYTES)?;
        Ok(result)
    }
    /// expected_broker_key MUST come from independent trusted enrollment.
    pub fn verify(&self, expected_broker_key: &str, now: i64) -> Result<()> {
        bounded_wire(self, MAX_SIGNED_REVIEW_BYTES)?;
        if self.schema_version != VERSION || self.broker_public_key != expected_broker_key {
            return Err(ReviewError::Signature);
        }
        self.document.validate_at(now)?;
        verify_signature(
            expected_broker_key,
            &self.signature,
            &bytes("opaque.scope.broker-review.v1", &self.document)?,
        )
        .map_err(|_| ReviewError::Signature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Reject,
}

pub fn decision_bytes(document: &ReviewDocument, decision: Decision) -> Result<Vec<u8>> {
    document.validate_at(document.created_at)?;
    bytes("opaque.scope.reviewer-decision.v1", &(document, decision))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewerDecision {
    pub schema_version: u16,
    pub round_id: String,
    pub reviewer_id: String,
    pub device_id: String,
    pub decision: Decision,
    pub signature: String,
}

impl ReviewerDecision {
    /// Call only after the trusted full-review/authentication ceremony succeeds.
    /// This function does not itself implement that human-presence ceremony.
    pub fn sign(
        review: &SignedReview,
        expected_broker_key: &str,
        key: &SigningKey,
        decision: Decision,
        now: i64,
    ) -> Result<Self> {
        review.verify(expected_broker_key, now)?;
        let authority = &review.document.authority;
        if authority.reviewer_public_key != hex(key.verifying_key().as_bytes()) {
            return Err(ReviewError::Binding);
        }
        Ok(Self {
            schema_version: VERSION,
            round_id: review.document.round_id.clone(),
            reviewer_id: authority.reviewer_id.clone(),
            device_id: authority.device_id.clone(),
            decision,
            signature: hex(&key
                .sign(&decision_bytes(&review.document, decision)?)
                .to_bytes()),
        })
    }
    pub fn verify(&self, document: &ReviewDocument) -> Result<()> {
        if self.schema_version != VERSION
            || self.round_id != document.round_id
            || self.reviewer_id != document.authority.reviewer_id
            || self.device_id != document.authority.device_id
        {
            return Err(ReviewError::Binding);
        }
        verify_signature(
            &document.authority.reviewer_public_key,
            &self.signature,
            &decision_bytes(document, self.decision)?,
        )
        .map_err(|_| ReviewError::Signature)
    }
}

/// The broker authenticates acceptance time and the exact human-signed decision.
/// verify() proves historical acceptance by the pinned broker, not current validity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub schema_version: u16,
    pub review: SignedReview,
    pub response: ReviewerDecision,
    pub accepted_at: i64,
    pub broker_signature: String,
}

impl DecisionReceipt {
    pub fn sign(
        review: SignedReview,
        response: ReviewerDecision,
        accepted_at: i64,
        key: &SigningKey,
    ) -> Result<Self> {
        review.verify(&hex(key.verifying_key().as_bytes()), accepted_at)?;
        response.verify(&review.document)?;
        let mut result = Self {
            schema_version: VERSION,
            review,
            response,
            accepted_at,
            broker_signature: String::new(),
        };
        result.broker_signature = hex(&key.sign(&result.signing_bytes()?).to_bytes());
        bounded_wire(&result, MAX_RECEIPT_BYTES)?;
        Ok(result)
    }
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        bytes(
            "opaque.scope.broker-receipt.v1",
            &(
                self.schema_version,
                &self.review,
                &self.response,
                self.accepted_at,
            ),
        )
    }
    pub fn verify(&self, expected_broker_key: &str) -> Result<()> {
        bounded_wire(self, MAX_RECEIPT_BYTES)?;
        if self.schema_version != VERSION {
            return Err(ReviewError::Invalid);
        }
        self.review.verify(expected_broker_key, self.accepted_at)?;
        self.response.verify(&self.review.document)?;
        verify_signature(
            expected_broker_key,
            &self.broker_signature,
            &self.signing_bytes()?,
        )
        .map_err(|_| ReviewError::Signature)
    }
    pub fn digest(&self) -> Result<String> {
        hash("opaque.scope.decision-receipt.v1", self)
    }
}

fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-/".contains(&b))
    {
        return Err(ReviewError::Invalid);
    }
    Ok(())
}
fn digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ReviewError::Invalid);
    }
    Ok(())
}
fn bytes(domain: &str, value: &impl Serialize) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value).map_err(|_| ReviewError::Invalid)?;
    if encoded.len() > 1024 * 1024 {
        return Err(ReviewError::Invalid);
    }
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(encoded);
    Ok(bytes)
}
fn bounded_wire(value: &impl Serialize, maximum: usize) -> Result<()> {
    if serde_json::to_vec(value)
        .map_err(|_| ReviewError::Invalid)?
        .len()
        > maximum
    {
        Err(ReviewError::Invalid)
    } else {
        Ok(())
    }
}
fn hash(domain: &str, value: &impl Serialize) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(bytes(domain, value)?)))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
