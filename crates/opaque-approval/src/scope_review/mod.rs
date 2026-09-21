//! Durable, broker-authenticated scope reviews. The host owns current identity,
//! enrollment and policy resolution and must hold its authority gate from those
//! checks through submission or final dispatch. This store supplies actual signed
//! reviews and retained decisions; it cannot replace the host's current checks.
mod store;

use ed25519_dalek::SigningKey;
use opaque_core::scope::{AuthorityOwner, PreparedAction, ReviewBinding, ScopeGrant};
pub use opaque_core::scope_review::{
    Decision, DecisionReceipt, ReviewAuthority, ReviewSubject, ReviewerDecision, SignedReview,
};
use opaque_core::scope_review::{MAX_ROUND_SECONDS, ReviewDocument, issuance_commitment};
use opaque_core::workstation::hex;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid scope review or signature")]
    Invalid,
    #[error("scope review current authority or exact context mismatch")]
    Authority,
    #[error("scope review is expired")]
    Expired,
    #[error("scope review not found")]
    NotFound,
    #[error("scope review already decided, cancelled, or superseded")]
    Closed,
    #[error("scope review was rejected")]
    Rejected,
    #[error("scope review ledger unavailable or invalid")]
    Storage,
    #[error("scope review ledger capacity reached")]
    Capacity,
    #[error("scope review ledger clock moved backwards")]
    ClockRegression,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Construct only after resolving the CURRENT actor, role, enrollment, policy,
/// owner generation and epochs from trusted host state. Deliberately not
/// Deserialize: an HTTP body or stored receipt must not supply current authority.
#[derive(Debug, Clone)]
pub struct CurrentAuthority(ReviewAuthority);
impl CurrentAuthority {
    pub fn new(authority: ReviewAuthority) -> Result<Self> {
        authority.validate().map_err(|_| Error::Authority)?;
        Ok(Self(authority))
    }
    pub fn authority(&self) -> &ReviewAuthority {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundState {
    Pending,
    Accepted,
    Rejected,
    Cancelled,
    CancelledRestart,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoundSnapshot {
    pub state: RoundState,
    pub review: SignedReview,
    pub receipt: Option<DecisionReceipt>,
}

pub struct ScopeReviewStore {
    ledger: store::Ledger,
    owner: AuthorityOwner,
    broker_key: SigningKey,
    broker_public_key: String,
}

impl ScopeReviewStore {
    /// Broker key must be loaded from trusted private custody and independently
    /// enrolled by the reviewer. A key inside an incoming review is not enrollment.
    pub fn open(
        path: &Path,
        owner: AuthorityOwner,
        broker_signing_key: SigningKey,
        now: i64,
    ) -> Result<Self> {
        owner.validate().map_err(|_| Error::Invalid)?;
        let broker_public_key = hex(broker_signing_key.verifying_key().as_bytes());
        let ledger = store::Ledger::open(path, &owner, &broker_public_key, now)?;
        Ok(Self {
            ledger,
            owner,
            broker_key: broker_signing_key,
            broker_public_key,
        })
    }
    pub fn broker_public_key(&self) -> &str {
        &self.broker_public_key
    }

    /// Host-only historical lookup to discover the recorded requester before
    /// resolving CURRENT authority. It is not exposed directly by server routes.
    pub fn retained(&self, round_id: &str) -> Result<RoundSnapshot> {
        self.ledger.retained(round_id)
    }

    /// Bounded historical inventory, never permission or proof of freshness.
    /// Hosts filter it through current identity/enrollment before remote exposure.
    pub fn list_retained(&self, limit: u32) -> Result<(u64, Vec<RoundSnapshot>)> {
        self.ledger.list_retained(limit)
    }

    fn current(&self, current: &CurrentAuthority, expected: &ReviewAuthority) -> Result<()> {
        current.0.validate().map_err(|_| Error::Authority)?;
        if current.0.owner != self.owner || &current.0 != expected {
            return Err(Error::Authority);
        }
        Ok(())
    }

    pub fn issue(
        &self,
        subject: ReviewSubject,
        current: &CurrentAuthority,
        lifetime_secs: i64,
        now: i64,
    ) -> Result<SignedReview> {
        self.current(current, &current.0)?;
        if !(1..=MAX_ROUND_SECONDS).contains(&lifetime_secs) || now < 0 {
            return Err(Error::Invalid);
        }
        subject
            .validate_for(&current.0)
            .map_err(|_| Error::Authority)?;
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or(Error::Invalid)?
            .min(subject.scope().expires_at);
        if expires_at <= now {
            return Err(Error::Expired);
        }
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| Error::Storage)?;
        let document = ReviewDocument::new(
            uuid::Uuid::new_v4().to_string(),
            hex(&nonce),
            now,
            expires_at,
            current.0.clone(),
            subject,
        )
        .map_err(|_| Error::Invalid)?;
        let review = SignedReview::sign(document, &self.broker_key).map_err(|_| Error::Invalid)?;
        self.ledger.insert(&review, now)?;
        Ok(review)
    }

    pub fn submit(
        &self,
        round_id: &str,
        response: &ReviewerDecision,
        current: &CurrentAuthority,
        now: i64,
    ) -> Result<DecisionReceipt> {
        // Retained pending bytes, not a caller-supplied document, are signed.
        self.ledger.decide(round_id, now, |snapshot| {
            self.current(current, &snapshot.review.document.authority)?;
            snapshot
                .review
                .verify(&self.broker_public_key, now)
                .map_err(|_| Error::Expired)?;
            response
                .verify(&snapshot.review.document)
                .map_err(|_| Error::Invalid)?;
            DecisionReceipt::sign(
                snapshot.review.clone(),
                response.clone(),
                now,
                &self.broker_key,
            )
            .map_err(|_| Error::Invalid)
        })
    }

    pub fn snapshot(
        &self,
        round_id: &str,
        current: &CurrentAuthority,
        now: i64,
    ) -> Result<RoundSnapshot> {
        self.ledger.read(round_id, now, |snapshot| {
            self.current(current, &snapshot.review.document.authority)
        })
    }

    /// Read-only acknowledgment recovery. Never resubmits the decision or work.
    pub fn receipt(
        &self,
        round_id: &str,
        current: &CurrentAuthority,
        now: i64,
    ) -> Result<Option<DecisionReceipt>> {
        Ok(self.snapshot(round_id, current, now)?.receipt)
    }

    pub fn cancel(&self, round_id: &str, current: &CurrentAuthority, now: i64) -> Result<()> {
        self.ledger.cancel(round_id, now, |snapshot| {
            self.current(current, &snapshot.review.document.authority)
        })
    }

    fn retained_approval(
        &self,
        receipt: &DecisionReceipt,
        current: &CurrentAuthority,
        now: i64,
    ) -> Result<()> {
        receipt
            .verify(&self.broker_public_key)
            .map_err(|_| Error::Invalid)?;
        self.current(current, &receipt.review.document.authority)?;
        if receipt.response.decision != Decision::Approve {
            return Err(Error::Rejected);
        }
        if now < receipt.accepted_at {
            return Err(Error::Expired);
        }
        let stored = self.snapshot(&receipt.review.document.round_id, current, now)?;
        if stored.state != RoundState::Accepted || stored.receipt.as_ref() != Some(receipt) {
            return Err(Error::Closed);
        }
        Ok(())
    }

    /// Finalizes the reviewed draft by inserting the authenticated acceptance
    /// receipt digest. Issuance use may outlive the short signing round, up to the
    /// reviewed grant expiry, provided current authority and retained state hold.
    pub fn materialize_scope(
        &self,
        receipt: &DecisionReceipt,
        current: &CurrentAuthority,
        now: i64,
    ) -> Result<ScopeGrant> {
        self.retained_approval(receipt, current, now)?;
        let ReviewSubject::ScopeIssuance { draft } = &receipt.review.document.subject else {
            return Err(Error::Authority);
        };
        if now >= draft.expires_at {
            return Err(Error::Expired);
        }
        let mut grant = draft.clone();
        grant.issuance_receipt_digest = receipt.digest().map_err(|_| Error::Invalid)?;
        grant.canonicalized().map_err(|_| Error::Invalid)
    }

    /// Call under the SAME host authority gate as the core dispatch admission.
    pub fn revalidate_scope(
        &self,
        grant: &ScopeGrant,
        receipt: &DecisionReceipt,
        current: &CurrentAuthority,
        now: i64,
    ) -> Result<()> {
        let approved = self.materialize_scope(receipt, current, now)?;
        if now < grant.not_before || now >= grant.expires_at {
            return Err(Error::Expired);
        }
        if issuance_commitment(grant).map_err(|_| Error::Invalid)?
            != issuance_commitment(&approved).map_err(|_| Error::Invalid)?
            || grant.digest().map_err(|_| Error::Invalid)?
                != approved.digest().map_err(|_| Error::Invalid)?
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    pub fn action_binding(
        &self,
        receipt: &DecisionReceipt,
        current: &CurrentAuthority,
        now: i64,
    ) -> Result<ReviewBinding> {
        self.retained_approval(receipt, current, now)?;
        let document = &receipt.review.document;
        document.validate_at(now).map_err(|_| Error::Expired)?;
        let ReviewSubject::ExactAction {
            scope,
            action,
            case_id,
            case_revision,
            ..
        } = &document.subject
        else {
            return Err(Error::Authority);
        };
        if now < scope.not_before || now >= scope.expires_at {
            return Err(Error::Expired);
        }
        Ok(ReviewBinding {
            schema_version: opaque_core::scope::VERSION,
            case_id: case_id.clone(),
            case_revision: *case_revision,
            action_id: action.action_id.clone(),
            action_digest: action.digest().map_err(|_| Error::Invalid)?,
            scope_digest: scope.digest().map_err(|_| Error::Invalid)?,
            evidence_digest: action.evidence_digest.clone(),
            policy_digest: scope.requirements.policy_digest.clone(),
            round_id: document.round_id.clone(),
            decision_receipt_digest: receipt.digest().map_err(|_| Error::Invalid)?,
            expires_at: document.expires_at,
        })
    }

    /// The host passes its CURRENT exact action and case revision. A historical
    /// signed decision cannot authorize a changed action or newer evidence.
    #[allow(
        clippy::too_many_arguments,
        reason = "keep current host inputs distinct from the historical receipt at this authorization boundary"
    )]
    pub fn revalidate_action(
        &self,
        scope: &ScopeGrant,
        action: &PreparedAction,
        case_id: &str,
        case_revision: u64,
        receipt: &DecisionReceipt,
        current: &CurrentAuthority,
        now: i64,
    ) -> Result<ReviewBinding> {
        let binding = self.action_binding(receipt, current, now)?;
        action.validate_for(scope).map_err(|_| Error::Authority)?;
        if binding.case_id != case_id
            || binding.case_revision != case_revision
            || binding.action_id != action.action_id
            || binding.action_digest != action.digest().map_err(|_| Error::Invalid)?
            || binding.scope_digest != scope.digest().map_err(|_| Error::Invalid)?
            || binding.evidence_digest != action.evidence_digest
        {
            return Err(Error::Authority);
        }
        Ok(binding)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
