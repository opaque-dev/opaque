//! Enrolled scope review and read-only acknowledgment recovery.
//! Native human review belongs to the CLI; this module never creates a decision.
use crate::{
    client::BrokerClient,
    custody::{BrokerEnrollment, WorkstationState},
};
use opaque_core::{
    scope_review::{Decision, DecisionReceipt, ReviewerDecision, SignedReview},
    workstation::decode_hex,
};
use serde::{Deserialize, Serialize};

/// Retrieved only over the independently enrolled, pinned TLS connection.
/// A key copied from a SignedReview must never be used as this trust source.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerIdentity {
    pub broker_public_key: String,
    pub reviewer_id: String,
    pub device_id: String,
    pub reviewer_public_key: String,
}

pub async fn identity(
    client: &BrokerClient,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
) -> Result<BrokerIdentity, String> {
    let identity: BrokerIdentity = client
        .request(
            reqwest::Method::GET,
            "/workstation/scopes/key",
            None,
            Some((&enrollment.device_id, &enrollment.token)),
        )
        .await?;
    let key = decode_hex::<32>(&identity.broker_public_key)
        .map_err(|_| "invalid enrolled scope broker key")?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| "invalid enrolled scope broker key")?;
    if identity.reviewer_id.is_empty()
        || identity.device_id != enrollment.device_id
        || identity.reviewer_public_key != state.public_key_hex
    {
        return Err("scope broker identity does not match workstation enrollment".into());
    }
    Ok(identity)
}

pub fn validate_review(
    review: &SignedReview,
    identity: &BrokerIdentity,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
    id: &str,
    now: i64,
) -> Result<(), String> {
    review
        .verify(&identity.broker_public_key, now)
        .map_err(|_| "invalid, changed or expired signed scope review")?;
    let authority = &review.document.authority;
    if review.document.round_id != id
        || authority.owner.broker_id != enrollment.broker_id
        || authority.reviewer_id != identity.reviewer_id
        || authority.device_id != enrollment.device_id
        || authority.device_id != identity.device_id
        || authority.reviewer_public_key != state.public_key_hex
        || authority.reviewer_public_key != identity.reviewer_public_key
    {
        return Err(
            "scope review does not match the enrolled broker, reviewer, device and round".into(),
        );
    }
    Ok(())
}

pub async fn fetch(
    client: &BrokerClient,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
    identity: &BrokerIdentity,
    id: &str,
    now: i64,
) -> Result<SignedReview, String> {
    let review = client
        .request(
            reqwest::Method::GET,
            &format!("/workstation/scopes/{id}"),
            None,
            Some((&enrollment.device_id, &enrollment.token)),
        )
        .await?;
    validate_review(&review, identity, enrollment, state, id, now)?;
    Ok(review)
}

pub async fn pending(
    client: &BrokerClient,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
    identity: &BrokerIdentity,
    now: i64,
) -> Result<Vec<SignedReview>, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pending {
        reviews: Vec<SignedReview>,
    }
    let pending: Pending = client
        .request(
            reqwest::Method::GET,
            "/workstation/scopes/pending",
            None,
            Some((&enrollment.device_id, &enrollment.token)),
        )
        .await?;
    if pending.reviews.len() > 1 {
        return Err("scope pending window exceeds the single-review limit".into());
    }
    for review in &pending.reviews {
        validate_review(
            review,
            identity,
            enrollment,
            state,
            &review.document.round_id,
            now,
        )?;
    }
    Ok(pending.reviews)
}

/// The native scrollable window receives every byte of the signed review text.
pub fn display(review: &SignedReview) -> String {
    format!(
        "OPAQUE / SCOPE AUTHORITY REVIEW\n\nRead every resource, field, value, lifetime, delegation and shared allowance in the complete document below. Approval records only this decision; it does not establish current authority, remaining budget or execution success.\n\n----- COMPLETE IMMUTABLE REVIEW -----\n{}",
        review.document.review_text
    )
}

pub fn validate_receipt(
    receipt: &DecisionReceipt,
    identity: &BrokerIdentity,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
    id: &str,
) -> Result<(), String> {
    receipt
        .verify(&identity.broker_public_key)
        .map_err(|_| "invalid signed scope decision receipt")?;
    // Historical acceptance is checked at its signed time, not wall-clock now.
    validate_review(
        &receipt.review,
        identity,
        enrollment,
        state,
        id,
        receipt.accepted_at,
    )
}

pub async fn receipt(
    client: &BrokerClient,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
    identity: &BrokerIdentity,
    id: &str,
) -> Result<DecisionReceipt, String> {
    let receipt = client
        .request(
            reqwest::Method::GET,
            &format!("/workstation/scopes/{id}/receipt"),
            None,
            Some((&enrollment.device_id, &enrollment.token)),
        )
        .await?;
    validate_receipt(&receipt, identity, enrollment, state, id)?;
    Ok(receipt)
}

#[derive(Debug, Serialize)]
pub struct DecisionReport {
    pub schema_version: u16,
    pub round_id: String,
    pub broker_id: String,
    pub decision: Decision,
    pub decision_status: &'static str,
    pub execution_status: &'static str,
    pub recovered_via_receipt: bool,
    pub message: &'static str,
}

/// Sends an already human-signed decision exactly once. An ambiguous or invalid
/// acknowledgment permits only a GET for the exact same signed decision.
pub async fn submit(
    client: &BrokerClient,
    enrollment: &BrokerEnrollment,
    state: &WorkstationState,
    identity: &BrokerIdentity,
    review: &SignedReview,
    response: ReviewerDecision,
    now: i64,
) -> Result<DecisionReport, String> {
    let id = &review.document.round_id;
    validate_review(review, identity, enrollment, state, id, now)?;
    response
        .verify(&review.document)
        .map_err(|_| "invalid scope reviewer decision")?;
    let exact = |receipt: &DecisionReceipt| {
        validate_receipt(receipt, identity, enrollment, state, id).is_ok()
            && receipt.review == *review
            && receipt.response == response
    };
    let accepted = client
        .request::<DecisionReceipt>(
            reqwest::Method::POST,
            &format!("/workstation/scopes/{id}/respond"),
            Some(serde_json::to_value(&response).map_err(|_| "scope decision encoding failed")?),
            Some((&enrollment.device_id, &enrollment.token)),
        )
        .await
        .is_ok_and(|receipt| exact(&receipt));
    let recovered = if accepted {
        false
    } else {
        receipt(client, enrollment, state, identity, id)
            .await
            .is_ok_and(|receipt| exact(&receipt))
    };
    Ok(DecisionReport {
        schema_version: 1,
        round_id: id.clone(),
        broker_id: enrollment.broker_id.clone(),
        decision: response.decision,
        decision_status: if accepted || recovered {
            "accepted"
        } else {
            "unknown"
        },
        execution_status: "not_observed",
        recovered_via_receipt: recovered,
        message: if accepted || recovered {
            "Decision accepted. Current authority and execution outcome are not established by this receipt."
        } else {
            "Decision acknowledgment unknown. Use read-only scope-receipt lookup; do not resubmit the decision or operation."
        },
    })
}
