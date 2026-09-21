use super::*;
use crate::scope::{FieldConstraint, MinimumApproval, ScopeRequirements};

fn fixture() -> (ScopeGrant, ReviewAuthority, SigningKey, SigningKey) {
    let broker = SigningKey::from_bytes(&[7; 32]);
    let reviewer = SigningKey::from_bytes(&[8; 32]);
    let owner = AuthorityOwner {
        tenant_id: "tenant-1".into(),
        broker_id: "broker-1".into(),
        generation: "generation-1".into(),
    };
    let grant = ScopeGrant {
        schema_version: 1,
        scope_id: "scope-1".into(),
        root_id: "scope-1".into(),
        parent_id: None,
        owner: owner.clone(),
        issuer: "requester".into(),
        subject: "requester".into(),
        operation: "case.update".into(),
        provider_profile_digest: "1".repeat(64),
        resources: vec!["case-1".into()],
        fields: vec![FieldConstraint {
            field: "status".into(),
            allowed_values: vec!["resolved".into()],
        }],
        not_before: 1000,
        expires_at: 2000,
        delegations_remaining: 0,
        max_charged_attempts: 10,
        max_distinct_resources: 1,
        requirements: ScopeRequirements {
            policy_digest: "2".repeat(64),
            minimum_approval: MinimumApproval::ExactAction,
            evaluator_checks: vec![],
        },
        issuance_receipt_digest: EMPTY_RECEIPT_DIGEST.into(),
    };
    let authority = ReviewAuthority {
        owner,
        requester_id: "requester".into(),
        reviewer_id: "reviewer".into(),
        device_id: "device-1".into(),
        reviewer_public_key: hex(reviewer.verifying_key().as_bytes()),
        required_role: "operator".into(),
        policy_digest: "2".repeat(64),
        authority_epoch: 1,
        enrollment_epoch: 1,
    };
    (grant, authority, broker, reviewer)
}
fn review() -> (SignedReview, SigningKey, SigningKey) {
    let (grant, authority, broker, reviewer) = fixture();
    let doc = ReviewDocument::new(
        uuid::Uuid::new_v4().to_string(),
        "a".repeat(64),
        1000,
        1100,
        authority,
        ReviewSubject::issuance(&grant).unwrap(),
    )
    .unwrap();
    (SignedReview::sign(doc, &broker).unwrap(), broker, reviewer)
}

#[test]
fn issuance_commitment_excludes_only_receipt_and_final_digest_includes_it() {
    let (mut grant, _, _, _) = fixture();
    let initial = issuance_commitment(&grant).unwrap();
    let digest = grant.digest().unwrap();
    grant.issuance_receipt_digest = "e".repeat(64);
    assert_eq!(initial, issuance_commitment(&grant).unwrap());
    assert_ne!(digest, grant.digest().unwrap());
    let expected = serde_json::to_value(grant.canonicalized().unwrap()).unwrap();
    let mut without = expected.as_object().unwrap().clone();
    without.remove("issuance_receipt_digest");
    assert_eq!(
        initial,
        hash(
            "opaque.scope.unsigned-issuance.v1",
            &serde_json::Value::Object(without)
        )
        .unwrap()
    );
    grant.max_charged_attempts += 1;
    assert_ne!(initial, issuance_commitment(&grant).unwrap());
}

#[test]
fn broker_key_must_be_independently_pinned_and_text_must_match_exact_subject() {
    let (mut signed, broker, _) = review();
    let expected = hex(broker.verifying_key().as_bytes());
    signed.verify(&expected, 1000).unwrap();
    assert_eq!(
        Err(ReviewError::Signature),
        signed.verify(&"f".repeat(64), 1000)
    );
    signed.document.review_text.push_str("\nNo risk.");
    assert_eq!(Err(ReviewError::Binding), signed.verify(&expected, 1000));
}

#[test]
fn changed_authority_and_rejection_cannot_reuse_approval_signature() {
    let (signed, broker, key) = review();
    let expected = hex(broker.verifying_key().as_bytes());
    let mut response =
        ReviewerDecision::sign(&signed, &expected, &key, Decision::Approve, 1001).unwrap();
    response.verify(&signed.document).unwrap();
    response.decision = Decision::Reject;
    assert_eq!(
        Err(ReviewError::Signature),
        response.verify(&signed.document)
    );
    let mut changed = signed.clone();
    changed.document.authority.enrollment_epoch += 1;
    assert!(changed.verify(&expected, 1001).is_err());
}

#[test]
fn broker_authenticates_acceptance_metadata_and_review_nonce() {
    let (signed, broker, key) = review();
    let expected = hex(broker.verifying_key().as_bytes());
    let response =
        ReviewerDecision::sign(&signed, &expected, &key, Decision::Approve, 1001).unwrap();
    let mut receipt = DecisionReceipt::sign(signed, response, 1001, &broker).unwrap();
    receipt.verify(&expected).unwrap();
    receipt.accepted_at = 1002;
    assert_eq!(Err(ReviewError::Signature), receipt.verify(&expected));
    receipt.accepted_at = 1001;
    receipt.review.document.nonce = "b".repeat(64);
    assert!(receipt.verify(&expected).is_err());
}

#[test]
fn deadlines_and_distinct_humans_are_enforced() {
    let (signed, broker, key) = review();
    let expected = hex(broker.verifying_key().as_bytes());
    assert_eq!(Err(ReviewError::Expired), signed.verify(&expected, 1100));
    assert!(ReviewerDecision::sign(&signed, &expected, &key, Decision::Approve, 999).is_err());
    let mut authority = signed.document.authority.clone();
    authority.reviewer_id = authority.requester_id.clone();
    assert_eq!(Err(ReviewError::Binding), authority.validate());
}

#[test]
fn legacy_wire_shape_and_unknown_fields_are_rejected() {
    let (signed, _, _) = review();
    let mut value = serde_json::to_value(&signed).unwrap();
    value["legacy_task_receipt"] = true.into();
    assert!(serde_json::from_value::<SignedReview>(value).is_err());
    assert!(
        serde_json::from_value::<DecisionReceipt>(
            serde_json::json!({"schema_version":1,"review":{},"response":{},"accepted_at":1001})
        )
        .is_err()
    );
}

#[test]
fn escaped_review_text_cannot_create_an_untransportable_signed_round() {
    let (mut grant, authority, broker, _) = fixture();
    grant.fields[0].allowed_values = (0..56)
        .map(|index| format!("{index:02}{}", "\\".repeat(1022)))
        .collect();
    let document = ReviewDocument::new(
        uuid::Uuid::new_v4().to_string(),
        "a".repeat(64),
        1000,
        1100,
        authority,
        ReviewSubject::issuance(&grant).unwrap(),
    )
    .unwrap();
    assert!(document.review_text.len() < MAX_REVIEW_BYTES);
    let oversized = SignedReview {
        schema_version: VERSION,
        document: document.clone(),
        broker_public_key: hex(broker.verifying_key().as_bytes()),
        signature: "a".repeat(128),
    };
    assert!(serde_json::to_vec(&oversized).unwrap().len() > MAX_SIGNED_REVIEW_BYTES);
    assert_eq!(
        SignedReview::sign(document, &broker),
        Err(ReviewError::Invalid)
    );
    assert_eq!(
        oversized.verify(&oversized.broker_public_key, 1001),
        Err(ReviewError::Invalid)
    );
}

#[test]
fn invisible_direction_controls_cannot_reorder_the_exact_native_review() {
    for codepoint in [0x061c, 0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069] {
        let (mut grant, authority, _, _) = fixture();
        grant.fields[0].allowed_values =
            vec![format!("closed{}open", char::from_u32(codepoint).unwrap())];
        // Scope values are a generic contract; the human review protocol adds
        // its presentation safety constraint before any broker signature.
        let subject = ReviewSubject::issuance(&grant).unwrap();
        assert_eq!(
            ReviewDocument::new(
                uuid::Uuid::new_v4().to_string(),
                "a".repeat(64),
                1000,
                1100,
                authority,
                subject
            ),
            Err(ReviewError::Invalid)
        );
    }
}

#[test]
fn contextual_evidence_binds_before_state_to_exact_provider_resource_and_version() {
    let (grant, authority, _, _) = fixture();
    let evidence = ReviewEvidence {
        provider_profile_digest: grant.provider_profile_digest.clone(),
        resource: "case-1".into(),
        resource_version: "version-1".into(),
        fields: vec![FieldValue {
            field: "status".into(),
            value: "open".into(),
        }],
    };
    let action = PreparedAction {
        schema_version: 1,
        action_id: "action-1".into(),
        request_id: "request-1".into(),
        scope_id: grant.scope_id.clone(),
        scope_digest: grant.digest().unwrap(),
        owner: grant.owner.clone(),
        subject: grant.subject.clone(),
        operation: grant.operation.clone(),
        provider_profile_digest: grant.provider_profile_digest.clone(),
        resource: evidence.resource.clone(),
        resource_version: evidence.resource_version.clone(),
        fields: vec![FieldValue {
            field: "status".into(),
            value: "resolved".into(),
        }],
        evidence_digest: evidence.digest().unwrap(),
    };
    let subject = ReviewSubject::exact_action_with_evidence(
        &grant,
        &action,
        "case-1".into(),
        1,
        evidence.clone(),
    )
    .unwrap();
    subject.validate_for(&authority).unwrap();
    for index in 0..4 {
        let mut changed = evidence.clone();
        match index {
            0 => changed.resource = "case-2".into(),
            1 => changed.resource_version = "version-2".into(),
            2 => changed.provider_profile_digest = "3".repeat(64),
            _ => changed.fields[0].value = "closed".into(),
        }
        assert!(
            ReviewSubject::exact_action_with_evidence(&grant, &action, "case-1".into(), 1, changed)
                .is_err()
        );
    }
    let mut duplicate = evidence.clone();
    duplicate.fields.push(duplicate.fields[0].clone());
    assert_eq!(duplicate.canonicalized(), Err(ReviewError::Invalid));
    let doc = ReviewDocument::new(
        uuid::Uuid::new_v4().to_string(),
        "a".repeat(64),
        1000,
        1100,
        authority,
        subject,
    )
    .unwrap();
    assert!(doc.review_text.contains("open"));
    assert!(doc.review_text.contains("resolved"));
}
