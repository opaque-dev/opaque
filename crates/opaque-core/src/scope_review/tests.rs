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

fn exact_fixture() -> (ScopeGrant, PreparedAction, ReviewAuthority, ReviewEvidence) {
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
    (grant, action, authority, evidence)
}

#[test]
fn untrusted_authority_requires_complete_identity_epochs_and_well_formed_keys() {
    let (_, authority, _, _) = fixture();
    for (pointer, replacement) in [
        ("/requester_id", serde_json::json!("")),
        ("/reviewer_id", serde_json::json!("x".repeat(257))),
        ("/device_id", serde_json::json!("device\nforged")),
        ("/required_role", serde_json::json!("approver bypass")),
        ("/reviewer_public_key", serde_json::json!("short")),
        ("/policy_digest", serde_json::json!("G".repeat(64))),
        ("/authority_epoch", serde_json::json!(0)),
        ("/enrollment_epoch", serde_json::json!(0)),
        ("/reviewer_id", serde_json::json!(authority.requester_id)),
    ] {
        let mut value = serde_json::to_value(&authority).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement;
        let changed: ReviewAuthority = serde_json::from_value(value).unwrap();
        assert!(changed.validate().is_err(), "{pointer}");
    }
}

#[test]
fn deserialized_subjects_cannot_rebind_or_expand_host_prepared_authority() {
    let (mut grant, action, authority, _) = exact_fixture();
    grant.resources.push("case-2".into());
    let issuance = ReviewSubject::issuance(&grant).unwrap();
    for (pointer, value) in [
        (
            "/draft/issuance_receipt_digest",
            serde_json::json!("e".repeat(64)),
        ),
        ("/draft/resources", serde_json::json!(["case-2", "case-1"])),
        ("/draft/owner/tenant_id", serde_json::json!("other-tenant")),
        ("/draft/issuer", serde_json::json!("other-requester")),
        (
            "/draft/requirements/policy_digest",
            serde_json::json!("e".repeat(64)),
        ),
    ] {
        let mut encoded = serde_json::to_value(&issuance).unwrap();
        *encoded.pointer_mut(pointer).unwrap() = value;
        assert!(
            serde_json::from_value::<ReviewSubject>(encoded)
                .unwrap()
                .validate_for(&authority)
                .is_err(),
            "{pointer}"
        );
    }
    let (grant, _, _, _) = exact_fixture();
    let exact = ReviewSubject::exact_action(&grant, &action, "case-review".into(), 1).unwrap();
    for (pointer, value) in [
        ("/case_revision", serde_json::json!(0)),
        ("/scope/owner/tenant_id", serde_json::json!("other-tenant")),
        ("/action/subject", serde_json::json!("other-requester")),
        (
            "/scope/requirements/policy_digest",
            serde_json::json!("e".repeat(64)),
        ),
        ("/scope/resources", serde_json::json!(["case-2", "case-1"])),
        (
            "/action/fields",
            serde_json::json!([{"field":"z","value":"x"},{"field":"a","value":"x"}]),
        ),
        ("/action/resource", serde_json::json!("outside-resource")),
    ] {
        let mut encoded = serde_json::to_value(&exact).unwrap();
        *encoded.pointer_mut(pointer).unwrap() = value;
        assert!(
            serde_json::from_value::<ReviewSubject>(encoded)
                .unwrap()
                .validate_for(&authority)
                .is_err(),
            "{pointer}"
        );
    }
    assert!(ReviewSubject::exact_action(&grant, &action, "case-review".into(), 0).is_err());
    assert!(ReviewSubject::exact_action(&grant, &action, "".into(), 1).is_err());
}

#[test]
fn contextual_evidence_rejects_unbounded_ambiguous_and_noncanonical_provider_state() {
    let (grant, mut action, authority, evidence) = exact_fixture();
    for (pointer, value) in [
        ("/resource_version", serde_json::json!("")),
        ("/resource_version", serde_json::json!("v".repeat(1025))),
        ("/resource_version", serde_json::json!("v\n1")),
        ("/fields", serde_json::json!([])),
        (
            "/fields",
            serde_json::json!(
                (0..33)
                    .map(|i| serde_json::json!({"field":format!("field{i}"),"value":"x"}))
                    .collect::<Vec<_>>()
            ),
        ),
        ("/fields/0/value", serde_json::json!("x".repeat(1025))),
        ("/fields/0/value", serde_json::json!("status\nspoof")),
    ] {
        let mut encoded = serde_json::to_value(&evidence).unwrap();
        *encoded.pointer_mut(pointer).unwrap() = value;
        assert!(
            serde_json::from_value::<ReviewEvidence>(encoded)
                .unwrap()
                .canonicalized()
                .is_err(),
            "{pointer}"
        );
    }
    let mut two = evidence;
    two.fields.push(FieldValue {
        field: "category".into(),
        value: "support".into(),
    });
    action.evidence_digest = two.digest().unwrap();
    let mut subject =
        ReviewSubject::exact_action_with_evidence(&grant, &action, "case-review".into(), 1, two)
            .unwrap();
    subject.validate_for(&authority).unwrap();
    if let ReviewSubject::ExactAction {
        evidence: Some(evidence),
        ..
    } = &mut subject
    {
        evidence.fields.reverse();
    }
    assert!(subject.validate_for(&authority).is_err());
}

#[test]
fn review_rounds_refuse_bad_version_nonce_time_and_scope_deadline_before_signing() {
    let (signed, broker, _) = review();
    for (pointer, value) in [
        ("/schema_version", serde_json::json!(2)),
        ("/round_id", serde_json::json!("not-a-round")),
        ("/nonce", serde_json::json!("bad")),
        ("/created_at", serde_json::json!(-1)),
        ("/expires_at", serde_json::json!(i64::MIN)),
        ("/expires_at", serde_json::json!(1000)),
        ("/expires_at", serde_json::json!(1301)),
        (
            "/review_text",
            serde_json::json!("x".repeat(MAX_REVIEW_BYTES + 1)),
        ),
    ] {
        let mut encoded = serde_json::to_value(&signed.document).unwrap();
        *encoded.pointer_mut(pointer).unwrap() = value;
        let changed: ReviewDocument = serde_json::from_value(encoded).unwrap();
        assert!(SignedReview::sign(changed, &broker).is_err(), "{pointer}");
    }
    let (mut grant, authority, _, _) = fixture();
    grant.expires_at = 1050;
    assert!(
        ReviewDocument::new(
            uuid::Uuid::new_v4().to_string(),
            "a".repeat(64),
            1000,
            1100,
            authority,
            ReviewSubject::issuance(&grant).unwrap()
        )
        .is_err()
    );
    let (mut grant, authority, _, _) = fixture();
    grant.fields[0].allowed_values = (0..64)
        .map(|i| format!("{i:02}{}", "\\".repeat(1022)))
        .collect();
    assert!(
        ReviewDocument::new(
            uuid::Uuid::new_v4().to_string(),
            "a".repeat(64),
            1000,
            1100,
            authority,
            ReviewSubject::issuance(&grant).unwrap()
        )
        .is_err()
    );
}

#[test]
fn version_and_signer_confusion_never_produce_an_accepted_decision() {
    let (review, broker, reviewer) = review();
    let expected = hex(broker.verifying_key().as_bytes());
    let mut wrong_version = review.clone();
    wrong_version.schema_version = 2;
    assert!(wrong_version.verify(&expected, 1001).is_err());
    assert!(ReviewerDecision::sign(&review, &expected, &broker, Decision::Approve, 1001).is_err());
    let response =
        ReviewerDecision::sign(&review, &expected, &reviewer, Decision::Approve, 1001).unwrap();
    for (pointer, value) in [
        ("/schema_version", serde_json::json!(2)),
        (
            "/round_id",
            serde_json::json!(uuid::Uuid::new_v4().to_string()),
        ),
        ("/reviewer_id", serde_json::json!("other-reviewer")),
        ("/device_id", serde_json::json!("other-device")),
    ] {
        let mut encoded = serde_json::to_value(&response).unwrap();
        *encoded.pointer_mut(pointer).unwrap() = value;
        assert!(
            serde_json::from_value::<ReviewerDecision>(encoded)
                .unwrap()
                .verify(&review.document)
                .is_err(),
            "{pointer}"
        );
    }
    let mut receipt = DecisionReceipt::sign(review, response, 1001, &broker).unwrap();
    receipt.schema_version = 2;
    assert!(receipt.verify(&expected).is_err());
    receipt.schema_version = 1;
    receipt.broker_signature = "a".repeat(MAX_RECEIPT_BYTES);
    assert_eq!(receipt.verify(&expected), Err(ReviewError::Invalid));
}
