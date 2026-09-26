//! Synthetic pinned TLS and native rejection only; never a human approval claim.
use super::*;
use ed25519_dalek::SigningKey;
use opaque_approver::scope_review::{self, BrokerIdentity};
use opaque_core::{
    scope::{AuthorityOwner, FieldConstraint, MinimumApproval, ScopeGrant, ScopeRequirements},
    scope_review::{
        Decision, DecisionReceipt, ReviewAuthority, ReviewDocument, ReviewSubject,
        ReviewerDecision, SignedReview,
    },
    workstation::hex,
};

fn fixture(
    workstation: &Workstation,
) -> (SigningKey, BrokerIdentity, SignedReview, DecisionReceipt) {
    let (state, key) = custody::load(&workstation.state).unwrap();
    let broker = SigningKey::from_bytes(&[31; 32]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let grant = ScopeGrant {
        schema_version: 1,
        scope_id: "scope-fixture".into(),
        root_id: "scope-fixture".into(),
        parent_id: None,
        owner: AuthorityOwner {
            tenant_id: "fixture".into(),
            broker_id: "opq-fixture".into(),
            generation: "g1".into(),
        },
        issuer: "requester".into(),
        subject: "agent".into(),
        operation: "fixture.update".into(),
        provider_profile_digest: "a".repeat(64),
        resources: vec!["resource-1".into()],
        fields: vec![FieldConstraint {
            field: "status".into(),
            allowed_values: vec!["closed".into()],
        }],
        not_before: now,
        expires_at: now + 600,
        delegations_remaining: 0,
        max_charged_attempts: 1,
        max_distinct_resources: 1,
        requirements: ScopeRequirements {
            policy_digest: "b".repeat(64),
            minimum_approval: MinimumApproval::ExactAction,
            evaluator_checks: vec![],
        },
        issuance_receipt_digest: "c".repeat(64),
    };
    let authority = ReviewAuthority {
        owner: grant.owner.clone(),
        requester_id: grant.issuer.clone(),
        reviewer_id: "human-fixture".into(),
        device_id: "00000000-0000-4000-8000-000000000005".into(),
        reviewer_public_key: state.public_key_hex.clone(),
        required_role: "operator".into(),
        policy_digest: grant.requirements.policy_digest.clone(),
        authority_epoch: 1,
        enrollment_epoch: 1,
    };
    let identity = BrokerIdentity {
        broker_public_key: hex(broker.verifying_key().as_bytes()),
        reviewer_id: authority.reviewer_id.clone(),
        device_id: authority.device_id.clone(),
        reviewer_public_key: authority.reviewer_public_key.clone(),
    };
    let doc = ReviewDocument::new(
        ID.into(),
        "d".repeat(64),
        now,
        now + 60,
        authority,
        ReviewSubject::issuance(&grant).unwrap(),
    )
    .unwrap();
    let review = SignedReview::sign(doc, &broker).unwrap();
    let response = ReviewerDecision::sign(
        &review,
        &identity.broker_public_key,
        &key,
        Decision::Reject,
        now,
    )
    .unwrap();
    let receipt = DecisionReceipt::sign(review.clone(), response, now, &broker).unwrap();
    (broker, identity, review, receipt)
}
fn encoded(value: &impl serde::Serialize) -> Vec<u8> {
    ok(&serde_json::to_value(value).unwrap())
}

#[tokio::test]
async fn scope_commands_require_enrollment_and_uuid_before_network() {
    let workstation = Workstation::new();
    for command in ["scope-review", "scope-receipt"] {
        failure(
            &workstation.run(command, &["--round-id", "../key"]).await,
            "round_id must be",
        );
        failure(
            &workstation.run(command, &["--round-id", ID]).await,
            "not enrolled",
        );
    }
    failure(&workstation.run("scope-list", &[]).await, "not enrolled");
}

#[tokio::test]
async fn scope_list_and_historical_receipt_are_authenticated_read_only_views() {
    let workstation = Workstation::new();
    let (_, identity, review, receipt) = fixture(&workstation);
    let peer = Peer::start(vec![
        encoded(&identity),
        ok(&json!({"reviews":[review]})),
        encoded(&identity),
        encoded(&receipt),
    ])
    .await;
    workstation.enroll(&peer);
    let listed = workstation.run("scope-list", &[]).await;
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let value: Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(value["reviews"][0]["document"]["round_id"], ID);
    assert!(value["window"].as_str().unwrap().contains("One assigned"));
    let retained = workstation.run("scope-receipt", &["--round-id", ID]).await;
    assert!(
        retained.status.success(),
        "{}",
        String::from_utf8_lossy(&retained.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<DecisionReceipt>(&retained.stdout).unwrap(),
        receipt
    );
    let requests = peer.finish().await;
    assert_eq!(requests.len(), 4);
    assert!(requests.iter().all(|request| request.starts_with("GET ")
        && request.contains("authorization: Bearer fixture-bearer")));
    assert!(!workstation.helper.with_extension("review").exists());
}

#[tokio::test]
async fn scope_native_rejection_binds_full_text_and_posts_once_with_read_only_recovery() {
    // Valid receipt, lost response with retained receipt, lost response without
    // receipt, and a well-signed but different decision in both responses.
    for case in 0..4 {
        let workstation = Workstation::new();
        let (broker, identity, review, receipt) = fixture(&workstation);
        let mut replies = vec![
            encoded(&identity),
            encoded(&review),
            encoded(&identity),
            encoded(&review),
        ];
        if case == 0 {
            replies.push(encoded(&receipt));
        } else if case == 3 {
            let (_, key) = custody::load(&workstation.state).unwrap();
            let other = ReviewerDecision::sign(
                &review,
                &identity.broker_public_key,
                &key,
                Decision::Approve,
                review.document.created_at,
            )
            .unwrap();
            let other =
                DecisionReceipt::sign(review.clone(), other, review.document.created_at, &broker)
                    .unwrap();
            replies.extend([encoded(&other), encoded(&other)]);
        } else {
            replies.push(vec![]);
            replies.push(if case == 1 {
                encoded(&receipt)
            } else {
                response("404 Not Found", b"{}")
            });
        }
        let peer = Peer::start(replies).await;
        workstation.enroll(&peer);
        let output = workstation.run("scope-review", &["--round-id", ID]).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["decision"], "reject");
        assert_eq!(
            report["decision_status"],
            if case < 2 { "accepted" } else { "unknown" }
        );
        assert_eq!(report["execution_status"], "not_observed");
        assert_eq!(report["recovered_via_receipt"], case == 1);
        let requests = peer.finish().await;
        assert_eq!(requests.len(), if case == 0 { 5 } else { 6 });
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("POST "))
                .count(),
            1
        );
        let submitted: ReviewerDecision =
            serde_json::from_str(requests[4].split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(submitted, receipt.response);
        if case != 0 {
            assert!(requests[5].starts_with(&format!("GET /workstation/scopes/{ID}/receipt ")));
        }
        let shown = std::fs::read_to_string(workstation.helper.with_extension("review")).unwrap();
        assert!(shown.contains(&review.document.review_text));
        assert!(shown.contains("Review fingerprint (SHA-256)"));
    }
}

#[tokio::test]
async fn scope_mutation_or_identity_rotation_after_native_review_sends_no_signature() {
    for change_identity in [false, true] {
        let workstation = Workstation::new();
        let (broker, identity, review, _) = fixture(&workstation);
        let mut replies = vec![encoded(&identity), encoded(&review)];
        if change_identity {
            let mut changed = identity.clone();
            changed.reviewer_id = "different-reviewer".into();
            replies.push(encoded(&changed));
        } else {
            let document = &review.document;
            let changed = ReviewDocument::new(
                ID.into(),
                "e".repeat(64),
                document.created_at,
                document.expires_at,
                document.authority.clone(),
                document.subject.clone(),
            )
            .unwrap();
            replies.extend([
                encoded(&identity),
                encoded(&SignedReview::sign(changed, &broker).unwrap()),
            ]);
        }
        let peer = Peer::start(replies).await;
        workstation.enroll(&peer);
        failure(
            &workstation.run("scope-review", &["--round-id", ID]).await,
            "changed after review; no signature sent",
        );
        assert!(
            peer.finish()
                .await
                .iter()
                .all(|request| request.starts_with("GET "))
        );
    }
}

#[tokio::test]
async fn scope_enrollment_and_independent_key_mismatch_fail_before_native_prompt() {
    for field in 0..7 {
        let workstation = Workstation::new();
        let (broker, mut identity, review, _) = fixture(&workstation);
        let mut doc = review.document.clone();
        match field {
            0 => {
                identity.broker_public_key =
                    hex(SigningKey::from_bytes(&[99; 32]).verifying_key().as_bytes())
            }
            1 => identity.device_id = "other-device".into(),
            2 => identity.reviewer_public_key = "a".repeat(64),
            3 => doc.authority.reviewer_id = "other-human".into(),
            4 => doc.authority.device_id = "other-device".into(),
            5 => {
                doc.authority.owner.broker_id = "other-broker".into();
                if let ReviewSubject::ScopeIssuance { ref mut draft } = doc.subject {
                    draft.owner = doc.authority.owner.clone();
                }
            }
            _ => doc.round_id = "00000000-0000-4000-8000-000000000099".into(),
        }
        let doc = ReviewDocument::new(
            doc.round_id,
            doc.nonce,
            doc.created_at,
            doc.expires_at,
            doc.authority,
            doc.subject,
        )
        .unwrap();
        let review = SignedReview::sign(doc, &broker).unwrap();
        let mut replies = vec![encoded(&identity)];
        if field != 1 && field != 2 {
            replies.push(encoded(&review));
        }
        let peer = Peer::start(replies).await;
        workstation.enroll(&peer);
        let output = workstation.run("scope-review", &["--round-id", ID]).await;
        assert!(!output.status.success());
        assert!(!workstation.helper.with_extension("review").exists());
        assert!(
            peer.finish()
                .await
                .iter()
                .all(|request| request.starts_with("GET "))
        );
    }
}

#[tokio::test]
async fn scope_pending_window_and_receipt_signature_are_fail_closed() {
    let workstation = Workstation::new();
    let (_, identity, review, mut receipt) = fixture(&workstation);
    receipt.broker_signature = "0".repeat(128);
    let peer = Peer::start(vec![
        encoded(&identity),
        ok(&json!({"reviews":[review,review]})),
        encoded(&identity),
        encoded(&receipt),
    ])
    .await;
    workstation.enroll(&peer);
    failure(
        &workstation.run("scope-list", &[]).await,
        "single-review limit",
    );
    failure(
        &workstation.run("scope-receipt", &["--round-id", ID]).await,
        "invalid signed scope decision receipt",
    );
    assert_eq!(peer.finish().await.len(), 4);
}

#[tokio::test]
async fn malformed_decision_cannot_reach_transport() {
    let workstation = Workstation::new();
    let (_, identity, review, mut receipt) = fixture(&workstation);
    let peer = Peer::start(vec![]).await;
    let enrollment = workstation.enroll(&peer);
    let state = custody::load(&workstation.state).unwrap().0;
    let client = BrokerClient::new(&peer.endpoint, &peer.pin).unwrap();
    receipt.response.signature = "0".repeat(128);
    assert!(
        scope_review::submit(
            &client,
            &enrollment,
            &state,
            &identity,
            &review,
            receipt.response,
            review.document.created_at
        )
        .await
        .is_err()
    );
    assert!(peer.finish().await.is_empty());
}

#[tokio::test]
async fn native_exact_action_review_includes_bound_before_and_after_values() {
    use opaque_core::{
        scope::{FieldValue, PreparedAction},
        scope_review::ReviewEvidence,
    };
    let workstation = Workstation::new();
    let (broker, identity, issuance, _) = fixture(&workstation);
    let ReviewSubject::ScopeIssuance { mut draft } = issuance.document.subject else {
        unreachable!()
    };
    draft.issuance_receipt_digest = "e".repeat(64);
    let before = ReviewEvidence {
        provider_profile_digest: draft.provider_profile_digest.clone(),
        resource: "resource-1".into(),
        resource_version: "v1".into(),
        fields: vec![FieldValue {
            field: "status".into(),
            value: "open".into(),
        }],
    };
    let action = PreparedAction {
        schema_version: 1,
        action_id: "action1".into(),
        request_id: "request1".into(),
        scope_id: draft.scope_id.clone(),
        scope_digest: draft.digest().unwrap(),
        owner: draft.owner.clone(),
        subject: draft.subject.clone(),
        operation: draft.operation.clone(),
        provider_profile_digest: draft.provider_profile_digest.clone(),
        resource: "resource-1".into(),
        resource_version: "v1".into(),
        fields: vec![FieldValue {
            field: "status".into(),
            value: "closed".into(),
        }],
        evidence_digest: before.digest().unwrap(),
    };
    let mut authority = issuance.document.authority;
    authority.requester_id = draft.subject.clone();
    let subject =
        ReviewSubject::exact_action_with_evidence(&draft, &action, "case1".into(), 1, before)
            .unwrap();
    let doc = ReviewDocument::new(
        ID.into(),
        "d".repeat(64),
        issuance.document.created_at,
        issuance.document.expires_at,
        authority,
        subject,
    )
    .unwrap();
    let review = SignedReview::sign(doc, &broker).unwrap();
    let (_, key) = custody::load(&workstation.state).unwrap();
    let decision = ReviewerDecision::sign(
        &review,
        &identity.broker_public_key,
        &key,
        Decision::Reject,
        review.document.created_at,
    )
    .unwrap();
    let receipt = DecisionReceipt::sign(
        review.clone(),
        decision,
        review.document.created_at,
        &broker,
    )
    .unwrap();
    let peer = Peer::start(vec![
        encoded(&identity),
        encoded(&review),
        encoded(&identity),
        encoded(&review),
        encoded(&receipt),
    ])
    .await;
    workstation.enroll(&peer);
    let output = workstation.run("scope-review", &["--round-id", ID]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let shown = std::fs::read_to_string(workstation.helper.with_extension("review")).unwrap();
    assert!(shown.contains(&review.document.review_text));
    assert!(shown.contains("\"open\"") && shown.contains("\"closed\""));
    assert_eq!(peer.finish().await.len(), 5);
}
