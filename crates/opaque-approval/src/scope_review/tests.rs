use super::*;
use opaque_core::scope::{FieldConstraint, FieldValue, MinimumApproval, ScopeRequirements};
use opaque_core::scope_review::EMPTY_RECEIPT_DIGEST;
use std::os::unix::fs::PermissionsExt;

fn keys() -> (SigningKey, SigningKey) {
    (
        SigningKey::from_bytes(&[7; 32]),
        SigningKey::from_bytes(&[8; 32]),
    )
}
fn owner() -> AuthorityOwner {
    AuthorityOwner {
        tenant_id: "tenant-1".into(),
        broker_id: "broker-1".into(),
        generation: "generation-1".into(),
    }
}
fn authority() -> CurrentAuthority {
    let (_, key) = keys();
    CurrentAuthority::new(ReviewAuthority {
        owner: owner(),
        requester_id: "requester".into(),
        reviewer_id: "reviewer".into(),
        device_id: "device-1".into(),
        reviewer_public_key: hex(key.verifying_key().as_bytes()),
        required_role: "operator".into(),
        policy_digest: "2".repeat(64),
        authority_epoch: 1,
        enrollment_epoch: 1,
    })
    .unwrap()
}
fn grant() -> ScopeGrant {
    ScopeGrant {
        schema_version: 1,
        scope_id: "scope-1".into(),
        root_id: "scope-1".into(),
        parent_id: None,
        owner: owner(),
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
    }
}
fn fixture() -> (tempfile::TempDir, ScopeReviewStore) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let store =
        ScopeReviewStore::open(&dir.path().join("reviews.db"), owner(), keys().0, 1000).unwrap();
    (dir, store)
}
fn sign(review: &SignedReview, decision: Decision) -> ReviewerDecision {
    ReviewerDecision::sign(
        review,
        &hex(keys().0.verifying_key().as_bytes()),
        &keys().1,
        decision,
        1000,
    )
    .unwrap()
}
fn approve(store: &ScopeReviewStore) -> (ScopeGrant, DecisionReceipt) {
    let review = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    let receipt = store
        .submit(
            &review.document.round_id,
            &sign(&review, Decision::Approve),
            &authority(),
            1000,
        )
        .unwrap();
    (
        store
            .materialize_scope(&receipt, &authority(), 1000)
            .unwrap(),
        receipt,
    )
}

#[test]
fn reviewed_issuance_materializes_without_circular_digest() {
    let (_dir, store) = fixture();
    let (grant, receipt) = approve(&store);
    assert_eq!(grant.issuance_receipt_digest, receipt.digest().unwrap());
    store
        .revalidate_scope(&grant, &receipt, &authority(), 1500)
        .unwrap(); // round ended; grant still valid
    let mut changed = grant.clone();
    changed.max_charged_attempts += 1;
    assert_eq!(
        Err(Error::Authority),
        store.revalidate_scope(&changed, &receipt, &authority(), 1500)
    );
    assert_eq!(
        Err(Error::Expired),
        store.revalidate_scope(&grant, &receipt, &authority(), 2000)
    );
}

#[test]
fn exact_action_receipt_binds_identity_revision_evidence_and_deadline() {
    let (_dir, store) = fixture();
    let (grant, _) = approve(&store);
    let action = PreparedAction {
        schema_version: 1,
        action_id: "action-1".into(),
        request_id: "request-1".into(),
        scope_id: grant.scope_id.clone(),
        scope_digest: grant.digest().unwrap(),
        owner: owner(),
        subject: "requester".into(),
        operation: grant.operation.clone(),
        provider_profile_digest: grant.provider_profile_digest.clone(),
        resource: "case-1".into(),
        resource_version: "version-1".into(),
        fields: vec![FieldValue {
            field: "status".into(),
            value: "resolved".into(),
        }],
        evidence_digest: "3".repeat(64),
    };
    let review = store
        .issue(
            ReviewSubject::exact_action(&grant, &action, "case-review-1".into(), 1).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    let receipt = store
        .submit(
            &review.document.round_id,
            &sign(&review, Decision::Approve),
            &authority(),
            1000,
        )
        .unwrap();
    let binding = store
        .revalidate_action(
            &grant,
            &action,
            "case-review-1",
            1,
            &receipt,
            &authority(),
            1000,
        )
        .unwrap();
    assert_eq!(action.action_id, binding.action_id);
    assert_eq!(
        Err(Error::Authority),
        store.revalidate_action(
            &grant,
            &action,
            "case-review-1",
            2,
            &receipt,
            &authority(),
            1000
        )
    );
    let mut changed = action.clone();
    changed.action_id = "action-2".into();
    assert_eq!(
        Err(Error::Authority),
        store.revalidate_action(
            &grant,
            &changed,
            "case-review-1",
            1,
            &receipt,
            &authority(),
            1000
        )
    );
    changed = action.clone();
    changed.evidence_digest = "4".repeat(64);
    assert_eq!(
        Err(Error::Authority),
        store.revalidate_action(
            &grant,
            &changed,
            "case-review-1",
            1,
            &receipt,
            &authority(),
            1000
        )
    );
    assert_eq!(
        Err(Error::Expired),
        store.action_binding(&receipt, &authority(), 1100)
    );
}

#[test]
fn changed_current_authority_blocks_submission_and_later_use() {
    let (_dir, store) = fixture();
    let review = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    let response = sign(&review, Decision::Approve);
    let mut changed = authority().authority().clone();
    changed.enrollment_epoch += 1;
    let changed = CurrentAuthority::new(changed).unwrap();
    assert_eq!(
        Err(Error::Authority),
        store.submit(&review.document.round_id, &response, &changed, 1000)
    );
    let receipt = store
        .submit(&review.document.round_id, &response, &authority(), 1000)
        .unwrap();
    assert_eq!(
        Err(Error::Authority),
        store.materialize_scope(&receipt, &changed, 1000)
    );
    let mut policy = authority().authority().clone();
    policy.policy_digest = "f".repeat(64);
    let policy = CurrentAuthority::new(policy).unwrap();
    assert_eq!(
        Err(Error::Authority),
        store.materialize_scope(&receipt, &policy, 1000)
    );
}

#[test]
fn rejection_replay_and_cancel_are_terminal() {
    let (_dir, store) = fixture();
    let review = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    let receipt = store
        .submit(
            &review.document.round_id,
            &sign(&review, Decision::Reject),
            &authority(),
            1000,
        )
        .unwrap();
    assert_eq!(
        Err(Error::Rejected),
        store.materialize_scope(&receipt, &authority(), 1000)
    );
    assert_eq!(
        Err(Error::Closed),
        store.submit(
            &review.document.round_id,
            &sign(&review, Decision::Approve),
            &authority(),
            1000
        )
    );
    let (_, accepted) = approve(&store);
    store
        .cancel(&accepted.review.document.round_id, &authority(), 1000)
        .unwrap();
    assert_eq!(
        Err(Error::Closed),
        store.materialize_scope(&accepted, &authority(), 1000)
    );
    assert_eq!(
        Some(accepted.clone()),
        store
            .receipt(&accepted.review.document.round_id, &authority(), 1000)
            .unwrap()
    );
}

#[test]
fn restart_cancels_pending_and_preserves_authenticated_receipts() {
    let (dir, store) = fixture();
    let (_, accepted) = approve(&store);
    let pending = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    drop(store);
    let store =
        ScopeReviewStore::open(&dir.path().join("reviews.db"), owner(), keys().0, 1001).unwrap();
    assert_eq!(
        RoundState::CancelledRestart,
        store.retained(&pending.document.round_id).unwrap().state
    );
    assert_eq!(
        Err(Error::Closed),
        store.submit(
            &pending.document.round_id,
            &sign(&pending, Decision::Approve),
            &authority(),
            1001
        )
    );
    store
        .materialize_scope(&accepted, &authority(), 1001)
        .unwrap();
    let (total, items) = store.list_retained(100).unwrap();
    assert_eq!(2, total);
    assert_eq!(2, items.len());
    assert!(store.list_retained(101).is_err());
}

#[test]
fn concurrent_signed_submissions_have_one_durable_acceptance() {
    let (_dir, store) = fixture();
    let store = std::sync::Arc::new(store);
    let review = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    let response = sign(&review, Decision::Approve);
    let threads = (0..8)
        .map(|_| {
            let store = store.clone();
            let response = response.clone();
            let id = review.document.round_id.clone();
            std::thread::spawn(move || store.submit(&id, &response, &authority(), 1000))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        1,
        threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|r| r.is_ok())
            .count()
    );
}

#[test]
fn expiry_and_tenant_generation_changes_fail_closed() {
    let (_dir, store) = fixture();
    let review = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            10,
            1000,
        )
        .unwrap();
    assert_eq!(
        Err(Error::Expired),
        store.submit(
            &review.document.round_id,
            &sign(&review, Decision::Approve),
            &authority(),
            1010
        )
    );
    let mut other = authority().authority().clone();
    other.owner.tenant_id = "tenant-2".into();
    let other = CurrentAuthority::new(other).unwrap();
    assert_eq!(
        Err(Error::Authority),
        store.snapshot(&review.document.round_id, &other, 1010)
    );
    assert!(
        store
            .issue(
                ReviewSubject::issuance(&grant()).unwrap(),
                &other,
                100,
                1010
            )
            .is_err()
    );
}

#[test]
fn recovery_rejects_schema_or_signed_content_mutation() {
    for sql in [
        "CREATE TRIGGER changed AFTER UPDATE ON rounds BEGIN DELETE FROM rounds; END;",
        "UPDATE rounds SET review=json_set(review,'$.document.authority.authority_epoch',2);",
    ] {
        let (dir, store) = fixture();
        approve(&store);
        drop(store);
        let path = dir.path().join("reviews.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(sql).unwrap();
        drop(conn);
        assert!(matches!(
            ScopeReviewStore::open(&path, owner(), keys().0, 1001),
            Err(Error::Storage)
        ));
    }
}
