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

#[test]
fn rounds_enforce_clock_lifetime_limits_and_receipt_purpose() {
    let (_dir, store) = fixture();
    let subject = ReviewSubject::issuance(&grant()).unwrap();
    for (ttl, now) in [(0, 1000), (301, 1000), (10, -1)] {
        assert_eq!(
            store.issue(subject.clone(), &authority(), ttl, now),
            Err(Error::Invalid)
        );
    }
    assert_eq!(
        store.issue(subject, &authority(), 10, 999),
        Err(Error::ClockRegression)
    );
    let mut expired = grant();
    expired.not_before = 0;
    expired.expires_at = 1000;
    assert_eq!(
        store.issue(
            ReviewSubject::issuance(&expired).unwrap(),
            &authority(),
            10,
            1000
        ),
        Err(Error::Expired)
    );
    let (grant, receipt) = approve(&store);
    assert_eq!(
        store.action_binding(&receipt, &authority(), 1000),
        Err(Error::Authority)
    );
    assert_eq!(
        store.materialize_scope(&receipt, &authority(), 999),
        Err(Error::Expired)
    );
    assert_eq!(
        store.materialize_scope(&receipt, &authority(), 2000),
        Err(Error::Expired)
    );
    let mut changed = grant.clone();
    changed.issuance_receipt_digest = "f".repeat(64);
    assert_eq!(
        store.revalidate_scope(&changed, &receipt, &authority(), 2000),
        Err(Error::Expired)
    );
    assert!(store.retained("malformed-id").is_err());
    assert!(store.retained(&uuid::Uuid::new_v4().to_string()).is_err());
    assert!(store.list_retained(0).is_err());
}

#[test]
fn future_scope_activation_and_action_receipts_preserve_distinct_time_boundaries() {
    let (_dir, store) = fixture();
    let mut future = grant();
    future.not_before = 1050;
    let review = store
        .issue(
            ReviewSubject::issuance(&future).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    let issuance = store
        .submit(
            &review.document.round_id,
            &sign(&review, Decision::Approve),
            &authority(),
            1000,
        )
        .unwrap();
    let grant = store
        .materialize_scope(&issuance, &authority(), 1000)
        .unwrap();
    assert_eq!(
        store.revalidate_scope(&grant, &issuance, &authority(), 1000),
        Err(Error::Expired)
    );
    let action = PreparedAction {
        schema_version: 1,
        action_id: "future-action".into(),
        request_id: "future-request".into(),
        scope_id: grant.scope_id.clone(),
        scope_digest: grant.digest().unwrap(),
        owner: owner(),
        subject: grant.subject.clone(),
        operation: grant.operation.clone(),
        provider_profile_digest: grant.provider_profile_digest.clone(),
        resource: "case-1".into(),
        resource_version: "v1".into(),
        fields: vec![FieldValue {
            field: "status".into(),
            value: "resolved".into(),
        }],
        evidence_digest: "3".repeat(64),
    };
    let review = store
        .issue(
            ReviewSubject::exact_action(&grant, &action, "case-review".into(), 1).unwrap(),
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
    assert_eq!(
        store.materialize_scope(&receipt, &authority(), 1000),
        Err(Error::Authority)
    );
    assert_eq!(
        store.action_binding(&receipt, &authority(), 1000),
        Err(Error::Expired)
    );
    store
        .revalidate_scope(&grant, &issuance, &authority(), 1050)
        .unwrap();
    store.action_binding(&receipt, &authority(), 1050).unwrap();
    let mut forged_receipt_field = grant.clone();
    forged_receipt_field.issuance_receipt_digest = "f".repeat(64);
    assert_eq!(
        store.revalidate_scope(&forged_receipt_field, &issuance, &authority(), 1050),
        Err(Error::Authority)
    );
    assert_eq!(
        store.revalidate_action(
            &grant,
            &action,
            "different-case",
            1,
            &receipt,
            &authority(),
            1050
        ),
        Err(Error::Authority)
    );
    let mut changed = action;
    changed.resource = "outside".into();
    assert_eq!(
        store.revalidate_action(
            &grant,
            &changed,
            "case-review",
            1,
            &receipt,
            &authority(),
            1050
        ),
        Err(Error::Authority)
    );
}

#[test]
fn consumed_or_rejected_rounds_remain_closed_and_restart_requires_fresh_nonce() {
    let (dir, store) = fixture();
    let old = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    let old_decision = sign(&old, Decision::Approve);
    drop(store);
    let store =
        ScopeReviewStore::open(&dir.path().join("reviews.db"), owner(), keys().0, 1001).unwrap();
    let fresh = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1001,
        )
        .unwrap();
    assert_ne!(old.document.nonce, fresh.document.nonce);
    assert_eq!(
        store.submit(&fresh.document.round_id, &old_decision, &authority(), 1001),
        Err(Error::Invalid)
    );
    let response = ReviewerDecision::sign(
        &fresh,
        store.broker_public_key(),
        &keys().1,
        Decision::Reject,
        1001,
    )
    .unwrap();
    let receipt = store
        .submit(&fresh.document.round_id, &response, &authority(), 1001)
        .unwrap();
    assert_eq!(
        store.materialize_scope(&receipt, &authority(), 1001),
        Err(Error::Rejected)
    );
    assert_eq!(
        store.cancel(&fresh.document.round_id, &authority(), 1001),
        Err(Error::Closed)
    );
    assert_eq!(
        store.cancel(&old.document.round_id, &authority(), 1001),
        Err(Error::Closed)
    );
    let cancelled = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1001,
        )
        .unwrap();
    store
        .cancel(&cancelled.document.round_id, &authority(), 1001)
        .unwrap();
    assert_eq!(
        store.retained(&cancelled.document.round_id).unwrap().state,
        RoundState::Cancelled
    );
    let other = CurrentAuthority::new(ReviewAuthority {
        owner: AuthorityOwner {
            tenant_id: "other-tenant".into(),
            ..owner()
        },
        ..authority().authority().clone()
    })
    .unwrap();
    assert_eq!(
        store.cancel(&cancelled.document.round_id, &other, 1001),
        Err(Error::Authority)
    );
}

#[test]
fn pending_capacity_preserves_existing_rounds_and_cancel_releases_only_queue_capacity() {
    let (_dir, store) = fixture();
    let mut first = None;
    for _ in 0..64 {
        let round = store
            .issue(
                ReviewSubject::issuance(&grant()).unwrap(),
                &authority(),
                100,
                1000,
            )
            .unwrap();
        first.get_or_insert(round.document.round_id);
    }
    assert_eq!(
        store.issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1000
        ),
        Err(Error::Capacity)
    );
    assert_eq!(store.list_retained(100).unwrap().0, 64);
    store
        .cancel(first.as_deref().unwrap(), &authority(), 1000)
        .unwrap();
    store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    assert_eq!(store.list_retained(100).unwrap().0, 65);
    assert_eq!(
        store.retained(first.as_deref().unwrap()).unwrap().state,
        RoundState::Cancelled
    );
}

#[test]
fn ledger_custody_refuses_second_writer_links_shared_permissions_and_invalid_paths() {
    let (dir, store) = fixture();
    let path = dir.path().join("reviews.db");
    assert!(matches!(
        ScopeReviewStore::open(&path, owner(), keys().0, 1000),
        Err(Error::Storage)
    ));
    assert!(matches!(
        ScopeReviewStore::open(Path::new("relative.db"), owner(), keys().0, 1000),
        Err(Error::Storage)
    ));
    assert!(matches!(
        ScopeReviewStore::open(&path, owner(), keys().0, -1),
        Err(Error::Storage)
    ));
    drop(store);
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = dir.path().join(format!("reviews.db{suffix}"));
        std::os::unix::fs::symlink(&path, &sidecar).unwrap();
        assert!(matches!(
            ScopeReviewStore::open(&path, owner(), keys().0, 1000),
            Err(Error::Storage)
        ));
        std::fs::remove_file(sidecar).unwrap();
    }
    let linked = dir.path().join("linked.db");
    std::os::unix::fs::symlink(&path, &linked).unwrap();
    assert!(matches!(
        ScopeReviewStore::open(&linked, owner(), keys().0, 1000),
        Err(Error::Storage)
    ));
    std::fs::remove_file(&linked).unwrap();
    std::fs::hard_link(&path, &linked).unwrap();
    assert!(matches!(
        ScopeReviewStore::open(&path, owner(), keys().0, 1000),
        Err(Error::Storage)
    ));
    std::fs::remove_file(&linked).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        ScopeReviewStore::open(&path, owner(), keys().0, 1000),
        Err(Error::Storage)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        ScopeReviewStore::open(&path, owner(), keys().0, 1000),
        Err(Error::Storage)
    ));
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    ScopeReviewStore::open(&path, owner(), keys().0, 1000).unwrap();
}

#[test]
fn recovery_rejects_index_state_receipt_and_owner_corruption_without_repairing_it() {
    for sql in [
        "PRAGMA user_version=2;",
        "PRAGMA user_version=0;",
        "UPDATE binding SET value='other-owner';",
        "UPDATE binding SET last_now=-1;",
        "UPDATE binding SET last_now=999;",
        "UPDATE rounds SET id='other-id';",
        "UPDATE rounds SET expires=expires+1;",
        "UPDATE rounds SET state='unknown-state';",
        "UPDATE rounds SET receipt=NULL;",
        "UPDATE rounds SET state='pending';",
        "UPDATE rounds SET state='rejected';",
        "UPDATE rounds SET receipt=json_set(receipt,'$.accepted_at',1001);",
    ] {
        let (dir, store) = fixture();
        approve(&store);
        drop(store);
        let path = dir.path().join("reviews.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(sql).unwrap();
        drop(conn);
        assert!(
            matches!(
                ScopeReviewStore::open(&path, owner(), keys().0, 1001),
                Err(Error::Storage)
            ),
            "{sql}"
        );
    }
    let (dir, store) = fixture();
    approve(&store);
    drop(store);
    let path = dir.path().join("reviews.db");
    assert!(matches!(
        ScopeReviewStore::open(
            &path,
            AuthorityOwner {
                tenant_id: "other".into(),
                ..owner()
            },
            keys().0,
            1001
        ),
        Err(Error::Storage)
    ));
    assert!(matches!(
        ScopeReviewStore::open(&path, owner(), keys().1, 1001),
        Err(Error::Storage)
    ));
    assert!(matches!(
        ScopeReviewStore::open(&path, owner(), keys().0, 999),
        Err(Error::ClockRegression)
    ));
}

#[test]
fn ledger_refuses_special_files_oversized_storage_and_negative_operational_clock() {
    use std::os::unix::ffi::OsStrExt;
    let (dir, store) = fixture();
    let review = store
        .issue(
            ReviewSubject::issuance(&grant()).unwrap(),
            &authority(),
            100,
            1000,
        )
        .unwrap();
    assert_eq!(
        store.snapshot(&review.document.round_id, &authority(), -1),
        Err(Error::ClockRegression)
    );
    assert_eq!(
        store.retained(&review.document.round_id).unwrap().state,
        RoundState::Pending
    );
    let fifo = dir.path().join("not-a-database.fifo");
    let cpath = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // O_NONBLOCK custody validation must reject this without waiting for a peer.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert!(matches!(
        ScopeReviewStore::open(&fifo, owner(), keys().0, 1000),
        Err(Error::Storage)
    ));
    let parent_file = dir.path().join("not-a-directory");
    std::fs::write(&parent_file, b"fixture").unwrap();
    assert!(matches!(
        ScopeReviewStore::open(&parent_file.join("reviews.db"), owner(), keys().0, 1000),
        Err(Error::Storage)
    ));
    let oversized = dir.path().join("oversized.db");
    let file = std::fs::File::create(&oversized).unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    file.set_len(256 * 1024 * 1024 + 1).unwrap(); // sparse fixture; no payload allocation
    assert!(matches!(
        ScopeReviewStore::open(&oversized, owner(), keys().0, 1000),
        Err(Error::Capacity)
    ));
}

#[test]
fn cryptographically_valid_receipts_must_match_retained_round_state_and_clock() {
    for corruption in ["different-round", "wrong-state", "future-acceptance"] {
        let (dir, store) = fixture();
        let (_, first) = approve(&store);
        let second = store
            .issue(
                ReviewSubject::issuance(&grant()).unwrap(),
                &authority(),
                100,
                1000,
            )
            .unwrap();
        let rejected = store
            .submit(
                &second.document.round_id,
                &sign(&second, Decision::Reject),
                &authority(),
                1001,
            )
            .unwrap();
        rejected.verify(store.broker_public_key()).unwrap();
        drop(store);
        let path = dir.path().join("reviews.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        match corruption {
            "different-round" => {
                conn.execute(
                    "UPDATE rounds SET receipt=?1 WHERE id=?2",
                    rusqlite::params![
                        serde_json::to_string(&rejected).unwrap(),
                        first.review.document.round_id
                    ],
                )
                .unwrap();
            }
            "wrong-state" => {
                conn.execute(
                    "UPDATE rounds SET state='accepted' WHERE id=?1",
                    [&second.document.round_id],
                )
                .unwrap();
            }
            _ => {
                conn.execute("UPDATE binding SET last_now=1000", [])
                    .unwrap();
            }
        }
        drop(conn);
        assert!(
            matches!(
                ScopeReviewStore::open(&path, owner(), keys().0, 1001),
                Err(Error::Storage)
            ),
            "{corruption}"
        );
    }
}
