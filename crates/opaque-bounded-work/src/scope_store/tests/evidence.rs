use super::*;
use opaque_core::{evidence_checkpoint as wire, scope_evidence::ScopeEvidence};

fn trust() -> (ed25519_dalek::SigningKey, wire::ProducerTrust) {
    let key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
    let owner = owner();
    let trust = wire::ProducerTrust {
        schema_version: 1,
        scope: wire::Scope {
            tenant_id: owner.tenant_id,
            broker_id: owner.broker_id,
            generation: owner.generation,
            stream_id: "scope-ledger".into(),
        },
        key_id: wire::key_id(&key.verifying_key()),
        public_key: wire::hex(key.verifying_key().as_bytes()),
    };
    (key, trust)
}

#[test]
fn complete_export_survives_restart_and_verifies_outside_the_store() {
    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    let store = ScopeStore::open(&path, owner()).unwrap();
    let guard = Guard::new();
    let mut grant = root();
    grant.max_charged_attempts = 50;
    store.issue_scope(grant.clone(), &guard, 100).unwrap();
    for i in 0..41 {
        let action = action(&grant, &format!("a{i:03}"), "r1");
        let evidence = evidence(&grant, &action);
        store
            .reserve(action.clone(), evidence, &guard, 101)
            .unwrap();
        store
            .claim_dispatch(&action.action_id, &action.digest().unwrap(), &guard, 101)
            .unwrap();
    }
    let pending = store.export_evidence().unwrap();
    assert_eq!(pending.actions.len(), 41);
    assert_eq!(pending.events.len(), 83);
    assert!(matches!(
        ScopeStore::export_stopped(&path, &owner()),
        Err(ScopeStoreError::Locked)
    ));
    drop(store);
    // Export itself must not rewrite interrupted actions or the database.
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        ScopeStore::export_stopped(&path, &owner()).unwrap(),
        pending
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let store = ScopeStore::open(&path, owner()).unwrap();
    store.revoke(&grant.scope_id, 103).unwrap();
    let recovered = store.export_evidence().unwrap();
    assert_eq!(recovered.actions.len(), 41);
    assert!(
        recovered
            .actions
            .iter()
            .all(|a| a.state == ExecutionState::Unknown)
    );
    assert_eq!(recovered.scopes[0].charged_attempts, 41);
    recovered.validate_extension(&pending).unwrap();
    let (key, trust) = trust();
    let (first, first_export) =
        wire::create_scope_checkpoint(&pending, &trust, &key, None, "test-fixture".into()).unwrap();
    let (second, export) = wire::create_scope_checkpoint(
        &recovered,
        &trust,
        &key,
        Some((&first, &first_export)),
        "test-fixture".into(),
    )
    .unwrap();
    assert_eq!(second.payload.record_count, 125);
    wire::verify_checkpoint(&second, &trust, &export).unwrap();
    let decoded = ScopeEvidence::decode(&export).unwrap();
    assert_eq!(decoded, recovered);
    assert!(
        wire::create_scope_checkpoint(
            &pending,
            &trust,
            &key,
            Some((&second, &export)),
            "rollback".into()
        )
        .is_err()
    );
    let mut corrupted = export.clone();
    corrupted[0] ^= 1;
    assert!(wire::verify_checkpoint(&second, &trust, &corrupted).is_err());
    let mut wrong_trust = trust.clone();
    wrong_trust.scope.generation = "other-generation".into();
    assert!(wire::verify_checkpoint(&second, &wrong_trust, &export).is_err());
}

#[test]
fn offline_checks_reject_refunds_omissions_and_rewritten_consumed_outcomes() {
    let dir = custody_dir();
    let store = ScopeStore::open(&dir.path().join("scope.db"), owner()).unwrap();
    let guard = Guard::new();
    let grant = root();
    store.issue_scope(grant.clone(), &guard, 100).unwrap();
    let action = action(&grant, "a1", "r1");
    store
        .reserve(action.clone(), evidence(&grant, &action), &guard, 101)
        .unwrap();
    store
        .claim_dispatch(&action.action_id, &action.digest().unwrap(), &guard, 102)
        .unwrap();
    store
        .finish(&action.action_id, Outcome::Unknown, 103)
        .unwrap();
    let snapshot = store.export_evidence().unwrap();
    let mut refund = snapshot.clone();
    refund.scopes[0].charged_attempts = 0;
    assert!(refund.validate().is_err());
    let mut omitted = snapshot.clone();
    omitted.actions.clear();
    assert!(omitted.validate().is_err());
    let mut gap = snapshot.clone();
    gap.events.remove(1);
    assert!(gap.validate().is_err());
    let mut duplicate = snapshot.clone();
    duplicate.actions.push(duplicate.actions[0].clone());
    assert!(duplicate.validate().is_err());
    let mut rewritten = snapshot.clone();
    rewritten.actions[0].state = ExecutionState::ApiAccepted;
    // A single producer statement can be internally consistent and still lie.
    rewritten.validate().unwrap();
    assert!(rewritten.validate_extension(&snapshot).is_err());
    let (key, trust) = trust();
    let (prior, prior_bytes) =
        wire::create_scope_checkpoint(&snapshot, &trust, &key, None, "fixture".into()).unwrap();
    assert!(
        wire::create_scope_checkpoint(
            &rewritten,
            &trust,
            &key,
            Some((&prior, &prior_bytes)),
            "fixture".into()
        )
        .is_err()
    );
}

#[test]
fn stopped_export_refuses_foreign_custody_missing_database_and_sql_aliases() {
    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    assert!(ScopeStore::export_stopped(&path, &owner()).is_err());
    assert!(!path.exists());
    drop(ScopeStore::open(&path, owner()).unwrap());
    let mut foreign = owner();
    foreign.tenant_id = "foreign".into();
    assert!(matches!(
        ScopeStore::export_stopped(&path, &foreign),
        Err(ScopeStoreError::OwnerMismatch)
    ));
    let alias = dir.path().join("alias.db");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(ScopeStore::export_stopped(&alias, &owner()).is_err());
    std::fs::remove_file(&alias).unwrap();
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(ScopeStore::export_stopped(&path, &owner()).is_err());
}

#[test]
fn stopped_export_refuses_missing_lock_unsafe_sidecars_and_unknown_schema_without_repair() {
    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    drop(ScopeStore::open(&path, owner()).unwrap());
    let lock = dir.path().join("scope.db.writer.lock");
    std::fs::remove_file(&lock).unwrap();
    assert!(ScopeStore::export_stopped(&path, &owner()).is_err());
    assert!(!lock.exists(), "export must never recreate missing custody");
    std::fs::write(&lock, []).unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    for suffix in ["-journal", "-wal", "-shm"] {
        let sidecar = dir.path().join(format!("scope.db{suffix}"));
        std::os::unix::fs::symlink(&path, &sidecar).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(ScopeStore::export_stopped(&path, &owner()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(sidecar.is_symlink());
        std::fs::remove_file(&sidecar).unwrap();
    }
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ScopeStore::export_stopped(&path, &owner()).is_err());
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA user_version = 999")
        .unwrap();
    drop(connection);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        ScopeStore::export_stopped(&path, &owner()),
        Err(ScopeStoreError::Corrupt)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn retained_review_signatures_bind_the_actual_scope_and_exact_charged_action() {
    use opaque_core::scope::{MinimumApproval, ReviewBinding};
    use opaque_core::scope_review::*;
    let broker = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
    let reviewer = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let broker_key = wire::hex(broker.verifying_key().as_bytes());
    let mut grant = root();
    grant.requirements.minimum_approval = MinimumApproval::ExactAction;
    grant.issuer = grant.subject.clone();
    let authority = ReviewAuthority {
        owner: owner(),
        requester_id: grant.subject.clone(),
        reviewer_id: "human".into(),
        device_id: "synthetic-reviewer".into(),
        reviewer_public_key: wire::hex(reviewer.verifying_key().as_bytes()),
        required_role: "approver".into(),
        policy_digest: grant.requirements.policy_digest.clone(),
        authority_epoch: 1,
        enrollment_epoch: 1,
    };
    let signed_receipt = |subject, round: &str| {
        let document = ReviewDocument::new(
            round.into(),
            "a".repeat(64),
            100,
            300,
            authority.clone(),
            subject,
        )
        .unwrap();
        let review = SignedReview::sign(document, &broker).unwrap();
        let decision =
            ReviewerDecision::sign(&review, &broker_key, &reviewer, Decision::Approve, 100)
                .unwrap();
        DecisionReceipt::sign(review, decision, 100, &broker).unwrap()
    };
    let issuance = signed_receipt(
        ReviewSubject::issuance(&grant).unwrap(),
        "00000000-0000-4000-8000-000000000001",
    );
    grant.issuance_receipt_digest = issuance.digest().unwrap();
    let action = action(&grant, "action-1", "r1");
    let exact = signed_receipt(
        ReviewSubject::exact_action(&grant, &action, "case-1".into(), 1).unwrap(),
        "00000000-0000-4000-8000-000000000002",
    );
    let mut admission = evidence(&grant, &action);
    admission.review = Some(ReviewBinding {
        schema_version: 1,
        case_id: "case-1".into(),
        case_revision: 1,
        action_id: action.action_id.clone(),
        action_digest: action.digest().unwrap(),
        scope_digest: grant.digest().unwrap(),
        evidence_digest: action.evidence_digest.clone(),
        policy_digest: grant.requirements.policy_digest.clone(),
        round_id: exact.review.document.round_id.clone(),
        decision_receipt_digest: exact.digest().unwrap(),
        expires_at: 300,
    });
    let dir = custody_dir();
    let store = ScopeStore::open(&dir.path().join("scope.db"), owner()).unwrap();
    store.issue_scope(grant, &Guard::new(), 100).unwrap();
    store
        .reserve(action, admission, &Guard::new(), 101)
        .unwrap();
    let export = store.export_evidence().unwrap();
    let receipts = [issuance, exact];
    export.verify_reviews(&receipts, &broker_key).unwrap();
    assert!(export.verify_reviews(&receipts[..1], &broker_key).is_err());
    assert!(
        export
            .verify_reviews(&receipts, &wire::hex(reviewer.verifying_key().as_bytes()))
            .is_err()
    );
    let mut tampered = receipts.clone();
    tampered[1].response.signature = "0".repeat(128);
    assert!(export.verify_reviews(&tampered, &broker_key).is_err());
    let mut changed_case = export.clone();
    changed_case.actions[0]
        .evidence
        .review
        .as_mut()
        .unwrap()
        .case_revision = 2;
    changed_case.validate().unwrap();
    assert!(changed_case.verify_reviews(&receipts, &broker_key).is_err());
}
