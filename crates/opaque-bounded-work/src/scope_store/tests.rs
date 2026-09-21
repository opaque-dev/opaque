use super::*;
mod qualification;
use opaque_core::scope::{
    FieldConstraint, FieldValue, MinimumApproval, ScopeRequirements, VERSION,
};
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicU64, Ordering},
};

struct Guard {
    revision: AtomicU64,
}
impl Guard {
    fn new() -> Self {
        Self {
            revision: AtomicU64::new(1),
        }
    }
}
impl AuthorityGuard for Guard {
    fn verify_scope(&self, _: &ScopeGrant, _: i64) -> Result<(), String> {
        Ok(())
    }
    fn verify_action(
        &self,
        _: &ScopeGrant,
        _: &PreparedAction,
        evidence: &AdmissionEvidence,
        _: i64,
    ) -> Result<(), String> {
        if evidence.authority_revision == self.revision.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err("authority changed".into())
        }
    }
}
fn custody_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn hash() -> String {
    "a".repeat(64)
}
fn owner() -> AuthorityOwner {
    AuthorityOwner {
        tenant_id: "tenant".into(),
        broker_id: "broker".into(),
        generation: "generation-1".into(),
    }
}
fn root() -> ScopeGrant {
    ScopeGrant {
        schema_version: VERSION,
        scope_id: "root".into(),
        root_id: "root".into(),
        parent_id: None,
        owner: owner(),
        issuer: "human".into(),
        subject: "agent-root".into(),
        operation: "fixture.update".into(),
        provider_profile_digest: hash(),
        resources: vec!["r1".into(), "r2".into(), "r3".into()],
        fields: vec![FieldConstraint {
            field: "status".into(),
            allowed_values: vec!["closed".into(), "open".into()],
        }],
        not_before: 50,
        expires_at: 1000,
        delegations_remaining: 2,
        max_charged_attempts: 10,
        max_distinct_resources: 3,
        requirements: ScopeRequirements {
            policy_digest: hash(),
            minimum_approval: MinimumApproval::ScopeIssuance,
            evaluator_checks: vec![],
        },
        issuance_receipt_digest: hash(),
    }
}
fn child(parent: &ScopeGrant, name: &str) -> ScopeGrant {
    let mut child = parent.clone();
    child.scope_id = name.into();
    child.parent_id = Some(parent.scope_id.clone());
    child.issuer = parent.subject.clone();
    child.subject = format!("agent-{name}");
    child.delegations_remaining -= 1;
    child
}
fn action(scope: &ScopeGrant, name: &str, resource: &str) -> PreparedAction {
    PreparedAction {
        schema_version: VERSION,
        action_id: name.into(),
        request_id: format!("request-{name}"),
        scope_id: scope.scope_id.clone(),
        scope_digest: scope.digest().unwrap(),
        owner: scope.owner.clone(),
        subject: scope.subject.clone(),
        operation: scope.operation.clone(),
        provider_profile_digest: scope.provider_profile_digest.clone(),
        resource: resource.into(),
        resource_version: "v1".into(),
        fields: vec![FieldValue {
            field: "status".into(),
            value: "closed".into(),
        }],
        evidence_digest: hash(),
    }
}
fn evidence(scope: &ScopeGrant, action: &PreparedAction) -> AdmissionEvidence {
    AdmissionEvidence {
        schema_version: VERSION,
        policy_digest: hash(),
        scope_digest: scope.digest().unwrap(),
        action_digest: action.digest().unwrap(),
        authority_revision: 1,
        evaluated_at: 100,
        expires_at: 900,
        review: None,
        evaluators: vec![],
    }
}
fn reserve(
    store: &ScopeStore,
    scope: &ScopeGrant,
    name: &str,
    resource: &str,
    guard: &Guard,
) -> Result<ActionRecord, ScopeStoreError> {
    let action = action(scope, name, resource);
    let evidence = evidence(scope, &action);
    store.reserve(action, evidence, guard, 100)
}

#[test]
fn siblings_race_for_shared_budget_without_partial_charges() {
    let dir = custody_dir();
    let store = Arc::new(ScopeStore::open(&dir.path().join("scope.db"), owner()).unwrap());
    let guard = Arc::new(Guard::new());
    let mut root = root();
    root.max_charged_attempts = 7;
    store
        .issue_scope(root.clone(), guard.as_ref(), 100)
        .unwrap();
    let children: Vec<_> = (0..10)
        .map(|n| child(&root, &format!("child-{n}")))
        .collect();
    for child in &children {
        store
            .issue_scope(child.clone(), guard.as_ref(), 100)
            .unwrap();
    }
    let barrier = Arc::new(Barrier::new(40));
    let threads: Vec<_> = (0..40)
        .map(|n| {
            let (store, guard, barrier, child) = (
                store.clone(),
                guard.clone(),
                barrier.clone(),
                children[n % 10].clone(),
            );
            std::thread::spawn(move || {
                barrier.wait();
                reserve(&store, &child, &format!("a{n}"), "r1", &guard).is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .filter(|t| t.thread().id() != std::thread::current().id())
            .map(|t| u64::from(t.join().unwrap()))
            .sum::<u64>(),
        7
    );
    assert_eq!(store.get_scope("root").unwrap().charged_attempts, 7);
    assert_eq!(
        children
            .iter()
            .map(|c| store.get_scope(&c.scope_id).unwrap().charged_attempts)
            .sum::<u64>(),
        7
    );
    assert_eq!(
        store.get_scope("root").unwrap().charged_resources,
        BTreeSet::from(["r1".into()])
    );
}

#[test]
fn distinct_resource_limit_counts_once_and_denial_does_not_charge_children() {
    let dir = custody_dir();
    let store = ScopeStore::open(&dir.path().join("scope.db"), owner()).unwrap();
    let guard = Guard::new();
    let mut root = root();
    root.max_distinct_resources = 1;
    let child = child(&root, "child");
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    store.issue_scope(child.clone(), &guard, 100).unwrap();
    reserve(&store, &child, "a1", "r1", &guard).unwrap();
    reserve(&store, &child, "a2", "r1", &guard).unwrap();
    assert!(matches!(
        reserve(&store, &child, "a3", "r2", &guard),
        Err(ScopeStoreError::BudgetExceeded)
    ));
    for id in ["root", "child"] {
        let record = store.get_scope(id).unwrap();
        assert_eq!(record.charged_attempts, 2);
        assert_eq!(record.charged_resources.len(), 1);
    }
    assert!(matches!(
        store.get_action("a3"),
        Err(ScopeStoreError::NotFound)
    ));
}

#[test]
fn duplicates_conflict_and_dispatch_claim_is_single_use() {
    let dir = custody_dir();
    let store = ScopeStore::open(&dir.path().join("scope.db"), owner()).unwrap();
    let guard = Guard::new();
    let root = root();
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    let reserved = reserve(&store, &root, "a1", "r1", &guard).unwrap();
    assert_eq!(
        reserve(&store, &root, "a1", "r1", &guard).unwrap(),
        reserved
    );
    assert!(matches!(
        reserve(&store, &root, "a1", "r2", &guard),
        Err(ScopeStoreError::IdempotencyConflict)
    ));
    let mut changed = reserved.action.clone();
    changed.action_id = "a2".into();
    assert!(matches!(
        store.reserve(changed.clone(), evidence(&root, &changed), &guard, 100),
        Err(ScopeStoreError::IdempotencyConflict)
    ));
    assert!(matches!(
        store.claim_dispatch("a1", &"b".repeat(64), &guard, 100),
        Err(ScopeStoreError::IdempotencyConflict)
    ));
    store
        .claim_dispatch("a1", &reserved.digest, &guard, 100)
        .unwrap();
    assert!(matches!(
        store.claim_dispatch("a1", &reserved.digest, &guard, 100),
        Err(ScopeStoreError::Consumed)
    ));
    store.finish("a1", Outcome::ApiAccepted, 101).unwrap();
    assert!(matches!(
        store.finish("a1", Outcome::ApiAccepted, 101),
        Err(ScopeStoreError::InvalidTransition)
    ));
    assert_eq!(store.get_scope("root").unwrap().charged_attempts, 1);
}

#[test]
fn ancestor_revocation_orders_against_charge_and_claim() {
    let dir = custody_dir();
    let store = ScopeStore::open(&dir.path().join("scope.db"), owner()).unwrap();
    let guard = Guard::new();
    let root = root();
    let child_grant = child(&root, "child");
    let grandchild = child(&child_grant, "grandchild");
    for scope in [&root, &child_grant, &grandchild] {
        store.issue_scope(scope.clone(), &guard, 100).unwrap();
    }
    let a = reserve(&store, &grandchild, "before", "r1", &guard).unwrap();
    let b = reserve(&store, &grandchild, "inflight", "r1", &guard).unwrap();
    store
        .claim_dispatch("inflight", &b.digest, &guard, 100)
        .unwrap();
    store.revoke("root", 100).unwrap();
    assert!(matches!(
        store.claim_dispatch("before", &a.digest, &guard, 100),
        Err(ScopeStoreError::Inactive)
    ));
    assert!(matches!(
        reserve(&store, &grandchild, "after", "r1", &guard),
        Err(ScopeStoreError::Inactive)
    ));
    store.finish("before", Outcome::Rejected, 100).unwrap();
    store.finish("inflight", Outcome::ApiAccepted, 100).unwrap();
    for id in ["root", "child", "grandchild"] {
        assert_eq!(store.get_scope(id).unwrap().charged_attempts, 2);
    }
}

#[test]
fn current_authority_and_expiry_are_rechecked_without_refunding() {
    let dir = custody_dir();
    let store = ScopeStore::open(&dir.path().join("scope.db"), owner()).unwrap();
    let guard = Guard::new();
    let root = root();
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    let a = reserve(&store, &root, "a1", "r1", &guard).unwrap();
    guard.revision.store(2, Ordering::SeqCst);
    assert!(matches!(
        store.claim_dispatch("a1", &a.digest, &guard, 101),
        Err(ScopeStoreError::Authority(_))
    ));
    guard.revision.store(1, Ordering::SeqCst);
    assert!(matches!(
        store.claim_dispatch("a1", &a.digest, &guard, 900),
        Err(ScopeStoreError::Validation(ScopeError::Evidence))
    ));
    assert!(matches!(
        store.claim_dispatch("a1", &a.digest, &guard, 899),
        Err(ScopeStoreError::ClockRollback)
    ));
    assert_eq!(store.get_scope("root").unwrap().charged_attempts, 1);
}

#[test]
fn restart_marks_reserved_and_claimed_unknown_without_reopening() {
    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    let guard = Guard::new();
    let root = root();
    let store = ScopeStore::open(&path, owner()).unwrap();
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    let a = reserve(&store, &root, "reserved", "r1", &guard).unwrap();
    let b = reserve(&store, &root, "claimed", "r2", &guard).unwrap();
    store
        .claim_dispatch("claimed", &b.digest, &guard, 100)
        .unwrap();
    assert!(matches!(
        ScopeStore::open(&path, owner()),
        Err(ScopeStoreError::Locked)
    ));
    drop(store);
    let store = ScopeStore::open(&path, owner()).unwrap();
    for record in [&a, &b] {
        let recovered = store.get_action(&record.action.action_id).unwrap();
        assert_eq!(recovered.state, ExecutionState::Unknown);
        assert_eq!(recovered.finished_at, None);
        assert!(matches!(
            store.claim_dispatch(&record.action.action_id, &record.digest, &guard, 100),
            Err(ScopeStoreError::Consumed)
        ));
    }
    assert_eq!(store.get_scope("root").unwrap().charged_attempts, 2);
    assert_eq!(
        store
            .events(0, 100)
            .unwrap()
            .iter()
            .filter(|e| e.kind == EventKind::Interrupted)
            .count(),
        2
    );
    drop(store);
    let store = ScopeStore::open(&path, owner()).unwrap();
    assert_eq!(store.events(0, 100).unwrap().len(), 6);
}

#[test]
fn invalid_child_owner_guard_and_schema_never_create_authority() {
    struct Reject;
    impl AuthorityGuard for Reject {
        fn verify_scope(&self, _: &ScopeGrant, _: i64) -> Result<(), String> {
            Err("no issuance receipt".into())
        }
        fn verify_action(
            &self,
            _: &ScopeGrant,
            _: &PreparedAction,
            _: &AdmissionEvidence,
            _: i64,
        ) -> Result<(), String> {
            Err("no receipt".into())
        }
    }
    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    let store = ScopeStore::open(&path, owner()).unwrap();
    let guard = Guard::new();
    let root = root();
    assert!(matches!(
        store.issue_scope(root.clone(), &Reject, 100),
        Err(ScopeStoreError::Authority(_))
    ));
    assert!(store.events(0, 100).unwrap().is_empty());
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    let mut child = child(&root, "child");
    child.resources.push("outside".into());
    assert!(matches!(
        store.issue_scope(child, &guard, 100),
        Err(ScopeStoreError::Validation(ScopeError::NotSubset))
    ));
    let action = action(&root, "a1", "r1");
    assert!(matches!(
        store.reserve(action.clone(), evidence(&root, &action), &Reject, 100),
        Err(ScopeStoreError::Authority(_))
    ));
    assert_eq!(store.get_scope("root").unwrap().charged_attempts, 0);
    drop(store);
    let mut wrong = owner();
    wrong.generation = "generation-2".into();
    assert!(matches!(
        ScopeStore::open(&path, wrong),
        Err(ScopeStoreError::OwnerMismatch)
    ));
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TRIGGER unexpected AFTER UPDATE ON scope_meta BEGIN DELETE FROM scope_actions; END;").unwrap();
    drop(connection);
    assert!(matches!(
        ScopeStore::open(&path, owner()),
        Err(ScopeStoreError::Corrupt)
    ));
}

#[test]
fn corruption_missing_history_and_broad_custody_fail_closed() {
    for modification in [
        "UPDATE scope_grants SET record = json_set(record, '$.charged_attempts', 0)",
        "DELETE FROM scope_events WHERE sequence = (SELECT MAX(sequence) FROM scope_events)",
        "DROP TABLE scope_actions",
    ] {
        let dir = custody_dir();
        let path = dir.path().join("scope.db");
        let guard = Guard::new();
        let root = root();
        let store = ScopeStore::open(&path, owner()).unwrap();
        store.issue_scope(root.clone(), &guard, 100).unwrap();
        reserve(&store, &root, "a1", "r1", &guard).unwrap();
        drop(store);
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(modification).unwrap();
        drop(connection);
        assert!(ScopeStore::open(&path, owner()).is_err(), "{modification}");
    }
    let dir = custody_dir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        ScopeStore::open(&dir.path().join("scope.db"), owner()),
        Err(ScopeStoreError::Corrupt)
    ));
}

#[test]
fn final_claim_and_revoke_concurrency_has_one_ordered_winner() {
    for run in 0..16 {
        let dir = custody_dir();
        let store = Arc::new(ScopeStore::open(&dir.path().join("scope.db"), owner()).unwrap());
        let guard = Arc::new(Guard::new());
        let root = root();
        store
            .issue_scope(root.clone(), guard.as_ref(), 100)
            .unwrap();
        let reserved = reserve(&store, &root, "a1", "r1", &guard).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let (s, g, b) = (store.clone(), guard.clone(), barrier.clone());
        let claim = std::thread::spawn(move || {
            b.wait();
            s.claim_dispatch("a1", &reserved.digest, g.as_ref(), 100)
                .is_ok()
        });
        barrier.wait();
        store.revoke("root", 100).unwrap();
        let claimed = claim.join().unwrap();
        let events = store.events(0, 100).unwrap();
        let revoked = events
            .iter()
            .find(|e| e.kind == EventKind::ScopeRevoked)
            .unwrap()
            .sequence;
        let dispatch = events.iter().find(|e| e.kind == EventKind::DispatchClaimed);
        assert_eq!(claimed, dispatch.is_some(), "run {run}");
        if let Some(dispatch) = dispatch {
            assert!(dispatch.sequence < revoked);
        }
        assert_eq!(store.get_scope("root").unwrap().charged_attempts, 1);
    }
}

#[test]
fn reopen_rejects_review_expired_before_claim_and_reordered_revocation() {
    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    let store = ScopeStore::open(&path, owner()).unwrap();
    let guard = Guard::new();
    let root = root();
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    let action = action(&root, "a1", "r1");
    let mut evidence = evidence(&root, &action);
    evidence.review = Some(opaque_core::scope::ReviewBinding {
        schema_version: VERSION,
        case_id: "case".into(),
        case_revision: 1,
        action_id: action.action_id.clone(),
        action_digest: action.digest().unwrap(),
        scope_digest: root.digest().unwrap(),
        evidence_digest: hash(),
        policy_digest: hash(),
        round_id: "round".into(),
        decision_receipt_digest: hash(),
        expires_at: 105,
    });
    let reserved = store.reserve(action, evidence, &guard, 100).unwrap();
    store
        .claim_dispatch("a1", &reserved.digest, &guard, 104)
        .unwrap();
    drop(store);
    let connection = Connection::open(&path).unwrap();
    connection.execute("UPDATE scope_actions SET record = json_set(record, '$.evidence.review.expires_at', 102)", []).unwrap();
    drop(connection);
    assert!(ScopeStore::open(&path, owner()).is_err());

    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    let store = ScopeStore::open(&path, owner()).unwrap();
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    let reserved = reserve(&store, &root, "a1", "r1", &guard).unwrap();
    store
        .claim_dispatch("a1", &reserved.digest, &guard, 100)
        .unwrap();
    store.revoke("root", 100).unwrap();
    drop(store);
    let connection = Connection::open(&path).unwrap();
    let claim: String = connection
        .query_row(
            "SELECT record FROM scope_events WHERE sequence = 3",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let revoke: String = connection
        .query_row(
            "SELECT record FROM scope_events WHERE sequence = 4",
            [],
            |r| r.get(0),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE scope_events SET record = json_set(?1, '$.sequence', 3) WHERE sequence = 3",
            [revoke],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE scope_events SET record = json_set(?1, '$.sequence', 4) WHERE sequence = 4",
            [claim],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        ScopeStore::open(&path, owner()),
        Err(ScopeStoreError::Corrupt)
    ));
}

#[test]
fn reopen_rejects_child_issued_before_parent_activation() {
    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    let store = ScopeStore::open(&path, owner()).unwrap();
    let guard = Guard::new();
    let mut root = root();
    root.not_before = 500;
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    let child = child(&root, "child");
    assert!(matches!(
        store.issue_scope(child.clone(), &guard, 100),
        Err(ScopeStoreError::Inactive)
    ));
    store.issue_scope(child, &guard, 500).unwrap();
    drop(store);
    let connection = Connection::open(&path).unwrap();
    connection.execute("UPDATE scope_grants SET record = json_set(record, '$.issued_at', 100) WHERE id = 'child'", []).unwrap();
    connection.execute("UPDATE scope_events SET record = json_set(record, '$.observed_at', 100) WHERE sequence = 2", []).unwrap();
    drop(connection);
    assert!(matches!(
        ScopeStore::open(&path, owner()),
        Err(ScopeStoreError::Corrupt)
    ));
}
