//! Stored-history fault injection exercises rejection, not successful recovery
//! from fabricated authority. Every mutation must leave admission unavailable.
use super::*;

type ScopeMutation = fn(&mut ScopeRecord);
type ActionMutation = fn(&mut ActionRecord);

fn history() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    let store = ScopeStore::open(&path, owner()).unwrap();
    let guard = Guard::new();
    let root = root();
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    for (name, state) in [
        ("reserved", ExecutionState::Reserved),
        ("accepted", ExecutionState::ApiAccepted),
        ("rejected", ExecutionState::Rejected),
        ("unknown", ExecutionState::Unknown),
        ("claimed", ExecutionState::DispatchClaimed),
    ] {
        let record = reserve(&store, &root, name, "r1", &guard).unwrap();
        if matches!(
            state,
            ExecutionState::ApiAccepted | ExecutionState::DispatchClaimed
        ) {
            store
                .claim_dispatch(name, &record.digest, &guard, 100)
                .unwrap();
        }
        match state {
            ExecutionState::ApiAccepted => {
                store.finish(name, Outcome::ApiAccepted, 100).unwrap();
            }
            ExecutionState::Rejected => {
                store.finish(name, Outcome::Rejected, 100).unwrap();
            }
            ExecutionState::Unknown => {
                store.finish(name, Outcome::Unknown, 100).unwrap();
            }
            _ => {}
        }
    }
    drop(store);
    (dir, path)
}

#[test]
fn completed_and_interrupted_outcomes_survive_repeated_recovery_without_refund() {
    let (_dir, path) = history();
    for _ in 0..2 {
        let store = ScopeStore::open(&path, owner()).unwrap();
        for (id, state) in [
            ("accepted", ExecutionState::ApiAccepted),
            ("rejected", ExecutionState::Rejected),
            ("unknown", ExecutionState::Unknown),
            ("reserved", ExecutionState::Unknown),
            ("claimed", ExecutionState::Unknown),
        ] {
            assert_eq!(store.get_action(id).unwrap().state, state);
        }
        assert_eq!(store.get_scope("root").unwrap().charged_attempts, 5);
        assert_eq!(
            store.get_scope("root").unwrap().charged_resources,
            BTreeSet::from(["r1".into()])
        );
        let events = store.events(0, 100).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.kind == EventKind::Interrupted)
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.kind == EventKind::AttemptFinished)
                .count(),
            3
        );
    }
}

#[test]
fn stored_scope_identity_lifetime_and_accounting_mutations_fail_closed() {
    let mutations: &[(&str, ScopeMutation)] = &[
        ("wrong row identity", |r| {
            r.grant.scope_id = "different".into()
        }),
        ("noncanonical resources", |r| r.grant.resources.reverse()),
        ("wrong digest", |r| r.digest = "b".repeat(64)),
        ("foreign owner", |r| {
            r.grant.owner.broker_id = "foreign".into();
            r.digest = r.grant.digest().unwrap();
        }),
        ("negative issue time", |r| r.issued_at = -1),
        ("future issue time", |r| r.issued_at = 101),
        ("revoked before issuance", |r| r.revoked_at = Some(99)),
        ("revoked in future", |r| r.revoked_at = Some(101)),
        ("attempt ceiling exceeded", |r| r.charged_attempts = 11),
        ("resource ceiling exceeded", |r| {
            r.charged_resources =
                BTreeSet::from(["r1".into(), "r2".into(), "r3".into(), "r4".into()])
        }),
        ("lost resource charge", |r| r.charged_resources.clear()),
        ("substituted resource charge", |r| {
            r.charged_resources = BTreeSet::from(["r2".into()])
        }),
    ];
    for (label, mutate) in mutations {
        let (_dir, path) = history();
        let connection = Connection::open(&path).unwrap();
        let mut record = load_scope(&connection, "root").unwrap();
        mutate(&mut record);
        connection
            .execute(
                "UPDATE scope_grants SET record = ?1 WHERE id = 'root'",
                [serde_json::to_string(&record).unwrap()],
            )
            .unwrap();
        drop(connection);
        assert!(ScopeStore::open(&path, owner()).is_err(), "{label}");
    }
    let (_dir, path) = history();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute("UPDATE scope_meta SET last_seen = 2000", [])
        .unwrap();
    connection
        .execute(
            "UPDATE scope_grants SET record = json_set(record, '$.issued_at', 1000)",
            [],
        )
        .unwrap();
    drop(connection);
    assert!(
        ScopeStore::open(&path, owner()).is_err(),
        "issued at expiry"
    );
}

#[test]
fn stored_action_identity_and_every_terminal_shape_are_checked() {
    let mutations: &[(&str, &str, ActionMutation)] = &[
        ("wrong action identity", "reserved", |r| {
            r.action.action_id = "other".into()
        }),
        ("wrong scope column", "reserved", |r| {
            r.action.scope_id = "other".into()
        }),
        ("wrong subject column", "reserved", |r| {
            r.action.subject = "other".into()
        }),
        ("wrong request column", "reserved", |r| {
            r.action.request_id = "other".into()
        }),
        ("noncanonical fields", "reserved", |r| {
            r.action.fields.push(FieldValue {
                field: "aaa".into(),
                value: "value".into(),
            })
        }),
        ("wrong digest", "reserved", |r| r.digest = "b".repeat(64)),
        ("future reservation", "reserved", |r| r.reserved_at = 101),
        ("reservation predates issuance", "reserved", |r| {
            r.reserved_at = 99;
            r.evidence.evaluated_at = 99;
        }),
        ("claim predates reservation", "claimed", |r| {
            r.dispatch_claimed_at = Some(99);
            r.evidence.evaluated_at = 99;
        }),
        ("claim in future", "claimed", |r| {
            r.dispatch_claimed_at = Some(101)
        }),
        ("result predates claim", "accepted", |r| {
            r.finished_at = Some(99)
        }),
        ("result in future", "accepted", |r| {
            r.finished_at = Some(101)
        }),
        ("reserved with claim", "reserved", |r| {
            r.dispatch_claimed_at = Some(100)
        }),
        ("reserved with result", "reserved", |r| {
            r.finished_at = Some(100)
        }),
        ("claimed without claim", "claimed", |r| {
            r.dispatch_claimed_at = None
        }),
        ("claimed with result", "claimed", |r| {
            r.finished_at = Some(100)
        }),
        ("accepted without claim", "accepted", |r| {
            r.dispatch_claimed_at = None
        }),
        ("accepted without result", "accepted", |r| {
            r.finished_at = None
        }),
        ("rejected without result", "rejected", |r| {
            r.finished_at = None
        }),
    ];
    for (label, id, mutate) in mutations {
        let (_dir, path) = history();
        let connection = Connection::open(&path).unwrap();
        let mut record = load_action(&connection, id).unwrap();
        mutate(&mut record);
        connection
            .execute(
                "UPDATE scope_actions SET record = ?1 WHERE id = ?2",
                params![serde_json::to_string(&record).unwrap(), id],
            )
            .unwrap();
        drop(connection);
        assert!(ScopeStore::open(&path, owner()).is_err(), "{label}");
    }
}

#[test]
fn command_boundaries_deduplication_and_failed_transitions_preserve_authority() {
    let dir = custody_dir();
    let store = ScopeStore::open(&dir.path().join("scope.db"), owner()).unwrap();
    let guard = Guard::new();
    let root = root();
    let issued = store.issue_scope(root.clone(), &guard, 100).unwrap();
    assert_eq!(
        store.issue_scope(root.clone(), &guard, 100).unwrap(),
        issued
    );
    let mut changed = root.clone();
    changed.subject = "new".into();
    assert!(matches!(
        store.issue_scope(changed, &guard, 100),
        Err(ScopeStoreError::IdempotencyConflict)
    ));
    let mut foreign = root.clone();
    foreign.owner.tenant_id = "other".into();
    assert!(matches!(
        store.issue_scope(foreign, &guard, 100),
        Err(ScopeStoreError::OwnerMismatch)
    ));
    let mut foreign = action(&root, "foreign", "r1");
    foreign.owner.generation = "other".into();
    assert!(matches!(
        store.reserve(foreign.clone(), evidence(&root, &foreign), &guard, 100),
        Err(ScopeStoreError::OwnerMismatch)
    ));
    for (after, limit) in [(0, 0), (0, 1001), (u64::MAX, 1)] {
        assert!(store.events(after, limit).is_err());
    }
    assert!(store.events(1, 1).unwrap().is_empty());
    assert!(matches!(
        store.get_scope("missing"),
        Err(ScopeStoreError::NotFound)
    ));
    assert!(matches!(
        store.finish("missing", Outcome::Unknown, 100),
        Err(ScopeStoreError::NotFound)
    ));
    reserve(&store, &root, "reserved", "r1", &guard).unwrap();
    assert!(matches!(
        store.finish("reserved", Outcome::ApiAccepted, 100),
        Err(ScopeStoreError::InvalidTransition)
    ));
    assert_eq!(
        store.get_action("reserved").unwrap().state,
        ExecutionState::Reserved
    );
    store.finish("reserved", Outcome::Unknown, 100).unwrap();
    assert_eq!(store.get_scope("root").unwrap().charged_attempts, 1);
    let revoked = store.revoke("root", 100).unwrap();
    assert_eq!(store.revoke("root", 100).unwrap(), revoked);
    assert_eq!(
        store
            .events(0, 100)
            .unwrap()
            .iter()
            .filter(|e| e.kind == EventKind::ScopeRevoked)
            .count(),
        1
    );
    let mut expired = root;
    expired.scope_id = "expired".into();
    expired.root_id = "expired".into();
    expired.expires_at = 100;
    assert!(matches!(
        store.issue_scope(expired, &guard, 100),
        Err(ScopeStoreError::Inactive)
    ));
}

#[test]
fn custody_aliases_missing_directories_and_foreign_schema_are_rejected() {
    let dir = custody_dir();
    let path = dir.path().join("new-parent/scope.db");
    let store = ScopeStore::open(&path, owner()).unwrap();
    assert_eq!(
        path.parent().unwrap().metadata().unwrap().mode() & 0o777,
        0o700
    );
    drop(store);
    let hardlink = path.with_file_name("alias.db");
    std::fs::hard_link(&path, &hardlink).unwrap();
    assert!(ScopeStore::open(&path, owner()).is_err());
    std::fs::remove_file(hardlink).unwrap();
    let symlink = path.with_file_name("symlink.db");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    assert!(ScopeStore::open(&symlink, owner()).is_err());
    for sql in [
        "PRAGMA user_version = 9",
        "PRAGMA user_version = 0",
        "DELETE FROM scope_meta",
        "ALTER TABLE scope_events RENAME TO wrong_events",
    ] {
        let dir = custody_dir();
        let path = dir.path().join("scope.db");
        drop(ScopeStore::open(&path, owner()).unwrap());
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        assert!(ScopeStore::open(&path, owner()).is_err(), "{sql}");
    }
    let dir = custody_dir();
    let path = dir.path().join("scope.db");
    std::fs::write(path.with_file_name("scope.db-journal"), []).unwrap();
    drop(ScopeStore::open(&path, owner()).unwrap());
}

fn rewrite_events(connection: &Connection, events: &[AuthorityEvent]) {
    connection.execute("DELETE FROM scope_events", []).unwrap();
    for (index, event) in events.iter().enumerate() {
        let mut event = event.clone();
        event.sequence = index as u64 + 1;
        connection
            .execute(
                "INSERT INTO scope_events VALUES (?1, ?2)",
                params![event.sequence, serde_json::to_string(&event).unwrap()],
            )
            .unwrap();
    }
}

#[test]
fn correlated_events_cannot_be_substituted_duplicated_omitted_or_reordered() {
    type EventMutation = fn(&mut Vec<AuthorityEvent>);
    let mutations: &[(&str, EventMutation)] = &[
        ("duplicate issuance", |e| {
            e.push(e[0].clone());
        }),
        ("missing issuance", |e| {
            e.remove(0);
        }),
        ("wrong action scope", |e| {
            e[1].scope_id = "missing".into();
        }),
        ("wrong action digest", |e| {
            e[1].content_digest = "b".repeat(64)
        }),
        ("wrong scope digest", |e| {
            e[0].content_digest = "b".repeat(64)
        }),
        ("event in future", |e| e[1].observed_at = Some(101)),
        ("time regressed", |e| e[1].observed_at = Some(99)),
        ("charge time absent", |e| e[1].observed_at = None),
        ("claim time absent", |e| {
            e.iter_mut()
                .find(|e| e.kind == EventKind::DispatchClaimed)
                .unwrap()
                .observed_at = None
        }),
        ("result time absent", |e| {
            e.iter_mut()
                .find(|e| e.kind == EventKind::AttemptFinished)
                .unwrap()
                .observed_at = None
        }),
        ("missing charge before claim", |e| {
            e.retain(|e| {
                !(e.action_id.as_deref() == Some("accepted") && e.kind == EventKind::AttemptCharged)
            });
        }),
        ("missing claim before result", |e| {
            e.retain(|e| {
                !(e.action_id.as_deref() == Some("accepted")
                    && e.kind == EventKind::DispatchClaimed)
            });
        }),
        ("missing final result", |e| {
            e.retain(|e| {
                !(e.action_id.as_deref() == Some("accepted")
                    && e.kind == EventKind::AttemptFinished)
            });
        }),
        ("unknown action identity", |e| {
            e[1].action_id = Some("nonexistent".into())
        }),
        ("scope event with action", |e| {
            e[0].action_id = Some("reserved".into())
        }),
        ("action event without action", |e| e[1].action_id = None),
    ];
    for (label, mutate) in mutations {
        let (_dir, path) = history();
        let store = ScopeStore::open(&path, owner()).unwrap();
        let mut events = store.events(0, 100).unwrap();
        drop(store);
        mutate(&mut events);
        let connection = Connection::open(&path).unwrap();
        rewrite_events(&connection, &events);
        drop(connection);
        assert!(ScopeStore::open(&path, owner()).is_err(), "{label}");
    }
}

#[test]
fn missing_rows_and_write_failure_do_not_silently_admit_or_refund() {
    let (_dir, path) = history();
    let store = ScopeStore::open(&path, owner()).unwrap();
    let scope = store.get_scope("root").unwrap();
    let action = store.get_action("accepted").unwrap();
    let connection = Connection::open(&path).unwrap();
    let mut nonexistent_scope = scope.clone();
    nonexistent_scope.grant.scope_id = "missing".into();
    assert!(matches!(
        save_scope(&connection, &nonexistent_scope),
        Err(ScopeStoreError::Corrupt)
    ));
    let mut nonexistent_action = action;
    nonexistent_action.action.action_id = "missing".into();
    assert!(matches!(
        save_action(&connection, &nonexistent_action),
        Err(ScopeStoreError::Corrupt)
    ));
    drop(connection);
    store
        .connection()
        .unwrap()
        .execute_batch("PRAGMA query_only = ON")
        .unwrap();
    assert!(store.revoke("root", 100).is_err());
    assert_eq!(store.get_scope("root").unwrap(), scope);
    store
        .connection()
        .unwrap()
        .execute_batch("PRAGMA query_only = OFF")
        .unwrap();
    store.revoke("root", 100).unwrap();
    assert_eq!(store.get_scope("root").unwrap().charged_attempts, 5);
}
