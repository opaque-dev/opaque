use super::*;

#[test]
fn bounded_projection_retains_totals_and_request_identity() {
    let dir = custody_dir();
    let store = ScopeStore::open(&dir.path().join("scopes.db"), owner()).unwrap();
    let guard = Guard::new();
    let root = root();
    store.issue_scope(root.clone(), &guard, 100).unwrap();
    let child = child(&root, "child");
    store.issue_scope(child.clone(), &guard, 101).unwrap();
    let action = action(&child, "first", "r1");
    let record = store
        .reserve(action.clone(), evidence(&child, &action), &guard, 102)
        .unwrap();
    assert_eq!(
        store
            .get_request(&child.scope_id, &child.subject, &action.request_id)
            .unwrap(),
        record
    );
    for (scope, subject, request) in [
        ("other", child.subject.as_str(), action.request_id.as_str()),
        (child.scope_id.as_str(), "other", action.request_id.as_str()),
        (child.scope_id.as_str(), child.subject.as_str(), "other"),
    ] {
        assert!(matches!(
            store.get_request(scope, subject, request),
            Err(ScopeStoreError::NotFound)
        ));
    }
    let projection = store.snapshot(1).unwrap();
    assert_eq!(projection["scopes_total"], 2);
    assert_eq!(projection["actions_total"], 1);
    assert_eq!(projection["events_total"], 3);
    assert_eq!(projection["scopes"][0]["grant"]["scope_id"], "child");
    assert_eq!(projection["events"][0]["sequence"], 3);
    assert_eq!(projection["scopes"].as_array().unwrap().len(), 1);
    for limit in [0, 101] {
        assert!(store.snapshot(limit).is_err());
    }
}
