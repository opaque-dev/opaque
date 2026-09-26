use super::*;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
fn fixture() -> Value {
    json!({"apiVersion":API_VERSION,"kind":KIND,"metadata":{"name":"case-status","namespace":"support"},
    "spec":{"tenantRef":"example","connectorRef":"support","authority":{"operation":OPERATION,"allowedStatuses":["resolved","closed"],"maxResources":2,"maxAttempts":10,"maxDuration":"1h"},
    "approval":{"scope":"Required","reviewerRef":"ops"}}})
}
fn dispatch_fixture() -> Value {
    json!({"apiVersion":API_VERSION,"kind":KIND,"metadata":{"name":"staging-dispatch","namespace":"release"},
    "spec":{"tenantRef":"example","connectorRef":"github","authority":{"operation":DISPATCH_OPERATION,"workflows":[
        {"repository":"example-org/service","path":".github/workflows/staging.yml","ref":"main"},
        {"repository":"example-org/service","path":".github/workflows/staging.yml","ref":"release/2026-09"}],
        "maxResources":2,"maxAttempts":5,"maxDuration":"30m"},
    "approval":{"scope":"Required","reviewerRef":"ops"}}})
}
fn check(v: &Value) -> Result<CompiledPolicy, String> {
    compile(&serde_json::to_vec(v).unwrap())
}
#[test]
fn equivalent_documents_canonicalize_defaults_duration_and_order() {
    let first = check(&fixture()).unwrap();
    assert_eq!(first.policy.spec.authority.max_duration, "3600s");
    assert_eq!(
        first.policy.spec.authority.allowed_statuses,
        Some(vec![Status::Closed, Status::Resolved])
    );
    assert!(first.policy.spec.authority.workflows.is_none());
    // The support kind serializes exactly as before the dispatch kind existed.
    let canonical = serde_json::to_value(&first.policy).unwrap();
    assert_eq!(
        canonical["spec"]["authority"],
        json!({"operation":OPERATION,"allowedStatuses":["closed","resolved"],"maxResources":2,"maxAttempts":10,"maxDuration":"3600s"})
    );
    assert_eq!(
        first.policy.spec.approval.action,
        ActionApproval::EveryAction
    );
    let mut other = fixture();
    other["spec"]["authority"]["allowedStatuses"] = json!(["closed", "resolved"]);
    other["spec"]["authority"]["maxDuration"] = json!("60m");
    other["spec"]["approval"]["action"] = json!("EveryAction");
    other["spec"]["mode"] = json!("Enforce");
    other["spec"]["evaluators"] = json!([]);
    assert_eq!(check(&other).unwrap(), first);
    let yaml=b"apiVersion: policy.opaque.dev/v1alpha1\nkind: AuthorityPolicy\nmetadata: {name: case-status, namespace: support}\nspec:\n  tenantRef: example\n  connectorRef: support\n  authority:\n    operation: support.case.setStatus\n    allowedStatuses: [closed, resolved]\n    maxResources: 2\n    maxAttempts: 10\n    maxDuration: 3600s\n  approval: {scope: Required, reviewerRef: ops}\n";
    assert_eq!(compile(yaml).unwrap(), first);
    assert_eq!(
        compile(&serde_json::to_vec(&first.policy).unwrap()).unwrap(),
        first
    );
}
#[test]
fn dispatch_kind_canonicalizes_targets_and_binds_them_into_the_digest() {
    let first = check(&dispatch_fixture()).unwrap();
    let authority = &first.policy.spec.authority;
    assert_eq!(authority.operation, DISPATCH_OPERATION);
    assert!(authority.allowed_statuses.is_none());
    assert_eq!(authority.max_duration, "1800s");
    let targets = authority.workflows.as_ref().unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].git_ref, "main");
    assert_eq!(
        targets[0].resource(),
        "example-org/service:.github/workflows/staging.yml:main"
    );
    assert_eq!(
        WorkflowTarget::parse(&targets[1].resource()).unwrap(),
        targets[1]
    );
    let mut reordered = dispatch_fixture();
    reordered["spec"]["authority"]["workflows"]
        .as_array_mut()
        .unwrap()
        .reverse();
    reordered["spec"]["authority"]["maxDuration"] = json!("1800s");
    assert_eq!(check(&reordered).unwrap(), first);
    assert_eq!(
        compile(&serde_json::to_vec(&first.policy).unwrap()).unwrap(),
        first
    );
    let yaml = b"apiVersion: policy.opaque.dev/v1alpha1\nkind: AuthorityPolicy\nmetadata: {name: staging-dispatch, namespace: release}\nspec:\n  tenantRef: example\n  connectorRef: github\n  authority:\n    operation: github.workflow.dispatch\n    workflows:\n      - {repository: example-org/service, path: .github/workflows/staging.yml, ref: release/2026-09}\n      - {repository: example-org/service, path: .github/workflows/staging.yml, ref: main}\n    maxResources: 2\n    maxAttempts: 5\n    maxDuration: 30m\n  approval: {scope: Required, reviewerRef: ops}\n";
    assert_eq!(compile(yaml).unwrap(), first);
    assert_ne!(first.digest, check(&fixture()).unwrap().digest);
    for (pointer, replacement) in [
        ("/spec/authority/workflows/0/ref", json!("develop")),
        (
            "/spec/authority/workflows/0/path",
            json!(".github/workflows/production.yml"),
        ),
        (
            "/spec/authority/workflows/0/repository",
            json!("example-org/other"),
        ),
    ] {
        let mut v = dispatch_fixture();
        *v.pointer_mut(pointer).unwrap() = replacement;
        assert_ne!(check(&v).unwrap().digest, first.digest, "{pointer}");
    }
}
#[test]
fn dispatch_kind_rejects_mixed_fields_and_untyped_targets_in_schema_and_compiler() {
    let validator = jsonschema::validator_for(&json_schema()).unwrap();
    assert!(validator.is_valid(&dispatch_fixture()));
    let mut mixed = dispatch_fixture();
    mixed["spec"]["authority"]["allowedStatuses"] = json!(["closed"]);
    assert!(check(&mixed).is_err());
    assert!(!validator.is_valid(&mixed));
    let mut mixed = fixture();
    mixed["spec"]["authority"]["workflows"] =
        dispatch_fixture()["spec"]["authority"]["workflows"].clone();
    assert!(check(&mixed).is_err());
    assert!(!validator.is_valid(&mixed));
    let mut swapped = fixture();
    swapped["spec"]["authority"]["operation"] = json!(DISPATCH_OPERATION);
    assert!(check(&swapped).is_err());
    assert!(!validator.is_valid(&swapped));
    let mut swapped = dispatch_fixture();
    swapped["spec"]["authority"]["operation"] = json!(OPERATION);
    assert!(check(&swapped).is_err());
    assert!(!validator.is_valid(&swapped));
    let mut explicit_empty = dispatch_fixture();
    explicit_empty["spec"]["authority"]["allowedStatuses"] = json!([]);
    assert!(check(&explicit_empty).is_err());
    assert!(!validator.is_valid(&explicit_empty));
    // The compiler is authoritative. The portable schema rejects what a regular
    // expression can express; the git-specific refusals (a `refs/` path, `..`,
    // a bare commit SHA, a traversal component) are compiler-only.
    for (pointer, replacement, schema_rejects) in [
        ("/spec/authority/workflows", json!([]), true),
        (
            "/spec/authority/workflows/0/repository",
            json!("service"),
            true,
        ),
        (
            "/spec/authority/workflows/0/repository",
            json!("a/b/c"),
            true,
        ),
        (
            "/spec/authority/workflows/0/repository",
            json!("example-org/../service"),
            true,
        ),
        (
            "/spec/authority/workflows/0/repository",
            json!("../service"),
            false,
        ),
        (
            "/spec/authority/workflows/0/path",
            json!("staging.yml"),
            true,
        ),
        (
            "/spec/authority/workflows/0/path",
            json!(".github/workflows/nested/staging.yml"),
            true,
        ),
        (
            "/spec/authority/workflows/0/path",
            json!(".github/workflows/staging.txt"),
            true,
        ),
        ("/spec/authority/workflows/0/ref", json!(""), true),
        (
            "/spec/authority/workflows/0/ref",
            json!("refs/heads/main"),
            false,
        ),
        (
            "/spec/authority/workflows/0/ref",
            json!("main..feature"),
            false,
        ),
        (
            "/spec/authority/workflows/0/ref",
            json!("a".repeat(40)),
            false,
        ),
        ("/spec/authority/workflows/0/ref", json!("main:tag"), true),
        (
            "/spec/authority/workflows/0/ref",
            json!("release@2026"),
            true,
        ),
        ("/spec/authority/workflows/0/ref", json!(".hidden"), true),
    ] {
        let mut v = dispatch_fixture();
        *v.pointer_mut(pointer).unwrap() = replacement;
        assert!(check(&v).is_err(), "{pointer}");
        assert_eq!(!validator.is_valid(&v), schema_rejects, "{pointer}");
    }
    let mut duplicate = dispatch_fixture();
    duplicate["spec"]["authority"]["workflows"][1] =
        duplicate["spec"]["authority"]["workflows"][0].clone();
    assert!(check(&duplicate).is_err());
    assert!(!validator.is_valid(&duplicate));
    let mut unknown = dispatch_fixture();
    unknown["spec"]["authority"]["workflows"][0]["inputs"] = json!({"environment":"production"});
    assert!(check(&unknown).is_err());
    assert!(!validator.is_valid(&unknown));
    let mut wide = dispatch_fixture();
    wide["spec"]["authority"]["workflows"] = json!(
        (0..=MAX_WORKFLOWS)
            .map(|i| json!({"repository":format!("example-org/service-{i}"),"path":".github/workflows/staging.yml","ref":"main"}))
            .collect::<Vec<_>>()
    );
    assert!(check(&wide).is_err());
    assert!(!validator.is_valid(&wide));
    for resource in [
        "example-org/service",
        "example-org/service:.github/workflows/staging.yml",
        "example-org/service:.github/workflows/staging.yml:main:extra",
        "example-org/service:.github/workflows/staging.yml:refs/heads/main",
        "",
    ] {
        assert!(WorkflowTarget::parse(resource).is_err(), "{resource}");
    }
}
#[test]
fn digest_binds_every_identity_authority_and_approval_field() {
    let value = fixture();
    let digest = check(&value).unwrap().digest;
    for (pointer, replacement) in [
        ("/metadata/name", json!("other")),
        ("/metadata/namespace", json!("other")),
        ("/spec/tenantRef", json!("other")),
        ("/spec/connectorRef", json!("other")),
        ("/spec/approval/reviewerRef", json!("other")),
        ("/spec/authority/maxResources", json!(1)),
        ("/spec/authority/maxAttempts", json!(1)),
        ("/spec/authority/maxDuration", json!("2h")),
        ("/spec/authority/allowedStatuses", json!(["open"])),
        ("/spec/approval/action", json!("WithinApprovedScope")),
    ] {
        let mut v = value.clone();
        if pointer.ends_with("/action") {
            v["spec"]["approval"]["action"] = replacement;
        } else {
            *v.pointer_mut(pointer).unwrap() = replacement;
        }
        assert_ne!(check(&v).unwrap().digest, digest, "{pointer}");
    }
}
#[test]
fn schema_and_typed_validation_reject_unsupported_or_widened_policy() {
    let schema = json_schema();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&fixture()));
    for (pointer, replacement) in [
        ("/apiVersion", json!("v2")),
        ("/kind", json!("Policy")),
        ("/metadata/name", json!("")),
        ("/metadata/namespace", json!("Upper")),
        ("/spec/tenantRef", json!("a".repeat(64))),
        ("/spec/connectorRef", json!("-a")),
        ("/spec/approval/reviewerRef", json!("a-")),
        ("/spec/authority/operation", json!("arbitrary.write")),
        ("/spec/authority/maxResources", json!(0)),
        ("/spec/authority/maxResources", json!(101)),
        ("/spec/authority/maxAttempts", json!(0)),
        ("/spec/authority/maxAttempts", json!(10001)),
        ("/spec/authority/allowedStatuses", json!([])),
        ("/spec/authority/allowedStatuses", json!(["open", "open"])),
        (
            "/spec/authority/allowedStatuses",
            json!(["open", "closed", "resolved", "open"]),
        ),
        ("/spec/approval/scope", json!("None")),
    ] {
        let mut v = fixture();
        *v.pointer_mut(pointer).unwrap() = replacement;
        assert!(check(&v).is_err(), "{pointer}");
        assert!(!validator.is_valid(&v), "{pointer}");
    }
    for (field, value) in [
        ("mode", json!("Shadow")),
        ("evaluators", json!([{"name":"jev"}])),
        ("endpoint", json!("https://attacker.invalid")),
    ] {
        let mut v = fixture();
        v["spec"][field] = value;
        assert!(check(&v).is_err());
        assert!(!validator.is_valid(&v));
    }
    for object in ["", "/metadata", "/spec/authority", "/spec/approval"] {
        let mut v = fixture();
        v.pointer_mut(object)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unknown".into(), json!(true));
        assert!(check(&v).is_err());
    }
    let mut v = fixture();
    v["spec"]["approval"]
        .as_object_mut()
        .unwrap()
        .remove("scope");
    assert!(check(&v).is_err());
}
#[test]
fn duration_schema_matches_finite_validator_and_never_panics_on_unicode() {
    let validator = jsonschema::validator_for(&json_schema()).unwrap();
    for duration in [
        "1s", "86400s", "1440m", "24h", "9999s", "80000s", "86399s", "1h", "60m", "1m",
    ] {
        let mut v = fixture();
        v["spec"]["authority"]["maxDuration"] = json!(duration);
        assert!(check(&v).is_ok(), "{duration}");
        assert!(validator.is_valid(&v), "{duration}");
    }
    for duration in [
        "",
        "s",
        "0s",
        "00s",
        "01h",
        "86401s",
        "1441m",
        "25h",
        "-1s",
        "1.5h",
        "1d",
        "1💩",
        "éhs",
        "9999999s",
        "99999999s",
    ] {
        let mut v = fixture();
        v["spec"]["authority"]["maxDuration"] = json!(duration);
        assert!(check(&v).is_err(), "{duration}");
        assert!(!validator.is_valid(&v), "{duration}");
    }
}
#[test]
fn strict_parser_rejects_duplicates_aliases_tags_multidoc_and_complex_keys() {
    for bytes in [
        b"{a: 1, a: 2}".as_slice(),
        b"{\"a\":1,\"a\":2}",
        b"a: &anchor value\nb: *anchor",
        b"&a [*a]",
        b"a: !tag x",
        b"a: !!str x",
        b"!!map {a: b}",
        b"!!seq [a]",
        b"---\na: b\n---\na: b",
        b"a: b\n...\na: b",
        b"? [complex, key]\n: value",
        b"1: value",
        b"<<: {a: b}",
        b"{a:",
        b"a: [",
        b"",
        b"\xff",
    ] {
        assert!(
            compile(bytes).is_err(),
            "{:?}",
            String::from_utf8_lossy(bytes)
        );
    }
    assert!(parse::document(b"values: [true, false, null, 1, 1.5, 'true', text]").is_ok());
}
#[test]
fn byte_depth_and_node_bounds_apply_before_typed_validation() {
    assert!(compile(&vec![b' '; MAX_BYTES + 1]).is_err());
    let deep = format!("{}0{}", "[".repeat(18), "]".repeat(18));
    assert!(parse::document(deep.as_bytes()).is_err());
    let wide = format!("[{}]", vec!["x"; 4097].join(","));
    assert!(parse::document(wide.as_bytes()).is_err());
    assert!(parse::document(b"{a: {b: [c]}}").is_ok());
}
#[test]
fn projected_symlink_reads_without_private_ownership_and_bad_files_fail() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("data");
    std::fs::write(&source, serde_json::to_vec(&fixture()).unwrap()).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o444)).unwrap();
    let link = dir.path().join("policy.json");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    assert_eq!(read(&source).unwrap(), read(&link).unwrap());
    assert!(read(dir.path()).is_err());
    assert!(read(&dir.path().join("missing")).is_err());
    assert!(read_bounded(&source, 1).is_err());
    let fifo = dir.path().join("fifo");
    let name = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: CString is a valid terminated path for this call.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(read(&fifo).is_err());
}
