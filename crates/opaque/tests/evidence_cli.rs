use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink};
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_opaque-evidence"))
        .args(args)
        .output()
        .unwrap()
}
fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn scope_cli_exports_stopped_state_and_rejects_live_writer_without_mutation() {
    use opaque_bounded_work::scope_store::ScopeStore;
    use opaque_core::{evidence_checkpoint as wire, scope::AuthorityOwner};
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path();
    let owner = AuthorityOwner {
        tenant_id: "tenant".into(),
        broker_id: "broker".into(),
        generation: "one".into(),
    };
    let key = root.join("producer.key");
    let public = root.join("public.json");
    assert!(
        run(&[
            "keygen",
            "--private-key",
            path(&key),
            "--public-key",
            path(&public)
        ])
        .status
        .success()
    );
    let public: Value = serde_json::from_slice(&std::fs::read(public).unwrap()).unwrap();
    let enrollment = root.join("enrollment.json");
    let trust = wire::ProducerTrust {
        schema_version: 1,
        scope: wire::Scope {
            tenant_id: "tenant".into(),
            broker_id: "broker".into(),
            generation: "one".into(),
            stream_id: "scope-ledger".into(),
        },
        key_id: public["key_id"].as_str().unwrap().into(),
        public_key: public["public_key"].as_str().unwrap().into(),
    };
    std::fs::write(&enrollment, wire::canonical(&trust).unwrap()).unwrap();
    let database = root.join("scopes.db");
    let store = ScopeStore::open(&database, owner).unwrap();
    let output = root.join("snapshot");
    let args = [
        "create-scope",
        "--database",
        path(&database),
        "--private-key",
        path(&key),
        "--enrollment",
        path(&enrollment),
        "--build-identity",
        "synthetic-test",
        "--output",
        path(&output),
    ];
    assert!(!run(&args).status.success());
    assert!(!output.exists());
    drop(store);
    let before = std::fs::read(&database).unwrap();
    let created = run(&args);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert_eq!(std::fs::read(&database).unwrap(), before);
    let result: Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(result["evidence_format"], "scope_ledger_v1");
    assert_eq!(result["approval_signatures"], "not_included");
    let checkpoint = output.join("checkpoint.json");
    let export = output.join("scope.json");
    let verify = [
        "verify",
        "--enrollment",
        path(&enrollment),
        "--checkpoint",
        path(&checkpoint),
        "--export",
        path(&export),
        "--expected-checkpoint-sha256",
        result["checkpoint_sha256"].as_str().unwrap(),
    ];
    let verified = run(&verify);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let summary: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(summary["evidence_format"], "scope_ledger_v1");
    let next = root.join("next");
    let continued = run(&[
        "create-scope",
        "--database",
        path(&database),
        "--private-key",
        path(&key),
        "--enrollment",
        path(&enrollment),
        "--build-identity",
        "synthetic-test",
        "--output",
        path(&next),
        "--previous",
        path(&checkpoint),
        "--previous-export",
        path(&export),
    ]);
    assert!(
        continued.status.success(),
        "{}",
        String::from_utf8_lossy(&continued.stderr)
    );
    assert!(
        !run(&[
            "create-scope",
            "--database",
            path(&database),
            "--private-key",
            path(&key),
            "--enrollment",
            path(&enrollment),
            "--build-identity",
            "synthetic-test",
            "--output",
            path(&root.join("invalid")),
            "--previous",
            path(&checkpoint)
        ])
        .status
        .success()
    );
    std::fs::write(&export, b"{}").unwrap();
    assert!(!run(&verify).status.success());
}

#[test]
fn key_enrollment_snapshot_verify_and_retention_request_roundtrip() {
    let directory = tempfile::tempdir().unwrap();
    let key = directory.path().join("evidence.key");
    let public = directory.path().join("public.json");
    let enrollment = directory.path().join("producer.json");
    let db = directory.path().join("audit.db");
    let output = directory.path().join("snapshot");
    let request = directory.path().join("request.json");
    let generated = run(&[
        "keygen",
        "--private-key",
        path(&key),
        "--public-key",
        path(&public),
    ]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let public_doc: Value = serde_json::from_slice(&std::fs::read(&public).unwrap()).unwrap();
    assert_eq!(std::fs::read(&key).unwrap().len(), 32);
    assert!(
        run(&[
            "enroll",
            "--public-key",
            public_doc["public_key"].as_str().unwrap(),
            "--key-id",
            public_doc["key_id"].as_str().unwrap(),
            "--tenant",
            "fixture-tenant",
            "--broker",
            "fixture-broker",
            "--stream",
            "audit",
            "--generation",
            "one",
            "--output",
            path(&enrollment)
        ])
        .status
        .success()
    );
    let sink = SqliteAuditSink::new(db.clone(), 0).unwrap();
    sink.emit(AuditEvent::new(AuditEventKind::OperationSucceeded).with_operation("synthetic.noop"));
    sink.close().unwrap();
    let created = run(&[
        "create",
        "--database",
        path(&db),
        "--private-key",
        path(&key),
        "--enrollment",
        path(&enrollment),
        "--build-identity",
        "test-build",
        "--output",
        path(&output),
    ]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let result: Value = serde_json::from_slice(&created.stdout).unwrap();
    let checkpoint = output.join("checkpoint.json");
    let export = output.join("audit.jsonl");
    let pin = result["checkpoint_sha256"].as_str().unwrap();
    let verified = run(&[
        "verify",
        "--enrollment",
        path(&enrollment),
        "--checkpoint",
        path(&checkpoint),
        "--export",
        path(&export),
        "--expected-checkpoint-sha256",
        pin,
    ]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let value: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(value["global_completeness"], "unknown");
    assert_eq!(value["independent_retention"], "not_checked");
    assert_eq!(value["checkpoint_pin"], "matched");
    assert_eq!(
        value["freshness"],
        "reference_match_only_latest_source_not_checked"
    );
    assert_eq!(value["history"], "not_checked_single_checkpoint");
    let unpinned = run(&[
        "verify",
        "--enrollment",
        path(&enrollment),
        "--checkpoint",
        path(&checkpoint),
        "--export",
        path(&export),
    ]);
    assert!(unpinned.status.success());
    let unpinned: Value = serde_json::from_slice(&unpinned.stdout).unwrap();
    assert_eq!(unpinned["checkpoint_pin"], "not_supplied");
    assert_eq!(unpinned["freshness"], "not_checked_no_checkpoint_pin");
    assert_eq!(unpinned["history"], "not_checked_single_checkpoint");
    assert!(
        run(&[
            "prepare-retention",
            "--enrollment",
            path(&enrollment),
            "--checkpoint",
            path(&checkpoint),
            "--export",
            path(&export),
            "--output",
            path(&request)
        ])
        .status
        .success()
    );
    assert_eq!(
        std::fs::read(&request).unwrap(),
        std::fs::read(output.join("retention-request.json")).unwrap()
    );
    assert!(
        !run(&[
            "verify",
            "--enrollment",
            path(&enrollment),
            "--checkpoint",
            path(&checkpoint),
            "--export",
            path(&export),
            "--expected-checkpoint-sha256",
            &"0".repeat(64)
        ])
        .status
        .success()
    );
    std::fs::write(&export, b"fabricated").unwrap();
    assert!(
        !run(&[
            "verify",
            "--enrollment",
            path(&enrollment),
            "--checkpoint",
            path(&checkpoint),
            "--export",
            path(&export)
        ])
        .status
        .success()
    );
    assert!(
        !run(&[
            "keygen",
            "--private-key",
            path(&key),
            "--public-key",
            path(&public)
        ])
        .status
        .success()
    );
}

#[test]
fn rejects_untrusted_fingerprint_and_input_symlink_without_overwriting() {
    let directory = tempfile::tempdir().unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let output = directory.path().join("trust.json");
    let public = opaque_core::evidence_checkpoint::hex(key.verifying_key().as_bytes());
    assert!(
        !run(&[
            "enroll",
            "--public-key",
            &public,
            "--key-id",
            &"0".repeat(64),
            "--tenant",
            "tenant",
            "--broker",
            "broker",
            "--stream",
            "audit",
            "--generation",
            "one",
            "--output",
            path(&output)
        ])
        .status
        .success()
    );
    assert!(!output.exists());
    let target = directory.path().join("target");
    std::fs::write(&target, b"unchanged").unwrap();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        !run(&[
            "keygen",
            "--private-key",
            path(&link),
            "--public-key",
            path(&output)
        ])
        .status
        .success()
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
}
