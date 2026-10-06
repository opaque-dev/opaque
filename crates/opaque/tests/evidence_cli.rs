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
fn scope_review_cli_verifies_signed_export_and_rejects_forged_receipt() {
    use std::os::unix::fs::PermissionsExt;

    use opaque_approval::scope_review::{CurrentAuthority, ScopeReviewStore};
    use opaque_bounded_work::scope_store::{AuthorityGuard, ScopeStore};
    use opaque_core::{
        evidence_checkpoint as wire,
        scope::{
            AdmissionEvidence, AuthorityOwner, FieldConstraint, MinimumApproval, PreparedAction,
            ScopeGrant, ScopeRequirements,
        },
        scope_review::{
            Decision, DecisionReceipt, EMPTY_RECEIPT_DIGEST, ReviewAuthority, ReviewSubject,
            ReviewerDecision,
        },
    };

    struct ReviewedAuthority {
        store: ScopeReviewStore,
        current: CurrentAuthority,
        receipt: DecisionReceipt,
    }
    impl AuthorityGuard for ReviewedAuthority {
        fn verify_scope(&self, grant: &ScopeGrant, now: i64) -> Result<(), String> {
            self.store
                .revalidate_scope(grant, &self.receipt, &self.current, now)
                .map_err(|error| error.to_string())
        }
        fn verify_action(
            &self,
            grant: &ScopeGrant,
            _: &PreparedAction,
            _: &AdmissionEvidence,
            now: i64,
        ) -> Result<(), String> {
            self.verify_scope(grant, now)
        }
    }

    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = directory.path();
    let owner = AuthorityOwner {
        tenant_id: "synthetic-tenant".into(),
        broker_id: "synthetic-broker".into(),
        generation: "one".into(),
    };
    let broker = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
    let reviewer = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let broker_public = wire::hex(broker.verifying_key().as_bytes());
    let draft = ScopeGrant {
        schema_version: 1,
        scope_id: "scope-1".into(),
        root_id: "scope-1".into(),
        parent_id: None,
        owner: owner.clone(),
        issuer: "requester".into(),
        subject: "requester".into(),
        operation: "synthetic.case.set_status".into(),
        provider_profile_digest: "1".repeat(64),
        resources: vec!["case-1".into()],
        fields: vec![FieldConstraint {
            field: "status".into(),
            allowed_values: vec!["resolved".into()],
        }],
        not_before: 1000,
        expires_at: 2000,
        delegations_remaining: 0,
        max_charged_attempts: 4,
        max_distinct_resources: 1,
        requirements: ScopeRequirements {
            policy_digest: "2".repeat(64),
            minimum_approval: MinimumApproval::ScopeIssuance,
            evaluator_checks: vec![],
        },
        issuance_receipt_digest: EMPTY_RECEIPT_DIGEST.into(),
    };
    let current = CurrentAuthority::new(ReviewAuthority {
        owner: owner.clone(),
        requester_id: draft.subject.clone(),
        reviewer_id: "synthetic-reviewer".into(),
        device_id: "synthetic-device".into(),
        reviewer_public_key: wire::hex(reviewer.verifying_key().as_bytes()),
        required_role: "approver".into(),
        policy_digest: draft.requirements.policy_digest.clone(),
        authority_epoch: 1,
        enrollment_epoch: 1,
    })
    .unwrap();
    let reviews =
        ScopeReviewStore::open(&root.join("reviews.db"), owner.clone(), broker, 1000).unwrap();
    let review = reviews
        .issue(
            ReviewSubject::issuance(&draft).unwrap(),
            &current,
            100,
            1000,
        )
        .unwrap();
    let decision =
        ReviewerDecision::sign(&review, &broker_public, &reviewer, Decision::Approve, 1000)
            .unwrap();
    let receipt = reviews
        .submit(&review.document.round_id, &decision, &current, 1000)
        .unwrap();
    let grant = reviews.materialize_scope(&receipt, &current, 1000).unwrap();
    let authority = ReviewedAuthority {
        store: reviews,
        current,
        receipt: receipt.clone(),
    };
    let store = ScopeStore::open(&root.join("scopes.db"), owner.clone()).unwrap();
    store.issue_scope(grant, &authority, 1000).unwrap();
    let evidence = store.export_evidence().unwrap();
    let producer = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
    let trust = wire::ProducerTrust {
        schema_version: 1,
        scope: wire::Scope {
            tenant_id: owner.tenant_id,
            broker_id: owner.broker_id,
            stream_id: "scope-ledger".into(),
            generation: owner.generation,
        },
        key_id: wire::key_id(&producer.verifying_key()),
        public_key: wire::hex(producer.verifying_key().as_bytes()),
    };
    let (checkpoint, export) =
        wire::create_scope_checkpoint(&evidence, &trust, &producer, None, "synthetic-test".into())
            .unwrap();
    let enrollment_path = root.join("producer.json");
    let checkpoint_path = root.join("checkpoint.json");
    let export_path = root.join("scope.json");
    let receipts_path = root.join("receipts.json");
    let pin = wire::checkpoint_digest(&checkpoint).unwrap();
    std::fs::write(&enrollment_path, wire::canonical(&trust).unwrap()).unwrap();
    std::fs::write(&checkpoint_path, wire::canonical(&checkpoint).unwrap()).unwrap();
    std::fs::write(&export_path, &export).unwrap();
    std::fs::write(&receipts_path, serde_json::to_vec(&[&receipt]).unwrap()).unwrap();
    let args = [
        "verify-scope-reviews",
        "--enrollment",
        path(&enrollment_path),
        "--checkpoint",
        path(&checkpoint_path),
        "--export",
        path(&export_path),
        "--receipts",
        path(&receipts_path),
        "--broker-public-key",
        &broker_public,
        "--expected-checkpoint-sha256",
        &pin,
    ];
    let verified = run(&args);
    assert!(verified.status.success(), "{verified:?}");
    let result: Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["review_signatures"], "verified_historical_bindings");

    let mut forged = receipt;
    forged.response.signature = "0".repeat(128);
    std::fs::write(&receipts_path, serde_json::to_vec(&[forged]).unwrap()).unwrap();
    let refused = run(&args);
    assert!(!refused.status.success(), "forged review was accepted");
    assert_eq!(std::fs::read(&export_path).unwrap(), export);
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
