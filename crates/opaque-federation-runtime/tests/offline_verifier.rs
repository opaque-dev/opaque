//! Exercise independent structural inspection and signed custody against real exports.
//! Synthetic records only; the verifier never receives the audit HMAC key.
use std::path::PathBuf;
use std::process::Command;

use ed25519_dalek::SigningKey;
use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink};
use opaque_core::evidence_checkpoint as evidence;
use opaque_federation_runtime::export::{
    ApprovalDetector, Finding, deliver_spool, read_rows_after,
};

#[test]
fn standalone_verifier_accepts_production_export_and_detects_truncated_delivery() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("audit.db");
    let spool = temp.path().join("audit.jsonl");
    let checkpoint = temp.path().join("checkpoint.json");
    let sink = SqliteAuditSink::new(db.clone(), 90).unwrap();
    for kind in [
        AuditEventKind::RequestReceived,
        AuditEventKind::ApprovalRequired,
        AuditEventKind::ApprovalGranted,
        AuditEventKind::OperationSucceeded,
    ] {
        sink.emit(
            AuditEvent::new(kind)
                .with_operation("test.noop")
                .with_outcome("synthetic")
                .with_detail("offline verifier compatibility ✓"),
        );
    }
    sink.close().unwrap();
    let rows = read_rows_after(&db, 0, 100).unwrap();
    assert_eq!(rows.len(), 4);
    deliver_spool(&spool, &rows).unwrap();
    // Real at-least-once delivery may replay an older batch after the new tail.
    deliver_spool(&spool, &rows[..2]).unwrap();
    let verifier =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/verify_audit_evidence.py");
    let created = Command::new("python3")
        .arg("-B")
        .arg(&verifier)
        .arg("checkpoint")
        .arg(&spool)
        .args(["--source-id", "synthetic-rust-export", "--output"])
        .arg(&checkpoint)
        .output()
        .unwrap();
    assert!(created.status.success(), "{:?}", created);
    let created: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    let pin = created["checkpoint_sha256"].as_str().unwrap();
    let verify = || {
        Command::new("python3")
            .arg("-B")
            .arg(&verifier)
            .arg("verify")
            .arg(&spool)
            .arg("--checkpoint")
            .arg(&checkpoint)
            .args(["--trusted-checkpoint-sha256", pin])
            .output()
            .unwrap()
    };
    let verified = verify();
    assert!(verified.status.success(), "{:?}", verified);
    let report: serde_json::Value = serde_json::from_slice(&verified.stdout).unwrap();
    assert_eq!(report["record_count"], 4);
    assert_eq!(report["duplicate_count"], 2);
    assert_eq!(report["audit_hmac"], "not_verified");
    // Delete a full final delivery: structural framing alone cannot detect it.
    let exported = std::fs::read_to_string(&spool).unwrap();
    let truncated: String = exported
        .lines()
        .take(5)
        .map(|line| format!("{line}\n"))
        .collect();
    std::fs::write(&spool, truncated).unwrap();
    let rejected = verify();
    assert_eq!(rejected.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
    assert_eq!(report["error"], "checkpoint_export_mismatch");
}

#[test]
fn actual_retained_export_has_signed_custody_and_deterministic_findings() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("audit.db");
    let initial = SqliteAuditSink::new(db.clone(), 0).unwrap();
    let mut old = AuditEvent::new(AuditEventKind::RequestReceived);
    old.ts_utc_ms = 1;
    initial.emit(old);
    initial.close().unwrap();
    let sink = SqliteAuditSink::new(db.clone(), 1).unwrap(); // authenticated prefix retention
    let request = AuditEvent::new(AuditEventKind::RequestReceived).event_id;
    let approval = AuditEvent::new(AuditEventKind::ApprovalRequired).event_id;
    for kind in [
        AuditEventKind::ApprovalRequired,
        AuditEventKind::OperationSucceeded,
    ] {
        sink.emit(
            AuditEvent::new(kind)
                .with_request_id(request)
                .with_approval_id(approval)
                .with_request_hash("a".repeat(64))
                .with_operation("test.noop"),
        );
    }
    sink.close().unwrap();
    let rows = read_rows_after(&db, 0, 100).unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows[0].sequence_number > 0);
    let mut detector = ApprovalDetector::default();
    let findings: Vec<_> = rows
        .iter()
        .flat_map(|row| detector.observe_findings(row))
        .collect();
    let expected = Finding::new("approval_missing", &rows[1], Some(rows[0].sequence_number));
    assert_eq!(findings, vec![expected]);
    assert_eq!(detector.health["prefix_unobserved"], 1);
    assert_eq!(detector.pending_count(), 0);

    let key = SigningKey::from_bytes(&[17; 32]); // synthetic fixture key, never production custody
    let trust = evidence::ProducerTrust {
        schema_version: 1,
        scope: evidence::Scope {
            tenant_id: "synthetic-tenant".into(),
            broker_id: "synthetic-broker".into(),
            stream_id: "audit".into(),
            generation: "fixture-1".into(),
        },
        key_id: evidence::key_id(&key.verifying_key()),
        public_key: evidence::hex(key.verifying_key().as_bytes()),
    };
    let (checkpoint, export) =
        evidence::create_checkpoint(&db, &trust, &key, None, "synthetic-build".into()).unwrap();
    let (repeated, repeated_export) =
        evidence::create_checkpoint(&db, &trust, &key, None, "synthetic-build".into()).unwrap();
    assert_eq!(checkpoint, repeated);
    assert_eq!(export, repeated_export);
    assert_eq!(checkpoint.payload.record_count, 2);
    assert_eq!(
        checkpoint.payload.coverage_start,
        Some(rows[0].sequence_number as u64)
    );
    let verified = evidence::verify_checkpoint(&checkpoint, &trust, &export).unwrap();
    assert_eq!(verified.export_sha256, evidence::sha256(&export));
    // The signed snapshot is one exact retained range, not the replaying SIEM spool.
    let truncated = &export[..export.len() - 1];
    assert!(evidence::verify_checkpoint(&checkpoint, &trust, truncated).is_err());
    let mut forged = checkpoint;
    forged.signature = "00".repeat(64);
    assert!(evidence::verify_checkpoint(&forged, &trust, &export).is_err());
}
