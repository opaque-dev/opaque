//! Public-core reproduction with synthetic identities, signatures and provider
//! effects. Uses real review/authority stores and a real SIGKILL. No network,
//! enterprise source, native human-presence claim or production credentials.
use ed25519_dalek::SigningKey;
use opaque_approval::scope_review::{CurrentAuthority, ScopeReviewStore};
use opaque_bounded_work::scope_store::{
    AuthorityGuard, ExecutionState, Outcome, ScopeStore, ScopeStoreError,
};
use opaque_core::{
    evidence_checkpoint as wire,
    identity::now_unix,
    scope::*,
    scope_review::{
        Decision, DecisionReceipt, EMPTY_RECEIPT_DIGEST, ReviewAuthority, ReviewSubject,
        ReviewerDecision,
    },
};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Barrier},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const WORKERS: usize = 16;
const BUDGET: u64 = 4;

fn owner() -> AuthorityOwner {
    AuthorityOwner {
        tenant_id: "synthetic-tenant".into(),
        broker_id: "synthetic-broker".into(),
        generation: "1".into(),
    }
}
fn key() -> Result<SigningKey> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)?;
    Ok(SigningKey::from_bytes(&bytes))
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
struct ReviewedAuthority {
    reviews: ScopeReviewStore,
    current: CurrentAuthority,
    receipt: DecisionReceipt,
}
impl AuthorityGuard for ReviewedAuthority {
    fn verify_scope(&self, grant: &ScopeGrant, now: i64) -> std::result::Result<(), String> {
        self.reviews
            .revalidate_scope(grant, &self.receipt, &self.current, now)
            .map_err(|e| e.to_string())
    }
    fn verify_action(
        &self,
        grant: &ScopeGrant,
        _: &PreparedAction,
        _: &AdmissionEvidence,
        now: i64,
    ) -> std::result::Result<(), String> {
        self.verify_scope(grant, now)
    }
}

fn worker(root: &Path) -> Result<()> {
    let now = now_unix();
    let broker_key = key()?;
    let reviewer_key = key()?;
    let broker_public = wire::hex(broker_key.verifying_key().as_bytes());
    write_new(
        &root.join("review-broker-public-key.txt"),
        broker_public.as_bytes(),
    )?;
    let reviews = ScopeReviewStore::open(&root.join("reviews.db"), owner(), broker_key, now)?;
    let draft = ScopeGrant {
        schema_version: 1,
        scope_id: "shared-run".into(),
        root_id: "shared-run".into(),
        parent_id: None,
        owner: owner(),
        issuer: "synthetic-requester".into(),
        subject: "synthetic-requester".into(),
        operation: "synthetic.case.set_status".into(),
        provider_profile_digest: wire::sha256(b"synthetic-local-provider"),
        resources: vec!["case-1".into()],
        fields: vec![FieldConstraint {
            field: "status".into(),
            allowed_values: vec!["resolved".into()],
        }],
        not_before: now,
        expires_at: now + 600,
        delegations_remaining: 0,
        max_charged_attempts: BUDGET,
        max_distinct_resources: 1,
        requirements: ScopeRequirements {
            policy_digest: wire::sha256(b"synthetic-policy"),
            minimum_approval: MinimumApproval::ScopeIssuance,
            evaluator_checks: vec![],
        },
        issuance_receipt_digest: EMPTY_RECEIPT_DIGEST.into(),
    };
    // This example deliberately substitutes an immutable synthetic identity
    // source. Production hosts must fence their changing identity/policy state.
    let current = CurrentAuthority::new(ReviewAuthority {
        owner: owner(),
        requester_id: draft.subject.clone(),
        reviewer_id: "synthetic-reviewer".into(),
        device_id: "synthetic-device".into(),
        reviewer_public_key: wire::hex(reviewer_key.verifying_key().as_bytes()),
        required_role: "approver".into(),
        policy_digest: draft.requirements.policy_digest.clone(),
        authority_epoch: 1,
        enrollment_epoch: 1,
    })?;
    let review = reviews.issue(ReviewSubject::issuance(&draft)?, &current, 300, now)?;
    // Synthetic signing, explicitly not a native human review ceremony.
    let decision = ReviewerDecision::sign(
        &review,
        &broker_public,
        &reviewer_key,
        Decision::Approve,
        now,
    )?;
    let receipt = reviews.submit(&review.document.round_id, &decision, &current, now)?;
    let grant = reviews.materialize_scope(&receipt, &current, now)?;
    write_new(
        &root.join("review-receipts.json"),
        &serde_json::to_vec(&vec![&receipt])?,
    )?;
    let authority = Arc::new(ReviewedAuthority {
        reviews,
        current,
        receipt,
    });
    let store = Arc::new(ScopeStore::open(&root.join("scopes.db"), owner())?);
    store.issue_scope(grant.clone(), authority.as_ref(), now)?;
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut threads = Vec::new();
    let request_ids = request_ids(Some(&root.join("request-ids.json")))?;
    for (i, request_id) in request_ids.into_iter().enumerate() {
        let (store, authority, barrier, grant) = (
            store.clone(),
            authority.clone(),
            barrier.clone(),
            grant.clone(),
        );
        threads.push(std::thread::spawn(move || {
            let action = PreparedAction {
                schema_version: 1,
                action_id: format!("action-{i:02}"),
                request_id,
                scope_id: grant.scope_id.clone(),
                scope_digest: grant.digest().unwrap(),
                owner: owner(),
                subject: grant.subject.clone(),
                operation: grant.operation.clone(),
                provider_profile_digest: grant.provider_profile_digest.clone(),
                resource: "case-1".into(),
                resource_version: "synthetic-v1".into(),
                fields: vec![FieldValue {
                    field: "status".into(),
                    value: "resolved".into(),
                }],
                evidence_digest: wire::sha256(b"synthetic-before-state"),
            };
            let evidence = AdmissionEvidence {
                schema_version: 1,
                policy_digest: grant.requirements.policy_digest.clone(),
                scope_digest: grant.digest().unwrap(),
                action_digest: action.digest().unwrap(),
                authority_revision: 1,
                evaluated_at: now,
                expires_at: grant.expires_at,
                review: None,
                evaluators: vec![],
            };
            barrier.wait();
            store.reserve(action, evidence, authority.as_ref(), now)
        }));
    }
    let mut admitted = Vec::new();
    let mut denied = 0;
    for thread in threads {
        match thread.join().map_err(|_| "worker thread panicked")? {
            Ok(record) => admitted.push(record),
            Err(ScopeStoreError::BudgetExceeded) => denied += 1,
            Err(error) => return Err(error.into()),
        }
    }
    admitted.sort_by(|a, b| a.action.action_id.cmp(&b.action.action_id));
    assert_eq!(admitted.len(), BUDGET as usize);
    assert_eq!(denied, WORKERS - BUDGET as usize);
    println!(
        "SYNTHETIC: {WORKERS} concurrent proposals, {} charged, {denied} budget denials",
        admitted.len()
    );
    for (i, record) in admitted.iter().take(3).enumerate() {
        store.claim_dispatch(
            &record.action.action_id,
            &record.digest,
            authority.as_ref(),
            now_unix(),
        )?;
        // A durable synthetic effect marker stands in for the provider write.
        // It is not an HTTP connector or a real business effect.
        write_new(
            &root.join(format!("synthetic-effect-{i}.json")),
            &serde_json::to_vec(&record.action)?,
        )?;
        if i < 2 {
            store.finish(
                &record.action.action_id,
                if i == 0 {
                    Outcome::ApiAccepted
                } else {
                    Outcome::Unknown
                },
                now_unix(),
            )?;
        }
    }
    store.revoke(&grant.scope_id, now_unix())?;
    assert!(matches!(
        store.claim_dispatch(
            &admitted[3].action.action_id,
            &admitted[3].digest,
            authority.as_ref(),
            now_unix()
        ),
        Err(ScopeStoreError::Inactive)
    ));
    write_new(
        &root.join("before-crash.json"),
        &store.export_evidence()?.encode()?,
    )?;
    println!("CRASH_READY");
    std::io::stdout().flush()?;
    // The parent kills this actual process while it owns both durable stores.
    loop {
        std::thread::park();
    }
}

fn request_ids(path: Option<&Path>) -> Result<Vec<String>> {
    let ids = if let Some(path) = path {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err("request IDs must be a regular JSON file".into());
        }
        let mut bytes = Vec::new();
        file.take(16385).read_to_end(&mut bytes)?;
        if bytes.len() > 16384 {
            return Err("request IDs exceed 16 KiB".into());
        }
        serde_json::from_slice(&bytes)?
    } else {
        (0..WORKERS)
            .map(|i| format!("worker-{i:02}/action-1"))
            .collect::<Vec<String>>()
    };
    let unique: std::collections::BTreeSet<_> = ids.iter().collect();
    if ids.len() != WORKERS
        || unique.len() != WORKERS
        || ids.iter().any(|id| {
            id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_:/".contains(&b))
        })
    {
        return Err("expected sixteen distinct bounded request identifiers".into());
    }
    Ok(ids)
}

fn run(root: &Path, correlation: Option<&Path>) -> Result<()> {
    if !root.is_absolute() {
        return Err("output path must be absolute and new".into());
    }
    let request_ids = request_ids(correlation)?;
    fs::DirBuilder::new().mode(0o700).create(root)?;
    write_new(
        &root.join("request-ids.json"),
        &serde_json::to_vec(&request_ids)?,
    )?;
    println!("SYNTHETIC PUBLIC-CORE REPRODUCTION: no native human ceremony or live provider");
    let mut child = Command::new(std::env::current_exe()?)
        .arg("--worker")
        .arg(root)
        .stdout(Stdio::piped())
        .spawn()?;
    let output = child.stdout.take().ok_or("worker output unavailable")?;
    let mut ready = false;
    for line in BufReader::new(output).lines() {
        let line = line?;
        if line == "CRASH_READY" {
            ready = true;
            break;
        }
        println!("{line}");
    }
    if !ready {
        let status = child.wait()?;
        return Err(format!("worker stopped before crash boundary: {status}").into());
    }
    child.kill()?;
    let status = child.wait()?;
    use std::os::unix::process::ExitStatusExt;
    if status.signal() != Some(libc::SIGKILL) {
        return Err("worker was not terminated with SIGKILL".into());
    }
    println!("Killed the producer after dispatch; restarting the ledger.");
    let before = opaque_core::scope_evidence::ScopeEvidence::decode(&fs::read(
        root.join("before-crash.json"),
    )?)?;
    let store = ScopeStore::open(&root.join("scopes.db"), owner())?;
    let after = store.export_evidence()?;
    after.validate_extension(&before)?;
    assert_eq!(after.scopes[0].charged_attempts, BUDGET);
    assert!(after.scopes[0].revoked_at.is_some());
    assert_eq!(
        after
            .actions
            .iter()
            .filter(|a| a.state == ExecutionState::Unknown)
            .count(),
        3
    );
    assert_eq!(
        after
            .actions
            .iter()
            .filter(|a| a.state == ExecutionState::ApiAccepted)
            .count(),
        1
    );
    let receipts: Vec<DecisionReceipt> =
        serde_json::from_slice(&fs::read(root.join("review-receipts.json"))?)?;
    after.verify_reviews(
        &receipts,
        &fs::read_to_string(root.join("review-broker-public-key.txt"))?,
    )?;
    let producer = key()?;
    let trust = wire::ProducerTrust {
        schema_version: 1,
        scope: wire::Scope {
            tenant_id: owner().tenant_id,
            broker_id: owner().broker_id,
            stream_id: "scope-ledger".into(),
            generation: "1".into(),
        },
        key_id: wire::key_id(&producer.verifying_key()),
        public_key: wire::hex(producer.verifying_key().as_bytes()),
    };
    let (first, first_bytes) = wire::create_scope_checkpoint(
        &before,
        &trust,
        &producer,
        None,
        "synthetic-example".into(),
    )?;
    let (checkpoint, bytes) = wire::create_scope_checkpoint(
        &after,
        &trust,
        &producer,
        Some((&first, &first_bytes)),
        "synthetic-example".into(),
    )?;
    wire::verify_checkpoint(&checkpoint, &trust, &bytes)?;
    write_new(&root.join("producer.json"), &wire::canonical(&trust)?)?;
    write_new(
        &root.join("before-checkpoint.json"),
        &wire::canonical(&first)?,
    )?;
    write_new(
        &root.join("checkpoint.json"),
        &wire::canonical(&checkpoint)?,
    )?;
    write_new(&root.join("scope.json"), &bytes)?;
    let mut corrupted = bytes.clone();
    corrupted.push(b' ');
    assert!(wire::verify_checkpoint(&checkpoint, &trust, &corrupted).is_err());
    println!(
        "{}",
        json!({"synthetic":true,"charged_attempts":BUDGET,"unknown":3,"api_accepted":1,"scope_revoked":true,
        "crash":"SIGKILL","review_signatures":"verified_synthetic","human_presence":"not_exercised","provider_effects":"synthetic_local_files",
        "corruption_rejected":true,"checkpoint_sha256":wire::checkpoint_digest(&checkpoint)?,"artifacts":root})
    );
    Ok(())
}
fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let result = match args.as_slice() {
        [mode, path] if mode == "--worker" => worker(Path::new(path)),
        [path] => run(Path::new(path), None),
        [path, option, ids] if option == "--request-ids" => {
            run(Path::new(path), Some(Path::new(ids)))
        }
        _ => {
            Err("usage: scope-recovery /absolute/new-output-directory [--request-ids FILE]".into())
        }
    };
    if let Err(error) = result {
        eprintln!("scope-recovery: {error}");
        std::process::exit(1);
    }
}
