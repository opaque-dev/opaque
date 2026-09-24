#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Offline evidence custody tools. Every source and destination is explicit.
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use opaque_core::evidence_checkpoint::*;
use serde::de::DeserializeOwned;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

#[derive(Parser)]
#[command(
    about = "Verify scoped producer evidence and independent retention receipts; no global completeness claim"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a dedicated evidence key. Private bytes are never printed.
    Keygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Enroll a public key and independently checked fingerprint for one stream.
    Enroll {
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        broker: String,
        #[arg(long)]
        stream: String,
        #[arg(long)]
        generation: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify the local audit snapshot, then sign/export its exact bytes.
    Create {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        enrollment: PathBuf,
        #[arg(long)]
        previous: Option<PathBuf>,
        #[arg(long)]
        build_identity: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Export a stopped scope ledger without recovery or mutation, then sign it.
    CreateScope {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        enrollment: PathBuf,
        /// Previous checkpoint and its exact export are required together.
        #[arg(long, requires = "previous_export")]
        previous: Option<PathBuf>,
        #[arg(long, requires = "previous")]
        previous_export: Option<PathBuf>,
        #[arg(long)]
        build_identity: String,
        #[arg(long)]
        output: PathBuf,
    },
    Verify {
        #[arg(long)]
        enrollment: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        export: PathBuf,
        #[arg(long)]
        expected_checkpoint_sha256: Option<String>,
    },
    /// Verify a scope export and the retained historical human-review signatures.
    VerifyScopeReviews {
        #[arg(long)]
        enrollment: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        export: PathBuf,
        /// JSON array of retained scope DecisionReceipts, never private keys.
        #[arg(long)]
        receipts: PathBuf,
        /// Independently enrolled review broker key, not a key from the receipts.
        #[arg(long)]
        broker_public_key: String,
        #[arg(long)]
        expected_checkpoint_sha256: Option<String>,
    },
    /// Verify first, then prepare the typed request; sends nothing externally.
    PrepareRetention {
        #[arg(long)]
        enrollment: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        export: PathBuf,
        #[arg(long)]
        expected_checkpoint_sha256: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
    VerifyReceipt {
        #[arg(long)]
        enrollment: PathBuf,
        #[arg(long)]
        custodian_enrollment: PathBuf,
        #[arg(long)]
        checkpoint: PathBuf,
        #[arg(long)]
        export: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        now_unix_ms: i64,
        #[arg(long)]
        expected_receipt_sha256: Option<String>,
    },
    /// Inspect only: today's digest is not an independently trusted historical pin.
    LegacyInspect {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Offline, old writers stopped: upgrade only against a previously trusted export.
    UpgradeLegacy {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        trusted_export_sha256: String,
    },
}

fn read(path: &Path, limit: usize, private: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || (private
            && (metadata.permissions().mode() & 0o077 != 0
                || metadata.uid() != unsafe { libc::geteuid() }))
    {
        return Err("input must be a regular file with appropriate private custody".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        if private {
            bytes.zeroize();
        }
        return Err("input exceeds limit".into());
    }
    Ok(bytes)
}

fn document<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn std::error::Error>> {
    Ok(decode(&read(path, MAX_DOCUMENT_BYTES, false)?)?)
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn pinned(actual: &str, expected: Option<&str>) -> Result<(), EvidenceError> {
    if let Some(expected) = expected {
        unhex::<32>(expected)?;
        if actual != expected {
            return Err(EvidenceError("independent pin mismatch"));
        }
    }
    Ok(())
}

fn verified(
    enrollment: &Path,
    checkpoint: &Path,
    export: &Path,
    pin: Option<&str>,
) -> Result<(SignedCheckpoint, VerifiedCheckpoint), Box<dyn std::error::Error>> {
    let trust: ProducerTrust = document(enrollment)?;
    let checkpoint: SignedCheckpoint = document(checkpoint)?;
    let result = verify_checkpoint(&checkpoint, &trust, &read(export, MAX_EXPORT_BYTES, false)?)?;
    pinned(&result.checkpoint_sha256, pin)?;
    Ok((checkpoint, result))
}

fn run(cli: Cli) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Keygen {
            private_key,
            public_key,
        } => {
            if private_key.exists() || public_key.exists() {
                return Err("key destination already exists".into());
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut seed[..]).map_err(|_| "key generation failed")?;
            let key = SigningKey::from_bytes(&seed);
            write(&private_key, &seed[..])?;
            let trust = CustodianTrust {
                schema_version: 1,
                key_id: key_id(&key.verifying_key()),
                public_key: hex(key.verifying_key().as_bytes()),
            };
            write(&public_key, &canonical(&trust)?)?;
            Ok(serde_json::json!({"ok":true,"key_id":trust.key_id,"public_key":trust.public_key}))
        }
        Command::Enroll {
            public_key,
            key_id: expected_id,
            tenant,
            broker,
            stream,
            generation,
            output,
        } => {
            let key = VerifyingKey::from_bytes(&unhex(&public_key)?)?;
            if key_id(&key) != expected_id {
                return Err("independently checked key fingerprint mismatch".into());
            }
            let trust = ProducerTrust {
                schema_version: 1,
                scope: Scope {
                    tenant_id: tenant,
                    broker_id: broker,
                    stream_id: stream,
                    generation,
                },
                key_id: expected_id,
                public_key,
            };
            trust.verifying_key()?;
            write(&output, &canonical(&trust)?)?;
            Ok(
                serde_json::json!({"ok":true,"trust":"caller_enrolled_public_key","key_id":trust.key_id}),
            )
        }
        Command::Create {
            database,
            private_key,
            enrollment,
            previous,
            build_identity,
            output,
        } => {
            let trust: ProducerTrust = document(&enrollment)?;
            let bytes = Zeroizing::new(read(&private_key, 32, true)?);
            let seed: &[u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid private key length")?;
            let key = SigningKey::from_bytes(seed);
            let previous: Option<SignedCheckpoint> =
                previous.as_deref().map(document).transpose()?;
            let (checkpoint, export) =
                create_checkpoint(&database, &trust, &key, previous.as_ref(), build_identity)?;
            std::fs::DirBuilder::new().mode(0o700).create(&output)?;
            // On failure preserve the partial directory for explicit inspection;
            // never retry/overwrite it or remove files supplied by another caller.
            write(&output.join("audit.jsonl"), &export)?;
            write(&output.join("checkpoint.json"), &canonical(&checkpoint)?)?;
            write(
                &output.join("retention-request.json"),
                &canonical(&retention_request(&checkpoint)?)?,
            )?;
            File::open(&output)?.sync_all()?;
            Ok(
                serde_json::json!({"ok":true,"checkpoint_sha256":checkpoint_digest(&checkpoint)?,"export_sha256":checkpoint.payload.export_sha256,"scope":"authenticated_instrumented_snapshot","global_completeness":"unknown","authority_recovery":"not_established"}),
            )
        }
        Command::CreateScope {
            database,
            private_key,
            enrollment,
            previous,
            previous_export,
            build_identity,
            output,
        } => {
            let trust: ProducerTrust = document(&enrollment)?;
            let bytes = Zeroizing::new(read(&private_key, 32, true)?);
            let seed: &[u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid private key length")?;
            let key = SigningKey::from_bytes(seed);
            let prior: Option<SignedCheckpoint> = previous.as_deref().map(document).transpose()?;
            let prior_export = previous_export
                .as_deref()
                .map(|p| read(p, MAX_EXPORT_BYTES, false))
                .transpose()?;
            let previous = match (&prior, &prior_export) {
                (Some(checkpoint), Some(export)) => Some((checkpoint, export.as_slice())),
                (None, None) => None,
                _ => return Err("previous checkpoint and export are required together".into()),
            };
            let owner = opaque_core::scope::AuthorityOwner {
                tenant_id: trust.scope.tenant_id.clone(),
                broker_id: trust.scope.broker_id.clone(),
                generation: trust.scope.generation.clone(),
            };
            let evidence =
                opaque_bounded_work::scope_store::ScopeStore::export_stopped(&database, &owner)?;
            let (checkpoint, export) =
                create_scope_checkpoint(&evidence, &trust, &key, previous, build_identity)?;
            std::fs::DirBuilder::new().mode(0o700).create(&output)?;
            write(&output.join("scope.json"), &export)?;
            write(&output.join("checkpoint.json"), &canonical(&checkpoint)?)?;
            write(
                &output.join("retention-request.json"),
                &canonical(&retention_request(&checkpoint)?)?,
            )?;
            File::open(&output)?.sync_all()?;
            Ok(
                serde_json::json!({"ok":true,"checkpoint_sha256":checkpoint_digest(&checkpoint)?,"export_sha256":checkpoint.payload.export_sha256,
                "evidence_format":"scope_ledger_v1","scope_count":evidence.scopes.len(),"action_count":evidence.actions.len(),"event_count":evidence.events.len(),
                "scope":"retained_single_owner_ledger","approval_signatures":"not_included","provider_effects":"not_established","global_completeness":"unknown","authority_recovery":"not_established"}),
            )
        }
        Command::Verify {
            enrollment,
            checkpoint,
            export,
            expected_checkpoint_sha256,
        } => {
            let (checkpoint, result) = verified(
                &enrollment,
                &checkpoint,
                &export,
                expected_checkpoint_sha256.as_deref(),
            )?;
            Ok(
                serde_json::json!({"ok":true,"checkpoint_sha256":result.checkpoint_sha256,"export_sha256":result.export_sha256,"producer":"matches_enrolled_public_key","evidence_format":if checkpoint.payload.schema_version == SCOPE_CHECKPOINT_VERSION { "scope_ledger_v1" } else { "audit_jsonl_v1" },"checkpoint_pin":if expected_checkpoint_sha256.is_some() { "matched" } else { "not_supplied" },"freshness":if expected_checkpoint_sha256.is_some() { "reference_match_only_latest_source_not_checked" } else { "not_checked_no_checkpoint_pin" },"history":"not_checked_single_checkpoint","independent_retention":"not_checked","global_completeness":"unknown"}),
            )
        }
        Command::VerifyScopeReviews {
            enrollment,
            checkpoint,
            export,
            receipts,
            broker_public_key,
            expected_checkpoint_sha256,
        } => {
            let trust: ProducerTrust = document(&enrollment)?;
            let checkpoint: SignedCheckpoint = document(&checkpoint)?;
            if checkpoint.payload.schema_version != SCOPE_CHECKPOINT_VERSION {
                return Err("requires a scope checkpoint".into());
            }
            let bytes = read(&export, MAX_EXPORT_BYTES, false)?;
            let result = verify_checkpoint(&checkpoint, &trust, &bytes)?;
            pinned(
                &result.checkpoint_sha256,
                expected_checkpoint_sha256.as_deref(),
            )?;
            let evidence = opaque_core::scope_evidence::ScopeEvidence::decode(&bytes)?;
            let receipts: Vec<opaque_core::scope_review::DecisionReceipt> =
                serde_json::from_slice(&read(&receipts, MAX_EXPORT_BYTES, false)?)?;
            unhex::<32>(&broker_public_key)?;
            evidence.verify_reviews(&receipts, &broker_public_key)?;
            Ok(
                serde_json::json!({"ok":true,"checkpoint_sha256":result.checkpoint_sha256,"export_sha256":result.export_sha256,
                "review_signatures":"verified_historical_bindings","human_presence":"not_established","current_authority":"not_established",
                "checkpoint_pin":if expected_checkpoint_sha256.is_some(){"matched"}else{"not_supplied"},"global_completeness":"unknown"}),
            )
        }
        Command::PrepareRetention {
            enrollment,
            checkpoint,
            export,
            expected_checkpoint_sha256,
            output,
        } => {
            let (checkpoint, _) = verified(
                &enrollment,
                &checkpoint,
                &export,
                expected_checkpoint_sha256.as_deref(),
            )?;
            write(&output, &canonical(&retention_request(&checkpoint)?)?)?;
            Ok(serde_json::json!({"ok":true,"delivery":"not_attempted"}))
        }
        Command::VerifyReceipt {
            enrollment,
            custodian_enrollment,
            checkpoint,
            export,
            receipt,
            now_unix_ms,
            expected_receipt_sha256,
        } => {
            let (checkpoint, _) = verified(&enrollment, &checkpoint, &export, None)?;
            let trust: CustodianTrust = document(&custodian_enrollment)?;
            let receipt: SignedRetentionReceipt = document(&receipt)?;
            verify_retention_receipt(&receipt, &trust, &checkpoint, now_unix_ms)?;
            let digest = receipt_digest(&receipt)?;
            pinned(&digest, expected_receipt_sha256.as_deref())?;
            Ok(
                serde_json::json!({"ok":true,"receipt_sha256":digest,"retention":"signed_custodian_commitment","physical_independence":"not_established_by_signature","global_completeness":"unknown"}),
            )
        }
        Command::LegacyInspect { database, output } => {
            let bytes = opaque_core::audit::checkpoint::inspect_legacy_export(&database)?;
            write(&output, &bytes)?;
            Ok(
                serde_json::json!({"ok":true,"export_sha256":sha256(&bytes),"trust":"current_local_inspection_only_not_a_historical_anchor"}),
            )
        }
        Command::UpgradeLegacy {
            database,
            trusted_export_sha256,
        } => {
            opaque_core::audit::checkpoint::upgrade_legacy_head(&database, &trusted_export_sha256)?;
            Ok(
                serde_json::json!({"ok":true,"audit_head_format":1,"authority_restore":"not_performed"}),
            )
        }
    }
}

fn main() {
    match run(Cli::parse()) {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("opaque-evidence: {error}");
            std::process::exit(2);
        }
    }
}
