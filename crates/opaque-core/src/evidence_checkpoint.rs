//! Portable producer checkpoints and independent retention receipts.
//! Signatures authenticate a declared instrumented range, never global completeness,
//! real-world effects, or the freshness of an authorization-store restore.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const MAX_EXPORT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
/// Checkpoint v1 signs audit JSONL; v2 signs a complete ScopeEvidence JSON
/// document. The version is signed and selects a distinct signature domain.
pub const SCOPE_CHECKPOINT_VERSION: u32 = 2;

#[derive(Debug, thiserror::Error)]
#[error("evidence validation failed: {0}")]
pub struct EvidenceError(pub &'static str);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub tenant_id: String,
    pub broker_id: String,
    pub stream_id: String,
    pub generation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerTrust {
    pub schema_version: u32,
    pub scope: Scope,
    pub key_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    pub first_sequence: u64,
    pub last_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub schema_version: u32,
    pub scope: Scope,
    pub key_id: String,
    pub checkpoint_sequence: u64,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub record_count: u64,
    pub export_sha256: String,
    pub previous_checkpoint_sha256: Option<String>,
    pub build_identity: String,
    pub coverage_start: Option<u64>,
    pub gaps: Vec<CoverageGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub payload: Checkpoint,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodianTrust {
    pub schema_version: u32,
    pub key_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionReceipt {
    pub schema_version: u32,
    pub custodian_key_id: String,
    pub scope: Scope,
    pub checkpoint_sha256: String,
    pub export_sha256: String,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub record_count: u64,
    pub object_id: String,
    pub object_version: String,
    pub previous_receipt_sha256: Option<String>,
    pub received_at_unix_ms: i64,
    pub retain_until_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRetentionReceipt {
    pub payload: RetentionReceipt,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionRequest {
    pub schema_version: u32,
    pub checkpoint: SignedCheckpoint,
    pub checkpoint_sha256: String,
    pub export_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    pub checkpoint_sha256: String,
    pub export_sha256: String,
}

pub fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn unhex<const N: usize>(value: &str) -> Result<[u8; N], EvidenceError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(EvidenceError("invalid lowercase hexadecimal"));
    }
    let mut bytes = [0; N];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
            .map_err(|_| EvidenceError("invalid hexadecimal"))?;
    }
    Ok(bytes)
}

pub fn key_id(public_key: &VerifyingKey) -> String {
    sha256(public_key.as_bytes())
}

/// V1 canonical form: compact UTF-8 JSON, fixed struct field order, no maps/floats.
/// Unknown/duplicate fields are rejected by typed serde decoding; signatures have
/// a separate domain prefix. Pretty-printed transport JSON is not the signed form.
pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, EvidenceError> {
    let bytes = serde_json::to_vec(value).map_err(|_| EvidenceError("invalid document"))?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(EvidenceError("document too large"));
    }
    Ok(bytes)
}

pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, EvidenceError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(EvidenceError("document too large"));
    }
    serde_json::from_slice(bytes).map_err(|_| EvidenceError("invalid document"))
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

impl Scope {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if [
            &self.tenant_id,
            &self.broker_id,
            &self.stream_id,
            &self.generation,
        ]
        .into_iter()
        .all(|v| label(v))
        {
            Ok(())
        } else {
            Err(EvidenceError("invalid scope"))
        }
    }
}

fn trusted_key(version: u32, id: &str, public: &str) -> Result<VerifyingKey, EvidenceError> {
    let key = VerifyingKey::from_bytes(&unhex(public)?)
        .map_err(|_| EvidenceError("invalid public key"))?;
    if version != 1 || key_id(&key) != id {
        return Err(EvidenceError("unsupported trust or key identity"));
    }
    Ok(key)
}

impl ProducerTrust {
    pub fn verifying_key(&self) -> Result<VerifyingKey, EvidenceError> {
        self.scope.validate()?;
        trusted_key(self.schema_version, &self.key_id, &self.public_key)
    }
}

impl CustodianTrust {
    pub fn verifying_key(&self) -> Result<VerifyingKey, EvidenceError> {
        trusted_key(self.schema_version, &self.key_id, &self.public_key)
    }
}

fn message<T: Serialize>(domain: &[u8], payload: &T) -> Result<Vec<u8>, EvidenceError> {
    let mut bytes = domain.to_vec();
    bytes.extend(canonical(payload)?);
    Ok(bytes)
}

fn validate_checkpoint(payload: &Checkpoint) -> Result<(), EvidenceError> {
    payload.scope.validate()?;
    unhex::<32>(&payload.key_id)?;
    unhex::<32>(&payload.export_sha256)?;
    if let Some(previous) = &payload.previous_checkpoint_sha256 {
        unhex::<32>(previous)?;
    }
    if !matches!(payload.schema_version, 1 | SCOPE_CHECKPOINT_VERSION)
        || !label(&payload.build_identity)
        || (payload.checkpoint_sequence == 1) != payload.previous_checkpoint_sha256.is_none()
        || payload.checkpoint_sequence == 0
        || payload.gaps.len() > 128
    {
        return Err(EvidenceError("invalid checkpoint metadata"));
    }
    match (
        payload.first_sequence,
        payload.last_sequence,
        payload.record_count,
    ) {
        (None, None, 0) if payload.coverage_start.is_none() && payload.gaps.is_empty() => {}
        (Some(first), Some(last), count)
            if count > 0 && first <= last && payload.coverage_start == Some(first) =>
        {
            let mut missing = 0u64;
            let mut previous = None;
            for gap in &payload.gaps {
                if gap.first_sequence <= first
                    || gap.last_sequence >= last
                    || gap.first_sequence > gap.last_sequence
                    || previous.is_some_and(|p| gap.first_sequence <= p)
                {
                    return Err(EvidenceError("invalid coverage gap"));
                }
                missing = missing
                    .checked_add(gap.last_sequence - gap.first_sequence + 1)
                    .ok_or(EvidenceError("range overflow"))?;
                previous = Some(gap.last_sequence);
            }
            if last
                .checked_sub(first)
                .and_then(|v| v.checked_add(1))
                .and_then(|v| v.checked_sub(missing))
                != Some(count)
            {
                return Err(EvidenceError("range count mismatch"));
            }
        }
        _ => return Err(EvidenceError("invalid range")),
    }
    Ok(())
}

pub fn checkpoint_digest(checkpoint: &SignedCheckpoint) -> Result<String, EvidenceError> {
    Ok(sha256(&canonical(checkpoint)?))
}

fn checkpoint_domain(version: u32) -> &'static [u8] {
    if version == SCOPE_CHECKPOINT_VERSION {
        b"opaque.evidence.scope-checkpoint.v2\0"
    } else {
        b"opaque.evidence.checkpoint.v1\0"
    }
}

fn scope_summary(
    evidence: &crate::scope_evidence::ScopeEvidence,
    trust: &ProducerTrust,
) -> Result<crate::audit::checkpoint::ExportSummary, EvidenceError> {
    if evidence.owner.tenant_id != trust.scope.tenant_id
        || evidence.owner.broker_id != trust.scope.broker_id
        || evidence.owner.generation != trust.scope.generation
    {
        return Err(EvidenceError("scope export owner differs from enrollment"));
    }
    Ok(crate::audit::checkpoint::ExportSummary {
        first_sequence: evidence.events.first().map(|event| event.sequence),
        last_sequence: evidence.events.last().map(|event| event.sequence),
        record_count: evidence.events.len() as u64,
        gaps: vec![],
    })
}

/// Authenticate the enrolled producer and exact export bytes. The caller owns
/// enrollment provenance and comparison with previously retained checkpoints.
pub fn verify_checkpoint(
    checkpoint: &SignedCheckpoint,
    trust: &ProducerTrust,
    export: &[u8],
) -> Result<VerifiedCheckpoint, EvidenceError> {
    validate_checkpoint(&checkpoint.payload)?;
    let key = trust.verifying_key()?;
    if checkpoint.payload.scope != trust.scope || checkpoint.payload.key_id != trust.key_id {
        return Err(EvidenceError("producer or scope mismatch"));
    }
    if export.len() > MAX_EXPORT_BYTES || sha256(export) != checkpoint.payload.export_sha256 {
        return Err(EvidenceError("export digest mismatch"));
    }
    let signature = Signature::from_bytes(&unhex(&checkpoint.signature)?);
    key.verify_strict(
        &message(
            checkpoint_domain(checkpoint.payload.schema_version),
            &checkpoint.payload,
        )?,
        &signature,
    )
    .map_err(|_| EvidenceError("checkpoint signature mismatch"))?;
    let summary = if checkpoint.payload.schema_version == SCOPE_CHECKPOINT_VERSION {
        scope_summary(
            &crate::scope_evidence::ScopeEvidence::decode(export)?,
            trust,
        )?
    } else {
        crate::audit::checkpoint::inspect_export(export)?
    };
    if summary.first_sequence != checkpoint.payload.first_sequence
        || summary.last_sequence != checkpoint.payload.last_sequence
        || summary.record_count != checkpoint.payload.record_count
        || summary.gaps != checkpoint.payload.gaps
    {
        return Err(EvidenceError("export range mismatch"));
    }
    Ok(VerifiedCheckpoint {
        checkpoint_sha256: checkpoint_digest(checkpoint)?,
        export_sha256: checkpoint.payload.export_sha256.clone(),
    })
}

/// Only signs a snapshot obtained by verifying the local audit HMAC chain inside
/// the very same read transaction used to export its bytes. No arbitrary-export
/// signing entry point is exposed.
pub fn create_checkpoint(
    db_path: &Path,
    trust: &ProducerTrust,
    signing_key: &SigningKey,
    previous: Option<&SignedCheckpoint>,
    build_identity: String,
) -> Result<(SignedCheckpoint, Vec<u8>), EvidenceError> {
    if trust.verifying_key()? != signing_key.verifying_key() {
        return Err(EvidenceError("signing key does not match enrollment"));
    }
    let snapshot = crate::audit::checkpoint::verified_snapshot(db_path)?;
    let sequence = if let Some(previous) = previous {
        validate_checkpoint(&previous.payload)?;
        if previous.payload.schema_version != 1
            || previous.payload.scope != trust.scope
            || previous.payload.key_id != trust.key_id
        {
            return Err(EvidenceError(
                "previous checkpoint scope or key changed; enroll a new generation",
            ));
        }
        signing_key
            .verifying_key()
            .verify_strict(
                &message(b"opaque.evidence.checkpoint.v1\0", &previous.payload)?,
                &Signature::from_bytes(&unhex(&previous.signature)?),
            )
            .map_err(|_| EvidenceError("invalid previous checkpoint"))?;
        if previous.payload.last_sequence.is_some_and(|last| {
            snapshot
                .summary
                .last_sequence
                .is_none_or(|head| head < last)
        }) {
            return Err(EvidenceError("audit head regressed"));
        }
        previous
            .payload
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(EvidenceError("checkpoint sequence exhausted"))?
    } else {
        1
    };
    let payload = Checkpoint {
        schema_version: 1,
        scope: trust.scope.clone(),
        key_id: trust.key_id.clone(),
        checkpoint_sequence: sequence,
        first_sequence: snapshot.summary.first_sequence,
        last_sequence: snapshot.summary.last_sequence,
        record_count: snapshot.summary.record_count,
        export_sha256: sha256(&snapshot.bytes),
        previous_checkpoint_sha256: previous.map(checkpoint_digest).transpose()?,
        build_identity,
        coverage_start: snapshot.summary.first_sequence,
        gaps: snapshot.summary.gaps,
    };
    validate_checkpoint(&payload)?;
    let signature = hex(&signing_key
        .sign(&message(b"opaque.evidence.checkpoint.v1\0", &payload)?)
        .to_bytes());
    Ok((SignedCheckpoint { payload, signature }, snapshot.bytes))
}

/// Sign a complete, structurally verified scope snapshot obtained by the trusted
/// producer from its ledger. Verification checks accounting/history, not whether
/// the producer is honest or the snapshot is its latest state. Continuing a
/// stream requires the previous exact export as well as its signed checkpoint.
pub fn create_scope_checkpoint(
    evidence: &crate::scope_evidence::ScopeEvidence,
    trust: &ProducerTrust,
    signing_key: &SigningKey,
    previous: Option<(&SignedCheckpoint, &[u8])>,
    build_identity: String,
) -> Result<(SignedCheckpoint, Vec<u8>), EvidenceError> {
    if trust.verifying_key()? != signing_key.verifying_key() {
        return Err(EvidenceError("signing key does not match enrollment"));
    }
    let export = evidence.encode()?;
    let summary = scope_summary(evidence, trust)?;
    let sequence = if let Some((checkpoint, prior_bytes)) = previous {
        if checkpoint.payload.schema_version != SCOPE_CHECKPOINT_VERSION {
            return Err(EvidenceError(
                "checkpoint format changed; enroll a new stream",
            ));
        }
        verify_checkpoint(checkpoint, trust, prior_bytes)?;
        evidence.validate_extension(&crate::scope_evidence::ScopeEvidence::decode(prior_bytes)?)?;
        checkpoint
            .payload
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(EvidenceError("checkpoint sequence exhausted"))?
    } else {
        1
    };
    let payload = Checkpoint {
        schema_version: SCOPE_CHECKPOINT_VERSION,
        scope: trust.scope.clone(),
        key_id: trust.key_id.clone(),
        checkpoint_sequence: sequence,
        first_sequence: summary.first_sequence,
        last_sequence: summary.last_sequence,
        record_count: summary.record_count,
        export_sha256: sha256(&export),
        previous_checkpoint_sha256: previous
            .map(|(checkpoint, _)| checkpoint_digest(checkpoint))
            .transpose()?,
        build_identity,
        coverage_start: summary.first_sequence,
        gaps: summary.gaps,
    };
    validate_checkpoint(&payload)?;
    let signature = hex(&signing_key
        .sign(&message(
            checkpoint_domain(payload.schema_version),
            &payload,
        )?)
        .to_bytes());
    Ok((SignedCheckpoint { payload, signature }, export))
}

pub fn retention_request(checkpoint: &SignedCheckpoint) -> Result<RetentionRequest, EvidenceError> {
    validate_checkpoint(&checkpoint.payload)?;
    Ok(RetentionRequest {
        schema_version: 1,
        checkpoint: checkpoint.clone(),
        checkpoint_sha256: checkpoint_digest(checkpoint)?,
        export_sha256: checkpoint.payload.export_sha256.clone(),
    })
}

fn validate_receipt(payload: &RetentionReceipt) -> Result<(), EvidenceError> {
    payload.scope.validate()?;
    for digest in [
        &payload.custodian_key_id,
        &payload.checkpoint_sha256,
        &payload.export_sha256,
    ] {
        unhex::<32>(digest)?;
    }
    if let Some(previous) = &payload.previous_receipt_sha256 {
        unhex::<32>(previous)?;
    }
    if payload.schema_version != 1
        || !label(&payload.object_id)
        || !label(&payload.object_version)
        || payload.received_at_unix_ms < 0
        || payload.retain_until_unix_ms <= payload.received_at_unix_ms
    {
        return Err(EvidenceError("invalid retention receipt"));
    }
    Ok(())
}

pub fn sign_retention_receipt(
    payload: RetentionReceipt,
    key: &SigningKey,
) -> Result<SignedRetentionReceipt, EvidenceError> {
    validate_receipt(&payload)?;
    if payload.custodian_key_id != key_id(&key.verifying_key()) {
        return Err(EvidenceError("custodian key mismatch"));
    }
    let signature = hex(&key
        .sign(&message(b"opaque.evidence.retention.v1\0", &payload)?)
        .to_bytes());
    Ok(SignedRetentionReceipt { payload, signature })
}

pub fn receipt_digest(receipt: &SignedRetentionReceipt) -> Result<String, EvidenceError> {
    Ok(sha256(&canonical(receipt)?))
}

/// Verifies signed retention intent/binding using a key distinct from the producer.
/// Distinct keys do not prove separate administrators, object custody, WORM
/// configuration, physical independence, read-back or future availability.
pub fn verify_retention_receipt(
    receipt: &SignedRetentionReceipt,
    trust: &CustodianTrust,
    checkpoint: &SignedCheckpoint,
    now_unix_ms: i64,
) -> Result<(), EvidenceError> {
    validate_receipt(&receipt.payload)?;
    let payload = &receipt.payload;
    let key = trust.verifying_key()?;
    if trust.key_id == checkpoint.payload.key_id {
        return Err(EvidenceError(
            "producer and custodian signer keys must differ",
        ));
    }
    if payload.custodian_key_id != trust.key_id
        || payload.scope != checkpoint.payload.scope
        || payload.checkpoint_sha256 != checkpoint_digest(checkpoint)?
        || payload.export_sha256 != checkpoint.payload.export_sha256
        || payload.first_sequence != checkpoint.payload.first_sequence
        || payload.last_sequence != checkpoint.payload.last_sequence
        || payload.record_count != checkpoint.payload.record_count
        || now_unix_ms < payload.received_at_unix_ms
        || now_unix_ms >= payload.retain_until_unix_ms
    {
        return Err(EvidenceError(
            "receipt binding or retention interval mismatch",
        ));
    }
    key.verify_strict(
        &message(b"opaque.evidence.retention.v1\0", payload)?,
        &Signature::from_bytes(&unhex(&receipt.signature)?),
    )
    .map_err(|_| EvidenceError("retention signature mismatch"))
}
