//! Portable scope ledger evidence, independent of a database or running broker.
//!
//! These records describe retained authority accounting. They grant no authority
//! and do not prove approval signatures, current enrollment, provider effects,
//! global completeness, or freshness. Verify producer enrollment separately.
use crate::evidence_checkpoint::{EvidenceError, MAX_EXPORT_BYTES};
use crate::scope::{AdmissionEvidence, AuthorityOwner, MAX_DEPTH, PreparedAction, ScopeGrant};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRecord {
    pub grant: ScopeGrant,
    pub digest: String,
    pub issued_at: i64,
    pub revoked_at: Option<i64>,
    pub charged_attempts: u64,
    pub charged_resources: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Reserved,
    DispatchClaimed,
    ApiAccepted,
    Rejected,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecord {
    pub action: PreparedAction,
    pub digest: String,
    pub evidence: AdmissionEvidence,
    pub reserved_at: i64,
    pub dispatch_claimed_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub state: ExecutionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ScopeIssued,
    ScopeRevoked,
    AttemptCharged,
    DispatchClaimed,
    AttemptFinished,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEvent {
    pub sequence: u64,
    pub scope_id: String,
    pub action_id: Option<String>,
    pub kind: EventKind,
    /// Recovery cannot know the interruption time; it records None.
    pub observed_at: Option<i64>,
    pub content_digest: String,
}

/// Complete retained state of one owner at one ledger frontier. Lists are
/// canonical (scope/action IDs ascending, event sequence ascending). No paging
/// or truncation is permitted in this format. Sequence counts refer to events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeEvidence {
    pub schema_version: u16,
    pub owner: AuthorityOwner,
    pub last_seen: i64,
    pub scopes: Vec<ScopeRecord>,
    pub actions: Vec<ActionRecord>,
    pub events: Vec<AuthorityEvent>,
}

impl ScopeEvidence {
    /// Verify retained scope-review protocol receipts against an independently
    /// enrolled broker key. This authenticates historical reviewer signatures
    /// and acceptance, not current identity/authority or human presence. Grants
    /// issued through other protocols need their own evidence verifier.
    pub fn verify_reviews(
        &self,
        receipts: &[crate::scope_review::DecisionReceipt],
        broker_public_key: &str,
    ) -> Result<(), EvidenceError> {
        use crate::scope_review::{Decision, ReviewSubject};
        self.validate()?;
        ed25519_dalek::VerifyingKey::from_bytes(&crate::evidence_checkpoint::unhex::<32>(
            broker_public_key,
        )?)
        .map_err(|_| EvidenceError("invalid review broker enrollment"))?;
        let mut indexed = BTreeMap::new();
        for receipt in receipts {
            receipt
                .verify(broker_public_key)
                .map_err(|_| EvidenceError("invalid historical review signature"))?;
            if receipt.review.document.authority.owner != self.owner {
                return Err(EvidenceError("review belongs to another owner"));
            }
            let digest = receipt
                .digest()
                .map_err(|_| EvidenceError("invalid review digest"))?;
            if indexed.insert(digest, receipt).is_some() {
                return Err(EvidenceError("duplicate review receipt"));
            }
        }
        for scope in &self.scopes {
            let receipt = indexed
                .get(&scope.grant.issuance_receipt_digest)
                .ok_or(EvidenceError("missing issuance receipt"))?;
            let ReviewSubject::ScopeIssuance { draft } = &receipt.review.document.subject else {
                return Err(EvidenceError("issuance receipt subject mismatch"));
            };
            let mut approved = draft.clone();
            approved.issuance_receipt_digest = scope.grant.issuance_receipt_digest.clone();
            if receipt.response.decision != Decision::Approve
                || approved != scope.grant
                || receipt.accepted_at > scope.issued_at
            {
                return Err(EvidenceError("issuance approval does not bind this grant"));
            }
        }
        for record in &self.actions {
            if let Some(binding) = &record.evidence.review {
                let receipt = indexed
                    .get(&binding.decision_receipt_digest)
                    .ok_or(EvidenceError("missing exact-action receipt"))?;
                let document = &receipt.review.document;
                let ReviewSubject::ExactAction {
                    scope,
                    action,
                    case_id,
                    case_revision,
                    ..
                } = &document.subject
                else {
                    return Err(EvidenceError("action receipt subject mismatch"));
                };
                if receipt.response.decision != Decision::Approve
                    || **action != record.action
                    || scope
                        .digest()
                        .map_err(|_| EvidenceError("invalid reviewed scope"))?
                        != binding.scope_digest
                    || *case_id != binding.case_id
                    || *case_revision != binding.case_revision
                    || document.round_id != binding.round_id
                    || document.expires_at != binding.expires_at
                    || receipt.accepted_at > record.reserved_at
                {
                    return Err(EvidenceError(
                        "exact-action approval does not bind this charge",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Check retained history against an independently retained prior export.
    /// Mutable projections may advance, but consumed outcomes, authority and
    /// append-only events cannot be rewritten or removed.
    pub fn validate_extension(&self, previous: &Self) -> Result<(), EvidenceError> {
        self.validate()?;
        previous.validate()?;
        if self.owner != previous.owner
            || self.last_seen < previous.last_seen
            || !self.events.starts_with(&previous.events)
            || self.events[previous.events.len()..]
                .iter()
                .any(|event| event.observed_at.is_some_and(|at| at < previous.last_seen))
        {
            return Err(EvidenceError("scope evidence history regressed or changed"));
        }
        for old in &previous.scopes {
            let new = self
                .scopes
                .binary_search_by(|r| r.grant.scope_id.cmp(&old.grant.scope_id))
                .ok()
                .map(|i| &self.scopes[i])
                .ok_or(EvidenceError("retained scope removed"))?;
            if new.grant != old.grant
                || new.issued_at != old.issued_at
                || old.revoked_at.is_some_and(|at| new.revoked_at != Some(at))
            {
                return Err(EvidenceError("retained scope changed"));
            }
        }
        for old in &previous.actions {
            let new = self
                .actions
                .binary_search_by(|r| r.action.action_id.cmp(&old.action.action_id))
                .ok()
                .map(|i| &self.actions[i])
                .ok_or(EvidenceError("retained action removed"))?;
            if new.action != old.action
                || new.evidence != old.evidence
                || new.reserved_at != old.reserved_at
                || old
                    .dispatch_claimed_at
                    .is_some_and(|at| new.dispatch_claimed_at != Some(at))
                || (matches!(
                    old.state,
                    ExecutionState::ApiAccepted
                        | ExecutionState::Rejected
                        | ExecutionState::Unknown
                ) && new != old)
            {
                return Err(EvidenceError("retained action or consumed outcome changed"));
            }
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() > MAX_EXPORT_BYTES {
            return Err(EvidenceError("scope export exceeds bound"));
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| EvidenceError("invalid scope export"))?;
        value.validate()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>, EvidenceError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| EvidenceError("invalid scope export"))?;
        if bytes.len() > MAX_EXPORT_BYTES {
            return Err(EvidenceError("scope export exceeds bound"));
        }
        Ok(bytes)
    }
}

impl ScopeEvidence {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.schema_version != 1 || self.last_seen < 0 {
            return Err(EvidenceError("invalid scope evidence version or time"));
        }
        self.owner
            .validate()
            .map_err(|_| EvidenceError("invalid scope evidence owner"))?;
        let owner = &self.owner;
        let last_seen = self.last_seen;
        if !self
            .scopes
            .windows(2)
            .all(|p| p[0].grant.scope_id < p[1].grant.scope_id)
            || !self
                .actions
                .windows(2)
                .all(|p| p[0].action.action_id < p[1].action.action_id)
        {
            return Err(EvidenceError(
                "duplicate or unordered scope evidence records",
            ));
        }
        let mut requests = BTreeSet::new();
        for record in &self.scopes {
            let grant = record
                .grant
                .canonicalized()
                .map_err(|_| EvidenceError("invalid grant"))?;
            if grant != record.grant
                || grant.digest().map_err(|_| EvidenceError("invalid grant"))? != record.digest
            {
                return Err(EvidenceError("scope digest mismatch"));
            }
        }
        for record in &self.actions {
            let action = record
                .action
                .canonicalized()
                .map_err(|_| EvidenceError("invalid action"))?;
            if action != record.action
                || action
                    .digest()
                    .map_err(|_| EvidenceError("invalid action"))?
                    != record.digest
                || !requests.insert((
                    action.scope_id.clone(),
                    action.subject.clone(),
                    action.request_id.clone(),
                ))
            {
                return Err(EvidenceError("action digest or request identity mismatch"));
            }
        }
        let mut expected: BTreeMap<String, (u64, BTreeSet<String>)> = BTreeMap::new();
        let mut scopes = BTreeMap::new();
        for record in &self.scopes {
            let id = record.grant.scope_id.clone();
            let records = ancestry(&self.scopes, &id)?;
            let scope = &records[0];
            if scope.grant.owner != *owner
                || scope.issued_at < 0
                || scope.issued_at > last_seen
                || scope.issued_at >= scope.grant.expires_at
                || scope
                    .revoked_at
                    .is_some_and(|at| at < scope.issued_at || at > last_seen)
                || scope.charged_attempts > scope.grant.max_charged_attempts
                || scope.charged_resources.len() > scope.grant.max_distinct_resources as usize
                || records.iter().skip(1).any(|p| {
                    p.issued_at > scope.issued_at
                        || scope.issued_at < p.grant.not_before
                        || scope.issued_at >= p.grant.expires_at
                        || p.revoked_at.is_some_and(|at| at < scope.issued_at)
                })
            {
                return Err(EvidenceError("inconsistent scope ledger"));
            }
            expected.insert(id.clone(), (0, BTreeSet::new()));
            scopes.insert(id, scope.clone());
        }
        let actions = &self.actions;
        for record in actions {
            let ancestry = ancestry(&self.scopes, &record.action.scope_id)?;
            record
                .evidence
                .validate_for(&ancestry[0].grant, &record.action, record.reserved_at)
                .map_err(|_| EvidenceError("invalid admission evidence"))?;
            if let Some(at) = record.dispatch_claimed_at {
                record
                    .evidence
                    .validate_for(&ancestry[0].grant, &record.action, at)
                    .map_err(|_| EvidenceError("invalid dispatch evidence"))?;
                if ancestry.iter().any(|scope| {
                    at < scope.grant.not_before
                        || at >= scope.grant.expires_at
                        || scope.revoked_at.is_some_and(|revoked| revoked < at)
                }) {
                    return Err(EvidenceError("inconsistent scope ledger"));
                }
            }
            if record.action.owner != *owner
                || record.reserved_at > last_seen
                || record.reserved_at < ancestry[0].issued_at
                || record.dispatch_claimed_at.is_some_and(|at| {
                    at < record.reserved_at || at > last_seen || at >= record.evidence.expires_at
                })
                || record.finished_at.is_some_and(|at| {
                    at < record.dispatch_claimed_at.unwrap_or(record.reserved_at) || at > last_seen
                })
                || ancestry.iter().any(|s| {
                    record.reserved_at < s.grant.not_before
                        || record.reserved_at >= s.grant.expires_at
                        || s.revoked_at.is_some_and(|at| at < record.reserved_at)
                })
            {
                return Err(EvidenceError("inconsistent scope ledger"));
            }
            match record.state {
                ExecutionState::Reserved
                    if record.dispatch_claimed_at.is_some() || record.finished_at.is_some() =>
                {
                    return Err(EvidenceError("inconsistent scope ledger"));
                }
                ExecutionState::DispatchClaimed
                    if record.dispatch_claimed_at.is_none() || record.finished_at.is_some() =>
                {
                    return Err(EvidenceError("inconsistent scope ledger"));
                }
                ExecutionState::ApiAccepted
                    if record.dispatch_claimed_at.is_none() || record.finished_at.is_none() =>
                {
                    return Err(EvidenceError("inconsistent scope ledger"));
                }
                ExecutionState::Rejected if record.finished_at.is_none() => {
                    return Err(EvidenceError("inconsistent scope ledger"));
                }
                _ => {}
            }
            for scope in ancestry {
                let count = expected
                    .get_mut(&scope.grant.scope_id)
                    .ok_or(EvidenceError("inconsistent scope ledger"))?;
                count.0 = count
                    .0
                    .checked_add(1)
                    .ok_or(EvidenceError("inconsistent scope ledger"))?;
                count.1.insert(record.action.resource.clone());
            }
        }
        for (id, (count, resources)) in expected {
            let scope = scopes
                .get(&id)
                .ok_or(EvidenceError("inconsistent scope ledger"))?;
            if scope.charged_attempts != count || scope.charged_resources != resources {
                return Err(EvidenceError("inconsistent scope ledger"));
            }
        }
        verify_events(&self.events, &scopes, actions, last_seen)
    }
}

fn ancestry(scopes: &[ScopeRecord], id: &str) -> Result<Vec<ScopeRecord>, EvidenceError> {
    let mut result = Vec::new();
    let mut current = Some(id);
    while let Some(id) = current {
        if result.len() > MAX_DEPTH as usize
            || result.iter().any(|r: &ScopeRecord| r.grant.scope_id == id)
        {
            return Err(EvidenceError("cyclic or overdeep authority chain"));
        }
        let record = scopes
            .binary_search_by(|r| r.grant.scope_id.as_str().cmp(id))
            .ok()
            .map(|i| &scopes[i])
            .ok_or(EvidenceError("missing scope ancestor"))?;
        current = record.grant.parent_id.as_deref();
        result.push(record.clone());
    }
    for pair in result.windows(2) {
        pair[0]
            .grant
            .validate_child_of(&pair[1].grant)
            .map_err(|_| EvidenceError("expanded child scope"))?;
    }
    Ok(result)
}

fn verify_events(
    events: &[AuthorityEvent],
    scopes: &BTreeMap<String, ScopeRecord>,
    actions: &[ActionRecord],
    last_seen: i64,
) -> Result<(), EvidenceError> {
    let mut sequence = 0_u64;
    let mut seen: BTreeMap<(String, EventKind), u64> = BTreeMap::new();
    let action_map: BTreeMap<_, _> = actions
        .iter()
        .map(|a| (a.action.action_id.as_str(), a))
        .collect();
    let mut previous_time = 0;
    for event in events {
        sequence += 1;
        let scope = scopes
            .get(&event.scope_id)
            .ok_or(EvidenceError("inconsistent scope event history"))?;
        if event.sequence != sequence
            || event
                .observed_at
                .is_some_and(|at| at < previous_time || at > last_seen)
        {
            return Err(EvidenceError("inconsistent scope event history"));
        }
        if let Some(at) = event.observed_at {
            previous_time = at;
        }
        let key = (
            event
                .action_id
                .clone()
                .unwrap_or_else(|| event.scope_id.clone()),
            event.kind,
        );
        if seen.insert(key, sequence).is_some() {
            return Err(EvidenceError("inconsistent scope event history"));
        }
        if event.kind != EventKind::ScopeIssued
            && !seen.contains_key(&(event.scope_id.clone(), EventKind::ScopeIssued))
        {
            return Err(EvidenceError("inconsistent scope event history"));
        }
        if matches!(
            event.kind,
            EventKind::ScopeIssued | EventKind::AttemptCharged | EventKind::DispatchClaimed
        ) {
            let mut ancestor = Some(scope);
            while let Some(current) = ancestor {
                if seen.contains_key(&(current.grant.scope_id.clone(), EventKind::ScopeRevoked))
                    || !seen.contains_key(&(current.grant.scope_id.clone(), EventKind::ScopeIssued))
                {
                    return Err(EvidenceError("inconsistent scope event history"));
                }
                ancestor = current
                    .grant
                    .parent_id
                    .as_ref()
                    .map(|id| {
                        scopes
                            .get(id)
                            .ok_or(EvidenceError("inconsistent scope event history"))
                    })
                    .transpose()?;
            }
        }
        if let Some(id) = &event.action_id {
            let action = action_map
                .get(id.as_str())
                .ok_or(EvidenceError("inconsistent scope event history"))?;
            if event.scope_id != action.action.scope_id || event.content_digest != action.digest {
                return Err(EvidenceError("inconsistent scope event history"));
            }
            let correct = match event.kind {
                EventKind::AttemptCharged => event.observed_at == Some(action.reserved_at),
                EventKind::DispatchClaimed => {
                    event.observed_at == action.dispatch_claimed_at
                        && action.dispatch_claimed_at.is_some()
                }
                EventKind::AttemptFinished => {
                    event.observed_at == action.finished_at && action.finished_at.is_some()
                }
                EventKind::Interrupted => {
                    event.observed_at.is_none()
                        && action.state == ExecutionState::Unknown
                        && action.finished_at.is_none()
                }
                _ => false,
            };
            if !correct {
                return Err(EvidenceError("inconsistent scope event history"));
            }
            if event.kind != EventKind::AttemptCharged
                && !seen.contains_key(&(id.clone(), EventKind::AttemptCharged))
            {
                return Err(EvidenceError("inconsistent scope event history"));
            }
            if matches!(
                event.kind,
                EventKind::AttemptFinished | EventKind::Interrupted
            ) && action.dispatch_claimed_at.is_some()
                && !seen.contains_key(&(id.clone(), EventKind::DispatchClaimed))
            {
                return Err(EvidenceError("inconsistent scope event history"));
            }
        } else if event.content_digest != scope.digest
            || !match event.kind {
                EventKind::ScopeIssued => event.observed_at == Some(scope.issued_at),
                EventKind::ScopeRevoked => {
                    event.observed_at == scope.revoked_at && scope.revoked_at.is_some()
                }
                _ => false,
            }
        {
            return Err(EvidenceError("inconsistent scope event history"));
        }
    }
    for scope in scopes.values() {
        if !seen.contains_key(&(scope.grant.scope_id.clone(), EventKind::ScopeIssued))
            || (scope.revoked_at.is_some()
                && !seen.contains_key(&(scope.grant.scope_id.clone(), EventKind::ScopeRevoked)))
        {
            return Err(EvidenceError("inconsistent scope event history"));
        }
    }
    for action in actions {
        for (required, kind) in [
            (true, EventKind::AttemptCharged),
            (
                action.dispatch_claimed_at.is_some(),
                EventKind::DispatchClaimed,
            ),
            (action.finished_at.is_some(), EventKind::AttemptFinished),
            (
                action.state == ExecutionState::Unknown && action.finished_at.is_none(),
                EventKind::Interrupted,
            ),
        ] {
            if required && !seen.contains_key(&(action.action.action_id.clone(), kind)) {
                return Err(EvidenceError("inconsistent scope event history"));
            }
        }
    }
    Ok(())
}
