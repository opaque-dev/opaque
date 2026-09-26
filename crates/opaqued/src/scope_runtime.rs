//! Opt-in typed support workflow. Authorization stays in this broker: a paired
//! reviewer signs issuance or an exact prepared action; immutable startup policy,
//! current identity and enrollment are fenced through durable dispatch claims.
pub(crate) mod connector;
use crate::identity::IdentityRuntime;
use connector::{Connector, Status};
use opaque_approval::{
    pairing::PairingManager,
    scope_review::{CurrentAuthority, RoundState, ScopeReviewStore},
};
use opaque_bounded_work::scope_store::{AuthorityGuard, ScopeStore};
use opaque_core::{
    identity::{PrincipalContext, PrincipalId, Role, now_unix},
    proto::{Request, Response},
    scope::*,
    scope_review::{
        DecisionReceipt, EMPTY_RECEIPT_DIGEST, ReviewAuthority, ReviewEvidence, ReviewSubject,
        ReviewerDecision, SignedReview,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::Path, sync::Arc};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Set only by the sealed manifest loader. Excluding None preserves legacy
    /// scope_workflow policy digests exactly; agents cannot deserialize this.
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub authority_policy: Option<opaque_core::authority_policy::CompiledPolicy>,
    pub profile: connector::Profile,
    pub reviewer_id: String,
    pub reviewer_public_key: String,
    #[serde(default = "generation")]
    pub generation: u64,
    #[serde(default = "scope_seconds")]
    pub max_scope_seconds: i64,
    #[serde(default = "attempts")]
    pub max_attempts: u64,
    #[serde(default = "resources")]
    pub max_resources: u32,
    /// Explicit operator choice. Default requires exact-action review; false
    /// enables bounded automatic status writes after human-approved issuance.
    #[serde(default = "yes")]
    pub exact_action: bool,
    pub allowed_statuses: Vec<Status>,
}
fn generation() -> u64 {
    1
}
fn scope_seconds() -> i64 {
    3600
}
fn attempts() -> u64 {
    100
}
fn resources() -> u32 {
    100
}
fn yes() -> bool {
    true
}
pub struct Runtime {
    config: Config,
    owner: AuthorityOwner,
    policy_digest: String,
    connector: Connector,
    ledger: ScopeStore,
    reviews: ScopeReviewStore,
    identity: Arc<IdentityRuntime>,
    pairing: Arc<PairingManager>,
    reviewer: PrincipalId,
    device_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    resources: Vec<String>,
    statuses: Vec<Status>,
    expires_in_secs: i64,
    max_attempts: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Round {
    round_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    scope_id: String,
    issuance_round_id: String,
    resource: String,
    status: Status,
    request_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Execute {
    round_id: String,
    issuance_round_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Id {
    scope_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeRequest {
    scope_id: String,
    request_id: String,
}

impl Runtime {
    pub fn open(
        config: Config,
        tenant: &opaque_core::tenant::TenantBinding,
        root: &Path,
        identity: Arc<IdentityRuntime>,
        pairing: Arc<PairingManager>,
    ) -> Result<Self, String> {
        if config.generation == 0
            || !(1..=86400).contains(&config.max_scope_seconds)
            || !(1..=10000).contains(&config.max_attempts)
            || !(1..=100).contains(&config.max_resources)
            || config.allowed_statuses.is_empty()
            || config.allowed_statuses.len() > 3
        {
            return Err("invalid scope workflow limits".into());
        }
        let reviewer =
            PrincipalId::parse(&config.reviewer_id).map_err(|_| "invalid scope reviewer")?;
        if !reviewer.is_human() {
            return Err("scope reviewer must be human".into());
        }
        let device = pairing
            .list_devices()
            .map_err(|_| "scope reviewer unavailable")?
            .into_iter()
            .find(|d| {
                d.public_key_hex == config.reviewer_public_key
                    && d.paired_by.as_deref() == Some(&config.reviewer_id)
            })
            .ok_or("scope reviewer must be an enrolled configured workstation")?;
        pairing
            .workstation_device(&device.device_id)
            .map_err(|_| "scope workstation unavailable")?;
        let connector = Connector::new(&config.profile)?;
        let owner = AuthorityOwner {
            tenant_id: tenant.tenant_id.to_string(),
            broker_id: pairing.server_id().into(),
            generation: config.generation.to_string(),
        };
        let policy_digest = connector::hash(
            &json!({"contract":"opaque.support.policy.v1","config":config,"tenant_binding":tenant}),
        )?;
        let key = crate::identity::keys::load_or_create_signing_key(&root.join("scope-review.key"))
            .map_err(|_| "scope signing custody unavailable")?;
        let reviews = ScopeReviewStore::open(
            &root.join("scope-reviews.db"),
            owner.clone(),
            key,
            now_unix(),
        )
        .map_err(|e| e.to_string())?;
        let ledger =
            ScopeStore::open(&root.join("scopes.db"), owner.clone()).map_err(|e| e.to_string())?;
        Ok(Self {
            config,
            owner,
            policy_digest,
            connector,
            ledger,
            reviews,
            identity,
            pairing,
            reviewer,
            device_id: device.device_id,
        })
    }
    /// Lock order: pairing -> identity -> review ledger -> scope ledger. Guards
    /// release only after the final local ledger transaction, never around I/O.
    fn authority<T>(
        &self,
        subject: &str,
        requester: Option<&PrincipalContext>,
        f: impl FnOnce(&CurrentAuthority) -> Result<T, String>,
    ) -> Result<T, String> {
        let subject_id = PrincipalId::parse(subject).map_err(|_| "invalid scope subject")?;
        if requester.is_some_and(|c| c.sub != subject_id) {
            return Err("scope requester mismatch".into());
        }
        let epoch = self
            .identity
            .reviewer_eligibility(&self.reviewer, Role::Approver)?;
        let mut result = None;
        let mut f = Some(f);
        self.pairing
            .with_workstation_authority(&self.device_id, &mut |device| {
                if device.public_key_hex != self.config.reviewer_public_key
                    || device.paired_by.as_deref() != Some(&self.config.reviewer_id)
                    || device.token_sha256.is_none()
                {
                    return Err("scope workstation enrollment unavailable".into());
                }
                let current = CurrentAuthority::new(ReviewAuthority {
                    owner: self.owner.clone(),
                    requester_id: subject.into(),
                    reviewer_id: self.config.reviewer_id.clone(),
                    device_id: self.device_id.clone(),
                    reviewer_public_key: self.config.reviewer_public_key.clone(),
                    required_role: "approver".into(),
                    policy_digest: self.policy_digest.clone(),
                    authority_epoch: epoch,
                    enrollment_epoch: u64::try_from(device.paired_at)
                        .map_err(|_| "invalid enrollment epoch")?,
                })
                .map_err(|e| e.to_string())?;
                self.identity.with_scope_authority(
                    requester,
                    Some(&subject_id),
                    Some((&self.reviewer, Role::Approver, epoch)),
                    &mut || {
                        result = Some(f.take().ok_or("reentered scope authority")?(&current)?);
                        Ok(())
                    },
                )
            })?;
        result.ok_or_else(|| "scope authority unavailable".into())
    }
    fn policy(&self, grant: &ScopeGrant) -> Result<(), String> {
        let expected = if self.config.exact_action {
            MinimumApproval::ExactAction
        } else {
            MinimumApproval::ScopeIssuance
        };
        if grant.owner != self.owner
            || grant.issuer != grant.subject
            || grant.parent_id.is_some()
            || grant.delegations_remaining != 0
            || grant.operation != connector::OPERATION
            || grant.provider_profile_digest != self.connector.digest
            || grant.requirements.policy_digest != self.policy_digest
            || !grant.requirements.evaluator_checks.is_empty()
            || grant.requirements.minimum_approval != expected
            || grant.max_charged_attempts > self.config.max_attempts
            || grant.max_distinct_resources > self.config.max_resources
            || grant.expires_at - grant.not_before > self.config.max_scope_seconds
            || grant.fields.len() != 1
            || grant.fields[0].field != "status"
            || grant.fields[0]
                .allowed_values
                .iter()
                .any(|s| !self.config.allowed_statuses.iter().any(|t| t.as_str() == s))
        {
            return Err("scope does not satisfy current support policy".into());
        }
        for id in &grant.resources {
            connector::identifier(id)?;
        }
        Ok(())
    }
    fn issuance(
        &self,
        id: &str,
        current: &CurrentAuthority,
        now: i64,
    ) -> Result<DecisionReceipt, String> {
        self.reviews
            .receipt(id, current, now)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "scope issuance has not been approved".into())
    }
    fn grant(&self, id: &str, subject: &str) -> Result<ScopeGrant, String> {
        let record = self.ledger.get_scope(id).map_err(|e| e.to_string())?;
        if record.revoked_at.is_some()
            || now_unix() < record.grant.not_before
            || now_unix() >= record.grant.expires_at
        {
            return Err("scope inactive".into());
        }
        if record.grant.subject != subject {
            return Err("scope owner mismatch".into());
        }
        self.policy(&record.grant)?;
        Ok(record.grant)
    }
    fn plan(&self, plan: Plan, context: &PrincipalContext) -> Result<Value, String> {
        if !(1..=self.config.max_scope_seconds).contains(&plan.expires_in_secs)
            || !(1..=self.config.max_attempts).contains(&plan.max_attempts)
            || plan.resources.is_empty()
            || plan.resources.len() > self.config.max_resources as usize
            || plan.statuses.is_empty()
        {
            return Err("scope request exceeds configured bounds".into());
        }
        let selected_resources = plan.resources.len() as u32;
        let now = now_unix();
        let id = uuid::Uuid::new_v4().to_string();
        let grant = ScopeGrant {
            schema_version: opaque_core::scope::VERSION,
            scope_id: id.clone(),
            root_id: id,
            parent_id: None,
            owner: self.owner.clone(),
            issuer: context.sub.to_string(),
            subject: context.sub.to_string(),
            operation: connector::OPERATION.into(),
            provider_profile_digest: self.connector.digest.clone(),
            resources: plan.resources,
            fields: vec![FieldConstraint {
                field: "status".into(),
                allowed_values: plan
                    .statuses
                    .into_iter()
                    .map(|s| s.as_str().into())
                    .collect(),
            }],
            not_before: now,
            expires_at: now + plan.expires_in_secs,
            delegations_remaining: 0,
            max_charged_attempts: plan.max_attempts,
            max_distinct_resources: selected_resources,
            requirements: ScopeRequirements {
                policy_digest: self.policy_digest.clone(),
                minimum_approval: if self.config.exact_action {
                    MinimumApproval::ExactAction
                } else {
                    MinimumApproval::ScopeIssuance
                },
                evaluator_checks: vec![],
            },
            issuance_receipt_digest: EMPTY_RECEIPT_DIGEST.into(),
        }
        .canonicalized()
        .map_err(|e| e.to_string())?;
        self.policy(&grant)?;
        self.authority(context.sub.as_str(), Some(context), |current| {
            Ok(json!(
                self.reviews
                    .issue(
                        ReviewSubject::issuance(&grant).map_err(|e| e.to_string())?,
                        current,
                        300,
                        now
                    )
                    .map_err(|e| e.to_string())?
            ))
        })
    }
    fn activate(&self, round: Round, context: &PrincipalContext) -> Result<Value, String> {
        let now = now_unix();
        self.authority(context.sub.as_str(), Some(context), |current| {
            let receipt = self.issuance(&round.round_id, current, now)?;
            let grant = self
                .reviews
                .materialize_scope(&receipt, current, now)
                .map_err(|e| e.to_string())?;
            let guard = Guard {
                runtime: self,
                current,
                issuance: &receipt,
                action_receipt: None,
            };
            Ok(json!(
                self.ledger
                    .issue_scope(grant, &guard, now)
                    .map_err(|e| e.to_string())?
            ))
        })
    }
    async fn prepare(
        &self,
        input: &Prepare,
        context: &PrincipalContext,
    ) -> Result<(PreparedAction, ReviewEvidence), String> {
        connector::identifier(&input.resource)?;
        connector::identifier(&input.request_id)?;
        let grant = self.grant(&input.scope_id, context.sub.as_str())?;
        self.authority(context.sub.as_str(), Some(context), |current| {
            let receipt = self.issuance(&input.issuance_round_id, current, now_unix())?;
            self.reviews
                .revalidate_scope(&grant, &receipt, current, now_unix())
                .map_err(|e| e.to_string())
        })?;
        if !grant.resources.contains(&input.resource)
            || !grant.fields[0]
                .allowed_values
                .iter()
                .any(|v| v == input.status.as_str())
        {
            return Err("proposed status or case is outside scope".into());
        }
        let before = self.connector.read(&input.resource).await?;
        let evidence = ReviewEvidence {
            provider_profile_digest: self.connector.digest.clone(),
            resource: before.id.clone(),
            resource_version: before.version.clone(),
            fields: vec![FieldValue {
                field: "status".into(),
                value: before.status.as_str().into(),
            }],
        }
        .canonicalized()
        .map_err(|e| e.to_string())?;
        let action = PreparedAction {
            schema_version: opaque_core::scope::VERSION,
            action_id: uuid::Uuid::new_v4().to_string(),
            request_id: input.request_id.clone(),
            scope_id: grant.scope_id.clone(),
            scope_digest: grant.digest().map_err(|e| e.to_string())?,
            owner: self.owner.clone(),
            subject: context.sub.to_string(),
            operation: connector::OPERATION.into(),
            provider_profile_digest: self.connector.digest.clone(),
            resource: input.resource.clone(),
            resource_version: before.version.clone(),
            fields: vec![FieldValue {
                field: "status".into(),
                value: input.status.as_str().into(),
            }],
            evidence_digest: evidence.digest().map_err(|e| e.to_string())?,
        }
        .canonicalized()
        .map_err(|e| e.to_string())?;
        action.validate_for(&grant).map_err(|e| e.to_string())?;
        Ok((action, evidence))
    }
    async fn review_action(
        &self,
        input: Prepare,
        context: &PrincipalContext,
    ) -> Result<Value, String> {
        let (action, evidence) = self.prepare(&input, context).await?;
        let scope = self.grant(&input.scope_id, context.sub.as_str())?;
        self.authority(context.sub.as_str(), Some(context), |current| {
            let issuance = self.issuance(&input.issuance_round_id, current, now_unix())?;
            self.reviews
                .revalidate_scope(&scope, &issuance, current, now_unix())
                .map_err(|e| e.to_string())?;
            let subject = ReviewSubject::exact_action_with_evidence(
                &scope,
                &action,
                action.action_id.clone(),
                1,
                evidence,
            )
            .map_err(|e| e.to_string())?;
            Ok(json!(
                self.reviews
                    .issue(subject, current, 300, now_unix())
                    .map_err(|e| e.to_string())?
            ))
        })
    }
    async fn execute(&self, input: Execute, context: &PrincipalContext) -> Result<Value, String> {
        let snapshot = self
            .reviews
            .retained(&input.round_id)
            .map_err(|e| e.to_string())?;
        let receipt = snapshot.receipt.ok_or("action review has no decision")?;
        let ReviewSubject::ExactAction { scope, action, .. } = &receipt.review.document.subject
        else {
            return Err("exact action round required".into());
        };
        self.dispatch(
            scope,
            action,
            &input.issuance_round_id,
            Some(&receipt),
            context,
        )
        .await
    }
    async fn run(&self, input: Prepare, context: &PrincipalContext) -> Result<Value, String> {
        if self.config.exact_action {
            return Err("current policy requires exact action review".into());
        }
        let (action, _evidence) = self.prepare(&input, context).await?;
        let scope = self.grant(&input.scope_id, context.sub.as_str())?;
        self.dispatch(&scope, &action, &input.issuance_round_id, None, context)
            .await
    }
    async fn dispatch(
        &self,
        scope: &ScopeGrant,
        action: &PreparedAction,
        issuance_id: &str,
        action_receipt: Option<&DecisionReceipt>,
        context: &PrincipalContext,
    ) -> Result<Value, String> {
        if scope.subject != context.sub.as_str()
            || action.fields.len() != 1
            || action.fields[0].field != "status"
        {
            return Err("invalid scoped action".into());
        }
        let status: Status = serde_json::from_value(json!(action.fields[0].value))
            .map_err(|_| "unsupported support status")?;
        let existing = self.authority(context.sub.as_str(), Some(context), |current| {
            let now = now_unix();
            let issuance = self.issuance(issuance_id, current, now)?;
            let guard = Guard {
                runtime: self,
                current,
                issuance: &issuance,
                action_receipt,
            };
            let review = action_receipt
                .map(|r| {
                    self.reviews
                        .action_binding(r, current, now)
                        .map_err(|e| e.to_string())
                })
                .transpose()?;
            let evidence = AdmissionEvidence {
                schema_version: opaque_core::scope::VERSION,
                policy_digest: self.policy_digest.clone(),
                scope_digest: scope.digest().map_err(|e| e.to_string())?,
                action_digest: action.digest().map_err(|e| e.to_string())?,
                authority_revision: current.authority().authority_epoch,
                evaluated_at: now,
                expires_at: review
                    .as_ref()
                    .map(|r| r.expires_at)
                    .unwrap_or(scope.expires_at)
                    .min(now + 60),
                review,
                evaluators: vec![],
            };
            let record = self
                .ledger
                .reserve(action.clone(), evidence, &guard, now)
                .map_err(|e| e.to_string())?;
            // A duplicate request returns its retained outcome, never a new send.
            // The first caller may still be in flight; RESERVED is not permission.
            if record.action.action_id != action.action_id
                || record.state != opaque_bounded_work::scope_store::ExecutionState::Reserved
            {
                return Ok(Some(json!(record)));
            }
            match self.ledger.claim_dispatch(
                &action.action_id,
                &action.digest().map_err(|e| e.to_string())?,
                &guard,
                now_unix(),
            ) {
                Ok(_) => Ok(None),
                Err(opaque_bounded_work::scope_store::ScopeStoreError::Consumed) => {
                    Ok(Some(json!(
                        self.ledger
                            .get_action(&action.action_id)
                            .map_err(|e| e.to_string())?
                    )))
                }
                Err(e) => Err(e.to_string()),
            }
        })?;
        if let Some(existing) = existing {
            return Ok(existing);
        }
        let outcome = self
            .connector
            .write(
                &action.resource,
                &action.resource_version,
                status,
                &action.action_id,
            )
            .await;
        Ok(json!(
            self.ledger
                .finish(&action.action_id, outcome, now_unix())
                .map_err(|_| "dispatch consumed; outcome storage unavailable, do not retry")?
        ))
    }
    fn snapshot(&self, context: &PrincipalContext) -> Result<Value, String> {
        if !context.sub_roles.contains(&Role::Auditor) && !context.sub_roles.contains(&Role::Admin)
        {
            return Err("scope audit role required".into());
        }
        let mut result = None;
        self.identity.with_dispatch_authority(Some(context),None,&mut ||{
            let mut ledger=self.ledger.snapshot(20).map_err(|e|e.to_string())?;
            for scope in ledger["scopes"].as_array_mut().ok_or("invalid ledger projection")? {
                let resources=scope["grant"]["resources"].take();
                scope["resource_count"]=json!(resources.as_array().ok_or("invalid resource projection")?.len());
                scope["resource_set_digest"]=json!(connector::hash(&resources)?);
                scope["grant"].as_object_mut().ok_or("invalid scope projection")?.remove("resources");
            }
            let (total,retained)=self.reviews.list_retained(20).map_err(|e|e.to_string())?;
            let mut reviews=Vec::new();
            for round in retained {
                let document=&round.review.document;
                if let ReviewSubject::ExactAction{action,case_id,case_revision,evidence,..}=&document.subject {
                    reviews.push(json!({"round_id":document.round_id,"state":round.state,"created_at":document.created_at,"expires_at":document.expires_at,
                        "action":action,"before_fields":evidence.as_ref().map(|e|&e.fields),"action_digest":action.digest().map_err(|e|e.to_string())?,"case_id":case_id,"case_revision":case_revision,
                        "required_role":document.authority.required_role,"policy_digest":document.authority.policy_digest,"receipt_digest":round.receipt.map(|r|r.digest()).transpose().map_err(|e|e.to_string())?}));
                }
            }
            let value=json!({"schema_version":1,"owner":self.owner,"observed_at":now_unix(),"ledger":ledger,"reviews_total":total,"reviews":reviews,
                "authority_policy":self.config.authority_policy.as_ref().map(|p|json!({"digest":p.digest,"identity":p.identity}))});
            if serde_json::to_vec(&value).map_err(|_|"snapshot encoding failed")?.len()>opaque_core::MAX_FRAME_LENGTH-4096{return Err("scope snapshot exceeds frame limit; narrower pagination required".into());}
            result=Some(value);Ok(())
        })?;
        result.ok_or_else(|| "scope snapshot unavailable".into())
    }
    fn read_or_revoke(
        &self,
        context: &PrincipalContext,
        id: &str,
        revoke: bool,
    ) -> Result<Value, String> {
        let mut result = None;
        self.identity
            .with_dispatch_authority(Some(context), None, &mut || {
                let record = self.ledger.get_scope(id).map_err(|e| e.to_string())?;
                if record.grant.subject != context.sub.as_str() {
                    return Err("scope owner mismatch".into());
                }
                result = Some(json!(if revoke {
                    self.ledger
                        .revoke(id, now_unix())
                        .map_err(|e| e.to_string())?
                } else {
                    record
                }));
                Ok(())
            })?;
        result.ok_or_else(|| "scope unavailable".into())
    }
    pub async fn handle(
        &self,
        request: &Request,
        context: &PrincipalContext,
    ) -> Result<Value, String> {
        fn decode<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, String> {
            serde_json::from_value(v.clone()).map_err(|_| "invalid scope request".into())
        }
        match request.method.as_str() {
            "scope_plan" => self.plan(decode(&request.params)?, context),
            "scope_activate" => self.activate(decode(&request.params)?, context),
            "scope_prepare" => self.review_action(decode(&request.params)?, context).await,
            "scope_execute" => self.execute(decode(&request.params)?, context).await,
            "scope_run" => self.run(decode(&request.params)?, context).await,
            "scope_snapshot" => {
                if request.params != json!({}) {
                    return Err("invalid snapshot request".into());
                }
                self.snapshot(context)
            }
            "scope_get" => {
                let input: Id = decode(&request.params)?;
                self.read_or_revoke(context, &input.scope_id, false)
            }
            "scope_outcome" => {
                let input: OutcomeRequest = decode(&request.params)?;
                let mut result = None;
                self.identity
                    .with_dispatch_authority(Some(context), None, &mut || {
                        result = Some(json!(
                            self.ledger
                                .get_request(
                                    &input.scope_id,
                                    context.sub.as_str(),
                                    &input.request_id
                                )
                                .map_err(|e| e.to_string())?
                        ));
                        Ok(())
                    })?;
                result.ok_or_else(|| "scope outcome unavailable".into())
            }
            "scope_revoke" => {
                let input: Id = decode(&request.params)?;
                self.read_or_revoke(context, &input.scope_id, true)
            }
            _ => Err("unsupported scope method".into()),
        }
    }
}
struct Guard<'a> {
    runtime: &'a Runtime,
    current: &'a CurrentAuthority,
    issuance: &'a DecisionReceipt,
    action_receipt: Option<&'a DecisionReceipt>,
}
impl AuthorityGuard for Guard<'_> {
    fn verify_scope(&self, grant: &ScopeGrant, now: i64) -> Result<(), String> {
        self.runtime.policy(grant)?;
        self.runtime
            .reviews
            .revalidate_scope(grant, self.issuance, self.current, now)
            .map_err(|e| e.to_string())
    }
    fn verify_action(
        &self,
        grant: &ScopeGrant,
        action: &PreparedAction,
        evidence: &AdmissionEvidence,
        now: i64,
    ) -> Result<(), String> {
        self.verify_scope(grant, now)?;
        if evidence.authority_revision != self.current.authority().authority_epoch
            || !evidence.evaluators.is_empty()
        {
            return Err("unsupported or stale admission evidence".into());
        }
        if let Some(receipt) = self.action_receipt {
            let ReviewSubject::ExactAction {
                case_id,
                case_revision,
                ..
            } = &receipt.review.document.subject
            else {
                return Err("exact action review required".into());
            };
            let binding = self
                .runtime
                .reviews
                .revalidate_action(
                    grant,
                    action,
                    case_id,
                    *case_revision,
                    receipt,
                    self.current,
                    now,
                )
                .map_err(|e| e.to_string())?;
            if evidence.review.as_ref() != Some(&binding) {
                return Err("review binding changed".into());
            }
        } else if grant.requirements.minimum_approval == MinimumApproval::ExactAction
            || evidence.review.is_some()
        {
            return Err("exact action approval missing".into());
        }
        Ok(())
    }
}

pub async fn handle(
    state: &crate::DaemonState,
    request: Request,
    context: Option<PrincipalContext>,
) -> Response {
    use opaque_core::audit::{AuditEvent, AuditEventKind};
    let correlation = uuid::Uuid::new_v4();
    let request_hash = connector::hash(&json!({"method":request.method,"params":request.params}))
        .unwrap_or_default();
    state.audit.emit(
        AuditEvent::new(AuditEventKind::RequestReceived)
            .with_request_id(correlation)
            .with_operation(connector::OPERATION)
            .with_request_hash(request_hash)
            .with_detail(
                "scope workflow RPC received; scope ledger retains authority and dispatch outcomes",
            ),
    );
    if state.enclave.confirm_audit(false).await.is_err() {
        return Response::err(
            Some(request.id),
            "audit_unavailable",
            "scope request was not dispatched: audit durability unavailable",
        );
    }
    let result = match (&state.scope_workflow, context) {
        (Some(runtime), Some(context)) => runtime.handle(&request, &context).await,
        _ => Err(
            "scope workflow requires configured isolated custody and verified delegation".into(),
        ),
    };
    match result {
        Ok(value) => Response::ok(request.id, value),
        Err(error) => {
            tracing::warn!(method=%request.method,error=%error,"scope request denied or unavailable");
            state.audit.emit(AuditEvent::new(AuditEventKind::OperationFailed).with_request_id(correlation).with_operation(connector::OPERATION).with_outcome("unavailable").with_detail("scope workflow denied or unavailable; inspect retained action outcome before any retry"));
            let _ = state.enclave.confirm_audit(true).await;
            Response::err(
                Some(request.id),
                "scope_unavailable",
                "scope request denied or unavailable; inspect broker audit and retained outcome before any retry",
            )
        }
    }
}

use opaque_approval::approval_server::{
    ScopeReviewKey, ScopeReviewService, ScopeReviewServiceError as ServiceError,
};
use opaque_approval::pairing::store::PairedDevice;
impl Runtime {
    fn device(&self, device: &PairedDevice) -> Result<(), ServiceError> {
        if device.device_id != self.device_id
            || device.public_key_hex != self.config.reviewer_public_key
            || device.paired_by.as_deref() != Some(&self.config.reviewer_id)
        {
            Err(ServiceError::Forbidden)
        } else {
            Ok(())
        }
    }
    fn reviewed<T>(
        &self,
        device: &PairedDevice,
        id: &str,
        f: impl FnOnce(&CurrentAuthority) -> Result<T, String>,
    ) -> Result<T, ServiceError> {
        self.device(device)?;
        let retained = self
            .reviews
            .retained(id)
            .map_err(|_| ServiceError::NotFound)?;
        self.authority(&retained.review.document.authority.requester_id, None, f)
            .map_err(|_| ServiceError::Conflict)
    }
}
impl ScopeReviewService for Runtime {
    fn key(&self, device: &PairedDevice) -> Result<ScopeReviewKey, ServiceError> {
        self.device(device)?;
        Ok(ScopeReviewKey {
            broker_public_key: self.reviews.broker_public_key().into(),
            reviewer_id: self.config.reviewer_id.clone(),
            device_id: self.device_id.clone(),
            reviewer_public_key: self.config.reviewer_public_key.clone(),
        })
    }
    fn pending(&self, device: &PairedDevice) -> Result<Vec<SignedReview>, ServiceError> {
        self.device(device)?;
        let (_, rounds) = self
            .reviews
            .list_retained(100)
            .map_err(|_| ServiceError::Unavailable)?;
        // Full documents are deliberately bounded to one transport response.
        // Known round IDs remain individually addressable regardless of window.
        for round in rounds {
            if round.state == RoundState::Pending
                && let Ok(review) = self.get(device, &round.review.document.round_id)
            {
                return Ok(vec![review]);
            }
        }
        Ok(vec![])
    }
    fn get(&self, device: &PairedDevice, id: &str) -> Result<SignedReview, ServiceError> {
        self.reviewed(device, id, |current| {
            let snapshot = self
                .reviews
                .snapshot(id, current, now_unix())
                .map_err(|e| e.to_string())?;
            if snapshot.state != RoundState::Pending {
                return Err("scope round is closed".into());
            }
            snapshot
                .review
                .verify(self.reviews.broker_public_key(), now_unix())
                .map_err(|e| e.to_string())?;
            self.policy(snapshot.review.document.subject.scope())?;
            if let ReviewSubject::ExactAction { scope, .. } = &snapshot.review.document.subject {
                self.grant(&scope.scope_id, &scope.subject)?;
            }
            Ok(snapshot.review)
        })
    }
    fn submit(
        &self,
        device: &PairedDevice,
        id: &str,
        response: &ReviewerDecision,
    ) -> Result<DecisionReceipt, ServiceError> {
        self.reviewed(device, id, |current| {
            let snapshot = self
                .reviews
                .snapshot(id, current, now_unix())
                .map_err(|e| e.to_string())?;
            self.policy(snapshot.review.document.subject.scope())?;
            if let ReviewSubject::ExactAction { scope, .. } = &snapshot.review.document.subject {
                self.grant(&scope.scope_id, &scope.subject)?;
            }
            self.reviews
                .submit(id, response, current, now_unix())
                .map_err(|e| e.to_string())
        })
    }
    fn receipt(
        &self,
        device: &PairedDevice,
        id: &str,
    ) -> Result<Option<DecisionReceipt>, ServiceError> {
        self.reviewed(device, id, |current| {
            self.reviews
                .receipt(id, current, now_unix())
                .map_err(|e| e.to_string())
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
