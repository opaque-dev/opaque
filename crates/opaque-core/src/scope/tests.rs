use super::*;
use proptest::prelude::*;

type GrantMutation = Box<dyn Fn(&mut ScopeGrant)>;
type ActionMutation = Box<dyn Fn(&mut PreparedAction)>;
type EvidenceMutation = Box<dyn Fn(&mut AdmissionEvidence)>;

fn h() -> String {
    "a".repeat(64)
}
fn grant() -> ScopeGrant {
    ScopeGrant {
        schema_version: VERSION,
        scope_id: "root".into(),
        root_id: "root".into(),
        parent_id: None,
        owner: AuthorityOwner {
            tenant_id: "tenant".into(),
            broker_id: "broker".into(),
            generation: "g1".into(),
        },
        issuer: "human".into(),
        subject: "agent".into(),
        operation: "fixture.update".into(),
        provider_profile_digest: h(),
        resources: vec!["r2".into(), "r1".into()],
        fields: vec![FieldConstraint {
            field: "status".into(),
            allowed_values: vec!["open".into(), "closed".into()],
        }],
        not_before: 10,
        expires_at: 1000,
        delegations_remaining: 2,
        max_charged_attempts: 10,
        max_distinct_resources: 2,
        requirements: ScopeRequirements {
            policy_digest: h(),
            minimum_approval: MinimumApproval::ExactAction,
            evaluator_checks: vec![EvaluatorRequirement {
                check_id: "intent".into(),
                contract_digest: h(),
            }],
        },
        issuance_receipt_digest: h(),
    }
}
fn child(parent: &ScopeGrant) -> ScopeGrant {
    let mut child = parent.clone();
    child.scope_id = "child".into();
    child.parent_id = Some(parent.scope_id.clone());
    child.issuer = parent.subject.clone();
    child.subject = "child-agent".into();
    child.delegations_remaining = 1;
    child
}
fn action(grant: &ScopeGrant) -> PreparedAction {
    PreparedAction {
        schema_version: VERSION,
        action_id: "a1".into(),
        request_id: "q1".into(),
        scope_id: grant.scope_id.clone(),
        scope_digest: grant.digest().unwrap(),
        owner: grant.owner.clone(),
        subject: grant.subject.clone(),
        operation: grant.operation.clone(),
        provider_profile_digest: h(),
        resource: "r1".into(),
        resource_version: "v1".into(),
        fields: vec![FieldValue {
            field: "status".into(),
            value: "closed".into(),
        }],
        evidence_digest: h(),
    }
}
fn evidence(grant: &ScopeGrant, action: &PreparedAction) -> AdmissionEvidence {
    AdmissionEvidence {
        schema_version: VERSION,
        policy_digest: h(),
        scope_digest: grant.digest().unwrap(),
        action_digest: action.digest().unwrap(),
        authority_revision: 1,
        evaluated_at: 100,
        expires_at: 800,
        review: Some(ReviewBinding {
            schema_version: VERSION,
            case_id: "case1".into(),
            case_revision: 1,
            action_id: action.action_id.clone(),
            action_digest: action.digest().unwrap(),
            scope_digest: grant.digest().unwrap(),
            evidence_digest: h(),
            policy_digest: h(),
            round_id: "round1".into(),
            decision_receipt_digest: h(),
            expires_at: 900,
        }),
        evaluators: vec![EvaluatorReceipt {
            check_id: "intent".into(),
            contract_digest: h(),
            receipt_digest: h(),
            action_digest: action.digest().unwrap(),
            evidence_digest: h(),
        }],
    }
}

#[test]
fn canonical_sets_are_order_independent_but_authority_is_bound() {
    let grant = grant();
    let hash = grant.digest().unwrap();
    let mut reordered = grant.clone();
    reordered.resources.reverse();
    reordered.fields[0].allowed_values.reverse();
    assert_eq!(hash, reordered.digest().unwrap());
    let mutations: Vec<GrantMutation> = vec![
        Box::new(|g| g.owner.generation = "g2".into()),
        Box::new(|g| g.subject = "other".into()),
        Box::new(|g| g.resources[0] = "r3".into()),
        Box::new(|g| g.fields[0].allowed_values[0] = "pending".into()),
        Box::new(|g| g.max_charged_attempts = 9),
        Box::new(|g| g.expires_at = 999),
        Box::new(|g| g.requirements.policy_digest = "b".repeat(64)),
        Box::new(|g| g.requirements.minimum_approval = MinimumApproval::ScopeIssuance),
    ];
    for mutate in mutations {
        let mut changed = grant.clone();
        mutate(&mut changed);
        assert_ne!(hash, changed.digest().unwrap());
    }
    assert_ne!(grant.digest().unwrap(), action(&grant).digest().unwrap());
}

#[test]
fn strict_wire_schema_rejects_unknown_duplicate_and_boolean_bypass() {
    let grant = grant();
    let json = serde_json::to_string(&grant).unwrap();
    assert!(
        serde_json::from_str::<ScopeGrant>(&json.replacen('{', "{\"schema_version\":1,", 1))
            .is_err()
    );
    let mut value = serde_json::to_value(&grant).unwrap();
    value["rate_per_minute"] = 100.into();
    assert!(serde_json::from_value::<ScopeGrant>(value).is_err());
    let mut value = serde_json::to_value(&grant).unwrap();
    value["requirements"]["minimum_approval"] = true.into();
    assert!(serde_json::from_value::<ScopeGrant>(value).is_err());
    let mut grant = grant;
    grant.schema_version = 2;
    assert_eq!(grant.canonicalized(), Err(ScopeError::Version));
}

#[test]
fn finite_bounds_duplicates_and_invalid_ids_fail() {
    let original = grant();
    let mutations: Vec<GrantMutation> = vec![
        Box::new(|g| g.resources.push(g.resources[0].clone())),
        Box::new(|g| g.fields.push(g.fields[0].clone())),
        Box::new(|g| g.fields[0].allowed_values.push("closed".into())),
        Box::new(|g| g.fields[0].allowed_values.clear()),
        Box::new(|g| g.resources.clear()),
        Box::new(|g| g.fields.clear()),
        Box::new(|g| g.resources = (0..MAX_RESOURCES + 1).map(|n| format!("r{n}")).collect()),
        Box::new(|g| g.fields[0].allowed_values[0] = "x".repeat(1025)),
        Box::new(|g| g.subject = "bad\nsubject".into()),
        Box::new(|g| g.provider_profile_digest = "A".repeat(64)),
        Box::new(|g| g.delegations_remaining = MAX_DEPTH + 1),
        Box::new(|g| g.not_before = -1),
        Box::new(|g| g.expires_at = g.not_before),
        Box::new(|g| g.max_charged_attempts = 0),
        Box::new(|g| g.max_distinct_resources = 3),
        Box::new(|g| g.parent_id = Some(g.scope_id.clone())),
        Box::new(|g| {
            g.requirements
                .evaluator_checks
                .push(g.requirements.evaluator_checks[0].clone())
        }),
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(changed.canonicalized().is_err());
    }
}

#[test]
fn child_must_narrow_every_authority_dimension_and_preserve_checks() {
    let parent = grant();
    let original = child(&parent);
    original.validate_child_of(&parent).unwrap();
    let mutations: Vec<GrantMutation> = vec![
        Box::new(|g| g.owner.tenant_id = "foreign".into()),
        Box::new(|g| g.owner.generation = "g2".into()),
        Box::new(|g| g.issuer = "other".into()),
        Box::new(|g| g.operation = "delete".into()),
        Box::new(|g| g.provider_profile_digest = "b".repeat(64)),
        Box::new(|g| g.resources[0] = "outside".into()),
        Box::new(|g| g.fields[0].field = "other".into()),
        Box::new(|g| g.fields[0].allowed_values[0] = "outside".into()),
        Box::new(|g| g.not_before = 9),
        Box::new(|g| g.expires_at = 1001),
        Box::new(|g| g.max_charged_attempts = 11),
        Box::new(|g| g.delegations_remaining = 2),
        Box::new(|g| g.requirements.minimum_approval = MinimumApproval::ScopeIssuance),
        Box::new(|g| g.requirements.evaluator_checks.clear()),
        Box::new(|g| g.requirements.policy_digest = "b".repeat(64)),
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(changed.validate_child_of(&parent).is_err());
    }
    let mut narrower = original;
    narrower.resources = vec!["r1".into()];
    narrower.max_distinct_resources = 1;
    narrower.fields[0].allowed_values = vec!["closed".into()];
    narrower.validate_child_of(&parent).unwrap();
}

#[test]
fn prepared_action_rejects_changed_identity_route_and_field_values() {
    let scope = grant();
    let original = action(&scope);
    original.validate_for(&scope).unwrap();
    let mutations: Vec<ActionMutation> = vec![
        Box::new(|a| a.owner.broker_id = "other".into()),
        Box::new(|a| a.subject = "other".into()),
        Box::new(|a| a.scope_digest = "b".repeat(64)),
        Box::new(|a| a.scope_id = "other".into()),
        Box::new(|a| a.resource = "outside".into()),
        Box::new(|a| a.operation = "delete".into()),
        Box::new(|a| a.provider_profile_digest = "b".repeat(64)),
        Box::new(|a| a.fields[0].value = "outside".into()),
        Box::new(|a| a.fields[0].field = "other".into()),
        Box::new(|a| a.fields.clear()),
        Box::new(|a| a.fields.push(a.fields[0].clone())),
        Box::new(|a| a.resource_version.clear()),
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(changed.validate_for(&scope).is_err());
    }
    let mut other = original.clone();
    other.action_id = "another".into();
    assert_ne!(other.digest().unwrap(), original.digest().unwrap());
    other = original.clone();
    other.resource_version = "v2".into();
    assert_ne!(other.digest().unwrap(), original.digest().unwrap());
    other = original.clone();
    other.evidence_digest = "b".repeat(64);
    assert_ne!(other.digest().unwrap(), original.digest().unwrap());
}

#[test]
fn required_review_and_evaluator_receipts_bind_exact_action_and_context() {
    let scope = grant();
    let action = action(&scope);
    let original = evidence(&scope, &action);
    original.validate_for(&scope, &action, 100).unwrap();
    let mutations: Vec<EvidenceMutation> = vec![
        Box::new(|e| e.review = None),
        Box::new(|e| e.evaluators.clear()),
        Box::new(|e| e.authority_revision = 0),
        Box::new(|e| e.evaluated_at = 101),
        Box::new(|e| e.expires_at = 100),
        Box::new(|e| e.expires_at = 1001),
        Box::new(|e| e.action_digest = "b".repeat(64)),
        Box::new(|e| e.policy_digest = "b".repeat(64)),
        Box::new(|e| e.review.as_mut().unwrap().action_id = "same-payload-new-action".into()),
        Box::new(|e| e.review.as_mut().unwrap().evidence_digest = "b".repeat(64)),
        Box::new(|e| e.review.as_mut().unwrap().expires_at = 100),
        Box::new(|e| e.review.as_mut().unwrap().case_revision = 0),
        Box::new(|e| e.evaluators[0].contract_digest = "b".repeat(64)),
        Box::new(|e| e.evaluators[0].action_digest = "b".repeat(64)),
        Box::new(|e| e.evaluators[0].evidence_digest = "b".repeat(64)),
        Box::new(|e| e.evaluators.push(e.evaluators[0].clone())),
    ];
    for mutate in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert!(changed.validate_for(&scope, &action, 100).is_err());
    }
    let review = original.review.unwrap();
    let mut changed = review.clone();
    changed.round_id = "another-round".into();
    assert_ne!(review.digest().unwrap(), changed.digest().unwrap());
}

proptest! {
    #[test]
    fn finite_child_membership_never_adds_a_resource(indices in prop::collection::btree_set(0_usize..12, 1..8)) {
        let mut parent = grant(); parent.resources = (0..8).map(|n| format!("r{n}")).collect(); parent.max_distinct_resources = 8;
        let mut descendant = child(&parent); descendant.resources = indices.iter().map(|n| format!("r{n}")).collect(); descendant.max_distinct_resources = descendant.resources.len() as u32;
        prop_assert_eq!(descendant.validate_child_of(&parent).is_ok(), indices.iter().all(|i| *i < 8));
    }
}
