//! Negative authority-boundary qualification using real retained signed reviews.
use super::*;

type ConfigMutation = (&'static str, fn(&mut Config));
type ScopeMutation = (&'static str, fn(&mut ScopeGrant));

#[tokio::test]
async fn invalid_startup_policy_or_reviewer_creates_no_authority_custody() {
    let provider = Provider::new(vec![]).await;
    let f = Fixture::new(&provider, true);
    let mutations: &[ConfigMutation] = &[
        ("generation", |c| c.generation = 0),
        ("duration zero", |c| c.max_scope_seconds = 0),
        ("duration excessive", |c| c.max_scope_seconds = 86401),
        ("attempts zero", |c| c.max_attempts = 0),
        ("attempts excessive", |c| c.max_attempts = 10001),
        ("resources zero", |c| c.max_resources = 0),
        ("resources excessive", |c| c.max_resources = 101),
        ("no statuses", |c| c.allowed_statuses.clear()),
        ("too many statuses", |c| {
            c.allowed_statuses = vec![Status::Closed; 4]
        }),
        ("invalid reviewer", |c| c.reviewer_id = "invalid".into()),
        ("unknown key", |c| c.reviewer_public_key = "ab".repeat(32)),
    ];
    for (name, mutate) in mutations {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = f.runtime.config.clone();
        mutate(&mut config);
        assert!(
            Runtime::open(
                config,
                &f.tenant,
                root.path(),
                f.runtime.identity.clone(),
                f.runtime.pairing.clone()
            )
            .is_err(),
            "{name}"
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0, "{name}");
    }
    let root = tempfile::tempdir().unwrap();
    let mut config = f.runtime.config.clone();
    config.reviewer_id = f.context.act.to_string();
    assert!(
        matches!(Runtime::open(config, &f.tenant, root.path(), f.runtime.identity.clone(), f.runtime.pairing.clone()), Err(e) if e == "scope reviewer must be human")
    );
    let mut config = f.runtime.config.clone();
    config.reviewer_id = f.context.sub.to_string();
    assert!(
        matches!(Runtime::open(config, &f.tenant, root.path(), f.runtime.identity.clone(), f.runtime.pairing.clone()), Err(e) if e.contains("enrolled configured workstation"))
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    assert!(provider.finish().await.is_empty());
}

#[tokio::test]
async fn typed_host_policy_rejects_every_unsupported_authority_expansion() {
    let provider = Provider::new(vec![]).await;
    let f = Fixture::new(&provider, true);
    let (scope, _) = f.issued(1);
    f.runtime.policy(&scope).unwrap();
    let mutations: &[ScopeMutation] = &[
        ("owner", |s| s.owner.generation = "2".into()),
        ("issuer", |s| s.issuer = "another-issuer".into()),
        ("child grant", |s| s.parent_id = Some("parent".into())),
        ("delegation", |s| s.delegations_remaining = 1),
        ("operation", |s| s.operation = "support.delete".into()),
        ("provider", |s| s.provider_profile_digest = "ab".repeat(32)),
        ("policy", |s| s.requirements.policy_digest = "ab".repeat(32)),
        ("evaluator", |s| {
            s.requirements.evaluator_checks.push(EvaluatorRequirement {
                check_id: "jev".into(),
                contract_digest: "ab".repeat(32),
            })
        }),
        ("approval downgrade", |s| {
            s.requirements.minimum_approval = MinimumApproval::ScopeIssuance
        }),
        ("attempt budget", |s| s.max_charged_attempts = 3),
        ("resource budget", |s| s.max_distinct_resources = 3),
        ("lifetime", |s| s.expires_at = s.not_before + 3601),
        ("missing field", |s| s.fields.clear()),
        ("additional field", |s| {
            s.fields.push(FieldConstraint {
                field: "assignee".into(),
                allowed_values: vec!["someone".into()],
            })
        }),
        ("field substitution", |s| {
            s.fields[0].field = "assignee".into()
        }),
        ("value widening", |s| {
            s.fields[0].allowed_values.push("open".into())
        }),
        ("resource path", |s| s.resources = vec!["../case1".into()]),
    ];
    for (name, mutate) in mutations {
        let mut changed = scope.clone();
        mutate(&mut changed);
        assert!(f.runtime.policy(&changed).is_err(), "{name}");
    }
    assert_eq!(
        f.runtime.ledger.get_scope(&scope.scope_id).unwrap().grant,
        scope
    );
    assert_eq!(
        f.runtime
            .ledger
            .get_scope(&scope.scope_id)
            .unwrap()
            .charged_attempts,
        0
    );
    assert!(provider.finish().await.is_empty());
}

#[tokio::test]
async fn dispatch_shape_and_review_kind_cannot_bypass_prepared_action_binding() {
    let provider = Provider::new(vec![read_reply()]).await;
    let f = Fixture::new(&provider, true);
    let (scope, issuance) = f.issued(1);
    let review = f.prepared(&scope, &issuance, "shape-boundary").await;
    let receipt = f.approve(&review);
    let ReviewSubject::ExactAction { action, .. } = &review.document.subject else {
        panic!()
    };
    let mut foreign = scope.clone();
    foreign.subject = "another-requester".into();
    assert_eq!(
        f.runtime
            .dispatch(&foreign, action, &issuance, Some(&receipt), &f.context)
            .await
            .unwrap_err(),
        "invalid scoped action"
    );
    for fields in [
        vec![],
        vec![FieldValue {
            field: "assignee".into(),
            value: "closed".into(),
        }],
        vec![FieldValue {
            field: "status".into(),
            value: "not-a-status".into(),
        }],
    ] {
        let mut changed = (**action).clone();
        changed.fields = fields;
        assert!(
            f.runtime
                .dispatch(&scope, &changed, &issuance, Some(&receipt), &f.context)
                .await
                .is_err()
        );
    }
    assert_eq!(
        f.runtime
            .execute(
                Execute {
                    round_id: issuance.clone(),
                    issuance_round_id: issuance
                },
                &f.context
            )
            .await
            .unwrap_err(),
        "exact action round required"
    );
    assert_eq!(
        f.runtime
            .ledger
            .get_scope(&scope.scope_id)
            .unwrap()
            .charged_attempts,
        0
    );
    assert_eq!(provider.finish().await.len(), 1);
}

#[tokio::test]
async fn admission_guard_requires_current_epoch_supported_evidence_and_exact_receipt() {
    for exact in [true, false] {
        let provider = Provider::new(vec![read_reply()]).await;
        let f = Fixture::new(&provider, exact);
        let (scope, issuance_id) = f.issued(1);
        let review = f.prepared(&scope, &issuance_id, "guard-boundary").await;
        let receipt = f.approve(&review);
        let issuance = f
            .runtime
            .reviews
            .retained(&issuance_id)
            .unwrap()
            .receipt
            .unwrap();
        let ReviewSubject::ExactAction { action, .. } = &review.document.subject else {
            panic!()
        };
        f.runtime
            .authority(f.context.sub.as_str(), Some(&f.context), |current| {
                let now = now_unix();
                let binding = f
                    .runtime
                    .reviews
                    .action_binding(&receipt, current, now)
                    .unwrap();
                let evidence = AdmissionEvidence {
                    schema_version: opaque_core::scope::VERSION,
                    policy_digest: f.runtime.policy_digest.clone(),
                    scope_digest: scope.digest().unwrap(),
                    action_digest: action.digest().unwrap(),
                    authority_revision: current.authority().authority_epoch,
                    evaluated_at: now,
                    expires_at: binding.expires_at,
                    review: Some(binding),
                    evaluators: vec![],
                };
                let guard = Guard {
                    runtime: &f.runtime,
                    current,
                    issuance: &issuance,
                    action_receipt: Some(&receipt),
                };
                guard.verify_action(&scope, action, &evidence, now).unwrap();
                let mut stale = evidence.clone();
                stale.authority_revision += 1;
                assert_eq!(
                    guard
                        .verify_action(&scope, action, &stale, now)
                        .unwrap_err(),
                    "unsupported or stale admission evidence"
                );
                let mut invented_evaluator = evidence.clone();
                invented_evaluator.evaluators.push(EvaluatorReceipt {
                    check_id: "jev".into(),
                    contract_digest: "ab".repeat(32),
                    receipt_digest: "cd".repeat(32),
                    action_digest: action.digest().unwrap(),
                    evidence_digest: action.evidence_digest.clone(),
                });
                assert_eq!(
                    guard
                        .verify_action(&scope, action, &invented_evaluator, now)
                        .unwrap_err(),
                    "unsupported or stale admission evidence"
                );
                let mut changed = evidence.clone();
                changed.review.as_mut().unwrap().case_revision += 1;
                assert_eq!(
                    guard
                        .verify_action(&scope, action, &changed, now)
                        .unwrap_err(),
                    "review binding changed"
                );
                changed.review = None;
                assert!(guard.verify_action(&scope, action, &changed, now).is_err());
                let wrong_kind = Guard {
                    action_receipt: Some(&issuance),
                    ..guard
                };
                assert_eq!(
                    wrong_kind
                        .verify_action(&scope, action, &evidence, now)
                        .unwrap_err(),
                    "exact action review required"
                );
                let absent = Guard {
                    action_receipt: None,
                    ..guard
                };
                assert_eq!(
                    absent
                        .verify_action(&scope, action, &evidence, now)
                        .unwrap_err(),
                    "exact action approval missing"
                );
                if exact {
                    assert!(absent.verify_action(&scope, action, &changed, now).is_err());
                } else {
                    absent.verify_action(&scope, action, &changed, now).unwrap();
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(
            f.runtime
                .ledger
                .get_scope(&scope.scope_id)
                .unwrap()
                .charged_attempts,
            0
        );
        assert_eq!(provider.finish().await.len(), 1);
    }
}

#[tokio::test]
async fn pending_reviews_and_agent_reads_observe_revocation_and_enrollment_binding() {
    let provider = Provider::new(vec![read_reply()]).await;
    let f = Fixture::new(&provider, true);
    let (scope, issuance) = f.issued(1);
    let review = f.prepared(&scope, &issuance, "revoked-pending").await;
    let device = f
        .runtime
        .pairing
        .workstation_device(&f.runtime.device_id)
        .unwrap();
    assert_eq!(
        ScopeReviewService::get(&f.runtime, &device, &review.document.round_id).unwrap(),
        review
    );
    for wrong_key in [true, false] {
        let mut changed = device.clone();
        if wrong_key {
            changed.public_key_hex = "ab".repeat(32);
        } else {
            changed.paired_by = Some(f.context.sub.to_string());
        }
        assert!(matches!(
            ScopeReviewService::key(&f.runtime, &changed),
            Err(ServiceError::Forbidden)
        ));
    }
    assert!(
        f.runtime
            .authority(f.runtime.reviewer.as_str(), Some(&f.context), |_| Ok(()))
            .is_err()
    );
    let request = |method: &str, params| Request {
        id: 1,
        method: method.into(),
        params,
    };
    let get = request("scope_get", json!({"scope_id":scope.scope_id}));
    assert!(f.runtime.handle(&get, &f.context).await.unwrap()["revoked_at"].is_null());
    let before = f
        .runtime
        .handle(&request("scope_snapshot", json!({})), &f.context)
        .await
        .unwrap();
    assert_eq!(before["reviews"].as_array().unwrap().len(), 1);
    let revoke = request("scope_revoke", json!({"scope_id":scope.scope_id}));
    assert!(f.runtime.handle(&revoke, &f.context).await.unwrap()["revoked_at"].is_i64());
    assert!(f.runtime.handle(&get, &f.context).await.unwrap()["revoked_at"].is_i64());
    assert!(ScopeReviewService::get(&f.runtime, &device, &review.document.round_id).is_err());
    assert!(
        ScopeReviewService::pending(&f.runtime, &device)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        f.runtime
            .ledger
            .get_scope(&scope.scope_id)
            .unwrap()
            .charged_attempts,
        0
    );
    assert_eq!(provider.finish().await.len(), 1);
}
