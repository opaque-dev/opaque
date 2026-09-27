//! Typed boundary mutations must be rejected before they can become authority
//! or completed-operation evidence. These use production validators directly.
use opaque_core::inference::{self, github::*, *};
use opaque_core::release::*;
use opaque_core::ssh::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn reject_mutations<T: Serialize + DeserializeOwned>(
    valid: &T,
    cases: Vec<(&str, Value)>,
    validate: impl Fn(&T) -> Result<(), &'static str>,
    reason: &str,
) {
    assert_eq!(validate(valid), Ok(()));
    let original = serde_json::to_value(valid).unwrap();
    for (pointer, value) in cases {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).expect("fixture field exists") = value.clone();
        let changed: T = serde_json::from_value(changed).expect("typed mutation");
        assert_eq!(validate(&changed), Err(reason), "{pointer}={value}");
    }
    assert_eq!(serde_json::to_value(valid).unwrap(), original);
}

fn tenant() -> opaque_core::tenant::TenantBinding {
    serde_json::from_value(json!({"schema_version":1,"tenant_id":"test-a","broker_id":"00000000-0000-4000-8000-000000000001"})).unwrap()
}

fn snapshot() -> GithubCiSnapshot {
    GithubCiSnapshot {
        source: GithubCiSource {
            repository: "owner/repo".into(),
            workflow_id: 1,
            branch: "main".into(),
        },
        repository_id: 2,
        observed_at: 100,
        runs: vec![GithubCiRun {
            id: 3,
            attempt: 1,
            head_sha: "a".repeat(40),
            status: RunStatus::Completed,
            conclusion: Some(RunConclusion::Success),
        }],
    }
}

#[test]
fn github_source_identifiers_and_branch_boundaries_reject_non_authority() {
    let source = snapshot().source;
    let mut cases = Vec::new();
    for repository in [
        "/repo".into(),
        "owner/".into(),
        "./repo".into(),
        "../repo".into(),
        "owner/.".into(),
        "owner/..".into(),
        format!("{}/repo", "a".repeat(40)),
        format!("owner/{}", "a".repeat(101)),
        "own er/repo".into(),
    ] {
        cases.push(("/repository", json!(repository)));
    }
    for branch in [
        "".into(),
        "a".repeat(65),
        "/main".into(),
        "main/".into(),
        "a..b".into(),
        "a//b".into(),
        "main?x".into(),
    ] {
        cases.push(("/branch", json!(branch)));
    }
    cases.extend([
        ("/workflow_id", json!(0)),
        ("/workflow_id", json!(9_007_199_254_740_992_u64)),
    ]);
    reject_mutations(
        &source,
        cases,
        GithubCiSource::validate,
        "invalid bounded GitHub source",
    );
    let mut missing = source.clone();
    missing.repository = "repository".into();
    assert_eq!(
        missing.validate(),
        Err("GitHub source requires owner/repository")
    );
    let mut boundary = source;
    boundary.repository = format!("{}/{}", "a".repeat(39), "b".repeat(100));
    boundary.branch = "a".repeat(64);
    boundary.workflow_id = 9_007_199_254_740_991;
    assert_eq!(boundary.validate(), Ok(()));
}

#[test]
fn github_snapshot_bounds_and_run_identity_cannot_create_prompt_evidence() {
    let valid = snapshot();
    reject_mutations(
        &valid,
        vec![
            ("/repository_id", json!(0)),
            ("/repository_id", json!(9_007_199_254_740_992_u64)),
            ("/observed_at", json!(0)),
            ("/runs", json!(vec![valid.runs[0].clone(); 4])),
        ],
        GithubCiSnapshot::validate,
        "invalid GitHub snapshot",
    );
    let cases = vec![
        ("/runs/0/id", json!(0)),
        ("/runs/0/id", json!(9_007_199_254_740_992_u64)),
        ("/runs/0/attempt", json!(0)),
        ("/runs/0/attempt", json!(1_000_001)),
        ("/runs/0/head_sha", json!("a".repeat(39))),
        ("/runs/0/head_sha", json!("A".repeat(40))),
        ("/runs/0/status", json!("queued")),
        ("/runs/0/conclusion", Value::Null),
    ];
    reject_mutations(
        &valid,
        cases.clone(),
        GithubCiSnapshot::validate,
        "invalid GitHub run evidence",
    );
    for (pointer, value) in cases {
        let mut changed = serde_json::to_value(&valid).unwrap();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed: GithubCiSnapshot = serde_json::from_value(changed).unwrap();
        assert!(changed.prompt(1).is_none());
    }
    let mut boundary = valid;
    boundary.runs[0].id = 9_007_199_254_740_991;
    boundary.runs[0].attempt = 1_000_000;
    boundary.runs[0].head_sha = "f".repeat(64);
    assert_eq!(boundary.validate(), Ok(()));
    assert!(boundary.prompt(0).is_none());
    assert!(boundary.prompt(4).is_none());
}

fn inference_action(ordinal: u32) -> InferenceAction {
    InferenceAction {
        operation: INFERENCE_OPERATION.into(),
        ordinal,
        tenant: tenant(),
        profile_id: "reviewed".into(),
        profile_sha256: "a".repeat(64),
        model_id: "model/weights:v1".into(),
        model_artifact_sha256: "b".repeat(64),
        source_id: "public-receipts".into(),
        source_snapshot_sha256: "c".repeat(64),
        github_ci_snapshot: None,
        prompt_sha256: inference::prompt_sha256(
            ["receipt_summary", "uncertainty_check", "next_safe_step"][ordinal as usize - 1],
        )
        .unwrap(),
        credential_ref: None,
        options: InferenceOptions::default(),
    }
}

#[test]
fn inference_authority_rejects_each_invalid_identity_and_non_default_generation_control() {
    let mut cases = vec![
        ("/operation", json!("inference.freeform")),
        ("/ordinal", json!(0)),
    ];
    for field in ["/source_id", "/profile_id"] {
        for value in [String::new(), "a".repeat(97), "name/other".into()] {
            cases.push((field, json!(value)));
        }
    }
    for value in [String::new(), "a".repeat(257), "model?redirect".into()] {
        cases.push(("/model_id", json!(value)));
    }
    for field in [
        "/source_snapshot_sha256",
        "/prompt_sha256",
        "/profile_sha256",
        "/model_artifact_sha256",
    ] {
        cases.push((field, json!("g".repeat(64))));
    }
    for field in [
        "/options/max_input_tokens",
        "/options/max_output_tokens",
        "/options/deadline_secs",
        "/options/temperature",
        "/options/seed",
    ] {
        cases.push((field, json!(1)));
    }
    cases.extend([
        ("/options/cache_prompt", json!(true)),
        ("/options/stream", json!(true)),
    ]);
    reject_mutations(
        &inference_action(1),
        cases,
        InferenceAction::validate,
        "invalid fixed inference authority",
    );
}

#[test]
fn inference_slots_cannot_mix_individually_valid_profiles_credentials_or_sources() {
    for (field, value) in [
        ("profile_sha256", json!("d".repeat(64))),
        ("model_id", json!("another-model")),
        ("model_artifact_sha256", json!("d".repeat(64))),
        ("credential_ref", json!("env:OTHER_TOKEN")),
        ("source_id", json!("other-source")),
        ("source_snapshot_sha256", json!("d".repeat(64))),
    ] {
        let mut actions = [
            inference_action(1),
            inference_action(2),
            inference_action(3),
        ];
        let mut changed = serde_json::to_value(&actions[2]).unwrap();
        changed[field] = value;
        actions[2] = serde_json::from_value(changed).unwrap();
        assert_eq!(actions[2].validate(), Ok(()));
        assert_eq!(
            validate_inference_actions(&actions.iter().collect::<Vec<_>>()),
            Err("inference slots must share one trusted profile"),
            "{field}"
        );
    }
}

#[test]
fn inference_github_binding_rejects_source_and_prompt_changes_after_snapshot_capture() {
    let snapshot = snapshot();
    let mut valid = inference_action(1);
    valid.source_id = SOURCE_ID.into();
    valid.source_snapshot_sha256 = snapshot.digest();
    valid.prompt_sha256 = sha256(snapshot.prompt(1).unwrap().as_bytes());
    valid.github_ci_snapshot = Some(snapshot);
    reject_mutations(
        &valid,
        vec![
            ("/source_id", json!("public-receipts")),
            ("/source_snapshot_sha256", json!("d".repeat(64))),
            ("/prompt_sha256", json!("d".repeat(64))),
            ("/ordinal", json!(4)),
        ],
        InferenceAction::validate,
        "invalid GitHub inference source binding",
    );
}

#[test]
fn inference_receipts_cannot_turn_missing_unsafe_or_uncertain_output_into_completion() {
    let action = inference_action(1);
    let receipt = InferenceReceipt {
        tenant: action.tenant.clone(),
        profile_sha256: action.profile_sha256.clone(),
        prompt_sha256: action.prompt_sha256.clone(),
        code: InferenceReceiptCode::CompletionObserved,
        reserved_output_tokens: 96,
        input_tokens: 1,
        observed_output_tokens: Some(1),
        output_sha256: Some(sha256(b"observed")),
        output_text: Some("observed".into()),
        duration_ms: 31_000,
        completed_at: 1,
    };
    reject_mutations(
        &receipt,
        vec![
            ("/input_tokens", json!(0)),
            ("/input_tokens", json!(513)),
            ("/completed_at", json!(0)),
            ("/duration_ms", json!(31_001)),
        ],
        |r| r.validate(&action),
        "invalid inference receipt binding",
    );
    reject_mutations(
        &receipt,
        vec![
            ("/observed_output_tokens", Value::Null),
            ("/observed_output_tokens", json!(97)),
            ("/output_text", Value::Null),
            ("/output_text", json!("changed")),
            ("/output_text", json!("x".repeat(4097))),
            ("/output_text", json!("visible\u{0007}hidden")),
            ("/output_text", json!("visible\u{202e}hidden")),
            ("/output_sha256", Value::Null),
        ],
        |r| r.validate(&action),
        "invalid inference completion evidence",
    );
    for code in [
        InferenceReceiptCode::TransportUnknown,
        InferenceReceiptCode::ProviderRejected,
        InferenceReceiptCode::ProviderContractViolation,
    ] {
        let mut uncertain = receipt.clone();
        uncertain.code = code;
        uncertain.observed_output_tokens = None;
        uncertain.output_text = None;
        uncertain.output_sha256 = None;
        reject_mutations(
            &uncertain,
            vec![
                ("/observed_output_tokens", json!(0)),
                ("/output_sha256", json!(sha256(b""))),
                ("/output_text", json!("")),
            ],
            |r| r.validate(&action),
            "uncertain inference cannot claim completed output",
        );
    }
}

fn release_action() -> StagingReleaseAction {
    StagingReleaseAction {
        operation: STAGING_RELEASE_OPERATION.into(),
        repo: "owner/app".into(),
        repository_id: 1,
        workflow_path: ".github/workflows/staging.yml".into(),
        workflow_id: 2,
        workflow_ref: "main".into(),
        approved_commit_sha: "a".repeat(40),
        workflow_sha256: "b".repeat(64),
        image_repository: "ghcr.io/owner/app".into(),
        image_digest: format!("sha256:{}", "c".repeat(64)),
        environment: "staging".into(),
        github_token_ref: Some("env:GITHUB_TOKEN".into()),
    }
}

#[test]
fn release_repositories_paths_branches_and_image_names_stay_in_the_reviewed_grammar() {
    let valid = release_action();
    let mut repositories = vec![("/repository_id", json!(0)), ("/workflow_id", json!(0))];
    for repo in [
        "/app".into(),
        "owner/".into(),
        "./app".into(),
        "../app".into(),
        "owner/a?b".into(),
        format!("{}/app", "a".repeat(101)),
    ] {
        repositories.push(("/repo", json!(repo)));
    }
    reject_mutations(
        &valid,
        repositories,
        StagingReleaseAction::validate,
        "invalid staging repository or workflow identity",
    );
    let mut paths = vec![];
    for name in [
        String::new(),
        "a".repeat(101),
        "stage.txt".into(),
        "stage/a.yml".into(),
    ] {
        paths.push(("/workflow_path", json!(format!(".github/workflows/{name}"))));
    }
    reject_mutations(
        &valid,
        paths,
        StagingReleaseAction::validate,
        "invalid staging workflow path",
    );
    let mut branches = vec![];
    for branch in [
        String::new(),
        "a".repeat(201),
        "main.".into(),
        "main/".into(),
        "a..b".into(),
        "a//b".into(),
        "/main".into(),
        "a/.hidden".into(),
        "a/b.lock".into(),
    ] {
        branches.push(("/workflow_ref", json!(branch)));
    }
    reject_mutations(
        &valid,
        branches,
        StagingReleaseAction::validate,
        "invalid staging branch",
    );
    let mut images = vec![];
    for image in [
        String::new(),
        format!("r/{}", "a".repeat(254)),
        "image".into(),
        "/image".into(),
        "r/image/".into(),
        "r//image".into(),
        "r/./image".into(),
        "r/../image".into(),
        "r/Image".into(),
    ] {
        images.push(("/image_repository", json!(image)));
    }
    reject_mutations(
        &valid,
        images,
        StagingReleaseAction::validate,
        "invalid staging image or destination",
    );
    let mut yaml = valid;
    yaml.workflow_path = ".github/workflows/staging.yaml".into();
    assert_eq!(yaml.validate(), Ok(()));
}

#[test]
fn release_observation_state_table_never_promotes_absence_or_reruns_to_success() {
    let action = release_action();
    for state in [
        ReleaseObservationState::Pending,
        ReleaseObservationState::Running,
        ReleaseObservationState::Succeeded,
        ReleaseObservationState::Failed,
        ReleaseObservationState::Ambiguous,
    ] {
        for code in [
            "run_not_observed",
            "run_in_progress",
            "workflow_succeeded",
            "workflow_failed",
            "run_correlation_ambiguous",
            "external_rerun_observed",
            "run_evidence_mismatch",
            "unknown",
        ] {
            for attempt in [None, Some(0), Some(1), Some(2)] {
                let bound = attempt.is_some();
                let observation = ReleaseObservation {
                    state,
                    correlation: ReleaseCorrelation::DispatchResponse,
                    code: code.into(),
                    run_id: bound.then_some(23),
                    run_url: bound
                        .then(|| "https://api.github.com/repos/owner/app/actions/runs/23".into()),
                    observed_commit_sha: bound.then(|| action.approved_commit_sha.clone()),
                    checked_at: 1,
                    run_attempt: attempt,
                };
                // Enumerated externally meaningful states: no run is pending
                // or ambiguous; first attempts may run/finish; reruns stay ambiguous.
                let expected = matches!(
                    (state, code, attempt),
                    (ReleaseObservationState::Pending, "run_not_observed", None)
                        | (
                            ReleaseObservationState::Ambiguous,
                            "run_correlation_ambiguous" | "run_evidence_mismatch",
                            None | Some(1)
                        )
                        | (ReleaseObservationState::Running, "run_in_progress", Some(1))
                        | (
                            ReleaseObservationState::Succeeded,
                            "workflow_succeeded",
                            Some(1)
                        )
                        | (ReleaseObservationState::Failed, "workflow_failed", Some(1))
                        | (
                            ReleaseObservationState::Ambiguous,
                            "external_rerun_observed",
                            Some(2)
                        )
                );
                assert_eq!(
                    observation
                        .validate(&action, "https://api.github.com")
                        .is_ok(),
                    expected,
                    "{state:?}/{code}/{attempt:?}"
                );
            }
        }
    }
    let valid = ReleaseObservation {
        state: ReleaseObservationState::Succeeded,
        correlation: ReleaseCorrelation::TaskTitle,
        code: "workflow_succeeded".into(),
        run_id: Some(23),
        run_url: Some("https://api.github.com/repos/owner/app/actions/runs/23".into()),
        observed_commit_sha: Some(action.approved_commit_sha.clone()),
        checked_at: 1,
        run_attempt: Some(1),
    };
    for (pointer, value) in [
        ("/checked_at", json!(0)),
        ("/run_id", json!(0)),
        ("/observed_commit_sha", json!("b".repeat(40))),
        ("/run_id", Value::Null),
    ] {
        let mut changed = serde_json::to_value(&valid).unwrap();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed: ReleaseObservation = serde_json::from_value(changed).unwrap();
        assert_eq!(
            changed.validate(&action, "https://api.github.com"),
            Err("invalid release observation".into())
        );
    }
}

fn ssh_action() -> SshHealthAction {
    serde_json::from_value(json!({"operation":SSH_OPERATION,"tenant":tenant(),"subject":"hum_00000000000000000000000000000001","delegation_id":"session-1","workload_uid":1000,"workload_exe_sha256":"e".repeat(64),"profile_id":"health","profile_sha256":"a".repeat(64),"destination_host":"192.0.2.1","destination_port":22,"host_key_sha256":"b".repeat(64),"vault_role":"health","vault_ca_sha256":"c".repeat(64),"vault_token_ref":"env:VAULT_TOKEN","principal":"health","login_user":"opaque","source_address":"192.0.2.2","command":SSH_FIXED_COMMAND,"max_session_secs":30,"grant_id":"00000000-0000-4000-8000-000000000002"})).unwrap()
}

#[test]
fn ssh_action_identity_bounds_and_local_health_paths_cannot_widen_authority() {
    let cases = vec![
        ("/profile_id", json!("")),
        ("/profile_id", json!("a".repeat(65))),
        ("/profile_sha256", json!("g".repeat(64))),
        ("/vault_ca_sha256", json!("g".repeat(64))),
        ("/vault_role", json!("-role")),
        ("/destination_port", json!(0)),
        ("/destination_host", json!("0.0.0.0")),
        ("/source_address", json!("224.0.0.1")),
        ("/workload_uid", json!(u32::MAX)),
        ("/workload_exe_sha256", json!("invalid")),
        ("/delegation_id", json!("")),
        ("/delegation_id", json!("a".repeat(129))),
    ];
    reject_mutations(
        &ssh_action(),
        cases,
        SshHealthAction::validate,
        "invalid fixed SSH authority",
    );
    let contract = SshHealthContract {
        service: "service".into(),
        version: "v1".into(),
        host: "127.0.0.1".into(),
        port: 9000,
        path: "/health".into(),
    };
    reject_mutations(
        &contract,
        vec![
            ("/version", json!("")),
            ("/path", json!(format!("/{}", "a".repeat(256)))),
            ("/path", json!("health")),
            ("/path", json!("/health/")),
            ("/path", json!("/./health")),
        ],
        SshHealthContract::validate,
        "invalid SSH health contract",
    );
}

#[test]
fn ssh_receipt_requires_exact_authority_time_and_contract_evidence() {
    let mut action = ssh_action();
    let receipt = SshReceipt {
        tenant: action.tenant.clone(),
        profile_sha256: action.profile_sha256.clone(),
        grant_id: action.grant_id.clone(),
        host_key_sha256: action.host_key_sha256.clone(),
        code: SshReceiptCode::HealthObserved,
        host: action.destination_host.clone(),
        principal: action.principal.clone(),
        operation: SSH_OPERATION.into(),
        started_at: 100,
        completed_at: 101,
        output_sha256: Some(sha256(b"healthy")),
        output_text: Some("healthy".into()),
        signed_receipt_sha256: "d".repeat(64),
    };
    reject_mutations(
        &receipt,
        vec![
            ("/tenant/tenant_id", json!("other")),
            ("/profile_sha256", json!("e".repeat(64))),
            ("/host_key_sha256", json!("e".repeat(64))),
            ("/host", json!("192.0.2.3")),
            ("/principal", json!("another")),
            ("/operation", json!("ssh.other")),
            ("/signed_receipt_sha256", json!("invalid")),
            ("/started_at", json!(0)),
            ("/completed_at", json!(99)),
        ],
        |r| r.validate(&action),
        "invalid SSH receipt binding",
    );
    reject_mutations(
        &receipt,
        vec![
            ("/output_text", Value::Null),
            ("/output_text", json!("\u{7}")),
        ],
        |r| r.validate(&action),
        "invalid SSH health evidence",
    );
    let mut failed = receipt.clone();
    failed.code = SshReceiptCode::Revoked;
    failed.output_text = None;
    failed.output_sha256 = None;
    reject_mutations(
        &failed,
        vec![("/output_sha256", json!(sha256(b"")))],
        |r| r.validate(&action),
        "incomplete SSH operation cannot claim health evidence",
    );
    let contract = SshHealthContract {
        service: "service".into(),
        version: "v1".into(),
        host: "127.0.0.1".into(),
        port: 9000,
        path: "/health".into(),
    };
    let mut approved = receipt;
    approved.output_text = Some(contract.expected_response().to_string());
    approved.output_sha256 = Some(sha256(approved.output_text.as_ref().unwrap().as_bytes()));
    action.health_contract = Some(contract);
    assert_eq!(approved.validate(&action), Ok(()));
    approved.output_text =
        Some(json!({"service":"other","status":"ok","version":"v1"}).to_string());
    approved.output_sha256 = Some(sha256(approved.output_text.as_ref().unwrap().as_bytes()));
    assert_eq!(
        approved.validate(&action),
        Err("SSH health response differs from approved contract")
    );
}

fn registry() -> Value {
    json!({"version":2,"routes":[{"protocol_version":opaque_core::mcp::PROTOCOL_VERSION,"alias":"note","server_id":"reviewed-server","endpoint":{"host":"mcp.example.com","path":"/mcp"},"tool":"add_note","credential_binding":"reviewed-credential","input_schema":{"type":"object","additionalProperties":false,"properties":{"id":{"type":"integer","minimum":1,"maximum":100},"status":{"type":"string","minLength":1,"maxLength":32}},"required":["id"]},"upstream_input_schema":{"type":"object","properties":{"id":{"type":"integer"},"status":{"type":"string"}},"required":["id"]},"output_policy":"withhold","max_request_bytes":4096,"max_response_bytes":4096,"timeout_ms":1000}]})
}

fn reject_registry_mutations(cases: Vec<(&str, Value)>, expected: opaque_core::mcp::ContractError) {
    use opaque_core::mcp::Registry;
    let original = registry();
    assert!(Registry::from_json(&serde_json::to_vec(&original).unwrap()).is_ok());
    for (pointer, value) in cases {
        let mut changed = original.clone();
        // Some optional schema keywords are absent in the valid document.
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        changed
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.into(), value.clone());
        let error = Registry::from_json(&serde_json::to_vec(&changed).unwrap())
            .err()
            .expect("registry must be rejected");
        assert_eq!(error, expected, "{pointer}={value}");
    }
}

#[test]
fn mcp_registry_identity_and_endpoint_bounds_do_not_admit_dynamic_destinations() {
    use opaque_core::mcp::ContractError::*;
    let mut cases = vec![
        ("/version", json!(3)),
        ("/routes", json!([])),
        ("/routes", json!(vec![registry()["routes"][0].clone(); 129])),
        ("/routes/0/protocol_version", json!("wrong")),
    ];
    for field in [
        "/routes/0/alias",
        "/routes/0/server_id",
        "/routes/0/tool",
        "/routes/0/credential_binding",
    ] {
        cases.push((field, json!("")));
        cases.push((field, json!("a".repeat(65))));
    }
    reject_registry_mutations(cases, InvalidRegistry);
    let mut cases = Vec::new();
    for host in [
        format!("{}.example", "a".repeat(254)),
        format!("{}.example", "a".repeat(64)),
        "-host.example".into(),
        "host-.example".into(),
    ] {
        cases.push(("/routes/0/endpoint/host", json!(host)));
    }
    for path in [
        "mcp".into(),
        format!("/{}", "a".repeat(256)),
        "/a/./b".into(),
        "/a/../b".into(),
    ] {
        cases.push(("/routes/0/endpoint/path", json!(path)));
    }
    reject_registry_mutations(cases, InvalidEndpoint);
}

#[test]
fn mcp_admitted_schema_rejects_open_bounds_ambiguous_required_fields_and_invalid_enums() {
    use opaque_core::mcp::ContractError::InvalidSchema;
    let properties: serde_json::Map<String, Value> = (0..65)
        .map(|i| (format!("p{i}"), json!({"type":"boolean"})))
        .collect();
    reject_registry_mutations(
        vec![
            ("/routes/0/input_schema", json!({"type":"boolean"})),
            ("/routes/0/input_schema/properties", json!(properties)),
            (
                "/routes/0/input_schema/properties",
                json!({"bad/name":{"type":"boolean"}}),
            ),
            ("/routes/0/input_schema/required", json!(["id", "id"])),
            ("/routes/0/input_schema/required", json!(["missing"])),
            ("/routes/0/input_schema/properties/status/enum", json!([])),
            (
                "/routes/0/input_schema/properties/status/enum",
                json!(vec!["a"; 65]),
            ),
            ("/routes/0/input_schema/properties/status/enum", json!([1])),
            ("/routes/0/input_schema/properties/id/enum", json!(["1"])),
            (
                "/routes/0/input_schema/properties/status/minLength",
                json!(33),
            ),
            (
                "/routes/0/input_schema/properties/status/maxLength",
                json!(4097),
            ),
            (
                "/routes/0/input_schema/properties/status",
                json!({"type":"array","items":{"type":"boolean"},"maxItems":257}),
            ),
        ],
        InvalidSchema,
    );
}

#[test]
fn mcp_upstream_schema_pin_rejects_unbounded_structure_and_annotation_payloads() {
    use opaque_core::mcp::ContractError::UnsupportedUpstreamSchema;
    let properties: serde_json::Map<String, Value> = (0..65)
        .map(|i| (format!("p{i}"), json!({"type":"boolean"})))
        .collect();
    reject_registry_mutations(
        vec![
            ("/routes/0/upstream_input_schema", json!({"type":"string"})),
            (
                "/routes/0/upstream_input_schema/properties",
                json!(properties),
            ),
            (
                "/routes/0/upstream_input_schema/properties",
                json!({"bad/name":{"type":"boolean"}}),
            ),
            (
                "/routes/0/upstream_input_schema/additionalProperties",
                json!({"type":"string"}),
            ),
            (
                "/routes/0/upstream_input_schema/required",
                json!(vec!["id"; 65]),
            ),
            (
                "/routes/0/upstream_input_schema/required",
                json!(["id", "id"]),
            ),
            (
                "/routes/0/upstream_input_schema/required",
                json!(["missing"]),
            ),
            ("/routes/0/upstream_input_schema/description", json!(7)),
            (
                "/routes/0/upstream_input_schema/title",
                json!("a".repeat(4097)),
            ),
            (
                "/routes/0/upstream_input_schema/properties/status/enum",
                json!([]),
            ),
            (
                "/routes/0/upstream_input_schema/properties/status/enum",
                json!(vec!["a"; 129]),
            ),
            (
                "/routes/0/upstream_input_schema/properties/status/enum",
                json!([null]),
            ),
            (
                "/routes/0/upstream_input_schema/properties/status/enum",
                json!([{}]),
            ),
        ],
        UnsupportedUpstreamSchema,
    );
    let mut deep = json!({"type":"boolean"});
    for _ in 0..9 {
        deep = json!({"type":"array","items":deep});
    }
    reject_registry_mutations(
        vec![("/routes/0/upstream_input_schema/properties/status", deep)],
        UnsupportedUpstreamSchema,
    );
}

#[test]
fn mcp_result_projection_rejects_ambiguous_names_and_unbounded_values_atomically() {
    use opaque_core::mcp::{ContractError, ResultProjection};
    let valid:ResultProjection=serde_json::from_value(json!({"fields":[{"source":"id","name":"resource_id","value_type":{"kind":"integer_id","maximum":100}},{"source":"status","name":"status","value_type":{"kind":"status","values":["created","queued"]}}]})).unwrap();
    let mut cases = vec![
        ("/fields", json!([])),
        (
            "/fields",
            json!(vec![serde_json::to_value(&valid.fields[0]).unwrap(); 9]),
        ),
        ("/fields/0/name", json!("bad/name")),
        ("/fields/1/source", json!("id")),
        ("/fields/1/name", json!("resource_id")),
        ("/fields/0/value_type/maximum", json!(0)),
        (
            "/fields/0/value_type/maximum",
            json!(9_007_199_254_740_992_u64),
        ),
    ];
    for values in [
        json!([]),
        json!(vec!["a"; 17]),
        json!(["a", "a"]),
        json!(["a".repeat(33)]),
        json!(["bad/name"]),
    ] {
        cases.push(("/fields/1/value_type/values", values));
    }
    assert_eq!(valid.validate(), Ok(()));
    for (pointer, value) in cases {
        let mut changed = serde_json::to_value(&valid).unwrap();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed: ResultProjection = serde_json::from_value(changed).unwrap();
        assert_eq!(changed.validate(), Err(ContractError::InvalidProjection));
        assert_eq!(
            changed.project(&json!({"id":1,"status":"created"})),
            Err(ContractError::InvalidProjection)
        );
    }
    assert_eq!(
        valid
            .project(&json!({"id":1,"status":"created","private":"must stay withheld"}))
            .unwrap(),
        std::collections::BTreeMap::from([
            ("resource_id".into(), json!(1)),
            ("status".into(), json!("created"))
        ])
    );
    for evidence in [
        json!({"id":101,"status":"created"}),
        json!({"id":1,"status":"free text"}),
        json!({"id":1}),
    ] {
        assert_eq!(
            valid.project(&evidence),
            Err(ContractError::InvalidProjection)
        );
    }
}

fn workstation_review() -> opaque_core::workstation::WorkstationReview {
    use opaque_core::workstation::*;
    WorkstationReview {
        review_text: "Review one bounded action".into(),
        challenge: WorkstationChallenge {
            schema_version: 2,
            authority: Some(WorkstationAuthority {
                binding: ApprovalBinding {
                    tenant: tenant(),
                    task_id: "00000000-0000-4000-8000-000000000003".into(),
                    manifest_digest: "a".repeat(64),
                    request_hash: "b".repeat(64),
                    policy_digest: "c".repeat(64),
                    requester: "requester".into(),
                },
                principal_id: "reviewer".into(),
                public_key_hex: hex(ed25519_dalek::SigningKey::from_bytes(&[17; 32])
                    .verifying_key()
                    .as_bytes()),
                required_role: "approver".into(),
                authority_epoch: 1,
            }),
            broker_id: "broker".into(),
            approval_id: "00000000-0000-4000-8000-000000000004".into(),
            request_id: "00000000-0000-4000-8000-000000000005".into(),
            operation: "github.publish_manifest".into(),
            content_hash: review_hash("Review one bounded action"),
            nonce: "d".repeat(64),
            created_at: 100,
            expires_at: 200,
        },
    }
}

#[test]
fn workstation_review_rejects_invalid_authority_identity_and_time_before_signature_use() {
    use opaque_core::workstation::*;
    let review = workstation_review();
    assert_eq!(review.validate("broker", 100), Ok(()));
    let cases = vec![
        ("/challenge/schema_version", json!(3)),
        ("/challenge/broker_id", json!("")),
        ("/challenge/broker_id", json!("a".repeat(129))),
        ("/challenge/approval_id", json!("invalid")),
        ("/challenge/request_id", json!("invalid")),
        ("/challenge/nonce", json!("z".repeat(64))),
        ("/challenge/content_hash", json!("z".repeat(64))),
        (
            "/challenge/authority/binding/tenant/schema_version",
            json!(0),
        ),
        ("/challenge/authority/binding/task_id", json!("invalid")),
        (
            "/challenge/authority/binding/manifest_digest",
            json!("z".repeat(64)),
        ),
        (
            "/challenge/authority/binding/request_hash",
            json!("z".repeat(64)),
        ),
        (
            "/challenge/authority/binding/policy_digest",
            json!("z".repeat(64)),
        ),
        ("/challenge/authority/binding/requester", json!("")),
        ("/challenge/authority/principal_id", json!("")),
        ("/challenge/authority/public_key_hex", json!("z".repeat(64))),
        ("/challenge/authority/required_role", json!("owner")),
        ("/challenge/created_at", json!(-1)),
        ("/challenge/expires_at", json!(100)),
        ("/challenge/expires_at", json!(401)),
    ];
    for (pointer, value) in cases {
        let mut changed = serde_json::to_value(&review).unwrap();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed: WorkstationReview = serde_json::from_value(changed).unwrap();
        assert_eq!(
            changed.validate("broker", 100),
            Err(WorkstationError::InvalidChallenge),
            "{pointer}"
        );
    }
    for text in [
        " \t\n".into(),
        "a".repeat(MAX_REVIEW_BYTES + 1),
        "visible\u{7}hidden".into(),
    ] {
        let mut changed = review.clone();
        changed.review_text = text;
        changed.challenge.content_hash = review_hash(&changed.review_text);
        assert_eq!(
            changed.validate("broker", 100),
            Err(WorkstationError::ContentMismatch)
        );
    }
}

#[test]
fn workstation_enrollment_and_notice_inputs_cannot_substitute_broker_or_key() {
    use opaque_core::workstation::*;
    let key = workstation_review()
        .challenge
        .authority
        .unwrap()
        .public_key_hex;
    let valid = EnrollmentChallenge {
        schema_version: 1,
        broker_id: "broker".into(),
        public_key_hex: key.clone(),
        nonce: "d".repeat(64),
        created_at: 100,
        expires_at: 200,
    };
    assert_eq!(valid.validate("broker", &key, 100), Ok(()));
    for (pointer, value) in [
        ("/schema_version", json!(2)),
        ("/broker_id", json!("")),
        ("/public_key_hex", json!("invalid")),
        ("/nonce", json!("invalid")),
        ("/public_key_hex", json!("e".repeat(64))),
    ] {
        let mut changed = serde_json::to_value(&valid).unwrap();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed: EnrollmentChallenge = serde_json::from_value(changed).unwrap();
        assert_eq!(
            changed.validate("broker", &key, 100),
            Err(WorkstationError::InvalidChallenge),
            "{pointer}"
        );
    }
    assert_eq!(
        valid.validate("other", &key, 100),
        Err(WorkstationError::WrongBroker)
    );
    assert_eq!(
        notice_link("", "00000000-0000-4000-8000-000000000001"),
        Err(WorkstationError::InvalidChallenge)
    );
    assert_eq!(
        notice_link("broker", "invalid"),
        Err(WorkstationError::InvalidChallenge)
    );
    assert_eq!(
        resolve_notice("opaque-approval://review/broker/extra/path", "broker"),
        Err(WorkstationError::InvalidChallenge)
    );
}

fn publish_manifest() -> opaque_core::task::TaskManifest {
    use opaque_core::task::*;
    TaskManifest {
        schema_version: 1,
        title: "Publish one reviewed secret".into(),
        expires_in_secs: 300,
        github_api_url: "https://api.github.com".into(),
        vault_api_url: "https://vault.example.com".into(),
        actions: vec![
            PublishAction {
                repo: "owner/repo".into(),
                repository_id: 1,
                secret_name: "APP_CONFIG".into(),
                value_ref: "vault:kv/data/app?version=1#VALUE".into(),
                github_token_ref: Some("env:GITHUB_TOKEN".into()),
            }
            .into(),
        ],
    }
}

#[test]
fn task_provider_urls_reject_ambiguous_authorities_and_preserve_literal_loopback_support() {
    use opaque_core::task::TaskValidationError;
    let valid = publish_manifest();
    assert_eq!(valid.validate(), Ok(()));
    for url in [
        format!("https://example.com/{}", "a".repeat(2048)),
        "ftp://example.com".into(),
        "https://".into(),
        "https://[invalid]".into(),
        format!("https://{}.com", "a".repeat(254)),
        format!("https://{}.com", "a".repeat(64)),
        "https://-host.example".into(),
        "https://host-.example".into(),
        "https://host.example:".into(),
        "https://host.example:0".into(),
        "https://host.example:65536".into(),
        "https://host.example:port".into(),
    ] {
        for field in ["github_api_url", "vault_api_url"] {
            let mut changed = serde_json::to_value(&valid).unwrap();
            changed[field] = json!(url);
            let changed: opaque_core::task::TaskManifest = serde_json::from_value(changed).unwrap();
            assert_eq!(
                changed.validate(),
                Err(TaskValidationError::ProviderUrl),
                "{field}={url}"
            );
        }
    }
    for url in [
        "http://[::1]",
        "http://[::1]:8080",
        "https://host.example:65535/api",
    ] {
        let mut changed = valid.clone();
        changed.github_api_url = url.into();
        assert_eq!(changed.validate(), Ok(()));
    }
}

#[test]
fn publish_identity_aliases_and_source_reference_limits_cannot_mint_duplicate_allowances() {
    use opaque_core::task::{TaskManifest, TaskValidationError};
    let valid = publish_manifest();
    for repo in [
        "/repo".into(),
        format!("{}/repo", "a".repeat(40)),
        "owner-/repo".into(),
        "owner/".into(),
        format!("owner/{}", "a".repeat(101)),
    ] {
        let mut changed = valid.clone();
        changed.actions[0].as_publish_mut().unwrap().repo = repo;
        assert_eq!(changed.validate(), Err(TaskValidationError::Repository));
    }
    let mut changed = valid.clone();
    changed.actions[0].as_publish_mut().unwrap().repository_id = 0;
    assert_eq!(changed.validate(), Err(TaskValidationError::RepositoryId));
    changed = valid.clone();
    changed.actions[0].as_publish_mut().unwrap().secret_name = "A".repeat(101);
    assert_eq!(changed.validate(), Err(TaskValidationError::SecretName));
    for reference in [
        "env:".into(),
        "env:forbidden?query".into(),
        format!("env:ghp_{}", "a".repeat(36)),
    ] {
        let mut changed = valid.clone();
        changed.actions[0]
            .as_publish_mut()
            .unwrap()
            .github_token_ref = Some(reference);
        assert_eq!(changed.validate(), Err(TaskValidationError::TokenRef));
    }
    for reference in [
        format!("vault:{}?version=1#VALUE", "a".repeat(769)),
        format!("vault:kv/data/{}?version=1#VALUE", "a".repeat(505)),
        format!("vault:kv/data/app?version=1#{}", "A".repeat(129)),
        "vault:kv/data/app?version=1#1VALUE".into(),
        "vault:kv/data/app?version=#VALUE".into(),
    ] {
        let mut changed = valid.clone();
        changed.actions[0].as_publish_mut().unwrap().value_ref = reference;
        assert_eq!(changed.validate(), Err(TaskValidationError::PinnedSource));
    }
    let mut alias = valid.clone();
    let mut second = alias.actions[0].clone();
    second.as_publish_mut().unwrap().repo = "other/spelling".into();
    alias.actions.push(second);
    assert_eq!(alias.validate(), Err(TaskValidationError::DuplicateAction));
    assert_eq!(alias.digest(), Err(TaskValidationError::DuplicateAction));
    let mut oversized: TaskManifest = valid;
    oversized.title = "A".repeat(161);
    assert_eq!(oversized.validate(), Err(TaskValidationError::Title));
}

#[test]
fn mcp_catalog_qualification_admits_at_most_128_tools_without_pagination() {
    use opaque_core::mcp::{ContractError, Registry};
    let registry = Registry::from_json(&serde_json::to_vec(&registry()).unwrap()).unwrap();
    let pinned = registry.routes()[0].upstream_schema().clone();
    // A captured tools/list result: the enrolled tool plus unrelated tools.
    let catalog = |count: usize| {
        let mut tools = vec![json!({"name":"add_note","inputSchema":pinned})];
        tools.extend((1..count).map(|n| json!({"name":format!("other_{n}")})));
        serde_json::to_vec(&json!({"tools":tools})).unwrap()
    };
    let at_bound = registry.qualify_catalog(&catalog(128)).unwrap();
    assert_eq!(at_bound.len(), 1);
    assert!(at_bound[0].compatible);
    assert_eq!(at_bound[0].diagnostic, "pinned_schema_matches");
    // One tool past the bound fails closed before any pin is compared, even
    // though the document is far below the byte limit and unpaginated.
    let over = catalog(129);
    assert!(over.len() < opaque_core::mcp::MAX_CATALOG_BYTES / 16);
    assert_eq!(
        registry.qualify_catalog(&over).err(),
        Some(ContractError::InvalidRegistry)
    );
}

#[test]
fn mcp_version_two_bounds_the_admitted_schema_at_64_kib_before_validation() {
    use opaque_core::mcp::{ContractError, MAX_UPSTREAM_SCHEMA_BYTES, Registry};
    // Every node, name, bound and depth here satisfies the admitted subset;
    // only its serialized size is exceptional.
    // 64-byte identifiers: a two-digit index followed by 62 padding letters.
    let group: serde_json::Map<String, Value> = (0..60)
        .map(|n| {
            (
                format!("{n:02}{}", "x".repeat(62)),
                json!({"type":"integer","minimum":1,"maximum":100}),
            )
        })
        .collect();
    assert_eq!(group.len(), 60);
    let properties: serde_json::Map<String, Value> = (0..16)
        .map(|n| {
            (
                format!("group_{n}"),
                json!({"type":"object","additionalProperties":false,"properties":group}),
            )
        })
        .collect();
    let schema = json!({"type":"object","additionalProperties":false,"properties":properties});
    let serialized = serde_json::to_vec(&schema).unwrap().len();
    assert!(serialized > MAX_UPSTREAM_SCHEMA_BYTES, "{serialized} bytes");
    let mut document = registry();
    document["routes"][0]["input_schema"] = schema;
    assert_eq!(
        Registry::from_json(&serde_json::to_vec(&document).unwrap()).err(),
        Some(ContractError::InvalidSchema)
    );
    // Version 1 has no separate upstream pin and no admitted-size bound, so the
    // identical legal schema is admitted: the rejection above is the size check.
    document["version"] = json!(1);
    document["routes"][0]
        .as_object_mut()
        .unwrap()
        .remove("upstream_input_schema");
    let legacy = Registry::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(legacy.route_count(), 1);
    assert_eq!(legacy.routes()[0].prepared_contract_version(), 2);
}
