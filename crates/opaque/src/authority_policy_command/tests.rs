use super::*;
fn fixture(dir: &std::path::Path) -> PathBuf {
    let file = dir.join("policy.json");
    std::fs::write(&file,serde_json::to_vec(&json!({"apiVersion":API_VERSION,"kind":KIND,"metadata":{"name":"cases","namespace":"support"},"spec":{"tenantRef":"example","connectorRef":"support","authority":{"operation":OPERATION,"allowedStatuses":["closed"],"maxResources":2,"maxAttempts":10,"maxDuration":"1h"},"approval":{"scope":"Required","reviewerRef":"ops"}}})).unwrap()).unwrap();
    file
}
fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/authority-policy")
        .join(name)
}
#[test]
fn shipped_examples_compile_for_both_operation_kinds_and_never_mix_their_fields() {
    let support = run(&Action::Compile {
        file: example("support.yaml"),
    })
    .unwrap();
    let dispatch = run(&Action::Compile {
        file: example("staging-dispatch.yaml"),
    })
    .unwrap();
    assert_eq!(
        support["policy"]["spec"]["authority"]["operation"],
        "support.case.setStatus"
    );
    assert!(
        support["policy"]["spec"]["authority"]
            .get("workflows")
            .is_none()
    );
    assert_eq!(
        dispatch["policy"]["spec"]["authority"]["operation"],
        "github.workflow.dispatch"
    );
    assert!(
        dispatch["policy"]["spec"]["authority"]
            .get("allowedStatuses")
            .is_none()
    );
    assert_eq!(
        dispatch["policy"]["spec"]["authority"]["workflows"],
        json!([{"repository":"example-org/service","path":".github/workflows/staging.yml","ref":"main"}])
    );
    assert_eq!(
        dispatch["policy"]["spec"]["approval"]["action"],
        "EveryAction"
    );
    assert_ne!(support["digest"], dispatch["digest"]);
    assert_eq!(
        run(&Action::Validate {
            file: example("staging-dispatch.yaml")
        })
        .unwrap()["digest"],
        dispatch["digest"]
    );
    let dir = tempfile::tempdir().unwrap();
    let mixed = dir.path().join("mixed.json");
    let mut value = dispatch["policy"].clone();
    value["spec"]["authority"]["allowedStatuses"] = json!(["closed"]);
    std::fs::write(&mixed, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(run(&Action::Validate { file: mixed }).is_err());
    let schema = run(&Action::Schema).unwrap();
    let kinds: Vec<_> = schema["properties"]["spec"]["properties"]["authority"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|branch| branch["properties"]["operation"]["enum"][0].clone())
        .collect();
    assert_eq!(
        kinds,
        vec![
            json!("support.case.setStatus"),
            json!("github.workflow.dispatch")
        ]
    );
}
#[test]
fn offline_commands_return_stable_compiler_contract_without_creating_other_files() {
    let dir = tempfile::tempdir().unwrap();
    let file = fixture(dir.path());
    let validated = run(&Action::Validate { file: file.clone() }).unwrap();
    let compiled = run(&Action::Compile { file: file.clone() }).unwrap();
    assert_eq!(validated["valid"], true);
    assert_eq!(compiled["schemaVersion"], 1);
    assert_eq!(validated["digest"], compiled["digest"]);
    assert_eq!(validated["identity"], compiled["identity"]);
    assert_eq!(run(&Action::Schema).unwrap(), policy::json_schema());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    std::fs::write(&file, "invalid: true").unwrap();
    assert!(run(&Action::Compile { file: file.clone() }).is_err());
    assert!(run(&Action::Validate { file }).is_err());
}
fn migrate(config: PathBuf) -> Action {
    Action::Migrate {
        config,
        name: "cases".into(),
        namespace: "support".into(),
        tenant_ref: "example".into(),
        connector_ref: "support".into(),
        reviewer_ref: "ops".into(),
    }
}
fn legacy(exact: Option<bool>) -> String {
    format!(
        "[scope_workflow]\nreviewer_id='hum_00000000000040008000000000000001'\nreviewer_public_key='{}'\nallowed_statuses=['closed']\n{}[scope_workflow.profile]\nendpoint='https://trusted.example.invalid/'\ntoken_file='/not-read/credential'\n",
        "ab".repeat(32),
        exact
            .map(|v| format!("exact_action={v}\n"))
            .unwrap_or_default()
    )
}
#[test]
fn migration_preserves_defaults_or_explicit_approval_and_never_copies_local_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    for exact in [None, Some(true), Some(false)] {
        let content = format!(
            "{}ca_certificate_file='/not-read/provider-ca.pem'\n",
            legacy(exact)
        );
        std::fs::write(&path, &content).unwrap();
        let result = run(&migrate(path.clone())).unwrap();
        assert_eq!(result["spec"]["approval"]["scope"], "Required");
        assert_eq!(
            result["spec"]["approval"]["action"],
            if exact == Some(false) {
                "WithinApprovedScope"
            } else {
                "EveryAction"
            }
        );
        assert_eq!(result["spec"]["authority"]["maxAttempts"], 100);
        assert_eq!(result["spec"]["authority"]["maxResources"], 100);
        assert_eq!(result["spec"]["authority"]["maxDuration"], "3600s");
        assert!(!result.to_string().contains("credential"));
        assert!(!result.to_string().contains("provider-ca"));
        assert!(!result.to_string().contains("trusted.example"));
        assert!(!result.to_string().contains("reviewer_public_key"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
#[test]
fn migration_rejects_invalid_ambiguous_or_unsupported_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    for text in [
        "[invalid".into(),
        "key='value'".into(),
        format!("{}\n[authority_policy]\npath='/any'", legacy(None)),
        legacy(None).replace(
            "allowed_statuses=['closed']",
            "allowed_statuses=['closed','closed']",
        ),
        legacy(None).replace("reviewer_id=", "unsupported="),
        legacy(None).replace("hum_", "agt_"),
        legacy(None).replace("/not-read/credential", "relative"),
        format!("{}ca_certificate_file='relative.pem'\n", legacy(None)),
        legacy(None).replace(
            "allowed_statuses=['closed']",
            "generation=0\nallowed_statuses=['closed']",
        ),
    ] {
        std::fs::write(&path, text).unwrap();
        assert!(run(&migrate(path.clone())).is_err());
    }
    std::fs::write(&path, [0xff]).unwrap();
    assert!(run(&migrate(path)).is_err());
}
