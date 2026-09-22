use super::*;
use opaque_core::tenant::{TenantBinding, TenantId};
use serde_json::json;
fn fixture() -> (tempfile::TempDir, Config, TenantBinding) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.json");
    let value = json!({"apiVersion":policy::API_VERSION,"kind":policy::KIND,"metadata":{"name":"cases","namespace":"support"},"spec":{"tenantRef":"example","connectorRef":"support","authority":{"operation":policy::OPERATION,"allowedStatuses":["open","closed","resolved"],"maxResources":2,"maxAttempts":10,"maxDuration":"1h"},"approval":{"scope":"Required","reviewerRef":"ops"}}});
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let compiled = policy::read(&path).unwrap();
    let config = Config {
        path,
        digest: compiled.digest,
        name: "cases".into(),
        namespace: "support".into(),
        tenant_ref: "example".into(),
        connector_ref: "support".into(),
        reviewer_ref: "ops".into(),
        reviewer_id: "trusted-principal".into(),
        reviewer_public_key: "ab".repeat(32),
        generation: 7,
        profile: crate::scope_runtime::connector::Profile {
            endpoint: "https://trusted.example.invalid/".into(),
            token_file: "/trusted/token".into(),
        },
    };
    let tenant =
        TenantBinding::new(TenantId::parse("example").unwrap(), uuid::Uuid::new_v4()).unwrap();
    (dir, config, tenant)
}
#[test]
fn resolution_pins_identity_and_only_trusted_config_supplies_connector_and_reviewer() {
    let (dir, config, tenant) = fixture();
    let before = std::fs::read(&config.path).unwrap();
    let result = config.resolve(&tenant).unwrap();
    assert_eq!(result.profile.endpoint, config.profile.endpoint);
    assert_eq!(result.profile.token_file, config.profile.token_file);
    assert_eq!(result.reviewer_id, config.reviewer_id);
    assert_eq!(result.reviewer_public_key, config.reviewer_public_key);
    assert_eq!(result.generation, 7);
    assert_eq!(result.max_scope_seconds, 3600);
    assert_eq!(result.max_attempts, 10);
    assert_eq!(result.max_resources, 2);
    assert!(result.exact_action);
    assert_eq!(result.allowed_statuses.len(), 3);
    assert_eq!(result.authority_policy.unwrap().digest, config.digest);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    assert_eq!(std::fs::read(&config.path).unwrap(), before);
    type Mutation = fn(&mut Config);
    let mutations: &[Mutation] = &[
        |c| c.digest = "00".repeat(32),
        |c| c.name = "other".into(),
        |c| c.namespace = "other".into(),
        |c| c.tenant_ref = "other".into(),
        |c| c.connector_ref = "other".into(),
        |c| c.reviewer_ref = "other".into(),
        |c| c.path = "relative".into(),
        |c| c.path = PathBuf::from("/missing-authority-policy.json"),
    ];
    for mutate in mutations {
        let mut changed = config.clone();
        mutate(&mut changed);
        assert!(changed.resolve(&tenant).is_err());
    }
    let foreign =
        TenantBinding::new(TenantId::parse("other").unwrap(), uuid::Uuid::new_v4()).unwrap();
    assert!(config.resolve(&foreign).is_err());
}
#[test]
fn startup_selection_is_exclusive_and_explicit_standing_scope_stays_human_issued() {
    let (_dir, mut config, tenant) = fixture();
    assert!(resolve(None, None, &tenant).unwrap().is_none());
    let legacy = config.resolve(&tenant).unwrap();
    assert!(resolve(Some(legacy.clone()), Some(&config), &tenant).is_err());
    assert_eq!(
        resolve(Some(legacy), None, &tenant)
            .unwrap()
            .unwrap()
            .generation,
        7
    );
    assert!(resolve(None, Some(&config), &tenant).unwrap().is_some());
    let mut policy = policy::read(&config.path).unwrap().policy;
    policy.spec.approval.action = ActionApproval::WithinApprovedScope;
    let compiled = policy.compile().unwrap();
    std::fs::write(&config.path, serde_json::to_vec(&compiled.policy).unwrap()).unwrap();
    assert!(config.resolve(&tenant).is_err());
    config.digest = compiled.digest;
    assert!(!config.resolve(&tenant).unwrap().exact_action);
    assert_eq!(
        compiled.policy.spec.approval.scope,
        policy::ScopeApproval::Required
    );
}
#[test]
fn legacy_digest_serialization_is_unchanged_and_internal_identity_cannot_be_injected() {
    let (_dir, config, tenant) = fixture();
    let mut resolved = config.resolve(&tenant).unwrap();
    resolved.authority_policy = None;
    let encoded = serde_json::to_value(&resolved).unwrap();
    assert!(encoded.get("authority_policy").is_none());
    let old = json!({"profile":{"endpoint":config.profile.endpoint,"token_file":config.profile.token_file},"reviewer_id":config.reviewer_id,"reviewer_public_key":config.reviewer_public_key,"generation":7,"max_scope_seconds":3600,"max_attempts":10,"max_resources":2,"exact_action":true,"allowed_statuses":["closed","open","resolved"]});
    assert_eq!(encoded, old);
    // Compare the actual legacy policy-digest input, including serde field order.
    let deserialized: crate::scope_runtime::Config = serde_json::from_value(old).unwrap();
    assert_eq!(crate::scope_runtime::connector::hash(&json!({"contract":"opaque.support.policy.v1","config":resolved,"tenant_binding":tenant})).unwrap(),crate::scope_runtime::connector::hash(&json!({"contract":"opaque.support.policy.v1","config":deserialized,"tenant_binding":tenant})).unwrap());
    let mut injected = encoded;
    injected["authority_policy"] = json!({});
    assert!(serde_json::from_value::<crate::scope_runtime::Config>(injected).is_err());
}
#[tokio::test]
async fn mixed_startup_fails_before_opening_any_custody() {
    let (dir, config, tenant) = fixture();
    let daemon = crate::DaemonConfig {
        scope_workflow: Some(config.resolve(&tenant).unwrap()),
        authority_policy: Some(config),
        ..Default::default()
    };
    assert!(
        crate::run(daemon, dir.path().join("absent-config.toml"))
            .await
            .unwrap_err()
            .to_string()
            .contains("cannot coexist")
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
