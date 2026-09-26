//! Actual daemon routing with persistent identity, enrollment and review stores.
//! Fixture software keys do not claim a physical human-presence ceremony.
use super::*;
use crate::approver_rpc_tests::{Fixture, ISSUER, error, ok};
use ed25519_dalek::{Signer, SigningKey};
use opaque_approval::pairing::{PairingManager, WorkstationApproverConfig, store::DeviceStore};
use opaque_core::{
    audit::{AuditEvent, AuditFlushError, InMemoryAuditEmitter},
    authority_policy::WorkflowTarget,
    identity::Role,
    tenant::{TenantBinding, TenantId},
    workstation::{EnrollmentRequest, enrollment_bytes, hex},
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, os::unix::fs::PermissionsExt, time::Duration};

const METHODS: &[&str] = &[
    "scope_plan",
    "scope_activate",
    "scope_prepare",
    "scope_execute",
    "scope_run",
    "scope_get",
    "scope_outcome",
    "scope_revoke",
    "scope_snapshot",
    "scope_unknown",
];

fn fixture(required: bool) -> Fixture {
    scoped(required, None)
}

/// `targets` selects the GitHub `workflow_dispatch` kind; None is the support kind.
fn scoped(required: bool, targets: Option<Vec<WorkflowTarget>>) -> Fixture {
    let mut fixture = Fixture::new(true);
    Arc::get_mut(fixture.state.identity.as_mut().unwrap())
        .unwrap()
        .config
        .required = required;
    let identity = fixture.state.identity.as_ref().unwrap().clone();
    identity
        .store
        .set_roles(
            &fixture.admin,
            &BTreeSet::from([Role::Admin, Role::Operator, Role::Auditor]),
        )
        .unwrap();
    identity
        .store
        .create_human_session(&fixture.admin, 3600, ISSUER)
        .unwrap();
    let reviewer = identity
        .store
        .upsert_human(
            ISSUER,
            "scope-reviewer",
            None,
            None,
            &BTreeSet::from([Role::Approver]),
        )
        .unwrap();
    let key = SigningKey::from_bytes(&[91; 32]);
    let pairing = Arc::new(PairingManager::new(
        "scope-rpc-fixture".into(),
        SigningKey::from_bytes(&[92; 32]),
        0,
        DeviceStore::new(
            fixture.directory.path().join("scope-devices.json"),
            vec![93; 32],
        ),
    ));
    let public_key = hex(key.verifying_key().as_bytes());
    pairing
        .enroll_workstation(&WorkstationApproverConfig {
            public_key_hex: public_key.clone(),
            name: "Synthetic scope reviewer".into(),
            principal_id: Some(reviewer.id.to_string()),
        })
        .unwrap();
    let challenge = pairing.begin_workstation_enrollment(&public_key).unwrap();
    pairing
        .complete_workstation_enrollment(&EnrollmentRequest {
            public_key_hex: public_key.clone(),
            nonce: challenge.nonce.clone(),
            signature: hex(&key.sign(&enrollment_bytes(&challenge)).to_bytes()),
        })
        .unwrap();
    std::fs::set_permissions(
        fixture.directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let token = fixture.directory.path().join("fixture-provider.token");
    std::fs::write(&token, "fixture-no-network-token").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut config: scope_runtime::Config = serde_json::from_value(json!({
        "profile":{"endpoint":"https://scope-provider.example.invalid/","token_file":token},
        "reviewer_id":reviewer.id,"reviewer_public_key":public_key,
        "allowed_statuses":["closed"],"exact_action":true
    }))
    .unwrap();
    if targets.is_some() {
        // Only the sealed manifest loader can select this kind; TOML cannot.
        config.allowed_statuses.clear();
        config.workflows = targets;
    }
    let tenant = TenantBinding::new(
        TenantId::parse("scope-rpc-fixture").unwrap(),
        Uuid::new_v4(),
    )
    .unwrap();
    fixture.state.scope_workflow = Some(Arc::new(
        scope_runtime::Runtime::open(config, &tenant, fixture.directory.path(), identity, pairing)
            .unwrap(),
    ));
    fixture
}

async fn call(
    fixture: &Fixture,
    method: &str,
    params: Value,
    client: ClientType,
    session: Option<&str>,
) -> Response {
    handle_request(
        &fixture.state,
        Request {
            id: 41,
            method: method.into(),
            params,
        },
        &Fixture::peer(),
        client,
        session,
    )
    .await
}

async fn session(fixture: &Fixture) -> String {
    ok(fixture
        .call("agent_session_start", json!({"mode":"delegated"}))
        .await)["session_id"]
        .as_str()
        .unwrap()
        .into()
}

fn retained_counts(fixture: &Fixture) -> (u64, u64, u64) {
    let reviews =
        rusqlite::Connection::open(fixture.directory.path().join("scope-reviews.db")).unwrap();
    let scopes = rusqlite::Connection::open(fixture.directory.path().join("scopes.db")).unwrap();
    (
        reviews
            .query_row("SELECT COUNT(*) FROM rounds", [], |r| r.get(0))
            .unwrap(),
        scopes
            .query_row("SELECT COUNT(*) FROM scope_grants", [], |r| r.get(0))
            .unwrap(),
        scopes
            .query_row("SELECT COUNT(*) FROM scope_actions", [], |r| r.get(0))
            .unwrap(),
    )
}

fn plan() -> Value {
    json!({"resources":["case1"],"statuses":["closed"],"expires_in_secs":600,"max_attempts":1})
}

#[tokio::test]
async fn disabled_scope_routes_are_recognized_and_fail_closed() {
    let fixture = Fixture::new(true);
    for method in METHODS {
        assert!(is_operation_method(method));
        error(
            call(&fixture, method, json!({}), ClientType::Human, None).await,
            "scope_unavailable",
        );
    }
    assert!(fixture.state.scope_workflow.is_none());
    assert_eq!(
        fixture
            .audit
            .events_of_kind(AuditEventKind::OperationSucceeded)
            .len(),
        0
    );
}

#[tokio::test]
async fn forged_principal_claims_do_not_replace_a_verified_delegation() {
    for required in [false, true] {
        let fixture = fixture(required);
        for client in [ClientType::Agent, ClientType::Human] {
            let mut params = plan();
            params["principal_context"] = json!({"sub":fixture.admin,"sub_roles":["admin","operator"],"act":"agent:forged","jti":"forged"});
            params["client_type"] = "human".into();
            params["session_token"] = "forged".into();
            let expected = if required && client == ClientType::Agent {
                "identity_required"
            } else {
                "scope_unavailable"
            };
            error(
                call(&fixture, "scope_plan", params, client, None).await,
                expected,
            );
        }
        assert_eq!(retained_counts(&fixture), (0, 0, 0));
    }
}

#[tokio::test]
async fn live_session_reaches_scope_runtime_and_revocation_gates_every_scope_method() {
    let fixture = fixture(true);
    let session = session(&fixture).await;
    let created = ok(call(
        &fixture,
        "scope_plan",
        plan(),
        ClientType::Agent,
        Some(&session),
    )
    .await);
    assert_eq!(
        created["document"]["authority"]["requester_id"],
        fixture.admin.to_string()
    );
    assert_eq!(created["document"]["subject"]["kind"], "scope_issuance");
    assert_eq!(retained_counts(&fixture), (1, 0, 0));
    let delegation = fixture.state.agent_sessions.read().await[&session]
        .delegation
        .clone()
        .unwrap();
    fixture
        .state
        .identity
        .as_ref()
        .unwrap()
        .store
        .revoke_delegation(&delegation.jti)
        .unwrap();
    for method in METHODS {
        error(
            call(
                &fixture,
                method,
                json!({}),
                ClientType::Agent,
                Some(&session),
            )
            .await,
            "delegation_invalid",
        );
    }
    assert_eq!(retained_counts(&fixture), (1, 0, 0));
}

#[tokio::test]
async fn dispatch_kind_routes_through_the_daemon_and_policy_denies_foreign_targets_before_review() {
    let staging = WorkflowTarget {
        repository: "example-org/service".into(),
        path: ".github/workflows/staging.yml".into(),
        git_ref: "main".into(),
    };
    let fixture = scoped(true, Some(vec![staging.clone()]));
    let session = session(&fixture).await;
    let dispatch_plan =
        |resource: String| json!({"resources":[resource],"expires_in_secs":600,"max_attempts":1});
    // Support-shaped requests and every foreign target are refused with no round.
    for params in [
        plan(),
        dispatch_plan("example-org/other:.github/workflows/staging.yml:main".into()),
        dispatch_plan("example-org/service:.github/workflows/production.yml:main".into()),
        dispatch_plan("example-org/service:.github/workflows/staging.yml:develop".into()),
        dispatch_plan("example-org/service:.github/workflows/staging.yml:refs/heads/main".into()),
        json!({"resources":[staging.resource()],"statuses":["closed"],"expires_in_secs":600,"max_attempts":1}),
    ] {
        error(
            call(
                &fixture,
                "scope_plan",
                params,
                ClientType::Agent,
                Some(&session),
            )
            .await,
            "scope_unavailable",
        );
    }
    assert_eq!(retained_counts(&fixture), (0, 0, 0));
    let created = ok(call(
        &fixture,
        "scope_plan",
        dispatch_plan(staging.resource()),
        ClientType::Agent,
        Some(&session),
    )
    .await);
    let draft = &created["document"]["subject"]["draft"];
    assert_eq!(created["document"]["subject"]["kind"], "scope_issuance");
    assert_eq!(draft["operation"], "github.dispatch_staging_workflow");
    assert_eq!(draft["resources"], json!([staging.resource()]));
    assert_eq!(
        draft["fields"],
        json!([{"field":"ref","allowed_values":["main"]}])
    );
    assert_eq!(retained_counts(&fixture), (1, 0, 0));
    // A prepared action outside the approved scope never reaches the ledger or
    // the provider: the fixture endpoint is unroutable and no read is attempted.
    error(
        call(
            &fixture,
            "scope_prepare",
            json!({"scope_id":"missing","issuance_round_id":created["document"]["round_id"],
                "resource":"example-org/service:.github/workflows/production.yml:main","request_id":"request-1"}),
            ClientType::Agent,
            Some(&session),
        )
        .await,
        "scope_unavailable",
    );
    assert_eq!(retained_counts(&fixture), (1, 0, 0));
    assert!(
        fixture
            .audit
            .events_of_kind(AuditEventKind::RequestReceived)
            .iter()
            .all(|event| event.operation.as_deref() == Some("github.dispatch_staging_workflow"))
    );
}

#[derive(Debug)]
struct FailedAudit(InMemoryAuditEmitter);
impl AuditSink for FailedAudit {
    fn emit(&self, event: AuditEvent) {
        self.0.emit(event);
    }
    fn flush(&self, _: Duration) -> Result<(), AuditFlushError> {
        Err(AuditFlushError::Storage(
            "synthetic unavailable audit".into(),
        ))
    }
}

#[tokio::test]
async fn audit_durability_failure_precedes_review_creation_or_scope_dispatch() {
    let mut fixture = fixture(true);
    let session = session(&fixture).await;
    let audit = Arc::new(FailedAudit(InMemoryAuditEmitter::new()));
    fixture.state.audit = audit.clone();
    fixture.state.enclave = crate::tests::build_test_state(audit.clone(), false).enclave;
    for (method, params) in [
        ("scope_plan", plan()),
        (
            "scope_execute",
            json!({"round_id":"untrusted","issuance_round_id":"untrusted"}),
        ),
        ("scope_run", json!({})),
    ] {
        error(
            call(&fixture, method, params, ClientType::Agent, Some(&session)).await,
            "audit_unavailable",
        );
        assert_eq!(retained_counts(&fixture), (0, 0, 0));
    }
    assert_eq!(
        audit
            .0
            .events_of_kind(AuditEventKind::RequestReceived)
            .len(),
        3
    );
    assert!(
        audit
            .0
            .events_of_kind(AuditEventKind::OperationSucceeded)
            .is_empty()
    );
}
