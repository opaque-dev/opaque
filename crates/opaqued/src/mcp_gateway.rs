//! Daemon-only composition for third-party MCP. Clients supply an alias and
//! arguments; signed registry, custody, policy and peer identity supply authority.
use super::*;
use opaque_bounded_work::mcp::{CallInput, Gateway};
use opaque_core::operation::WorkspaceContext;

pub fn initialize(
    config: &DaemonConfig,
    state_dir: &Path,
    tenant: Option<opaque_core::tenant::TenantBinding>,
) -> std::io::Result<Option<Arc<Gateway>>> {
    let Some(mcp) = config.mcp.clone() else {
        return Ok(None);
    };
    let fixture = config.approval_backend.as_deref() == Some("insecure_auto_approve")
        && std::env::var("OPAQUE_INSECURE_AUTO_APPROVE").as_deref() == Ok("1");
    if fixture && mcp.fixture_origin.is_none() {
        return Err(std::io::Error::other(
            "MCP insecure approval is limited to explicit loopback fixtures",
        ));
    }
    if !fixture
        && (!config.trust_domain.enforce
            || !config.require_seal
            || tenant.is_none()
            || !config.enforce_agent_sessions
            || !config
                .identity
                .as_ref()
                .is_some_and(|i| i.required && !i.allowed_subjects.is_empty()))
    {
        return Err(std::io::Error::other(
            "MCP production requires sealed isolated tenant custody and required delegated identity",
        ));
    }
    if mcp.credentials.values().any(|p| {
        !p.starts_with(state_dir)
            || p.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
    }) {
        return Err(std::io::Error::other(
            "MCP credential files must remain inside broker state custody",
        ));
    }
    for path in mcp.credentials.values() {
        validate_path_chain(path)?;
    }
    Gateway::new(mcp, &state_dir.join("mcp-invocations.db"), tenant, fixture)
        .map(Arc::new)
        .map(Some)
        .map_err(std::io::Error::other)
}

pub async fn handle(
    state: &DaemonState,
    req: Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    principal: Option<PrincipalContext>,
    workspace: Result<Option<WorkspaceContext>, String>,
) -> Response {
    let result = inner(
        state,
        &req,
        identity,
        client_type,
        session_id,
        principal,
        workspace,
    )
    .await;
    match result {
        Ok(value) => Response::ok(req.id, value),
        Err(_) => Response::err(
            Some(req.id),
            "mcp_unavailable",
            "MCP invocation unavailable; inspect the invocation receipt before creating new work",
        ),
    }
}
fn base(
    identity: &ClientIdentity,
    client_type: ClientType,
    principal: Option<PrincipalContext>,
) -> OperationRequest {
    OperationRequest {
        request_id: uuid::Uuid::new_v4(),
        client_identity: identity.clone(),
        client_type,
        principal,
        operation: "mcp.call".into(),
        target: HashMap::new(),
        secret_ref_names: vec![],
        created_at: SystemTime::now(),
        expires_at: None,
        params: serde_json::Value::Null,
        workspace: None,
    }
}
async fn inner(
    state: &DaemonState,
    req: &Request,
    identity: &ClientIdentity,
    client_type: ClientType,
    session_id: Option<&str>,
    principal: Option<PrincipalContext>,
    workspace: Result<Option<WorkspaceContext>, String>,
) -> Result<serde_json::Value, String> {
    let Some(gateway) = &state.mcp else {
        if req.method == "mcp_catalog" {
            // Discovery states that no invocation method is served, so the
            // adapter advertises no invocation tools.
            return Ok(serde_json::json!({
                "tools": [], "gateway": {"availability": "disabled"},
            }));
        }
        return Err("disabled".into());
    };
    let owner = state
        .tenant
        .as_ref()
        .map(|tenant| tenant.owner_key(identity.uid, principal.as_ref().map(|p| &p.sub)))
        .unwrap_or_else(|| match &principal {
            Some(p) => format!("uid:{}:sub:{}", identity.uid, p.sub.as_str()),
            None => format!("uid:{}", identity.uid),
        });
    if req.method == "mcp_catalog" {
        if !req.params.as_object().is_some_and(|m| m.is_empty()) {
            return Err("invalid catalog".into());
        }
        let mut catalog = gateway.catalog()?;
        if let Some(tools) = catalog
            .get_mut("tools")
            .and_then(serde_json::Value::as_array_mut)
        {
            tools.retain(|tool| {
                let mut request = base(identity, client_type, principal.clone());
                request.target =
                    serde_json::from_value(tool["policy_target"].clone()).unwrap_or_default();
                request.secret_ref_names = tool["secret_ref"]
                    .as_str()
                    .map(|s| vec![s.to_owned()])
                    .unwrap_or_default();
                state.enclave.mcp_route_allowed(&request)
            });
        }
        // Policy can hide every route from this caller while `mcp_get` and
        // `mcp_revoke` still serve receipts it owns, so availability is
        // reported separately from the visible route list.
        catalog["gateway"] = serde_json::json!({"availability": availability(gateway)});
        return Ok(catalog);
    }
    if matches!(req.method.as_str(), "mcp_get" | "mcp_revoke") {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Reference {
            invocation_id: String,
        }
        let reference: Reference =
            serde_json::from_value(req.params.clone()).map_err(|_| "invalid reference")?;
        let mut receipt = if req.method == "mcp_revoke" {
            gateway.ledger.revoke(&owner, &reference.invocation_id)?
        } else {
            gateway.ledger.get(&owner, &reference.invocation_id)?
        };
        if receipt.response_sha256.is_some() || receipt.response_bytes.is_some() {
            let action = gateway
                .ledger
                .get_action(&owner, &reference.invocation_id)?;
            let mut request = base(identity, client_type, principal);
            request.target = action.target();
            request.params =
                serde_json::to_value(&action).map_err(|_| "MCP action encoding failed")?;
            request.secret_ref_names = vec![action.credential_ref.clone()];
            state.enclave.filter_mcp_receipt_metadata(
                gateway,
                &owner,
                &request,
                &action,
                &mut receipt,
            );
        }
        return Ok(serde_json::json!({"receipt":receipt}));
    }
    let mut params = req.params.clone();
    if let Some(map) = params.as_object_mut() {
        map.remove("workspace");
    }
    let input: CallInput = serde_json::from_value(params).map_err(|_| "invalid call")?;
    let action = gateway.prepare(input)?;
    let mut request = base(identity, client_type, principal);
    request.workspace = workspace?;
    let claimed_workspace = request.workspace.clone();
    let result = state
        .enclave
        .execute_mcp(gateway, &owner, request, action, || async {
            if let Some(claimed) = &claimed_workspace {
                verify_workspace(claimed, identity.pid).await?;
            }
            resolve_principal_context(state, session_id).await
        })
        .await?;
    serde_json::to_value(result).map_err(|_| "MCP result encoding failed".into())
}

/// Shared vocabulary for the `operations` inventory and `mcp_catalog` discovery.
fn availability(gateway: &Gateway) -> &'static str {
    if gateway.fixture_only() {
        "fixture_only"
    } else {
        "enabled"
    }
}

/// Configured dedicated runner availability; the raw generic execute route
/// deliberately has no MCP handler and cannot bypass invocation accounting.
pub fn operation_catalog(state: &DaemonState) -> Vec<serde_json::Value> {
    let mut catalog = state.enclave.operation_catalog();
    if let Some(entry) = catalog.iter_mut().find(|e| e["name"] == "mcp.call") {
        entry["mcp_exposed"] = serde_json::json!(state.mcp.is_some());
        if let Some(gateway) = &state.mcp {
            entry["availability"] = serde_json::json!(availability(gateway));
            entry["execution_paths"] = serde_json::json!(["mcp_invocation"]);
        }
    }
    catalog
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use opaque_bounded_work::mcp::Config;
    use opaque_core::audit::InMemoryAuditEmitter;
    use opaque_core::bundle::{BundlePayload, sign_bundle};
    use opaque_core::mcp::{PROTOCOL_VERSION, RegistryDocument};
    use opaque_core::tenant::{TenantBinding, TenantId};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    #[derive(Debug)]
    struct UnexpectedApproval;
    impl opaque_core::approval_gate::ApprovalGate for UnexpectedApproval {
        fn request_approval(
            &self,
            _: uuid::Uuid,
            _: &OperationRequest,
            _: &[opaque_core::operation::ApprovalFactor],
            _: &str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<opaque_core::approval_gate::ApprovalOutcome, String>,
                    > + Send
                    + '_,
            >,
        > {
            panic!("catalog and receipt controls must not request approval")
        }
    }
    struct Fixture {
        _directory: tempfile::TempDir,
        root: PathBuf,
        config: DaemonConfig,
        tenant: TenantBinding,
    }
    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().canonicalize().unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let tenant = opaque_tenant::tenant::TenantBoundary::open(
                &opaque_tenant::tenant::TenantConfig {
                    id: TenantId::parse("mcp-test").unwrap(),
                },
                &root,
                true,
            )
            .unwrap();
            let tenant_binding = tenant.binding().clone();
            drop(tenant);
            let key = ed25519_dalek::SigningKey::from_bytes(&[53; 32]);
            let credential = root.join("credential");
            std::fs::write(&credential, b"synthetic-custody-fixture").unwrap();
            std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
            let registry: RegistryDocument = serde_json::from_value(json!({"version":1,"routes":[{"protocol_version":PROTOCOL_VERSION,"alias":"post_note","server_id":"fixture","endpoint":{"host":"mcp.example.com","path":"/mcp"},"tool":"post_note","credential_binding":"notes","input_schema":{"type":"object","additionalProperties":false,"required":["message"],"properties":{"message":{"type":"string","maxLength":64}}},"output_policy":"withhold","max_request_bytes":4096,"max_response_bytes":4096,"timeout_ms":1000}]})).unwrap();
            let now = opaque_bounded_work::mcp::now();
            let bundle = root.join("registry.bundle");
            std::fs::write(
                &bundle,
                sign_bundle(
                    &BundlePayload {
                        org: "fixture".into(),
                        version: 1,
                        issued_at: now - 1,
                        expires_at: Some(now + 600),
                        key_id: String::new(),
                        teams: vec![],
                        rules: vec![],
                        mcp_registry: Some(registry),
                    },
                    &key,
                )
                .unwrap(),
            )
            .unwrap();
            let mut config = DaemonConfig {
                mcp: Some(Config {
                    bundle_path: bundle, org: "fixture".into(),
                    trust_anchors: vec![opaque_core::workstation::hex(key.verifying_key().as_bytes())],
                    credentials: BTreeMap::from([("notes".into(), credential)]),
                    fixture_origin: None,
                }),
                require_seal: true, enforce_agent_sessions: true,
                identity: Some(serde_json::from_value(json!({"issuer":"https://issuer.example","client_id":"fixture","required":true,"allowed_subjects":["admitted"]})).unwrap()),
                ..DaemonConfig::default()
            };
            // A production backend prevents ambient fixture opt-in from being consulted.
            config.trust_domain.enforce = true;
            let tenant = tenant_binding;
            Self {
                _directory: directory,
                root,
                config,
                tenant,
            }
        }
        fn state(&self, allow: bool) -> DaemonState {
            let audit = Arc::new(InMemoryAuditEmitter::new());
            let mut state = crate::tests::build_test_state(audit.clone(), false);
            let mut registry = OperationRegistry::new();
            registry.register(crate::enclave::mcp_operation()).unwrap();
            let rules = if allow {
                vec![serde_json::from_value(json!({"name":"allow route","operation_pattern":"mcp.call","allow":true,"approval":{"require":"never"}})).unwrap()]
            } else {
                vec![]
            };
            state.enclave = Arc::new(
                Enclave::builder()
                    .registry(registry)
                    .policy(PolicyEngine::with_rules(rules))
                    .approval_gate(Box::new(UnexpectedApproval))
                    .audit(audit)
                    .build()
                    .unwrap(),
            );
            state.mcp = initialize(&self.config, &self.root, Some(self.tenant.clone())).unwrap();
            state.tenant = Some(
                opaque_tenant::tenant::TenantBoundary::open(
                    &opaque_tenant::tenant::TenantConfig {
                        id: self.tenant.tenant_id.clone(),
                    },
                    &self.root,
                    true,
                )
                .unwrap(),
            );
            state
        }
    }
    fn identity() -> ClientIdentity {
        ClientIdentity {
            uid: 501,
            gid: 20,
            pid: None,
            exe_path: None,
            exe_sha256: None,
            codesign_team_id: None,
            workload: None,
        }
    }
    async fn call(state: &DaemonState, method: &str, params: serde_json::Value) -> Response {
        handle(
            state,
            Request {
                id: 41,
                method: method.into(),
                params,
            },
            &identity(),
            ClientType::Agent,
            None,
            None,
            Ok(None),
        )
        .await
    }
    fn denied(response: Response) {
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            json!({"id":41,"error":{"code":"mcp_unavailable","message":"MCP invocation unavailable; inspect the invocation receipt before creating new work"}})
        );
    }

    #[test]
    fn production_mcp_requires_every_custody_and_identity_prerequisite() {
        let f = Fixture::new();
        for missing in 0..7 {
            let mut config = f.config.clone();
            let mut tenant = Some(f.tenant.clone());
            match missing {
                0 => config.trust_domain.enforce = false,
                1 => config.require_seal = false,
                2 => tenant = None,
                3 => config.enforce_agent_sessions = false,
                4 => config.identity = None,
                5 => config.identity.as_mut().unwrap().required = false,
                _ => config.identity.as_mut().unwrap().allowed_subjects.clear(),
            }
            let error = initialize(&config, &f.root, tenant)
                .err()
                .expect("missing prerequisite must fail");
            assert_eq!(
                error.to_string(),
                "MCP production requires sealed isolated tenant custody and required delegated identity"
            );
            assert!(!f.root.join("mcp-invocations.db").exists());
        }
        let gateway = initialize(&f.config, &f.root, Some(f.tenant.clone()))
            .unwrap()
            .unwrap();
        assert!(!gateway.fixture_only());
        assert_eq!(
            gateway.catalog().unwrap()["tools"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(f.root.join("mcp-invocations.db").is_file());
    }

    #[test]
    fn production_mcp_rejects_escaped_or_symlinked_credential_custody() {
        let f = Fixture::new();
        for path in [
            f.root.parent().unwrap().join("outside-credential"),
            f.root.join("child/../credential"),
        ] {
            let mut config = f.config.clone();
            config
                .mcp
                .as_mut()
                .unwrap()
                .credentials
                .insert("notes".into(), path);
            assert_eq!(
                initialize(&config, &f.root, Some(f.tenant.clone()))
                    .err()
                    .unwrap()
                    .to_string(),
                "MCP credential files must remain inside broker state custody"
            );
            assert!(!f.root.join("mcp-invocations.db").exists());
        }
        let link = f.root.join("credential-link");
        std::os::unix::fs::symlink(f.root.join("credential"), &link).unwrap();
        let mut config = f.config.clone();
        config
            .mcp
            .as_mut()
            .unwrap()
            .credentials
            .insert("notes".into(), link);
        assert_eq!(
            initialize(&config, &f.root, Some(f.tenant.clone()))
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(!f.root.join("mcp-invocations.db").exists());
    }

    #[tokio::test]
    async fn disabled_gateway_advertises_no_tools_and_rejects_invocation_methods() {
        let state = crate::tests::build_test_state(Arc::new(InMemoryAuditEmitter::new()), false);
        assert!(
            initialize(&state.config, Path::new("/unused"), None)
                .unwrap()
                .is_none()
        );
        assert!(operation_catalog(&state).is_empty());
        assert_eq!(
            call(&state, "mcp_catalog", json!({})).await.result.unwrap(),
            json!({"tools":[],"gateway":{"availability":"disabled"}})
        );
        for method in ["mcp_call", "mcp_get", "mcp_revoke"] {
            denied(call(&state, method, json!({"secret":"must not echo"})).await);
        }
    }

    #[tokio::test]
    async fn catalog_filters_signed_routes_by_current_policy_and_validates_parameters() {
        let f = Fixture::new();
        let state = f.state(true);
        let catalog = call(&state, "mcp_catalog", json!({})).await.result.unwrap();
        assert_eq!(catalog["tools"].as_array().unwrap().len(), 1);
        assert_eq!(catalog["tools"][0]["name"], "opaque_mcp_tool_post_note");
        assert_eq!(catalog["gateway"], json!({"availability":"enabled"}));
        let operation = operation_catalog(&state)
            .into_iter()
            .find(|e| e["name"] == "mcp.call")
            .unwrap();
        assert_eq!(operation["availability"], "enabled");
        assert_eq!(operation["execution_paths"], json!(["mcp_invocation"]));
        assert_eq!(operation["mcp_exposed"], true);
        for params in [
            json!(null),
            json!([]),
            json!({"secret":"not a catalog parameter"}),
        ] {
            denied(call(&state, "mcp_catalog", params).await);
        }
        state.enclave.swap_policy(PolicyEngine::new());
        // Policy hides every route, yet owned receipts stay readable, so the
        // gateway still reports itself as served.
        assert_eq!(
            call(&state, "mcp_catalog", json!({})).await.result.unwrap(),
            json!({"tools":[],"gateway":{"availability":"enabled"}})
        );
    }

    #[tokio::test]
    async fn invocation_receipts_are_owner_bound_and_revocation_never_replays_work() {
        let f = Fixture::new();
        let mut state = f.state(true);
        let gateway = state.mcp.as_ref().unwrap().clone();
        let action = gateway
            .prepare(CallInput {
                invocation_id: uuid::Uuid::new_v4().to_string(),
                route: "post_note".into(),
                arguments: serde_json::from_value(json!({"message":"ledger fixture only"}))
                    .unwrap(),
                expires_in_secs: 120,
            })
            .unwrap();
        let owner = f.tenant.owner_key(identity().uid, None);
        gateway.ledger.claim(&owner, &action).unwrap();
        let reference = json!({"invocation_id":action.invocation_id});
        let receipt = call(&state, "mcp_get", reference.clone())
            .await
            .result
            .unwrap()["receipt"]
            .clone();
        assert_eq!(receipt["attempt_charged"], false);
        assert_eq!(receipt["revoked"], false);
        let tenant = state.tenant.take();
        denied(call(&state, "mcp_get", reference.clone()).await);
        state.tenant = tenant;
        for params in [
            json!(null),
            json!({"invocation_id":action.invocation_id,"unexpected":"sensitive"}),
        ] {
            denied(call(&state, "mcp_get", params).await);
        }
        let revoked = call(&state, "mcp_revoke", reference.clone())
            .await
            .result
            .unwrap()["receipt"]
            .clone();
        assert_eq!(revoked["revoked"], true);
        assert_eq!(revoked["attempt_charged"], false);
        assert_eq!(
            call(&state, "mcp_get", reference).await.result.unwrap()["receipt"],
            revoked
        );
        assert!(gateway.ledger.claim(&owner, &action).is_err());
        for params in [
            json!(null),
            json!({"route":"post_note","secret":"must not echo"}),
        ] {
            denied(call(&state, "mcp_call", params).await);
        }
    }
}
