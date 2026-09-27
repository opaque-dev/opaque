//! Synthetic reviewer key signatures are protocol fixtures, not human presence.
//! Real identity/enrollment stores, signed review ledger and TLS provider I/O.
use super::*;
use crate::identity::{IdentityConfig, store::DelegationRecord};
use ed25519_dalek::{Signer, SigningKey};
use opaque_approval::pairing::{WorkstationApproverConfig, store::DeviceStore};
use opaque_core::{
    identity::AccessMode,
    scope_review::Decision,
    tenant::{TenantBinding, TenantId},
    workstation::{EnrollmentRequest, enrollment_bytes, hex},
};
use std::{
    collections::{BTreeSet, VecDeque},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod authority_policy;
mod github_dispatch;
mod qualification;

struct Provider {
    endpoint: String,
    certificate: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: tokio::task::JoinHandle<()>,
}
impl Provider {
    async fn new(replies: Vec<Vec<u8>>) -> Self {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = certificate.cert.pem();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!(
            "https://localhost:{}/",
            listener.local_addr().unwrap().port()
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let halted = stop.clone();
        let worker = tokio::spawn(async move {
            let mut replies = VecDeque::from(replies);
            loop {
                let socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if halted.load(Ordering::Acquire) {
                            assert!(replies.is_empty(), "provider response not consumed");
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        continue;
                    }
                    Err(e) => panic!("provider accept: {e}"),
                };
                let Some(reply) = replies.pop_front() else {
                    seen.lock().unwrap().push("<unexpected connection>".into());
                    continue;
                };
                socket.set_nonblocking(true).unwrap();
                let socket = tokio::net::TcpStream::from_std(socket).unwrap();
                let bytes = tokio::time::timeout(Duration::from_secs(5), async {
                    let mut stream = acceptor.accept(socket).await.unwrap();
                    let mut bytes = Vec::new();
                    loop {
                        let mut chunk = [0; 4096];
                        let n = stream.read(&mut chunk).await.unwrap();
                        assert!(n > 0 && bytes.len() + n < 32 * 1024);
                        bytes.extend_from_slice(&chunk[..n]);
                        if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                            let headers = std::str::from_utf8(&bytes[..end]).unwrap();
                            let length = headers
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length: ")
                                        .map(|v| v.parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            if bytes.len() >= end + 4 + length {
                                break;
                            }
                        }
                    }
                    let _ = stream.write_all(&reply).await;
                    let _ = stream.shutdown().await;
                    bytes
                })
                .await
                .unwrap();
                seen.lock().unwrap().push(String::from_utf8(bytes).unwrap());
            }
        });
        Self {
            endpoint,
            certificate: pem,
            requests,
            stop,
            worker,
        }
    }
    async fn finish(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(5), &mut self.worker)
            .await
            .unwrap()
            .unwrap();
        self.requests.lock().unwrap().clone()
    }
}
impl Drop for Provider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.abort();
    }
}
fn reply(status: &str, body: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(body).unwrap();
    let mut result=format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
    result.extend(body);
    result
}
fn read_reply() -> Vec<u8> {
    reply(
        "200 OK",
        &json!({"id":"case1","status":"open","version":"v1"}),
    )
}

struct Fixture {
    runtime: Runtime,
    context: PrincipalContext,
    key: SigningKey,
    tenant: TenantBinding,
    directory: tempfile::TempDir,
}
impl Fixture {
    fn new(provider: &Provider, exact: bool) -> Self {
        Self::build(
            &provider.endpoint,
            &provider.certificate,
            |profile, reviewer_id, reviewer_public_key| Config {
                authority_policy: None,
                workflows: None,
                profile,
                reviewer_id,
                reviewer_public_key,
                generation: 1,
                max_scope_seconds: 3600,
                max_attempts: 2,
                max_resources: 2,
                exact_action: exact,
                allowed_statuses: vec![Status::Closed, Status::Resolved],
            },
        )
    }
    /// Real identity/enrollment stores plus a broker-custody credential and CA
    /// file for the given HTTPS endpoint; the closure selects the kind.
    fn build(
        endpoint: &str,
        certificate: &str,
        configure: impl FnOnce(connector::Profile, String, String) -> Config,
    ) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let identity_config: IdentityConfig = serde_json::from_value(
            json!({"issuer":"https://identity.example.invalid","client_id":"scope-fixture"}),
        )
        .unwrap();
        let identity =
            Arc::new(IdentityRuntime::initialize(identity_config, directory.path()).unwrap());
        let requester = identity
            .store
            .upsert_human(
                &identity.config.issuer,
                "requester",
                None,
                None,
                &BTreeSet::from([Role::Operator, Role::Auditor]),
            )
            .unwrap();
        let reviewer = identity
            .store
            .upsert_human(
                &identity.config.issuer,
                "reviewer",
                None,
                None,
                &BTreeSet::from([Role::Approver]),
            )
            .unwrap();
        let actor = identity.store.upsert_agent("scope-fixture").unwrap();
        let session = identity
            .store
            .create_human_session(&requester.id, 600, &identity.config.issuer)
            .unwrap();
        let context = PrincipalContext {
            sub: requester.id.clone(),
            sub_label: requester.display_label(),
            sub_roles: requester.roles.clone(),
            sub_teams: vec![],
            act: actor.id.clone(),
            act_label: actor.display_label(),
            mode: AccessMode::Delegated,
            jti: uuid::Uuid::new_v4().to_string(),
            human_session_id: Some(session.id),
        };
        identity
            .store
            .record_delegation(&DelegationRecord {
                jti: context.jti.clone(),
                sub_principal: context.sub.clone(),
                act_principal: context.act.clone(),
                mode: context.mode,
                human_session_id: context.human_session_id.clone(),
                approved_by: Some(requester.id),
                created_at: now_unix(),
                expires_at: now_unix() + 600,
                revoked_at: None,
            })
            .unwrap();
        let pairing = Arc::new(PairingManager::new(
            "opq-fixture".into(),
            SigningKey::from_bytes(&[22; 32]),
            8443,
            DeviceStore::new(directory.path().join("devices.json"), vec![23; 32]),
        ));
        let key = SigningKey::from_bytes(&[24; 32]);
        let enrolled = pairing
            .enroll_workstation(&WorkstationApproverConfig {
                public_key_hex: hex(key.verifying_key().as_bytes()),
                name: "Synthetic scope reviewer".into(),
                principal_id: Some(reviewer.id.to_string()),
            })
            .unwrap();
        let challenge = pairing
            .begin_workstation_enrollment(&enrolled.public_key_hex)
            .unwrap();
        pairing
            .complete_workstation_enrollment(&EnrollmentRequest {
                public_key_hex: enrolled.public_key_hex.clone(),
                nonce: challenge.nonce.clone(),
                signature: hex(&key.sign(&enrollment_bytes(&challenge)).to_bytes()),
            })
            .unwrap();
        let token = directory.path().join("provider.token");
        std::fs::write(&token, "fixture-provider-token").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let ca = directory.path().join("provider-ca.pem");
        std::fs::write(&ca, certificate).unwrap();
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = configure(
            connector::Profile {
                endpoint: endpoint.into(),
                token_file: token,
                ca_certificate_file: Some(ca),
            },
            reviewer.id.to_string(),
            enrolled.public_key_hex,
        );
        let tenant =
            TenantBinding::new(TenantId::parse("fixture").unwrap(), uuid::Uuid::new_v4()).unwrap();
        let runtime = Runtime::open(config, &tenant, directory.path(), identity, pairing).unwrap();
        Self {
            runtime,
            context,
            key,
            tenant,
            directory,
        }
    }
    fn restart(self) -> Self {
        let Self {
            runtime,
            context,
            key,
            tenant,
            directory,
        } = self;
        let config = runtime.config.clone();
        let identity = runtime.identity.clone();
        let pairing = runtime.pairing.clone();
        drop(runtime);
        let runtime = Runtime::open(config, &tenant, directory.path(), identity, pairing).unwrap();
        Self {
            runtime,
            context,
            key,
            tenant,
            directory,
        }
    }
    fn approve(&self, review: &SignedReview) -> DecisionReceipt {
        let response = ReviewerDecision::sign(
            review,
            self.runtime.reviews.broker_public_key(),
            &self.key,
            Decision::Approve,
            now_unix(),
        )
        .unwrap();
        let device = self
            .runtime
            .pairing
            .workstation_device(&self.runtime.device_id)
            .unwrap();
        ScopeReviewService::submit(&self.runtime, &device, &review.document.round_id, &response)
            .unwrap()
    }
    fn issued(&self, attempts: u64) -> (ScopeGrant, String) {
        let value = self
            .runtime
            .plan(
                Plan {
                    resources: vec!["case1".into()],
                    statuses: vec![Status::Closed],
                    expires_in_secs: 600,
                    max_attempts: attempts,
                },
                &self.context,
            )
            .unwrap();
        let review: SignedReview = serde_json::from_value(value).unwrap();
        self.approve(&review);
        let round_id = review.document.round_id;
        let value = self
            .runtime
            .activate(
                Round {
                    round_id: round_id.clone(),
                },
                &self.context,
            )
            .unwrap();
        (
            serde_json::from_value(value["grant"].clone()).unwrap(),
            round_id,
        )
    }
    async fn prepared(&self, scope: &ScopeGrant, issuance: &str, request: &str) -> SignedReview {
        let value = self
            .runtime
            .review_action(
                Prepare {
                    scope_id: scope.scope_id.clone(),
                    issuance_round_id: issuance.into(),
                    resource: "case1".into(),
                    status: Some(Status::Closed),
                    request_id: request.into(),
                },
                &self.context,
            )
            .await
            .unwrap();
        serde_json::from_value(value).unwrap()
    }
    async fn execute(&self, review: &SignedReview, issuance: &str) -> Result<Value, String> {
        self.runtime
            .execute(
                Execute {
                    round_id: review.document.round_id.clone(),
                    issuance_round_id: issuance.into(),
                },
                &self.context,
            )
            .await
    }
}

#[tokio::test]
async fn approved_issuance_exact_review_writes_once_and_retains_restart_evidence() {
    let provider = Provider::new(vec![
        read_reply(),
        reply("200 OK", &json!({"accepted":true})),
    ])
    .await;
    let f = Fixture::new(&provider, true);
    let (scope, issuance) = f.issued(1);
    let review = f.prepared(&scope, &issuance, "request1").await;
    let ReviewSubject::ExactAction {
        action,
        evidence: Some(before),
        ..
    } = &review.document.subject
    else {
        panic!("provider before-state must be reviewable");
    };
    assert_eq!(
        before.fields,
        vec![FieldValue {
            field: "status".into(),
            value: "open".into()
        }]
    );
    assert_eq!(
        action.fields,
        vec![FieldValue {
            field: "status".into(),
            value: "closed".into()
        }]
    );
    assert_eq!(action.evidence_digest, before.digest().unwrap());
    assert!(f.execute(&review, &issuance).await.is_err());
    f.approve(&review);
    let result = f.execute(&review, &issuance).await.unwrap();
    assert_eq!(result["state"], "api_accepted");
    assert_eq!(f.execute(&review, &issuance).await.unwrap(), result);
    let snapshot = f.runtime.snapshot(&f.context).unwrap();
    assert_eq!(snapshot["ledger"]["actions"].as_array().unwrap().len(), 1);
    let f = f.restart();
    assert_eq!(f.execute(&review, &issuance).await.unwrap(), result);
    let requests = provider.finish().await;
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /cases/case1 "));
    assert!(requests[1].starts_with("PATCH /cases/case1 "));
    assert!(requests[1].contains("if-match: \"v1\""));
    assert!(requests[1].contains("idempotency-key: "));
    assert!(requests[1].ends_with("{\"status\":\"closed\"}"));
    assert!(
        requests
            .iter()
            .all(|r| r.contains("authorization: Bearer fixture-provider-token"))
    );
}

#[tokio::test]
async fn version_conflict_and_lost_ack_consume_once_without_replay_after_restart() {
    for (reply_bytes, state) in [
        (reply("412 Precondition Failed", &json!({})), "rejected"),
        (reply("409 Conflict", &json!({})), "rejected"),
        (reply("500 Internal Server Error", &json!({})), "unknown"),
        (reply("302 Found", &json!({})), "unknown"),
        (vec![], "unknown"),
    ] {
        let provider = Provider::new(vec![read_reply(), reply_bytes]).await;
        let f = Fixture::new(&provider, true);
        let (scope, issuance) = f.issued(1);
        let review = f.prepared(&scope, &issuance, "request1").await;
        f.approve(&review);
        let result = f.execute(&review, &issuance).await.unwrap();
        assert_eq!(result["state"], state);
        let f = f.restart();
        assert_eq!(f.execute(&review, &issuance).await.unwrap(), result);
        assert_eq!(
            f.runtime
                .ledger
                .get_scope(&scope.scope_id)
                .unwrap()
                .charged_attempts,
            1
        );
        assert_eq!(provider.finish().await.len(), 2);
    }
}

#[tokio::test]
async fn changed_live_authority_or_scope_revocation_after_review_prevents_provider_write() {
    for change in 0..5 {
        let provider = Provider::new(vec![read_reply()]).await;
        let f = Fixture::new(&provider, true);
        let (scope, issuance) = f.issued(1);
        let review = f.prepared(&scope, &issuance, "request1").await;
        f.approve(&review);
        match change {
            0 => f
                .runtime
                .pairing
                .revoke_device(&f.runtime.device_id)
                .unwrap(),
            1 => f
                .runtime
                .identity
                .store
                .set_roles(&f.runtime.reviewer, &BTreeSet::new())
                .unwrap(),
            2 => {
                f.runtime
                    .identity
                    .store
                    .revoke_delegation(&f.context.jti)
                    .unwrap();
            }
            3 => {
                f.runtime
                    .identity
                    .store
                    .revoke_all_human_sessions()
                    .unwrap();
            }
            _ => {
                f.runtime
                    .ledger
                    .revoke(&scope.scope_id, now_unix())
                    .unwrap();
            }
        }
        assert!(f.execute(&review, &issuance).await.is_err());
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
async fn standing_issuance_respects_budget_and_exact_policy_cannot_skip_review() {
    for exact in [false, true] {
        let provider = Provider::new(if exact {
            vec![]
        } else {
            vec![read_reply(), reply("200 OK", &json!({})), read_reply()]
        })
        .await;
        let f = Fixture::new(&provider, exact);
        let (scope, issuance) = f.issued(1);
        let prepare = |id: &str| Prepare {
            scope_id: scope.scope_id.clone(),
            issuance_round_id: issuance.clone(),
            resource: "case1".into(),
            status: Some(Status::Closed),
            request_id: id.into(),
        };
        let first = f.runtime.run(prepare("request1"), &f.context).await;
        if exact {
            assert!(first.is_err());
        } else {
            assert_eq!(first.unwrap()["state"], "api_accepted");
            assert!(
                f.runtime
                    .run(prepare("request2"), &f.context)
                    .await
                    .is_err()
            );
            assert_eq!(
                f.runtime
                    .ledger
                    .get_scope(&scope.scope_id)
                    .unwrap()
                    .charged_attempts,
                1
            );
        }
        assert_eq!(provider.finish().await.len(), if exact { 0 } else { 3 });
    }
}

#[tokio::test]
async fn concurrent_execution_of_one_approved_action_has_one_provider_send() {
    let provider = Provider::new(vec![read_reply(), reply("200 OK", &json!({}))]).await;
    let f = Fixture::new(&provider, true);
    let (scope, issuance) = f.issued(2);
    let review = f.prepared(&scope, &issuance, "same-request").await;
    f.approve(&review);
    let (first, second) =
        tokio::join!(f.execute(&review, &issuance), f.execute(&review, &issuance));
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first["action"]["action_id"], second["action"]["action_id"]);
    assert!(first["state"] == "api_accepted" || second["state"] == "api_accepted");
    assert_eq!(
        f.runtime
            .ledger
            .get_scope(&scope.scope_id)
            .unwrap()
            .charged_attempts,
        1
    );
    assert_eq!(provider.finish().await.len(), 2);
}

#[tokio::test]
async fn malformed_or_outside_scope_agent_requests_never_reach_provider() {
    let provider = Provider::new(vec![]).await;
    let f = Fixture::new(&provider, true);
    let (scope, issuance) = f.issued(1);
    for (method, params) in [
        (
            "scope_plan",
            json!({"resources":["case1"],"statuses":["closed"],"expires_in_secs":600,"max_attempts":1,"skip_review":true}),
        ),
        ("scope_snapshot", json!({"all":true})),
        (
            "scope_execute",
            json!({"round_id":"missing","issuance_round_id":issuance}),
        ),
        ("scope_unknown", json!({})),
        (
            "scope_prepare",
            json!({"scope_id":scope.scope_id,"issuance_round_id":issuance,"resource":"../other","status":"closed","request_id":"request1"}),
        ),
        (
            "scope_prepare",
            json!({"scope_id":scope.scope_id,"issuance_round_id":issuance,"resource":"case2","status":"closed","request_id":"request1"}),
        ),
        (
            "scope_prepare",
            json!({"scope_id":scope.scope_id,"issuance_round_id":issuance,"resource":"case1","status":"resolved","request_id":"request1"}),
        ),
        (
            "scope_prepare",
            json!({"scope_id":scope.scope_id,"issuance_round_id":"wrong","resource":"case1","status":"closed","request_id":"request1"}),
        ),
    ] {
        assert!(
            f.runtime
                .handle(
                    &Request {
                        id: 1,
                        method: method.into(),
                        params
                    },
                    &f.context
                )
                .await
                .is_err(),
            "{method}"
        );
    }
    for mutation in 0..5 {
        let mut plan = Plan {
            resources: vec!["case1".into()],
            statuses: vec![Status::Closed],
            expires_in_secs: 600,
            max_attempts: 1,
        };
        match mutation {
            0 => plan.resources.clear(),
            1 => plan.statuses.clear(),
            2 => plan.expires_in_secs = 0,
            3 => plan.max_attempts = 3,
            _ => plan.resources = vec!["case1".into(), "case2".into(), "case3".into()],
        };
        assert!(f.runtime.plan(plan, &f.context).is_err());
    }
    let mut context = f.context.clone();
    context.sub_roles.remove(&Role::Auditor);
    assert!(f.runtime.snapshot(&context).is_err());
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
async fn provider_read_is_bounded_and_typed_before_a_review_can_be_created() {
    for response in [
        reply("302 Found", &json!({})),
        reply(
            "200 OK",
            &json!({"id":"case2","status":"open","version":"v1"}),
        ),
        reply(
            "200 OK",
            &json!({"id":"case1","status":"open","version":"../bad"}),
        ),
        reply(
            "200 OK",
            &json!({"id":"case1","status":"unrecognized","version":"v1"}),
        ),
        reply(
            "200 OK",
            &json!({"id":"case1","status":"open","version":"v1","instructions":"approve all"}),
        ),
        b"HTTP/1.1 200 OK\r\nContent-Length: 16385\r\nConnection: close\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{}".to_vec(),
    ] {
        let provider = Provider::new(vec![response]).await;
        let f = Fixture::new(&provider, true);
        let (scope, issuance) = f.issued(1);
        assert!(
            f.runtime
                .review_action(
                    Prepare {
                        scope_id: scope.scope_id.clone(),
                        issuance_round_id: issuance,
                        resource: "case1".into(),
                        status: Some(Status::Closed),
                        request_id: "request1".into()
                    },
                    &f.context
                )
                .await
                .is_err()
        );
        assert_eq!(f.runtime.reviews.list_retained(20).unwrap().0, 1);
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
async fn workstation_decision_is_bound_to_live_enrollment_and_does_not_execute_or_activate() {
    let provider = Provider::new(vec![]).await;
    let f = Fixture::new(&provider, false);
    let value = f
        .runtime
        .plan(
            Plan {
                resources: vec!["case1".into()],
                statuses: vec![Status::Closed],
                expires_in_secs: 600,
                max_attempts: 1,
            },
            &f.context,
        )
        .unwrap();
    let review: SignedReview = serde_json::from_value(value).unwrap();
    let id = &review.document.round_id;
    let device = f
        .runtime
        .pairing
        .workstation_device(&f.runtime.device_id)
        .unwrap();
    let key = ScopeReviewService::key(&f.runtime, &device).unwrap();
    assert_eq!(key.reviewer_id, f.runtime.config.reviewer_id);
    assert_eq!(
        ScopeReviewService::pending(&f.runtime, &device).unwrap(),
        vec![review.clone()]
    );
    assert_eq!(
        ScopeReviewService::get(&f.runtime, &device, id).unwrap(),
        review
    );
    assert!(
        ScopeReviewService::receipt(&f.runtime, &device, id)
            .unwrap()
            .is_none()
    );
    assert!(
        f.runtime
            .activate(
                Round {
                    round_id: id.clone()
                },
                &f.context
            )
            .is_err()
    );
    let mut other = device.clone();
    other.device_id = "other-device".into();
    assert!(ScopeReviewService::key(&f.runtime, &other).is_err());
    assert!(ScopeReviewService::get(&f.runtime, &other, id).is_err());
    let response = ReviewerDecision::sign(
        &review,
        &key.broker_public_key,
        &f.key,
        Decision::Reject,
        now_unix(),
    )
    .unwrap();
    let receipt = ScopeReviewService::submit(&f.runtime, &device, id, &response).unwrap();
    receipt.verify(&key.broker_public_key).unwrap();
    assert_eq!(
        ScopeReviewService::receipt(&f.runtime, &device, id).unwrap(),
        Some(receipt)
    );
    assert!(ScopeReviewService::get(&f.runtime, &device, id).is_err());
    assert!(
        ScopeReviewService::pending(&f.runtime, &device)
            .unwrap()
            .is_empty()
    );
    assert!(
        f.runtime
            .activate(
                Round {
                    round_id: id.clone()
                },
                &f.context
            )
            .is_err()
    );
    assert!(provider.finish().await.is_empty());
}

#[test]
fn connector_admits_only_fixed_https_origin_and_private_single_link_credentials() {
    use std::os::unix::ffi::OsStrExt;
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("token");
    std::fs::write(&token, "fixture-token").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let profile = connector::Profile {
        endpoint: "https://support.example.invalid/v1/".into(),
        token_file: token.clone(),
        ca_certificate_file: None,
    };
    assert!(Connector::new(&profile).is_ok());
    for endpoint in [
        "invalid",
        "http://support.example.invalid/",
        "https://user:pass@support.example.invalid/",
        "https://support.example.invalid/?token=value",
        "https://support.example.invalid/#fragment",
        "https://support.example.invalid/v1",
    ] {
        let mut changed = profile.clone();
        changed.endpoint = endpoint.into();
        assert!(Connector::new(&changed).is_err(), "{endpoint}");
    }
    let mut changed = profile.clone();
    changed.token_file = "relative/token".into();
    assert!(Connector::new(&changed).is_err());
    changed.token_file = directory.path().join("missing");
    assert!(Connector::new(&changed).is_err());
    changed.token_file = directory.path().to_path_buf();
    assert!(Connector::new(&changed).is_err());
    let fifo = directory.path().join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: CString supplies a terminated path valid for the duration of mkfifo.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    changed.token_file = fifo;
    let (send, receive) = std::sync::mpsc::channel();
    let fifo_check =
        std::thread::spawn(move || send.send(Connector::new(&changed).is_err()).unwrap());
    assert!(receive.recv_timeout(Duration::from_secs(5)).unwrap());
    fifo_check.join().unwrap();
    let mut changed = profile.clone();
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&token, &link).unwrap();
    changed.token_file = link;
    assert!(Connector::new(&changed).is_err());
    let hardlink = directory.path().join("hardlink");
    std::fs::hard_link(&token, &hardlink).unwrap();
    assert!(Connector::new(&profile).is_err());
    std::fs::remove_file(hardlink).unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Connector::new(&profile).is_err());
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    for bytes in [
        vec![],
        vec![b'a'; 4097],
        b"bad\ntoken".to_vec(),
        vec![0xff],
        b"token:injection".to_vec(),
    ] {
        std::fs::write(&token, bytes).unwrap();
        assert!(Connector::new(&profile).is_err());
    }
}

#[tokio::test]
async fn connector_identifiers_cannot_select_paths_headers_or_create_an_attempt() {
    use opaque_bounded_work::scope_store::Outcome;
    let provider = Provider::new(vec![]).await;
    let f = Fixture::new(&provider, true);
    for id in [
        "",
        "../case1",
        "case1?admin=true",
        "case1/other",
        "case1\r\nAuthorization: bad",
    ] {
        assert!(f.runtime.support().read(id).await.is_err());
        assert_eq!(
            f.runtime
                .support()
                .write(id, "v1", Status::Closed, "action1")
                .await,
            Outcome::Unknown
        );
    }
    assert!(connector::identifier(&"x".repeat(129)).is_err());
    assert_eq!(
        f.runtime
            .support()
            .write("case1", "", Status::Closed, "action1")
            .await,
        Outcome::Unknown
    );
    assert_eq!(
        f.runtime
            .support()
            .write("case1", "v1", Status::Closed, "")
            .await,
        Outcome::Unknown
    );
    assert!(provider.finish().await.is_empty());
}

#[test]
fn provider_profile_changes_when_the_loaded_credential_changes_at_the_same_path() {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("token");
    std::fs::write(&token, "fixture-account-one-token").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let profile = connector::Profile {
        endpoint: "https://support.example.invalid/v1/".into(),
        token_file: token.clone(),
        ca_certificate_file: None,
    };
    let original = Connector::new(&profile).unwrap().digest;
    assert_eq!(Connector::new(&profile).unwrap().digest, original);
    // File formatting does not change the credential actually sent to the API.
    std::fs::write(&token, "fixture-account-one-token\n").unwrap();
    assert_eq!(Connector::new(&profile).unwrap().digest, original);
    std::fs::write(&token, "fixture-account-two-token").unwrap();
    let changed = Connector::new(&profile).unwrap().digest;
    assert_ne!(changed, original);
    assert_eq!(changed.len(), 64);
    assert!(!changed.contains("fixture-account"));
}

#[tokio::test]
async fn credential_rotation_at_restart_invalidates_old_scope_and_approved_action_before_write() {
    let provider = Provider::new(vec![read_reply()]).await;
    let f = Fixture::new(&provider, true);
    let (scope, issuance) = f.issued(1);
    let review = f.prepared(&scope, &issuance, "request1").await;
    f.approve(&review);
    let original_profile = f.runtime.support().digest.clone();
    std::fs::write(
        &f.runtime.config.profile.token_file,
        "fixture-other-provider-account-token",
    )
    .unwrap();
    let f = f.restart();
    assert_ne!(f.runtime.support().digest, original_profile);
    assert!(f.execute(&review, &issuance).await.is_err());
    assert!(
        f.runtime
            .review_action(
                Prepare {
                    scope_id: scope.scope_id.clone(),
                    issuance_round_id: issuance,
                    resource: "case1".into(),
                    status: Some(Status::Closed),
                    request_id: "request2".into()
                },
                &f.context
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.runtime
            .ledger
            .get_scope(&scope.scope_id)
            .unwrap()
            .charged_attempts,
        0
    );
    let (fresh, _) = f.issued(1);
    assert_eq!(fresh.provider_profile_digest, f.runtime.support().digest);
    assert_ne!(fresh.provider_profile_digest, scope.provider_profile_digest);
    let requests = provider.finish().await;
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /cases/case1 "));
}

#[test]
fn configured_ca_requires_private_bounded_regular_certificate_custody() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, "synthetic-token").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ca = dir.path().join("ca.pem");
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .unwrap()
        .cert
        .pem();
    std::fs::write(&ca, &certificate).unwrap();
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o600)).unwrap();
    let profile = connector::Profile {
        endpoint: "https://localhost/".into(),
        token_file: token,
        ca_certificate_file: Some(ca.clone()),
    };
    let pinned = Connector::new(&profile).unwrap().digest;
    let public = connector::Profile {
        ca_certificate_file: None,
        ..profile.clone()
    };
    assert_ne!(Connector::new(&public).unwrap().digest, pinned);
    assert!(
        serde_json::to_value(&public)
            .unwrap()
            .get("ca_certificate_file")
            .is_none()
    );
    for path in [
        PathBuf::from("relative"),
        dir.path().join("missing"),
        dir.path().to_path_buf(),
    ] {
        assert!(
            Connector::new(&connector::Profile {
                ca_certificate_file: Some(path),
                ..profile.clone()
            })
            .is_err()
        );
    }
    let link = dir.path().join("link.pem");
    std::os::unix::fs::symlink(&ca, &link).unwrap();
    assert!(
        Connector::new(&connector::Profile {
            ca_certificate_file: Some(link),
            ..profile.clone()
        })
        .is_err()
    );
    let hardlink = dir.path().join("hard.pem");
    std::fs::hard_link(&ca, &hardlink).unwrap();
    assert!(Connector::new(&profile).is_err());
    std::fs::remove_file(hardlink).unwrap();
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Connector::new(&profile).is_err());
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o600)).unwrap();
    for bytes in [
        vec![],
        b"not a certificate".to_vec(),
        vec![b'x'; 65537],
        certificate.repeat(17).into_bytes(),
        b"-----BEGIN CERTIFICATE-----\n?\n-----END CERTIFICATE-----".to_vec(),
    ] {
        std::fs::write(&ca, bytes).unwrap();
        assert!(Connector::new(&profile).is_err());
    }
    let fifo = dir.path().join("fifo.pem");
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: CString is a valid terminated path during mkfifo.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        send.send(
            Connector::new(&connector::Profile {
                ca_certificate_file: Some(fifo),
                ..profile
            })
            .is_err(),
        )
        .unwrap()
    });
    assert!(receive.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.join().unwrap();
}

#[tokio::test]
async fn configured_ca_rotation_requires_fresh_scope_before_any_provider_write() {
    let provider = Provider::new(vec![read_reply()]).await;
    let f = Fixture::new(&provider, true);
    let (scope, issuance) = f.issued(1);
    let review = f.prepared(&scope, &issuance, "ca-rotation").await;
    f.approve(&review);
    let path = f
        .runtime
        .config
        .profile
        .ca_certificate_file
        .as_ref()
        .unwrap();
    let original = f.runtime.support().digest.clone();
    let other = rcgen::generate_simple_self_signed(vec!["other.invalid".into()]).unwrap();
    std::fs::write(path, other.cert.pem()).unwrap();
    // The loaded connector remains immutable until an explicit broker restart.
    assert_eq!(f.runtime.support().digest, original);
    assert_ne!(
        Connector::new(&f.runtime.config.profile).unwrap().digest,
        original
    );
    let f = f.restart();
    assert_ne!(f.runtime.support().digest, original);
    assert!(f.execute(&review, &issuance).await.is_err());
    assert!(
        f.runtime
            .review_action(
                Prepare {
                    scope_id: scope.scope_id.clone(),
                    issuance_round_id: issuance,
                    resource: "case1".into(),
                    status: Some(Status::Closed),
                    request_id: "new-request".into(),
                },
                &f.context
            )
            .await
            .is_err()
    );
    assert_eq!(
        f.runtime
            .ledger
            .get_scope(&scope.scope_id)
            .unwrap()
            .charged_attempts,
        0
    );
    let (fresh, _) = f.issued(1);
    assert_eq!(fresh.provider_profile_digest, f.runtime.support().digest);
    assert_ne!(fresh.provider_profile_digest, scope.provider_profile_digest);
    let requests = provider.finish().await;
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /cases/case1 "));
}

#[tokio::test]
async fn configured_ca_does_not_bypass_certificate_or_hostname_verification() {
    for mode in ["untrusted", "default-roots", "wrong-hostname"] {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "synthetic-token").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let foreign = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(
            &ca,
            if mode == "untrusted" {
                foreign.cert.pem()
            } else {
                server.cert.pem()
            },
        )
        .unwrap();
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o600)).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![server.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(server.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let observed = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await.is_err()
        });
        let host = if mode == "wrong-hostname" {
            "127.0.0.1"
        } else {
            "localhost"
        };
        let connector = Connector::new(&connector::Profile {
            endpoint: format!("https://{host}:{port}/"),
            token_file: token,
            ca_certificate_file: if mode == "default-roots" {
                None
            } else {
                Some(ca)
            },
        })
        .unwrap();
        assert!(connector.read("case1").await.is_err(), "{mode}");
        assert!(
            tokio::time::timeout(Duration::from_secs(5), observed)
                .await
                .unwrap()
                .unwrap(),
            "{mode}: server unexpectedly completed the TLS handshake"
        );
    }
}
