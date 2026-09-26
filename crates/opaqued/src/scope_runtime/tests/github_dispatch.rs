//! GitHub `workflow_dispatch` through the same runtime, review ledger and
//! custody path as the support kind. The provider is a synthetic HTTPS GitHub:
//! a TLS terminator in front of wiremock, so every request is matched exactly.
//! Nothing here dispatches against real GitHub or proves a live workflow ran.
use super::*;
use opaque_core::authority_policy::{self as policy, WorkflowTarget};
use std::sync::atomic::AtomicUsize;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REPO: &str = "example-org/service";
const WORKFLOW: &str = ".github/workflows/staging.yml";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const MOVED: &str = "fedcba9876543210fedcba9876543210fedcba98";

fn target(repository: &str, path: &str, git_ref: &str) -> WorkflowTarget {
    WorkflowTarget {
        repository: repository.into(),
        path: path.into(),
        git_ref: git_ref.into(),
    }
}
fn staging() -> WorkflowTarget {
    target(REPO, WORKFLOW, "main")
}

struct GitHub {
    server: MockServer,
    endpoint: String,
    certificate: String,
    drop_posts: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
    worker: tokio::task::JoinHandle<()>,
}
impl GitHub {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let upstream = *server.address();
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "https://localhost:{}/",
            listener.local_addr().unwrap().port()
        );
        let drop_posts = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let (flag, count) = (drop_posts.clone(), dropped.clone());
        let worker = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let (flag, count) = (flag.clone(), count.clone());
                tokio::spawn(async move {
                    let Ok(client) = acceptor.accept(socket).await else {
                        return;
                    };
                    let Ok(upstream) = tokio::net::TcpStream::connect(upstream).await else {
                        return;
                    };
                    let (mut from_client, mut to_client) = tokio::io::split(client);
                    let (mut from_upstream, mut to_upstream) = upstream.into_split();
                    let responses = tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut from_upstream, &mut to_client).await;
                    });
                    let mut buffer = vec![0u8; 16384];
                    while let Ok(n) = from_client.read(&mut buffer).await {
                        if n == 0 {
                            break;
                        }
                        // Simulated transport loss: the request never reaches the
                        // provider and the client sees a closed connection.
                        if flag.load(Ordering::Acquire) && buffer[..n].starts_with(b"POST ") {
                            count.fetch_add(1, Ordering::AcqRel);
                            responses.abort();
                            return;
                        }
                        if to_upstream.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = to_upstream.shutdown().await;
                    let _ = responses.await;
                });
            }
        });
        Self {
            server,
            endpoint,
            certificate: pem,
            drop_posts,
            dropped,
            worker,
        }
    }
    /// The three bounded reads the broker performs before review and the one
    /// branch re-read before dispatch. `heads` are served in order; the last
    /// one repeats.
    async fn reads(&self, target: &WorkflowTarget, heads: &[&str]) {
        let file = target.path.rsplit('/').next().unwrap();
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/{}/actions/workflows/{file}",
                target.repository
            )))
            .and(header("authorization", "Bearer fixture-provider-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"id":71,"path":target.path,"state":"active","name":"Staging"}),
            ))
            .mount(&self.server)
            .await;
        for (index, head) in heads.iter().enumerate() {
            let mut mock = Mock::given(method("GET"))
                .and(path(format!(
                    "/repos/{}/branches/{}",
                    target.repository, target.git_ref
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    json!({"name":target.git_ref,"protected":true,"commit":{"sha":head}}),
                ));
            if index + 1 < heads.len() {
                mock = mock.up_to_n_times(1);
            }
            mock.mount(&self.server).await;
        }
        Mock::given(method("GET"))
            .and(path(format!(
                "/repos/{}/git/ref/tags/{}",
                target.repository, target.git_ref
            )))
            .respond_with(ResponseTemplate::new(404))
            .mount(&self.server)
            .await;
    }
    async fn dispatches(&self, target: &WorkflowTarget, response: ResponseTemplate) {
        let file = target.path.rsplit('/').next().unwrap();
        Mock::given(method("POST"))
            .and(path(format!(
                "/repos/{}/actions/workflows/{file}/dispatches",
                target.repository
            )))
            .and(header("authorization", "Bearer fixture-provider-token"))
            .and(header("x-github-api-version", "2026-03-10"))
            .and(header("accept", "application/vnd.github+json"))
            .and(body_json(json!({"ref":target.git_ref})))
            .respond_with(response)
            .mount(&self.server)
            .await;
    }
    async fn posts(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == "POST")
            .count()
    }
    async fn requests(&self) -> usize {
        self.server.received_requests().await.unwrap().len()
    }
}
impl Drop for GitHub {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

fn fixture(github: &GitHub, targets: Vec<WorkflowTarget>, attempts: u64) -> Fixture {
    Fixture::build(
        &github.endpoint,
        &github.certificate,
        |profile, reviewer_id, reviewer_public_key| Config {
            authority_policy: None,
            workflows: Some(targets),
            profile,
            reviewer_id,
            reviewer_public_key,
            generation: 1,
            max_scope_seconds: 3600,
            max_attempts: attempts,
            max_resources: 2,
            exact_action: true,
            allowed_statuses: vec![],
        },
    )
}
fn plan(resources: &[&WorkflowTarget], attempts: u64) -> Plan {
    Plan {
        resources: resources.iter().map(|t| t.resource()).collect(),
        statuses: vec![],
        expires_in_secs: 600,
        max_attempts: attempts,
    }
}
fn issued(f: &Fixture, resources: &[&WorkflowTarget], attempts: u64) -> (ScopeGrant, String) {
    let value = f
        .runtime
        .plan(plan(resources, attempts), &f.context)
        .unwrap();
    let review: SignedReview = serde_json::from_value(value).unwrap();
    f.approve(&review);
    let round_id = review.document.round_id;
    let value = f
        .runtime
        .activate(
            Round {
                round_id: round_id.clone(),
            },
            &f.context,
        )
        .unwrap();
    (
        serde_json::from_value(value["grant"].clone()).unwrap(),
        round_id,
    )
}
fn prepare(scope: &ScopeGrant, issuance: &str, target: &WorkflowTarget, request: &str) -> Prepare {
    Prepare {
        scope_id: scope.scope_id.clone(),
        issuance_round_id: issuance.into(),
        resource: target.resource(),
        status: None,
        request_id: request.into(),
    }
}
async fn prepared(
    f: &Fixture,
    scope: &ScopeGrant,
    issuance: &str,
    target: &WorkflowTarget,
    request: &str,
) -> SignedReview {
    let value = f
        .runtime
        .review_action(prepare(scope, issuance, target, request), &f.context)
        .await
        .unwrap();
    serde_json::from_value(value).unwrap()
}
fn charged(f: &Fixture, scope: &ScopeGrant) -> u64 {
    f.runtime
        .ledger
        .get_scope(&scope.scope_id)
        .unwrap()
        .charged_attempts
}

#[tokio::test]
async fn in_scope_dispatch_is_api_accepted_budget_blocks_the_third_and_replay_never_resends() {
    let github = GitHub::start().await;
    github.reads(&staging(), &[SHA]).await;
    github
        .dispatches(&staging(), ResponseTemplate::new(204))
        .await;
    let f = fixture(&github, vec![staging()], 2);
    let (scope, issuance) = issued(&f, &[&staging()], 2);
    assert_eq!(scope.operation, "github.dispatch_staging_workflow");
    assert_eq!(scope.resources, vec![staging().resource()]);
    assert_eq!(
        scope.fields,
        vec![FieldConstraint {
            field: "ref".into(),
            allowed_values: vec!["main".into()]
        }]
    );
    let review = prepared(&f, &scope, &issuance, &staging(), "dispatch-1").await;
    let ReviewSubject::ExactAction {
        action,
        evidence: Some(before),
        ..
    } = &review.document.subject
    else {
        panic!("broker-read provider state must be reviewable");
    };
    assert_eq!(action.resource, staging().resource());
    assert_eq!(action.resource_version, SHA);
    assert_eq!(
        action.fields,
        vec![FieldValue {
            field: "ref".into(),
            value: "main".into()
        }]
    );
    assert_eq!(
        before.fields,
        vec![
            FieldValue {
                field: "branch_protected".into(),
                value: "true".into()
            },
            FieldValue {
                field: "head_sha".into(),
                value: SHA.into()
            },
            FieldValue {
                field: "workflow_id".into(),
                value: "71".into()
            },
            FieldValue {
                field: "workflow_state".into(),
                value: "active".into()
            },
        ]
    );
    // Review is not approval: no dispatch before the signed decision.
    assert!(f.execute(&review, &issuance).await.is_err());
    assert_eq!(github.posts().await, 0);
    f.approve(&review);
    let first = f.execute(&review, &issuance).await.unwrap();
    assert_eq!(first["state"], "api_accepted");
    assert_eq!(f.execute(&review, &issuance).await.unwrap(), first);
    assert_eq!(github.posts().await, 1);
    let second_review = prepared(&f, &scope, &issuance, &staging(), "dispatch-2").await;
    f.approve(&second_review);
    assert_eq!(
        f.execute(&second_review, &issuance).await.unwrap()["state"],
        "api_accepted"
    );
    assert_eq!(github.posts().await, 2);
    assert_eq!(charged(&f, &scope), 2);
    // The third exact action can be reviewed but never charged or dispatched.
    let third = prepared(&f, &scope, &issuance, &staging(), "dispatch-3").await;
    f.approve(&third);
    assert!(f.execute(&third, &issuance).await.is_err());
    assert_eq!(charged(&f, &scope), 2);
    assert_eq!(github.posts().await, 2);
    let f = f.restart();
    assert_eq!(f.execute(&review, &issuance).await.unwrap(), first);
    assert_eq!(
        f.runtime
            .handle(
                &Request {
                    id: 1,
                    method: "scope_outcome".into(),
                    params: json!({"scope_id":scope.scope_id,"request_id":"dispatch-1"}),
                },
                &f.context
            )
            .await
            .unwrap()["state"],
        "api_accepted"
    );
    assert_eq!(github.posts().await, 2);
    // The budget-blocked third action was never reserved, so only two charged
    // actions exist; the ledger records consumption, not requests.
    let snapshot = f.runtime.snapshot(&f.context).unwrap();
    assert_eq!(snapshot["ledger"]["actions"].as_array().unwrap().len(), 2);
    assert_eq!(snapshot["ledger"]["scopes"][0]["resource_count"], 1);
    assert_eq!(
        snapshot["ledger"]["scopes"][0]["grant"]["operation"],
        "github.dispatch_staging_workflow"
    );
}

#[tokio::test]
async fn out_of_scope_repository_workflow_and_ref_are_denied_before_any_provider_call() {
    let github = GitHub::start().await;
    let release = target(REPO, WORKFLOW, "release/2026-09");
    let f = fixture(&github, vec![staging(), release.clone()], 2);
    let other_repo = target("example-org/other", WORKFLOW, "main");
    let production = target(REPO, ".github/workflows/production.yml", "main");
    let other_ref = target(REPO, WORKFLOW, "develop");
    // Policy denies at plan time: no review round is created for a foreign target.
    for foreign in [&other_repo, &production, &other_ref] {
        assert!(
            f.runtime.plan(plan(&[foreign], 1), &f.context).is_err(),
            "{}",
            foreign.resource()
        );
        assert!(
            f.runtime
                .plan(plan(&[&staging(), foreign], 1), &f.context)
                .is_err(),
            "{}",
            foreign.resource()
        );
    }
    let mut with_statuses = plan(&[&staging()], 1);
    with_statuses.statuses = vec![Status::Closed];
    assert!(f.runtime.plan(with_statuses, &f.context).is_err());
    for malformed in [
        "",
        REPO,
        &format!("{REPO}:{WORKFLOW}"),
        &format!("{REPO}:{WORKFLOW}:main:extra"),
        &format!("{REPO}:{WORKFLOW}:refs/heads/main"),
        &format!("{REPO}:{WORKFLOW}:{SHA}"),
        &format!("{REPO}:workflows/staging.yml:main"),
        &format!("{REPO}:{WORKFLOW}:../main"),
        "../service:.github/workflows/staging.yml:main",
    ] {
        assert!(
            f.runtime
                .plan(
                    Plan {
                        resources: vec![malformed.into()],
                        statuses: vec![],
                        expires_in_secs: 600,
                        max_attempts: 1,
                    },
                    &f.context
                )
                .is_err(),
            "{malformed}"
        );
    }
    assert_eq!(f.runtime.reviews.list_retained(20).unwrap().0, 0);
    // The scope names one policy target; the other policy target stays outside it.
    let (scope, issuance) = issued(&f, &[&staging()], 1);
    for outside in [&other_repo, &production, &other_ref, &release] {
        assert!(
            f.runtime
                .review_action(prepare(&scope, &issuance, outside, "request-1"), &f.context)
                .await
                .is_err(),
            "{}",
            outside.resource()
        );
    }
    let mut with_status = prepare(&scope, &issuance, &staging(), "request-1");
    with_status.status = Some(Status::Closed);
    assert!(
        f.runtime
            .review_action(with_status, &f.context)
            .await
            .is_err()
    );
    assert!(
        f.runtime
            .handle(
                &Request {
                    id: 1,
                    method: "scope_prepare".into(),
                    params: json!({"scope_id":scope.scope_id,"issuance_round_id":issuance,"resource":production.resource(),"request_id":"request-1","status":"closed"}),
                },
                &f.context
            )
            .await
            .is_err()
    );
    assert!(
        f.runtime
            .run(
                prepare(&scope, &issuance, &staging(), "request-1"),
                &f.context
            )
            .await
            .is_err(),
        "exact-action policy never permits automatic dispatch"
    );
    assert_eq!(github.requests().await, 0);
    assert_eq!(charged(&f, &scope), 0);
}

#[tokio::test]
async fn server_error_lost_connection_and_timeout_are_unknown_charged_and_never_resent() {
    for mode in ["500", "502", "dropped", "timeout"] {
        let github = GitHub::start().await;
        github.reads(&staging(), &[SHA]).await;
        match mode {
            "500" => {
                github
                    .dispatches(&staging(), ResponseTemplate::new(500))
                    .await
            }
            "502" => {
                github
                    .dispatches(&staging(), ResponseTemplate::new(502))
                    .await
            }
            "dropped" => github.drop_posts.store(true, Ordering::Release),
            _ => {
                github
                    .dispatches(
                        &staging(),
                        ResponseTemplate::new(204).set_delay(Duration::from_secs(9)),
                    )
                    .await
            }
        }
        let f = fixture(&github, vec![staging()], 2);
        let (scope, issuance) = issued(&f, &[&staging()], 2);
        let review = prepared(&f, &scope, &issuance, &staging(), "uncertain").await;
        f.approve(&review);
        let result = f.execute(&review, &issuance).await.unwrap();
        assert_eq!(result["state"], "unknown", "{mode}");
        assert_eq!(charged(&f, &scope), 1, "{mode}");
        // Replay and restart return the retained record; nothing is sent again.
        assert_eq!(f.execute(&review, &issuance).await.unwrap(), result);
        let f = f.restart();
        assert_eq!(f.execute(&review, &issuance).await.unwrap(), result);
        assert_eq!(charged(&f, &scope), 1, "{mode}");
        let expected_posts = if mode == "dropped" { 0 } else { 1 };
        assert_eq!(github.posts().await, expected_posts, "{mode}");
        assert_eq!(
            github.dropped.load(Ordering::Acquire),
            usize::from(mode == "dropped"),
            "{mode}"
        );
    }
}

#[tokio::test]
async fn provider_refusal_and_moved_head_are_rejected_without_creating_a_run() {
    for moved in [false, true] {
        let github = GitHub::start().await;
        github
            .reads(&staging(), if moved { &[SHA, MOVED] } else { &[SHA] })
            .await;
        github
            .dispatches(
                &staging(),
                ResponseTemplate::new(422).set_body_json(
                    json!({"message":"Workflow does not have 'workflow_dispatch' trigger"}),
                ),
            )
            .await;
        let f = fixture(&github, vec![staging()], 2);
        let (scope, issuance) = issued(&f, &[&staging()], 2);
        let review = prepared(&f, &scope, &issuance, &staging(), "refused").await;
        f.approve(&review);
        let result = f.execute(&review, &issuance).await.unwrap();
        assert_eq!(result["state"], "rejected", "moved={moved}");
        assert_eq!(charged(&f, &scope), 1);
        // A moved head is refused by the broker before any POST; a provider 4xx
        // means GitHub validated and refused, so no run exists either way.
        assert_eq!(github.posts().await, usize::from(!moved), "moved={moved}");
        let f = f.restart();
        assert_eq!(f.execute(&review, &issuance).await.unwrap(), result);
        assert_eq!(github.posts().await, usize::from(!moved));
    }
}

#[tokio::test]
async fn revocation_between_prepare_and_execute_refuses_dispatch() {
    for via_rpc in [false, true] {
        let github = GitHub::start().await;
        github.reads(&staging(), &[SHA]).await;
        github
            .dispatches(&staging(), ResponseTemplate::new(204))
            .await;
        let f = fixture(&github, vec![staging()], 2);
        let (scope, issuance) = issued(&f, &[&staging()], 2);
        let review = prepared(&f, &scope, &issuance, &staging(), "revoked").await;
        f.approve(&review);
        if via_rpc {
            f.runtime
                .handle(
                    &Request {
                        id: 1,
                        method: "scope_revoke".into(),
                        params: json!({"scope_id":scope.scope_id}),
                    },
                    &f.context,
                )
                .await
                .unwrap();
        } else {
            f.runtime
                .ledger
                .revoke(&scope.scope_id, now_unix())
                .unwrap();
        }
        assert!(f.execute(&review, &issuance).await.is_err());
        assert_eq!(charged(&f, &scope), 0);
        let f = f.restart();
        assert!(f.execute(&review, &issuance).await.is_err());
        assert!(
            f.runtime
                .review_action(
                    prepare(&scope, &issuance, &staging(), "after-revocation"),
                    &f.context
                )
                .await
                .is_err()
        );
        assert_eq!(github.posts().await, 0);
        assert!(
            f.runtime
                .ledger
                .get_scope(&scope.scope_id)
                .unwrap()
                .revoked_at
                .is_some()
        );
    }
}

#[tokio::test]
async fn dispatch_manifest_binds_targets_and_startup_rejects_widened_or_mixed_config() {
    let github = GitHub::start().await;
    github.reads(&staging(), &[SHA]).await;
    github
        .dispatches(&staging(), ResponseTemplate::new(204))
        .await;
    let mut f = fixture(&github, vec![staging()], 2);
    let manifest = json!({"apiVersion":policy::API_VERSION,"kind":policy::KIND,"metadata":{"name":"staging-dispatch","namespace":"release"},
        "spec":{"tenantRef":"fixture","connectorRef":"github","authority":{"operation":policy::DISPATCH_OPERATION,
        "workflows":[{"repository":REPO,"path":WORKFLOW,"ref":"main"}],"maxResources":1,"maxAttempts":3,"maxDuration":"1h"},
        "approval":{"scope":"Required","action":"EveryAction","reviewerRef":"ops"}}});
    let path = f.directory.path().join("authority-policy.json");
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let compiled = policy::read(&path).unwrap();
    let binding = crate::authority_policy::Config {
        path,
        digest: compiled.digest.clone(),
        name: "staging-dispatch".into(),
        namespace: "release".into(),
        tenant_ref: "fixture".into(),
        connector_ref: "github".into(),
        reviewer_ref: "ops".into(),
        reviewer_id: f.runtime.config.reviewer_id.clone(),
        reviewer_public_key: f.runtime.config.reviewer_public_key.clone(),
        generation: 1,
        profile: f.runtime.config.profile.clone(),
    };
    let resolved = binding.resolve(&f.tenant).unwrap();
    assert_eq!(resolved.workflows, Some(vec![staging()]));
    assert!(resolved.allowed_statuses.is_empty());
    assert_eq!(resolved.max_attempts, 3);
    assert!(resolved.exact_action);
    f.runtime.config = resolved;
    let f = f.restart();
    let snapshot = f.runtime.snapshot(&f.context).unwrap();
    assert_eq!(snapshot["authority_policy"]["digest"], compiled.digest);
    assert_eq!(
        snapshot["authority_policy"]["identity"]["namespace"],
        "release"
    );
    let (scope, issuance) = issued(&f, &[&staging()], 1);
    let review = prepared(&f, &scope, &issuance, &staging(), "manifest-dispatch").await;
    f.approve(&review);
    assert_eq!(
        f.execute(&review, &issuance).await.unwrap()["state"],
        "api_accepted"
    );
    assert_eq!(github.posts().await, 1);
    // Startup refuses a dispatch config that also carries support statuses,
    // an empty or unsorted target set, or an unparsable target.
    type Mutation = (&'static str, fn(&mut Config));
    let mutations: &[Mutation] = &[
        ("mixed statuses", |c| {
            c.allowed_statuses = vec![Status::Closed]
        }),
        ("no targets", |c| c.workflows = Some(vec![])),
        ("unsorted targets", |c| {
            c.workflows = Some(vec![
                target(REPO, WORKFLOW, "release/2026-09"),
                target(REPO, WORKFLOW, "main"),
            ])
        }),
        ("duplicate targets", |c| {
            c.workflows = Some(vec![staging(), staging()])
        }),
        ("invalid target", |c| {
            c.workflows = Some(vec![target(REPO, "staging.yml", "main")])
        }),
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
}

#[test]
fn dispatch_profile_digest_is_distinct_from_the_support_digest_for_the_same_custody() {
    let directory = tempfile::tempdir().unwrap();
    let token = directory.path().join("token");
    std::fs::write(&token, "fixture-token").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let profile = connector::Profile {
        endpoint: "https://api.github.example.invalid/".into(),
        token_file: token.clone(),
        ca_certificate_file: None,
    };
    let github = dispatch::Connector::new(&profile).unwrap().digest;
    assert_eq!(github, dispatch::Connector::new(&profile).unwrap().digest);
    assert_ne!(github, Connector::new(&profile).unwrap().digest);
    std::fs::write(&token, "rotated-token").unwrap();
    assert_ne!(github, dispatch::Connector::new(&profile).unwrap().digest);
    for endpoint in [
        "http://api.github.com/",
        "https://ghes.example.invalid/api/v3",
        "https://user:pass@api.github.com/",
        "https://api.github.com/?token=x",
    ] {
        let mut changed = profile.clone();
        changed.endpoint = endpoint.into();
        assert!(dispatch::Connector::new(&changed).is_err(), "{endpoint}");
    }
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(dispatch::Connector::new(&profile).is_err());
}
