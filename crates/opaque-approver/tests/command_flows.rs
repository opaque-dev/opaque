//! Real CLI and pinned TLS; the private native helper supplies only a scripted
//! review rejection. No native authentication or provider operation is claimed.
use opaque_approver::{
    client::{BrokerClient, certificate_fingerprint},
    custody::{self, BrokerEnrollment},
};
use opaque_core::workstation::{WorkstationReview, review_hash};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[path = "support/scope_flows.rs"]
mod scope_flows;

struct Peer {
    endpoint: String,
    pin: String,
    task: tokio::task::JoinHandle<Vec<String>>,
    stop: Arc<AtomicBool>,
}
impl Peer {
    async fn start(responses: Vec<Vec<u8>>) -> Self {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pin = certificate_fingerprint(certificate.cert.der());
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
        // A nonblocking accept lets shutdown drain the kernel backlog before
        // declaring that no extra connection was attempted by the completed CLI.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("https://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut responses = std::collections::VecDeque::from(responses);
            let mut deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if worker_stop.load(Ordering::Acquire) {
                            assert!(
                                responses.is_empty(),
                                "CLI ended before all expected requests"
                            );
                            break;
                        }
                        assert!(
                            responses.is_empty() || tokio::time::Instant::now() < deadline,
                            "missing expected CLI request"
                        );
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        continue;
                    }
                    Err(error) => panic!("peer accept failed: {error}"),
                };
                assert!(
                    requests.len() < 1024,
                    "unbounded unexpected CLI connections"
                );
                let Some(response) = responses.pop_front() else {
                    // Connecting alone violates no-I/O/no-replay. Record it
                    // without waiting for a TLS handshake or HTTP body.
                    requests.push("<unexpected connection>".into());
                    continue;
                };
                stream.set_nonblocking(true).unwrap();
                let stream = tokio::net::TcpStream::from_std(stream).unwrap();
                let request = tokio::time::timeout(Duration::from_secs(5), async {
                    let mut stream = acceptor.accept(stream).await.unwrap();
                    let mut bytes = Vec::new();
                    loop {
                        let mut chunk = [0; 4096];
                        let count = stream.read(&mut chunk).await.unwrap();
                        assert!(count > 0 && bytes.len() + count < 256 * 1024);
                        bytes.extend_from_slice(&chunk[..count]);
                        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
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
                    // The client may reject an advertised oversized body early.
                    let _ = stream.write_all(&response).await;
                    let _ = stream.shutdown().await;
                    String::from_utf8(bytes).unwrap()
                })
                .await
                .expect("peer TLS/HTTP exchange exceeded its bound");
                requests.push(request);
                deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            }
            requests
        });
        Self {
            endpoint,
            pin,
            task,
            stop,
        }
    }
    async fn finish(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(5), &mut self.task)
            .await
            .unwrap()
            .unwrap()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.task.abort();
    }
}
fn response(status: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes
}
fn ok(body: &Value) -> Vec<u8> {
    response("200 OK", &serde_json::to_vec(body).unwrap())
}

struct CliImage {
    _directory: tempfile::TempDir,
    binary: PathBuf,
}

static CLI_IMAGE: std::sync::Mutex<std::sync::Weak<CliImage>> =
    std::sync::Mutex::new(std::sync::Weak::new());

fn cli_image(temp_parent: &Path) -> Arc<CliImage> {
    let mut published = CLI_IMAGE.lock().unwrap();
    if let Some(image) = published.upgrade() {
        return image;
    }
    let directory = tempfile::tempdir_in(temp_parent).unwrap();
    let binary = directory.path().join("opaque-approver");
    let source = Path::new(env!("CARGO_BIN_EXE_opaque-approver"));
    match std::fs::hard_link(source, &binary) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
            // /target and the private tmpfs may differ. Copy all bytes without
            // stripping coverage sections, and close the writer before atomic
            // publication. The Mutex/Arc prevents rewriting this image while
            // any fixture can spawn and inherit a writable descriptor.
            let staged = directory.path().join("image.staged");
            {
                let mut input = std::fs::File::open(source).unwrap();
                let mut output = std::fs::File::create_new(&staged).unwrap();
                std::io::copy(&mut input, &mut output).unwrap();
                output
                    .set_permissions(input.metadata().unwrap().permissions())
                    .unwrap();
                output.sync_all().unwrap();
            }
            std::fs::rename(staged, &binary).unwrap();
        }
        Err(error) => panic!("immutable CLI publication failed: {error}"),
    }
    let image = Arc::new(CliImage {
        _directory: directory,
        binary,
    });
    *published = Arc::downgrade(&image);
    image
}

struct Workstation {
    _directory: tempfile::TempDir,
    state: PathBuf,
    binary: PathBuf,
    helper: PathBuf,
    _image: Arc<CliImage>,
}
impl Workstation {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        custody::initialize(&state, "Disposable command reviewer").unwrap();
        let binary = directory.path().join("opaque-approver");
        let image = cli_image(directory.path().parent().unwrap());
        std::fs::hard_link(&image.binary, &binary).unwrap();
        let helper = directory.path().join("opaque-approve-helper");
        std::os::unix::fs::symlink(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/native-review.sh"
            ),
            &helper,
        )
        .unwrap();
        Self {
            _directory: directory,
            state,
            binary,
            helper,
            _image: image,
        }
    }
    fn enroll(&self, peer: &Peer) -> BrokerEnrollment {
        let mut state = custody::load(&self.state).unwrap().0;
        let enrollment = BrokerEnrollment {
            endpoint: peer.endpoint.clone(),
            broker_id: "opq-fixture".into(),
            tls_fingerprint: peer.pin.clone(),
            device_id: "00000000-0000-4000-8000-000000000005".into(),
            token: "fixture-bearer".into(),
        };
        state.enrollment = Some(enrollment.clone());
        custody::save(&self.state, &state).unwrap();
        enrollment
    }
    async fn run(&self, command: &str, extra: &[&str]) -> Output {
        let mut child = tokio::process::Command::new(&self.binary);
        child
            .arg(command)
            .args(["--state-dir", self.state.to_str().unwrap()])
            .args(extra)
            .env("HOME", self._directory.path())
            .env_remove("OPAQUE_SESSION_TOKEN")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        tokio::time::timeout(Duration::from_secs(10), child.output())
            .await
            .unwrap()
            .unwrap()
    }
}
fn review(state: &Path, id: &str) -> WorkstationReview {
    let key = custody::load(state).unwrap().0.public_key_hex;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let body = "One exact disposable task; no provider side effects.\n";
    serde_json::from_value(json!({"challenge":{"schema_version":2,"broker_id":"opq-fixture","approval_id":id,"request_id":"00000000-0000-4000-8000-000000000002","operation":"github.release_manifest","content_hash":review_hash(body),"nonce":"aa".repeat(32),"created_at":now,"expires_at":now+60,
        "authority":{"binding":{"tenant":{"schema_version":1,"tenant_id":"fixture","broker_id":"00000000-0000-4000-8000-000000000003"},"task_id":"00000000-0000-4000-8000-000000000004","manifest_digest":"bb".repeat(32),"request_hash":"cc".repeat(32),"policy_digest":"dd".repeat(32),"requester":"svc-fixture"},"principal_id":"human-fixture","public_key_hex":key,"required_role":"operator","authority_epoch":1}},"review_text":body})).unwrap()
}
const ID: &str = "00000000-0000-4000-8000-000000000001";
fn failure(output: &Output, expected: &str) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(expected),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn transport_enforces_response_limits_and_reports_exact_failure_class() {
    let mut chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for length in [131072, 131073] {
        chunked.extend_from_slice(format!("{length:x}\r\n").as_bytes());
        chunked.extend(vec![b' '; length]);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    for (bytes, expected) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 262145\r\nConnection: close\r\n\r\n".to_vec(),
            "broker response exceeds the review limit",
        ),
        (chunked, "broker response exceeds the review limit"),
        (
            response("200 OK", b"not JSON"),
            "broker returned an invalid workstation response",
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{}".to_vec(),
            "broker response interrupted",
        ),
        (
            response("403 Forbidden", b"do not expose this peer body"),
            "broker rejected workstation request (HTTP 403)",
        ),
    ] {
        let peer = Peer::start(vec![bytes]).await;
        let client = BrokerClient::new(&peer.endpoint, &peer.pin).unwrap();
        assert_eq!(
            client
                .request::<Value>(reqwest::Method::GET, "/workstation/check", None, None)
                .await
                .unwrap_err(),
            expected
        );
        assert_eq!(peer.finish().await.len(), 1);
    }
}

#[tokio::test]
async fn empty_success_is_null_and_json_credentials_reach_only_the_pinned_peer() {
    let peer = Peer::start(vec![response("204 No Content", b"")]).await;
    let client = BrokerClient::new(&peer.endpoint, &peer.pin).unwrap();
    assert_eq!(
        client
            .request::<Value>(
                reqwest::Method::POST,
                "/workstation/check",
                Some(json!({"decision":"reject"})),
                Some(("fixture-device", "fixture-token"))
            )
            .await
            .unwrap(),
        Value::Null
    );
    let requests = peer.finish().await;
    assert!(requests[0].contains("x-opaque-device: fixture-device"));
    assert!(requests[0].contains("authorization: Bearer fixture-token"));
    assert!(requests[0].ends_with("{\"decision\":\"reject\"}"));
}

#[tokio::test]
async fn cli_rejects_invalid_ids_unenrolled_custody_and_delegated_execution() {
    let workstation = Workstation::new();
    for command in ["review", "receipt"] {
        failure(
            &workstation
                .run(command, &["--approval-id", "not-a-uuid"])
                .await,
            "approval_id must be",
        );
    }
    for command in ["review", "receipt"] {
        failure(
            &workstation.run(command, &["--approval-id", ID]).await,
            "not enrolled",
        );
    }
    failure(&workstation.run("list", &[]).await, "not enrolled");
    for command in ["open", "inspect"] {
        failure(
            &workstation
                .run(command, &["--notice", "not-a-notice"])
                .await,
            "not enrolled",
        );
    }
    let output = Command::new(&workstation.binary)
        .args(["list", "--state-dir", workstation.state.to_str().unwrap()])
        .env("OPAQUE_SESSION_TOKEN", "fixture-session")
        .output()
        .unwrap();
    failure(&output, "outside delegated agent sessions");
}

#[tokio::test]
async fn cli_list_and_inspect_bind_metadata_to_the_exact_enrollment() {
    let workstation = Workstation::new();
    let document = review(&workstation.state, ID);
    let peer = Peer::start(vec![
        ok(&json!({"approvals":[document.challenge]})),
        ok(&serde_json::to_value(&document).unwrap()),
    ])
    .await;
    workstation.enroll(&peer);
    let listed = workstation.run("list", &[]).await;
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&listed.stdout).unwrap()[0]["approval_id"],
        ID
    );
    let notice = opaque_core::workstation::notice_link("opq-fixture", ID).unwrap();
    let inspected = workstation.run("inspect", &["--notice", &notice]).await;
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let context: Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(context["approval_id"], ID);
    assert_eq!(context["reviewer"], "human-fixture");
    assert_eq!(peer.finish().await.len(), 2);
}

#[tokio::test]
async fn cli_refuses_replaced_or_foreign_review_before_opening_native_ui() {
    for wrong_key in [false, true] {
        let workstation = Workstation::new();
        let mut document = review(&workstation.state, ID);
        if wrong_key {
            document
                .challenge
                .authority
                .as_mut()
                .unwrap()
                .public_key_hex = "11".repeat(32);
        } else {
            document.challenge.approval_id = "00000000-0000-4000-8000-000000000009".into();
        }
        let peer = Peer::start(vec![ok(&serde_json::to_value(&document).unwrap())]).await;
        workstation.enroll(&peer);
        let output = workstation.run("review", &["--approval-id", ID]).await;
        failure(
            &output,
            if wrong_key {
                "different enrolled workstation key"
            } else {
                "different approval round"
            },
        );
        assert!(!workstation.helper.with_extension("review").exists());
        assert_eq!(peer.finish().await.len(), 1);
    }
}

#[tokio::test]
async fn cli_native_rejection_is_signed_once_after_unchanged_round_revalidation() {
    let workstation = Workstation::new();
    let document = review(&workstation.state, ID);
    let peer = Peer::start(vec![
        ok(&serde_json::to_value(&document).unwrap()),
        ok(&serde_json::to_value(&document).unwrap()),
        ok(&json!({"accepted":true})),
    ])
    .await;
    workstation.enroll(&peer);
    let output = workstation.run("review", &["--approval-id", ID]).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = peer.finish().await;
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("GET "));
    assert!(requests[1].starts_with("GET "));
    assert!(requests[2].starts_with("POST "));
    let response: opaque_core::workstation::WorkstationResponse =
        serde_json::from_str(requests[2].split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(
        response.decision,
        opaque_core::workstation::WorkstationDecision::Reject
    );
    let receipt = opaque_core::workstation::SignedWorkstationReceipt {
        schema_version: 1,
        review: document,
        response,
        accepted_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    };
    receipt.verify().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("\"decision_status\":\"accepted\""));
    let shown = std::fs::read_to_string(workstation.helper.with_extension("review")).unwrap();
    assert!(shown.contains("COMPLETE IMMUTABLE REVIEW"));
    assert!(shown.contains("Review fingerprint (SHA-256)"));
}

#[tokio::test]
async fn cli_replaced_round_after_native_rejection_never_posts_a_signature() {
    let workstation = Workstation::new();
    let document = review(&workstation.state, ID);
    let mut replacement = document.clone();
    replacement.challenge.nonce = "ee".repeat(32);
    let peer = Peer::start(vec![
        ok(&serde_json::to_value(&document).unwrap()),
        ok(&serde_json::to_value(&replacement).unwrap()),
    ])
    .await;
    workstation.enroll(&peer);
    failure(
        &workstation.run("review", &["--approval-id", ID]).await,
        "changed after review; no signature sent",
    );
    let requests = peer.finish().await;
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
}

#[tokio::test]
async fn cli_enrollment_proves_key_possession_and_refuses_foreign_or_short_credentials() {
    use ed25519_dalek::Signer;
    use opaque_core::workstation::{
        EnrollmentChallenge, EnrollmentRequest, enrollment_bytes, verify_signature,
    };
    for invalid in 0..3 {
        let workstation = Workstation::new();
        let state = custody::load(&workstation.state).unwrap().0;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let challenge = EnrollmentChallenge {
            schema_version: 1,
            broker_id: "opq-fixture".into(),
            public_key_hex: state.public_key_hex.clone(),
            nonce: "af".repeat(32),
            created_at: now,
            expires_at: now + 120,
        };
        let credential = json!({"device_id":ID,"server_id":if invalid == 1 {"opq-other"} else {"opq-fixture"},"token":if invalid == 2 {"short".into()} else {"ab".repeat(32)}});
        let peer = Peer::start(vec![
            ok(&serde_json::to_value(&challenge).unwrap()),
            ok(&credential),
        ])
        .await;
        let output = workstation
            .run(
                "enroll",
                &[
                    "--broker",
                    &peer.endpoint,
                    "--broker-id",
                    "opq-fixture",
                    "--tls-fingerprint",
                    &peer.pin,
                ],
            )
            .await;
        if invalid == 0 {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let enrolled = custody::load(&workstation.state)
                .unwrap()
                .0
                .enrollment
                .unwrap();
            assert_eq!(enrolled.token, "ab".repeat(32));
            assert_eq!(enrolled.endpoint, peer.endpoint);
            assert_eq!(enrolled.tls_fingerprint, peer.pin);
        } else {
            failure(&output, "broker enrollment identity mismatch");
            assert!(
                custody::load(&workstation.state)
                    .unwrap()
                    .0
                    .enrollment
                    .is_none()
            );
        }
        let requests = peer.finish().await;
        assert_eq!(requests.len(), 2);
        let proof: EnrollmentRequest =
            serde_json::from_str(requests[1].split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(proof.nonce, challenge.nonce);
        verify_signature(
            &state.public_key_hex,
            &proof.signature,
            &enrollment_bytes(&challenge),
        )
        .unwrap();
        let (_, key) = custody::load(&workstation.state).unwrap();
        assert_eq!(
            proof.signature,
            opaque_core::workstation::hex(&key.sign(&enrollment_bytes(&challenge)).to_bytes())
        );
    }
}

#[tokio::test]
async fn cli_reenrollment_cannot_replace_any_pinned_broker_component() {
    let workstation = Workstation::new();
    let peer = Peer::start(vec![]).await;
    let original = workstation.enroll(&peer);
    for field in 0..3 {
        let endpoint = if field == 0 {
            "https://127.0.0.1:9"
        } else {
            &peer.endpoint
        };
        let broker_id = if field == 1 {
            "opq-other"
        } else {
            "opq-fixture"
        };
        let pin = if field == 2 {
            "ab".repeat(32)
        } else {
            peer.pin.clone()
        };
        failure(
            &workstation
                .run(
                    "enroll",
                    &[
                        "--broker",
                        endpoint,
                        "--broker-id",
                        broker_id,
                        "--tls-fingerprint",
                        &pin,
                    ],
                )
                .await,
            "already pinned to a different broker",
        );
        assert_eq!(
            serde_json::to_value(
                custody::load(&workstation.state)
                    .unwrap()
                    .0
                    .enrollment
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(&original).unwrap()
        );
    }
    assert!(peer.finish().await.is_empty());
}

#[tokio::test]
async fn cli_inspect_refuses_foreign_ids_keys_and_notice_brokers() {
    for field in 0..3 {
        let workstation = Workstation::new();
        let mut document = review(&workstation.state, ID);
        if field == 0 {
            document.challenge.approval_id = "00000000-0000-4000-8000-000000000099".into();
        }
        if field == 1 {
            document
                .challenge
                .authority
                .as_mut()
                .unwrap()
                .public_key_hex = "ab".repeat(32);
        }
        let peer = Peer::start(if field == 2 {
            vec![]
        } else {
            vec![ok(&serde_json::to_value(document).unwrap())]
        })
        .await;
        workstation.enroll(&peer);
        let notice = opaque_core::workstation::notice_link(
            if field == 2 {
                "opq-foreign"
            } else {
                "opq-fixture"
            },
            ID,
        )
        .unwrap();
        failure(
            &workstation.run("inspect", &["--notice", &notice]).await,
            if field == 2 {
                "notice does not refer"
            } else {
                "review does not match"
            },
        );
        assert_eq!(peer.finish().await.len(), usize::from(field != 2));
        assert!(!workstation.helper.with_extension("review").exists());
    }
}

#[tokio::test]
async fn cli_open_resolves_notice_and_receipt_rejects_other_enrollments() {
    use ed25519_dalek::Signer;
    use opaque_core::workstation::{
        SignedWorkstationReceipt, WorkstationDecision, WorkstationResponse, hex,
        workstation_decision_bytes,
    };
    let workstation = Workstation::new();
    let document = review(&workstation.state, ID);
    let (_, key) = custody::load(&workstation.state).unwrap();
    let receipt = SignedWorkstationReceipt {
        schema_version: 1,
        review: document.clone(),
        response: WorkstationResponse {
            device_id: "00000000-0000-4000-8000-000000000005".into(),
            decision: WorkstationDecision::Reject,
            signature: hex(&key
                .sign(&workstation_decision_bytes(&document.challenge, false))
                .to_bytes()),
        },
        accepted_at: document.challenge.created_at,
    };
    let peer = Peer::start(vec![
        ok(&serde_json::to_value(&document).unwrap()),
        ok(&serde_json::to_value(&document).unwrap()),
        ok(&json!({"accepted":true})),
        ok(&serde_json::to_value(&receipt).unwrap()),
    ])
    .await;
    let enrollment = workstation.enroll(&peer);
    let notice = opaque_core::workstation::notice_link("opq-fixture", ID).unwrap();
    let opened = workstation.run("open", &["--notice", &notice]).await;
    assert!(
        opened.status.success(),
        "{}",
        String::from_utf8_lossy(&opened.stderr)
    );
    let retained = workstation.run("receipt", &["--approval-id", ID]).await;
    assert!(
        retained.status.success(),
        "{}",
        String::from_utf8_lossy(&retained.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<SignedWorkstationReceipt>(&retained.stdout).unwrap(),
        receipt
    );
    assert_eq!(peer.finish().await.len(), 4);
    let state = custody::load(&workstation.state).unwrap().0;
    for field in 0..4 {
        let mut enrolled = enrollment.clone();
        let mut identity = state.clone();
        let id = if field == 0 {
            "00000000-0000-4000-8000-000000000099"
        } else {
            ID
        };
        if field == 1 {
            enrolled.broker_id = "opq-foreign".into();
        }
        if field == 2 {
            enrolled.device_id = "00000000-0000-4000-8000-000000000099".into();
        }
        if field == 3 {
            identity.public_key_hex = "ab".repeat(32);
        }
        assert_eq!(
            opaque_approver::review::validate_receipt(&receipt, &enrolled, &identity, id)
                .unwrap_err(),
            "receipt belongs to another enrollment"
        );
    }
}

#[tokio::test]
async fn cli_native_capability_rejects_malformed_or_inflated_helper_claims() {
    let workstation = Workstation::new();
    for report in [
        "not json",
        r#"{"check":"wrong","ready":true,"visibility_verified":false}"#,
        r#"{"check":"native_review_ui","ready":false,"visibility_verified":false}"#,
        r#"{"check":"native_review_ui","ready":true,"visibility_verified":true}"#,
    ] {
        std::fs::write(workstation.helper.with_extension("report"), report).unwrap();
        let output = tokio::process::Command::new(&workstation.binary)
            .arg("check-native")
            .env_remove("OPAQUE_SESSION_TOKEN")
            .output()
            .await
            .unwrap();
        failure(
            &output,
            if report == "not json" {
                "invalid capability report"
            } else {
                "capability mismatch"
            },
        );
    }
    std::fs::remove_file(workstation.helper.with_extension("report")).unwrap();
    let output = tokio::process::Command::new(&workstation.binary)
        .arg("check-native")
        .env_remove("OPAQUE_SESSION_TOKEN")
        .output()
        .await
        .unwrap();
    failure(&output, "native review UI unavailable");
}

#[tokio::test]
async fn tls_peer_observes_zero_expected_and_trailing_unexpected_connections() {
    for expected in [false, true] {
        let peer = Peer::start(if expected {
            vec![ok(&json!({"observed":true}))]
        } else {
            vec![]
        })
        .await;
        if expected {
            let client = BrokerClient::new(&peer.endpoint, &peer.pin).unwrap();
            assert_eq!(
                client
                    .request::<Value>(reqwest::Method::GET, "/workstation/check", None, None)
                    .await
                    .unwrap(),
                json!({"observed":true})
            );
        }
        // Keep a real connection open without sending TLS. finish must drain
        // this accepted/queued connection, never block for a protocol frame.
        let unexpected =
            tokio::net::TcpStream::connect(peer.endpoint.strip_prefix("https://").unwrap())
                .await
                .unwrap();
        let observed = peer.finish().await;
        assert_eq!(observed.len(), if expected { 2 } else { 1 });
        assert_eq!(observed.last().unwrap(), "<unexpected connection>");
        if expected {
            assert!(observed[0].starts_with("GET /workstation/check "));
        }
        drop(unexpected);
    }
}
