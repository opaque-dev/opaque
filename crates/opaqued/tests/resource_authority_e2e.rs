//! Real-daemon resource-authority integration through the public BrokerClient.
//! Only this test may mutate its private fixture identity database. The external
//! consumer holds a separate resource credential and provider credential.
#[cfg(coverage)]
#[path = "support/coverage.rs"]
mod coverage;

use opaque_core::{
    resource_auth::{AuthError, BrokerClient, BrokerClientConfig, VerifiedAccess},
    tenant::{TenantBinding, TenantId},
};
use serde_json::{Value, json};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
const PRIVATE_KEY: &str = include_str!("fixtures/test_rsa_key.pem");
const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5+m4fkcL6cuTGRLTSSrF\n7zfrwFFnYRJG1yVmmCwn4q0PXhuWmUu9mo2wg9ftf9BLFspkMqyzxpdfzGTan6J9\n5w7Ad7gbP5R2aDGnVJRTX9dph3cKBgwnDsUa751mYWfr1rsTnoiMIDWzOGsRSdOi\nRzZGCYo3yo4YNB+sNIOFMQ/tc3X558HGCZl3boecDmlwt1lHebe6/+kXRTYLLpIl\nf7u1mw98TYtOenu2SIUOrJKY9VGluMxvGH9e4SExpZaG61wTNsosD20tEBkWUjCo\nxo01adXNjPYKx/mJB3NgCIWacU4NwbZxVRUg5HYR85cq+5I2oNQDwuyNDv7kZQfA\nywIDAQAB\n-----END PUBLIC KEY-----\n";
const SCOPES: &str =
    "metrics:read metrics:explain metrics:stream metrics:metric:requests_per_second";
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
struct Daemon {
    child: Child,
    root: PathBuf,
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Daemon {
    async fn start(root: &Path) -> Self {
        let _ = std::fs::remove_file(root.join("resource.sock")); // Our killed fixture's path only.
        let mut command = Command::new(env!("CARGO_BIN_EXE_opaqued"));
        command
            .env("HOME", root)
            .env("XDG_RUNTIME_DIR", root.join("run"))
            .env("OPAQUE_CONFIG", root.join("config.toml"))
            .env("OPAQUE_RESOURCE_AUTHORITY_FIXTURE", "1")
            .env_remove("OPAQUE_SOCK")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        #[cfg(coverage)]
        coverage::subprocess(&mut command, "daemon");
        let mut child = command.spawn().unwrap();
        for _ in 0..200 {
            if root.join("resource.sock").exists() {
                return Self {
                    child,
                    root: root.into(),
                };
            }
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "fixture daemon exited: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        panic!(
            "fixture daemon unavailable: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    fn db(&self) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(self.root.join("state/identity.db")).unwrap();
        c.busy_timeout(Duration::from_secs(2)).unwrap();
        c
    }
    fn update(&self, sql: &str) {
        self.db().execute(sql, []).unwrap();
    }
}
fn sign(claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("at+jwt".into());
    jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}
// A test-only external consumer: authorize before reading and before disclosure.
async fn guarded_read(
    broker: &BrokerClient,
    access: &VerifiedAccess,
    source: &str,
) -> Result<Value, AuthError> {
    broker.check_access(access)?;
    access.require_scope("metrics:read")?;
    let value = reqwest::Client::new()
        .post(format!("{source}/observation"))
        .bearer_auth("synthetic-provider-credential")
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    broker.check_access(access)?;
    Ok(value)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn broker_identity_is_live_for_external_reads_and_durable_revocation() {
    let tmp = Path::new("/tmp").canonicalize().unwrap();
    let directory = tempfile::Builder::new()
        .prefix("oq-resource-")
        .tempdir_in(tmp)
        .unwrap();
    let root = directory.path();
    for child in ["run", "state"] {
        std::fs::create_dir(root.join(child)).unwrap();
        std::fs::set_permissions(root.join(child), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(root.join("resource.key"), [7u8; 32]).unwrap();
    std::fs::set_permissions(
        root.join("resource.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let issuer = MockServer::start().await;
    let source = MockServer::start().await;
    let audience = "https://resource.example/mcp";
    let binding =
        TenantBinding::new(TenantId::parse("customer-a").unwrap(), uuid::Uuid::new_v4()).unwrap();
    let uid = unsafe { libc::geteuid() };
    let scopes = SCOPES.split(' ').collect::<Vec<_>>();
    let config = format!(
        r#"data_dir = {state}
[identity]
issuer = {issuer}
client_id = "opaque-login"
required = true
allowed_subjects = ["fixture-user"]
allowed_email_domains = ["example.com"]
[resource_authority]
socket_path = {socket}
credential_file = {key}
allowed_gateway_uids = [{uid}]
fixture_mode = true
[resource_authority.binding]
schema_version = 1
tenant_id = "customer-a"
broker_id = "{broker_id}"
[resource_authority.role_scopes]
operator = {scopes}
[resource_authority.auth]
issuer = {issuer}
resource_audience = {audience}
public_key_pem = '''{public_key}'''
allow_loopback_http = true
[[resource_authority.auth.admissions]]
tenant_id = "customer-a"
subject = "fixture-user"
client_id = "gateway-client"
scopes = {scopes}
"#,
        state = json!(root.join("state")),
        issuer = json!(issuer.uri()),
        socket = json!(root.join("resource.sock")),
        key = json!(root.join("resource.key")),
        broker_id = binding.broker_id,
        scopes = json!(scopes),
        audience = json!(audience),
        public_key = PUBLIC_KEY
    );
    std::fs::write(root.join("config.toml"), config).unwrap();
    let mut daemon = Daemon::start(root).await;
    let broker_config = BrokerClientConfig {
        socket_path: root.join("resource.sock"),
        credential_file: root.join("resource.key"),
        broker_uid: uid,
        binding: binding.clone(),
    };
    let broker = BrokerClient::new(broker_config.clone(), issuer.uri(), audience.into()).unwrap();
    let claims = json!({"iss":issuer.uri(),"aud":audience,"sub":"fixture-user","client_id":"gateway-client","tenant_id":"customer-a","scope":SCOPES,"jti":"active-fixture","iat":now(),"exp":now()+600});
    let bearer = format!("Bearer {}", sign(&claims));
    assert_eq!(
        broker.verify_bearer(Some(&bearer)).unwrap_err(),
        AuthError::NotAdmitted,
        "a token must never bootstrap a broker principal"
    );
    daemon.db().execute("INSERT INTO principals(id,kind,iss,sub,email,roles,created_at,last_seen) VALUES('hum_00000000000000000000000000000001','human',?1,'fixture-user','fixture@example.com','operator',?2,?2)",rusqlite::params![issuer.uri(),now()]).unwrap();
    let access = broker.verify_bearer(Some(&bearer)).unwrap();
    let mut wrong_uid = broker_config.clone();
    wrong_uid.broker_uid = uid.wrapping_add(1);
    assert_eq!(
        BrokerClient::new(wrong_uid, issuer.uri(), audience.into())
            .unwrap()
            .verify_bearer(Some(&bearer))
            .unwrap_err(),
        AuthError::Unavailable
    );
    let wrong_key_path = root.join("wrong-resource.key");
    std::fs::write(&wrong_key_path, [8u8; 32]).unwrap();
    std::fs::set_permissions(&wrong_key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut wrong_key = broker_config.clone();
    wrong_key.credential_file = wrong_key_path;
    assert_eq!(
        BrokerClient::new(wrong_key, issuer.uri(), audience.into())
            .unwrap()
            .verify_bearer(Some(&bearer))
            .unwrap_err(),
        AuthError::NotAdmitted
    );
    let mut foreign = broker_config;
    foreign.binding.broker_id = uuid::Uuid::new_v4();
    assert_eq!(
        BrokerClient::new(foreign, issuer.uri(), audience.into())
            .unwrap()
            .verify_bearer(Some(&bearer))
            .unwrap_err(),
        AuthError::NotAdmitted
    );
    for (field, value) in [
        ("tenant_id", json!("customer-b")),
        ("client_id", json!("foreign-client")),
        ("iss", json!("https://other.example")),
        ("exp", json!(now() - 1)),
    ] {
        let mut invalid = claims.clone();
        invalid[field] = value;
        if field == "exp" {
            invalid["iat"] = json!(now() - 30);
        }
        assert!(
            broker
                .verify_bearer(Some(&format!("Bearer {}", sign(&invalid))))
                .is_err()
        );
    }
    let mut short = claims.clone();
    short["jti"] = json!("short-lived-fixture");
    short["exp"] = json!(now() + 2);
    let short_access = broker
        .verify_bearer(Some(&format!("Bearer {}", sign(&short))))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2050)).await;
    assert_eq!(
        broker.check_access(&short_access),
        Err(AuthError::InvalidToken)
    );
    Mock::given(method("POST"))
        .and(path("/observation"))
        .respond_with(|request: &wiremock::Request| {
            assert_eq!(
                request.headers.get("authorization").unwrap(),
                "Bearer synthetic-provider-credential"
            );
            ResponseTemplate::new(200).set_body_json(json!({"observation":17.25}))
        })
        .mount(&source)
        .await;
    assert_eq!(
        guarded_read(&broker, &access, &source.uri()).await.unwrap()["observation"],
        17.25
    );
    let before = source.received_requests().await.unwrap().len();
    for sql in [
        "UPDATE principals SET disabled=1",
        "UPDATE principals SET roles='auditor'",
        "UPDATE principals SET email='fixture@removed.example'",
        "UPDATE principals SET sub='removed-subject'",
    ] {
        daemon.update(sql);
        assert!(broker.check_access(&access).is_err());
        assert!(guarded_read(&broker, &access, &source.uri()).await.is_err());
        assert_eq!(source.received_requests().await.unwrap().len(), before);
        daemon.update("UPDATE principals SET disabled=0,roles='operator',email='fixture@example.com',sub='fixture-user'");
    }
    source.reset().await;
    let database = root.join("state/identity.db");
    Mock::given(method("POST"))
        .and(path("/observation"))
        .respond_with(move |_: &wiremock::Request| {
            rusqlite::Connection::open(&database)
                .unwrap()
                .execute("UPDATE principals SET roles=''", [])
                .unwrap();
            ResponseTemplate::new(200).set_body_json(json!({"observation":918273.5}))
        })
        .mount(&source)
        .await;
    assert!(
        guarded_read(&broker, &access, &source.uri()).await.is_err(),
        "access loss during a read must withhold its result"
    );
    // Losing normal access must not prevent denial-only self-revocation.
    daemon.update("UPDATE principals SET roles='',disabled=1");
    broker.revoke_access(&access).unwrap();
    daemon.update("UPDATE principals SET roles='operator',disabled=0");
    assert_eq!(broker.check_access(&access), Err(AuthError::Revoked));
    assert_eq!(
        daemon
            .db()
            .query_row(
                "SELECT COUNT(*) FROM resource_revocations WHERE jti='active-fixture'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    let mut outage_claims = claims;
    outage_claims["jti"] = json!("outage-revocation-fixture");
    let outage_bearer = format!("Bearer {}", sign(&outage_claims));
    let outage_access = broker.verify_bearer(Some(&outage_bearer)).unwrap();
    daemon.child.kill().unwrap();
    daemon.child.wait().unwrap();
    assert_eq!(
        broker.revoke_access(&outage_access),
        Err(AuthError::Unavailable)
    );
    assert_eq!(broker.check_access(&access), Err(AuthError::Unavailable));
    daemon = Daemon::start(root).await;
    broker.revoke_bearer(Some(&outage_bearer)).unwrap();
    broker.revoke_access(&outage_access).unwrap();
    assert_eq!(
        daemon
            .db()
            .query_row(
                "SELECT COUNT(*) FROM resource_revocations WHERE jti='outage-revocation-fixture'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1,
        "both public revocation paths must share one durable denial"
    );
    assert_eq!(
        broker.verify_bearer(Some(&outage_bearer)).unwrap_err(),
        AuthError::Revoked
    );
    assert_eq!(
        broker.check_access(&access),
        Err(AuthError::Revoked),
        "restart must preserve revocation"
    );
    drop(daemon);
}
