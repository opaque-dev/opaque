#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Composable local dashboard. Trusted applications consume this library; the
//! default binary needs no organization service or private package.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio_util::sync::CancellationToken;

pub mod config;
pub mod daemon_client;
mod routes;
pub use routes::api_error as routes_error;
pub mod security;
mod sse;

#[derive(Parser)]
#[command(name = "opaque-web", about = "Opaque local dashboard")]
pub struct DashboardOptions {
    /// Port to listen on.
    #[arg(long, default_value = "7380")]
    pub port: u16,

    /// Open the dashboard in the default browser on startup.
    #[arg(long)]
    pub open: bool,

    /// Isolated data directory (config.toml, audit.db, web.token, run/opaqued.sock).
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// Read policy from this config file.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Connect to this daemon Unix socket.
    #[arg(long)]
    pub socket: Option<PathBuf>,
}

/// Shared application state available to all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub daemon: daemon_client::DaemonClient,
    pub config_path: PathBuf,
    pub audit_db_path: PathBuf,
    pub cancel: CancellationToken,
    pub auth_token: String,
}

/// Run a loopback dashboard with trusted application extensions.
pub async fn run_dashboard(
    args: DashboardOptions,
    extension: DashboardExtension,
) -> std::io::Result<()> {
    let cancel = CancellationToken::new();

    let paths = config::resolve_paths(args.data_dir, args.config, args.socket);
    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    // Bind before writing the token or opening a browser. A failed second launch
    // must not replace the running dashboard's token file.
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound_port = listener.local_addr()?.port();
    let auth_token = security::generate_token();
    let token_path = security::write_token_file(&paths.data_dir, &auth_token)?;
    tracing::info!("auth token written to {}", token_path.display());

    let state = AppState {
        daemon: daemon_client::DaemonClient::new(Some(paths.socket)),
        config_path: paths.config,
        audit_db_path: paths.audit_db,
        cancel: cancel.clone(),
        auth_token,
    };
    let app = application_with_extension(state, bound_port, extension);
    let url = format!("http://127.0.0.1:{bound_port}");
    tracing::info!("opaque-web listening on {url}");

    if args.open
        && let Err(e) = open_browser(&url)
    {
        tracing::warn!("failed to open browser: {e}");
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(cancel))
    .await
    .map_err(std::io::Error::other)
}

/// Build the real router, also exercised directly by integration tests.
pub fn application(state: AppState, port: u16) -> axum::Router {
    application_with_extension(state, port, DashboardExtension::default())
}

/// Compose trusted, compile-time UI code. Every extension route is authenticated,
/// including routes outside /api; only the built-in shell/brand assets are public.
/// Never interpolate runtime secrets or private data into shell fragments.
#[derive(Default)]
pub struct DashboardExtension {
    pub routes: axum::Router<AppState>,
    pub tabs: &'static str,
    pub panels: &'static str,
    pub style: &'static str,
    pub script: &'static str,
}

pub fn render_shell(extension: &DashboardExtension) -> String {
    include_str!("../static/index.html")
        .replace("<!-- opaque:extension-tabs -->", extension.tabs)
        .replace("<!-- opaque:extension-panels -->", extension.panels)
        .replace("/* opaque:extension-style */", extension.style)
        .replace("/* opaque:extension-script */", extension.script)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod extension_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn extension_routes_require_auth_even_outside_api_and_obey_origin() {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState {
            daemon: daemon_client::DaemonClient::new(Some(dir.path().join("missing.sock"))),
            config_path: dir.path().join("config.toml"),
            audit_db_path: dir.path().join("audit.db"),
            cancel: CancellationToken::new(),
            auth_token: "extension-fixture-owner".into(),
        };
        let extension = DashboardExtension {
            routes: axum::Router::new().route("/reports", get(|| async { "private report" })),
            ..Default::default()
        };
        let app = application_with_extension(state, 7380, extension);
        for (token, origin, expected) in [
            (None, None, StatusCode::UNAUTHORIZED),
            (Some("wrong"), None, StatusCode::UNAUTHORIZED),
            (
                Some("extension-fixture-owner"),
                Some("https://other.example"),
                StatusCode::FORBIDDEN,
            ),
            (Some("extension-fixture-owner"), None, StatusCode::OK),
        ] {
            let mut request = Request::builder()
                .uri("/reports")
                .header("host", "127.0.0.1:7380");
            if let Some(token) = token {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            if let Some(origin) = origin {
                request = request.header("origin", origin);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
    }

    #[test]
    fn default_shell_has_only_local_views_and_no_extension_implementation() {
        let html = render_shell(&DashboardExtension::default());
        assert!(!html.contains("/api/fleet"));
        assert!(!html.contains("loadFleet"));
        assert!(!html.contains("opaque:extension-"));
        assert_eq!(html.matches("class=\"tab-btn").count(), 5);
    }
}

pub fn application_with_extension(
    state: AppState,
    port: u16,
    extension: DashboardExtension,
) -> axum::Router {
    let auth = security::AuthToken(Arc::new(state.auth_token.clone()));
    let html = render_shell(&extension);
    let extra = extension.routes.layer(axum::middleware::from_fn_with_state(
        auth.clone(),
        security::require_token,
    ));
    routes::router()
        .merge(extra)
        .route(
            "/",
            axum::routing::get(move || {
                let html = html.clone();
                async move { axum::response::Html(html) }
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            auth,
            |axum::extract::State(auth): axum::extract::State<security::AuthToken>,
             request,
             next| async move { security::require_api_token(auth, request, next).await },
        ))
        .layer(axum::middleware::from_fn_with_state(
            security::LocalOrigin::new(port),
            security::validate_origin,
        ))
        .with_state(state)
}

async fn shutdown_signal(cancel: CancellationToken) {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received ctrl-c, shutting down");
        }
    }
    cancel.cancel();
}

fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod integration_tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use opaque_core::audit::{AuditEvent, AuditEventKind, AuditSink, SqliteAuditSink};
    use tower::ServiceExt;

    struct Fixture {
        dir: PathBuf,
        state: AppState,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = PathBuf::from("/tmp").join(format!("ow-{}", uuid::Uuid::new_v4()));
            let socket = dir.join("run/opaqued.sock");
            opaque_core::socket::ensure_socket_parent_dir(&socket).unwrap();
            Self {
                state: AppState {
                    daemon: daemon_client::DaemonClient::new(Some(socket)),
                    config_path: dir.join("config.toml"),
                    audit_db_path: dir.join("audit.db"),
                    cancel: CancellationToken::new(),
                    auth_token: "router-test-token".into(),
                },
                dir,
            }
        }
        fn app(&self) -> axum::Router {
            application(self.state.clone(), 9389)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.state.cancel.cancel();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    fn request(uri: &str) -> axum::http::request::Builder {
        Request::builder().uri(uri).header("host", "127.0.0.1:9389")
    }
    fn authenticated(uri: &str) -> Request<Body> {
        request(uri)
            .header("authorization", "Bearer router-test-token")
            .body(Body::empty())
            .unwrap()
    }
    async fn json_body(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn real_router_requires_bearer_for_every_read_api_including_stream() {
        let fixture = Fixture::new();
        for uri in [
            "/api/status",
            "/api/tasks",
            "/api/tasks/test",
            "/api/audit",
            "/api/audit/stream",
            "/api/policy",
            "/api/sessions",
            "/api/operations",
        ] {
            for (uri, bearer) in [
                (uri.to_string(), None),
                (uri.to_string(), Some("Bearer wrong-token")),
                (format!("{uri}?token=router-test-token"), None),
            ] {
                let mut req = request(&uri);
                if let Some(bearer) = bearer {
                    req = req.header("authorization", bearer);
                }
                let response = fixture
                    .app()
                    .oneshot(req.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
                assert_eq!(response.headers()["cache-control"], "no-store");
            }
        }
        let response = fixture
            .app()
            .oneshot(
                request("/api/status?token=router-test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn configured_port_origin_works_and_cross_origin_and_rebinding_fail() {
        let fixture = Fixture::new();
        for origin in ["http://localhost:9389", "http://127.0.0.1:9389"] {
            let req = request("/api/status")
                .header("origin", origin)
                .header("authorization", "Bearer router-test-token")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                fixture.app().oneshot(req).await.unwrap().status(),
                StatusCode::OK
            );
        }
        for origin in ["http://localhost:7380", "https://evil.example", "null"] {
            let req = request("/")
                .header("origin", origin)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                fixture.app().oneshot(req).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
        for host in ["evil.example:9389", "127.0.0.1:7380"] {
            let req = Request::builder()
                .uri("/")
                .header("host", host)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                fixture.app().oneshot(req).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
    }

    #[tokio::test]
    async fn spa_is_identical_and_credential_free_with_or_without_authentication() {
        let fixture = Fixture::new();
        let response = fixture
            .app()
            .oneshot(request("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        let body = String::from_utf8(
            to_bytes(response.into_body(), 1_000_000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!body.contains("router-test-token"));
        assert!(!body.contains("opaque-auth-token"));
        assert!(body.contains("id=\"unlock-token\""));
        assert!(body.contains("type=\"password\""));
        let authenticated_body = to_bytes(
            fixture
                .app()
                .oneshot(authenticated("/"))
                .await
                .unwrap()
                .into_body(),
            1_000_000,
        )
        .await
        .unwrap();
        assert_eq!(body.as_bytes(), authenticated_body.as_ref());
    }

    #[tokio::test]
    async fn owner_file_token_is_the_sole_credential_and_no_anonymous_get_reveals_it() {
        // SR-002, security-equivalent of the distinct-UID scenario. This host
        // cannot spawn a distinct OS UID, so the literal "a second Unix account
        // is refused" step is UNEXECUTED: environment cannot provide a distinct
        // UID. What is proved here is the invariant that makes that refusal hold:
        // the only working credential is the exact contents of the 0600 web.token
        // file, no unauthenticated GET (shell or brand asset) discloses those
        // bytes, and a token that is not the file's bytes is rejected. A separate
        // UID that cannot read the 0600 file therefore has no path to a credential.
        let dir = PathBuf::from("/tmp").join(format!("ow-token-file-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let token = security::generate_token();
        let token_path = security::write_token_file(&dir, &token).unwrap();
        // The credential the server accepts is whatever the private file holds.
        let file_token = std::fs::read_to_string(&token_path).unwrap();
        assert_eq!(file_token, token);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&token_path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "web.token must stay owner-only (0600)");
        }

        let socket = dir.join("run/opaqued.sock");
        opaque_core::socket::ensure_socket_parent_dir(&socket).unwrap();
        let state = AppState {
            daemon: daemon_client::DaemonClient::new(Some(socket)),
            config_path: dir.join("config.toml"),
            audit_db_path: dir.join("audit.db"),
            cancel: CancellationToken::new(),
            auth_token: file_token.clone(),
        };
        let app = || application(state.clone(), 9389);
        let bearer = format!("Bearer {file_token}");

        for (method, uri) in [
            ("GET", "/api/status"),
            ("GET", "/api/tasks"),
            ("GET", "/api/tasks/task-1"),
            ("POST", "/api/tasks/task-1/reconcile"),
            ("GET", "/api/audit"),
            ("GET", "/api/audit/stream"),
            ("GET", "/api/policy"),
            ("GET", "/api/sessions"),
            ("GET", "/api/operations"),
        ] {
            let anonymous = request(uri).method(method).body(Body::empty()).unwrap();
            assert_eq!(
                app().oneshot(anonymous).await.unwrap().status(),
                StatusCode::UNAUTHORIZED,
                "no credential must fail: {uri}"
            );
            let guessed = request(uri)
                .method(method)
                .header("authorization", "Bearer not-the-file-token")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                app().oneshot(guessed).await.unwrap().status(),
                StatusCode::UNAUTHORIZED,
                "a token that is not the file's bytes must fail: {uri}"
            );
            let owner = request(uri)
                .method(method)
                .header("authorization", &bearer)
                .body(Body::empty())
                .unwrap();
            let status = app().oneshot(owner).await.unwrap().status();
            assert_ne!(
                status,
                StatusCode::UNAUTHORIZED,
                "the exact file token must authorize: {uri}"
            );
            assert_ne!(
                status,
                StatusCode::FORBIDDEN,
                "the exact file token must pass origin checks: {uri}"
            );
        }

        // Nothing served without a credential discloses the credential.
        let contains = |haystack: &[u8], needle: &[u8]| {
            !needle.is_empty()
                && haystack
                    .windows(needle.len())
                    .any(|window| window == needle)
        };
        let shell = app()
            .oneshot(request("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(shell.status(), StatusCode::OK);
        let shell_body = to_bytes(shell.into_body(), 5_000_000).await.unwrap();
        assert!(
            !contains(&shell_body, file_token.as_bytes()),
            "the anonymous shell must not embed the owner token"
        );
        for asset in routes::brand::assets::ASSETS {
            let uri = format!("/brand/{}", asset.path);
            let response = app()
                .oneshot(request(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            let body = to_bytes(response.into_body(), 5_000_000).await.unwrap();
            assert!(
                !contains(&body, file_token.as_bytes()),
                "brand asset must not embed the owner token: {uri}"
            );
        }

        state.cancel.cancel();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn brand_assets_are_exact_public_bytes_under_existing_security_headers() {
        let fixture = Fixture::new();
        for asset in routes::brand::assets::ASSETS {
            let uri = format!("/brand/{}", asset.path);
            let response = fixture
                .app()
                .oneshot(request(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            assert_eq!(response.headers()["content-type"], asset.content_type);
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert_eq!(response.headers()["x-frame-options"], "DENY");
            let csp = response.headers()["content-security-policy"]
                .to_str()
                .unwrap();
            assert!(csp.contains("style-src 'self' 'unsafe-inline';"));
            assert!(csp.contains("font-src 'self';"));
            assert!(csp.contains("connect-src 'self';"));
            assert!(csp.starts_with("default-src 'none';"));
            assert!(!csp.contains("https:"));
            assert_eq!(
                to_bytes(response.into_body(), 1_000_000)
                    .await
                    .unwrap()
                    .as_ref(),
                asset.bytes
            );
        }
    }

    #[tokio::test]
    async fn brand_assets_do_not_expose_source_paths_or_bypass_origin_controls() {
        let fixture = Fixture::new();
        for uri in [
            "/brand/manifest.json",
            "/brand/embedded.rs",
            "/brand/README.md",
            "/brand/../config.toml",
            "/brand/%2e%2e/config.toml",
            "/brand/fonts/../../config.toml",
            "/brand/fonts/missing.ttf",
        ] {
            let response = fixture
                .app()
                .oneshot(request(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        for asset in ["opaque.css", "fonts/archivo-variable.ttf"] {
            let uri = format!("/brand/{asset}");
            for req in [
                request(&uri).header("origin", "https://evil.example"),
                Request::builder()
                    .uri(&uri)
                    .header("host", "evil.example:9389"),
            ] {
                let response = fixture
                    .app()
                    .oneshot(req.body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert!(
                    to_bytes(response.into_body(), 1_000)
                        .await
                        .unwrap()
                        .is_empty()
                );
            }
        }
        let response = fixture
            .app()
            .oneshot(request("/api/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_live_resources_never_fall_back_to_synthetic_data() {
        let fixture = Fixture::new();
        let status = json_body(
            fixture
                .app()
                .oneshot(authenticated("/api/status"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status["mode"], "disconnected");
        for uri in [
            "/api/audit",
            "/api/audit/stream",
            "/api/policy",
            "/api/sessions",
            "/api/tasks",
        ] {
            let response = fixture.app().oneshot(authenticated(uri)).await.unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
            let body = json_body(response).await;
            assert_eq!(body["mode"], "unavailable");
            assert!(body.get("events").is_none());
        }
    }

    #[tokio::test]
    async fn live_audit_and_resume_stream_report_real_persisted_events() {
        use futures_util::StreamExt;
        let fixture = Fixture::new();
        let sink = SqliteAuditSink::new(fixture.state.audit_db_path.clone(), 90).unwrap();
        sink.emit(AuditEvent::new(AuditEventKind::OperationSucceeded).with_operation("test.first"));
        sink.emit(
            AuditEvent::new(AuditEventKind::OperationSucceeded).with_operation("test.second"),
        );
        sink.flush(std::time::Duration::from_secs(2)).unwrap();
        let response = fixture
            .app()
            .oneshot(authenticated("/api/audit"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["mode"], "live");
        assert_eq!(body["events"].as_array().unwrap().len(), 2);
        let cursor = body["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["sequence_number"].as_i64().unwrap())
            .min()
            .unwrap();
        let req = request("/api/audit/stream")
            .header("authorization", "Bearer router-test-token")
            .header("last-event-id", cursor.to_string())
            .body(Body::empty())
            .unwrap();
        let response = fixture.app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let mut stream = response.into_body().into_data_stream();
        let bytes = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("event: audit"));
        assert!(text.contains("test.second"));
        assert!(!text.contains("test.first"));
        drop(sink);
    }

    async fn daemon_response(
        fixture: &Fixture,
        expected_method: &'static str,
        result: serde_json::Value,
    ) -> tokio::task::JoinHandle<()> {
        use std::os::unix::fs::PermissionsExt;
        let socket = fixture.state.daemon.socket_path();
        std::fs::write(
            socket.parent().unwrap().join("daemon.token"),
            "daemon-test-token",
        )
        .unwrap();
        let listener = tokio::net::UnixListener::bind(socket).unwrap();
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        tokio::spawn(async move {
            use futures_util::{SinkExt, StreamExt};
            let (socket, _) = listener.accept().await.unwrap();
            let mut framed = tokio_util::codec::Framed::new(
                socket,
                tokio_util::codec::LengthDelimitedCodec::new(),
            );
            let handshake: serde_json::Value =
                serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
            assert_eq!(handshake["daemon_token"], "daemon-test-token");
            let request: serde_json::Value =
                serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
            assert_eq!(request["method"], expected_method);
            if matches!(expected_method, "task_get" | "task_reconcile") {
                assert_eq!(request["params"]["task_id"], "task-123");
            }
            if result.get("next_cursor").and_then(|value| value.as_str()) == Some("page-2") {
                assert_eq!(request["params"]["cursor"], "page-1");
            }
            let response = opaque_core::proto::Response::ok(1, result);
            framed
                .send(bytes::Bytes::from(serde_json::to_vec(&response).unwrap()))
                .await
                .unwrap();
        })
    }

    #[tokio::test]
    async fn operation_inventory_never_substitutes_examples_for_a_disconnected_daemon() {
        let fixture = Fixture::new();
        let response = fixture
            .app()
            .oneshot(authenticated("/api/operations"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(response).await;
        assert!(body.get("operations").is_none());
        assert!(body["error"].as_str().unwrap().contains("disconnected"));
    }

    #[tokio::test]
    async fn live_operation_inventory_preserves_the_selected_daemons_capability_status() {
        let fixture = Fixture::new();
        let payload = serde_json::json!({"mode":"live", "operations":[
            {"name":"fixture.custom", "safety":"SensitiveOutput", "availability":"enabled",
             "mcp_exposed":false, "policy_status":"evaluated_per_request"},
            {"name":"aws.create_secret", "safety":"Safe", "availability":"disabled",
             "mcp_exposed":true, "policy_status":"evaluated_per_request"},
            {"name":"fixture.mock", "safety":"Safe", "availability":"fixture_only",
             "mcp_exposed":false, "policy_status":"evaluated_per_request"}
        ]});
        let server = daemon_response(&fixture, "operations", payload.clone()).await;
        let response = fixture
            .app()
            .oneshot(authenticated("/api/operations"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await, payload);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn malformed_daemon_inventory_fails_instead_of_returning_a_partial_catalog() {
        let fixture = Fixture::new();
        let server = daemon_response(
            &fixture,
            "operations",
            serde_json::json!({"operations":null}),
        )
        .await;
        let response = fixture
            .app()
            .oneshot(authenticated("/api/operations"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(json_body(response).await.get("operations").is_none());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sessions_unwrap_daemon_envelope_and_task_routes_preserve_scoped_receipts() {
        for (uri, method, result, key) in [
            (
                "/api/sessions",
                "agent_session_list",
                serde_json::json!({"count":1,"sessions":[{"session_id":"session-1"}]}),
                "sessions",
            ),
            (
                "/api/tasks",
                "task_list",
                serde_json::json!({"tasks":[{"id":"task-123"}]}),
                "tasks",
            ),
            (
                "/api/tasks/task-123",
                "task_get",
                serde_json::json!({"task":{"id":"task-123"}}),
                "task",
            ),
        ] {
            let fixture = Fixture::new();
            let server = daemon_response(&fixture, method, result.clone()).await;
            let response = fixture.app().oneshot(authenticated(uri)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            assert_eq!(body[key], result[key]);
            assert_eq!(body["mode"], "live");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn status_reports_the_actual_approval_backend_from_version_rpc() {
        let fixture = Fixture::new();
        let server = daemon_response(
            &fixture,
            "version",
            serde_json::json!({
                "version": "test-version", "approval_backend": "insecure_auto_approve",
                "task_grants_enabled": true, "trust_domain_enforced": false,
                "workstation_test_mode": true,
            }),
        )
        .await;
        let body = json_body(
            fixture
                .app()
                .oneshot(authenticated("/api/status"))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["mode"], "live");
        assert_eq!(body["daemon_version"], "test-version");
        assert_eq!(body["approval_backend"], "insecure_auto_approve");
        assert_eq!(body["task_grants_enabled"], true);
        assert_eq!(body["workstation_test_mode"], true);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn workflow_check_requires_auth_and_only_calls_read_only_reconciliation() {
        let fixture = Fixture::new();
        let uri = "/api/tasks/task-123/reconcile";
        for (request_uri, bearer) in [
            (uri.to_string(), None),
            (uri.to_string(), Some("Bearer wrong-token")),
            (format!("{uri}?token=router-test-token"), None),
        ] {
            let mut req = request(&request_uri).method("POST");
            if let Some(bearer) = bearer {
                req = req.header("authorization", bearer);
            }
            assert_eq!(
                fixture
                    .app()
                    .oneshot(req.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED,
            );
        }
        let cross_origin = request(uri)
            .method("POST")
            .header("authorization", "Bearer router-test-token")
            .header("origin", "https://untrusted.example")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            fixture.app().oneshot(cross_origin).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let result = serde_json::json!({"task": {
            "id": "task-123", "state": "completed", "approval_mode": "paired_workstation",
            "release_observation": {"state": "failed", "code": "workflow_failed", "run_id": 42}
        }});
        let server = daemon_response(&fixture, "task_reconcile", result.clone()).await;
        let req = request(uri)
            .method("POST")
            .header("authorization", "Bearer router-test-token")
            .body(Body::empty())
            .unwrap();
        let response = fixture.app().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["task"], result["task"]);
        server.await.unwrap();
        for uri in ["/api/tasks/task-123/run", "/api/tasks/task-123/approve"] {
            let req = request(uri)
                .method("POST")
                .header("authorization", "Bearer router-test-token")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                fixture.app().oneshot(req).await.unwrap().status(),
                StatusCode::NOT_FOUND
            );
        }
    }

    #[tokio::test]
    async fn task_pagination_preserves_the_daemon_cursor() {
        let fixture = Fixture::new();
        let result = serde_json::json!({"tasks": [], "has_more": true, "next_cursor": "page-2"});
        let server = daemon_response(&fixture, "task_list", result).await;
        let response = fixture
            .app()
            .oneshot(authenticated("/api/tasks?cursor=page-1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["has_more"], true);
        assert_eq!(body["next_cursor"], "page-2");
        server.await.unwrap();
    }

    #[test]
    fn isolated_paths_and_explicit_overrides_do_not_touch_default_home() {
        let dir = PathBuf::from("/tmp/opaque-dogfood");
        let paths = config::resolve_paths(Some(dir.clone()), None, None);
        assert_eq!(paths.config, dir.join("config.toml"));
        assert_eq!(paths.audit_db, dir.join("audit.db"));
        assert_eq!(paths.socket, dir.join("run/opaqued.sock"));
        let paths = config::resolve_paths(
            Some(dir),
            Some("/tmp/other.toml".into()),
            Some("/tmp/other.sock".into()),
        );
        assert_eq!(paths.config, PathBuf::from("/tmp/other.toml"));
        assert_eq!(paths.socket, PathBuf::from("/tmp/other.sock"));
    }
}
