//! Exercise the actual stdio executable and framed Unix-daemon boundary.
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;
use std::time::Duration;

use futures_util::{FutureExt, SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::UnixListener;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

struct Server {
    child: Child,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
}
impl Server {
    fn start(directory: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_opaque-mcp"))
            .env("OPAQUE_SOCK", directory.join("daemon.sock"))
            .env_remove("OPAQUE_SESSION_TOKEN")
            .current_dir(directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap()).lines();
        Self {
            child,
            input,
            output,
        }
    }
    async fn send(&mut self, request: Value) {
        self.input
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        self.input.flush().await.unwrap();
    }
    async fn receive(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(5), self.output.next_line())
            .await
            .expect("stdio response deadline")
            .unwrap()
            .expect("server remains alive");
        serde_json::from_str(&line).unwrap()
    }
    async fn stop(mut self) {
        self.input.shutdown().await.unwrap();
        drop(self.input);
        assert!(
            tokio::time::timeout(Duration::from_secs(5), self.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
}
fn daemon_fixture() -> (tempfile::TempDir, UnixListener) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(directory.path().join("daemon.token"), "test-token").unwrap();
    let path = directory.path().join("daemon.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (directory, listener)
}

#[tokio::test]
async fn duplicate_ids_and_unmatched_cancellation_do_not_repeat_or_drop_dispatched_work() {
    let (directory, listener) = daemon_fixture();
    let mut server = Server::start(directory.path());
    server
        .send(json!({"jsonrpc":"2.0","id":71,"method":"tools/list","params":{}}))
        .await;
    let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
    let handshake: Value = serde_json::from_slice(
        &tokio::time::timeout(Duration::from_secs(5), framed.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        handshake,
        json!({"handshake":"v1","daemon_token":"test-token"})
    );
    let request: Value = serde_json::from_slice(
        &tokio::time::timeout(Duration::from_secs(5), framed.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(request, json!({"id":1,"method":"mcp_catalog","params":{}}));
    // The broker has observed the first call but has not answered. These
    // controls must neither abort that call nor create a second dispatch.
    server.input.write_all(b"\n \t\r\n").await.unwrap();
    server
        .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}))
        .await;
    server.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"unknown"}})).await;
    server
        .send(json!({"jsonrpc":"2.0","id":71,"method":"tools/list","params":{}}))
        .await;
    server
        .send(json!({"jsonrpc":"2.0","id":72,"method":"ping","params":{}}))
        .await;
    let duplicate = server.receive().await;
    assert_eq!(duplicate["id"], 71);
    assert_eq!(duplicate["error"]["code"], -32600);
    assert_eq!(
        duplicate["error"]["message"],
        "request ID is already in use"
    );
    let ping = server.receive().await;
    assert_eq!(ping["id"], 72);
    assert_eq!(ping["result"], json!({}));
    framed
        .send(
            serde_json::to_vec(&json!({"id":1,"result":{"tools":[]}}))
                .unwrap()
                .into(),
        )
        .await
        .unwrap();
    let completed = server.receive().await;
    assert_eq!(completed["id"], 71);
    assert!(completed.get("error").is_none());
    assert!(
        completed["result"]["tools"]
            .as_array()
            .is_some_and(|tools| !tools.is_empty())
    );
    server.stop().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), framed.next())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        listener.accept().now_or_never().is_none(),
        "only one broker connection is permitted"
    );
}

#[tokio::test]
async fn delayed_authenticated_catalog_remains_discoverable_without_blocking_ping_or_retrying() {
    let (directory, listener) = daemon_fixture();
    let mut server = Server::start(directory.path());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        let handshake: Value =
            serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(
            handshake,
            json!({"handshake":"v1","daemon_token":"test-token"})
        );
        let request: Value =
            serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(request, json!({"id":1,"method":"mcp_catalog","params":{}}));
        ready_tx.send(()).unwrap();
        // Hold the authenticated catalog until after the control response,
        // then exceed the former two-second discovery cutoff deliberately.
        release_rx.await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        framed
            .send(
                serde_json::to_vec(&json!({"id":1,"result":{"tools":[{
                    "name":"opaque_mcp_tool_fixture_note",
                    "description":"Enrolled fixture tool",
                    "inputSchema":{"type":"object","additionalProperties":false}
                }]}}))
                .unwrap()
                .into(),
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), framed.next())
                .await
                .unwrap()
                .is_none()
        );
        // Discovery sends one read-only request and never retries it or work.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    server
        .send(json!({"jsonrpc":"2.0","id":"slow-list","method":"tools/list"}))
        .await;
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    server
        .send(json!({"jsonrpc":"2.0","id":"responsive-ping","method":"ping"}))
        .await;
    assert_eq!(
        server.receive().await,
        json!({"jsonrpc":"2.0","id":"responsive-ping","result":{}})
    );
    release_tx.send(()).unwrap();
    let listed = server.receive().await;
    assert_eq!(listed["id"], "slow-list");
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "opaque_task_list"));
    assert_eq!(
        tools
            .iter()
            .filter(|tool| tool["name"] == "opaque_mcp_tool_fixture_note")
            .collect::<Vec<_>>(),
        vec![&json!({
            "name":"opaque_mcp_tool_fixture_note",
            "description":"Enrolled fixture tool",
            "inputSchema":{"type":"object","additionalProperties":false}
        })]
    );
    tokio::time::timeout(Duration::from_secs(5), daemon)
        .await
        .unwrap()
        .unwrap();
    server.stop().await;
}

#[tokio::test]
async fn authenticated_catalog_error_keeps_static_tools_without_retry_or_error_disclosure() {
    let (directory, listener) = daemon_fixture();
    let mut server = Server::start(directory.path());
    let daemon = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        let handshake: Value =
            serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(
            handshake,
            json!({"handshake":"v1","daemon_token":"test-token"})
        );
        let request: Value =
            serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(request, json!({"id":1,"method":"mcp_catalog","params":{}}));
        framed
            .send(
                serde_json::to_vec(&json!({"id":1,"error":{
                    "code":"catalog_unavailable","message":"synthetic-private-catalog-detail"
                }}))
                .unwrap()
                .into(),
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    server
        .send(json!({"jsonrpc":"2.0","id":"unavailable-list","method":"tools/list"}))
        .await;
    let listed = server.receive().await;
    assert_eq!(listed["id"], "unavailable-list");
    assert!(listed.get("error").is_none());
    assert!(
        !listed
            .to_string()
            .contains("synthetic-private-catalog-detail")
    );
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert!(tools.iter().any(|tool| tool["name"] == "opaque_task_list"));
    assert!(
        tools
            .iter()
            .all(|tool| !tool["name"].as_str().unwrap().starts_with("opaque_mcp_"))
    );
    tokio::time::timeout(Duration::from_secs(5), daemon)
        .await
        .unwrap()
        .unwrap();
    server.stop().await;
}

#[tokio::test]
async fn offline_gateway_contract_does_not_enable_runtime_proxying() {
    let (directory, listener) = daemon_fixture();
    let mut server = Server::start(directory.path());
    // The signed runtime asks its authenticated daemon for an enrolled catalog.
    // An offline contract file alone supplies no enrolled tool authority.
    let catalog = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        framed.next().await.unwrap().unwrap();
        let request: Value =
            serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
        assert_eq!(request["method"], "mcp_catalog");
        framed
            .send(
                serde_json::to_vec(&json!({"id":1,"result":{"tools":[]}}))
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();
        listener
    });
    server
        .send(json!({"jsonrpc":"2.0","id":"list","method":"tools/list"}))
        .await;
    let listed = server.receive().await;
    let listener = catalog.await.unwrap();
    let tools = listed["result"]["tools"].as_array().unwrap();
    for name in ["staging.status", "opaque_mcp_call", "opaque_gateway_call"] {
        assert!(tools.iter().all(|tool| tool["name"] != name));
        server
            .send(
                json!({"jsonrpc":"2.0","id":name,"method":"tools/call","params":{
                    "name":name,"arguments":{"route":"staging.status","arguments":{}}
                }}),
            )
            .await;
        let response = server.receive().await;
        assert_eq!(response["id"], name);
        assert_eq!(response["error"]["code"], -32602);
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    server
        .send(json!({"jsonrpc":"2.0","id":"alive","method":"ping"}))
        .await;
    assert_eq!(server.receive().await["result"], json!({}));
    server.stop().await;
}

#[tokio::test]
async fn malformed_tool_calls_return_errors_and_the_real_process_keeps_serving() {
    let directory = tempfile::tempdir().unwrap();
    let mut server = Server::start(directory.path());
    server
        .send(json!({"jsonrpc":"2.0","id":"init","method":"initialize"}))
        .await;
    assert_eq!(
        server.receive().await["result"]["serverInfo"]["name"],
        "opaque-mcp"
    );
    let arguments = [
        json!([]),
        json!(null),
        json!(false),
        json!(42),
        json!("text"),
        json!({}),
        json!({"repo": 42, "secret_name":"key", "value_ref":"env:VALUE"}),
    ];
    for (index, arguments) in arguments.into_iter().enumerate() {
        server
            .send(
                json!({"jsonrpc":"2.0","id":index,"method":"tools/call","params":{
            "name":"opaque_github_set_actions_secret", "arguments":arguments}}),
            )
            .await;
        assert_eq!(server.receive().await["error"]["code"], -32602);
    }
    let mut names = vec![
        String::new(),
        "private-tool-name".into(),
        "秘密".repeat(4096),
    ];
    names.extend((61..=65).map(|length| format!("{}é", "a".repeat(length))));
    for (index, name) in names.into_iter().enumerate() {
        let id = format!("unknown-{index}");
        server
            .send(
                json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                    "name":name,"arguments":{}
                }}),
            )
            .await;
        assert_eq!(
            server.receive().await,
            json!({"jsonrpc":"2.0","id":id,
            "error":{"code":-32602,"message":"unknown tool"}})
        );
    }
    server
        .send(
            json!({"jsonrpc":"2.0","id":"extra","method":"tools/call","params":{
        "name":"opaque_task_list", "arguments":{"unexpected":"authority"}}}),
        )
        .await;
    assert_eq!(server.receive().await["error"]["code"], -32602);
    server
        .send(json!({"jsonrpc":"2.0","id":"alive","method":"ping"}))
        .await;
    assert_eq!(
        server.receive().await,
        json!({"jsonrpc":"2.0","id":"alive","result":{}})
    );
    server
        .send(json!({"jsonrpc":"2.0","id":"list-after-errors","method":"tools/list"}))
        .await;
    let listed = server.receive().await;
    assert_eq!(listed["id"], "list-after-errors");
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 22);
    server.stop().await;
}

#[tokio::test]
async fn full_tool_capacity_keeps_control_responsive_and_cancellation_closes_ipc() {
    let (directory, listener) = daemon_fixture();
    let mut server = Server::start(directory.path());
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(async move {
        let mut connections = Vec::new();
        for _ in 0..8 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
            assert!(framed.next().await.unwrap().is_ok()); // handshake
            let request: Value =
                serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
            assert_eq!(request["method"], "onepassword");
            connections.push(framed);
        }
        ready_tx.send(()).unwrap();
        for mut connection in connections {
            assert!(
                tokio::time::timeout(Duration::from_secs(5), connection.next())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        closed_tx.send(()).unwrap();
        // Cancellation released capacity; a fresh request reaches the daemon.
        let (stream, _) = listener.accept().await.unwrap();
        let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
        framed.next().await.unwrap().unwrap();
        framed.next().await.unwrap().unwrap();
        framed
            .send(
                serde_json::to_vec(&json!({"id":1,"result":{"fresh":true}}))
                    .unwrap()
                    .into(),
            )
            .await
            .unwrap();
    });
    for id in 0..8 {
        server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"opaque_onepassword_list_vaults","arguments":{}}})).await;
    }
    tokio::time::timeout(Duration::from_secs(5), ready_rx)
        .await
        .unwrap()
        .unwrap();
    server.send(json!({"jsonrpc":"2.0","id":"busy","method":"tools/call","params":{"name":"opaque_onepassword_list_vaults"}})).await;
    assert_eq!(server.receive().await["error"]["code"], -32000);
    server
        .send(json!({"jsonrpc":"2.0","id":"ping","method":"ping"}))
        .await;
    assert_eq!(server.receive().await["id"], "ping");
    server
        .send(json!({"jsonrpc":"2.0","id":"list","method":"tools/list"}))
        .await;
    assert!(server.receive().await["result"]["tools"].is_array());
    for id in 0..8 {
        server.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id}})).await;
    }
    tokio::time::timeout(Duration::from_secs(5), closed_rx)
        .await
        .unwrap()
        .unwrap();
    server.send(json!({"jsonrpc":"2.0","id":"fresh","method":"tools/call","params":{"name":"opaque_onepassword_list_vaults"}})).await;
    let response = server.receive().await;
    assert_eq!(response["id"], "fresh");
    assert_eq!(response["result"]["isError"], false);
    tokio::time::timeout(Duration::from_secs(5), daemon)
        .await
        .unwrap()
        .unwrap();
    server.stop().await;
}

#[tokio::test]
async fn oversized_stdio_frame_is_rejected_without_killing_the_server() {
    let directory = tempfile::tempdir().unwrap();
    let mut server = Server::start(directory.path());
    server
        .input
        .write_all(("x".repeat(opaque_core::MAX_FRAME_LENGTH + 1) + "\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(server.receive().await["error"]["code"], -32700);
    server
        .send(json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .await;
    assert_eq!(server.receive().await["id"], 1);
    server.stop().await;
}

#[tokio::test]
async fn malformed_daemon_envelopes_never_fabricate_tool_success() {
    let (directory, listener) = daemon_fixture();
    let mut server = Server::start(directory.path());
    let daemon = tokio::spawn(async move {
        for envelope in [
            json!({"id":1}),
            json!({"id":2,"result":{"ok":true}}),
            json!({"id":1,"result":{},"error":{"code":"bad","message":"bad"}}),
            json!({"id":1,"error":null}),
            json!({"id":1,"result":null}),
        ] {
            let (stream, _) = listener.accept().await.unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
            framed.next().await.unwrap().unwrap();
            framed.next().await.unwrap().unwrap();
            framed
                .send(serde_json::to_vec(&envelope).unwrap().into())
                .await
                .unwrap();
        }
    });
    for id in 0..5 {
        server.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"opaque_onepassword_list_vaults"}})).await;
        let response = server.receive().await;
        assert_eq!(response["id"], id);
        assert_eq!(response["result"]["isError"], id < 4);
        if id < 4 {
            assert!(
                response["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("outcome unknown")
            );
        } else {
            assert_eq!(response["result"]["content"][0]["text"], "null");
        }
    }
    daemon.await.unwrap();
    server.stop().await;
}

#[tokio::test]
async fn batch_client_closing_stdin_still_receives_every_response() {
    // dogfood-style batch transport: write every request, close stdin, then
    // read. EOF must switch the server to draining, not drop in-flight calls.
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut server = Server::start(directory.path());
    server
        .send(
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "batch-check", "version": "1"}}}),
        )
        .await;
    server
        .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    server
        .send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}))
        .await;
    // The daemon socket does not exist, so the call resolves as an error
    // result. It must still be answered after EOF.
    server
        .send(
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "opaque_task_list", "arguments": {}}}),
        )
        .await;
    server.input.shutdown().await.unwrap();
    let mut answered = std::collections::BTreeSet::new();
    while answered.len() < 3 {
        let response = server.receive().await;
        answered.insert(response["id"].as_i64().expect("response carries an ID"));
    }
    assert_eq!(answered.into_iter().collect::<Vec<_>>(), vec![1, 2, 3]);
    drop(server.input);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), server.child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

/// Answer one authenticated `mcp_catalog` exchange per reply, in order, then
/// refuse any further connection: discovery never retries.
fn scripted_catalog_daemon(
    listener: UnixListener,
    replies: Vec<Value>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for reply in replies {
            let (stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
            let handshake: Value =
                serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
            assert_eq!(
                handshake,
                json!({"handshake":"v1","daemon_token":"test-token"})
            );
            let request: Value =
                serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
            assert_eq!(request, json!({"id":1,"method":"mcp_catalog","params":{}}));
            framed
                .send(
                    serde_json::to_vec(&json!({"id":1,"result":reply}))
                        .unwrap()
                        .into(),
                )
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(5), framed.next())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    })
}

fn tool_names(listed: &Value) -> Vec<&str> {
    listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect()
}

const INVOCATION_TOOLS: [&str; 2] = ["opaque_mcp_invocation_get", "opaque_mcp_invocation_revoke"];

#[tokio::test]
async fn tools_list_never_advertises_invocation_tools_the_daemon_does_not_serve() {
    let (directory, listener) = daemon_fixture();
    let mut server = Server::start(directory.path());
    // A daemon through 0.5.0 answers without availability; a current daemon
    // without an `[mcp]` section says `disabled`; an unrecognized value is
    // treated as not served.
    let daemon = scripted_catalog_daemon(
        listener,
        vec![
            json!({"tools":[]}),
            json!({"tools":[],"gateway":{"availability":"disabled"}}),
            json!({"tools":[],"gateway":{"availability":"unrecognized"}}),
        ],
    );
    for id in [
        "legacy-daemon",
        "disabled-gateway",
        "unrecognized-availability",
    ] {
        server
            .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/list","params":{}}))
            .await;
        let listed = server.receive().await;
        assert_eq!(listed["id"], id);
        assert!(listed.get("error").is_none());
        let names = tool_names(&listed);
        assert_eq!(names.len(), 22, "{id}: {names:?}");
        assert!(names.contains(&"opaque_secrets_status"));
        assert!(
            names.iter().all(|name| !name.starts_with("opaque_mcp_")),
            "{id}: {names:?}"
        );
        for tool in INVOCATION_TOOLS {
            assert!(!names.contains(&tool), "{id} advertised {tool}");
        }
    }
    tokio::time::timeout(Duration::from_secs(5), daemon)
        .await
        .unwrap()
        .unwrap();
    server.stop().await;
}

#[tokio::test]
async fn tools_list_advertises_invocation_tools_only_when_the_daemon_serves_its_gateway() {
    let (directory, listener) = daemon_fixture();
    let mut server = Server::start(directory.path());
    let enrolled = json!({
        "name":"opaque_mcp_tool_fixture_note",
        "description":"Enrolled fixture tool",
        "inputSchema":{"type":"object","additionalProperties":false}
    });
    let daemon = scripted_catalog_daemon(
        listener,
        vec![
            // Policy may hide every route while owned receipts stay readable.
            json!({"tools":[],"gateway":{"availability":"fixture_only"}}),
            json!({"tools":[enrolled],"gateway":{"availability":"enabled"}}),
        ],
    );
    let mut invocation_definitions = Vec::new();
    for (id, expected) in [
        ("fixture-gateway", 22 + INVOCATION_TOOLS.len()),
        ("enabled-gateway", 23 + INVOCATION_TOOLS.len()),
    ] {
        server
            .send(json!({"jsonrpc":"2.0","id":id,"method":"tools/list","params":{}}))
            .await;
        let listed = server.receive().await;
        assert_eq!(listed["id"], id);
        let names = tool_names(&listed);
        assert_eq!(names.len(), expected, "{id}: {names:?}");
        for tool in INVOCATION_TOOLS {
            assert!(names.contains(&tool), "{id} omitted {tool}");
        }
        assert_eq!(
            names.contains(&"opaque_mcp_tool_fixture_note"),
            id == "enabled-gateway"
        );
        let definitions: Vec<Value> = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|tool| INVOCATION_TOOLS.contains(&tool["name"].as_str().unwrap()))
            .cloned()
            .collect();
        for definition in &definitions {
            assert_eq!(
                definition["inputSchema"],
                json!({"type":"object","additionalProperties":false,"required":["invocation_id"],"properties":{"invocation_id":{"type":"string","minLength":36,"maxLength":36}}})
            );
        }
        invocation_definitions.push(definitions);
    }
    // The adapter owns the invocation tool contract; the daemon only says
    // whether it is served.
    assert_eq!(invocation_definitions[0], invocation_definitions[1]);
    tokio::time::timeout(Duration::from_secs(5), daemon)
        .await
        .unwrap()
        .unwrap();
    server.stop().await;
}
