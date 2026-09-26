#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use futures_util::future::{AbortHandle, Abortable, BoxFuture};
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt, StreamExt};

#[cfg(test)]
use opaque_mcp::protocol::JsonRpcRequest;
use opaque_mcp::protocol::{McpLines, parse_request};
use opaque_mcp::validation;
use serde::Serialize;
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio_util::codec::FramedRead;
use tracing::{debug, error, info};

mod daemon_client;
mod external;
mod tools;

use daemon_client::DaemonClient;

/// Build a version string that includes the git SHA: `0.1.0+abc1234`.
const fn version_string() -> &'static str {
    concat!(env!("CARGO_PKG_VERSION"), "+", env!("OPAQUE_GIT_SHA"))
}

// ---------------------------------------------------------------------------
// MCP JSON-RPC types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    fn ok(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn error(id: Option<serde_json::Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

// JSON-RPC error codes
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;
const INVALID_REQUEST: i64 = -32600;
const SERVER_BUSY: i64 = -32000;
const MAX_IN_FLIGHT: usize = 8;

fn tool_definitions() -> &'static [(tools::ToolDef, jsonschema::Validator)] {
    static DEFINITIONS: OnceLock<Vec<(tools::ToolDef, jsonschema::Validator)>> = OnceLock::new();
    DEFINITIONS.get_or_init(|| {
        tools::safe_tools()
            .into_iter()
            .map(|tool| {
                let validator = jsonschema::validator_for(&tool.input_schema)
                    .expect("built-in MCP input schema must compile");
                (tool, validator)
            })
            .collect()
    })
}

fn maybe_handle_cli_flag() -> bool {
    let mut args = std::env::args().skip(1);
    let Some(arg) = args.next() else {
        return false;
    };

    match arg.as_str() {
        "-V" | "--version" => {
            println!("opaque-mcp {}", version_string());
            true
        }
        "-h" | "--help" => {
            println!("opaque-mcp {}", version_string());
            println!("Usage: opaque-mcp [--version]");
            println!("Runs as an MCP server over stdio.");
            true
        }
        _ => {
            eprintln!("unknown argument: {arg}");
            eprintln!("Usage: opaque-mcp [--version]");
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// MCP protocol handling
// ---------------------------------------------------------------------------

/// Handle `initialize` — return server capabilities.
fn handle_initialize(id: Option<serde_json::Value>) -> JsonRpcResponse {
    JsonRpcResponse::ok(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "opaque-mcp",
                "version": version_string()
            }
        }),
    )
}

/// Handle `tools/list` — return the hard-coded Safe tool list.
fn handle_tools_list(id: Option<serde_json::Value>) -> JsonRpcResponse {
    let tool_defs = tool_definitions();
    let tools_json: Vec<serde_json::Value> = tool_defs
        .iter()
        .map(|(t, _)| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema
            })
        })
        .collect();

    JsonRpcResponse::ok(id, json!({ "tools": tools_json }))
}

/// Handle `tools/call` — execute a tool by forwarding to the daemon.
async fn handle_tools_call(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    client: &DaemonClient,
) -> JsonRpcResponse {
    let tool_name = match params.get("name").and_then(|v| v.as_str()) {
        Some(name) => name,
        None => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "missing 'name' in tools/call");
        }
    };

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    if !arguments.is_object() {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "tool arguments must be a JSON object");
    }
    if external::recognizes(tool_name) {
        return external::call(id, tool_name, arguments, client).await;
    }
    let Some((tool_def, validator)) = tool_definitions()
        .iter()
        .find(|(tool, _)| tool.name == tool_name)
    else {
        return JsonRpcResponse::error(id, INVALID_PARAMS, "unknown tool");
    };
    // The message names the failing field path and constraint from the
    // published schema so the caller can correct the call in one step. It
    // never quotes supplied values or caller-chosen property names.
    if let Some(message) =
        validation::describe_failures(&tool_def.input_schema, validator, &arguments)
    {
        return JsonRpcResponse::error(id, INVALID_PARAMS, message);
    }
    // Blocking lookups hold a separate bounded permit even if their caller is
    // cancelled, since aborting an async task cannot stop a blocking syscall.
    match tool_name {
        "opaque_sandbox_list_profiles" => {
            let response_id = id.clone();
            return blocking_lookup(move || handle_list_profiles(id))
                .await
                .unwrap_or_else(|message| {
                    JsonRpcResponse::error(response_id, SERVER_BUSY, message)
                });
        }
        "opaque_secrets_status" => {
            let response_id = id.clone();
            return blocking_lookup(move || handle_secrets_status(id, &arguments))
                .await
                .unwrap_or_else(|message| {
                    JsonRpcResponse::error(response_id, SERVER_BUSY, message)
                });
        }
        _ => {}
    }
    let Some(daemon_method) = tools::tool_to_daemon_method(tool_name) else {
        return JsonRpcResponse::error(id, INTERNAL_ERROR, "tool has no daemon method");
    };

    // Build daemon IPC params.
    let mut daemon_params = (tool_def.build_params)(&arguments);
    if daemon_method == "github" || daemon_method.starts_with("task_") {
        // Workspace claims come from this MCP server's actual process cwd,
        // never the model's tool arguments. The daemon verifies the claim
        // against this process before using repo-scoped policy.
        daemon_params["workspace"] = match blocking_lookup(|| {
            std::env::current_dir()
                .ok()
                .and_then(|cwd| collect_workspace_context(&cwd))
        })
        .await
        {
            Ok(workspace) => workspace.unwrap_or(serde_json::Value::Null),
            Err(message) => return JsonRpcResponse::error(id, SERVER_BUSY, message),
        };
    }

    debug!(
        tool = tool_name,
        daemon_method, "forwarding tool call to daemon"
    );

    // Call the daemon wrapper method with tool-specific params.
    match client.call(daemon_method, daemon_params).await {
        Ok(resp) => {
            if let Some(ref err) = resp.error {
                // Daemon returned an error — surface it as MCP tool error content.
                let error_text = format!("Opaque error [{}]: {}", err.code, err.message);
                JsonRpcResponse::ok(
                    id,
                    json!({
                        "content": [{"type": "text", "text": error_text}],
                        "isError": true
                    }),
                )
            } else if tool_name == "opaque_sandbox_exec" {
                // Sandbox exec returns structured output with stdout/stderr.
                format_sandbox_exec_response(id, resp.result)
            } else {
                // Daemon returned success.
                let incomplete_task = (tool_name == "opaque_task_run"
                    && resp
                        .result
                        .as_ref()
                        .and_then(|result| result.get("task"))
                        .and_then(|task| task.get("state"))
                        .and_then(|state| state.as_str())
                        != Some("completed"))
                    || (tool_name == "opaque_task_reconcile"
                        && matches!(
                            resp.result
                                .as_ref()
                                .and_then(|r| r.pointer("/task/release_observation/state"))
                                .and_then(|s| s.as_str()),
                            Some("failed" | "ambiguous")
                        ));
                let result_text = match resp.result {
                    Some(val) => {
                        if let Some(s) = val.as_str() {
                            s.to_string()
                        } else {
                            serde_json::to_string_pretty(&val).unwrap_or_else(|_| val.to_string())
                        }
                    }
                    None => {
                        return JsonRpcResponse::ok(
                            id,
                            json!({
                                "content": [{"type":"text", "text":"Broker response is missing a result; execution outcome is unknown."}],
                                "isError": true
                            }),
                        );
                    }
                };
                JsonRpcResponse::ok(
                    id,
                    json!({
                        "content": [{"type": "text", "text": result_text}],
                        "isError": incomplete_task
                    }),
                )
            }
        }
        Err(e) => {
            // Sanitize the error to prevent leaking filesystem paths or
            // credentials embedded in connection strings to the LLM context.
            let sanitizer = opaque_core::sanitize::Sanitizer::new();
            let error_text = format!(
                "Failed to communicate with opaqued: {}",
                sanitizer.scrub_error(&e.to_string())
            );
            JsonRpcResponse::ok(
                id,
                json!({
                    "content": [{"type": "text", "text": error_text}],
                    "isError": true
                }),
            )
        }
    }
}

async fn blocking_lookup<T: Send + 'static>(
    lookup: impl FnOnce() -> T + Send + 'static,
) -> Result<T, &'static str> {
    blocking_lookup_with_deadline(lookup, std::time::Duration::from_secs(30)).await
}

async fn blocking_lookup_with_deadline<T: Send + 'static>(
    lookup: impl FnOnce() -> T + Send + 'static,
    deadline: std::time::Duration,
) -> Result<T, &'static str> {
    static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let permit = SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| "local lookup capacity is occupied")?;
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        lookup()
    });
    // Stop waiting even if the filesystem or native lookup stalls. The worker
    // still owns its permit until it exits, so timeouts cannot grow the pool.
    tokio::time::timeout(deadline, worker)
        .await
        .map_err(|_| "local lookup timed out")?
        .map_err(|_| "local lookup failed")
}

fn collect_workspace_context(cwd: &std::path::Path) -> Option<serde_json::Value> {
    fn git(cwd: &std::path::Path, arguments: &[&str]) -> Option<String> {
        let output = std::process::Command::new("git")
            .current_dir(cwd)
            .args(arguments)
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_COMMON_DIR")
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
    let repo_root = git(cwd, &["rev-parse", "--show-toplevel"])?;
    let remote_url = git(cwd, &["remote", "get-url", "origin"])
        .map(|url| opaque_core::validate::InputValidator::sanitize_url(&url));
    let branch = git(cwd, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let head_sha = git(cwd, &["rev-parse", "HEAD"]);
    let dirty = git(cwd, &["status", "--porcelain"]).is_some_and(|status| !status.is_empty());
    Some(json!({
        "repo_root": repo_root, "remote_url": remote_url,
        "branch": branch, "head_sha": head_sha, "dirty": dirty,
    }))
}

/// Handle `opaque_sandbox_list_profiles` client-side by reading profile TOMLs.
fn handle_list_profiles(id: Option<serde_json::Value>) -> JsonRpcResponse {
    let profiles_dir = opaque_core::profile::profiles_dir();
    let profiles = tools::list_profiles(&profiles_dir);

    let result_text = serde_json::to_string_pretty(&profiles).unwrap_or_else(|_| "[]".to_string());

    JsonRpcResponse::ok(
        id,
        json!({
            "content": [{"type": "text", "text": result_text}]
        }),
    )
}

/// Handle `opaque_secrets_status` client-side by parsing profile secrets.
fn handle_secrets_status(
    id: Option<serde_json::Value>,
    arguments: &serde_json::Value,
) -> JsonRpcResponse {
    let profile_name = match arguments.get("profile").and_then(|v| v.as_str()) {
        Some(name) => name,
        None => {
            return JsonRpcResponse::ok(
                id,
                json!({
                    "content": [{"type": "text", "text": "missing required parameter: profile"}],
                    "isError": true
                }),
            );
        }
    };

    let profiles_dir = opaque_core::profile::profiles_dir();
    match tools::secrets_status(&profiles_dir, profile_name) {
        Ok(statuses) => {
            let result_text =
                serde_json::to_string_pretty(&statuses).unwrap_or_else(|_| "[]".to_string());
            JsonRpcResponse::ok(
                id,
                json!({
                    "content": [{"type": "text", "text": result_text}]
                }),
            )
        }
        Err(e) => JsonRpcResponse::ok(
            id,
            json!({
                "content": [{"type": "text", "text": e}],
                "isError": true
            }),
        ),
    }
}

/// Format a sandbox exec daemon response into MCP content items (metadata only).
fn format_sandbox_exec_response(
    id: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
) -> JsonRpcResponse {
    let Some(val) = result else {
        return JsonRpcResponse::ok(
            id,
            json!({
                "content": [{"type": "text", "text": "Broker response is missing the sandbox result; execution outcome is unknown."}],
                "isError": true
            }),
        );
    };

    let mut content = Vec::new();

    // Build metadata summary.
    let exit_code = val.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(-1);
    let duration_ms = val.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0);
    let truncated = val
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut meta = format!("exit_code: {exit_code}, duration: {duration_ms}ms");
    if truncated {
        meta.push_str(" (output truncated)");
    }
    content.push(json!({"type": "text", "text": meta}));

    // SECURITY (C2): never forward stdout/stderr *content* to the LLM. The daemon
    // returns only lengths, and even if a future change re-added content, this
    // boundary must not relay command output — it may contain secrets the command
    // printed. Only exit code and length metadata cross to the model.
    let stdout_len = val
        .get("stdout_length")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let stderr_len = val
        .get("stderr_length")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if stdout_len > 0 || stderr_len > 0 {
        content.push(json!({"type": "text", "text":
            format!("output withheld — stdout: {stdout_len} bytes, stderr: {stderr_len} bytes")}));
    }

    let is_error = exit_code != 0;
    let mut result_obj = json!({ "content": content });
    if is_error {
        result_obj["isError"] = json!(true);
    }

    JsonRpcResponse::ok(id, result_obj)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    if maybe_handle_cli_flag() {
        return;
    }

    // Tracing goes to stderr only — stdout is the MCP transport.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    info!("opaque-mcp {} starting", version_string());

    // Allow socket path override via env var or CLI arg.
    let socket_override = std::env::var("OPAQUE_SOCK").ok().map(PathBuf::from);
    let client = DaemonClient::new(socket_override);
    let _ = tool_definitions();

    if let Err(error) = run_transport(tokio::io::stdin(), tokio::io::stdout(), client).await {
        error!(%error, "MCP transport stopped");
    }

    info!("opaque-mcp shutting down");
}

/// Keep the reader and control messages independent of potentially slow tool
/// calls. Pending work is bounded; overload never creates an unbounded queue.
async fn run_transport(
    input: impl tokio::io::AsyncRead + Unpin,
    mut output: impl tokio::io::AsyncWrite + Unpin,
    client: DaemonClient,
) -> std::io::Result<()> {
    type Completion = (String, Option<JsonRpcResponse>);
    let mut lines = FramedRead::new(input, McpLines::new());
    let mut pending: FuturesUnordered<BoxFuture<'static, Completion>> = FuturesUnordered::new();
    let mut cancellations: HashMap<String, AbortHandle> = HashMap::new();
    let mut draining = false;
    loop {
        if draining && pending.is_empty() {
            break;
        }
        let response = tokio::select! {
            completed = pending.next(), if !pending.is_empty() => {
                let (key, response) = completed.expect("nonempty pending set");
                cancellations.remove(&key);
                response
            }
            line = lines.next(), if !draining => {
                let Some(line) = line else {
                    // EOF: accept nothing new, but deliver responses for calls
                    // already sent to the broker. Each call is bounded by its
                    // own deadline and the delivery timeout below, so the drain
                    // terminates; a batch client that writes requests and
                    // closes stdin still receives every answer.
                    draining = true;
                    continue;
                };
                match line {
                    Err(error) => return Err(error),
                    Ok(Err(message)) => Some(JsonRpcResponse::error(None, -32700, message)),
                    Ok(Ok(line)) => {
                        if line.trim().is_empty() { continue; }
                        match parse_request(line.as_bytes()) {
                            Err(error) => Some(JsonRpcResponse::error(None, error.code(), error.message())),
                            Ok(request) => {
                                match &request.id {
                                    None => {
                                    if request.method == "notifications/cancelled"
                                        && let Some(id) = request.params.get("requestId")
                                        && let Some(handle) = cancellations.get(&id.to_string())
                                    {
                                        // Stops waiting; already-dispatched work is not undone.
                                        handle.abort();
                                    }
                                    None
                                    }
                                    Some(id) => {
                                    let key = id.to_string();
                                    if cancellations.contains_key(&key) {
                                        Some(JsonRpcResponse::error(request.id, INVALID_REQUEST, "request ID is already in use"))
                                    } else {
                                        match request.method.as_str() {
                                            "initialize" => Some(handle_initialize(request.id)),
                                            "ping" => Some(JsonRpcResponse::ok(request.id, json!({}))),

                                            "tools/list" if pending.len() >= MAX_IN_FLIGHT => Some(handle_tools_list(request.id)),
                                            "tools/call" if pending.len() >= MAX_IN_FLIGHT => Some(JsonRpcResponse::error(request.id, SERVER_BUSY, "too many in-flight tool calls")),
                                            "tools/call" | "tools/list" => {
                                                let (handle, registration) = AbortHandle::new_pair();
                                                cancellations.insert(key.clone(), handle);
                                                let client = client.clone();
                                                pending.push(async move {
                                                    let result = Abortable::new(async {
                                                        if request.method == "tools/list" { external::list(request.id, &client).await }
                                                        else {handle_tools_call(request.id, &request.params, &client).await}
                                                    }, registration).await.ok();
                                                    (key, result)
                                                }.boxed());
                                                None
                                            }
                                            _ => Some(JsonRpcResponse::error(request.id, METHOD_NOT_FOUND, "method not found")),
                                        }
                                    }
                                }
                                }
                            }
                        }
                    }
                }
            }
            else => break,
        };
        if let Some(response) = response {
            let mut bytes = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
            bytes.push(b'\n');
            // A client that stops consuming cannot retain the server forever.
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                output.write_all(&bytes).await?;
                output.flush().await
            })
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "MCP response delivery timed out",
                )
            })??;
        }
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use serde_json::Value;

    fn scripted_broker(
        exchanges: Vec<(&'static str, serde_json::Value)>,
    ) -> (
        tempfile::TempDir,
        DaemonClient,
        tokio::task::JoinHandle<Vec<serde_json::Value>>,
    ) {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(directory.path().join("daemon.token"), "test-token").unwrap();
        let path = directory.path().join("daemon.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let task = tokio::spawn(async move {
            use futures_util::{SinkExt, StreamExt};
            let mut observed = Vec::new();
            for (method, reply) in exchanges {
                let (stream, _) =
                    tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut framed = tokio_util::codec::Framed::new(
                    stream,
                    tokio_util::codec::LengthDelimitedCodec::new(),
                );
                let handshake: serde_json::Value =
                    serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
                assert_eq!(handshake["handshake"], "v1");
                assert_eq!(handshake["daemon_token"], "test-token");
                let request: serde_json::Value =
                    serde_json::from_slice(&framed.next().await.unwrap().unwrap()).unwrap();
                assert_eq!(request["id"], 1);
                assert_eq!(request["method"], method);
                observed.push(request);
                framed
                    .send(serde_json::to_vec(&reply).unwrap().into())
                    .await
                    .unwrap();
                assert!(
                    tokio::time::timeout(std::time::Duration::from_secs(5), framed.next())
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            // The caller has completed every exchange; no background retry or
            // second effect request is permitted on this owned listener.
            assert!(listener.accept().now_or_never().is_none());
            observed
        });
        (directory, DaemonClient::new(Some(path)), task)
    }

    #[tokio::test]
    async fn external_catalog_bounds_and_names_never_expand_the_admitted_tool_set() {
        let invocation_tools = ["opaque_mcp_invocation_get", "opaque_mcp_invocation_revoke"];
        let enrolled = json!({"name":"opaque_mcp_tool_test","description":"test","inputSchema":{"type":"object"}});
        for (catalog, expected) in [
            (
                json!({"tools":vec![json!({"name":"opaque_mcp_tool_test"});129],"gateway":{"availability":"enabled"}}),
                vec![],
            ),
            (
                json!({"tools":[{"name":"untrusted"},{"name":4},enrolled],"gateway":{"availability":"enabled"}}),
                vec![
                    "opaque_mcp_tool_test",
                    "opaque_mcp_invocation_get",
                    "opaque_mcp_invocation_revoke",
                ],
            ),
            // A daemon through 0.5.0 answers without availability. It serves
            // no gateway, so no invocation tool is advertised.
            (json!({"tools":[]}), vec![]),
            (
                json!({"tools":[],"gateway":{"availability":"disabled"}}),
                vec![],
            ),
            (
                json!({"tools":[],"gateway":{"availability":"fixture_only"}}),
                invocation_tools.to_vec(),
            ),
            // Every route hidden by policy still leaves owned receipts readable.
            (
                json!({"tools":[],"gateway":{"availability":"enabled"}}),
                invocation_tools.to_vec(),
            ),
            (
                json!({"tools":[],"gateway":{"availability":"unrecognized"}}),
                vec![],
            ),
            (json!({"tools":[],"gateway":{"availability":true}}), vec![]),
            (
                json!({"tools":null,"gateway":{"availability":"enabled"}}),
                vec![],
            ),
        ] {
            let (directory, client, broker) =
                scripted_broker(vec![("mcp_catalog", json!({"id":1,"result":catalog}))]);
            let response = external::list(Some(json!(7)), &client).await;
            assert_eq!(response.id, Some(json!(7)));
            let tools = response.result.unwrap()["tools"]
                .as_array()
                .unwrap()
                .clone();
            let external_names: Vec<_> = tools
                .iter()
                .filter_map(|t| t["name"].as_str())
                .filter(|n| n.starts_with("opaque_mcp_"))
                .collect();
            assert_eq!(external_names, expected, "{catalog}");
            assert_eq!(tools.len(), 22 + expected.len(), "{catalog}");
            assert_eq!(broker.await.unwrap().len(), 1);
            drop(directory);
        }
    }

    #[tokio::test]
    async fn external_alias_and_schema_denials_send_only_read_only_discovery() {
        for (catalog, args, message) in [
            (json!({"tools":[]}), json!({}), "unknown tool"),
            (
                json!({"tools":[{"name":"opaque_mcp_tool_note","route":"different"}]}),
                json!({}),
                "unknown tool",
            ),
            (
                json!({"tools":[{"name":"opaque_mcp_tool_note","route":"note","inputSchema":{"type":"object","required":["id"],"additionalProperties":false,"properties":{"id":{"type":"integer"}}}}]}),
                json!({"id":"not an integer"}),
                "tool arguments do not match the input schema: \"/id\" must be of type integer",
            ),
            (
                json!({"tools":[{"name":"opaque_mcp_tool_note","route":"note","inputSchema":{"type":"object","required":["id"],"additionalProperties":false,"properties":{"id":{"type":"integer"}}}}]}),
                json!({"id":1,"private":"synthetic-private-argument"}),
                "tool arguments do not match the input schema: \"/\" has 1 unexpected field; allowed fields: id",
            ),
            (
                json!({"tools":[{"name":"opaque_mcp_tool_note","route":"note","inputSchema":{"type":"unsupported"}}]}),
                json!({}),
                "tool arguments do not match the input schema",
            ),
        ] {
            let (_directory, client, broker) =
                scripted_broker(vec![("mcp_catalog", json!({"id":1,"result":catalog}))]);
            let response = handle_tools_call(
                Some(json!(1)),
                &json!({"name":"opaque_mcp_tool_note","arguments":args}),
                &client,
            )
            .await;
            assert!(response.result.is_none());
            let error = response.error.unwrap();
            assert_eq!(error.code, INVALID_PARAMS);
            assert_eq!(error.message, message);
            assert_eq!(
                broker.await.unwrap(),
                vec![json!({"id":1,"method":"mcp_catalog","params":{}})]
            );
        }
    }

    #[tokio::test]
    async fn invocation_inspection_and_revocation_preserve_exact_reference_and_missing_result_uncertainty()
     {
        let id = "00000000-0000-4000-8000-000000000001";
        for (name, method) in [
            ("opaque_mcp_invocation_get", "mcp_get"),
            ("opaque_mcp_invocation_revoke", "mcp_revoke"),
        ] {
            for result in [
                json!({"receipt":{"state":"revoked","invocation_id":id}}),
                Value::Null,
            ] {
                // An absent result differs from a present JSON null. Exercise
                // the malformed missing-result envelope, which the production
                // decoder rejects before the adapter can report success.
                let reply = if result.is_null() {
                    json!({"id":1})
                } else {
                    json!({"id":1,"result":result})
                };
                let (_directory, client, broker) = scripted_broker(vec![(method, reply)]);
                let response = handle_tools_call(
                    Some(json!(1)),
                    &json!({"name":name,"arguments":{"invocation_id":id}}),
                    &client,
                )
                .await;
                let observed = broker.await.unwrap();
                assert_eq!(
                    observed,
                    vec![json!({"id":1,"method":method,"params":{"invocation_id":id}})]
                );
                let returned = response.result.unwrap();
                assert_eq!(returned["isError"], result.is_null());
                if result.is_null() {
                    assert!(
                        returned["content"][0]["text"]
                            .as_str()
                            .unwrap()
                            .contains("not retried")
                    );
                } else {
                    assert_eq!(
                        serde_json::from_str::<Value>(
                            returned["content"][0]["text"].as_str().unwrap()
                        )
                        .unwrap(),
                        result
                    );
                }
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let client = DaemonClient::new(Some(directory.path().join("absent")));
        for arguments in [
            json!({}),
            json!({"invocation_id":id,"route":"forged"}),
            json!({"invocation_id":1}),
            json!({"invocation_id":"short"}),
            json!([]),
        ] {
            let response = handle_tools_call(
                Some(json!(1)),
                &json!({"name":"opaque_mcp_invocation_get","arguments":arguments}),
                &client,
            )
            .await;
            assert_eq!(response.error.unwrap().code, INVALID_PARAMS);
            assert!(response.result.is_none());
        }
    }

    #[tokio::test]
    async fn task_state_and_provider_errors_are_not_reported_as_successful_tool_calls() {
        for (tool, method, args, result, expected_error) in [
            (
                "opaque_task_run",
                "task_run",
                json!({"task_id":"task-1"}),
                json!({"task":{"state":"completed"}}),
                false,
            ),
            (
                "opaque_task_run",
                "task_run",
                json!({"task_id":"task-1"}),
                json!({"task":{"state":"unknown"}}),
                true,
            ),
            (
                "opaque_task_reconcile",
                "task_reconcile",
                json!({"task_id":"task-1"}),
                json!({"task":{"release_observation":{"state":"failed"}}}),
                true,
            ),
            (
                "opaque_task_reconcile",
                "task_reconcile",
                json!({"task_id":"task-1"}),
                json!({"task":{"release_observation":{"state":"ambiguous"}}}),
                true,
            ),
            (
                "opaque_task_reconcile",
                "task_reconcile",
                json!({"task_id":"task-1"}),
                json!({"task":{"release_observation":{"state":"succeeded"}}}),
                false,
            ),
            (
                "opaque_task_get",
                "task_get",
                json!({"task_id":"task-1"}),
                json!("fixed broker result"),
                false,
            ),
        ] {
            let (_directory, client, broker) =
                scripted_broker(vec![(method, json!({"id":1,"result":result}))]);
            let response = handle_tools_call(
                Some(json!(9)),
                &json!({"name":tool,"arguments":args}),
                &client,
            )
            .await;
            assert!(response.error.is_none(), "{tool}: {:?}", response.error);
            let returned = response.result.unwrap();
            assert_eq!(
                returned
                    .get("isError")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                expected_error,
                "{tool}/{result}"
            );
            let text = returned["content"][0]["text"].as_str().unwrap();
            if let Some(expected) = result.as_str() {
                assert_eq!(text, expected);
            } else {
                assert_eq!(serde_json::from_str::<Value>(text).unwrap(), result);
            }
            let requests = broker.await.unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0]["params"]["task_id"], "task-1");
        }
        let (_directory, client, broker) = scripted_broker(vec![(
            "task_run",
            json!({"id":1,"error":{"code":"approval_denied","message":"review was rejected"}}),
        )]);
        let response = handle_tools_call(
            Some(json!(10)),
            &json!({"name":"opaque_task_run","arguments":{"task_id":"task-1"}}),
            &client,
        )
        .await;
        let result = response.result.unwrap();
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["content"][0]["text"],
            "Opaque error [approval_denied]: review was rejected"
        );
        assert_eq!(broker.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn framed_sandbox_response_withholds_output_and_preserves_failure_metadata() {
        let (_directory, client, broker) = scripted_broker(vec![(
            "sandbox.exec",
            json!({"id":1,"result":{"exit_code":1,"duration_ms":7,"stdout_length":21,"stderr_length":19,"truncated":false,"stdout":"synthetic-private-out","stderr":"synthetic-private-error"}}),
        )]);
        let response=handle_tools_call(Some(json!(11)), &json!({"name":"opaque_sandbox_exec","arguments":{"profile":"fixture","command":["fixture-command"]}}),&client).await;
        let result = response.result.unwrap();
        assert_eq!(result["isError"], true);
        assert!(
            result["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("exit_code: 1")
        );
        assert!(
            result["content"][1]["text"]
                .as_str()
                .unwrap()
                .contains("withheld")
        );
        assert!(!result.to_string().contains("synthetic-private"));
        assert_eq!(
            broker.await.unwrap(),
            vec![
                json!({"id":1,"method":"sandbox.exec","params":{"profile":"fixture","command":["fixture-command"]}})
            ]
        );
        let directory = tempfile::tempdir().unwrap();
        let client = DaemonClient::new(Some(directory.path().join("absent")));
        let rejected = handle_tools_call(
            Some(json!(12)),
            &json!({"name":"opaque_task_run","arguments":{"task_id":null}}),
            &client,
        )
        .await;
        assert!(rejected.result.is_none());
        assert_eq!(
            rejected.error.unwrap().message,
            "tool arguments do not match the input schema: \"/task_id\" must be of type string"
        );
    }

    #[tokio::test]
    async fn schema_rejections_name_the_field_and_constraint_without_quoting_values() {
        let directory = tempfile::tempdir().unwrap();
        let client = DaemonClient::new(Some(directory.path().join("absent")));
        let secret = "synthetic-private-value-91c2";
        for (tool, arguments, expected) in [
            (
                "opaque_secrets_status",
                json!({}),
                "missing required field \"/profile\"",
            ),
            (
                "opaque_secrets_status",
                json!({"profile":42}),
                "\"/profile\" must be of type string",
            ),
            (
                "opaque_task_list",
                json!({"cursor":secret,"approved":true}),
                "\"/\" has 1 unexpected field; allowed fields: cursor",
            ),
            (
                "opaque_task_plan_ssh",
                json!({"title":secret,"expires_in_secs":0}),
                "\"/expires_in_secs\" must be at least 1",
            ),
            (
                "opaque_task_plan",
                json!({"manifest":{"schema_version":1,"title":"t","expires_in_secs":60,"actions":[{"repo":"o/r","secret_name":"lower","value_ref":secret}]}}),
                "\"/manifest/actions/0/secret_name\" must match the pattern ^[A-Z_][A-Z0-9_]*$",
            ),
            (
                "opaque_github_set_org_secret",
                json!({"org":"o","secret_name":"S","value_ref":secret,"visibility":secret}),
                "\"/visibility\" must be one of \"all\", \"private\", \"selected\"",
            ),
        ] {
            let response = handle_tools_call(
                Some(json!(tool)),
                &json!({"name":tool,"arguments":arguments}),
                &client,
            )
            .await;
            assert!(response.result.is_none(), "{tool}");
            let error = response.error.unwrap();
            assert_eq!(error.code, INVALID_PARAMS);
            assert_eq!(
                error.message,
                format!("tool arguments do not match the input schema: {expected}"),
                "{tool}"
            );
            assert!(!error.message.contains(secret), "{tool}: {}", error.message);
            assert!(error.data.is_none());
        }
    }

    #[tokio::test]
    async fn unknown_tool_handler_never_echoes_untrusted_names() {
        let directory = tempfile::tempdir().unwrap();
        let client = DaemonClient::new(Some(directory.path().join("absent.sock")));
        let mut names = vec![
            String::new(),
            "private-tool-name".into(),
            "秘密".repeat(4096),
        ];
        names.extend((61..=65).map(|length| format!("{}é", "a".repeat(length))));
        for (index, name) in names.into_iter().enumerate() {
            let id = Some(json!(index));
            let response =
                handle_tools_call(id.clone(), &json!({"name":name,"arguments":{}}), &client).await;
            assert_eq!(response.id, id);
            assert!(response.result.is_none());
            let error = response.error.unwrap();
            assert_eq!(error.code, INVALID_PARAMS);
            assert_eq!(error.message, "unknown tool");
            assert!(error.data.is_none());
        }
        for params in [
            json!({}),
            json!({"name":null}),
            json!({"name":42}),
            json!({"name":[]}),
        ] {
            let response = handle_tools_call(Some(json!("missing")), &params, &client).await;
            assert_eq!(response.id, Some(json!("missing")));
            let error = response.error.unwrap();
            assert_eq!(error.code, INVALID_PARAMS);
            assert_eq!(error.message, "missing 'name' in tools/call");
        }
    }

    #[tokio::test]
    async fn stalled_local_lookup_has_a_terminal_response() {
        let (release, gate) = std::sync::mpsc::sync_channel(1);
        let result = blocking_lookup_with_deadline(
            move || gate.recv().unwrap(),
            std::time::Duration::from_millis(20),
        )
        .await;
        assert_eq!(result, Err("local lookup timed out"));
        // Release the actual worker; a timeout does not cancel its syscall.
        release.send(()).unwrap();
    }

    #[test]
    fn initialize_response_has_tools_capability() {
        let resp = handle_initialize(Some(json!(1)));
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "opaque-mcp");
    }

    #[test]
    fn tools_list_returns_only_safe_operations() {
        let resp = handle_tools_list(Some(json!(1)));
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 22);

        let tool_names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

        // Verify Safe operations are present.
        assert!(tool_names.contains(&"opaque_github_set_actions_secret"));
        assert!(tool_names.contains(&"opaque_github_list_secrets"));
        assert!(tool_names.contains(&"opaque_gitlab_set_ci_variable"));
        assert!(tool_names.contains(&"opaque_onepassword_list_vaults"));
        assert!(tool_names.contains(&"opaque_bitwarden_list_projects"));

        // Verify sandbox tools are present.
        assert!(tool_names.contains(&"opaque_sandbox_exec"));
        assert!(tool_names.contains(&"opaque_sandbox_list_profiles"));
        assert!(tool_names.contains(&"opaque_secrets_status"));
        assert!(tool_names.contains(&"opaque_task_plan"));
        assert!(tool_names.contains(&"opaque_task_plan_ssh"));
        assert!(tool_names.contains(&"opaque_task_run"));
        assert!(tool_names.contains(&"opaque_task_get"));
        assert!(tool_names.contains(&"opaque_task_list"));
        assert!(tool_names.contains(&"opaque_task_revoke"));

        // Verify no Reveal operations leak through.
        for name in &tool_names {
            assert!(!name.contains("read_field"), "Reveal tool leaked: {name}");
            assert!(!name.contains("read_secret"), "Reveal tool leaked: {name}");
            assert!(!name.contains("noop"), "test tool leaked: {name}");
        }
    }

    #[test]
    fn tools_list_schemas_are_valid() {
        let resp = handle_tools_list(Some(json!(1)));
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        for tool in tools {
            assert!(tool["name"].is_string());
            assert!(tool["description"].is_string());
            assert_eq!(tool["inputSchema"]["type"], "object");
        }
    }

    #[test]
    fn jsonrpc_response_ok_serialization() {
        let resp = JsonRpcResponse::ok(Some(json!(42)), json!({"status": "ok"}));
        let s = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["result"]["status"], "ok");
        assert!(parsed.get("error").is_none());
    }

    #[test]
    fn jsonrpc_response_error_serialization() {
        let resp = JsonRpcResponse::error(Some(json!(1)), METHOD_NOT_FOUND, "not found");
        let s = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["error"]["code"], -32601);
        assert_eq!(parsed["error"]["message"], "not found");
        assert!(parsed.get("result").is_none());
    }

    #[test]
    fn jsonrpc_request_parsing() {
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let req: JsonRpcRequest = serde_json::from_str(input).unwrap();
        assert_eq!(req.method, "tools/list");
        assert_eq!(req.id, Some(json!(1)));
    }

    #[test]
    fn jsonrpc_notification_parsing() {
        let input = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(input).unwrap();
        assert!(req.id.is_none());
        assert_eq!(req.method, "notifications/initialized");
    }

    #[test]
    fn initialize_response_id_propagated() {
        let resp = handle_initialize(Some(json!("abc-123")));
        assert_eq!(resp.id, Some(json!("abc-123")));
    }

    #[test]
    fn sandbox_exec_response_success() {
        let result = json!({
            "exit_code": 0,
            "duration_ms": 1234,
            "stdout_length": 10,
            "stderr_length": 0,
            "truncated": false,
            "stdout": "all passed",
            "stderr": ""
        });

        let resp = format_sandbox_exec_response(Some(json!(1)), Some(result));
        let r = resp.result.unwrap();
        let content = r["content"].as_array().unwrap();

        // First item is metadata.
        assert!(
            content[0]["text"]
                .as_str()
                .unwrap()
                .contains("exit_code: 0")
        );
        assert!(
            content[0]["text"]
                .as_str()
                .unwrap()
                .contains("duration: 1234ms")
        );

        // Second item is a length-only "withheld" note — never the content.
        assert!(content[1]["text"].as_str().unwrap().contains("withheld"));
        assert!(
            !content
                .iter()
                .any(|c| c["text"].as_str().unwrap_or("").contains("all passed")),
            "stdout content must never reach the LLM"
        );

        // isError should not be set for exit_code 0.
        assert!(r.get("isError").is_none());
    }

    #[test]
    fn sandbox_exec_response_failure() {
        let result = json!({
            "exit_code": 1,
            "duration_ms": 500,
            "stdout_length": 0,
            "stderr_length": 5,
            "truncated": false,
            "stdout": "",
            "stderr": "error"
        });

        let resp = format_sandbox_exec_response(Some(json!(1)), Some(result));
        let r = resp.result.unwrap();

        // isError should be set for non-zero exit_code.
        assert_eq!(r["isError"], true);

        let content = r["content"].as_array().unwrap();
        // Metadata + a length-only "withheld" note; never the stderr content.
        assert_eq!(content.len(), 2);
        assert!(content[1]["text"].as_str().unwrap().contains("withheld"));
        assert!(
            !content
                .iter()
                .any(|c| c["text"].as_str().unwrap_or("").contains("error")),
            "stderr content must never reach the LLM"
        );
    }

    #[test]
    fn sandbox_exec_response_truncated() {
        let result = json!({
            "exit_code": 0,
            "duration_ms": 100,
            "truncated": true,
            "stdout": "partial",
            "stderr": ""
        });

        let resp = format_sandbox_exec_response(Some(json!(1)), Some(result));
        let r = resp.result.unwrap();
        let content = r["content"].as_array().unwrap();
        assert!(content[0]["text"].as_str().unwrap().contains("truncated"));
    }

    #[test]
    fn sandbox_exec_response_no_result() {
        let resp = format_sandbox_exec_response(Some(json!(1)), None);
        let r = resp.result.unwrap();
        let content = r["content"].as_array().unwrap();
        assert!(content[0]["text"].as_str().unwrap().contains("missing"));
        assert_eq!(r["isError"], true);
    }

    #[test]
    fn handle_list_profiles_returns_json() {
        // This reads from the real ~/.opaque/profiles/ which may not exist.
        // The function should gracefully return an empty list.
        let resp = handle_list_profiles(Some(json!(1)));
        let r = resp.result.unwrap();
        let content = r["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "text");
        // Should be valid JSON (either [] or a list of profiles).
        let text = content[0]["text"].as_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn handle_secrets_status_missing_profile_param() {
        let resp = handle_secrets_status(Some(json!(1)), &json!({}));
        let r = resp.result.unwrap();
        assert_eq!(r["isError"], true);
        let text = r["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("missing required parameter"));
    }

    #[test]
    fn workspace_context_uses_actual_git_checkout_and_scrubs_remote_credentials() {
        let directory = tempfile::tempdir().unwrap();
        assert!(collect_workspace_context(directory.path()).is_none());
        assert!(
            std::process::Command::new("git")
                .args(["init", "--quiet"])
                .current_dir(directory.path())
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("git")
                .args([
                    "remote",
                    "add",
                    "origin",
                    "https://credential@github.com/owner/repo.git"
                ])
                .current_dir(directory.path())
                .status()
                .unwrap()
                .success()
        );
        let workspace = collect_workspace_context(directory.path()).unwrap();
        assert_eq!(
            std::path::PathBuf::from(workspace["repo_root"].as_str().unwrap())
                .canonicalize()
                .unwrap(),
            directory.path().canonicalize().unwrap()
        );
        assert_eq!(workspace["remote_url"], "https://github.com/owner/repo.git");
        assert!(workspace.get("workspace_verified").is_none());
    }
}
