//! Discovery and dispatch stay in the authenticated daemon. The adapter has no
//! upstream destination, credential, discovery or approval authority of its own.
use super::*;
const PREFIX: &str = "opaque_mcp_tool_";
/// The daemon states in every `mcp_catalog` reply whether its signed gateway
/// serves `mcp_call`, `mcp_get` and `mcp_revoke`. Only these two values mean
/// yes; a missing field (daemons through 0.5.0) or any other value hides the
/// invocation tools, so a fresh installation never advertises a v2 surface
/// its daemon would refuse.
fn serves_gateway(catalog: &serde_json::Value) -> bool {
    matches!(
        catalog
            .pointer("/gateway/availability")
            .and_then(serde_json::Value::as_str),
        Some("enabled" | "fixture_only")
    )
}
pub async fn list(id: Option<serde_json::Value>, client: &DaemonClient) -> JsonRpcResponse {
    let mut response = handle_tools_list(id);
    // DaemonClient already bounds this read-only exchange to 30 seconds,
    // including peer authentication. A shorter outer deadline can repeatedly
    // hide enrolled tools while the daemon is still attesting the adapter.
    if let Ok(reply) = client.call("mcp_catalog", json!({})).await
        && reply.error.is_none()
        && let Some(catalog) = reply.result
        && let Some(tools) = catalog.get("tools").and_then(serde_json::Value::as_array)
    {
        if tools.len() > 128 {
            return response;
        }
        if let Some(output) = response
            .result
            .as_mut()
            .and_then(|v| v.get_mut("tools"))
            .and_then(serde_json::Value::as_array_mut)
        {
            for tool in tools {
                if tool["name"].as_str().is_some_and(|n| n.starts_with(PREFIX)) {
                    output.push(json!({"name":tool["name"],"description":tool["description"],"inputSchema":tool["inputSchema"]}));
                }
            }
            if !serves_gateway(&catalog) {
                return response;
            }
            for (name, description) in [
                (
                    "opaque_mcp_invocation_get",
                    "Inspect one invocation receipt; never retries work",
                ),
                (
                    "opaque_mcp_invocation_revoke",
                    "Revoke an invocation before its final dispatch fence; accepted effects cannot be recalled",
                ),
            ] {
                output.push(json!({"name":name,"description":description,"inputSchema":{"type":"object","additionalProperties":false,"required":["invocation_id"],"properties":{"invocation_id":{"type":"string","minLength":36,"maxLength":36}}}}));
            }
        }
    }
    response
}
pub fn recognizes(name: &str) -> bool {
    name.starts_with(PREFIX)
        || matches!(
            name,
            "opaque_mcp_invocation_get" | "opaque_mcp_invocation_revoke"
        )
}
pub async fn call(
    id: Option<serde_json::Value>,
    name: &str,
    args: serde_json::Value,
    client: &DaemonClient,
) -> JsonRpcResponse {
    let (method, mut params) = if let Some(alias) = name.strip_prefix(PREFIX) {
        let catalog = match client.call("mcp_catalog", json!({})).await {
            Ok(r) if r.error.is_none() => r.result,
            _ => None,
        };
        let tool = catalog
            .as_ref()
            .and_then(|v| v["tools"].as_array())
            .and_then(|tools| {
                tools
                    .iter()
                    .find(|t| t["name"] == name && t["route"] == alias)
            });
        let Some(tool) = tool else {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "unknown tool");
        };
        // A catalog schema the adapter cannot compile admits nothing and is
        // not described, since the failure is the schema, not the arguments.
        let Ok(validator) = jsonschema::validator_for(&tool["inputSchema"]) else {
            return JsonRpcResponse::error(id, INVALID_PARAMS, validation::SCHEMA_MISMATCH);
        };
        if let Some(message) =
            validation::describe_failures(&tool["inputSchema"], &validator, &args)
        {
            return JsonRpcResponse::error(id, INVALID_PARAMS, message);
        }
        let mut params = args;
        params["route"] = json!(alias);
        ("mcp_call", params)
    } else {
        if args.as_object().is_none_or(|m| m.len() != 1)
            || args
                .get("invocation_id")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|s| s.len() != 36)
        {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "invalid invocation reference");
        }
        (
            if name == "opaque_mcp_invocation_get" {
                "mcp_get"
            } else {
                "mcp_revoke"
            },
            args,
        )
    };
    if method == "mcp_call" {
        params["workspace"] = match blocking_lookup(|| {
            std::env::current_dir()
                .ok()
                .and_then(|cwd| collect_workspace_context(&cwd))
        })
        .await
        {
            Ok(w) => w.unwrap_or(serde_json::Value::Null),
            Err(_) => {
                return JsonRpcResponse::error(id, SERVER_BUSY, "workspace lookup unavailable");
            }
        };
    }
    let result = match client.call(method, params).await {
        Ok(r) if r.error.is_none() => r.result,
        _ => None,
    };
    let Some(result) = result else {
        return JsonRpcResponse::ok(
            id,
            json!({"content":[{"type":"text","text":"MCP broker unavailable. Work was not retried; inspect the invocation receipt before creating new work."}],"isError":true}),
        );
    };
    let error = method == "mcp_call"
        && result
            .pointer("/receipt/state")
            .and_then(serde_json::Value::as_str)
            != Some("accepted");
    JsonRpcResponse::ok(
        id,
        json!({"content":[{"type":"text","text":serde_json::to_string(&result).expect("receipt JSON serializes")}],"isError":error}),
    )
}
