use axum::Json;
use axum::extract::State;
use serde_json::json;

use crate::AppState;

pub async fn get_status(State(state): State<AppState>) -> Json<serde_json::Value> {
    let mut status = json!({
        "mode": "disconnected",
        "daemon_running": false,
        "socket_path": state.daemon.socket_path(),
        "config_path": state.config_path,
        "audit_db_path": state.audit_db_path,
        "audit_available": state.audit_db_path.exists(),
    });
    match state.daemon.call("version", json!({})).await {
        Ok(resp) if resp.error.is_none() => {
            status["mode"] = json!("live");
            status["daemon_running"] = json!(true);
            for key in [
                "approval_backend",
                "task_grants_enabled",
                "trust_domain_enforced",
                "workstation_test_mode",
            ] {
                status[key] = resp
                    .result
                    .as_ref()
                    .and_then(|r| r.get(key))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
            }
            status["daemon_version"] = resp
                .result
                .as_ref()
                .and_then(|r| r.get("version"))
                .cloned()
                .unwrap_or(json!("unknown"));
        }
        Ok(_) => {
            status["message"] = json!(
                "The daemon rejected the health check. Check daemon authentication and configuration."
            )
        }
        Err(error) => status["message"] = json!(format!("Cannot connect to daemon: {error}")),
    }
    Json(status)
}
