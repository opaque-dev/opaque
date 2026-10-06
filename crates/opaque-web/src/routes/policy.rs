use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde_json::json;

use crate::AppState;

pub async fn get_policy(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    match crate::config::load_web_config(&state.config_path) {
        Ok(config) => {
            let seal_present = state
                .config_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("config.seal")
                .exists();
            (
                StatusCode::OK,
                Json(json!({
                    "mode": "live", "config_path": state.config_path,
                    "seal_present": seal_present,
                    "enforce_agent_sessions": config.enforce_agent_sessions,
                    "agent_session_ttl_secs": config.agent_session_ttl_secs,
                    "rules": config.rules,
                })),
            )
        }
        Err(error) => super::api_error(StatusCode::SERVICE_UNAVAILABLE, &error),
    }
}
