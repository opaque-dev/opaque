use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde_json::json;

use crate::AppState;

pub async fn get_sessions(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    match state.daemon.call("agent_session_list", json!({})).await {
        Ok(resp) if resp.error.is_none() => {
            match resp.result.and_then(|r| r.get("sessions").cloned()) {
                Some(sessions) if sessions.is_array() => (
                    StatusCode::OK,
                    Json(json!({"mode":"live", "sessions": sessions})),
                ),
                _ => super::api_error(
                    StatusCode::BAD_GATEWAY,
                    "Daemon returned an invalid session list.",
                ),
            }
        }
        Ok(_) => super::api_error(StatusCode::BAD_GATEWAY, "Daemon rejected session listing."),
        Err(_) => super::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Sessions unavailable. Start the daemon using the selected socket and refresh.",
        ),
    }
}
