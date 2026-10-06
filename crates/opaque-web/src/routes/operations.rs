use crate::AppState;
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

/// Live inventory comes from the authenticated, selected daemon.
pub async fn get_operations(State(state): State<AppState>) -> Response {
    match state.daemon.call("operations", json!({})).await {
        Ok(response) if response.error.is_none() => match response.result {
            Some(result)
                if result
                    .get("operations")
                    .is_some_and(|value| value.is_array()) =>
            {
                Json(result).into_response()
            }
            _ => super::api_error(
                StatusCode::BAD_GATEWAY,
                "Daemon returned an invalid operation inventory.",
            )
            .into_response(),
        },
        Ok(_) => super::api_error(
            StatusCode::BAD_GATEWAY,
            "Daemon operation inventory unavailable; update the selected daemon.",
        )
        .into_response(),
        Err(_) => super::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Daemon disconnected; live operation inventory unavailable.",
        )
        .into_response(),
    }
}
