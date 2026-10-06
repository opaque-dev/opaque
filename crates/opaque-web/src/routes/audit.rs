use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use opaque_core::audit::{AuditEventKind, AuditFilter, query_audit_db};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

#[derive(Deserialize, Default)]
pub struct AuditParams {
    pub kind: Option<String>,
    pub operation: Option<String>,
    pub outcome: Option<String>,
    pub q: Option<String>,
    pub limit: Option<usize>,
}

pub async fn get_audit(
    State(state): State<AppState>,
    Query(params): Query<AuditParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    let kind = match params
        .kind
        .as_deref()
        .map(str::parse::<AuditEventKind>)
        .transpose()
    {
        Ok(kind) => kind,
        Err(_) => return super::api_error(StatusCode::BAD_REQUEST, "Unknown audit event kind."),
    };
    if !state.audit_db_path.exists() {
        return super::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Audit database is not available yet. Start the selected daemon and run a task.",
        );
    }
    let filter = AuditFilter {
        kind,
        operation: params.operation,
        outcome: params.outcome,
        text_query: params.q,
        limit: params.limit.unwrap_or(100).clamp(1, 500),
        ..Default::default()
    };
    match query_audit_db(&state.audit_db_path, &filter) {
        Ok(events) => (
            StatusCode::OK,
            Json(json!({ "mode": "live", "events": events })),
        ),
        Err(e) => {
            tracing::warn!("failed to query audit db: {e}");
            super::api_error(
                StatusCode::BAD_REQUEST,
                "Audit query failed. Check the search syntax and the selected audit database.",
            )
        }
    }
}

pub async fn get_audit_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> axum::response::Response {
    let last_seq = match headers.get("last-event-id") {
        Some(value) => match value.to_str().ok().and_then(|v| v.parse::<i64>().ok()) {
            Some(value) if value >= -1 => Some(value),
            _ => {
                return super::api_error(StatusCode::BAD_REQUEST, "Invalid audit resume cursor.")
                    .into_response();
            }
        },
        None => None,
    };
    match crate::sse::audit_sse_stream(state.audit_db_path, state.cancel, last_seq) {
        Ok(stream) => stream.into_response(),
        Err(error) => {
            tracing::warn!("failed to open audit stream: {error}");
            super::api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Audit stream unavailable. Check the selected daemon and audit database.",
            )
            .into_response()
        }
    }
}
