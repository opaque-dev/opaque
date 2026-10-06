use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;

type ApiResult = (StatusCode, Json<Value>);

#[derive(Deserialize, Default)]
pub struct TaskParams {
    cursor: Option<String>,
}

pub async fn list_tasks(
    State(state): State<AppState>,
    Query(params): Query<TaskParams>,
) -> ApiResult {
    task_call(
        &state,
        "task_list",
        json!({"cursor": params.cursor}),
        "tasks",
    )
    .await
}

pub async fn get_task(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult {
    task_call(&state, "task_get", json!({"task_id":id}), "task").await
}

/// Refresh only the provider's workflow evidence. This endpoint cannot approve,
/// dispatch, retry, or mint task authority; the daemon enforces owner scope.
pub async fn reconcile_task(State(state): State<AppState>, Path(id): Path<String>) -> ApiResult {
    task_call(&state, "task_reconcile", json!({"task_id":id}), "task").await
}

async fn task_call(state: &AppState, method: &str, params: Value, key: &str) -> ApiResult {
    match state.daemon.call(method, params).await {
        Ok(resp) if resp.error.is_none() => match resp.result.filter(|r| r.get(key).is_some()) {
            Some(result) => {
                let mut body = json!({"mode":"live", key:result[key]});
                if key == "tasks" {
                    body["has_more"] = result.get("has_more").cloned().unwrap_or(json!(false));
                    body["next_cursor"] = result.get("next_cursor").cloned().unwrap_or(Value::Null);
                }
                (StatusCode::OK, Json(body))
            }
            None => super::api_error(
                StatusCode::BAD_GATEWAY,
                "Daemon returned an invalid task response.",
            ),
        },
        // The daemon owns visibility and authorization. Do not replace denied
        // results with unscoped reads from its database.
        Ok(_) => super::api_error(
            StatusCode::BAD_GATEWAY,
            "Daemon could not return this task. Check its availability and your task access.",
        ),
        Err(_) => super::api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Tasks unavailable. Start the daemon using the selected socket and refresh.",
        ),
    }
}
