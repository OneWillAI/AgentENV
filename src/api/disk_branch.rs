use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use super::ApiImpl;
use crate::orchestrator::OrchestratorError;
use crate::types::SandboxId;

#[derive(Debug, Default, Deserialize)]
pub struct DiskBranchRequest {
    #[serde(default, rename = "idempotencyKey")]
    idempotency_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiskBranchResponse {
    image: String,
}

pub(crate) fn router<I>(api_impl: I) -> Router
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/sandboxes/{sandbox_id}/disk-branch",
            post(disk_branch::<I>),
        )
        .with_state(api_impl)
}

async fn disk_branch<I>(
    State(api_impl): State<I>,
    Path(sandbox_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DiskBranchRequest>,
) -> Response
where
    I: AsRef<ApiImpl> + Send + Sync,
{
    if !has_control_plane_auth(&headers) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "message": "API key is required" })),
        )
            .into_response();
    }
    let Ok(sandbox_id) = SandboxId::parse_str(&sandbox_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "sandbox not found" })),
        )
            .into_response();
    };
    match api_impl
        .as_ref()
        .orchestrator()
        .branch_sandbox_disk(sandbox_id, body.idempotency_key)
        .await
    {
        Ok(image) => (StatusCode::OK, Json(DiskBranchResponse { image })).into_response(),
        Err(OrchestratorError::SandboxNotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "sandbox not found" })),
        )
            .into_response(),
        Err(OrchestratorError::InvalidSandboxState { state, .. }) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "message": format!("sandbox cannot be disk-branched from {state:?} state")
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "message": error.to_string() })),
        )
            .into_response(),
    }
}

fn has_control_plane_auth(headers: &HeaderMap) -> bool {
    nonempty_header(headers, "x-api-key") || nonempty_header(headers, "x-admin-token")
}

fn nonempty_header(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.is_empty())
}
