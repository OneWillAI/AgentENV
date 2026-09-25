use super::ApiImpl;
use crate::{cfg::ConfigManager, orchestrator::OrchestratorError, types::SandboxId};
use agentenv_http_server::apis::ApiKeyAuthHeader;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RebootRequest {
    tools_version: String,
}

pub(crate) fn router<I>(api_impl: I) -> Router
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/sandboxes/{sandbox_id}/reboot", post(reboot::<I>))
        .with_state(api_impl)
}

async fn reboot<I>(
    State(api): State<I>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RebootRequest>,
) -> Response
where
    I: AsRef<ApiImpl> + Send + Sync,
{
    if api
        .as_ref()
        .extract_claims_from_header(&headers, "X-API-Key")
        .await
        .is_none()
    {
        return error(StatusCode::UNAUTHORIZED, "API key is required".into());
    }
    if body.tools_version != ConfigManager::global_config().resolved_tools_version() {
        return error(
            StatusCode::CONFLICT,
            "requested tools are not the node's installed release".into(),
        );
    }
    let Ok(id) = SandboxId::parse_str(&id) else {
        return error(StatusCode::NOT_FOUND, "sandbox not found".into());
    };
    match api.as_ref().orchestrator().reboot_sandbox(id).await {
        Ok(metadata) => Json(serde_json::json!({
            "sandboxID": metadata.id.to_string(), "toolsVersion": metadata.runtime_versions.tools_drive_version,
            "state": metadata.state.to_string(),
        })).into_response(),
        Err(OrchestratorError::SandboxNotFound(_)) => error(StatusCode::NOT_FOUND, "sandbox not found".into()),
        Err(OrchestratorError::InvalidSandboxState { state, .. }) => error(StatusCode::CONFLICT, format!("sandbox cannot reboot from {state:?}")),
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

fn error(status: StatusCode, message: String) -> Response {
    (status, Json(serde_json::json!({"message": message}))).into_response()
}
