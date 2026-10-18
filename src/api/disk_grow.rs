use super::ApiImpl;
use crate::{orchestrator::OrchestratorError, types::SandboxId};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrowRequest {
    #[serde(rename = "sizeMiB")]
    size_mib: u64,
}

pub(crate) fn router<I>(api: I) -> Router
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/sandboxes/{sandbox_id}/disk-grow", post(grow::<I>))
        .with_state(api)
}

async fn grow<I>(
    State(api): State<I>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<GrowRequest>,
) -> Response
where
    I: AsRef<ApiImpl> + Send + Sync,
{
    if !api.as_ref().has_valid_api_key(&headers) {
        return error(StatusCode::UNAUTHORIZED, "API key is required".into());
    }
    let Some(bytes) = body
        .size_mib
        .checked_mul(1 << 20)
        .filter(|size| *size > 0 && *size <= i64::MAX as u64)
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "sizeMiB must be a positive supported disk size".into(),
        );
    };
    let Ok(id) = SandboxId::parse_str(&id) else {
        return error(StatusCode::NOT_FOUND, "sandbox not found".into());
    };
    match api
        .as_ref()
        .orchestrator()
        .grow_sandbox_disk(id, bytes)
        .await
    {
        Ok(actual) => Json(serde_json::json!({"sizeMiB": actual / (1 << 20)})).into_response(),
        Err(OrchestratorError::SandboxNotFound(_)) => {
            error(StatusCode::NOT_FOUND, "sandbox not found".into())
        }
        Err(OrchestratorError::InvalidSandboxState { state, .. }) => error(
            StatusCode::CONFLICT,
            format!("disk growth requires a running sandbox, found {state:?}"),
        ),
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

fn error(status: StatusCode, message: String) -> Response {
    (status, Json(serde_json::json!({"message": message}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::GrowRequest;

    #[test]
    fn accepts_documented_size_mib_field() {
        let request: GrowRequest = serde_json::from_str(r#"{"sizeMiB":65536}"#).unwrap();
        assert_eq!(request.size_mib, 65536);
    }
}
