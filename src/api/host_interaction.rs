use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;

use super::ApiImpl;
use crate::orchestrator::ProxyLookupResult;
use crate::types::SandboxId;

#[derive(Debug, Serialize)]
pub struct HostInteractionIpResponse {
    #[serde(rename = "hostInteractionIp")]
    host_interaction_ip: String,
}

pub(crate) fn router<I>(api_impl: I) -> Router
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/sandboxes/{sandbox_id}/host-interaction-ip",
            get(host_interaction_ip::<I>),
        )
        .with_state(api_impl)
}

async fn host_interaction_ip<I>(
    State(api_impl): State<I>,
    Path(sandbox_id): Path<String>,
    headers: HeaderMap,
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
        .proxy_lookup_for(&sandbox_id)
        .await
    {
        Ok(ProxyLookupResult::Ready(target)) => (
            StatusCode::OK,
            Json(HostInteractionIpResponse {
                host_interaction_ip: target.ip.to_string(),
            }),
        )
            .into_response(),
        Ok(ProxyLookupResult::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "message": "sandbox not found" })),
        )
            .into_response(),
        Ok(lookup) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "message": lookup_conflict_message(&lookup)
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

fn lookup_conflict_message(lookup: &ProxyLookupResult) -> String {
    match lookup {
        ProxyLookupResult::Paused { .. } => {
            "sandbox host interaction address is unavailable while paused".to_string()
        }
        ProxyLookupResult::Unavailable(state) => {
            format!("sandbox host interaction address is unavailable in {state:?} state")
        }
        ProxyLookupResult::RouteMissing => {
            "running sandbox is missing a host interaction route".to_string()
        }
        ProxyLookupResult::Ready(_) | ProxyLookupResult::NotFound => {
            "sandbox host interaction address is unavailable".to_string()
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::{ProxyLookupResult, ProxyTarget, SandboxState};
    use std::net::Ipv4Addr;

    #[test]
    fn paused_and_missing_routes_explain_the_conflict() {
        assert!(lookup_conflict_message(&ProxyLookupResult::Paused {
            auto_resume: true
        })
        .contains("paused"));
        assert!(
            lookup_conflict_message(&ProxyLookupResult::Unavailable(SandboxState::Creating))
                .contains("Creating")
        );
        assert!(lookup_conflict_message(&ProxyLookupResult::RouteMissing).contains("missing"));
        assert_eq!(
            lookup_conflict_message(&ProxyLookupResult::Ready(ProxyTarget::new(
                Ipv4Addr::new(10, 11, 0, 5)
            ))),
            "sandbox host interaction address is unavailable"
        );
    }
}
