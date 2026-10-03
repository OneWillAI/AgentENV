//! Connection-independent execution. Hambody persists the operation before
//! submission; a runtime restart may interrupt it, but a client disconnect may not.
use super::ApiImpl;
use crate::{
    snapshot::{
        SnapshotAlias, SnapshotId, SnapshotPublishMetadata, SnapshotPublishSource, SnapshotSource,
    },
    types::SandboxId,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation {
    id: String,
    source: String,
    name: String,
    status: String,
    progress: String,
    error: Option<String>,
    snapshot_id: Option<String>,
}
#[derive(Deserialize)]
struct Submit {
    name: String,
}

pub(crate) fn router<I>(api: I) -> Router
where
    I: AsRef<ApiImpl> + Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/sandboxes/{sandbox_id}/snapshot-operations/{id}",
            get(observe::<I>).put(submit::<I>),
        )
        .with_state(api)
}

async fn observe<I>(State(api): State<I>, Path((source, id)): Path<(String, String)>) -> Response
where
    I: AsRef<ApiImpl> + Send + Sync,
{
    let Ok(id) = SnapshotId::parse(&id).map(|id| id.to_string()) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let api = api.as_ref();
    let operations = api.snapshot_operations.lock().await;
    if let Some(operation) = operations.get(&id) {
        if operation.source != source {
            return StatusCode::CONFLICT.into_response();
        }
        return Json(operation.clone()).into_response();
    }
    drop(operations);
    // Missing execution state is not proof of failed publication.
    match api.snapshot_manager.get(&id).await {
        Ok(Some(record)) if record.committed.is_none() => StatusCode::CONFLICT.into_response(),
        Ok(Some(record)) if !matches!(&record.source, SnapshotSource::Sandbox { source_sandbox_id } if source_sandbox_id == &source) => StatusCode::CONFLICT.into_response(),
        Ok(Some(record)) => Json(Operation { id, source, name: record.alias.as_ref().map(|alias| alias.to_string()).unwrap_or_default(), status: "ready".into(), progress: "Snapshot published".into(), error: None, snapshot_id: Some(record.id.to_string()) }).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"message": format!("Catalog reconciliation unavailable: {error:#}")}))).into_response(),
    }
}

async fn submit<I>(
    State(api): State<I>,
    Path((source, id)): Path<(String, String)>,
    Json(body): Json<Submit>,
) -> Response
where
    I: AsRef<ApiImpl> + Send + Sync,
{
    let Ok(sandbox_id) = SandboxId::parse_str(&source) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(snapshot_id) = SnapshotId::parse(&id) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let id = snapshot_id.to_string();
    // Stable alias and ID make a lost submission response safe to observe/replay.
    let Ok(alias) = SnapshotAlias::parse(&body.name) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let api = api.as_ref().clone();
    let mut operations = api.snapshot_operations.lock().await;
    let operation = match operations.entry(id.clone()) {
        Entry::Occupied(entry) => {
            if entry.get().source != source || entry.get().name != body.name {
                return StatusCode::CONFLICT.into_response();
            }
            return Json(entry.get().clone()).into_response();
        }
        Entry::Vacant(entry) => entry
            .insert(Operation {
                id: id.clone(),
                source,
                name: body.name,
                status: "capturing".into(),
                progress: "Preparing capture".into(),
                error: None,
                snapshot_id: None,
            })
            .clone(),
    };
    drop(operations);
    // The runtime owns this task and its capture guards. No HTTP request future
    // owns publication. The outer task records panics as well as ordinary errors.
    let runner = api.clone();
    let request_id = id.clone();
    tokio::spawn(async move {
        let execution = tokio::spawn(async move {
            runner
                .execute_snapshot_operation(&request_id, sandbox_id, snapshot_id, alias)
                .await
        });
        let result = match execution.await {
            Ok(result) => result,
            Err(error) => Err(anyhow::anyhow!("Snapshot execution stopped: {error}")),
        };
        let result = match result {
            Ok(id) => Ok(id),
            Err(error) => match api.snapshot_manager.get(&id).await {
                Ok(Some(record))
                    if record.committed.is_some()
                        && matches!(&record.source, SnapshotSource::Sandbox { source_sandbox_id } if source_sandbox_id == &sandbox_id.to_string()) =>
                {
                    Ok(record.id.to_string())
                }
                Ok(Some(_)) => Err(format!("{error:#}")),
                Ok(None) => Err(format!("{error:#}")),
                Err(lookup) => Err(format!(
                    "{error:#}; publication reconciliation unavailable: {lookup:#}"
                )),
            },
        };
        let mut operations = api.snapshot_operations.lock().await;
        if let Some(operation) = operations.get_mut(&id) {
            match result {
                Ok(snapshot_id) => {
                    operation.status = "ready".into();
                    operation.progress = "Snapshot published".into();
                    operation.snapshot_id = Some(snapshot_id);
                }
                Err(error) => {
                    operation.status = "failed".into();
                    operation.progress = "Snapshot saving failed".into();
                    operation.error = Some(error);
                }
            }
        }
    });
    (StatusCode::ACCEPTED, Json(operation)).into_response()
}

impl ApiImpl {
    async fn execute_snapshot_operation(
        &self,
        id: &str,
        source: SandboxId,
        snapshot_id: SnapshotId,
        alias: SnapshotAlias,
    ) -> anyhow::Result<String> {
        if let Some(record) = self.snapshot_manager.get(id).await? {
            anyhow::ensure!(
                record.committed.is_some(),
                "Snapshot ID has an unfinished publication"
            );
            anyhow::ensure!(
                matches!(&record.source, SnapshotSource::Sandbox { source_sandbox_id } if source_sandbox_id == &source.to_string()),
                "Snapshot request ID belongs to another source"
            );
            return Ok(record.id.to_string());
        }
        if let Some(record) = self.snapshot_manager.get(alias.as_ref()).await? {
            anyhow::ensure!(
                record.committed.is_some(),
                "Snapshot ID has an unfinished publication"
            );
            anyhow::ensure!(
                matches!(&record.source, SnapshotSource::Sandbox { source_sandbox_id } if source_sandbox_id == &source.to_string()),
                "Snapshot alias belongs to another source"
            );
            return Ok(record.id.to_string());
        }
        let capture = self.orchestrator.capture_snapshot(source).await?;
        if let Some(operation) = self.snapshot_operations.lock().await.get_mut(id) {
            operation.status = "uploading".into();
            operation.progress = "Capture complete; uploading and publishing snapshot".into();
        }
        let volume_snapshots = super::sandbox::snapshot_sandbox_volumes(self, &capture.metadata)
            .await
            .map_err(|error| anyhow::anyhow!("{}", error.message))?;
        let record = self
            .snapshot_manager
            .publish_captured(
                SnapshotPublishMetadata {
                    id: snapshot_id,
                    alias: Some(alias),
                    source: SnapshotPublishSource::Sandbox {
                        source_sandbox_id: source.to_string(),
                    },
                    context: capture.metadata.context.clone(),
                    startup: capture.metadata.startup.clone(),
                    resources: capture.metadata.resources,
                    runtime_versions: capture.metadata.runtime_versions.clone(),
                    virtualization_mode: capture.metadata.virtualization_mode,
                    image_configs: capture.metadata.image_configs.clone(),
                    volume_snapshots,
                    custom_extension_params: capture.metadata.custom_extension_params.clone(),
                },
                capture.captured_snapshot,
            )
            .await?;
        Ok(record.id.to_string())
    }
}
