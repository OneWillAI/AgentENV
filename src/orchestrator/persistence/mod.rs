mod file_backed;
#[cfg(test)]
mod mock;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::orchestrator::store::SandboxMetadata;
use crate::sandbox::{PausedSandboxState, SandboxBackendFactory};
use crate::types::SandboxId;

pub use file_backed::{
    FileBackedSandboxPersister, PausedSandboxQuarantine, PausedSandboxRecoveryReport,
};
#[cfg(test)]
pub(crate) use mock::{RecordingCall, RecordingPersister};

pub type PersistenceResult<T> = std::result::Result<T, SandboxPersistenceError>;

/// Durable state for one node-local sandbox-create idempotency claim.
///
/// Records are written before a runtime is started and are retained on every
/// uncertain failure. `Deleting` is written only after the runtime has been
/// positively stopped; startup may therefore finish deleting its paused
/// record and release the key without risking a live orphan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreateIdempotencyRecordState {
    Creating,
    Succeeded,
    Failed,
    Deleting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateIdempotencyRecord {
    pub key: String,
    pub request_fingerprint: String,
    pub sandbox_id: SandboxId,
    pub state: CreateIdempotencyRecordState,
}

#[derive(Debug, thiserror::Error)]
pub enum SandboxPersistenceError {
    #[error("failed to {operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid sandbox record: {reason}")]
    InvalidRecord {
        reason: String,
        #[source]
        source: Option<anyhow::Error>,
    },
    #[error("invalid paused sandbox runtime state: {reason}")]
    RuntimeState { reason: &'static str },
    #[error("paused sandbox store operation failed: {operation}: {source}")]
    Store {
        operation: &'static str,
        #[source]
        source: anyhow::Error,
    },
    /// A durable write may have reached storage even though the caller saw an
    /// error.  Callers must leave the snapshot in place and route the sandbox
    /// through recovery rather than attempting a resume or cleanup.
    #[error("paused sandbox persistence commit is uncertain for {sandbox_id}: {reason}")]
    UncertainCommit {
        sandbox_id: SandboxId,
        reason: String,
        #[source]
        source: Option<anyhow::Error>,
    },
}

impl SandboxPersistenceError {
    pub(super) fn io(
        operation: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    pub(super) fn store(operation: &'static str, source: anyhow::Error) -> Self {
        Self::Store { operation, source }
    }

    pub fn is_uncertain_commit(&self) -> bool {
        matches!(self, Self::UncertainCommit { .. })
    }
}

#[async_trait]
/// Persistence interface for sandbox records and artifacts.
pub trait SandboxPersister: Send + Sync {
    /// Load all persisted sandbox metadata.
    async fn load_all<F>(&self, factory: &F) -> PersistenceResult<Vec<SandboxMetadata>>
    where
        F: SandboxBackendFactory;

    /// Allocate an UNIQUE directory for sandbox artifacts.
    ///
    /// `None` means persistence is disabled and the sandbox backend should manage
    /// the lifecycle of its temporary artifacts.
    async fn allocate_artifact_root(
        &self,
        sandbox_id: &SandboxId,
    ) -> PersistenceResult<Option<PathBuf>>;

    /// Persist metadata and runtime state for a paused sandbox.
    async fn persist_paused(
        &self,
        metadata: &SandboxMetadata,
        artifact_root: Option<&Path>,
        paused_state: &dyn PausedSandboxState,
    ) -> PersistenceResult<()>;

    /// Durably record that the live runtime was positively stopped after its
    /// paused state was persisted. Existing persisters fail closed until they
    /// implement this proof transition.
    async fn mark_paused_runtime_stopped(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Err(SandboxPersistenceError::InvalidRecord {
            reason: "paused runtime stop proof is not supported by this persister".to_string(),
            source: None,
        })
    }

    /// Mark a paused sandbox as resuming.
    async fn mark_resuming(&self, sandbox_id: &SandboxId) -> PersistenceResult<()>;

    /// Roll back a resuming mark after a failed resume attempt.
    async fn rollback_resuming(&self, sandbox_id: &SandboxId) -> PersistenceResult<()>;

    /// Delete the persistence record for a sandbox.
    async fn delete_record(&self, sandbox_id: &SandboxId) -> PersistenceResult<()>;

    /// Delete the persistence record and all associated artifacts.
    async fn delete_record_and_artifacts(&self, sandbox_id: &SandboxId) -> PersistenceResult<()>;

    /// Load the durable create-idempotency journal.
    ///
    /// The default keeps existing third-party persister implementations source
    /// compatible. Such implementations fail closed when an idempotent create
    /// is attempted until they provide durable journal storage.
    async fn load_create_idempotency_records(
        &self,
    ) -> PersistenceResult<Vec<CreateIdempotencyRecord>> {
        Ok(Vec::new())
    }

    /// Atomically persist one create-idempotency record before acknowledging
    /// its state transition.
    async fn persist_create_idempotency_record(
        &self,
        _record: &CreateIdempotencyRecord,
    ) -> PersistenceResult<()> {
        Err(SandboxPersistenceError::InvalidRecord {
            reason: "create idempotency persistence is not supported by this persister".to_string(),
            source: None,
        })
    }

    /// Durably release an idempotency key after deletion is proven complete.
    async fn delete_create_idempotency_record(&self, _key: &str) -> PersistenceResult<()> {
        Err(SandboxPersistenceError::InvalidRecord {
            reason: "create idempotency persistence is not supported by this persister".to_string(),
            source: None,
        })
    }
}

#[derive(Default)]
pub struct DisabledSandboxPersister;

#[async_trait]
impl SandboxPersister for DisabledSandboxPersister {
    async fn load_all<F>(&self, _factory: &F) -> PersistenceResult<Vec<SandboxMetadata>>
    where
        F: SandboxBackendFactory,
    {
        Ok(Vec::new())
    }

    async fn allocate_artifact_root(
        &self,
        _sandbox_id: &SandboxId,
    ) -> PersistenceResult<Option<PathBuf>> {
        Ok(None)
    }

    async fn persist_paused(
        &self,
        _metadata: &SandboxMetadata,
        _artifact_root: Option<&Path>,
        _paused_state: &dyn PausedSandboxState,
    ) -> PersistenceResult<()> {
        Ok(())
    }

    async fn mark_paused_runtime_stopped(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Ok(())
    }

    async fn mark_resuming(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Ok(())
    }

    async fn rollback_resuming(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Ok(())
    }

    async fn delete_record(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Ok(())
    }

    async fn delete_record_and_artifacts(&self, _sandbox_id: &SandboxId) -> PersistenceResult<()> {
        Ok(())
    }

    async fn persist_create_idempotency_record(
        &self,
        _record: &CreateIdempotencyRecord,
    ) -> PersistenceResult<()> {
        Ok(())
    }

    async fn delete_create_idempotency_record(&self, _key: &str) -> PersistenceResult<()> {
        Ok(())
    }
}
