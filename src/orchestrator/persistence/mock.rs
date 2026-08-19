use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;
use tonic::async_trait;

use super::super::store::SandboxMetadata;
use super::{
    CreateIdempotencyRecord, PersistenceResult, SandboxPersistenceError, SandboxPersister,
};
use crate::sandbox::PausedSandboxState;
use crate::types::SandboxId;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) enum RecordingCall {
    LoadAll,
    AllocateArtifactRoot,
    PersistPaused,
    MarkPausedRuntimeStopped,
    MarkResuming,
    RollbackResuming,
    DeleteRecord,
    DeleteRecordAndArtifacts,
    LoadCreateIdempotency,
    PersistCreateIdempotency,
    DeleteCreateIdempotency,
}

impl RecordingCall {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LoadAll => "load_all",
            Self::AllocateArtifactRoot => "allocate_artifact_root",
            Self::PersistPaused => "persist_paused",
            Self::MarkPausedRuntimeStopped => "mark_paused_runtime_stopped",
            Self::MarkResuming => "mark_resuming",
            Self::RollbackResuming => "rollback_resuming",
            Self::DeleteRecord => "delete_record",
            Self::DeleteRecordAndArtifacts => "delete_record_and_artifacts",
            Self::LoadCreateIdempotency => "load_create_idempotency",
            Self::PersistCreateIdempotency => "persist_create_idempotency",
            Self::DeleteCreateIdempotency => "delete_create_idempotency",
        }
    }
}

impl fmt::Display for RecordingCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Default)]
pub(crate) struct RecordingPersister {
    pub(crate) calls: Arc<Mutex<Vec<RecordingCall>>>,
    loaded: Arc<Mutex<Vec<SandboxMetadata>>>,
    create_idempotency: Arc<Mutex<HashMap<String, CreateIdempotencyRecord>>>,
    failures: Arc<Mutex<HashMap<RecordingCall, usize>>>,
    uncertain_failures: Arc<Mutex<HashMap<RecordingCall, usize>>>,
    next_create_idempotency_persist_barrier: Arc<Mutex<Option<RecordingPersistBarrier>>>,
}

#[derive(Clone)]
struct RecordingPersistBarrier {
    entered: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl RecordingPersister {
    pub(crate) fn with_loaded(loaded: Vec<SandboxMetadata>) -> Self {
        Self {
            loaded: Arc::new(Mutex::new(loaded)),
            ..Default::default()
        }
    }

    pub(crate) fn with_loaded_and_create_idempotency(
        loaded: Vec<SandboxMetadata>,
        records: Vec<CreateIdempotencyRecord>,
    ) -> Self {
        Self {
            loaded: Arc::new(Mutex::new(loaded)),
            create_idempotency: Arc::new(Mutex::new(
                records
                    .into_iter()
                    .map(|record| (record.key.clone(), record))
                    .collect(),
            )),
            ..Default::default()
        }
    }

    pub(crate) fn create_idempotency_records(&self) -> Vec<CreateIdempotencyRecord> {
        self.create_idempotency
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    pub(crate) fn loaded_sandboxes(&self) -> Vec<SandboxMetadata> {
        self.loaded.lock().unwrap().clone()
    }

    pub(crate) fn calls(&self) -> Vec<RecordingCall> {
        self.calls.lock().unwrap().clone()
    }

    pub(crate) fn clear_calls(&self) {
        self.calls.lock().unwrap().clear();
    }

    pub(crate) fn block_next_create_idempotency_persist(&self) -> (Arc<Semaphore>, Arc<Semaphore>) {
        let barrier = RecordingPersistBarrier {
            entered: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        };
        *self.next_create_idempotency_persist_barrier.lock().unwrap() = Some(barrier.clone());
        (barrier.entered, barrier.release)
    }

    pub(crate) fn record(&self, call: RecordingCall) {
        self.calls.lock().unwrap().push(call);
    }

    pub(crate) fn fail_next(&self, call: RecordingCall) {
        let mut failures = self.failures.lock().unwrap();
        *failures.entry(call).or_default() += 1;
    }

    pub(crate) fn fail_next_uncertain(&self, call: RecordingCall) {
        let mut failures = self.uncertain_failures.lock().unwrap();
        *failures.entry(call).or_default() += 1;
    }

    fn maybe_fail(&self, call: RecordingCall) -> PersistenceResult<()> {
        if let Some(remaining) = self.failures.lock().unwrap().get_mut(&call) {
            if *remaining > 0 {
                *remaining -= 1;
                return Err(SandboxPersistenceError::InvalidRecord {
                    reason: format!("forced {call} failure"),
                    source: None,
                });
            }
        }
        if let Some(remaining) = self.uncertain_failures.lock().unwrap().get_mut(&call) {
            if *remaining > 0 {
                *remaining -= 1;
                return Err(SandboxPersistenceError::UncertainCommit {
                    sandbox_id: SandboxId::new(),
                    reason: format!("forced uncertain {call} failure"),
                    source: None,
                });
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SandboxPersister for RecordingPersister {
    async fn load_all<F>(&self, _factory: &F) -> PersistenceResult<Vec<SandboxMetadata>>
    where
        F: crate::sandbox::SandboxBackendFactory,
    {
        self.record(RecordingCall::LoadAll);
        self.maybe_fail(RecordingCall::LoadAll)?;
        Ok(self.loaded.lock().unwrap().clone())
    }

    async fn allocate_artifact_root(
        &self,
        _sandbox_id: &SandboxId,
    ) -> PersistenceResult<Option<PathBuf>> {
        self.record(RecordingCall::AllocateArtifactRoot);
        self.maybe_fail(RecordingCall::AllocateArtifactRoot)?;
        Ok(None)
    }

    async fn persist_paused(
        &self,
        metadata: &SandboxMetadata,
        _artifact_root: Option<&Path>,
        _paused_state: &dyn PausedSandboxState,
    ) -> PersistenceResult<()> {
        self.record(RecordingCall::PersistPaused);
        self.maybe_fail(RecordingCall::PersistPaused)?;
        let mut loaded = self.loaded.lock().unwrap();
        loaded.retain(|current| current.id != metadata.id);
        loaded.push(metadata.clone());
        Ok(())
    }

    async fn mark_paused_runtime_stopped(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        self.record(RecordingCall::MarkPausedRuntimeStopped);
        self.maybe_fail(RecordingCall::MarkPausedRuntimeStopped)?;
        let mut loaded = self.loaded.lock().unwrap();
        let metadata = loaded
            .iter_mut()
            .find(|metadata| metadata.id == *sandbox_id)
            .ok_or_else(|| SandboxPersistenceError::InvalidRecord {
                reason: format!("paused sandbox record {sandbox_id} not found"),
                source: None,
            })?;
        metadata.paused_runtime_stopped = true;
        Ok(())
    }

    async fn mark_resuming(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        self.record(RecordingCall::MarkResuming);
        self.maybe_fail(RecordingCall::MarkResuming)?;
        if let Some(metadata) = self
            .loaded
            .lock()
            .unwrap()
            .iter_mut()
            .find(|metadata| metadata.id == *sandbox_id)
        {
            metadata.paused_runtime_stopped = false;
        }
        Ok(())
    }

    async fn rollback_resuming(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        self.record(RecordingCall::RollbackResuming);
        self.maybe_fail(RecordingCall::RollbackResuming)?;
        if let Some(metadata) = self
            .loaded
            .lock()
            .unwrap()
            .iter_mut()
            .find(|metadata| metadata.id == *sandbox_id)
        {
            metadata.paused_runtime_stopped = false;
        }
        Ok(())
    }

    async fn delete_record(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        self.record(RecordingCall::DeleteRecord);
        self.maybe_fail(RecordingCall::DeleteRecord)?;
        self.loaded
            .lock()
            .unwrap()
            .retain(|metadata| metadata.id != *sandbox_id);
        Ok(())
    }

    async fn delete_record_and_artifacts(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        self.record(RecordingCall::DeleteRecordAndArtifacts);
        self.maybe_fail(RecordingCall::DeleteRecordAndArtifacts)?;
        self.loaded
            .lock()
            .unwrap()
            .retain(|metadata| metadata.id != *sandbox_id);
        Ok(())
    }

    async fn load_create_idempotency_records(
        &self,
    ) -> PersistenceResult<Vec<CreateIdempotencyRecord>> {
        self.record(RecordingCall::LoadCreateIdempotency);
        self.maybe_fail(RecordingCall::LoadCreateIdempotency)?;
        Ok(self
            .create_idempotency
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect())
    }

    async fn persist_create_idempotency_record(
        &self,
        record: &CreateIdempotencyRecord,
    ) -> PersistenceResult<()> {
        self.record(RecordingCall::PersistCreateIdempotency);
        let barrier = self
            .next_create_idempotency_persist_barrier
            .lock()
            .unwrap()
            .take();
        if let Some(barrier) = barrier {
            barrier.entered.add_permits(1);
            barrier
                .release
                .acquire_owned()
                .await
                .expect("recording persistence barrier must remain open")
                .forget();
        }
        self.maybe_fail(RecordingCall::PersistCreateIdempotency)?;
        self.create_idempotency
            .lock()
            .unwrap()
            .insert(record.key.clone(), record.clone());
        Ok(())
    }

    async fn delete_create_idempotency_record(&self, key: &str) -> PersistenceResult<()> {
        self.record(RecordingCall::DeleteCreateIdempotency);
        self.maybe_fail(RecordingCall::DeleteCreateIdempotency)?;
        self.create_idempotency.lock().unwrap().remove(key);
        Ok(())
    }
}
