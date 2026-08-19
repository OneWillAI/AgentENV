use std::collections::HashSet;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::fs;
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::{
    CreateIdempotencyRecord, PersistenceResult, SandboxPersistenceError, SandboxPersister,
};
use crate::local_store::{LocalKvStore, LocalStoreDurability};
use crate::orchestrator::{store::SandboxMetadata, SandboxState};
use crate::sandbox::{PausedSandboxState, SandboxBackendFactory};
use crate::types::SandboxId;
use crate::virtualization::VirtualizationMode;

const RECORD_VERSION: u32 = 1;
const RECORD_DB_DIR: &str = "records.db";
const CREATE_IDEMPOTENCY_RECORD_VERSION: u32 = 1;
const CREATE_IDEMPOTENCY_DB_DIR: &str = "create-idempotency.db";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedPausedLifecycle {
    Paused,
    /// The resumed VM has not yet reached the durable-success point. Keep
    /// this record and its artifacts across restart: a process crash here may
    /// have left the previous Firecracker child alive.
    Resuming,
    /// The resumed VM was published as Running. This durable commit permits
    /// exact snapshot cleanup, including after a crash during cleanup.
    Resumed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedPausedRecord {
    version: u32,
    lifecycle: PersistedPausedLifecycle,
    /// Linux boot identity captured before a resume can launch a new VM.
    /// Absent legacy records fail closed during startup recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resuming_boot_id: Option<String>,
    metadata: SandboxMetadata,
    artifact_root: PathBuf,
    state: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedCreateIdempotencyRecord {
    version: u32,
    record: CreateIdempotencyRecord,
}

impl PersistedPausedRecord {
    fn into_metadata<F>(mut self, factory: &F) -> PersistenceResult<SandboxMetadata>
    where
        F: SandboxBackendFactory,
    {
        ensure_supported_version(self.version)?;

        let paused_state = factory
            .decode_paused_state(self.artifact_root, self.state)
            .map_err(|source| SandboxPersistenceError::InvalidRecord {
                reason: "failed to decode paused sandbox state".to_string(),
                source: Some(source),
            })?;
        self.metadata.state = SandboxState::Paused;
        self.metadata.paused_state = Some(paused_state);

        Ok(self.metadata)
    }

    fn into_metadata_without_runtime_state(mut self) -> SandboxMetadata {
        self.metadata.state = SandboxState::Paused;
        self.metadata.paused_state = None;
        self.metadata
    }

    fn into_recovery_pending_metadata<F>(self, factory: &F) -> PersistenceResult<SandboxMetadata>
    where
        F: SandboxBackendFactory,
    {
        let mut metadata = self.into_metadata(factory)?;
        metadata.paused_runtime_stopped = false;
        metadata.resume_recovery_pending = true;
        Ok(metadata)
    }
}

fn decode_record(bytes: &[u8]) -> PersistenceResult<PersistedPausedRecord> {
    let record: PersistedPausedRecord =
        serde_json::from_slice(bytes).map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "failed to deserialize record".to_string(),
            source: Some(source.into()),
        })?;
    ensure_supported_version(record.version)?;
    Ok(record)
}

fn ensure_supported_version(version: u32) -> PersistenceResult<()> {
    if version == RECORD_VERSION {
        Ok(())
    } else {
        Err(SandboxPersistenceError::InvalidRecord {
            reason: format!("unsupported record version {version}"),
            source: None,
        })
    }
}

/// A changed Linux boot ID proves any Firecracker child from an interrupted
/// prior AgentENV process cannot still be alive. Missing boot IDs deliberately
/// provide no proof, including for legacy records written before this field.
fn host_reboot_proves_runtime_absent(
    recorded_boot_id: Option<&str>,
    current_boot_id: Option<&str>,
) -> bool {
    matches!(
        (recorded_boot_id, current_boot_id),
        (Some(recorded), Some(current)) if recorded != current
    )
}

fn current_host_boot_id() -> Option<String> {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let boot_id = boot_id.trim();
    (!boot_id.is_empty()).then(|| boot_id.to_owned())
}

fn decode_create_idempotency_record(bytes: &[u8]) -> PersistenceResult<CreateIdempotencyRecord> {
    let persisted: PersistedCreateIdempotencyRecord =
        serde_json::from_slice(bytes).map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "failed to deserialize create idempotency record".to_string(),
            source: Some(source.into()),
        })?;
    if persisted.version != CREATE_IDEMPOTENCY_RECORD_VERSION {
        return Err(SandboxPersistenceError::InvalidRecord {
            reason: format!(
                "unsupported create idempotency record version {}",
                persisted.version
            ),
            source: None,
        });
    }
    if persisted.record.key.is_empty() || persisted.record.request_fingerprint.is_empty() {
        return Err(SandboxPersistenceError::InvalidRecord {
            reason: "create idempotency record has an empty key or fingerprint".to_string(),
            source: None,
        });
    }
    Ok(persisted.record)
}

pub struct FileBackedSandboxPersister {
    root: PathBuf,
    virtualization_mode: VirtualizationMode,
    durability: LocalStoreDurability,
    db: OnceCell<LocalKvStore>,
    create_idempotency_db: OnceCell<LocalKvStore>,
}

impl FileBackedSandboxPersister {
    pub fn new(root: PathBuf, virtualization_mode: VirtualizationMode) -> Self {
        Self {
            root,
            virtualization_mode,
            durability: LocalStoreDurability::Sync,
            db: OnceCell::new(),
            create_idempotency_db: OnceCell::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(root: PathBuf) -> Self {
        Self::new(root, VirtualizationMode::Kvm)
    }

    pub fn with_durability(mut self, durability: LocalStoreDurability) -> Self {
        self.durability = durability;
        self
    }

    fn records_db_path(&self) -> PathBuf {
        self.root.join(RECORD_DB_DIR)
    }

    fn create_idempotency_db_path(&self) -> PathBuf {
        self.root.join(CREATE_IDEMPOTENCY_DB_DIR)
    }

    fn artifacts_root(&self) -> PathBuf {
        self.root.join("artifacts")
    }

    fn sandbox_artifact_root(&self, sandbox_id: &SandboxId) -> PathBuf {
        self.artifacts_root().join(sandbox_id.to_string())
    }

    async fn db(&self) -> PersistenceResult<LocalKvStore> {
        self.db
            .get_or_try_init(|| async {
                LocalKvStore::open(self.records_db_path(), self.durability)
                    .await
                    .map_err(|source| SandboxPersistenceError::store("open RocksDB", source))
            })
            .await
            .cloned()
    }

    async fn create_idempotency_db(&self) -> PersistenceResult<LocalKvStore> {
        self.create_idempotency_db
            .get_or_try_init(|| async {
                LocalKvStore::open(self.create_idempotency_db_path(), self.durability)
                    .await
                    .map_err(|source| {
                        SandboxPersistenceError::store("open create idempotency RocksDB", source)
                    })
            })
            .await
            .cloned()
    }

    async fn get_record(&self, sandbox_id: &SandboxId) -> PersistenceResult<PersistedPausedRecord> {
        let bytes = self
            .db()
            .await?
            .get(sandbox_id.to_string())
            .await
            .map_err(|source| SandboxPersistenceError::store("read paused sandbox record", source))?
            .ok_or_else(|| SandboxPersistenceError::InvalidRecord {
                reason: format!("paused sandbox record {sandbox_id} not found"),
                source: None,
            })?;
        decode_record(&bytes)
    }

    async fn put_record(&self, record: &PersistedPausedRecord) -> PersistenceResult<()> {
        let bytes = serde_json::to_vec(record).map_err(|source| {
            SandboxPersistenceError::InvalidRecord {
                reason: "failed to serialize record".to_string(),
                source: Some(source.into()),
            }
        })?;

        self.db()
            .await?
            .put(record.metadata.id.to_string(), bytes)
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("persist paused sandbox record", source)
            })
    }

    async fn remove_record(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        self.db()
            .await?
            .delete(sandbox_id.to_string())
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("remove paused sandbox record", source)
            })
    }

    async fn remove_artifact_root(path: &Path) -> PersistenceResult<()> {
        match fs::remove_dir_all(path).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(SandboxPersistenceError::io(
                "remove paused sandbox artifacts",
                path,
                source,
            )),
        }
    }

    /// Remove only the generation consumed by a committed resume. New pause
    /// cycles allocate separate generation directories, so deleting the whole
    /// `<sandbox-id>` directory here would reintroduce a resume/pause race.
    async fn cleanup_consumed_resume_generation(
        &self,
        artifact_root: &Path,
    ) -> PersistenceResult<()> {
        Self::remove_artifact_root(artifact_root).await
    }

    /// Make successful-resume cleanup crash-safe. The `Resumed` marker is the
    /// durable commit point: if the process dies before it, startup retains a
    /// `Resuming` tombstone; if it dies after it, startup can finish deleting
    /// exactly this generation and the record.
    async fn finalize_resumed_record(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        let mut record = self.get_record(sandbox_id).await?;
        match record.lifecycle {
            PersistedPausedLifecycle::Resuming => {
                record.lifecycle = PersistedPausedLifecycle::Resumed;
                record.resuming_boot_id = None;
                self.put_record(&record).await?;
            }
            PersistedPausedLifecycle::Resumed => {}
            PersistedPausedLifecycle::Paused => {
                return Err(SandboxPersistenceError::InvalidRecord {
                    reason: format!(
                        "cannot finalize paused sandbox {sandbox_id} before it is marked resuming"
                    ),
                    source: None,
                });
            }
        }

        self.cleanup_consumed_resume_generation(&record.artifact_root)
            .await?;
        self.remove_record(sandbox_id).await
    }

    async fn cleanup_invalid_record(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        debug!(sandbox_id = %sandbox_id, "cleaning up invalid paused sandbox record");
        self.remove_record(sandbox_id).await?;
        Self::remove_artifact_root(&self.sandbox_artifact_root(sandbox_id)).await?;
        Ok(())
    }

    async fn cleanup_orphan_artifacts(
        &self,
        retained_sandbox_ids: &HashSet<SandboxId>,
    ) -> PersistenceResult<()> {
        let artifacts_root = self.artifacts_root();
        let mut entries = match fs::read_dir(&artifacts_root).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(SandboxPersistenceError::io(
                    "read paused sandbox artifacts",
                    &artifacts_root,
                    source,
                ));
            }
        };

        while let Some(entry) = entries.next_entry().await.map_err(|source| {
            SandboxPersistenceError::io("scan paused sandbox artifacts", &artifacts_root, source)
        })? {
            let file_type = entry.file_type().await.map_err(|source| {
                SandboxPersistenceError::io(
                    "inspect paused sandbox artifacts",
                    entry.path(),
                    source,
                )
            })?;
            if !file_type.is_dir() {
                continue;
            }

            let Some(sandbox_id) = entry
                .file_name()
                .to_str()
                .and_then(|name| SandboxId::parse_str(name).ok())
            else {
                continue;
            };

            if !retained_sandbox_ids.contains(&sandbox_id) {
                info!(
                    sandbox_id = %sandbox_id,
                    artifacts = %entry.path().display(),
                    "removing orphaned paused sandbox artifacts"
                );
                Self::remove_artifact_root(&entry.path()).await?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl SandboxPersister for FileBackedSandboxPersister {
    async fn load_all<F>(&self, factory: &F) -> PersistenceResult<Vec<SandboxMetadata>>
    where
        F: SandboxBackendFactory,
    {
        info!(store = %self.root.display(), "loading paused sandbox records");
        let records = self.db().await?.entries().await.map_err(|source| {
            SandboxPersistenceError::store("scan paused sandbox records", source)
        })?;
        let mut sandboxes = Vec::new();
        let mut retained_artifacts = HashSet::new();

        for (key, bytes) in records {
            let sandbox_id_from_key = std::str::from_utf8(&key)
                .ok()
                .and_then(|value| SandboxId::parse_str(value).ok());
            let mut record = match decode_record(&bytes) {
                Ok(record) => record,
                Err(err) => {
                    warn!(record_key = %String::from_utf8_lossy(&key), error = %err, "discarding invalid paused sandbox record");
                    if let Some(sandbox_id) = sandbox_id_from_key {
                        let _ = self.remove_record(&sandbox_id).await;
                    }
                    continue;
                }
            };
            let sandbox_id = record.metadata.id;

            if record.lifecycle == PersistedPausedLifecycle::Resumed {
                info!(sandbox_id = %sandbox_id, "finishing committed resumed sandbox cleanup");
                self.finalize_resumed_record(&sandbox_id).await?;
                // Do not let the generic orphan sweep remove any sibling
                // generation here. This cleanup is intentionally exact.
                retained_artifacts.insert(sandbox_id);
                continue;
            }

            if record.lifecycle == PersistedPausedLifecycle::Resuming {
                if host_reboot_proves_runtime_absent(
                    record.resuming_boot_id.as_deref(),
                    current_host_boot_id().as_deref(),
                ) {
                    info!(sandbox_id = %sandbox_id, "host reboot proved interrupted resumed runtime absent; restoring paused record");
                    record.lifecycle = PersistedPausedLifecycle::Paused;
                    record.resuming_boot_id = None;
                    record.metadata.paused_runtime_stopped = true;
                    self.put_record(&record).await?;
                } else {
                    warn!(sandbox_id = %sandbox_id, "retaining paused sandbox record left in resuming state until a later host boot proves runtime absence");
                    retained_artifacts.insert(sandbox_id);
                    if record.metadata.virtualization_mode != self.virtualization_mode {
                        let mut metadata = record.into_metadata_without_runtime_state();
                        metadata.paused_runtime_stopped = false;
                        metadata.resume_recovery_pending = true;
                        sandboxes.push(metadata);
                    } else {
                        match record.into_recovery_pending_metadata(factory) {
                            Ok(metadata) => sandboxes.push(metadata),
                            Err(err) => {
                                warn!(sandbox_id = %sandbox_id, error = %err, "retaining interrupted resume whose paused state could not be decoded");
                            }
                        }
                    }
                    continue;
                }
            }

            if record.metadata.virtualization_mode != self.virtualization_mode {
                warn!(
                    sandbox_id = %sandbox_id,
                    record_mode = %record.metadata.virtualization_mode,
                    node_mode = %self.virtualization_mode,
                    "loading paused sandbox metadata without resumable runtime state because its virtualization mode is incompatible"
                );
                retained_artifacts.insert(sandbox_id);
                sandboxes.push(record.into_metadata_without_runtime_state());
                continue;
            }

            match record.into_metadata(factory) {
                Ok(metadata) => {
                    retained_artifacts.insert(sandbox_id);
                    sandboxes.push(metadata);
                }
                Err(err) => {
                    warn!(sandbox_id = %sandbox_id, error = %err, "discarding unusable paused sandbox record");
                    self.cleanup_invalid_record(&sandbox_id).await?;
                }
            }
        }

        self.cleanup_orphan_artifacts(&retained_artifacts).await?;

        info!(
            loaded = sandboxes.len(),
            retained = retained_artifacts.len(),
            "loaded paused sandbox records"
        );

        Ok(sandboxes)
    }

    async fn allocate_artifact_root(
        &self,
        sandbox_id: &SandboxId,
    ) -> PersistenceResult<Option<PathBuf>> {
        let artifact_root = self
            .sandbox_artifact_root(sandbox_id)
            .join(Uuid::now_v7().to_string());
        fs::create_dir_all(&artifact_root).await.map_err(|source| {
            SandboxPersistenceError::io(
                "allocate paused sandbox artifact root",
                &artifact_root,
                source,
            )
        })?;
        Ok(Some(artifact_root))
    }

    async fn persist_paused(
        &self,
        metadata: &SandboxMetadata,
        artifact_root: Option<&Path>,
        paused_state: &dyn PausedSandboxState,
    ) -> PersistenceResult<()> {
        let artifact_root = artifact_root.ok_or_else(|| SandboxPersistenceError::RuntimeState {
            reason: "file-backed persister requires an allocated artifact root",
        })?;
        debug!(
            sandbox_id = %metadata.id,
            artifact_root = %artifact_root.display(),
            "persisting paused sandbox"
        );
        let state = match paused_state.encode() {
            Ok(state) => state,
            Err(source) => {
                let _ = Self::remove_artifact_root(artifact_root).await;
                return Err(SandboxPersistenceError::InvalidRecord {
                    reason: "failed to encode paused sandbox state".to_string(),
                    source: Some(source),
                });
            }
        };
        let record = PersistedPausedRecord {
            version: RECORD_VERSION,
            lifecycle: PersistedPausedLifecycle::Paused,
            resuming_boot_id: None,
            metadata: metadata.clone(),
            artifact_root: artifact_root.to_path_buf(),
            state,
        };
        let result = self.put_record(&record).await;
        if result.is_err() {
            let _ = Self::remove_artifact_root(artifact_root).await;
        }
        result
    }

    async fn mark_paused_runtime_stopped(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        debug!(sandbox_id = %sandbox_id, "marking paused runtime as stopped");
        let mut record = self.get_record(sandbox_id).await?;
        if record.lifecycle != PersistedPausedLifecycle::Paused {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "cannot mark paused runtime {sandbox_id} stopped while record is {:?}",
                    record.lifecycle
                ),
                source: None,
            });
        }
        record.metadata.paused_runtime_stopped = true;
        self.put_record(&record).await
    }

    async fn mark_resuming(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        debug!(sandbox_id = %sandbox_id, "marking paused sandbox as resuming");
        let boot_id = current_host_boot_id().ok_or_else(|| SandboxPersistenceError::InvalidRecord {
            reason: format!(
                "cannot mark paused sandbox {sandbox_id} resuming because the Linux host boot ID is unavailable"
            ),
            source: None,
        })?;
        let mut record = self.get_record(sandbox_id).await?;
        record.lifecycle = PersistedPausedLifecycle::Resuming;
        record.resuming_boot_id = Some(boot_id);
        record.metadata.paused_runtime_stopped = false;
        self.put_record(&record).await
    }

    async fn rollback_resuming(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        debug!(sandbox_id = %sandbox_id, "rolling back paused sandbox to paused");
        let mut record = self.get_record(sandbox_id).await?;
        record.lifecycle = PersistedPausedLifecycle::Paused;
        record.resuming_boot_id = None;
        record.metadata.paused_runtime_stopped = false;
        self.put_record(&record).await
    }

    async fn delete_record(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        debug!(sandbox_id = %sandbox_id, "committing resumed sandbox record cleanup");
        self.finalize_resumed_record(sandbox_id).await
    }

    async fn delete_record_and_artifacts(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        debug!(sandbox_id = %sandbox_id, "deleting paused sandbox record and artifacts");
        self.remove_record(sandbox_id).await?;
        Self::remove_artifact_root(&self.sandbox_artifact_root(sandbox_id)).await?;
        Ok(())
    }

    async fn load_create_idempotency_records(
        &self,
    ) -> PersistenceResult<Vec<CreateIdempotencyRecord>> {
        let entries = self
            .create_idempotency_db()
            .await?
            .entries()
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("scan create idempotency records", source)
            })?;
        let mut records = Vec::with_capacity(entries.len());
        for (key, bytes) in entries {
            let stored_key = String::from_utf8(key).map_err(|source| {
                SandboxPersistenceError::InvalidRecord {
                    reason: "create idempotency record key is not UTF-8".to_string(),
                    source: Some(source.into()),
                }
            })?;
            let record = decode_create_idempotency_record(&bytes)?;
            if record.key != stored_key {
                return Err(SandboxPersistenceError::InvalidRecord {
                    reason: format!(
                        "create idempotency record key mismatch: database key '{stored_key}' contains '{}'",
                        record.key
                    ),
                    source: None,
                });
            }
            records.push(record);
        }
        Ok(records)
    }

    async fn persist_create_idempotency_record(
        &self,
        record: &CreateIdempotencyRecord,
    ) -> PersistenceResult<()> {
        if record.key.is_empty() || record.request_fingerprint.is_empty() {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: "create idempotency record has an empty key or fingerprint".to_string(),
                source: None,
            });
        }
        let bytes = serde_json::to_vec(&PersistedCreateIdempotencyRecord {
            version: CREATE_IDEMPOTENCY_RECORD_VERSION,
            record: record.clone(),
        })
        .map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "failed to serialize create idempotency record".to_string(),
            source: Some(source.into()),
        })?;
        self.create_idempotency_db()
            .await?
            .put(record.key.as_bytes().to_vec(), bytes)
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("persist create idempotency record", source)
            })
    }

    async fn delete_create_idempotency_record(&self, key: &str) -> PersistenceResult<()> {
        self.create_idempotency_db()
            .await?
            .delete(key.as_bytes().to_vec())
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("delete create idempotency record", source)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::persistence::CreateIdempotencyRecordState;
    use crate::sandbox::{
        mock::{MockBackendFactory, MockSnapshot},
        FreshSandboxBuildSpec, PausedSandboxState, RuntimeArtifactSet, SandboxBackend,
        SandboxLaunchConfig,
    };
    use crate::snapshot::RunnableSnapshot;
    use anyhow::Result;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    #[derive(Debug)]
    struct FailingEncodeState;

    impl PausedSandboxState for FailingEncodeState {
        fn encode(&self) -> Result<Value> {
            anyhow::bail!("forced encode failure")
        }

        fn runtime_artifacts(&self) -> RuntimeArtifactSet {
            RuntimeArtifactSet::empty()
        }
    }

    #[derive(Default)]
    struct RejectingFactory;

    impl SandboxBackendFactory for RejectingFactory {
        fn build(
            &self,
            _build_spec: FreshSandboxBuildSpec,
            _launch_config: SandboxLaunchConfig,
        ) -> Result<Box<dyn SandboxBackend>> {
            unreachable!("persister tests only decode state")
        }

        fn build_from_snapshot(
            &self,
            _snapshot: &RunnableSnapshot,
            _launch_config: SandboxLaunchConfig,
        ) -> Result<Box<dyn SandboxBackend>> {
            unreachable!("persister tests only decode state")
        }

        fn build_from_paused_state(
            &self,
            _sandbox_id: SandboxId,
            _state: &dyn PausedSandboxState,
            _envd_access_token: Option<crate::sandbox::EnvdAccessToken>,
        ) -> Result<Box<dyn SandboxBackend>> {
            unreachable!("persister tests only decode state")
        }

        fn decode_paused_state(
            &self,
            _artifact_root: PathBuf,
            _state: Value,
        ) -> Result<Arc<dyn PausedSandboxState>> {
            anyhow::bail!("forced decode failure")
        }
    }

    fn paused_state(root: &Path) -> Arc<dyn PausedSandboxState> {
        std::fs::create_dir_all(root).expect("create test artifact root");
        Arc::new(MockSnapshot)
    }

    fn test_persister(root: &Path) -> FileBackedSandboxPersister {
        FileBackedSandboxPersister::new_for_test(root.to_path_buf())
            .with_durability(LocalStoreDurability::Memory)
    }

    async fn persist_test_record(
        persister: &FileBackedSandboxPersister,
        snapshot_root: &Path,
    ) -> anyhow::Result<(SandboxId, Arc<dyn PausedSandboxState>)> {
        let paused_state = paused_state(snapshot_root);
        let metadata = SandboxMetadata {
            id: SandboxId::new(),
            virtualization_mode: persister.virtualization_mode,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        let sandbox_id = metadata.id;
        persister
            .persist_paused(&metadata, Some(snapshot_root), paused_state.as_ref())
            .await?;
        Ok((sandbox_id, paused_state))
    }

    async fn has_record(
        persister: &FileBackedSandboxPersister,
        sandbox_id: &SandboxId,
    ) -> anyhow::Result<bool> {
        Ok(persister
            .db()
            .await?
            .get(sandbox_id.to_string())
            .await?
            .is_some())
    }

    #[tokio::test]
    async fn create_idempotency_journal_round_trips_and_deletes() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let mut record = CreateIdempotencyRecord {
            key: "create-journal-roundtrip".to_string(),
            request_fingerprint: "sha256:journal-roundtrip".to_string(),
            sandbox_id: SandboxId::new(),
            state: CreateIdempotencyRecordState::Creating,
        };

        persister.persist_create_idempotency_record(&record).await?;
        assert_eq!(
            persister.load_create_idempotency_records().await?,
            vec![record.clone()]
        );

        record.state = CreateIdempotencyRecordState::Succeeded;
        persister.persist_create_idempotency_record(&record).await?;
        assert_eq!(
            persister.load_create_idempotency_records().await?,
            vec![record.clone()]
        );

        persister
            .delete_create_idempotency_record(&record.key)
            .await?;
        assert!(persister
            .load_create_idempotency_records()
            .await?
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn file_persister_round_trips_paused_record() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            timeout: Some(Duration::from_secs(5)),
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };

        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;
        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, metadata.id);
        assert!(loaded[0]
            .paused_state
            .as_ref()
            .expect("paused state should be restored")
            .downcast_ref::<MockSnapshot>()
            .is_some());
        Ok(())
    }

    #[tokio::test]
    async fn paused_record_from_other_mode_is_visible_but_not_resumable() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let kvm_persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        let (sandbox_id, _paused_state) =
            persist_test_record(&kvm_persister, &snapshot_root).await?;
        drop(kvm_persister);
        let pvm_persister =
            FileBackedSandboxPersister::new(temp.path().to_path_buf(), VirtualizationMode::Pvm)
                .with_durability(LocalStoreDurability::Memory);

        let loaded = pvm_persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, sandbox_id);
        assert_eq!(loaded[0].state, SandboxState::Paused);
        assert_eq!(loaded[0].virtualization_mode, VirtualizationMode::Kvm);
        assert!(loaded[0].paused_state.is_none());
        assert!(has_record(&pvm_persister, &sandbox_id).await?);
        assert!(snapshot_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn mixed_mode_records_are_both_visible_and_retained() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let kvm_persister = test_persister(temp.path());
        let kvm_root = temp.path().join("kvm-artifacts");
        let (kvm_id, _kvm_state) = persist_test_record(&kvm_persister, &kvm_root).await?;
        drop(kvm_persister);

        let pvm_persister =
            FileBackedSandboxPersister::new(temp.path().to_path_buf(), VirtualizationMode::Pvm)
                .with_durability(LocalStoreDurability::Memory);
        let pvm_root = temp.path().join("pvm-artifacts");
        let (pvm_id, _pvm_state) = persist_test_record(&pvm_persister, &pvm_root).await?;

        let mut loaded = pvm_persister.load_all(&MockBackendFactory::new()).await?;
        loaded.sort_by_key(|metadata| metadata.id);

        let kvm_metadata = loaded
            .iter()
            .find(|metadata| metadata.id == kvm_id)
            .expect("KVM metadata should remain visible");
        assert_eq!(kvm_metadata.virtualization_mode, VirtualizationMode::Kvm);
        assert!(kvm_metadata.paused_state.is_none());

        let pvm_metadata = loaded
            .iter()
            .find(|metadata| metadata.id == pvm_id)
            .expect("PVM metadata should load");
        assert_eq!(pvm_metadata.virtualization_mode, VirtualizationMode::Pvm);
        assert!(pvm_metadata.paused_state.is_some());

        assert!(has_record(&pvm_persister, &kvm_id).await?);
        assert!(has_record(&pvm_persister, &pvm_id).await?);
        assert!(kvm_root.exists());
        assert!(pvm_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn allocate_artifact_root_creates_unique_snapshot_roots() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();

        let first_root = persister
            .allocate_artifact_root(&sandbox_id)
            .await?
            .expect("file-backed persister should allocate artifact root");
        let second_root = persister
            .allocate_artifact_root(&sandbox_id)
            .await?
            .expect("file-backed persister should allocate artifact root");
        let sandbox_id_dir = sandbox_id.to_string();

        assert_ne!(first_root, second_root);
        assert!(first_root.is_dir());
        assert!(second_root.is_dir());
        assert_eq!(
            first_root.parent().and_then(Path::file_name),
            Some(std::ffi::OsStr::new(&sandbox_id_dir))
        );
        assert_eq!(
            first_root
                .parent()
                .and_then(Path::parent)
                .and_then(Path::file_name),
            Some(std::ffi::OsStr::new("artifacts"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn resuming_records_are_retained_as_same_boot_recovery_tombstones() -> anyhow::Result<()>
    {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = persister
            .sandbox_artifact_root(&sandbox_id)
            .join("snapshot");
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };

        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;
        persister.mark_resuming(&metadata.id).await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, metadata.id);
        assert_eq!(loaded[0].state, SandboxState::Paused);
        assert!(loaded[0].resume_recovery_pending);
        assert!(loaded[0].paused_state.is_some());
        assert!(has_record(&persister, &metadata.id).await?);
        assert!(persister.sandbox_artifact_root(&metadata.id).exists());
        Ok(())
    }

    #[tokio::test]
    async fn later_boot_reconciles_resuming_record_to_paused() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = persister
            .sandbox_artifact_root(&sandbox_id)
            .join("snapshot");
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;
        persister.mark_resuming(&sandbox_id).await?;

        // Model a record inherited from a prior Linux boot. A distinct boot
        // identity is the positive absence proof for the old Firecracker VM.
        let mut record = persister.get_record(&sandbox_id).await?;
        let current_boot = current_host_boot_id().expect("Linux test host has a boot ID");
        record.resuming_boot_id = Some(format!("{current_boot}-previous"));
        persister.put_record(&record).await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert!(!loaded[0].resume_recovery_pending);
        assert!(loaded[0].paused_runtime_stopped);
        let record = persister.get_record(&sandbox_id).await?;
        assert_eq!(record.lifecycle, PersistedPausedLifecycle::Paused);
        assert!(record.resuming_boot_id.is_none());
        assert!(snapshot_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn persist_paused_accepts_backend_agnostic_state() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata::default();

        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;
        drop(paused_state);

        assert!(snapshot_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn persist_paused_cleans_artifacts_when_encode_fails() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        tokio::fs::create_dir_all(&snapshot_root).await?;
        let paused_state: Arc<dyn PausedSandboxState> = Arc::new(FailingEncodeState);
        let err = persister
            .persist_paused(
                &SandboxMetadata::default(),
                Some(&snapshot_root),
                paused_state.as_ref(),
            )
            .await
            .expect_err("encode failure should reject paused state");

        assert!(matches!(err, SandboxPersistenceError::InvalidRecord { .. }));
        assert!(!snapshot_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn mark_resuming_and_rollback_preserve_loadability() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        let (sandbox_id, _paused_state) = persist_test_record(&persister, &snapshot_root).await?;

        persister.mark_resuming(&sandbox_id).await?;
        assert_eq!(
            persister.get_record(&sandbox_id).await?.lifecycle,
            PersistedPausedLifecycle::Resuming
        );

        persister.rollback_resuming(&sandbox_id).await?;
        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, sandbox_id);
        assert!(snapshot_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn successful_resume_removes_only_the_consumed_generation() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let consumed_generation = persister
            .allocate_artifact_root(&sandbox_id)
            .await?
            .expect("file-backed persister should allocate artifacts");
        let next_generation = persister
            .allocate_artifact_root(&sandbox_id)
            .await?
            .expect("file-backed persister should allocate artifacts");
        let paused_state = paused_state(&consumed_generation);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&consumed_generation), paused_state.as_ref())
            .await?;
        persister.mark_resuming(&sandbox_id).await?;

        persister.delete_record(&sandbox_id).await?;

        assert!(!has_record(&persister, &sandbox_id).await?);
        assert!(!consumed_generation.exists());
        assert!(next_generation.exists());
        Ok(())
    }

    #[tokio::test]
    async fn startup_finishes_committed_resumed_generation_cleanup() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let consumed_generation = persister
            .allocate_artifact_root(&sandbox_id)
            .await?
            .expect("file-backed persister should allocate artifacts");
        let sibling_generation = persister
            .allocate_artifact_root(&sandbox_id)
            .await?
            .expect("file-backed persister should allocate artifacts");
        let paused_state = paused_state(&consumed_generation);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&consumed_generation), paused_state.as_ref())
            .await?;
        persister.mark_resuming(&sandbox_id).await?;
        let mut record = persister.get_record(&sandbox_id).await?;
        record.lifecycle = PersistedPausedLifecycle::Resumed;
        record.resuming_boot_id = None;
        persister.put_record(&record).await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert!(loaded.is_empty());
        assert!(!has_record(&persister, &sandbox_id).await?);
        assert!(!consumed_generation.exists());
        assert!(sibling_generation.exists());
        Ok(())
    }

    #[tokio::test]
    async fn load_all_removes_orphan_artifacts_without_records() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let artifact_root = persister
            .sandbox_artifact_root(&sandbox_id)
            .join("resumed-generation");
        tokio::fs::create_dir_all(&artifact_root).await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert!(loaded.is_empty());
        assert!(!persister.sandbox_artifact_root(&sandbox_id).exists());
        Ok(())
    }

    #[tokio::test]
    async fn load_all_keeps_artifacts_for_valid_paused_record() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = persister
            .sandbox_artifact_root(&sandbox_id)
            .join("paused-generation");
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert!(persister.sandbox_artifact_root(&sandbox_id).exists());
        Ok(())
    }

    #[tokio::test]
    async fn delete_record_and_artifacts_removes_both() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = persister
            .sandbox_artifact_root(&sandbox_id)
            .join("snapshot");
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;

        persister.delete_record_and_artifacts(&sandbox_id).await?;

        assert!(!has_record(&persister, &sandbox_id).await?);
        assert!(!persister.sandbox_artifact_root(&sandbox_id).exists());
        Ok(())
    }

    #[tokio::test]
    async fn delete_record_and_artifacts_removes_artifacts_without_record() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let sandbox_artifact_root = persister.sandbox_artifact_root(&sandbox_id);
        tokio::fs::create_dir_all(sandbox_artifact_root.join("stale-generation")).await?;

        persister.delete_record_and_artifacts(&sandbox_id).await?;

        assert!(!sandbox_artifact_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn delete_record_and_artifacts_removes_invalid_record() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        persister
            .db()
            .await?
            .put(sandbox_id.to_string(), b"not-json")
            .await?;

        persister.delete_record_and_artifacts(&sandbox_id).await?;

        assert!(!has_record(&persister, &sandbox_id).await?);
        Ok(())
    }

    #[tokio::test]
    async fn load_all_discards_invalid_record() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        persister
            .db()
            .await?
            .put(sandbox_id.to_string(), b"not-json")
            .await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert!(loaded.is_empty());
        assert!(!has_record(&persister, &sandbox_id).await?);
        Ok(())
    }

    #[tokio::test]
    async fn load_all_discards_unusable_record_and_artifacts() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = persister
            .sandbox_artifact_root(&sandbox_id)
            .join("snapshot");
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;

        let loaded = persister.load_all(&RejectingFactory).await?;

        assert!(loaded.is_empty());
        assert!(!has_record(&persister, &sandbox_id).await?);
        assert!(!persister.sandbox_artifact_root(&sandbox_id).exists());
        Ok(())
    }
}
