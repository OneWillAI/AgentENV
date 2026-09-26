use std::collections::{HashMap, HashSet};
use std::fs as stdfs;
use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::codecs::{
    decode_paused_index, decode_record, sha256_hex, ManifestEntry, PersistedPausedIndex,
    PersistedPausedRecord, PAUSED_INDEX_VERSION, PAUSED_MANIFEST_FILE, PAUSED_MANIFEST_VERSION,
    PAUSED_RECOVERY_MARKER_FILE, QUARANTINE_VERSION,
};
use super::paused_transactions::{
    PersistedPausedCommitState, PersistedPausedLifecycle, StopProofReconciliation,
};
use super::recovery::{
    ManifestReconciliation, PausedRecoveryBlocks, PausedSandboxQuarantine,
    PausedSandboxRecoveryReport, PersistedRecordLoad, PurgeableArtifactTarget,
    QuarantinePurgeAction, StoredPausedSandboxQuarantine,
};
use super::{
    CreateIdempotencyRecord, PersistenceResult, SandboxPersistenceError, SandboxPersister,
};
use crate::local_store::{LocalKvStore, LocalStoreDurability};
use crate::orchestrator::store::SandboxMetadata;
#[cfg(test)]
use crate::orchestrator::SandboxState;
use crate::sandbox::{PausedSandboxState, SandboxBackendFactory};
use crate::types::SandboxId;
use crate::virtualization::VirtualizationMode;

const RECORD_DB_DIR: &str = "records.db";
const QUARANTINE_DB_DIR: &str = "quarantine.db";
const CREATE_IDEMPOTENCY_DB_DIR: &str = "create-idempotency.db";

fn current_host_boot_id() -> Option<String> {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let boot_id = boot_id.trim();
    (!boot_id.is_empty()).then(|| boot_id.to_owned())
}

pub struct FileBackedSandboxPersister {
    root: PathBuf,
    virtualization_mode: VirtualizationMode,
    durability: LocalStoreDurability,
    db: OnceCell<LocalKvStore>,
    quarantine_db: OnceCell<LocalKvStore>,
    create_idempotency_db: OnceCell<LocalKvStore>,
}

impl FileBackedSandboxPersister {
    pub fn new(root: PathBuf, virtualization_mode: VirtualizationMode) -> Self {
        Self {
            root,
            virtualization_mode,
            durability: LocalStoreDurability::Sync,
            db: OnceCell::new(),
            quarantine_db: OnceCell::new(),
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


    fn manifest_path(artifact_root: &Path) -> PathBuf {
        artifact_root.join(PAUSED_MANIFEST_FILE)
    }

    fn recovery_marker_path(artifact_root: &Path) -> PathBuf {
        artifact_root.join(PAUSED_RECOVERY_MARKER_FILE)
    }

    fn validated_managed_artifact_path(&self, path: &Path) -> Option<PathBuf> {
        super::managed_paths::validated_artifact_path(
            &self.root,
            &self.records_db_path(),
            &self.quarantine_db_path(),
            &self.create_idempotency_db_path(),
            path,
        )
    }

    fn path_is_managed_artifact(&self, path: &Path) -> bool {
        self.validated_managed_artifact_path(path).is_some()
    }

    fn validated_managed_generation_path(
        &self,
        sandbox_id: &SandboxId,
        path: &Path,
    ) -> Option<PathBuf> {
        super::managed_paths::validated_generation_path(&self.root, sandbox_id, path)
    }

    fn path_is_managed_generation(&self, sandbox_id: &SandboxId, path: &Path) -> bool {
        self.validated_managed_generation_path(sandbox_id, path)
            .is_some()
    }

    /// The leftover `<store>/artifacts/<sandbox-id>` directory after the index
    /// is gone. Purge may remove that exact tree; it still refuses `..` and
    /// anything that is not this sandbox's managed root.
    fn validated_managed_sandbox_root_path(
        &self,
        sandbox_id: &SandboxId,
        path: &Path,
    ) -> Option<PathBuf> {
        super::managed_paths::validated_sandbox_root_path(&self.root, sandbox_id, path)
    }















    async fn recovery_blocks(&self) -> PersistenceResult<PausedRecoveryBlocks> {
        let mut blocks = PausedRecoveryBlocks::default();
        for entry in self.stored_quarantines().await? {
            if !entry.requires_manual_recovery {
                continue;
            }
            if let Some(sandbox_id) = entry
                .record_key
                .as_deref()
                .and_then(|record_key| SandboxId::parse_str(record_key).ok())
            {
                blocks.sandbox_ids.insert(sandbox_id);
            }
            if let Some(artifact_root) = entry.artifact_root {
                blocks.artifact_roots.insert(artifact_root);
            }
            if let Some(manifest_path) = entry.manifest_path {
                blocks.manifest_paths.insert(manifest_path);
            }
        }
        Ok(blocks)
    }


    async fn get_record(&self, sandbox_id: &SandboxId) -> PersistenceResult<PersistedPausedRecord> {
        let key = sandbox_id.to_string();
        let bytes = self
            .db()
            .await?
            .get(key.as_bytes().to_vec())
            .await
            .map_err(|source| SandboxPersistenceError::store("read paused sandbox record", source))?
            .ok_or_else(|| SandboxPersistenceError::InvalidRecord {
                reason: format!("paused sandbox record {sandbox_id} not found"),
                source: None,
            })?;
        let index = decode_paused_index(&bytes)?;
        self.resolve_index(sandbox_id, &index).await
    }



    async fn write_manifest(
        &self,
        record: &PersistedPausedRecord,
    ) -> PersistenceResult<ManifestEntry> {
        let manifest_path = Self::manifest_path(&record.artifact_root);
        let bytes = serde_json::to_vec(record).map_err(|source| {
            SandboxPersistenceError::InvalidRecord {
                reason: "failed to serialize paused sandbox manifest".to_string(),
                source: Some(source.into()),
            }
        })?;
        let root = self.root.clone();
        let manifest_path_for_write = manifest_path.clone();
        let bytes_for_write = bytes.clone();
        tokio::task::spawn_blocking(move || {
            super::durable_storage::write_file_atomically_and_sync(
                &manifest_path_for_write,
                &bytes_for_write,
                &root,
            )
        })
        .await
        .map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "join paused sandbox manifest write task".to_string(),
            source: Some(source.into()),
        })?
        .map_err(|source| {
            SandboxPersistenceError::io("write paused sandbox manifest", &manifest_path, source)
        })?;
        Ok(ManifestEntry {
            path: manifest_path,
            bytes,
            record: record.clone(),
            recovery_marker_present: false,
        })
    }

    async fn write_recovery_marker(
        &self,
        sandbox_id: SandboxId,
        artifact_root: &Path,
    ) -> PersistenceResult<()> {
        let marker_path = Self::recovery_marker_path(artifact_root);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "version": PAUSED_MANIFEST_VERSION,
            "sandboxId": sandbox_id,
        }))
        .map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "failed to serialize paused sandbox recovery marker".to_string(),
            source: Some(source.into()),
        })?;
        let root = self.root.clone();
        let marker_path_for_write = marker_path.clone();
        tokio::task::spawn_blocking(move || {
            super::durable_storage::write_file_atomically_and_sync(
                &marker_path_for_write,
                &bytes,
                &root,
            )
        })
        .await
        .map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "join paused sandbox recovery marker write task".to_string(),
            source: Some(source.into()),
        })?
        .map_err(|source| {
            SandboxPersistenceError::io(
                "write paused sandbox recovery marker",
                &marker_path,
                source,
            )
        })
    }

    async fn remove_recovery_marker(&self, artifact_root: &Path) -> PersistenceResult<()> {
        let marker_path = Self::recovery_marker_path(artifact_root);
        let root = self.root.clone();
        let marker_path_for_remove = marker_path.clone();
        tokio::task::spawn_blocking(move || {
            super::durable_storage::remove_file_and_sync(&marker_path_for_remove, &root)
        })
        .await
        .map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "join paused sandbox recovery marker removal task".to_string(),
            source: Some(source.into()),
        })?
        .map_err(|source| {
            SandboxPersistenceError::io(
                "remove paused sandbox recovery marker",
                &marker_path,
                source,
            )
        })
    }

    async fn write_index(&self, entry: &ManifestEntry) -> PersistenceResult<()> {
        let index = PersistedPausedIndex {
            index_version: PAUSED_INDEX_VERSION,
            sandbox_id: entry.sandbox_id(),
            manifest_path: entry.path.clone(),
            manifest_sha256: entry.fingerprint(),
        };
        let bytes = serde_json::to_vec(&index).map_err(|source| {
            SandboxPersistenceError::InvalidRecord {
                reason: "failed to serialize paused sandbox index".to_string(),
                source: Some(source.into()),
            }
        })?;
        self.db()
            .await?
            .put(index.sandbox_id.to_string(), bytes)
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("persist paused sandbox index", source)
            })
    }

    /// Publish a v2 record through an explicit prepared/committed transition.
    /// Every acknowledged state has a synced manifest before RocksDB points at
    /// it; every ambiguous error leaves a recovery-pending manifest and keeps
    /// all artifacts for a later reconcile.
    async fn put_record(&self, record: &PersistedPausedRecord) -> PersistenceResult<()> {
        let sandbox_id = record.metadata.id;
        let artifact_root = record.artifact_root.clone();
        if !self.path_is_managed_generation(&sandbox_id, &artifact_root) {
            let record_key = sandbox_id.to_string();
            self.quarantine(
                "paused sandbox record references an artifact root outside the managed persisted store",
                Some(record_key.as_bytes()),
                None,
                Some(&artifact_root),
                Some(&Self::manifest_path(&artifact_root)),
            )
            .await?;
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "paused sandbox {sandbox_id} artifact root is outside the managed persisted store"
                ),
                source: None,
            });
        }
        let mut prepared = record.clone();
        prepared.version = PAUSED_MANIFEST_VERSION;
        prepared.commit_state = PersistedPausedCommitState::Prepared;
        prepared.metadata.resume_recovery_pending = true;
        prepared.metadata.paused_runtime_stopped = false;
        let _prepared_entry = match self.write_manifest(&prepared).await {
            Ok(entry) => entry,
            Err(source) => {
                return Err(self
                    .quarantine_uncertain_commit(
                        record,
                        "failed to durably publish prepared paused sandbox manifest",
                        source,
                    )
                    .await);
            }
        };
        // Keep the previous authoritative index until all new artifacts and
        // the committed manifest are durable. Prepared state is never current.

        if let Err(source) = self.write_recovery_marker(sandbox_id, &artifact_root).await {
            return Err(self
                .quarantine_uncertain_commit(
                    record,
                    "failed to durably publish paused sandbox recovery marker",
                    source,
                )
                .await);
        }

        let mut committed = record.clone();
        committed.version = PAUSED_MANIFEST_VERSION;
        committed.commit_state = PersistedPausedCommitState::Committed;
        let committed_entry = match self.write_manifest(&committed).await {
            Ok(entry) => entry,
            Err(source) => {
                return Err(self
                    .quarantine_uncertain_commit(
                        record,
                        "failed to durably commit paused sandbox manifest",
                        source,
                    )
                    .await);
            }
        };
        if let Err(source) = self.write_index(&committed_entry).await {
            return Err(self
                .quarantine_uncertain_commit(
                    record,
                    "failed to durably index committed paused sandbox manifest",
                    source,
                )
                .await);
        }
        if let Err(source) = self.remove_recovery_marker(&artifact_root).await {
            return Err(self
                .quarantine_uncertain_commit(
                    record,
                    "failed to clear paused sandbox recovery marker after final index acknowledgement",
                    source,
                )
                .await);
        }
        Ok(())
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

    async fn sync_artifact_tree(&self, artifact_root: &Path) -> PersistenceResult<()> {
        let artifact_root = artifact_root.to_path_buf();
        let sync_artifact_root = artifact_root.clone();
        let sync_root = self.root.clone();
        tokio::task::spawn_blocking(move || {
            super::durable_storage::sync_artifact_tree_and_parents(&sync_artifact_root, &sync_root)
        })
        .await
        .map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "join paused sandbox artifact sync task".to_string(),
            source: Some(source.into()),
        })?
        .map_err(|source| {
            SandboxPersistenceError::io("sync paused sandbox artifacts", artifact_root, source)
        })
    }

    async fn remove_artifact_root(path: &Path) -> PersistenceResult<()> {
        super::artifact_cleanup::remove_root(path).await
    }

    /// Destroy may leave an empty `<sandbox-id>` directory after the last
    /// generation is gone. That leftover is not recovery data: if it stays,
    /// the next delete sees "unreferenced artifacts" and fail-closes.
    async fn remove_empty_sandbox_artifact_root(
        &self,
        sandbox_id: &SandboxId,
    ) -> PersistenceResult<()> {
        let sandbox_root = self.sandbox_artifact_root(sandbox_id);
        match fs::remove_dir(&sandbox_root).await {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                Ok(())
            }
            Err(source) => Err(SandboxPersistenceError::io(
                "remove empty paused sandbox artifact root",
                sandbox_root,
                source,
            )),
        }
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
    /// Drop the paused index after a live resume. Keep the last generation:
    /// the next incremental pause still reads that memory config, and a
    /// worker restart can rehydrate it from the on-disk manifest.
    async fn finalize_resumed_record(&self, sandbox_id: &SandboxId) -> PersistenceResult<()> {
        let mut record = self.get_record(sandbox_id).await?;
        if record.metadata.resume_recovery_pending
            || record.commit_state != PersistedPausedCommitState::Committed
        {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "cannot clean paused sandbox {sandbox_id} while its persistence commit is recovery-pending"
                ),
                source: None,
            });
        }
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

        self.remove_record(sandbox_id).await
    }























}

#[async_trait]
impl SandboxPersister for FileBackedSandboxPersister {
    async fn load_all<F>(&self, factory: &F) -> PersistenceResult<Vec<SandboxMetadata>>
    where
        F: SandboxBackendFactory,
    {
        info!(store = %self.root.display(), "loading paused sandbox records");
        let (records, recovery_report) = self.reconcile_manifest_index(false).await?;
        let mut sandboxes = Vec::new();
        let mut seen_sandbox_ids = HashSet::new();

        for record in records {
            let sandbox_id = record.metadata.id;
            let record_artifact_root = record.artifact_root.clone();
            let record_manifest_path = Self::manifest_path(&record_artifact_root);
            if !seen_sandbox_ids.insert(sandbox_id) {
                self.quarantine(
                    "multiple persisted paused records claim the same sandbox ID",
                    None,
                    None,
                    Some(&record_artifact_root),
                    Some(&record_manifest_path),
                )
                .await?;
                continue;
            }

            match self.reconcile_record_lifecycle(record, factory).await? {
                PersistedRecordLoad::Complete(Some(metadata)) => sandboxes.push(metadata),
                PersistedRecordLoad::Complete(None) => {}
                PersistedRecordLoad::Continue(record) => {
                    if let Some(metadata) = self.load_reconciled_record(record, factory).await? {
                        sandboxes.push(metadata);
                    }
                }
            }
        }

        info!(
            loaded = sandboxes.len(),
            rebuilt_indexes = recovery_report.indexed_manifests,
            quarantined = recovery_report.quarantined_items,
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
        self.sync_artifact_tree(&artifact_root).await?;
        Ok(Some(artifact_root))
    }

    async fn discard_empty_capture(
        &self,
        sandbox_id: &SandboxId,
        artifact_root: &Path,
    ) -> PersistenceResult<()> {
        if matches!(fs::symlink_metadata(artifact_root).await, Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            return Ok(());
        }
        if !self.path_is_managed_generation(sandbox_id, artifact_root) {
            return Err(SandboxPersistenceError::RuntimeState {
                reason: "empty capture cleanup requires an owned generation",
            });
        }
        // rmdir is atomic and cannot erase any payload, manifest, or child
        // directory. Never use recursive deletion for a failed checkpoint.
        match fs::remove_dir(artifact_root).await {
            Ok(()) => {
                let parent = self.sandbox_artifact_root(sandbox_id);
                super::durable_storage::sync_directory_chain(&parent, &self.root).map_err(
                    |source| {
                        SandboxPersistenceError::io("sync empty capture removal", &parent, source)
                    },
                )
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                Ok(())
            }
            Err(source) => Err(SandboxPersistenceError::io(
                "remove empty capture directory",
                artifact_root,
                source,
            )),
        }
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
        let record_key = metadata.id.to_string();
        if !self.path_is_managed_generation(&metadata.id, artifact_root) {
            self.quarantine(
                "paused sandbox persistence received an artifact root outside the managed persisted store",
                Some(record_key.as_bytes()),
                None,
                Some(artifact_root),
                None,
            )
            .await?;
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: "file-backed persister requires artifact roots below its persisted store"
                    .to_string(),
                source: None,
            });
        }
        let state = match paused_state.encode() {
            Ok(state) => state,
            Err(source) => {
                self.quarantine(
                    "paused sandbox state encoding failed before metadata commit",
                    Some(record_key.as_bytes()),
                    None,
                    Some(artifact_root),
                    None,
                )
                .await?;
                return Err(SandboxPersistenceError::InvalidRecord {
                    reason: "failed to encode paused sandbox state".to_string(),
                    source: Some(source),
                });
            }
        };
        if let Err(source) = self.sync_artifact_tree(artifact_root).await {
            self.quarantine(
                format!("paused sandbox artifacts failed durability sync: {source}"),
                Some(record_key.as_bytes()),
                None,
                Some(artifact_root),
                None,
            )
            .await?;
            return Err(source);
        }
        let record = PersistedPausedRecord {
            checkpoint_at_unix_ms: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            ),
            version: PAUSED_MANIFEST_VERSION,
            commit_state: PersistedPausedCommitState::Committed,
            lifecycle: PersistedPausedLifecycle::Paused,
            resuming_boot_id: None,
            unproven_stop_boot_id: None,
            metadata: metadata.clone(),
            artifact_root: artifact_root.to_path_buf(),
            state,
        };
        self.put_record(&record).await?;
        // Retention is performed only after runtime-stop proof, with a
        // reference inventory. Publication must never delete rollback state.
        Ok(())
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
        record.unproven_stop_boot_id = None;
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
        let record = match self.get_record(sandbox_id).await {
            Ok(record) => record,
            Err(SandboxPersistenceError::InvalidRecord { reason, .. })
                if reason == format!("paused sandbox record {sandbox_id} not found") =>
            {
                let sandbox_root = self.sandbox_artifact_root(sandbox_id);
                if fs::symlink_metadata(&sandbox_root).await.is_ok() {
                    // Resume keeps the last generation after dropping the
                    // index. An explicit destroy has already proven the
                    // runtime is gone, so this last copy may be removed.
                    Self::remove_artifact_root(&sandbox_root).await?;
                    return Ok(());
                }
                return Ok(());
            }
            Err(error @ SandboxPersistenceError::InvalidRecord { .. }) => {
                let record_key = sandbox_id.to_string();
                let record_bytes = self
                    .db()
                    .await?
                    .get(record_key.as_bytes().to_vec())
                    .await
                    .map_err(|source| {
                        SandboxPersistenceError::store(
                            "read invalid paused sandbox record before delete",
                            source,
                        )
                    })?;
                self.quarantine(
                    format!(
                        "refusing automatic deletion of invalid paused sandbox record: {error}"
                    ),
                    Some(record_key.as_bytes()),
                    record_bytes.as_deref(),
                    None,
                    None,
                )
                .await?;
                return Err(SandboxPersistenceError::manual_recovery(
                    *sandbox_id,
                    format!("invalid paused sandbox record: {error}"),
                    None,
                ));
            }
            Err(error) => return Err(error),
        };
        if record.metadata.resume_recovery_pending
            || record.commit_state != PersistedPausedCommitState::Committed
        {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "refusing automatic deletion of recovery-pending paused sandbox {sandbox_id}"
                ),
                source: None,
            });
        }
        // Revalidate immediately before deletion and remove only the
        // canonical managed generation.
        let canonical_artifact_root =
            self.validated_managed_generation_path(sandbox_id, &record.artifact_root);
        let Some(canonical_artifact_root) = canonical_artifact_root else {
            let record_key = sandbox_id.to_string();
            self.quarantine(
                "refusing automatic deletion of paused sandbox record with an unsafe artifact root",
                Some(record_key.as_bytes()),
                None,
                Some(&record.artifact_root),
                Some(&Self::manifest_path(&record.artifact_root)),
            )
            .await?;
            return Err(SandboxPersistenceError::manual_recovery(
                *sandbox_id,
                "artifact root is not an exact managed generation",
                None,
            ));
        };
        // Remove the generation first. If the process dies after this, startup
        // sees a record whose artifacts are gone and quarantines it; if it
        // dies after dropping the index instead, leftover files become
        // unreferenced and used to prevent the worker from booting.
        Self::remove_artifact_root(&canonical_artifact_root).await?;
        self.remove_record(sandbox_id).await?;
        // Sibling generations stay until an administrator purges them. An
        // empty `<sandbox-id>` directory is not recovery data.
        self.remove_empty_sandbox_artifact_root(sandbox_id).await?;
        Ok(())
    }

    async fn load_create_idempotency_records(
        &self,
    ) -> PersistenceResult<Vec<CreateIdempotencyRecord>> {
        let journal = self.create_idempotency_db().await?;
        super::operation_journal::load(&journal).await
    }

    async fn persist_create_idempotency_record(
        &self,
        record: &CreateIdempotencyRecord,
    ) -> PersistenceResult<()> {
        let journal = self.create_idempotency_db().await?;
        super::operation_journal::put(&journal, record).await
    }

    async fn delete_create_idempotency_record(&self, key: &str) -> PersistenceResult<()> {
        let journal = self.create_idempotency_db().await?;
        super::operation_journal::delete(&journal, key).await
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

    fn test_snapshot_root(
        persister: &FileBackedSandboxPersister,
        sandbox_id: &SandboxId,
    ) -> PathBuf {
        persister.sandbox_artifact_root(sandbox_id).join("snapshot")
    }

    async fn persist_test_record(
        persister: &FileBackedSandboxPersister,
    ) -> anyhow::Result<(SandboxId, PathBuf, Arc<dyn PausedSandboxState>)> {
        let sandbox_id = SandboxId::new();
        let snapshot_root = test_snapshot_root(persister, &sandbox_id);
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            virtualization_mode: persister.virtualization_mode,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;
        Ok((sandbox_id, snapshot_root, paused_state))
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
        let sandbox_id = SandboxId::new();
        let snapshot_root = test_snapshot_root(&persister, &sandbox_id);
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
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
    async fn failed_index_write_is_an_uncertain_commit_that_retains_artifacts() -> anyhow::Result<()>
    {
        let temp = TempDir::new()?;
        let records_db_path = temp.path().join(RECORD_DB_DIR);
        std::fs::write(&records_db_path, b"not-a-rocksdb-directory")?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = test_snapshot_root(&persister, &sandbox_id);
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };

        let err = persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await
            .expect_err("an unavailable index must leave an uncertain commit");

        assert!(matches!(
            err,
            SandboxPersistenceError::UncertainCommit { .. }
        ));
        assert!(snapshot_root.exists());
        assert!(FileBackedSandboxPersister::manifest_path(&snapshot_root).exists());
        assert!(FileBackedSandboxPersister::recovery_marker_path(&snapshot_root).exists());
        assert_eq!(persister.list_quarantines().await?.len(), 1);
        Ok(())
    }




    #[tokio::test]
    async fn purging_a_misplaced_root_marker_cannot_remove_a_valid_sibling_generation(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = test_snapshot_root(&persister, &sandbox_id);
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;
        let misplaced_marker = persister
            .sandbox_artifact_root(&sandbox_id)
            .join(PAUSED_MANIFEST_FILE);
        std::fs::write(&misplaced_marker, b"malformed-root-marker")?;

        persister.load_all(&MockBackendFactory::new()).await?;
        let quarantine = persister
            .list_quarantines()
            .await?
            .into_iter()
            .find(|entry| entry.artifact_root.as_deref() == Some(misplaced_marker.as_path()))
            .expect("misplaced marker should be quarantined as a file target");

        persister.purge_quarantine(&quarantine.id).await?;

        assert!(!misplaced_marker.exists());
        assert!(snapshot_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn paused_record_from_other_mode_is_visible_but_not_resumable() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let kvm_persister = test_persister(temp.path());
        let (sandbox_id, snapshot_root, _paused_state) =
            persist_test_record(&kvm_persister).await?;
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
        assert!(snapshot_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn mixed_mode_records_are_both_visible_and_retained() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let kvm_persister = test_persister(temp.path());
        let (kvm_id, kvm_root, _kvm_state) = persist_test_record(&kvm_persister).await?;
        drop(kvm_persister);

        let pvm_persister =
            FileBackedSandboxPersister::new(temp.path().to_path_buf(), VirtualizationMode::Pvm)
                .with_durability(LocalStoreDurability::Memory);
        let (pvm_id, pvm_root, _pvm_state) = persist_test_record(&pvm_persister).await?;

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
        assert!(persister.sandbox_artifact_root(&metadata.id).exists());
        Ok(())
    }


    #[tokio::test]
    async fn persist_paused_accepts_backend_agnostic_state() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = test_snapshot_root(&persister, &sandbox_id);
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            ..Default::default()
        };

        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await?;
        drop(paused_state);

        assert!(snapshot_root.exists());
        Ok(())
    }



    #[tokio::test]
    async fn mark_resuming_and_rollback_preserve_loadability() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let (sandbox_id, snapshot_root, _paused_state) = persist_test_record(&persister).await?;

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
    async fn successful_resume_keeps_the_last_memory_generation() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let consumed_generation = persister
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

        assert!(consumed_generation.exists());
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
    async fn failed_capture_cleanup_removes_only_empty_owned_generations() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let id = SandboxId::new();
        for _ in 0..4 {
            let empty = persister.allocate_artifact_root(&id).await?.unwrap();
            persister.discard_empty_capture(&id, &empty).await?;
            persister.discard_empty_capture(&id, &empty).await?;
            assert!(!empty.exists());
        }
        let partial = persister.allocate_artifact_root(&id).await?.unwrap();
        std::fs::write(partial.join("payload"), b"retain uncertain data")?;
        persister.discard_empty_capture(&id, &partial).await?;
        assert_eq!(
            std::fs::read(partial.join("payload"))?,
            b"retain uncertain data"
        );
        assert!(persister
            .discard_empty_capture(&SandboxId::new(), &partial)
            .await
            .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn process_exit_before_pointer_publication_preserves_prior_checkpoint(
    ) -> anyhow::Result<()> {
        const CHILD_ROOT: &str = "AENV_PERSISTENCE_CRASH_TEST_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            let persister = FileBackedSandboxPersister::new_for_test(root.clone())
                .with_durability(LocalStoreDurability::Sync);
            let id = SandboxId::new();
            let old = persister.allocate_artifact_root(&id).await?.unwrap();
            std::fs::write(old.join("payload"), b"previous valid checkpoint")?;
            let state = paused_state(&old);
            let metadata = SandboxMetadata {
                id,
                state: SandboxState::Paused,
                paused_state: Some(Arc::clone(&state)),
                ..Default::default()
            };
            persister
                .persist_paused(&metadata, Some(&old), state.as_ref())
                .await?;
            persister.mark_paused_runtime_stopped(&id).await?;
            let old_manifest = std::fs::read(FileBackedSandboxPersister::manifest_path(&old))?;
            let old_index = persister.db().await?.get(id.to_string()).await?.unwrap();
            std::fs::write(root.join("old-manifest"), old_manifest)?;
            std::fs::write(root.join("old-index"), old_index)?;
            let new = persister.allocate_artifact_root(&id).await?.unwrap();
            std::fs::write(new.join("payload"), b"unpublished checkpoint")?;
            persister.sync_artifact_tree(&new).await?;
            let mut record = persister.get_record(&id).await?;
            record.artifact_root = new.clone();
            record.commit_state = PersistedPausedCommitState::Prepared;
            record.metadata.resume_recovery_pending = true;
            record.metadata.paused_runtime_stopped = false;
            persister.write_manifest(&record).await?;
            std::fs::write(
                root.join("fixture.json"),
                serde_json::to_vec(&(id, old, new))?,
            )?;
            // Exit without running destructors or closing RocksDB. The WAL must
            // preserve the old pointer; the Prepared sibling must block stale recovery.
            std::process::exit(73);
        }
        let temp = TempDir::new()?;
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "orchestrator::persistence::file_backed::tests::process_exit_before_pointer_publication_preserves_prior_checkpoint", "--nocapture"])
            .env(CHILD_ROOT, temp.path())
            .status()?;
        assert_eq!(status.code(), Some(73));
        let (id, old, new): (SandboxId, PathBuf, PathBuf) =
            serde_json::from_slice(&std::fs::read(temp.path().join("fixture.json"))?)?;
        let persister = FileBackedSandboxPersister::new_for_test(temp.path().to_path_buf())
            .with_durability(LocalStoreDurability::Sync);
        assert_eq!(
            persister.db().await?.get(id.to_string()).await?.unwrap(),
            std::fs::read(temp.path().join("old-index"))?
        );
        for _ in 0..2 {
            let loaded = persister.load_all(&MockBackendFactory::new()).await?;
            assert!(loaded
                .iter()
                .all(|item| item.resume_recovery_pending && !item.paused_runtime_stopped));
            assert!(!persister.list_quarantines().await?.is_empty());
            assert_eq!(
                std::fs::read(FileBackedSandboxPersister::manifest_path(&old))?,
                std::fs::read(temp.path().join("old-manifest"))?
            );
            assert_eq!(
                std::fs::read(old.join("payload"))?,
                b"previous valid checkpoint"
            );
            assert_eq!(
                std::fs::read(new.join("payload"))?,
                b"unpublished checkpoint"
            );
        }
        // A pointer to an absent generation must quarantine, not panic while
        // trying to select one of the surviving manifests.
        let mut index: serde_json::Value =
            serde_json::from_slice(&std::fs::read(temp.path().join("old-index"))?)?;
        index["manifestPath"] = serde_json::Value::String(
            temp.path()
                .join("missing/manifest.json")
                .display()
                .to_string(),
        );
        persister
            .db()
            .await?
            .put(id.to_string(), serde_json::to_vec(&index)?)
            .await?;
        let loaded = persister.load_all(&MockBackendFactory::new()).await?;
        assert!(loaded.iter().all(|item| item.resume_recovery_pending));
        Ok(())
    }

    #[tokio::test]
    async fn next_pause_preserves_the_previous_rollback_generation() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let first_generation = persister
            .allocate_artifact_root(&sandbox_id)
            .await?
            .expect("file-backed persister should allocate artifacts");
        let first_state = paused_state(&first_generation);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&first_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&first_generation), first_state.as_ref())
            .await?;
        persister.mark_resuming(&sandbox_id).await?;
        persister.delete_record(&sandbox_id).await?;

        let second_generation = persister
            .allocate_artifact_root(&sandbox_id)
            .await?
            .expect("file-backed persister should allocate artifacts");
        let second_state = paused_state(&second_generation);
        persister
            .persist_paused(&metadata, Some(&second_generation), second_state.as_ref())
            .await?;

        assert!(first_generation.exists());
        assert!(second_generation.exists());
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

        assert!(!snapshot_root.exists());
        assert!(!persister.sandbox_artifact_root(&sandbox_id).exists());
        Ok(())
    }

    #[tokio::test]
    async fn delete_record_and_artifacts_removes_the_last_copy_after_resume() -> anyhow::Result<()>
    {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let last_generation = persister
            .allocate_artifact_root(&sandbox_id)
            .await?
            .expect("file-backed persister should allocate artifacts");
        let paused_state = paused_state(&last_generation);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&last_generation), paused_state.as_ref())
            .await?;
        persister.mark_resuming(&sandbox_id).await?;
        persister.delete_record(&sandbox_id).await?;
        assert!(last_generation.exists());

        persister.delete_record_and_artifacts(&sandbox_id).await?;

        assert!(!last_generation.exists());
        assert!(!persister.sandbox_artifact_root(&sandbox_id).exists());
        assert!(persister.list_quarantines().await?.is_empty());
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
