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

/// A changed Linux boot ID proves any Firecracker child from an interrupted
/// prior AgentENV process cannot still be alive. Missing boot IDs deliberately
/// provide no proof.
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

    fn quarantine_db_path(&self) -> PathBuf {
        self.root.join(QUARANTINE_DB_DIR)
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

    async fn quarantine_db(&self) -> PersistenceResult<LocalKvStore> {
        self.quarantine_db
            .get_or_try_init(|| async {
                LocalKvStore::open(self.quarantine_db_path(), self.durability)
                    .await
                    .map_err(|source| {
                        SandboxPersistenceError::store(
                            "open paused sandbox quarantine RocksDB",
                            source,
                        )
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

    /// A raw index can be replaced only when a fully valid, same-ID v2
    /// manifest already exists.  Preserve the raw bytes in quarantine first.
    /// Recognizable but conflicting identities and unsupported formats remain
    /// blocking rather than being silently superseded.
    fn raw_index_can_be_rebuilt_from_manifest(
        bytes: &[u8],
        sandbox_id: &SandboxId,
        candidate: &ManifestEntry,
    ) -> bool {
        let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
            return true;
        };
        let Some(object) = value.as_object() else {
            return true;
        };

        if let Some(index_version) = object.get("indexVersion") {
            match index_version.as_u64() {
                Some(version) if version != u64::from(PAUSED_INDEX_VERSION) => return false,
                // A malformed version is damaged index data. Continue checking
                // any identity fields before using the coherent manifest.
                Some(_) | None => {}
            }
        }
        if let Some(raw_sandbox_id) = object.get("sandboxId").and_then(Value::as_str) {
            match SandboxId::parse_str(raw_sandbox_id) {
                Ok(index_sandbox_id) if index_sandbox_id == *sandbox_id => {}
                Ok(_) => return false,
                // Malformed index data does not override the coherent manifest.
                Err(_) => {}
            }
        }
        if let Some(raw_manifest_path) = object.get("manifestPath").and_then(Value::as_str) {
            if Path::new(raw_manifest_path) != candidate.path {
                return false;
            }
        }
        true
    }

    fn validated_purgeable_artifact_path(&self, path: &Path) -> Option<PathBuf> {
        let target = self.parse_purgeable_artifact_target(path)?;
        let canonical_artifacts = self.canonical_artifacts_root_for_purge()?;
        let sandbox_path = self.artifacts_root().join(&target.sandbox_id);
        let canonical_sandbox = Self::canonical_child_for_purge(
            &sandbox_path,
            &canonical_artifacts,
            &target.sandbox_id,
        )?;
        let canonical_parent = if let Some(generation) = target.generation.as_deref() {
            Self::canonical_child_for_purge(
                &sandbox_path.join(generation),
                &canonical_sandbox,
                generation,
            )?
        } else {
            canonical_sandbox
        };
        Self::canonical_child_for_purge(path, &canonical_parent, &target.name)
    }

    fn parse_purgeable_artifact_target(&self, path: &Path) -> Option<PurgeableArtifactTarget> {
        let relative = path.strip_prefix(self.artifacts_root()).ok()?;
        let mut components = relative.components();
        let Some(Component::Normal(sandbox_id)) = components.next() else {
            return None;
        };
        if SandboxId::parse_str(&sandbox_id.to_string_lossy()).is_err() {
            return None;
        }
        let target_components = components
            .map(|component| match component {
                Component::Normal(component) => Some(component.to_os_string()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        // Never permit recursive sandbox-root deletion: a malformed root
        // marker or bad raw index must not erase valid sibling generations.
        // A purge target is either one exact generation, or one of the two
        // metadata files at a known generation/sandbox location.
        let (name, generation) = match target_components.as_slice() {
            [] => return None,
            [name] if name == PAUSED_MANIFEST_FILE || name == PAUSED_RECOVERY_MARKER_FILE => {
                (name.clone(), None)
            }
            [generation] => (generation.clone(), None),
            [generation, name]
                if name == PAUSED_MANIFEST_FILE || name == PAUSED_RECOVERY_MARKER_FILE =>
            {
                (name.clone(), Some(generation.clone()))
            }
            _ => return None,
        };

        Some(PurgeableArtifactTarget {
            sandbox_id: sandbox_id.to_os_string(),
            generation,
            name,
        })
    }

    fn canonical_artifacts_root_for_purge(&self) -> Option<PathBuf> {
        let artifacts_root = self.artifacts_root();
        match stdfs::symlink_metadata(&artifacts_root) {
            Ok(metadata) if metadata.file_type().is_symlink() => return None,
            Ok(_) => self.validated_managed_artifact_path(&artifacts_root)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                stdfs::canonicalize(&self.root).ok()?.join("artifacts")
            }
            Err(_) => return None,
        }
        .into()
    }

    fn canonical_child_for_purge(
        path: &Path,
        canonical_parent: &Path,
        child_name: &std::ffi::OsStr,
    ) -> Option<PathBuf> {
        match stdfs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => return None,
            Ok(_) => {
                let canonical_child = stdfs::canonicalize(path).ok()?;
                (canonical_child.parent() == Some(canonical_parent)).then_some(canonical_child)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Some(canonical_parent.join(child_name))
            }
            Err(_) => return None,
        }
    }

    fn quarantine_target_for_manifest(
        &self,
        directory: &Path,
        manifest_path: &Path,
    ) -> Option<PathBuf> {
        self.validated_purgeable_artifact_path(directory)
            .map(|_| directory.to_path_buf())
            .or_else(|| {
                self.validated_purgeable_artifact_path(manifest_path)
                    .map(|_| manifest_path.to_path_buf())
            })
    }

    fn quarantine_id(
        record_key: Option<&[u8]>,
        artifact_root: Option<&Path>,
        manifest_path: Option<&Path>,
        reason: &str,
        requires_manual_recovery: bool,
        reconcile_if_coherent: bool,
    ) -> String {
        let mut hasher = Sha256::new();
        if requires_manual_recovery {
            hasher.update(b"manual:yes");
        } else {
            hasher.update(b"manual:no");
        }
        if reconcile_if_coherent {
            hasher.update(b"reconcile:yes");
        } else {
            hasher.update(b"reconcile:no");
        }
        if let Some(record_key) = record_key {
            hasher.update(b"record:");
            hasher.update(record_key);
        }
        if let Some(artifact_root) = artifact_root {
            hasher.update(b"artifact:");
            hasher.update(artifact_root.as_os_str().as_encoded_bytes());
        }
        if let Some(manifest_path) = manifest_path {
            hasher.update(b"manifest:");
            hasher.update(manifest_path.as_os_str().as_encoded_bytes());
        }
        if record_key.is_none() && artifact_root.is_none() && manifest_path.is_none() {
            hasher.update(b"reason:");
            hasher.update(reason.as_bytes());
        }
        format!("paused-{}", hex::encode(hasher.finalize()))
    }

    async fn quarantine(
        &self,
        reason: impl Into<String>,
        record_key: Option<&[u8]>,
        record_bytes: Option<&[u8]>,
        artifact_root: Option<&Path>,
        manifest_path: Option<&Path>,
    ) -> PersistenceResult<String> {
        self.quarantine_with_policy(
            reason,
            record_key,
            record_bytes,
            artifact_root,
            manifest_path,
            true,
            false,
        )
        .await
    }

    async fn quarantine_uncertain(
        &self,
        reason: impl Into<String>,
        record_key: Option<&[u8]>,
        record_bytes: Option<&[u8]>,
        artifact_root: Option<&Path>,
        manifest_path: Option<&Path>,
    ) -> PersistenceResult<String> {
        self.quarantine_with_policy(
            reason,
            record_key,
            record_bytes,
            artifact_root,
            manifest_path,
            true,
            true,
        )
        .await
    }

    /// Keep malformed index bytes for forensic recovery without making a
    /// coherent v2 manifest permanently unavailable.  The caller must have
    /// already proven the candidate manifest has the same sandbox identity.
    async fn quarantine_repairable_index(
        &self,
        reason: impl Into<String>,
        record_key: Option<&[u8]>,
        record_bytes: Option<&[u8]>,
        artifact_root: Option<&Path>,
        manifest_path: Option<&Path>,
    ) -> PersistenceResult<String> {
        self.quarantine_nonblocking(
            reason,
            record_key,
            record_bytes,
            artifact_root,
            manifest_path,
        )
        .await
    }

    async fn quarantine_nonblocking(
        &self,
        reason: impl Into<String>,
        record_key: Option<&[u8]>,
        record_bytes: Option<&[u8]>,
        artifact_root: Option<&Path>,
        manifest_path: Option<&Path>,
    ) -> PersistenceResult<String> {
        self.quarantine_with_policy(
            reason,
            record_key,
            record_bytes,
            artifact_root,
            manifest_path,
            false,
            false,
        )
        .await
    }

    async fn quarantine_with_policy(
        &self,
        reason: impl Into<String>,
        record_key: Option<&[u8]>,
        record_bytes: Option<&[u8]>,
        artifact_root: Option<&Path>,
        manifest_path: Option<&Path>,
        requires_manual_recovery: bool,
        reconcile_if_coherent: bool,
    ) -> PersistenceResult<String> {
        let reason = reason.into();
        let id = Self::quarantine_id(
            record_key,
            artifact_root,
            manifest_path,
            &reason,
            requires_manual_recovery,
            reconcile_if_coherent,
        );
        let mut entry = StoredPausedSandboxQuarantine {
            version: QUARANTINE_VERSION,
            id: id.clone(),
            reason,
            requires_manual_recovery,
            reconcile_if_coherent,
            record_key: record_key.map(|key| String::from_utf8_lossy(key).into_owned()),
            record_key_sha256: record_key.map(sha256_hex),
            record_sha256: record_bytes.map(sha256_hex),
            record_bytes_base64: record_bytes
                .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
            artifact_root: artifact_root.map(Path::to_path_buf),
            manifest_path: manifest_path.map(Path::to_path_buf),
        };
        let quarantine_db = self.quarantine_db().await?;
        // Marker discovery is intentionally idempotent. Do not discard the
        // original index hash/bytes captured by an uncertain commit merely
        // because a later startup re-inventories the same marker.
        if record_bytes.is_none() {
            if let Some(existing_bytes) =
                quarantine_db
                    .get(id.as_bytes().to_vec())
                    .await
                    .map_err(|source| {
                        SandboxPersistenceError::store("read paused sandbox quarantine", source)
                    })?
            {
                let existing: StoredPausedSandboxQuarantine =
                    serde_json::from_slice(&existing_bytes).map_err(|source| {
                        SandboxPersistenceError::InvalidRecord {
                            reason:
                                "failed to deserialize existing paused sandbox quarantine record"
                                    .to_string(),
                            source: Some(source.into()),
                        }
                    })?;
                if existing.version != QUARANTINE_VERSION {
                    return Err(SandboxPersistenceError::InvalidRecord {
                        reason: format!(
                            "unsupported existing paused sandbox quarantine version {}",
                            existing.version
                        ),
                        source: None,
                    });
                }
                entry.record_sha256 = existing.record_sha256;
                entry.record_bytes_base64 = existing.record_bytes_base64;
            }
        }
        // Marker discovery can happen after an uncertain index write has
        // returned. Capture the exact current record if it is readable so an
        // explicit purge can distinguish that known state from a later
        // replacement. Failure to read RocksDB must not prevent preserving
        // the durable marker in quarantine.
        if entry.record_sha256.is_none() {
            if let Some(record_key) = entry.record_key.clone() {
                match self.db().await {
                    Ok(db) => match db.get(record_key.as_bytes().to_vec()).await {
                        Ok(Some(current)) => {
                            entry.record_sha256 = Some(sha256_hex(&current));
                            entry.record_bytes_base64 =
                                Some(base64::engine::general_purpose::STANDARD.encode(current));
                        }
                        Ok(None) => {}
                        Err(error) => warn!(
                            error = %error,
                            "failed to read paused sandbox record while indexing quarantine"
                        ),
                    },
                    Err(error) => warn!(
                        error = %error,
                        "failed to open paused sandbox record store while indexing quarantine"
                    ),
                }
            }
        }
        let bytes = serde_json::to_vec(&entry).map_err(|source| {
            SandboxPersistenceError::InvalidRecord {
                reason: "failed to serialize paused sandbox quarantine record".to_string(),
                source: Some(source.into()),
            }
        })?;
        quarantine_db
            .put(id.as_bytes().to_vec(), bytes)
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("persist paused sandbox quarantine", source)
            })?;
        Ok(id)
    }

    async fn stored_quarantines(&self) -> PersistenceResult<Vec<StoredPausedSandboxQuarantine>> {
        let entries = self
            .quarantine_db()
            .await?
            .entries()
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("scan paused sandbox quarantine", source)
            })?;
        let mut quarantines = Vec::with_capacity(entries.len());
        for (_key, bytes) in entries {
            let entry: StoredPausedSandboxQuarantine =
                serde_json::from_slice(&bytes).map_err(|source| {
                    SandboxPersistenceError::InvalidRecord {
                        reason: "failed to deserialize paused sandbox quarantine record"
                            .to_string(),
                        source: Some(source.into()),
                    }
                })?;
            if entry.version != QUARANTINE_VERSION {
                return Err(SandboxPersistenceError::InvalidRecord {
                    reason: format!(
                        "unsupported paused sandbox quarantine version {}",
                        entry.version
                    ),
                    source: None,
                });
            }
            quarantines.push(entry);
        }
        Ok(quarantines)
    }

    async fn delete_quarantine(&self, quarantine_id: &str) -> PersistenceResult<()> {
        self.quarantine_db()
            .await?
            .delete(quarantine_id.as_bytes().to_vec())
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("delete paused sandbox quarantine", source)
            })
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

    async fn quarantine_uncertain_commit(
        &self,
        record: &PersistedPausedRecord,
        reason: impl Into<String>,
        source: SandboxPersistenceError,
    ) -> SandboxPersistenceError {
        let reason = reason.into();
        let sandbox_id = record.metadata.id;
        let artifact_root = &record.artifact_root;
        let record_key = sandbox_id.to_string();
        let manifest_path = Self::manifest_path(artifact_root);
        // This marker lives with the snapshot rather than only in RocksDB, so
        // restart recovery cannot mistake an ambiguous final index write for
        // a normal committed pause.
        let marker_written = match self.write_recovery_marker(sandbox_id, artifact_root).await {
            Ok(()) => true,
            Err(marker_error) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %marker_error,
                    "failed to durably mark uncertain paused sandbox commit"
                );
                false
            }
        };
        let mut recovery_record = record.clone();
        recovery_record.version = PAUSED_MANIFEST_VERSION;
        recovery_record.commit_state = PersistedPausedCommitState::Prepared;
        recovery_record.metadata.resume_recovery_pending = true;
        recovery_record.metadata.paused_runtime_stopped = false;
        let recovery_manifest_written = match self.write_manifest(&recovery_record).await {
            Ok(_) => true,
            Err(manifest_error) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %manifest_error,
                    "failed to publish recovery-pending paused sandbox manifest"
                );
                false
            }
        };
        // If an index write may actually have committed, retain its exact
        // current bytes. Purge later refuses a changed replacement, but can
        // intentionally remove this known uncertain generation.
        let current_record_bytes = match self.db().await {
            Ok(db) => match db.get(record_key.as_bytes().to_vec()).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %error,
                        "failed to read paused sandbox index while recording uncertain commit"
                    );
                    None
                }
            },
            Err(error) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %error,
                    "failed to open paused sandbox index while recording uncertain commit"
                );
                None
            }
        };
        let quarantine_result = if marker_written || recovery_manifest_written {
            // The manifest/marker is authoritative and will force the
            // recovery-pending path. Keep a nonblocking inventory entry so
            // restart can still load the guarded metadata and the CLI has an
            // explicit purge target.
            self.quarantine_nonblocking(
                format!("{reason}; original write error: {source}"),
                Some(record_key.as_bytes()),
                current_record_bytes.as_deref(),
                Some(artifact_root),
                Some(&manifest_path),
            )
            .await
        } else {
            self.quarantine_uncertain(
                format!("{reason}; original write error: {source}"),
                Some(record_key.as_bytes()),
                current_record_bytes.as_deref(),
                Some(artifact_root),
                Some(&manifest_path),
            )
            .await
        };
        if let Err(quarantine_error) = quarantine_result {
            warn!(
                sandbox_id = %sandbox_id,
                error = %quarantine_error,
                "failed to index uncertain paused sandbox commit in quarantine"
            );
        }
        SandboxPersistenceError::UncertainCommit {
            sandbox_id,
            reason,
            source: Some(anyhow::Error::new(source)),
        }
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

    async fn resolve_index(
        &self,
        expected_sandbox_id: &SandboxId,
        index: &PersistedPausedIndex,
    ) -> PersistenceResult<PersistedPausedRecord> {
        if index.index_version != PAUSED_INDEX_VERSION {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "unsupported paused sandbox index version {}",
                    index.index_version
                ),
                source: None,
            });
        }
        if index.sandbox_id != *expected_sandbox_id {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "paused sandbox index key {expected_sandbox_id} points at {}",
                    index.sandbox_id
                ),
                source: None,
            });
        }
        if !self.path_is_managed_artifact(&index.manifest_path) {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "paused sandbox index {expected_sandbox_id} references a manifest outside the managed artifacts root"
                ),
                source: None,
            });
        }

        let entry = self
            .read_manifest(&index.manifest_path, Some(expected_sandbox_id))
            .await?;
        if !entry.matches_index(index) {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "paused sandbox index {expected_sandbox_id} does not match its manifest"
                ),
                source: None,
            });
        }
        Ok(entry.record)
    }

    async fn read_manifest(
        &self,
        manifest_path: &Path,
        expected_sandbox_id: Option<&SandboxId>,
    ) -> PersistenceResult<ManifestEntry> {
        let bytes = fs::read(manifest_path).await.map_err(|source| {
            SandboxPersistenceError::io("read paused sandbox manifest", manifest_path, source)
        })?;
        let raw: Value = serde_json::from_slice(&bytes).map_err(|source| {
            SandboxPersistenceError::InvalidRecord {
                reason: "failed to deserialize paused sandbox manifest".to_string(),
                source: Some(source.into()),
            }
        })?;
        let mut record = decode_record(&bytes)?;
        if record.version != PAUSED_MANIFEST_VERSION {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "paused sandbox manifest {} has unsupported version {}",
                    manifest_path.display(),
                    record.version
                ),
                source: None,
            });
        }
        if raw.get("commitState").is_none() {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "paused sandbox manifest {} is missing its v2 commit state",
                    manifest_path.display()
                ),
                source: None,
            });
        }
        let expected_manifest_path = Self::manifest_path(&record.artifact_root);
        if expected_manifest_path != manifest_path {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "paused sandbox manifest {} does not match its artifact root {}",
                    manifest_path.display(),
                    record.artifact_root.display()
                ),
                source: None,
            });
        }
        if !self.path_is_managed_generation(&record.metadata.id, &record.artifact_root) {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "paused sandbox manifest {} does not reference an exact managed artifact generation",
                    manifest_path.display()
                ),
                source: None,
            });
        }
        if let Some(expected_sandbox_id) = expected_sandbox_id {
            if record.metadata.id != *expected_sandbox_id {
                return Err(SandboxPersistenceError::InvalidRecord {
                    reason: format!(
                        "paused sandbox manifest {} contains metadata for {} instead of {}",
                        manifest_path.display(),
                        record.metadata.id,
                        expected_sandbox_id
                    ),
                    source: None,
                });
            }
        }
        let marker_path = Self::recovery_marker_path(&record.artifact_root);
        let recovery_marker_present = match fs::symlink_metadata(&marker_path).await {
            Ok(metadata) if metadata.file_type().is_file() => {
                // The marker is deliberately fail-closed. Its presence means
                // a metadata write was observed as ambiguous, even if RocksDB
                // later happens to contain a matching index.
                record.metadata.resume_recovery_pending = true;
                record.metadata.paused_runtime_stopped = false;
                true
            }
            Ok(_) => {
                return Err(SandboxPersistenceError::InvalidRecord {
                    reason: format!(
                        "paused sandbox recovery marker {} is not a regular file",
                        marker_path.display()
                    ),
                    source: None,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(source) => {
                return Err(SandboxPersistenceError::io(
                    "inspect paused sandbox recovery marker",
                    &marker_path,
                    source,
                ));
            }
        };
        Ok(ManifestEntry {
            path: manifest_path.to_path_buf(),
            bytes,
            record,
            recovery_marker_present,
        })
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
        let prepared_entry = match self.write_manifest(&prepared).await {
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
        if let Err(source) = self.write_index(&prepared_entry).await {
            return Err(self
                .quarantine_uncertain_commit(
                    record,
                    "failed to durably index prepared paused sandbox manifest",
                    source,
                )
                .await);
        }

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

    /// Drop every managed generation except `keep`. The next incremental pause
    /// still needs the last memory config, so resume must not call this.
    async fn retire_replaced_generations(
        &self,
        sandbox_id: &SandboxId,
        keep: &Path,
    ) -> PersistenceResult<()> {
        let Some(keep) = self.validated_managed_generation_path(sandbox_id, keep) else {
            return Ok(());
        };
        let sandbox_root = self.sandbox_artifact_root(sandbox_id);
        let mut entries = match fs::read_dir(&sandbox_root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(SandboxPersistenceError::io(
                    "read paused sandbox generations",
                    sandbox_root,
                    source,
                ));
            }
        };
        while let Some(entry) = entries.next_entry().await.map_err(|source| {
            SandboxPersistenceError::io("scan paused sandbox generations", &sandbox_root, source)
        })? {
            let path = entry.path();
            if path == keep {
                continue;
            }
            let file_type = entry.file_type().await.map_err(|source| {
                SandboxPersistenceError::io("inspect paused sandbox generation", &path, source)
            })?;
            if file_type.is_dir() && self.path_is_managed_generation(sandbox_id, &path) {
                Self::remove_artifact_root(&path).await?;
            }
        }
        Ok(())
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

    async fn scan_manifest_directory(
        &self,
        directory: &Path,
        expected_sandbox_id: Option<&SandboxId>,
        entries: &mut Vec<ManifestEntry>,
        quarantined: &mut usize,
    ) -> PersistenceResult<bool> {
        let manifest_path = Self::manifest_path(directory);
        let quarantine_target = self.quarantine_target_for_manifest(directory, &manifest_path);
        match fs::symlink_metadata(&manifest_path).await {
            Ok(metadata) if metadata.file_type().is_file() => {
                match self
                    .read_manifest(&manifest_path, expected_sandbox_id)
                    .await
                {
                    Ok(entry) => {
                        if entry.recovery_marker_present
                            || entry.record.commit_state == PersistedPausedCommitState::Prepared
                            || entry.record.metadata.resume_recovery_pending
                        {
                            // A failed quarantine write must not make an
                            // on-tree uncertain record invisible to the
                            // host-local recovery utility. The marker is
                            // authoritative when present, but a crash may
                            // have happened after a durable Prepared manifest
                            // and before marker publication. Inventory all
                            // recovery-pending forms nonblockingly: their
                            // manifest state still prevents resume/delete.
                            let record_key = entry.sandbox_id().to_string();
                            self.quarantine_nonblocking(
                                "durable paused sandbox manifest requires explicit host recovery",
                                Some(record_key.as_bytes()),
                                None,
                                Some(&entry.record.artifact_root),
                                Some(&entry.path),
                            )
                            .await?;
                            *quarantined += 1;
                        }
                        entries.push(entry);
                    }
                    Err(error) => {
                        warn!(manifest = %manifest_path.display(), error = %error, "quarantining invalid paused sandbox manifest");
                        self.quarantine(
                            format!("invalid paused sandbox manifest: {error}"),
                            None,
                            None,
                            quarantine_target.as_deref(),
                            Some(&manifest_path),
                        )
                        .await?;
                        *quarantined += 1;
                    }
                }
                Ok(true)
            }
            Ok(_) => {
                self.quarantine(
                    "paused sandbox manifest path is not a regular file",
                    None,
                    None,
                    quarantine_target.as_deref(),
                    Some(&manifest_path),
                )
                .await?;
                *quarantined += 1;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(SandboxPersistenceError::io(
                "inspect paused sandbox manifest",
                &manifest_path,
                source,
            )),
        }
    }

    /// Find manifest generations without following symlinks.  A directory
    /// without a manifest is intentionally not an orphan to delete: it is a
    /// recovery candidate and is indexed in quarantine instead.
    async fn scan_manifests(&self) -> PersistenceResult<(Vec<ManifestEntry>, usize)> {
        let artifacts_root = self.artifacts_root();
        let mut manifests = Vec::new();
        let mut quarantined = 0;
        let _ = self
            .scan_manifest_directory(&artifacts_root, None, &mut manifests, &mut quarantined)
            .await?;

        let mut sandbox_dirs = match fs::read_dir(&artifacts_root).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((manifests, quarantined));
            }
            Err(source) => {
                return Err(SandboxPersistenceError::io(
                    "read paused sandbox artifacts",
                    &artifacts_root,
                    source,
                ));
            }
        };
        while let Some(sandbox_dir) = sandbox_dirs.next_entry().await.map_err(|source| {
            SandboxPersistenceError::io("scan paused sandbox artifacts", &artifacts_root, source)
        })? {
            let sandbox_path = sandbox_dir.path();
            let file_type = sandbox_dir.file_type().await.map_err(|source| {
                SandboxPersistenceError::io(
                    "inspect paused sandbox artifacts",
                    &sandbox_path,
                    source,
                )
            })?;
            let sandbox_id = sandbox_dir
                .file_name()
                .to_str()
                .and_then(|name| SandboxId::parse_str(name).ok());
            if !file_type.is_dir() || sandbox_id.is_none() {
                self.quarantine(
                    "unreferenced or markerless paused sandbox artifact entry",
                    None,
                    None,
                    Some(&sandbox_path),
                    None,
                )
                .await?;
                quarantined += 1;
                continue;
            }
            let sandbox_id = sandbox_id.expect("checked above");
            // A manifest directly under `<sandbox-id>` is misplaced (v2
            // requires a generation directory). Quarantine it, but keep
            // walking its children: a damaged root marker must not hide a
            // valid sibling generation or markerless artifact.
            let _ = self
                .scan_manifest_directory(
                    &sandbox_path,
                    Some(&sandbox_id),
                    &mut manifests,
                    &mut quarantined,
                )
                .await?;

            let mut generations = fs::read_dir(&sandbox_path).await.map_err(|source| {
                SandboxPersistenceError::io("read paused sandbox generation", &sandbox_path, source)
            })?;
            while let Some(generation) = generations.next_entry().await.map_err(|source| {
                SandboxPersistenceError::io("scan paused sandbox generation", &sandbox_path, source)
            })? {
                let generation_path = generation.path();
                let generation_type = generation.file_type().await.map_err(|source| {
                    SandboxPersistenceError::io(
                        "inspect paused sandbox generation",
                        &generation_path,
                        source,
                    )
                })?;
                if generation_type.is_dir()
                    && self
                        .scan_manifest_directory(
                            &generation_path,
                            Some(&sandbox_id),
                            &mut manifests,
                            &mut quarantined,
                        )
                        .await?
                {
                    continue;
                }
                self.quarantine(
                    "markerless paused sandbox artifact generation",
                    None,
                    None,
                    Some(&generation_path),
                    None,
                )
                .await?;
                quarantined += 1;
            }
        }
        Ok((manifests, quarantined))
    }

    async fn index_manifest_or_quarantine(
        &self,
        entry: &ManifestEntry,
        report: &mut PausedSandboxRecoveryReport,
    ) -> PersistenceResult<()> {
        if let Err(source) = self.write_index(entry).await {
            return Err(self
                .quarantine_uncertain_commit(
                    &entry.record,
                    "failed to rebuild paused sandbox index from a valid manifest",
                    source,
                )
                .await);
        }
        report.indexed_manifests += 1;
        Ok(())
    }

    fn indexed_manifests(
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> HashMap<SandboxId, PersistedPausedIndex> {
        entries
            .iter()
            .filter_map(|(key, bytes)| {
                let key_id = std::str::from_utf8(key)
                    .ok()
                    .and_then(|value| SandboxId::parse_str(value).ok())?;
                let index = decode_paused_index(bytes).ok()?;
                (index.sandbox_id == key_id).then_some((key_id, index))
            })
            .collect()
    }

    fn manifest_needs_recovery(entry: &ManifestEntry) -> bool {
        entry.recovery_marker_present
            || entry.record.commit_state != PersistedPausedCommitState::Committed
            || entry.record.metadata.resume_recovery_pending
    }

    async fn select_manifest_candidates(
        &self,
        entries: &[(Vec<u8>, Vec<u8>)],
        manifests: Vec<ManifestEntry>,
    ) -> PersistenceResult<ManifestReconciliation> {
        let indexed_manifests = Self::indexed_manifests(entries);
        let mut grouped = HashMap::<SandboxId, Vec<ManifestEntry>>::new();
        for entry in manifests {
            grouped.entry(entry.sandbox_id()).or_default().push(entry);
        }

        let mut selection = ManifestReconciliation::default();
        for (sandbox_id, mut group) in grouped {
            if group.len() == 1 {
                selection
                    .candidates
                    .insert(sandbox_id, group.pop().expect("one manifest candidate"));
                continue;
            }

            let selected_position = indexed_manifests.get(&sandbox_id).and_then(|index| {
                let matches = group
                    .iter()
                    .enumerate()
                    .filter_map(|(position, entry)| entry.matches_index(index).then_some(position))
                    .collect::<Vec<_>>();
                (matches.len() == 1).then_some(matches[0])
            });
            if let Some(position) = selected_position {
                let selected = group.swap_remove(position);
                // A coherent current index disambiguates clean generations
                // left behind after an acknowledged replacement. An
                // uncommitted sibling could instead be a newer ambiguous
                // operation, so that case remains fail-closed.
                if group
                    .iter()
                    .all(|entry| !Self::manifest_needs_recovery(entry))
                {
                    if selected.record.lifecycle == PersistedPausedLifecycle::Paused
                        && selected.record.metadata.paused_runtime_stopped
                        && !Self::manifest_needs_recovery(&selected)
                    {
                        selection.retire_after_selection.insert(
                            sandbox_id,
                            group
                                .iter()
                                .map(|entry| entry.record.artifact_root.clone())
                                .collect(),
                        );
                    }
                    selection.candidates.insert(sandbox_id, selected);
                    continue;
                }
                group.push(selected);
            }

            selection.blocked.insert(sandbox_id);
            for entry in group {
                self.quarantine(
                    "multiple paused sandbox manifests cannot be safely ordered",
                    None,
                    None,
                    Some(&entry.record.artifact_root),
                    Some(&entry.path),
                )
                .await?;
                selection.quarantined_items += 1;
            }
        }
        Ok(selection)
    }

    async fn retire_reconciled_generations(
        &self,
        sandbox_id: &SandboxId,
        artifact_roots: &[PathBuf],
    ) -> PersistenceResult<()> {
        for artifact_root in artifact_roots {
            let Some(path) = self.validated_managed_generation_path(sandbox_id, artifact_root)
            else {
                return Err(SandboxPersistenceError::InvalidRecord {
                    reason: format!(
                        "refusing to retire reconciled generation outside sandbox {sandbox_id}"
                    ),
                    source: None,
                });
            };
            Self::remove_artifact_root(&path).await?;
        }
        Ok(())
    }

    async fn reconcile_v2_index_entry(
        &self,
        key_id: Option<SandboxId>,
        key: &[u8],
        bytes: &[u8],
        index: PersistedPausedIndex,
        candidates: &HashMap<SandboxId, ManifestEntry>,
        recovery_blocks: &PausedRecoveryBlocks,
        selected_v2: &mut HashMap<SandboxId, PersistedPausedRecord>,
        blocked: &mut HashSet<SandboxId>,
        report: &mut PausedSandboxRecoveryReport,
    ) -> PersistenceResult<()> {
        let Some(sandbox_id) = key_id else {
            self.quarantine(
                "paused sandbox index has a non-sandbox record key",
                Some(key),
                Some(bytes),
                None,
                Some(&index.manifest_path),
            )
            .await?;
            report.quarantined_items += 1;
            return Ok(());
        };
        if blocked.contains(&sandbox_id) || recovery_blocks.contains_sandbox(&sandbox_id) {
            blocked.insert(sandbox_id);
            return Ok(());
        }

        let candidate = candidates.get(&sandbox_id);
        if !self.index_matches_candidate(&index, sandbox_id, candidate) {
            self.quarantine(
                "paused sandbox index and manifest identity disagree",
                Some(key),
                Some(bytes),
                candidate.map(|entry| entry.record.artifact_root.as_path()),
                Some(&index.manifest_path),
            )
            .await?;
            report.quarantined_items += 1;
            blocked.insert(sandbox_id);
            return Ok(());
        }

        match self.resolve_index(&sandbox_id, &index).await {
            Ok(record) => {
                selected_v2.insert(sandbox_id, record);
            }
            Err(error) => {
                self.quarantine(
                    format!("paused sandbox index/manifest mismatch: {error}"),
                    Some(key),
                    Some(bytes),
                    candidate.map(|entry| entry.record.artifact_root.as_path()),
                    Some(&index.manifest_path),
                )
                .await?;
                report.quarantined_items += 1;
                blocked.insert(sandbox_id);
            }
        }
        Ok(())
    }

    fn index_matches_candidate(
        &self,
        index: &PersistedPausedIndex,
        sandbox_id: SandboxId,
        candidate: Option<&ManifestEntry>,
    ) -> bool {
        index.index_version == PAUSED_INDEX_VERSION
            && index.sandbox_id == sandbox_id
            && self.path_is_managed_artifact(&index.manifest_path)
            && candidate.is_none_or(|entry| entry.matches_index(index))
    }

    async fn reconcile_invalid_index_entry(
        &self,
        key_id: Option<SandboxId>,
        key: &[u8],
        bytes: &[u8],
        error: &SandboxPersistenceError,
        candidates: &HashMap<SandboxId, ManifestEntry>,
        blocked: &mut HashSet<SandboxId>,
        report: &mut PausedSandboxRecoveryReport,
    ) -> PersistenceResult<()> {
        let repairable_candidate = key_id.and_then(|sandbox_id| {
            candidates.get(&sandbox_id).filter(|candidate| {
                Self::raw_index_can_be_rebuilt_from_manifest(bytes, &sandbox_id, candidate)
            })
        });
        if let Some(candidate) = repairable_candidate {
            self.quarantine_repairable_index(
                format!(
                    "malformed paused sandbox index rebuilt from coherent v2 manifest: {error}"
                ),
                Some(key),
                Some(bytes),
                Some(&candidate.record.artifact_root),
                Some(&candidate.path),
            )
            .await?;
            report.quarantined_items += 1;
            return Ok(());
        }

        self.quarantine(
            format!("invalid or unsupported paused sandbox record: {error}"),
            Some(key),
            Some(bytes),
            None,
            None,
        )
        .await?;
        report.quarantined_items += 1;
        if let Some(sandbox_id) = key_id {
            blocked.insert(sandbox_id);
        }
        Ok(())
    }

    async fn rebuild_missing_manifest_indexes(
        &self,
        candidates: HashMap<SandboxId, ManifestEntry>,
        recovery_blocks: &PausedRecoveryBlocks,
        selected_v2: &mut HashMap<SandboxId, PersistedPausedRecord>,
        blocked: &HashSet<SandboxId>,
        report: &mut PausedSandboxRecoveryReport,
    ) -> PersistenceResult<()> {
        for (sandbox_id, candidate) in candidates {
            if selected_v2.contains_key(&sandbox_id)
                || blocked.contains(&sandbox_id)
                || recovery_blocks.contains_manifest(&candidate)
            {
                continue;
            }
            self.index_manifest_or_quarantine(&candidate, report)
                .await?;
            selected_v2.insert(sandbox_id, candidate.record);
        }
        Ok(())
    }

    async fn retire_selected_generations(
        &self,
        retire_after_selection: HashMap<SandboxId, Vec<PathBuf>>,
        recovery_blocks: &PausedRecoveryBlocks,
        selected_v2: &HashMap<SandboxId, PersistedPausedRecord>,
        blocked: &HashSet<SandboxId>,
    ) {
        for (sandbox_id, artifact_roots) in retire_after_selection {
            if !selected_v2.contains_key(&sandbox_id)
                || blocked.contains(&sandbox_id)
                || artifact_roots
                    .iter()
                    .any(|path| recovery_blocks.contains_record(&sandbox_id, path))
            {
                continue;
            }
            if let Err(error) = self
                .retire_reconciled_generations(&sandbox_id, &artifact_roots)
                .await
            {
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %error,
                    "failed to retire superseded paused generations after index reconciliation"
                );
            }
        }
    }

    async fn reconcile_manifest_index(
        &self,
        allow_manual_recovery: bool,
    ) -> PersistenceResult<(Vec<PersistedPausedRecord>, PausedSandboxRecoveryReport)> {
        let entries = self.db().await?.entries().await.map_err(|source| {
            SandboxPersistenceError::store("scan paused sandbox records", source)
        })?;

        let (manifests, mut quarantined) = self.scan_manifests().await?;
        let manifest_selection = self.select_manifest_candidates(&entries, manifests).await?;
        quarantined += manifest_selection.quarantined_items;
        let mut report = PausedSandboxRecoveryReport {
            indexed_manifests: 0,
            quarantined_items: quarantined,
            reconciled_quarantines: 0,
        };
        let candidates = manifest_selection.candidates;
        let retire_after_selection = manifest_selection.retire_after_selection;

        let recovery_blocks = if allow_manual_recovery {
            PausedRecoveryBlocks::default()
        } else {
            self.recovery_blocks().await?
        };
        let mut selected_v2 = HashMap::new();
        let mut blocked = manifest_selection.blocked;
        for (sandbox_id, candidate) in &candidates {
            if recovery_blocks.contains_manifest(candidate) {
                blocked.insert(*sandbox_id);
            }
        }

        for (key, bytes) in entries {
            let key_id = std::str::from_utf8(&key)
                .ok()
                .and_then(|value| SandboxId::parse_str(value).ok());
            match decode_paused_index(&bytes) {
                Ok(index) => {
                    self.reconcile_v2_index_entry(
                        key_id,
                        &key,
                        &bytes,
                        index,
                        &candidates,
                        &recovery_blocks,
                        &mut selected_v2,
                        &mut blocked,
                        &mut report,
                    )
                    .await?;
                }
                Err(error) => {
                    self.reconcile_invalid_index_entry(
                        key_id,
                        &key,
                        &bytes,
                        &error,
                        &candidates,
                        &mut blocked,
                        &mut report,
                    )
                    .await?;
                }
            }
        }

        self.rebuild_missing_manifest_indexes(
            candidates,
            &recovery_blocks,
            &mut selected_v2,
            &blocked,
            &mut report,
        )
        .await?;
        self.retire_selected_generations(
            retire_after_selection,
            &recovery_blocks,
            &selected_v2,
            &blocked,
        )
        .await;

        Ok((selected_v2.into_values().collect(), report))
    }

    async fn reconcile_uncertain_quarantines(&self) -> PersistenceResult<usize> {
        // A coherent manifest/index pair proves storage agreement, not that a
        // paused runtime was stopped or is absent. Keep ambiguous commits
        // recovery-pending until an operator explicitly purges or performs a
        // higher-level runtime recovery with positive stop/absence proof.
        Ok(0)
    }

    /// Lists only recovery state that cannot be exposed through the public
    /// sandbox API.  The recovery binary is the intended caller.
    pub async fn list_quarantines(&self) -> PersistenceResult<Vec<PausedSandboxQuarantine>> {
        let mut quarantines = self
            .stored_quarantines()
            .await?
            .into_iter()
            .map(PausedSandboxQuarantine::from)
            .collect::<Vec<_>>();
        quarantines.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(quarantines)
    }

    /// Re-run non-destructive manifest/index reconciliation.  This repairs
    /// only absent or corrupt index entries from a valid v2 manifest; an index
    /// mismatch remains quarantined for explicit operator review.
    pub async fn reconcile_quarantines(&self) -> PersistenceResult<PausedSandboxRecoveryReport> {
        let (_records, mut report) = self.reconcile_manifest_index(true).await?;
        report.reconciled_quarantines += self.reconcile_uncertain_quarantines().await?;
        Ok(report)
    }

    async fn nonblocking_quarantine_was_superseded(
        &self,
        entry: &StoredPausedSandboxQuarantine,
        current_record: &[u8],
    ) -> PersistenceResult<bool> {
        if entry.requires_manual_recovery {
            return Ok(false);
        }
        let Some(sandbox_id) = entry
            .record_key
            .as_deref()
            .and_then(|record_key| SandboxId::parse_str(record_key).ok())
        else {
            return Ok(false);
        };
        let Ok(index) = decode_paused_index(current_record) else {
            return Ok(false);
        };
        if index.sandbox_id != sandbox_id
            || entry
                .manifest_path
                .as_ref()
                .is_some_and(|path| path != &index.manifest_path)
        {
            return Ok(false);
        }
        let Ok(record) = self.resolve_index(&sandbox_id, &index).await else {
            return Ok(false);
        };
        Ok(entry
            .artifact_root
            .as_ref()
            .is_none_or(|artifact_root| artifact_root == &record.artifact_root))
    }

    async fn load_quarantine_for_purge(
        &self,
        quarantine_id: &str,
    ) -> PersistenceResult<StoredPausedSandboxQuarantine> {
        let bytes = self
            .quarantine_db()
            .await?
            .get(quarantine_id.as_bytes().to_vec())
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("read paused sandbox quarantine", source)
            })?
            .ok_or_else(|| SandboxPersistenceError::InvalidRecord {
                reason: format!("paused sandbox quarantine {quarantine_id} not found"),
                source: None,
            })?;
        let entry: StoredPausedSandboxQuarantine =
            serde_json::from_slice(&bytes).map_err(|source| {
                SandboxPersistenceError::InvalidRecord {
                    reason: "failed to deserialize paused sandbox quarantine record".to_string(),
                    source: Some(source.into()),
                }
            })?;
        if entry.version != QUARANTINE_VERSION {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "unsupported paused sandbox quarantine version {}",
                    entry.version
                ),
                source: None,
            });
        }
        Ok(entry)
    }

    async fn quarantine_purge_action(
        &self,
        quarantine_id: &str,
        entry: &StoredPausedSandboxQuarantine,
    ) -> PersistenceResult<QuarantinePurgeAction> {
        let Some(record_key) = entry.record_key.as_deref() else {
            return Ok(QuarantinePurgeAction::PurgeState { record_key: None });
        };
        let current = self
            .db()
            .await?
            .get(record_key.as_bytes().to_vec())
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("read paused sandbox index before purge", source)
            })?;
        if let Some(current) = current.as_deref() {
            let replaced = entry
                .record_sha256
                .as_deref()
                .is_some_and(|expected_hash| sha256_hex(current) != expected_hash)
                && self
                    .nonblocking_quarantine_was_superseded(entry, current)
                    .await?;
            if replaced {
                return Ok(QuarantinePurgeAction::QuarantineOnly);
            }
        }
        match (current, entry.record_sha256.as_deref()) {
            (Some(current), Some(expected_hash)) if sha256_hex(&current) == expected_hash => {
                Ok(QuarantinePurgeAction::PurgeState {
                    record_key: Some(record_key.to_owned()),
                })
            }
            (Some(_), _) => Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "refusing to purge paused sandbox quarantine {quarantine_id}: its record key now points at newer or unknown state"
                ),
                source: None,
            }),
            (None, _) => Ok(QuarantinePurgeAction::PurgeState { record_key: None }),
        }
    }

    fn quarantine_artifact_path_for_purge(
        &self,
        quarantine_id: &str,
        entry: &StoredPausedSandboxQuarantine,
        path: &Path,
    ) -> PersistenceResult<PathBuf> {
        let expected_sandbox_id = entry
            .record_key
            .as_deref()
            .and_then(|record_key| SandboxId::parse_str(record_key).ok());
        let valid_path = match expected_sandbox_id {
            Some(sandbox_id) => self
                .validated_managed_generation_path(&sandbox_id, path)
                .or_else(|| self.validated_managed_sandbox_root_path(&sandbox_id, path)),
            None => self.validated_purgeable_artifact_path(path),
        };
        valid_path.ok_or_else(|| SandboxPersistenceError::InvalidRecord {
            reason: match expected_sandbox_id {
                Some(sandbox_id) => format!(
                    "refusing to purge paused sandbox quarantine {quarantine_id}: artifact path is not an exact managed generation for sandbox {sandbox_id}"
                ),
                None => format!(
                    "refusing to purge paused sandbox quarantine {quarantine_id}: artifact path is not an exact managed generation or metadata file"
                ),
            },
            source: None,
        })
    }

    async fn delete_purged_record(&self, record_key: Option<String>) -> PersistenceResult<()> {
        if let Some(record_key) = record_key {
            self.db()
                .await?
                .delete(record_key.as_bytes().to_vec())
                .await
                .map_err(|source| {
                    SandboxPersistenceError::store("purge paused sandbox index", source)
                })?;
        }
        Ok(())
    }

    /// Explicit destructive recovery action.  It never follows paths outside
    /// this persister's artifacts directory, and it never deletes a newer
    /// index entry that differs from the quarantined original bytes.
    pub async fn purge_quarantine(&self, quarantine_id: &str) -> PersistenceResult<()> {
        let entry = self.load_quarantine_for_purge(quarantine_id).await?;
        let remove_record = match self.quarantine_purge_action(quarantine_id, &entry).await? {
            QuarantinePurgeAction::QuarantineOnly => {
                return self.delete_quarantine(quarantine_id).await;
            }
            QuarantinePurgeAction::PurgeState { record_key } => record_key,
        };
        if let Some(path) = entry.artifact_root.as_deref() {
            let canonical_artifact_path =
                self.quarantine_artifact_path_for_purge(quarantine_id, &entry, path)?;
            Self::remove_artifact_root(&canonical_artifact_path).await?;
        }
        self.delete_purged_record(remove_record).await?;
        self.delete_quarantine(quarantine_id).await
    }

    async fn reconcile_record_lifecycle<F>(
        &self,
        mut record: PersistedPausedRecord,
        factory: &F,
    ) -> PersistenceResult<PersistedRecordLoad>
    where
        F: SandboxBackendFactory,
    {
        if record.commit_state == PersistedPausedCommitState::Prepared
            || record.metadata.resume_recovery_pending
        {
            warn!(sandbox_id = %record.metadata.id, "retaining paused sandbox whose persistence commit is recovery-pending");
            return self.load_recovery_pending_record(record, factory).await;
        }
        if record.lifecycle == PersistedPausedLifecycle::Resumed {
            info!(sandbox_id = %record.metadata.id, "restoring last paused snapshot after a committed resume; the live VM cannot still be running");
            record.lifecycle = PersistedPausedLifecycle::Paused;
            record.resuming_boot_id = None;
            record.unproven_stop_boot_id = None;
            record.metadata.paused_runtime_stopped = true;
            self.put_record(&record).await?;
        }
        if record.lifecycle == PersistedPausedLifecycle::Resuming {
            return self.reconcile_interrupted_resume(record, factory).await;
        }
        Ok(PersistedRecordLoad::Continue(record))
    }

    async fn load_recovery_pending_record<F>(
        &self,
        mut record: PersistedPausedRecord,
        factory: &F,
    ) -> PersistenceResult<PersistedRecordLoad>
    where
        F: SandboxBackendFactory,
    {
        let artifact_root = record.artifact_root.clone();
        let manifest_path = Self::manifest_path(&artifact_root);
        record.metadata.resume_recovery_pending = true;
        record.metadata.paused_runtime_stopped = false;
        if record.metadata.virtualization_mode != self.virtualization_mode {
            return Ok(PersistedRecordLoad::Complete(Some(
                super::codecs::paused_metadata_without_runtime_state(record),
            )));
        }
        let metadata = match super::codecs::decode_recovery_pending_state(record, factory) {
            Ok(metadata) => Some(metadata),
            Err(error) => {
                self.quarantine(
                    format!("recovery-pending paused sandbox could not be decoded: {error}"),
                    None,
                    None,
                    Some(&artifact_root),
                    Some(&manifest_path),
                )
                .await?;
                None
            }
        };
        Ok(PersistedRecordLoad::Complete(metadata))
    }

    async fn reconcile_interrupted_resume<F>(
        &self,
        mut record: PersistedPausedRecord,
        factory: &F,
    ) -> PersistenceResult<PersistedRecordLoad>
    where
        F: SandboxBackendFactory,
    {
        let sandbox_id = record.metadata.id;
        if host_reboot_proves_runtime_absent(
            record.resuming_boot_id.as_deref(),
            current_host_boot_id().as_deref(),
        ) {
            info!(sandbox_id = %sandbox_id, "host reboot proved interrupted resumed runtime absent; restoring paused record");
            record.lifecycle = PersistedPausedLifecycle::Paused;
            record.resuming_boot_id = None;
            record.unproven_stop_boot_id = None;
            record.metadata.paused_runtime_stopped = true;
            self.put_record(&record).await?;
            return Ok(PersistedRecordLoad::Continue(record));
        }

        warn!(sandbox_id = %sandbox_id, "retaining paused sandbox record left in resuming state until a later host boot proves runtime absence");
        if record.metadata.virtualization_mode != self.virtualization_mode {
            let mut metadata = super::codecs::paused_metadata_without_runtime_state(record);
            metadata.paused_runtime_stopped = false;
            metadata.resume_recovery_pending = true;
            return Ok(PersistedRecordLoad::Complete(Some(metadata)));
        }
        let artifact_root = record.artifact_root.clone();
        let manifest_path = Self::manifest_path(&artifact_root);
        let metadata = match super::codecs::decode_recovery_pending_state(record, factory) {
            Ok(metadata) => Some(metadata),
            Err(error) => {
                warn!(sandbox_id = %sandbox_id, error = %error, "quarantining interrupted resume whose paused state could not be decoded");
                self.quarantine(
                    format!(
                        "interrupted resume paused sandbox state could not be decoded: {error}"
                    ),
                    None,
                    None,
                    Some(&artifact_root),
                    Some(&manifest_path),
                )
                .await?;
                None
            }
        };
        Ok(PersistedRecordLoad::Complete(metadata))
    }

    async fn load_reconciled_record<F>(
        &self,
        mut record: PersistedPausedRecord,
        factory: &F,
    ) -> PersistenceResult<Option<SandboxMetadata>>
    where
        F: SandboxBackendFactory,
    {
        let sandbox_id = record.metadata.id;
        if let Some(boot_id) = current_host_boot_id() {
            match record.reconcile_stop_proof_for_boot(&boot_id) {
                StopProofReconciliation::Unchanged => {}
                StopProofReconciliation::ObservationRecorded => {
                    info!(sandbox_id = %sandbox_id, "recorded host boot for paused sandbox without stop proof");
                    self.put_record(&record).await?;
                }
                StopProofReconciliation::RuntimeAbsent => {
                    info!(sandbox_id = %sandbox_id, "later host boot proved paused runtime absent; restored stop proof");
                    self.put_record(&record).await?;
                }
            }
        }
        if record.metadata.virtualization_mode != self.virtualization_mode {
            warn!(
                sandbox_id = %sandbox_id,
                record_mode = %record.metadata.virtualization_mode,
                node_mode = %self.virtualization_mode,
                "loading paused sandbox metadata without resumable runtime state because its virtualization mode is incompatible"
            );
            return Ok(Some(super::codecs::paused_metadata_without_runtime_state(
                record,
            )));
        }

        let artifact_root = record.artifact_root.clone();
        let manifest_path = Self::manifest_path(&artifact_root);
        match super::codecs::decode_paused_state(record, factory) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) => {
                warn!(sandbox_id = %sandbox_id, error = %error, "quarantining unusable paused sandbox record without deleting artifacts");
                self.quarantine(
                    format!("paused sandbox state could not be decoded: {error}"),
                    None,
                    None,
                    Some(&artifact_root),
                    Some(&manifest_path),
                )
                .await?;
                Ok(None)
            }
        }
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
        if let Err(error) = self
            .retire_replaced_generations(&metadata.id, artifact_root)
            .await
        {
            warn!(
                sandbox_id = %metadata.id,
                error = %error,
                "failed to retire replaced paused generations"
            );
        }
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
    async fn missing_v2_commit_state_is_quarantined_without_deleting_the_manifest(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let (_sandbox_id, snapshot_root, _paused_state) = persist_test_record(&persister).await?;
        let manifest_path = FileBackedSandboxPersister::manifest_path(&snapshot_root);
        let mut value: Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
        value
            .as_object_mut()
            .expect("paused manifest is a JSON object")
            .remove("commitState");
        std::fs::write(&manifest_path, serde_json::to_vec(&value)?)?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert!(loaded.is_empty());
        assert!(manifest_path.exists());
        assert!(!persister.list_quarantines().await?.is_empty());
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
    async fn failed_manifest_index_rebuild_writes_a_durable_recovery_marker() -> anyhow::Result<()>
    {
        let temp = TempDir::new()?;
        std::fs::write(temp.path().join(RECORD_DB_DIR), b"not-a-rocksdb-directory")?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = test_snapshot_root(&persister, &sandbox_id);
        let paused_state = paused_state(&snapshot_root);
        let record = PersistedPausedRecord {
            version: PAUSED_MANIFEST_VERSION,
            commit_state: PersistedPausedCommitState::Committed,
            lifecycle: PersistedPausedLifecycle::Paused,
            resuming_boot_id: None,
            unproven_stop_boot_id: None,
            metadata: SandboxMetadata {
                id: sandbox_id,
                paused_state: Some(Arc::clone(&paused_state)),
                ..Default::default()
            },
            artifact_root: snapshot_root.clone(),
            state: paused_state.encode()?,
        };
        let manifest = persister.write_manifest(&record).await?;
        let mut report = PausedSandboxRecoveryReport::default();

        let error = persister
            .index_manifest_or_quarantine(&manifest, &mut report)
            .await
            .expect_err("failed rebuild write must be uncertain");

        assert!(matches!(
            error,
            SandboxPersistenceError::UncertainCommit { .. }
        ));
        assert!(FileBackedSandboxPersister::recovery_marker_path(&snapshot_root).exists());
        let recovered_manifest = persister
            .read_manifest(
                &FileBackedSandboxPersister::manifest_path(&snapshot_root),
                None,
            )
            .await?;
        assert!(recovered_manifest.recovery_marker_present);
        assert!(recovered_manifest.record.metadata.resume_recovery_pending);
        assert_eq!(
            recovered_manifest.record.commit_state,
            PersistedPausedCommitState::Prepared
        );
        Ok(())
    }

    #[tokio::test]
    async fn prepared_manifest_without_marker_is_quarantined_and_loaded_only_recovery_pending(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = test_snapshot_root(&persister, &sandbox_id);
        let paused_state = paused_state(&snapshot_root);
        let mut metadata = SandboxMetadata {
            id: sandbox_id,
            paused_state: Some(Arc::clone(&paused_state)),
            ..Default::default()
        };
        metadata.resume_recovery_pending = true;
        metadata.paused_runtime_stopped = false;
        let record = PersistedPausedRecord {
            version: PAUSED_MANIFEST_VERSION,
            commit_state: PersistedPausedCommitState::Prepared,
            lifecycle: PersistedPausedLifecycle::Paused,
            resuming_boot_id: None,
            unproven_stop_boot_id: None,
            metadata,
            artifact_root: snapshot_root.clone(),
            state: paused_state.encode()?,
        };
        persister.write_manifest(&record).await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, sandbox_id);
        assert!(loaded[0].resume_recovery_pending);
        assert!(!loaded[0].paused_runtime_stopped);
        assert!(!FileBackedSandboxPersister::recovery_marker_path(&snapshot_root).exists());
        assert_eq!(persister.list_quarantines().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn explicit_purge_can_remove_a_known_marker_quarantine_but_not_a_replacement(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let (sandbox_id, snapshot_root, _paused_state) = persist_test_record(&persister).await?;
        persister
            .write_recovery_marker(sandbox_id, &snapshot_root)
            .await?;
        persister.load_all(&MockBackendFactory::new()).await?;
        let quarantine = persister
            .list_quarantines()
            .await?
            .into_iter()
            .next()
            .expect("marker should be indexed for host-local purge");

        persister.purge_quarantine(&quarantine.id).await?;

        assert!(!snapshot_root.exists());
        assert!(persister.list_quarantines().await?.is_empty());
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
    async fn persist_paused_preserves_and_quarantines_artifacts_when_encode_fails(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = test_snapshot_root(&persister, &sandbox_id);
        tokio::fs::create_dir_all(&snapshot_root).await?;
        let paused_state: Arc<dyn PausedSandboxState> = Arc::new(FailingEncodeState);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            ..Default::default()
        };
        let err = persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await
            .expect_err("encode failure should reject paused state");

        assert!(matches!(err, SandboxPersistenceError::InvalidRecord { .. }));
        assert!(snapshot_root.exists());
        assert_eq!(persister.list_quarantines().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn explicit_quarantine_purge_is_the_only_path_that_removes_quarantined_artifacts(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = test_snapshot_root(&persister, &sandbox_id);
        tokio::fs::create_dir_all(&snapshot_root).await?;
        let paused_state: Arc<dyn PausedSandboxState> = Arc::new(FailingEncodeState);
        let metadata = SandboxMetadata {
            id: sandbox_id,
            ..Default::default()
        };
        persister
            .persist_paused(&metadata, Some(&snapshot_root), paused_state.as_ref())
            .await
            .expect_err("encode failure should create a quarantine");
        let quarantine = persister
            .list_quarantines()
            .await?
            .into_iter()
            .next()
            .expect("failed encode should be quarantined");

        persister.purge_quarantine(&quarantine.id).await?;

        assert!(!snapshot_root.exists());
        assert!(persister.list_quarantines().await?.is_empty());
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
    async fn successful_resume_rehydrates_the_last_snapshot_on_startup() -> anyhow::Result<()> {
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

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, sandbox_id);
        assert_eq!(loaded[0].state, SandboxState::Paused);
        assert!(last_generation.exists());
        assert!(persister.list_quarantines().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn next_pause_retires_the_replaced_generation() -> anyhow::Result<()> {
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

        assert!(!first_generation.exists());
        assert!(second_generation.exists());
        Ok(())
    }

    #[tokio::test]
    async fn startup_restores_a_committed_resume_as_the_last_paused_snapshot() -> anyhow::Result<()>
    {
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
        let mut record = persister.get_record(&sandbox_id).await?;
        record.lifecycle = PersistedPausedLifecycle::Resumed;
        record.resuming_boot_id = None;
        persister.put_record(&record).await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, sandbox_id);
        assert_eq!(loaded[0].state, SandboxState::Paused);
        assert!(consumed_generation.exists());
        Ok(())
    }

    #[tokio::test]
    async fn load_all_preserves_and_quarantines_orphan_artifacts_without_records(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let artifact_root = persister
            .sandbox_artifact_root(&sandbox_id)
            .join("resumed-generation");
        tokio::fs::create_dir_all(&artifact_root).await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert!(loaded.is_empty());
        assert!(persister.sandbox_artifact_root(&sandbox_id).exists());
        assert_eq!(persister.list_quarantines().await?.len(), 1);
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
    async fn load_all_preserves_and_quarantines_unusable_record_and_artifacts() -> anyhow::Result<()>
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

        let loaded = persister.load_all(&RejectingFactory).await?;

        assert!(loaded.is_empty());
        assert!(persister.sandbox_artifact_root(&sandbox_id).exists());
        assert_eq!(persister.list_quarantines().await?.len(), 1);
        Ok(())
    }
}
