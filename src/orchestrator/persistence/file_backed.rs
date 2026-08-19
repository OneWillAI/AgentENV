use std::collections::{HashMap, HashSet};
use std::fs::{self as stdfs, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
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

/// Version one records live directly in RocksDB.  They remain readable so
/// existing paused sandboxes survive the upgrade, but every new write uses a
/// manifest and a small RocksDB index entry instead.
const LEGACY_RECORD_VERSION: u32 = 1;
const PAUSED_MANIFEST_VERSION: u32 = 2;
const PAUSED_INDEX_VERSION: u32 = 2;
const RECORD_DB_DIR: &str = "records.db";
const QUARANTINE_DB_DIR: &str = "quarantine.db";
const PAUSED_MANIFEST_FILE: &str = "paused-record.v2.json";
const PAUSED_RECOVERY_MARKER_FILE: &str = ".paused-record.v2.recovery-pending";
const QUARANTINE_VERSION: u32 = 1;
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

/// A manifest is first published as `Prepared`.  It is only promoted to
/// `Committed` after the synchronous index write has completed.  Any crash or
/// write error between those points restores the sandbox as recovery-pending,
/// rather than guessing that a snapshot is safe to resume or remove.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedPausedCommitState {
    Prepared,
    Committed,
}

fn default_commit_state() -> PersistedPausedCommitState {
    PersistedPausedCommitState::Committed
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedPausedRecord {
    version: u32,
    #[serde(default = "default_commit_state")]
    commit_state: PersistedPausedCommitState,
    lifecycle: PersistedPausedLifecycle,
    /// Linux boot identity captured before a resume can launch a new VM.
    /// Absent legacy records fail closed during startup recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resuming_boot_id: Option<String>,
    metadata: SandboxMetadata,
    artifact_root: PathBuf,
    state: Value,
}

/// RocksDB is deliberately just an index for v2 records.  The full record is
/// atomically stored with its snapshot artifacts, so a missing or damaged
/// index can be rebuilt without inventing state.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedPausedIndex {
    index_version: u32,
    sandbox_id: SandboxId,
    manifest_path: PathBuf,
    manifest_sha256: String,
}

#[derive(Clone, Debug)]
struct ManifestEntry {
    path: PathBuf,
    bytes: Vec<u8>,
    record: PersistedPausedRecord,
}

#[derive(Default)]
struct PausedRecoveryBlocks {
    sandbox_ids: HashSet<SandboxId>,
    artifact_roots: HashSet<PathBuf>,
    manifest_paths: HashSet<PathBuf>,
}

impl PausedRecoveryBlocks {
    fn contains_manifest(&self, entry: &ManifestEntry) -> bool {
        self.sandbox_ids.contains(&entry.sandbox_id())
            || self.artifact_roots.contains(&entry.record.artifact_root)
            || self.manifest_paths.contains(&entry.path)
    }

    fn contains_sandbox(&self, sandbox_id: &SandboxId) -> bool {
        self.sandbox_ids.contains(sandbox_id)
    }

    fn contains_record(&self, sandbox_id: &SandboxId, artifact_root: &Path) -> bool {
        self.contains_sandbox(sandbox_id) || self.artifact_roots.contains(artifact_root)
    }
}

impl ManifestEntry {
    fn sandbox_id(&self) -> SandboxId {
        self.record.metadata.id
    }

    fn fingerprint(&self) -> String {
        sha256_hex(&self.bytes)
    }

    fn matches_index(&self, index: &PersistedPausedIndex) -> bool {
        index.sandbox_id == self.sandbox_id()
            && index.manifest_path == self.path
            && index.manifest_sha256 == self.fingerprint()
    }
}

#[derive(Clone, Debug)]
enum StoredPausedEntry {
    Legacy(PersistedPausedRecord),
    Index(PersistedPausedIndex),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredPausedSandboxQuarantine {
    version: u32,
    id: String,
    reason: String,
    /// When true, normal startup must not load or delete a record matching
    /// this item. It has to be reviewed/reconciled by the host-local tool.
    #[serde(default = "default_true")]
    requires_manual_recovery: bool,
    /// Only ambiguous commits are eligible for an explicit `reconcile`
    /// promotion after their manifest and index can be proven coherent.
    #[serde(default)]
    reconcile_if_coherent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_key_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_bytes_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    artifact_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest_path: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

/// A host-local recovery item.  It is intentionally unavailable through the
/// HTTP API: an operator must run the recovery binary on the worker that owns
/// the persisted state.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PausedSandboxQuarantine {
    pub id: String,
    pub reason: String,
    pub requires_manual_recovery: bool,
    pub record_key: Option<String>,
    pub artifact_root: Option<PathBuf>,
    pub manifest_path: Option<PathBuf>,
}

impl From<StoredPausedSandboxQuarantine> for PausedSandboxQuarantine {
    fn from(value: StoredPausedSandboxQuarantine) -> Self {
        Self {
            id: value.id,
            reason: value.reason,
            requires_manual_recovery: value.requires_manual_recovery,
            record_key: value.record_key,
            artifact_root: value.artifact_root,
            manifest_path: value.manifest_path,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PausedSandboxRecoveryReport {
    pub indexed_manifests: usize,
    pub quarantined_items: usize,
    pub reconciled_quarantines: usize,
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
        ensure_supported_record_version(self.version)?;

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
    ensure_supported_record_version(record.version)?;
    Ok(record)
}

fn ensure_supported_record_version(version: u32) -> PersistenceResult<()> {
    if matches!(version, LEGACY_RECORD_VERSION | PAUSED_MANIFEST_VERSION) {
        Ok(())
    } else {
        Err(SandboxPersistenceError::InvalidRecord {
            reason: format!("unsupported record version {version}"),
            source: None,
        })
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_stored_paused_entry(bytes: &[u8]) -> PersistenceResult<StoredPausedEntry> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "failed to deserialize paused sandbox record or index".to_string(),
            source: Some(source.into()),
        })?;
    if value.get("indexVersion").is_some() {
        let index: PersistedPausedIndex = serde_json::from_value(value).map_err(|source| {
            SandboxPersistenceError::InvalidRecord {
                reason: "failed to deserialize paused sandbox index".to_string(),
                source: Some(source.into()),
            }
        })?;
        if index.index_version != PAUSED_INDEX_VERSION {
            return Err(SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "unsupported paused sandbox index version {}",
                    index.index_version
                ),
                source: None,
            });
        }
        return Ok(StoredPausedEntry::Index(index));
    }

    let record = decode_record(bytes)?;
    if record.version != LEGACY_RECORD_VERSION {
        return Err(SandboxPersistenceError::InvalidRecord {
            reason: format!(
                "paused sandbox record version {} must be stored in a v2 manifest",
                record.version
            ),
            source: None,
        });
    }
    Ok(StoredPausedEntry::Legacy(record))
}

fn sync_regular_file(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(target_os = "linux")]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

// APFS does not support fsync on directories.  The runtime data-safety
// contract is enforced on Linux workers; this lets host-side unit tests run on
// development Macs without silently weakening the production path.
#[cfg(not(target_os = "linux"))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn sync_tree_bottom_up(path: &Path) -> std::io::Result<()> {
    let metadata = stdfs::symlink_metadata(path)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        // The snapshot producer may deliberately use links to immutable image
        // cache layers.  Do not follow arbitrary links while syncing a
        // recovery tree; their target is not owned by this persistence record.
        return Ok(());
    }
    if file_type.is_file() {
        return sync_regular_file(path);
    }
    if !file_type.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "unsupported paused snapshot artifact type at {}",
                path.display()
            ),
        ));
    }
    for entry in stdfs::read_dir(path)? {
        sync_tree_bottom_up(&entry?.path())?;
    }
    sync_directory(path)
}

fn sync_directory_chain(start: &Path, root: &Path) -> std::io::Result<()> {
    let mut current = Some(start);
    while let Some(directory) = current {
        sync_directory(directory)?;
        if directory == root {
            break;
        }
        current = directory.parent();
    }
    Ok(())
}

fn sync_artifact_tree_and_parents(artifact_root: &Path, root: &Path) -> std::io::Result<()> {
    sync_tree_bottom_up(artifact_root)?;
    let parent = artifact_root.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "paused snapshot artifact root {} has no parent",
                artifact_root.display()
            ),
        )
    })?;
    sync_directory_chain(parent, root)
}

fn write_file_atomically_and_sync(path: &Path, bytes: &[u8], root: &Path) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "paused sandbox manifest path {} has no parent",
                path.display()
            ),
        )
    })?;
    stdfs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_directory_chain(parent, root)
}

fn remove_file_and_sync(path: &Path, root: &Path) -> std::io::Result<()> {
    match stdfs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "paused sandbox recovery marker path {} has no parent",
                path.display()
            ),
        )
    })?;
    sync_directory_chain(parent, root)
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
        // Canonicalization and component-by-component symlink rejection are
        // both required: a syntactically rooted path such as
        // `<store>/artifacts/../../other`, or an artifact-tree symlink, must
        // never become eligible for read-through recovery or purge.
        let relative = path.strip_prefix(&self.root).ok()?;
        let mut components = relative.components();
        if !matches!(components.next(), Some(Component::Normal(name)) if name == "artifacts") {
            return None;
        }
        let mut probe = self.root.clone();
        probe.push("artifacts");
        if matches!(stdfs::symlink_metadata(&probe), Ok(metadata) if metadata.file_type().is_symlink())
        {
            return None;
        }
        for component in components {
            let Component::Normal(component) = component else {
                return None;
            };
            probe.push(component);
            if matches!(stdfs::symlink_metadata(&probe), Ok(metadata) if metadata.file_type().is_symlink())
            {
                return None;
            }
        }
        let root = stdfs::canonicalize(&self.root).ok()?;
        let candidate = stdfs::canonicalize(path).ok()?;
        if candidate == root || !candidate.starts_with(&root) {
            return None;
        }

        let avoids_databases = [
            self.records_db_path(),
            self.quarantine_db_path(),
            self.create_idempotency_db_path(),
        ]
        .into_iter()
        .filter_map(|database_path| stdfs::canonicalize(database_path).ok())
        .all(|database_path| !candidate.starts_with(database_path));
        avoids_databases.then_some(candidate)
    }

    fn path_is_managed_artifact(&self, path: &Path) -> bool {
        self.validated_managed_artifact_path(path).is_some()
    }

    fn validated_managed_generation_path(
        &self,
        sandbox_id: &SandboxId,
        path: &Path,
    ) -> Option<PathBuf> {
        let relative = path.strip_prefix(self.artifacts_root()).ok()?;
        let mut components = relative.components();
        let Some(Component::Normal(found_sandbox_id)) = components.next() else {
            return None;
        };
        if found_sandbox_id.to_string_lossy() != sandbox_id.to_string() {
            return None;
        }
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return None;
        }
        self.validated_purgeable_artifact_path(path)
    }

    fn path_is_managed_generation(&self, sandbox_id: &SandboxId, path: &Path) -> bool {
        self.validated_managed_generation_path(sandbox_id, path)
            .is_some()
    }

    fn validated_purgeable_artifact_path(&self, path: &Path) -> Option<PathBuf> {
        let relative = path.strip_prefix(self.artifacts_root()).ok()?;
        let mut components = relative.components();
        let Some(Component::Normal(sandbox_id)) = components.next() else {
            return None;
        };
        if SandboxId::parse_str(&sandbox_id.to_string_lossy()).is_err() {
            return None;
        }
        let generation = match (components.next(), components.next()) {
            (None, None) => None,
            (Some(Component::Normal(generation)), None) => Some(generation),
            _ => return None,
        };
        let artifacts_root = self.artifacts_root();
        let canonical_artifacts = match stdfs::symlink_metadata(&artifacts_root) {
            Ok(metadata) if metadata.file_type().is_symlink() => return None,
            Ok(_) => self.validated_managed_artifact_path(&artifacts_root)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                stdfs::canonicalize(&self.root).ok()?.join("artifacts")
            }
            Err(_) => return None,
        };
        let sandbox_path = self.artifacts_root().join(sandbox_id);
        let canonical_parent = match generation {
            None => canonical_artifacts,
            Some(_) => match stdfs::symlink_metadata(&sandbox_path) {
                Ok(metadata) if metadata.file_type().is_symlink() => return None,
                Ok(_) => {
                    let canonical_sandbox = stdfs::canonicalize(&sandbox_path).ok()?;
                    (canonical_sandbox.parent() == Some(canonical_artifacts.as_path()))
                        .then_some(canonical_sandbox)?
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    canonical_artifacts.join(sandbox_id)
                }
                Err(_) => return None,
            },
        };
        match stdfs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => None,
            Ok(_) => {
                let canonical_target = stdfs::canonicalize(path).ok()?;
                (canonical_target.parent() == Some(canonical_parent.as_path()))
                    .then_some(canonical_target)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Some(canonical_parent.join(path.file_name()?))
            }
            Err(_) => None,
        }
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
        let entry = StoredPausedSandboxQuarantine {
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
        let bytes = serde_json::to_vec(&entry).map_err(|source| {
            SandboxPersistenceError::InvalidRecord {
                reason: "failed to serialize paused sandbox quarantine record".to_string(),
                source: Some(source.into()),
            }
        })?;
        self.quarantine_db()
            .await?
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
        if let Err(marker_error) = self.write_recovery_marker(sandbox_id, artifact_root).await {
            warn!(
                sandbox_id = %sandbox_id,
                error = %marker_error,
                "failed to durably mark uncertain paused sandbox commit"
            );
        }
        let mut recovery_record = record.clone();
        recovery_record.version = PAUSED_MANIFEST_VERSION;
        recovery_record.commit_state = PersistedPausedCommitState::Prepared;
        recovery_record.metadata.resume_recovery_pending = true;
        recovery_record.metadata.paused_runtime_stopped = false;
        if let Err(manifest_error) = self.write_manifest(&recovery_record).await {
            warn!(
                sandbox_id = %sandbox_id,
                error = %manifest_error,
                "failed to publish recovery-pending paused sandbox manifest"
            );
        }
        if let Err(quarantine_error) = self
            .quarantine_uncertain(
                format!("{reason}; original write error: {source}"),
                Some(record_key.as_bytes()),
                None,
                Some(artifact_root),
                Some(&manifest_path),
            )
            .await
        {
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
        match decode_stored_paused_entry(&bytes)? {
            StoredPausedEntry::Legacy(record) => {
                if record.metadata.id != *sandbox_id {
                    return Err(SandboxPersistenceError::InvalidRecord {
                        reason: format!(
                            "paused sandbox record key {sandbox_id} contains metadata for {}",
                            record.metadata.id
                        ),
                        source: None,
                    });
                }
                Ok(record)
            }
            StoredPausedEntry::Index(index) => self.resolve_index(sandbox_id, &index).await,
        }
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
        match fs::symlink_metadata(&marker_path).await {
            Ok(metadata) if metadata.file_type().is_file() => {
                // The marker is deliberately fail-closed. Its presence means
                // a metadata write was observed as ambiguous, even if RocksDB
                // later happens to contain a matching index.
                record.metadata.resume_recovery_pending = true;
                record.metadata.paused_runtime_stopped = false;
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
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(SandboxPersistenceError::io(
                    "inspect paused sandbox recovery marker",
                    &marker_path,
                    source,
                ));
            }
        }
        Ok(ManifestEntry {
            path: manifest_path.to_path_buf(),
            bytes,
            record,
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
            write_file_atomically_and_sync(&manifest_path_for_write, &bytes_for_write, &root)
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
            write_file_atomically_and_sync(&marker_path_for_write, &bytes, &root)
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
        tokio::task::spawn_blocking(move || remove_file_and_sync(&marker_path_for_remove, &root))
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
            sync_artifact_tree_and_parents(&sync_artifact_root, &sync_root)
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
        match fs::symlink_metadata(path).await {
            Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(path).await,
            Ok(_) => fs::remove_file(path).await,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(source) => {
                return Err(SandboxPersistenceError::io(
                    "inspect paused sandbox artifacts",
                    path,
                    source,
                ));
            }
        }
        .map_err(|source| {
            SandboxPersistenceError::io("remove paused sandbox artifacts", path, source)
        })
    }

    /// Remove only the generation consumed by a committed resume. New pause
    /// cycles allocate separate generation directories, so deleting the whole
    /// `<sandbox-id>` directory here would reintroduce a resume/pause race.
    async fn cleanup_consumed_resume_generation(
        &self,
        sandbox_id: &SandboxId,
        artifact_root: &Path,
    ) -> PersistenceResult<()> {
        let canonical_artifact_root = self
            .validated_managed_generation_path(sandbox_id, artifact_root)
            .ok_or_else(|| SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "refusing cleanup for paused sandbox {sandbox_id}: artifact root is not an exact managed generation"
                ),
                source: None,
            })?;
        Self::remove_artifact_root(&canonical_artifact_root).await
    }

    /// Make successful-resume cleanup crash-safe. The `Resumed` marker is the
    /// durable commit point: if the process dies before it, startup retains a
    /// `Resuming` tombstone; if it dies after it, startup can finish deleting
    /// exactly this generation and the index.
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

        self.cleanup_consumed_resume_generation(sandbox_id, &record.artifact_root)
            .await?;
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
        match fs::symlink_metadata(&manifest_path).await {
            Ok(metadata) if metadata.file_type().is_file() => {
                match self
                    .read_manifest(&manifest_path, expected_sandbox_id)
                    .await
                {
                    Ok(entry) => entries.push(entry),
                    Err(error) => {
                        warn!(manifest = %manifest_path.display(), error = %error, "quarantining invalid paused sandbox manifest");
                        self.quarantine(
                            format!("invalid paused sandbox manifest: {error}"),
                            None,
                            None,
                            Some(directory),
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
                    Some(directory),
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
    async fn scan_manifests(
        &self,
        legacy_artifact_roots: &HashSet<PathBuf>,
    ) -> PersistenceResult<(Vec<ManifestEntry>, usize)> {
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
                if stdfs::canonicalize(&generation_path)
                    .ok()
                    .is_some_and(|path| legacy_artifact_roots.contains(&path))
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
        self.write_index(entry).await.map_err(|source| {
            SandboxPersistenceError::UncertainCommit {
                sandbox_id: entry.sandbox_id(),
                reason: "failed to rebuild paused sandbox index from a valid manifest".to_string(),
                source: Some(anyhow::Error::new(source)),
            }
        })?;
        report.indexed_manifests += 1;
        Ok(())
    }

    async fn reconcile_manifest_index(
        &self,
        allow_manual_recovery: bool,
    ) -> PersistenceResult<(
        Vec<PersistedPausedRecord>,
        Vec<PersistedPausedRecord>,
        PausedSandboxRecoveryReport,
    )> {
        let entries = self.db().await?.entries().await.map_err(|source| {
            SandboxPersistenceError::store("scan paused sandbox records", source)
        })?;

        // A valid v1 record is still the source of truth for its snapshot
        // tree. Discover it before looking for markerless generations so the
        // migration scanner never quarantines a valid legacy pause.
        let legacy_artifact_roots = entries
            .iter()
            .filter_map(|(key, bytes)| {
                let key_id = std::str::from_utf8(key)
                    .ok()
                    .and_then(|value| SandboxId::parse_str(value).ok())?;
                let StoredPausedEntry::Legacy(record) = decode_stored_paused_entry(bytes).ok()?
                else {
                    return None;
                };
                (record.metadata.id == key_id
                    && self.path_is_managed_generation(&key_id, &record.artifact_root))
                .then(|| stdfs::canonicalize(record.artifact_root).ok())
                .flatten()
            })
            .collect::<HashSet<_>>();
        let (manifests, mut quarantined) = self.scan_manifests(&legacy_artifact_roots).await?;
        let mut report = PausedSandboxRecoveryReport {
            indexed_manifests: 0,
            quarantined_items: quarantined,
            reconciled_quarantines: 0,
        };

        let mut candidates = HashMap::new();
        let mut duplicate_ids = HashSet::new();
        for entry in manifests {
            let sandbox_id = entry.sandbox_id();
            if let Some(previous) = candidates.insert(sandbox_id, entry.clone()) {
                duplicate_ids.insert(sandbox_id);
                self.quarantine(
                    "multiple paused sandbox manifests claim the same sandbox ID",
                    None,
                    None,
                    Some(&previous.record.artifact_root),
                    Some(&previous.path),
                )
                .await?;
                self.quarantine(
                    "multiple paused sandbox manifests claim the same sandbox ID",
                    None,
                    None,
                    Some(&entry.record.artifact_root),
                    Some(&entry.path),
                )
                .await?;
                quarantined += 2;
            }
        }
        for sandbox_id in &duplicate_ids {
            candidates.remove(sandbox_id);
        }
        report.quarantined_items = quarantined;

        let recovery_blocks = if allow_manual_recovery {
            PausedRecoveryBlocks::default()
        } else {
            self.recovery_blocks().await?
        };
        let mut selected_v2 = HashMap::new();
        let mut legacy = Vec::new();
        let mut blocked = duplicate_ids;
        for (sandbox_id, candidate) in &candidates {
            if recovery_blocks.contains_manifest(candidate) {
                blocked.insert(*sandbox_id);
            }
        }

        for (key, bytes) in entries {
            let key_id = std::str::from_utf8(&key)
                .ok()
                .and_then(|value| SandboxId::parse_str(value).ok());
            match decode_stored_paused_entry(&bytes) {
                Ok(StoredPausedEntry::Legacy(record)) => {
                    let sandbox_id = record.metadata.id;
                    if key_id != Some(sandbox_id) {
                        self.quarantine(
                            "legacy paused sandbox record key does not match metadata",
                            Some(&key),
                            Some(&bytes),
                            Some(&record.artifact_root),
                            None,
                        )
                        .await?;
                        report.quarantined_items += 1;
                    } else if candidates.contains_key(&sandbox_id) {
                        self.quarantine(
                            "legacy paused sandbox record conflicts with a v2 manifest",
                            Some(&key),
                            Some(&bytes),
                            Some(&record.artifact_root),
                            None,
                        )
                        .await?;
                        if let Some(candidate) = candidates.get(&sandbox_id) {
                            self.quarantine(
                                "v2 paused sandbox manifest conflicts with a legacy record",
                                None,
                                None,
                                Some(&candidate.record.artifact_root),
                                Some(&candidate.path),
                            )
                            .await?;
                        }
                        report.quarantined_items += 2;
                        blocked.insert(sandbox_id);
                    } else if !self.path_is_managed_generation(&sandbox_id, &record.artifact_root) {
                        self.quarantine(
                            "legacy paused sandbox record references an unsafe artifact path",
                            Some(&key),
                            Some(&bytes),
                            Some(&record.artifact_root),
                            None,
                        )
                        .await?;
                        report.quarantined_items += 1;
                        blocked.insert(sandbox_id);
                    } else if recovery_blocks.contains_record(&sandbox_id, &record.artifact_root) {
                        blocked.insert(sandbox_id);
                    } else {
                        legacy.push(record);
                    }
                }
                Ok(StoredPausedEntry::Index(index)) => {
                    let Some(sandbox_id) = key_id else {
                        self.quarantine(
                            "paused sandbox index has a non-sandbox record key",
                            Some(&key),
                            Some(&bytes),
                            None,
                            Some(&index.manifest_path),
                        )
                        .await?;
                        report.quarantined_items += 1;
                        continue;
                    };
                    if blocked.contains(&sandbox_id)
                        || recovery_blocks.contains_sandbox(&sandbox_id)
                    {
                        blocked.insert(sandbox_id);
                        continue;
                    }

                    let candidate = candidates.get(&sandbox_id);
                    let explicit_mismatch = index.index_version != PAUSED_INDEX_VERSION
                        || index.sandbox_id != sandbox_id
                        || !self.path_is_managed_artifact(&index.manifest_path)
                        || candidate.is_some_and(|entry| !entry.matches_index(&index));
                    if explicit_mismatch {
                        self.quarantine(
                            "paused sandbox index and manifest identity disagree",
                            Some(&key),
                            Some(&bytes),
                            candidate.map(|entry| entry.record.artifact_root.as_path()),
                            Some(&index.manifest_path),
                        )
                        .await?;
                        report.quarantined_items += 1;
                        blocked.insert(sandbox_id);
                        continue;
                    }

                    match self.resolve_index(&sandbox_id, &index).await {
                        Ok(record) => {
                            selected_v2.insert(sandbox_id, record);
                        }
                        Err(error) => {
                            // A decoded index that cannot resolve its declared
                            // manifest is a mismatch, not a repair candidate.
                            self.quarantine(
                                format!("paused sandbox index/manifest mismatch: {error}"),
                                Some(&key),
                                Some(&bytes),
                                candidate.map(|entry| entry.record.artifact_root.as_path()),
                                Some(&index.manifest_path),
                            )
                            .await?;
                            report.quarantined_items += 1;
                            blocked.insert(sandbox_id);
                        }
                    }
                }
                Err(error) => {
                    let inferred_artifact_root =
                        key_id.map(|sandbox_id| self.sandbox_artifact_root(&sandbox_id));
                    self.quarantine(
                        format!("invalid or unsupported paused sandbox record: {error}"),
                        Some(&key),
                        Some(&bytes),
                        inferred_artifact_root.as_deref(),
                        None,
                    )
                    .await?;
                    report.quarantined_items += 1;
                    if let Some(sandbox_id) = key_id {
                        blocked.insert(sandbox_id);
                    }
                }
            }
        }

        for (sandbox_id, candidate) in candidates {
            if selected_v2.contains_key(&sandbox_id)
                || blocked.contains(&sandbox_id)
                || recovery_blocks.contains_manifest(&candidate)
            {
                continue;
            }
            self.index_manifest_or_quarantine(&candidate, &mut report)
                .await?;
            selected_v2.insert(sandbox_id, candidate.record);
        }

        Ok((selected_v2.into_values().collect(), legacy, report))
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
        let (_v2, _legacy, mut report) = self.reconcile_manifest_index(true).await?;
        report.reconciled_quarantines = self.reconcile_uncertain_quarantines().await?;
        Ok(report)
    }

    /// Explicit destructive recovery action.  It never follows paths outside
    /// this persister's artifacts directory, and it never deletes a newer
    /// index entry that differs from the quarantined original bytes.
    pub async fn purge_quarantine(&self, quarantine_id: &str) -> PersistenceResult<()> {
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

        let mut remove_record = None;
        if let Some(record_key) = entry.record_key.as_deref() {
            let current = self
                .db()
                .await?
                .get(record_key.as_bytes().to_vec())
                .await
                .map_err(|source| {
                    SandboxPersistenceError::store("read paused sandbox index before purge", source)
                })?;
            match (current, entry.record_sha256.as_deref()) {
                (Some(current), Some(expected_hash)) if sha256_hex(&current) == expected_hash => {
                    remove_record = Some(record_key.to_owned());
                }
                (Some(_), _) => {
                    return Err(SandboxPersistenceError::InvalidRecord {
                        reason: format!(
                            "refusing to purge paused sandbox quarantine {quarantine_id}: its record key now points at newer or unknown state"
                        ),
                        source: None,
                    });
                }
                (None, _) => {}
            }
        }
        if let Some(path) = entry.artifact_root.as_deref() {
            let canonical_artifact_path = self
                .validated_purgeable_artifact_path(path)
                .ok_or_else(|| SandboxPersistenceError::InvalidRecord {
                    reason: format!(
                        "refusing to purge paused sandbox quarantine {quarantine_id}: artifact path is not a managed sandbox root or generation"
                    ),
                    source: None,
                })?;
            Self::remove_artifact_root(&canonical_artifact_path).await?;
        }
        if let Some(record_key) = remove_record {
            self.db()
                .await?
                .delete(record_key.as_bytes().to_vec())
                .await
                .map_err(|source| {
                    SandboxPersistenceError::store("purge paused sandbox index", source)
                })?;
        }
        self.quarantine_db()
            .await?
            .delete(quarantine_id.as_bytes().to_vec())
            .await
            .map_err(|source| {
                SandboxPersistenceError::store("delete paused sandbox quarantine", source)
            })
    }
}

#[async_trait]
impl SandboxPersister for FileBackedSandboxPersister {
    async fn load_all<F>(&self, factory: &F) -> PersistenceResult<Vec<SandboxMetadata>>
    where
        F: SandboxBackendFactory,
    {
        info!(store = %self.root.display(), "loading paused sandbox records");
        let (mut v2_records, legacy_records, recovery_report) =
            self.reconcile_manifest_index(false).await?;
        v2_records.extend(legacy_records);
        let mut sandboxes = Vec::new();
        let mut seen_sandbox_ids = HashSet::new();

        for mut record in v2_records {
            let sandbox_id = record.metadata.id;
            let record_artifact_root = record.artifact_root.clone();
            let record_manifest_path = (record.version == PAUSED_MANIFEST_VERSION)
                .then(|| Self::manifest_path(&record_artifact_root));
            if !seen_sandbox_ids.insert(sandbox_id) {
                self.quarantine(
                    "multiple persisted paused records claim the same sandbox ID",
                    None,
                    None,
                    Some(&record_artifact_root),
                    record_manifest_path.as_deref(),
                )
                .await?;
                continue;
            }

            if record.commit_state == PersistedPausedCommitState::Prepared
                || record.metadata.resume_recovery_pending
            {
                warn!(sandbox_id = %sandbox_id, "retaining paused sandbox whose persistence commit is recovery-pending");
                record.metadata.resume_recovery_pending = true;
                record.metadata.paused_runtime_stopped = false;
                if record.metadata.virtualization_mode != self.virtualization_mode {
                    sandboxes.push(record.into_metadata_without_runtime_state());
                } else {
                    match record.into_recovery_pending_metadata(factory) {
                        Ok(metadata) => sandboxes.push(metadata),
                        Err(error) => {
                            self.quarantine(
                                format!(
                                    "recovery-pending paused sandbox could not be decoded: {error}"
                                ),
                                None,
                                None,
                                Some(&record_artifact_root),
                                record_manifest_path.as_deref(),
                            )
                            .await?;
                        }
                    }
                }
                continue;
            }

            if record.lifecycle == PersistedPausedLifecycle::Resumed {
                info!(sandbox_id = %sandbox_id, "finishing committed resumed sandbox cleanup");
                self.finalize_resumed_record(&sandbox_id).await?;
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
                    if record.metadata.virtualization_mode != self.virtualization_mode {
                        let mut metadata = record.into_metadata_without_runtime_state();
                        metadata.paused_runtime_stopped = false;
                        metadata.resume_recovery_pending = true;
                        sandboxes.push(metadata);
                    } else {
                        match record.into_recovery_pending_metadata(factory) {
                            Ok(metadata) => sandboxes.push(metadata),
                            Err(err) => {
                                warn!(sandbox_id = %sandbox_id, error = %err, "quarantining interrupted resume whose paused state could not be decoded");
                                self.quarantine(
                                    format!(
                                        "interrupted resume paused sandbox state could not be decoded: {err}"
                                    ),
                                    None,
                                    None,
                                    Some(&record_artifact_root),
                                    record_manifest_path.as_deref(),
                                )
                                .await?;
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
                sandboxes.push(record.into_metadata_without_runtime_state());
                continue;
            }

            match record.into_metadata(factory) {
                Ok(metadata) => {
                    sandboxes.push(metadata);
                }
                Err(err) => {
                    warn!(sandbox_id = %sandbox_id, error = %err, "quarantining unusable paused sandbox record without deleting artifacts");
                    self.quarantine(
                        format!("paused sandbox state could not be decoded: {err}"),
                        None,
                        None,
                        Some(&record_artifact_root),
                        record_manifest_path.as_deref(),
                    )
                    .await?;
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
            metadata: metadata.clone(),
            artifact_root: artifact_root.to_path_buf(),
            state,
        };
        self.put_record(&record).await
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
        let record = match self.get_record(sandbox_id).await {
            Ok(record) => record,
            Err(SandboxPersistenceError::InvalidRecord { reason, source })
                if reason == format!("paused sandbox record {sandbox_id} not found") =>
            {
                let sandbox_root = self.sandbox_artifact_root(sandbox_id);
                let record_key = sandbox_id.to_string();
                if fs::symlink_metadata(&sandbox_root).await.is_ok() {
                    self.quarantine(
                        "refusing automatic deletion of unreferenced paused sandbox artifacts",
                        Some(record_key.as_bytes()),
                        None,
                        Some(&sandbox_root),
                        None,
                    )
                    .await?;
                    return Err(SandboxPersistenceError::InvalidRecord {
                        reason: format!(
                            "paused sandbox {sandbox_id} has unreferenced artifacts; use the host-local recovery purge command"
                        ),
                        source,
                    });
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
                let sandbox_root = self.sandbox_artifact_root(sandbox_id);
                let artifact_root = fs::symlink_metadata(&sandbox_root)
                    .await
                    .ok()
                    .map(|_| sandbox_root.as_path());
                self.quarantine(
                    format!(
                        "refusing automatic deletion of invalid paused sandbox record: {error}"
                    ),
                    Some(record_key.as_bytes()),
                    record_bytes.as_deref(),
                    artifact_root,
                    None,
                )
                .await?;
                return Err(error);
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
        let canonical_artifact_root = self
            .validated_managed_generation_path(sandbox_id, &record.artifact_root)
            .ok_or_else(|| SandboxPersistenceError::InvalidRecord {
                reason: format!(
                    "refusing automatic deletion of paused sandbox {sandbox_id}: artifact root is not an exact managed generation"
                ),
                source: None,
            })?;
        self.remove_record(sandbox_id).await?;
        // Delete only the indexed generation.  Any sibling generation may be
        // a quarantine candidate and must remain until an administrator
        // explicitly purges it.
        Self::remove_artifact_root(&canonical_artifact_root).await?;
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
    async fn v2_manifest_is_durable_source_and_rocksdb_contains_only_its_index(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        let (sandbox_id, _paused_state) = persist_test_record(&persister, &snapshot_root).await?;

        let index_bytes = persister
            .db()
            .await?
            .get(sandbox_id.to_string())
            .await?
            .expect("v2 record index should be present");
        let StoredPausedEntry::Index(index) = decode_stored_paused_entry(&index_bytes)? else {
            anyhow::bail!("v2 paused records must be stored as manifest indexes");
        };
        let manifest = persister
            .read_manifest(
                &FileBackedSandboxPersister::manifest_path(&snapshot_root),
                None,
            )
            .await?;

        assert_eq!(manifest.record.version, PAUSED_MANIFEST_VERSION);
        assert_eq!(
            manifest.record.commit_state,
            PersistedPausedCommitState::Committed
        );
        assert!(manifest.matches_index(&index));
        Ok(())
    }

    #[tokio::test]
    async fn load_all_rebuilds_a_missing_v2_index_from_a_valid_manifest() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        let (sandbox_id, _paused_state) = persist_test_record(&persister, &snapshot_root).await?;
        persister.db().await?.delete(sandbox_id.to_string()).await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, sandbox_id);
        assert!(has_record(&persister, &sandbox_id).await?);
        assert!(persister.list_quarantines().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn load_all_rebuilds_a_corrupt_v2_index_without_deleting_its_artifacts(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        let (sandbox_id, _paused_state) = persist_test_record(&persister, &snapshot_root).await?;
        persister
            .db()
            .await?
            .put(sandbox_id.to_string(), b"corrupt-index")
            .await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, sandbox_id);
        assert!(snapshot_root.exists());
        assert!(matches!(
            decode_stored_paused_entry(
                &persister
                    .db()
                    .await?
                    .get(sandbox_id.to_string())
                    .await?
                    .expect("replacement index should be present")
            )?,
            StoredPausedEntry::Index(_)
        ));
        assert!(!persister.list_quarantines().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn valid_legacy_v1_record_remains_readable() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let snapshot_root = temp.path().join("legacy-artifacts");
        let paused_state = paused_state(&snapshot_root);
        let record = PersistedPausedRecord {
            version: LEGACY_RECORD_VERSION,
            commit_state: PersistedPausedCommitState::Committed,
            lifecycle: PersistedPausedLifecycle::Paused,
            resuming_boot_id: None,
            metadata: SandboxMetadata {
                id: sandbox_id,
                paused_state: Some(Arc::clone(&paused_state)),
                ..Default::default()
            },
            artifact_root: snapshot_root.clone(),
            state: paused_state.encode()?,
        };
        persister
            .db()
            .await?
            .put(sandbox_id.to_string(), serde_json::to_vec(&record)?)
            .await?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, sandbox_id);
        assert!(has_record(&persister, &sandbox_id).await?);
        assert!(persister.list_quarantines().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn missing_v2_commit_state_is_quarantined_without_deleting_the_manifest(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        let (sandbox_id, _paused_state) = persist_test_record(&persister, &snapshot_root).await?;
        let manifest_path = FileBackedSandboxPersister::manifest_path(&snapshot_root);
        let mut value: Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
        value
            .as_object_mut()
            .expect("paused manifest is a JSON object")
            .remove("commitState");
        std::fs::write(&manifest_path, serde_json::to_vec(&value)?)?;

        let loaded = persister.load_all(&MockBackendFactory::new()).await?;

        assert!(loaded.is_empty());
        assert!(has_record(&persister, &sandbox_id).await?);
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
        let snapshot_root = temp.path().join("artifacts");
        let paused_state = paused_state(&snapshot_root);
        let metadata = SandboxMetadata {
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
        assert_eq!(persister.list_quarantines().await?.len(), 1);
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
    async fn persist_paused_preserves_and_quarantines_artifacts_when_encode_fails(
    ) -> anyhow::Result<()> {
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
        assert!(snapshot_root.exists());
        assert_eq!(persister.list_quarantines().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn explicit_quarantine_purge_is_the_only_path_that_removes_quarantined_artifacts(
    ) -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let snapshot_root = temp.path().join("artifacts");
        tokio::fs::create_dir_all(&snapshot_root).await?;
        let paused_state: Arc<dyn PausedSandboxState> = Arc::new(FailingEncodeState);
        persister
            .persist_paused(
                &SandboxMetadata::default(),
                Some(&snapshot_root),
                paused_state.as_ref(),
            )
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

        assert!(!has_record(&persister, &sandbox_id).await?);
        assert!(!snapshot_root.exists());
        Ok(())
    }

    #[tokio::test]
    async fn delete_record_and_artifacts_refuses_unreferenced_artifacts() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        let sandbox_artifact_root = persister.sandbox_artifact_root(&sandbox_id);
        tokio::fs::create_dir_all(sandbox_artifact_root.join("stale-generation")).await?;

        let err = persister
            .delete_record_and_artifacts(&sandbox_id)
            .await
            .expect_err("unreferenced artifacts must require explicit recovery purge");

        assert!(matches!(err, SandboxPersistenceError::InvalidRecord { .. }));
        assert!(sandbox_artifact_root.exists());
        assert_eq!(persister.list_quarantines().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn delete_record_and_artifacts_refuses_invalid_record() -> anyhow::Result<()> {
        let temp = TempDir::new()?;
        let persister = test_persister(temp.path());
        let sandbox_id = SandboxId::new();
        persister
            .db()
            .await?
            .put(sandbox_id.to_string(), b"not-json")
            .await?;

        let err = persister
            .delete_record_and_artifacts(&sandbox_id)
            .await
            .expect_err("invalid records must not be removed automatically");

        assert!(matches!(err, SandboxPersistenceError::InvalidRecord { .. }));
        assert!(has_record(&persister, &sandbox_id).await?);
        assert_eq!(persister.list_quarantines().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn load_all_preserves_and_quarantines_invalid_record() -> anyhow::Result<()> {
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
        assert!(has_record(&persister, &sandbox_id).await?);
        assert_eq!(persister.list_quarantines().await?.len(), 1);
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
        assert!(has_record(&persister, &sandbox_id).await?);
        assert!(persister.sandbox_artifact_root(&sandbox_id).exists());
        assert_eq!(persister.list_quarantines().await?.len(), 1);
        Ok(())
    }
}
