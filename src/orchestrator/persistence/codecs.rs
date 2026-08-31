//! Versioned on-disk representations and their codecs.
//!
//! Persistence policy lives in the persister; this module only knows how to
//! decode the records that have existed in the store. Keeping these codecs
//! separate makes compatibility changes reviewable without mixing them with
//! filesystem or recovery actions.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::paused_transactions::{PersistedPausedCommitState, PersistedPausedLifecycle};
use super::{PersistenceResult, SandboxPersistenceError};
use crate::orchestrator::{store::SandboxMetadata, SandboxState};
use crate::sandbox::SandboxBackendFactory;
use crate::types::SandboxId;

pub(super) const LEGACY_RECORD_VERSION: u32 = 1;
pub(super) const PAUSED_MANIFEST_VERSION: u32 = 2;
pub(super) const PAUSED_INDEX_VERSION: u32 = 2;
pub(super) const PAUSED_MANIFEST_FILE: &str = "paused-record.v2.json";
pub(super) const PAUSED_RECOVERY_MARKER_FILE: &str = ".paused-record.v2.recovery-pending";
pub(super) const QUARANTINE_VERSION: u32 = 1;
pub(super) const CREATE_IDEMPOTENCY_RECORD_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PersistedPausedRecord {
    pub(super) version: u32,
    #[serde(default = "default_commit_state")]
    pub(super) commit_state: PersistedPausedCommitState,
    pub(super) lifecycle: PersistedPausedLifecycle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) resuming_boot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) unproven_stop_boot_id: Option<String>,
    pub(super) metadata: SandboxMetadata,
    pub(super) artifact_root: PathBuf,
    pub(super) state: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PersistedPausedIndex {
    pub(super) index_version: u32,
    pub(super) sandbox_id: SandboxId,
    pub(super) manifest_path: PathBuf,
    pub(super) manifest_sha256: String,
}

#[derive(Clone, Debug)]
pub(super) struct ManifestEntry {
    pub(super) path: PathBuf,
    pub(super) bytes: Vec<u8>,
    pub(super) record: PersistedPausedRecord,
    pub(super) recovery_marker_present: bool,
}

impl ManifestEntry {
    pub(super) fn sandbox_id(&self) -> SandboxId {
        self.record.metadata.id
    }

    pub(super) fn fingerprint(&self) -> String {
        sha256_hex(&self.bytes)
    }

    pub(super) fn matches_index(&self, index: &PersistedPausedIndex) -> bool {
        index.sandbox_id == self.sandbox_id()
            && index.manifest_path == self.path
            && index.manifest_sha256 == self.fingerprint()
    }
}

#[derive(Clone, Debug)]
pub(super) enum StoredPausedEntry {
    Legacy(PersistedPausedRecord),
    Index(PersistedPausedIndex),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PersistedCreateIdempotencyRecord {
    pub(super) version: u32,
    pub(super) record: super::CreateIdempotencyRecord,
}

fn default_commit_state() -> PersistedPausedCommitState {
    PersistedPausedCommitState::Committed
}

pub(super) fn decode_record(bytes: &[u8]) -> PersistenceResult<PersistedPausedRecord> {
    let record: PersistedPausedRecord =
        serde_json::from_slice(bytes).map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "failed to deserialize record".to_string(),
            source: Some(source.into()),
        })?;
    ensure_supported_record_version(record.version)?;
    Ok(record)
}

pub(super) fn ensure_supported_record_version(version: u32) -> PersistenceResult<()> {
    if matches!(version, LEGACY_RECORD_VERSION | PAUSED_MANIFEST_VERSION) {
        Ok(())
    } else {
        Err(SandboxPersistenceError::InvalidRecord {
            reason: format!("unsupported record version {version}"),
            source: None,
        })
    }
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn decode_stored_paused_entry(bytes: &[u8]) -> PersistenceResult<StoredPausedEntry> {
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

pub(super) fn decode_create_idempotency_record(
    bytes: &[u8],
) -> PersistenceResult<super::CreateIdempotencyRecord> {
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

pub(super) fn encode_create_idempotency_record(
    record: &super::CreateIdempotencyRecord,
) -> PersistenceResult<Vec<u8>> {
    serde_json::to_vec(&PersistedCreateIdempotencyRecord {
        version: CREATE_IDEMPOTENCY_RECORD_VERSION,
        record: record.clone(),
    })
    .map_err(|source| SandboxPersistenceError::InvalidRecord {
        reason: "failed to serialize create idempotency record".to_string(),
        source: Some(source.into()),
    })
}

pub(super) fn paused_metadata_without_runtime_state(
    mut record: PersistedPausedRecord,
) -> SandboxMetadata {
    record.metadata.state = SandboxState::Paused;
    record.metadata.paused_state = None;
    record.metadata
}

pub(super) fn decode_paused_state<F>(
    record: PersistedPausedRecord,
    factory: &F,
) -> PersistenceResult<SandboxMetadata>
where
    F: SandboxBackendFactory,
{
    ensure_supported_record_version(record.version)?;
    let paused_state = factory
        .decode_paused_state(record.artifact_root, record.state)
        .map_err(|source| SandboxPersistenceError::InvalidRecord {
            reason: "failed to decode paused sandbox state".to_string(),
            source: Some(source),
        })?;
    let mut metadata = record.metadata;
    metadata.state = SandboxState::Paused;
    metadata.paused_state = Some(paused_state);
    Ok(metadata)
}

pub(super) fn decode_recovery_pending_state<F>(
    record: PersistedPausedRecord,
    factory: &F,
) -> PersistenceResult<SandboxMetadata>
where
    F: SandboxBackendFactory,
{
    let mut metadata = decode_paused_state(record, factory)?;
    metadata.paused_runtime_stopped = false;
    metadata.resume_recovery_pending = true;
    Ok(metadata)
}
