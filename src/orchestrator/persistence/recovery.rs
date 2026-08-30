//! Recovery inventory types shared by startup reconciliation and the operator
//! recovery CLI. No deletion policy belongs here; callers decide when a
//! quarantined item may be explicitly purged.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::codecs::{ManifestEntry, PersistedPausedRecord};
use crate::orchestrator::store::SandboxMetadata;
use crate::types::SandboxId;

#[derive(Default)]
pub(super) struct PausedRecoveryBlocks {
    pub(super) sandbox_ids: HashSet<SandboxId>,
    pub(super) artifact_roots: HashSet<PathBuf>,
    pub(super) manifest_paths: HashSet<PathBuf>,
}

impl PausedRecoveryBlocks {
    pub(super) fn contains_manifest(&self, entry: &ManifestEntry) -> bool {
        self.sandbox_ids.contains(&entry.sandbox_id())
            || self.artifact_roots.contains(&entry.record.artifact_root)
            || self.manifest_paths.contains(&entry.path)
    }

    pub(super) fn contains_sandbox(&self, sandbox_id: &SandboxId) -> bool {
        self.sandbox_ids.contains(sandbox_id)
    }

    pub(super) fn contains_record(
        &self,
        sandbox_id: &SandboxId,
        artifact_root: &std::path::Path,
    ) -> bool {
        self.contains_sandbox(sandbox_id) || self.artifact_roots.contains(artifact_root)
    }
}

#[derive(Default)]
pub(super) struct ManifestReconciliation {
    pub(super) candidates: HashMap<SandboxId, ManifestEntry>,
    pub(super) blocked: HashSet<SandboxId>,
    pub(super) retire_after_selection: HashMap<SandboxId, Vec<PathBuf>>,
    pub(super) quarantined_items: usize,
}

pub(super) struct PurgeableArtifactTarget {
    pub(super) sandbox_id: OsString,
    pub(super) generation: Option<OsString>,
    pub(super) name: OsString,
}

pub(super) enum QuarantinePurgeAction {
    QuarantineOnly,
    PurgeState { record_key: Option<String> },
}

pub(super) enum PersistedRecordLoad {
    Continue(PersistedPausedRecord),
    Complete(Option<SandboxMetadata>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct StoredPausedSandboxQuarantine {
    pub(super) version: u32,
    pub(super) id: String,
    pub(super) reason: String,
    #[serde(default = "default_true")]
    pub(super) requires_manual_recovery: bool,
    #[serde(default)]
    pub(super) reconcile_if_coherent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) record_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) record_key_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) record_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) record_bytes_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) artifact_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) manifest_path: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

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
