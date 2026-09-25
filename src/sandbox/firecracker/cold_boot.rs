//! Disk-only recovery uses the existing paused-record publication and retention
//! machinery, but never interprets a memory checkpoint as a cold-boot record.
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{FirecrackerPausedState, FirecrackerSandboxConfig, FirecrackerSnapshotConfig};
use crate::sandbox::{PausedSandboxState, RuntimeArtifactSet};

/// Keep boot-time writes in the retained generation, not the disposable VM
/// work directory. The existing runtime materializer reopens this same upper
/// on retry; normal pause subsequently exports and compacts it as usual.
pub(super) fn prepare_writable_disk(image_path: &Path, virtual_size: u64) -> Result<()> {
    use overlaybd::config::{load_image_config, UpperConfig, UpperMode};
    let mut image = load_image_config(image_path)?;
    ensure!(
        image.upper.data.is_empty(),
        "cold-boot capture already has a writable upper"
    );
    let root = image_path
        .parent()
        .context("cold-boot disk has no parent")?;
    let data = root.join("boot-upper.data");
    let index = root.join("boot-upper.index");
    overlaybd::helper::prepare_runtime_upper(
        &data,
        Some(&index),
        virtual_size,
        UpperMode::LogStructured,
    )?;
    image.upper = UpperConfig {
        data: data.display().to_string(),
        index: index.display().to_string(),
        mode: Some(UpperMode::LogStructured),
        ..Default::default()
    };
    // This private generation is synced before the existing persister publishes
    // its recovery record. No already-published image config is modified.
    std::fs::write(image_path, serde_json::to_vec_pretty(&image)?)?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FirecrackerColdBootState {
    cold_boot_version: u32,
    pub(super) config: FirecrackerSandboxConfig,
}

impl FirecrackerColdBootState {
    pub(super) fn new(config: FirecrackerSandboxConfig) -> Result<Self> {
        config.validate_persisted()?;
        Ok(Self {
            cold_boot_version: 1,
            config,
        })
    }

    fn decode(state: Value) -> Result<Self> {
        let record: Self = serde_json::from_value(state).context("decode disk-only boot record")?;
        ensure!(
            record.cold_boot_version == 1,
            "unsupported disk-only boot record version"
        );
        record.config.validate_persisted()?;
        Ok(record)
    }
}

impl PausedSandboxState for FirecrackerColdBootState {
    fn encode(&self) -> Result<Value> {
        self.config.validate_persisted()?;
        serde_json::to_value(self).context("encode disk-only boot record")
    }

    fn runtime_artifacts(&self) -> RuntimeArtifactSet {
        RuntimeArtifactSet::from_overlaybd_image_configs(
            super::sandbox::rootfs_and_extra_drive_image_config_paths(&self.config.common),
        )
    }
}

pub(super) fn decode_recovery_state(
    root: PathBuf,
    state: Value,
) -> Result<Arc<dyn PausedSandboxState>> {
    if state.get("cold_boot_version").is_some() {
        Ok(Arc::new(FirecrackerColdBootState::decode(state)?))
    } else {
        Ok(Arc::new(FirecrackerPausedState::decode(root, state)?))
    }
}

pub(crate) fn recovery_checkpoint_references(state: Value) -> Result<Vec<PathBuf>> {
    if state.get("cold_boot_version").is_some() {
        FirecrackerColdBootState::decode(state)?
            .config
            .common
            .disk_references()
    } else {
        let config: FirecrackerSnapshotConfig = serde_json::from_value(state)
            .context("unknown checkpoint storage schema; retaining all generations")?;
        config.checkpoint_references()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_recovery_survives_missing_boot_dependencies_without_memory_artifacts() -> Result<()> {
        let root = tempfile::tempdir()?;
        let image = root.path().join("image.json");
        let layer = root.path().join("disk.commit");
        std::fs::write(&layer, b"retained disk")?;
        std::fs::write(
            &image,
            serde_json::to_vec(&serde_json::json!({"lowers":[{"file":layer}]}))?,
        )?;
        prepare_writable_disk(&image, 1024 * 1024)?;
        let upper = overlaybd::config::load_image_config(&image)?.upper;
        assert!(Path::new(&upper.data).is_file());
        assert!(Path::new(&upper.index).is_file());
        assert!(
            prepare_writable_disk(&image, 1024 * 1024).is_err(),
            "retry must never replace an existing writable layer"
        );
        let mut config = FirecrackerSandboxConfig::new(
            root.path().join("missing-firecracker"),
            root.path().join("missing-kernel"),
            "approved-tools".into(),
            image.clone(),
        );
        config.common.rootfs_virtual_size = Some(1024 * 1024);
        let state = FirecrackerColdBootState::new(config)?.encode()?;
        let recovered = decode_recovery_state(root.path().to_path_buf(), state.clone())?;
        let cold = recovered
            .downcast_ref::<FirecrackerColdBootState>()
            .unwrap();
        assert_eq!(cold.config.common.tools_drive_version, "approved-tools");
        let references = recovery_checkpoint_references(state.clone())?;
        for retained in [image.clone(), layer, upper.data.into(), upper.index.into()] {
            assert!(
                references.contains(&retained),
                "missing retained disk file: {retained:?}"
            );
        }
        assert!(
            cold.config.validate().is_err(),
            "missing launch dependencies must prevent boot"
        );

        let mut unsupported = state.clone();
        unsupported["cold_boot_version"] = 2.into();
        assert!(decode_recovery_state(root.path().to_path_buf(), unsupported).is_err());
        std::fs::remove_file(image)?;
        assert!(decode_recovery_state(root.path().to_path_buf(), state).is_err());
        Ok(())
    }
}
