//! A restore policy only selects the format of a NEW rootfs upper. The
//! immutable checkpoint, RAM image and old live device are never rewritten.
use anyhow::{ensure, Context, Result};
use overlaybd::config::{load_image_config, UpperMode};

use super::FirecrackerSnapshotConfig;
use crate::sandbox::UblkBackend;

pub(super) fn migrate_restored_log_upper(
    snapshot: &mut FirecrackerSnapshotConfig,
    enabled: bool,
) -> Result<bool> {
    if !enabled || snapshot.pack_recording {
        return Ok(false);
    }
    let Some(rootfs) = snapshot.common.rootfs_image_config.as_ref() else {
        return Ok(false);
    };
    if rootfs.read_only || rootfs.runtime_upper_mode != UpperMode::LogStructured {
        return Ok(false);
    }
    let image = load_image_config(&rootfs.image_config_path)?;
    ensure!(image.upper.data.is_empty() && image.upper.index.is_empty()
        && image.upper.target.is_empty() && image.upper.gzip_index.is_empty(),
        "hybrid restore migration requires an immutable exported checkpoint without an existing upper");
    let backend = snapshot
        .common
        .ublk_config
        .as_ref()
        .context("hybrid restore migration requires an OverlayBD rootfs")?;
    let UblkBackend::Overlaybd(source) = &backend.backend;
    ensure!(
        source.image_config_path == rootfs.image_config_path
            && !source.read_only
            && source.runtime_upper_mode == UpperMode::LogStructured,
        "hybrid restore migration requires consistent writable rootfs configuration"
    );
    snapshot
        .common
        .rootfs_image_config
        .as_mut()
        .unwrap()
        .runtime_upper_mode = UpperMode::HybridLogStructured;
    let UblkBackend::Overlaybd(source) = &mut snapshot.common.ublk_config.as_mut().unwrap().backend;
    source.runtime_upper_mode = UpperMode::HybridLogStructured;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{
        FirecrackerCommonConfig, FirecrackerRuntimePolicy, OverlaybdConfig, UblkConfig,
    };
    use std::{path::Path, time::Duration};

    fn checkpoint(root: &Path) -> Result<FirecrackerSnapshotConfig> {
        let path = root.join("image.json");
        let layer = root.join("disk.commit");
        std::fs::write(&layer, b"immutable checkpoint payload")?;
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"lowers": [{"file": layer}]}))?,
        )?;
        let disk = OverlaybdConfig {
            image_config_path: path,
            read_only: false,
            runtime_upper_mode: UpperMode::LogStructured,
        };
        let mut common = FirecrackerCommonConfig::new(
            root.join("retained-firecracker"),
            "retained-tools-version".into(),
            FirecrackerRuntimePolicy {
                socket_timeout: Duration::from_secs(1),
                socket_poll_interval: Duration::from_millis(10),
                envd_timeout: Duration::from_secs(2),
                envd_poll_interval: Duration::from_millis(20),
            },
        );
        common.kernel_sha256 = Some("retained-kernel-identity".into());
        common.firecracker_sha256 = Some("retained-vmm-identity".into());
        common.rootfs_image_config = Some(disk.clone());
        common.ublk_config = Some(UblkConfig {
            backend: UblkBackend::Overlaybd(disk),
        });
        common.rootfs_virtual_size = Some(1024 * 1024);
        common.env_vars = Some(std::collections::HashMap::from([(
            "KEEP".into(),
            "value".into(),
        )]));
        let vm_state_path = root.join("vm_state.bin");
        std::fs::write(&vm_state_path, b"retained CPU and device state")?;
        let memory = root.join("memory.json");
        std::fs::write(&memory, b"retained RAM image descriptor")?;
        Ok(FirecrackerSnapshotConfig {
            common,
            vm_state_path,
            mem_overlaybd_config: OverlaybdConfig {
                image_config_path: memory,
                read_only: true,
                runtime_upper_mode: UpperMode::LogStructured,
            },
            mem_virtual_size: 16 * 1024 * 1024,
            managed_snapshot_root: None,
            pack_recording: false,
            memory_startup_pack: None,
        })
    }

    #[test]
    fn explicit_migration_changes_only_new_upper_policy_and_never_checkpoint_bytes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let mut snapshot = checkpoint(root.path())?;
        let original = serde_json::to_value(&snapshot)?;
        let before: Vec<_> = std::fs::read_dir(root.path())?
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        assert!(!migrate_restored_log_upper(&mut snapshot, false)?);
        assert_eq!(serde_json::to_value(&snapshot)?, original);
        assert!(migrate_restored_log_upper(&mut snapshot, true)?);
        assert_eq!(
            snapshot
                .common
                .rootfs_image_config
                .as_ref()
                .unwrap()
                .runtime_upper_mode,
            UpperMode::HybridLogStructured
        );
        let UblkBackend::Overlaybd(backend) =
            &snapshot.common.ublk_config.as_ref().unwrap().backend;
        assert_eq!(backend.runtime_upper_mode, UpperMode::HybridLogStructured);
        assert!(
            !migrate_restored_log_upper(&mut snapshot, true)?,
            "already hybrid is unchanged"
        );
        // Normalize only the two intentionally changed fields; every persisted
        // identity, memory/VM reference and other launch setting must be intact.
        snapshot
            .common
            .rootfs_image_config
            .as_mut()
            .unwrap()
            .runtime_upper_mode = UpperMode::LogStructured;
        let UblkBackend::Overlaybd(backend) =
            &mut snapshot.common.ublk_config.as_mut().unwrap().backend;
        backend.runtime_upper_mode = UpperMode::LogStructured;
        assert_eq!(serde_json::to_value(&snapshot)?, original);
        for (path, bytes) in before {
            assert_eq!(std::fs::read(path)?, bytes);
        }
        assert_eq!(std::fs::read_dir(root.path())?.count(), 4);
        Ok(())
    }

    #[test]
    fn migration_refuses_existing_upper_and_inconsistent_backend_without_mutation() -> Result<()> {
        for invalid in [
            "upper-data",
            "upper-index",
            "backend-mode",
            "backend-path",
            "backend-read-only",
            "missing-backend",
            "malformed-image",
        ] {
            let root = tempfile::tempdir()?;
            let mut snapshot = checkpoint(root.path())?;
            let image_path = snapshot
                .common
                .rootfs_image_config
                .as_ref()
                .unwrap()
                .image_config_path
                .clone();
            match invalid {
                "upper-data" | "upper-index" => {
                    let mut image = load_image_config(&image_path)?;
                    let upper = root.path().join("live-upper");
                    std::fs::write(&upper, b"must never rewrite this upper")?;
                    if invalid == "upper-data" {
                        image.upper.data = upper.display().to_string();
                    } else {
                        image.upper.index = upper.display().to_string();
                    }
                    std::fs::write(&image_path, serde_json::to_vec(&image)?)?;
                }
                "missing-backend" => snapshot.common.ublk_config = None,
                "malformed-image" => std::fs::write(&image_path, b"not JSON")?,
                _ => {
                    let UblkBackend::Overlaybd(backend) =
                        &mut snapshot.common.ublk_config.as_mut().unwrap().backend;
                    match invalid {
                        "backend-mode" => backend.runtime_upper_mode = UpperMode::Sparse,
                        "backend-path" => {
                            backend.image_config_path = root.path().join("different.json")
                        }
                        "backend-read-only" => backend.read_only = true,
                        _ => unreachable!(),
                    }
                }
            }
            let before = serde_json::to_value(&snapshot)?;
            let bytes = std::fs::read(&image_path)?;
            assert!(
                migrate_restored_log_upper(&mut snapshot, true).is_err(),
                "{invalid}"
            );
            assert_eq!(serde_json::to_value(&snapshot)?, before, "{invalid}");
            assert_eq!(std::fs::read(&image_path)?, bytes, "{invalid}");
        }
        Ok(())
    }

    #[test]
    fn migration_skips_read_only_other_modes_and_pack_recording() -> Result<()> {
        let root = tempfile::tempdir()?;
        for (read_only, mode, recording) in [
            (true, UpperMode::LogStructured, false),
            (false, UpperMode::Sparse, false),
            (false, UpperMode::HybridLogStructured, false),
            (false, UpperMode::LogStructured, true),
        ] {
            let mut snapshot = checkpoint(root.path())?;
            let disk = snapshot.common.rootfs_image_config.as_mut().unwrap();
            disk.read_only = read_only;
            disk.runtime_upper_mode = mode;
            snapshot.pack_recording = recording;
            let before = serde_json::to_value(&snapshot)?;
            assert!(!migrate_restored_log_upper(&mut snapshot, true)?);
            assert_eq!(serde_json::to_value(&snapshot)?, before);
        }
        Ok(())
    }
}
