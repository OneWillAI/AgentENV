//! Collection excludes lifecycle changes and protects live guest references.
//! It runs after ordinary pauses as well as shutdown preparation. Retain current + one rollback generation,
//! every uncertain/incomplete generation, and their transitive path references.
use super::codecs::{decode_record, PAUSED_MANIFEST_FILE};
use super::paused_transactions::PersistedPausedCommitState;
use crate::sandbox::FirecrackerSnapshotConfig;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const MANIFEST: &str = PAUSED_MANIFEST_FILE;

#[derive(Debug, Default, Serialize)]
pub struct RetentionPlan {
    pub generations: Vec<PathBuf>,
    pub unused_layers: Vec<PathBuf>,
    pub reclaimable_bytes: u64,
    pub retained_generations: usize,
}

fn files(root: &Path, result: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            bail!("retention refuses symlink: {}", entry.path().display());
        }
        if kind.is_dir() {
            files(&entry.path(), result)?;
        } else if kind.is_file() {
            result.push(entry.path());
        } else {
            bail!("retention refuses non-regular artifact");
        }
    }
    Ok(())
}

pub(super) fn plan(
    artifacts: &Path,
    current: &[PathBuf],
    protected: &[PathBuf],
) -> Result<RetentionPlan> {
    let artifacts = fs::canonicalize(artifacts)?;
    let mut generations = BTreeMap::<PathBuf, Vec<PathBuf>>::new();
    let mut retained = BTreeSet::new();
    let mut complete = BTreeSet::new();
    let mut references = BTreeMap::new();
    for path in current {
        retained.insert(fs::canonicalize(path)?);
    }
    for sandbox in fs::read_dir(&artifacts)? {
        let sandbox = sandbox?;
        if !sandbox.file_type()?.is_dir()
            || uuid::Uuid::parse_str(&sandbox.file_name().to_string_lossy()).is_err()
        {
            bail!("retention refuses unknown artifact root");
        }
        let mut successful = Vec::new();
        for generation in fs::read_dir(sandbox.path())? {
            let generation = generation?;
            if !generation.file_type()?.is_dir()
                || uuid::Uuid::parse_str(&generation.file_name().to_string_lossy()).is_err()
            {
                bail!("retention refuses unknown generation");
            }
            let root = generation.path();
            let mut inventory = Vec::new();
            files(&root, &mut inventory)?;
            // Unknown/incomplete generations may contain references we cannot
            // interpret. Refuse the whole plan rather than guessing or deleting.
            let record = decode_record(&fs::read(root.join(MANIFEST))?)?;
            anyhow::ensure!(
                record.artifact_root == root
                    && record.metadata.id.to_string() == sandbox.file_name().to_string_lossy(),
                "checkpoint identity differs from its managed directory"
            );
            let snapshot: FirecrackerSnapshotConfig = serde_json::from_value(record.state.clone())
                .context("unknown checkpoint storage schema; retaining all generations")?;
            references.insert(root.clone(), snapshot.checkpoint_references()?);
            if record.checkpoint_at_unix_ms.is_none()
                || record.commit_state != PersistedPausedCommitState::Committed
                || record.metadata.resume_recovery_pending
                || root.join(".paused-record.v2.recovery-pending").exists()
            {
                retained.insert(root.clone());
            } else {
                complete.insert(root.clone());
                successful.push((record.checkpoint_at_unix_ms.unwrap(), root.clone()));
            }
            generations.insert(root, inventory);
        }
        successful.sort();
        // Always keep the latest successful rollback copy in addition to the
        // authoritative pointer, even if the index is older than directory age.
        for (_, root) in successful.into_iter().rev().take(2) {
            retained.insert(root);
        }
    }
    for root in &retained {
        if !generations.contains_key(root) {
            bail!("current generation is outside managed inventory");
        }
    }
    let protected = protected
        .iter()
        .map(|path| crate::sandbox::checkpoint_references::absolute(path))
        .collect::<Result<Vec<_>>>()?;
    // Cache entries outside this store may have been evicted. Missing payloads
    // inside a managed checkpoint still block the whole deletion plan.
    for path in references.values().flatten().chain(protected.iter()) {
        anyhow::ensure!(
            !path.starts_with(&artifacts) || path.exists(),
            "managed checkpoint reference is missing: {}",
            path.display()
        );
    }
    let live: BTreeSet<_> = generations
        .keys()
        .filter(|root| protected.iter().any(|path| path.starts_with(root)))
        .cloned()
        .collect();
    retained.extend(live.iter().cloned());
    loop {
        let before = retained.len();
        for root in retained.clone() {
            for target in &references[&root] {
                for candidate in generations.keys() {
                    if target.starts_with(candidate) {
                        retained.insert(candidate.clone());
                    }
                }
            }
        }
        if retained.len() == before {
            break;
        }
    }
    let mut plan = RetentionPlan {
        retained_generations: retained.len(),
        ..Default::default()
    };
    let referenced_files: BTreeSet<_> = references.values().flatten().cloned().collect();
    let mut inodes = BTreeMap::<(u64, u64), (u64, u64, u64)>::new();
    for (root, inventory) in &generations {
        let deleting_generation = !retained.contains(root);
        if deleting_generation {
            plan.generations.push(root.clone());
        }
        for path in inventory {
            if !deleting_generation {
                if !complete.contains(root) || live.contains(root) {
                    continue;
                }
                if path
                    .extension()
                    .is_none_or(|extension| extension != "commit")
                    || referenced_files
                        .iter()
                        .any(|reference| path.starts_with(reference))
                {
                    continue;
                }
                plan.unused_layers.push(path.clone());
            }
            let metadata = fs::metadata(path)?;
            let item = inodes.entry((metadata.dev(), metadata.ino())).or_insert((
                0,
                metadata.nlink(),
                metadata.blocks() * 512,
            ));
            item.0 += 1;
        }
    }
    // Shared hardlinks consume no reclaimable bytes unless every link is in
    // this deletion plan. Never count logical sparse-file length as disk use.
    plan.reclaimable_bytes = inodes
        .values()
        .filter(|(removed, total, _)| removed == total)
        .map(|(_, _, bytes)| bytes)
        .sum();
    Ok(plan)
}

fn remove_generation(root: &Path) -> Result<()> {
    let mut inventory = Vec::new();
    files(root, &mut inventory)?;
    // Keep the identifying manifest until all payload files are gone. If the
    // process is interrupted, incomplete artifacts remain identifiable for review.
    inventory.sort_by_key(|path| path.file_name().is_some_and(|name| name == MANIFEST));
    for file in inventory {
        fs::remove_file(file)?;
    }
    fn remove_dirs(path: &Path) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                bail!("artifact changed during collection");
            }
            remove_dirs(&entry.path())?;
        }
        fs::remove_dir(path)?;
        Ok(())
    }
    remove_dirs(root)?;
    fs::File::open(root.parent().context("generation has no parent")?)?.sync_all()?;
    Ok(())
}

pub(super) fn collect(
    artifacts: &Path,
    current: &[PathBuf],
    protected: &[PathBuf],
) -> Result<RetentionPlan> {
    let plan = plan(artifacts, current, protected)?;
    tracing::info!(plan = %serde_json::to_string(&plan)?, "checkpoint retention plan before deletion");
    for root in &plan.generations {
        remove_generation(root)?;
    }
    for file in &plan.unused_layers {
        fs::remove_file(file)?;
        fs::File::open(file.parent().context("layer has no parent")?)?.sync_all()?;
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::super::codecs::{PersistedPausedRecord, PAUSED_MANIFEST_VERSION};
    use super::super::paused_transactions::PersistedPausedLifecycle;
    use super::*;
    use crate::orchestrator::{SandboxMetadata, SandboxState};
    use crate::sandbox::FirecrackerSandboxConfig;
    use crate::types::SandboxId;

    fn generation(artifacts: &Path, guest: SandboxId, stamp: u64) -> PathBuf {
        let root = artifacts
            .join(guest.to_string())
            .join(uuid::Uuid::now_v7().to_string());
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("data.commit"), vec![1u8; 4096]).unwrap();
        fs::write(root.join("vm_state.bin"), b"state").unwrap();
        fs::write(
            root.join("image.json"),
            serde_json::to_vec(&serde_json::json!({
                "lowers": [{"file": root.join("data.commit")}]
            }))
            .unwrap(),
        )
        .unwrap();
        let common = FirecrackerSandboxConfig::new(
            "firecracker".into(),
            "vmlinux".into(),
            "test".into(),
            root.join("image.json"),
        )
        .common;
        let record = PersistedPausedRecord {
            version: PAUSED_MANIFEST_VERSION,
            commit_state: PersistedPausedCommitState::Committed,
            lifecycle: PersistedPausedLifecycle::Paused,
            checkpoint_at_unix_ms: Some(stamp),
            resuming_boot_id: None,
            unproven_stop_boot_id: None,
            metadata: SandboxMetadata {
                id: guest,
                state: SandboxState::Paused,
                paused_runtime_stopped: true,
                user_metadata: Some(std::collections::HashMap::from([(
                    "note".into(),
                    "../workspace".into(),
                )])),
                ..Default::default()
            },
            artifact_root: root.clone(),
            state: serde_json::json!({
                "common": common, "vm_state_path": root.join("vm_state.bin"),
                "mem_overlaybd_config": {"image_config_path": root.join("image.json"), "read_only": true},
                "mem_virtual_size": 4096,
            }),
        };
        fs::write(root.join(MANIFEST), serde_json::to_vec(&record).unwrap()).unwrap();
        root
    }

    #[test]
    fn repeated_pauses_bound_generations_and_preserve_live_and_shared_references() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let guest = SandboxId::new();
        let live = generation(temp.path(), guest, 0);
        let mut previous = live.clone();
        for stamp in 1..8 {
            let current = generation(temp.path(), guest, stamp);
            // Another live guest can still need an old generation, including
            // its currently unreferenced layers. Do not prune within that root.
            fs::write(live.join("live-only.commit"), b"live")?;
            let plan = collect(temp.path(), &[current.clone()], &[live.join("data.commit")])?;
            assert!(plan.retained_generations <= 3);
            assert!(live.join("live-only.commit").exists());
            assert!(previous.join("data.commit").exists());
            assert!(current.join("data.commit").exists());
            previous = current;
        }
        // Once that guest releases the reference, normal collection returns to two.
        assert_eq!(
            collect(temp.path(), &[previous.clone()], &[])?.retained_generations,
            2
        );
        assert!(!live.exists());
        assert_eq!(fs::read(previous.join("data.commit"))?, vec![1u8; 4096]);
        Ok(())
    }

    #[test]
    fn typed_references_protect_cross_guest_layers_and_ignore_user_metadata() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let guest = SandboxId::new();
        let old = generation(temp.path(), guest, 1);
        let _rollback = generation(temp.path(), guest, 2);
        let current = generation(temp.path(), guest, 3);
        let other = generation(temp.path(), SandboxId::new(), 1);
        fs::write(
            other.join("image.json"),
            serde_json::to_vec(&serde_json::json!({
                "lowers": [{"file": old.join("data.commit")}]
            }))?,
        )?;
        fs::write(current.join("unused.commit"), b"compaction input")?;
        let plan = collect(temp.path(), &[current.clone(), other.clone()], &[])?;
        assert_eq!(plan.retained_generations, 4);
        assert!(old.join("data.commit").exists());
        assert!(!current.join("unused.commit").exists());
        // Drop the cross-guest reference, preserving a hardlink to its payload.
        assert!(!other.join("data.commit").exists());
        fs::hard_link(old.join("data.commit"), other.join("data.commit"))?;
        fs::write(
            other.join("image.json"),
            serde_json::to_vec(&serde_json::json!({
                "lowers": [{"file": other.join("data.commit")}]
            }))?,
        )?;
        collect(temp.path(), &[current, other.clone()], &[])?;
        assert!(!old.exists());
        assert_eq!(fs::read(other.join("data.commit"))?, vec![1u8; 4096]);
        Ok(())
    }

    #[test]
    fn evicted_external_cache_does_not_block_collection_but_missing_checkpoint_data_does(
    ) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let artifacts = temp.path().join("artifacts");
        let cache = temp.path().join("cache");
        fs::create_dir(&artifacts)?;
        fs::create_dir(&cache)?;
        let guest = SandboxId::new();
        let old = generation(&artifacts, guest, 1);
        let rollback = generation(&artifacts, guest, 2);
        let current = generation(&artifacts, guest, 3);
        fs::write(
            current.join("image.json"),
            serde_json::to_vec(&serde_json::json!({
                "repoBlobUrl": "https://example.test/blobs",
                "lowers": [{"file": current.join("data.commit")}, {"dir": cache.join("evicted"), "digest": format!("sha256:{}", "a".repeat(64))}]
            }))?,
        )?;
        collect(&artifacts, &[current.clone()], &[cache.join("evicted")])?;
        assert!(!old.exists());
        assert!(rollback.exists());
        fs::remove_file(current.join("data.commit"))?;
        assert!(collect(&artifacts, &[current.clone()], &[]).is_err());
        assert!(rollback.exists());
        fs::write(current.join("data.commit"), b"restored")?;
        // A dangling alias cannot hide an unresolved reference into the store.
        std::os::unix::fs::symlink(current.join("missing"), cache.join("evicted"))?;
        assert!(collect(&artifacts, &[current], &[]).is_err());
        Ok(())
    }

    #[test]
    fn unknown_or_partial_checkpoints_block_deletion() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let guest = SandboxId::new();
        let old = generation(temp.path(), guest, 1);
        let _rollback = generation(temp.path(), guest, 2);
        let current = generation(temp.path(), guest, 3);
        let partial = temp
            .path()
            .join(guest.to_string())
            .join(uuid::Uuid::now_v7().to_string());
        fs::create_dir(&partial)?;
        fs::write(partial.join("partial.commit"), b"uncertain")?;
        assert!(collect(temp.path(), &[current], &[]).is_err());
        assert!(old.join("data.commit").exists());
        assert_eq!(fs::read(partial.join("partial.commit"))?, b"uncertain");
        Ok(())
    }
}
