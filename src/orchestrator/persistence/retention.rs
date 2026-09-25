//! Collection runs only after the orchestrator has blocked lifecycle admission
//! and proven every guest stopped. Retain current + one rollback generation,
//! every uncertain/incomplete generation, and their transitive path references.
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const MANIFEST: &str = "paused-record.v2.json";

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

fn strings(value: &Value, directory: &Path, found: &mut Vec<PathBuf>) -> Result<()> {
    match value {
        Value::String(value) if !value.contains("://") => {
            let path = Path::new(value);
            // References are normally absolute. Conservatively resolve relative
            // filenames too, and refuse ambiguous parent traversal instead of
            // deleting a generation that might still be referenced.
            if path
                .components()
                .any(|part| part == std::path::Component::ParentDir)
            {
                bail!("retention refuses parent-traversing artifact reference");
            }
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                directory.join(path)
            };
            found.push(path.components().collect());
        }
        Value::Array(values) => {
            for value in values {
                strings(value, directory, found)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                strings(value, directory, found)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn plan(artifacts: &Path, current: &[PathBuf]) -> Result<RetentionPlan> {
    let artifacts = fs::canonicalize(artifacts)?;
    let mut generations = BTreeMap::<PathBuf, Vec<PathBuf>>::new();
    let mut retained = BTreeSet::new();
    let mut complete = BTreeSet::new();
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
            let manifest = fs::read(root.join(MANIFEST))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
            let timestamp = manifest
                .as_ref()
                .and_then(|m| m.get("checkpointAtUnixMs"))
                .and_then(Value::as_u64);
            let committed = manifest
                .as_ref()
                .is_some_and(|m| m.get("commitState").and_then(Value::as_str) == Some("committed"));
            if timestamp.is_none()
                || !committed
                || root.join(".paused-record.v2.recovery-pending").exists()
            {
                retained.insert(root.clone());
            } else {
                complete.insert(root.clone());
                successful.push((timestamp.unwrap(), root.clone()));
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
    let mut references = BTreeMap::new();
    for (root, inventory) in &generations {
        let mut targets = Vec::new();
        for file in inventory {
            if file.extension().is_some_and(|ext| ext == "json") {
                let value: Value = serde_json::from_slice(&fs::read(file)?)
                    .with_context(|| format!("retention cannot parse {}", file.display()))?;
                strings(
                    &value,
                    file.parent().context("JSON artifact parent")?,
                    &mut targets,
                )?;
            }
        }
        references.insert(root.clone(), targets);
    }
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
                if !complete.contains(root) {
                    continue;
                }
                if path
                    .extension()
                    .is_none_or(|extension| extension != "commit")
                    || referenced_files.contains(path)
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
    // process is interrupted, the next plan can still identify and retry it.
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

pub(super) fn collect(artifacts: &Path, current: &[PathBuf]) -> Result<RetentionPlan> {
    let plan = plan(artifacts, current)?;
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
    use super::*;

    fn generation(artifacts: &Path, guest: uuid::Uuid, stamp: u64) -> PathBuf {
        let root = artifacts
            .join(guest.to_string())
            .join(uuid::Uuid::now_v7().to_string());
        fs::create_dir_all(&root).unwrap();
        let layer = root.join("data.commit");
        fs::write(&layer, vec![1u8; 4096]).unwrap();
        fs::write(
            root.join(MANIFEST),
            serde_json::to_vec(&serde_json::json!({
                "commitState": "committed", "checkpointAtUnixMs": stamp,
                "state": {"layer": layer},
            }))
            .unwrap(),
        )
        .unwrap();
        root
    }

    #[test]
    fn keeps_current_rollback_and_transitively_shared_layers() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let guest = uuid::Uuid::new_v4();
        let oldest = generation(temp.path(), guest, 1);
        let rollback = generation(temp.path(), guest, 2);
        let current = generation(temp.path(), guest, 3);
        fs::write(
            current.join("shared.json"),
            serde_json::to_vec(&serde_json::json!({
                "layer": oldest.join("data.commit"),
            }))?,
        )?;
        let planned = plan(temp.path(), &[current.clone()])?;
        assert!(planned.generations.is_empty());
        assert_eq!(planned.retained_generations, 3);
        fs::remove_file(current.join("shared.json"))?;
        let planned = collect(temp.path(), &[current.clone()])?;
        assert_eq!(planned.generations, vec![oldest.clone()]);
        assert!(!oldest.exists());
        assert!(rollback.exists());
        assert!(current.exists());
        assert!(collect(temp.path(), &[current])?.generations.is_empty());
        Ok(())
    }

    #[test]
    fn shared_hardlink_survives_and_incomplete_artifacts_are_not_collected() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let guest = uuid::Uuid::new_v4();
        let old = generation(temp.path(), guest, 1);
        let _rollback = generation(temp.path(), guest, 2);
        let current = generation(temp.path(), guest, 3);
        fs::remove_file(current.join("data.commit"))?;
        fs::hard_link(old.join("data.commit"), current.join("data.commit"))?;
        let incomplete = temp
            .path()
            .join(guest.to_string())
            .join(uuid::Uuid::now_v7().to_string());
        fs::create_dir_all(&incomplete)?;
        fs::write(incomplete.join("partial.commit"), b"recovery evidence")?;
        let planned = plan(temp.path(), &[current.clone()])?;
        let old_manifest_bytes = fs::metadata(old.join(MANIFEST))?.blocks() * 512;
        assert_eq!(planned.reclaimable_bytes, old_manifest_bytes);
        collect(temp.path(), &[current.clone()])?;
        assert_eq!(fs::read(current.join("data.commit"))?, vec![1u8; 4096]);
        assert_eq!(
            fs::read(incomplete.join("partial.commit"))?,
            b"recovery evidence"
        );
        Ok(())
    }

    #[test]
    fn interrupted_payload_deletion_can_be_retried_without_touching_rollback() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let guest = uuid::Uuid::new_v4();
        let old = generation(temp.path(), guest, 1);
        let rollback = generation(temp.path(), guest, 2);
        let current = generation(temp.path(), guest, 3);
        // Interruption after the payload is removed, before the manifest.
        fs::remove_file(old.join("data.commit"))?;
        collect(temp.path(), &[current])?;
        assert!(!old.exists());
        assert!(rollback.join("data.commit").exists());
        Ok(())
    }
}
