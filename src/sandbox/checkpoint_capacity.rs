//! Conservative peak allocation preflight. Checks are repeated immediately
//! before capture under a process-wide serialization lock. They are not a disk
//! reservation: ENOSPC during writing must still be handled without VM teardown.
use anyhow::{bail, Context, Result};
use nix::sys::statvfs::statvfs;
use std::{
    collections::BTreeMap,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub static CAPTURE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Debug)]
pub struct CheckpointCapacity {
    pub path: PathBuf,
    pub bytes: u64,
    pub inodes: u64,
}

impl CheckpointCapacity {
    pub fn new(path: PathBuf, disk_bytes: u64, memory_bytes: u64, drives: u64) -> Result<Self> {
        // Exported disk plus its compaction output, and memory plus its compaction output
        // can coexist with all existing artifacts. Add 25% for indexes/encoding.
        let raw = disk_bytes
            .checked_mul(2)
            .context("checkpoint disk estimate overflow")?
            .checked_add(
                memory_bytes
                    .checked_mul(2)
                    .context("checkpoint memory estimate overflow")?,
            )
            .context("checkpoint estimate overflow")?;
        let bytes = raw
            .checked_add(raw / 4)
            .context("checkpoint estimate overflow")?;
        let inodes = drives
            .checked_add(1)
            .and_then(|n| n.checked_mul(2048))
            .context("checkpoint inode estimate overflow")?;
        Ok(Self {
            path,
            bytes,
            inodes,
        })
    }
}

fn existing_ancestor(path: &Path) -> Result<&Path> {
    let mut current = path;
    while !current.try_exists()? {
        current = current
            .parent()
            .context("checkpoint path has no existing ancestor")?;
    }
    Ok(current)
}

fn largest_consumers(root: &Path) -> Vec<(String, u64)> {
    fn allocated(
        path: &Path,
        seen: &mut std::collections::BTreeSet<(u64, u64)>,
    ) -> std::io::Result<u64> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !seen.insert((metadata.dev(), metadata.ino())) {
            return Ok(0);
        }
        let mut bytes = metadata.blocks().saturating_mul(512);
        if metadata.is_dir() {
            for child in std::fs::read_dir(path)? {
                bytes = bytes.saturating_add(allocated(&child?.path(), seen)?);
            }
        }
        Ok(bytes)
    }
    let mut usage = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            // Managed state directory names only; never enumerate guest files
            // or print configuration/credential contents.
            if let Ok(bytes) = allocated(&entry.path(), &mut Default::default()) {
                usage.push((entry.file_name().to_string_lossy().into_owned(), bytes));
            }
        }
    }
    usage.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));
    usage.truncate(5);
    usage
}

pub fn check(requirements: &[CheckpointCapacity]) -> Result<()> {
    let mut filesystems: BTreeMap<u64, (PathBuf, u64, u64)> = BTreeMap::new();
    for requirement in requirements {
        let path = existing_ancestor(&requirement.path)?;
        let dev = std::fs::metadata(path)?.dev();
        let entry = filesystems.entry(dev).or_insert((path.to_path_buf(), 0, 0));
        entry.1 = entry
            .1
            .checked_add(requirement.bytes)
            .context("checkpoint bytes overflow")?;
        entry.2 = entry
            .2
            .checked_add(requirement.inodes)
            .context("checkpoint inodes overflow")?;
    }
    for (_, (path, bytes, inodes)) in filesystems {
        let stats = statvfs(&path).context("inspect checkpoint filesystem capacity")?;
        let available = stats
            .blocks_available()
            .saturating_mul(stats.fragment_size());
        let total = stats.blocks().saturating_mul(stats.fragment_size());
        let headroom = (total / 20).max(1 << 30);
        let required = bytes
            .checked_add(headroom)
            .context("checkpoint headroom overflow")?;
        let required_inodes = inodes.saturating_add(4096);
        if available < required || stats.files_available() < required_inodes {
            bail!("checkpoint capacity refused before stopping guests: filesystem={} required_bytes={} available_bytes={} headroom_bytes={} required_inodes={} available_inodes={} largest_state_consumers={:?}; add capacity or review reference-aware cleanup; do not remove live layers or recovery backups",
                path.display(), required, available, headroom, required_inodes, stats.files_available(), largest_consumers(&path));
        }
        tracing::info!(filesystem = %path.display(), required_bytes = required,
            available_bytes = available, required_inodes, available_inodes = stats.files_available(),
            "checkpoint capacity preflight passed; recheck required at capture");
    }
    Ok(())
}
