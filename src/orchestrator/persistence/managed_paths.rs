//! Validation of paths owned by the persisted-sandbox store.
//!
//! All callers must pass through these checks before reading or deleting an
//! artifact. In particular, a path under `artifacts/` is not trusted when any
//! component is a symlink or resolves outside the store.

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::types::SandboxId;

pub(super) fn validated_artifact_path(
    root: &Path,
    records_db: &Path,
    quarantine_db: &Path,
    create_idempotency_db: &Path,
    path: &Path,
) -> Option<PathBuf> {
    let relative = path.strip_prefix(root).ok()?;
    let mut components = relative.components();
    if !matches!(components.next(), Some(Component::Normal(name)) if name == "artifacts") {
        return None;
    }
    let mut probe = root.join("artifacts");
    if matches!(fs::symlink_metadata(&probe), Ok(metadata) if metadata.file_type().is_symlink()) {
        return None;
    }
    for component in components {
        let Component::Normal(component) = component else {
            return None;
        };
        probe.push(component);
        if matches!(fs::symlink_metadata(&probe), Ok(metadata) if metadata.file_type().is_symlink())
        {
            return None;
        }
    }
    let canonical_root = fs::canonicalize(root).ok()?;
    let candidate = fs::canonicalize(path).ok()?;
    if candidate == canonical_root || !candidate.starts_with(&canonical_root) {
        return None;
    }
    let database_paths = [records_db, quarantine_db, create_idempotency_db];
    database_paths
        .into_iter()
        .filter_map(|database_path| fs::canonicalize(database_path).ok())
        .all(|database_path| !candidate.starts_with(database_path))
        .then_some(candidate)
}

pub(super) fn validated_generation_path(
    root: &Path,
    sandbox_id: &SandboxId,
    path: &Path,
) -> Option<PathBuf> {
    let artifacts_root = root.join("artifacts");
    let relative = path.strip_prefix(&artifacts_root).ok()?;
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
    let canonical = validated_artifact_path(
        root,
        &root.join("records.db"),
        &root.join("quarantine.db"),
        &root.join("create-idempotency.db"),
        path,
    )?;
    matches!(fs::symlink_metadata(&canonical), Ok(metadata) if metadata.file_type().is_dir())
        .then_some(canonical)
}

pub(super) fn validated_sandbox_root_path(
    root: &Path,
    sandbox_id: &SandboxId,
    path: &Path,
) -> Option<PathBuf> {
    let artifacts_root = root.join("artifacts");
    let relative = path.strip_prefix(&artifacts_root).ok()?;
    let mut components = relative.components();
    let Some(Component::Normal(found_sandbox_id)) = components.next() else {
        return None;
    };
    if found_sandbox_id.to_string_lossy() != sandbox_id.to_string() || components.next().is_some() {
        return None;
    }
    let canonical = validated_artifact_path(
        root,
        &root.join("records.db"),
        &root.join("quarantine.db"),
        &root.join("create-idempotency.db"),
        path,
    )?;
    matches!(fs::symlink_metadata(&canonical), Ok(metadata) if metadata.file_type().is_dir())
        .then_some(canonical)
}
