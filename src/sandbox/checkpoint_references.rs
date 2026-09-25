//! Explicit storage references shared by checkpoint retention and live guests.
use anyhow::{bail, Context, Result};
use std::path::{Component, Path, PathBuf};

pub(crate) fn absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        bail!(
            "checkpoint artifact reference must be absolute without parent traversal: {}",
            path.display()
        );
    }
    // Resolve aliases before comparing with managed checkpoint directories.
    // An evicted cache entry may be absent; resolve its existing parent rather
    // than treating cache residency as checkpoint integrity. Never guess through
    // a dangling symlink or a missing/ambiguous parent.
    match std::fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && std::fs::symlink_metadata(path)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            let parent = path.parent().context("reference has no parent")?;
            Ok(std::fs::canonicalize(parent)?
                .join(path.file_name().context("reference has no filename")?))
        }
        Err(error) => {
            Err(error).with_context(|| format!("resolve checkpoint reference: {}", path.display()))
        }
    }
}

/// Only storage fields are references. Environment, user metadata, URLs and
/// extension parameters must never influence checkpoint collection.
pub(crate) fn image(path: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = vec![absolute(path)?];
    let config = overlaybd::config::load_image_config(path)
        .with_context(|| format!("read checkpoint image references: {}", path.display()))?;
    for layer in config.lowers {
        for value in [layer.file, layer.target_file, layer.gzip_index, layer.dir] {
            if !value.is_empty() {
                paths.push(absolute(Path::new(&value))?);
            }
        }
    }
    for value in [
        config.upper.data,
        config.upper.index,
        config.upper.target,
        config.upper.gzip_index,
    ] {
        if !value.is_empty() {
            paths.push(absolute(Path::new(&value))?);
        }
    }
    Ok(paths)
}
