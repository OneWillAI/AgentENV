//! Filesystem durability primitives used by paused-sandbox transactions.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub(super) fn sync_regular_file(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(target_os = "linux")]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(target_os = "linux"))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

pub(super) fn sync_tree_bottom_up(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
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
    for entry in fs::read_dir(path)? {
        sync_tree_bottom_up(&entry?.path())?;
    }
    sync_directory(path)
}

pub(super) fn sync_directory_chain(start: &Path, root: &Path) -> std::io::Result<()> {
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

pub(super) fn sync_artifact_tree_and_parents(
    artifact_root: &Path,
    root: &Path,
) -> std::io::Result<()> {
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

pub(super) fn write_file_atomically_and_sync(
    path: &Path,
    bytes: &[u8],
    root: &Path,
) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "paused sandbox manifest path {} has no parent",
                path.display()
            ),
        )
    })?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_directory_chain(parent, root)
}

pub(super) fn remove_file_and_sync(path: &Path, root: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
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
