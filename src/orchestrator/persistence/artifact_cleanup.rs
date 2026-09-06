//! Safe cleanup primitives for persisted sandbox artifact trees.

use std::path::Path;

use tokio::fs;

use super::{PersistenceResult, SandboxPersistenceError};

/// Remove exactly one already-validated artifact root. Path authorization is
/// intentionally kept in `managed_paths`; this helper only performs the
/// filesystem operation and translates errors.
pub(super) async fn remove_root(path: &Path) -> PersistenceResult<()> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(path).await,
        Ok(_) => fs::remove_file(path).await,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(SandboxPersistenceError::io(
                "inspect paused sandbox artifacts",
                path,
                source,
            ));
        }
    }
    .map_err(|source| SandboxPersistenceError::io("remove paused sandbox artifacts", path, source))
}
