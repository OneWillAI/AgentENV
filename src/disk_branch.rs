//! Immutable, durably published disk branches. Published data is retained until
//! an operator retires every dependent sandbox and snapshot; see the API guide.
use crate::cfg::AppConfig;
use crate::orchestrator::persistence::durable_storage::{
    sync_artifact_tree_and_parents, sync_directory_chain, write_file_atomically_and_sync,
};
use crate::types::SandboxId;
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

pub(crate) fn root(config: &AppConfig) -> PathBuf {
    config
        .firecracker
        .work_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join("aenv"))
        .join("managed-snapshots")
        .join("disk-branches")
}

pub(crate) fn identity(source: SandboxId, key: Option<&str>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"agentenv-disk-branch-v1\0");
    hash.update(source.to_string().as_bytes());
    hash.update([0]);
    // No retry key means a new snapshot on each call, never an implicit replay.
    let nonce = SandboxId::new().to_string();
    hash.update(key.unwrap_or(&nonce).as_bytes());
    hex::encode(hash.finalize())
}

pub(crate) struct Publication {
    pub(crate) id: String,
    root: PathBuf,
    pub(crate) directory: PathBuf,
    _lock: File,
}

impl Publication {
    pub(crate) async fn acquire(root: PathBuf, id: String) -> Result<Self> {
        tokio::task::spawn_blocking(move || {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&root)?;
            let root = root.canonicalize()?;
            sync_directory_chain(&root, root.ancestors().nth(2).unwrap_or(&root))?;
            let locks = root.join(".locks");
            fs::create_dir_all(&locks)?;
            let lock = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(locks.join(&id))?;
            lock.lock().context("lock disk-branch publication")?;
            Ok(Self {
                directory: root.join(&id),
                id,
                root,
                _lock: lock,
            })
        })
        .await
        .context("join disk-branch publication lock")?
    }

    pub(crate) fn replay(&self) -> Result<Option<String>> {
        let marker = self.directory.join("branch.ref");
        let image = match fs::read_to_string(&marker) {
            Ok(image) => image,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("read disk-branch replay marker"),
        };
        let path = image
            .strip_prefix("overlaybd-config:")
            .context("invalid branch marker")?;
        validate(&self.root, Path::new(path))?;
        // Also completes durability after an interrupted directory fsync.
        sync_artifact_tree_and_parents(&self.directory, &self.root)?;
        Ok(Some(image))
    }

    pub(crate) fn prepare(&self) -> Result<()> {
        // Only callers holding the stable lock may remove an incomplete attempt.
        // A committed branch is never overwritten, including after parent deletion.
        ensure!(
            !self.directory.join("branch.ref").exists(),
            "branch already published"
        );
        if self.directory.exists() {
            ensure!(
                !fs::symlink_metadata(&self.directory)?
                    .file_type()
                    .is_symlink(),
                "branch directory is a symlink"
            );
            fs::remove_dir_all(&self.directory)?;
        }
        fs::create_dir(&self.directory)?;
        Ok(())
    }

    pub(crate) fn commit(&self, config: &Path) -> Result<String> {
        let config = config.canonicalize()?;
        ensure!(
            config.starts_with(&self.directory) && config.is_file(),
            "branch image escaped its directory"
        );
        sync_artifact_tree_and_parents(&self.directory, &self.root)?;
        let image = format!("overlaybd-config:{}", config.display());
        write_file_atomically_and_sync(
            &self.directory.join("branch.ref"),
            image.as_bytes(),
            &self.root,
        )?;
        Ok(image)
    }
}

pub(crate) fn validate(root: &Path, requested: &Path) -> Result<PathBuf> {
    ensure!(
        requested.is_absolute(),
        "branch image path must be absolute"
    );
    let root = root
        .canonicalize()
        .context("resolve managed disk-branch root")?;
    let path = requested.canonicalize().context("resolve branch image")?;
    let relative = path
        .strip_prefix(&root)
        .context("image is outside managed disk-branch root")?;
    let id = relative
        .components()
        .next()
        .context("missing branch identity")?
        .as_os_str();
    let id_text = id.to_str().context("invalid branch identity")?;
    ensure!(
        id_text.len() == 64 && id_text.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid branch identity"
    );
    ensure!(path.is_file(), "branch image is not a file");
    let marker =
        fs::read_to_string(root.join(id).join("branch.ref")).context("branch is not committed")?;
    ensure!(
        marker == format!("overlaybd-config:{}", path.display()),
        "branch marker does not name this image"
    );
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn published_branches_replay_after_reopen_without_overwriting_contents() {
        let temp = tempdir().unwrap();
        let source = SandboxId::new();
        let id = identity(source, Some("retry:key"));
        let branch = Publication::acquire(temp.path().to_owned(), id.clone())
            .await
            .unwrap();
        branch.prepare().unwrap();
        let config = branch.directory.join("image.json");
        fs::write(&config, b"parent contents").unwrap();
        assert!(
            validate(temp.path(), &config).is_err(),
            "unpublished images must not resolve"
        );
        let image = branch.commit(&config).unwrap();
        assert!(branch.prepare().is_err());
        drop(branch);
        let reopened = Publication::acquire(temp.path().to_owned(), id)
            .await
            .unwrap();
        assert_eq!(reopened.replay().unwrap(), Some(image));
        assert_eq!(fs::read(&config).unwrap(), b"parent contents");
        assert!(validate(temp.path(), &config).is_ok());
    }

    #[tokio::test]
    async fn concurrent_publishers_serialize_and_interrupted_attempts_are_cleaned() {
        let temp = tempdir().unwrap();
        let id = identity(SandboxId::new(), Some("same"));
        let first = Publication::acquire(temp.path().to_owned(), id.clone())
            .await
            .unwrap();
        first.prepare().unwrap();
        fs::write(first.directory.join("partial"), b"incomplete").unwrap();
        let root = temp.path().to_owned();
        let mut waiting =
            tokio::spawn(async move { Publication::acquire(root, id).await.unwrap() });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut waiting)
                .await
                .is_err(),
            "a concurrent publisher cannot enter before the first releases its lock"
        );
        // Releasing the OS lock models process exit before publication.
        drop(first);
        let second = waiting.await.unwrap();
        assert!(second.replay().unwrap().is_none());
        second.prepare().unwrap();
        assert!(!second.directory.join("partial").exists());
        let config = second.directory.join("image.json");
        fs::write(&config, b"complete").unwrap();
        second.commit(&config).unwrap();
    }

    #[tokio::test]
    async fn marker_publication_failure_cannot_report_success_or_resolve() {
        let temp = tempdir().unwrap();
        let branch = Publication::acquire(
            temp.path().to_owned(),
            identity(SandboxId::new(), Some("key")),
        )
        .await
        .unwrap();
        branch.prepare().unwrap();
        let config = branch.directory.join("image.json");
        fs::write(&config, b"{}").unwrap();
        fs::create_dir(branch.directory.join("branch.ref")).unwrap();
        assert!(branch.commit(&config).is_err());
        assert!(branch.replay().is_err());
        assert!(validate(temp.path(), &config).is_err());
    }

    #[test]
    fn exact_retry_keys_and_source_identity_never_alias_path_components() {
        let source = SandboxId::new();
        let keys = ["a:b", "a_b", ".", "..", " key", "key", "key "];
        let ids: std::collections::HashSet<_> =
            keys.iter().map(|key| identity(source, Some(key))).collect();
        assert_eq!(ids.len(), keys.len());
        for id in ids {
            assert_eq!(id.len(), 64);
            assert!(!id.contains('.'));
        }
        assert_ne!(
            identity(source, Some("key")),
            identity(SandboxId::new(), Some("key"))
        );
        assert_ne!(identity(source, None), identity(source, None));
    }

    #[tokio::test]
    async fn resolver_rejects_other_roots_symlinks_and_uncommitted_images() {
        use std::os::unix::fs::symlink;
        let temp = tempdir().unwrap();
        let other = tempdir().unwrap();
        let branch = Publication::acquire(
            other.path().join("disk-branches"),
            identity(SandboxId::new(), Some("key")),
        )
        .await
        .unwrap();
        branch.prepare().unwrap();
        let config = branch.directory.join("image.json");
        fs::write(&config, b"{}").unwrap();
        branch.commit(&config).unwrap();
        assert!(validate(temp.path(), &config).is_err());
        let link = temp.path().join("image.json");
        symlink(&config, &link).unwrap();
        assert!(validate(temp.path(), &link).is_err());
        let extra = branch.directory.join("other.json");
        fs::write(&extra, b"{}").unwrap();
        assert!(validate(other.path().join("disk-branches").as_path(), &extra).is_err());
    }
}
