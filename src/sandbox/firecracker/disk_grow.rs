//! Resize intent stays beside the runtime image until filesystem growth is done.
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::orchestrator::persistence::durable_storage::write_file_atomically_and_sync;

#[derive(Serialize, Deserialize)]
pub(super) struct GrowIntent {
    pub target_bytes: u64,
    pub token: Uuid,
    pub complete: bool,
}

impl GrowIntent {
    fn path(image: &Path) -> PathBuf {
        image.with_extension("grow.json")
    }

    pub fn read(image: &Path) -> Result<Option<Self>> {
        match std::fs::read(Self::path(image)) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("read disk grow intent")?,
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context("read disk grow intent"),
        }
    }

    pub fn begin(image: &Path, target_bytes: u64) -> Result<Self> {
        if let Some(prior) = Self::read(image)? {
            ensure!(
                target_bytes >= prior.target_bytes,
                "disk shrink is not supported"
            );
            if !prior.complete {
                ensure!(
                    target_bytes == prior.target_bytes,
                    "retry unfinished grow to {} bytes first",
                    prior.target_bytes
                );
                // The caller has thawed the prior lease. Use a fresh token so
                // its still-sleeping watchdog cannot thaw this retry's freeze.
            }
        }
        let intent = Self {
            target_bytes,
            token: Uuid::new_v4(),
            complete: false,
        };
        intent.save(image)?;
        Ok(intent)
    }

    pub fn save(&self, image: &Path) -> Result<()> {
        let path = Self::path(image);
        write_file_atomically_and_sync(
            &path,
            &serde_json::to_vec(self)?,
            path.parent().context("grow intent parent")?,
        )
        .context("persist disk grow intent")
    }

    pub fn ensure_complete(image: &Path) -> Result<()> {
        ensure!(
            Self::read(image)?.is_none_or(|intent| intent.complete),
            "retry unfinished disk grow before capturing this VM"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_growth_renews_lease_token_and_blocks_capture() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let image = dir.path().join("image.json");
        let first = GrowIntent::begin(&image, 32 << 20)?;
        assert!(GrowIntent::ensure_complete(&image).is_err());
        assert_eq!(GrowIntent::read(&image)?.unwrap().token, first.token);
        let mut retry = GrowIntent::begin(&image, 32 << 20)?;
        assert_ne!(retry.token, first.token);
        assert!(GrowIntent::begin(&image, 64 << 20).is_err());
        retry.complete = true;
        retry.save(&image)?;
        GrowIntent::ensure_complete(&image)?;
        assert!(GrowIntent::begin(&image, 16 << 20).is_err());
        assert_ne!(GrowIntent::begin(&image, 64 << 20)?.token, first.token);
        Ok(())
    }
}
