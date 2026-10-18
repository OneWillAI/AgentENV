//! Recoverable, grow-only updates of an existing writable upper's headers.
//! The caller must exclude image I/O and sealing while growing/recovering.
use super::types::HEADER_SIZE;
use crate::config::{UpperConfig, UpperMode};
use crate::lsmt::format::HeaderTrailer;
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::mem::size_of;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use zerocopy::{FromBytes, IntoBytes};

#[derive(Serialize, Deserialize)]
struct HeaderUpdate {
    device: u64,
    inode: u64,
    bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Intent {
    version: u32,
    size: u64,
    data: HeaderUpdate,
    index: Option<HeaderUpdate>,
}

pub(crate) fn journal_path(upper: &UpperConfig) -> PathBuf {
    let mut path = PathBuf::from(&upper.data).into_os_string();
    path.push(".grow-intent");
    path.into()
}

fn open(path: &str) -> Result<File> {
    Ok(OpenOptions::new().read(true).write(true).open(path)?)
}

fn header(bytes: &[u8]) -> Result<HeaderTrailer> {
    ensure!(
        bytes.len() == HEADER_SIZE as usize,
        "invalid grow header length"
    );
    let h = HeaderTrailer::read_from_bytes(&bytes[..size_of::<HeaderTrailer>()])
        .map_err(|_| anyhow::anyhow!("invalid grow header"))?;
    ensure!(
        h.verify_magic() && h.is_header() && !h.is_sealed(),
        "grow requires an unsealed upper header"
    );
    Ok(h)
}

fn prepare(file: &File, size: u64, data: bool) -> Result<(HeaderUpdate, u64)> {
    let mut bytes = vec![0; HEADER_SIZE as usize];
    file.read_exact_at(&mut bytes, 0)?;
    let mut h = header(&bytes)?;
    ensure!(h.is_data_file() == data, "unexpected upper header type");
    let old_size = h.virtual_size.get();
    ensure!(size >= old_size, "disk shrink is not supported");
    h.virtual_size.set(size);
    bytes[..size_of::<HeaderTrailer>()].copy_from_slice(h.as_bytes());
    let metadata = file.metadata()?;
    Ok((
        HeaderUpdate {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes,
        },
        old_size,
    ))
}

fn verify_identity(file: &File, update: &HeaderUpdate, size: u64) -> Result<()> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.dev() == update.device && metadata.ino() == update.inode,
        "grow intent belongs to a different upper file"
    );
    ensure!(
        header(&update.bytes)?.virtual_size.get() == size,
        "grow intent size mismatch"
    );
    Ok(())
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

fn apply(
    upper: &UpperConfig,
    intent: &Intent,
    hook: &mut impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    ensure!(intent.version == 1, "unsupported grow intent version");
    let data = open(&upper.data)?;
    let index = intent
        .index
        .as_ref()
        .map(|_| open(&upper.index))
        .transpose()?;
    verify_identity(&data, &intent.data, intent.size)?;
    if let (Some(file), Some(update)) = (&index, &intent.index) {
        verify_identity(file, update, intent.size)?;
    }
    // Validate every identity before modifying either file. A crash at any point
    // leaves the durable redo record available; replay never depends on the
    // possibly torn live header.
    if header(&intent.data.bytes)?.is_sparse_rw() {
        data.set_len(
            intent
                .size
                .checked_add(HEADER_SIZE)
                .context("grow size overflow")?,
        )?;
    }
    data.write_all_at(&intent.data.bytes, 0)?;
    hook("data_header")?;
    if let (Some(file), Some(update)) = (&index, &intent.index) {
        file.write_all_at(&update.bytes, 0)?;
        hook("index_header")?;
        file.sync_all()?;
    }
    data.sync_all()?;
    hook("headers_synced")?;
    let path = journal_path(upper);
    fs::remove_file(&path)?;
    sync_parent(&path)?;
    hook("committed")?;
    Ok(())
}

pub(crate) fn recover(upper: &UpperConfig) -> Result<Option<u64>> {
    let bytes = match fs::read(journal_path(upper)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let intent: Intent = serde_json::from_slice(&bytes).context("read grow intent")?;
    apply(upper, &intent, &mut |_| Ok(()))?;
    Ok(Some(intent.size))
}

pub(crate) fn grow(upper: &UpperConfig, size: u64) -> Result<u64> {
    grow_with_hook(upper, size, &mut |_| Ok(()))
}

fn grow_with_hook(
    upper: &UpperConfig,
    size: u64,
    hook: &mut impl FnMut(&str) -> Result<()>,
) -> Result<u64> {
    ensure!(
        size != 0 && size.is_multiple_of(HEADER_SIZE) && size.checked_add(HEADER_SIZE).is_some(),
        "invalid grow size"
    );
    let size = recover(upper)?.map_or(size, |pending| size.max(pending));
    let data_file = open(&upper.data)?;
    let (data, old_size) = prepare(&data_file, size, true)?;
    let data_header = header(&data.bytes)?;
    ensure!(
        data_header.is_sparse_rw() == matches!(upper.writable_mode(), UpperMode::Sparse),
        "upper mode/header mismatch"
    );
    ensure!(
        data_header.is_hybrid_rw()
            == matches!(upper.writable_mode(), UpperMode::HybridLogStructured),
        "upper mode/header mismatch"
    );
    let index = match upper.writable_mode() {
        UpperMode::Sparse => None,
        UpperMode::LogStructured | UpperMode::HybridLogStructured => {
            let (index, index_size) = prepare(&open(&upper.index)?, size, false)?;
            ensure!(
                header(&index.bytes)?.uuid == data_header.uuid,
                "upper header UUIDs disagree"
            );
            ensure!(
                index_size == old_size,
                "upper header sizes disagree before grow"
            );
            Some(index)
        }
    };
    if size == old_size {
        return Ok(size);
    }
    let intent = Intent {
        version: 1,
        size,
        data,
        index,
    };
    let path = journal_path(upper);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&serde_json::to_vec(&intent)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(&path).map_err(|e| e.error)?;
    sync_parent(&path)?;
    hook("intent_synced")?;
    apply(upper, &intent, hook)?;
    Ok(size)
}

pub(crate) fn ensure_complete(upper: &UpperConfig) -> Result<()> {
    if !upper.data.is_empty() && journal_path(upper).try_exists()? {
        bail!("upper grow requires recovery before snapshot or seal");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{initialize_file_rw_paths, RwLayout};
    use super::*;

    fn fixture(tmp: &tempfile::TempDir) -> UpperConfig {
        let data = tmp.path().join("upper.data");
        let index = tmp.path().join("upper.index");
        initialize_file_rw_paths(&data, Some(&index), 8192, RwLayout::LogStructured).unwrap();
        UpperConfig {
            data: data.to_string_lossy().into_owned(),
            index: index.to_string_lossy().into_owned(),
            ..UpperConfig::default()
        }
    }

    #[test]
    fn interrupted_grow_replays_both_headers_without_touching_payload() {
        for stage in [
            "intent_synced",
            "data_header",
            "index_header",
            "headers_synced",
            "committed",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let upper = fixture(&tmp);
            let payload = vec![0x7b; 8192];
            open(&upper.data)
                .unwrap()
                .write_all_at(&payload, HEADER_SIZE)
                .unwrap();
            let result = grow_with_hook(&upper, 32768, &mut |at| {
                if at == stage {
                    bail!("injected interruption at {stage}");
                }
                Ok(())
            });
            assert!(result.is_err());
            if stage != "committed" {
                assert!(ensure_complete(&upper).is_err());
            }
            recover(&upper).unwrap();
            ensure_complete(&upper).unwrap();
            for path in [&upper.data, &upper.index] {
                let mut bytes = vec![0; HEADER_SIZE as usize];
                open(path).unwrap().read_exact_at(&mut bytes, 0).unwrap();
                assert_eq!(header(&bytes).unwrap().virtual_size.get(), 32768);
            }
            let mut actual = vec![0; payload.len()];
            open(&upper.data)
                .unwrap()
                .read_exact_at(&mut actual, HEADER_SIZE)
                .unwrap();
            assert_eq!(actual, payload);
            assert_eq!(grow(&upper, 32768).unwrap(), 32768);
            assert!(grow(&upper, 8192).is_err());
        }
    }

    #[test]
    fn recovery_refuses_replaced_upper() {
        let tmp = tempfile::tempdir().unwrap();
        let upper = fixture(&tmp);
        grow_with_hook(&upper, 32768, &mut |_| bail!("interrupt")).unwrap_err();
        fs::rename(&upper.data, tmp.path().join("old.data")).unwrap();
        File::create(&upper.data)
            .unwrap()
            .write_all(&vec![0x33; 4096])
            .unwrap();
        assert!(recover(&upper).is_err());
        assert_eq!(fs::read(&upper.data).unwrap(), vec![0x33; 4096]);
    }
}
