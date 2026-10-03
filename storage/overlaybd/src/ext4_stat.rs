//! Best-effort ext4 usage probe over a read-only view of a block device.
//!
//! Reads primary block-group free counters, which change while ext4 is mounted.
//! The superblock summary can remain unchanged after writes and sync. Includes
//! filesystem metadata in allocated bytes. No journal replay or checksum
//! verification: committed metadata can lag active guest writes. Unsupported
//! layouts return unknown rather than a misleading zero or stale summary.

use std::sync::Arc;

use anyhow::{ensure, Context, Result};

use crate::io::virtual_file::VirtualFile;

const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_LEN: usize = 1024;
const EXT4_MAGIC: u16 = 0xEF53;
const FEATURE_INCOMPAT_64BIT: u32 = 0x0080;

fn le16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().expect("le16"))
}

fn le32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("le32"))
}

pub struct Ext4Usage {
    pub used_bytes: u64,
    /// End of the primary allocation metadata range starting at byte 1024.
    pub metadata_end: u64,
}

pub async fn ext4_used_bytes(file: &Arc<dyn VirtualFile>) -> Result<u64> {
    Ok(ext4_usage(file).await?.used_bytes)
}

/// Probe committed allocation counters without walking files or block bitmaps.
pub async fn ext4_usage(file: &Arc<dyn VirtualFile>) -> Result<Ext4Usage> {
    let sb = file
        .read_at(SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)
        .await
        .context("read ext4 superblock")?;
    ensure!(sb.len() == SUPERBLOCK_LEN, "short read on ext4 superblock");
    ensure!(
        le16(&sb, 0x38) == EXT4_MAGIC,
        "not an ext4 filesystem (bad superblock magic)"
    );
    let block_size = 1024u64
        .checked_shl(le32(&sb, 0x18))
        .context("ext4 block size shift overflow")?;
    ensure!(
        (1024..=65536).contains(&block_size),
        "unsupported ext4 block size"
    );
    let incompat = le32(&sb, 0x60);
    ensure!(incompat & 0x10 == 0, "ext4 meta_bg layout unsupported");
    ensure!(
        le32(&sb, 0x64) & 0x200 == 0,
        "ext4 bigalloc layout unsupported"
    );
    let is_64bit = incompat & FEATURE_INCOMPAT_64BIT != 0;
    let mut blocks_count = u64::from(le32(&sb, 0x04));
    if is_64bit {
        blocks_count |= u64::from(le32(&sb, 0x150)) << 32;
    }
    let first_block = u64::from(le32(&sb, 0x14));
    let per_group = u64::from(le32(&sb, 0x20));
    ensure!(
        blocks_count > first_block && per_group > 0 && per_group <= block_size * 8,
        "invalid ext4 group geometry"
    );
    ensure!(
        first_block == u64::from(block_size == 1024),
        "invalid ext4 first block"
    );
    let descriptor_size = if is_64bit {
        u64::from(le16(&sb, 0xfe))
    } else {
        32
    };
    ensure!(
        ((if is_64bit { 64 } else { 32 })..=block_size).contains(&descriptor_size)
            && descriptor_size.is_power_of_two(),
        "invalid ext4 descriptor size"
    );
    let groups = (blocks_count - first_block).div_ceil(per_group);
    let table_size = groups
        .checked_mul(descriptor_size)
        .context("ext4 table overflow")?;
    ensure!(
        table_size <= 16 * 1024 * 1024,
        "ext4 descriptor table too large"
    );
    let table_start = (first_block + 1) * block_size;
    let read_size = table_size.div_ceil(block_size) * block_size;
    let table = file
        .read_at(table_start, read_size as usize)
        .await
        .context("read ext4 group descriptors")?;
    ensure!(
        table.len() == read_size as usize,
        "short ext4 descriptor table"
    );
    let mut free_blocks = 0u64;
    for group in 0..groups {
        let offset = (group * descriptor_size) as usize;
        let mut free = u64::from(le16(&table, offset + 0x0c));
        if is_64bit {
            free |= u64::from(le16(&table, offset + 0x2c)) << 16;
        }
        let group_blocks = per_group.min(blocks_count - first_block - group * per_group);
        ensure!(free <= group_blocks, "invalid ext4 group free count");
        free_blocks += free;
    }
    Ok(Ext4Usage {
        used_bytes: (blocks_count - free_blocks)
            .checked_mul(block_size)
            .context("ext4 used size overflow")?,
        metadata_end: table_start + table_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::local::LocalFile;

    fn put16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Minimal ext4 geometry and primary descriptor table.
    fn fake_image(block_shift: u32, blocks: u64, free: u64, use_64bit: bool) -> Vec<u8> {
        let block_size = 1024u64 << block_shift;
        let per_group = block_size * 8;
        let groups = blocks.div_ceil(per_group);
        let descriptor_size = if use_64bit { 64 } else { 32 };
        let mut img = vec![
            0u8;
            (block_size + (groups * descriptor_size).div_ceil(block_size) * block_size)
                as usize
        ];
        let sb = &mut img[1024..2048];
        put16(sb, 0x38, EXT4_MAGIC);
        put32(sb, 0x18, block_shift);
        put32(sb, 0x04, blocks as u32);
        put32(sb, 0x0C, 0); // Deliberately stale superblock summary.
        put32(sb, 0x20, per_group as u32);
        if use_64bit {
            put32(sb, 0x60, FEATURE_INCOMPAT_64BIT);
            put32(sb, 0x150, (blocks >> 32) as u32);
            put16(sb, 0xfe, 64);
        }
        let mut remaining = free;
        for group in 0..groups {
            let count = remaining.min(per_group.min(blocks - group * per_group));
            remaining -= count;
            let offset = (block_size + group * descriptor_size) as usize;
            put16(&mut img, offset + 12, count as u16);
            if use_64bit {
                put16(&mut img, offset + 44, (count >> 16) as u16);
            }
        }
        img
    }

    async fn open_image(dir: &tempfile::TempDir, bytes: &[u8]) -> Arc<dyn VirtualFile> {
        let path = dir.path().join("dev.img");
        std::fs::write(&path, bytes).unwrap();
        Arc::new(LocalFile::open_ro(&path).unwrap())
    }

    #[tokio::test]
    async fn reads_group_counts_despite_stale_superblock() {
        let dir = tempfile::tempdir().unwrap();
        // 4 KiB blocks, 1000 blocks total, 250 free → used = 750 * 4096.
        let file = open_image(&dir, &fake_image(2, 1000, 250, false)).await;
        assert_eq!(ext4_used_bytes(&file).await.unwrap(), 750 * 4096);
    }

    #[tokio::test]
    async fn reads_64bit_counters() {
        let dir = tempfile::tempdir().unwrap();
        let blocks = 5u64 << 30;
        let free = 1u64 << 30;
        let file = open_image(&dir, &fake_image(2, blocks, free, true)).await;
        assert_eq!(
            ext4_used_bytes(&file).await.unwrap(),
            (blocks - free) * 4096
        );
    }

    #[tokio::test]
    async fn rejects_non_ext4_view() {
        let dir = tempfile::tempdir().unwrap();
        let file = open_image(&dir, &vec![0u8; 2048]).await;
        assert!(ext4_used_bytes(&file).await.is_err());
    }
}
