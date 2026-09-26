//! Read-only physical block planning statistics for a recorded first-touch
//! page list against final memory layer objects. Usage:
//!
//!   pack_plan_stats --mem-virtual-size <bytes> --budget <bytes> \
//!     --pages <file-with-u64-le-offsets> --layer <path=size=digest>...
//!
//! Prints the plan's coverage/amplification stats as JSON. No network access.

use anyhow::{Context, Result};
use overlaybd::pack_planner::{plan_blocks, FinalLayerBytes, FinalLayerSource};

#[derive(clap::Parser)]
struct Args {
    /// Memory image virtual size in bytes.
    #[arg(long)]
    mem_virtual_size: u64,
    /// Total pack budget in bytes (header + tables + payload).
    #[arg(long, default_value_t = 1 << 30)]
    budget: u64,
    /// File with the first-touch list: little-endian u64 page offsets.
    #[arg(long)]
    pages: std::path::PathBuf,
    /// Final layer object as `path=size=digest`, bottom-to-top order.
    #[arg(long)]
    layer: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = <Args as clap::Parser>::parse();

    let raw = std::fs::read(&args.pages)
        .with_context(|| format!("read pages file {}", args.pages.display()))?;
    anyhow::ensure!(raw.len() % 8 == 0, "pages file not u64-aligned");
    let pages: Vec<u32> = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| {
            let offset = u64::from_le_bytes(*chunk);
            u32::try_from(offset / 4096).context("page index overflow")
        })
        .collect::<Result<Vec<_>>>()?;

    let mut layers = Vec::with_capacity(args.layer.len());
    for spec in &args.layer {
        let (path, size, digest) = spec
            .split_once('=')
            .and_then(|(left, rest)| rest.split_once('=').map(|(s, d)| (left, s, d)))
            .with_context(|| format!("invalid layer spec '{spec}' (want path=size=digest)"))?;
        layers.push(FinalLayerSource {
            digest: digest.to_string(),
            size: size
                .parse()
                .with_context(|| format!("invalid size in '{spec}'"))?,
            source: FinalLayerBytes::LocalPath(std::path::PathBuf::from(path)),
        });
    }

    let plan = plan_blocks(&pages, args.mem_virtual_size, &layers, args.budget).await?;
    let stats = &plan.stats;
    let mut blocks_per_object = vec![0u64; plan.objects.len()];
    for block in &plan.blocks {
        blocks_per_object[block.object as usize] += 1;
    }
    println!(
        "{}",
        serde_json::json!({
            "objects": plan.objects.len(),
            "blocks": plan.blocks.len(),
            "blocks_per_object": blocks_per_object,
            "pages_total": stats.pages_total,
            "pages_backed": stats.pages_backed,
            "pages_zero_hole": stats.pages_zero_hole,
            "pages_truncated_by_budget": stats.pages_truncated_by_budget,
            "data_blocks": stats.data_blocks,
            "metadata_blocks": stats.metadata_blocks,
            "unique_blocks": stats.unique_blocks,
            "payload_bytes": stats.payload_bytes,
            "gap_runs": stats.gap_runs,
            "gap_blocks": stats.gap_blocks,
        })
    );
    Ok(())
}
