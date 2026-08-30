//! Host-local recovery utility for paused-sandbox persistence quarantine.
//!
//! This intentionally does not initialize the AgentENV runtime or expose an
//! HTTP endpoint.  Run it on the worker that owns the persisted-sandbox disk,
//! with the AgentENV server stopped, when an operator needs to inspect or
//! explicitly purge state that startup refused to delete automatically.

use std::path::PathBuf;

use agentenv::orchestrator::{FileBackedSandboxPersister, PausedSandboxRecoveryReport};
use agentenv::virtualization::VirtualizationMode;
use anyhow::Context as _;
use clap::{Parser, Subcommand};
use nix::unistd::Uid;

#[derive(Debug, Parser)]
#[command(
    name = "aenv-paused-recovery",
    about = "Inspect, reconcile, or explicitly purge quarantined AgentENV paused-sandbox state"
)]
struct Cli {
    /// Absolute path to AgentENV's persisted sandbox store.  Supplying it
    /// explicitly prevents accidental recovery work against another worker's
    /// state directory.
    #[arg(long)]
    store: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print quarantined records and artifact paths as JSON.
    List,
    /// Rebuild only missing/corrupt RocksDB index entries from valid v2
    /// manifests.  Manifest/index mismatches stay quarantined.
    Reconcile,
    /// Permanently remove one quarantine item and its tracked artifact path.
    /// This is the sole automated destructive path for quarantined data.
    Purge {
        /// Quarantine ID reported by `list`.
        id: String,

        /// Acknowledge that this permanently removes the selected data.
        #[arg(long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if !cli.store.is_absolute() {
        anyhow::bail!("--store must be an absolute path");
    }
    if !Uid::effective().is_root() {
        anyhow::bail!("aenv-paused-recovery must be run by a host administrator (effective UID 0)");
    }
    let persister = FileBackedSandboxPersister::new(cli.store, VirtualizationMode::Kvm);

    match cli.command {
        Command::List => {
            let quarantines = persister
                .list_quarantines()
                .await
                .context("list paused-sandbox quarantine")?;
            println!("{}", serde_json::to_string_pretty(&quarantines)?);
        }
        Command::Reconcile => {
            let report = persister
                .reconcile_quarantines()
                .await
                .context("reconcile paused-sandbox manifest index")?;
            print_report(report)?;
        }
        Command::Purge { id, yes } => {
            if !yes {
                anyhow::bail!("refusing destructive purge without --yes");
            }
            persister
                .purge_quarantine(&id)
                .await
                .with_context(|| format!("purge paused-sandbox quarantine {id}"))?;
            println!("{{\"purged\":{}}}", serde_json::to_string(&id)?);
        }
    }
    Ok(())
}

fn print_report(report: PausedSandboxRecoveryReport) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
