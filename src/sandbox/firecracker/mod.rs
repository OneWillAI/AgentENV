//! Firecracker-based sandbox backend implementation.
//!
//! Provides [`FirecrackerSandbox`] (the concrete VM-backed sandbox) and
//! [`FirecrackerSandboxFactory`] which wires sandbox configuration from the
//! global [`ConfigManager`][crate::cfg::ConfigManager].

mod cold_boot;
mod config;
mod connector;
mod factory;
mod instance;
mod mmds;
mod overlaybd_snapshot;
mod pool;
mod process_vm_reader;
mod sandbox;
mod socket;
mod startup_pack;
mod upper_mode_policy;

pub(crate) use cold_boot::recovery_checkpoint_references;
pub use config::{
    FirecrackerCommonConfig, FirecrackerRuntimePolicy, FirecrackerSandboxConfig,
    FirecrackerSnapshotConfig,
};
pub use factory::FirecrackerSandboxFactory;
pub(super) use instance::FirecrackerInstance;
pub use pool::FirecrackerPool;
pub use sandbox::{FirecrackerCaptureArtifacts, FirecrackerPausedState, FirecrackerSandbox};
pub(crate) use startup_pack::record_startup_pack;
