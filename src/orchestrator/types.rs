use std::collections::HashMap;
use std::fmt::Display;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::sandbox::CustomExtensionParams;
use crate::snapshot::CommandContext;
use crate::types::{ImageConfigs, SandboxId, SandboxResources};

pub const MAX_CREATE_IDEMPOTENCY_KEY_LEN: usize = 128;

/// Client-supplied identity for safely retrying one sandbox create operation.
///
/// The key is opaque to AgentENV. The fingerprint is computed by the API from
/// the create route and request body so reusing a key for a different request
/// is rejected instead of silently returning an unrelated sandbox. Claims are
/// coordinated within one orchestrator node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateSandboxIdempotency {
    key: String,
    request_fingerprint: String,
}

impl CreateSandboxIdempotency {
    pub fn new(
        key: impl Into<String>,
        request_fingerprint: impl Into<String>,
    ) -> std::result::Result<Self, String> {
        let key = key.into();
        if key.is_empty() {
            return Err("idempotencyKey must not be empty".to_string());
        }
        if key.chars().count() > MAX_CREATE_IDEMPOTENCY_KEY_LEN {
            return Err(format!(
                "idempotencyKey must not exceed {MAX_CREATE_IDEMPOTENCY_KEY_LEN} characters"
            ));
        }

        let request_fingerprint = request_fingerprint.into();
        if request_fingerprint.is_empty() {
            return Err("create request fingerprint must not be empty".to_string());
        }

        Ok(Self {
            key,
            request_fingerprint,
        })
    }

    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    pub(crate) fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }
}

#[derive(Clone)]
pub enum SandboxLaunchSource {
    Snapshot(Box<crate::snapshot::RunnableSnapshot>),
    Image {
        image_ref: String,
        overlaybd_config_path: PathBuf,
        context: Box<CommandContext>,
        resources: Option<crate::types::SandboxResources>,
        extra_drives: Vec<crate::sandbox::ExtraDrive>,
        extra_boot_args: Option<String>,
        /// Raw source image config metadata for the sandbox's resolved images.
        image_configs: Box<ImageConfigs>,
    },
}

#[derive(Clone)]
pub struct CreateSandboxRequest {
    pub source: SandboxLaunchSource,
    pub timeout: Option<Duration>,
    pub timeout_action: super::SandboxTimeoutAction,
    pub auto_resume: bool,
    pub user_metadata: Option<HashMap<String, String>>,
    pub env_vars: Option<HashMap<String, String>>,
    pub network_policy: crate::sandbox::SandboxNetworkPolicy,
    pub secure: bool,
    /// Optional retry identity for this create operation.
    pub idempotency: Option<CreateSandboxIdempotency>,
    /// Opaque user-provided JSON passed through to the custom extension hooks.
    pub custom_extension_params: Option<CustomExtensionParams>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxLifecycleEventType {
    Create,
    Delete,
    Pause,
    Resume,
    Fork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxLifecycleEvent {
    pub event_type: SandboxLifecycleEventType,
    pub sandbox_id: SandboxId,
    pub resources: SandboxResources,
}

#[derive(Clone, Debug, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxState {
    Creating,
    Resuming,
    Running,
    Snapshotting,
    Forking,
    Pausing,
    Paused,
    Killing,
}

impl Display for SandboxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SandboxState::Creating => "creating",
            SandboxState::Resuming => "resuming",
            SandboxState::Running => "running",
            SandboxState::Snapshotting => "snapshotting",
            SandboxState::Forking => "forking",
            SandboxState::Pausing => "pausing",
            SandboxState::Paused => "paused",
            SandboxState::Killing => "killing",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug)]
pub struct SnapshotCaptureResult {
    pub metadata: super::store::SandboxMetadata,
    pub captured_snapshot: crate::sandbox::CapturedSandboxSnapshot,
}
