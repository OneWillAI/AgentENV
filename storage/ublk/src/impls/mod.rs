mod overlaybd_target;
pub mod startup_pack_recorder;

pub use overlaybd_target::{OverlaybdTarget, OverlaybdTargetConfig};
pub use startup_pack_recorder::{
    FinalizeOutcome, RecordingVerdict, StartupPackReadGuard, StartupPackRecorder,
};
