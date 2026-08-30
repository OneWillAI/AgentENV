//! Lifecycle transition states used by the orchestrator.
//!
//! These small enums make the durable boundary explicit: callers can only
//! finalize a transition after the corresponding state has been recorded.

use super::launch_plan::LaunchPlan;
use super::store::SandboxMetadata;
use super::types::SandboxState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailedLaunchStage {
    Registered,
    TransitionalPersisted,
    RunningPersisted,
}

impl FailedLaunchStage {
    pub(super) fn rollback_expected_state(self, plan: &LaunchPlan) -> Option<SandboxState> {
        match self {
            Self::Registered => None,
            Self::TransitionalPersisted => Some(plan.transitional_state()),
            Self::RunningPersisted => Some(SandboxState::Running),
        }
    }

    pub(super) fn should_detach_proxy_route(self) -> bool {
        matches!(self, Self::RunningPersisted)
    }
}

#[derive(Debug)]
pub(super) enum DeleteTransition {
    Retry,
    Complete,
}

#[derive(Debug)]
pub(super) enum ResumePreparation {
    Paused(SandboxMetadata),
    Complete(SandboxMetadata),
}
