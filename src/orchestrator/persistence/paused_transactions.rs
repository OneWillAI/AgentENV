//! Explicit transaction states for paused-sandbox persistence.

use super::codecs::PersistedPausedRecord;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PersistedPausedLifecycle {
    Paused,
    /// A resume has started but has not reached its durable-success point.
    Resuming,
    /// The resumed VM was published as running. The final generation remains
    /// available for the next incremental pause or crash recovery.
    Resumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PersistedPausedCommitState {
    Prepared,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StopProofReconciliation {
    Unchanged,
    ObservationRecorded,
    RuntimeAbsent,
}

impl PersistedPausedRecord {
    pub(super) fn reconcile_stop_proof_for_boot(
        &mut self,
        current_boot_id: &str,
    ) -> StopProofReconciliation {
        if self.lifecycle != PersistedPausedLifecycle::Paused
            || self.commit_state != PersistedPausedCommitState::Committed
            || self.metadata.resume_recovery_pending
            || self.metadata.paused_runtime_stopped
        {
            return StopProofReconciliation::Unchanged;
        }

        match self.unproven_stop_boot_id.as_deref() {
            Some(observed_boot_id) if observed_boot_id != current_boot_id => {
                self.unproven_stop_boot_id = None;
                self.metadata.paused_runtime_stopped = true;
                StopProofReconciliation::RuntimeAbsent
            }
            Some(_) => StopProofReconciliation::Unchanged,
            None => {
                self.unproven_stop_boot_id = Some(current_boot_id.to_owned());
                StopProofReconciliation::ObservationRecorded
            }
        }
    }
}
