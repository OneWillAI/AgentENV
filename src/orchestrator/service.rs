use std::collections::{HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use futures::FutureExt;
use tokio::sync::{broadcast, oneshot, watch, Mutex, RwLock};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, trace, warn};

use crate::cfg::ConfigManager;
use crate::image::cache::{
    local_image_services_from_global_config, RuntimeImageOwner, RuntimeImageRefs,
};
use crate::sandbox::{
    CustomExtensionClient, CustomExtensionParams, EnvdAccessToken, FirecrackerSandboxFactory,
    FreshSandboxBuildSpec, PausedSandboxState, RuntimeArtifactSet, SandboxAccessTokenGenerator,
    SandboxBackend, SandboxBackendFactory, SandboxCaptureError, SandboxForkSpec,
    SandboxLaunchConfig, SandboxNetworkPolicy, SandboxRuntimeInfo,
};
use crate::snapshot::SnapshotRuntimeVersions;
use crate::types::{bytes_to_mib_ceil, SandboxId, SandboxResources};
use crate::volume::VolumeManager;

use super::launch_plan::{CreateLaunchSource, LaunchPlan};
use super::metrics::{
    aggregate_resource_metrics, OrchestratorCounters, OrchestratorMetrics, SandboxContribution,
};
use super::persistence::{
    CreateIdempotencyRecord, CreateIdempotencyRecordState, DisabledSandboxPersister,
    FileBackedSandboxPersister, SandboxPersistenceError, SandboxPersister,
};
use super::proxy::{ProxyLookupResult, ProxyRoute, ProxyRouteTable, ProxyTarget};
use super::state_machine::{
    DeleteTransition, FailedLaunchStage, PausePreparation, ResumePreparation,
};
use super::store::*;
use super::types::{
    CreateSandboxIdempotency, CreateSandboxRequest, SandboxForkChildSpec, SandboxLaunchSource,
    SandboxLifecycleEvent, SandboxLifecycleEventType, SandboxState, SnapshotCaptureResult,
};
use super::{OrchestratorError, Result, SandboxForkOutcome, SandboxOperation};

#[path = "sandbox_metrics.rs"]
mod sandbox_metrics;
use sandbox_metrics::SandboxMetrics;

type SandboxHandle = Arc<Mutex<Box<dyn SandboxBackend>>>;
#[derive(Default)]
enum DeleteProgress {
    #[default]
    Capture,
    Stop {
        capture_failed: bool,
    },
    Release {
        capture_failed: bool,
    },
    Done,
}

/// Maximum time to wait for a sandbox to leave a transitional state.
/// Guards against indefinite blocking when a sandbox's in-progress operation
/// never completes (e.g. the task holding the state panics without rolling back).
const WAIT_TRANSITION_TIMEOUT: Duration = Duration::from_secs(60);
const SANDBOX_EVENT_CHANNEL_CAPACITY: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum CreateIdempotencyState {
    Creating,
    Succeeded,
    Failed(String),
    Deleting,
}

#[derive(Debug)]
struct CreateIdempotencyEntry {
    sandbox_id: SandboxId,
    request_fingerprint: String,
    state: watch::Sender<CreateIdempotencyState>,
}

impl CreateIdempotencyEntry {
    fn durable_record(
        &self,
        key: impl Into<String>,
        state: CreateIdempotencyRecordState,
    ) -> CreateIdempotencyRecord {
        CreateIdempotencyRecord {
            key: key.into(),
            request_fingerprint: self.request_fingerprint.clone(),
            sandbox_id: self.sandbox_id,
            state,
        }
    }
}

/// Ensures an unexpected panic/abort cannot leave in-process replays waiting on
/// `Creating` forever. The durable journal remains `Creating` in that case and
/// startup converts it to a fail-closed tombstone.
struct CreateIdempotencyCompletionGuard {
    entry: Arc<CreateIdempotencyEntry>,
    armed: bool,
}

    fn should_detach_proxy_route(self) -> bool {
        matches!(self, Self::RunningPersisted)
    }
impl CreateIdempotencyCompletionGuard {
    fn new(entry: Arc<CreateIdempotencyEntry>) -> Self {
        Self { entry, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CreateIdempotencyCompletionGuard {
    fn drop(&mut self) {
        if self.armed {
            self.entry.state.send_if_modified(|state| {
                if matches!(state, CreateIdempotencyState::Creating) {
                    *state = CreateIdempotencyState::Failed(
                        "create operation ended unexpectedly".to_string(),
                    );
                    true
                } else {
                    false
                }
            });
        }
    }
}

enum CreateIdempotencyClaim {
    Owner(Arc<CreateIdempotencyEntry>),
    Replay(Arc<CreateIdempotencyEntry>),
}

pub struct Orchestrator<
    S: MetadataStore = InMemoryMetadataStore,
    F: SandboxBackendFactory = FirecrackerSandboxFactory,
    P: SandboxPersister = FileBackedSandboxPersister,
> {
    store: S,
    factory: F,
    persister: P,
    sandboxes: RwLock<HashMap<SandboxId, SandboxHandle>>,
    template_build_ids: RwLock<HashSet<SandboxId>>,
    deletions: Mutex<HashMap<SandboxId, Arc<Mutex<DeleteProgress>>>>,
    proxy_routes: RwLock<ProxyRouteTable>,
    next_proxy_route_version: AtomicU64,
    counters: OrchestratorCounters,
    sandbox_metrics: Mutex<SandboxMetrics>,
    sandbox_event_tx: broadcast::Sender<SandboxLifecycleEvent>,
    default_sandbox_timeout: Duration,
    is_shutting_down: std::sync::atomic::AtomicBool,
    shutdown_tx: watch::Sender<bool>,
    shutdown_complete: Mutex<bool>,
    lifecycle_gate: RwLock<()>,
    image_refs: Arc<dyn RuntimeImageRefs>,
    access_tokens: SandboxAccessTokenGenerator,
    create_idempotency: Mutex<HashMap<String, Arc<CreateIdempotencyEntry>>>,
    volume_manager: Option<Arc<VolumeManager>>,
}

impl Orchestrator<InMemoryMetadataStore, FirecrackerSandboxFactory, DisabledSandboxPersister> {
    pub async fn with_in_memory_store() -> Arc<Self> {
        Self::new(
            InMemoryMetadataStore::new(),
            FirecrackerSandboxFactory::new(),
            DisabledSandboxPersister,
        )
        .await
        .expect("in-memory orchestrator should never fail to initialize")
    }
}

impl<F> Orchestrator<InMemoryMetadataStore, F>
where
    F: SandboxBackendFactory,
{
    pub async fn with_file_backed_store_and_factory(factory: F) -> Result<Arc<Self>> {
        let config = ConfigManager::global_config();
        let store = InMemoryMetadataStore::new();
        let persister = FileBackedSandboxPersister::new(
            config.orchestrator.persisted_sandbox_store_path.clone(),
            config.virtualization_mode,
        );
        Self::new(store, factory, persister).await
    }

    pub async fn with_file_backed_store_factory_and_volumes(
        factory: F,
        volume_manager: Arc<VolumeManager>,
    ) -> Result<Arc<Self>> {
        let config = ConfigManager::global_config();
        let store = InMemoryMetadataStore::new();
        let persister = FileBackedSandboxPersister::new(
            config.orchestrator.persisted_sandbox_store_path.clone(),
            config.virtualization_mode,
        );
        let image_refs = local_image_services_from_global_config().runtime_refs;
        Self::new_inner_with_volumes(store, factory, persister, image_refs, Some(volume_manager))
            .await
    }
}

impl<S, F, P> Orchestrator<S, F, P>
where
    S: MetadataStore + 'static,
    F: SandboxBackendFactory,
    P: SandboxPersister + 'static,
{
    pub async fn new(store: S, factory: F, persister: P) -> Result<Arc<Self>> {
        let image_refs = local_image_services_from_global_config().runtime_refs;
        Self::new_inner(store, factory, persister, image_refs).await
    }

    async fn new_inner(
        store: S,
        factory: F,
        persister: P,
        image_refs: Arc<dyn RuntimeImageRefs>,
    ) -> Result<Arc<Self>> {
        Self::new_inner_with_volumes(store, factory, persister, image_refs, None).await
    }

    async fn new_inner_with_volumes(
        store: S,
        factory: F,
        persister: P,
        image_refs: Arc<dyn RuntimeImageRefs>,
        volume_manager: Option<Arc<VolumeManager>>,
    ) -> Result<Arc<Self>> {
        let app_config = ConfigManager::global_config();
        let config = &app_config.orchestrator;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (sandbox_event_tx, _sandbox_event_rx) =
            broadcast::channel(SANDBOX_EVENT_CHANNEL_CAPACITY);

        // Restore persisted sandboxes from the previous run, keeping the paused
        // ones (with their state) for the paused-protection reconcile below.
        let mut persisted = persister.load_all(&factory).await?;
        let durable_create_idempotency = persister.load_create_idempotency_records().await?;
        let create_idempotency = Self::restore_create_idempotency(
            &persister,
            &mut persisted,
            durable_create_idempotency,
        )
        .await?;
        let managed_seed_must_exist = persisted_sandboxes_require_managed_seed(&persisted);
        let access_tokens = tokio::task::spawn_blocking(move || {
            SandboxAccessTokenGenerator::load_or_create(app_config, managed_seed_must_exist)
        })
        .await
        .context("join sandbox access-token seed loader")??;
        let restored_paused: Vec<(SandboxId, Arc<dyn PausedSandboxState>)> = persisted
            .iter()
            .filter(|metadata| metadata.state == SandboxState::Paused)
            .filter_map(|metadata| {
                metadata
                    .paused_state
                    .as_ref()
                    .map(|paused_state| (metadata.id, Arc::clone(paused_state)))
            })
            .collect();
        for metadata in persisted {
            store.add(metadata).await?;
        }

        let orchestrator = Arc::new(Self {
            store,
            factory,
            persister,
            sandboxes: RwLock::new(HashMap::new()),
            template_build_ids: RwLock::new(HashSet::new()),
            deletions: Mutex::new(HashMap::new()),
            proxy_routes: RwLock::new(ProxyRouteTable::default()),
            next_proxy_route_version: AtomicU64::new(1),
            counters: OrchestratorCounters::default(),
            sandbox_metrics: Mutex::new(SandboxMetrics::default()),
            sandbox_event_tx,
            default_sandbox_timeout: Duration::from_secs(config.default_sandbox_timeout_secs),
            is_shutting_down: std::sync::atomic::AtomicBool::new(false),
            shutdown_tx,
            shutdown_complete: Mutex::new(false),
            lifecycle_gate: RwLock::new(()),
            image_refs,
            access_tokens,
            create_idempotency: Mutex::new(create_idempotency),
            volume_manager,
        });

        Self::start_metrics_task(&orchestrator);

        // Start the auto-evict task.
        let evict_interval = Duration::from_millis(config.auto_evict_interval_ms);
        Self::start_auto_evict_task(Arc::clone(&orchestrator), evict_interval, shutdown_rx);

        // Reconcile durable paused protection, then start maintenance (fail-closed).
        let gc = app_config.image.cache.gc_schedule();
        if gc.enabled {
            match orchestrator
                .reconcile_paused_at_startup(&restored_paused)
                .await
            {
                Ok(()) => {
                    Self::start_local_image_maintenance_task(
                        Arc::clone(&orchestrator),
                        gc.interval,
                        orchestrator.shutdown_tx.subscribe(),
                    );
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        "local image protection reconcile failed at startup; not starting maintenance (fail-closed)"
                    );
                }
            }
        }

        Ok(orchestrator)
    }

    async fn restore_create_idempotency(
        persister: &P,
        persisted: &mut Vec<SandboxMetadata>,
        records: Vec<CreateIdempotencyRecord>,
    ) -> Result<HashMap<String, Arc<CreateIdempotencyEntry>>> {
        let mut durable = Self::validate_durable_create_records(records)?;
        Self::migrate_paused_create_records(persister, persisted, &mut durable).await?;
        let (deleting_keys, deleting_sandboxes) =
            Self::reconcile_interrupted_create_records(persister, &mut durable).await?;
        persisted.retain(|metadata| !deleting_sandboxes.contains(&metadata.id));
        Ok(Self::restore_create_entries(durable, &deleting_keys))
    }

    fn validate_durable_create_records(
        records: Vec<CreateIdempotencyRecord>,
    ) -> Result<HashMap<String, CreateIdempotencyRecord>> {
        let mut durable = HashMap::new();
        for record in records {
            CreateSandboxIdempotency::new(record.key.clone(), record.request_fingerprint.clone())
                .map_err(|message| {
                OrchestratorError::InternalError(format!(
                    "invalid durable create idempotency record for sandbox {}: {message}",
                    record.sandbox_id
                ))
            })?;
            let key = record.key.clone();
            if durable.insert(key.clone(), record).is_some() {
                return Err(OrchestratorError::InternalError(format!(
                    "duplicate durable create idempotency key '{key}'"
                )));
            }
        }
        Ok(durable)
    }

    async fn migrate_paused_create_records(
        persister: &P,
        persisted: &[SandboxMetadata],
        durable: &mut HashMap<String, CreateIdempotencyRecord>,
    ) -> Result<()> {
        let mut paused_keys = HashMap::<String, (SandboxId, String)>::new();
        for metadata in persisted {
            Self::migrate_paused_create_record(persister, metadata, &mut paused_keys, durable)
                .await?;
        }
        Ok(())
    }

    async fn migrate_paused_create_record(
        persister: &P,
        metadata: &SandboxMetadata,
        paused_keys: &mut HashMap<String, (SandboxId, String)>,
        durable: &mut HashMap<String, CreateIdempotencyRecord>,
    ) -> Result<()> {
        let (key, request_fingerprint) = match (
            metadata.create_idempotency_key.as_ref(),
            metadata.create_request_fingerprint.as_ref(),
        ) {
            (None, None) => return Ok(()),
            (Some(key), Some(request_fingerprint)) => (key, request_fingerprint),
            _ => {
                return Err(OrchestratorError::InternalError(format!(
                    "sandbox {} has incomplete create idempotency metadata",
                    metadata.id
                )));
            }
        };
        CreateSandboxIdempotency::new(key.clone(), request_fingerprint.clone()).map_err(
            |message| {
                OrchestratorError::InternalError(format!(
                    "sandbox {} has invalid create idempotency metadata: {message}",
                    metadata.id
                ))
            },
        )?;
        if let Some((other_id, _)) =
            paused_keys.insert(key.clone(), (metadata.id, request_fingerprint.clone()))
        {
            return Err(OrchestratorError::InternalError(format!(
                "paused sandboxes {other_id} and {} share create idempotency key '{key}'",
                metadata.id
            )));
        }

        match durable.get_mut(key) {
            Some(record)
                if record.sandbox_id != metadata.id
                    || record.request_fingerprint != *request_fingerprint =>
            {
                Err(OrchestratorError::InternalError(format!(
                    "paused sandbox {} conflicts with durable create idempotency key '{key}'",
                    metadata.id
                )))
            }
            Some(record) if record.state == CreateIdempotencyRecordState::Creating => {
                record.state = CreateIdempotencyRecordState::Succeeded;
                persister.persist_create_idempotency_record(record).await?;
                Ok(())
            }
            Some(record) if record.state == CreateIdempotencyRecordState::Failed => {
                Err(OrchestratorError::InternalError(format!(
                    "paused sandbox {} conflicts with failed create idempotency key '{key}'",
                    metadata.id
                )))
            }
            Some(_) => Ok(()),
            None => {
                let record = CreateIdempotencyRecord {
                    key: key.clone(),
                    request_fingerprint: request_fingerprint.clone(),
                    sandbox_id: metadata.id,
                    state: CreateIdempotencyRecordState::Succeeded,
                };
                persister.persist_create_idempotency_record(&record).await?;
                durable.insert(key.clone(), record);
                Ok(())
            }
        }
    }

    async fn reconcile_interrupted_create_records(
        persister: &P,
        durable: &mut HashMap<String, CreateIdempotencyRecord>,
    ) -> Result<(HashSet<String>, HashSet<SandboxId>)> {
        let mut deleting_keys = HashSet::new();
        let mut deleting_sandboxes = HashSet::new();
        for (key, record) in durable.iter_mut() {
            if Self::reconcile_interrupted_create_record(persister, key, record).await? {
                deleting_keys.insert(key.clone());
                deleting_sandboxes.insert(record.sandbox_id);
            }
        }
        Ok((deleting_keys, deleting_sandboxes))
    }

    async fn reconcile_interrupted_create_record(
        persister: &P,
        key: &str,
        record: &mut CreateIdempotencyRecord,
    ) -> Result<bool> {
        match record.state {
            CreateIdempotencyRecordState::Deleting => {
                match persister
                    .delete_record_and_artifacts(&record.sandbox_id)
                    .await
                {
                    Ok(()) => {
                        persister.delete_create_idempotency_record(key).await?;
                        Ok(true)
                    }
                    Err(error) if error.requires_explicit_purge() => {
                        warn!(
                            sandbox_id = %record.sandbox_id,
                            error = %error,
                            "paused sandbox delete at startup left artifacts in host-local quarantine; releasing the create key"
                        );
                        persister.delete_create_idempotency_record(key).await?;
                        Ok(true)
                    }
                    Err(error) => {
                        warn!(
                            sandbox_id = %record.sandbox_id,
                            error = %error,
                            "paused sandbox delete at startup could not finish; retaining a failed create-key tombstone"
                        );
                        record.state = CreateIdempotencyRecordState::Failed;
                        persister.persist_create_idempotency_record(record).await?;
                        Ok(false)
                    }
                }
            }
            CreateIdempotencyRecordState::Creating => {
                record.state = CreateIdempotencyRecordState::Failed;
                persister.persist_create_idempotency_record(record).await?;
                Ok(false)
            }
            CreateIdempotencyRecordState::Succeeded | CreateIdempotencyRecordState::Failed => {
                Ok(false)
            }
        }
    }

    fn restore_create_entries(
        durable: HashMap<String, CreateIdempotencyRecord>,
        deleting_keys: &HashSet<String>,
    ) -> HashMap<String, Arc<CreateIdempotencyEntry>> {
        let mut entries = HashMap::new();
        for (key, record) in durable {
            if deleting_keys.contains(&key) {
                continue;
            }
            let restored_state = match record.state {
                CreateIdempotencyRecordState::Creating => unreachable!(
                    "interrupted creating records are converted to failed before restoration"
                ),
                CreateIdempotencyRecordState::Succeeded => CreateIdempotencyState::Succeeded,
                CreateIdempotencyRecordState::Failed => CreateIdempotencyState::Failed(
                    "previous create outcome is unavailable after restart".to_string(),
                ),
                CreateIdempotencyRecordState::Deleting => {
                    unreachable!("deleting records are reconciled before restoration")
                }
            };
            let (state, _) = watch::channel(restored_state);
            entries.insert(
                key,
                Arc::new(CreateIdempotencyEntry {
                    sandbox_id: record.sandbox_id,
                    request_fingerprint: record.request_fingerprint,
                    state,
                }),
            );
        }
        entries
    }

    async fn run_cancellation_safe<T>(
        self: &Arc<Self>,
        operation: &'static str,
        sandbox_id: SandboxId,
        future: impl std::future::Future<Output = Result<T>> + Send + 'static,
    ) -> Result<T>
    where
        T: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let guard = this.lifecycle_gate.read().await;
            let result = match this.ensure_accepting_lifecycle_operations() {
                Ok(()) => future.await,
                Err(error) => {
                    if operation == "create" {
                        this.counters.record_create_fail(1);
                    }
                    Err(error)
                }
            };
            drop(guard);
            if matches!(operation, "pause" | "reboot" | "evict") && result.is_ok() {
                let _exclusive = this.lifecycle_gate.write().await;
                this.collect_checkpoints().await;
            }
            if tx.send(result).is_err() {
                debug!(
                    sandbox_id = %sandbox_id,
                    operation,
                    "operation completed after caller stopped waiting"
                );
            }
        });

        rx.await.map_err(|err| {
            OrchestratorError::InternalError(format!(
                "operation task ended before reporting result: {err}"
            ))
        })?
    }

    async fn protect_image_refs(
        &self,
        owner: RuntimeImageOwner,
        artifacts: RuntimeArtifactSet,
        context: &'static str,
    ) -> Result<()> {
        self.image_refs
            .pin(owner, artifacts)
            .await
            .map_err(|error| {
                OrchestratorError::InternalError(format!("pin {context} image refs: {error:#}"))
            })
    }

    async fn release_image_refs(&self, owner: RuntimeImageOwner) {
        self.image_refs.unpin_best_effort(owner).await;
    }

    async fn publish_sandbox_volume_backings(
        &self,
        sandbox_id: SandboxId,
        volume_ids: &[String],
    ) -> Result<()> {
        let Some(manager) = self.volume_manager.as_ref() else {
            return Ok(());
        };
        manager
            .recover_and_publish_backings(&sandbox_id.to_string(), volume_ids)
            .await
            .map_err(|error| OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::SnapshotVolumes,
                source: error.into(),
            })
    }

    async fn finalize_terminal_volumes(&self, metadata: &SandboxMetadata) {
        let Some(manager) = self.volume_manager.as_ref() else {
            return;
        };
        let volume_ids = metadata.volume_mounts.values().cloned().collect::<Vec<_>>();
        if volume_ids.is_empty() {
            return;
        }
        let owner = metadata.id.to_string();
        if let Err(error) = manager
            .recover_and_publish_backings(&owner, &volume_ids)
            .await
        {
            warn!(sandbox_id = %metadata.id, %error, "failed to publish volumes during terminal sandbox cleanup");
        }
        if let Err(error) = manager.replace_owner_for(&owner, None, &volume_ids).await {
            warn!(sandbox_id = %metadata.id, %error, "failed to release volumes during terminal sandbox cleanup");
        }
    }

    /// Snapshot the running set's local runtime artifacts for maintenance.
    async fn collect_running_artifacts(&self) -> Vec<(SandboxId, RuntimeArtifactSet)> {
        let handles = {
            self.sandboxes
                .read()
                .await
                .iter()
                .map(|(sandbox_id, handle)| (*sandbox_id, Arc::clone(handle)))
                .collect::<Vec<_>>()
        };
        let mut running = Vec::with_capacity(handles.len());
        for (sandbox_id, handle) in handles {
            let artifacts = {
                let sandbox = handle.lock().await;
                sandbox.runtime_info().runtime_artifacts
            };
            running.push((sandbox_id, artifacts));
        }
        running
    }

    /// Fail-closed startup reconcile before maintenance can run: durably protect
    /// every restored paused sandbox, then drop orphaned paused protection.
    async fn reconcile_paused_at_startup(
        &self,
        restored_paused: &[(SandboxId, Arc<dyn PausedSandboxState>)],
    ) -> Result<()> {
        let mut live_paused = Vec::with_capacity(restored_paused.len());
        for (sandbox_id, paused_state) in restored_paused {
            self.protect_image_refs(
                RuntimeImageOwner::PausedSandbox(*sandbox_id),
                paused_state.runtime_artifacts(),
                "paused sandbox",
            )
            .await?;
            live_paused.push(*sandbox_id);
        }
        self.image_refs
            .reconcile_paused(&live_paused)
            .await
            .map_err(|error| {
                OrchestratorError::InternalError(format!(
                    "reconcile local image protection: {error:#}"
                ))
            })
    }

    /// Creates and starts a new sandbox from a resolved launch source.
    ///
    /// This call only returns after the sandbox is fully ready and persisted
    /// as `Running`, so callers can treat a successful return as immediately
    /// usable without additional polling.
    pub async fn create_sandbox(
        self: &Arc<Self>,
        request: CreateSandboxRequest,
    ) -> Result<SandboxMetadata> {
        self.create_sandbox_with_volume_reservation(request, None)
            .await
    }

    /// Claim volume ownership before any backend can open the mounted disks.
    /// API cancellation cannot interrupt this handoff or the supervised launch.
    pub(crate) async fn create_sandbox_with_volume_reservation(
        self: &Arc<Self>,
        request: CreateSandboxRequest,
        pending_volume_owner: Option<String>,
    ) -> Result<SandboxMetadata> {
        let sandbox_id = SandboxId::new();
        let this = Arc::clone(self);
        self.run_cancellation_safe("create", sandbox_id, async move {
            if request.idempotency.is_some() {
                this.create_idempotent_sandbox(sandbox_id, request, pending_volume_owner)
                    .await
            } else {
                this.create_sandbox_inner(sandbox_id, request, false, pending_volume_owner)
                    .await
            }
        })
        .await
    }

    pub(crate) async fn create_template_builder(
        self: &Arc<Self>,
        build_id: SandboxId,
        request: CreateSandboxRequest,
    ) -> Result<SandboxMetadata> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("create_builder", build_id, async move {
            this.create_sandbox_inner(build_id, request, true, None)
                .await
        })
        .await
    }

    /// Supervise the entire idempotent operation, including the first durable
    /// claim write and its publication in memory. The caller only waits on the
    /// outer oneshot, so cancellation cannot detach an in-flight RocksDB write
    /// from the claim that owns it.
    async fn create_idempotent_sandbox(
        self: Arc<Self>,
        candidate_sandbox_id: SandboxId,
        request: CreateSandboxRequest,
        pending_volume_owner: Option<String>,
    ) -> Result<SandboxMetadata> {
        let idempotency = request
            .idempotency
            .clone()
            .expect("idempotent create supervisor requires idempotency");
        match self
            .claim_create_idempotency(&idempotency, candidate_sandbox_id)
            .await?
        {
            CreateIdempotencyClaim::Replay(entry) => {
                self.replay_idempotent_create(idempotency.key(), entry)
                    .await
            }
            CreateIdempotencyClaim::Owner(entry) => {
                let sandbox_id = entry.sandbox_id;
                let key = idempotency.key().to_string();
                let mut completion_guard =
                    CreateIdempotencyCompletionGuard::new(Arc::clone(&entry));
                let result = match AssertUnwindSafe(Arc::clone(&self).create_sandbox_inner(
                    sandbox_id,
                    request,
                    false,
                    pending_volume_owner,
                ))
                .catch_unwind()
                .await
                {
                    Ok(result) => result,
                    Err(payload) => {
                        let message = payload
                            .downcast_ref::<&str>()
                            .map(|message| (*message).to_string())
                            .or_else(|| payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "unknown panic payload".to_string());
                        Err(OrchestratorError::InternalError(format!(
                            "idempotent create panicked: {message}"
                        )))
                    }
                };
                let result = self.finish_idempotent_create(&key, &entry, result).await;
                completion_guard.disarm();
                result
            }
        }
    }

    /// Return or join an existing create claim without allocating a new one.
    /// API handlers use this before mutable template/image resolution so a
    /// successful replay cannot be invalidated by later source changes.
    pub async fn replay_create_if_present(
        &self,
        idempotency: &CreateSandboxIdempotency,
    ) -> Result<Option<SandboxMetadata>> {
        let entry = {
            let entries = self.create_idempotency.lock().await;
            let Some(entry) = entries.get(idempotency.key()) else {
                return Ok(None);
            };
            if entry.request_fingerprint != idempotency.request_fingerprint() {
                return Err(OrchestratorError::CreateIdempotencyConflict {
                    key: idempotency.key().to_string(),
                });
            }
            Arc::clone(entry)
        };
        self.replay_idempotent_create(idempotency.key(), entry)
            .await
            .map(Some)
    }

    async fn claim_create_idempotency(
        &self,
        idempotency: &CreateSandboxIdempotency,
        candidate_sandbox_id: SandboxId,
    ) -> Result<CreateIdempotencyClaim> {
        let mut entries = self.create_idempotency.lock().await;
        if let Some(entry) = entries.get(idempotency.key()) {
            if entry.request_fingerprint != idempotency.request_fingerprint() {
                return Err(OrchestratorError::CreateIdempotencyConflict {
                    key: idempotency.key().to_string(),
                });
            }
            return Ok(CreateIdempotencyClaim::Replay(Arc::clone(entry)));
        }

        let (state, _) = watch::channel(CreateIdempotencyState::Creating);
        let entry = Arc::new(CreateIdempotencyEntry {
            sandbox_id: candidate_sandbox_id,
            request_fingerprint: idempotency.request_fingerprint().to_string(),
            state,
        });
        self.persister
            .persist_create_idempotency_record(
                &entry.durable_record(idempotency.key(), CreateIdempotencyRecordState::Creating),
            )
            .await?;
        entries.insert(idempotency.key().to_string(), Arc::clone(&entry));
        Ok(CreateIdempotencyClaim::Owner(entry))
    }

    async fn replay_idempotent_create(
        &self,
        key: &str,
        entry: Arc<CreateIdempotencyEntry>,
    ) -> Result<SandboxMetadata> {
        let mut state = entry.state.subscribe();
        loop {
            let current = state.borrow_and_update().clone();
            match current {
                CreateIdempotencyState::Creating => {
                    state.changed().await.map_err(|_| {
                        OrchestratorError::InternalError(format!(
                            "idempotent create state closed before completion for key '{key}'"
                        ))
                    })?;
                }
                CreateIdempotencyState::Succeeded => {
                    return self.store.get(&entry.sandbox_id).await?.ok_or_else(|| {
                        OrchestratorError::CreateIdempotencyResultUnavailable {
                            key: key.to_string(),
                        }
                    });
                }
                CreateIdempotencyState::Failed(message) => {
                    return Err(OrchestratorError::InternalError(format!(
                        "idempotent create for key '{key}' failed: {message}"
                    )));
                }
                CreateIdempotencyState::Deleting => {
                    return Err(OrchestratorError::CreateIdempotencyResultUnavailable {
                        key: key.to_string(),
                    });
                }
            }
        }
    }

    async fn finish_idempotent_create(
        &self,
        key: &str,
        entry: &Arc<CreateIdempotencyEntry>,
        result: Result<SandboxMetadata>,
    ) -> Result<SandboxMetadata> {
        // Serialize owner completion with deletion and any later claim. A
        // delete may observe Running metadata just before this function; once
        // it marks the entry Deleting, this owner must never overwrite that
        // journal phase with Succeeded or Failed.
        let entries = self.create_idempotency.lock().await;
        let current = entries.get(key);
        if !current.is_some_and(|current| Arc::ptr_eq(current, entry))
            || !matches!(&*entry.state.borrow(), CreateIdempotencyState::Creating)
        {
            return match result {
                Ok(_) => Err(OrchestratorError::CreateIdempotencyResultUnavailable {
                    key: key.to_string(),
                }),
                Err(err) => Err(err),
            };
        }

        match result {
            Ok(metadata) => {
                if let Err(err) = self
                    .persister
                    .persist_create_idempotency_record(
                        &entry.durable_record(key, CreateIdempotencyRecordState::Succeeded),
                    )
                    .await
                {
                    let message = format!("failed to persist successful create result: {err}");
                    let _ = entry
                        .state
                        .send_replace(CreateIdempotencyState::Failed(message));
                    // The durable Creating record and in-memory Failed state are
                    // both fail-closed; never return an unjournaled success.
                    return Err(OrchestratorError::from(err));
                }
                let _ = entry.state.send_replace(CreateIdempotencyState::Succeeded);
                Ok(metadata)
            }
            Err(err) => {
                if let Err(persist_err) = self
                    .persister
                    .persist_create_idempotency_record(
                        &entry.durable_record(key, CreateIdempotencyRecordState::Failed),
                    )
                    .await
                {
                    // The original durable Creating record remains a safe
                    // tombstone and startup converts it to Failed.
                    warn!(error = ?persist_err, "failed to persist create failure tombstone");
                }
                let _ = entry
                    .state
                    .send_replace(CreateIdempotencyState::Failed(err.to_string()));
                Err(err)
            }
        }
    }

    #[tracing::instrument(
        name = "create_sandbox",
        skip(self, request),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn create_sandbox_inner(
        self: Arc<Self>,
        sandbox_id: SandboxId,
        request: CreateSandboxRequest,
        template_builder: bool,
        pending_volume_owner: Option<String>,
    ) -> Result<SandboxMetadata> {
        if let Err(err) = self.ensure_accepting_lifecycle_operations() {
            self.counters.record_create_fail(1);
            return Err(err);
        }

        let CreateSandboxRequest {
            source,
            timeout,
            timeout_action,
            user_metadata,
            env_vars,
            auto_resume,
            network_policy,
            custom_extension_params,
            secure,
            idempotency,
            volume_mounts,
            extra_drives: launch_extra_drives,
            extra_drives_in_snapshot,
        } = request;
        let create_idempotency_key = idempotency.as_ref().map(|value| value.key().to_string());
        let create_request_fingerprint = idempotency
            .as_ref()
            .map(|value| value.request_fingerprint().to_string());
        let envd_access_token = secure.then(|| self.access_tokens.generate(sandbox_id));
        info!(timeout = ?timeout, "creating sandbox");

        let result = match source {
            SandboxLaunchSource::Snapshot(snapshot) => {
                let record = snapshot.record();
                let committed = snapshot.committed();
                let configured_mode = ConfigManager::global_config().virtualization_mode;
                if committed.virtualization_mode != configured_mode {
                    self.counters.record_create_fail(1);
                    return Err(OrchestratorError::VirtualizationModeMismatch {
                        resource: format!("snapshot {}", record.id),
                        resource_mode: committed.virtualization_mode,
                        node_mode: configured_mode,
                    });
                }
                let launch_image_configs = committed.image_configs.clone();
                let mut extra_mmds = serde_json::Map::new();
                if !launch_image_configs.is_empty() {
                    extra_mmds.insert("imageConfigs".to_string(), launch_image_configs.to_value());
                };
                // Effective custom config: a launch-provided value overrides the
                // one persisted in the source snapshot; otherwise inherit it.
                // Store the effective value so publishing a snapshot from this
                // sandbox keeps the inherited config instead of dropping it.
                let effective_custom_extension_params = custom_extension_params
                    .clone()
                    .or_else(|| committed.custom_extension_params.clone());
                let launch_config = SandboxLaunchConfig {
                    sandbox_id,
                    snapshot_id: record.id.to_string(),
                    env_vars,
                    network: network_policy.runtime_policy(),
                    extra_mmds,
                    custom_extension_params: effective_custom_extension_params.clone(),
                    envd_access_token: envd_access_token.clone(),
                    extra_drives: launch_extra_drives.clone(),
                    extra_drives_in_snapshot,
                };

                let transitional_metadata = SandboxMetadata {
                    id: sandbox_id,
                    template_builder,
                    snapshot_id: record.id.to_string(),
                    snapshot_alias: record.alias.as_ref().map(ToString::to_string),
                    virtualization_mode: committed.virtualization_mode,
                    runtime_versions: committed.runtime_versions.clone(),
                    resources: *snapshot.resources(),
                    context: committed.context.clone(),
                    startup: committed.startup.clone(),
                    image_configs: launch_image_configs,
                    timeout_action,
                    auto_resume,
                    user_metadata,
                    create_idempotency_key,
                    create_request_fingerprint,
                    network_policy,
                    custom_extension_params: effective_custom_extension_params,
                    volume_mounts: volume_mounts.clone(),
                    secure,
                    ..Default::default()
                };

                self.launch_sandbox_with_volume_reservation(
                    LaunchPlan::for_create_from_snapshot(
                        sandbox_id,
                        snapshot,
                        launch_config,
                        transitional_metadata,
                        NewTimeout::Set(timeout.unwrap_or(self.default_sandbox_timeout)),
                    ),
                    pending_volume_owner.as_deref(),
                )
                .await
            }
            SandboxLaunchSource::Image {
                image_ref,
                overlaybd_config_path,
                context,
                resources,
                mut extra_drives,
                extra_boot_args,
                image_configs,
            } => {
                let context = *context;
                extra_drives.extend(launch_extra_drives);
                let resources = resources.unwrap_or_else(default_fresh_sandbox_resources);
                let launch_image_configs = *image_configs;
                let mut extra_mmds = serde_json::Map::new();
                if !launch_image_configs.is_empty() {
                    extra_mmds.insert("imageConfigs".to_string(), launch_image_configs.to_value());
                };
                let launch_config = SandboxLaunchConfig {
                    sandbox_id,
                    snapshot_id: image_ref.clone(),
                    env_vars,
                    network: network_policy.runtime_policy(),
                    extra_mmds,
                    custom_extension_params: custom_extension_params.clone(),
                    envd_access_token,
                    extra_drives: Vec::new(),
                    extra_drives_in_snapshot: false,
                };
                let build_spec = FreshSandboxBuildSpec {
                    image_config_path: overlaybd_config_path,
                    context: context.clone(),
                    resources,
                    extra_drives,
                    extra_boot_args,
                };

                let transitional_metadata = SandboxMetadata {
                    id: sandbox_id,
                    template_builder,
                    snapshot_id: image_ref,
                    snapshot_alias: None,
                    virtualization_mode: ConfigManager::global_config().virtualization_mode,
                    runtime_versions: configured_runtime_versions(),
                    resources,
                    context,
                    image_configs: launch_image_configs,
                    timeout_action,
                    auto_resume,
                    user_metadata,
                    create_idempotency_key,
                    create_request_fingerprint,
                    network_policy,
                    custom_extension_params,
                    volume_mounts,
                    secure,
                    ..Default::default()
                };

                self.launch_sandbox_with_volume_reservation(
                    LaunchPlan::for_create_fresh(
                        sandbox_id,
                        build_spec,
                        launch_config,
                        transitional_metadata,
                        NewTimeout::Set(timeout.unwrap_or(self.default_sandbox_timeout)),
                    ),
                    pending_volume_owner.as_deref(),
                )
                .await
            }
        };

        match result {
            Ok(metadata) => {
                self.counters.record_create_success(1);
                self.publish_sandbox_event(
                    SandboxLifecycleEventType::Create,
                    metadata.id,
                    metadata.resources,
                );
                Ok(metadata)
            }
            Err(err) => {
                self.counters.record_create_fail(1);
                Err(err)
            }
        }
    }

    /// Forks a running sandbox into multiple new sandboxes on the same node.
    pub async fn fork_sandbox(
        self: &Arc<Self>,
        source_sandbox_id: SandboxId,
        count: u32,
        new_timeout: NewTimeout,
    ) -> Result<Vec<SandboxForkOutcome>> {
        if self
            .store
            .get(&source_sandbox_id)
            .await?
            .is_some_and(|metadata| !metadata.volume_mounts.is_empty())
        {
            return Err(OrchestratorError::InternalError(
                "fork with volume mounts requires volume-aware child specs".to_string(),
            ));
        }
        let child_specs = (0..count)
            .map(|_| SandboxForkChildSpec {
                sandbox_id: SandboxId::new(),
                ..Default::default()
            })
            .collect();
        self.fork_sandbox_with_specs(source_sandbox_id, child_specs, new_timeout)
            .await
    }

    pub async fn fork_sandbox_with_specs(
        self: &Arc<Self>,
        source_sandbox_id: SandboxId,
        child_specs: Vec<SandboxForkChildSpec>,
        new_timeout: NewTimeout,
    ) -> Result<Vec<SandboxForkOutcome>> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("fork", source_sandbox_id, async move {
            this.fork_sandbox_inner(source_sandbox_id, child_specs, new_timeout)
                .await
        })
        .await
    }



    #[tracing::instrument(
        name = "fork_sandbox",
        skip(self, child_specs),
        fields(source_sandbox_id = %source_sandbox_id, count = child_specs.len())
    )]
    async fn fork_sandbox_inner(
        self: Arc<Self>,
        source_sandbox_id: SandboxId,
        child_specs: Vec<SandboxForkChildSpec>,
        new_timeout: NewTimeout,
    ) -> Result<Vec<SandboxForkOutcome>> {
        self.ensure_accepting_lifecycle_operations()?;

        let count = u32::try_from(child_specs.len())
            .map_err(|_| OrchestratorError::InternalError("too many fork children".to_string()))?;
        let mut child_ids = HashSet::with_capacity(child_specs.len());
        for child in &child_specs {
            if child.sandbox_id == source_sandbox_id || !child_ids.insert(child.sandbox_id) {
                return Err(OrchestratorError::InternalError(
                    "fork child sandbox IDs must be unique and differ from the source".to_string(),
                ));
            }
            if self.store.get(&child.sandbox_id).await?.is_some() {
                return Err(OrchestratorError::InternalError(format!(
                    "fork child sandbox {} already exists",
                    child.sandbox_id
                )));
            }
        }
        info!("forking sandboxes");

        let source_handle = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.get(&source_sandbox_id).cloned()
        }
        .ok_or(OrchestratorError::SandboxNotFound(source_sandbox_id))?;

        let source_metadata = self
            .store
            .update_if_state(&source_sandbox_id, &[SandboxState::Running], |metadata| {
                metadata.state = SandboxState::Forking
            })
            .await
            .map_err(|err| match err {
                StoreError::StateConflict { actual_state, .. } => match actual_state {
                    SandboxState::Killing => OrchestratorError::SandboxNotFound(source_sandbox_id),
                    _ => OrchestratorError::InvalidSandboxState {
                        sandbox_id: source_sandbox_id,
                        state: actual_state,
                    },
                },
                err => OrchestratorError::from(err),
            })?
            .previous;

        let backend_specs = child_specs
            .iter()
            .map(|child| SandboxForkSpec {
                sandbox_id: child.sandbox_id,
                envd_access_token: source_metadata
                    .secure
                    .then(|| self.access_tokens.generate(child.sandbox_id)),
                extra_drives: child.extra_drives.clone(),
                replace_drive_ids: child.replace_drive_ids.clone(),
            })
            .collect::<Vec<_>>();

        // Start to fork the sandbox.
        // This is a single operation that will return a list of results for each child sandbox.
        let fork_result = {
            let mut sandbox = source_handle.lock().await;
            sandbox.fork(&backend_specs).await
        };
        let forked_backends = match fork_result {
            Ok(forked_backends) => forked_backends,
            Err(err) => {
                warn!(error = ?err, "failed to fork sandbox");
                self.counters.record_create_fail(u64::from(count));
                if err.is_terminal() {
                    self.detach_sandbox_handle_and_route(&source_sandbox_id)
                        .await;
                    let _ = {
                        let mut sandbox = source_handle.lock().await;
                        sandbox.stop().await
                    };
                    self.finalize_terminal_volumes(&source_metadata).await;
                    self.store.remove(&source_sandbox_id).await?;
                } else {
                    let _ = self
                        .store
                        .update_state_if_state(
                            &source_sandbox_id,
                            SandboxState::Running,
                            &[SandboxState::Forking],
                        )
                        .await;
                }
                return Err(OrchestratorError::SandboxOperationFailed {
                    sandbox_id: source_sandbox_id,
                    operation: SandboxOperation::Fork,
                    source: err.into(),
                });
            }
        };

        // Restore the source sandbox's state to Running.
        if let Err(err) = self
            .store
            .update_state_if_state(
                &source_sandbox_id,
                SandboxState::Running,
                &[SandboxState::Forking],
            )
            .await
        {
            warn!(error = ?err, "failed to restore source sandbox metadata after fork");
        }

        // Register each forked sandbox in the store and runtime, and publish events.
        let mut outcomes = Vec::with_capacity(child_specs.len());
        let mut successes = 0u64;
        let now = SystemTime::now();
        for (child, backend) in child_specs.into_iter().zip(forked_backends) {
            let sandbox_id = child.sandbox_id;
            let backend = match backend {
                Ok(backend) => backend,
                Err(err) => {
                    warn!(%sandbox_id, error = ?err, "failed to start forked sandbox");
                    outcomes.push(Err(Self::fork_child_error(sandbox_id, err)));
                    continue;
                }
            };

            let mut metadata = source_metadata.clone();
            metadata.id = sandbox_id;
            metadata.state = SandboxState::Running;
            metadata.created_at = now;
            metadata.paused_state = None;
            metadata.volume_mounts = child.volume_mounts;
            metadata.update_timeout(new_timeout);

            let proxy_target = match Self::proxy_target_from_sandbox(backend.as_ref()) {
                Ok(proxy_target) => proxy_target,
                Err(err) => {
                    Self::stop_failed_fork(backend, sandbox_id).await;
                    outcomes.push(Err(Self::fork_child_error(
                        sandbox_id,
                        anyhow::Error::new(err),
                    )));
                    continue;
                }
            };
            if let Err(err) = self.store.add(metadata.clone()).await {
                warn!(%sandbox_id, error = ?err, "failed to register forked sandbox");
                Self::stop_failed_fork(backend, sandbox_id).await;
                outcomes.push(Err(Self::fork_child_error(
                    sandbox_id,
                    anyhow::Error::new(err),
                )));
                continue;
            }
            self.sandboxes
                .write()
                .await
                .insert(metadata.id, Arc::new(Mutex::new(backend)));
            self.upsert_proxy_route(metadata.id, proxy_target).await;
            self.publish_sandbox_event(
                SandboxLifecycleEventType::Fork,
                metadata.id,
                metadata.resources,
            );
            successes += 1;
            outcomes.push(Ok(metadata));
        }

        self.counters.record_create_success(successes);
        self.counters
            .record_create_fail(u64::from(count) - successes);
        Ok(outcomes)
    }


    fn fork_child_error(sandbox_id: SandboxId, source: anyhow::Error) -> OrchestratorError {
        OrchestratorError::SandboxOperationFailed {
            sandbox_id,
            operation: SandboxOperation::Fork,
            source,
        }
    }

    async fn stop_failed_fork(mut backend: Box<dyn SandboxBackend>, sandbox_id: SandboxId) {
        if let Err(err) = backend.stop().await {
            warn!(%sandbox_id, error = ?err, "failed to stop unsuccessful fork");
        }
    }

    /// Retrieves the metadata for a sandbox by its ID.
    #[tracing::instrument(skip(self), fields(sandbox_id = %sandbox_id))]
    pub async fn get_sandbox(&self, sandbox_id: &SandboxId) -> Result<Option<SandboxMetadata>> {
        Ok(self.store.get(sandbox_id).await?)
    }

    /// Lists all sandboxes with their metadata.
    #[tracing::instrument(skip(self))]
    pub async fn list_sandboxes(&self) -> Result<Vec<SandboxMetadata>> {
        self.list_sandboxes_filtered(SandboxListFilter::matches_all())
            .await
    }

    /// Lists all sandbox IDs currently tracked by the store.
    pub async fn list_sandbox_ids(&self) -> Result<Vec<SandboxId>> {
        // Reserve builder routing while its image is resolving and while the
        // final template is publishing, even when no VM is currently running.
        let mut ids: HashSet<_> = self.store.list_ids().await?.into_iter().collect();
        ids.extend(self.template_build_ids.read().await.iter().copied());
        Ok(ids.into_iter().collect())
    }

    pub(crate) async fn register_template_build(&self, id: SandboxId) {
        self.template_build_ids.write().await.insert(id);
    }

    pub(crate) async fn unregister_template_build(&self, id: SandboxId) {
        self.template_build_ids.write().await.remove(&id);
    }

    /// Lists sandboxes that match the provided filter criteria:
    /// - If `states` is provided, only sandboxes in those states will be included.
    /// - If `user_metadata` is provided, only sandboxes whose user metadata contains
    ///   all the specified key-value pairs will be included.
    /// - If `started_after` is provided, only sandboxes created at or after that instant
    ///   will be included.
    /// - If `template` is provided, only sandboxes using the matching snapshot ID or alias
    ///   will be included.
    #[tracing::instrument(skip(self, filter))]
    pub async fn list_sandboxes_filtered(
        &self,
        filter: SandboxListFilter,
    ) -> Result<Vec<SandboxMetadata>> {
        Ok(self
            .store
            .list_filtered(filter)
            .await?
            .into_iter()
            .filter(|metadata| !metadata.template_builder)
            .collect())
    }

    pub fn get_envd_access_token(&self, metadata: &SandboxMetadata) -> Option<EnvdAccessToken> {
        metadata
            .secure
            .then(|| self.access_tokens.generate(metadata.id))
    }

    pub fn validate_envd_access_token(&self, sandbox_id: SandboxId, candidate: &str) -> bool {
        self.access_tokens.matches(sandbox_id, candidate)
    }

    pub fn traffic_access_token(&self, sandbox_id: SandboxId) -> String {
        self.access_tokens.generate_traffic(sandbox_id)
    }

    pub fn validate_traffic_access_token(&self, sandbox_id: SandboxId, candidate: &str) -> bool {
        self.access_tokens.matches_traffic(sandbox_id, candidate)
    }

    /// Resolves the current proxyability of a sandbox without touching the sandbox mutex.
    #[tracing::instrument(skip(self), fields(sandbox_id = %sandbox_id))]
    pub async fn proxy_lookup_for(&self, sandbox_id: &SandboxId) -> Result<ProxyLookupResult> {
        if let Some(route) = self.proxy_routes.read().await.route(sandbox_id).cloned() {
            trace!(
                version = route.version(),
                "resolved running proxy target from runtime table"
            );
            return Ok(ProxyLookupResult::Ready(route.target().clone()));
        }

        let metadata = self.store.get(sandbox_id).await?;
        Ok(match metadata {
            None => {
                debug!("sandbox has no runtime route or persisted metadata");
                ProxyLookupResult::NotFound
            }
            Some(metadata) if metadata.state == SandboxState::Running => {
                warn!("running sandbox is missing a runtime proxy route");
                ProxyLookupResult::RouteMissing
            }
            Some(metadata) if metadata.state == SandboxState::Paused => {
                debug!(auto_resume = metadata.auto_resume, "sandbox is paused");
                ProxyLookupResult::Paused {
                    auto_resume: metadata.auto_resume,
                }
            }
            Some(metadata) => {
                debug!(state = ?metadata.state, "sandbox exists but is not proxyable");
                ProxyLookupResult::Unavailable(metadata.state)
            }
        })
    }

    /// Updates the keep-alive timeout for a RUNNING sandbox.
    /// If `timeout` is `None`, default timeout will be applied.
    /// If `allow_shorter` is `false`, the update will be skipped if the new TTL is not longer than the existing TTL.
    ///
    /// When the sandbox is in a transitional state that may resolve to `Running`,
    /// this method waits for the transition to complete before re-evaluating the state.
    #[tracing::instrument(skip(self), fields(sandbox_id = %sandbox_id, allow_shorter = allow_shorter))]
    pub async fn keep_alive_for(
        &self,
        sandbox_id: SandboxId,
        timeout: Option<Duration>,
        allow_shorter: bool,
    ) -> Result<Option<SandboxMetadata>> {
        self.ensure_accepting_lifecycle_operations()?;

        if timeout.is_none() {
            debug!("applying default timeout for keep-alive");
        } else {
            debug!(?timeout, "updating keep-alive timeout");
        }
        let valid_timeout = timeout.unwrap_or(self.default_sandbox_timeout);

        let mut metadata = match self.store.get(&sandbox_id).await? {
            Some(metadata) => metadata,
            None => return Err(OrchestratorError::SandboxNotFound(sandbox_id)),
        };

        // If the sandbox is in a transitional state that may lead to Running,
        // wait for the transition to complete before checking whether the
        // keep-alive is applicable.
        if matches!(
            metadata.state,
            SandboxState::Creating
                | SandboxState::Resuming
                | SandboxState::Snapshotting
                | SandboxState::Forking
        ) {
            debug!(state = ?metadata.state, "sandbox in transitional state, waiting before applying keep-alive");
            metadata = self.wait_for_transition(sandbox_id, metadata.state).await?;
        }

        if metadata.state != SandboxState::Running {
            info!(state = ?metadata.state, "cannot update keep-alive timeout in non-running state");
            return Err(OrchestratorError::InvalidSandboxState {
                sandbox_id,
                state: metadata.state,
            });
        }

        let mut timeout_updated = false;
        let update_result = self
            .store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                let new_expire_time = SystemTime::now().checked_add(valid_timeout);
                if !allow_shorter {
                    if let Some(current_expire) = metadata.expires_at {
                        if let Some(new_expire) = new_expire_time {
                            if new_expire <= current_expire {
                                info!(
                                    current_expire = ?current_expire,
                                    new_expire = ?new_expire,
                                    "new timeout is not longer than current timeout, skipping update",
                                );
                                return;
                            }
                        }
                    }
                }

                metadata.set_timeout(Some(valid_timeout));
                timeout_updated = true;
            })
            .await
            .map_err(|err| match err {
                StoreError::StateConflict { actual_state, .. } => {
                    info!(state = ?actual_state, "keep-alive update failed due to state conflict");
                    OrchestratorError::InvalidSandboxState {
                        sandbox_id,
                        state: actual_state,
                    }
                }
                other => OrchestratorError::from(other),
            })?;
        if timeout_updated {
            info!(?valid_timeout, "sandbox keep-alive timeout updated");
        }

        Ok(Some(update_result.current))
    }

    /// Stops and deletes the sandbox with the given ID.
    ///
    /// If the sandbox is currently in a transitional state, this method waits for
    /// the in-progress operation to finish before proceeding with deletion, preventing
    /// races where an ongoing operation might overwrite the `Killing` state.
    pub async fn delete_sandbox(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("delete", sandbox_id, async move {
            this.delete_sandbox_inner(sandbox_id).await
        })
        .await
    }

    async fn deletion_progress(&self, sandbox_id: SandboxId) -> Arc<Mutex<DeleteProgress>> {
        self.deletions
            .lock()
            .await
            .entry(sandbox_id)
            .or_default()
            .clone()
    }

    #[tracing::instrument(
        name = "delete_sandbox",
        skip(self),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn delete_sandbox_inner(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        info!("deleting sandbox");
        let deletion = self.deletion_progress(sandbox_id).await;
        let mut progress = deletion.lock().await;
        match *progress {
            DeleteProgress::Done => return Ok(()),
            DeleteProgress::Capture => {}
            _ => {
                return self
                    .delete_sandbox_impl(sandbox_id, SandboxState::Killing, &mut progress)
                    .await
            }
        }

        // Attempt to transition to Killing, retrying after waiting whenever we
        // find the sandbox in a transitional state.
        let previous_state = loop {
            match self
                .store
                .update_state_if_state(
                    &sandbox_id,
                    SandboxState::Killing,
                    &[SandboxState::Running, SandboxState::Paused],
                )
                .await
            {
                Ok(previous_state) => break previous_state,
                Err(StoreError::StateConflict { actual_state, .. }) => match actual_state {
                    SandboxState::Killing => {
                        debug!("sandbox already in killing state, waiting for delete to finish");
                        match self
                            .wait_for_transition(sandbox_id, SandboxState::Killing)
                            .await
                        {
                            Ok(_) => {
                                // The in-flight delete rolled back to a stable state.
                                // Retry the Killing CAS rather than letting multiple
                                // deleters run concurrently.
                                continue;
                            }
                            Err(OrchestratorError::SandboxNotFound(_)) => {
                                info!("sandbox was deleted by a concurrent delete");
                                return Ok(());
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    SandboxState::Creating
                    | SandboxState::Snapshotting
                    | SandboxState::Forking
                    | SandboxState::Pausing
                    | SandboxState::Resuming => {
                        // An in-progress operation is currently holding the sandbox in this
                        // transitional state.  Wait for it to finish so our Killing transition
                        // doesn't race with the final state write from that operation.
                        debug!(
                            state = ?actual_state,
                            "sandbox in transitional state, waiting before deletion"
                        );
                        match self.wait_for_transition(sandbox_id, actual_state).await {
                            Ok(_) => {
                                // Transition finished; retry the Killing CAS.
                                continue;
                            }
                            Err(OrchestratorError::SandboxNotFound(_)) => {
                                // Sandbox was removed while we waited (e.g. by
                                // another concurrent delete).
                                info!("sandbox was deleted while waiting for transitional state");
                                return Ok(());
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    _ => {
                        return Err(OrchestratorError::from(StoreError::StateConflict {
                            sandbox_id,
                            expected_states: vec![SandboxState::Running, SandboxState::Paused],
                            actual_state,
                        }));
                    }
                },
                Err(err) => {
                    if matches!(err, StoreError::SandboxNotFound { .. }) {
                        self.deletions.lock().await.remove(&sandbox_id);
                    }
                    return Err(OrchestratorError::from(err));
                }
            }
        };

        self.delete_sandbox_impl(sandbox_id, previous_state, &mut progress)
            .await
    }


    async fn claim_expired_running_sandbox(
        &self,
        sandbox_id: SandboxId,
        cutoff: SystemTime,
        claimed_state: SandboxState,
    ) -> Result<bool> {
        match self
            .store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                if metadata.is_expired(cutoff) {
                    metadata.state = claimed_state;
                }
            })
            .await
        {
            Ok(update) if update.current.state == claimed_state => Ok(true),
            Ok(update) => {
                debug!(
                    expires_at = ?update.current.expires_at,
                    ?cutoff,
                    "skipping auto-eviction because sandbox expiry was updated"
                );
                Ok(false)
            }
            Err(StoreError::StateConflict { actual_state, .. }) => {
                debug!(
                    state = ?actual_state,
                    "skipping auto-eviction because sandbox state changed"
                );
                Ok(false)
            }
            Err(StoreError::SandboxNotFound { .. }) => {
                debug!("skipping auto-eviction because sandbox no longer exists");
                Ok(false)
            }
            Err(err) => Err(OrchestratorError::from(err)),
        }
    }

    async fn delete_sandbox_impl(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        previous_state: SandboxState,
        progress: &mut DeleteProgress,
    ) -> Result<()> {
        let metadata = self.store.get(&sandbox_id).await?;
        let optional_cache = metadata
            .as_ref()
            .is_some_and(|record| record.template_builder);
        let volume_ids = metadata
            .map(|metadata| metadata.volume_mounts.into_values().collect::<Vec<_>>())
            .unwrap_or_default();
        let (handle, removed_route) = self.detach_sandbox_handle_and_route(&sandbox_id).await;
        let mut capture_error = None;

        if matches!(progress, DeleteProgress::Capture) {
            let mut volumes_frozen = false;
            let capture_result: std::result::Result<(), SandboxCaptureError> = async {
                if let Some(handle) = handle.as_ref() {
                    if previous_state == SandboxState::Running && !volume_ids.is_empty() {
                        handle.lock().await.freeze_and_snapshot_volumes().await?;
                        volumes_frozen = true;
                    }
                }
                self.publish_sandbox_volume_backings(sandbox_id, &volume_ids)
                    .await
                    .map_err(|error| SandboxCaptureError::recoverable(error.into()))
            }
            .await;
            if let Err(mut error) = capture_result {
                if volumes_frozen && !error.is_terminal() && !optional_cache {
                    if let Some(handle) = handle.as_ref() {
                        if let Err(thaw_error) = handle.lock().await.thaw_volumes().await {
                            error = SandboxCaptureError::terminal(anyhow::anyhow!(
                                "delete failed: {error}; thaw failed: {thaw_error:#}"
                            ));
                        }
                    }
                }
                // Builder caches are optional; still stop and release the worker on capture failure.
                if !error.is_terminal() && !optional_cache {
                    if let Some(handle) = handle {
                        self.sandboxes.write().await.insert(sandbox_id, handle);
                    }
                    self.restore_proxy_route(sandbox_id, removed_route).await;
                    self.store
                        .update_state_if_state(
                            &sandbox_id,
                            previous_state,
                            &[SandboxState::Killing],
                        )
                        .await?;
                    return Err(OrchestratorError::SandboxOperationFailed {
                        sandbox_id,
                        operation: SandboxOperation::Stop,
                        source: error.into(),
                    });
                }
                warn!(
                    ?error,
                    "volume capture failed; stopping sandbox and failing its volumes"
                );
                capture_error = Some(error);
            }
            *progress = DeleteProgress::Stop {
                capture_failed: capture_error.is_some(),
            };
        }

        let cleanup: anyhow::Result<()> = async {
            if let DeleteProgress::Stop { capture_failed } = *progress {
                if let Some(handle) = handle.as_ref() {
                    handle.lock().await.stop().await?;
                }
                *progress = DeleteProgress::Release { capture_failed };
            }
            if let DeleteProgress::Release { capture_failed } = *progress {
                if let Some(manager) = self.volume_manager.as_ref() {
                    let owner = sandbox_id.to_string();
                    // An incomplete restack may leave image.json pointing at old
                    // layers. Never publish that backing as a successful capture.
                    if capture_failed {
                        manager.fail_backings(&owner, &volume_ids).await?;
                    }
                    manager.replace_owner_for(&owner, None, &volume_ids).await?;
                }
                self.remove_deleted_sandbox(sandbox_id).await?;
                *progress = DeleteProgress::Done;
            }
            Ok(())
        }
        .await;
        if let Err(error) = cleanup {
            if matches!(progress, DeleteProgress::Stop { .. }) {
                if let Some(handle) = handle {
                    self.sandboxes.write().await.insert(sandbox_id, handle);
                }
            }
            warn!(?error, "sandbox deletion needs a cleanup retry");
            return Err(OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::Stop,
                source: error,
            });
        }
        if let Some(error) = capture_error.filter(|_| !optional_cache) {
            return Err(OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::Stop,
                source: error.into(),
            });
        }
        Ok(())
    }

    async fn remove_deleted_sandbox(&self, sandbox_id: SandboxId) -> Result<()> {
        let metadata = self.store.remove(&sandbox_id).await?;
        if let Some(metadata) = metadata {
            self.publish_sandbox_event(
                SandboxLifecycleEventType::Delete,
                metadata.id,
                metadata.resources,
            );
        }
        if let Err(err) = self
            .persister
            .delete_record_and_artifacts(&sandbox_id)
            .await
        {
            warn!(error = ?err, "failed to delete persisted sandbox state");
        }
        self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
            .await;
        self.deletions.lock().await.remove(&sandbox_id);
        info!("sandbox deleted");

        Ok(())
    }




    async fn idempotent_delete_entry(
        &self,
        metadata: &SandboxMetadata,
        previous_state: SandboxState,
    ) -> Result<Option<(String, Arc<CreateIdempotencyEntry>)>> {
        let Some(key) = metadata.create_idempotency_key.as_ref() else {
            return Ok(None);
        };
        let entry = self.create_idempotency.lock().await.get(key).cloned();
        let Some(entry) = entry else {
            self.rollback_delete_state(metadata.id, previous_state)
                .await?;
            return Err(OrchestratorError::InternalError(format!(
                "sandbox {} is missing create idempotency entry '{key}'",
                metadata.id
            )));
        };
        if entry.sandbox_id != metadata.id {
            self.rollback_delete_state(metadata.id, previous_state)
                .await?;
            return Err(OrchestratorError::InternalError(format!(
                "sandbox {} create idempotency entry '{key}' points to {}",
                metadata.id, entry.sandbox_id
            )));
        }
        Ok(Some((key.clone(), entry)))
    }


    async fn mark_create_entry_deleting(
        &self,
        sandbox_id: SandboxId,
        idempotent_delete: Option<&(String, Arc<CreateIdempotencyEntry>)>,
    ) -> Result<()> {
        let Some((key, entry)) = idempotent_delete else {
            return Ok(());
        };
        let entries = self.create_idempotency.lock().await;
        if !entries
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            return Err(OrchestratorError::InternalError(format!(
                "sandbox {sandbox_id} create idempotency entry '{key}' changed during delete"
            )));
        }
        let _ = entry.state.send_replace(CreateIdempotencyState::Deleting);
        Ok(())
    }


    async fn deleting_create_for_sandbox(
        &self,
        sandbox_id: SandboxId,
    ) -> Option<(String, Arc<CreateIdempotencyEntry>)> {
        self.create_idempotency
            .lock()
            .await
            .iter()
            .find(|(_, entry)| {
                entry.sandbox_id == sandbox_id
                    && matches!(&*entry.state.borrow(), CreateIdempotencyState::Deleting)
            })
            .map(|(key, entry)| (key.clone(), Arc::clone(entry)))
    }


    /// Stops every known sandbox and tears down in-memory runtime state.
    ///
    /// This is single-flight: the first caller performs cleanup and subsequent
    /// callers wait for the same outcome rather than starting duplicate work.
    ///
    /// Cleanup itself is still best-effort: the executor keeps attempting
    /// remaining sandboxes even if individual deletions fail, then returns an
    /// error if any sandbox could not be cleaned up after several passes.
    #[tracing::instrument(skip(self))]
    pub async fn shutdown(self: &Arc<Self>) -> Result<()> {
        let was_already_shutting_down = self.is_shutting_down.swap(true, Ordering::AcqRel);
        let _ = self.shutdown_tx.send_replace(true);

        if !was_already_shutting_down {
            info!("orchestrator shutdown requested; stopping all sandboxes");
        }

        let this = Arc::clone(self);
        let outcome = self
            .shutdown_outcome
            .get_or_init(|| async move {
                ShutdownOutcome::from_result(this.run_shutdown_cleanup().await)
            })
            .await;

        outcome.as_result()
    }

    /// Pauses a running sandbox by taking a snapshot and stopping its VM.
    ///
    /// If another `pause_sandbox` call is already in progress for the same
    /// sandbox (`Pausing` state), this call waits for it to complete and then
    /// returns the outcome rather than duplicating the work.
    pub async fn pause_sandbox(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("pause", sandbox_id, async move {
            this.pause_sandbox_inner(sandbox_id).await
        })
        .await
    }


    #[tracing::instrument(
        name = "pause_sandbox",
        skip(self),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn pause_sandbox_inner(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        self.preserve_sandbox(sandbox_id, None).await
    }

    // Both memory resume and disk-only cold boot use the same publication,
    // retention and stop proof. The caller owns maintenance admission.
    async fn preserve_sandbox(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        cold_boot_tools: Option<&str>,
    ) -> Result<()> {
        info!("pausing sandbox");
        match self.transition_to_pausing(sandbox_id).await? {
            PausePreparation::Owner => {}
            PausePreparation::Complete => return Ok(()),
        }
        self.preserve_claimed_sandbox(sandbox_id, cold_boot_tools)
            .await
    }

    async fn preserve_claimed_sandbox(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        cold_boot_tools: Option<&str>,
    ) -> Result<()> {
        self.protect_pause_artifacts(sandbox_id).await?;
        let artifact_root = self.allocate_pause_artifact_root(sandbox_id).await?;

        let (handle, removed_proxy_route) = self.detach_sandbox_handle_and_route(&sandbox_id).await;
        let handle = self.require_pause_handle(sandbox_id, handle).await?;
        let paused_state = self
            .pause_runtime(
                sandbox_id,
                &handle,
                removed_proxy_route.clone(),
                artifact_root.as_deref(),
                cold_boot_tools,
            )
            .await?;

        let persisted_metadata = {
            let mut metadata = self
                .store
                .get(&sandbox_id)
                .await?
                .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?;
            metadata.state = SandboxState::Paused;
            metadata.paused_state = Some(paused_state.clone());
            metadata.paused_runtime_stopped = false;
            if let Some(tools_version) = cold_boot_tools {
                metadata.runtime_versions.tools_drive_version = tools_version.to_owned();
            }
            metadata
        };
        if let Err(err) = self
            .persister
            .persist_paused(
                &persisted_metadata,
                artifact_root.as_deref(),
                paused_state.as_ref(),
            )
            .await
        {
            return self
                .recover_failed_pause_persistence(
                    sandbox_id,
                    &handle,
                    removed_proxy_route,
                    &persisted_metadata,
                    err,
                )
                .await;
        }
        let resources = persisted_metadata.resources;
        self.store.update(persisted_metadata).await?;
        if let Err(error) = self
            .stop_and_ack_paused_runtime(sandbox_id, &handle, Some(&paused_state))
            .await
        {
            self.sandboxes
                .write()
                .await
                .insert(sandbox_id, Arc::clone(&handle));
            return Err(error);
        }
        self.publish_sandbox_event(SandboxLifecycleEventType::Pause, sandbox_id, resources);
        info!("sandbox paused");

        Ok(())
    }

    async fn transition_to_pausing(&self, sandbox_id: SandboxId) -> Result<PausePreparation> {
        match self
            .store
            .update_state_if_state(&sandbox_id, SandboxState::Pausing, &[SandboxState::Running])
            .await
        {
            Ok(_) => Ok(PausePreparation::Owner),
            Err(StoreError::StateConflict { actual_state, .. }) => match actual_state {
                SandboxState::Pausing => {
                    self.join_concurrent_pause(sandbox_id).await?;
                    Ok(PausePreparation::Complete)
                }
                SandboxState::Paused => {
                    let metadata = self
                        .store
                        .get(&sandbox_id)
                        .await?
                        .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?;
                    Self::require_resume_recovery_resolved(&metadata)?;
                    Self::require_paused_stop_proof(&metadata)?;
                    Ok(PausePreparation::Complete)
                }
                SandboxState::Killing => {
                    info!("sandbox is being deleted while pausing");
                    Err(OrchestratorError::SandboxNotFound(sandbox_id))
                }
                state => {
                    info!(?state, "cannot pause sandbox in current state");
                    Err(OrchestratorError::InvalidSandboxState { sandbox_id, state })
                }
            },
            Err(error) => Err(OrchestratorError::from(error)),
        }
    }


    async fn allocate_pause_artifact_root(
        &self,
        sandbox_id: SandboxId,
    ) -> Result<Option<std::path::PathBuf>> {
        match self.persister.allocate_artifact_root(&sandbox_id).await {
            Ok(artifact_root) => Ok(artifact_root),
            Err(error) => {
                warn!(error = ?error, "failed to allocate paused sandbox artifact root");
                self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
                    .await;
                let _ = self
                    .store
                    .update_state_if_state(
                        &sandbox_id,
                        SandboxState::Running,
                        &[SandboxState::Pausing],
                    )
                    .await;
                Err(OrchestratorError::from(error))
            }
        }
    }


    async fn pause_runtime(
        &self,
        sandbox_id: SandboxId,
        handle: &SandboxHandle,
        removed_proxy_route: Option<ProxyRoute>,
        artifact_root: Option<&std::path::Path>,
        cold_boot_tools: Option<&str>,
    ) -> Result<Arc<dyn PausedSandboxState>> {
        let pause_result = if let Some(tools_version) = cold_boot_tools {
            let resources = self
                .store
                .get(&sandbox_id)
                .await?
                .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?
                .resources;
            match artifact_root {
                Some(root) => {
                    handle
                        .lock()
                        .await
                        .pause_for_cold_boot(root, tools_version, resources)
                        .await
                }
                None => Err(crate::sandbox::SandboxCaptureError::recoverable(
                    anyhow::anyhow!("retained-disk cold boot requires durable sandbox persistence"),
                )),
            }
        } else {
            handle.lock().await.pause(artifact_root).await
        };
        let error = match pause_result {
            Ok(paused_state) => return Ok(paused_state),
            Err(error) => error,
        };

        warn!(error = ?error, "failed to pause sandbox");
        if error.is_terminal() {
            // Retain ownership: dropping this handle kills Firecracker. An
            // ambiguous capture requires intervention, never destructive cleanup.
            self.retain_failed_pause(sandbox_id, handle).await?;
        } else {
            self.sandboxes
                .write()
                .await
                .insert(sandbox_id, Arc::clone(handle));
            if let Some(root) = artifact_root {
                if let Err(cleanup_error) = self
                    .persister
                    .discard_empty_capture(&sandbox_id, root)
                    .await
                {
                    warn!(error = %cleanup_error, "retaining failed capture directory after empty-directory cleanup failed");
                }
            }
            self.restore_proxy_route(sandbox_id, removed_proxy_route)
                .await;
            let _ = self
                .store
                .update_state_if_state(&sandbox_id, SandboxState::Running, &[SandboxState::Pausing])
                .await;
        }
        self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
            .await;
        Err(OrchestratorError::SandboxOperationFailed {
            sandbox_id,
            operation: SandboxOperation::Pause,
            source: error.into(),
        })
    }

    async fn recover_failed_pause_persistence(
        &self,
        sandbox_id: SandboxId,
        handle: &SandboxHandle,
        removed_proxy_route: Option<ProxyRoute>,
        persisted_metadata: &SandboxMetadata,
        error: SandboxPersistenceError,
    ) -> Result<()> {
        warn!(error = ?error, "failed to persist paused sandbox state");
        if error.is_uncertain_commit() {
            let mut recovery_metadata = persisted_metadata.clone();
            recovery_metadata.resume_recovery_pending = true;
            recovery_metadata.paused_runtime_stopped = false;
            if let Err(store_error) = self.store.update(recovery_metadata).await {
                warn!(error = ?store_error, "failed to mark uncertain paused sandbox recovery-pending");
            }
            self.sandboxes
                .write()
                .await
                .insert(sandbox_id, Arc::clone(handle));
            return Err(OrchestratorError::SandboxRecoveryRequired { sandbox_id });
        }

        let resume_result = handle.lock().await.resume().await;
        if let Err(resume_error) = resume_result {
            warn!(error = ?resume_error, "failed to resume sandbox after pause failure");
            self.retain_failed_pause(sandbox_id, handle).await?;
        } else {
            self.sandboxes
                .write()
                .await
                .insert(sandbox_id, Arc::clone(handle));
            self.restore_proxy_route(sandbox_id, removed_proxy_route)
                .await;
            let _ = self
                .store
                .update_state_if_state(&sandbox_id, SandboxState::Running, &[SandboxState::Pausing])
                .await;
        }
        self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
            .await;
        Err(OrchestratorError::InternalError(format!(
            "failed to persist paused sandbox state: {error:#}"
        )))
    }




    fn require_resume_recovery_resolved(metadata: &SandboxMetadata) -> Result<()> {
        if metadata.resume_recovery_pending {
            return Err(OrchestratorError::SandboxRecoveryRequired {
                sandbox_id: metadata.id,
            });
        }
        Ok(())
    }

    /// Resumes a paused sandbox from its snapshot.
    ///
    /// If another `resume_sandbox` call is already in progress (`Resuming`
    /// state), this call waits for the ongoing resume to finish and then
    /// returns the actual outcome (either `Running` or an error) rather than
    /// duplicating the work. On success the sandbox is ready for use when this
    /// method returns.
    pub async fn resume_sandbox(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<SandboxMetadata> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("resume", sandbox_id, async move {
            this.resume_sandbox_inner(sandbox_id, timeout).await
        })
        .await
    }

    #[tracing::instrument(
        name = "resume_sandbox",
        skip(self),
        fields(sandbox_id = %sandbox_id, timeout = ?timeout)
    )]
    async fn resume_sandbox_inner(
        self: Arc<Self>,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<SandboxMetadata> {
        self.ensure_accepting_lifecycle_operations()?;

        info!("resuming sandbox");
        let metadata = match self.prepare_resume(sandbox_id, timeout).await? {
            ResumePreparation::Paused(metadata) => metadata,
            ResumePreparation::Complete(metadata) => return Ok(metadata),
        };

        let prior_paused_stop_proof = metadata.paused_runtime_stopped;
        if let Some(metadata) = self.transition_to_resuming(sandbox_id, timeout).await? {
            return Ok(metadata);
        }
        self.mark_resume_started(sandbox_id, prior_paused_stop_proof)
            .await?;

        let paused_state = metadata.paused_state.as_ref().ok_or_else(|| {
            warn!("missing paused state while resuming");
            OrchestratorError::InternalError("missing paused state".to_string())
        })?;

        let resumed = self
            .launch_sandbox(LaunchPlan::for_resume(
                sandbox_id,
                Arc::clone(paused_state),
                timeout,
                metadata.resources,
                metadata
                    .secure
                    .then(|| self.access_tokens.generate(metadata.id)),
            ))
            .await;
        if let Ok(metadata) = resumed.as_ref() {
            self.release_image_refs(RuntimeImageOwner::PausedSandbox(sandbox_id))
                .await;
            self.publish_sandbox_event(
                SandboxLifecycleEventType::Resume,
                metadata.id,
                metadata.resources,
            );
        }
        resumed
    }

    async fn prepare_resume(
        &self,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<ResumePreparation> {
        let mut metadata = self
            .store
            .get(&sandbox_id)
            .await?
            .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?;
        if metadata.state == SandboxState::Resuming {
            metadata = self
                .wait_for_transition(sandbox_id, SandboxState::Resuming)
                .await?;
        }
        Self::require_resume_recovery_resolved(&metadata)?;
        match metadata.state {
            SandboxState::Killing => {
                return Err(OrchestratorError::SandboxNotFound(sandbox_id));
            }
            SandboxState::Running => {
                return Ok(ResumePreparation::Complete(
                    self.maybe_update_running_timeout(sandbox_id, timeout)
                        .await?,
                ));
            }
            SandboxState::Paused => {}
            state => {
                return Err(OrchestratorError::InvalidSandboxState { sandbox_id, state });
            }
        }
        Self::require_paused_stop_proof(&metadata)?;
        let node_mode = ConfigManager::global_config().virtualization_mode;
        if metadata.virtualization_mode != node_mode {
            return Err(OrchestratorError::VirtualizationModeMismatch {
                resource: format!("paused sandbox {sandbox_id}"),
                resource_mode: metadata.virtualization_mode,
                node_mode,
            });
        }
        Ok(ResumePreparation::Paused(metadata))
    }

    async fn transition_to_resuming(
        &self,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<Option<SandboxMetadata>> {
        match self
            .store
            .update_if_state(&sandbox_id, &[SandboxState::Paused], |metadata| {
                metadata.state = SandboxState::Resuming;
                metadata.paused_runtime_stopped = false;
            })
            .await
        {
            Ok(_) => Ok(None),
            Err(StoreError::StateConflict { actual_state, .. }) => match actual_state {
                SandboxState::Running => Ok(Some(
                    self.maybe_update_running_timeout(sandbox_id, timeout)
                        .await?,
                )),
                SandboxState::Resuming => Ok(Some(
                    self.join_concurrent_resume(sandbox_id, timeout).await?,
                )),
                SandboxState::Killing => {
                    info!("sandbox is being deleted while resuming");
                    Err(OrchestratorError::SandboxNotFound(sandbox_id))
                }
                state => {
                    info!(?state, "cannot resume sandbox in current state");
                    Err(OrchestratorError::InvalidSandboxState { sandbox_id, state })
                }
            },
            Err(error) => Err(OrchestratorError::from(error)),
        }
    }

    async fn mark_resume_started(
        &self,
        sandbox_id: SandboxId,
        prior_paused_stop_proof: bool,
    ) -> Result<()> {
        let Err(error) = self.persister.mark_resuming(&sandbox_id).await else {
            return Ok(());
        };
        warn!(error = ?error, "failed to mark persisted sandbox record as resuming");
        let uncertain_commit = error.is_uncertain_commit();
        let _ = self
            .store
            .update_if_state(&sandbox_id, &[SandboxState::Resuming], |metadata| {
                metadata.state = SandboxState::Paused;
                metadata.paused_runtime_stopped = prior_paused_stop_proof;
                metadata.resume_recovery_pending = uncertain_commit;
            })
            .await;
        if uncertain_commit {
            return Err(OrchestratorError::SandboxRecoveryRequired { sandbox_id });
        }
        Err(OrchestratorError::InternalError(format!(
            "failed to mark persisted sandbox record as resuming: {error:#}"
        )))
    }

    /// Captures a snapshot of a running sandbox.
    pub async fn capture_snapshot(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
    ) -> Result<SnapshotCaptureResult> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("snapshot", sandbox_id, async move {
            this.capture_snapshot_inner(sandbox_id).await
        })
        .await
    }

    async fn begin_snapshot_operation(&self, sandbox_id: SandboxId) -> Result<SandboxHandle> {
        self.ensure_accepting_lifecycle_operations()?;
        self.store
            .update_state_if_state(
                &sandbox_id,
                SandboxState::Snapshotting,
                &[SandboxState::Running],
            )
            .await
            .map_err(|error| match error {
                StoreError::StateConflict {
                    actual_state: SandboxState::Killing,
                    ..
                } => OrchestratorError::SandboxNotFound(sandbox_id),
                StoreError::StateConflict { actual_state, .. } => {
                    OrchestratorError::InvalidSandboxState {
                        sandbox_id,
                        state: actual_state,
                    }
                }
                error => OrchestratorError::from(error),
            })?;

        if let Some(handle) = self.sandboxes.read().await.get(&sandbox_id).cloned() {
            return Ok(handle);
        }
        warn!("sandbox handle not found while snapshotting, removing from store");
        self.detach_sandbox_handle_and_route(&sandbox_id).await;
        if let Some(metadata) = self.store.get(&sandbox_id).await? {
            self.finalize_terminal_volumes(&metadata).await;
        }
        self.store.remove(&sandbox_id).await?;
        Err(OrchestratorError::SandboxNotFound(sandbox_id))
    }


    async fn fail_snapshot_operation<T>(
        &self,
        sandbox_id: SandboxId,
        handle: &SandboxHandle,
        error: SandboxCaptureError,
        operation: SandboxOperation,
    ) -> Result<T> {
        warn!(?error, ?operation, "sandbox snapshot operation failed");
        if error.is_terminal() {
            self.detach_sandbox_handle_and_route(&sandbox_id).await;
            if let Err(stop_error) = handle.lock().await.stop().await {
                warn!(
                    ?stop_error,
                    ?operation,
                    "failed to stop sandbox after terminal snapshot failure"
                );
            }
            if let Some(metadata) = self.store.get(&sandbox_id).await? {
                self.finalize_terminal_volumes(&metadata).await;
            }
            self.store.remove(&sandbox_id).await?;
        } else {
            let _ = self
                .store
                .update_state_if_state(
                    &sandbox_id,
                    SandboxState::Running,
                    &[SandboxState::Snapshotting],
                )
                .await;
        }
        Err(OrchestratorError::SandboxOperationFailed {
            sandbox_id,
            operation,
            source: error.into(),
        })
    }

    async fn finish_snapshot_operation(&self, sandbox_id: SandboxId) -> Result<()> {
        self.store
            .update_state_if_state(
                &sandbox_id,
                SandboxState::Running,
                &[SandboxState::Snapshotting],
            )
            .await?;
        Ok(())
    }

    /// Seals writable persistent-volume uppers without capturing the VM's
    /// rootfs, memory, or device state so callers can clone them locally.
    pub async fn snapshot_volume_mounts(self: &Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("snapshot_volumes", sandbox_id, async move {
            this.snapshot_volume_mounts_inner(sandbox_id).await
        })
        .await
    }

    #[tracing::instrument(
        name = "snapshot_volume_mounts",
        skip(self),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn snapshot_volume_mounts_inner(self: Arc<Self>, sandbox_id: SandboxId) -> Result<()> {
        let handle = self.begin_snapshot_operation(sandbox_id).await?;
        if let Err(error) = {
            let mut sandbox = handle.lock().await;
            sandbox.snapshot_volumes().await
        } {
            return self
                .fail_snapshot_operation(
                    sandbox_id,
                    &handle,
                    error,
                    SandboxOperation::SnapshotVolumes,
                )
                .await;
        }
        self.finish_snapshot_operation(sandbox_id).await
    }

    #[tracing::instrument(
        name = "capture_snapshot",
        skip(self),
        fields(sandbox_id = %sandbox_id)
    )]
    async fn capture_snapshot_inner(
        self: Arc<Self>,
        sandbox_id: SandboxId,
    ) -> Result<SnapshotCaptureResult> {
        info!("capturing sandbox snapshot");
        let handle = self.begin_snapshot_operation(sandbox_id).await?;
        let result = {
            let mut sandbox = handle.lock().await;
            sandbox.snapshot().await
        };
        let captured_snapshot = match result {
            Ok(captured_snapshot) => captured_snapshot,
            Err(error) => {
                return self
                    .fail_snapshot_operation(sandbox_id, &handle, error, SandboxOperation::Snapshot)
                    .await;
            }
        };

        self.finish_snapshot_operation(sandbox_id).await?;
        let metadata = match self.store.get(&sandbox_id).await? {
            Some(metadata) => metadata,
            None => {
                warn!("sandbox disappeared after snapshotting");
                return Err(OrchestratorError::SandboxNotFound(sandbox_id));
            }
        };

        info!("snapshot captured");
        Ok(SnapshotCaptureResult {
            metadata,
            captured_snapshot,
        })
    }

    pub async fn replace_sandbox_network_policy(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        network_policy: SandboxNetworkPolicy,
    ) -> Result<()> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("update_network", sandbox_id, async move {
            this.replace_sandbox_network_policy_inner(sandbox_id, network_policy)
                .await
        })
        .await
    }

    #[tracing::instrument(
        name = "replace_sandbox_network_policy",
        skip(self, network_policy),
        fields(sandbox_id = %sandbox_id))
    ]
    async fn replace_sandbox_network_policy_inner(
        &self,
        sandbox_id: SandboxId,
        mut network_policy: SandboxNetworkPolicy,
    ) -> Result<()> {
        let metadata = self
            .store
            .get(&sandbox_id)
            .await?
            .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?;
        if metadata.state != SandboxState::Running {
            return Err(OrchestratorError::InvalidSandboxState {
                sandbox_id,
                state: metadata.state,
            });
        }
        network_policy.allow_public_traffic = metadata.network_policy.allow_public_traffic;

        let sandbox = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.get(&sandbox_id).cloned()
        }
        .ok_or_else(|| OrchestratorError::SandboxOperationConflict {
            sandbox_id,
            operation: SandboxOperation::UpdateNetwork,
        })?;

        let runtime_policy = network_policy.runtime_policy();

        let update_result = {
            let mut sandbox = sandbox.lock().await;
            sandbox.update_network_policy(runtime_policy).await
        };
        update_result.map_err(|source| OrchestratorError::SandboxOperationFailed {
            sandbox_id,
            operation: SandboxOperation::UpdateNetwork,
            source,
        })?;

        self.store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                metadata.network_policy = network_policy;
            })
            .await?;

        Ok(())
    }

    /// Patch the custom extension params of a running sandbox.
    ///
    /// The patch document is passed through verbatim to the custom
    /// extension's patch-params hook, which returns the updated full params.
    /// On hook failure the sandbox keeps its previous params and the
    /// metadata store is left untouched. Returns the new full params (`None`
    /// means empty params).
    pub async fn patch_sandbox_custom_extension_params(
        self: &Arc<Self>,
        sandbox_id: SandboxId,
        patch: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CustomExtensionParams>> {
        let this = Arc::clone(self);
        self.run_cancellation_safe("patch_custom_extension_params", sandbox_id, async move {
            this.patch_sandbox_custom_extension_params_inner(sandbox_id, patch)
                .await
        })
        .await
    }

    #[tracing::instrument(
        name = "patch_sandbox_custom_extension_params",
        skip(self, patch),
        fields(sandbox_id = %sandbox_id))
    ]
    async fn patch_sandbox_custom_extension_params_inner(
        &self,
        sandbox_id: SandboxId,
        patch: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<CustomExtensionParams>> {
        let metadata = self
            .store
            .get(&sandbox_id)
            .await?
            .ok_or(OrchestratorError::SandboxNotFound(sandbox_id))?;
        if metadata.state != SandboxState::Running {
            return Err(OrchestratorError::InvalidSandboxState {
                sandbox_id,
                state: metadata.state,
            });
        }

        let sandbox = {
            let sandboxes = self.sandboxes.read().await;
            sandboxes.get(&sandbox_id).cloned()
        }
        .ok_or_else(|| OrchestratorError::SandboxOperationConflict {
            sandbox_id,
            operation: SandboxOperation::PatchCustomExtensionParams,
        })?;

        // Invoke the extension's patch-params hook here (the backend only
        // stores the approved value). The sandbox lock is not held during
        // the hook call so pause/stop are not blocked on extension latency.
        let client = CustomExtensionClient::global().ok_or_else(|| {
            OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::PatchCustomExtensionParams,
                source: anyhow::anyhow!(
                    "custom extension is not configured ([custom_extension].url is unset)"
                ),
            }
        })?;
        let new_params = client
            .hook_patch_params(sandbox_id, patch)
            .await
            .map_err(|source| OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::PatchCustomExtensionParams,
                source,
            })?;

        {
            let mut sandbox = sandbox.lock().await;
            sandbox.update_custom_extension_params(new_params.clone());
        }

        // NOTE: a concurrent pause may have transitioned the sandbox since the entry check,
        // so this may fail. But it's acceptable since extension state should be transient like network policy
        self.store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                metadata.custom_extension_params = new_params.clone();
            })
            .await
            .map_err(|err| match err {
                // Lost a race against a concurrent state transition (e.g.
                // pause): report it as a conflict instead of a 500.
                StoreError::StateConflict {
                    sandbox_id,
                    actual_state,
                    ..
                } => OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: actual_state,
                },
                other => OrchestratorError::from(other),
            })?;

        Ok(new_params)
    }

    /// Returns the current orchestrator metrics snapshot.
    ///
    /// Counter fields are read atomically; resource fields are aggregated by
    /// scanning the metadata store, so the returned snapshot is always
    /// consistent with the orchestrator's current set of sandboxes.
    pub async fn metrics_snapshot(&self) -> Result<OrchestratorMetrics> {
        let mut metrics = OrchestratorMetrics::default();
        let owned: std::collections::HashSet<_> =
            self.sandboxes.read().await.keys().copied().collect();
        self.store
            .list_with_callback(|metadata| {
                aggregate_resource_metrics(
                    &mut metrics,
                    SandboxContribution::new(
                        if metadata.state == SandboxState::Paused && owned.contains(&metadata.id) {
                            // An unproven/failed stop still owns VM resources.
                            SandboxState::Pausing
                        } else {
                            metadata.state
                        },
                        metadata.resources,
                    ),
                );
            })
            .await?;
        metrics.create_successes = self.counters.create_successes();
        metrics.create_fails = self.counters.create_fails();
        Ok(metrics)
    }

    pub fn subscribe_sandbox_events(&self) -> broadcast::Receiver<SandboxLifecycleEvent> {
        self.sandbox_event_tx.subscribe()
    }

    fn publish_sandbox_event(
        &self,
        event_type: SandboxLifecycleEventType,
        sandbox_id: SandboxId,
        resources: SandboxResources,
    ) {
        let event = SandboxLifecycleEvent {
            event_type,
            sandbox_id,
            resources,
        };
        let _ = self.sandbox_event_tx.send(event);
    }

    /// Waits for `sandbox_id` to leave `transitional_state`, then returns the
    /// resulting metadata. Returns `SandboxNotFound` if the sandbox is removed
    /// while waiting, or `InvalidSandboxState` if the sandbox is still in the
    /// transitional state after the [`WAIT_TRANSITION_TIMEOUT`] elapses.
    pub(crate) async fn wait_for_transition(
        &self,
        sandbox_id: SandboxId,
        transitional_state: SandboxState,
    ) -> Result<SandboxMetadata> {
        let states = [transitional_state];
        let wait = self.store.wait_while_in_states(&sandbox_id, &states);
        match tokio::time::timeout(WAIT_TRANSITION_TIMEOUT, wait).await {
            Ok(Ok(Some(m))) => Ok(m),
            Ok(Ok(None)) => Err(OrchestratorError::SandboxNotFound(sandbox_id)),
            Ok(Err(e)) => Err(OrchestratorError::from(e)),
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    state = ?transitional_state,
                    "timed out waiting for sandbox to leave transitional state"
                );
                Err(OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: transitional_state,
                })
            }
        }
    }

    /// Applies `timeout` to `metadata` and persists the change if the sandbox
    /// is still `Running`. Returns the updated metadata. If `timeout` is `None`,
    /// the timeout will be cleared, which indicates no expiration.
    async fn maybe_update_running_timeout(
        &self,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<SandboxMetadata> {
        let update_result = self
            .store
            .update_if_state(&sandbox_id, &[SandboxState::Running], |metadata| {
                metadata.update_timeout(timeout);
            })
            .await
            .map_err(|err| match err {
                StoreError::StateConflict { actual_state, .. } => {
                    info!(state = ?actual_state, "cannot update timeout for sandbox in current state");
                    OrchestratorError::InvalidSandboxState {
                        sandbox_id,
                        state: actual_state,
                    }
                }
                other => OrchestratorError::from(other),
            })?;
        Ok(update_result.current)
    }

    /// Joins a concurrent pause already in progress for the same sandbox.
    /// Waits for the `Pausing` state to resolve and maps the final state to
    /// the appropriate `Ok(())` / `Err(...)` result.
    async fn join_concurrent_pause(&self, sandbox_id: SandboxId) -> Result<()> {
        debug!("concurrent pause in progress, waiting for completion");
        let m = self
            .wait_for_transition(sandbox_id, SandboxState::Pausing)
            .await?;
        match m.state {
            SandboxState::Paused => {
                debug!("concurrent pause succeeded");
                Self::require_paused_stop_proof(&m)
            }
            SandboxState::Running => {
                info!("concurrent pause failed; sandbox returned to running state");
                Err(OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: SandboxState::Running,
                })
            }
            SandboxState::Killing => {
                info!("sandbox is being deleted after concurrent pause attempt");
                Err(OrchestratorError::SandboxNotFound(sandbox_id))
            }
            other => {
                info!(state = ?other, "unexpected state after waiting for concurrent pause");
                Err(OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: other,
                })
            }
        }
    }

    /// Joins a concurrent resume already in progress for the same sandbox.
    /// Waits for the `Resuming` state to resolve, then applies `timeout` if
    /// the sandbox reached `Running`, and returns the final metadata.
    async fn join_concurrent_resume(
        &self,
        sandbox_id: SandboxId,
        timeout: NewTimeout,
    ) -> Result<SandboxMetadata> {
        debug!("concurrent resume in progress, waiting for completion");
        let m = self
            .wait_for_transition(sandbox_id, SandboxState::Resuming)
            .await?;
        match m.state {
            SandboxState::Running => self.maybe_update_running_timeout(sandbox_id, timeout).await,
            SandboxState::Paused => {
                info!("concurrent resume failed; sandbox returned to paused state");
                Err(OrchestratorError::InvalidSandboxState {
                    sandbox_id,
                    state: SandboxState::Paused,
                })
            }
            SandboxState::Killing => {
                info!("sandbox is being deleted while resuming");
                Err(OrchestratorError::SandboxNotFound(sandbox_id))
            }
            state => {
                info!(state = ?state, "unexpected state after waiting for concurrent resume");
                Err(OrchestratorError::InvalidSandboxState { sandbox_id, state })
            }
        }
    }

    /// Automatically pauses or stops sandboxes whose timeout has expired.
    async fn evict_expired_sandboxes(self: &Arc<Self>) -> Result<Vec<SandboxId>> {
        if self.is_shutting_down() {
            debug!("skipping auto-evict because orchestrator is shutting down");
            return Ok(Vec::new());
        }

        let eviction_cutoff = SystemTime::now();
        let expired = self.store.list_expired(eviction_cutoff).await?;
        let mut evicted_ids = Vec::new();

        for metadata in expired {
            if metadata.state != SandboxState::Running {
                continue;
            }
            let this = Arc::clone(self);
            let result = self
                .run_cancellation_safe("evict", metadata.id, async move {
                    let claimed_state = match metadata.timeout_action {
                        SandboxTimeoutAction::Pause => SandboxState::Pausing,
                        SandboxTimeoutAction::Delete => SandboxState::Killing,
                    };
                    // Use the same operation lock as explicit deletion before claiming Killing.
                    let deletion = this.deletion_progress(metadata.id).await;
                    let mut progress = deletion.lock().await;
                    match this
                        .claim_expired_running_sandbox(metadata.id, eviction_cutoff, claimed_state)
                        .await
                    {
                        Ok(true) => match metadata.timeout_action {
                            SandboxTimeoutAction::Pause => {
                                this.preserve_claimed_sandbox(metadata.id, None).await
                            }
                            SandboxTimeoutAction::Delete => {
                                this.delete_sandbox_impl(
                                    metadata.id,
                                    SandboxState::Running,
                                    &mut progress,
                                )
                                .await
                            }
                        }
                        .map(|_| true),
                        Ok(false) => Ok(false),
                        Err(err) => Err(err),
                    }
                })
                .await;
            match result {
                Ok(true) => evicted_ids.push(metadata.id),
                Ok(false) => continue,
                Err(err) => warn!(
                    sandbox_id = %metadata.id,
                    action = ?metadata.timeout_action,
                    error = ?err,
                    "failed to auto-evict expired sandbox"
                ),
            }
        }

        Ok(evicted_ids)
    }

    /// Starts a background task that periodically evicts expired sandboxes.
    /// The eviction policy is defined by the sandbox's [`timeout_action`](SandboxMetadata::timeout_action).
    fn start_auto_evict_task(
        this: Arc<Self>,
        evict_interval: Duration,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let Ok(runtime_handle) = tokio::runtime::Handle::try_current() else {
            warn!("auto-evict task not started: no Tokio runtime available");
            return;
        };

        let this = Arc::downgrade(&this);
        runtime_handle.spawn(async move {
            let mut ticker = tokio::time::interval(evict_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            debug!("auto-evict task started with interval {:?}", evict_interval);

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            debug!("auto-evict task stopping because orchestrator is shutting down");
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let Some(this) = this.upgrade() else {
                            debug!("auto-evict task stopping because orchestrator was dropped");
                            break;
                        };
                        if let Err(err) = this.evict_expired_sandboxes().await {
                            warn!("auto-evict task failed: {err}");
                        }
                    }
                }
            }
        });
    }

    /// Starts a background task that periodically runs local image maintenance
    /// (capacity eviction + fail-closed GC) over the current running set.
    fn start_local_image_maintenance_task(
        this: Arc<Self>,
        interval: Duration,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let Ok(runtime_handle) = tokio::runtime::Handle::try_current() else {
            warn!("local image maintenance task not started: no Tokio runtime available");
            return;
        };

        let this = Arc::downgrade(&this);
        runtime_handle.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            info!(interval = ?interval, "local image maintenance task started");

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            debug!("local image maintenance task stopping because orchestrator is shutting down");
                            break;
                        }
                    }
                    _ = ticker.tick() => {
                        let Some(this) = this.upgrade() else {
                            debug!("local image maintenance task stopping because orchestrator was dropped");
                            break;
                        };

                        let running = this.collect_running_artifacts().await;
                        if let Err(err) = this.image_refs.maintain_running(running).await {
                            warn!("local image maintenance pass failed: {err:#}");
                        }
                    }
                }
            }
        });
    }


    #[tracing::instrument(skip(self, plan))]
    async fn launch_sandbox(self: &Arc<Self>, plan: LaunchPlan) -> Result<SandboxMetadata> {
        self.ensure_accepting_lifecycle_operations()?;

        let sandbox_id = plan.sandbox_id();
        let transitional_state = plan.transitional_state();

        // Build and start the sandbox first, before making any state changes, so that we don't
        // have to roll back any persisted state if the build fails.
        // Meanwhile, the start process can be overlapped with the initial state persistence.
        let mut sandbox = match self.build_sandbox(&plan) {
            Ok(sandbox) => sandbox,
            Err(err) => {
                self.rollback_failed_launch_metadata(&plan, transitional_state)
                    .await;
                return Err(err);
            }
        };

        // Protect artifacts before the backend opens them.
        let startup_artifacts = sandbox.startup_artifacts();
        if let Err(err) = self
            .protect_image_refs(
                RuntimeImageOwner::StartingSandbox(sandbox_id),
                startup_artifacts,
                "starting sandbox",
            )
            .await
        {
            warn!(error = %format_args!("{err:#}"), "failed to protect starting runtime artifacts");
            self.rollback_failed_launch_metadata(&plan, transitional_state)
                .await;
            return Err(err);
        }
        if let Err(source) = sandbox.start_nowait().await {
            warn!(error = %format_args!("{source:#}"), "failed to start sandbox");
            if let Err(stop_err) = sandbox.stop().await {
                warn!(error = %format_args!("{stop_err:#}"), "failed to stop sandbox after start failure");
            }
            self.rollback_failed_launch_metadata(&plan, transitional_state)
                .await;
            return Err(OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::Start,
                source,
            });
        }
        debug!("sandbox start requested");

        // If the orchestrator started shutting down, stop here before we persist any state.
        if self.is_shutting_down() {
            info!("orchestrator started shutting down just after starting the sandbox");
            if let Err(err) = sandbox.stop().await {
                warn!(error = %format_args!("{err:#}"), "failed to stop sandbox");
            }
            self.rollback_failed_launch_metadata(&plan, transitional_state)
                .await;
            return Err(OrchestratorError::ShuttingDown);
        }

        let runtime_resources =
            resources_with_runtime_info(plan.resources(), sandbox.runtime_info());
        let transitional_metadata = plan.transitional_metadata().map(|metadata| {
            let mut metadata = metadata.clone();
            metadata.resources = runtime_resources;
            metadata
        });

        // Store the sandbox handle in memory.
        let handle = Arc::new(Mutex::new(sandbox));
        self.sandboxes
            .write()
            .await
            .insert(sandbox_id, handle.clone());

        self.release_image_refs(RuntimeImageOwner::StartingSandbox(sandbox_id))
            .await;

        // Persist the sandbox metadata if needed (during creation).
        if let Some(metadata) = transitional_metadata.as_ref() {
            if let Err(err) = self.store.add(metadata.clone()).await {
                warn!(error = %format_args!("{err:#}"), "failed to persist sandbox metadata; cleaning up");
                self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::Registered)
                    .await;
                return Err(OrchestratorError::from(err));
            }
        }

        // Check for shutdown again before we wait for the sandbox to become ready.
        if self.is_shutting_down() {
            info!("orchestrator started shutting down before sandbox became ready");
            self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::TransitionalPersisted)
                .await;
            return Err(OrchestratorError::ShuttingDown);
        }

        // Wait for the sandbox to be ready
        let wait_result = {
            let sandbox = handle.lock().await;
            sandbox.wait_for_ready().await
        };
        if let Err(source) = wait_result {
            warn!(error = %format_args!("{source:#}"), "sandbox failed to become ready");
            self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::TransitionalPersisted)
                .await;
            return Err(OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::WaitReady,
                source,
            });
        }

        // Check for shutdown again before we persist the final state and publish the proxy route.
        if self.is_shutting_down() {
            info!("orchestrator started shutting down while sandbox was becoming ready");
            self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::TransitionalPersisted)
                .await;
            return Err(OrchestratorError::ShuttingDown);
        }

        let launch_timeout = plan.timeout();
        let final_metadata = match self
            .store
            .update_if_state(
                &sandbox_id,
                std::slice::from_ref(&transitional_state),
                move |metadata| {
                    metadata.resources = runtime_resources;
                    metadata.state = SandboxState::Running;
                    metadata.update_timeout(launch_timeout);
                },
            )
            .await
        {
            Ok(update) => update.current,
            Err(err) => {
                warn!(error = %format_args!("{err:#}"), "failed to persist final sandbox metadata after launch");
                self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::TransitionalPersisted)
                    .await;
                return Err(OrchestratorError::from(err));
            }
        };

        let proxy_target = {
            let sandbox = handle.lock().await;
            match Self::proxy_target_from_sandbox(sandbox.as_ref()) {
                Ok(proxy_target) => proxy_target,
                Err(err) => {
                    warn!(error = %format_args!("{err:#}"), "sandbox became ready without a proxy target; rolling back launch");
                    drop(sandbox);
                    self.cleanup_failed_launch(&plan, handle, FailedLaunchStage::RunningPersisted)
                        .await;
                    return Err(err);
                }
            }
        };
        if !self
            .upsert_proxy_route_if_current_handle(sandbox_id, &handle, proxy_target)
            .await
        {
            debug!("skipping runtime proxy route publication because sandbox handle is stale");
        }

        if matches!(plan, LaunchPlan::Resume(_)) {
            if let Err(err) = self.persister.delete_record(&sandbox_id).await {
                warn!(error = %format_args!("{err:#}"), "failed to delete persisted sandbox record after resume");
            }
        }

        info!("sandbox launch completed");
        Ok(final_metadata)
    }

    async fn build_and_start_sandbox(
        &self,
        plan: &LaunchPlan,
        transitional_state: SandboxState,
    ) -> Result<Box<dyn SandboxBackend>> {
        let sandbox_id = plan.sandbox_id();
        let mut sandbox = match self.build_sandbox(plan) {
            Ok(sandbox) => sandbox,
            Err(error) => {
                self.rollback_failed_launch_metadata(plan, transitional_state, true)
                    .await;
                return Err(error);
            }
        };
        if let Err(error) = self
            .protect_image_refs(
                RuntimeImageOwner::StartingSandbox(sandbox_id),
                sandbox.startup_artifacts(),
                "starting sandbox",
            )
            .await
        {
            warn!(error = %format_args!("{error:#}"), "failed to protect starting runtime artifacts");
            self.rollback_failed_launch_metadata(plan, transitional_state, true)
                .await;
            return Err(error);
        }
        if let Err(source) = sandbox.start_nowait().await {
            warn!(error = %format_args!("{source:#}"), "failed to start sandbox");
            let runtime_absence_proven = self.stop_unregistered_sandbox(plan, sandbox).await;
            self.rollback_failed_launch_metadata(plan, transitional_state, runtime_absence_proven)
                .await;
            return Err(OrchestratorError::SandboxOperationFailed {
                sandbox_id,
                operation: SandboxOperation::Start,
                source,
            });
        }
        debug!("sandbox start requested");
        if self.is_shutting_down() {
            info!("orchestrator started shutting down just after starting the sandbox");
            let runtime_absence_proven = self.stop_unregistered_sandbox(plan, sandbox).await;
            self.rollback_failed_launch_metadata(plan, transitional_state, runtime_absence_proven)
                .await;
            return Err(OrchestratorError::ShuttingDown);
        }
        Ok(sandbox)
    }






    fn build_sandbox(&self, plan: &LaunchPlan) -> Result<Box<dyn SandboxBackend>> {
        let build_result = match plan {
            LaunchPlan::Create(plan) => match &plan.source {
                CreateLaunchSource::Snapshot { snapshot } => self
                    .factory
                    .build_from_snapshot(snapshot, plan.launch_config.clone()),
                CreateLaunchSource::Fresh { build_spec } => self
                    .factory
                    .build((**build_spec).clone(), plan.launch_config.clone()),
            },
            LaunchPlan::Resume(plan) => self.factory.build_from_paused_state(
                plan.sandbox_id,
                plan.paused_state.as_ref(),
                plan.envd_access_token.clone(),
            ),
        };
        build_result.map_err(|source| {
            warn!(error = %format_args!("{source:#}"), "failed to build sandbox");
            OrchestratorError::SandboxOperationFailed {
                sandbox_id: plan.sandbox_id(),
                operation: SandboxOperation::Build,
                source,
            }
        })
    }

    async fn cleanup_failed_launch(
        &self,
        plan: &LaunchPlan,
        handle: SandboxHandle,
        stage: FailedLaunchStage,
    ) {
        let should_rollback_shared_state = self
            .detach_launch_runtime_if_current(
                &plan.sandbox_id(),
                &handle,
                stage.should_detach_proxy_route(),
                stage,
            )
            .await;

        // Stop the sandbox.
        let stop_result = {
            let mut sandbox = handle.lock().await;
            sandbox.stop().await
        };
        if let Err(err) = stop_result {
            warn!(error = %format_args!("{err:#}"), "failed to stop sandbox while rolling back launch");
        }

        if !should_rollback_shared_state {
            return;
        }

        if let Some(expected_state) = stage.rollback_expected_state(plan) {
            self.rollback_failed_launch_metadata(plan, expected_state)
                .await;
        }
    }

    async fn rollback_failed_launch_metadata(
        &self,
        plan: &LaunchPlan,
        expected_state: SandboxState,
    ) {
        self.release_image_refs(RuntimeImageOwner::StartingSandbox(plan.sandbox_id()))
            .await;
        match plan {
            LaunchPlan::Create(_) => {
                if let Err(err) = self.store.remove(&plan.sandbox_id()).await {
                    warn!(error = %format_args!("{err:#}"), "failed to remove sandbox metadata during launch rollback");
                }
            }
            LaunchPlan::Resume(_) => {
                if let Err(err) = self
                    .store
                    .update_state_if_state(
                        &plan.sandbox_id(),
                        SandboxState::Paused,
                        std::slice::from_ref(&expected_state),
                    )
                    .await
                {
                    warn!(error = %format_args!("{err:#}"), "failed to restore sandbox metadata during launch rollback");
                }
                if let Err(err) = self.persister.rollback_resuming(&plan.sandbox_id()).await {
                    warn!(error = %format_args!("{err:#}"), "failed to restore persisted sandbox record lifecycle during launch rollback");
                }
            }
        }
    }


    async fn detach_launch_runtime_if_current(
        &self,
        sandbox_id: &SandboxId,
        handle: &SandboxHandle,
        detach_proxy_route: bool,
        stage: FailedLaunchStage,
    ) -> bool {
        let mut sandboxes = self.sandboxes.write().await;
        let Some(current_handle) = sandboxes.get(sandbox_id) else {
            return true;
        };

        if !Arc::ptr_eq(current_handle, handle) {
            warn!(
                stage = ?stage,
                "sandbox handle was replaced during failed launch cleanup; skipping shared state rollback"
            );
            return false;
        }

        sandboxes.remove(sandbox_id);

        if detach_proxy_route {
            let removed_route = self.proxy_routes.write().await.remove(sandbox_id);
            if let Some(route) = removed_route.as_ref() {
                debug!(version = route.version(), "removed runtime proxy route");
            }
        }

        drop(sandboxes);
        true
    }

    fn proxy_target_from_sandbox(sandbox: &dyn SandboxBackend) -> Result<ProxyTarget> {
        sandbox
            .host_interaction_ip()
            .map(ProxyTarget::new)
            .ok_or_else(|| {
                warn!("sandbox started without an interaction IP");
                OrchestratorError::InternalError(
                    "sandbox missing host interaction IP after start".to_string(),
                )
            })
    }

    async fn upsert_proxy_route(&self, sandbox_id: SandboxId, target: ProxyTarget) {
        let version = self
            .next_proxy_route_version
            .fetch_add(1, Ordering::Relaxed);
        let route = self
            .proxy_routes
            .write()
            .await
            .upsert(sandbox_id, target, version);
        debug!(
            version = route.version(),
            updated_at = ?route.updated_at(),
            host_interaction_ip = %route.target().ip,
            "updated runtime proxy route"
        );
    }

    async fn upsert_proxy_route_if_current_handle(
        &self,
        sandbox_id: SandboxId,
        handle: &SandboxHandle,
        target: ProxyTarget,
    ) -> bool {
        // Keep the lock order aligned with detach_sandbox_handle_and_route:
        // sandboxes first, then proxy_routes.
        let sandboxes = self.sandboxes.write().await;
        let Some(current_handle) = sandboxes.get(&sandbox_id) else {
            return false;
        };

        if !Arc::ptr_eq(current_handle, handle) {
            return false;
        }

        let version = self
            .next_proxy_route_version
            .fetch_add(1, Ordering::Relaxed);
        let route = self
            .proxy_routes
            .write()
            .await
            .upsert(sandbox_id, target, version);
        drop(sandboxes);

        debug!(
            version = route.version(),
            updated_at = ?route.updated_at(),
            host_interaction_ip = %route.target().ip,
            "updated runtime proxy route"
        );
        true
    }

    async fn restore_proxy_route(&self, sandbox_id: SandboxId, route: Option<ProxyRoute>) {
        let Some(route) = route else {
            return;
        };
        self.upsert_proxy_route(sandbox_id, route.target().clone())
            .await;
    }

    async fn detach_sandbox_handle_and_route(
        &self,
        sandbox_id: &SandboxId,
    ) -> (Option<SandboxHandle>, Option<ProxyRoute>) {
        // Keep the lock order aligned with upsert_proxy_route_if_current_handle:
        // sandboxes first, then proxy_routes.
        let mut sandboxes = self.sandboxes.write().await;
        let handle = sandboxes.remove(sandbox_id);

        let removed_route = self.proxy_routes.write().await.remove(sandbox_id);
        if let Some(route) = removed_route.as_ref() {
            debug!(version = route.version(), "removed runtime proxy route");
        }

        drop(sandboxes);
        (handle, removed_route)
    }


    async fn run_shutdown_cleanup(self: &Arc<Self>) -> Result<()> {
        const MAX_SHUTDOWN_PASSES: usize = 3;
        let mut last_failures = Vec::new();

        // Preserve recoverable sandboxes by pausing running VMs before process exit.
        for pass in 1..=MAX_SHUTDOWN_PASSES {
            let sandboxes = self
                .store
                .list_filtered(SandboxListFilter {
                    excluded_states: Some(vec![SandboxState::Paused]),
                    ..SandboxListFilter::matches_all()
                })
                .await?;
            if sandboxes.is_empty() {
                break;
            }
            last_failures.clear();

            info!(
                pass,
                remaining = sandboxes.len(),
                "preserving sandboxes during shutdown"
            );

            for metadata in sandboxes {
                let sandbox_id = metadata.id;
                match metadata.state {
                    SandboxState::Paused => {
                        unreachable!("paused sandboxes should have been filtered out")
                    }
                    SandboxState::Running => {
                        let result = if metadata.template_builder {
                            self.delete_sandbox_inner(sandbox_id).await
                        } else {
                            self.pause_sandbox_inner(sandbox_id).await
                        };
                        if let Err(err) = result {
                            last_failures.push(format!("{sandbox_id}: {err}"));
                        }
                    }
                    SandboxState::Creating
                    | SandboxState::Snapshotting
                    | SandboxState::Forking
                    | SandboxState::Pausing
                    | SandboxState::Resuming
                    | SandboxState::Killing => {
                        match self.wait_for_transition(sandbox_id, metadata.state).await {
                            Ok(_) | Err(OrchestratorError::SandboxNotFound(_)) => {}
                            Err(err) => {
                                warn!(
                                    sandbox_id = %sandbox_id,
                                    error = ?err,
                                    pass,
                                    "failed to wait for sandbox transition during orchestrator shutdown"
                                );
                                last_failures.push(format!("{sandbox_id}: {err}"));
                            }
                        }
                    }
                }
            }

            if last_failures.is_empty() {
                continue;
            }

            warn!(
                pass,
                failures = last_failures.len(),
                max_passes = MAX_SHUTDOWN_PASSES,
                "shutdown preservation pass completed with failures"
            );
        }

        if !last_failures.is_empty() {
            return Err(OrchestratorError::InternalError(format!(
                "failed to preserve all sandboxes during shutdown after {MAX_SHUTDOWN_PASSES} passes: {}",
                last_failures.join(", ")
            )));
        }

        // Clean up remaining network resources.
        if let Some(manager) = crate::sandbox::NetworkManager::global_if_initialized() {
            if let Err(err) = manager.shutdown() {
                warn!(error = ?err, "failed to clean up network resources during orchestrator shutdown");
            }
        }

        info!("orchestrator shutdown completed");
        Ok(())
    }

    fn is_shutting_down(&self) -> bool {
        self.is_shutting_down.load(Ordering::Acquire)
    }

    fn ensure_accepting_lifecycle_operations(&self) -> Result<()> {
        if self.is_shutting_down() {
            info!("rejecting lifecycle operation because orchestrator is shutting down");
            return Err(OrchestratorError::ShuttingDown);
        }

        Ok(())
    }
}

fn persisted_sandboxes_require_managed_seed(persisted: &[SandboxMetadata]) -> bool {
    persisted
        .iter()
        .any(|metadata| metadata.secure || !metadata.network_policy.allow_public_traffic)
}

#[cfg(test)]
impl<S, F, P> Orchestrator<S, F, P>
where
    S: MetadataStore + 'static,
    F: SandboxBackendFactory,
    P: SandboxPersister + 'static,
{
    pub(crate) async fn set_proxy_target_for_test(
        &self,
        sandbox_id: SandboxId,
        target: ProxyTarget,
        state: SandboxState,
    ) {
        self.set_metadata_state_for_test(sandbox_id, state)
            .await
            .expect("seed proxy metadata state for test");

        if state == SandboxState::Running {
            self.upsert_proxy_route(sandbox_id, target).await;
        } else {
            let _ = self.proxy_routes.write().await.remove(&sandbox_id);
        }
    }

    pub(crate) async fn set_metadata_state_for_test(
        &self,
        sandbox_id: SandboxId,
        state: SandboxState,
    ) -> Result<()> {
        let existing = self.store.get(&sandbox_id).await?;
        match existing {
            Some(mut metadata) => {
                metadata.state = state;
                self.store.update(metadata).await?;
            }
            None => {
                let metadata = SandboxMetadata {
                    id: sandbox_id,
                    state,
                    ..Default::default()
                };
                self.store.add(metadata.clone()).await?;
            }
        }

        Ok(())
    }

    pub(crate) async fn set_auto_resume_for_test(
        &self,
        sandbox_id: &SandboxId,
        auto_resume_enabled: bool,
    ) -> Result<()> {
        let Some(mut metadata) = self.store.get(sandbox_id).await? else {
            return Err(OrchestratorError::SandboxNotFound(*sandbox_id));
        };

        metadata.auto_resume = auto_resume_enabled;
        self.store.update(metadata).await?;

        Ok(())
    }

    pub(crate) async fn set_secure_for_test(
        &self,
        sandbox_id: &SandboxId,
        secure: bool,
    ) -> Result<()> {
        let Some(mut metadata) = self.store.get(sandbox_id).await? else {
            return Err(OrchestratorError::SandboxNotFound(*sandbox_id));
        };
        metadata.secure = secure;
        self.store.update(metadata).await?;
        Ok(())
    }

    pub(crate) async fn set_template_builder_for_test(&self, sandbox_id: &SandboxId) -> Result<()> {
        let Some(mut metadata) = self.store.get(sandbox_id).await? else {
            return Err(OrchestratorError::SandboxNotFound(*sandbox_id));
        };
        metadata.template_builder = true;
        self.store.update(metadata).await?;
        Ok(())
    }

    pub(crate) async fn set_allow_public_traffic_for_test(
        &self,
        sandbox_id: &SandboxId,
        allow_public_traffic: bool,
    ) -> Result<()> {
        let Some(mut metadata) = self.store.get(sandbox_id).await? else {
            return Err(OrchestratorError::SandboxNotFound(*sandbox_id));
        };
        metadata.network_policy.allow_public_traffic = allow_public_traffic;
        self.store.update(metadata).await?;
        Ok(())
    }

    pub(crate) async fn remove_proxy_route_for_test(&self, sandbox_id: &SandboxId) {
        let _ = self.proxy_routes.write().await.remove(sandbox_id);
    }
}

fn default_fresh_sandbox_resources() -> SandboxResources {
    let config = ConfigManager::global_config();
    SandboxResources {
        cpu_count: config.machine.vcpu_count,
        memory_mib: config.machine.mem_size_mib,
        // Filled from backend runtime info after the rootfs device is created.
        disk_size_mib: 0,
    }
}

fn resources_with_runtime_info(
    mut resources: SandboxResources,
    runtime_info: SandboxRuntimeInfo,
) -> SandboxResources {
    // This API resource field tracks the rootfs block device size. Attached
    // drives are separately configured storage and are not folded into it.
    if let Some(size) = runtime_info.rootfs_virtual_size {
        resources.disk_size_mib = bytes_to_mib_ceil(size);
    }
    resources
}

fn configured_runtime_versions() -> SnapshotRuntimeVersions {
    let config = ConfigManager::global_config();
    SnapshotRuntimeVersions::new(
        config
            .kernel
            .version
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        config
            .firecracker
            .version
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        config.envd.version.clone(),
        config.resolved_tools_version().to_string(),
    )
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
