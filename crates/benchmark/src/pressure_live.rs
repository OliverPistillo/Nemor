//! Checkpoint 3C pressure-only preflight, executor state machine, and evidence.

use crate::observer_service::ObserverServiceBackend;
use crate::performance::{detect_nemord_processes, reject_foreign_nemord};
use crate::pressure::{
    next_level_action_order, required_level_health_gates, HealthGate, HealthGateResult,
    LevelClassification, LevelEvidence, PressureExecutorAction, PressureMetric,
    PressureMetricScope, SafetyAbortClass,
};
use crate::pressure_prepare::{
    verify_prepared_pressure_manifest, PlannedPressureRun, PreparedPressureManifest,
    PressureRunState,
};
use crate::{EnvironmentFingerprint, EvaluationState, StructuralSnapshot};
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

pub const PRESSURE_EXECUTION_SCHEMA_VERSION: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PressurePreflightHost {
    pub material_environment_hash: String,
    pub current_available_memory_bytes: u64,
    pub foreign_nemord_clear: bool,
    pub benchmark_transient_units_clear: bool,
    pub cgroup_memory_controller_available: bool,
    pub host_psi_available: bool,
    pub cgroup_psi_supported: bool,
    pub observer_contract_supported: bool,
    pub output_fresh: bool,
    pub effective_uid: u32,
    pub current_runner_identity_verified: bool,
    pub release_binary_provenance_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PressurePreflightReport {
    pub manifest_verified: bool,
    pub release_binary_provenance_verified: bool,
    pub current_runner_identity_verified: bool,
    pub performance_claim_eligible: bool,
    pub scenario_contract_verified: bool,
    pub run_plan_verified: bool,
    pub pressure_plans_verified: bool,
    pub worker_protocol_supported: bool,
    pub observer_contract_supported: bool,
    pub cgroup_memory_controller_available: bool,
    pub host_psi_available: bool,
    pub cgroup_psi_supported: bool,
    pub material_environment_match: bool,
    pub foreign_nemord_clear: bool,
    pub benchmark_transient_units_clear: bool,
    pub output_fresh: bool,
    pub current_headroom_sufficient: bool,
    pub frozen_headroom_contract_safe: bool,
    pub current_identity_authorized: bool,
    pub requires_privileged_execution: bool,
    pub preflight_mutated: bool,
    pub execution_ready_except_authorization: bool,
    pub preparation_available_memory_bytes: u64,
    pub current_available_memory_bytes: u64,
    pub required_current_memory_bytes: u64,
}

pub fn evaluate_pressure_preflight(
    manifest: &PreparedPressureManifest,
    host: &PressurePreflightHost,
) -> PressurePreflightReport {
    let payload = &manifest.payload;
    let required_current_memory_bytes = payload
        .memory_max_derivation
        .shared_memory_max_bytes
        .saturating_add(payload.headroom.total_reserved_bytes);
    let current_headroom_sufficient =
        host.current_available_memory_bytes >= required_current_memory_bytes;
    let frozen_headroom_contract_safe = payload
        .headroom_policy
        .derive(payload.input_available_memory_bytes)
        .is_ok_and(|derived| {
            derived == payload.headroom
                && payload.memory_max_derivation.shared_memory_max_bytes
                    <= derived.effective_maximum_bytes
        });
    let material_environment_match =
        host.material_environment_hash == payload.material_environment_hash;
    let current_identity_authorized = host.effective_uid == 0;
    let non_authorization_ready = payload.performance_source_eligible
        && host.current_runner_identity_verified
        && host.release_binary_provenance_verified
        && host.observer_contract_supported
        && host.cgroup_memory_controller_available
        && host.host_psi_available
        && host.cgroup_psi_supported
        && material_environment_match
        && host.foreign_nemord_clear
        && host.benchmark_transient_units_clear
        && host.output_fresh
        && current_headroom_sufficient
        && frozen_headroom_contract_safe;
    PressurePreflightReport {
        manifest_verified: true,
        release_binary_provenance_verified: host.release_binary_provenance_verified,
        current_runner_identity_verified: host.current_runner_identity_verified,
        performance_claim_eligible: payload.performance_source_eligible,
        scenario_contract_verified: true,
        run_plan_verified: true,
        pressure_plans_verified: true,
        worker_protocol_supported: crate::pressure_worker::PRESSURE_WORKER_PROTOCOL_VERSION == 1,
        observer_contract_supported: host.observer_contract_supported,
        cgroup_memory_controller_available: host.cgroup_memory_controller_available,
        host_psi_available: host.host_psi_available,
        cgroup_psi_supported: host.cgroup_psi_supported,
        material_environment_match,
        foreign_nemord_clear: host.foreign_nemord_clear,
        benchmark_transient_units_clear: host.benchmark_transient_units_clear,
        output_fresh: host.output_fresh,
        current_headroom_sufficient,
        frozen_headroom_contract_safe,
        current_identity_authorized,
        requires_privileged_execution: true,
        preflight_mutated: false,
        execution_ready_except_authorization: non_authorization_ready,
        preparation_available_memory_bytes: payload.input_available_memory_bytes,
        current_available_memory_bytes: host.current_available_memory_bytes,
        required_current_memory_bytes,
    }
}

pub fn verify_current_runner_identity_at(
    manifest: &PreparedPressureManifest,
    current_executable: &Path,
    embedded_git_head: &str,
    embedded_build_profile: &str,
    embedded_schema_version: u32,
) -> Result<()> {
    let current = current_executable.canonicalize()?;
    let frozen = manifest.payload.runner_path.canonicalize()?;
    let current_sha256 = hex::encode(Sha256::digest(fs::read(&current)?));
    let payload = &manifest.payload;
    if current != frozen
        || current_sha256 != payload.runner_binary.sha256
        || current_sha256 != payload.provenance.binary_sha256
        || embedded_git_head != payload.runner_binary.embedded_git_head
        || embedded_git_head != payload.provenance.git_head
        || embedded_build_profile != payload.runner_binary.build_profile
        || embedded_build_profile != payload.provenance.build_profile
        || embedded_schema_version != payload.provenance.benchmark_schema_version
        || payload.runner_binary.source_state_id != payload.provenance.source_state_id
        || !payload.provenance.clean_release_eligible()
    {
        bail!("current pressure runner identity differs from frozen clean release");
    }
    Ok(())
}

fn current_embedded_build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

pub fn pressure_worker_executable(manifest: &PreparedPressureManifest) -> Result<PathBuf> {
    let executable = manifest.payload.runner_path.canonicalize()?;
    if executable != manifest.payload.worker_executable_path.canonicalize()? {
        bail!("pressure worker executable differs from frozen runner");
    }
    Ok(executable)
}

pub fn touched_ack_allows_hold(actual_touched_bytes: u64, target_touched_bytes: u64) -> bool {
    actual_touched_bytes == target_touched_bytes
}

fn mem_available_bytes() -> Result<u64> {
    let value = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|value| value.split_whitespace().next())
        .context("MemAvailable missing")?
        .parse::<u64>()?;
    value
        .checked_mul(1024)
        .ok_or_else(|| anyhow::anyhow!("MemAvailable overflow"))
}

fn output_is_fresh(manifest: &PreparedPressureManifest) -> bool {
    let payload = &manifest.payload;
    fs::read_dir(&payload.output_root)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false)
        && !payload.database_path.exists()
        && !payload.report_path.exists()
        && !payload.runs_path.exists()
}

pub fn capture_pressure_preflight_host(
    manifest: &PreparedPressureManifest,
) -> Result<PressurePreflightHost> {
    let payload = &manifest.payload;
    let environment = EnvironmentFingerprint::capture_for_performance(
        &payload.config_sha256,
        &payload.provenance.git_head,
    )?;
    let foreign = detect_nemord_processes(&payload.observer_path, None);
    let benchmark_transient_units_clear = crate::systemd::SystemdDbusBackend::system()
        .and_then(|backend| backend.list_owned_benchmark_units())
        .map(|units| units.is_empty())
        .unwrap_or(false);
    let current_executable = std::env::current_exe()?;
    let current_runner_identity_verified = verify_current_runner_identity_at(
        manifest,
        &current_executable,
        crate::BUILD_GIT_HEAD,
        current_embedded_build_profile(),
        crate::BENCHMARK_SCHEMA_VERSION,
    )
    .is_ok();
    let release_binary_provenance_verified = current_runner_identity_verified
        && payload.performance_source_eligible
        && payload.provenance.clean_release_eligible();
    Ok(PressurePreflightHost {
        material_environment_hash: environment.material_hash()?,
        current_available_memory_bytes: mem_available_bytes()?,
        foreign_nemord_clear: reject_foreign_nemord(&foreign, None).is_ok(),
        benchmark_transient_units_clear,
        cgroup_memory_controller_available: fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
            .map(|value| value.split_whitespace().any(|item| item == "memory"))
            .unwrap_or(false),
        host_psi_available: Path::new("/proc/pressure/memory").is_file(),
        cgroup_psi_supported: Path::new("/sys/fs/cgroup/memory.pressure").is_file(),
        observer_contract_supported:
            crate::observer_service::SystemdObserverServiceBackend::system()
                .and_then(|backend| backend.preflight())
                .is_ok(),
        output_fresh: output_is_fresh(manifest),
        effective_uid: nix::unistd::geteuid().as_raw(),
        current_runner_identity_verified,
        release_binary_provenance_verified,
    })
}

pub fn pressure_preflight(manifest_path: &Path) -> Result<PressurePreflightReport> {
    let manifest = verify_prepared_pressure_manifest(manifest_path)?;
    let host = capture_pressure_preflight_host(&manifest)?;
    Ok(evaluate_pressure_preflight(&manifest, &host))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureExperimentState {
    Running,
    CompletedFrameworkValidation,
    RejectedBeforeRun0,
    InvalidRun,
    UnsustainableHealth,
    SafetyAbort,
    ExecutionError,
}

pub fn pressure_execution_exit_status(state: PressureExperimentState) -> i32 {
    if state == PressureExperimentState::CompletedFrameworkValidation {
        0
    } else {
        1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureRunRecord {
    pub planned: PlannedPressureRun,
    pub state: PressureRunState,
    pub levels: Vec<LevelEvidence>,
    pub level_progress: Vec<PressureLevelProgress>,
    pub structural_before: Option<StructuralSnapshot>,
    pub structural_after: Option<StructuralSnapshot>,
    pub stop_reason: Option<String>,
    pub restore_passed: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureLevelProgressStage {
    TransitionStarting,
    TransitionTimeout,
    LevelAcknowledged,
    StabilizationStarting,
    HoldStarting,
    Sampling,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureLevelProgress {
    pub level_index: usize,
    pub stage: PressureLevelProgressStage,
    pub monotonic_ns: u64,
    pub target_touched_bytes: u64,
    pub requested_delta_bytes: u64,
    pub expected_workload_identity: String,
    pub acknowledgement: Option<crate::pressure::WorkerLevelAcknowledgement>,
    pub transition_duration_ms: Option<u64>,
    pub configured_transition_deadline_ms: Option<u64>,
    pub sample: Option<crate::pressure::PressureLevelSample>,
}

#[derive(Debug, Clone)]
pub enum PressurePersistenceEvent {
    Progress(Box<PressureLevelProgress>),
    Completed(Box<LevelEvidence>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureExecutionEvidence {
    pub schema_version: u32,
    pub experiment_id: String,
    pub state: PressureExperimentState,
    pub runs: Vec<PressureRunRecord>,
    pub execution_error: Option<String>,
    pub search_complete: bool,
    pub capacity_gain_percent: EvaluationState,
}

impl PressureExecutionEvidence {
    fn planned(manifest: &PreparedPressureManifest) -> Self {
        Self {
            schema_version: PRESSURE_EXECUTION_SCHEMA_VERSION,
            experiment_id: manifest.payload.experiment_id.clone(),
            state: PressureExperimentState::Running,
            runs: manifest
                .payload
                .run_plan
                .runs
                .iter()
                .cloned()
                .map(|planned| PressureRunRecord {
                    state: planned.state,
                    planned,
                    levels: Vec::new(),
                    level_progress: Vec::new(),
                    structural_before: None,
                    structural_after: None,
                    stop_reason: None,
                    restore_passed: None,
                })
                .collect(),
            execution_error: None,
            search_complete: false,
            capacity_gain_percent: EvaluationState::NotEvaluated,
        }
    }
}

pub struct IncrementalPressureStore {
    report: PathBuf,
    database: PathBuf,
    runs: PathBuf,
}

impl IncrementalPressureStore {
    pub fn create(manifest: &PreparedPressureManifest) -> Result<Self> {
        fs::create_dir(&manifest.payload.runs_path)?;
        fs::set_permissions(
            &manifest.payload.runs_path,
            fs::Permissions::from_mode(0o755),
        )?;
        let connection = Connection::open(&manifest.payload.database_path)?;
        connection.execute_batch(
            "CREATE TABLE pressure_experiment (
                 id TEXT PRIMARY KEY, state TEXT NOT NULL, evidence_json TEXT NOT NULL
             );
             CREATE TABLE pressure_level (
                 experiment_id TEXT NOT NULL, run_order INTEGER NOT NULL,
                 level_index INTEGER NOT NULL, evidence_json TEXT NOT NULL,
                 PRIMARY KEY(experiment_id,run_order,level_index)
             );
             CREATE TABLE pressure_level_progress (
                 experiment_id TEXT NOT NULL, run_order INTEGER NOT NULL,
                 level_index INTEGER NOT NULL, stage TEXT NOT NULL,
                 monotonic_ns INTEGER NOT NULL, evidence_json TEXT NOT NULL,
                 PRIMARY KEY(experiment_id,run_order,level_index,stage,monotonic_ns)
             );",
        )?;
        Ok(Self {
            report: manifest.payload.report_path.clone(),
            database: manifest.payload.database_path.clone(),
            runs: manifest.payload.runs_path.clone(),
        })
    }

    pub fn persist(&self, evidence: &PressureExecutionEvidence) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(evidence)?;
        let temporary = self.report.with_extension("json.tmp");
        fs::write(&temporary, &bytes)?;
        fs::rename(&temporary, &self.report)?;
        let connection = Connection::open(&self.database)?;
        connection.execute(
            "INSERT INTO pressure_experiment(id,state,evidence_json) VALUES(?1,?2,?3)
             ON CONFLICT(id) DO UPDATE SET state=excluded.state,evidence_json=excluded.evidence_json",
            params![
                evidence.experiment_id,
                format!("{:?}", evidence.state),
                String::from_utf8(bytes)?
            ],
        )?;
        for (order, run) in evidence.runs.iter().enumerate() {
            let run_path = self.runs.join(format!("run-{order}.json"));
            fs::write(run_path, serde_json::to_vec_pretty(run)?)?;
            for level in &run.levels {
                connection.execute(
                    "INSERT OR REPLACE INTO pressure_level(experiment_id,run_order,level_index,evidence_json)
                     VALUES(?1,?2,?3,?4)",
                    params![
                        evidence.experiment_id,
                        order as i64,
                        level.level_index as i64,
                        serde_json::to_string(level)?
                    ],
                )?;
            }
            for progress in &run.level_progress {
                connection.execute(
                    "INSERT OR REPLACE INTO pressure_level_progress(
                         experiment_id,run_order,level_index,stage,monotonic_ns,evidence_json
                     ) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![
                        evidence.experiment_id,
                        order as i64,
                        progress.level_index as i64,
                        format!("{:?}", progress.stage),
                        progress.monotonic_ns as i64,
                        serde_json::to_string(progress)?
                    ],
                )?;
            }
        }
        Ok(())
    }
}

pub trait PressureExecutionBackend {
    fn execute_run(
        &mut self,
        manifest: &PreparedPressureManifest,
        order_index: usize,
        persist_event: &mut dyn FnMut(PressurePersistenceEvent) -> Result<()>,
    ) -> Result<PressureBackendRunResult>;

    fn structural_snapshot(&mut self) -> StructuralSnapshot {
        StructuralSnapshot::capture()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PressureCleanupEvidence {
    pub worker_absent: bool,
    pub pre_stop_unit_present: bool,
    pub stop_action: PressureScopeStopAction,
    pub worker_scope_stopped: bool,
    pub worker_scope_zero_members: bool,
    pub worker_scope_absent: bool,
    pub observer_absent: bool,
    pub observer_runtime_directory_absent: bool,
    pub stop_job_result: Option<String>,
    pub final_active_state: Option<String>,
    pub final_sub_state: Option<String>,
    pub cgroup_member_count: Option<usize>,
    pub unit_removed: bool,
    pub removal_wait_ms: u64,
    pub classification: PressureScopeCleanupClassification,
    pub failure_reason: Option<String>,
}

impl PressureCleanupEvidence {
    pub fn passed(&self) -> bool {
        self.worker_absent
            && self.worker_scope_stopped
            && self.worker_scope_zero_members
            && self.worker_scope_absent
            && self.observer_absent
            && self.observer_runtime_directory_absent
            && self.unit_removed
            && self.classification == PressureScopeCleanupClassification::Clean
    }

    #[cfg(test)]
    fn simulated(passed: bool) -> Self {
        Self {
            worker_absent: passed,
            pre_stop_unit_present: passed,
            stop_action: if passed {
                PressureScopeStopAction::StopUnitRequested
            } else {
                PressureScopeStopAction::StopFailed
            },
            worker_scope_stopped: passed,
            worker_scope_zero_members: passed,
            worker_scope_absent: passed,
            observer_absent: passed,
            observer_runtime_directory_absent: passed,
            stop_job_result: Some(if passed { "done" } else { "failed" }.into()),
            final_active_state: Some(if passed { "inactive" } else { "active" }.into()),
            final_sub_state: Some(if passed { "dead" } else { "running" }.into()),
            cgroup_member_count: Some(usize::from(!passed)),
            unit_removed: passed,
            removal_wait_ms: 0,
            classification: if passed {
                PressureScopeCleanupClassification::Clean
            } else {
                PressureScopeCleanupClassification::ActiveOrMembered
            },
            failure_reason: (!passed).then(|| "simulated cleanup failure".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureScopeStopAction {
    AlreadyAbsent,
    StopUnitRequested,
    StopUnitNoSuchUnitReconciled,
    StopFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureScopeCleanupClassification {
    Clean,
    ActiveOrMembered,
    TransientScopeRemovalTimeout,
    StopFailed,
}

pub fn wait_for_transient_scope_removal(
    timeout: Duration,
    mut unit_exists: impl FnMut() -> Result<bool>,
) -> Result<u64> {
    let started = Instant::now();
    loop {
        if !unit_exists()? {
            return Ok(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX));
        }
        if started.elapsed() >= timeout {
            bail!("TRANSIENT_SCOPE_REMOVAL_TIMEOUT");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

pub fn already_absent_scope_is_clean(
    worker_absent: bool,
    cgroup_member_count: Option<usize>,
    unit_absent: bool,
) -> bool {
    worker_absent && cgroup_member_count == Some(0) && unit_absent
}

pub fn no_such_unit_race_reconciles(
    worker_absent: bool,
    cgroup_member_count: Option<usize>,
    unit_absent_after_error: bool,
) -> bool {
    already_absent_scope_is_clean(worker_absent, cgroup_member_count, unit_absent_after_error)
}

pub fn initial_scope_stop_action(
    state_readable: bool,
    unit_present: bool,
    ownership_exact: bool,
) -> PressureScopeStopAction {
    if !state_readable || !ownership_exact {
        PressureScopeStopAction::StopFailed
    } else if unit_present {
        PressureScopeStopAction::StopUnitRequested
    } else {
        PressureScopeStopAction::AlreadyAbsent
    }
}

#[derive(Debug, Clone)]
pub struct PressureBackendRunResult {
    pub state: PressureRunState,
    pub reason: String,
    pub execution_error: Option<String>,
    pub cleanup: PressureCleanupEvidence,
}

pub fn execute_pressure_with_backend(
    manifest: &PreparedPressureManifest,
    backend: &mut dyn PressureExecutionBackend,
    store: &IncrementalPressureStore,
) -> Result<PressureExecutionEvidence> {
    let mut evidence = PressureExecutionEvidence::planned(manifest);
    store.persist(&evidence)?;
    for order in 0..evidence.runs.len() {
        evidence.runs[order].structural_before = Some(backend.structural_snapshot());
        store.persist(&evidence)?;
        let result = backend.execute_run(manifest, order, &mut |event| {
            match event {
                PressurePersistenceEvent::Progress(progress) => {
                    evidence.runs[order].level_progress.push(*progress);
                }
                PressurePersistenceEvent::Completed(level) => {
                    evidence.runs[order]
                        .level_progress
                        .push(PressureLevelProgress {
                            level_index: level.level_index,
                            stage: PressureLevelProgressStage::Completed,
                            monotonic_ns: level.ended_monotonic_ns,
                            target_touched_bytes: level.actual_touched_bytes,
                            requested_delta_bytes: level
                                .worker_acknowledgement
                                .requested_delta_bytes,
                            expected_workload_identity: level.workload_identity.clone(),
                            acknowledgement: Some(level.worker_acknowledgement.clone()),
                            transition_duration_ms: None,
                            configured_transition_deadline_ms: None,
                            sample: None,
                        });
                    evidence.runs[order].levels.push(*level);
                }
            }
            store.persist(&evidence)
        });
        match result {
            Ok(result) => {
                evidence.runs[order].state = result.state;
                evidence.runs[order].stop_reason = Some(result.reason.clone());
                evidence.runs[order].structural_after = Some(backend.structural_snapshot());
                let structural_restore = evidence.runs[order]
                    .structural_before
                    .as_ref()
                    .zip(evidence.runs[order].structural_after.as_ref())
                    .is_some_and(|(before, after)| before.matches(after));
                let restore_passed = result.cleanup.passed() && structural_restore;
                evidence.runs[order].restore_passed = Some(restore_passed);
                store.persist(&evidence)?;
                if !restore_passed {
                    let original = match result.execution_error.as_deref() {
                        Some(error) => format!("{}; execution_error={error}", result.reason),
                        None => result.reason.clone(),
                    };
                    evidence.runs[order].state = PressureRunState::SafetyAbort;
                    evidence.runs[order].stop_reason = Some(format!(
                        "RESTORE_FAILURE cleanup={:?} structural_match={structural_restore}; original={}",
                        result.cleanup, original
                    ));
                    evidence.state = PressureExperimentState::SafetyAbort;
                    if let Some(error) = result.execution_error {
                        evidence.execution_error = Some(error);
                    }
                    store.persist(&evidence)?;
                    break;
                }
                if let Some(error) = result.execution_error {
                    evidence.runs[order].state = PressureRunState::Invalid;
                    evidence.runs[order].stop_reason =
                        Some(format!("execution_error_cleanup_passed: {error}"));
                    evidence.state = PressureExperimentState::ExecutionError;
                    evidence.execution_error = Some(error);
                    store.persist(&evidence)?;
                    break;
                }
                if matches!(result.state, PressureRunState::SafetyAbort) {
                    evidence.state = PressureExperimentState::SafetyAbort;
                    break;
                }
                if matches!(result.state, PressureRunState::Invalid) {
                    evidence.state = PressureExperimentState::InvalidRun;
                    break;
                }
                if matches!(result.state, PressureRunState::UnsustainableBoundary) {
                    evidence.state = PressureExperimentState::UnsustainableHealth;
                    break;
                }
            }
            Err(error) => {
                evidence.runs[order].state = PressureRunState::Invalid;
                evidence.runs[order].stop_reason = Some(format!("{error:#}"));
                evidence.state = PressureExperimentState::ExecutionError;
                evidence.execution_error = Some(format!("{error:#}"));
                store.persist(&evidence)?;
                break;
            }
        }
    }
    if evidence.state == PressureExperimentState::Running {
        evidence.state = PressureExperimentState::CompletedFrameworkValidation;
    } else {
        for run in &mut evidence.runs {
            if run.state == PressureRunState::Planned {
                run.state = PressureRunState::NotExecutedAfterStop;
                run.stop_reason = Some(format!(
                    "not executed after experiment state {:?}",
                    evidence.state
                ));
            }
        }
    }
    store.persist(&evidence)?;
    Ok(evidence)
}

pub fn execute_pressure_experiment(manifest_path: &Path) -> Result<PressureExecutionEvidence> {
    let manifest = verify_prepared_pressure_manifest(manifest_path)?;
    if !nix::unistd::geteuid().is_root() {
        bail!("pressure execution requires privileged execution");
    }
    let sudo_uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    let sudo_gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok());
    if sudo_uid != Some(manifest.payload.preparing_uid)
        || sudo_gid != Some(manifest.payload.preparing_gid)
    {
        bail!("pressure sudo identity differs from preparing identity");
    }
    let preflight = pressure_preflight(manifest_path)?;
    if !preflight.execution_ready_except_authorization || !preflight.current_identity_authorized {
        if output_is_fresh(&manifest) {
            let store = IncrementalPressureStore::create(&manifest)?;
            let mut evidence = PressureExecutionEvidence::planned(&manifest);
            evidence.state = PressureExperimentState::RejectedBeforeRun0;
            evidence.execution_error =
                Some("pressure execution freeze check failed before run 0".into());
            store.persist(&evidence)?;
        }
        bail!("pressure execution freeze check failed before run 0");
    }
    let store = IncrementalPressureStore::create(&manifest)?;
    let mut backend = RealPressureExecutionBackend;
    execute_pressure_with_backend(&manifest, &mut backend, &store)
}

pub struct RealPressureExecutionBackend;

impl PressureExecutionBackend for RealPressureExecutionBackend {
    fn execute_run(
        &mut self,
        manifest: &PreparedPressureManifest,
        order_index: usize,
        persist_event: &mut dyn FnMut(PressurePersistenceEvent) -> Result<()>,
    ) -> Result<PressureBackendRunResult> {
        execute_real_pressure_run(manifest, order_index, persist_event)
    }
}

fn process_start_ticks(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| anyhow::anyhow!("malformed worker stat"))?;
    Ok(stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .context("worker start ticks missing")?
        .parse()?)
}

fn counter_map(path: &Path) -> Result<std::collections::BTreeMap<String, u64>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((fields.next()?.into(), fields.next()?.parse().ok()?))
        })
        .collect())
}

fn scalar(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn cgroup_member_count(cgroup: &Path) -> Option<usize> {
    if !cgroup.exists() {
        return Some(0);
    }
    fs::read_to_string(cgroup.join("cgroup.procs"))
        .ok()
        .map(|members| {
            members
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count()
        })
}

fn process_cpu_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let fields = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
    fields
        .get(11)?
        .parse::<u64>()
        .ok()?
        .checked_add(fields.get(12)?.parse::<u64>().ok()?)
}

fn block_write_bytes() -> Option<u64> {
    fs::read_to_string("/proc/diskstats")
        .ok()?
        .lines()
        .try_fold(0u64, |sum, line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let sectors = fields.get(9)?.parse::<u64>().ok()?;
            sum.checked_add(sectors.checked_mul(512)?)
        })
}

fn relative_counter(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    before.zip(after).and_then(|(a, b)| b.checked_sub(a))
}

#[derive(Debug, Clone)]
struct LevelGateObservations {
    worker_alive: bool,
    worker_identity: bool,
    heartbeat_fresh: bool,
    worker_integrity: bool,
    cgroup_membership: bool,
    memory_limit_contract: bool,
    host_psi: bool,
    cgroup_psi: bool,
    major_faults: bool,
    swap_in: bool,
    swap_out: bool,
    block_writes: bool,
    worker_cpu: bool,
    runner_cpu: bool,
    observer_contract: bool,
    elapsed_duration: bool,
}

fn granular_health_gates(
    variant: crate::BenchmarkVariant,
    observed: &LevelGateObservations,
) -> std::collections::BTreeMap<HealthGate, HealthGateResult> {
    required_level_health_gates(variant)
        .into_iter()
        .map(|gate| {
            let passed = match gate {
                HealthGate::WorkerAlive => observed.worker_alive,
                HealthGate::WorkerIdentity => observed.worker_identity,
                HealthGate::HeartbeatFresh => observed.heartbeat_fresh,
                HealthGate::WorkerIntegrity => observed.worker_integrity,
                HealthGate::CgroupMembership => observed.cgroup_membership,
                HealthGate::MemoryLimitContract => observed.memory_limit_contract,
                HealthGate::HostPsi => observed.host_psi,
                HealthGate::CgroupPsi => observed.cgroup_psi,
                HealthGate::MajorFaults => observed.major_faults,
                HealthGate::SwapIn => observed.swap_in,
                HealthGate::SwapOut => observed.swap_out,
                HealthGate::BlockWrites => observed.block_writes,
                HealthGate::WorkerCpu => observed.worker_cpu,
                HealthGate::RunnerCpu => observed.runner_cpu,
                HealthGate::ObserverContract => observed.observer_contract,
                HealthGate::ElapsedDuration => observed.elapsed_duration,
                HealthGate::RestoreOwnership => false,
            };
            (
                gate,
                HealthGateResult {
                    passed,
                    mandatory: true,
                    reason: (!passed).then(|| format!("{gate:?} evidence missing or failed")),
                },
            )
        })
        .collect()
}

fn timestamp_ns() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .map(|seconds| (seconds * 1_000_000_000.0) as u64)
        .unwrap_or(0)
}

fn worker_message_identity(
    experiment_id: &str,
    run_id: &str,
    pid: u32,
    start_ticks: u64,
) -> (u32, String, String, u32, u64) {
    (
        crate::pressure_worker::PRESSURE_WORKER_PROTOCOL_VERSION,
        experiment_id.into(),
        run_id.into(),
        pid,
        start_ticks,
    )
}

fn send_stop(
    client: &mut crate::pressure_worker::PressureWorkerClient,
    experiment_id: &str,
    run_id: &str,
    pid: u32,
    start_ticks: u64,
    timeout: Duration,
) -> bool {
    let (version, experiment_id, run_id, pid, start_ticks) =
        worker_message_identity(experiment_id, run_id, pid, start_ticks);
    client
        .send_with_timeout(
            &crate::pressure_worker::WorkerIpcMessage::Stop {
                version,
                experiment_id,
                run_id,
                pid,
                start_ticks,
            },
            timeout,
            "STOP",
        )
        .is_ok()
}

fn execute_real_pressure_run(
    manifest: &PreparedPressureManifest,
    order_index: usize,
    persist_event: &mut dyn FnMut(PressurePersistenceEvent) -> Result<()>,
) -> Result<PressureBackendRunResult> {
    use crate::systemd::TransientScopeBackend;
    let payload = &manifest.payload;
    let planned = payload
        .run_plan
        .runs
        .get(order_index)
        .context("pressure run order absent")?;
    let plan = payload
        .pressure_plans
        .get(order_index)
        .context("pressure plan absent")?;
    let heartbeat_timeout = Duration::from_millis(plan.watchdog.heartbeat_timeout_ms);
    let transition_timeout = Duration::from_millis(plan.watchdog.level_transition_timeout_ms);
    let total_timeout = Duration::from_millis(plan.watchdog.total_timeout_ms);
    let run_id = format!(
        "c3c-run-o{}-r{}-{}",
        order_index, planned.repetition_index, payload.experiment_id
    );
    let socket = payload.runs_path.join(format!("worker-{order_index}.sock"));
    if socket.exists() {
        bail!("pressure worker socket collision");
    }
    verify_current_runner_identity_at(
        manifest,
        &std::env::current_exe()?,
        crate::BUILD_GIT_HEAD,
        current_embedded_build_profile(),
        crate::BENCHMARK_SCHEMA_VERSION,
    )?;
    let executable = pressure_worker_executable(manifest)?;
    let mut child = Command::new(&executable)
        .arg("pressure-worker")
        .arg("--socket")
        .arg(&socket)
        .arg("--experiment-id")
        .arg(&payload.experiment_id)
        .arg("--run-id")
        .arg(&run_id)
        .arg("--seed")
        .arg(planned.run_seed.to_string())
        .spawn()?;
    let pid = child.id();
    let start_ticks = match process_start_ticks(pid) {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let mut client = match crate::pressure_worker::PressureWorkerClient::connect(&socket) {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let hello = match client.receive_with_timeout(heartbeat_timeout, "HELLO") {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    if hello
        != (crate::pressure_worker::WorkerIpcMessage::Hello {
            version: crate::pressure_worker::PRESSURE_WORKER_PROTOCOL_VERSION,
            experiment_id: payload.experiment_id.clone(),
            run_id: run_id.clone(),
            pid,
            start_ticks,
            touched_bytes: 0,
        })
    {
        let _ = child.kill();
        let _ = child.wait();
        bail!("pressure worker HELLO identity mismatch");
    }
    let identity = crate::harness::OwnedProcessIdentity {
        run_id: run_id.clone(),
        pid,
        start_ticks,
    };
    let unit_lifetime_usec = plan
        .watchdog
        .total_timeout_ms
        .checked_add(10_000)
        .and_then(|value| value.checked_mul(1_000))
        .context("pressure unit lifetime overflow")?;
    let scope_plan = crate::systemd::TransientScopePlan::with_pressure_limits(
        &run_id,
        identity,
        plan.worker_memory_max_bytes,
        unit_lifetime_usec,
    )?;
    let mut systemd = crate::systemd::SystemdDbusBackend::system()?;
    let scope = match systemd.start_owned_scope(&scope_plan) {
        Ok(scope) => scope,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let observe_run = payload
        .observer_runs
        .iter()
        .find(|run| run.order_index == order_index);
    let mut observer = None;
    let cgroup = Path::new("/sys/fs/cgroup").join(scope.control_group.trim_start_matches('/'));
    let host_oom_before = counter_map(Path::new("/proc/vmstat"))
        .ok()
        .and_then(|values| values.get("oom_kill").copied());
    let mut prior = 0;
    let mut final_state = PressureRunState::Completed;
    let mut reason = "all conservative framework levels sustainable".to_string();
    let run_result = (|| -> Result<()> {
        scope.verify(&scope_plan)?;
        let (version, experiment_id, ipc_run_id, ipc_pid, ipc_ticks) =
            worker_message_identity(&payload.experiment_id, &run_id, pid, start_ticks);
        let boundary = client.send_with_timeout(
            &crate::pressure_worker::WorkerIpcMessage::VerifyBoundary {
                version,
                experiment_id,
                run_id: ipc_run_id,
                pid: ipc_pid,
                start_ticks: ipc_ticks,
                memory_max_bytes: plan.worker_memory_max_bytes,
            },
            heartbeat_timeout,
            "VERIFY_BOUNDARY",
        )?;
        if !matches!(
            boundary,
            crate::pressure_worker::WorkerIpcMessage::BoundaryVerified { .. }
        ) {
            bail!("worker boundary verification acknowledgement missing");
        }
        if planned.variant == crate::BenchmarkVariant::CachyosBaseline && observe_run.is_some() {
            bail!("baseline pressure run cannot own observer");
        }
        if planned.variant == crate::BenchmarkVariant::NemorObserve {
            let frozen = observe_run.context("observe pressure run lacks observer transaction")?;
            observer = Some(crate::observer_service::start_performance_observer(
                &frozen.service_plan,
                &payload.observer_path,
                &payload.observer_binary.sha256,
                &frozen.prepared_config_path,
                &frozen.prepared_config_sha256,
            )?);
        }
        let total_deadline = Instant::now() + total_timeout;
        for level in &plan.levels {
            let expected_workload_identity = payload
                .expected_level_workload_identities
                .get(order_index)
                .and_then(|levels| levels.get(level.level_index))
                .context("frozen pressure workload identity missing")?
                .clone();
            let recomputed_workload_identity = crate::pressure::pressure_workload_identity(
                &crate::pressure::PressureWorkloadIdentityContract {
                    domain: "nemor.phase10.pressure_workload",
                    version: crate::pressure::PRESSURE_WORKLOAD_IDENTITY_VERSION,
                    scenario: &plan.scenario,
                    scenario_version: plan.scenario_version,
                    generator_id: &plan.generator_id,
                    generator_version: plan.generator_version,
                    run_seed: planned.run_seed,
                    level_index: level.level_index,
                    planned_logical_bytes: level.target_logical_bytes,
                    planned_touched_bytes: level.target_touched_bytes,
                    pressure_plan_version: plan.version,
                    worker_implementation_identity: &payload.worker_implementation_identity,
                },
            )?;
            if recomputed_workload_identity != expected_workload_identity {
                bail!("frozen pressure workload identity mismatch before allocation");
            }
            if Instant::now() >= total_deadline {
                final_state = PressureRunState::SafetyAbort;
                reason = "WATCHDOG_TIMEOUT before next level".into();
                break;
            }
            let host_psi = fs::read_to_string("/proc/pressure/memory")
                .ok()
                .and_then(|value| crate::parse_psi(&value).ok());
            if host_psi
                .as_ref()
                .and_then(|psi| psi.full.as_ref())
                .is_some_and(|full| {
                    crate::pressure::psi_avg10_threshold_crossed(
                        full.avg10,
                        plan.health.host_psi_full_avg10_emergency,
                    )
                    .unwrap_or(true)
                })
            {
                final_state = PressureRunState::SafetyAbort;
                reason = "HOST_PSI_EMERGENCY before next allocation".into();
                break;
            }
            let vm_before = counter_map(Path::new("/proc/vmstat")).ok();
            let level_deadline =
                Instant::now() + Duration::from_millis(plan.watchdog.level_timeout_ms);
            let major_fault_before = vm_before
                .as_ref()
                .and_then(|values| values.get("pgmajfault").copied());
            let swap_in_before = vm_before
                .as_ref()
                .and_then(|values| values.get("pswpin").copied());
            let swap_out_before = vm_before
                .as_ref()
                .and_then(|values| values.get("pswpout").copied());
            let block_write_before = block_write_bytes();
            let worker_cpu_before = process_cpu_ticks(pid);
            let runner_cpu_before = process_cpu_ticks(std::process::id());
            let command = crate::pressure_worker::command_for_level(
                &payload.experiment_id,
                &run_id,
                level,
                prior,
            )?;
            persist_event(PressurePersistenceEvent::Progress(Box::new(
                PressureLevelProgress {
                    level_index: level.level_index,
                    stage: PressureLevelProgressStage::TransitionStarting,
                    monotonic_ns: timestamp_ns(),
                    target_touched_bytes: command.target_touched_bytes,
                    requested_delta_bytes: command.requested_delta_bytes,
                    expected_workload_identity: expected_workload_identity.clone(),
                    acknowledgement: None,
                    transition_duration_ms: None,
                    configured_transition_deadline_ms: Some(
                        plan.watchdog.level_transition_timeout_ms,
                    ),
                    sample: None,
                },
            )))?;
            let (version, experiment_id, ipc_run_id, ipc_pid, ipc_ticks) =
                worker_message_identity(&payload.experiment_id, &run_id, pid, start_ticks);
            let transition_started = Instant::now();
            let ack_message = match client.send_with_timeout(
                &crate::pressure_worker::WorkerIpcMessage::LevelRequest {
                    version,
                    experiment_id,
                    run_id: ipc_run_id,
                    pid: ipc_pid,
                    start_ticks: ipc_ticks,
                    command,
                    monotonic_ns: timestamp_ns(),
                },
                transition_timeout,
                "LEVEL_REQUEST/LEVEL_ACK",
            ) {
                Ok(message) => message,
                Err(_) => {
                    let elapsed_ms = transition_started
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX);
                    persist_event(PressurePersistenceEvent::Progress(Box::new(
                        PressureLevelProgress {
                            level_index: level.level_index,
                            stage: PressureLevelProgressStage::TransitionTimeout,
                            monotonic_ns: timestamp_ns(),
                            target_touched_bytes: level.target_touched_bytes,
                            requested_delta_bytes: level.target_touched_bytes.saturating_sub(prior),
                            expected_workload_identity: expected_workload_identity.clone(),
                            acknowledgement: None,
                            transition_duration_ms: Some(elapsed_ms),
                            configured_transition_deadline_ms: Some(
                                plan.watchdog.level_transition_timeout_ms,
                            ),
                            sample: None,
                        },
                    )))?;
                    final_state = PressureRunState::SafetyAbort;
                    reason = "WATCHDOG_TIMEOUT during bounded worker level transition".into();
                    break;
                }
            };
            let acknowledgement = match ack_message {
                crate::pressure_worker::WorkerIpcMessage::LevelAck {
                    acknowledgement, ..
                } => acknowledgement,
                _ => bail!("worker LEVEL_ACK missing"),
            };
            let transition_duration_ms = transition_started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            persist_event(PressurePersistenceEvent::Progress(Box::new(
                PressureLevelProgress {
                    level_index: level.level_index,
                    stage: PressureLevelProgressStage::LevelAcknowledged,
                    monotonic_ns: timestamp_ns(),
                    target_touched_bytes: level.target_touched_bytes,
                    requested_delta_bytes: acknowledgement.requested_delta_bytes,
                    expected_workload_identity: expected_workload_identity.clone(),
                    acknowledgement: Some(acknowledgement.clone()),
                    transition_duration_ms: Some(transition_duration_ms),
                    configured_transition_deadline_ms: Some(
                        plan.watchdog.level_transition_timeout_ms,
                    ),
                    sample: None,
                },
            )))?;
            if !touched_ack_allows_hold(
                acknowledgement.actual_touched_bytes,
                level.target_touched_bytes,
            ) {
                final_state = PressureRunState::Invalid;
                reason = "worker touched-byte contract mismatch".into();
                let observed = LevelGateObservations {
                    worker_alive: process_start_ticks(pid).ok() == Some(start_ticks),
                    worker_identity: acknowledgement.worker_pid == pid
                        && acknowledgement.worker_start_ticks == start_ticks,
                    heartbeat_fresh: false,
                    worker_integrity: false,
                    cgroup_membership: fs::read_to_string(format!("/proc/{pid}/cgroup"))
                        .is_ok_and(|membership| membership.contains(&scope.control_group)),
                    memory_limit_contract: scalar(&cgroup.join("memory.max"))
                        == Some(plan.worker_memory_max_bytes),
                    host_psi: true,
                    cgroup_psi: true,
                    major_faults: false,
                    swap_in: false,
                    swap_out: false,
                    block_writes: false,
                    worker_cpu: process_cpu_ticks(pid).is_some(),
                    runner_cpu: process_cpu_ticks(std::process::id()).is_some(),
                    observer_contract: planned.variant == crate::BenchmarkVariant::CachyosBaseline
                        || observer.is_some(),
                    elapsed_duration: false,
                };
                let started = acknowledgement.acknowledged_monotonic_ns;
                let payload_integrity_identity = acknowledgement.integrity_identity.clone();
                let invalid = LevelEvidence {
                    version: crate::pressure::LEVEL_EVIDENCE_VERSION,
                    experiment_id: payload.experiment_id.clone(),
                    run_id: run_id.clone(),
                    variant: planned.variant,
                    repetition_index: planned.repetition_index,
                    level_index: level.level_index,
                    planned_logical_bytes: level.target_logical_bytes,
                    actual_touched_bytes: acknowledgement.actual_touched_bytes,
                    worker_acknowledgement: acknowledgement,
                    worker_memory_max_bytes: plan.worker_memory_max_bytes,
                    generator_id: plan.generator_id.clone(),
                    generator_version: plan.generator_version,
                    workload_identity: expected_workload_identity.clone(),
                    payload_integrity_identity,
                    started_monotonic_ns: started,
                    ended_monotonic_ns: started.saturating_add(1),
                    stabilization_completed_ms: 0,
                    duration_ms: 0,
                    sample_count: 0,
                    raw_samples: Vec::new(),
                    memory_mean_bytes: None,
                    memory_peak_bytes: None,
                    metrics: Vec::new(),
                    major_fault_delta: None,
                    swap_in_bytes_delta: None,
                    swap_out_bytes_delta: None,
                    block_write_bytes_delta: None,
                    watchdog_triggered: false,
                    oom: 0,
                    oom_kill: 0,
                    health_gates: granular_health_gates(planned.variant, &observed),
                    classification: LevelClassification::InvalidLevelEvidence,
                    safety_abort: None,
                    failure_reason: Some("worker_level_contract_failure".into()),
                };
                invalid.validate(level, plan)?;
                persist_event(PressurePersistenceEvent::Completed(Box::new(invalid)))?;
                break;
            }
            persist_event(PressurePersistenceEvent::Progress(Box::new(
                PressureLevelProgress {
                    level_index: level.level_index,
                    stage: PressureLevelProgressStage::StabilizationStarting,
                    monotonic_ns: timestamp_ns(),
                    target_touched_bytes: level.target_touched_bytes,
                    requested_delta_bytes: acknowledgement.requested_delta_bytes,
                    expected_workload_identity: expected_workload_identity.clone(),
                    acknowledgement: Some(acknowledgement.clone()),
                    transition_duration_ms: Some(transition_duration_ms),
                    configured_transition_deadline_ms: Some(
                        plan.watchdog.level_transition_timeout_ms,
                    ),
                    sample: None,
                },
            )))?;
            thread::sleep(Duration::from_millis(plan.stabilization_duration_ms));
            if Instant::now() >= level_deadline || Instant::now() >= total_deadline {
                final_state = PressureRunState::SafetyAbort;
                reason = "WATCHDOG_TIMEOUT before measurement hold".into();
                break;
            }
            let (version, experiment_id, ipc_run_id, ipc_pid, ipc_ticks) =
                worker_message_identity(&payload.experiment_id, &run_id, pid, start_ticks);
            let first_integrity = client.send_with_timeout(
                &crate::pressure_worker::WorkerIpcMessage::BeginHold {
                    version,
                    experiment_id,
                    run_id: ipc_run_id,
                    pid: ipc_pid,
                    start_ticks: ipc_ticks,
                },
                heartbeat_timeout,
                "BEGIN_HOLD",
            )?;
            persist_event(PressurePersistenceEvent::Progress(Box::new(
                PressureLevelProgress {
                    level_index: level.level_index,
                    stage: PressureLevelProgressStage::HoldStarting,
                    monotonic_ns: timestamp_ns(),
                    target_touched_bytes: level.target_touched_bytes,
                    requested_delta_bytes: acknowledgement.requested_delta_bytes,
                    expected_workload_identity: expected_workload_identity.clone(),
                    acknowledgement: Some(acknowledgement.clone()),
                    transition_duration_ms: Some(transition_duration_ms),
                    configured_transition_deadline_ms: Some(
                        plan.watchdog.level_transition_timeout_ms,
                    ),
                    sample: None,
                },
            )))?;
            if !matches!(
                first_integrity,
                crate::pressure_worker::WorkerIpcMessage::IntegrityResult { .. }
            ) {
                bail!("worker integrity result missing at hold start");
            }
            let _initial_heartbeat =
                client.receive_with_timeout(heartbeat_timeout, "BEGIN_HOLD heartbeat")?;
            let measurement_start = Instant::now();
            let mut memory_values = Vec::new();
            let mut peak = 0;
            let mut sample_count = 0usize;
            let mut raw_samples = Vec::new();
            while measurement_start.elapsed() < Duration::from_millis(plan.hold_duration_ms) {
                if Instant::now() >= level_deadline || Instant::now() >= total_deadline {
                    bail!("pressure worker IPC timeout/failure during level lifecycle watchdog");
                }
                thread::sleep(Duration::from_millis(plan.sample_interval_ms));
                let (version, experiment_id, ipc_run_id, ipc_pid, ipc_ticks) =
                    worker_message_identity(&payload.experiment_id, &run_id, pid, start_ticks);
                let heartbeat = client.send_with_timeout(
                    &crate::pressure_worker::WorkerIpcMessage::HeartbeatRequest {
                        version,
                        experiment_id,
                        run_id: ipc_run_id,
                        pid: ipc_pid,
                        start_ticks: ipc_ticks,
                    },
                    heartbeat_timeout,
                    "HEARTBEAT",
                )?;
                let heartbeat_touched = match heartbeat {
                    crate::pressure_worker::WorkerIpcMessage::Heartbeat {
                        touched_bytes, ..
                    } if touched_bytes == level.target_touched_bytes => touched_bytes,
                    _ => bail!("worker heartbeat identity or touched total mismatch"),
                };
                let integrity_identity = match client
                    .receive_with_timeout(heartbeat_timeout, "INTEGRITY_RESULT")?
                {
                    crate::pressure_worker::WorkerIpcMessage::IntegrityResult {
                        identity, ..
                    } => Some(identity),
                    _ => bail!("worker integrity result missing during hold"),
                };
                let memory_current = scalar(&cgroup.join("memory.current"));
                if let Some(current) = memory_current {
                    memory_values.push(current);
                    peak = peak.max(current);
                }
                let host_full = fs::read_to_string("/proc/pressure/memory")
                    .ok()
                    .and_then(|value| crate::parse_psi(&value).ok())
                    .and_then(|psi| psi.full.map(|full| full.avg10));
                let cgroup_full = fs::read_to_string(cgroup.join("memory.pressure"))
                    .ok()
                    .and_then(|value| crate::parse_psi(&value).ok())
                    .and_then(|psi| psi.full.map(|full| full.avg10));
                let sample = crate::pressure::PressureLevelSample {
                    monotonic_ns: timestamp_ns(),
                    memory_current_bytes: memory_current,
                    host_memory_full_avg10_percent: host_full,
                    cgroup_memory_full_avg10_percent: cgroup_full,
                    worker_alive: process_start_ticks(pid).ok() == Some(start_ticks),
                    heartbeat_touched_bytes: heartbeat_touched,
                    integrity_identity,
                };
                raw_samples.push(sample.clone());
                sample_count += 1;
                persist_event(PressurePersistenceEvent::Progress(Box::new(
                    PressureLevelProgress {
                        level_index: level.level_index,
                        stage: PressureLevelProgressStage::Sampling,
                        monotonic_ns: sample.monotonic_ns,
                        target_touched_bytes: level.target_touched_bytes,
                        requested_delta_bytes: acknowledgement.requested_delta_bytes,
                        expected_workload_identity: expected_workload_identity.clone(),
                        acknowledgement: Some(acknowledgement.clone()),
                        transition_duration_ms: Some(transition_duration_ms),
                        configured_transition_deadline_ms: Some(
                            plan.watchdog.level_transition_timeout_ms,
                        ),
                        sample: Some(sample),
                    },
                )))?;
            }
            let ended = measurement_start.elapsed();
            let events = counter_map(&cgroup.join("memory.events")).unwrap_or_default();
            let oom = events.get("oom").copied().unwrap_or(0);
            let oom_kill = events.get("oom_kill").copied().unwrap_or(0);
            let host_oom_after = counter_map(Path::new("/proc/vmstat"))
                .ok()
                .and_then(|values| values.get("oom_kill").copied());
            let host_oom_delta = host_oom_before
                .zip(host_oom_after)
                .and_then(|(before, after)| after.checked_sub(before));
            let vm_after = counter_map(Path::new("/proc/vmstat")).ok();
            let major_fault_delta = relative_counter(
                major_fault_before,
                vm_after
                    .as_ref()
                    .and_then(|values| values.get("pgmajfault").copied()),
            );
            let swap_in_bytes_delta = relative_counter(
                swap_in_before,
                vm_after
                    .as_ref()
                    .and_then(|values| values.get("pswpin").copied()),
            )
            .and_then(|pages| pages.checked_mul(4096));
            let swap_out_bytes_delta = relative_counter(
                swap_out_before,
                vm_after
                    .as_ref()
                    .and_then(|values| values.get("pswpout").copied()),
            )
            .and_then(|pages| pages.checked_mul(4096));
            let block_write_bytes_delta = relative_counter(block_write_before, block_write_bytes());
            let worker_cpu_delta = relative_counter(worker_cpu_before, process_cpu_ticks(pid));
            let runner_cpu_delta =
                relative_counter(runner_cpu_before, process_cpu_ticks(std::process::id()));
            let host_psi_healthy = raw_samples.iter().all(|sample| {
                sample.host_memory_full_avg10_percent.is_some_and(|value| {
                    !crate::pressure::psi_avg10_threshold_crossed(
                        value,
                        plan.health.host_psi_full_avg10_emergency,
                    )
                    .unwrap_or(true)
                })
            });
            let cgroup_psi_healthy = raw_samples.iter().all(|sample| {
                sample
                    .cgroup_memory_full_avg10_percent
                    .is_some_and(|value| {
                        !crate::pressure::psi_avg10_threshold_crossed(
                            value,
                            plan.health.cgroup_psi_full_avg10_unsustainable,
                        )
                        .unwrap_or(true)
                    })
            });
            let runtime_healthy = major_fault_delta
                .is_some_and(|value| value <= plan.health.max_major_faults_per_level)
                && swap_in_bytes_delta
                    .is_some_and(|value| value <= plan.health.max_swap_in_bytes_per_level)
                && swap_out_bytes_delta
                    .is_some_and(|value| value <= plan.health.max_swap_out_bytes_per_level)
                && block_write_bytes_delta
                    .is_some_and(|value| value <= plan.health.max_block_writes_bytes_per_level);
            let identity_healthy = raw_samples.iter().all(|sample| {
                sample.worker_alive
                    && sample.heartbeat_touched_bytes == level.target_touched_bytes
                    && sample.integrity_identity.is_some()
            });
            let cgroup_membership_healthy = fs::read_to_string(format!("/proc/{pid}/cgroup"))
                .is_ok_and(|membership| membership.contains(&scope.control_group));
            let memory_limit_healthy =
                scalar(&cgroup.join("memory.max")) == Some(plan.worker_memory_max_bytes);
            let observer_contract_healthy =
                planned.variant == crate::BenchmarkVariant::CachyosBaseline || observer.is_some();
            let elapsed_healthy = ended.as_millis() as u64
                >= plan
                    .hold_duration_ms
                    .saturating_sub(plan.sample_interval_ms)
                && sample_count as u64 >= plan.hold_duration_ms.div_ceil(plan.sample_interval_ms);
            let observed = LevelGateObservations {
                worker_alive: raw_samples.iter().all(|sample| sample.worker_alive),
                worker_identity: process_start_ticks(pid).ok() == Some(start_ticks),
                heartbeat_fresh: raw_samples
                    .iter()
                    .all(|sample| sample.heartbeat_touched_bytes == level.target_touched_bytes),
                worker_integrity: raw_samples
                    .iter()
                    .all(|sample| sample.integrity_identity.is_some()),
                cgroup_membership: cgroup_membership_healthy,
                memory_limit_contract: memory_limit_healthy,
                host_psi: host_psi_healthy,
                cgroup_psi: cgroup_psi_healthy,
                major_faults: major_fault_delta
                    .is_some_and(|value| value <= plan.health.max_major_faults_per_level),
                swap_in: swap_in_bytes_delta
                    .is_some_and(|value| value <= plan.health.max_swap_in_bytes_per_level),
                swap_out: swap_out_bytes_delta
                    .is_some_and(|value| value <= plan.health.max_swap_out_bytes_per_level),
                block_writes: block_write_bytes_delta
                    .is_some_and(|value| value <= plan.health.max_block_writes_bytes_per_level),
                worker_cpu: worker_cpu_delta.is_some(),
                runner_cpu: runner_cpu_delta.is_some(),
                observer_contract: observer_contract_healthy,
                elapsed_duration: elapsed_healthy,
            };
            let health_gates = granular_health_gates(planned.variant, &observed);
            let every_health_gate_passed = health_gates
                .values()
                .all(|gate| gate.mandatory && gate.passed);
            let safety_abort = if host_oom_delta.is_some_and(|value| value > 0) {
                Some(SafetyAbortClass::HostOomDetected)
            } else if !host_psi_healthy {
                Some(SafetyAbortClass::HostPsiEmergency)
            } else if !observed.worker_alive || !observed.worker_identity {
                Some(SafetyAbortClass::WorkerIdentityLost)
            } else if !observed.cgroup_membership {
                Some(SafetyAbortClass::CgroupOwnershipLost)
            } else if !observed.memory_limit_contract {
                Some(SafetyAbortClass::MemoryLimitContractBroken)
            } else if !observed.observer_contract {
                Some(SafetyAbortClass::ObserverContractBroken)
            } else {
                None
            };
            let classification = if safety_abort.is_some() {
                LevelClassification::SafetyAbort
            } else if oom > 0
                || oom_kill > 0
                || !runtime_healthy
                || !identity_healthy
                || !every_health_gate_passed
            {
                LevelClassification::UnsustainableHealth
            } else {
                LevelClassification::Sustainable
            };
            let payload_integrity_identity = acknowledgement.integrity_identity.clone();
            let level_evidence = LevelEvidence {
                version: crate::pressure::LEVEL_EVIDENCE_VERSION,
                experiment_id: payload.experiment_id.clone(),
                run_id: run_id.clone(),
                variant: planned.variant,
                repetition_index: planned.repetition_index,
                level_index: level.level_index,
                planned_logical_bytes: level.target_logical_bytes,
                actual_touched_bytes: acknowledgement.actual_touched_bytes,
                worker_acknowledgement: acknowledgement,
                worker_memory_max_bytes: plan.worker_memory_max_bytes,
                generator_id: plan.generator_id.clone(),
                generator_version: plan.generator_version,
                workload_identity: expected_workload_identity,
                payload_integrity_identity,
                started_monotonic_ns: timestamp_ns().saturating_sub(ended.as_nanos() as u64),
                ended_monotonic_ns: timestamp_ns(),
                stabilization_completed_ms: plan.stabilization_duration_ms,
                duration_ms: ended.as_millis().try_into().unwrap_or(u64::MAX),
                sample_count,
                raw_samples,
                memory_mean_bytes: (!memory_values.is_empty())
                    .then(|| memory_values.iter().sum::<u64>() as f64 / memory_values.len() as f64),
                memory_peak_bytes: (!memory_values.is_empty()).then_some(peak),
                metrics: vec![
                    if memory_values.is_empty() {
                        PressureMetric::unavailable(
                            "memory_current",
                            "bytes",
                            PressureMetricScope::WorkerCgroup,
                            "memory.current",
                            "cgroup memory.current was unavailable",
                        )
                    } else {
                        PressureMetric::measured(
                            "memory_current",
                            peak as f64,
                            "bytes",
                            PressureMetricScope::WorkerCgroup,
                            "memory.current",
                        )
                    },
                    PressureMetric::unavailable(
                        "host_oom_log",
                        "events",
                        PressureMetricScope::Host,
                        "/proc/vmstat oom_kill",
                        "counter is host-wide and cannot attribute an event to this run",
                    ),
                ],
                major_fault_delta,
                swap_in_bytes_delta,
                swap_out_bytes_delta,
                block_write_bytes_delta,
                watchdog_triggered: false,
                oom,
                oom_kill,
                health_gates,
                classification,
                safety_abort,
                failure_reason: (classification != LevelClassification::Sustainable)
                    .then(|| format!("{classification:?}")),
            };
            level_evidence.validate(level, plan)?;
            persist_event(PressurePersistenceEvent::Completed(Box::new(
                level_evidence,
            )))?;
            prior = level.target_touched_bytes;
            if classification != LevelClassification::Sustainable {
                final_state = match classification {
                    LevelClassification::Sustainable => PressureRunState::Completed,
                    LevelClassification::UnsustainableHealth => {
                        PressureRunState::UnsustainableBoundary
                    }
                    LevelClassification::InvalidLevelEvidence => PressureRunState::Invalid,
                    LevelClassification::SafetyAbort => PressureRunState::SafetyAbort,
                };
                reason = format!("{classification:?}");
                break;
            }
        }
        Ok(())
    })();
    let _stop_acknowledged = send_stop(
        &mut client,
        &payload.experiment_id,
        &run_id,
        pid,
        start_ticks,
        heartbeat_timeout,
    );
    let child_stopped = wait_child(&mut child, start_ticks, heartbeat_timeout);
    let observer_runtime_directory = observer
        .as_ref()
        .map(|handle| Path::new("/run").join(&handle.plan.runtime_directory));
    let observer_stopped = observer
        .take()
        .map(|handle| handle.stop_and_cleanup().is_ok())
        .unwrap_or(true);
    let worker_absent = child_stopped && process_start_ticks(pid).is_err();
    let pre_stop_state = systemd.read_scope_state(&scope_plan.unit_name);
    let pre_stop_unit_present = pre_stop_state.as_ref().is_ok_and(Option::is_some);
    let ownership_exact = pre_stop_state.as_ref().is_ok_and(|state| {
        state.as_ref().is_none_or(|state| {
            state.unit_name == scope_plan.unit_name
                && state.object_path == scope.object_path
                && state.control_group == scope.control_group
                && state.memory_max == scope_plan.memory_max
                && state.runtime_max_usec == scope_plan.runtime_max_usec
        })
    });
    let pre_stop_members = cgroup_member_count(&cgroup);
    let mut stop_action = initial_scope_stop_action(
        pre_stop_state.is_ok(),
        pre_stop_unit_present,
        ownership_exact,
    );
    let stop_job_result;
    let mut worker_scope_stopped = false;
    if stop_action == PressureScopeStopAction::AlreadyAbsent {
        stop_job_result = Some("not_requested_already_absent".into());
        worker_scope_stopped = already_absent_scope_is_clean(worker_absent, pre_stop_members, true);
    } else if stop_action == PressureScopeStopAction::StopUnitRequested {
        match systemd.stop_owned_scope(&scope_plan) {
            Ok(()) => {
                stop_job_result = Some("done".into());
                worker_scope_stopped = systemd
                    .wait_inactive_or_removed(&scope_plan.unit_name, heartbeat_timeout)
                    .is_ok();
            }
            Err(error)
                if error.to_string().contains("NoSuchUnit")
                    || error.to_string().contains("not loaded") =>
            {
                let reconciled_absent = systemd
                    .read_scope_state(&scope_plan.unit_name)
                    .is_ok_and(|state| state.is_none());
                let reconciled_members = cgroup_member_count(&cgroup);
                if no_such_unit_race_reconciles(
                    worker_absent,
                    reconciled_members,
                    reconciled_absent,
                ) {
                    stop_action = PressureScopeStopAction::StopUnitNoSuchUnitReconciled;
                    stop_job_result = Some("no_such_unit_reconciled".into());
                    worker_scope_stopped = true;
                } else {
                    stop_action = PressureScopeStopAction::StopFailed;
                    stop_job_result = Some(format!("failed: {error:#}"));
                }
            }
            Err(error) => {
                stop_action = PressureScopeStopAction::StopFailed;
                stop_job_result = Some(format!("failed: {error:#}"));
            }
        }
    } else {
        stop_job_result = Some("ownership_ambiguous_stop_not_requested".into());
    }
    let final_scope_state = systemd
        .read_scope_state(&scope_plan.unit_name)
        .ok()
        .flatten();
    let final_active_state = final_scope_state
        .as_ref()
        .map(|state| state.active_state.clone());
    let final_sub_state = final_scope_state
        .as_ref()
        .map(|state| state.sub_state.clone());
    let cgroup_member_count = cgroup_member_count(&cgroup);
    let worker_scope_zero_members = cgroup_member_count == Some(0);
    let removal_started = Instant::now();
    let removal_result = if worker_absent && worker_scope_stopped && worker_scope_zero_members {
        wait_for_transient_scope_removal(heartbeat_timeout, || {
            systemd.unit_exists(&scope_plan.unit_name)
        })
    } else {
        Err(anyhow::anyhow!("scope remained active or membered"))
    };
    let removal_wait_ms = removal_result.as_ref().copied().unwrap_or_else(|_| {
        removal_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    });
    let unit_removed = removal_result.is_ok();
    let classification = if stop_action == PressureScopeStopAction::StopFailed {
        PressureScopeCleanupClassification::StopFailed
    } else if !worker_absent || !worker_scope_stopped || !worker_scope_zero_members {
        PressureScopeCleanupClassification::ActiveOrMembered
    } else if !unit_removed {
        PressureScopeCleanupClassification::TransientScopeRemovalTimeout
    } else {
        PressureScopeCleanupClassification::Clean
    };
    let failure_reason = match classification {
        PressureScopeCleanupClassification::Clean => None,
        PressureScopeCleanupClassification::TransientScopeRemovalTimeout => {
            Some("TRANSIENT_SCOPE_REMOVAL_TIMEOUT".into())
        }
        PressureScopeCleanupClassification::ActiveOrMembered => {
            Some("worker scope remained active or membered".into())
        }
        PressureScopeCleanupClassification::StopFailed => stop_job_result.clone(),
    };
    let _ = fs::remove_file(&socket);
    let observer_runtime_directory_absent = observer_runtime_directory
        .as_ref()
        .is_none_or(|path| !path.exists());
    let cleanup = PressureCleanupEvidence {
        worker_absent,
        pre_stop_unit_present,
        stop_action,
        worker_scope_stopped,
        worker_scope_zero_members,
        worker_scope_absent: unit_removed,
        observer_absent: observer_stopped,
        observer_runtime_directory_absent,
        stop_job_result,
        final_active_state,
        final_sub_state,
        cgroup_member_count,
        unit_removed,
        removal_wait_ms,
        classification,
        failure_reason,
    };
    let workload_error = run_result.err().map(|error| format!("{error:#}"));
    let timed_out = workload_error
        .as_deref()
        .is_some_and(|error| error.contains("pressure worker IPC timeout/failure"));
    if timed_out {
        final_state = PressureRunState::SafetyAbort;
        reason = "WATCHDOG_TIMEOUT during bounded worker IPC".into();
    } else if let Some(error) = workload_error.as_deref() {
        final_state = PressureRunState::Invalid;
        reason = format!("pressure workload/executor error: {error}");
    }
    Ok(PressureBackendRunResult {
        state: final_state,
        reason,
        execution_error: (!timed_out).then_some(workload_error).flatten(),
        cleanup,
    })
}

fn wait_child(child: &mut Child, expected_start_ticks: u64, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    match process_start_ticks(child.id()) {
        Err(_) => return true,
        Ok(actual) if actual != expected_start_ticks => return false,
        Ok(_) => {}
    }
    child.kill().is_ok() && child.wait().is_ok()
}

pub fn classify_level_stop(level: &LevelEvidence) -> PressureRunState {
    match level.classification {
        LevelClassification::Sustainable => PressureRunState::Completed,
        LevelClassification::UnsustainableHealth => PressureRunState::UnsustainableBoundary,
        LevelClassification::InvalidLevelEvidence => PressureRunState::Invalid,
        LevelClassification::SafetyAbort => PressureRunState::SafetyAbort,
    }
}

pub fn emergency_order_is_safe(emergency: bool) -> bool {
    let order = next_level_action_order(emergency);
    order.first() == Some(&PressureExecutorAction::CheckEmergencyGates)
        && (!emergency || !order.contains(&PressureExecutorAction::IssueNextLevel))
}

pub fn distinguish_oom(
    host_oom_delta: Option<u64>,
    cgroup_oom_delta: Option<u64>,
) -> Option<SafetyAbortClass> {
    if host_oom_delta.is_some_and(|value| value > 0) {
        Some(SafetyAbortClass::HostOomDetected)
    } else {
        let _ = cgroup_oom_delta;
        None
    }
}

pub fn pressure_manifest_file_sha256(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(material: &str, available: u64, uid: u32) -> PressurePreflightHost {
        PressurePreflightHost {
            material_environment_hash: material.into(),
            current_available_memory_bytes: available,
            foreign_nemord_clear: true,
            benchmark_transient_units_clear: true,
            cgroup_memory_controller_available: true,
            host_psi_available: true,
            cgroup_psi_supported: true,
            observer_contract_supported: true,
            output_fresh: true,
            effective_uid: uid,
            current_runner_identity_verified: true,
            release_binary_provenance_verified: true,
        }
    }

    fn manifest_fixture() -> PreparedPressureManifest {
        let value = serde_json::json!({
            "payload": {
                "schema_version": 5,
                "experiment_id": "checkpoint3c-test",
                "scenario": "progressive_memory_pressure",
                "scenario_version": 1,
                "comparison_purpose": "pressure_framework_validation",
                "generator_id": "nemor.synthetic.splitmix64",
                "generator_version": 1,
                "provenance": {
                    "git_head":"head","git_dirty":false,"source_state_id":"source",
                    "binary_sha256":"runner","build_profile":"release",
                    "benchmark_schema_version":1,"development_build":false
                },
                "runner_binary":{"path_role":"nemor_benchmark","sha256":"runner","build_profile":"release","source_state_id":"source","embedded_git_head":"head"},
                "observer_binary":{"path_role":"nemord","sha256":"observer","build_profile":"release","source_state_id":"source","embedded_git_head":"head"},
                "worker_implementation_identity":"worker",
                "worker_protocol_version":1,
                "pressure_executor_schema_version":3,
                "worker_executable_path":"/runner",
                "config_sha256":"config",
                "environment":{
                    "schema_version":1,"nemor_commit":"head","nemor_version":"0",
                    "config_hash":"config","kernel_release":"k","distro_id":"d",
                    "distro_version":"v","cpu_model":"c","logical_cpus":1,
                    "total_ram_bytes":10000,"swap_topology":[],"zram_inventory":[],
                    "zswap_state":"off","root_filesystem":"x","storage_class":"x",
                    "gpu_identity":null,"cgroup_v2":true,"psi":true,"damon":false,
                    "ksm":false,"ksm_run":null,"cpu_governor":null,"power_profile":null,
                    "thermal_sensor_available":false,"energy_provider":null,
                    "thermal_state_unverified":true
                },
                "environment_hash":"full","material_environment_schema_version":1,
                "material_environment_hash":"material","performance_source_eligible":true,
                "preparing_uid":1000,"preparing_gid":1000,
                "repository":"/repo","config_path":"/config","runner_path":"/runner",
                "observer_path":"/observer","prepared_root":"/prepared","output_root":"/output",
                "database_path":"/output/experiment.sqlite","report_path":"/output/experiment.json",
                "runs_path":"/output/runs","input_available_memory_bytes":10000,
                "headroom_policy":{"host_reserve_permille":100,"minimum_host_reserve_bytes":100,
                    "runner_reserve_bytes":100,"observer_reserve_bytes":100,
                    "rollback_cleanup_reserve_bytes":100,"operating_system_variance_bytes":100},
                "headroom":{"host_bytes":1000,"runner_bytes":100,"observer_bytes":100,
                    "rollback_cleanup_bytes":100,"operating_system_variance_bytes":100,
                    "total_reserved_bytes":1400,"effective_maximum_bytes":8600},
                "pilot_policy":{"version":1,"fractions_permille":[100,200,300],
                    "alignment_bytes":1,"refinement_mode":"disabled_for_framework_pilot"},
                "memory_max_derivation":{"highest_target_bytes":2500,"worker_margin_bytes":500,
                    "alignment_bytes":1,"shared_memory_max_bytes":3000},
                "run_plan":{"version":1,"repetitions":3,"experiment_seed":1,"runs":[],"automatic_retry":false},
                "pressure_plans":[],"expected_level_workload_identities":[],
                "observer_property_contract_version":2,"observer_runs":[],
                "capacity_gain_percent":"not_evaluated","search_complete":false,
                "preparation_audit":{"privileged_operations":0,"systemd_units_started":0,
                    "cgroup_writes":0,"workload_bytes_allocated":0,"observer_processes_started":0}
            },
            "payload_sha256":"unused"
        });
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn user_and_root_preflight_differ_only_in_authorization() {
        let manifest = manifest_fixture();
        let user = evaluate_pressure_preflight(&manifest, &host("material", 5_000, 1000));
        let root = evaluate_pressure_preflight(&manifest, &host("material", 5_000, 0));
        let mut normalized = root.clone();
        normalized.current_identity_authorized = false;
        assert_eq!(user, normalized);
        assert!(!user.current_identity_authorized);
        assert!(root.current_identity_authorized);
        assert!(!user.preflight_mutated);
    }

    #[test]
    fn volatile_available_memory_need_not_equal_snapshot_but_must_be_safe() {
        let manifest = manifest_fixture();
        let report = evaluate_pressure_preflight(&manifest, &host("material", 5_000, 0));
        assert_ne!(
            report.current_available_memory_bytes,
            report.preparation_available_memory_bytes
        );
        assert!(report.current_headroom_sufficient);
        let low = evaluate_pressure_preflight(&manifest, &host("material", 4_399, 0));
        assert!(!low.current_headroom_sufficient);
    }

    #[test]
    fn material_foreign_unit_and_output_fail_independently() {
        let manifest = manifest_fixture();
        let mut snapshot = host("stale", 5_000, 0);
        let report = evaluate_pressure_preflight(&manifest, &snapshot);
        assert!(!report.material_environment_match);
        snapshot.material_environment_hash = "material".into();
        snapshot.foreign_nemord_clear = false;
        assert!(!evaluate_pressure_preflight(&manifest, &snapshot).foreign_nemord_clear);
        snapshot.foreign_nemord_clear = true;
        snapshot.benchmark_transient_units_clear = false;
        assert!(!evaluate_pressure_preflight(&manifest, &snapshot).benchmark_transient_units_clear);
        snapshot.benchmark_transient_units_clear = true;
        snapshot.output_fresh = false;
        assert!(!evaluate_pressure_preflight(&manifest, &snapshot).output_fresh);
    }

    #[test]
    fn host_and_cgroup_oom_are_distinct() {
        assert_eq!(
            distinguish_oom(Some(1), Some(1)),
            Some(SafetyAbortClass::HostOomDetected)
        );
        assert_eq!(distinguish_oom(Some(0), Some(1)), None);
        assert_eq!(distinguish_oom(None, Some(1)), None);
    }

    #[test]
    fn emergency_always_precedes_next_level() {
        assert!(emergency_order_is_safe(true));
        assert!(emergency_order_is_safe(false));
        assert_eq!(
            next_level_action_order(true),
            [
                PressureExecutorAction::CheckEmergencyGates,
                PressureExecutorAction::PersistCompletedLevel,
                PressureExecutorAction::ExactOwnedCleanup
            ]
        );
    }

    #[test]
    fn pressure_manifest_type_does_not_parse_fixed_load_shape() {
        let fixed = serde_json::json!({"payload":{"plan":{"scenario":"synthetic_incompressible"}}});
        assert!(serde_json::from_value::<PreparedPressureManifest>(fixed).is_err());
    }

    #[test]
    fn historical_v3_pressure_manifest_is_not_reinterpreted_as_current_evidence() {
        let mut historical = manifest_fixture();
        historical.payload.schema_version = 3;
        historical.payload.pressure_executor_schema_version = 1;
        historical.payload_sha256 = hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&historical.payload).unwrap(),
        ));
        assert!(historical.verify_payload().is_err());
    }

    #[test]
    fn historical_v4_pressure_manifest_remains_immutable_incomplete_evidence() {
        let mut historical = manifest_fixture();
        historical.payload.schema_version = 4;
        historical.payload.pressure_executor_schema_version = 2;
        historical.payload_sha256 = hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&historical.payload).unwrap(),
        ));
        assert!(historical.verify_payload().is_err());
        let evidence = PressureExecutionEvidence {
            schema_version: 2,
            experiment_id: "checkpoint3c-1785315276506307352".into(),
            state: PressureExperimentState::SafetyAbort,
            runs: Vec::new(),
            execution_error: Some("transition watchdog".into()),
            search_complete: false,
            capacity_gain_percent: EvaluationState::NotEvaluated,
        };
        assert!(!evidence.search_complete);
        assert_eq!(
            evidence.capacity_gain_percent,
            EvaluationState::NotEvaluated
        );
        assert_ne!(pressure_execution_exit_status(evidence.state), 0);
    }

    fn identity_fixture() -> (tempfile::TempDir, PreparedPressureManifest, PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let runner = temporary.path().join("nemor-benchmark");
        fs::copy(std::env::current_exe().unwrap(), &runner).unwrap();
        let sha = hex::encode(Sha256::digest(fs::read(&runner).unwrap()));
        let mut manifest = manifest_fixture();
        manifest.payload.runner_path = runner.clone();
        manifest.payload.worker_executable_path = runner.clone();
        manifest.payload.runner_binary.sha256 = sha.clone();
        manifest.payload.provenance.binary_sha256 = sha;
        manifest.payload.runner_binary.embedded_git_head = "frozen-head".into();
        manifest.payload.provenance.git_head = "frozen-head".into();
        manifest.payload.runner_binary.build_profile = "release".into();
        manifest.payload.provenance.build_profile = "release".into();
        manifest.payload.provenance.git_dirty = false;
        manifest.payload.provenance.development_build = false;
        manifest.payload.provenance.benchmark_schema_version = crate::BENCHMARK_SCHEMA_VERSION;
        (temporary, manifest, runner)
    }

    #[test]
    fn current_executable_frozen_identity_passes_and_is_spawn_source() {
        let (_temporary, manifest, runner) = identity_fixture();
        verify_current_runner_identity_at(
            &manifest,
            &runner,
            "frozen-head",
            "release",
            crate::BENCHMARK_SCHEMA_VERSION,
        )
        .unwrap();
        assert_eq!(
            pressure_worker_executable(&manifest).unwrap(),
            runner.canonicalize().unwrap()
        );
    }

    #[test]
    fn current_executable_path_or_sha_mismatch_fails() {
        let (temporary, mut manifest, runner) = identity_fixture();
        let other = temporary.path().join("other-runner");
        fs::copy(&runner, &other).unwrap();
        assert!(verify_current_runner_identity_at(
            &manifest,
            &other,
            "frozen-head",
            "release",
            crate::BENCHMARK_SCHEMA_VERSION,
        )
        .is_err());
        manifest.payload.runner_binary.sha256 = "00".repeat(32);
        assert!(verify_current_runner_identity_at(
            &manifest,
            &runner,
            "frozen-head",
            "release",
            crate::BENCHMARK_SCHEMA_VERSION,
        )
        .is_err());
    }

    #[test]
    fn readiness_and_release_provenance_require_current_runner_gate() {
        let manifest = manifest_fixture();
        let mut snapshot = host("material", 5_000, 0);
        snapshot.current_runner_identity_verified = false;
        let report = evaluate_pressure_preflight(&manifest, &snapshot);
        assert!(!report.current_runner_identity_verified);
        assert!(!report.execution_ready_except_authorization);
        snapshot.current_runner_identity_verified = true;
        snapshot.release_binary_provenance_verified = false;
        let report = evaluate_pressure_preflight(&manifest, &snapshot);
        assert!(!report.release_binary_provenance_verified);
        assert!(!report.execution_ready_except_authorization);
    }

    #[test]
    fn touched_byte_mismatch_never_enters_hold() {
        assert!(touched_ack_allows_hold(4096, 4096));
        assert!(!touched_ack_allows_hold(4095, 4096));
    }

    #[test]
    fn granular_health_gates_preserve_individual_results() {
        let observed = LevelGateObservations {
            worker_alive: true,
            worker_identity: true,
            heartbeat_fresh: true,
            worker_integrity: false,
            cgroup_membership: true,
            memory_limit_contract: true,
            host_psi: true,
            cgroup_psi: false,
            major_faults: true,
            swap_in: true,
            swap_out: true,
            block_writes: false,
            worker_cpu: true,
            runner_cpu: true,
            observer_contract: true,
            elapsed_duration: true,
        };
        let gates = granular_health_gates(crate::BenchmarkVariant::NemorObserve, &observed);
        assert!(gates[&HealthGate::WorkerAlive].passed);
        assert!(!gates[&HealthGate::WorkerIntegrity].passed);
        assert!(!gates[&HealthGate::CgroupPsi].passed);
        assert!(!gates[&HealthGate::BlockWrites].passed);
        assert!(gates[&HealthGate::ObserverContract].passed);
    }

    struct RestoreFailureBackend {
        calls: usize,
    }

    impl PressureExecutionBackend for RestoreFailureBackend {
        fn execute_run(
            &mut self,
            _manifest: &PreparedPressureManifest,
            _order_index: usize,
            _persist_level: &mut dyn FnMut(PressurePersistenceEvent) -> Result<()>,
        ) -> Result<PressureBackendRunResult> {
            self.calls += 1;
            Ok(PressureBackendRunResult {
                state: PressureRunState::Completed,
                reason: "simulated".into(),
                execution_error: None,
                cleanup: PressureCleanupEvidence::simulated(false),
            })
        }
    }

    #[test]
    fn restore_failure_persists_and_blocks_next_run_without_retry() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        fs::create_dir(&output).unwrap();
        let mut manifest = manifest_fixture();
        manifest.payload.output_root = output.clone();
        manifest.payload.report_path = output.join("experiment.json");
        manifest.payload.database_path = output.join("experiment.sqlite");
        manifest.payload.runs_path = output.join("runs");
        manifest.payload.run_plan.runs = (0..6)
            .map(|order_index| PlannedPressureRun {
                order_index,
                variant: if order_index % 2 == 0 {
                    crate::BenchmarkVariant::CachyosBaseline
                } else {
                    crate::BenchmarkVariant::NemorObserve
                },
                repetition_index: order_index / 2,
                run_seed: 100 + (order_index / 2) as u64,
                state: PressureRunState::Planned,
            })
            .collect();
        let store = IncrementalPressureStore::create(&manifest).unwrap();
        let mut backend = RestoreFailureBackend { calls: 0 };
        let evidence = execute_pressure_with_backend(&manifest, &mut backend, &store).unwrap();
        assert_eq!(backend.calls, 1);
        assert_eq!(evidence.state, PressureExperimentState::SafetyAbort);
        assert_eq!(evidence.runs[0].state, PressureRunState::SafetyAbort);
        assert!(evidence.runs[1..]
            .iter()
            .all(|run| run.state == PressureRunState::NotExecutedAfterStop));
        let persisted: PressureExecutionEvidence =
            serde_json::from_slice(&fs::read(&manifest.payload.report_path).unwrap()).unwrap();
        assert_eq!(persisted.state, PressureExperimentState::SafetyAbort);
    }

    struct OutcomeBackend {
        calls: usize,
        execution_error: Option<String>,
        cleanup_passes: bool,
        before: StructuralSnapshot,
        after: StructuralSnapshot,
        snapshots: usize,
    }

    impl PressureExecutionBackend for OutcomeBackend {
        fn execute_run(
            &mut self,
            _manifest: &PreparedPressureManifest,
            _order_index: usize,
            _persist_level: &mut dyn FnMut(PressurePersistenceEvent) -> Result<()>,
        ) -> Result<PressureBackendRunResult> {
            self.calls += 1;
            Ok(PressureBackendRunResult {
                state: PressureRunState::Completed,
                reason: "simulated workload result".into(),
                execution_error: self.execution_error.clone(),
                cleanup: PressureCleanupEvidence::simulated(self.cleanup_passes),
            })
        }

        fn structural_snapshot(&mut self) -> StructuralSnapshot {
            let result = if self.snapshots == 0 {
                self.before.clone()
            } else {
                self.after.clone()
            };
            self.snapshots += 1;
            result
        }
    }

    fn runnable_manifest(temporary: &tempfile::TempDir) -> PreparedPressureManifest {
        let output = temporary.path().join("output");
        fs::create_dir(&output).unwrap();
        let mut manifest = manifest_fixture();
        manifest.payload.output_root = output.clone();
        manifest.payload.report_path = output.join("experiment.json");
        manifest.payload.database_path = output.join("experiment.sqlite");
        manifest.payload.runs_path = output.join("runs");
        manifest.payload.run_plan.runs = (0..6)
            .map(|order_index| PlannedPressureRun {
                order_index,
                variant: if order_index % 2 == 0 {
                    crate::BenchmarkVariant::CachyosBaseline
                } else {
                    crate::BenchmarkVariant::NemorObserve
                },
                repetition_index: order_index / 2,
                run_seed: 100 + (order_index / 2) as u64,
                state: PressureRunState::Planned,
            })
            .collect();
        manifest
    }

    #[test]
    fn structural_mismatch_blocks_next_run_even_after_successful_cleanup() {
        let temporary = tempfile::tempdir().unwrap();
        let manifest = runnable_manifest(&temporary);
        let before = StructuralSnapshot::capture();
        let mut after = before.clone();
        after.zswap_enabled = Some("structural-mismatch".into());
        let mut backend = OutcomeBackend {
            calls: 0,
            execution_error: None,
            cleanup_passes: true,
            before,
            after,
            snapshots: 0,
        };
        let store = IncrementalPressureStore::create(&manifest).unwrap();
        let evidence = execute_pressure_with_backend(&manifest, &mut backend, &store).unwrap();
        assert_eq!(backend.calls, 1);
        assert_eq!(evidence.state, PressureExperimentState::SafetyAbort);
        assert!(!evidence.runs[0].restore_passed.unwrap());
    }

    #[test]
    fn execution_error_retains_cleanup_success_or_escalates_cleanup_failure() {
        for cleanup_passes in [true, false] {
            let temporary = tempfile::tempdir().unwrap();
            let manifest = runnable_manifest(&temporary);
            let snapshot = StructuralSnapshot::capture();
            let mut backend = OutcomeBackend {
                calls: 0,
                execution_error: Some("simulated IPC failure".into()),
                cleanup_passes,
                before: snapshot.clone(),
                after: snapshot,
                snapshots: 0,
            };
            let store = IncrementalPressureStore::create(&manifest).unwrap();
            let evidence = execute_pressure_with_backend(&manifest, &mut backend, &store).unwrap();
            assert_eq!(backend.calls, 1);
            assert_eq!(
                evidence.state,
                if cleanup_passes {
                    PressureExperimentState::ExecutionError
                } else {
                    PressureExperimentState::SafetyAbort
                }
            );
            assert_eq!(evidence.runs[0].restore_passed, Some(cleanup_passes));
            let reason = evidence.runs[0].stop_reason.as_deref().unwrap();
            assert!(reason.contains("simulated IPC failure"));
            if !cleanup_passes {
                assert!(reason.contains("RESTORE_FAILURE"));
                assert!(reason.contains("simulated cleanup failure"));
            }
        }
    }

    #[test]
    fn pressure_cli_status_is_zero_only_for_completed_framework_validation() {
        assert_eq!(
            pressure_execution_exit_status(PressureExperimentState::CompletedFrameworkValidation),
            0
        );
        for state in [
            PressureExperimentState::RejectedBeforeRun0,
            PressureExperimentState::InvalidRun,
            PressureExperimentState::UnsustainableHealth,
            PressureExperimentState::SafetyAbort,
            PressureExperimentState::ExecutionError,
        ] {
            assert_ne!(pressure_execution_exit_status(state), 0);
        }
    }

    #[test]
    fn bounded_scope_gc_wait_accepts_eventual_removal() {
        let mut observations = 0;
        let waited = wait_for_transient_scope_removal(Duration::from_millis(200), || {
            observations += 1;
            Ok(observations < 3)
        })
        .unwrap();
        assert!(observations >= 3);
        assert!(waited <= 200);
    }

    #[test]
    fn bounded_scope_gc_wait_reports_explicit_timeout() {
        let error =
            wait_for_transient_scope_removal(Duration::from_millis(20), || Ok(true)).unwrap_err();
        assert!(format!("{error:#}").contains("TRANSIENT_SCOPE_REMOVAL_TIMEOUT"));
    }

    #[test]
    fn already_absent_scope_requires_absent_worker_and_zero_members() {
        assert!(already_absent_scope_is_clean(true, Some(0), true));
        assert!(!already_absent_scope_is_clean(false, Some(0), true));
        assert!(!already_absent_scope_is_clean(true, Some(1), true));
        assert!(!already_absent_scope_is_clean(true, None, true));
        assert!(!already_absent_scope_is_clean(true, Some(0), false));
    }

    #[test]
    fn no_such_unit_race_reconciles_only_complete_final_absence() {
        assert!(no_such_unit_race_reconciles(true, Some(0), true));
        assert!(!no_such_unit_race_reconciles(true, Some(1), true));
        assert!(!no_such_unit_race_reconciles(false, Some(0), true));
        assert!(!no_such_unit_race_reconciles(true, Some(0), false));
    }

    #[test]
    fn ambiguous_or_unreadable_scope_never_selects_stop_unit() {
        assert_eq!(
            initial_scope_stop_action(true, true, true),
            PressureScopeStopAction::StopUnitRequested
        );
        assert_eq!(
            initial_scope_stop_action(true, false, true),
            PressureScopeStopAction::AlreadyAbsent
        );
        assert_eq!(
            initial_scope_stop_action(true, true, false),
            PressureScopeStopAction::StopFailed
        );
        assert_eq!(
            initial_scope_stop_action(false, true, true),
            PressureScopeStopAction::StopFailed
        );
    }

    #[test]
    fn cleanup_evidence_distinguishes_natural_collection_and_active_stop() {
        let natural = PressureCleanupEvidence {
            worker_absent: true,
            pre_stop_unit_present: false,
            stop_action: PressureScopeStopAction::AlreadyAbsent,
            worker_scope_stopped: true,
            worker_scope_zero_members: true,
            worker_scope_absent: true,
            observer_absent: true,
            observer_runtime_directory_absent: true,
            stop_job_result: Some("not_requested_already_absent".into()),
            final_active_state: None,
            final_sub_state: None,
            cgroup_member_count: Some(0),
            unit_removed: true,
            removal_wait_ms: 0,
            classification: PressureScopeCleanupClassification::Clean,
            failure_reason: None,
        };
        let mut actively_stopped = natural.clone();
        actively_stopped.pre_stop_unit_present = true;
        actively_stopped.stop_action = PressureScopeStopAction::StopUnitRequested;
        actively_stopped.stop_job_result = Some("done".into());
        assert!(natural.passed());
        assert!(actively_stopped.passed());
        assert_ne!(natural.stop_action, actively_stopped.stop_action);
    }

    struct TransitionTimeoutBackend;

    impl PressureExecutionBackend for TransitionTimeoutBackend {
        fn execute_run(
            &mut self,
            _manifest: &PreparedPressureManifest,
            _order_index: usize,
            persist_event: &mut dyn FnMut(PressurePersistenceEvent) -> Result<()>,
        ) -> Result<PressureBackendRunResult> {
            persist_event(PressurePersistenceEvent::Progress(Box::new(
                PressureLevelProgress {
                    level_index: 2,
                    stage: PressureLevelProgressStage::TransitionTimeout,
                    monotonic_ns: 8_001_000_000,
                    target_touched_bytes: 2_130_706_432,
                    requested_delta_bytes: 704_643_072,
                    expected_workload_identity: "frozen-level-2".into(),
                    acknowledgement: None,
                    transition_duration_ms: Some(8_001),
                    configured_transition_deadline_ms: Some(8_000),
                    sample: None,
                },
            )))?;
            Ok(PressureBackendRunResult {
                state: PressureRunState::SafetyAbort,
                reason: "WATCHDOG_TIMEOUT during bounded worker level transition".into(),
                execution_error: None,
                cleanup: PressureCleanupEvidence::simulated(true),
            })
        }
    }

    #[test]
    fn transition_timeout_persists_terminal_progress_and_is_only_safety_abort() {
        let temporary = tempfile::tempdir().unwrap();
        let manifest = runnable_manifest(&temporary);
        let store = IncrementalPressureStore::create(&manifest).unwrap();
        let evidence =
            execute_pressure_with_backend(&manifest, &mut TransitionTimeoutBackend, &store)
                .unwrap();
        assert_eq!(evidence.state, PressureExperimentState::SafetyAbort);
        assert_eq!(
            evidence.runs[0].level_progress[0].stage,
            PressureLevelProgressStage::TransitionTimeout
        );
        assert_eq!(
            evidence.runs[0].level_progress[0].transition_duration_ms,
            Some(8_001)
        );
        assert!(evidence.runs[0].levels.is_empty());
        assert!(!evidence.search_complete);
        assert_eq!(
            evidence.capacity_gain_percent,
            EvaluationState::NotEvaluated
        );
    }

    struct PartialEvidenceBackend;

    impl PressureExecutionBackend for PartialEvidenceBackend {
        fn execute_run(
            &mut self,
            manifest: &PreparedPressureManifest,
            order_index: usize,
            persist_event: &mut dyn FnMut(PressurePersistenceEvent) -> Result<()>,
        ) -> Result<PressureBackendRunResult> {
            let identity = "frozen-pressure-identity".to_string();
            persist_event(PressurePersistenceEvent::Progress(Box::new(
                PressureLevelProgress {
                    level_index: 0,
                    stage: PressureLevelProgressStage::TransitionStarting,
                    monotonic_ns: 1,
                    target_touched_bytes: 4096,
                    requested_delta_bytes: 4096,
                    expected_workload_identity: identity.clone(),
                    acknowledgement: None,
                    transition_duration_ms: None,
                    configured_transition_deadline_ms: Some(8000),
                    sample: None,
                },
            )))?;
            persist_event(PressurePersistenceEvent::Progress(Box::new(
                PressureLevelProgress {
                    level_index: 0,
                    stage: PressureLevelProgressStage::LevelAcknowledged,
                    monotonic_ns: 2,
                    target_touched_bytes: 4096,
                    requested_delta_bytes: 4096,
                    expected_workload_identity: identity,
                    acknowledgement: Some(crate::pressure::WorkerLevelAcknowledgement {
                        experiment_id: manifest.payload.experiment_id.clone(),
                        run_id: format!("run-{order_index}"),
                        level_index: 0,
                        seed: 1,
                        prior_touched_bytes: 0,
                        requested_delta_bytes: 4096,
                        actual_touched_bytes: 4096,
                        worker_pid: 10,
                        worker_start_ticks: 20,
                        generator_id: crate::performance::INCOMPRESSIBLE_GENERATOR_ID.into(),
                        generator_version: crate::performance::SYNTHETIC_GENERATOR_VERSION,
                        integrity_identity: "integrity".into(),
                        acknowledged_monotonic_ns: 2,
                    }),
                    transition_duration_ms: Some(1),
                    configured_transition_deadline_ms: Some(8000),
                    sample: None,
                },
            )))?;
            Ok(PressureBackendRunResult {
                state: PressureRunState::Invalid,
                reason: "pressure workload identity construction failed".into(),
                execution_error: Some("pressure workload identity construction failed".into()),
                cleanup: PressureCleanupEvidence::simulated(true),
            })
        }
    }

    #[test]
    fn partial_transition_and_ack_survive_later_level_construction_error() {
        let temporary = tempfile::tempdir().unwrap();
        let manifest = runnable_manifest(&temporary);
        let store = IncrementalPressureStore::create(&manifest).unwrap();
        let evidence =
            execute_pressure_with_backend(&manifest, &mut PartialEvidenceBackend, &store).unwrap();
        assert_eq!(evidence.state, PressureExperimentState::ExecutionError);
        assert!(evidence.runs[0].levels.is_empty());
        assert_eq!(evidence.runs[0].level_progress.len(), 2);
        assert_eq!(
            evidence.runs[0].level_progress[0].stage,
            PressureLevelProgressStage::TransitionStarting
        );
        assert!(evidence.runs[0].level_progress[1].acknowledgement.is_some());
        let persisted: PressureExecutionEvidence =
            serde_json::from_slice(&fs::read(&manifest.payload.report_path).unwrap()).unwrap();
        assert_eq!(persisted.runs[0].level_progress.len(), 2);
        assert!(persisted.runs[0].levels.is_empty());
    }
}
