//! Checkpoint 3C pressure-only preflight, executor state machine, and evidence.

use crate::observer_service::ObserverServiceBackend;
use crate::performance::{detect_nemord_processes, reject_foreign_nemord};
use crate::pressure::{
    next_level_action_order, required_level_health_gates, HealthGateResult, LevelClassification,
    LevelEvidence, PressureExecutorAction, PressureMetric, PressureMetricScope, SafetyAbortClass,
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

pub const PRESSURE_EXECUTION_SCHEMA_VERSION: u32 = 1;

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PressurePreflightReport {
    pub manifest_verified: bool,
    pub release_binary_provenance_verified: bool,
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
        release_binary_provenance_verified: true,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureRunRecord {
    pub planned: PlannedPressureRun,
    pub state: PressureRunState,
    pub levels: Vec<LevelEvidence>,
    pub structural_before: Option<StructuralSnapshot>,
    pub structural_after: Option<StructuralSnapshot>,
    pub stop_reason: Option<String>,
    pub restore_passed: Option<bool>,
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
        }
        Ok(())
    }
}

pub trait PressureExecutionBackend {
    fn execute_run(
        &mut self,
        manifest: &PreparedPressureManifest,
        order_index: usize,
        persist_level: &mut dyn FnMut(LevelEvidence) -> Result<()>,
    ) -> Result<(PressureRunState, String, bool)>;
}

pub fn execute_pressure_with_backend(
    manifest: &PreparedPressureManifest,
    backend: &mut dyn PressureExecutionBackend,
    store: &IncrementalPressureStore,
) -> Result<PressureExecutionEvidence> {
    let mut evidence = PressureExecutionEvidence::planned(manifest);
    store.persist(&evidence)?;
    for order in 0..evidence.runs.len() {
        evidence.runs[order].structural_before = Some(StructuralSnapshot::capture());
        store.persist(&evidence)?;
        let mut collected = Vec::new();
        let result = backend.execute_run(manifest, order, &mut |level| {
            collected.push(level);
            evidence.runs[order].levels = collected.clone();
            store.persist(&evidence)
        });
        match result {
            Ok((state, reason, restore_passed)) => {
                evidence.runs[order].state = state;
                evidence.runs[order].stop_reason = Some(reason);
                evidence.runs[order].restore_passed = Some(restore_passed);
                evidence.runs[order].structural_after = Some(StructuralSnapshot::capture());
                store.persist(&evidence)?;
                if !restore_passed {
                    evidence.runs[order].state = PressureRunState::SafetyAbort;
                    evidence.runs[order].stop_reason =
                        Some("RESTORE_FAILURE after exact-owned cleanup".into());
                    evidence.state = PressureExperimentState::SafetyAbort;
                    store.persist(&evidence)?;
                    break;
                }
                if matches!(state, PressureRunState::SafetyAbort) {
                    evidence.state = PressureExperimentState::SafetyAbort;
                    break;
                }
                if matches!(state, PressureRunState::Invalid) {
                    evidence.state = PressureExperimentState::InvalidRun;
                    break;
                }
                if matches!(state, PressureRunState::UnsustainableBoundary) {
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
        persist_level: &mut dyn FnMut(LevelEvidence) -> Result<()>,
    ) -> Result<(PressureRunState, String, bool)> {
        execute_real_pressure_run(manifest, order_index, persist_level)
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
) {
    let (version, experiment_id, run_id, pid, start_ticks) =
        worker_message_identity(experiment_id, run_id, pid, start_ticks);
    let _ = client.send(&crate::pressure_worker::WorkerIpcMessage::Stop {
        version,
        experiment_id,
        run_id,
        pid,
        start_ticks,
    });
}

fn execute_real_pressure_run(
    manifest: &PreparedPressureManifest,
    order_index: usize,
    persist_level: &mut dyn FnMut(LevelEvidence) -> Result<()>,
) -> Result<(PressureRunState, String, bool)> {
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
    let run_id = format!(
        "c3c-run-o{}-r{}-{}",
        order_index, planned.repetition_index, payload.experiment_id
    );
    let socket = payload.runs_path.join(format!("worker-{order_index}.sock"));
    if socket.exists() {
        bail!("pressure worker socket collision");
    }
    let executable = std::env::current_exe()?;
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
    let hello = match client.receive() {
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
        let boundary = client.send(&crate::pressure_worker::WorkerIpcMessage::VerifyBoundary {
            version,
            experiment_id,
            run_id: ipc_run_id,
            pid: ipc_pid,
            start_ticks: ipc_ticks,
            memory_max_bytes: plan.worker_memory_max_bytes,
        })?;
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
        for level in &plan.levels {
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
            let (version, experiment_id, ipc_run_id, ipc_pid, ipc_ticks) =
                worker_message_identity(&payload.experiment_id, &run_id, pid, start_ticks);
            let ack_message =
                client.send(&crate::pressure_worker::WorkerIpcMessage::LevelRequest {
                    version,
                    experiment_id,
                    run_id: ipc_run_id,
                    pid: ipc_pid,
                    start_ticks: ipc_ticks,
                    command,
                    monotonic_ns: timestamp_ns(),
                })?;
            let acknowledgement = match ack_message {
                crate::pressure_worker::WorkerIpcMessage::LevelAck {
                    acknowledgement, ..
                } => acknowledgement,
                _ => bail!("worker LEVEL_ACK missing"),
            };
            if acknowledgement.actual_touched_bytes != level.target_touched_bytes {
                final_state = PressureRunState::Invalid;
                reason = "worker touched-byte contract mismatch".into();
            }
            thread::sleep(Duration::from_millis(plan.stabilization_duration_ms));
            let (version, experiment_id, ipc_run_id, ipc_pid, ipc_ticks) =
                worker_message_identity(&payload.experiment_id, &run_id, pid, start_ticks);
            let first_integrity =
                client.send(&crate::pressure_worker::WorkerIpcMessage::BeginHold {
                    version,
                    experiment_id,
                    run_id: ipc_run_id,
                    pid: ipc_pid,
                    start_ticks: ipc_ticks,
                })?;
            if !matches!(
                first_integrity,
                crate::pressure_worker::WorkerIpcMessage::IntegrityResult { .. }
            ) {
                bail!("worker integrity result missing at hold start");
            }
            let _initial_heartbeat = client.receive()?;
            let measurement_start = Instant::now();
            let mut memory_values = Vec::new();
            let mut peak = 0;
            let mut sample_count = 0usize;
            let mut raw_samples = Vec::new();
            while measurement_start.elapsed() < Duration::from_millis(plan.hold_duration_ms) {
                thread::sleep(Duration::from_millis(plan.sample_interval_ms));
                let (version, experiment_id, ipc_run_id, ipc_pid, ipc_ticks) =
                    worker_message_identity(&payload.experiment_id, &run_id, pid, start_ticks);
                let heartbeat = client.send(
                    &crate::pressure_worker::WorkerIpcMessage::HeartbeatRequest {
                        version,
                        experiment_id,
                        run_id: ipc_run_id,
                        pid: ipc_pid,
                        start_ticks: ipc_ticks,
                    },
                )?;
                let heartbeat_touched = match heartbeat {
                    crate::pressure_worker::WorkerIpcMessage::Heartbeat {
                        touched_bytes, ..
                    } if touched_bytes == level.target_touched_bytes => touched_bytes,
                    _ => bail!("worker heartbeat identity or touched total mismatch"),
                };
                let integrity_identity = match client.receive()? {
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
                raw_samples.push(crate::pressure::PressureLevelSample {
                    monotonic_ns: timestamp_ns(),
                    memory_current_bytes: memory_current,
                    host_memory_full_avg10_percent: host_full,
                    cgroup_memory_full_avg10_percent: cgroup_full,
                    worker_alive: process_start_ticks(pid).ok() == Some(start_ticks),
                    heartbeat_touched_bytes: heartbeat_touched,
                    integrity_identity,
                });
                sample_count += 1;
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
            let classification =
                if host_oom_delta.is_some_and(|value| value > 0) || !host_psi_healthy {
                    LevelClassification::SafetyAbort
                } else if acknowledgement.actual_touched_bytes != level.target_touched_bytes {
                    LevelClassification::InvalidLevelEvidence
                } else if oom > 0
                    || oom_kill > 0
                    || !cgroup_psi_healthy
                    || !runtime_healthy
                    || !identity_healthy
                    || worker_cpu_delta.is_none()
                    || runner_cpu_delta.is_none()
                {
                    LevelClassification::UnsustainableHealth
                } else {
                    LevelClassification::Sustainable
                };
            let safety_abort = if host_oom_delta.is_some_and(|value| value > 0) {
                Some(SafetyAbortClass::HostOomDetected)
            } else if !host_psi_healthy {
                Some(SafetyAbortClass::HostPsiEmergency)
            } else {
                None
            };
            let health_gates = required_level_health_gates(planned.variant)
                .into_iter()
                .map(|gate| {
                    (
                        gate,
                        HealthGateResult {
                            passed: classification == LevelClassification::Sustainable,
                            mandatory: true,
                            reason: (classification != LevelClassification::Sustainable)
                                .then(|| "level classification did not pass".into()),
                        },
                    )
                })
                .collect();
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
                workload_identity: crate::performance::workload_identity(
                    &plan.scenario,
                    &plan.generator_id,
                    plan.generator_version,
                    level.seed,
                    level.target_logical_bytes,
                )?,
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
            persist_level(level_evidence)?;
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
    send_stop(
        &mut client,
        &payload.experiment_id,
        &run_id,
        pid,
        start_ticks,
    );
    let child_stopped = wait_child(&mut child, start_ticks, Duration::from_secs(4));
    let observer_stopped = observer
        .take()
        .map(|handle| handle.stop_and_cleanup().is_ok())
        .unwrap_or(true);
    let scope_stopped = systemd
        .stop_owned_scope(&scope_plan)
        .and_then(|_| {
            systemd.wait_inactive_or_removed(&scope_plan.unit_name, Duration::from_secs(4))
        })
        .is_ok();
    let _ = fs::remove_file(&socket);
    run_result?;
    let restore = child_stopped && observer_stopped && scope_stopped;
    Ok((final_state, reason, restore))
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
        }
    }

    fn manifest_fixture() -> PreparedPressureManifest {
        let value = serde_json::json!({
            "payload": {
                "schema_version": 2,
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
                "pressure_executor_schema_version":1,
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
                "pressure_plans":[],"observer_property_contract_version":2,"observer_runs":[],
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

    struct RestoreFailureBackend {
        calls: usize,
    }

    impl PressureExecutionBackend for RestoreFailureBackend {
        fn execute_run(
            &mut self,
            _manifest: &PreparedPressureManifest,
            _order_index: usize,
            _persist_level: &mut dyn FnMut(LevelEvidence) -> Result<()>,
        ) -> Result<(PressureRunState, String, bool)> {
            self.calls += 1;
            Ok((PressureRunState::Completed, "simulated".into(), false))
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
}
