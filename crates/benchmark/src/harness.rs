use crate::systemd::{
    ScopeState, SystemdCapability, SystemdDbusBackend, SystemdOperationFailure,
    SystemdStartEvidence, TransientScopeBackend, TransientScopePlan, UNIT_PREFIX,
};
use crate::{
    collect_read_only_metrics, parse_cgroup_key_values, parse_io_stat, parse_key_u64, parse_psi,
    BuildProvenance, EvidenceKind, MetricValue, StructuralSnapshot, BENCHMARK_SCHEMA_VERSION,
    HARNESS_DEFAULT_WORKER_BYTES, HARNESS_MAX_WORKER_BYTES,
};
use anyhow::{bail, Context, Result};
use common::LoadedConfig;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const CHECKPOINT2_REQUIRED_GATES: [&str; 26] = [
    "systemd_capability",
    "cgroup_memory_capability",
    "headroom",
    "worker_spawned",
    "worker_ready_outside_scope",
    "audit_before_mutation",
    "transient_scope_created",
    "scope_identity_verified",
    "memory_limit_property_verified",
    "control_group_resolved",
    "memory_limit_kernel_verified",
    "owned_child_attached",
    "exclusive_membership",
    "worker_payload_allocated",
    "worker_ready",
    "worker_integrity",
    "metrics_collected",
    "watchdog",
    "no_oom",
    "worker_cleanup",
    "scope_cleanup",
    "owned_unit_absent_final",
    "owned_cgroup_absent_final",
    "owned_process_absent_final",
    "configuration_restored",
    "host_unchanged",
];

const REQUIRED_MEMORY_FILES: [&str; 5] = [
    "memory.max",
    "memory.current",
    "memory.events",
    "memory.stat",
    "memory.pressure",
];

pub fn missing_required_memory_files<'a>(
    present: impl IntoIterator<Item = &'a str>,
) -> Vec<&'static str> {
    let present = present.into_iter().collect::<BTreeSet<_>>();
    REQUIRED_MEMORY_FILES
        .iter()
        .copied()
        .filter(|name| !present.contains(name))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupCapabilityEvidence {
    pub unified_v2: bool,
    pub memory_supported: bool,
    pub candidate_parent_role: String,
    pub parent_type: Option<String>,
    pub parent_populated: Option<bool>,
    pub parent_direct_process_count: Option<usize>,
    pub available_controllers: Vec<String>,
    pub enabled_subtree_controllers: Vec<String>,
    pub memory_enabled_for_children: bool,
    pub parent_usable: bool,
    pub child_memory_interface_expected: bool,
    pub reason: String,
}

impl CgroupCapabilityEvidence {
    pub fn from_values(
        unified_v2: bool,
        parent_type: Option<String>,
        populated: Option<bool>,
        direct_process_count: Option<usize>,
        available: Vec<String>,
        enabled: Vec<String>,
    ) -> Self {
        let memory_supported = available.iter().any(|item| item == "memory");
        let memory_enabled_for_children = enabled.iter().any(|item| item == "memory");
        let domain_valid = parent_type.as_deref() == Some("domain");
        let parent_usable =
            unified_v2 && memory_supported && memory_enabled_for_children && domain_valid;
        let reason = if !unified_v2 {
            "cgroup_v2_unavailable"
        } else if !domain_valid {
            "cgroup_topology_invalid"
        } else if !memory_supported {
            "parent_memory_controller_unavailable"
        } else if !memory_enabled_for_children {
            "parent_memory_controller_not_enabled"
        } else {
            "memory_controller_delegated"
        };
        Self {
            unified_v2,
            memory_supported,
            candidate_parent_role: "current_process_cgroup_leaf".into(),
            parent_type,
            parent_populated: populated,
            parent_direct_process_count: direct_process_count,
            available_controllers: available,
            enabled_subtree_controllers: enabled,
            memory_enabled_for_children,
            parent_usable,
            child_memory_interface_expected: parent_usable,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationDiagnostic {
    pub operation: String,
    pub path_role: String,
    pub error_kind: Option<String>,
    pub errno: Option<i32>,
    pub message: String,
    pub mutation_started: bool,
    pub cleanup_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub systemd_failure: Option<SystemdOperationFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OwnedProcessIdentity {
    pub run_id: String,
    pub pid: u32,
    pub start_ticks: u64,
}

impl OwnedProcessIdentity {
    pub fn stable_key(&self) -> String {
        format!(
            "nemor-benchmark:{}:{}:{}",
            self.run_id, self.pid, self.start_ticks
        )
    }

    pub fn verify(&self) -> Result<()> {
        if read_start_ticks(self.pid) != Some(self.start_ticks) {
            bail!("owned worker PID/start_ticks identity is stale");
        }
        Ok(())
    }
}

pub fn identity_matches(
    expected: &OwnedProcessIdentity,
    observed_pid: u32,
    observed_start_ticks: u64,
) -> bool {
    expected.pid == observed_pid && expected.start_ticks == observed_start_ticks
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupHarnessPlan {
    pub worker_bytes: u64,
    pub memory_max_bytes: u64,
    pub mem_available_bytes: u64,
    pub rollback_reserve_bytes: u64,
    pub minimum_host_reserve_bytes: u64,
    pub parent: PathBuf,
    pub group_name: String,
    pub measurement_ms: u64,
    pub stabilization_ms: u64,
    pub timeout_ms: u64,
    pub oom_requested: bool,
}

impl CgroupHarnessPlan {
    pub fn derive(
        worker_bytes: u64,
        mem_available_bytes: u64,
        total_ram_bytes: u64,
        parent: PathBuf,
        run_id: &str,
    ) -> Result<Self> {
        if worker_bytes == 0 || worker_bytes > HARNESS_MAX_WORKER_BYTES {
            bail!("Checkpoint 2 worker must be within 1..=128 MiB");
        }
        let rollback_reserve_bytes = worker_bytes;
        let minimum_host_reserve_bytes = (total_ram_bytes / 10).max(1024 * 1024 * 1024);
        let required = worker_bytes
            .checked_add(rollback_reserve_bytes)
            .and_then(|value| value.checked_add(minimum_host_reserve_bytes))
            .context("headroom calculation overflow")?;
        if mem_available_bytes <= required {
            bail!("insufficient conservative host headroom");
        }
        let memory_max_bytes = worker_bytes
            .checked_mul(2)
            .context("memory.max calculation overflow")?;
        let suffix: String = run_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(32)
            .collect();
        let group_name = format!("{UNIT_PREFIX}{suffix}.scope");
        crate::systemd::validate_unit_name(&group_name)?;
        Ok(Self {
            worker_bytes,
            memory_max_bytes,
            mem_available_bytes,
            rollback_reserve_bytes,
            minimum_host_reserve_bytes,
            parent,
            group_name,
            measurement_ms: 2_000,
            stabilization_ms: 500,
            timeout_ms: 15_000,
            oom_requested: false,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.oom_requested {
            bail!("Checkpoint 2 cannot request OOM");
        }
        if self.worker_bytes > HARNESS_MAX_WORKER_BYTES
            || self.memory_max_bytes <= self.worker_bytes
            || self.memory_max_bytes > self.worker_bytes.saturating_mul(3)
            || self.measurement_ms == 0
            || self.timeout_ms <= self.measurement_ms + self.stabilization_ms
            || crate::systemd::validate_unit_name(&self.group_name).is_err()
        {
            bail!("unsafe Checkpoint 2 cgroup plan");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessAudit {
    pub benchmark_run_id: String,
    pub audit_id: String,
    pub transaction_id: String,
    pub target_identity: OwnedProcessIdentity,
    pub planned_cgroup: String,
    pub memory_ceiling_bytes: u64,
    pub worker_bytes: u64,
    pub host_headroom_baseline_bytes: u64,
    pub persisted_before_mutation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupSample {
    pub timestamp_ns: u64,
    pub memory_current: Option<u64>,
    pub memory_peak: Option<u64>,
    pub memory_max: Option<u64>,
    pub memory_events: BTreeMap<String, u64>,
    pub memory_stat: BTreeMap<String, u64>,
    pub cpu_stat: BTreeMap<String, u64>,
    pub io_stat: Option<BTreeMap<String, u64>>,
    pub memory_pressure: Option<crate::PsiSnapshot>,
    pub worker_rss_bytes: Option<u64>,
    pub worker_pss_bytes: Option<u64>,
    pub worker_major_faults: Option<u64>,
    pub host_metrics: Vec<MetricValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchdogEvidence {
    pub heartbeat_timeout_ms: u64,
    pub host_psi_full_emergency_threshold: f64,
    pub peak_host_psi_full_avg10: f64,
    pub heartbeat_stalled: bool,
    pub identity_changed: bool,
    pub foreign_pids: Vec<u32>,
    pub memory_expectation_exceeded: bool,
    pub unexpected_oom: bool,
    pub ownership_lost: bool,
    pub unit_disappeared_unexpectedly: bool,
    pub unit_state_invalid: bool,
    pub control_group_changed: bool,
    pub systemd_connection_lost: bool,
    pub systemd_job_failed: bool,
    pub timeout: bool,
    pub triggered: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WatchdogInputs {
    pub heartbeat_age_ms: u64,
    pub heartbeat_timeout_ms: u64,
    pub identity_valid: bool,
    pub observed_pids: BTreeSet<u32>,
    pub expected_pid: u32,
    pub memory_current: u64,
    pub memory_expectation: u64,
    pub oom: u64,
    pub oom_kill: u64,
    pub host_psi_full_avg10: f64,
    pub host_psi_full_emergency_threshold: f64,
    pub ownership_valid: bool,
    pub unit_present: bool,
    pub unit_state_valid: bool,
    pub control_group_stable: bool,
    pub systemd_connection_valid: bool,
    pub systemd_job_failed: bool,
    pub timed_out: bool,
}

pub fn evaluate_watchdog(inputs: &WatchdogInputs) -> WatchdogEvidence {
    let mut result = empty_watchdog(inputs.host_psi_full_emergency_threshold);
    result.heartbeat_timeout_ms = inputs.heartbeat_timeout_ms;
    result.heartbeat_stalled = inputs.heartbeat_age_ms > inputs.heartbeat_timeout_ms;
    result.identity_changed = !inputs.identity_valid;
    result.foreign_pids = inputs
        .observed_pids
        .iter()
        .copied()
        .filter(|pid| *pid != inputs.expected_pid)
        .collect();
    result.memory_expectation_exceeded = inputs.memory_current > inputs.memory_expectation;
    result.unexpected_oom = inputs.oom > 0 || inputs.oom_kill > 0;
    result.peak_host_psi_full_avg10 = inputs.host_psi_full_avg10;
    result.ownership_lost = !inputs.ownership_valid;
    result.unit_disappeared_unexpectedly = !inputs.unit_present;
    result.unit_state_invalid = !inputs.unit_state_valid;
    result.control_group_changed = !inputs.control_group_stable;
    result.systemd_connection_lost = !inputs.systemd_connection_valid;
    result.systemd_job_failed = inputs.systemd_job_failed;
    result.timeout = inputs.timed_out;
    result.reason = if result.heartbeat_stalled {
        Some("heartbeat_timeout".into())
    } else if result.identity_changed {
        Some("child_identity_stale".into())
    } else if !result.foreign_pids.is_empty() {
        Some("foreign_process_in_owned_cgroup".into())
    } else if result.memory_expectation_exceeded {
        Some("memory_current_exceeded_limit".into())
    } else if result.unexpected_oom {
        Some("unexpected_oom".into())
    } else if inputs.host_psi_full_avg10 > inputs.host_psi_full_emergency_threshold {
        Some("host_psi_emergency".into())
    } else if result.ownership_lost {
        Some("cgroup_ownership_lost".into())
    } else if result.unit_disappeared_unexpectedly {
        Some("unit_disappeared_unexpectedly".into())
    } else if result.unit_state_invalid {
        Some("unit_state_invalid".into())
    } else if result.control_group_changed {
        Some("control_group_changed".into())
    } else if result.systemd_connection_lost {
        Some("systemd_connection_lost".into())
    } else if result.systemd_job_failed {
        Some("systemd_job_failed".into())
    } else if result.timeout {
        Some("harness_timeout".into())
    } else {
        None
    };
    result.triggered = result.reason.is_some();
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateState {
    Pass,
    Fail,
    NotEvaluated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessGate {
    pub name: String,
    pub state: GateState,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessOutcome {
    pub required_gates_passed: bool,
    pub failure_class: Option<String>,
    pub failure_reason: Option<String>,
    pub errors: Vec<String>,
    pub exit_code: i32,
}

pub fn finalize_harness(gates: &[HarnessGate]) -> HarnessOutcome {
    let first_failure = CHECKPOINT2_REQUIRED_GATES.iter().find_map(|required| {
        gates
            .iter()
            .find(|gate| gate.name == *required)
            .filter(|gate| gate.state != GateState::Pass)
    });
    match first_failure {
        None => HarnessOutcome {
            required_gates_passed: true,
            failure_class: None,
            failure_reason: None,
            errors: Vec::new(),
            exit_code: 0,
        },
        Some(failure) => {
            let class = if matches!(
                failure.name.as_str(),
                "worker_cleanup"
                    | "scope_cleanup"
                    | "owned_unit_absent_final"
                    | "owned_cgroup_absent_final"
                    | "owned_process_absent_final"
                    | "configuration_restored"
                    | "host_unchanged"
            ) {
                "cleanup_failure"
            } else {
                "safety_failure"
            };
            HarnessOutcome {
                required_gates_passed: false,
                failure_class: Some(class.into()),
                failure_reason: Some(failure.name.clone()),
                errors: vec![format!("{}: {}", failure.name, failure.detail)],
                exit_code: 1,
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupOwnershipEvidence {
    pub mount: PathBuf,
    pub unit_name: String,
    pub unit_object_path: Option<String>,
    pub control_group: Option<String>,
    pub baseline_owned_units: Vec<String>,
    pub final_owned_units: Vec<String>,
    pub exclusive_pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessValidationReport {
    pub benchmark_schema_version: u32,
    pub scenario_version: u32,
    pub evidence_kind: EvidenceKind,
    pub performance_claim_eligible: bool,
    pub provenance: BuildProvenance,
    pub config_hash: String,
    pub run_id: String,
    pub systemd_capability: SystemdCapability,
    pub scope_state: Option<ScopeState>,
    pub start_evidence: Option<SystemdStartEvidence>,
    pub operation_diagnostics: Vec<OperationDiagnostic>,
    pub audit: Option<HarnessAudit>,
    pub plan: CgroupHarnessPlan,
    pub ownership: CgroupOwnershipEvidence,
    pub samples: Vec<CgroupSample>,
    pub sample_count: usize,
    pub wall_seconds: f64,
    pub runner_cpu_seconds: Option<f64>,
    pub worker_cpu_seconds: Option<f64>,
    pub clk_tck: Option<u64>,
    pub watchdog: WatchdogEvidence,
    pub worker_result: Option<WorkerResult>,
    pub baseline: StructuralSnapshot,
    pub final_snapshot: StructuralSnapshot,
    pub structural_restore_passed: bool,
    pub runtime_counter_deltas: BTreeMap<String, i128>,
    pub gates: Vec<HarnessGate>,
    pub outcome: HarnessOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    pub pid: u32,
    pub start_ticks: u64,
    pub allocation_bytes: u64,
    pub setup_wall_seconds: f64,
    pub measurement_wall_seconds: f64,
    pub heartbeat_count: u64,
    pub bounded_integrity_pages_checked: u64,
    pub full_generation_passes: u64,
    pub full_prefault_passes: u64,
    pub full_rewrite_passes_during_measurement: u64,
    pub fingerprint_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerProtocolState {
    Spawned,
    ReadyOutsideScope,
    ScopeAttached,
    Allocate,
    ReadyMeasurement,
    Stop,
    Exited,
}

pub fn worker_transition_allowed(from: WorkerProtocolState, to: WorkerProtocolState) -> bool {
    matches!(
        (from, to),
        (
            WorkerProtocolState::Spawned,
            WorkerProtocolState::ReadyOutsideScope
        ) | (
            WorkerProtocolState::ReadyOutsideScope,
            WorkerProtocolState::ScopeAttached
        ) | (
            WorkerProtocolState::ScopeAttached,
            WorkerProtocolState::Allocate
        ) | (
            WorkerProtocolState::Allocate,
            WorkerProtocolState::ReadyMeasurement
        ) | (
            WorkerProtocolState::ReadyMeasurement,
            WorkerProtocolState::Stop
        ) | (WorkerProtocolState::Stop, WorkerProtocolState::Exited)
    )
}

#[derive(Debug, Clone)]
pub struct HarnessOptions {
    pub config: PathBuf,
    pub database: PathBuf,
    pub report_dir: PathBuf,
    pub worker_bytes: u64,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            config: PathBuf::from("config/default.toml"),
            database: PathBuf::from("/tmp/nemor-phase10-checkpoint2.sqlite"),
            report_dir: PathBuf::from("/tmp/nemor-phase10-checkpoint2-reports"),
            worker_bytes: HARNESS_DEFAULT_WORKER_BYTES,
        }
    }
}

pub fn run_live(options: &HarnessOptions) -> Result<(HarnessValidationReport, PathBuf)> {
    let wall_start = Instant::now();
    let runner_ticks_start = process_cpu_ticks(std::process::id());
    let clk_tck = detect_clk_tck();
    let loaded = LoadedConfig::load(&options.config)?;
    let provenance = BuildProvenance::capture()?;
    let run_id = format!("checkpoint2-{}", now_ns());
    let cgroup_mount = PathBuf::from("/sys/fs/cgroup");
    let mut backend = SystemdDbusBackend::system()?;
    let systemd_capability = backend.capability()?;
    if !systemd_capability.supported {
        bail!(
            "systemd transient scope capability unavailable: {}",
            systemd_capability.reason
        );
    }
    let baseline_owned_units = backend.list_owned_units()?;
    if !baseline_owned_units.is_empty() {
        bail!("pre-existing Nemor benchmark transient unit requires recovery review");
    }
    let meminfo = parse_key_u64(&fs::read_to_string("/proc/meminfo")?);
    let available = meminfo
        .get("MemAvailable")
        .copied()
        .unwrap_or(0)
        .saturating_mul(1024);
    let total = meminfo
        .get("MemTotal")
        .copied()
        .unwrap_or(0)
        .saturating_mul(1024);
    let plan = CgroupHarnessPlan::derive(
        options.worker_bytes,
        available,
        total,
        cgroup_mount.clone(),
        &run_id,
    )?;
    plan.validate()?;
    if options.worker_bytes != HARNESS_DEFAULT_WORKER_BYTES {
        bail!("Checkpoint 2 live validation requires exactly 64 MiB");
    }
    let controllers = fs::read_to_string(cgroup_mount.join("cgroup.controllers"))
        .context("cannot read parent cgroup controllers")?;
    if !controllers.split_whitespace().any(|item| item == "memory") {
        bail!("memory controller is unavailable in the current cgroup parent");
    }
    let baseline = StructuralSnapshot::capture();
    fs::create_dir_all(&options.report_dir)?;
    let control_dir = options.report_dir.join(format!(".control-{run_id}"));
    fs::create_dir(&control_dir)?;
    let mut gates = CHECKPOINT2_REQUIRED_GATES
        .iter()
        .map(|name| HarnessGate {
            name: (*name).into(),
            state: GateState::NotEvaluated,
            detail: "not reached".into(),
        })
        .collect::<Vec<_>>();
    set_gate(
        &mut gates,
        "systemd_capability",
        GateState::Pass,
        "PID 1 systemd, system bus, Manager and StartTransientUnit available",
    );
    set_gate(
        &mut gates,
        "cgroup_memory_capability",
        GateState::Pass,
        "unified cgroup v2 memory controller available",
    );
    set_gate(
        &mut gates,
        "headroom",
        GateState::Pass,
        "dynamic reserve and rollback headroom satisfied",
    );
    let mut child = spawn_worker(options.worker_bytes, &control_dir)?;
    set_gate(
        &mut gates,
        "worker_spawned",
        GateState::Pass,
        "fresh owned worker spawned with minimal memory",
    );
    let mutation_result = run_mutating_sequence(
        &mut backend,
        &mut child,
        &control_dir,
        &plan,
        &loaded.sha256,
        &options.database,
        &provenance,
        &run_id,
        &mut gates,
        loaded.config.pressure.emergency_psi_full_avg10_threshold,
    );
    if cleanup_live(&mut backend, &mut child, &control_dir, &plan, &mut gates).is_err() {
        for name in ["worker_cleanup", "scope_cleanup"] {
            if gates
                .iter()
                .find(|gate| gate.name == name)
                .is_some_and(|gate| gate.state == GateState::NotEvaluated)
            {
                set_gate(
                    &mut gates,
                    name,
                    GateState::Fail,
                    "common cleanup path failed before absence verification",
                );
            }
        }
    }
    let final_snapshot = StructuralSnapshot::capture();
    let exact_unit_absent = backend
        .unit_exists(&plan.group_name)
        .is_ok_and(|exists| !exists);
    let final_owned_units = backend.list_owned_units().unwrap_or_default();
    let final_unit_absent = exact_unit_absent && final_owned_units.is_empty();
    let saved_control_group = read_json::<ScopeState>(&control_dir.join("scope_state.json"))
        .ok()
        .and_then(|state| state.kernel_path().ok())
        .or_else(|| {
            read_json::<SystemdStartEvidence>(&control_dir.join("start_evidence.json"))
                .ok()
                .and_then(|evidence| evidence.control_group)
                .filter(|group| group.starts_with('/') && !group.contains(".."))
                .map(|group| Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/')))
        });
    let final_control_group_absent = saved_control_group
        .as_ref()
        .is_some_and(|path| !path.exists())
        || (saved_control_group.is_none() && final_unit_absent);
    let final_process_absent = child.try_wait()?.is_some();
    set_gate(
        &mut gates,
        "owned_unit_absent_final",
        if final_unit_absent {
            GateState::Pass
        } else {
            GateState::Fail
        },
        "transaction-owned transient unit absent",
    );
    set_gate(
        &mut gates,
        "owned_cgroup_absent_final",
        if final_control_group_absent {
            GateState::Pass
        } else {
            GateState::Fail
        },
        if saved_control_group.is_some() {
            "saved systemd ControlGroup path is absent"
        } else if final_unit_absent {
            "unit absence proves systemd-collected ControlGroup despite no saved path"
        } else {
            "ControlGroup unresolved and unit remains; absence unproven"
        },
    );
    set_gate(
        &mut gates,
        "owned_process_absent_final",
        if final_process_absent {
            GateState::Pass
        } else {
            GateState::Fail
        },
        "owned worker exited",
    );
    let structural_restore_passed = baseline.matches(&final_snapshot);
    set_gate(
        &mut gates,
        "configuration_restored",
        if structural_restore_passed {
            GateState::Pass
        } else {
            GateState::Fail
        },
        "configuration/topology snapshot restored; cumulative counters ignored",
    );
    let cleanup_gates_passed = [
        "worker_cleanup",
        "scope_cleanup",
        "owned_unit_absent_final",
        "owned_cgroup_absent_final",
        "owned_process_absent_final",
    ]
    .into_iter()
    .all(|name| {
        gates
            .iter()
            .find(|gate| gate.name == name)
            .is_some_and(|gate| gate.state == GateState::Pass)
    });
    set_gate(
        &mut gates,
        "host_unchanged",
        if structural_restore_passed && cleanup_gates_passed {
            GateState::Pass
        } else {
            GateState::Fail
        },
        "structural configuration plus transaction-owned resource absence",
    );
    // Keep the mutating-sequence result separate from cleanup: a safety abort can
    // still have a successful, mandatory rollback.
    let _mutation_result = mutation_result;
    let outcome = finalize_harness(&gates);
    let worker_result = read_json::<WorkerResult>(&control_dir.join("result.json")).ok();
    let samples =
        read_json::<Vec<CgroupSample>>(&control_dir.join("samples.json")).unwrap_or_default();
    let audit = read_json::<HarnessAudit>(&control_dir.join("audit.json")).ok();
    let watchdog = read_json::<WatchdogEvidence>(&control_dir.join("watchdog.json"))
        .unwrap_or_else(|_| {
            empty_watchdog(loaded.config.pressure.emergency_psi_full_avg10_threshold)
        });
    let runtime_counter_deltas = baseline.runtime_counter_deltas(&final_snapshot);
    let persisted_start_evidence =
        read_json::<SystemdStartEvidence>(&control_dir.join("start_evidence.json")).ok();
    let persisted_scope_state = read_json::<ScopeState>(&control_dir.join("scope_state.json")).ok();
    let report = HarnessValidationReport {
        benchmark_schema_version: BENCHMARK_SCHEMA_VERSION,
        scenario_version: 1,
        evidence_kind: EvidenceKind::HarnessValidation,
        performance_claim_eligible: false,
        provenance,
        config_hash: loaded.sha256,
        run_id: run_id.clone(),
        systemd_capability,
        scope_state: persisted_scope_state.clone(),
        start_evidence: persisted_start_evidence.clone(),
        operation_diagnostics: read_json(&control_dir.join("operation_errors.json"))
            .unwrap_or_default(),
        audit: audit.clone(),
        plan: plan.clone(),
        ownership: CgroupOwnershipEvidence {
            mount: cgroup_mount,
            unit_name: plan.group_name.clone(),
            unit_object_path: persisted_scope_state
                .as_ref()
                .map(|state| state.object_path.clone())
                .or_else(|| {
                    persisted_start_evidence
                        .as_ref()
                        .and_then(|evidence| evidence.unit_object_path.clone())
                }),
            control_group: persisted_scope_state
                .as_ref()
                .map(|state| state.control_group.clone())
                .or_else(|| {
                    persisted_start_evidence
                        .as_ref()
                        .and_then(|evidence| evidence.control_group.clone())
                }),
            baseline_owned_units,
            final_owned_units,
            exclusive_pid: audit.as_ref().map(|audit| audit.target_identity.pid),
        },
        sample_count: samples.len(),
        wall_seconds: wall_start.elapsed().as_secs_f64(),
        runner_cpu_seconds: clk_tck
            .zip(runner_ticks_start.zip(process_cpu_ticks(std::process::id())))
            .and_then(|(ticks_per_second, (before, after))| {
                after
                    .checked_sub(before)
                    .map(|delta| delta as f64 / ticks_per_second as f64)
            }),
        worker_cpu_seconds: samples
            .first()
            .and_then(|first| first.cpu_stat.get("usage_usec"))
            .zip(
                samples
                    .last()
                    .and_then(|last| last.cpu_stat.get("usage_usec")),
            )
            .and_then(|(before, after)| after.checked_sub(*before))
            .map(|delta| delta as f64 / 1_000_000.0),
        clk_tck,
        samples,
        watchdog,
        worker_result,
        baseline,
        final_snapshot,
        structural_restore_passed,
        runtime_counter_deltas,
        gates,
        outcome,
    };
    let report_path = options.report_dir.join(format!("{run_id}.json"));
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    fs::write(
        "/tmp/nemor-benchmark-validation-report.json",
        serde_json::to_vec_pretty(&report)?,
    )?;
    persist_harness_report(&options.database, &report)?;
    let _ = remove_control_dir(&control_dir);
    Ok((report, report_path))
}

#[allow(clippy::too_many_arguments)]
fn run_mutating_sequence(
    backend: &mut impl TransientScopeBackend,
    child: &mut Child,
    control_dir: &Path,
    plan: &CgroupHarnessPlan,
    config_hash: &str,
    database: &Path,
    provenance: &BuildProvenance,
    run_id: &str,
    gates: &mut [HarnessGate],
    psi_threshold: f64,
) -> Result<()> {
    wait_for_file(
        &control_dir.join("ready_outside.json"),
        Duration::from_secs(5),
    )?;
    let ready: WorkerReady = read_json(&control_dir.join("ready_outside.json"))?;
    if ready.pid != child.id() {
        bail!("worker ready PID mismatch");
    }
    let identity = OwnedProcessIdentity {
        run_id: run_id.into(),
        pid: ready.pid,
        start_ticks: ready.start_ticks,
    };
    identity.verify()?;
    set_gate(
        gates,
        "worker_ready_outside_scope",
        GateState::Pass,
        "exact PID/start_ticks READY outside transient scope",
    );
    let scope_plan = TransientScopePlan::new(run_id, identity.clone())?;
    let audit = HarnessAudit {
        benchmark_run_id: run_id.into(),
        audit_id: format!("audit-{run_id}"),
        transaction_id: format!("transaction-{run_id}"),
        target_identity: identity.clone(),
        planned_cgroup: scope_plan.unit_name.clone(),
        memory_ceiling_bytes: plan.memory_max_bytes,
        worker_bytes: plan.worker_bytes,
        host_headroom_baseline_bytes: plan.mem_available_bytes,
        persisted_before_mutation: true,
    };
    persist_pre_mutation_audit(database, config_hash, provenance, &audit)?;
    write_json_create_new(&control_dir.join("audit.json"), &audit)?;
    set_gate(
        gates,
        "audit_before_mutation",
        GateState::Pass,
        "audit persisted before cgroup creation",
    );

    let scope_result = backend.start_owned_scope(&scope_plan);
    if let Some(evidence) = backend.start_evidence() {
        write_json(&control_dir.join("start_evidence.json"), &evidence)?;
    }
    let scope = match scope_result {
        Ok(scope) => scope,
        Err(error) => {
            let systemd_failure = error.downcast_ref::<SystemdOperationFailure>().cloned();
            let start_evidence = backend.start_evidence();
            let detail = systemd_failure
                .as_ref()
                .map(|failure| failure.error_category.as_str())
                .unwrap_or("start_transient_scope_failed")
                .to_owned();
            let diagnostic = OperationDiagnostic {
                operation: "StartTransientUnit".into(),
                path_role: "transaction_owned_transient_scope".into(),
                error_kind: systemd_failure
                    .as_ref()
                    .map(|failure| failure.error_category.clone()),
                errno: None,
                message: error.to_string().chars().take(512).collect(),
                mutation_started: systemd_failure
                    .as_ref()
                    .is_some_and(|failure| failure.mutation_may_have_started)
                    || start_evidence
                        .as_ref()
                        .is_some_and(|evidence| evidence.mutation_may_have_started),
                cleanup_required: systemd_failure
                    .as_ref()
                    .is_some_and(|failure| failure.cleanup_required)
                    || start_evidence
                        .as_ref()
                        .is_some_and(|evidence| evidence.cleanup_required),
                systemd_failure: systemd_failure.clone(),
            };
            write_json(
                &control_dir.join("operation_errors.json"),
                &vec![diagnostic],
            )?;
            if start_evidence
                .as_ref()
                .is_some_and(SystemdStartEvidence::job_done)
            {
                set_gate(
                    gates,
                    "transient_scope_created",
                    GateState::Pass,
                    "StartTransientUnit job completed with result=done",
                );
                let identity_complete = start_evidence.as_ref().is_some_and(|evidence| {
                    evidence.unit_object_path.is_some()
                        && evidence.unit_object_path == evidence.worker_unit_object_path
                        && evidence.unit_id.as_deref() == Some(scope_plan.unit_name.as_str())
                        && evidence.load_state.as_deref() == Some("loaded")
                        && evidence.active_state.as_deref() == Some("active")
                        && evidence.sub_state.as_deref() == Some("running")
                });
                set_gate(
                    gates,
                    "scope_identity_verified",
                    if identity_complete {
                        GateState::Pass
                    } else {
                        GateState::Fail
                    },
                    if identity_complete {
                        "GetUnit/GetUnitByPID and Unit identity/state verified"
                    } else {
                        &detail
                    },
                );
                if identity_complete {
                    let failing_gate = match systemd_failure.as_ref().map(|failure| {
                        (
                            failure.stage.as_str(),
                            failure.property.as_deref().unwrap_or(""),
                        )
                    }) {
                        Some(("control_group", _)) | Some((_, "ControlGroup")) => {
                            "control_group_resolved"
                        }
                        Some(("resource_property", _)) => "memory_limit_property_verified",
                        _ => "scope_identity_verified",
                    };
                    set_gate(gates, failing_gate, GateState::Fail, &detail);
                }
            } else {
                set_gate(gates, "transient_scope_created", GateState::Fail, &detail);
            }
            return Err(error);
        }
    };
    set_gate(
        gates,
        "transient_scope_created",
        GateState::Pass,
        "systemd StartTransientUnit created exact owned scope",
    );
    write_json(&control_dir.join("scope_state.json"), &scope)?;
    if scope.unit_name != scope_plan.unit_name {
        set_gate(
            gates,
            "scope_identity_verified",
            GateState::Fail,
            "systemd unit identity mismatch",
        );
        bail!("systemd unit identity mismatch");
    }
    set_gate(
        gates,
        "scope_identity_verified",
        GateState::Pass,
        "exact transaction unit and object path verified",
    );
    if scope.memory_max != scope_plan.memory_max
        || !scope.memory_accounting
        || !scope.cpu_accounting
        || !scope.io_accounting
    {
        set_gate(
            gates,
            "memory_limit_property_verified",
            GateState::Fail,
            "systemd resource property mismatch",
        );
        bail!("systemd resource property mismatch");
    }
    set_gate(
        gates,
        "memory_limit_property_verified",
        GateState::Pass,
        "systemd MemoryMax and accounting properties verified",
    );
    let group_path = match scope.kernel_path() {
        Ok(path) => path,
        Err(error) => {
            set_gate(
                gates,
                "control_group_resolved",
                GateState::Fail,
                "systemd ControlGroup unavailable or invalid",
            );
            return Err(error);
        }
    };
    set_gate(
        gates,
        "control_group_resolved",
        GateState::Pass,
        "kernel path resolved only from systemd ControlGroup property",
    );
    let missing = REQUIRED_MEMORY_FILES
        .iter()
        .filter(|name| !group_path.join(name).is_file())
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        let diagnostic = OperationDiagnostic {
            operation: "verify_child_memory_interface".into(),
            path_role: "owned_benchmark_cgroup".into(),
            error_kind: Some("not_found".into()),
            errno: Some(2),
            message: format!("required memory interface absent: {}", missing.join(",")),
            mutation_started: true,
            cleanup_required: true,
            systemd_failure: None,
        };
        write_json(
            &control_dir.join("operation_errors.json"),
            &vec![diagnostic],
        )?;
        set_gate(
            gates,
            "memory_limit_kernel_verified",
            GateState::Fail,
            "child_memory_interface_missing",
        );
        bail!("child memory controller interface is absent");
    }
    let readback = match fs::read_to_string(group_path.join("memory.max")) {
        Ok(value) => value,
        Err(error) => {
            record_operation_error(
                control_dir,
                "readback_memory_max",
                "owned_benchmark_cgroup/memory.max",
                &error,
            )?;
            set_gate(
                gates,
                "memory_limit_kernel_verified",
                GateState::Fail,
                "memory_max_readback_failed",
            );
            return Err(error.into());
        }
    };
    let effective: u64 = match readback.trim().parse() {
        Ok(value) => value,
        Err(error) => {
            let diagnostic = OperationDiagnostic {
                operation: "parse_memory_max_readback".into(),
                path_role: "owned_benchmark_cgroup/memory.max".into(),
                error_kind: Some("invalid_data".into()),
                errno: None,
                message: error.to_string(),
                mutation_started: true,
                cleanup_required: true,
                systemd_failure: None,
            };
            write_json(
                &control_dir.join("operation_errors.json"),
                &vec![diagnostic],
            )?;
            set_gate(
                gates,
                "memory_limit_kernel_verified",
                GateState::Fail,
                "memory_max_readback_invalid",
            );
            return Err(error.into());
        }
    };
    if effective != plan.memory_max_bytes {
        let diagnostic = OperationDiagnostic {
            operation: "verify_memory_max_readback".into(),
            path_role: "owned_benchmark_cgroup/memory.max".into(),
            error_kind: Some("readback_mismatch".into()),
            errno: None,
            message: format!("requested={} effective={effective}", plan.memory_max_bytes),
            mutation_started: true,
            cleanup_required: true,
            systemd_failure: None,
        };
        write_json(
            &control_dir.join("operation_errors.json"),
            &vec![diagnostic],
        )?;
        set_gate(
            gates,
            "memory_limit_kernel_verified",
            GateState::Fail,
            "memory_max_mismatch",
        );
        bail!("memory.max readback mismatch");
    }
    set_gate(
        gates,
        "memory_limit_kernel_verified",
        GateState::Pass,
        "kernel memory.max matches systemd MemoryMax",
    );
    identity.verify()?;
    if scope.members != BTreeSet::from([identity.pid]) {
        set_gate(
            gates,
            "exclusive_membership",
            GateState::Fail,
            "foreign or missing scope member",
        );
        bail!("systemd scope membership is not exclusive");
    }
    set_gate(
        gates,
        "owned_child_attached",
        GateState::Pass,
        "systemd attached exact PID and start_ticks remained stable",
    );
    verify_exclusive_membership(&group_path, identity.pid)?;
    set_gate(
        gates,
        "exclusive_membership",
        GateState::Pass,
        "only exact owned PID present",
    );
    write_json(
        &control_dir.join("scope_attached.json"),
        &serde_json::json!({
            "unit_name": scope.unit_name,
            "control_group": scope.control_group,
            "pid": identity.pid,
            "start_ticks": identity.start_ticks,
        }),
    )?;
    fs::write(control_dir.join("allocate"), b"allocate")?;
    wait_for_file(
        &control_dir.join("ready_memory.json"),
        Duration::from_secs(8),
    )?;
    set_gate(
        gates,
        "worker_payload_allocated",
        GateState::Pass,
        "64 MiB allocation occurred only after scope and limit verification",
    );
    set_gate(
        gates,
        "worker_ready",
        GateState::Pass,
        "64 MiB prefaulted worker reached READY",
    );
    thread::sleep(Duration::from_millis(plan.stabilization_ms));
    let (samples, watchdog) = monitor(
        backend,
        &scope_plan,
        &scope.control_group,
        &identity,
        &group_path,
        control_dir,
        plan,
        psi_threshold,
    )?;
    fs::write(
        control_dir.join("samples.json"),
        serde_json::to_vec_pretty(&samples)?,
    )?;
    fs::write(
        control_dir.join("watchdog.json"),
        serde_json::to_vec_pretty(&watchdog)?,
    )?;
    if watchdog.triggered {
        set_gate(
            gates,
            "watchdog",
            GateState::Fail,
            watchdog.reason.as_deref().unwrap_or("watchdog_triggered"),
        );
        if watchdog.unexpected_oom {
            set_gate(
                gates,
                "no_oom",
                GateState::Fail,
                "memory.events reported OOM or OOM kill",
            );
        }
        bail!(
            "watchdog triggered: {}",
            watchdog.reason.unwrap_or_default()
        );
    }
    set_gate(
        gates,
        "watchdog",
        GateState::Pass,
        "independent watchdog remained clear",
    );
    let oom = samples.iter().any(|sample| {
        sample.memory_events.get("oom").copied().unwrap_or(0) > 0
            || sample.memory_events.get("oom_kill").copied().unwrap_or(0) > 0
    });
    set_gate(
        gates,
        "no_oom",
        if oom {
            GateState::Fail
        } else {
            GateState::Pass
        },
        "memory.events oom and oom_kill remained zero",
    );
    if oom {
        bail!("unexpected cgroup OOM event");
    }
    set_gate(
        gates,
        "metrics_collected",
        if samples.is_empty() {
            GateState::Fail
        } else {
            GateState::Pass
        },
        "bounded cgroup/worker/host samples captured",
    );
    if samples.is_empty() {
        bail!("no cgroup metric samples captured");
    }
    Ok(())
}

fn cleanup_live(
    backend: &mut impl TransientScopeBackend,
    child: &mut Child,
    control_dir: &Path,
    _plan: &CgroupHarnessPlan,
    gates: &mut [HarnessGate],
) -> Result<()> {
    let audit = read_json::<HarnessAudit>(&control_dir.join("audit.json")).ok();
    let cleanup_scope_plan = audit
        .clone()
        .map(|audit| {
            let run_id = audit.target_identity.run_id.clone();
            TransientScopePlan::new(&run_id, audit.target_identity)
        })
        .transpose()?;
    let start_evidence = backend
        .start_evidence()
        .or_else(|| read_json(&control_dir.join("start_evidence.json")).ok());
    let scope_owned_before_worker_stop =
        cleanup_scope_plan.as_ref().is_some_and(|scope_plan| {
            start_evidence.as_ref().is_some_and(|evidence| {
                evidence.job_done()
                    && evidence.requested_unit == scope_plan.unit_name
                    && evidence.cleanup_required
            })
        }) || cleanup_scope_plan.as_ref().is_some_and(|scope_plan| {
            backend
                .read_scope_state(&scope_plan.unit_name)
                .ok()
                .flatten()
                .is_some_and(|state| state.verify(scope_plan).is_ok())
        });

    // Worker cleanup is mandatory for every path after spawn, including
    // failures before allocation or measurement.
    let _ = fs::write(control_dir.join("stop"), b"stop");
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    if child.try_wait()?.is_none() {
        if let Some(audit) = audit.as_ref() {
            if audit.target_identity.verify().is_ok() {
                child.kill()?;
                child.wait()?;
            }
        }
    }
    let worker_absent = child.try_wait()?.is_some();
    set_gate(
        gates,
        "worker_cleanup",
        if worker_absent {
            GateState::Pass
        } else {
            GateState::Fail
        },
        if worker_absent {
            "owned worker cooperatively stopped or exact identity terminated"
        } else {
            "owned worker remained after bounded cleanup"
        },
    );
    if let Ok(result) = read_json::<WorkerResult>(&control_dir.join("result.json")) {
        set_gate(
            gates,
            "worker_integrity",
            if result.fingerprint_valid && result.full_rewrite_passes_during_measurement == 0 {
                GateState::Pass
            } else {
                GateState::Fail
            },
            "content fingerprint valid and no measurement rewrite",
        );
    }
    let (scope_cleanup_state, scope_cleanup_detail) = match cleanup_scope_plan {
        None => (GateState::Pass, "scope cleanup not required before audit"),
        Some(scope_plan) => match backend.unit_exists(&scope_plan.unit_name) {
            Ok(false) => (GateState::Pass, "exact scope already absent or collected"),
            Ok(true) if !scope_owned_before_worker_stop => (
                GateState::Fail,
                "scope exists but staged transaction ownership is ambiguous",
            ),
            Ok(true) => {
                let stop = backend
                    .stop_owned_scope(&scope_plan)
                    .and_then(|_| {
                        backend
                            .wait_inactive_or_removed(&scope_plan.unit_name, Duration::from_secs(4))
                    })
                    .and_then(|_| {
                        if backend.unit_exists(&scope_plan.unit_name)? {
                            bail!("exact owned scope remains after StopUnit")
                        }
                        Ok(())
                    });
                if stop.is_ok() {
                    (
                        GateState::Pass,
                        "exact staged-owned scope stopped and collected",
                    )
                } else {
                    (GateState::Fail, "exact staged-owned scope cleanup failed")
                }
            }
            Err(_) => (GateState::Fail, "scope absence could not be verified"),
        },
    };
    set_gate(
        gates,
        "scope_cleanup",
        scope_cleanup_state,
        scope_cleanup_detail,
    );
    Ok(())
}

fn spawn_worker(bytes: u64, control_dir: &Path) -> Result<Child> {
    let executable = std::env::current_exe()?;
    Ok(Command::new(executable)
        .arg("worker-hold")
        .arg("--bytes")
        .arg(bytes.to_string())
        .arg("--control-dir")
        .arg(control_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerReady {
    pid: u32,
    start_ticks: u64,
}

pub fn run_worker(bytes: u64, control_dir: &Path) -> Result<()> {
    if bytes != HARNESS_DEFAULT_WORKER_BYTES {
        bail!("Checkpoint 2 worker requires exactly 64 MiB");
    }
    let pid = std::process::id();
    let start_ticks = read_start_ticks(pid).context("cannot read worker identity")?;
    write_json_create_new(
        &control_dir.join("ready_outside.json"),
        &WorkerReady { pid, start_ticks },
    )?;
    wait_for_file(
        &control_dir.join("scope_attached.json"),
        Duration::from_secs(10),
    )?;
    wait_for_file(&control_dir.join("allocate"), Duration::from_secs(10))?;
    let setup_start = Instant::now();
    let mut memory = vec![0u8; usize::try_from(bytes)?];
    for (index, byte) in memory.iter_mut().enumerate() {
        *byte = ((index / 4096) % 251) as u8 ^ 0x5a;
    }
    let fingerprint = Sha256::digest(&memory);
    let setup_wall_seconds = setup_start.elapsed().as_secs_f64();
    write_json_create_new(
        &control_dir.join("ready_memory.json"),
        &serde_json::json!({"pid": pid, "bytes": bytes, "fingerprint": hex::encode(fingerprint)}),
    )?;
    let measurement_start = Instant::now();
    let mut heartbeat_count = 0u64;
    let mut checked = 0u64;
    while !control_dir.join("stop").exists() {
        let page = heartbeat_count as usize % (memory.len() / 4096);
        std::hint::black_box(memory[page * 4096]);
        checked += 1;
        heartbeat_count += 1;
        fs::write(control_dir.join("heartbeat"), now_ns().to_string())?;
        thread::sleep(Duration::from_millis(100));
    }
    let result = WorkerResult {
        pid,
        start_ticks,
        allocation_bytes: bytes,
        setup_wall_seconds,
        measurement_wall_seconds: measurement_start.elapsed().as_secs_f64(),
        heartbeat_count,
        bounded_integrity_pages_checked: checked,
        full_generation_passes: 1,
        full_prefault_passes: 1,
        full_rewrite_passes_during_measurement: 0,
        fingerprint_valid: Sha256::digest(&memory).as_slice() == fingerprint.as_slice(),
    };
    fs::write(
        control_dir.join("result.json"),
        serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn monitor(
    backend: &impl TransientScopeBackend,
    scope_plan: &TransientScopePlan,
    expected_control_group: &str,
    identity: &OwnedProcessIdentity,
    group_path: &Path,
    control_dir: &Path,
    plan: &CgroupHarnessPlan,
    psi_threshold: f64,
) -> Result<(Vec<CgroupSample>, WatchdogEvidence)> {
    let started = Instant::now();
    let mut samples = Vec::new();
    let mut watchdog = empty_watchdog(psi_threshold);
    while started.elapsed() < Duration::from_millis(plan.measurement_ms) {
        let state = match backend.read_scope_state(&scope_plan.unit_name) {
            Ok(Some(state)) => state,
            Ok(None) => {
                watchdog.unit_disappeared_unexpectedly = true;
                watchdog.reason = Some("unit_disappeared_unexpectedly".into());
                break;
            }
            Err(_) => {
                watchdog.systemd_connection_lost = true;
                watchdog.reason = Some("systemd_connection_lost".into());
                break;
            }
        };
        if state.active_state != "active" {
            watchdog.unit_state_invalid = true;
            watchdog.reason = Some("unit_state_invalid".into());
            break;
        }
        if state.control_group != expected_control_group {
            watchdog.control_group_changed = true;
            watchdog.reason = Some("control_group_changed".into());
            break;
        }
        if identity.verify().is_err() {
            watchdog.identity_changed = true;
            watchdog.reason = Some("child_identity_stale".into());
            break;
        }
        let pids = read_pids(&group_path.join("cgroup.procs"))?;
        let foreign: Vec<_> = pids
            .into_iter()
            .filter(|pid| *pid != identity.pid)
            .collect();
        if !foreign.is_empty() {
            watchdog.foreign_pids = foreign;
            watchdog.reason = Some("foreign_process_in_owned_cgroup".into());
            break;
        }
        let sample = collect_cgroup_sample(group_path, identity.pid)?;
        if sample.memory_current.unwrap_or(0) > plan.memory_max_bytes {
            watchdog.memory_expectation_exceeded = true;
            watchdog.reason = Some("memory_current_exceeded_limit".into());
            break;
        }
        if sample.memory_events.get("oom").copied().unwrap_or(0) > 0
            || sample.memory_events.get("oom_kill").copied().unwrap_or(0) > 0
        {
            watchdog.unexpected_oom = true;
            watchdog.reason = Some("unexpected_oom".into());
            break;
        }
        let psi = fs::read_to_string("/proc/pressure/memory")
            .ok()
            .and_then(|value| parse_psi(&value).ok())
            .and_then(|value| value.full)
            .map(|value| value.avg10)
            .unwrap_or(0.0);
        watchdog.peak_host_psi_full_avg10 = watchdog.peak_host_psi_full_avg10.max(psi);
        if psi > psi_threshold {
            watchdog.reason = Some("host_psi_emergency".into());
            break;
        }
        let heartbeat_age = fs::metadata(control_dir.join("heartbeat"))
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .unwrap_or(Duration::MAX);
        if heartbeat_age > Duration::from_millis(watchdog.heartbeat_timeout_ms) {
            watchdog.heartbeat_stalled = true;
            watchdog.reason = Some("heartbeat_timeout".into());
            break;
        }
        samples.push(sample);
        thread::sleep(Duration::from_millis(250));
    }
    watchdog.triggered = watchdog.reason.is_some();
    Ok((samples, watchdog))
}

fn collect_cgroup_sample(group: &Path, pid: u32) -> Result<CgroupSample> {
    let scalar = |name: &str| -> Option<u64> {
        fs::read_to_string(group.join(name))
            .ok()
            .and_then(|value| value.trim().parse().ok())
    };
    let map = |name: &str| -> BTreeMap<String, u64> {
        fs::read_to_string(group.join(name))
            .ok()
            .and_then(|value| parse_cgroup_key_values(&value).ok())
            .unwrap_or_default()
    };
    let status =
        parse_key_u64(&fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default());
    let pss = fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))
        .ok()
        .map(|value| parse_key_u64(&value))
        .and_then(|value| value.get("Pss").copied())
        .map(|value| value * 1024);
    let major_faults = read_process_stat(pid).and_then(|fields| fields.get(8).copied());
    Ok(CgroupSample {
        timestamp_ns: now_ns(),
        memory_current: scalar("memory.current"),
        memory_peak: scalar("memory.peak"),
        memory_max: scalar("memory.max"),
        memory_events: map("memory.events"),
        memory_stat: map("memory.stat"),
        cpu_stat: map("cpu.stat"),
        io_stat: fs::read_to_string(group.join("io.stat"))
            .ok()
            .and_then(|value| parse_io_stat(&value).ok()),
        memory_pressure: fs::read_to_string(group.join("memory.pressure"))
            .ok()
            .and_then(|value| parse_psi(&value).ok()),
        worker_rss_bytes: status.get("VmRSS").copied().map(|value| value * 1024),
        worker_pss_bytes: pss,
        worker_major_faults: major_faults,
        host_metrics: collect_read_only_metrics().values,
    })
}

fn persist_pre_mutation_audit(
    database: &Path,
    config_hash: &str,
    provenance: &BuildProvenance,
    audit: &HarnessAudit,
) -> Result<()> {
    let connection = Connection::open(database)?;
    connection.execute_batch("PRAGMA foreign_keys=ON;")?;
    connection.execute_batch(include_str!("../../../migrations/0008_benchmark.sql"))?;
    connection.execute(
        "INSERT INTO benchmark_experiments(id,scenario_id,scenario_version,seed,repetition_count,host_fingerprint_hash,nemor_commit,config_hash,evidence_kind,source_state_id,binary_sha256,development_build,performance_claim_eligible,created_at_ns,status)
         VALUES (?1,'harness_cgroup_lifecycle',1,0,1,'pending',?2,?3,'harness_validation',?4,?5,?6,0,?7,'audit_persisted')",
        params![
            audit.benchmark_run_id,
            provenance.git_head,
            config_hash,
            provenance.source_state_id,
            provenance.binary_sha256,
            provenance.development_build,
            now_ns() as i64,
        ],
    )?;
    Ok(())
}

fn persist_harness_report(database: &Path, report: &HarnessValidationReport) -> Result<()> {
    let connection = Connection::open(database)?;
    connection.execute(
        "INSERT INTO benchmark_run_manifests(id,experiment_id,variant,repetition,run_order,status,valid,invalid_reason,logical_workload_bytes,physical_memory_bytes,requested_variant,resolved_variant_state,effective_state_hash,variant_diff_summary,cgroup_ownership_json,restore_evidence_json,started_monotonic_ns,ended_monotonic_ns,manifest_json)
         VALUES (?1,?1,'harness_validation',0,0,?2,?3,?4,?5,NULL,'harness_validation','executable',?6,'owned cgroup lifecycle only',?7,?8,0,?9,?10)",
        params![
            report.run_id,
            if report.outcome.required_gates_passed { "completed" } else { "failed" },
            report.outcome.required_gates_passed,
            report.outcome.failure_reason,
            report.plan.worker_bytes as i64,
            report.provenance.source_state_id,
            serde_json::to_string(&report.ownership)?,
            serde_json::to_string(&serde_json::json!({
                "configuration_restored": report.gates.iter().find(|gate| gate.name == "configuration_restored"),
                "host_unchanged": report.gates.iter().find(|gate| gate.name == "host_unchanged"),
            }))?,
            now_ns() as i64,
            serde_json::to_string(report)?,
        ],
    )?;
    Ok(())
}

fn set_gate(gates: &mut [HarnessGate], name: &str, state: GateState, detail: &str) {
    if let Some(gate) = gates.iter_mut().find(|gate| gate.name == name) {
        gate.state = state;
        gate.detail = detail.into();
    }
}

fn empty_watchdog(psi_threshold: f64) -> WatchdogEvidence {
    WatchdogEvidence {
        heartbeat_timeout_ms: 1_000,
        host_psi_full_emergency_threshold: psi_threshold,
        peak_host_psi_full_avg10: 0.0,
        heartbeat_stalled: false,
        identity_changed: false,
        foreign_pids: Vec::new(),
        memory_expectation_exceeded: false,
        unexpected_oom: false,
        ownership_lost: false,
        unit_disappeared_unexpectedly: false,
        unit_state_invalid: false,
        control_group_changed: false,
        systemd_connection_lost: false,
        systemd_job_failed: false,
        timeout: false,
        triggered: false,
        reason: None,
    }
}

pub fn inspect_cgroup_parent(parent: &Path) -> Result<CgroupCapabilityEvidence> {
    let read_words = |name: &str| -> Result<Vec<String>> {
        Ok(fs::read_to_string(parent.join(name))?
            .split_whitespace()
            .map(str::to_owned)
            .collect())
    };
    let parent_type = fs::read_to_string(parent.join("cgroup.type"))
        .ok()
        .map(|value| value.trim().to_owned());
    let events = fs::read_to_string(parent.join("cgroup.events"))
        .ok()
        .map(|value| parse_cgroup_key_values(&value))
        .transpose()?;
    let populated = events
        .as_ref()
        .and_then(|values| values.get("populated"))
        .map(|value| *value != 0);
    let direct_process_count = fs::read_to_string(parent.join("cgroup.procs"))
        .ok()
        .map(|value| value.lines().filter(|line| !line.trim().is_empty()).count());
    Ok(CgroupCapabilityEvidence::from_values(
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
        parent_type,
        populated,
        direct_process_count,
        read_words("cgroup.controllers")?,
        read_words("cgroup.subtree_control")?,
    ))
}

fn verify_exclusive_membership(group: &Path, pid: u32) -> Result<()> {
    let pids = read_pids(&group.join("cgroup.procs"))?;
    validate_exclusive_membership(pid, &pids)
}

pub fn validate_exclusive_membership(expected_pid: u32, pids: &BTreeSet<u32>) -> Result<()> {
    if pids != &BTreeSet::from([expected_pid]) {
        bail!("owned cgroup membership is not exclusive");
    }
    Ok(())
}

fn read_pids(path: &Path) -> Result<BTreeSet<u32>> {
    Ok(fs::read_to_string(path)?
        .lines()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?)
}

fn read_start_ticks(pid: u32) -> Option<u64> {
    read_process_stat(pid).and_then(|fields| fields.get(18).copied())
}

fn read_process_stat(pid: u32) -> Option<Vec<u64>> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    Some(
        stat[close + 1..]
            .split_whitespace()
            .skip(1)
            .map(|value| value.parse::<u64>().unwrap_or(0))
            .collect(),
    )
}

fn process_cpu_ticks(pid: u32) -> Option<u64> {
    let fields = read_process_stat(pid)?;
    Some(fields.get(10)?.saturating_add(*fields.get(11)?))
}

fn detect_clk_tck() -> Option<u64> {
    let output = Command::new("/usr/bin/getconf")
        .arg("CLK_TCK")
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok()?.trim().parse().ok())
        .flatten()
}

fn wait_for_file(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    bail!("timeout waiting for {}", path.display())
}

fn write_json_create_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn record_operation_error(
    control_dir: &Path,
    operation: &str,
    path_role: &str,
    error: &std::io::Error,
) -> Result<()> {
    let diagnostic = OperationDiagnostic {
        operation: operation.into(),
        path_role: path_role.into(),
        error_kind: Some(format!("{:?}", error.kind()).to_lowercase()),
        errno: error.raw_os_error(),
        message: error.to_string(),
        mutation_started: true,
        cleanup_required: true,
        systemd_failure: None,
    };
    write_json(
        &control_dir.join("operation_errors.json"),
        &vec![diagnostic],
    )
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn remove_control_dir(path: &Path) -> Result<()> {
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".control-checkpoint2-"))
    {
        bail!("refusing to remove non-owned control directory");
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if entry.path().is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    fs::remove_dir(path)?;
    Ok(())
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos() as u64
}

#[derive(Debug, Clone)]
pub struct SimulatedRecoveryState {
    pub owned_group: Option<String>,
    pub owned_identity: Option<OwnedProcessIdentity>,
    pub group_empty: bool,
    pub foreign_group: bool,
    pub cleaned: bool,
}

pub fn recover_simulated(state: &mut SimulatedRecoveryState) -> Result<()> {
    if state.foreign_group {
        bail!("foreign or unknown cgroup is never removed");
    }
    if let Some(group) = &state.owned_group {
        let legacy_owned = group.starts_with("nemor-validation-benchmark-")
            && group.ends_with(".scope")
            && !group.contains('/');
        let transient_owned = crate::systemd::validate_unit_name(group).is_ok();
        if !legacy_owned && !transient_owned {
            bail!("recovery group is outside Nemor ownership");
        }
    }
    if let Some(identity) = &state.owned_identity {
        if identity.pid == 0 || identity.start_ticks == 0 {
            bail!("stale or incomplete owned identity");
        }
    }
    if state.group_empty {
        state.owned_group = None;
    }
    state.cleaned = state.owned_group.is_none();
    Ok(())
}
