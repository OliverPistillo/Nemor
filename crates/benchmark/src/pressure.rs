//! Checkpoint 3C controlled progressive-pressure framework.
//!
//! This module is deliberately model-only. It has no process, allocation,
//! cgroup, systemd, shell, or privileged backend.

use crate::performance::{INCOMPRESSIBLE_GENERATOR_ID, SYNTHETIC_GENERATOR_VERSION};
use crate::{BenchmarkVariant, EvaluationState, MetricScope};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PRESSURE_SCENARIO: &str = "progressive_memory_pressure";
pub const PRESSURE_SCENARIO_VERSION: u32 = 1;
pub const PRESSURE_PLAN_VERSION: u32 = 1;
pub const PRESSURE_HEALTH_POLICY_VERSION: u32 = 1;
pub const LEVEL_EVIDENCE_VERSION: u32 = 2;
pub const MAX_PRESSURE_LEVELS: usize = 12;
pub const MAX_PRESSURE_DURATION_MS: u64 = 15 * 60 * 1_000;
pub const PRESSURE_FRAMEWORK_MANIFEST_VERSION: u32 = 1;
pub const PSI_AVG10_UNIT: &str = "percent_stall_time_as_emitted_by_linux";

pub fn psi_avg10_threshold_crossed(observed_linux_avg10: f64, threshold: f64) -> Result<bool> {
    if !observed_linux_avg10.is_finite()
        || !threshold.is_finite()
        || observed_linux_avg10 < 0.0
        || threshold < 0.0
        || observed_linux_avg10 > 100.0
        || threshold > 100.0
    {
        bail!("PSI avg10 values must use Linux percent units in [0,100]");
    }
    Ok(observed_linux_avg10 >= threshold)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PressureFrameworkManifest {
    pub version: u32,
    pub plan: ProgressivePressurePlan,
    pub material_environment_schema_version: u32,
    pub material_environment_hash: String,
    pub worker_implementation_hash: String,
    pub live_execution_enabled: bool,
}

impl PressureFrameworkManifest {
    pub fn validate(&self) -> Result<()> {
        self.plan.validate()?;
        if self.version != PRESSURE_FRAMEWORK_MANIFEST_VERSION
            || self.material_environment_schema_version
                != crate::MATERIAL_ENVIRONMENT_SCHEMA_VERSION
            || self.material_environment_hash.is_empty()
            || self.worker_implementation_hash.is_empty()
            || self.live_execution_enabled
        {
            bail!("invalid or live-enabled Checkpoint 3C framework manifest");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PressureRunPreflightBinding {
    pub run_order_index: usize,
    pub material_environment_hash: String,
    pub plan_contract_hash: String,
    pub worker_implementation_hash: String,
}

impl PressureRunPreflightBinding {
    pub fn validate(
        &self,
        manifest: &PressureFrameworkManifest,
        run_order_index: usize,
    ) -> Result<()> {
        if self.run_order_index != run_order_index
            || self.material_environment_hash != manifest.material_environment_hash
            || self.plan_contract_hash != manifest.plan.contract_hash()?
            || self.worker_implementation_hash != manifest.worker_implementation_hash
        {
            bail!("pressure run preflight binding mismatch");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureComparisonPurpose {
    PressureFrameworkValidation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannedLevelState {
    Planned,
    CompletedSustainable,
    CompletedUnsustainable,
    InvalidLevelEvidence,
    SafetyAbort,
    NotExecutedAfterUnsustainable,
    NotExecutedAfterInvalid,
    NotExecutedAfterSafetyAbort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedPressureLevel {
    pub level_index: usize,
    pub target_logical_bytes: u64,
    pub target_touched_bytes: u64,
    pub seed: u64,
    pub state: PlannedLevelState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PressureWatchdogPolicy {
    pub heartbeat_timeout_ms: u64,
    pub level_timeout_ms: u64,
    pub total_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PressureHealthPolicy {
    pub version: u32,
    pub host_psi_full_avg10_emergency: f64,
    pub cgroup_psi_full_avg10_unsustainable: f64,
    pub max_major_faults_per_level: u64,
    pub max_swap_in_bytes_per_level: u64,
    pub max_swap_out_bytes_per_level: u64,
    pub max_block_writes_bytes_per_level: u64,
    pub host_oom_forbidden: bool,
    pub request_oom: bool,
    pub zero_limits_mean_zero_tolerance: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefinementMode {
    DeterministicBracket,
    DisabledForFrameworkPilot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefinementPolicy {
    pub mode: RefinementMode,
    pub granularity_bytes: u64,
    pub maximum_refinements: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadroomReserve {
    pub host_bytes: u64,
    pub runner_bytes: u64,
    pub observer_bytes: u64,
    pub rollback_cleanup_bytes: u64,
    pub operating_system_variance_bytes: u64,
    pub total_reserved_bytes: u64,
    pub effective_maximum_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeadroomPolicy {
    pub host_reserve_permille: u16,
    pub minimum_host_reserve_bytes: u64,
    pub runner_reserve_bytes: u64,
    pub observer_reserve_bytes: u64,
    pub rollback_cleanup_reserve_bytes: u64,
    pub operating_system_variance_bytes: u64,
}

impl HeadroomPolicy {
    pub fn derive(&self, available_bytes: u64) -> Result<HeadroomReserve> {
        if self.host_reserve_permille == 0
            || self.host_reserve_permille > 1_000
            || self.minimum_host_reserve_bytes == 0
            || self.runner_reserve_bytes == 0
            || self.observer_reserve_bytes == 0
            || self.rollback_cleanup_reserve_bytes == 0
            || self.operating_system_variance_bytes == 0
            || available_bytes == 0
        {
            bail!("invalid pressure headroom policy");
        }
        let fractional = available_bytes
            .checked_mul(u64::from(self.host_reserve_permille))
            .ok_or_else(|| anyhow::anyhow!("headroom multiplication overflow"))?
            / 1_000;
        let host_bytes = fractional.max(self.minimum_host_reserve_bytes);
        let total_reserved_bytes = [
            host_bytes,
            self.runner_reserve_bytes,
            self.observer_reserve_bytes,
            self.rollback_cleanup_reserve_bytes,
            self.operating_system_variance_bytes,
        ]
        .into_iter()
        .try_fold(0u64, |sum, value| sum.checked_add(value))
        .ok_or_else(|| anyhow::anyhow!("headroom reserve overflow"))?;
        let effective_maximum_bytes = available_bytes
            .checked_sub(total_reserved_bytes)
            .ok_or_else(|| anyhow::anyhow!("headroom reserve exceeds available memory"))?;
        Ok(HeadroomReserve {
            host_bytes,
            runner_bytes: self.runner_reserve_bytes,
            observer_bytes: self.observer_reserve_bytes,
            rollback_cleanup_bytes: self.rollback_cleanup_reserve_bytes,
            operating_system_variance_bytes: self.operating_system_variance_bytes,
            total_reserved_bytes,
            effective_maximum_bytes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopPolicy {
    pub stop_after_first_unsustainable: bool,
    pub stop_immediately_on_safety_abort: bool,
    pub never_use_safety_abort_as_capacity_bound: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressivePressurePlan {
    pub version: u32,
    pub scenario: String,
    pub scenario_version: u32,
    pub comparison_purpose: PressureComparisonPurpose,
    pub variants: Vec<BenchmarkVariant>,
    pub generator_id: String,
    pub generator_version: u32,
    pub experiment_seed: u64,
    pub levels: Vec<PlannedPressureLevel>,
    pub hold_duration_ms: u64,
    pub stabilization_duration_ms: u64,
    pub sample_interval_ms: u64,
    pub worker_memory_max_bytes: u64,
    pub watchdog: PressureWatchdogPolicy,
    pub health: PressureHealthPolicy,
    pub stop_policy: StopPolicy,
    pub refinement: RefinementPolicy,
    pub maximum_levels: usize,
    pub maximum_total_duration_ms: u64,
    pub headroom: HeadroomReserve,
    pub systemd_transient_scope_required: bool,
    pub exact_owned_worker_required: bool,
}

impl ProgressivePressurePlan {
    pub fn validate(&self) -> Result<()> {
        if self.version != PRESSURE_PLAN_VERSION
            || self.scenario != PRESSURE_SCENARIO
            || self.scenario_version != PRESSURE_SCENARIO_VERSION
            || self.comparison_purpose != PressureComparisonPurpose::PressureFrameworkValidation
            || self.variants
                != [
                    BenchmarkVariant::CachyosBaseline,
                    BenchmarkVariant::NemorObserve,
                ]
            || self.generator_id != INCOMPRESSIBLE_GENERATOR_ID
            || self.generator_version != SYNTHETIC_GENERATOR_VERSION
            || !self.systemd_transient_scope_required
            || !self.exact_owned_worker_required
        {
            bail!("invalid Checkpoint 3C scenario or ownership contract");
        }
        if self.levels.is_empty()
            || self.levels.len() > MAX_PRESSURE_LEVELS
            || self.levels.len() > self.maximum_levels
            || self.maximum_levels > MAX_PRESSURE_LEVELS
            || self.maximum_total_duration_ms == 0
            || self.maximum_total_duration_ms > MAX_PRESSURE_DURATION_MS
            || self.hold_duration_ms == 0
            || self.stabilization_duration_ms == 0
            || self.sample_interval_ms == 0
            || self.sample_interval_ms > self.hold_duration_ms
            || self.watchdog.heartbeat_timeout_ms == 0
            || self.watchdog.level_timeout_ms == 0
            || self.watchdog.total_timeout_ms == 0
            || self.watchdog.total_timeout_ms > self.maximum_total_duration_ms
            || self.health.version != PRESSURE_HEALTH_POLICY_VERSION
            || !self.health.host_psi_full_avg10_emergency.is_finite()
            || self.health.host_psi_full_avg10_emergency < 0.0
            || self.health.host_psi_full_avg10_emergency > 100.0
            || !self.health.cgroup_psi_full_avg10_unsustainable.is_finite()
            || self.health.cgroup_psi_full_avg10_unsustainable < 0.0
            || self.health.cgroup_psi_full_avg10_unsustainable > 100.0
            || self.health.request_oom
            || !self.health.host_oom_forbidden
            || !self.health.zero_limits_mean_zero_tolerance
            || !self.stop_policy.stop_after_first_unsustainable
            || !self.stop_policy.stop_immediately_on_safety_abort
            || !self.stop_policy.never_use_safety_abort_as_capacity_bound
            || self.refinement.granularity_bytes == 0
            || self.refinement.maximum_refinements > self.maximum_levels
            || (self.refinement.mode == RefinementMode::DeterministicBracket
                && self.refinement.maximum_refinements == 0)
            || (self.refinement.mode == RefinementMode::DisabledForFrameworkPilot
                && self.refinement.maximum_refinements != 0)
        {
            bail!("unsafe or unbounded Checkpoint 3C pressure plan");
        }
        let per_level_lifecycle = self
            .hold_duration_ms
            .checked_add(self.stabilization_duration_ms)
            .and_then(|value| value.checked_add(self.watchdog.heartbeat_timeout_ms))
            .ok_or_else(|| anyhow::anyhow!("level lifecycle overflow"))?;
        if self.watchdog.level_timeout_ms < per_level_lifecycle {
            bail!("level watchdog cannot cover the frozen level lifecycle");
        }
        let possible_level_count = self
            .levels
            .len()
            .checked_add(self.refinement.maximum_refinements)
            .ok_or_else(|| anyhow::anyhow!("pressure level count overflow"))?;
        let planned_duration = (possible_level_count as u64)
            .checked_mul(per_level_lifecycle)
            .ok_or_else(|| anyhow::anyhow!("planned duration overflow"))?;
        if planned_duration > self.maximum_total_duration_ms
            || self.watchdog.total_timeout_ms < planned_duration
        {
            bail!("planned levels exceed maximum experiment duration");
        }
        let mut previous = 0;
        let mut indices = BTreeSet::new();
        if self.worker_memory_max_bytes == 0
            || self.worker_memory_max_bytes > self.headroom.effective_maximum_bytes
        {
            bail!("worker MemoryMax exceeds the derived effective headroom");
        }
        for (expected_index, level) in self.levels.iter().enumerate() {
            if level.target_logical_bytes == 0
                || level.target_touched_bytes != level.target_logical_bytes
                || level.target_logical_bytes <= previous
                || level.target_touched_bytes > self.worker_memory_max_bytes
                || level.target_touched_bytes > self.headroom.effective_maximum_bytes
                || level.state != PlannedLevelState::Planned
                || level.level_index != expected_index
                || !indices.insert(level.level_index)
            {
                bail!("pressure levels must be unique, increasing, bounded and planned");
            }
            previous = level.target_logical_bytes;
        }
        Ok(())
    }

    pub fn contract_hash(&self) -> Result<String> {
        self.validate()?;
        Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(self)?)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureMetricScope {
    Host,
    WorkerCgroup,
    WorkerProcess,
    RunnerProcess,
    ObserverProcess,
}

impl From<PressureMetricScope> for MetricScope {
    fn from(value: PressureMetricScope) -> Self {
        match value {
            PressureMetricScope::Host => Self::Host,
            PressureMetricScope::WorkerCgroup => Self::Cgroup,
            PressureMetricScope::WorkerProcess
            | PressureMetricScope::RunnerProcess
            | PressureMetricScope::ObserverProcess => Self::Process,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PressureMetric {
    pub name: String,
    pub value: Option<f64>,
    pub unit: String,
    pub scope: PressureMetricScope,
    pub source: String,
    pub available: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveTelemetryContract {
    pub host_sources: BTreeMap<String, String>,
    pub worker_cgroup_sources: BTreeMap<String, String>,
    pub worker_process_sources: BTreeMap<String, String>,
    pub runner_sources: BTreeMap<String, String>,
    pub observer_sources: BTreeMap<String, String>,
    pub host_oom_separate_from_cgroup_events: bool,
    pub unavailable_is_not_zero: bool,
}

impl LiveTelemetryContract {
    pub fn checkpoint3c_v1() -> Self {
        Self {
            host_sources: BTreeMap::from([
                ("psi".into(), "/proc/pressure/memory".into()),
                ("oom".into(), "host_oom_evidence".into()),
                ("swap".into(), "/proc/vmstat".into()),
                ("block_writes".into(), "/proc/diskstats".into()),
            ]),
            worker_cgroup_sources: BTreeMap::from([
                ("memory_current".into(), "memory.current".into()),
                ("memory_events".into(), "memory.events".into()),
                ("memory_psi".into(), "memory.pressure".into()),
                ("membership".into(), "cgroup.procs_read_only".into()),
                ("memory_max".into(), "MemoryMax_dbus_readback".into()),
            ]),
            worker_process_sources: BTreeMap::from([
                ("identity".into(), "pid_start_ticks".into()),
                ("heartbeat".into(), "owned_worker_protocol".into()),
                ("integrity".into(), "bounded_payload_check".into()),
                ("cpu".into(), "/proc/pid/stat".into()),
            ]),
            runner_sources: BTreeMap::from([("cpu".into(), "/proc/self/stat".into())]),
            observer_sources: BTreeMap::from([
                ("identity".into(), "owned_dynamic_user_service".into()),
                ("cpu".into(), "/proc/pid/stat".into()),
            ]),
            host_oom_separate_from_cgroup_events: true,
            unavailable_is_not_zero: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureExecutorAction {
    CheckEmergencyGates,
    PersistCompletedLevel,
    IssueNextLevel,
    ExactOwnedCleanup,
}

pub fn next_level_action_order(emergency_crossed: bool) -> Vec<PressureExecutorAction> {
    if emergency_crossed {
        vec![
            PressureExecutorAction::CheckEmergencyGates,
            PressureExecutorAction::PersistCompletedLevel,
            PressureExecutorAction::ExactOwnedCleanup,
        ]
    } else {
        vec![
            PressureExecutorAction::CheckEmergencyGates,
            PressureExecutorAction::PersistCompletedLevel,
            PressureExecutorAction::IssueNextLevel,
        ]
    }
}

impl PressureMetric {
    pub fn measured(
        name: &str,
        value: f64,
        unit: &str,
        scope: PressureMetricScope,
        source: &str,
    ) -> Self {
        Self {
            name: name.into(),
            value: Some(value),
            unit: unit.into(),
            scope,
            source: source.into(),
            available: true,
            reason: None,
        }
    }

    pub fn unavailable(
        name: &str,
        unit: &str,
        scope: PressureMetricScope,
        source: &str,
        reason: &str,
    ) -> Self {
        Self {
            name: name.into(),
            value: None,
            unit: unit.into(),
            scope,
            source: source.into(),
            available: false,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthGate {
    WorkerAlive,
    WorkerIdentity,
    HeartbeatFresh,
    WorkerIntegrity,
    CgroupMembership,
    MemoryLimitContract,
    HostPsi,
    CgroupPsi,
    MajorFaults,
    SwapIn,
    SwapOut,
    BlockWrites,
    WorkerCpu,
    RunnerCpu,
    ObserverContract,
    ElapsedDuration,
    RestoreOwnership,
}

pub fn required_level_health_gates(variant: BenchmarkVariant) -> BTreeSet<HealthGate> {
    let mut gates = BTreeSet::from([
        HealthGate::WorkerAlive,
        HealthGate::WorkerIdentity,
        HealthGate::HeartbeatFresh,
        HealthGate::WorkerIntegrity,
        HealthGate::CgroupMembership,
        HealthGate::MemoryLimitContract,
        HealthGate::HostPsi,
        HealthGate::CgroupPsi,
        HealthGate::MajorFaults,
        HealthGate::SwapIn,
        HealthGate::SwapOut,
        HealthGate::BlockWrites,
        HealthGate::WorkerCpu,
        HealthGate::RunnerCpu,
        HealthGate::ElapsedDuration,
    ]);
    if variant == BenchmarkVariant::NemorObserve {
        gates.insert(HealthGate::ObserverContract);
    }
    gates
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthGateResult {
    pub passed: bool,
    pub mandatory: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SafetyAbortClass {
    HostPsiEmergency,
    HostOomDetected,
    CgroupOwnershipLost,
    WorkerIdentityLost,
    WorkerHeartbeatTimeout,
    WatchdogTimeout,
    MemoryLimitContractBroken,
    ObserverContractBroken,
    RestoreFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LevelClassification {
    Sustainable,
    UnsustainableHealth,
    InvalidLevelEvidence,
    SafetyAbort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerLevelAcknowledgement {
    pub experiment_id: String,
    pub run_id: String,
    pub level_index: usize,
    pub seed: u64,
    pub prior_touched_bytes: u64,
    pub requested_delta_bytes: u64,
    pub actual_touched_bytes: u64,
    pub worker_pid: u32,
    pub worker_start_ticks: u64,
    pub generator_id: String,
    pub generator_version: u32,
    pub integrity_identity: String,
    pub acknowledged_monotonic_ns: u64,
}

impl WorkerLevelAcknowledgement {
    pub fn validate(
        &self,
        evidence: &LevelEvidence,
        level: &PlannedPressureLevel,
        prior_touched_bytes: u64,
    ) -> Result<()> {
        let expected_delta = level
            .target_touched_bytes
            .checked_sub(prior_touched_bytes)
            .ok_or_else(|| anyhow::anyhow!("pressure level cannot shrink the touched payload"))?;
        if self.experiment_id != evidence.experiment_id
            || self.run_id != evidence.run_id
            || self.level_index != level.level_index
            || self.seed != level.seed
            || self.prior_touched_bytes != prior_touched_bytes
            || self.requested_delta_bytes != expected_delta
            || self.worker_pid == 0
            || self.worker_start_ticks == 0
            || self.generator_id != evidence.generator_id
            || self.generator_version != evidence.generator_version
            || self.integrity_identity != evidence.payload_integrity_identity
            || self.acknowledged_monotonic_ns > evidence.started_monotonic_ns
        {
            bail!("worker level acknowledgement does not match the planned delta");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PressureLevelSample {
    pub monotonic_ns: u64,
    pub memory_current_bytes: Option<u64>,
    pub host_memory_full_avg10_percent: Option<f64>,
    pub cgroup_memory_full_avg10_percent: Option<f64>,
    pub worker_alive: bool,
    pub heartbeat_touched_bytes: u64,
    pub integrity_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LevelEvidence {
    pub version: u32,
    pub experiment_id: String,
    pub run_id: String,
    pub variant: BenchmarkVariant,
    pub repetition_index: usize,
    pub level_index: usize,
    pub planned_logical_bytes: u64,
    pub actual_touched_bytes: u64,
    pub worker_acknowledgement: WorkerLevelAcknowledgement,
    pub worker_memory_max_bytes: u64,
    pub generator_id: String,
    pub generator_version: u32,
    pub workload_identity: String,
    pub payload_integrity_identity: String,
    pub started_monotonic_ns: u64,
    pub ended_monotonic_ns: u64,
    pub stabilization_completed_ms: u64,
    pub duration_ms: u64,
    pub sample_count: usize,
    pub raw_samples: Vec<PressureLevelSample>,
    pub memory_mean_bytes: Option<f64>,
    pub memory_peak_bytes: Option<u64>,
    pub metrics: Vec<PressureMetric>,
    pub major_fault_delta: Option<u64>,
    pub swap_in_bytes_delta: Option<u64>,
    pub swap_out_bytes_delta: Option<u64>,
    pub block_write_bytes_delta: Option<u64>,
    pub watchdog_triggered: bool,
    pub oom: u64,
    pub oom_kill: u64,
    pub health_gates: BTreeMap<HealthGate, HealthGateResult>,
    pub classification: LevelClassification,
    pub safety_abort: Option<SafetyAbortClass>,
    pub failure_reason: Option<String>,
}

impl LevelEvidence {
    pub fn validate(
        &self,
        level: &PlannedPressureLevel,
        plan: &ProgressivePressurePlan,
    ) -> Result<()> {
        if self.version != LEVEL_EVIDENCE_VERSION
            || self.level_index != level.level_index
            || self.planned_logical_bytes != level.target_logical_bytes
            || self.worker_memory_max_bytes != plan.worker_memory_max_bytes
            || self.generator_id != plan.generator_id
            || self.generator_version != plan.generator_version
            || self.ended_monotonic_ns <= self.started_monotonic_ns
            || self.duration_ms > plan.watchdog.level_timeout_ms
            || self.stabilization_completed_ms < plan.stabilization_duration_ms
            || self.workload_identity.is_empty()
            || self.payload_integrity_identity.is_empty()
        {
            bail!("level evidence does not match frozen pressure contract");
        }
        let prior_touched_bytes = if level.level_index == 0 {
            0
        } else {
            plan.levels[level.level_index - 1].target_touched_bytes
        };
        self.worker_acknowledgement
            .validate(self, level, prior_touched_bytes)?;
        if self.actual_touched_bytes != self.worker_acknowledgement.actual_touched_bytes {
            bail!("level evidence and worker acknowledgement disagree");
        }
        let elapsed_ms = self
            .ended_monotonic_ns
            .checked_sub(self.started_monotonic_ns)
            .ok_or_else(|| anyhow::anyhow!("level monotonic duration underflow"))?
            / 1_000_000;
        let minimum_samples = plan
            .hold_duration_ms
            .checked_add(plan.sample_interval_ms - 1)
            .ok_or_else(|| anyhow::anyhow!("sample coverage overflow"))?
            / plan.sample_interval_ms;
        let minimum_duration_ms = plan
            .hold_duration_ms
            .saturating_sub(plan.sample_interval_ms.min(plan.hold_duration_ms));
        if self.duration_ms < minimum_duration_ms
            || elapsed_ms < minimum_duration_ms
            || elapsed_ms.abs_diff(self.duration_ms) > plan.sample_interval_ms
            || u64::try_from(self.sample_count).unwrap_or(u64::MAX) < minimum_samples
        {
            bail!("completed level has insufficient timing or sample coverage");
        }
        if !self.raw_samples.is_empty() && self.raw_samples.len() != self.sample_count {
            bail!("raw pressure sample count differs from level sample contract");
        }
        if self.classification == LevelClassification::Sustainable {
            let required = required_level_health_gates(self.variant);
            let present = self.health_gates.keys().copied().collect::<BTreeSet<_>>();
            if present != required
                || self.actual_touched_bytes != level.target_touched_bytes
                || self.watchdog_triggered
                || self.oom != 0
                || self.oom_kill != 0
                || self
                    .health_gates
                    .values()
                    .any(|gate| !gate.mandatory || !gate.passed)
            {
                bail!("sustainable level did not pass its complete mandatory contract");
            }
        }
        if self.classification == LevelClassification::UnsustainableHealth
            && self.actual_touched_bytes != level.target_touched_bytes
        {
            bail!("unsustainable capacity evidence must reach the exact planned target");
        }
        if self.classification == LevelClassification::SafetyAbort && self.safety_abort.is_none() {
            bail!("safety abort evidence requires an explicit abort class");
        }
        if self.classification != LevelClassification::SafetyAbort && self.safety_abort.is_some() {
            bail!("normal level result cannot contain a safety abort class");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefinementDecision {
    pub sustainable_lower_bytes: u64,
    pub unsustainable_upper_bytes: u64,
    pub granularity_bytes: u64,
    pub refinements_completed: usize,
    pub maximum_refinements: usize,
    pub tested_bytes: Vec<u64>,
    pub next_test_bytes: Option<u64>,
    pub reason: String,
}

pub fn next_refinement(
    sustainable_lower_bytes: u64,
    unsustainable_upper_bytes: u64,
    policy: &RefinementPolicy,
    tested: &BTreeSet<u64>,
    refinements_completed: usize,
) -> Result<RefinementDecision> {
    if policy.mode != RefinementMode::DeterministicBracket
        || sustainable_lower_bytes == 0
        || sustainable_lower_bytes >= unsustainable_upper_bytes
        || policy.granularity_bytes == 0
        || !tested.contains(&sustainable_lower_bytes)
        || !tested.contains(&unsustainable_upper_bytes)
    {
        bail!("refinement requires a tested sustainable/unsustainable bracket");
    }
    let span = unsustainable_upper_bytes - sustainable_lower_bytes;
    let midpoint = sustainable_lower_bytes + span / 2;
    let aligned = midpoint / policy.granularity_bytes * policy.granularity_bytes;
    let next = (refinements_completed < policy.maximum_refinements
        && aligned > sustainable_lower_bytes
        && aligned < unsustainable_upper_bytes
        && !tested.contains(&aligned))
    .then_some(aligned);
    Ok(RefinementDecision {
        sustainable_lower_bytes,
        unsustainable_upper_bytes,
        granularity_bytes: policy.granularity_bytes,
        refinements_completed,
        maximum_refinements: policy.maximum_refinements,
        tested_bytes: tested.iter().copied().collect(),
        next_test_bytes: next,
        reason: if refinements_completed >= policy.maximum_refinements {
            "maximum deterministic refinement count reached".into()
        } else if next.is_some() {
            "deterministic midpoint inside tested closed bracket".into()
        } else {
            "no untested aligned point remains inside bracket".into()
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityResult {
    pub highest_tested_sustainable_bytes: Option<u64>,
    pub lowest_tested_unsustainable_bytes: Option<u64>,
    pub search_complete: bool,
    pub safety_abort: Option<SafetyAbortClass>,
    pub capacity_gain_percent: EvaluationState,
    contract_digest: String,
}

impl CapacityResult {
    fn digest(
        highest: Option<u64>,
        lowest: Option<u64>,
        search_complete: bool,
        safety_abort: Option<SafetyAbortClass>,
    ) -> String {
        hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&(highest, lowest, search_complete, safety_abort))
                .expect("capacity digest tuple is serializable"),
        ))
    }

    fn from_summary(
        highest: Option<u64>,
        lowest: Option<u64>,
        search_complete: bool,
        safety_abort: Option<SafetyAbortClass>,
    ) -> Self {
        Self {
            highest_tested_sustainable_bytes: highest,
            lowest_tested_unsustainable_bytes: lowest,
            search_complete,
            safety_abort,
            capacity_gain_percent: EvaluationState::NotEvaluated,
            contract_digest: Self::digest(highest, lowest, search_complete, safety_abort),
        }
    }

    fn internally_consistent(&self) -> bool {
        self.contract_digest
            == Self::digest(
                self.highest_tested_sustainable_bytes,
                self.lowest_tested_unsustainable_bytes,
                self.search_complete,
                self.safety_abort,
            )
    }

    pub fn validate(&self, levels: &[LevelEvidence]) -> Result<()> {
        let highest = levels
            .iter()
            .filter(|level| {
                level.classification == LevelClassification::Sustainable
                    && level.actual_touched_bytes == level.planned_logical_bytes
            })
            .map(|level| level.actual_touched_bytes)
            .max();
        let lowest = levels
            .iter()
            .filter(|level| {
                level.classification == LevelClassification::UnsustainableHealth
                    && level.actual_touched_bytes == level.planned_logical_bytes
            })
            .map(|level| level.planned_logical_bytes)
            .min();
        let invalid = levels
            .iter()
            .any(|level| level.classification == LevelClassification::InvalidLevelEvidence);
        if !self.internally_consistent()
            || self.highest_tested_sustainable_bytes != highest
            || self.lowest_tested_unsustainable_bytes != lowest
            || (self.search_complete
                && (self.safety_abort.is_some()
                    || invalid
                    || highest.is_none()
                    || lowest.is_none()))
        {
            bail!("capacity result is inconsistent with actually tested valid levels");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressiveRunEvidence {
    pub experiment_id: String,
    pub run_id: String,
    pub variant: BenchmarkVariant,
    pub repetition_index: usize,
    pub planned_levels: Vec<PlannedPressureLevel>,
    pub levels: Vec<LevelEvidence>,
    pub highest_tested_sustainable_bytes: Option<u64>,
    pub lowest_tested_unsustainable_bytes: Option<u64>,
    pub refinement_eligible: bool,
    pub invalid_level_evidence: bool,
    pub safety_abort: Option<SafetyAbortClass>,
    pub stopped_reason: String,
    pub capacity: CapacityResult,
}

impl ProgressiveRunEvidence {
    fn summarize(
        experiment_id: &str,
        run_id: &str,
        variant: BenchmarkVariant,
        repetition_index: usize,
        planned_levels: Vec<PlannedPressureLevel>,
        levels: Vec<LevelEvidence>,
        stopped_reason: String,
    ) -> Self {
        let highest = levels
            .iter()
            .filter(|level| level.classification == LevelClassification::Sustainable)
            .map(|level| level.actual_touched_bytes)
            .max();
        let lowest = levels
            .iter()
            .filter(|level| {
                level.classification == LevelClassification::UnsustainableHealth
                    && level.actual_touched_bytes == level.planned_logical_bytes
            })
            .map(|level| level.planned_logical_bytes)
            .min();
        let safety_abort = levels.iter().find_map(|level| level.safety_abort);
        let invalid_level_evidence = levels
            .iter()
            .any(|level| level.classification == LevelClassification::InvalidLevelEvidence);
        let refinement_eligible =
            plan_refinement_eligible(safety_abort, invalid_level_evidence, highest, lowest);
        Self {
            experiment_id: experiment_id.into(),
            run_id: run_id.into(),
            variant,
            repetition_index,
            planned_levels,
            levels,
            highest_tested_sustainable_bytes: highest,
            lowest_tested_unsustainable_bytes: lowest,
            refinement_eligible,
            invalid_level_evidence,
            safety_abort,
            stopped_reason,
            capacity: CapacityResult::from_summary(highest, lowest, false, safety_abort),
        }
    }
}

fn plan_refinement_eligible(
    safety_abort: Option<SafetyAbortClass>,
    invalid_level_evidence: bool,
    highest: Option<u64>,
    lowest: Option<u64>,
) -> bool {
    safety_abort.is_none()
        && !invalid_level_evidence
        && highest.zip(lowest).is_some_and(|(lo, hi)| lo < hi)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulatedLevelOutcome {
    Sustainable,
    UnsustainableHealth(String),
    SafetyAbort(SafetyAbortClass),
    TouchedBytesMismatch(u64),
}

#[derive(Debug, Clone)]
pub struct SimulatedPressureBackend {
    outcomes: BTreeMap<usize, SimulatedLevelOutcome>,
    pub privileged_operations: usize,
    pub allocated_bytes: usize,
}

impl SimulatedPressureBackend {
    pub fn new(outcomes: BTreeMap<usize, SimulatedLevelOutcome>) -> Self {
        Self {
            outcomes,
            privileged_operations: 0,
            allocated_bytes: 0,
        }
    }

    fn level_evidence(
        &self,
        plan: &ProgressivePressurePlan,
        level: &PlannedPressureLevel,
        variant: BenchmarkVariant,
        repetition_index: usize,
        outcome: SimulatedLevelOutcome,
    ) -> LevelEvidence {
        let (classification, safety_abort, failure_reason, touched) = match outcome {
            SimulatedLevelOutcome::Sustainable => (
                LevelClassification::Sustainable,
                None,
                None,
                level.target_touched_bytes,
            ),
            SimulatedLevelOutcome::UnsustainableHealth(reason) => (
                LevelClassification::UnsustainableHealth,
                None,
                Some(reason),
                level.target_touched_bytes,
            ),
            SimulatedLevelOutcome::SafetyAbort(class) => (
                LevelClassification::SafetyAbort,
                Some(class),
                Some(format!("{class:?}")),
                level.target_touched_bytes,
            ),
            SimulatedLevelOutcome::TouchedBytesMismatch(actual) => (
                LevelClassification::InvalidLevelEvidence,
                None,
                Some("worker_level_contract_failure".into()),
                actual,
            ),
        };
        let mandatory_pass = classification == LevelClassification::Sustainable;
        let failed_gate = match safety_abort {
            Some(SafetyAbortClass::HostPsiEmergency) | Some(SafetyAbortClass::HostOomDetected) => {
                HealthGate::HostPsi
            }
            Some(SafetyAbortClass::CgroupOwnershipLost) => HealthGate::CgroupMembership,
            Some(SafetyAbortClass::WorkerIdentityLost) => HealthGate::WorkerIdentity,
            Some(SafetyAbortClass::WorkerHeartbeatTimeout) => HealthGate::HeartbeatFresh,
            Some(SafetyAbortClass::WatchdogTimeout) => HealthGate::ElapsedDuration,
            Some(SafetyAbortClass::MemoryLimitContractBroken) => HealthGate::MemoryLimitContract,
            Some(SafetyAbortClass::ObserverContractBroken) => HealthGate::ObserverContract,
            Some(SafetyAbortClass::RestoreFailure) => HealthGate::RestoreOwnership,
            None => HealthGate::WorkerIntegrity,
        };
        let health_gates = required_level_health_gates(variant)
            .into_iter()
            .map(|gate| {
                let passed = mandatory_pass || gate != failed_gate;
                (
                    gate,
                    HealthGateResult {
                        passed,
                        mandatory: true,
                        reason: (!passed).then(|| "simulated outcome".into()),
                    },
                )
            })
            .collect();
        LevelEvidence {
            version: LEVEL_EVIDENCE_VERSION,
            experiment_id: "simulated-3c".into(),
            run_id: format!("simulated-{variant:?}-{repetition_index}"),
            variant,
            repetition_index,
            level_index: level.level_index,
            planned_logical_bytes: level.target_logical_bytes,
            actual_touched_bytes: touched,
            worker_acknowledgement: WorkerLevelAcknowledgement {
                experiment_id: "simulated-3c".into(),
                run_id: format!("simulated-{variant:?}-{repetition_index}"),
                level_index: level.level_index,
                seed: level.seed,
                prior_touched_bytes: if level.level_index == 0 {
                    0
                } else {
                    plan.levels[level.level_index - 1].target_touched_bytes
                },
                requested_delta_bytes: if level.level_index == 0 {
                    level.target_touched_bytes
                } else {
                    level.target_touched_bytes
                        - plan.levels[level.level_index - 1].target_touched_bytes
                },
                actual_touched_bytes: touched,
                worker_pid: 4242,
                worker_start_ticks: 31337,
                generator_id: plan.generator_id.clone(),
                generator_version: plan.generator_version,
                integrity_identity: format!("integrity-{}-{}", level.seed, touched),
                acknowledged_monotonic_ns: level.level_index as u64 * 1_000_000,
            },
            worker_memory_max_bytes: plan.worker_memory_max_bytes,
            generator_id: plan.generator_id.clone(),
            generator_version: plan.generator_version,
            workload_identity: format!("workload-{}-{}", level.seed, touched),
            payload_integrity_identity: format!("integrity-{}-{}", level.seed, touched),
            started_monotonic_ns: level.level_index as u64 * 1_000_000,
            ended_monotonic_ns: level.level_index as u64 * 1_000_000
                + plan.hold_duration_ms * 1_000_000,
            stabilization_completed_ms: plan.stabilization_duration_ms,
            duration_ms: plan.hold_duration_ms,
            sample_count: usize::try_from(plan.hold_duration_ms / plan.sample_interval_ms)
                .unwrap_or(1)
                .max(1),
            raw_samples: Vec::new(),
            memory_mean_bytes: Some(touched as f64),
            memory_peak_bytes: Some(touched),
            metrics: vec![
                PressureMetric::measured(
                    "memory_psi_some_total",
                    1.0,
                    "microseconds",
                    PressureMetricScope::WorkerCgroup,
                    "memory.pressure",
                ),
                PressureMetric::unavailable(
                    "energy",
                    "joules",
                    PressureMetricScope::Host,
                    "powercap",
                    "not available in deterministic simulation",
                ),
            ],
            major_fault_delta: Some(0),
            swap_in_bytes_delta: Some(0),
            swap_out_bytes_delta: Some(0),
            block_write_bytes_delta: Some(0),
            watchdog_triggered: matches!(safety_abort, Some(SafetyAbortClass::WatchdogTimeout)),
            oom: u64::from(matches!(
                safety_abort,
                Some(SafetyAbortClass::HostOomDetected)
            )),
            oom_kill: 0,
            health_gates,
            classification,
            safety_abort,
            failure_reason,
        }
    }
}

pub fn simulate_pressure_run(
    plan: &ProgressivePressurePlan,
    variant: BenchmarkVariant,
    repetition_index: usize,
    backend: &SimulatedPressureBackend,
) -> Result<ProgressiveRunEvidence> {
    plan.validate()?;
    let mut evidence = Vec::new();
    let mut planned_levels = plan.levels.clone();
    let mut stopped_reason = "all_planned_levels_completed".to_string();
    for level in &plan.levels {
        let outcome = backend
            .outcomes
            .get(&level.level_index)
            .cloned()
            .unwrap_or(SimulatedLevelOutcome::Sustainable);
        let result = backend.level_evidence(plan, level, variant, repetition_index, outcome);
        result.validate(level, plan)?;
        let stop = match result.classification {
            LevelClassification::Sustainable => false,
            LevelClassification::UnsustainableHealth => {
                plan.stop_policy.stop_after_first_unsustainable
            }
            LevelClassification::InvalidLevelEvidence | LevelClassification::SafetyAbort => true,
        };
        stopped_reason = result
            .failure_reason
            .clone()
            .unwrap_or_else(|| stopped_reason.clone());
        evidence.push(result);
        planned_levels[level.level_index].state = match evidence
            .last()
            .expect("just pushed level evidence")
            .classification
        {
            LevelClassification::Sustainable => PlannedLevelState::CompletedSustainable,
            LevelClassification::UnsustainableHealth => PlannedLevelState::CompletedUnsustainable,
            LevelClassification::InvalidLevelEvidence => PlannedLevelState::InvalidLevelEvidence,
            LevelClassification::SafetyAbort => PlannedLevelState::SafetyAbort,
        };
        if stop {
            let later_state = match evidence
                .last()
                .expect("just pushed level evidence")
                .classification
            {
                LevelClassification::UnsustainableHealth => {
                    PlannedLevelState::NotExecutedAfterUnsustainable
                }
                LevelClassification::InvalidLevelEvidence => {
                    PlannedLevelState::NotExecutedAfterInvalid
                }
                LevelClassification::SafetyAbort => PlannedLevelState::NotExecutedAfterSafetyAbort,
                LevelClassification::Sustainable => unreachable!("sustainable level does not stop"),
            };
            for later in planned_levels.iter_mut().skip(level.level_index + 1) {
                later.state = later_state;
            }
            break;
        }
    }
    Ok(ProgressiveRunEvidence::summarize(
        "simulated-3c",
        &format!("simulated-{variant:?}-{repetition_index}"),
        variant,
        repetition_index,
        planned_levels,
        evidence,
        stopped_reason,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PressureComparisonContract {
    pub scenario: String,
    pub scenario_version: u32,
    pub generator_id: String,
    pub generator_version: u32,
    pub seed: u64,
    pub schedule_hash: String,
    pub refinement_hash: String,
    pub timing_hash: String,
    pub worker_memory_max_bytes: u64,
    pub material_environment_hash: String,
    pub worker_implementation_hash: String,
}

pub fn pressure_runs_comparable(
    baseline: &PressureComparisonContract,
    observe: &PressureComparisonContract,
) -> bool {
    baseline == observe
}

pub fn capacity_gain(
    baseline: &CapacityResult,
    candidate: &CapacityResult,
    comparable: bool,
) -> Option<f64> {
    if !comparable
        || !baseline.search_complete
        || !candidate.search_complete
        || baseline.safety_abort.is_some()
        || candidate.safety_abort.is_some()
        || baseline.capacity_gain_percent != EvaluationState::NotEvaluated
        || candidate.capacity_gain_percent != EvaluationState::NotEvaluated
        || !baseline.internally_consistent()
        || !candidate.internally_consistent()
    {
        return None;
    }
    let baseline_bytes = baseline.highest_tested_sustainable_bytes?;
    let candidate_bytes = candidate.highest_tested_sustainable_bytes?;
    if baseline.lowest_tested_unsustainable_bytes? <= baseline_bytes
        || candidate.lowest_tested_unsustainable_bytes? <= candidate_bytes
    {
        return None;
    }
    (baseline_bytes != 0).then(|| (candidate_bytes as f64 / baseline_bytes as f64 - 1.0) * 100.0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConservativePilotPolicy {
    pub level_permille_of_effective_maximum: Vec<u16>,
    pub alignment_bytes: u64,
}

impl ConservativePilotPolicy {
    pub fn freeze_levels(
        &self,
        reserve: &HeadroomReserve,
        seed: u64,
    ) -> Result<Vec<PlannedPressureLevel>> {
        if self.alignment_bytes == 0
            || self.level_permille_of_effective_maximum.is_empty()
            || self
                .level_permille_of_effective_maximum
                .iter()
                .any(|value| *value == 0 || *value > 1_000)
        {
            bail!("invalid conservative pressure pilot policy");
        }
        let levels = self
            .level_permille_of_effective_maximum
            .iter()
            .enumerate()
            .map(|(level_index, fraction)| {
                let raw = reserve
                    .effective_maximum_bytes
                    .checked_mul(u64::from(*fraction))
                    .ok_or_else(|| anyhow::anyhow!("pilot level overflow"))?
                    / 1_000;
                let bytes = raw / self.alignment_bytes * self.alignment_bytes;
                Ok(PlannedPressureLevel {
                    level_index,
                    target_logical_bytes: bytes,
                    target_touched_bytes: bytes,
                    seed,
                    state: PlannedLevelState::Planned,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if levels.iter().any(|level| level.target_logical_bytes == 0)
            || !levels
                .windows(2)
                .all(|pair| pair[0].target_logical_bytes < pair[1].target_logical_bytes)
        {
            bail!("pilot fractions collapse to zero, duplicate, or unordered levels");
        }
        Ok(levels)
    }
}

use sha2::Digest;

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn fixture_plan() -> ProgressivePressurePlan {
        let headroom = HeadroomPolicy {
            host_reserve_permille: 100,
            minimum_host_reserve_bytes: 256 * MIB,
            runner_reserve_bytes: 64 * MIB,
            observer_reserve_bytes: 64 * MIB,
            rollback_cleanup_reserve_bytes: 128 * MIB,
            operating_system_variance_bytes: 128 * MIB,
        }
        .derive(4 * 1024 * MIB)
        .unwrap();
        ProgressivePressurePlan {
            version: PRESSURE_PLAN_VERSION,
            scenario: PRESSURE_SCENARIO.into(),
            scenario_version: PRESSURE_SCENARIO_VERSION,
            comparison_purpose: PressureComparisonPurpose::PressureFrameworkValidation,
            variants: vec![
                BenchmarkVariant::CachyosBaseline,
                BenchmarkVariant::NemorObserve,
            ],
            generator_id: INCOMPRESSIBLE_GENERATOR_ID.into(),
            generator_version: SYNTHETIC_GENERATOR_VERSION,
            experiment_seed: 7,
            levels: [128, 256, 384]
                .into_iter()
                .enumerate()
                .map(|(level_index, mib)| PlannedPressureLevel {
                    level_index,
                    target_logical_bytes: mib * MIB,
                    target_touched_bytes: mib * MIB,
                    seed: 7,
                    state: PlannedLevelState::Planned,
                })
                .collect(),
            hold_duration_ms: 5_000,
            stabilization_duration_ms: 2_000,
            sample_interval_ms: 1_000,
            worker_memory_max_bytes: 512 * MIB,
            watchdog: PressureWatchdogPolicy {
                heartbeat_timeout_ms: 2_000,
                level_timeout_ms: 10_000,
                total_timeout_ms: 90_000,
            },
            health: PressureHealthPolicy {
                version: PRESSURE_HEALTH_POLICY_VERSION,
                host_psi_full_avg10_emergency: 0.2,
                cgroup_psi_full_avg10_unsustainable: 0.1,
                max_major_faults_per_level: 1_000,
                max_swap_in_bytes_per_level: 64 * MIB,
                max_swap_out_bytes_per_level: 64 * MIB,
                max_block_writes_bytes_per_level: 128 * MIB,
                host_oom_forbidden: true,
                request_oom: false,
                zero_limits_mean_zero_tolerance: true,
            },
            stop_policy: StopPolicy {
                stop_after_first_unsustainable: true,
                stop_immediately_on_safety_abort: true,
                never_use_safety_abort_as_capacity_bound: true,
            },
            refinement: RefinementPolicy {
                mode: RefinementMode::DeterministicBracket,
                granularity_bytes: 16 * MIB,
                maximum_refinements: 3,
            },
            maximum_levels: 6,
            maximum_total_duration_ms: 90_000,
            headroom,
            systemd_transient_scope_required: true,
            exact_owned_worker_required: true,
        }
    }

    #[test]
    fn explicit_scenario_contract_is_incompressible_and_non_capacity() {
        let plan = fixture_plan();
        assert!(plan.validate().is_ok());
        assert_eq!(plan.scenario, "progressive_memory_pressure");
        assert_eq!(plan.scenario_version, 1);
        assert_eq!(plan.generator_id, "nemor.synthetic.splitmix64");
        assert_eq!(
            plan.comparison_purpose,
            PressureComparisonPurpose::PressureFrameworkValidation
        );
    }

    #[test]
    fn fixed_load_contracts_cannot_select_pressure() {
        assert!(crate::performance::generator_contract(PRESSURE_SCENARIO).is_err());
        assert!(
            !crate::performance::PerformanceProfile::checkpoint3a(MIB)
                .unwrap()
                .pressure_mode
        );
        assert!(
            !crate::performance::PerformanceProfile::checkpoint3b(MIB)
                .unwrap()
                .pressure_mode
        );
    }

    #[test]
    fn levels_are_nonzero_strictly_increasing_unique_and_bounded() {
        let mut plan = fixture_plan();
        plan.levels[0].target_logical_bytes = 0;
        plan.levels[0].target_touched_bytes = 0;
        assert!(plan.validate().is_err());
        plan = fixture_plan();
        plan.levels[1].target_logical_bytes = plan.levels[0].target_logical_bytes;
        plan.levels[1].target_touched_bytes = plan.levels[0].target_touched_bytes;
        assert!(plan.validate().is_err());
        plan = fixture_plan();
        plan.levels[1].level_index = plan.levels[0].level_index;
        assert!(plan.validate().is_err());
        plan = fixture_plan();
        plan.levels[2].target_logical_bytes = plan.worker_memory_max_bytes + 1;
        plan.levels[2].target_touched_bytes = plan.worker_memory_max_bytes + 1;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn maximum_count_and_duration_are_enforced() {
        let mut plan = fixture_plan();
        plan.maximum_levels = 2;
        assert!(plan.validate().is_err());
        plan = fixture_plan();
        plan.maximum_total_duration_ms = 20_000;
        assert!(plan.validate().is_err());
        plan = fixture_plan();
        plan.levels.extend(
            (3..=MAX_PRESSURE_LEVELS).map(|level_index| PlannedPressureLevel {
                level_index,
                target_logical_bytes: (level_index as u64 + 1) * 32 * MIB,
                target_touched_bytes: (level_index as u64 + 1) * 32 * MIB,
                seed: 7,
                state: PlannedLevelState::Planned,
            }),
        );
        assert!(plan.validate().is_err());
    }

    #[test]
    fn headroom_is_explicit_and_rejects_unsafe_envelope() {
        let policy = HeadroomPolicy {
            host_reserve_permille: 100,
            minimum_host_reserve_bytes: 200,
            runner_reserve_bytes: 100,
            observer_reserve_bytes: 100,
            rollback_cleanup_reserve_bytes: 100,
            operating_system_variance_bytes: 100,
        };
        let reserve = policy.derive(2_000).unwrap();
        assert_eq!(reserve.total_reserved_bytes, 600);
        assert_eq!(reserve.effective_maximum_bytes, 1_400);
        assert!(policy.derive(500).is_err());
    }

    #[test]
    fn same_memorymax_and_schedule_are_required_for_comparison() {
        let plan = fixture_plan();
        let contract = PressureComparisonContract {
            scenario: plan.scenario.clone(),
            scenario_version: plan.scenario_version,
            generator_id: plan.generator_id.clone(),
            generator_version: plan.generator_version,
            seed: plan.experiment_seed,
            schedule_hash: plan.contract_hash().unwrap(),
            refinement_hash: "refinement".into(),
            timing_hash: "timing".into(),
            worker_memory_max_bytes: plan.worker_memory_max_bytes,
            material_environment_hash: "material".into(),
            worker_implementation_hash: "worker".into(),
        };
        assert!(pressure_runs_comparable(&contract, &contract));
        let mut changed = contract.clone();
        changed.worker_memory_max_bytes += 1;
        assert!(!pressure_runs_comparable(&contract, &changed));
        changed = contract.clone();
        changed.schedule_hash = "different".into();
        assert!(!pressure_runs_comparable(&contract, &changed));
        changed = contract.clone();
        changed.material_environment_hash = "different".into();
        assert!(!pressure_runs_comparable(&contract, &changed));
    }

    #[test]
    fn all_sustainable_simulation_uses_no_memory_or_privilege() {
        let plan = fixture_plan();
        let backend = SimulatedPressureBackend::new(BTreeMap::new());
        let run =
            simulate_pressure_run(&plan, BenchmarkVariant::CachyosBaseline, 0, &backend).unwrap();
        assert_eq!(run.levels.len(), 3);
        assert_eq!(run.highest_tested_sustainable_bytes, Some(384 * MIB));
        assert_eq!(backend.allocated_bytes, 0);
        assert_eq!(backend.privileged_operations, 0);
        assert!(run
            .planned_levels
            .iter()
            .all(|level| level.state == PlannedLevelState::CompletedSustainable));
    }

    #[test]
    fn unsustainable_level_is_preserved_and_stops_later_levels() {
        let plan = fixture_plan();
        let backend = SimulatedPressureBackend::new(BTreeMap::from([(
            1,
            SimulatedLevelOutcome::UnsustainableHealth("cgroup_psi".into()),
        )]));
        let run =
            simulate_pressure_run(&plan, BenchmarkVariant::CachyosBaseline, 0, &backend).unwrap();
        assert_eq!(run.levels.len(), 2);
        assert_eq!(
            run.levels[1].classification,
            LevelClassification::UnsustainableHealth
        );
        assert_eq!(
            run.planned_levels[2].state,
            PlannedLevelState::NotExecutedAfterUnsustainable
        );
        assert_eq!(run.lowest_tested_unsustainable_bytes, Some(256 * MIB));
        assert!(run.refinement_eligible);
    }

    #[test]
    fn safety_abort_is_preserved_never_becomes_capacity_upper_bound() {
        let plan = fixture_plan();
        for class in [
            SafetyAbortClass::HostPsiEmergency,
            SafetyAbortClass::HostOomDetected,
            SafetyAbortClass::CgroupOwnershipLost,
            SafetyAbortClass::WorkerIdentityLost,
            SafetyAbortClass::WorkerHeartbeatTimeout,
            SafetyAbortClass::WatchdogTimeout,
            SafetyAbortClass::MemoryLimitContractBroken,
            SafetyAbortClass::ObserverContractBroken,
            SafetyAbortClass::RestoreFailure,
        ] {
            let backend = SimulatedPressureBackend::new(BTreeMap::from([(
                1,
                SimulatedLevelOutcome::SafetyAbort(class),
            )]));
            let run =
                simulate_pressure_run(&plan, BenchmarkVariant::NemorObserve, 0, &backend).unwrap();
            assert_eq!(run.safety_abort, Some(class));
            assert_eq!(run.lowest_tested_unsustainable_bytes, None);
            assert!(!run.refinement_eligible);
            assert_eq!(
                run.planned_levels[2].state,
                PlannedLevelState::NotExecutedAfterSafetyAbort
            );
            assert_eq!(
                run.capacity.capacity_gain_percent,
                EvaluationState::NotEvaluated
            );
        }
    }

    #[test]
    fn successful_level_requires_exact_actual_touched_bytes() {
        let plan = fixture_plan();
        let backend = SimulatedPressureBackend::new(BTreeMap::from([(
            0,
            SimulatedLevelOutcome::TouchedBytesMismatch(64 * MIB),
        )]));
        let run =
            simulate_pressure_run(&plan, BenchmarkVariant::CachyosBaseline, 0, &backend).unwrap();
        assert_eq!(
            run.levels[0].classification,
            LevelClassification::InvalidLevelEvidence
        );
        assert_eq!(
            run.levels[0].failure_reason.as_deref(),
            Some("worker_level_contract_failure")
        );
        assert_eq!(run.lowest_tested_unsustainable_bytes, None);
        assert!(!run.refinement_eligible);
    }

    #[test]
    fn refinement_requires_tested_bracket_is_internal_unique_and_deterministic() {
        let policy = RefinementPolicy {
            mode: RefinementMode::DeterministicBracket,
            granularity_bytes: 16,
            maximum_refinements: 3,
        };
        let tested = BTreeSet::from([128, 256]);
        let first = next_refinement(128, 256, &policy, &tested, 0).unwrap();
        let second = next_refinement(128, 256, &policy, &tested, 0).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.next_test_bytes, Some(192));
        assert!(first.next_test_bytes.unwrap() > 128);
        assert!(first.next_test_bytes.unwrap() < 256);
        assert!(next_refinement(64, 256, &policy, &tested, 0).is_err());
        let tested = BTreeSet::from([128, 192, 256]);
        assert_ne!(
            next_refinement(128, 256, &policy, &tested, 1)
                .unwrap()
                .next_test_bytes,
            Some(192)
        );
        assert_eq!(
            next_refinement(128, 256, &policy, &BTreeSet::from([128, 256]), 3)
                .unwrap()
                .next_test_bytes,
            None
        );
    }

    #[test]
    fn highest_sustainable_is_actual_and_never_interpolated() {
        let plan = fixture_plan();
        let backend = SimulatedPressureBackend::new(BTreeMap::from([(
            2,
            SimulatedLevelOutcome::UnsustainableHealth("swap_activity".into()),
        )]));
        let run =
            simulate_pressure_run(&plan, BenchmarkVariant::CachyosBaseline, 0, &backend).unwrap();
        assert_eq!(run.highest_tested_sustainable_bytes, Some(256 * MIB));
        assert!(run
            .levels
            .iter()
            .any(|level| level.actual_touched_bytes == 256 * MIB));
        assert_eq!(run.lowest_tested_unsustainable_bytes, Some(384 * MIB));
    }

    #[test]
    fn host_and_cgroup_psi_scopes_are_distinct_and_missing_is_not_zero() {
        let host = PressureMetric::unavailable(
            "psi_full",
            "microseconds",
            PressureMetricScope::Host,
            "/proc/pressure/memory",
            "unavailable",
        );
        let cgroup = PressureMetric::measured(
            "psi_full",
            0.0,
            "microseconds",
            PressureMetricScope::WorkerCgroup,
            "memory.pressure",
        );
        assert_ne!(host.scope, cgroup.scope);
        assert!(!host.available);
        assert_eq!(host.value, None);
        assert!(cgroup.available);
        assert_eq!(cgroup.value, Some(0.0));
    }

    #[test]
    fn swap_runtime_activity_is_not_swap_topology() {
        let runtime = PressureMetric::measured(
            "swap_out_bytes_delta",
            4096.0,
            "bytes",
            PressureMetricScope::Host,
            "/proc/vmstat",
        );
        let topology = "type=partition size_kib=1024 priority=100";
        assert_eq!(runtime.name, "swap_out_bytes_delta");
        assert!(!topology.contains("delta"));
    }

    #[test]
    fn capacity_gain_waits_for_complete_comparable_non_abort_searches() {
        let incomplete = CapacityResult::from_summary(Some(100), Some(200), false, None);
        let complete = CapacityResult::from_summary(Some(100), Some(200), true, None);
        assert_eq!(capacity_gain(&incomplete, &complete, true), None);
        assert_eq!(capacity_gain(&complete, &complete, false), None);
        assert_eq!(capacity_gain(&complete, &complete, true), Some(0.0));
        let aborted = CapacityResult::from_summary(
            Some(100),
            Some(200),
            false,
            Some(SafetyAbortClass::HostOomDetected),
        );
        assert_eq!(capacity_gain(&complete, &aborted, true), None);
    }

    #[test]
    fn conservative_pilot_policy_freezes_exact_bytes_only_at_preparation() {
        let reserve = HeadroomPolicy {
            host_reserve_permille: 100,
            minimum_host_reserve_bytes: 256 * MIB,
            runner_reserve_bytes: 64 * MIB,
            observer_reserve_bytes: 64 * MIB,
            rollback_cleanup_reserve_bytes: 128 * MIB,
            operating_system_variance_bytes: 128 * MIB,
        }
        .derive(4 * 1024 * MIB)
        .unwrap();
        let policy = ConservativePilotPolicy {
            level_permille_of_effective_maximum: vec![100, 200, 300],
            alignment_bytes: 16 * MIB,
        };
        let levels = policy.freeze_levels(&reserve, 7).unwrap();
        assert_eq!(levels.len(), 3);
        assert!(levels
            .windows(2)
            .all(|pair| { pair[0].target_logical_bytes < pair[1].target_logical_bytes }));
        assert!(levels.iter().all(|level| {
            level.target_logical_bytes % (16 * MIB) == 0
                && level.target_logical_bytes <= reserve.effective_maximum_bytes
        }));
    }

    #[test]
    fn serialized_plan_freezes_every_pressure_contract_input() {
        let plan = fixture_plan();
        let json = serde_json::to_value(&plan).unwrap();
        for field in [
            "scenario",
            "scenario_version",
            "generator_id",
            "generator_version",
            "experiment_seed",
            "levels",
            "hold_duration_ms",
            "stabilization_duration_ms",
            "sample_interval_ms",
            "worker_memory_max_bytes",
            "watchdog",
            "health",
            "stop_policy",
            "refinement",
            "maximum_levels",
            "maximum_total_duration_ms",
            "headroom",
        ] {
            assert!(json.get(field).is_some(), "missing {field}");
        }
    }

    #[test]
    fn framework_manifest_is_non_live_and_preflight_binding_is_mandatory() {
        let plan = fixture_plan();
        let manifest = PressureFrameworkManifest {
            version: PRESSURE_FRAMEWORK_MANIFEST_VERSION,
            plan: plan.clone(),
            material_environment_schema_version: crate::MATERIAL_ENVIRONMENT_SCHEMA_VERSION,
            material_environment_hash: "material-environment".into(),
            worker_implementation_hash: "worker-implementation".into(),
            live_execution_enabled: false,
        };
        assert!(manifest.validate().is_ok());
        let binding = PressureRunPreflightBinding {
            run_order_index: 0,
            material_environment_hash: manifest.material_environment_hash.clone(),
            plan_contract_hash: plan.contract_hash().unwrap(),
            worker_implementation_hash: manifest.worker_implementation_hash.clone(),
        };
        assert!(binding.validate(&manifest, 0).is_ok());
        let mut mismatch = binding.clone();
        mismatch.material_environment_hash = "full-observational-hash".into();
        assert!(mismatch.validate(&manifest, 0).is_err());
        let mut live = manifest;
        live.live_execution_enabled = true;
        assert!(live.validate().is_err());
    }

    fn sustainable_level_fixture(
        variant: BenchmarkVariant,
    ) -> (ProgressivePressurePlan, LevelEvidence) {
        let plan = fixture_plan();
        let evidence = SimulatedPressureBackend::new(BTreeMap::new()).level_evidence(
            &plan,
            &plan.levels[0],
            variant,
            0,
            SimulatedLevelOutcome::Sustainable,
        );
        (plan, evidence)
    }

    #[test]
    fn sustainable_requires_complete_authoritative_gate_set() {
        let (plan, mut evidence) = sustainable_level_fixture(BenchmarkVariant::CachyosBaseline);
        evidence.health_gates.remove(&HealthGate::WorkerAlive);
        assert!(evidence.validate(&plan.levels[0], &plan).is_err());
        evidence.health_gates.clear();
        assert!(evidence.validate(&plan.levels[0], &plan).is_err());
    }

    #[test]
    fn sustainable_rejects_any_failed_or_nonmandatory_required_gate() {
        let (plan, mut evidence) = sustainable_level_fixture(BenchmarkVariant::NemorObserve);
        evidence
            .health_gates
            .get_mut(&HealthGate::ObserverContract)
            .unwrap()
            .passed = false;
        assert!(evidence.validate(&plan.levels[0], &plan).is_err());
        evidence
            .health_gates
            .get_mut(&HealthGate::ObserverContract)
            .unwrap()
            .passed = true;
        evidence
            .health_gates
            .get_mut(&HealthGate::RunnerCpu)
            .unwrap()
            .mandatory = false;
        assert!(evidence.validate(&plan.levels[0], &plan).is_err());
    }

    #[test]
    fn completed_level_requires_full_sample_and_monotonic_duration_coverage() {
        let (plan, mut evidence) = sustainable_level_fixture(BenchmarkVariant::CachyosBaseline);
        evidence.sample_count = 1;
        assert!(evidence.validate(&plan.levels[0], &plan).is_err());
        let (_, mut evidence) = sustainable_level_fixture(BenchmarkVariant::CachyosBaseline);
        evidence.duration_ms = 0;
        evidence.ended_monotonic_ns = evidence.started_monotonic_ns;
        assert!(evidence.validate(&plan.levels[0], &plan).is_err());
    }

    #[test]
    fn stop_policy_and_watchdog_cover_the_complete_frozen_path() {
        let mut plan = fixture_plan();
        plan.stop_policy.stop_after_first_unsustainable = false;
        assert!(plan.validate().is_err());
        let mut plan = fixture_plan();
        plan.watchdog.total_timeout_ms = 0;
        assert!(plan.validate().is_err());
        let mut plan = fixture_plan();
        plan.watchdog.total_timeout_ms = 10_000;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn psi_thresholds_reject_nan_infinity_negative_and_out_of_range() {
        for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1, 100.1] {
            let mut plan = fixture_plan();
            plan.health.host_psi_full_avg10_emergency = invalid;
            assert!(plan.validate().is_err());
            let mut plan = fixture_plan();
            plan.health.cgroup_psi_full_avg10_unsustainable = invalid;
            assert!(plan.validate().is_err());
        }
        assert!(!psi_avg10_threshold_crossed(0.19, 0.20).unwrap());
        assert!(psi_avg10_threshold_crossed(0.20, 0.20).unwrap());
        assert!(!psi_avg10_threshold_crossed(0.09, 0.10).unwrap());
        assert!(psi_avg10_threshold_crossed(0.10, 0.10).unwrap());
        assert_eq!(PSI_AVG10_UNIT, "percent_stall_time_as_emitted_by_linux");
    }

    #[test]
    fn capacity_result_must_match_actual_valid_level_evidence() {
        let plan = fixture_plan();
        let run = simulate_pressure_run(
            &plan,
            BenchmarkVariant::CachyosBaseline,
            0,
            &SimulatedPressureBackend::new(BTreeMap::from([(
                1,
                SimulatedLevelOutcome::UnsustainableHealth("health".into()),
            )])),
        )
        .unwrap();
        assert!(run.capacity.validate(&run.levels).is_ok());
        let mut fabricated = run.capacity;
        fabricated.highest_tested_sustainable_bytes = Some(999);
        fabricated.search_complete = true;
        assert!(fabricated.validate(&run.levels).is_err());
        assert_eq!(capacity_gain(&fabricated, &fabricated, true), None);
    }

    #[test]
    fn host_oom_is_distinct_safety_abort_and_never_refines() {
        let plan = fixture_plan();
        let run = simulate_pressure_run(
            &plan,
            BenchmarkVariant::CachyosBaseline,
            0,
            &SimulatedPressureBackend::new(BTreeMap::from([(
                1,
                SimulatedLevelOutcome::SafetyAbort(SafetyAbortClass::HostOomDetected),
            )])),
        )
        .unwrap();
        assert_eq!(run.safety_abort, Some(SafetyAbortClass::HostOomDetected));
        assert!(!run.refinement_eligible);
        assert_eq!(run.lowest_tested_unsustainable_bytes, None);
    }

    #[test]
    fn telemetry_sources_and_preallocation_emergency_order_are_explicit() {
        let contract = LiveTelemetryContract::checkpoint3c_v1();
        assert!(contract.host_oom_separate_from_cgroup_events);
        assert!(contract.unavailable_is_not_zero);
        let abort = next_level_action_order(true);
        assert_eq!(abort[0], PressureExecutorAction::CheckEmergencyGates);
        assert!(!abort.contains(&PressureExecutorAction::IssueNextLevel));
        let proceed = next_level_action_order(false);
        assert_eq!(proceed[0], PressureExecutorAction::CheckEmergencyGates);
        assert_eq!(
            proceed.last(),
            Some(&PressureExecutorAction::IssueNextLevel)
        );
    }
}
