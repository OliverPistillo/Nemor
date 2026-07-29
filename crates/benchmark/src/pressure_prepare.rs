//! Unprivileged Checkpoint 3C live-pilot preparation bridge.
//!
//! Preparation captures and freezes contracts only. This module has no
//! systemd, cgroup, workload-allocation, observer-start, or execution path.

use crate::observer_service::{ObserverServicePlan, OBSERVER_PROPERTY_CONTRACT_VERSION};
use crate::performance::{
    validate_observer_run_uniqueness, BinaryIdentity, PreparedObserveRun,
    INCOMPRESSIBLE_GENERATOR_ID, SYNTHETIC_GENERATOR_VERSION,
};
use crate::pressure::{
    ConservativePilotPolicy, HeadroomPolicy, HeadroomReserve, PlannedPressureLevel,
    PressureComparisonPurpose, PressureHealthPolicy, PressureWatchdogPolicy,
    ProgressivePressurePlan, RefinementMode, RefinementPolicy, StopPolicy,
    PRESSURE_HEALTH_POLICY_VERSION, PRESSURE_PLAN_VERSION, PRESSURE_SCENARIO,
    PRESSURE_SCENARIO_VERSION,
};
use crate::{
    deterministic_order, now_ns, BenchmarkVariant, BuildProvenance, EnvironmentFingerprint,
    EvaluationState, MATERIAL_ENVIRONMENT_SCHEMA_VERSION,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const PREPARED_PRESSURE_SCHEMA_VERSION: u32 = 6;
pub const PRESSURE_RUN_PLAN_VERSION: u32 = 1;
pub const CONSERVATIVE_PILOT_POLICY_VERSION: u32 = 1;
pub const PRESSURE_WORKER_PROTOCOL_VERSION: u32 = 1;
pub const MIB: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureRunState {
    Planned,
    Completed,
    Invalid,
    UnsustainableBoundary,
    SafetyAbort,
    NotExecutedAfterStop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedPressureRun {
    pub order_index: usize,
    pub variant: BenchmarkVariant,
    pub repetition_index: usize,
    pub run_seed: u64,
    pub state: PressureRunState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PressureExperimentRunPlan {
    pub version: u32,
    pub repetitions: usize,
    pub experiment_seed: u64,
    pub runs: Vec<PlannedPressureRun>,
    pub automatic_retry: bool,
}

impl PressureExperimentRunPlan {
    pub fn new(experiment_seed: u64) -> Self {
        let variants = [
            BenchmarkVariant::CachyosBaseline,
            BenchmarkVariant::NemorObserve,
        ];
        let runs = deterministic_order(&variants, 3, experiment_seed)
            .into_iter()
            .enumerate()
            .map(
                |(order_index, (variant, repetition_index))| PlannedPressureRun {
                    order_index,
                    variant,
                    repetition_index,
                    run_seed: paired_run_seed(experiment_seed, repetition_index),
                    state: PressureRunState::Planned,
                },
            )
            .collect();
        Self {
            version: PRESSURE_RUN_PLAN_VERSION,
            repetitions: 3,
            experiment_seed,
            runs,
            automatic_retry: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != PRESSURE_RUN_PLAN_VERSION
            || self.repetitions != 3
            || self.runs.len() != 6
            || self.automatic_retry
        {
            bail!("invalid Checkpoint 3C six-run plan");
        }
        let expected = Self::new(self.experiment_seed);
        if &expected != self {
            bail!("pressure run order or paired seeds are not deterministic");
        }
        for repetition in 0..3 {
            let paired = self
                .runs
                .iter()
                .filter(|run| run.repetition_index == repetition)
                .collect::<Vec<_>>();
            if paired.len() != 2
                || paired[0].run_seed != paired[1].run_seed
                || !paired
                    .iter()
                    .any(|run| run.variant == BenchmarkVariant::CachyosBaseline)
                || !paired
                    .iter()
                    .any(|run| run.variant == BenchmarkVariant::NemorObserve)
            {
                bail!("pressure repetition is not an exact baseline/observe seed pair");
            }
        }
        Ok(())
    }
}

pub fn paired_run_seed(experiment_seed: u64, repetition_index: usize) -> u64 {
    experiment_seed.rotate_left(17) ^ repetition_index as u64
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotPolicyV1 {
    pub version: u32,
    pub fractions_permille: Vec<u16>,
    pub alignment_bytes: u64,
    pub refinement_mode: RefinementMode,
}

impl PilotPolicyV1 {
    pub fn conservative_v1() -> Self {
        Self {
            version: CONSERVATIVE_PILOT_POLICY_VERSION,
            fractions_permille: vec![100, 200, 300],
            alignment_bytes: 16 * MIB,
            refinement_mode: RefinementMode::DisabledForFrameworkPilot,
        }
    }

    pub fn freeze(
        &self,
        reserve: &HeadroomReserve,
        seed: u64,
    ) -> Result<Vec<PlannedPressureLevel>> {
        if self.version != CONSERVATIVE_PILOT_POLICY_VERSION
            || self.fractions_permille != [100, 200, 300]
            || self.alignment_bytes != 16 * MIB
            || self.refinement_mode != RefinementMode::DisabledForFrameworkPilot
        {
            bail!("unsupported conservative pilot policy");
        }
        let levels = ConservativePilotPolicy {
            level_permille_of_effective_maximum: self.fractions_permille.clone(),
            alignment_bytes: self.alignment_bytes,
        }
        .freeze_levels(reserve, seed)?;
        let unique = levels
            .iter()
            .map(|level| level.target_logical_bytes)
            .collect::<BTreeSet<_>>();
        if levels.len() != 3
            || unique.len() != 3
            || levels.iter().any(|level| level.target_logical_bytes == 0)
            || !levels
                .windows(2)
                .all(|pair| pair[0].target_logical_bytes < pair[1].target_logical_bytes)
        {
            bail!("10/20/30 pilot cannot produce nonzero unique increasing aligned levels");
        }
        Ok(levels)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryMaxDerivation {
    pub highest_target_bytes: u64,
    pub worker_margin_bytes: u64,
    pub alignment_bytes: u64,
    pub shared_memory_max_bytes: u64,
}

pub fn derive_memory_max(
    highest_target_bytes: u64,
    effective_maximum_bytes: u64,
    alignment_bytes: u64,
) -> Result<MemoryMaxDerivation> {
    if alignment_bytes == 0 || highest_target_bytes == 0 {
        bail!("MemoryMax derivation requires nonzero target and alignment");
    }
    let margin = (highest_target_bytes / 10).max(64 * MIB);
    let unaligned = highest_target_bytes
        .checked_add(margin)
        .ok_or_else(|| anyhow::anyhow!("MemoryMax derivation overflow"))?;
    let rounded = unaligned
        .checked_add(alignment_bytes - 1)
        .ok_or_else(|| anyhow::anyhow!("MemoryMax alignment overflow"))?
        / alignment_bytes
        * alignment_bytes;
    if rounded > effective_maximum_bytes || rounded <= highest_target_bytes {
        bail!("shared MemoryMax is outside the safe effective envelope");
    }
    Ok(MemoryMaxDerivation {
        highest_target_bytes,
        worker_margin_bytes: rounded - highest_target_bytes,
        alignment_bytes,
        shared_memory_max_bytes: rounded,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PressurePreparationAudit {
    pub privileged_operations: u32,
    pub systemd_units_started: u32,
    pub cgroup_writes: u32,
    pub workload_bytes_allocated: u64,
    pub observer_processes_started: u32,
}

impl PressurePreparationAudit {
    fn unprivileged_only() -> Self {
        Self {
            privileged_operations: 0,
            systemd_units_started: 0,
            cgroup_writes: 0,
            workload_bytes_allocated: 0,
            observer_processes_started: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedPressurePayload {
    pub schema_version: u32,
    pub experiment_id: String,
    pub scenario: String,
    pub scenario_version: u32,
    pub comparison_purpose: PressureComparisonPurpose,
    pub generator_id: String,
    pub generator_version: u32,
    pub provenance: BuildProvenance,
    pub runner_binary: BinaryIdentity,
    pub observer_binary: BinaryIdentity,
    pub worker_implementation_identity: String,
    pub worker_protocol_version: u32,
    pub pressure_executor_schema_version: u32,
    pub worker_executable_path: PathBuf,
    pub config_sha256: String,
    pub environment: EnvironmentFingerprint,
    pub environment_hash: String,
    pub material_environment_schema_version: u32,
    pub material_environment_hash: String,
    pub performance_source_eligible: bool,
    pub preparing_uid: u32,
    pub preparing_gid: u32,
    pub repository: PathBuf,
    pub config_path: PathBuf,
    pub runner_path: PathBuf,
    pub observer_path: PathBuf,
    pub prepared_root: PathBuf,
    pub output_root: PathBuf,
    pub database_path: PathBuf,
    pub report_path: PathBuf,
    pub runs_path: PathBuf,
    pub input_available_memory_bytes: u64,
    pub headroom_policy: HeadroomPolicy,
    pub headroom: HeadroomReserve,
    pub pilot_policy: PilotPolicyV1,
    pub memory_max_derivation: MemoryMaxDerivation,
    pub run_plan: PressureExperimentRunPlan,
    pub pressure_plans: Vec<ProgressivePressurePlan>,
    pub expected_level_workload_identities: Vec<Vec<String>>,
    pub observer_property_contract_version: u32,
    pub observer_runs: Vec<PreparedObserveRun>,
    pub capacity_gain_percent: EvaluationState,
    pub search_complete: bool,
    pub preparation_audit: PressurePreparationAudit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedPressureManifest {
    pub payload: PreparedPressurePayload,
    pub payload_sha256: String,
}

impl PreparedPressureManifest {
    pub fn verify_payload(&self) -> Result<()> {
        let expected = hex::encode(Sha256::digest(serde_json::to_vec(&self.payload)?));
        if self.payload_sha256 != expected {
            bail!("prepared pressure manifest payload integrity mismatch");
        }
        self.payload.run_plan.validate()?;
        if self.payload.schema_version != PREPARED_PRESSURE_SCHEMA_VERSION
            || self.payload.scenario != PRESSURE_SCENARIO
            || self.payload.scenario_version != PRESSURE_SCENARIO_VERSION
            || self.payload.comparison_purpose
                != PressureComparisonPurpose::PressureFrameworkValidation
            || self.payload.generator_id != INCOMPRESSIBLE_GENERATOR_ID
            || self.payload.generator_version != SYNTHETIC_GENERATOR_VERSION
            || self.payload.worker_protocol_version
                != crate::pressure_worker::PRESSURE_WORKER_PROTOCOL_VERSION
            || self.payload.pressure_executor_schema_version
                != crate::pressure_live::PRESSURE_EXECUTION_SCHEMA_VERSION
            || self.payload.worker_executable_path != self.payload.runner_path
            || self.payload.pressure_plans.len() != 6
            || self.payload.expected_level_workload_identities.len() != 6
            || self.payload.observer_runs.len() != 3
            || self.payload.observer_property_contract_version != OBSERVER_PROPERTY_CONTRACT_VERSION
            || !self.payload.performance_source_eligible
            || self.payload.search_complete
            || self.payload.capacity_gain_percent != EvaluationState::NotEvaluated
            || self.payload.preparation_audit != PressurePreparationAudit::unprivileged_only()
        {
            bail!("prepared pressure manifest is not the exact V1 framework pilot contract");
        }
        if self
            .payload
            .headroom_policy
            .derive(self.payload.input_available_memory_bytes)?
            != self.payload.headroom
        {
            bail!("prepared pressure headroom derivation is not reproducible");
        }
        for (run, plan) in self
            .payload
            .run_plan
            .runs
            .iter()
            .zip(&self.payload.pressure_plans)
        {
            plan.validate()?;
            if plan.experiment_seed != run.run_seed
                || plan.refinement.mode != RefinementMode::DisabledForFrameworkPilot
                || plan.worker_memory_max_bytes
                    != self.payload.memory_max_derivation.shared_memory_max_bytes
            {
                bail!("per-run pressure contract differs from the paired frozen pilot");
            }
        }
        for ((run, plan), identities) in self
            .payload
            .run_plan
            .runs
            .iter()
            .zip(&self.payload.pressure_plans)
            .zip(&self.payload.expected_level_workload_identities)
        {
            if identities.len() != plan.levels.len() {
                bail!("prepared pressure workload identity schedule is incomplete");
            }
            for (level, frozen) in plan.levels.iter().zip(identities) {
                let expected = crate::pressure::pressure_workload_identity(
                    &crate::pressure::PressureWorkloadIdentityContract {
                        domain: "nemor.phase10.pressure_workload",
                        version: crate::pressure::PRESSURE_WORKLOAD_IDENTITY_VERSION,
                        scenario: &plan.scenario,
                        scenario_version: plan.scenario_version,
                        generator_id: &plan.generator_id,
                        generator_version: plan.generator_version,
                        run_seed: run.run_seed,
                        level_index: level.level_index,
                        planned_logical_bytes: level.target_logical_bytes,
                        planned_touched_bytes: level.target_touched_bytes,
                        pressure_plan_version: plan.version,
                        worker_implementation_identity: &self
                            .payload
                            .worker_implementation_identity,
                    },
                )?;
                if frozen != &expected {
                    bail!("prepared pressure workload identity is not integrity-bound");
                }
            }
        }
        for repetition in 0..3 {
            let paired = self
                .payload
                .run_plan
                .runs
                .iter()
                .enumerate()
                .filter(|(_, run)| run.repetition_index == repetition)
                .collect::<Vec<_>>();
            if paired.len() != 2
                || self.payload.pressure_plans[paired[0].0].contract_hash()?
                    != self.payload.pressure_plans[paired[1].0].contract_hash()?
            {
                bail!("paired baseline/observe pressure contracts differ");
            }
        }
        validate_observer_run_uniqueness(&self.payload.observer_runs)?;
        Ok(())
    }
}

fn default_headroom_policy() -> HeadroomPolicy {
    HeadroomPolicy {
        host_reserve_permille: 250,
        minimum_host_reserve_bytes: 2 * 1024 * MIB,
        runner_reserve_bytes: 256 * MIB,
        observer_reserve_bytes: 128 * MIB,
        rollback_cleanup_reserve_bytes: 512 * MIB,
        operating_system_variance_bytes: 1024 * MIB,
    }
}

fn read_mem_available() -> Result<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|value| value.split_whitespace().next())
        .context("MemAvailable is unavailable")?
        .parse::<u64>()?;
    kib.checked_mul(1024)
        .ok_or_else(|| anyhow::anyhow!("MemAvailable overflow"))
}

pub fn validate_preparing_uid(euid: u32) -> Result<()> {
    if euid == 0 {
        bail!("pressure experiment preparation must run unprivileged");
    }
    Ok(())
}

pub fn validate_fresh_pressure_paths(prepared_root: &Path, output_root: &Path) -> Result<()> {
    if prepared_root.exists() || output_root.exists() {
        bail!("pressure prepared/output path already exists; refusing reuse");
    }
    if !prepared_root.is_absolute() || !output_root.is_absolute() {
        bail!("pressure prepared/output paths must be absolute");
    }
    Ok(())
}

pub fn validate_empty_pressure_output(output_root: &Path) -> Result<()> {
    if fs::read_dir(output_root)?.next().is_some() {
        bail!("pressure output root is not empty after preparation");
    }
    Ok(())
}

fn pressure_observer_run_id(
    experiment_id: &str,
    order_index: usize,
    repetition_index: usize,
) -> String {
    format!("c3c-o{order_index}-r{repetition_index}-{experiment_id}")
}

pub fn pressure_observer_runtime_max_usec(plan: &ProgressivePressurePlan) -> Result<u64> {
    let level_ms = plan
        .watchdog
        .level_transition_timeout_ms
        .checked_add(plan.stabilization_duration_ms)
        .and_then(|value| value.checked_add(plan.hold_duration_ms))
        .context("pressure observer per-level duration overflow")?;
    let measured_ms = (plan.levels.len() as u64)
        .checked_mul(level_ms)
        .context("pressure observer measured duration overflow")?;
    let runtime_ms = measured_ms
        .checked_add(5_000) // bounded startup/readiness
        .and_then(|value| value.checked_add(5_000)) // bounded exact-owned cleanup
        .and_then(|value| value.checked_add(3_000)) // scheduler margin
        .context("pressure observer runtime overflow")?;
    let runtime_usec = runtime_ms
        .checked_mul(1_000)
        .context("pressure observer runtime usec overflow")?;
    if runtime_usec > crate::observer_service::PERFORMANCE_SERVICE_RUNTIME_MAX_USEC {
        bail!("pressure observer lifecycle exceeds the hard RuntimeMax");
    }
    Ok(runtime_usec)
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_pressure_experiment(
    repository: &Path,
    config: &Path,
    observer_binary: &Path,
    prepared_root: &Path,
    output_root: &Path,
    seed: u64,
) -> Result<PathBuf> {
    validate_preparing_uid(nix::unistd::geteuid().as_raw())?;
    validate_fresh_pressure_paths(prepared_root, output_root)?;
    let repository = repository.canonicalize()?;
    if std::env::current_dir()?.canonicalize()? != repository || !repository.join(".git").exists() {
        bail!("pressure preparation repository is not the explicit current repository");
    }
    let config = config.canonicalize()?;
    let observer_path = observer_binary.canonicalize()?;
    let runner_path = std::env::current_exe()?.canonicalize()?;
    let loaded = common::LoadedConfig::load(&config)?;
    let provenance = BuildProvenance::capture()?;
    let runner_binary = BinaryIdentity::capture(
        "nemor_benchmark",
        &runner_path,
        &provenance.source_state_id,
        &provenance.git_head,
    )?;
    let observer_identity = BinaryIdentity::capture(
        "nemord",
        &observer_path,
        &provenance.source_state_id,
        &provenance.git_head,
    )?;
    if !provenance.clean_release_eligible()
        || runner_binary.build_profile != "release"
        || observer_identity.build_profile != "release"
        || runner_binary.sha256 != provenance.binary_sha256
    {
        bail!("pressure preparation requires exact clean release provenance");
    }
    let environment =
        EnvironmentFingerprint::capture_for_performance(&loaded.sha256, &provenance.git_head)?;
    let environment_hash = environment.hash()?;
    let material_environment_hash = environment.material_hash()?;
    let available = read_mem_available()?;
    let headroom_policy = default_headroom_policy();
    let headroom = headroom_policy.derive(available)?;
    let pilot_policy = PilotPolicyV1::conservative_v1();
    let base_levels = pilot_policy.freeze(&headroom, seed)?;
    let highest = base_levels
        .last()
        .context("conservative pilot produced no levels")?
        .target_logical_bytes;
    let memory_max_derivation =
        derive_memory_max(highest, headroom.effective_maximum_bytes, 16 * MIB)?;
    let run_plan = PressureExperimentRunPlan::new(seed);
    run_plan.validate()?;
    let pressure_plans = run_plan
        .runs
        .iter()
        .map(|run| {
            let mut levels = pilot_policy.freeze(&headroom, run.run_seed)?;
            for level in &mut levels {
                level.seed = run.run_seed;
            }
            let plan = ProgressivePressurePlan {
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
                experiment_seed: run.run_seed,
                levels,
                hold_duration_ms: 5_000,
                stabilization_duration_ms: 2_000,
                sample_interval_ms: 1_000,
                worker_memory_max_bytes: memory_max_derivation.shared_memory_max_bytes,
                watchdog: PressureWatchdogPolicy {
                    heartbeat_timeout_ms: 2_000,
                    level_transition_timeout_ms: 8_000,
                    level_timeout_ms: 17_000,
                    total_timeout_ms: 51_000,
                },
                health: PressureHealthPolicy {
                    version: PRESSURE_HEALTH_POLICY_VERSION,
                    host_psi_full_avg10_emergency: 0.20,
                    cgroup_psi_full_avg10_unsustainable: 0.10,
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
                    mode: RefinementMode::DisabledForFrameworkPilot,
                    granularity_bytes: 16 * MIB,
                    maximum_refinements: 0,
                },
                maximum_levels: 3,
                maximum_total_duration_ms: 51_000,
                headroom: headroom.clone(),
                systemd_transient_scope_required: true,
                exact_owned_worker_required: true,
            };
            plan.validate()?;
            Ok(plan)
        })
        .collect::<Result<Vec<_>>>()?;
    let experiment_id = format!("checkpoint3c-{}", now_ns());
    fs::create_dir(prepared_root)?;
    fs::set_permissions(prepared_root, fs::Permissions::from_mode(0o755))?;
    fs::create_dir(output_root)?;
    fs::set_permissions(output_root, fs::Permissions::from_mode(0o755))?;
    let observer_runs = run_plan
        .runs
        .iter()
        .filter(|run| run.variant == BenchmarkVariant::NemorObserve)
        .map(|run| {
            let run_id =
                pressure_observer_run_id(&experiment_id, run.order_index, run.repetition_index);
            let (binary, staged_config) = crate::observer_service::staged_observer_paths(&run_id)?;
            let service_plan = ObserverServicePlan::new_with_runtime(
                &run_id,
                binary,
                staged_config,
                pressure_observer_runtime_max_usec(
                    pressure_plans
                        .get(run.order_index)
                        .context("pressure plan missing for observer RuntimeMax")?,
                )?,
            )?;
            let prepared_config_path =
                prepared_root.join(format!("observe-{}.toml", run.order_index));
            let prepared_config_sha256 = crate::performance::write_inspection_config(
                &config,
                &service_plan.database,
                &prepared_config_path,
            )?;
            Ok(PreparedObserveRun {
                order_index: run.order_index,
                repetition_index: run.repetition_index,
                run_id,
                service_plan,
                prepared_config_path,
                prepared_config_sha256,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    validate_observer_run_uniqueness(&observer_runs)?;
    let worker_implementation_identity = hex::encode(Sha256::digest(format!(
        "{}:{}:{}:{}",
        runner_binary.sha256,
        PRESSURE_WORKER_PROTOCOL_VERSION,
        INCOMPRESSIBLE_GENERATOR_ID,
        SYNTHETIC_GENERATOR_VERSION
    )));
    let expected_level_workload_identities = run_plan
        .runs
        .iter()
        .zip(&pressure_plans)
        .map(|(run, plan)| {
            plan.levels
                .iter()
                .map(|level| {
                    crate::pressure::pressure_workload_identity(
                        &crate::pressure::PressureWorkloadIdentityContract {
                            domain: "nemor.phase10.pressure_workload",
                            version: crate::pressure::PRESSURE_WORKLOAD_IDENTITY_VERSION,
                            scenario: &plan.scenario,
                            scenario_version: plan.scenario_version,
                            generator_id: &plan.generator_id,
                            generator_version: plan.generator_version,
                            run_seed: run.run_seed,
                            level_index: level.level_index,
                            planned_logical_bytes: level.target_logical_bytes,
                            planned_touched_bytes: level.target_touched_bytes,
                            pressure_plan_version: plan.version,
                            worker_implementation_identity: &worker_implementation_identity,
                        },
                    )
                })
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    let payload = PreparedPressurePayload {
        schema_version: PREPARED_PRESSURE_SCHEMA_VERSION,
        experiment_id,
        scenario: PRESSURE_SCENARIO.into(),
        scenario_version: PRESSURE_SCENARIO_VERSION,
        comparison_purpose: PressureComparisonPurpose::PressureFrameworkValidation,
        generator_id: INCOMPRESSIBLE_GENERATOR_ID.into(),
        generator_version: SYNTHETIC_GENERATOR_VERSION,
        provenance,
        runner_binary,
        observer_binary: observer_identity,
        worker_implementation_identity,
        worker_protocol_version: crate::pressure_worker::PRESSURE_WORKER_PROTOCOL_VERSION,
        pressure_executor_schema_version: crate::pressure_live::PRESSURE_EXECUTION_SCHEMA_VERSION,
        worker_executable_path: runner_path.clone(),
        config_sha256: loaded.sha256,
        environment,
        environment_hash,
        material_environment_schema_version: MATERIAL_ENVIRONMENT_SCHEMA_VERSION,
        material_environment_hash,
        performance_source_eligible: true,
        preparing_uid: nix::unistd::getuid().as_raw(),
        preparing_gid: nix::unistd::getgid().as_raw(),
        repository,
        config_path: config,
        runner_path,
        observer_path,
        prepared_root: prepared_root.to_path_buf(),
        output_root: output_root.to_path_buf(),
        database_path: output_root.join("experiment.sqlite"),
        report_path: output_root.join("experiment.json"),
        runs_path: output_root.join("runs"),
        input_available_memory_bytes: available,
        headroom_policy,
        headroom,
        pilot_policy,
        memory_max_derivation,
        run_plan,
        pressure_plans,
        expected_level_workload_identities,
        observer_property_contract_version: OBSERVER_PROPERTY_CONTRACT_VERSION,
        observer_runs,
        capacity_gain_percent: EvaluationState::NotEvaluated,
        search_complete: false,
        preparation_audit: PressurePreparationAudit::unprivileged_only(),
    };
    let payload_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&payload)?));
    let manifest = PreparedPressureManifest {
        payload,
        payload_sha256,
    };
    manifest.verify_payload()?;
    let path = prepared_root.join("pressure-experiment.manifest.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&path)?;
    file.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    file.sync_all()?;
    validate_empty_pressure_output(output_root)?;
    Ok(path)
}

pub fn verify_prepared_pressure_manifest(path: &Path) -> Result<PreparedPressureManifest> {
    let metadata = fs::symlink_metadata(path)?;
    let manifest: PreparedPressureManifest = serde_json::from_slice(&fs::read(path)?)?;
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != manifest.payload.preparing_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("prepared pressure manifest metadata is unsafe");
    }
    manifest.verify_payload()?;
    if hex::encode(Sha256::digest(fs::read(&manifest.payload.runner_path)?))
        != manifest.payload.runner_binary.sha256
        || hex::encode(Sha256::digest(fs::read(&manifest.payload.observer_path)?))
            != manifest.payload.observer_binary.sha256
        || hex::encode(Sha256::digest(fs::read(&manifest.payload.config_path)?))
            != manifest.payload.config_sha256
    {
        bail!("prepared pressure source input hash changed");
    }
    for run in &manifest.payload.observer_runs {
        if hex::encode(Sha256::digest(fs::read(&run.prepared_config_path)?))
            != run.prepared_config_sha256
        {
            bail!("prepared pressure observer config hash changed");
        }
        run.service_plan.validate()?;
    }
    validate_empty_pressure_output(&manifest.payload.output_root)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paired_six_run_order_is_deterministic_and_unique() {
        let a = PressureExperimentRunPlan::new(7);
        let b = PressureExperimentRunPlan::new(7);
        assert_eq!(a, b);
        a.validate().unwrap();
        assert_eq!(
            a.runs
                .iter()
                .map(|run| run.order_index)
                .collect::<BTreeSet<_>>()
                .len(),
            6
        );
    }

    #[test]
    fn conservative_policy_is_exact_and_refinement_disabled() {
        let reserve = default_headroom_policy().derive(16 * 1024 * MIB).unwrap();
        let policy = PilotPolicyV1::conservative_v1();
        let levels = policy.freeze(&reserve, 1).unwrap();
        assert_eq!(policy.fractions_permille, [100, 200, 300]);
        assert_eq!(
            policy.refinement_mode,
            RefinementMode::DisabledForFrameworkPilot
        );
        assert!(levels.iter().all(|level| level.target_logical_bytes > 0));
    }

    #[test]
    fn tiny_envelope_fails_instead_of_collapsing_levels() {
        let reserve = HeadroomReserve {
            host_bytes: 1,
            runner_bytes: 1,
            observer_bytes: 1,
            rollback_cleanup_bytes: 1,
            operating_system_variance_bytes: 1,
            total_reserved_bytes: 5,
            effective_maximum_bytes: 16 * MIB,
        };
        assert!(PilotPolicyV1::conservative_v1()
            .freeze(&reserve, 1)
            .is_err());
    }

    #[test]
    fn root_preparation_is_rejected_before_side_effects() {
        assert!(validate_preparing_uid(0).is_err());
        assert!(validate_preparing_uid(1000).is_ok());
    }

    #[test]
    fn memorymax_is_bounded_and_has_real_margin() {
        let result = derive_memory_max(512 * MIB, 2 * 1024 * MIB, 16 * MIB).unwrap();
        assert!(result.shared_memory_max_bytes > result.highest_target_bytes);
        assert!(result.shared_memory_max_bytes <= 2 * 1024 * MIB);
    }

    #[test]
    fn fresh_path_reuse_fails_closed_and_empty_output_is_enforced() {
        let root = tempfile::tempdir().unwrap();
        let existing = root.path().join("existing");
        fs::create_dir(&existing).unwrap();
        let absent = root.path().join("absent");
        assert!(validate_fresh_pressure_paths(&existing, &absent).is_err());
        assert!(validate_empty_pressure_output(&existing).is_ok());
        fs::write(existing.join("unexpected"), b"x").unwrap();
        assert!(validate_empty_pressure_output(&existing).is_err());
    }

    #[test]
    fn preparation_audit_proves_no_privileged_or_live_operations() {
        assert_eq!(
            PressurePreparationAudit::unprivileged_only(),
            PressurePreparationAudit {
                privileged_operations: 0,
                systemd_units_started: 0,
                cgroup_writes: 0,
                workload_bytes_allocated: 0,
                observer_processes_started: 0,
            }
        );
    }

    #[test]
    fn pressure_observer_runtime_covers_full_pilot_and_stays_bounded() {
        let reserve = default_headroom_policy().derive(16 * 1024 * MIB).unwrap();
        let levels = PilotPolicyV1::conservative_v1()
            .freeze(&reserve, 1)
            .unwrap();
        let plan = ProgressivePressurePlan {
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
            experiment_seed: 1,
            levels,
            hold_duration_ms: 5_000,
            stabilization_duration_ms: 2_000,
            sample_interval_ms: 1_000,
            worker_memory_max_bytes: 1024 * MIB,
            watchdog: PressureWatchdogPolicy {
                heartbeat_timeout_ms: 2_000,
                level_transition_timeout_ms: 8_000,
                level_timeout_ms: 17_000,
                total_timeout_ms: 51_000,
            },
            health: PressureHealthPolicy {
                version: PRESSURE_HEALTH_POLICY_VERSION,
                host_psi_full_avg10_emergency: 0.2,
                cgroup_psi_full_avg10_unsustainable: 0.1,
                max_major_faults_per_level: 1_000,
                max_swap_in_bytes_per_level: 1,
                max_swap_out_bytes_per_level: 1,
                max_block_writes_bytes_per_level: 1,
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
                mode: RefinementMode::DisabledForFrameworkPilot,
                granularity_bytes: 16 * MIB,
                maximum_refinements: 0,
            },
            maximum_levels: 3,
            maximum_total_duration_ms: 51_000,
            headroom: reserve,
            systemd_transient_scope_required: true,
            exact_owned_worker_required: true,
        };
        assert_eq!(
            pressure_observer_runtime_max_usec(&plan).unwrap(),
            58_000_000
        );
        let mut excessive = plan;
        excessive.watchdog.level_transition_timeout_ms = 9_000;
        excessive.watchdog.level_timeout_ms = 18_000;
        excessive.watchdog.total_timeout_ms = 54_000;
        excessive.maximum_total_duration_ms = 54_000;
        assert!(pressure_observer_runtime_max_usec(&excessive).is_err());
    }
}
