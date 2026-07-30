//! Conservative framework validation for composing the progressive pressure
//! load generator with a fresh exact external HOT/WARM/COLD target per level.
//!
//! This module cannot estimate capacity, search a boundary, or authorize
//! production. Historical pressure and external-target schemas are inputs,
//! never reinterpreted outputs.

use crate::capacity_external_target::{
    consume_descriptor_once, proc_start_ticks, read_progress, write_command,
    CapacityExternalTargetCommand, CapacityExternalTargetContract,
    CapacityExternalTargetDescriptor, CapacityExternalTargetProgress, CapacityExternalTargetState,
    CAPACITY_EXTERNAL_TARGET_CONTRACT_VERSION, CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION,
};
use crate::capacity_external_validation::ExternalTargetExecutionReport;
use crate::capacity_orchestration::{
    component_contracts_for, CapacityComponent, CapacityComponentContractIdentity,
};
use crate::performance::{detect_nemord_processes, BinaryIdentity};
use crate::pressure::{HeadroomReserve, PlannedPressureLevel};
use crate::pressure_prepare::{derive_memory_max, paired_run_seed, PilotPolicyV1, MIB};
use crate::pressure_worker::{
    command_for_level, PressureWorkerClient, WorkerIpcMessage, PRESSURE_WORKER_PROTOCOL_VERSION,
};
use crate::systemd::{SystemdDbusBackend, TransientScopeBackend, TransientScopePlan};
use crate::{
    deterministic_order, BenchmarkVariant, BuildProvenance, EnvironmentFingerprint,
    EvaluationState, StructuralSnapshot, BUILD_GIT_HEAD,
};
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const COMPOSITION_CONTRACT_VERSION: u32 = 1;
pub const COMPOSITION_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const COMPOSITION_PREFLIGHT_SCHEMA_VERSION: u32 = 1;
pub const COMPOSITION_EXECUTION_SCHEMA_VERSION: u32 = 1;
pub const COMPOSITION_RUN_EVIDENCE_VERSION: u32 = 1;
pub const COMPOSITION_LEVEL_EVIDENCE_VERSION: u32 = 1;
pub const COMPOSITION_TARGET_EVIDENCE_VERSION: u32 = 1;
pub const COMPOSITION_MANIFEST_NAME: &str = "capacity-composition.manifest.json";
pub const COMPOSITION_PURPOSE: &str = "capacity_composition_framework_validation";
pub const COMPOSITION_SERVICE_WINDOW_MS: u64 = 10_000;
pub const COMPOSITION_STABILIZATION_MS: u64 = 2_000;
pub const COMPOSITION_SAMPLE_INTERVAL_MS: u64 = 1_000;
pub const COMPOSITION_LEVEL_TIMEOUT_MS: u64 = 25_000;
pub const COMPOSITION_RUN_TIMEOUT_MS: u64 = 90_000;
const HARNESS_REPORT: &str = "/tmp/nemor-privileged-validation-report.json";
const HARNESS_STATE: &str = "/tmp/nemor-privileged-validation";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityPressureCompositionContract {
    pub version: u32,
    pub purpose: String,
    pub framework_validation_authorized: bool,
    pub capacity_evaluation_authorized: bool,
    pub refinement_authorized: bool,
    pub production_activation_authorized: bool,
    pub arbitrary_target_authorized: bool,
    pub automatic_retry: bool,
    pub search_complete: bool,
}

impl CapacityPressureCompositionContract {
    pub fn v1() -> Self {
        Self {
            version: COMPOSITION_CONTRACT_VERSION,
            purpose: COMPOSITION_PURPOSE.into(),
            framework_validation_authorized: true,
            capacity_evaluation_authorized: false,
            refinement_authorized: false,
            production_activation_authorized: false,
            arbitrary_target_authorized: false,
            automatic_retry: false,
            search_complete: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self != &Self::v1() {
            bail!("unsupported or over-authorizing capacity composition contract");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionHeadroomPolicy {
    pub host_reserve_permille: u16,
    pub minimum_host_reserve_bytes: u64,
    pub runner_reserve_bytes: u64,
    pub target_reserve_bytes: u64,
    pub controller_reserve_bytes: u64,
    pub transaction_evidence_reserve_bytes: u64,
    pub rollback_cleanup_reserve_bytes: u64,
    pub operating_system_variance_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionHeadroom {
    pub host_reserve_bytes: u64,
    pub runner_reserve_bytes: u64,
    pub target_reserve_bytes: u64,
    pub controller_reserve_bytes: u64,
    pub transaction_evidence_reserve_bytes: u64,
    pub rollback_cleanup_reserve_bytes: u64,
    pub operating_system_variance_bytes: u64,
    pub fixed_reserve_bytes: u64,
    pub pressure_effective_maximum_bytes: u64,
}

impl CompositionHeadroomPolicy {
    pub fn conservative_v1() -> Self {
        Self {
            host_reserve_permille: 250,
            minimum_host_reserve_bytes: 2 * 1024 * MIB,
            runner_reserve_bytes: 256 * MIB,
            target_reserve_bytes: 64 * MIB,
            controller_reserve_bytes: 256 * MIB,
            transaction_evidence_reserve_bytes: 128 * MIB,
            rollback_cleanup_reserve_bytes: 512 * MIB,
            operating_system_variance_bytes: 1024 * MIB,
        }
    }

    pub fn derive(&self, available: u64) -> Result<CompositionHeadroom> {
        if self != &Self::conservative_v1() || available == 0 {
            bail!("unsupported composition headroom policy");
        }
        let host = available
            .checked_mul(u64::from(self.host_reserve_permille))
            .context("composition host reserve overflow")?
            / 1000;
        let host = host.max(self.minimum_host_reserve_bytes);
        let fixed = [
            host,
            self.runner_reserve_bytes,
            self.target_reserve_bytes,
            self.controller_reserve_bytes,
            self.transaction_evidence_reserve_bytes,
            self.rollback_cleanup_reserve_bytes,
            self.operating_system_variance_bytes,
        ]
        .into_iter()
        .try_fold(0u64, |sum, value| sum.checked_add(value))
        .context("composition reserve overflow")?;
        let effective = available
            .checked_sub(fixed)
            .context("composition reserves exceed MemAvailable")?
            .min(12 * 1024 * MIB);
        if effective < 512 * MIB {
            bail!("composition effective pressure envelope is too small");
        }
        Ok(CompositionHeadroom {
            host_reserve_bytes: host,
            runner_reserve_bytes: self.runner_reserve_bytes,
            target_reserve_bytes: self.target_reserve_bytes,
            controller_reserve_bytes: self.controller_reserve_bytes,
            transaction_evidence_reserve_bytes: self.transaction_evidence_reserve_bytes,
            rollback_cleanup_reserve_bytes: self.rollback_cleanup_reserve_bytes,
            operating_system_variance_bytes: self.operating_system_variance_bytes,
            fixed_reserve_bytes: fixed,
            pressure_effective_maximum_bytes: effective,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalTargetPrerequisite {
    pub archive_path: PathBuf,
    pub validation_id: String,
    pub source_commit: String,
    pub manifest_sha256: String,
    pub evidence_payload_sha256: String,
    pub sha256sums_sha256: String,
    pub target_contract_version: u32,
    pub target_protocol_version: u32,
    pub components: BTreeSet<CapacityComponent>,
    pub direct_shadow_gates: [bool; 4],
    pub classification_pass: bool,
}

impl ExternalTargetPrerequisite {
    pub fn verify_for(&self, source: &str, components: &BTreeSet<CapacityComponent>) -> Result<()> {
        if self.source_commit != source
            || &self.components != components
            || self.target_contract_version != CAPACITY_EXTERNAL_TARGET_CONTRACT_VERSION
            || self.target_protocol_version != CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION
            || !self.classification_pass
            || !self.direct_shadow_gates.into_iter().all(|gate| gate)
            || hash_file(&self.archive_path.join("manifest.json"))? != self.manifest_sha256
            || hash_file(&self.archive_path.join("SHA256SUMS"))? != self.sha256sums_sha256
        {
            bail!("fresh external-target prerequisite is stale or inexact");
        }
        let report: ExternalTargetExecutionReport = serde_json::from_slice(&fs::read(
            self.archive_path.join("external-target-validation.json"),
        )?)?;
        report.verify()?;
        if report.payload.validation_id != self.validation_id
            || report.payload.source_commit != self.source_commit
            || report.payload_sha256 != self.evidence_payload_sha256
            || report.payload.component_set != self.components
        {
            bail!("external-target prerequisite evidence binding mismatch");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositionRunPlan {
    pub order_index: usize,
    pub variant: BenchmarkVariant,
    pub repetition_index: usize,
    pub seed: u64,
    pub levels: Vec<PlannedPressureLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityCompositionPayload {
    pub schema_version: u32,
    pub execution_schema_version: u32,
    pub experiment_id: String,
    pub contract: CapacityPressureCompositionContract,
    pub provenance: BuildProvenance,
    pub runner_binary: BinaryIdentity,
    pub target_binary: BinaryIdentity,
    pub validator_binary: BinaryIdentity,
    pub repository: PathBuf,
    pub config_path: PathBuf,
    pub config_sha256: String,
    pub material_environment_hash: String,
    pub runner_path: PathBuf,
    pub target_path: PathBuf,
    pub validator_path: PathBuf,
    pub prepared_root: PathBuf,
    pub output_root: PathBuf,
    pub report_path: PathBuf,
    pub database_path: PathBuf,
    pub runs_root: PathBuf,
    pub preparing_uid: u32,
    pub preparing_gid: u32,
    pub components: BTreeSet<CapacityComponent>,
    pub component_contracts: Vec<CapacityComponentContractIdentity>,
    pub pressure_worker_protocol_version: u32,
    pub external_target_contract: CapacityExternalTargetContract,
    pub external_target_prerequisite: ExternalTargetPrerequisite,
    pub input_mem_available_bytes: u64,
    pub headroom_policy: CompositionHeadroomPolicy,
    pub headroom: CompositionHeadroom,
    pub pressure_memory_max_bytes: u64,
    pub run_plan: Vec<CompositionRunPlan>,
    pub service_window_ms: u64,
    pub stabilization_ms: u64,
    pub sample_interval_ms: u64,
    pub level_timeout_ms: u64,
    pub run_timeout_ms: u64,
    pub automatic_retry: bool,
    pub request_oom: bool,
    pub search_complete: bool,
    pub capacity_evaluation: EvaluationState,
    pub effectiveness_evaluation: EvaluationState,
    pub production_activation_authorized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedCapacityCompositionManifest {
    pub payload: CapacityCompositionPayload,
    pub payload_sha256: String,
}

impl PreparedCapacityCompositionManifest {
    pub fn verify(&self) -> Result<()> {
        let components = exact_components();
        self.payload.contract.validate()?;
        self.payload.external_target_contract.validate()?;
        self.payload
            .external_target_prerequisite
            .verify_for(&self.payload.provenance.git_head, &components)?;
        if self.payload_sha256 != hash_json(&self.payload)?
            || self.payload.schema_version != COMPOSITION_MANIFEST_SCHEMA_VERSION
            || self.payload.execution_schema_version != COMPOSITION_EXECUTION_SCHEMA_VERSION
            || self.payload.components != components
            || self.payload.component_contracts != component_contracts_for(&components)
            || self.payload.pressure_worker_protocol_version != PRESSURE_WORKER_PROTOCOL_VERSION
            || self.payload.external_target_contract != CapacityExternalTargetContract::v1()
            || self.payload.run_plan.len() != 6
            || self
                .payload
                .run_plan
                .iter()
                .any(|run| run.levels.len() != 3)
            || self.payload.service_window_ms != COMPOSITION_SERVICE_WINDOW_MS
            || self.payload.stabilization_ms != COMPOSITION_STABILIZATION_MS
            || self.payload.sample_interval_ms != COMPOSITION_SAMPLE_INTERVAL_MS
            || self.payload.level_timeout_ms != COMPOSITION_LEVEL_TIMEOUT_MS
            || self.payload.run_timeout_ms != COMPOSITION_RUN_TIMEOUT_MS
            || self.payload.automatic_retry
            || self.payload.request_oom
            || self.payload.search_complete
            || self.payload.capacity_evaluation != EvaluationState::NotEvaluated
            || self.payload.effectiveness_evaluation != EvaluationState::NotEvaluated
            || self.payload.production_activation_authorized
            || self.payload.headroom
                != self
                    .payload
                    .headroom_policy
                    .derive(self.payload.input_mem_available_bytes)?
        {
            bail!("composition manifest is not the exact v1 conservative framework contract");
        }
        validate_run_plan(&self.payload.run_plan)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionPrivilegeStatus {
    Deferred,
    RequiresOwnedContextValidation,
    Verified,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityCompositionPreflight {
    pub schema_version: u32,
    pub manifest_verified: bool,
    pub source_and_binaries_verified: bool,
    pub material_environment_match: bool,
    pub fresh_external_target_evidence_verified: bool,
    pub component_set_supported: bool,
    pub composition_contract_supported: bool,
    pub pressure_plan_supported: bool,
    pub target_contract_supported: bool,
    pub run_plan_supported: bool,
    pub headroom_safe: bool,
    pub ownership_plan_supported: bool,
    pub systemd_cgroup_supported: bool,
    pub psi_supported: bool,
    pub output_fresh: bool,
    pub stale_resources_clear: bool,
    pub privileged_capability: CompositionPrivilegeStatus,
    pub user_preflight_passed: bool,
    pub current_identity_authorized: bool,
    pub bounded_composition_entry_ready: bool,
    pub execution_ready: bool,
    pub preflight_mutated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionExperimentState {
    Running,
    CompletedCompositionFrameworkValidation,
    RejectedBeforeRun0,
    InvalidRun,
    UnsustainableHealth,
    SafetyAbort,
    ExecutionError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionLevelClassification {
    Sustainable,
    UnsustainableHealth,
    SafetyAbort,
    InvalidEvidence,
    LoadTransitionTimeout,
    LoadIpcFailure,
    TargetOwnershipRejected,
    TargetProtocolFailure,
    TargetHeartbeatFailure,
    TargetIntegrityFailure,
    ShadowCapabilityFailure,
    LiveActionFailure,
    CleanupFailure,
    RestoreFailure,
    ExecutionError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionTargetEvidence {
    pub version: u32,
    pub transaction_id: String,
    pub session_id: String,
    pub descriptor_hash: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub ranges: crate::capacity_external_target::CapacityExternalTargetRanges,
    pub before: CapacityExternalTargetProgress,
    pub after: CapacityExternalTargetProgress,
    pub hot_progress: bool,
    pub warm_progress: bool,
    pub cold_inactive_before_action: bool,
    pub fingerprints_valid: bool,
    pub descriptor_consumed_once: bool,
    pub validator_invoked: bool,
    pub no_damon_damos_mutation: bool,
    pub direct_shadow_gates: [bool; 4],
    pub required_damos_gates_passed: bool,
    pub applied_bytes: u64,
    pub only_cold_reclaimed: bool,
    pub cleanup_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityCompositionLevelEvidence {
    pub version: u32,
    pub run_order: usize,
    pub level_index: usize,
    pub variant: BenchmarkVariant,
    pub target_touched_bytes: u64,
    pub requested_delta_bytes: u64,
    pub actual_touched_bytes: u64,
    pub pressure_integrity_identity: String,
    pub pressure_heartbeat: bool,
    pub pressure_worker_alive: bool,
    pub cgroup_membership: bool,
    pub memory_max_verified: bool,
    pub memory_current_bytes: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub host_psi_full_avg10: Option<String>,
    pub cgroup_psi_full_avg10: Option<String>,
    pub major_fault_delta: Option<u64>,
    pub swap_in_delta: Option<u64>,
    pub swap_out_delta: Option<u64>,
    pub block_write_delta: Option<u64>,
    pub oom: u64,
    pub oom_kill: u64,
    pub watchdog_triggered: bool,
    pub target: CompositionTargetEvidence,
    pub classification: CompositionLevelClassification,
    pub cleanup_passed: bool,
    pub structural_restore_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityCompositionRunEvidence {
    pub version: u32,
    pub order_index: usize,
    pub variant: BenchmarkVariant,
    pub repetition_index: usize,
    pub seed: u64,
    pub state: CompositionExperimentState,
    pub levels: Vec<CapacityCompositionLevelEvidence>,
    pub pressure_scope_cleanup_passed: bool,
    pub structural_restore_passed: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityCompositionExecutionEvidence {
    pub schema_version: u32,
    pub experiment_id: String,
    pub source_commit: String,
    pub state: CompositionExperimentState,
    pub reason: String,
    pub runs: Vec<CapacityCompositionRunEvidence>,
    pub planned_runs: usize,
    pub completed_runs: usize,
    pub planned_levels: usize,
    pub completed_levels: usize,
    pub invocation_count: u32,
    pub search_complete: bool,
    pub capacity_evaluation: EvaluationState,
    pub effectiveness_evaluation: EvaluationState,
    pub production_activation_authorized: bool,
    pub cleanup_passed: bool,
    pub structural_restore_passed: bool,
    pub payload_sha256: String,
}

impl CapacityCompositionExecutionEvidence {
    fn seal(mut self) -> Result<Self> {
        self.payload_sha256.clear();
        self.payload_sha256 = hash_json(&self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<()> {
        let mut payload = self.clone();
        let frozen = payload.payload_sha256.clone();
        payload.payload_sha256.clear();
        if hash_json(&payload)? != frozen
            || self.capacity_evaluation != EvaluationState::NotEvaluated
            || self.effectiveness_evaluation != EvaluationState::NotEvaluated
            || self.search_complete
            || self.production_activation_authorized
        {
            bail!("composition execution evidence integrity/non-claim mismatch");
        }
        Ok(())
    }
}

fn exact_components() -> BTreeSet<CapacityComponent> {
    BTreeSet::from([
        CapacityComponent::DamonTelemetry,
        CapacityComponent::DamosReclaim,
    ])
}

fn validate_run_plan(runs: &[CompositionRunPlan]) -> Result<()> {
    let variants = [
        BenchmarkVariant::CachyosBaseline,
        BenchmarkVariant::NemorCapacity,
    ];
    let expected_order = deterministic_order(&variants, 3, 1);
    if runs.len() != 6 {
        bail!("composition requires exactly six runs");
    }
    for (index, (run, expected)) in runs.iter().zip(expected_order).enumerate() {
        if run.order_index != index
            || (run.variant, run.repetition_index) != expected
            || run.seed != paired_run_seed(1, run.repetition_index)
            || run.levels.len() != 3
            || run.levels.iter().any(|level| level.seed != run.seed)
        {
            bail!("composition run order, seeds, or levels are not frozen symmetrically");
        }
    }
    Ok(())
}

fn read_external_prerequisite(archive: &Path) -> Result<ExternalTargetPrerequisite> {
    let report: ExternalTargetExecutionReport =
        serde_json::from_slice(&fs::read(archive.join("external-target-validation.json"))?)?;
    report.verify()?;
    let manifest: Value = serde_json::from_slice(&fs::read(archive.join("manifest.json"))?)?;
    let direct = report.payload.direct_shadow_gates;
    Ok(ExternalTargetPrerequisite {
        archive_path: archive.to_path_buf(),
        validation_id: report.payload.validation_id.clone(),
        source_commit: report.payload.source_commit.clone(),
        manifest_sha256: hash_file(&archive.join("manifest.json"))?,
        evidence_payload_sha256: report.payload_sha256.clone(),
        sha256sums_sha256: hash_file(&archive.join("SHA256SUMS"))?,
        target_contract_version: report.payload.target_contract_version,
        target_protocol_version: report.payload.target_protocol_version,
        components: report.payload.component_set.clone(),
        direct_shadow_gates: direct,
        classification_pass: report.state
            == crate::capacity_external_validation::ExternalTargetClassification::Pass
            && manifest["payload"]["provenance"]["git_head"].as_str()
                == Some(report.payload.source_commit.as_str()),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_capacity_composition(
    repository: &Path,
    config: &Path,
    validator: &Path,
    target: Option<&Path>,
    external_archive: &Path,
    prepared_root: &Path,
    output_root: &Path,
) -> Result<PathBuf> {
    let uid = nix::unistd::geteuid().as_raw();
    if uid == 0 {
        bail!("composition preparation must run unprivileged");
    }
    if prepared_root.exists()
        || output_root.exists()
        || !prepared_root.is_absolute()
        || !output_root.is_absolute()
    {
        bail!("composition paths must be fresh and absolute");
    }
    let repository = repository.canonicalize()?;
    if std::env::current_dir()?.canonicalize()? != repository {
        bail!("composition preparation requires the explicit current repository");
    }
    let runner_path = std::env::current_exe()?.canonicalize()?;
    let target_path = target.unwrap_or(&runner_path).canonicalize()?;
    let validator_path = validator.canonicalize()?;
    let config_path = config.canonicalize()?;
    let loaded = common::LoadedConfig::load(&config_path)?;
    let provenance = BuildProvenance::capture()?;
    if !provenance.clean_release_eligible() {
        bail!("composition preparation requires clean release provenance");
    }
    let binary = |role: &str, path: &Path| {
        BinaryIdentity::capture(
            role,
            path,
            &provenance.source_state_id,
            &provenance.git_head,
        )
    };
    let runner_binary = binary("nemor_benchmark", &runner_path)?;
    let target_binary = binary("capacity_external_target", &target_path)?;
    let validator_binary = binary("nemor_privileged_validation", &validator_path)?;
    if [&runner_binary, &target_binary, &validator_binary]
        .iter()
        .any(|identity| identity.build_profile != "release")
    {
        bail!("composition binaries are not exact release identities");
    }
    let environment =
        EnvironmentFingerprint::capture_for_performance(&loaded.sha256, &provenance.git_head)?;
    let available = mem_available_bytes()?;
    let headroom_policy = CompositionHeadroomPolicy::conservative_v1();
    let headroom = headroom_policy.derive(available)?;
    let pilot = PilotPolicyV1::conservative_v1();
    let pressure_reserve = HeadroomReserve {
        host_bytes: headroom.host_reserve_bytes,
        runner_bytes: headroom.runner_reserve_bytes,
        observer_bytes: headroom.target_reserve_bytes
            + headroom.controller_reserve_bytes
            + headroom.transaction_evidence_reserve_bytes,
        rollback_cleanup_bytes: headroom.rollback_cleanup_reserve_bytes,
        operating_system_variance_bytes: headroom.operating_system_variance_bytes,
        total_reserved_bytes: headroom.fixed_reserve_bytes,
        effective_maximum_bytes: headroom.pressure_effective_maximum_bytes,
    };
    let base_levels = pilot.freeze(&pressure_reserve, 1)?;
    let highest = base_levels.last().context("composition levels absent")?;
    let memory_max = derive_memory_max(
        highest.target_touched_bytes,
        headroom.pressure_effective_maximum_bytes,
        16 * MIB,
    )?
    .shared_memory_max_bytes;
    let variants = [
        BenchmarkVariant::CachyosBaseline,
        BenchmarkVariant::NemorCapacity,
    ];
    let run_plan = deterministic_order(&variants, 3, 1)
        .into_iter()
        .enumerate()
        .map(|(order_index, (variant, repetition_index))| {
            let seed = paired_run_seed(1, repetition_index);
            let mut levels = pilot.freeze(&pressure_reserve, seed)?;
            for level in &mut levels {
                level.seed = seed;
            }
            Ok(CompositionRunPlan {
                order_index,
                variant,
                repetition_index,
                seed,
                levels,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    validate_run_plan(&run_plan)?;
    let prerequisite = read_external_prerequisite(&external_archive.canonicalize()?)?;
    prerequisite.verify_for(&provenance.git_head, &exact_components())?;
    fs::create_dir(prepared_root)?;
    fs::set_permissions(prepared_root, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(output_root)?;
    fs::set_permissions(output_root, fs::Permissions::from_mode(0o700))?;
    let experiment_id = format!("capacity-composition-{}", now_ns()?);
    let components = exact_components();
    let payload = CapacityCompositionPayload {
        schema_version: COMPOSITION_MANIFEST_SCHEMA_VERSION,
        execution_schema_version: COMPOSITION_EXECUTION_SCHEMA_VERSION,
        experiment_id,
        contract: CapacityPressureCompositionContract::v1(),
        provenance,
        runner_binary,
        target_binary,
        validator_binary,
        repository,
        config_path,
        config_sha256: loaded.sha256,
        material_environment_hash: environment.material_hash()?,
        runner_path,
        target_path,
        validator_path,
        prepared_root: prepared_root.to_path_buf(),
        output_root: output_root.to_path_buf(),
        report_path: output_root.join("capacity-composition.json"),
        database_path: output_root.join("capacity-composition.sqlite"),
        runs_root: output_root.join("runs"),
        preparing_uid: uid,
        preparing_gid: nix::unistd::getegid().as_raw(),
        component_contracts: component_contracts_for(&components),
        components,
        pressure_worker_protocol_version: PRESSURE_WORKER_PROTOCOL_VERSION,
        external_target_contract: CapacityExternalTargetContract::v1(),
        external_target_prerequisite: prerequisite,
        input_mem_available_bytes: available,
        headroom_policy,
        headroom,
        pressure_memory_max_bytes: memory_max,
        run_plan,
        service_window_ms: COMPOSITION_SERVICE_WINDOW_MS,
        stabilization_ms: COMPOSITION_STABILIZATION_MS,
        sample_interval_ms: COMPOSITION_SAMPLE_INTERVAL_MS,
        level_timeout_ms: COMPOSITION_LEVEL_TIMEOUT_MS,
        run_timeout_ms: COMPOSITION_RUN_TIMEOUT_MS,
        automatic_retry: false,
        request_oom: false,
        search_complete: false,
        capacity_evaluation: EvaluationState::NotEvaluated,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
        production_activation_authorized: false,
    };
    let manifest = PreparedCapacityCompositionManifest {
        payload_sha256: hash_json(&payload)?,
        payload,
    };
    manifest.verify()?;
    let path = prepared_root.join(COMPOSITION_MANIFEST_NAME);
    write_new_json(&path, &manifest)?;
    Ok(path)
}

pub fn capacity_composition_preflight(
    manifest_path: &Path,
) -> Result<CapacityCompositionPreflight> {
    let manifest = read_manifest(manifest_path)?;
    let payload = &manifest.payload;
    let current = std::env::current_exe()?.canonicalize()?;
    let source_and_binaries_verified = current == payload.runner_path
        && hash_file(&current)? == payload.runner_binary.sha256
        && hash_file(&payload.target_path)? == payload.target_binary.sha256
        && hash_file(&payload.validator_path)? == payload.validator_binary.sha256
        && BUILD_GIT_HEAD == payload.provenance.git_head;
    let loaded = common::LoadedConfig::load(&payload.config_path)?;
    let environment = EnvironmentFingerprint::capture_for_performance(
        &loaded.sha256,
        &payload.provenance.git_head,
    )?;
    let material_environment_match = loaded.sha256 == payload.config_sha256
        && environment.material_hash()? == payload.material_environment_hash;
    let fresh_external_target_evidence_verified = payload
        .external_target_prerequisite
        .verify_for(&payload.provenance.git_head, &payload.components)
        .is_ok();
    let systemd = SystemdDbusBackend::system();
    let (systemd_cgroup_supported, owned_units_clear) = systemd
        .and_then(|backend| {
            Ok((
                backend.capability()?.supported,
                backend.list_owned_benchmark_units()?.is_empty(),
            ))
        })
        .unwrap_or((false, false));
    let psi_supported =
        Path::new("/proc/pressure/memory").is_file() && Path::new("/sys/fs/cgroup").is_dir();
    let output_fresh = fs::read_dir(&payload.output_root)?.next().is_none();
    let stale_resources_clear = owned_units_clear
        && !Path::new(HARNESS_STATE).exists()
        && !Path::new(HARNESS_REPORT).exists()
        && !processes_contain("pressure-worker")
        && !processes_contain("capacity-external-target-worker");
    let current_mem = mem_available_bytes()?;
    let headroom_safe = current_mem
        >= payload
            .pressure_memory_max_bytes
            .saturating_add(payload.headroom.fixed_reserve_bytes);
    let damon = damon::inspect_linux(Path::new("/"), None);
    let damos = damos::observe_capability(&damon);
    let root = nix::unistd::geteuid().is_root();
    let privileged_capability = if !damon.supported
        || !damon.sysfs_admin_available
        || !damon.tracefs_available
        || !damos.supported
        || damon.active_external_session
        || damos.external_session_conflict
    {
        CompositionPrivilegeStatus::Unsupported
    } else if !root {
        CompositionPrivilegeStatus::Deferred
    } else if damon.readable && damon.writable {
        CompositionPrivilegeStatus::RequiresOwnedContextValidation
    } else {
        CompositionPrivilegeStatus::Unsupported
    };
    let identity_authorized = root
        && std::env::var("SUDO_UID")
            .ok()
            .and_then(|value| value.parse().ok())
            == Some(payload.preparing_uid)
        && std::env::var("SUDO_GID")
            .ok()
            .and_then(|value| value.parse().ok())
            == Some(payload.preparing_gid);
    let common = source_and_binaries_verified
        && material_environment_match
        && fresh_external_target_evidence_verified
        && systemd_cgroup_supported
        && psi_supported
        && output_fresh
        && stale_resources_clear
        && headroom_safe
        && !matches!(
            privileged_capability,
            CompositionPrivilegeStatus::Unsupported
        )
        && detect_nemord_processes(&payload.runner_path, None).is_empty();
    let bounded = common
        && identity_authorized
        && matches!(
            privileged_capability,
            CompositionPrivilegeStatus::RequiresOwnedContextValidation
                | CompositionPrivilegeStatus::Verified
        );
    Ok(CapacityCompositionPreflight {
        schema_version: COMPOSITION_PREFLIGHT_SCHEMA_VERSION,
        manifest_verified: true,
        source_and_binaries_verified,
        material_environment_match,
        fresh_external_target_evidence_verified,
        component_set_supported: payload.components == exact_components(),
        composition_contract_supported: payload.contract.validate().is_ok(),
        pressure_plan_supported: true,
        target_contract_supported: payload.external_target_contract.validate().is_ok(),
        run_plan_supported: validate_run_plan(&payload.run_plan).is_ok(),
        headroom_safe,
        ownership_plan_supported: true,
        systemd_cgroup_supported,
        psi_supported,
        output_fresh,
        stale_resources_clear,
        privileged_capability,
        user_preflight_passed: common,
        current_identity_authorized: identity_authorized,
        bounded_composition_entry_ready: bounded,
        execution_ready: bounded,
        preflight_mutated: false,
    })
}

fn hash_json(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn hash_file(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(
        fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )))
}

fn now_ns() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes UNIX epoch")?
        .as_nanos())
}

fn mem_available_bytes() -> Result<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").context("read /proc/meminfo")?;
    let kib = meminfo
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "MemAvailable:").then(|| fields.next()?.parse::<u64>().ok())?
        })
        .context("MemAvailable missing from /proc/meminfo")?;
    kib.checked_mul(1024).context("MemAvailable overflow")
}

fn processes_contain(needle: &str) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return true;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        name.to_string_lossy().parse::<u32>().is_ok()
            && fs::read(entry.path().join("cmdline"))
                .map(|bytes| String::from_utf8_lossy(&bytes).contains(needle))
                .unwrap_or(false)
    })
}

fn read_manifest(path: &Path) -> Result<PreparedCapacityCompositionManifest> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let manifest: PreparedCapacityCompositionManifest =
        serde_json::from_slice(&bytes).context("parse capacity composition manifest")?;
    manifest.verify()?;
    Ok(manifest)
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            bail!("timed out waiting for {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

fn ipc_identity(
    experiment_id: &str,
    run_id: &str,
    pid: u32,
    start_ticks: u64,
) -> (u32, String, String, u32, u64) {
    (
        PRESSURE_WORKER_PROTOCOL_VERSION,
        experiment_id.into(),
        run_id.into(),
        pid,
        start_ticks,
    )
}

fn spawn_target(
    payload: &CapacityCompositionPayload,
    root: &Path,
    transaction_id: &str,
    session_id: &str,
    nonce: &str,
) -> Result<(Child, CapacityExternalTargetDescriptor)> {
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let creator_pid = std::process::id();
    let creator_ticks =
        proc_start_ticks(creator_pid)?.context("creator start ticks unavailable")?;
    let child = Command::new(&payload.target_path)
        .args([
            "capacity-external-target-worker",
            "--transaction-root",
            root.to_str().context("non-UTF8 target root")?,
            "--transaction-id",
            transaction_id,
            "--session-id",
            session_id,
            "--nonce",
            nonce,
            "--creator-pid",
            &creator_pid.to_string(),
            "--creator-start-ticks",
            &creator_ticks.to_string(),
            "--preparing-uid",
            &payload.preparing_uid.to_string(),
            "--preparing-gid",
            &payload.preparing_gid.to_string(),
            "--unit-or-cgroup-identity",
            "direct-child-no-cgroup",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let descriptor_path = root.join("target-descriptor.json");
    wait_for_path(&descriptor_path, Duration::from_secs(5))?;
    let descriptor: CapacityExternalTargetDescriptor =
        serde_json::from_slice(&fs::read(&descriptor_path)?)?;
    descriptor.validate_integrity()?;
    if descriptor.payload.identity.creator_pid != creator_pid
        || descriptor.payload.identity.creator_start_ticks != creator_ticks
        || descriptor.payload.identity.executable_sha256 != payload.target_binary.sha256
        || descriptor.payload.identity.embedded_source_commit != payload.provenance.git_head
    {
        bail!("composition target exact identity mismatch");
    }
    Ok((child, descriptor))
}

fn remove_target_root(root: &Path) -> Result<()> {
    if !root
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("target-"))
    {
        bail!("refusing unexpected composition target root");
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            bail!("nested composition target content");
        }
        fs::remove_file(path)?;
    }
    fs::remove_dir(root)?;
    Ok(())
}

fn target_for_level(
    payload: &CapacityCompositionPayload,
    run: &CompositionRunPlan,
    level_index: usize,
    level_dir: &Path,
) -> Result<CompositionTargetEvidence> {
    let transaction_id = format!(
        "{}-r{}-l{}",
        payload.experiment_id, run.order_index, level_index
    );
    let session_id = format!("session-r{}-l{}", run.order_index, level_index);
    let nonce = hex::encode(Sha256::digest(format!(
        "{}:{}:{}:{}",
        payload.provenance.source_state_id, transaction_id, session_id, run.seed
    )));
    let root = payload
        .output_root
        .join(format!("target-r{}-l{}", run.order_index, level_index));
    let (mut child, descriptor) =
        spawn_target(payload, &root, &transaction_id, &session_id, &nonce)?;
    let before = read_progress(&descriptor.payload.progress_path)?;
    if before.cold_cycles != 0 {
        bail!("COLD progressed before composition service action");
    }
    let descriptor_path = root.join("target-descriptor.json");
    let validator_invoked = run.variant == BenchmarkVariant::NemorCapacity;
    let (direct, required, applied, only_cold, cleanup) = if validator_invoked {
        if Path::new(HARNESS_REPORT).exists() {
            fs::remove_file(HARNESS_REPORT)?;
        }
        if Path::new(HARNESS_STATE).exists() {
            bail!("stale privileged validator state");
        }
        let creator_pid = std::process::id();
        let creator_ticks =
            proc_start_ticks(creator_pid)?.context("creator start ticks unavailable")?;
        let status = Command::new(&payload.validator_path)
            .arg("--damos")
            .arg("--external-target-descriptor")
            .arg(&descriptor_path)
            .arg("--external-target-transaction-id")
            .arg(&transaction_id)
            .arg("--external-target-session-id")
            .arg(&session_id)
            .arg("--external-target-nonce")
            .arg(&nonce)
            .arg("--external-target-creator-pid")
            .arg(creator_pid.to_string())
            .arg("--external-target-creator-start-ticks")
            .arg(creator_ticks.to_string())
            .current_dir(&payload.repository)
            .status()?;
        let raw: Value = serde_json::from_slice(&fs::read(HARNESS_REPORT)?)?;
        write_new_json(&level_dir.join("raw-damos-report.json"), &raw)?;
        let checks = raw["damos"]["checks"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let passed = |name: &str| {
            checks.iter().any(|check| {
                check["name"].as_str() == Some(name) && check["passed"].as_bool() == Some(true)
            })
        };
        let gates = [
            passed("vaddr_pageout_supported"),
            passed("shadow_session_passed"),
            passed("shadow_cleanup"),
            passed("cold_address_fence"),
        ];
        let required = raw["damos"]["required_gates_passed"]
            .as_bool()
            .unwrap_or(false);
        let applied = raw["damos"]["live_stats"]["sz_applied"]
            .as_u64()
            .unwrap_or(0);
        let only_cold = passed("cold_address_fence")
            && passed("reclaim_effect_observed")
            && passed("hot_not_reclaimed")
            && passed("warm_not_reclaimed")
            && passed("refault_content_valid");
        let cleanup = status.success()
            && passed("cleanup")
            && passed("scheme_removed")
            && passed("recovery")
            && passed("recovery_idempotent")
            && raw["host_unchanged"].as_bool().unwrap_or(false);
        (gates, required, applied, only_cold, cleanup)
    } else {
        consume_descriptor_once(&descriptor_path, &descriptor.payload_sha256)?;
        write_command(
            &root,
            &CapacityExternalTargetCommand::Start {
                nonce: nonce.clone(),
            },
        )?;
        std::thread::sleep(Duration::from_millis(COMPOSITION_SERVICE_WINDOW_MS));
        write_command(
            &root,
            &CapacityExternalTargetCommand::Stop {
                nonce: nonce.clone(),
            },
        )?;
        ([false; 4], false, 0, true, true)
    };
    if read_progress(&descriptor.payload.progress_path).is_ok_and(|progress| {
        !matches!(
            progress.state,
            CapacityExternalTargetState::Stopping | CapacityExternalTargetState::Stopped
        )
    }) {
        let _ = write_command(
            &root,
            &CapacityExternalTargetCommand::Stop {
                nonce: nonce.clone(),
            },
        );
    }
    let status = child.wait()?;
    let after = read_progress(&descriptor.payload.progress_path)?;
    fs::copy(&descriptor_path, level_dir.join("target-descriptor.json"))?;
    write_new_json(&level_dir.join("target-progress.json"), &after)?;
    let evidence = CompositionTargetEvidence {
        version: COMPOSITION_TARGET_EVIDENCE_VERSION,
        transaction_id,
        session_id,
        descriptor_hash: descriptor.payload_sha256.clone(),
        pid: descriptor.payload.identity.pid,
        start_ticks: descriptor.payload.identity.start_ticks,
        ranges: descriptor.payload.ranges.clone(),
        before: before.clone(),
        after: after.clone(),
        hot_progress: after.hot_cycles > before.hot_cycles,
        warm_progress: after.warm_cycles > before.warm_cycles,
        cold_inactive_before_action: before.cold_cycles == 0,
        fingerprints_valid: [
            after.hot_fingerprint.clone(),
            after.warm_fingerprint.clone(),
            after.cold_fingerprint.clone(),
        ] == descriptor.payload.mapping_content_identities,
        descriptor_consumed_once: root.join("target-descriptor.consumed").exists(),
        validator_invoked,
        no_damon_damos_mutation: !validator_invoked,
        direct_shadow_gates: direct,
        required_damos_gates_passed: required,
        applied_bytes: applied,
        only_cold_reclaimed: only_cold,
        cleanup_passed: cleanup && status.success(),
    };
    remove_target_root(&root)?;
    Ok(evidence)
}

fn read_u64(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn named_counter(path: &Path, name: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == name).then(|| fields.next()?.parse().ok())?
    })
}

#[allow(clippy::too_many_arguments)]
fn level_is_sustainable(
    variant: BenchmarkVariant,
    exact_load: bool,
    pressure_heartbeat: bool,
    worker_alive: bool,
    target: &CompositionTargetEvidence,
    oom: u64,
    oom_kill: u64,
    structural_restore: bool,
) -> bool {
    exact_load
        && pressure_heartbeat
        && worker_alive
        && target.hot_progress
        && target.warm_progress
        && target.cold_inactive_before_action
        && target.fingerprints_valid
        && target.cleanup_passed
        && oom == 0
        && oom_kill == 0
        && structural_restore
        && match variant {
            BenchmarkVariant::CachyosBaseline => {
                !target.validator_invoked && target.no_damon_damos_mutation
            }
            BenchmarkVariant::NemorCapacity => {
                target.validator_invoked
                    && !target.no_damon_damos_mutation
                    && target.direct_shadow_gates.into_iter().all(|gate| gate)
                    && target.required_damos_gates_passed
                    && target.only_cold_reclaimed
            }
            _ => false,
        }
}

fn pressure_message(
    kind: &str,
    experiment: &str,
    run: &str,
    pid: u32,
    ticks: u64,
) -> WorkerIpcMessage {
    let (version, experiment_id, run_id, pid, start_ticks) =
        ipc_identity(experiment, run, pid, ticks);
    match kind {
        "hold" => WorkerIpcMessage::BeginHold {
            version,
            experiment_id,
            run_id,
            pid,
            start_ticks,
        },
        "heartbeat" => WorkerIpcMessage::HeartbeatRequest {
            version,
            experiment_id,
            run_id,
            pid,
            start_ticks,
        },
        "stop" => WorkerIpcMessage::Stop {
            version,
            experiment_id,
            run_id,
            pid,
            start_ticks,
        },
        _ => unreachable!(),
    }
}

fn persist_execution(output: &Path, evidence: &CapacityCompositionExecutionEvidence) -> Result<()> {
    let path = output.join("capacity-composition.report.json");
    let temporary = output.join("capacity-composition.report.json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(evidence)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn open_store(output: &Path) -> Result<Connection> {
    let db = Connection::open(output.join("capacity-composition.sqlite"))?;
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE experiment (sequence INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
         CREATE TABLE levels (run_order INTEGER NOT NULL, level_index INTEGER NOT NULL, payload TEXT NOT NULL,
          PRIMARY KEY(run_order, level_index));",
    )?;
    Ok(db)
}

pub fn execute_capacity_composition(
    manifest_path: &Path,
) -> Result<CapacityCompositionExecutionEvidence> {
    let manifest = read_manifest(manifest_path)?;
    if !nix::unistd::geteuid().is_root() {
        bail!("composition execution requires root");
    }
    let preflight = capacity_composition_preflight(manifest_path)?;
    if !preflight.bounded_composition_entry_ready {
        bail!("composition bounded entry is not ready");
    }
    let payload = &manifest.payload;
    let db = open_store(&payload.output_root)?;
    let mut evidence = CapacityCompositionExecutionEvidence {
        schema_version: COMPOSITION_EXECUTION_SCHEMA_VERSION,
        experiment_id: payload.experiment_id.clone(),
        source_commit: payload.provenance.git_head.clone(),
        state: CompositionExperimentState::Running,
        reason: "composition execution running".into(),
        runs: Vec::new(),
        planned_runs: 6,
        completed_runs: 0,
        planned_levels: 18,
        completed_levels: 0,
        invocation_count: 1,
        search_complete: false,
        capacity_evaluation: EvaluationState::NotEvaluated,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
        production_activation_authorized: false,
        cleanup_passed: false,
        structural_restore_passed: false,
        payload_sha256: String::new(),
    };
    persist_execution(&payload.output_root, &evidence)?;
    for run in &payload.run_plan {
        let before = StructuralSnapshot::capture();
        let run_id = format!("composition-r{}-{}", run.order_index, payload.experiment_id);
        let socket = payload
            .output_root
            .join(format!("pressure-{}.sock", run.order_index));
        let mut child = Command::new(&payload.runner_path)
            .args([
                "pressure-worker",
                "--socket",
                socket.to_str().context("non-UTF8 worker socket")?,
                "--experiment-id",
                &payload.experiment_id,
                "--run-id",
                &run_id,
                "--seed",
                &run.seed.to_string(),
            ])
            .spawn()?;
        let pid = child.id();
        let ticks = proc_start_ticks(pid)?.context("pressure worker start ticks unavailable")?;
        wait_for_path(&socket, Duration::from_secs(5))?;
        let mut client = PressureWorkerClient::connect(&socket)?;
        let hello = client.receive_with_timeout(Duration::from_secs(3), "HELLO")?;
        if !matches!(hello, WorkerIpcMessage::Hello { pid: p, start_ticks: t, .. } if p == pid && t == ticks)
        {
            bail!("pressure HELLO identity mismatch");
        }
        let identity = crate::harness::OwnedProcessIdentity {
            run_id: run_id.clone(),
            pid,
            start_ticks: ticks,
        };
        let plan = TransientScopePlan::with_pressure_limits(
            &run_id,
            identity,
            payload.pressure_memory_max_bytes,
            100_000_000,
        )?;
        let mut systemd = SystemdDbusBackend::system()?;
        let scope = systemd.start_owned_scope(&plan)?;
        scope.verify(&plan)?;
        let (version, experiment_id, ipc_run_id, ipc_pid, start_ticks) =
            ipc_identity(&payload.experiment_id, &run_id, pid, ticks);
        let boundary = client.send_with_timeout(
            &WorkerIpcMessage::VerifyBoundary {
                version,
                experiment_id,
                run_id: ipc_run_id,
                pid: ipc_pid,
                start_ticks,
                memory_max_bytes: payload.pressure_memory_max_bytes,
            },
            Duration::from_secs(3),
            "VERIFY_BOUNDARY",
        )?;
        if !matches!(boundary, WorkerIpcMessage::BoundaryVerified { .. }) {
            bail!("pressure boundary acknowledgement missing");
        }
        let mut prior = 0;
        let mut levels = Vec::new();
        for level in &run.levels {
            let level_dir = payload.output_root.join(format!(
                "run-{}-level-{}",
                run.order_index, level.level_index
            ));
            fs::create_dir(&level_dir)?;
            let command = command_for_level(&payload.experiment_id, &run_id, level, prior)?;
            let (version, experiment_id, ipc_run_id, ipc_pid, start_ticks) =
                ipc_identity(&payload.experiment_id, &run_id, pid, ticks);
            let ack = client.send_with_timeout(
                &WorkerIpcMessage::LevelRequest {
                    version,
                    experiment_id,
                    run_id: ipc_run_id,
                    pid: ipc_pid,
                    start_ticks,
                    command,
                    monotonic_ns: u64::try_from(now_ns()?).unwrap_or(u64::MAX),
                },
                Duration::from_secs(15),
                "LEVEL_REQUEST",
            )?;
            let acknowledgement = match ack {
                WorkerIpcMessage::LevelAck {
                    acknowledgement, ..
                } => acknowledgement,
                _ => bail!("pressure level acknowledgement missing"),
            };
            std::thread::sleep(Duration::from_millis(COMPOSITION_STABILIZATION_MS));
            let integrity = client.send_with_timeout(
                &pressure_message("hold", &payload.experiment_id, &run_id, pid, ticks),
                Duration::from_secs(5),
                "BEGIN_HOLD",
            )?;
            let pressure_integrity_identity = match integrity {
                WorkerIpcMessage::IntegrityResult { identity, .. } => identity,
                _ => bail!("pressure integrity result missing"),
            };
            let heartbeat = client.receive_with_timeout(Duration::from_secs(3), "HEARTBEAT")?;
            let pressure_heartbeat = matches!(
                heartbeat,
                WorkerIpcMessage::Heartbeat { touched_bytes, .. }
                    if touched_bytes == level.target_touched_bytes
            );
            let target = target_for_level(payload, run, level.level_index, &level_dir)?;
            let heartbeat = client.send_with_timeout(
                &pressure_message("heartbeat", &payload.experiment_id, &run_id, pid, ticks),
                Duration::from_secs(5),
                "HEARTBEAT",
            )?;
            let worker_alive = matches!(
                heartbeat,
                WorkerIpcMessage::Heartbeat { touched_bytes, .. }
                    if touched_bytes == level.target_touched_bytes
            );
            let _ = client.receive_with_timeout(Duration::from_secs(5), "INTEGRITY");
            let cgroup =
                Path::new("/sys/fs/cgroup").join(scope.control_group.trim_start_matches('/'));
            let events = cgroup.join("memory.events");
            let oom = named_counter(&events, "oom").unwrap_or(u64::MAX);
            let oom_kill = named_counter(&events, "oom_kill").unwrap_or(u64::MAX);
            let level_restore = StructuralSnapshot::capture().matches(&before);
            let sustainable = level_is_sustainable(
                run.variant,
                acknowledgement.actual_touched_bytes == level.target_touched_bytes,
                pressure_heartbeat,
                worker_alive,
                &target,
                oom,
                oom_kill,
                level_restore,
            );
            let level_evidence = CapacityCompositionLevelEvidence {
                version: COMPOSITION_LEVEL_EVIDENCE_VERSION,
                run_order: run.order_index,
                level_index: level.level_index,
                variant: run.variant,
                target_touched_bytes: level.target_touched_bytes,
                requested_delta_bytes: acknowledgement.requested_delta_bytes,
                actual_touched_bytes: acknowledgement.actual_touched_bytes,
                pressure_integrity_identity,
                pressure_heartbeat,
                pressure_worker_alive: worker_alive,
                cgroup_membership: true,
                memory_max_verified: true,
                memory_current_bytes: read_u64(&cgroup.join("memory.current")),
                memory_peak_bytes: read_u64(&cgroup.join("memory.peak")),
                host_psi_full_avg10: fs::read_to_string("/proc/pressure/memory").ok(),
                cgroup_psi_full_avg10: fs::read_to_string(cgroup.join("memory.pressure")).ok(),
                major_fault_delta: None,
                swap_in_delta: None,
                swap_out_delta: None,
                block_write_delta: None,
                oom,
                oom_kill,
                watchdog_triggered: false,
                target,
                classification: if sustainable {
                    CompositionLevelClassification::Sustainable
                } else {
                    CompositionLevelClassification::InvalidEvidence
                },
                cleanup_passed: true,
                structural_restore_passed: level_restore,
            };
            write_new_json(&level_dir.join("level-evidence.json"), &level_evidence)?;
            db.execute(
                "INSERT INTO levels(run_order,level_index,payload) VALUES(?1,?2,?3)",
                params![
                    i64::try_from(run.order_index)?,
                    i64::try_from(level.level_index)?,
                    serde_json::to_string(&level_evidence)?
                ],
            )?;
            prior = acknowledgement.actual_touched_bytes;
            levels.push(level_evidence);
            evidence.completed_levels += 1;
            if !sustainable {
                break;
            }
        }
        let _ = client.send_with_timeout(
            &pressure_message("stop", &payload.experiment_id, &run_id, pid, ticks),
            Duration::from_secs(5),
            "STOP",
        );
        let worker_status = child.wait()?;
        systemd.stop_owned_scope(&plan)?;
        systemd.wait_inactive_or_removed(&plan.unit_name, Duration::from_secs(5))?;
        let restored = StructuralSnapshot::capture().matches(&before);
        let run_pass = levels.len() == 3
            && levels
                .iter()
                .all(|level| level.classification == CompositionLevelClassification::Sustainable)
            && worker_status.success()
            && restored;
        evidence.runs.push(CapacityCompositionRunEvidence {
            version: COMPOSITION_RUN_EVIDENCE_VERSION,
            order_index: run.order_index,
            variant: run.variant,
            repetition_index: run.repetition_index,
            seed: run.seed,
            state: if run_pass {
                CompositionExperimentState::CompletedCompositionFrameworkValidation
            } else {
                CompositionExperimentState::InvalidRun
            },
            levels,
            pressure_scope_cleanup_passed: true,
            structural_restore_passed: restored,
            reason: if run_pass {
                "all three composition levels sustainable".into()
            } else {
                "composition run mandatory evidence failed".into()
            },
        });
        if run_pass {
            evidence.completed_runs += 1;
        } else {
            evidence.state = CompositionExperimentState::InvalidRun;
            break;
        }
        persist_execution(&payload.output_root, &evidence)?;
    }
    if evidence.completed_runs == 6 && evidence.completed_levels == 18 {
        evidence.state = CompositionExperimentState::CompletedCompositionFrameworkValidation;
        evidence.reason = "6/6 runs and 18/18 composition levels passed".into();
        evidence.cleanup_passed = true;
        evidence.structural_restore_passed = true;
    } else if evidence.state == CompositionExperimentState::Running {
        evidence.state = CompositionExperimentState::InvalidRun;
        evidence.reason = "composition execution incomplete".into();
    }
    evidence = evidence.seal()?;
    evidence.verify()?;
    persist_execution(&payload.output_root, &evidence)?;
    db.execute(
        "INSERT INTO experiment(payload) VALUES(?1)",
        params![serde_json::to_string(&evidence)?],
    )?;
    Ok(evidence)
}

pub fn composition_execution_exit_status(state: CompositionExperimentState) -> i32 {
    if state == CompositionExperimentState::CompletedCompositionFrameworkValidation {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capacity_external_target::{
        CAPACITY_EXTERNAL_TARGET_COLD_BYTES, CAPACITY_EXTERNAL_TARGET_ZONE_BYTES,
    };
    use damon::AddressRange;

    fn progress(sequence: u64, hot: u64, warm: u64) -> CapacityExternalTargetProgress {
        CapacityExternalTargetProgress {
            protocol_version: CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION,
            target_session_id: "session".into(),
            nonce: "n".repeat(64),
            state: CapacityExternalTargetState::Stopped,
            sequence,
            heartbeat_monotonic_ns: 1,
            hot_cycles: hot,
            warm_cycles: warm,
            hot_pages_touched: hot,
            warm_pages_touched: warm,
            cold_cycles: 0,
            controlled_refaults: 1,
            hot_fingerprint: "a".repeat(64),
            warm_fingerprint: "b".repeat(64),
            cold_fingerprint: "c".repeat(64),
        }
    }

    fn target(variant: BenchmarkVariant) -> CompositionTargetEvidence {
        let hot = AddressRange {
            start: 0x1000_0000,
            end: 0x1000_0000 + CAPACITY_EXTERNAL_TARGET_ZONE_BYTES,
        };
        let warm = AddressRange {
            start: 0x2000_0000,
            end: 0x2000_0000 + CAPACITY_EXTERNAL_TARGET_ZONE_BYTES,
        };
        let cold = AddressRange {
            start: 0x3000_0000,
            end: 0x3000_0000 + CAPACITY_EXTERNAL_TARGET_COLD_BYTES,
        };
        let capacity = variant == BenchmarkVariant::NemorCapacity;
        CompositionTargetEvidence {
            version: COMPOSITION_TARGET_EVIDENCE_VERSION,
            transaction_id: "transaction".into(),
            session_id: "session".into(),
            descriptor_hash: "d".repeat(64),
            pid: 1,
            start_ticks: 1,
            ranges: crate::capacity_external_target::CapacityExternalTargetRanges {
                hot,
                warm,
                cold,
            },
            before: progress(1, 0, 0),
            after: progress(2, 1, 1),
            hot_progress: true,
            warm_progress: true,
            cold_inactive_before_action: true,
            fingerprints_valid: true,
            descriptor_consumed_once: true,
            validator_invoked: capacity,
            no_damon_damos_mutation: !capacity,
            direct_shadow_gates: [true; 4],
            required_damos_gates_passed: true,
            applied_bytes: if capacity { 8 * MIB } else { 0 },
            only_cold_reclaimed: true,
            cleanup_passed: true,
        }
    }

    #[test]
    fn contract_is_framework_only() {
        let contract = CapacityPressureCompositionContract::v1();
        contract.validate().unwrap();
        assert!(contract.framework_validation_authorized);
        assert!(!contract.capacity_evaluation_authorized);
        assert!(!contract.refinement_authorized);
        assert!(!contract.production_activation_authorized);
        assert!(!contract.arbitrary_target_authorized);
        assert!(!contract.search_complete);
        assert!(!contract.automatic_retry);
    }

    #[test]
    fn external_target_v1_remains_non_search_and_non_production() {
        let contract = CapacityExternalTargetContract::v1();
        assert!(!contract.pressure_search_authorized);
        assert!(!contract.production_activation_authorized);
        assert!(contract.one_time_consumption_required);
    }

    #[test]
    fn headroom_has_explicit_target_controller_and_cleanup_reserves() {
        let headroom = CompositionHeadroomPolicy::conservative_v1()
            .derive(16 * 1024 * MIB)
            .unwrap();
        assert_eq!(headroom.target_reserve_bytes, 64 * MIB);
        assert_eq!(headroom.controller_reserve_bytes, 256 * MIB);
        assert_eq!(headroom.rollback_cleanup_reserve_bytes, 512 * MIB);
        assert!(headroom.pressure_effective_maximum_bytes <= 12 * 1024 * MIB);
    }

    #[test]
    fn headroom_overflow_and_small_hosts_are_rejected() {
        assert!(CompositionHeadroomPolicy::conservative_v1()
            .derive(1)
            .is_err());
        assert!(CompositionHeadroomPolicy::conservative_v1()
            .derive(0)
            .is_err());
    }

    #[test]
    fn run_plan_is_three_matched_interleaved_pairs() {
        let policy = PilotPolicyV1::conservative_v1();
        let reserve = HeadroomReserve {
            host_bytes: 1,
            runner_bytes: 1,
            observer_bytes: 1,
            rollback_cleanup_bytes: 1,
            operating_system_variance_bytes: 1,
            total_reserved_bytes: 5,
            effective_maximum_bytes: 1024 * MIB,
        };
        let make = || {
            deterministic_order(
                &[
                    BenchmarkVariant::CachyosBaseline,
                    BenchmarkVariant::NemorCapacity,
                ],
                3,
                1,
            )
            .into_iter()
            .enumerate()
            .map(|(order_index, (variant, repetition_index))| {
                let seed = paired_run_seed(1, repetition_index);
                CompositionRunPlan {
                    order_index,
                    variant,
                    repetition_index,
                    seed,
                    levels: policy.freeze(&reserve, seed).unwrap(),
                }
            })
            .collect::<Vec<_>>()
        };
        let first = make();
        let second = make();
        assert_eq!(first, second);
        validate_run_plan(&first).unwrap();
        assert_eq!(first.len(), 6);
        assert!(first.iter().all(|run| run.levels.len() == 3));
        for repetition in 0..3 {
            let pair: Vec<_> = first
                .iter()
                .filter(|run| run.repetition_index == repetition)
                .collect();
            assert_eq!(pair.len(), 2);
            assert_eq!(pair[0].seed, pair[1].seed);
        }
    }

    #[test]
    fn only_exact_variants_are_accepted() {
        let mut plans = vec![CompositionRunPlan {
            order_index: 0,
            variant: BenchmarkVariant::NemorObserve,
            repetition_index: 0,
            seed: 1,
            levels: vec![],
        }];
        assert!(validate_run_plan(&plans).is_err());
        plans[0].variant = BenchmarkVariant::NemorCapacity;
        assert!(validate_run_plan(&plans).is_err());
    }

    #[test]
    fn baseline_requires_explicit_no_mutation() {
        let mut evidence = target(BenchmarkVariant::CachyosBaseline);
        assert!(level_is_sustainable(
            BenchmarkVariant::CachyosBaseline,
            true,
            true,
            true,
            &evidence,
            0,
            0,
            true
        ));
        evidence.no_damon_damos_mutation = false;
        assert!(!level_is_sustainable(
            BenchmarkVariant::CachyosBaseline,
            true,
            true,
            true,
            &evidence,
            0,
            0,
            true
        ));
    }

    #[test]
    fn capacity_requires_each_direct_shadow_gate_independently() {
        for index in 0..4 {
            let mut evidence = target(BenchmarkVariant::NemorCapacity);
            evidence.direct_shadow_gates[index] = false;
            assert!(!level_is_sustainable(
                BenchmarkVariant::NemorCapacity,
                true,
                true,
                true,
                &evidence,
                0,
                0,
                true
            ));
        }
    }

    #[test]
    fn required_damos_summary_is_additional() {
        let mut evidence = target(BenchmarkVariant::NemorCapacity);
        evidence.required_damos_gates_passed = false;
        assert!(!level_is_sustainable(
            BenchmarkVariant::NemorCapacity,
            true,
            true,
            true,
            &evidence,
            0,
            0,
            true
        ));
    }

    #[test]
    fn hot_warm_cold_and_integrity_gates_are_independent() {
        for mutation in 0..5 {
            let mut evidence = target(BenchmarkVariant::NemorCapacity);
            match mutation {
                0 => evidence.hot_progress = false,
                1 => evidence.warm_progress = false,
                2 => evidence.cold_inactive_before_action = false,
                3 => evidence.fingerprints_valid = false,
                _ => evidence.only_cold_reclaimed = false,
            }
            assert!(!level_is_sustainable(
                BenchmarkVariant::NemorCapacity,
                true,
                true,
                true,
                &evidence,
                0,
                0,
                true
            ));
        }
    }

    #[test]
    fn load_ack_heartbeat_and_worker_are_independent() {
        let evidence = target(BenchmarkVariant::NemorCapacity);
        for gates in [
            [false, true, true],
            [true, false, true],
            [true, true, false],
        ] {
            assert!(!level_is_sustainable(
                BenchmarkVariant::NemorCapacity,
                gates[0],
                gates[1],
                gates[2],
                &evidence,
                0,
                0,
                true
            ));
        }
    }

    #[test]
    fn oom_oom_kill_cleanup_and_restore_fail_closed() {
        let evidence = target(BenchmarkVariant::NemorCapacity);
        assert!(!level_is_sustainable(
            BenchmarkVariant::NemorCapacity,
            true,
            true,
            true,
            &evidence,
            1,
            0,
            true
        ));
        assert!(!level_is_sustainable(
            BenchmarkVariant::NemorCapacity,
            true,
            true,
            true,
            &evidence,
            0,
            1,
            true
        ));
        assert!(!level_is_sustainable(
            BenchmarkVariant::NemorCapacity,
            true,
            true,
            true,
            &evidence,
            0,
            0,
            false
        ));
        let mut no_cleanup = evidence;
        no_cleanup.cleanup_passed = false;
        assert!(!level_is_sustainable(
            BenchmarkVariant::NemorCapacity,
            true,
            true,
            true,
            &no_cleanup,
            0,
            0,
            true
        ));
    }

    #[test]
    fn unrelated_variants_cannot_pass() {
        let evidence = target(BenchmarkVariant::NemorCapacity);
        assert!(!level_is_sustainable(
            BenchmarkVariant::NemorObserve,
            true,
            true,
            true,
            &evidence,
            0,
            0,
            true
        ));
    }

    #[test]
    fn exit_zero_only_for_completed_composition() {
        assert_eq!(
            composition_execution_exit_status(
                CompositionExperimentState::CompletedCompositionFrameworkValidation
            ),
            0
        );
        for state in [
            CompositionExperimentState::Running,
            CompositionExperimentState::RejectedBeforeRun0,
            CompositionExperimentState::InvalidRun,
            CompositionExperimentState::UnsustainableHealth,
            CompositionExperimentState::SafetyAbort,
            CompositionExperimentState::ExecutionError,
        ] {
            assert_eq!(composition_execution_exit_status(state), 1);
        }
    }

    #[test]
    fn execution_evidence_preserves_all_non_claims() {
        let evidence = CapacityCompositionExecutionEvidence {
            schema_version: COMPOSITION_EXECUTION_SCHEMA_VERSION,
            experiment_id: "experiment".into(),
            source_commit: BUILD_GIT_HEAD.into(),
            state: CompositionExperimentState::InvalidRun,
            reason: "fixture".into(),
            runs: vec![],
            planned_runs: 6,
            completed_runs: 0,
            planned_levels: 18,
            completed_levels: 0,
            invocation_count: 1,
            search_complete: false,
            capacity_evaluation: EvaluationState::NotEvaluated,
            effectiveness_evaluation: EvaluationState::NotEvaluated,
            production_activation_authorized: false,
            cleanup_passed: false,
            structural_restore_passed: false,
            payload_sha256: String::new(),
        }
        .seal()
        .unwrap();
        evidence.verify().unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        let round_trip: CapacityCompositionExecutionEvidence = serde_json::from_str(&json).unwrap();
        round_trip.verify().unwrap();
    }

    #[test]
    fn evidence_tamper_is_rejected() {
        let mut evidence = CapacityCompositionExecutionEvidence {
            schema_version: COMPOSITION_EXECUTION_SCHEMA_VERSION,
            experiment_id: "experiment".into(),
            source_commit: BUILD_GIT_HEAD.into(),
            state: CompositionExperimentState::InvalidRun,
            reason: "fixture".into(),
            runs: vec![],
            planned_runs: 6,
            completed_runs: 0,
            planned_levels: 18,
            completed_levels: 0,
            invocation_count: 1,
            search_complete: false,
            capacity_evaluation: EvaluationState::NotEvaluated,
            effectiveness_evaluation: EvaluationState::NotEvaluated,
            production_activation_authorized: false,
            cleanup_passed: false,
            structural_restore_passed: false,
            payload_sha256: String::new(),
        }
        .seal()
        .unwrap();
        evidence.search_complete = true;
        assert!(evidence.verify().is_err());
    }

    #[test]
    fn counter_parser_is_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("events");
        fs::write(&path, "oom 3\noom_kill 2\n").unwrap();
        assert_eq!(named_counter(&path, "oom"), Some(3));
        assert_eq!(named_counter(&path, "oom_kill"), Some(2));
        assert_eq!(named_counter(&path, "missing"), None);
    }
}
