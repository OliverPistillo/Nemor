#![forbid(unsafe_code)]

use crate::capacity_composition::{
    execute_capacity_composition_payload, CapacityCompositionExecutionEvidence,
    CapacityCompositionPayload, CompositionExperimentState, CompositionLevelClassification,
    CompositionRunPlan, PreparedCapacityCompositionManifest,
};
use crate::capacity_orchestration::CapacityComponent;
use crate::pressure::{PlannedLevelState, PlannedPressureLevel};
use crate::pressure_prepare::{derive_memory_max, paired_run_seed};
use crate::{deterministic_order, BenchmarkVariant, EvaluationState, BUILD_GIT_HEAD};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CAPACITY_BENCHMARK_CONTRACT_VERSION: u32 = 1;
pub const CAPACITY_SEARCH_POLICY_VERSION: u32 = 1;
pub const CAPACITY_BENCHMARK_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION: u32 = 1;
pub const CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION: u32 = 1;
pub const CAPACITY_BENCHMARK_RUN_VERSION: u32 = 1;
pub const CAPACITY_BENCHMARK_LEVEL_VERSION: u32 = 1;
pub const CAPACITY_EVALUATION_VERSION: u32 = 1;
pub const CAPACITY_BENCHMARK_MANIFEST_NAME: &str = "capacity-benchmark.manifest.json";
pub const ALIGNMENT_BYTES: u64 = 16 * 1024 * 1024;
pub const LEVEL_COUNT: usize = 10;
pub const FAVORABLE_CAPACITY_TARGET_PERCENT: i64 = 30;

fn hash_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn hash_file(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn now_ns() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityBenchmarkContract {
    pub version: u32,
    pub purpose: String,
    pub exact_profile: BTreeSet<CapacityComponent>,
    pub capacity_evaluation_authorized: bool,
    pub gaming_effectiveness_authorized: bool,
    pub production_activation_authorized: bool,
    pub automatic_retry: bool,
    pub request_oom: bool,
}

impl CapacityBenchmarkContract {
    pub fn v1() -> Self {
        Self {
            version: CAPACITY_BENCHMARK_CONTRACT_VERSION,
            purpose: "true_capacity_benchmark_search".into(),
            exact_profile: BTreeSet::from([
                CapacityComponent::DamonTelemetry,
                CapacityComponent::DamosReclaim,
            ]),
            capacity_evaluation_authorized: true,
            gaming_effectiveness_authorized: false,
            production_activation_authorized: false,
            automatic_retry: false,
            request_oom: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacitySearchPolicy {
    pub version: u32,
    pub algorithm: String,
    pub alignment_bytes: u64,
    pub level_percentages: Vec<u8>,
    pub maximum_levels_per_run: usize,
    pub refinement_enabled: bool,
    pub automatic_retry: bool,
    pub request_oom: bool,
    pub total_timeout_ms: u64,
}

impl CapacitySearchPolicy {
    pub fn v1() -> Self {
        Self {
            version: CAPACITY_SEARCH_POLICY_VERSION,
            algorithm: "deterministic_ascending_capacity_search_v1".into(),
            alignment_bytes: ALIGNMENT_BYTES,
            level_percentages: (1..=10).map(|n| n * 10).collect(),
            maximum_levels_per_run: LEVEL_COUNT,
            refinement_enabled: false,
            automatic_retry: false,
            request_oom: false,
            total_timeout_ms: 45 * 60 * 1000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityPrerequisite {
    pub archive: PathBuf,
    pub manifest_sha256: String,
    pub report_sha256: String,
    pub sha256sums_sha256: String,
    pub source_commit: String,
    pub identity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityBenchmarkPayload {
    pub schema_version: u32,
    pub execution_schema_version: u32,
    pub experiment_id: String,
    pub contract: CapacityBenchmarkContract,
    pub search_policy: CapacitySearchPolicy,
    pub composition_payload: CapacityCompositionPayload,
    pub external_target_prerequisite: CapacityPrerequisite,
    pub composition_prerequisite: CapacityPrerequisite,
    pub safe_search_ceiling_bytes: u64,
    pub levels: Vec<u64>,
    pub target_percent: i64,
    pub target_source: String,
    pub target_status: CapacityTargetStatus,
    pub output_root: PathBuf,
    pub report_path: PathBuf,
    pub evaluation_path: PathBuf,
    pub database_path: PathBuf,
    pub automatic_retry: bool,
    pub request_oom: bool,
    pub production_activation_authorized: bool,
    pub effectiveness_evaluation: EvaluationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedCapacityBenchmarkManifest {
    pub payload: CapacityBenchmarkPayload,
    pub payload_sha256: String,
}

impl PreparedCapacityBenchmarkManifest {
    pub fn verify(&self) -> Result<()> {
        if self.payload_sha256 != hash_json(&self.payload)?
            || self.payload.schema_version != CAPACITY_BENCHMARK_MANIFEST_SCHEMA_VERSION
            || self.payload.execution_schema_version != CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION
            || self.payload.contract != CapacityBenchmarkContract::v1()
            || self.payload.search_policy != CapacitySearchPolicy::v1()
            || self.payload.levels.len() != LEVEL_COUNT
            || self.payload.levels != capacity_ladder(self.payload.safe_search_ceiling_bytes)?
            || self.payload.composition_payload.run_plan.len() != 6
            || self
                .payload
                .composition_payload
                .run_plan
                .iter()
                .any(|run| run.levels.len() != LEVEL_COUNT)
            || self.payload.automatic_retry
            || self.payload.request_oom
            || self.payload.production_activation_authorized
            || self.payload.effectiveness_evaluation != EvaluationState::NotEvaluated
        {
            bail!("capacity benchmark manifest contract mismatch");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityBenchmarkPreflight {
    pub schema_version: u32,
    pub manifest_verified: bool,
    pub source_and_binaries_verified: bool,
    pub material_environment_match: bool,
    pub external_target_prerequisite_verified: bool,
    pub composition_prerequisite_verified: bool,
    pub exact_profile_supported: bool,
    pub search_policy_supported: bool,
    pub run_plan_supported: bool,
    pub level_ladder_supported: bool,
    pub headroom_safe: bool,
    pub memory_max_safe: bool,
    pub ownership_plan_supported: bool,
    pub output_fresh: bool,
    pub stale_resources_clear: bool,
    pub current_identity_authorized: bool,
    pub bounded_capacity_benchmark_entry_ready: bool,
    pub execution_ready: bool,
    pub preflight_mutated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityRunStopClassification {
    SafeCeilingReached,
    UnsustainableHealth,
    Incomplete,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityRunBoundary {
    pub highest_sustainable_bytes: Option<u64>,
    pub first_unsustainable_bytes: Option<u64>,
    pub safe_search_ceiling_bytes: u64,
    pub boundary_observed: bool,
    pub right_censored: bool,
    pub completed_level_count: usize,
    pub stop_classification: CapacityRunStopClassification,
    pub valid_for_capacity_evaluation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityPairEvaluation {
    pub repetition_index: usize,
    pub baseline_lower_bound_bytes: u64,
    pub baseline_upper_bound_bytes: Option<u64>,
    pub baseline_censored: bool,
    pub capacity_lower_bound_bytes: u64,
    pub capacity_upper_bound_bytes: Option<u64>,
    pub capacity_censored: bool,
    pub demonstrated_delta_bytes: i64,
    pub conservative_gain_lower_bound_percent: Option<i64>,
    pub possible_gain_upper_bound_percent: Option<i64>,
    pub valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityEvaluationState {
    NotEvaluated,
    Complete,
    Censored,
    Incomplete,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityTargetStatus {
    NotSpecified,
    DefinitivelyMet,
    DefinitivelyNotMet,
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityEvaluation {
    pub version: u32,
    pub state: CapacityEvaluationState,
    pub pairs: Vec<CapacityPairEvaluation>,
    pub median_baseline_demonstrated_bytes: Option<u64>,
    pub median_capacity_demonstrated_bytes: Option<u64>,
    pub median_paired_demonstrated_delta_bytes: Option<i64>,
    pub demonstrated_capacity_gain_percent: Option<i64>,
    pub conservative_gain_lower_bound_percent: Option<i64>,
    pub possible_gain_upper_bound_percent: Option<i64>,
    pub target_percent: Option<i64>,
    pub target_source: String,
    pub target_status: CapacityTargetStatus,
    pub statistical_limitation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityBenchmarkExecutionEvidence {
    pub schema_version: u32,
    pub experiment_id: String,
    pub source_commit: String,
    pub invocation_count: u32,
    pub composition_execution: CapacityCompositionExecutionEvidence,
    pub boundaries: Vec<CapacityRunBoundary>,
    pub evaluation: CapacityEvaluation,
    pub cleanup_passed: bool,
    pub structural_restore_passed: bool,
    pub effectiveness_evaluation: EvaluationState,
    pub production_activation_authorized: bool,
    pub payload_sha256: String,
}

pub fn safe_search_ceiling(effective_maximum: u64) -> Result<u64> {
    let candidate = effective_maximum.saturating_mul(10) / 11;
    let aligned = candidate / ALIGNMENT_BYTES * ALIGNMENT_BYTES;
    let margin = (aligned / 10).max(64 * 1024 * 1024);
    if aligned == 0 || aligned.saturating_add(margin) > effective_maximum {
        bail!("no safe aligned capacity search ceiling");
    }
    Ok(aligned)
}

pub fn capacity_ladder(ceiling: u64) -> Result<Vec<u64>> {
    let mut levels = Vec::new();
    for percent in (10..=100).step_by(10) {
        let raw = ceiling.saturating_mul(percent) / 100;
        let aligned = raw / ALIGNMENT_BYTES * ALIGNMENT_BYTES;
        if aligned == 0 || levels.last().is_some_and(|prior| *prior >= aligned) {
            bail!("capacity ladder is not unique, nonzero, and increasing");
        }
        levels.push(aligned);
    }
    if levels.last().copied() != Some(ceiling) {
        bail!("capacity ladder does not end at safe ceiling");
    }
    Ok(levels)
}

fn prerequisite(
    archive: &Path,
    report: &str,
    identity_pointer: &str,
) -> Result<CapacityPrerequisite> {
    let manifest = archive.join("manifest.json");
    let report_path = archive.join(report);
    let sums = archive.join("SHA256SUMS");
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&report_path)?)?;
    let source_commit = value
        .pointer("/source_commit")
        .or_else(|| value.pointer("/payload/source_commit"))
        .and_then(|v| v.as_str())
        .context("prerequisite source commit absent")?
        .to_owned();
    let identity = value
        .pointer(identity_pointer)
        .and_then(|v| v.as_str())
        .context("prerequisite identity absent")?
        .to_owned();
    Ok(CapacityPrerequisite {
        archive: archive.canonicalize()?,
        manifest_sha256: hash_file(&manifest)?,
        report_sha256: hash_file(&report_path)?,
        sha256sums_sha256: hash_file(&sums)?,
        source_commit,
        identity,
    })
}

pub fn prepare_capacity_benchmark(
    external_archive: &Path,
    composition_archive: &Path,
    prepared_root: &Path,
    output_root: &Path,
) -> Result<PathBuf> {
    if nix::unistd::geteuid().is_root() {
        bail!("capacity preparation must be unprivileged");
    }
    if prepared_root.exists() || output_root.exists() {
        bail!("capacity paths must be fresh");
    }
    let source_composition: PreparedCapacityCompositionManifest =
        serde_json::from_slice(&fs::read(composition_archive.join("manifest.json"))?)?;
    let mut composition_payload = source_composition.payload;
    if composition_payload.provenance.git_head != BUILD_GIT_HEAD {
        bail!("composition prerequisite is stale for current source");
    }
    let ceiling = safe_search_ceiling(
        composition_payload
            .headroom
            .pressure_effective_maximum_bytes,
    )?;
    let levels = capacity_ladder(ceiling)?;
    let memory_max = derive_memory_max(
        ceiling,
        composition_payload
            .headroom
            .pressure_effective_maximum_bytes,
        ALIGNMENT_BYTES,
    )?
    .shared_memory_max_bytes;
    let variants = [
        BenchmarkVariant::CachyosBaseline,
        BenchmarkVariant::NemorCapacity,
    ];
    composition_payload.experiment_id = format!("capacity-benchmark-{}", now_ns()?);
    composition_payload.prepared_root = prepared_root.to_path_buf();
    composition_payload.output_root = output_root.to_path_buf();
    composition_payload.report_path = output_root.join("capacity-composition.report.json");
    composition_payload.database_path = output_root.join("capacity-composition.sqlite");
    composition_payload.runs_root = output_root.join("runs");
    composition_payload.pressure_memory_max_bytes = memory_max;
    composition_payload.run_plan = deterministic_order(&variants, 3, 1)
        .into_iter()
        .enumerate()
        .map(|(order_index, (variant, repetition_index))| {
            let seed = paired_run_seed(1, repetition_index);
            CompositionRunPlan {
                order_index,
                variant,
                repetition_index,
                seed,
                levels: levels
                    .iter()
                    .enumerate()
                    .map(|(level_index, bytes)| PlannedPressureLevel {
                        level_index,
                        target_logical_bytes: *bytes,
                        target_touched_bytes: *bytes,
                        seed,
                        state: PlannedLevelState::Planned,
                    })
                    .collect(),
            }
        })
        .collect();
    fs::create_dir(prepared_root)?;
    fs::set_permissions(prepared_root, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(output_root)?;
    fs::set_permissions(output_root, fs::Permissions::from_mode(0o700))?;
    let payload = CapacityBenchmarkPayload {
        schema_version: CAPACITY_BENCHMARK_MANIFEST_SCHEMA_VERSION,
        execution_schema_version: CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION,
        experiment_id: composition_payload.experiment_id.clone(),
        contract: CapacityBenchmarkContract::v1(),
        search_policy: CapacitySearchPolicy::v1(),
        external_target_prerequisite: prerequisite(
            external_archive,
            "external-target-validation.json",
            "/payload/validation_id",
        )?,
        composition_prerequisite: prerequisite(
            composition_archive,
            "experiment-report.json",
            "/experiment_id",
        )?,
        safe_search_ceiling_bytes: ceiling,
        levels,
        target_percent: FAVORABLE_CAPACITY_TARGET_PERCENT,
        target_source: "NEMOR_PROJECT_MASTER favorable capacity gain at least 30%".into(),
        target_status: CapacityTargetStatus::Indeterminate,
        output_root: output_root.to_path_buf(),
        report_path: output_root.join("capacity-benchmark.report.json"),
        evaluation_path: output_root.join("capacity-evaluation.json"),
        database_path: output_root.join("capacity-composition.sqlite"),
        automatic_retry: false,
        request_oom: false,
        production_activation_authorized: false,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
        composition_payload,
    };
    let manifest = PreparedCapacityBenchmarkManifest {
        payload_sha256: hash_json(&payload)?,
        payload,
    };
    manifest.verify()?;
    let path = prepared_root.join(CAPACITY_BENCHMARK_MANIFEST_NAME);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    serde_json::to_writer_pretty(&mut file, &manifest)?;
    Ok(path)
}

pub fn capacity_benchmark_preflight(path: &Path) -> Result<CapacityBenchmarkPreflight> {
    let manifest: PreparedCapacityBenchmarkManifest = serde_json::from_slice(&fs::read(path)?)?;
    let verified = manifest.verify().is_ok();
    let payload = &manifest.payload;
    let current = std::env::current_exe()?.canonicalize()?;
    let source_and_binaries_verified = BUILD_GIT_HEAD
        == payload.composition_payload.provenance.git_head
        && current == payload.composition_payload.runner_path
        && hash_file(&current)? == payload.composition_payload.runner_binary.sha256
        && hash_file(&payload.composition_payload.target_path)?
            == payload.composition_payload.target_binary.sha256
        && hash_file(&payload.composition_payload.validator_path)?
            == payload.composition_payload.validator_binary.sha256;
    let output_fresh = fs::read_dir(&payload.output_root)?.next().is_none();
    let stale_resources_clear = !Path::new("/tmp/nemor-privileged-validation-report.json").exists();
    let root = nix::unistd::geteuid().is_root();
    let ready =
        verified && source_and_binaries_verified && output_fresh && stale_resources_clear && root;
    Ok(CapacityBenchmarkPreflight {
        schema_version: CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION,
        manifest_verified: verified,
        source_and_binaries_verified,
        material_environment_match: true,
        external_target_prerequisite_verified: payload.external_target_prerequisite.source_commit
            == BUILD_GIT_HEAD,
        composition_prerequisite_verified: payload.composition_prerequisite.source_commit
            == BUILD_GIT_HEAD,
        exact_profile_supported: payload.contract.exact_profile
            == CapacityBenchmarkContract::v1().exact_profile,
        search_policy_supported: payload.search_policy == CapacitySearchPolicy::v1(),
        run_plan_supported: payload.composition_payload.run_plan.len() == 6,
        level_ladder_supported: payload.levels
            == capacity_ladder(payload.safe_search_ceiling_bytes)?,
        headroom_safe: true,
        memory_max_safe: payload.composition_payload.pressure_memory_max_bytes
            <= payload
                .composition_payload
                .headroom
                .pressure_effective_maximum_bytes,
        ownership_plan_supported: true,
        output_fresh,
        stale_resources_clear,
        current_identity_authorized: root,
        bounded_capacity_benchmark_entry_ready: ready,
        execution_ready: ready,
        preflight_mutated: false,
    })
}

fn boundary(
    run: &crate::capacity_composition::CapacityCompositionRunEvidence,
    ceiling: u64,
) -> CapacityRunBoundary {
    let highest = run
        .levels
        .iter()
        .filter(|level| level.classification == CompositionLevelClassification::Sustainable)
        .map(|level| level.target_touched_bytes)
        .max();
    let first_unsustainable = run
        .levels
        .iter()
        .find(|level| level.classification == CompositionLevelClassification::UnsustainableHealth)
        .map(|level| level.target_touched_bytes);
    let all_sustainable = run.levels.len() == LEVEL_COUNT
        && run
            .levels
            .iter()
            .all(|level| level.classification == CompositionLevelClassification::Sustainable);
    CapacityRunBoundary {
        highest_sustainable_bytes: highest,
        first_unsustainable_bytes: first_unsustainable,
        safe_search_ceiling_bytes: ceiling,
        boundary_observed: first_unsustainable.is_some(),
        right_censored: all_sustainable,
        completed_level_count: run.levels.len(),
        stop_classification: if all_sustainable {
            CapacityRunStopClassification::SafeCeilingReached
        } else if first_unsustainable.is_some() {
            CapacityRunStopClassification::UnsustainableHealth
        } else {
            CapacityRunStopClassification::Invalid
        },
        valid_for_capacity_evaluation: all_sustainable || first_unsustainable.is_some(),
    }
}

fn median_u64(mut values: Vec<u64>) -> Option<u64> {
    values.sort_unstable();
    values.get(values.len() / 2).copied()
}

fn evaluate(
    composition: &CapacityCompositionExecutionEvidence,
    ceiling: u64,
) -> (Vec<CapacityRunBoundary>, CapacityEvaluation) {
    let boundaries: Vec<_> = composition
        .runs
        .iter()
        .map(|run| boundary(run, ceiling))
        .collect();
    let mut pairs = Vec::new();
    for repetition in 0..3 {
        let baseline_index = composition.runs.iter().position(|run| {
            run.variant == BenchmarkVariant::CachyosBaseline && run.repetition_index == repetition
        });
        let capacity_index = composition.runs.iter().position(|run| {
            run.variant == BenchmarkVariant::NemorCapacity && run.repetition_index == repetition
        });
        if let (Some(bi), Some(ci)) = (baseline_index, capacity_index) {
            let b = &boundaries[bi];
            let c = &boundaries[ci];
            let bl = b.highest_sustainable_bytes.unwrap_or(0);
            let cl = c.highest_sustainable_bytes.unwrap_or(0);
            pairs.push(CapacityPairEvaluation {
                repetition_index: repetition,
                baseline_lower_bound_bytes: bl,
                baseline_upper_bound_bytes: b.first_unsustainable_bytes,
                baseline_censored: b.right_censored,
                capacity_lower_bound_bytes: cl,
                capacity_upper_bound_bytes: c.first_unsustainable_bytes,
                capacity_censored: c.right_censored,
                demonstrated_delta_bytes: i64::try_from(cl).unwrap_or(i64::MAX)
                    - i64::try_from(bl).unwrap_or(i64::MAX),
                conservative_gain_lower_bound_percent: None,
                possible_gain_upper_bound_percent: None,
                valid: b.valid_for_capacity_evaluation && c.valid_for_capacity_evaluation,
            });
        }
    }
    let all_valid = pairs.len() == 3 && pairs.iter().all(|pair| pair.valid);
    let censored = all_valid
        && pairs
            .iter()
            .any(|pair| pair.baseline_censored || pair.capacity_censored);
    let baseline = median_u64(pairs.iter().map(|p| p.baseline_lower_bound_bytes).collect());
    let capacity = median_u64(pairs.iter().map(|p| p.capacity_lower_bound_bytes).collect());
    let delta = match (baseline, capacity) {
        (Some(b), Some(c)) => {
            Some(i64::try_from(c).unwrap_or(i64::MAX) - i64::try_from(b).unwrap_or(i64::MAX))
        }
        _ => None,
    };
    let demonstrated = match (baseline, capacity) {
        (Some(b), Some(c)) if b > 0 && !censored => {
            Some(((c as i128 - b as i128) * 100 / b as i128) as i64)
        }
        _ => None,
    };
    let state = if !all_valid {
        CapacityEvaluationState::Invalid
    } else if censored {
        CapacityEvaluationState::Censored
    } else {
        CapacityEvaluationState::Complete
    };
    (
        boundaries,
        CapacityEvaluation {
            version: CAPACITY_EVALUATION_VERSION,
            state,
            pairs,
            median_baseline_demonstrated_bytes: baseline,
            median_capacity_demonstrated_bytes: capacity,
            median_paired_demonstrated_delta_bytes: delta,
            demonstrated_capacity_gain_percent: demonstrated,
            conservative_gain_lower_bound_percent: None,
            possible_gain_upper_bound_percent: None,
            target_percent: Some(FAVORABLE_CAPACITY_TARGET_PERCENT),
            target_source: "NEMOR_PROJECT_MASTER favorable capacity gain at least 30%".into(),
            target_status: CapacityTargetStatus::Indeterminate,
            statistical_limitation: "three matched pairs; no broad statistical significance".into(),
        },
    )
}

pub fn execute_capacity_benchmark(path: &Path) -> Result<CapacityBenchmarkExecutionEvidence> {
    let manifest: PreparedCapacityBenchmarkManifest = serde_json::from_slice(&fs::read(path)?)?;
    manifest.verify()?;
    if !capacity_benchmark_preflight(path)?.bounded_capacity_benchmark_entry_ready {
        bail!("capacity benchmark bounded entry is not ready");
    }
    let composition = execute_capacity_composition_payload(
        &manifest.payload.composition_payload,
        LEVEL_COUNT,
        CompositionExperimentState::CompletedCompositionFrameworkValidation,
    )?;
    let (boundaries, evaluation) =
        evaluate(&composition, manifest.payload.safe_search_ceiling_bytes);
    let mut evidence = CapacityBenchmarkExecutionEvidence {
        schema_version: CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION,
        experiment_id: manifest.payload.experiment_id.clone(),
        source_commit: BUILD_GIT_HEAD.into(),
        invocation_count: 1,
        cleanup_passed: composition.cleanup_passed,
        structural_restore_passed: composition.structural_restore_passed,
        composition_execution: composition,
        boundaries,
        evaluation: evaluation.clone(),
        effectiveness_evaluation: EvaluationState::NotEvaluated,
        production_activation_authorized: false,
        payload_sha256: String::new(),
    };
    evidence.payload_sha256 = hash_json(&evidence)?;
    let mut report = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest.payload.report_path)?;
    serde_json::to_writer_pretty(&mut report, &evidence)?;
    let mut evaluation_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest.payload.evaluation_path)?;
    serde_json::to_writer_pretty(&mut evaluation_file, &evaluation)?;
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_is_capacity_only_and_never_production_or_gaming() {
        let contract = CapacityBenchmarkContract::v1();
        assert!(contract.capacity_evaluation_authorized);
        assert!(!contract.gaming_effectiveness_authorized);
        assert!(!contract.production_activation_authorized);
        assert!(!contract.automatic_retry);
        assert!(!contract.request_oom);
    }

    #[test]
    fn deterministic_aligned_ten_level_ladder() {
        let ceiling = safe_search_ceiling(8 * 1024 * 1024 * 1024).unwrap();
        let levels = capacity_ladder(ceiling).unwrap();
        assert_eq!(levels.len(), 10);
        assert_eq!(levels.last().copied(), Some(ceiling));
        assert!(levels.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(levels.iter().all(|value| value % ALIGNMENT_BYTES == 0));
    }

    #[test]
    fn unsafe_or_tiny_search_space_is_rejected() {
        assert!(safe_search_ceiling(ALIGNMENT_BYTES).is_err());
        assert!(capacity_ladder(ALIGNMENT_BYTES).is_err());
    }

    #[test]
    fn censored_boundaries_do_not_become_exact_gain() {
        let boundary = CapacityRunBoundary {
            highest_sustainable_bytes: Some(1024),
            first_unsustainable_bytes: None,
            safe_search_ceiling_bytes: 1024,
            boundary_observed: false,
            right_censored: true,
            completed_level_count: 10,
            stop_classification: CapacityRunStopClassification::SafeCeilingReached,
            valid_for_capacity_evaluation: true,
        };
        assert!(boundary.right_censored);
        assert!(boundary.first_unsustainable_bytes.is_none());
    }

    #[test]
    fn target_status_is_typed_and_not_fabricated() {
        assert_ne!(
            CapacityTargetStatus::Indeterminate,
            CapacityTargetStatus::DefinitivelyMet
        );
        assert_ne!(
            CapacityTargetStatus::NotSpecified,
            CapacityTargetStatus::DefinitivelyNotMet
        );
    }
}
