#![forbid(unsafe_code)]

use crate::capacity_composition::{
    execute_capacity_composition_payload, CapacityCompositionExecutionEvidence,
    CapacityCompositionPayload, CompositionExperimentState, CompositionLevelClassification,
    CompositionRunPlan, PreparedCapacityCompositionManifest,
};
use crate::capacity_external_target::{
    TARGET_COMMAND_REFAULT_FILE, TARGET_COMMAND_START_FILE, TARGET_COMMAND_STOP_FILE,
    TARGET_CONSUMED_FILE, TARGET_DESCRIPTOR_FILE, TARGET_PROGRESS_FILE,
};
use crate::capacity_external_validation::ExternalTargetExecutionReport;
use crate::capacity_orchestration::CapacityComponent;
use crate::pressure::{PlannedLevelState, PlannedPressureLevel};
use crate::pressure_prepare::{derive_memory_max, paired_run_seed};
use crate::systemd::SystemdDbusBackend;
use crate::{
    deterministic_order, BenchmarkVariant, BuildProvenance, EnvironmentFingerprint,
    EvaluationState, BUILD_GIT_HEAD,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CAPACITY_BENCHMARK_CONTRACT_VERSION: u32 = 2;
pub const CAPACITY_SEARCH_POLICY_VERSION: u32 = 1;
pub const CAPACITY_BENCHMARK_MANIFEST_SCHEMA_VERSION: u32 = 4;
pub const CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION: u32 = 4;
pub const CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION: u32 = 3;
pub const CAPACITY_BENCHMARK_RUN_VERSION: u32 = 3;
pub const CAPACITY_BENCHMARK_LEVEL_VERSION: u32 = 3;
pub const CAPACITY_EVALUATION_VERSION: u32 = 2;
pub const CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION: u32 = 1;
pub const CAPACITY_PATH_CONTRACT_VERSION: u32 = 1;
pub const CAPACITY_BENCHMARK_MANIFEST_NAME: &str = "capacity-benchmark.manifest.json";
pub const ALIGNMENT_BYTES: u64 = 16 * 1024 * 1024;
pub const LEVEL_COUNT: usize = 10;
pub const FAVORABLE_CAPACITY_TARGET_PERCENT: i64 = 30;
pub const CAPACITY_SCOPE_RUNTIME_MAX_USEC: u64 = 300_000_000;
pub const CAPACITY_LEVEL_TIMEOUT_MS: u64 = 30_000;
pub const CAPACITY_RUN_TIMEOUT_MS: u64 = 280_000;

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
    pub fn v2() -> Self {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityPrerequisiteKind {
    ExternalTarget,
    Composition,
}

impl CapacityPrerequisiteKind {
    fn report_name(self) -> &'static str {
        match self {
            Self::ExternalTarget => "external-target-validation.json",
            Self::Composition => "experiment-report.json",
        }
    }

    fn identity_pointer(self) -> &'static str {
        match self {
            Self::ExternalTarget => "/payload/validation_id",
            Self::Composition => "/experiment_id",
        }
    }

    fn identity_key(self) -> &'static str {
        match self {
            Self::ExternalTarget => "validation_id",
            Self::Composition => "experiment_id",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapacityPrerequisiteStatus {
    version: u32,
    kind: CapacityPrerequisiteKind,
    identity: String,
    source_commit: String,
    manifest_sha256: String,
    manifest_payload_sha256: String,
    execution_payload_sha256: String,
    external_target_identity: Option<String>,
    invocation_count: u32,
    cleanup_passed: bool,
    structural_restore_passed: bool,
    legacy_global_report_absent: bool,
    validator_state_absent: bool,
    final_nr_kdamonds: u32,
    capacity_evaluation: EvaluationState,
    effectiveness_evaluation: EvaluationState,
    production_activation_authorized: bool,
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
    pub capacity_scope_runtime_max_usec: u64,
    pub per_level_timeout_ms: u64,
    pub per_run_timeout_ms: u64,
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
            || self.payload.contract != CapacityBenchmarkContract::v2()
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
            || self.payload.capacity_scope_runtime_max_usec != CAPACITY_SCOPE_RUNTIME_MAX_USEC
            || self.payload.per_level_timeout_ms != CAPACITY_LEVEL_TIMEOUT_MS
            || self.payload.per_run_timeout_ms != CAPACITY_RUN_TIMEOUT_MS
            || self.payload.per_run_timeout_ms.saturating_mul(6)
                > self.payload.search_policy.total_timeout_ms
            || !capacity_payload_path_layout_supported(&self.payload)
            || !capacity_run_plan_supported(&self.payload)
            || self.payload.composition_payload.pressure_memory_max_bytes
                != derive_memory_max(
                    self.payload.safe_search_ceiling_bytes,
                    self.payload
                        .composition_payload
                        .headroom
                        .pressure_effective_maximum_bytes,
                    ALIGNMENT_BYTES,
                )?
                .shared_memory_max_bytes
        {
            bail!("capacity benchmark manifest contract mismatch");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityBenchmarkPreflight {
    pub schema_version: u32,
    pub prerequisite_status_contract_version: u32,
    pub path_contract_version: u32,
    pub manifest_verified: bool,
    pub source_and_binaries_verified: bool,
    pub material_environment_match: bool,
    pub external_target_prerequisite_verified: bool,
    pub composition_prerequisite_verified: bool,
    pub prerequisite_lineage_link_verified: bool,
    pub exact_profile_supported: bool,
    pub search_policy_supported: bool,
    pub run_plan_supported: bool,
    pub level_ladder_supported: bool,
    pub safe_search_ceiling_supported: bool,
    pub headroom_safe: bool,
    pub memory_max_safe: bool,
    pub ownership_plan_supported: bool,
    pub output_fresh: bool,
    pub stale_resources_clear: bool,
    pub report_lifecycle_version_supported: bool,
    pub legacy_global_report_absent: bool,
    pub validator_state_absent: bool,
    pub user_preflight_passed: bool,
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
    pub state: CapacityBenchmarkState,
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
    pub primary_error: Option<String>,
    pub secondary_errors: Vec<String>,
    pub payload_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityBenchmarkState {
    Running,
    Complete,
    Censored,
    Incomplete,
    Invalid,
}

impl CapacityBenchmarkExecutionEvidence {
    pub fn seal(mut self) -> Result<Self> {
        self.payload_sha256.clear();
        self.payload_sha256 = hash_json(&self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<()> {
        let mut candidate = self.clone();
        let frozen = candidate.payload_sha256.clone();
        candidate.payload_sha256.clear();
        if self.schema_version != CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION
            || frozen != hash_json(&candidate)?
            || self.effectiveness_evaluation != EvaluationState::NotEvaluated
            || self.production_activation_authorized
            || matches!(
                self.state,
                CapacityBenchmarkState::Complete | CapacityBenchmarkState::Censored
            ) && (!self.cleanup_passed || !self.structural_restore_passed)
        {
            bail!("capacity benchmark execution evidence contract mismatch");
        }
        Ok(())
    }
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

fn prerequisite(archive: &Path, kind: CapacityPrerequisiteKind) -> Result<CapacityPrerequisite> {
    let manifest = archive.join("manifest.json");
    let report_path = archive.join(kind.report_name());
    let sums = archive.join("SHA256SUMS");
    let value: serde_json::Value = serde_json::from_slice(&fs::read(&report_path)?)?;
    let source_commit = value
        .pointer("/source_commit")
        .or_else(|| value.pointer("/payload/source_commit"))
        .and_then(|v| v.as_str())
        .context("prerequisite source commit absent")?
        .to_owned();
    let identity = value
        .pointer(kind.identity_pointer())
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

fn parse_status_entries(status: &str) -> Result<BTreeMap<&str, &str>> {
    let mut entries = BTreeMap::new();
    if status.is_empty() {
        bail!("capacity prerequisite STATUS is empty");
    }
    for line in status.lines() {
        let (key, value) = line
            .split_once('=')
            .context("malformed capacity prerequisite STATUS line")?;
        if key.is_empty()
            || value.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
            || entries.insert(key, value).is_some()
        {
            bail!("ambiguous capacity prerequisite STATUS entry");
        }
    }
    Ok(entries)
}

fn expect_status(entries: &BTreeMap<&str, &str>, key: &str, expected: &str) -> Result<()> {
    if entries.get(key).copied() != Some(expected) {
        bail!("capacity prerequisite STATUS {key} mismatch");
    }
    Ok(())
}

fn status_allowed_keys(kind: CapacityPrerequisiteKind) -> BTreeSet<&'static str> {
    match kind {
        CapacityPrerequisiteKind::ExternalTarget => BTreeSet::from([
            "status",
            "validation_id",
            "source_commit",
            "manifest_sha256",
            "manifest_payload_sha256",
            "execution_payload_sha256",
            "invocation_count",
            "validator_report_lifecycle",
            "validator_report_raw_sha256",
            "validator_report_canonical_sha256",
            "direct_shadow_gates",
            "required_damos_gates",
            "hot_warm_service",
            "cold_controlled_refault",
            "host_oom",
            "cleanup",
            "recovery",
            "idempotent_recovery",
            "structural_restore",
            "legacy_global_report_absent",
            "validator_state_absent",
            "final_nr_kdamonds",
            "capacity",
            "effectiveness",
            "production_activation",
        ]),
        CapacityPrerequisiteKind::Composition => BTreeSet::from([
            "status",
            "experiment_id",
            "source_commit",
            "manifest_sha256",
            "manifest_payload_sha256",
            "execution_payload_sha256",
            "external_target_lineage",
            "invocation_count",
            "runs",
            "levels",
            "sustainable_levels",
            "baseline_runs",
            "capacity_runs",
            "transaction_scoped_capacity_reports",
            "report_lifecycle",
            "legacy_global_report_absent",
            "validator_state_absent",
            "host_oom",
            "cgroup_oom_kill",
            "watchdog",
            "target_cleanup",
            "scope_cleanup",
            "structural_restore",
            "final_nr_kdamonds",
            "capacity",
            "effectiveness",
            "production_activation",
        ]),
    }
}

fn parse_prerequisite_status(
    status: &str,
    kind: CapacityPrerequisiteKind,
) -> Result<CapacityPrerequisiteStatus> {
    let entries = parse_status_entries(status)?;
    let actual_keys = entries.keys().copied().collect::<BTreeSet<_>>();
    if actual_keys != status_allowed_keys(kind) {
        bail!("capacity prerequisite STATUS key set mismatch");
    }
    expect_status(&entries, "status", "PASS")?;
    expect_status(&entries, "invocation_count", "1")?;
    expect_status(&entries, "structural_restore", "PASS")?;
    expect_status(&entries, "legacy_global_report_absent", "true")?;
    expect_status(&entries, "validator_state_absent", "true")?;
    expect_status(&entries, "final_nr_kdamonds", "0")?;
    expect_status(&entries, "capacity", "NotEvaluated")?;
    expect_status(&entries, "effectiveness", "NotEvaluated")?;
    expect_status(&entries, "production_activation", "false")?;
    match kind {
        CapacityPrerequisiteKind::ExternalTarget => {
            for (key, expected) in [
                ("validator_report_lifecycle", "PASS"),
                ("direct_shadow_gates", "4/4"),
                ("required_damos_gates", "48/48"),
                ("hot_warm_service", "PASS"),
                ("cold_controlled_refault", "PASS"),
                ("host_oom", "0"),
                ("cleanup", "PASS"),
                ("recovery", "PASS"),
                ("idempotent_recovery", "PASS"),
            ] {
                expect_status(&entries, key, expected)?;
            }
            for key in [
                "validator_report_raw_sha256",
                "validator_report_canonical_sha256",
            ] {
                let value = entries.get(key).copied().context("STATUS hash absent")?;
                if value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    bail!("capacity prerequisite STATUS hash is not lowercase SHA-256");
                }
            }
        }
        CapacityPrerequisiteKind::Composition => {
            for (key, expected) in [
                ("runs", "6/6"),
                ("levels", "18/18"),
                ("sustainable_levels", "18/18"),
                ("baseline_runs", "3"),
                ("capacity_runs", "3"),
                ("transaction_scoped_capacity_reports", "9"),
                ("report_lifecycle", "PASS"),
                ("host_oom", "0"),
                ("cgroup_oom_kill", "0"),
                ("watchdog", "false"),
                ("target_cleanup", "PASS"),
                ("scope_cleanup", "PASS"),
            ] {
                expect_status(&entries, key, expected)?;
            }
        }
    }
    Ok(CapacityPrerequisiteStatus {
        version: CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION,
        kind,
        identity: entries[kind.identity_key()].to_owned(),
        source_commit: entries["source_commit"].to_owned(),
        manifest_sha256: entries["manifest_sha256"].to_owned(),
        manifest_payload_sha256: entries["manifest_payload_sha256"].to_owned(),
        execution_payload_sha256: entries["execution_payload_sha256"].to_owned(),
        external_target_identity: match kind {
            CapacityPrerequisiteKind::ExternalTarget => None,
            CapacityPrerequisiteKind::Composition => {
                Some(entries["external_target_lineage"].to_owned())
            }
        },
        invocation_count: entries["invocation_count"].parse()?,
        cleanup_passed: match kind {
            CapacityPrerequisiteKind::ExternalTarget => entries["cleanup"] == "PASS",
            CapacityPrerequisiteKind::Composition => {
                entries["target_cleanup"] == "PASS" && entries["scope_cleanup"] == "PASS"
            }
        },
        structural_restore_passed: entries["structural_restore"] == "PASS",
        legacy_global_report_absent: entries["legacy_global_report_absent"] == "true",
        validator_state_absent: entries["validator_state_absent"] == "true",
        final_nr_kdamonds: entries["final_nr_kdamonds"].parse()?,
        capacity_evaluation: EvaluationState::NotEvaluated,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
        production_activation_authorized: false,
    })
}

fn verify_all_sums(archive: &Path) -> Result<()> {
    let sums = fs::read_to_string(archive.join("SHA256SUMS"))?;
    let mut seen = BTreeSet::new();
    for line in sums.lines() {
        let (expected, relative) = line
            .split_once("  ")
            .context("malformed prerequisite SHA256SUMS")?;
        let relative = Path::new(relative);
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || !seen.insert(relative.to_path_buf())
        {
            bail!("ambiguous capacity prerequisite SHA256SUMS entry");
        }
        let path = archive.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        if path.canonicalize()?.strip_prefix(archive).is_err()
            || !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || hash_file(&path)? != expected
        {
            bail!("capacity prerequisite archive checksum mismatch");
        }
    }
    for required in ["manifest.json", "STATUS", "evidence.tar"] {
        if !seen.contains(Path::new(required)) {
            bail!("capacity prerequisite SHA256SUMS omits required evidence");
        }
    }
    Ok(())
}

fn verify_archive(
    prerequisite: &CapacityPrerequisite,
    kind: CapacityPrerequisiteKind,
) -> Result<()> {
    let archive = prerequisite.archive.canonicalize()?;
    let report_name = kind.report_name();
    if archive != prerequisite.archive
        || hash_file(&archive.join("manifest.json"))? != prerequisite.manifest_sha256
        || hash_file(&archive.join(report_name))? != prerequisite.report_sha256
        || hash_file(&archive.join("SHA256SUMS"))? != prerequisite.sha256sums_sha256
    {
        bail!("capacity prerequisite frozen identity mismatch");
    }
    verify_all_sums(&archive)?;
    let report_bytes = fs::read(archive.join(report_name))?;
    let status = parse_prerequisite_status(&fs::read_to_string(archive.join("STATUS"))?, kind)?;
    if status.version != CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION
        || status.kind != kind
        || status.identity != prerequisite.identity
        || status.source_commit != prerequisite.source_commit
        || status.manifest_sha256 != prerequisite.manifest_sha256
        || status.invocation_count != 1
        || !status.cleanup_passed
        || !status.structural_restore_passed
        || !status.legacy_global_report_absent
        || !status.validator_state_absent
        || status.final_nr_kdamonds != 0
        || status.capacity_evaluation != EvaluationState::NotEvaluated
        || status.effectiveness_evaluation != EvaluationState::NotEvaluated
        || status.production_activation_authorized
    {
        bail!("capacity prerequisite typed STATUS identity or non-claim mismatch");
    }
    match kind {
        CapacityPrerequisiteKind::ExternalTarget => {
            let manifest:
                crate::capacity_external_validation::PreparedExternalTargetValidationManifest =
                serde_json::from_slice(&fs::read(archive.join("manifest.json"))?)?;
            let report: ExternalTargetExecutionReport = serde_json::from_slice(&report_bytes)?;
            report.verify()?;
            if status.manifest_payload_sha256 != manifest.payload_sha256
                || status.execution_payload_sha256 != report.payload_sha256
                || status.external_target_identity.is_some()
                || !matches!(
                    report.state,
                    crate::capacity_external_validation::ExternalTargetClassification::Pass
                )
                || report.payload.validation_id != status.identity
                || report.payload.source_commit != status.source_commit
                || !report.payload.validator_exit_success
                || !report
                    .payload
                    .direct_shadow_gates
                    .into_iter()
                    .all(|gate| gate)
                || !report.payload.required_damos_gates_passed
                || !report.payload.zero_host_oom
                || !report.payload.cleanup_passed
                || !report.payload.recovery_passed
                || !report.payload.recovery_idempotent_passed
                || !report.payload.structural_restore_passed
            {
                bail!("external-target prerequisite STATUS/report contract mismatch");
            }
        }
        CapacityPrerequisiteKind::Composition => {
            let manifest: PreparedCapacityCompositionManifest =
                serde_json::from_slice(&fs::read(archive.join("manifest.json"))?)?;
            let report: CapacityCompositionExecutionEvidence =
                serde_json::from_slice(&report_bytes)?;
            report.verify()?;
            if status.manifest_payload_sha256 != manifest.payload_sha256
                || status.execution_payload_sha256 != report.payload_sha256
                || status.external_target_identity.as_deref()
                    != Some(
                        manifest
                            .payload
                            .external_target_prerequisite
                            .validation_id
                            .as_str(),
                    )
                || report.state
                    != CompositionExperimentState::CompletedCompositionFrameworkValidation
                || report.experiment_id != status.identity
                || report.source_commit != status.source_commit
                || report.invocation_count != 1
                || report.completed_runs != 6
                || report.completed_levels != 18
                || !report.cleanup_passed
                || !report.structural_restore_passed
            {
                bail!("composition prerequisite STATUS/report contract mismatch");
            }
        }
    }
    Ok(())
}

fn capacity_path_lineage(path: &Path, role: &str) -> Option<u32> {
    if path.parent()? != Path::new("/tmp") {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    let lineage = name
        .strip_prefix("nemor-capacity-benchmark-")?
        .strip_suffix(role)?;
    if lineage.is_empty()
        || !lineage.bytes().all(|byte| byte.is_ascii_digit())
        || lineage.starts_with('0')
    {
        return None;
    }
    let parsed = lineage.parse::<u32>().ok()?;
    (parsed > 0 && parsed.to_string() == lineage).then_some(parsed)
}

fn capacity_path_plan_supported(prepared_root: &Path, output_root: &Path) -> bool {
    let prepared_lineage = capacity_path_lineage(prepared_root, "-prepared");
    let output_lineage = capacity_path_lineage(output_root, "-output");
    prepared_lineage.is_some() && prepared_lineage == output_lineage
}

fn private_owned_directory(path: &Path, uid: u32, gid: u32) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    metadata.file_type().is_dir()
        && metadata.uid() == uid
        && metadata.gid() == gid
        && metadata.mode() & 0o7777 == 0o700
        && path.canonicalize().is_ok_and(|canonical| canonical == path)
}

fn capacity_payload_path_layout_supported(payload: &CapacityBenchmarkPayload) -> bool {
    let composition = &payload.composition_payload;
    let prepared_root = &composition.prepared_root;
    let output_root = &payload.output_root;
    capacity_path_plan_supported(prepared_root, output_root)
        && payload.experiment_id == composition.experiment_id
        && payload
            .experiment_id
            .strip_prefix("capacity-benchmark-")
            .is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
        && composition.output_root == *output_root
        && payload.report_path == output_root.join("capacity-benchmark.report.json")
        && payload.evaluation_path == output_root.join("capacity-evaluation.json")
        && payload.database_path == output_root.join("capacity-composition.sqlite")
        && composition.report_path == output_root.join("capacity-composition.report.json")
        && composition.database_path == payload.database_path
        && composition.runs_root == output_root.join("runs")
}

fn capacity_payload_paths_supported(
    manifest_path: &Path,
    payload: &CapacityBenchmarkPayload,
) -> bool {
    let composition = &payload.composition_payload;
    let prepared_root = &composition.prepared_root;
    let output_root = &payload.output_root;
    capacity_payload_path_layout_supported(payload)
        && manifest_path == prepared_root.join(CAPACITY_BENCHMARK_MANIFEST_NAME)
        && private_owned_directory(
            prepared_root,
            composition.preparing_uid,
            composition.preparing_gid,
        )
        && private_owned_directory(
            output_root,
            composition.preparing_uid,
            composition.preparing_gid,
        )
}

fn external_prerequisite_matches_composition(
    external: &CapacityPrerequisite,
    composition: &CapacityCompositionPayload,
) -> Result<bool> {
    let nested = &composition.external_target_prerequisite;
    let report: ExternalTargetExecutionReport = serde_json::from_slice(&fs::read(
        external
            .archive
            .join(CapacityPrerequisiteKind::ExternalTarget.report_name()),
    )?)?;
    Ok(nested.archive_path.canonicalize()? == external.archive
        && nested.validation_id == external.identity
        && nested.source_commit == external.source_commit
        && nested.manifest_sha256 == external.manifest_sha256
        && nested.sha256sums_sha256 == external.sha256sums_sha256
        && nested.evidence_payload_sha256 == report.payload_sha256)
}

fn capacity_run_plan_supported(payload: &CapacityBenchmarkPayload) -> bool {
    let expected = deterministic_order(
        &[
            BenchmarkVariant::CachyosBaseline,
            BenchmarkVariant::NemorCapacity,
        ],
        3,
        1,
    );
    payload.composition_payload.run_plan.len() == expected.len()
        && payload
            .composition_payload
            .run_plan
            .iter()
            .zip(expected)
            .enumerate()
            .all(|(order_index, (run, (variant, repetition_index)))| {
                let seed = paired_run_seed(1, repetition_index);
                run.order_index == order_index
                    && run.variant == variant
                    && run.repetition_index == repetition_index
                    && run.seed == seed
                    && run.levels.len() == payload.levels.len()
                    && run.levels.iter().zip(&payload.levels).enumerate().all(
                        |(level_index, (level, expected_bytes))| {
                            level.level_index == level_index
                                && level.target_logical_bytes == *expected_bytes
                                && level.target_touched_bytes == *expected_bytes
                                && level.seed == seed
                                && level.state == PlannedLevelState::Planned
                        },
                    )
            })
}

#[derive(Debug, Clone, Copy)]
struct CapacityReadinessGates {
    manifest_verified: bool,
    source_and_binaries_verified: bool,
    material_environment_match: bool,
    external_target_prerequisite_verified: bool,
    composition_prerequisite_verified: bool,
    prerequisite_lineage_link_verified: bool,
    exact_profile_supported: bool,
    search_policy_supported: bool,
    run_plan_supported: bool,
    level_ladder_supported: bool,
    safe_search_ceiling_supported: bool,
    headroom_safe: bool,
    memory_max_safe: bool,
    ownership_plan_supported: bool,
    output_fresh: bool,
    stale_resources_clear: bool,
    report_lifecycle_version_supported: bool,
    legacy_global_report_absent: bool,
    validator_state_absent: bool,
}

impl CapacityReadinessGates {
    fn user_ready(self) -> bool {
        [
            self.manifest_verified,
            self.source_and_binaries_verified,
            self.material_environment_match,
            self.external_target_prerequisite_verified,
            self.composition_prerequisite_verified,
            self.prerequisite_lineage_link_verified,
            self.exact_profile_supported,
            self.search_policy_supported,
            self.run_plan_supported,
            self.level_ladder_supported,
            self.safe_search_ceiling_supported,
            self.headroom_safe,
            self.memory_max_safe,
            self.ownership_plan_supported,
            self.output_fresh,
            self.stale_resources_clear,
            self.report_lifecycle_version_supported,
            self.legacy_global_report_absent,
            self.validator_state_absent,
        ]
        .into_iter()
        .all(|gate| gate)
    }
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
    if prepared_root.exists()
        || output_root.exists()
        || !capacity_path_plan_supported(prepared_root, output_root)
    {
        bail!("capacity paths must be fresh and satisfy the exact v1 path contract");
    }
    let source_composition: PreparedCapacityCompositionManifest =
        serde_json::from_slice(&fs::read(composition_archive.join("manifest.json"))?)?;
    source_composition.verify()?;
    if source_composition.payload.provenance.git_head != BUILD_GIT_HEAD {
        bail!("composition prerequisite is stale for current source");
    }
    let external_target_prerequisite =
        prerequisite(external_archive, CapacityPrerequisiteKind::ExternalTarget)?;
    let composition_prerequisite =
        prerequisite(composition_archive, CapacityPrerequisiteKind::Composition)?;
    verify_archive(
        &external_target_prerequisite,
        CapacityPrerequisiteKind::ExternalTarget,
    )?;
    verify_archive(
        &composition_prerequisite,
        CapacityPrerequisiteKind::Composition,
    )?;
    if external_target_prerequisite.source_commit != BUILD_GIT_HEAD
        || composition_prerequisite.source_commit != BUILD_GIT_HEAD
        || !external_prerequisite_matches_composition(
            &external_target_prerequisite,
            &source_composition.payload,
        )?
    {
        bail!("capacity prerequisites are stale, unrelated, or cross-lineage ambiguous");
    }
    let mut composition_payload = source_composition.payload;
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
        contract: CapacityBenchmarkContract::v2(),
        search_policy: CapacitySearchPolicy::v1(),
        external_target_prerequisite,
        composition_prerequisite,
        safe_search_ceiling_bytes: ceiling,
        levels,
        target_percent: FAVORABLE_CAPACITY_TARGET_PERCENT,
        target_source: "NEMOR_PROJECT_MASTER favorable capacity gain at least 30%".into(),
        target_status: CapacityTargetStatus::Indeterminate,
        capacity_scope_runtime_max_usec: CAPACITY_SCOPE_RUNTIME_MAX_USEC,
        per_level_timeout_ms: CAPACITY_LEVEL_TIMEOUT_MS,
        per_run_timeout_ms: CAPACITY_RUN_TIMEOUT_MS,
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
    let current_provenance = BuildProvenance::capture()?;
    let source_and_binaries_verified = BUILD_GIT_HEAD
        == payload.composition_payload.provenance.git_head
        && current_provenance.clean_release_eligible()
        && current_provenance.source_state_id
            == payload.composition_payload.provenance.source_state_id
        && current == payload.composition_payload.runner_path
        && hash_file(&current)? == payload.composition_payload.runner_binary.sha256
        && hash_file(&payload.composition_payload.target_path)?
            == payload.composition_payload.target_binary.sha256
        && hash_file(&payload.composition_payload.validator_path)?
            == payload.composition_payload.validator_binary.sha256;
    let loaded = common::LoadedConfig::load(&payload.composition_payload.config_path)?;
    let environment = EnvironmentFingerprint::capture_for_performance(
        &loaded.sha256,
        &payload.composition_payload.provenance.git_head,
    )?;
    let material_environment_match = loaded.sha256 == payload.composition_payload.config_sha256
        && environment.material_hash()? == payload.composition_payload.material_environment_hash;
    let external_target_prerequisite_verified = payload.external_target_prerequisite.source_commit
        == BUILD_GIT_HEAD
        && verify_archive(
            &payload.external_target_prerequisite,
            CapacityPrerequisiteKind::ExternalTarget,
        )
        .is_ok();
    let composition_prerequisite_verified = payload.composition_prerequisite.source_commit
        == BUILD_GIT_HEAD
        && verify_archive(
            &payload.composition_prerequisite,
            CapacityPrerequisiteKind::Composition,
        )
        .is_ok();
    let prerequisite_lineage_link_verified = external_prerequisite_matches_composition(
        &payload.external_target_prerequisite,
        &payload.composition_payload,
    )
    .unwrap_or(false);
    let output_fresh = fs::read_dir(&payload.output_root)?.next().is_none();
    let legacy_global_report_absent = crate::validator_report::legacy_report_absent();
    let validator_state_absent = crate::validator_report::validator_state_absent();
    let stale_resources_clear = legacy_global_report_absent
        && validator_state_absent
        && !super::capacity_composition::processes_contain("pressure-worker")
        && !super::capacity_composition::processes_contain("capacity-external-target-worker")
        && !payload.output_root.join("pressure-0.sock").exists();
    let root = nix::unistd::geteuid().is_root();
    let identity_authorized = root
        && std::env::var("SUDO_UID")
            .ok()
            .and_then(|value| value.parse().ok())
            == Some(payload.composition_payload.preparing_uid)
        && std::env::var("SUDO_GID")
            .ok()
            .and_then(|value| value.parse().ok())
            == Some(payload.composition_payload.preparing_gid);
    let current_mem = super::capacity_composition::mem_available_bytes()?;
    let recomputed_ceiling = safe_search_ceiling(
        payload
            .composition_payload
            .headroom
            .pressure_effective_maximum_bytes,
    )?;
    let safe_search_ceiling_supported = recomputed_ceiling == payload.safe_search_ceiling_bytes;
    let headroom_safe = current_mem
        >= payload
            .composition_payload
            .pressure_memory_max_bytes
            .saturating_add(payload.composition_payload.headroom.fixed_reserve_bytes);
    let memory_max_safe = derive_memory_max(
        payload.safe_search_ceiling_bytes,
        payload
            .composition_payload
            .headroom
            .pressure_effective_maximum_bytes,
        ALIGNMENT_BYTES,
    )
    .is_ok_and(|derived| {
        payload.composition_payload.pressure_memory_max_bytes == derived.shared_memory_max_bytes
            && derived.shared_memory_max_bytes
                <= payload
                    .composition_payload
                    .headroom
                    .pressure_effective_maximum_bytes
    });
    let ownership_plan_supported = payload.composition_payload.preparing_uid != 0
        && payload.composition_payload.preparing_gid != 0
        && capacity_payload_paths_supported(path, payload);
    let exact_profile_supported =
        payload.contract.exact_profile == CapacityBenchmarkContract::v2().exact_profile;
    let search_policy_supported = payload.search_policy == CapacitySearchPolicy::v1();
    let run_plan_supported = capacity_run_plan_supported(payload);
    let level_ladder_supported =
        payload.levels == capacity_ladder(payload.safe_search_ceiling_bytes)?;
    let report_lifecycle_version_supported =
        crate::capacity_composition::COMPOSITION_TARGET_EVIDENCE_VERSION == 2;
    let gates = CapacityReadinessGates {
        manifest_verified: verified,
        source_and_binaries_verified,
        material_environment_match,
        external_target_prerequisite_verified,
        composition_prerequisite_verified,
        prerequisite_lineage_link_verified,
        exact_profile_supported,
        search_policy_supported,
        run_plan_supported,
        level_ladder_supported,
        safe_search_ceiling_supported,
        headroom_safe,
        memory_max_safe,
        ownership_plan_supported,
        output_fresh,
        stale_resources_clear,
        report_lifecycle_version_supported,
        legacy_global_report_absent,
        validator_state_absent,
    };
    let user_preflight_passed = gates.user_ready();
    let ready = user_preflight_passed && identity_authorized;
    Ok(CapacityBenchmarkPreflight {
        schema_version: CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION,
        prerequisite_status_contract_version: CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION,
        path_contract_version: CAPACITY_PATH_CONTRACT_VERSION,
        manifest_verified: verified,
        source_and_binaries_verified,
        material_environment_match,
        external_target_prerequisite_verified,
        composition_prerequisite_verified,
        prerequisite_lineage_link_verified,
        exact_profile_supported,
        search_policy_supported,
        run_plan_supported,
        level_ladder_supported,
        safe_search_ceiling_supported,
        headroom_safe,
        memory_max_safe,
        ownership_plan_supported,
        output_fresh,
        stale_resources_clear,
        report_lifecycle_version_supported,
        legacy_global_report_absent,
        validator_state_absent,
        user_preflight_passed,
        current_identity_authorized: identity_authorized,
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

fn median_i64(mut values: Vec<i64>) -> Option<i64> {
    values.sort_unstable();
    values.get(values.len() / 2).copied()
}

fn percent_floor(numerator: i128, denominator: u64) -> Option<i64> {
    if denominator == 0 {
        return None;
    }
    let denominator = i128::from(denominator);
    let scaled = numerator.checked_mul(100)?;
    let quotient = scaled.div_euclid(denominator);
    i64::try_from(quotient).ok()
}

fn percent_ceil(numerator: i128, denominator: u64) -> Option<i64> {
    if denominator == 0 {
        return None;
    }
    let denominator = i128::from(denominator);
    let scaled = numerator.checked_mul(100)?;
    let quotient = -((-scaled).div_euclid(denominator));
    i64::try_from(quotient).ok()
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
            let conservative = b.first_unsustainable_bytes.and_then(|baseline_upper| {
                percent_floor(i128::from(cl) - i128::from(baseline_upper), baseline_upper)
            });
            let possible = c.first_unsustainable_bytes.and_then(|capacity_upper| {
                percent_ceil(i128::from(capacity_upper) - i128::from(bl), bl)
            });
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
                conservative_gain_lower_bound_percent: conservative,
                possible_gain_upper_bound_percent: possible,
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
    let delta = median_i64(
        pairs
            .iter()
            .map(|pair| pair.demonstrated_delta_bytes)
            .collect(),
    );
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
    let conservative = if all_valid {
        let values: Vec<_> = pairs
            .iter()
            .filter_map(|pair| pair.conservative_gain_lower_bound_percent)
            .collect();
        (values.len() == 3).then(|| median_i64(values)).flatten()
    } else {
        None
    };
    let possible = if all_valid {
        let values: Vec<_> = pairs
            .iter()
            .filter_map(|pair| pair.possible_gain_upper_bound_percent)
            .collect();
        (values.len() == 3).then(|| median_i64(values)).flatten()
    } else {
        None
    };
    let target_status =
        if conservative.is_some_and(|value| value >= FAVORABLE_CAPACITY_TARGET_PERCENT) {
            CapacityTargetStatus::DefinitivelyMet
        } else if possible.is_some_and(|value| value < FAVORABLE_CAPACITY_TARGET_PERCENT) {
            CapacityTargetStatus::DefinitivelyNotMet
        } else {
            CapacityTargetStatus::Indeterminate
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
            conservative_gain_lower_bound_percent: conservative,
            possible_gain_upper_bound_percent: possible,
            target_percent: Some(FAVORABLE_CAPACITY_TARGET_PERCENT),
            target_source: "NEMOR_PROJECT_MASTER favorable capacity gain at least 30%".into(),
            target_status,
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
    let blank_composition = || CapacityCompositionExecutionEvidence {
        schema_version: crate::capacity_composition::COMPOSITION_EXECUTION_SCHEMA_VERSION,
        experiment_id: manifest.payload.experiment_id.clone(),
        source_commit: BUILD_GIT_HEAD.into(),
        state: CompositionExperimentState::Running,
        reason: "capacity benchmark execution starting".into(),
        runs: Vec::new(),
        planned_runs: 6,
        completed_runs: 0,
        planned_levels: 6 * LEVEL_COUNT,
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
    let invalid_evaluation = || CapacityEvaluation {
        version: CAPACITY_EVALUATION_VERSION,
        state: CapacityEvaluationState::Invalid,
        pairs: Vec::new(),
        median_baseline_demonstrated_bytes: None,
        median_capacity_demonstrated_bytes: None,
        median_paired_demonstrated_delta_bytes: None,
        demonstrated_capacity_gain_percent: None,
        conservative_gain_lower_bound_percent: None,
        possible_gain_upper_bound_percent: None,
        target_percent: Some(FAVORABLE_CAPACITY_TARGET_PERCENT),
        target_source: manifest.payload.target_source.clone(),
        target_status: CapacityTargetStatus::Indeterminate,
        statistical_limitation: "execution invalid; no capacity inference".into(),
    };
    let persist = |evidence: &CapacityBenchmarkExecutionEvidence| -> Result<()> {
        evidence.verify()?;
        let temporary = manifest.payload.report_path.with_extension("json.tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(evidence)?)?;
        fs::rename(temporary, &manifest.payload.report_path)?;
        fs::write(
            &manifest.payload.evaluation_path,
            serde_json::to_vec_pretty(&evidence.evaluation)?,
        )?;
        Ok(())
    };
    let initial = CapacityBenchmarkExecutionEvidence {
        schema_version: CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION,
        state: CapacityBenchmarkState::Running,
        experiment_id: manifest.payload.experiment_id.clone(),
        source_commit: BUILD_GIT_HEAD.into(),
        invocation_count: 1,
        composition_execution: blank_composition(),
        boundaries: Vec::new(),
        evaluation: CapacityEvaluation {
            state: CapacityEvaluationState::NotEvaluated,
            ..invalid_evaluation()
        },
        cleanup_passed: false,
        structural_restore_passed: false,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
        production_activation_authorized: false,
        primary_error: None,
        secondary_errors: Vec::new(),
        payload_sha256: String::new(),
    }
    .seal()?;
    persist(&initial)?;
    let composition = match execute_capacity_composition_payload(
        &manifest.payload.composition_payload,
        LEVEL_COUNT,
        CompositionExperimentState::CompletedCompositionFrameworkValidation,
    ) {
        Ok(composition) => composition,
        Err(error) => {
            let composition = fs::read(&manifest.payload.composition_payload.report_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_else(blank_composition);
            let evidence = CapacityBenchmarkExecutionEvidence {
                schema_version: CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION,
                state: CapacityBenchmarkState::Invalid,
                experiment_id: manifest.payload.experiment_id.clone(),
                source_commit: BUILD_GIT_HEAD.into(),
                invocation_count: 1,
                cleanup_passed: composition.cleanup_passed,
                structural_restore_passed: composition.structural_restore_passed,
                composition_execution: composition,
                boundaries: Vec::new(),
                evaluation: invalid_evaluation(),
                effectiveness_evaluation: EvaluationState::NotEvaluated,
                production_activation_authorized: false,
                primary_error: Some(format!("{error:#}")),
                secondary_errors: Vec::new(),
                payload_sha256: String::new(),
            }
            .seal()?;
            persist(&evidence)?;
            return Ok(evidence);
        }
    };
    let (boundaries, evaluation) =
        evaluate(&composition, manifest.payload.safe_search_ceiling_bytes);
    let evidence = CapacityBenchmarkExecutionEvidence {
        schema_version: CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION,
        state: match evaluation.state {
            CapacityEvaluationState::Complete => CapacityBenchmarkState::Complete,
            CapacityEvaluationState::Censored => CapacityBenchmarkState::Censored,
            CapacityEvaluationState::Incomplete => CapacityBenchmarkState::Incomplete,
            _ => CapacityBenchmarkState::Invalid,
        },
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
        primary_error: None,
        secondary_errors: Vec::new(),
        payload_sha256: String::new(),
    }
    .seal()?;
    persist(&evidence)?;
    Ok(evidence)
}

const LINEAGE1_ARCHIVE: &str = "/home/oliver/.local/share/nemor/validation-history/phase10-capacity-benchmark-1-execution-error";
const LINEAGE1_OUTPUT_ROOT: &str = "/tmp/nemor-capacity-benchmark-1-output";
pub const CAPACITY_RECOVERY_PREFLIGHT_SCHEMA_VERSION: u32 = 2;
pub const CAPACITY_RECOVERY_REPORT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPathKind {
    PressureSocket,
    TargetTransactionDirectory,
    PreservedEvidence,
    Unexpected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPathMetadata {
    pub path: PathBuf,
    pub kind: RecoveryPathKind,
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub link_count: u64,
    pub file_type: String,
    pub mountpoint: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryCandidateEvidence {
    pub metadata: RecoveryPathMetadata,
    pub expected_uid: u32,
    pub expected_gid: u32,
    pub children: Vec<RecoveryPathMetadata>,
    pub valid: bool,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub output_root: RecoveryPathMetadata,
    pub socket_candidates: Vec<PathBuf>,
    pub transaction_candidates: Vec<PathBuf>,
    pub existing_candidates: Vec<RecoveryCandidateEvidence>,
    pub preserved_evidence: Vec<PathBuf>,
    pub unexpected_entries: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryClassification {
    Pass,
    NoMutationAlreadyClean,
    PartialFailure,
    RejectedBeforeMutation,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPathAction {
    pub path: PathBuf,
    pub kind: RecoveryPathKind,
    pub removed: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapacityRecoveryPreflight {
    pub schema_version: u32,
    pub experiment_id: String,
    pub manifest_sha256: String,
    pub archive_verified: bool,
    pub consumed_lineage: bool,
    pub exact_processes_absent: bool,
    pub exact_units_absent: bool,
    pub exact_cgroups_clear: bool,
    pub damon_damos_clear: bool,
    pub plan: RecoveryPlan,
    pub exact_paths_verified: bool,
    pub current_identity_authorized: bool,
    pub recovery_ready: bool,
    pub preflight_mutated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityRecoveryReport {
    pub schema_version: u32,
    pub classification: RecoveryClassification,
    pub experiment_id: String,
    pub manifest_sha256: String,
    pub preflight_sha256: String,
    pub before: RecoveryPlan,
    pub actions: Vec<RecoveryPathAction>,
    pub removed_sockets: Vec<PathBuf>,
    pub removed_transactions: Vec<PathBuf>,
    pub preserved_evidence: Vec<PathBuf>,
    pub primary_error: Option<String>,
    pub secondary_errors: Vec<String>,
    pub after: RecoveryPlan,
    pub exact_processes_absent: bool,
    pub exact_units_absent: bool,
    pub exact_cgroups_clear: bool,
    pub damon_damos_clear: bool,
    pub idempotent_clean: bool,
    pub production_activation_authorized: bool,
    pub lineage_reexecution_authorized: bool,
    pub payload_sha256: String,
}

impl CapacityRecoveryReport {
    fn seal(mut self) -> Result<Self> {
        self.payload_sha256.clear();
        self.payload_sha256 = hash_json(&self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<()> {
        let mut candidate = self.clone();
        let frozen = candidate.payload_sha256.clone();
        candidate.payload_sha256.clear();
        if self.schema_version != CAPACITY_RECOVERY_REPORT_SCHEMA_VERSION
            || frozen != hash_json(&candidate)?
            || self.production_activation_authorized
            || self.lineage_reexecution_authorized
            || !matches!(
                self.classification,
                RecoveryClassification::Pass | RecoveryClassification::NoMutationAlreadyClean
            )
            || !self.idempotent_clean
        {
            bail!("capacity recovery evidence contract mismatch");
        }
        Ok(())
    }
}

struct LegacyRecoveryIdentity {
    experiment_id: String,
    output_root: PathBuf,
    preparing_uid: u32,
    preparing_gid: u32,
    runs: Vec<(usize, Vec<usize>)>,
}

fn legacy_capacity_identity(path: &Path) -> Result<LegacyRecoveryIdentity> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    let experiment = value
        .pointer("/payload/experiment_id")
        .and_then(|value| value.as_str())
        .context("legacy capacity experiment identity absent")?
        .to_owned();
    let output = value
        .pointer("/payload/output_root")
        .and_then(|value| value.as_str())
        .map(PathBuf::from)
        .context("legacy capacity output root absent")?;
    let uid = value
        .pointer("/payload/composition_payload/preparing_uid")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .context("legacy preparing UID absent")?;
    let gid = value
        .pointer("/payload/composition_payload/preparing_gid")
        .and_then(|value| value.as_u64())
        .and_then(|value| u32::try_from(value).ok())
        .context("legacy preparing GID absent")?;
    let runs = value
        .pointer("/payload/composition_payload/run_plan")
        .and_then(|value| value.as_array())
        .context("legacy capacity run plan absent")?
        .iter()
        .map(|run| {
            let order = run
                .get("order_index")
                .and_then(|value| value.as_u64())
                .and_then(|value| usize::try_from(value).ok())
                .context("legacy run order absent")?;
            let levels = run
                .get("levels")
                .and_then(|value| value.as_array())
                .context("legacy run levels absent")?
                .iter()
                .map(|level| {
                    level
                        .get("level_index")
                        .and_then(|value| value.as_u64())
                        .and_then(|value| usize::try_from(value).ok())
                        .context("legacy level index absent")
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((order, levels))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(LegacyRecoveryIdentity {
        experiment_id: experiment,
        output_root: output,
        preparing_uid: uid,
        preparing_gid: gid,
        runs,
    })
}

fn is_mountpoint(path: &Path) -> Result<bool> {
    let canonical = path.canonicalize()?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    Ok(mounts.lines().any(|line| {
        line.split_whitespace()
            .nth(4)
            .is_some_and(|mount| Path::new(mount) == canonical)
    }))
}

fn metadata_snapshot(path: &Path, kind: RecoveryPathKind) -> Result<RecoveryPathMetadata> {
    let metadata = fs::symlink_metadata(path)?;
    let file_type = if metadata.file_type().is_symlink() {
        "symlink"
    } else if metadata.file_type().is_socket() {
        "socket"
    } else if metadata.is_dir() {
        "directory"
    } else if metadata.is_file() {
        "regular"
    } else {
        "special"
    };
    Ok(RecoveryPathMetadata {
        path: path.to_path_buf(),
        kind,
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        link_count: metadata.nlink(),
        file_type: file_type.into(),
        mountpoint: is_mountpoint(path).unwrap_or(false),
    })
}

fn exact_parent(path: &Path, root: &Path) -> bool {
    path.parent() == Some(root) && root.join(path.file_name().unwrap_or_default()) == path
}

fn allowed_transaction_child(name: &str) -> bool {
    matches!(
        name,
        TARGET_DESCRIPTOR_FILE
            | TARGET_PROGRESS_FILE
            | TARGET_CONSUMED_FILE
            | TARGET_COMMAND_START_FILE
            | TARGET_COMMAND_REFAULT_FILE
            | TARGET_COMMAND_STOP_FILE
    )
}

fn validate_candidate(
    path: &Path,
    kind: RecoveryPathKind,
    output: &RecoveryPathMetadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<RecoveryCandidateEvidence> {
    let metadata = metadata_snapshot(path, kind)?;
    let mut children = Vec::new();
    let mut failures = Vec::new();
    if !exact_parent(path, &output.path)
        || metadata.device != output.device
        || metadata.mountpoint
        || metadata.uid != expected_uid
        || metadata.gid != expected_gid
    {
        failures.push("parent/device/mount/ownership mismatch".to_owned());
    }
    match kind {
        RecoveryPathKind::PressureSocket => {
            if metadata.file_type != "socket" || metadata.link_count != 1 || metadata.mode != 0o600
            {
                failures.push("pressure socket type/link/mode mismatch".to_owned());
            }
        }
        RecoveryPathKind::TargetTransactionDirectory => {
            if metadata.file_type != "directory"
                || metadata.link_count != 2
                || metadata.mode != 0o700
            {
                failures.push("transaction directory type/link/mode mismatch".to_owned());
            } else {
                for entry in fs::read_dir(path)? {
                    let entry = entry?;
                    let child_path = entry.path();
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let child =
                        metadata_snapshot(&child_path, RecoveryPathKind::PreservedEvidence)?;
                    if !allowed_transaction_child(&name)
                        || child.file_type != "regular"
                        || child.link_count != 1
                        || child.mode != 0o600
                        || child.uid != expected_uid
                        || child.gid != expected_gid
                        || child.device != output.device
                        || child.mountpoint
                        || child_path.parent() != Some(path)
                    {
                        failures.push(format!("unsafe transaction child: {name}"));
                    }
                    children.push(child);
                }
                children.sort_by(|a, b| a.path.cmp(&b.path));
            }
        }
        _ => failures.push("invalid recovery candidate kind".to_owned()),
    }
    Ok(RecoveryCandidateEvidence {
        metadata,
        expected_uid,
        expected_gid,
        children,
        valid: failures.is_empty(),
        failure_reason: (!failures.is_empty()).then(|| failures.join("; ")),
    })
}

fn preserved_evidence_name(name: &str, runs: &[(usize, Vec<usize>)]) -> bool {
    matches!(
        name,
        "capacity-composition.report.json"
            | "capacity-benchmark.report.json"
            | "capacity-evaluation.json"
            | "capacity-composition.sqlite"
            | "capacity-composition.sqlite-shm"
            | "capacity-composition.sqlite-wal"
    ) || runs.iter().any(|(run, levels)| {
        levels
            .iter()
            .any(|level| name == format!("run-{run}-level-{level}"))
    })
}

fn build_recovery_plan(
    output: &Path,
    preparing_uid: u32,
    preparing_gid: u32,
    runs: &[(usize, Vec<usize>)],
) -> Result<RecoveryPlan> {
    if output != Path::new(LINEAGE1_OUTPUT_ROOT)
        || output.canonicalize()? != Path::new(LINEAGE1_OUTPUT_ROOT)
    {
        bail!("legacy recovery output root is not exactly the frozen Lineage 1 root");
    }
    let root = metadata_snapshot(output, RecoveryPathKind::PreservedEvidence)?;
    if root.file_type != "directory"
        || root.mode != 0o700
        || root.uid != preparing_uid
        || root.gid != preparing_gid
        || root.mountpoint
    {
        bail!("legacy recovery output root metadata mismatch");
    }
    let socket_candidates = runs
        .iter()
        .map(|(run, _)| output.join(format!("pressure-{run}.sock")))
        .collect::<Vec<_>>();
    let transaction_candidates = runs
        .iter()
        .flat_map(|(run, levels)| {
            levels
                .iter()
                .map(move |level| output.join(format!("target-r{run}-l{level}")))
        })
        .collect::<Vec<_>>();
    let socket_set = socket_candidates.iter().cloned().collect::<BTreeSet<_>>();
    let transaction_set = transaction_candidates
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_uid = nix::unistd::geteuid().as_raw();
    let expected_gid = nix::unistd::getegid().as_raw();
    let mut existing_candidates = Vec::new();
    let mut preserved_evidence = Vec::new();
    let mut unexpected_entries = Vec::new();
    for entry in fs::read_dir(output)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if socket_set.contains(&path) {
            existing_candidates.push(validate_candidate(
                &path,
                RecoveryPathKind::PressureSocket,
                &root,
                expected_uid,
                expected_gid,
            )?);
        } else if transaction_set.contains(&path) {
            existing_candidates.push(validate_candidate(
                &path,
                RecoveryPathKind::TargetTransactionDirectory,
                &root,
                expected_uid,
                expected_gid,
            )?);
        } else if preserved_evidence_name(&name, runs) {
            preserved_evidence.push(path);
        } else {
            unexpected_entries.push(path);
        }
    }
    existing_candidates.sort_by(|a, b| a.metadata.path.cmp(&b.metadata.path));
    preserved_evidence.sort();
    unexpected_entries.sort();
    Ok(RecoveryPlan {
        output_root: root,
        socket_candidates,
        transaction_candidates,
        existing_candidates,
        preserved_evidence,
        unexpected_entries,
    })
}

pub fn capacity_benchmark_recovery_preflight(
    manifest_path: &Path,
) -> Result<CapacityRecoveryPreflight> {
    let identity = legacy_capacity_identity(manifest_path)?;
    let archive = Path::new(LINEAGE1_ARCHIVE);
    let archive_verified = hash_file(&archive.join("manifest.json"))? == hash_file(manifest_path)?
        && verify_all_sums(archive).is_ok()
        && fs::read_to_string(archive.join("STATUS"))?.contains("classification=EXECUTION_ERROR");
    let consumed_lineage =
        fs::read_to_string(archive.join("STATUS"))?.contains("invocation_count=1");
    let exact_processes_absent =
        !super::capacity_composition::processes_contain(&identity.experiment_id)
            && !super::capacity_composition::processes_contain("pressure-worker");
    let plan = build_recovery_plan(
        &identity.output_root,
        identity.preparing_uid,
        identity.preparing_gid,
        &identity.runs,
    )?;
    let exact_units_absent = SystemdDbusBackend::system()
        .and_then(|backend| backend.list_owned_benchmark_units())
        .map(|units| units.is_empty())
        .unwrap_or(false);
    let exact_cgroups_clear = fs::read_dir("/sys/fs/cgroup")
        .map(|entries| {
            !entries.flatten().any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("nemor-benchmark-")
            })
        })
        .unwrap_or(false);
    let damon = damon::inspect_linux(Path::new("/"), None);
    let damos = damos::observe_capability(&damon);
    let damon_damos_clear = !damon.active_external_session && !damos.external_session_conflict;
    let root = nix::unistd::geteuid().is_root();
    let identity_authorized = root
        && std::env::var("SUDO_UID")
            .ok()
            .and_then(|value| value.parse().ok())
            == Some(identity.preparing_uid)
        && std::env::var("SUDO_GID")
            .ok()
            .and_then(|value| value.parse().ok())
            == Some(identity.preparing_gid);
    let exact_paths_verified = plan.existing_candidates.iter().all(|item| item.valid)
        && plan.unexpected_entries.is_empty();
    let ready = archive_verified
        && consumed_lineage
        && exact_processes_absent
        && exact_units_absent
        && exact_cgroups_clear
        && damon_damos_clear
        && exact_paths_verified
        && identity_authorized;
    Ok(CapacityRecoveryPreflight {
        schema_version: CAPACITY_RECOVERY_PREFLIGHT_SCHEMA_VERSION,
        experiment_id: identity.experiment_id,
        manifest_sha256: hash_file(manifest_path)?,
        archive_verified,
        consumed_lineage,
        exact_processes_absent,
        exact_units_absent,
        exact_cgroups_clear,
        damon_damos_clear,
        plan,
        exact_paths_verified,
        current_identity_authorized: identity_authorized,
        recovery_ready: ready,
        preflight_mutated: false,
    })
}

pub fn recover_capacity_benchmark(
    manifest_path: &Path,
    idempotence_check: bool,
) -> Result<CapacityRecoveryReport> {
    let preflight = capacity_benchmark_recovery_preflight(manifest_path)?;
    if !preflight.recovery_ready {
        bail!("capacity recovery exact-owned preflight is not ready");
    }
    if idempotence_check && !preflight.plan.existing_candidates.is_empty() {
        bail!("idempotence check refuses pending mutation");
    }
    let preflight_sha256 = hash_json(&preflight)?;
    let before = preflight.plan.clone();
    let mut removed_sockets = Vec::new();
    let mut removed_transactions = Vec::new();
    let mut actions = Vec::new();
    let mut primary_error = None;
    let mut secondary_errors = Vec::new();
    if !idempotence_check {
        for candidate in &preflight.plan.existing_candidates {
            let revalidated = validate_candidate(
                &candidate.metadata.path,
                candidate.metadata.kind,
                &preflight.plan.output_root,
                candidate.expected_uid,
                candidate.expected_gid,
            );
            let result = match revalidated {
                Ok(current) if current == *candidate => match candidate.metadata.kind {
                    RecoveryPathKind::PressureSocket => fs::remove_file(&candidate.metadata.path)
                        .map(|_| {
                            removed_sockets.push(candidate.metadata.path.clone());
                        }),
                    RecoveryPathKind::TargetTransactionDirectory => (|| {
                        for child in &candidate.children {
                            fs::remove_file(&child.path)?;
                        }
                        fs::remove_dir(&candidate.metadata.path)?;
                        removed_transactions.push(candidate.metadata.path.clone());
                        Ok(())
                    })(),
                    _ => unreachable!("preflight admits only exact recovery candidates"),
                },
                Ok(_) => Err(std::io::Error::other(
                    "candidate metadata changed after preflight",
                )),
                Err(error) => Err(std::io::Error::other(format!("{error:#}"))),
            };
            let error = result.err().map(|error| error.to_string());
            if let Some(error) = &error {
                if primary_error.is_none() {
                    primary_error = Some(error.clone());
                } else {
                    secondary_errors.push(error.clone());
                }
            }
            actions.push(RecoveryPathAction {
                path: candidate.metadata.path.clone(),
                kind: candidate.metadata.kind,
                removed: error.is_none(),
                error,
            });
        }
    }
    let after_preflight = capacity_benchmark_recovery_preflight(manifest_path)?;
    let clean = after_preflight.plan.existing_candidates.is_empty()
        && after_preflight.exact_processes_absent
        && after_preflight.exact_units_absent
        && after_preflight.exact_cgroups_clear
        && after_preflight.damon_damos_clear;
    let classification = if primary_error.is_some() {
        RecoveryClassification::PartialFailure
    } else if !clean {
        RecoveryClassification::Invalid
    } else if idempotence_check {
        RecoveryClassification::NoMutationAlreadyClean
    } else {
        RecoveryClassification::Pass
    };
    let report = CapacityRecoveryReport {
        schema_version: CAPACITY_RECOVERY_REPORT_SCHEMA_VERSION,
        classification,
        experiment_id: preflight.experiment_id,
        manifest_sha256: preflight.manifest_sha256,
        preflight_sha256,
        before,
        actions,
        removed_sockets,
        removed_transactions,
        preserved_evidence: after_preflight.plan.preserved_evidence.clone(),
        primary_error,
        secondary_errors,
        after: after_preflight.plan,
        exact_processes_absent: after_preflight.exact_processes_absent,
        exact_units_absent: after_preflight.exact_units_absent,
        exact_cgroups_clear: after_preflight.exact_cgroups_clear,
        damon_damos_clear: after_preflight.damon_damos_clear,
        idempotent_clean: clean,
        production_activation_authorized: false,
        lineage_reexecution_authorized: false,
        payload_sha256: String::new(),
    }
    .seal()?;
    if matches!(
        report.classification,
        RecoveryClassification::Pass | RecoveryClassification::NoMutationAlreadyClean
    ) {
        report.verify()?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_is_capacity_only_and_never_production_or_gaming() {
        let contract = CapacityBenchmarkContract::v2();
        assert_eq!(contract.version, 2);
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

    #[test]
    fn conservative_percent_rounds_down_for_positive_and_negative_values() {
        assert_eq!(percent_floor(1, 3), Some(33));
        assert_eq!(percent_floor(-1, 3), Some(-34));
    }

    #[test]
    fn possible_percent_rounds_up_for_positive_and_negative_values() {
        assert_eq!(percent_ceil(1, 3), Some(34));
        assert_eq!(percent_ceil(-1, 3), Some(-33));
    }

    #[test]
    fn percent_arithmetic_rejects_zero_denominator() {
        assert_eq!(percent_floor(1, 0), None);
        assert_eq!(percent_ceil(1, 0), None);
    }

    #[test]
    fn capacity_scope_runtime_is_sufficient_and_finite() {
        let runtime = CAPACITY_SCOPE_RUNTIME_MAX_USEC;
        let run_timeout = CAPACITY_RUN_TIMEOUT_MS;
        assert!(runtime / 1_000 >= run_timeout);
        assert!(run_timeout * 6 <= CapacitySearchPolicy::v1().total_timeout_ms);
        assert_eq!(CapacitySearchPolicy::v1().total_timeout_ms, 45 * 60 * 1000);
    }

    fn external_status() -> String {
        [
            "status=PASS",
            "validation_id=capacity-external-target-1",
            "source_commit=0123456789abcdef0123456789abcdef01234567",
            "manifest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "manifest_payload_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "execution_payload_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "invocation_count=1",
            "validator_report_lifecycle=PASS",
            "validator_report_raw_sha256=dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "validator_report_canonical_sha256=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "direct_shadow_gates=4/4",
            "required_damos_gates=48/48",
            "hot_warm_service=PASS",
            "cold_controlled_refault=PASS",
            "host_oom=0",
            "cleanup=PASS",
            "recovery=PASS",
            "idempotent_recovery=PASS",
            "structural_restore=PASS",
            "legacy_global_report_absent=true",
            "validator_state_absent=true",
            "final_nr_kdamonds=0",
            "capacity=NotEvaluated",
            "effectiveness=NotEvaluated",
            "production_activation=false",
        ]
        .join("\n")
    }

    fn composition_status() -> String {
        [
            "status=PASS",
            "experiment_id=capacity-composition-1",
            "source_commit=0123456789abcdef0123456789abcdef01234567",
            "manifest_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "manifest_payload_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "execution_payload_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "external_target_lineage=capacity-external-target-1",
            "invocation_count=1",
            "runs=6/6",
            "levels=18/18",
            "sustainable_levels=18/18",
            "baseline_runs=3",
            "capacity_runs=3",
            "transaction_scoped_capacity_reports=9",
            "report_lifecycle=PASS",
            "legacy_global_report_absent=true",
            "validator_state_absent=true",
            "host_oom=0",
            "cgroup_oom_kill=0",
            "watchdog=false",
            "target_cleanup=PASS",
            "scope_cleanup=PASS",
            "structural_restore=PASS",
            "final_nr_kdamonds=0",
            "capacity=NotEvaluated",
            "effectiveness=NotEvaluated",
            "production_activation=false",
        ]
        .join("\n")
    }

    #[test]
    fn fresh_prerequisite_status_contracts_are_typed_and_exact() {
        let external =
            parse_prerequisite_status(&external_status(), CapacityPrerequisiteKind::ExternalTarget)
                .unwrap();
        assert_eq!(external.identity, "capacity-external-target-1");
        assert!(external.cleanup_passed);
        let composition =
            parse_prerequisite_status(&composition_status(), CapacityPrerequisiteKind::Composition)
                .unwrap();
        assert_eq!(composition.identity, "capacity-composition-1");
        assert_eq!(
            composition.external_target_identity.as_deref(),
            Some("capacity-external-target-1")
        );
    }

    #[test]
    fn prerequisite_status_rejects_substrings_duplicates_and_legacy_aliases() {
        let status = external_status();
        assert!(parse_prerequisite_status(
            &status.replace(
                "production_activation=false",
                "xproduction_activation=false"
            ),
            CapacityPrerequisiteKind::ExternalTarget,
        )
        .is_err());
        assert!(parse_prerequisite_status(
            &format!("{status}\nstatus=PASS"),
            CapacityPrerequisiteKind::ExternalTarget,
        )
        .is_err());
        assert!(parse_prerequisite_status(
            &status.replace("status=PASS", "classification=PASS"),
            CapacityPrerequisiteKind::ExternalTarget,
        )
        .is_err());
        assert!(parse_prerequisite_status(
            &status.replace("cleanup=PASS", "cleanup=PASS extra"),
            CapacityPrerequisiteKind::ExternalTarget,
        )
        .is_err());
    }

    #[test]
    fn capacity_path_contract_matches_exact_components_and_lineage() {
        assert!(capacity_path_plan_supported(
            Path::new("/tmp/nemor-capacity-benchmark-3-prepared"),
            Path::new("/tmp/nemor-capacity-benchmark-3-output"),
        ));
        for (prepared, output) in [
            (
                "/tmp/nemor-capacity-benchmark-3-prepared",
                "/tmp/nemor-capacity-benchmark-4-output",
            ),
            (
                "/tmp/nemor-capacity-benchmark-03-prepared",
                "/tmp/nemor-capacity-benchmark-03-output",
            ),
            (
                "/tmp/nemor-capacity-benchmark--prepared",
                "/tmp/nemor-capacity-benchmark--output",
            ),
            (
                "/var/tmp/nemor-capacity-benchmark-3-prepared",
                "/var/tmp/nemor-capacity-benchmark-3-output",
            ),
            (
                "/tmp/nemor-capacity-benchmark-/3-prepared",
                "/tmp/nemor-capacity-benchmark-/3-output",
            ),
            (
                "/tmp/foreign-nemor-capacity-benchmark-3-prepared",
                "/tmp/foreign-nemor-capacity-benchmark-3-output",
            ),
        ] {
            assert!(!capacity_path_plan_supported(
                Path::new(prepared),
                Path::new(output)
            ));
        }
    }

    #[test]
    fn readiness_is_the_conjunction_of_every_reported_user_gate() {
        let ready = CapacityReadinessGates {
            manifest_verified: true,
            source_and_binaries_verified: true,
            material_environment_match: true,
            external_target_prerequisite_verified: true,
            composition_prerequisite_verified: true,
            prerequisite_lineage_link_verified: true,
            exact_profile_supported: true,
            search_policy_supported: true,
            run_plan_supported: true,
            level_ladder_supported: true,
            safe_search_ceiling_supported: true,
            headroom_safe: true,
            memory_max_safe: true,
            ownership_plan_supported: true,
            output_fresh: true,
            stale_resources_clear: true,
            report_lifecycle_version_supported: true,
            legacy_global_report_absent: true,
            validator_state_absent: true,
        };
        assert!(ready.user_ready());
        macro_rules! reject_false_gate {
            ($($field:ident),+ $(,)?) => {
                $(
                    let mut candidate = ready;
                    candidate.$field = false;
                    assert!(!candidate.user_ready(), stringify!($field));
                )+
            };
        }
        reject_false_gate!(
            manifest_verified,
            source_and_binaries_verified,
            material_environment_match,
            external_target_prerequisite_verified,
            composition_prerequisite_verified,
            prerequisite_lineage_link_verified,
            exact_profile_supported,
            search_policy_supported,
            run_plan_supported,
            level_ladder_supported,
            safe_search_ceiling_supported,
            headroom_safe,
            memory_max_safe,
            ownership_plan_supported,
            output_fresh,
            stale_resources_clear,
            report_lifecycle_version_supported,
            legacy_global_report_absent,
            validator_state_absent,
        );
    }

    #[test]
    fn paired_median_is_used_for_signed_deltas() {
        assert_eq!(median_i64(vec![-10, 30, 0]), Some(0));
        assert_eq!(median_i64(vec![30, 10, 20]), Some(20));
    }

    #[test]
    fn execution_evidence_seal_detects_tamper_and_preserves_nonclaims() {
        let evidence = CapacityBenchmarkExecutionEvidence {
            schema_version: CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION,
            state: CapacityBenchmarkState::Invalid,
            experiment_id: "experiment".into(),
            source_commit: BUILD_GIT_HEAD.into(),
            invocation_count: 1,
            composition_execution: CapacityCompositionExecutionEvidence {
                schema_version: crate::capacity_composition::COMPOSITION_EXECUTION_SCHEMA_VERSION,
                experiment_id: "experiment".into(),
                source_commit: BUILD_GIT_HEAD.into(),
                state: CompositionExperimentState::InvalidRun,
                reason: "injected primary failure".into(),
                runs: Vec::new(),
                planned_runs: 6,
                completed_runs: 0,
                planned_levels: 60,
                completed_levels: 0,
                invocation_count: 1,
                search_complete: false,
                capacity_evaluation: EvaluationState::NotEvaluated,
                effectiveness_evaluation: EvaluationState::NotEvaluated,
                production_activation_authorized: false,
                cleanup_passed: false,
                structural_restore_passed: false,
                payload_sha256: String::new(),
            },
            boundaries: Vec::new(),
            evaluation: CapacityEvaluation {
                version: CAPACITY_EVALUATION_VERSION,
                state: CapacityEvaluationState::Invalid,
                pairs: Vec::new(),
                median_baseline_demonstrated_bytes: None,
                median_capacity_demonstrated_bytes: None,
                median_paired_demonstrated_delta_bytes: None,
                demonstrated_capacity_gain_percent: None,
                conservative_gain_lower_bound_percent: None,
                possible_gain_upper_bound_percent: None,
                target_percent: Some(30),
                target_source: "master".into(),
                target_status: CapacityTargetStatus::Indeterminate,
                statistical_limitation: "three pairs".into(),
            },
            cleanup_passed: false,
            structural_restore_passed: false,
            effectiveness_evaluation: EvaluationState::NotEvaluated,
            production_activation_authorized: false,
            primary_error: Some("primary".into()),
            secondary_errors: vec!["secondary".into()],
            payload_sha256: String::new(),
        }
        .seal()
        .unwrap();
        evidence.verify().unwrap();
        let mut tampered = evidence;
        tampered.primary_error = Some("changed".into());
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn successful_evidence_requires_cleanup_and_restore() {
        let mut evidence = CapacityBenchmarkExecutionEvidence {
            schema_version: CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION,
            state: CapacityBenchmarkState::Censored,
            experiment_id: "experiment".into(),
            source_commit: BUILD_GIT_HEAD.into(),
            invocation_count: 1,
            composition_execution: CapacityCompositionExecutionEvidence {
                schema_version: crate::capacity_composition::COMPOSITION_EXECUTION_SCHEMA_VERSION,
                experiment_id: "experiment".into(),
                source_commit: BUILD_GIT_HEAD.into(),
                state: CompositionExperimentState::CompletedCompositionFrameworkValidation,
                reason: "done".into(),
                runs: Vec::new(),
                planned_runs: 6,
                completed_runs: 6,
                planned_levels: 60,
                completed_levels: 60,
                invocation_count: 1,
                search_complete: false,
                capacity_evaluation: EvaluationState::NotEvaluated,
                effectiveness_evaluation: EvaluationState::NotEvaluated,
                production_activation_authorized: false,
                cleanup_passed: true,
                structural_restore_passed: true,
                payload_sha256: String::new(),
            },
            boundaries: Vec::new(),
            evaluation: CapacityEvaluation {
                version: CAPACITY_EVALUATION_VERSION,
                state: CapacityEvaluationState::Censored,
                pairs: Vec::new(),
                median_baseline_demonstrated_bytes: None,
                median_capacity_demonstrated_bytes: None,
                median_paired_demonstrated_delta_bytes: None,
                demonstrated_capacity_gain_percent: None,
                conservative_gain_lower_bound_percent: None,
                possible_gain_upper_bound_percent: None,
                target_percent: Some(30),
                target_source: "master".into(),
                target_status: CapacityTargetStatus::Indeterminate,
                statistical_limitation: "three pairs".into(),
            },
            cleanup_passed: false,
            structural_restore_passed: true,
            effectiveness_evaluation: EvaluationState::NotEvaluated,
            production_activation_authorized: false,
            primary_error: None,
            secondary_errors: Vec::new(),
            payload_sha256: String::new(),
        }
        .seal()
        .unwrap();
        assert!(evidence.verify().is_err());
        evidence.cleanup_passed = true;
        evidence = evidence.seal().unwrap();
        evidence.verify().unwrap();
    }

    #[test]
    fn recovery_evidence_is_idempotent_non_production_and_non_reexecution() {
        let root = RecoveryPathMetadata {
            path: PathBuf::from("/tmp/output"),
            kind: RecoveryPathKind::PreservedEvidence,
            device: 1,
            inode: 2,
            uid: 1000,
            gid: 1000,
            mode: 0o700,
            link_count: 2,
            file_type: "directory".into(),
            mountpoint: false,
        };
        let plan = RecoveryPlan {
            output_root: root,
            socket_candidates: Vec::new(),
            transaction_candidates: Vec::new(),
            existing_candidates: Vec::new(),
            preserved_evidence: Vec::new(),
            unexpected_entries: Vec::new(),
        };
        let report = CapacityRecoveryReport {
            schema_version: CAPACITY_RECOVERY_REPORT_SCHEMA_VERSION,
            classification: RecoveryClassification::Pass,
            experiment_id: "consumed".into(),
            manifest_sha256: "manifest".into(),
            preflight_sha256: "preflight".into(),
            before: plan.clone(),
            actions: Vec::new(),
            removed_sockets: vec![PathBuf::from("/tmp/output/pressure-0.sock")],
            removed_transactions: vec![PathBuf::from("/tmp/output/target-r0-l2")],
            preserved_evidence: Vec::new(),
            primary_error: None,
            secondary_errors: Vec::new(),
            after: plan,
            exact_processes_absent: true,
            exact_units_absent: true,
            exact_cgroups_clear: true,
            damon_damos_clear: true,
            idempotent_clean: true,
            production_activation_authorized: false,
            lineage_reexecution_authorized: false,
            payload_sha256: String::new(),
        }
        .seal()
        .unwrap();
        report.verify().unwrap();
        let mut tampered = report;
        tampered.lineage_reexecution_authorized = true;
        assert!(tampered.verify().is_err());
    }

    fn fixture_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn transaction_directory_uses_normal_link_count_two() {
        let root = fixture_root();
        let transaction = root.path().join("target-r0-l0");
        fs::create_dir(&transaction).unwrap();
        fs::set_permissions(&transaction, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(fs::symlink_metadata(&transaction).unwrap().nlink(), 2);
        let output = metadata_snapshot(root.path(), RecoveryPathKind::PreservedEvidence).unwrap();
        let item = validate_candidate(
            &transaction,
            RecoveryPathKind::TargetTransactionDirectory,
            &output,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
        .unwrap();
        assert!(item.valid, "{:?}", item.failure_reason);
    }

    #[test]
    fn nested_or_unknown_transaction_content_is_rejected() {
        let root = fixture_root();
        let transaction = root.path().join("target-r0-l0");
        fs::create_dir(&transaction).unwrap();
        fs::set_permissions(&transaction, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(transaction.join("nested")).unwrap();
        let output = metadata_snapshot(root.path(), RecoveryPathKind::PreservedEvidence).unwrap();
        let item = validate_candidate(
            &transaction,
            RecoveryPathKind::TargetTransactionDirectory,
            &output,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
        .unwrap();
        assert!(!item.valid);
    }

    #[test]
    fn allowlisted_private_child_is_valid_and_hardlink_is_rejected() {
        let root = fixture_root();
        let transaction = root.path().join("target-r0-l0");
        fs::create_dir(&transaction).unwrap();
        fs::set_permissions(&transaction, fs::Permissions::from_mode(0o700)).unwrap();
        let child = transaction.join(TARGET_PROGRESS_FILE);
        fs::write(&child, b"{}").unwrap();
        fs::set_permissions(&child, fs::Permissions::from_mode(0o600)).unwrap();
        let output = metadata_snapshot(root.path(), RecoveryPathKind::PreservedEvidence).unwrap();
        let valid = validate_candidate(
            &transaction,
            RecoveryPathKind::TargetTransactionDirectory,
            &output,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
        .unwrap();
        assert!(valid.valid);
        fs::hard_link(&child, root.path().join("alias")).unwrap();
        let invalid = validate_candidate(
            &transaction,
            RecoveryPathKind::TargetTransactionDirectory,
            &output,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
        .unwrap();
        assert!(!invalid.valid);
    }

    #[test]
    fn exact_socket_requires_socket_type_mode_and_single_link() {
        use std::os::unix::net::UnixListener;
        let root = fixture_root();
        let path = root.path().join("pressure-0.sock");
        let _listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let output = metadata_snapshot(root.path(), RecoveryPathKind::PreservedEvidence).unwrap();
        let item = validate_candidate(
            &path,
            RecoveryPathKind::PressureSocket,
            &output,
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
        .unwrap();
        assert!(item.valid);
    }

    #[test]
    fn output_prefix_collision_and_symlink_are_not_exact() {
        let root = fixture_root();
        assert!(!exact_parent(
            &PathBuf::from(format!("{}-foreign/pressure-0.sock", root.path().display())),
            root.path()
        ));
        let link = root.path().with_extension("link");
        std::os::unix::fs::symlink(root.path(), &link).unwrap();
        assert_eq!(
            metadata_snapshot(&link, RecoveryPathKind::PreservedEvidence)
                .unwrap()
                .file_type,
            "symlink"
        );
    }

    #[test]
    fn preserved_evidence_does_not_match_arbitrary_recovery_prefixes() {
        let runs = vec![(0, vec![0, 1])];
        assert!(preserved_evidence_name("run-0-level-1", &runs));
        assert!(!preserved_evidence_name("pressure-999.sock", &runs));
        assert!(!preserved_evidence_name("target-r99-l99", &runs));
    }

    #[test]
    fn recovery_v1_is_not_accepted_as_v2() {
        let value = serde_json::json!({
            "schema_version": 1,
            "classification": "pass"
        });
        assert!(serde_json::from_value::<CapacityRecoveryReport>(value).is_err());
        assert_eq!(CAPACITY_BENCHMARK_CONTRACT_VERSION, 2);
        assert_eq!(CAPACITY_BENCHMARK_MANIFEST_SCHEMA_VERSION, 4);
        assert_eq!(CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION, 4);
        assert_eq!(CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION, 3);
        assert_eq!(CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION, 1);
        assert_eq!(CAPACITY_PATH_CONTRACT_VERSION, 1);
        assert_eq!(CAPACITY_EVALUATION_VERSION, 2);
        assert_eq!(
            crate::capacity_external_target::CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION,
            1
        );
    }
}
