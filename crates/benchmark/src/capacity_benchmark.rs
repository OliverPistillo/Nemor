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
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CAPACITY_BENCHMARK_CONTRACT_VERSION: u32 = 1;
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
    pub kind: CapacityPrerequisiteKind,
    pub status_contract_version: u32,
    pub archive: PathBuf,
    pub manifest_sha256: String,
    pub report_sha256: String,
    pub sha256sums_sha256: String,
    pub status_sha256: String,
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
    validator_report_raw_sha256: Option<String>,
    validator_report_canonical_sha256: Option<String>,
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
    _unknown_metadata: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityDirectoryIdentity {
    pub canonical_path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
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
    pub manifest_path: PathBuf,
    pub output_root: PathBuf,
    pub prepared_root_identity: CapacityDirectoryIdentity,
    pub output_root_identity: CapacityDirectoryIdentity,
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
            || self.payload.external_target_prerequisite.kind
                != CapacityPrerequisiteKind::ExternalTarget
            || self.payload.composition_prerequisite.kind != CapacityPrerequisiteKind::Composition
            || self
                .payload
                .external_target_prerequisite
                .status_contract_version
                != CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION
            || self
                .payload
                .composition_prerequisite
                .status_contract_version
                != CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION
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
            || self.payload.target_percent != FAVORABLE_CAPACITY_TARGET_PERCENT
            || self.payload.target_status != CapacityTargetStatus::Indeterminate
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
    pub prerequisite_status_contract_supported: bool,
    pub prerequisite_lineage_link_verified: bool,
    pub exact_profile_supported: bool,
    pub search_policy_supported: bool,
    pub run_plan_supported: bool,
    pub level_ladder_supported: bool,
    pub safe_search_ceiling_supported: bool,
    pub headroom_safe: bool,
    pub memory_max_safe: bool,
    pub path_contract_supported: bool,
    pub prepared_root_identity_verified: bool,
    pub output_root_identity_verified: bool,
    pub frozen_child_paths_verified: bool,
    pub ownership_plan_supported: bool,
    pub output_fresh: bool,
    pub stale_resources_clear: bool,
    pub report_lifecycle_version_supported: bool,
    pub legacy_global_report_absent: bool,
    pub validator_state_absent: bool,
    pub all_non_authorization_gates_pass: bool,
    pub user_preflight_passed: bool,
    pub current_identity_authorized: bool,
    pub bounded_capacity_benchmark_entry_ready: bool,
    pub execution_ready: bool,
    pub preflight_mutated: bool,
}

impl CapacityBenchmarkPreflight {
    pub fn all_non_authorization_gates_pass(&self) -> bool {
        [
            self.manifest_verified,
            self.source_and_binaries_verified,
            self.material_environment_match,
            self.external_target_prerequisite_verified,
            self.composition_prerequisite_verified,
            self.prerequisite_status_contract_supported,
            self.prerequisite_lineage_link_verified,
            self.exact_profile_supported,
            self.search_policy_supported,
            self.run_plan_supported,
            self.level_ladder_supported,
            self.safe_search_ceiling_supported,
            self.headroom_safe,
            self.memory_max_safe,
            self.path_contract_supported,
            self.prepared_root_identity_verified,
            self.output_root_identity_verified,
            self.frozen_child_paths_verified,
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

    pub fn verify_readiness_consistency(&self) -> Result<()> {
        let non_authorization = self.all_non_authorization_gates_pass();
        let ready = non_authorization && self.current_identity_authorized;
        if self.schema_version != CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION
            || self.prerequisite_status_contract_version
                != CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION
            || self.path_contract_version != CAPACITY_PATH_CONTRACT_VERSION
            || self.all_non_authorization_gates_pass != non_authorization
            || self.user_preflight_passed != non_authorization
            || self.bounded_capacity_benchmark_entry_ready != ready
            || self.execution_ready != ready
            || self.preflight_mutated
        {
            bail!("capacity benchmark preflight readiness is internally inconsistent");
        }
        Ok(())
    }
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
    let archive = archive.canonicalize()?;
    let manifest = archive.join("manifest.json");
    let report_path = archive.join(kind.report_name());
    let sums = archive.join("SHA256SUMS");
    let status = archive.join("STATUS");
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
        kind,
        status_contract_version: CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION,
        archive,
        manifest_sha256: hash_file(&manifest)?,
        report_sha256: hash_file(&report_path)?,
        sha256sums_sha256: hash_file(&sums)?,
        status_sha256: hash_file(&status)?,
        source_commit,
        identity,
    })
}

fn status_relevant_keys(kind: CapacityPrerequisiteKind) -> BTreeSet<&'static str> {
    let mut keys = match kind {
        CapacityPrerequisiteKind::ExternalTarget => BTreeSet::from([
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
    };
    keys.insert("status");
    keys.insert("classification");
    keys
}

type StatusEntries = BTreeMap<String, String>;
type UnknownStatusMetadata = Vec<(String, String)>;

fn parse_status_entries(
    status: &str,
    kind: CapacityPrerequisiteKind,
) -> Result<(StatusEntries, UnknownStatusMetadata)> {
    let mut entries = BTreeMap::new();
    let mut unknown = Vec::new();
    let relevant = status_relevant_keys(kind);
    let normalized = status.replace("\r\n", "\n");
    if normalized.contains('\r') {
        bail!("capacity prerequisite STATUS contains an unsupported line ending");
    }
    for raw_line in normalized.split('\n') {
        let line = raw_line.trim_matches(|character: char| character.is_ascii_whitespace());
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split('=');
        let key = fields
            .next()
            .expect("split always returns one field")
            .trim_matches(|character: char| character.is_ascii_whitespace());
        let value = fields
            .next()
            .context("malformed capacity prerequisite STATUS line")?
            .trim_matches(|character: char| character.is_ascii_whitespace());
        if fields.next().is_some()
            || key.is_empty()
            || value.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            bail!("malformed capacity prerequisite STATUS line");
        }
        if relevant.contains(key) {
            if entries.insert(key.to_owned(), value.to_owned()).is_some() {
                bail!("duplicate relevant capacity prerequisite STATUS key");
            }
        } else {
            unknown.push((key.to_owned(), value.to_owned()));
        }
    }
    if entries.is_empty() && unknown.is_empty() {
        bail!("capacity prerequisite STATUS is empty");
    }
    Ok((entries, unknown))
}

fn expect_status(entries: &StatusEntries, key: &str, expected: &str) -> Result<()> {
    if entries.get(key).map(String::as_str) != Some(expected) {
        bail!("capacity prerequisite STATUS {key} mismatch");
    }
    Ok(())
}

fn valid_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_prerequisite_status(
    status: &str,
    kind: CapacityPrerequisiteKind,
) -> Result<CapacityPrerequisiteStatus> {
    let (entries, unknown_metadata) = parse_status_entries(status, kind)?;
    let status_terminal = entries.get("status").map(String::as_str);
    let classification_terminal = entries.get("classification").map(String::as_str);
    if status_terminal.is_none() && classification_terminal.is_none() {
        bail!("capacity prerequisite STATUS terminal state is missing");
    }
    if status_terminal.is_some_and(|value| value != "PASS") {
        bail!("capacity prerequisite STATUS terminal status is not PASS");
    }
    let classification_allowed = match kind {
        CapacityPrerequisiteKind::ExternalTarget => {
            classification_terminal.is_none_or(|value| value == "PASS")
        }
        CapacityPrerequisiteKind::Composition => classification_terminal.is_none_or(|value| {
            matches!(value, "PASS" | "COMPLETED_COMPOSITION_FRAMEWORK_VALIDATION")
        }),
    };
    if !classification_allowed {
        bail!("capacity prerequisite STATUS terminal classification conflicts with PASS");
    }
    for key in [
        "manifest_sha256",
        "manifest_payload_sha256",
        "execution_payload_sha256",
    ] {
        if !entries
            .get(key)
            .is_some_and(|value| valid_lowercase_sha256(value))
        {
            bail!("capacity prerequisite STATUS {key} is not lowercase SHA-256");
        }
    }
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
                let value = entries.get(key).context("STATUS hash absent")?;
                if !valid_lowercase_sha256(value) {
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
        identity: entries
            .get(kind.identity_key())
            .context("STATUS identity absent")?
            .to_owned(),
        source_commit: entries
            .get("source_commit")
            .context("STATUS source commit absent")?
            .to_owned(),
        manifest_sha256: entries
            .get("manifest_sha256")
            .context("STATUS manifest SHA-256 absent")?
            .to_owned(),
        manifest_payload_sha256: entries
            .get("manifest_payload_sha256")
            .context("STATUS manifest payload SHA-256 absent")?
            .to_owned(),
        execution_payload_sha256: entries
            .get("execution_payload_sha256")
            .context("STATUS execution payload SHA-256 absent")?
            .to_owned(),
        validator_report_raw_sha256: entries.get("validator_report_raw_sha256").cloned(),
        validator_report_canonical_sha256: entries
            .get("validator_report_canonical_sha256")
            .cloned(),
        external_target_identity: match kind {
            CapacityPrerequisiteKind::ExternalTarget => None,
            CapacityPrerequisiteKind::Composition => Some(
                entries
                    .get("external_target_lineage")
                    .context("STATUS external-target lineage absent")?
                    .to_owned(),
            ),
        },
        invocation_count: entries
            .get("invocation_count")
            .context("STATUS invocation count absent")?
            .parse()?,
        cleanup_passed: match kind {
            CapacityPrerequisiteKind::ExternalTarget => entries["cleanup"] == "PASS",
            CapacityPrerequisiteKind::Composition => {
                entries["target_cleanup"] == "PASS" && entries["scope_cleanup"] == "PASS"
            }
        },
        structural_restore_passed: entries["structural_restore"] == "PASS",
        legacy_global_report_absent: entries["legacy_global_report_absent"] == "true",
        validator_state_absent: entries["validator_state_absent"] == "true",
        final_nr_kdamonds: entries
            .get("final_nr_kdamonds")
            .context("STATUS final nr_kdamonds absent")?
            .parse()?,
        capacity_evaluation: EvaluationState::NotEvaluated,
        effectiveness_evaluation: EvaluationState::NotEvaluated,
        production_activation_authorized: false,
        _unknown_metadata: unknown_metadata,
    })
}

fn verify_ledger_entries(archive: &Path) -> Result<BTreeSet<PathBuf>> {
    if archive.canonicalize()? != archive {
        bail!("capacity prerequisite archive root is not canonical");
    }
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
    Ok(seen)
}

fn verify_all_sums(archive: &Path, kind: CapacityPrerequisiteKind) -> Result<()> {
    let seen = verify_ledger_entries(archive)?;
    for required in ["manifest.json", "STATUS", kind.report_name()] {
        if !seen.contains(Path::new(required)) {
            bail!("capacity prerequisite SHA256SUMS omits required evidence");
        }
    }
    Ok(())
}

fn validator_lifecycle_common_supported(
    lifecycle: &crate::validator_report::ValidatorReportLifecycleEvidence,
) -> bool {
    lifecycle.version == 1
        && lifecycle.legacy_global_absent_before
        && lifecycle.legacy_global_absent_after
        && lifecycle.validator_state_absent
}

fn composition_run_is_complete(
    run: &crate::capacity_composition::CapacityCompositionRunEvidence,
) -> bool {
    use crate::validator_report::ValidatorReportLifecycleClassification;

    run.version == crate::capacity_composition::COMPOSITION_RUN_EVIDENCE_VERSION
        && run.state == CompositionExperimentState::CompletedCompositionFrameworkValidation
        && run.levels.len() == 3
        && run.pressure_scope_cleanup_passed
        && run.scope_cleanup.passed()
        && run.structural_restore_passed
        && run.levels.iter().all(|level| {
            let lifecycle = &level.target.validator_report_lifecycle;
            let lifecycle_supported = validator_lifecycle_common_supported(lifecycle)
                && match run.variant {
                    BenchmarkVariant::CachyosBaseline => {
                        lifecycle.classification
                            == ValidatorReportLifecycleClassification::BaselineNoReport
                            && lifecycle.report_path.is_none()
                            && lifecycle.raw_sha256.is_none()
                            && lifecycle.canonical_semantic_sha256.is_none()
                            && lifecycle.validator_exit_status.is_none()
                            && !lifecycle.explicit_path_mode
                            && !level.target.validator_invoked
                            && level.target.no_damon_damos_mutation
                    }
                    BenchmarkVariant::NemorCapacity => {
                        lifecycle.classification == ValidatorReportLifecycleClassification::Pass
                            && lifecycle.report_path.is_some()
                            && lifecycle.raw_sha256.is_some()
                            && lifecycle.canonical_semantic_sha256.is_some()
                            && lifecycle.validator_exit_status == Some(0)
                            && lifecycle.explicit_path_mode
                            && level.target.validator_invoked
                            && level
                                .target
                                .direct_shadow_gates
                                .into_iter()
                                .all(|gate| gate)
                            && level.target.required_damos_gates_passed
                            && level.target.applied_bytes > 0
                    }
                    _ => false,
                };
            level.version == crate::capacity_composition::COMPOSITION_LEVEL_EVIDENCE_VERSION
                && level.run_order == run.order_index
                && level.variant == run.variant
                && level.classification == CompositionLevelClassification::Sustainable
                && level.pressure_heartbeat
                && level.pressure_worker_alive
                && level.cgroup_membership
                && level.memory_max_verified
                && level.oom == 0
                && level.oom_kill == 0
                && !level.watchdog_triggered
                && level.target.version
                    == crate::capacity_composition::COMPOSITION_TARGET_EVIDENCE_VERSION
                && level.target.hot_progress
                && level.target.warm_progress
                && level.target.cold_inactive_before_action
                && level.target.fingerprints_valid
                && level.target.only_cold_reclaimed
                && level.target.cleanup_passed
                && level.cleanup_passed
                && level.structural_restore_passed
                && lifecycle_supported
        })
}

fn composition_report_matches_manifest(
    report: &CapacityCompositionExecutionEvidence,
    manifest: &PreparedCapacityCompositionManifest,
) -> bool {
    report.runs.len() == manifest.payload.run_plan.len()
        && report
            .runs
            .iter()
            .zip(&manifest.payload.run_plan)
            .all(|(run, planned)| {
                run.order_index == planned.order_index
                    && run.variant == planned.variant
                    && run.repetition_index == planned.repetition_index
                    && run.seed == planned.seed
                    && run.levels.len() == planned.levels.len()
                    && run
                        .levels
                        .iter()
                        .zip(&planned.levels)
                        .all(|(level, planned)| {
                            level.level_index == planned.level_index
                                && level.target_touched_bytes == planned.target_touched_bytes
                        })
            })
}

fn verify_archive(
    prerequisite: &CapacityPrerequisite,
    kind: CapacityPrerequisiteKind,
) -> Result<()> {
    if prerequisite.kind != kind
        || prerequisite.status_contract_version != CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION
    {
        bail!("capacity prerequisite kind or STATUS contract version mismatch");
    }
    let archive = prerequisite.archive.canonicalize()?;
    let report_name = kind.report_name();
    if archive != prerequisite.archive
        || hash_file(&archive.join("manifest.json"))? != prerequisite.manifest_sha256
        || hash_file(&archive.join(report_name))? != prerequisite.report_sha256
        || hash_file(&archive.join("SHA256SUMS"))? != prerequisite.sha256sums_sha256
        || hash_file(&archive.join("STATUS"))? != prerequisite.status_sha256
    {
        bail!("capacity prerequisite frozen identity mismatch");
    }
    verify_all_sums(&archive, kind)?;
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
            manifest.verify()?;
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
                || manifest.payload.validation_id != status.identity
                || manifest.payload.provenance.git_head != status.source_commit
                || report.payload.component_set
                    != BTreeSet::from([
                        CapacityComponent::DamonTelemetry,
                        CapacityComponent::DamosReclaim,
                    ])
                || report.payload.target_contract_version
                    != crate::capacity_external_target::CAPACITY_EXTERNAL_TARGET_CONTRACT_VERSION
                || report.payload.target_protocol_version
                    != crate::capacity_external_target::CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION
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
                || report.payload.capacity_evaluation != EvaluationState::NotEvaluated
                || report.payload.effectiveness_evaluation != EvaluationState::NotEvaluated
                || report.payload.production_activation_authorized
                || report.payload.validator_report_lifecycle.version != 1
                || report
                    .payload
                    .validator_report_lifecycle
                    .validator_exit_status
                    != Some(0)
                || !report.payload.validator_report_lifecycle.explicit_path_mode
                || report
                    .payload
                    .validator_report_lifecycle
                    .raw_sha256
                    .as_deref()
                    != status.validator_report_raw_sha256.as_deref()
                || report
                    .payload
                    .validator_report_lifecycle
                    .canonical_semantic_sha256
                    .as_deref()
                    != status.validator_report_canonical_sha256.as_deref()
            {
                bail!("external-target prerequisite STATUS/report contract mismatch");
            }
        }
        CapacityPrerequisiteKind::Composition => {
            let manifest: PreparedCapacityCompositionManifest =
                serde_json::from_slice(&fs::read(archive.join("manifest.json"))?)?;
            manifest.verify()?;
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
                || manifest.payload.experiment_id != status.identity
                || manifest.payload.provenance.git_head != status.source_commit
                || report.invocation_count != 1
                || report.planned_runs != 6
                || report.completed_runs != 6
                || report.planned_levels != 18
                || report.completed_levels != 18
                || report.runs.len() != 6
                || !report.runs.iter().all(composition_run_is_complete)
                || !composition_report_matches_manifest(&report, &manifest)
                || report.search_complete
                || report.capacity_evaluation != EvaluationState::NotEvaluated
                || report.effectiveness_evaluation != EvaluationState::NotEvaluated
                || report.production_activation_authorized
                || !report.cleanup_passed
                || !report.structural_restore_passed
            {
                bail!("composition prerequisite STATUS/report contract mismatch");
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapacityPathContract {
    lineage: u64,
    prepared_root: PathBuf,
    output_root: PathBuf,
}

impl CapacityPathContract {
    fn parse(prepared_root: &Path, output_root: &Path) -> Result<Self> {
        let prepared_lineage = capacity_path_lineage(prepared_root, "-prepared")
            .context("invalid capacity prepared-root grammar")?;
        let output_lineage = capacity_path_lineage(output_root, "-output")
            .context("invalid capacity output-root grammar")?;
        if prepared_lineage != output_lineage || prepared_root == output_root {
            bail!("capacity prepared/output roots do not share one exact lineage");
        }
        Ok(Self {
            lineage: prepared_lineage,
            prepared_root: prepared_root.to_path_buf(),
            output_root: output_root.to_path_buf(),
        })
    }
}

fn capacity_path_lineage(path: &Path, role: &str) -> Option<u64> {
    if !path.is_absolute() || path.parent()? != Path::new("/tmp") {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    let lineage = name
        .strip_prefix("nemor-capacity-benchmark-")?
        .strip_suffix(role)?;
    if lineage.is_empty()
        || lineage.starts_with('0')
        || !lineage.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let parsed = lineage.parse::<u64>().ok()?;
    (parsed > 0 && parsed.to_string() == lineage).then_some(parsed)
}

fn capacity_path_plan_supported(prepared_root: &Path, output_root: &Path) -> bool {
    CapacityPathContract::parse(prepared_root, output_root).is_ok()
}

fn directory_identity_fields_supported(
    identity: &CapacityDirectoryIdentity,
    path: &Path,
    uid: u32,
    gid: u32,
    tmp_device: u64,
) -> bool {
    identity.canonical_path == path
        && identity.device == tmp_device
        && identity.uid == uid
        && identity.gid == gid
        && identity.mode == 0o700
}

fn capture_capacity_directory_identity(
    path: &Path,
    uid: u32,
    gid: u32,
) -> Result<CapacityDirectoryIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    let tmp_metadata = fs::symlink_metadata("/tmp")?;
    let canonical_path = path.canonicalize()?;
    let identity = CapacityDirectoryIdentity {
        canonical_path,
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    };
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || !directory_identity_fields_supported(&identity, path, uid, gid, tmp_metadata.dev())
    {
        bail!("capacity root identity, ownership, mode, or mount boundary mismatch");
    }
    Ok(identity)
}

fn frozen_capacity_directory_identity_verified(
    path: &Path,
    frozen: &CapacityDirectoryIdentity,
    uid: u32,
    gid: u32,
) -> bool {
    capture_capacity_directory_identity(path, uid, gid).is_ok_and(|current| current == *frozen)
}

#[allow(clippy::too_many_arguments)]
fn frozen_child_paths_supported(
    prepared_root: &Path,
    output_root: &Path,
    manifest_path: &Path,
    benchmark_report_path: &Path,
    evaluation_path: &Path,
    database_path: &Path,
    composition_report_path: &Path,
    runs_root: &Path,
) -> bool {
    manifest_path == prepared_root.join(CAPACITY_BENCHMARK_MANIFEST_NAME)
        && benchmark_report_path == output_root.join("capacity-benchmark.report.json")
        && evaluation_path == output_root.join("capacity-evaluation.json")
        && database_path == output_root.join("capacity-composition.sqlite")
        && composition_report_path == output_root.join("capacity-composition.report.json")
        && runs_root == output_root.join("runs")
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
        && frozen_child_paths_supported(
            prepared_root,
            output_root,
            &payload.manifest_path,
            &payload.report_path,
            &payload.evaluation_path,
            &payload.database_path,
            &composition.report_path,
            &composition.runs_root,
        )
        && composition.database_path == payload.database_path
        && payload.prepared_root_identity.canonical_path == *prepared_root
        && payload.output_root_identity.canonical_path == *output_root
        && payload.prepared_root_identity.uid == composition.preparing_uid
        && payload.prepared_root_identity.gid == composition.preparing_gid
        && payload.output_root_identity.uid == composition.preparing_uid
        && payload.output_root_identity.gid == composition.preparing_gid
        && payload.prepared_root_identity.mode == 0o700
        && payload.output_root_identity.mode == 0o700
        && payload.prepared_root_identity.device == payload.output_root_identity.device
        && payload.prepared_root_identity.inode != payload.output_root_identity.inode
}

fn capacity_payload_paths_supported(
    manifest_path: &Path,
    payload: &CapacityBenchmarkPayload,
) -> bool {
    let composition = &payload.composition_payload;
    let prepared_root = &composition.prepared_root;
    let output_root = &payload.output_root;
    capacity_payload_path_layout_supported(payload)
        && manifest_path == payload.manifest_path
        && frozen_capacity_directory_identity_verified(
            prepared_root,
            &payload.prepared_root_identity,
            composition.preparing_uid,
            composition.preparing_gid,
        )
        && frozen_capacity_directory_identity_verified(
            output_root,
            &payload.output_root_identity,
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

fn remove_exact_created_manifest(
    path: &Path,
    prepared_root: &Path,
    uid: u32,
    gid: u32,
) -> Result<()> {
    if path.parent() != Some(prepared_root)
        || path.file_name().and_then(|name| name.to_str()) != Some(CAPACITY_BENCHMARK_MANIFEST_NAME)
    {
        bail!("refusing to remove a non-contract capacity manifest path");
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.nlink() != 1
    {
        bail!("refusing to remove a capacity manifest with unexpected identity");
    }
    fs::remove_file(path)?;
    Ok(())
}

fn remove_exact_empty_created_root(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let tmp_metadata = fs::symlink_metadata("/tmp")?;
    if path.parent() != Some(Path::new("/tmp"))
        || metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.dev() != tmp_metadata.dev()
        || path.canonicalize()? != path
        || fs::read_dir(path)?.next().is_some()
    {
        bail!("refusing to remove a nonempty or unexpected capacity root");
    }
    fs::remove_dir(path)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cleanup_new_capacity_paths(
    manifest_path: &Path,
    prepared_root: &Path,
    output_root: &Path,
    uid: u32,
    gid: u32,
    manifest_created: bool,
    prepared_created: bool,
    output_created: bool,
) -> Result<()> {
    let mut failures = Vec::new();
    if manifest_created && manifest_path.exists() {
        if let Err(error) = remove_exact_created_manifest(manifest_path, prepared_root, uid, gid) {
            failures.push(format!("manifest: {error:#}"));
        }
    }
    if output_created && output_root.exists() {
        if let Err(error) = remove_exact_empty_created_root(output_root, uid, gid) {
            failures.push(format!("output root: {error:#}"));
        }
    }
    if prepared_created && prepared_root.exists() {
        if let Err(error) = remove_exact_empty_created_root(prepared_root, uid, gid) {
            failures.push(format!("prepared root: {error:#}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("{}", failures.join("; "))
    }
}

fn create_new_private_synced_file(path: &Path, bytes: &[u8], created: &mut bool) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    *created = true;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn identity_context_supported(
    root: bool,
    current_uid: u32,
    current_gid: u32,
    sudo_uid: Option<u32>,
    sudo_gid: Option<u32>,
    preparing_uid: u32,
    preparing_gid: u32,
) -> bool {
    if root {
        sudo_uid == Some(preparing_uid) && sudo_gid == Some(preparing_gid)
    } else {
        current_uid == preparing_uid && current_gid == preparing_gid
    }
}

pub fn prepare_capacity_benchmark(
    external_archive: &Path,
    composition_archive: &Path,
    prepared_root: &Path,
    output_root: &Path,
) -> Result<PathBuf> {
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    if uid == 0 {
        bail!("capacity preparation must be unprivileged");
    }
    let path_contract = CapacityPathContract::parse(prepared_root, output_root)?;
    if fs::symlink_metadata(prepared_root).is_ok() || fs::symlink_metadata(output_root).is_ok() {
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
    let manifest_path = prepared_root.join(CAPACITY_BENCHMARK_MANIFEST_NAME);
    let mut prepared_created = false;
    let mut output_created = false;
    let mut manifest_created = false;
    let result = (|| -> Result<PathBuf> {
        fs::create_dir(prepared_root)?;
        prepared_created = true;
        fs::set_permissions(prepared_root, fs::Permissions::from_mode(0o700))?;
        fs::create_dir(output_root)?;
        output_created = true;
        fs::set_permissions(output_root, fs::Permissions::from_mode(0o700))?;
        let prepared_root_identity = capture_capacity_directory_identity(prepared_root, uid, gid)?;
        let output_root_identity = capture_capacity_directory_identity(output_root, uid, gid)?;
        if prepared_root_identity.device != output_root_identity.device
            || prepared_root_identity.inode == output_root_identity.inode
            || path_contract.prepared_root != prepared_root
            || path_contract.output_root != output_root
            || path_contract.lineage == 0
            || fs::read_dir(output_root)?.next().is_some()
        {
            bail!("capacity roots failed post-creation identity or freshness verification");
        }
        let payload = CapacityBenchmarkPayload {
            schema_version: CAPACITY_BENCHMARK_MANIFEST_SCHEMA_VERSION,
            execution_schema_version: CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION,
            experiment_id: composition_payload.experiment_id.clone(),
            contract: CapacityBenchmarkContract::v1(),
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
            manifest_path: manifest_path.clone(),
            output_root: output_root.to_path_buf(),
            prepared_root_identity,
            output_root_identity,
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
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        manifest_bytes.push(b'\n');
        create_new_private_synced_file(&manifest_path, &manifest_bytes, &mut manifest_created)?;
        File::open(prepared_root)?.sync_all()?;
        let manifest_metadata = fs::symlink_metadata(&manifest_path)?;
        if !manifest_metadata.file_type().is_file()
            || manifest_metadata.file_type().is_symlink()
            || manifest_metadata.uid() != uid
            || manifest_metadata.gid() != gid
            || manifest_metadata.mode() & 0o7777 != 0o600
            || manifest_metadata.nlink() != 1
            || manifest_metadata.dev() != manifest.payload.prepared_root_identity.device
            || !frozen_capacity_directory_identity_verified(
                prepared_root,
                &manifest.payload.prepared_root_identity,
                uid,
                gid,
            )
            || !frozen_capacity_directory_identity_verified(
                output_root,
                &manifest.payload.output_root_identity,
                uid,
                gid,
            )
            || fs::read_dir(output_root)?.next().is_some()
        {
            bail!("capacity manifest or root post-write identity verification failed");
        }
        Ok(manifest_path.clone())
    })();
    match result {
        Ok(path) => Ok(path),
        Err(primary) => {
            let cleanup = cleanup_new_capacity_paths(
                &manifest_path,
                prepared_root,
                output_root,
                uid,
                gid,
                manifest_created,
                prepared_created,
                output_created,
            );
            match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup_error) => Err(primary.context(format!(
                    "post-failure cleanup also failed: {cleanup_error:#}"
                ))),
            }
        }
    }
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
    let prerequisite_status_contract_supported = [
        (
            &payload.external_target_prerequisite,
            CapacityPrerequisiteKind::ExternalTarget,
        ),
        (
            &payload.composition_prerequisite,
            CapacityPrerequisiteKind::Composition,
        ),
    ]
    .into_iter()
    .all(|(prerequisite, kind)| {
        prerequisite.kind == kind
            && prerequisite.status_contract_version == CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION
            && hash_file(&prerequisite.archive.join("STATUS"))
                .is_ok_and(|sha256| sha256 == prerequisite.status_sha256)
            && fs::read_to_string(prerequisite.archive.join("STATUS"))
                .ok()
                .and_then(|status| parse_prerequisite_status(&status, kind).ok())
                .is_some_and(|status| {
                    status.version == prerequisite.status_contract_version
                        && status.kind == prerequisite.kind
                        && status.identity == prerequisite.identity
                        && status.source_commit == prerequisite.source_commit
                })
    });
    let prerequisite_lineage_link_verified = external_prerequisite_matches_composition(
        &payload.external_target_prerequisite,
        &payload.composition_payload,
    )
    .unwrap_or(false);
    let output_fresh =
        fs::read_dir(&payload.output_root).is_ok_and(|mut entries| entries.next().is_none());
    let legacy_global_report_absent = crate::validator_report::legacy_report_absent();
    let validator_state_absent = crate::validator_report::validator_state_absent();
    let stale_resources_clear = legacy_global_report_absent
        && validator_state_absent
        && !super::capacity_composition::processes_contain("pressure-worker")
        && !super::capacity_composition::processes_contain("capacity-external-target-worker")
        && !payload.output_root.join("pressure-0.sock").exists();
    let root = nix::unistd::geteuid().is_root();
    let sudo_uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse().ok());
    let sudo_gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse().ok());
    let identity_context_supported = identity_context_supported(
        root,
        nix::unistd::geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
        sudo_uid,
        sudo_gid,
        payload.composition_payload.preparing_uid,
        payload.composition_payload.preparing_gid,
    );
    let identity_authorized = root && identity_context_supported;
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
    let path_contract_supported = CapacityPathContract::parse(
        &payload.composition_payload.prepared_root,
        &payload.output_root,
    )
    .is_ok();
    let prepared_root_identity_verified = frozen_capacity_directory_identity_verified(
        &payload.composition_payload.prepared_root,
        &payload.prepared_root_identity,
        payload.composition_payload.preparing_uid,
        payload.composition_payload.preparing_gid,
    );
    let output_root_identity_verified = frozen_capacity_directory_identity_verified(
        &payload.output_root,
        &payload.output_root_identity,
        payload.composition_payload.preparing_uid,
        payload.composition_payload.preparing_gid,
    );
    let frozen_child_paths_verified =
        capacity_payload_path_layout_supported(payload) && path == payload.manifest_path;
    let ownership_plan_supported = payload.composition_payload.preparing_uid != 0
        && payload.composition_payload.preparing_gid != 0
        && path_contract_supported
        && prepared_root_identity_verified
        && output_root_identity_verified
        && frozen_child_paths_verified
        && identity_context_supported
        && capacity_payload_paths_supported(path, payload);
    let exact_profile_supported =
        payload.contract.exact_profile == CapacityBenchmarkContract::v1().exact_profile;
    let search_policy_supported = payload.search_policy == CapacitySearchPolicy::v1();
    let run_plan_supported = capacity_run_plan_supported(payload);
    let level_ladder_supported =
        payload.levels == capacity_ladder(payload.safe_search_ceiling_bytes)?;
    let report_lifecycle_version_supported =
        crate::capacity_composition::COMPOSITION_TARGET_EVIDENCE_VERSION == 2;
    let mut report = CapacityBenchmarkPreflight {
        schema_version: CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION,
        prerequisite_status_contract_version: CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION,
        path_contract_version: CAPACITY_PATH_CONTRACT_VERSION,
        manifest_verified: verified,
        source_and_binaries_verified,
        material_environment_match,
        external_target_prerequisite_verified,
        composition_prerequisite_verified,
        prerequisite_status_contract_supported,
        prerequisite_lineage_link_verified,
        exact_profile_supported,
        search_policy_supported,
        run_plan_supported,
        level_ladder_supported,
        safe_search_ceiling_supported,
        headroom_safe,
        memory_max_safe,
        path_contract_supported,
        prepared_root_identity_verified,
        output_root_identity_verified,
        frozen_child_paths_verified,
        ownership_plan_supported,
        output_fresh,
        stale_resources_clear,
        report_lifecycle_version_supported,
        legacy_global_report_absent,
        validator_state_absent,
        all_non_authorization_gates_pass: false,
        user_preflight_passed: false,
        current_identity_authorized: identity_authorized,
        bounded_capacity_benchmark_entry_ready: false,
        execution_ready: false,
        preflight_mutated: false,
    };
    let non_authorization = report.all_non_authorization_gates_pass();
    let ready = non_authorization && identity_authorized;
    report.all_non_authorization_gates_pass = non_authorization;
    report.user_preflight_passed = non_authorization;
    report.bounded_capacity_benchmark_entry_ready = ready;
    report.execution_ready = ready;
    report.verify_readiness_consistency()?;
    Ok(report)
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
        && verify_ledger_entries(archive).is_ok()
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
        let contract = CapacityBenchmarkContract::v1();
        assert_eq!(contract.version, 1);
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
    fn prerequisite_status_rejects_substrings_duplicates_and_failed_supporting_gates() {
        let status = external_status();
        assert!(parse_prerequisite_status(
            &status.replace("production_activation=false", "production_activation=true"),
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
        .is_ok());
        assert!(parse_prerequisite_status(
            &status.replace("cleanup=PASS", "cleanup=PASS extra"),
            CapacityPrerequisiteKind::ExternalTarget,
        )
        .is_err());
    }

    #[test]
    fn status_contract_accepts_current_legacy_and_matching_terminal_forms() {
        let external = external_status();
        assert!(parse_prerequisite_status(
            &external.replace("status=PASS", "classification=PASS"),
            CapacityPrerequisiteKind::ExternalTarget,
        )
        .is_ok());
        let composition = composition_status();
        for terminal in [
            "status=PASS",
            "classification=PASS",
            "classification=COMPLETED_COMPOSITION_FRAMEWORK_VALIDATION",
            "status=PASS\nclassification=PASS",
            "status=PASS\nclassification=COMPLETED_COMPOSITION_FRAMEWORK_VALIDATION",
        ] {
            assert!(parse_prerequisite_status(
                &composition.replace("status=PASS", terminal),
                CapacityPrerequisiteKind::Composition,
            )
            .is_ok());
        }
    }

    #[test]
    fn status_contract_rejects_missing_duplicate_conflicting_and_nonpass_terminals() {
        let status = external_status();
        for candidate in [
            status.replace("status=PASS\n", ""),
            format!("{status}\nstatus=PASS"),
            status.replace("status=PASS", "status=PASS\nclassification=FAIL"),
            status.replace("status=PASS", "status=PASSING"),
            status.replace("status=PASS", "status=FAIL"),
            status.replace("status=PASS", "status=ERROR"),
            status.replace("status=PASS", "status=BLOCKED"),
            status.replace("status=PASS", "status=INCOMPLETE"),
        ] {
            assert!(parse_prerequisite_status(
                &candidate,
                CapacityPrerequisiteKind::ExternalTarget,
            )
            .is_err());
        }
    }

    #[test]
    fn status_contract_normalizes_crlf_trims_ascii_and_preserves_unknown_metadata() {
        let status = external_status()
            .lines()
            .map(|line| format!(" \t{line} \t"))
            .chain(["future_metadata = harmless".to_owned(), String::new()])
            .collect::<Vec<_>>()
            .join("\r\n");
        let parsed =
            parse_prerequisite_status(&status, CapacityPrerequisiteKind::ExternalTarget).unwrap();
        assert_eq!(
            parsed._unknown_metadata,
            vec![("future_metadata".into(), "harmless".into())]
        );
    }

    #[test]
    fn status_contract_rejects_malformed_unknown_lines_and_supporting_gate_failures() {
        let status = external_status();
        assert!(parse_prerequisite_status(
            &format!("{status}\nmalformed future metadata"),
            CapacityPrerequisiteKind::ExternalTarget,
        )
        .is_err());
        for (from, to) in [
            ("cleanup=PASS", "cleanup=FAIL"),
            ("structural_restore=PASS", "structural_restore=FAIL"),
            ("production_activation=false", "production_activation=true"),
        ] {
            assert!(parse_prerequisite_status(
                &status.replace(from, to),
                CapacityPrerequisiteKind::ExternalTarget,
            )
            .is_err());
        }
    }

    fn write_ledger(root: &Path, paths: &[&str]) {
        let ledger = paths
            .iter()
            .map(|relative| format!("{}  {relative}", hash_file(&root.join(relative)).unwrap()))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(root.join("SHA256SUMS"), format!("{ledger}\n")).unwrap();
    }

    fn ledger_fixture(kind: CapacityPrerequisiteKind) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("manifest.json"), b"manifest").unwrap();
        fs::write(root.path().join(kind.report_name()), b"report").unwrap();
        fs::write(root.path().join("STATUS"), b"status").unwrap();
        fs::write(root.path().join("future-metadata.txt"), b"future").unwrap();
        write_ledger(
            root.path(),
            &[
                "manifest.json",
                kind.report_name(),
                "STATUS",
                "future-metadata.txt",
            ],
        );
        root
    }

    #[test]
    fn prerequisite_ledger_accepts_complete_archives_and_extra_metadata() {
        for kind in [
            CapacityPrerequisiteKind::ExternalTarget,
            CapacityPrerequisiteKind::Composition,
        ] {
            let fixture = ledger_fixture(kind);
            verify_all_sums(&fixture.path().canonicalize().unwrap(), kind).unwrap();
        }
    }

    #[test]
    fn prerequisite_ledger_rejects_hash_mismatch_duplicate_and_path_escape() {
        for changed in ["STATUS", "manifest.json", "external-target-validation.json"] {
            let fixture = ledger_fixture(CapacityPrerequisiteKind::ExternalTarget);
            let root = fixture.path().canonicalize().unwrap();
            fs::write(root.join(changed), b"tampered").unwrap();
            assert!(verify_all_sums(&root, CapacityPrerequisiteKind::ExternalTarget).is_err());
        }
        let fixture = ledger_fixture(CapacityPrerequisiteKind::ExternalTarget);
        let root = fixture.path().canonicalize().unwrap();
        write_ledger(
            &root,
            &[
                "manifest.json",
                "external-target-validation.json",
                "STATUS",
                "STATUS",
            ],
        );
        assert!(verify_all_sums(&root, CapacityPrerequisiteKind::ExternalTarget).is_err());
        fs::write(
            root.join("SHA256SUMS"),
            format!("{}  ../escape\n", "0".repeat(64)),
        )
        .unwrap();
        assert!(verify_all_sums(&root, CapacityPrerequisiteKind::ExternalTarget).is_err());
    }

    #[test]
    fn prerequisite_ledger_rejects_symlinks_and_missing_required_files() {
        for missing in ["manifest.json", "external-target-validation.json", "STATUS"] {
            let fixture = ledger_fixture(CapacityPrerequisiteKind::ExternalTarget);
            let root = fixture.path().canonicalize().unwrap();
            let paths = [
                "manifest.json",
                "external-target-validation.json",
                "STATUS",
                "future-metadata.txt",
            ]
            .into_iter()
            .filter(|path| *path != missing)
            .collect::<Vec<_>>();
            write_ledger(&root, &paths);
            assert!(verify_all_sums(&root, CapacityPrerequisiteKind::ExternalTarget).is_err());
        }
        let fixture = ledger_fixture(CapacityPrerequisiteKind::ExternalTarget);
        let root = fixture.path().canonicalize().unwrap();
        std::os::unix::fs::symlink("manifest.json", root.join("manifest-link")).unwrap();
        let mut ledger = fs::read_to_string(root.join("SHA256SUMS")).unwrap();
        ledger.push_str(&format!(
            "{}  manifest-link\n",
            hash_file(&root.join("manifest.json")).unwrap()
        ));
        fs::write(root.join("SHA256SUMS"), ledger).unwrap();
        assert!(verify_all_sums(&root, CapacityPrerequisiteKind::ExternalTarget).is_err());
    }

    fn copy_archive_tree(source: &Path, destination: &Path) {
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                fs::create_dir(&target).unwrap();
                copy_archive_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    fn archive_copy(source: &Path) -> tempfile::TempDir {
        let destination = tempfile::tempdir().unwrap();
        copy_archive_tree(source, destination.path());
        destination
    }

    fn rewrite_status_key(root: &Path, key: &str, value: &str) {
        let status_path = root.join("STATUS");
        let status = fs::read_to_string(&status_path).unwrap();
        let mut replaced = false;
        let rewritten = status
            .lines()
            .map(|line| {
                if line
                    .split_once('=')
                    .is_some_and(|(candidate, _)| candidate == key)
                {
                    replaced = true;
                    format!("{key}={value}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(replaced, "missing STATUS key {key}");
        fs::write(status_path, format!("{rewritten}\n")).unwrap();
    }

    fn rebuild_archive_ledger(root: &Path) {
        let paths = fs::read_to_string(root.join("SHA256SUMS"))
            .unwrap()
            .lines()
            .map(|line| line.split_once("  ").unwrap().1.to_owned())
            .collect::<Vec<_>>();
        let ledger = paths
            .iter()
            .map(|relative| format!("{}  {relative}", hash_file(&root.join(relative)).unwrap()))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(root.join("SHA256SUMS"), format!("{ledger}\n")).unwrap();
    }

    fn reseal_external_archive(root: &Path, report: &mut ExternalTargetExecutionReport) {
        report.payload_sha256 = hash_json(&report.payload).unwrap();
        fs::write(
            root.join(CapacityPrerequisiteKind::ExternalTarget.report_name()),
            serde_json::to_vec_pretty(report).unwrap(),
        )
        .unwrap();
        rewrite_status_key(root, "execution_payload_sha256", &report.payload_sha256);
        rebuild_archive_ledger(root);
    }

    fn reseal_composition_archive(root: &Path, report: &mut CapacityCompositionExecutionEvidence) {
        report.payload_sha256.clear();
        report.payload_sha256 = hash_json(report).unwrap();
        fs::write(
            root.join(CapacityPrerequisiteKind::Composition.report_name()),
            serde_json::to_vec_pretty(report).unwrap(),
        )
        .unwrap();
        rewrite_status_key(root, "execution_payload_sha256", &report.payload_sha256);
        rebuild_archive_ledger(root);
    }

    #[test]
    fn prerequisite_current_external_lineage6_and_composition_lineage5_archives_pass() {
        for (path, kind) in [
            (
                "/home/oliver/.local/share/nemor/validation-history/phase10-capacity-external-target-6-completed",
                CapacityPrerequisiteKind::ExternalTarget,
            ),
            (
                "/home/oliver/.local/share/nemor/validation-history/phase10-capacity-composition-5-completed",
                CapacityPrerequisiteKind::Composition,
            ),
        ] {
            let archive = Path::new(path);
            if archive.exists() {
                if kind == CapacityPrerequisiteKind::Composition {
                    let report: CapacityCompositionExecutionEvidence = serde_json::from_slice(
                        &fs::read(archive.join(kind.report_name())).unwrap(),
                    )
                    .unwrap();
                    for (index, run) in report.runs.iter().enumerate() {
                        assert!(composition_run_is_complete(run), "composition run {index}");
                    }
                }
                let prerequisite = prerequisite(archive, kind).unwrap();
                verify_archive(&prerequisite, kind).unwrap();
            }
        }
    }

    #[test]
    fn prerequisite_external_typed_report_rejects_each_required_false_gate() {
        let source = Path::new(
            "/home/oliver/.local/share/nemor/validation-history/phase10-capacity-external-target-6-completed",
        );
        if !source.exists() {
            return;
        }
        for case in 0..18 {
            let fixture = archive_copy(source);
            let root = fixture.path().canonicalize().unwrap();
            let mut report: ExternalTargetExecutionReport = serde_json::from_slice(
                &fs::read(root.join(CapacityPrerequisiteKind::ExternalTarget.report_name()))
                    .unwrap(),
            )
            .unwrap();
            match case {
                0 => {
                    report.state =
                        crate::capacity_external_validation::ExternalTargetClassification::Invalid
                }
                1 => report.payload.validator_exit_success = false,
                2 => report.payload.direct_shadow_gates[0] = false,
                3 => report.payload.required_damos_gates_passed = false,
                4 => report.payload.zero_host_oom = false,
                5 => report.payload.cleanup_passed = false,
                6 => report.payload.recovery_passed = false,
                7 => report.payload.recovery_idempotent_passed = false,
                8 => report.payload.structural_restore_passed = false,
                9 => report.payload.validator_report_lifecycle.version = 0,
                10 => {
                    report
                        .payload
                        .validator_report_lifecycle
                        .legacy_global_absent_after = false
                }
                11 => {
                    report
                        .payload
                        .validator_report_lifecycle
                        .validator_state_absent = false
                }
                12 => report.payload.target_contract_version += 1,
                13 => report.payload.target_protocol_version += 1,
                14 => {
                    report
                        .payload
                        .component_set
                        .remove(&CapacityComponent::DamosReclaim);
                }
                15 => report.payload.capacity_evaluation = EvaluationState::Pass,
                16 => report.payload.effectiveness_evaluation = EvaluationState::Pass,
                17 => report.payload.production_activation_authorized = true,
                _ => unreachable!(),
            }
            reseal_external_archive(&root, &mut report);
            let prerequisite =
                prerequisite(&root, CapacityPrerequisiteKind::ExternalTarget).unwrap();
            assert!(
                verify_archive(&prerequisite, CapacityPrerequisiteKind::ExternalTarget).is_err(),
                "external gate case {case}"
            );
        }
    }

    #[test]
    fn prerequisite_composition_typed_report_rejects_each_terminal_failure() {
        let source = Path::new(
            "/home/oliver/.local/share/nemor/validation-history/phase10-capacity-composition-5-completed",
        );
        if !source.exists() {
            return;
        }
        for case in 0..21 {
            let fixture = archive_copy(source);
            let root = fixture.path().canonicalize().unwrap();
            let mut report: CapacityCompositionExecutionEvidence = serde_json::from_slice(
                &fs::read(root.join(CapacityPrerequisiteKind::Composition.report_name())).unwrap(),
            )
            .unwrap();
            match case {
                0 => report.state = CompositionExperimentState::InvalidRun,
                1 => report.planned_runs = 5,
                2 => report.completed_runs = 5,
                3 => report.planned_levels = 17,
                4 => report.completed_levels = 17,
                5 => {
                    report.runs.pop();
                }
                6 => report.runs[0].state = CompositionExperimentState::InvalidRun,
                7 => {
                    report.runs[0].levels.pop();
                }
                8 => {
                    report.runs[0].levels[0].classification =
                        CompositionLevelClassification::InvalidEvidence
                }
                9 => report.runs[0].pressure_scope_cleanup_passed = false,
                10 => report.runs[0].scope_cleanup.worker_absent = false,
                11 => report.runs[0].structural_restore_passed = false,
                12 => report.runs[0].levels[0].cleanup_passed = false,
                13 => report.runs[0].levels[0].structural_restore_passed = false,
                14 => {
                    report.runs[0].levels[0]
                        .target
                        .validator_report_lifecycle
                        .version = 0
                }
                15 => report.cleanup_passed = false,
                16 => report.structural_restore_passed = false,
                17 => report.search_complete = true,
                18 => report.capacity_evaluation = EvaluationState::Pass,
                19 => report.production_activation_authorized = true,
                20 => report.effectiveness_evaluation = EvaluationState::Pass,
                _ => unreachable!(),
            }
            reseal_composition_archive(&root, &mut report);
            let prerequisite = prerequisite(&root, CapacityPrerequisiteKind::Composition).unwrap();
            assert!(
                verify_archive(&prerequisite, CapacityPrerequisiteKind::Composition).is_err(),
                "composition gate case {case}"
            );
        }
    }

    #[test]
    fn prerequisite_rejects_status_report_conflict_wrong_kind_hash_source_and_identity() {
        let source = Path::new(
            "/home/oliver/.local/share/nemor/validation-history/phase10-capacity-external-target-6-completed",
        );
        if !source.exists() {
            return;
        }
        let fixture = archive_copy(source);
        let root = fixture.path().canonicalize().unwrap();
        rewrite_status_key(&root, "cleanup", "FAIL");
        rebuild_archive_ledger(&root);
        let conflicted = prerequisite(&root, CapacityPrerequisiteKind::ExternalTarget).unwrap();
        assert!(verify_archive(&conflicted, CapacityPrerequisiteKind::ExternalTarget).is_err());

        let valid = prerequisite(source, CapacityPrerequisiteKind::ExternalTarget).unwrap();
        let mut changed = valid.clone();
        changed.kind = CapacityPrerequisiteKind::Composition;
        assert!(verify_archive(&changed, CapacityPrerequisiteKind::ExternalTarget).is_err());
        changed = valid.clone();
        changed.status_sha256 = "0".repeat(64);
        assert!(verify_archive(&changed, CapacityPrerequisiteKind::ExternalTarget).is_err());
        changed = valid.clone();
        changed.source_commit = "0".repeat(40);
        assert!(verify_archive(&changed, CapacityPrerequisiteKind::ExternalTarget).is_err());
        changed = valid;
        changed.identity = "wrong-validation".into();
        assert!(verify_archive(&changed, CapacityPrerequisiteKind::ExternalTarget).is_err());
    }

    #[test]
    fn capacity_path_contract_matches_exact_components_and_lineage() {
        assert!(capacity_path_plan_supported(
            Path::new("/tmp/nemor-capacity-benchmark-3-prepared"),
            Path::new("/tmp/nemor-capacity-benchmark-3-output"),
        ));
        assert!(capacity_path_plan_supported(
            Path::new("/tmp/nemor-capacity-benchmark-12345-prepared"),
            Path::new("/tmp/nemor-capacity-benchmark-12345-output"),
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
            (
                "nemor-capacity-benchmark-3-prepared",
                "nemor-capacity-benchmark-3-output",
            ),
            (
                "/tmp/nemor-capacity-benchmark-0-prepared",
                "/tmp/nemor-capacity-benchmark-0-output",
            ),
            (
                "/tmp/nemor-capacity-benchmark-+3-prepared",
                "/tmp/nemor-capacity-benchmark-+3-output",
            ),
            (
                "/tmp/nemor-capacity-benchmark-x-prepared",
                "/tmp/nemor-capacity-benchmark-x-output",
            ),
            (
                "/tmp/nemor-capacity-benchmark-3-prepared",
                "/tmp/nemor-capacity-benchmark-3-output-extra",
            ),
            (
                "/tmp/nemor-capacity-benchmark-3-prepared/child",
                "/tmp/nemor-capacity-benchmark-3-output/child",
            ),
        ] {
            assert!(!capacity_path_plan_supported(
                Path::new(prepared),
                Path::new(output)
            ));
        }
    }

    #[test]
    fn path_contract_rejects_symlink_wrong_identity_mode_and_mount_device() {
        let root = fixture_root();
        let uid = nix::unistd::geteuid().as_raw();
        let gid = nix::unistd::getegid().as_raw();
        let identity = capture_capacity_directory_identity(root.path(), uid, gid).unwrap();
        let tmp_device = fs::symlink_metadata("/tmp").unwrap().dev();
        let mut wrong = identity.clone();
        wrong.uid = wrong.uid.saturating_add(1);
        assert!(!directory_identity_fields_supported(
            &wrong,
            root.path(),
            uid,
            gid,
            tmp_device
        ));
        wrong = identity.clone();
        wrong.gid = wrong.gid.saturating_add(1);
        assert!(!directory_identity_fields_supported(
            &wrong,
            root.path(),
            uid,
            gid,
            tmp_device
        ));
        wrong = identity.clone();
        wrong.mode = 0o755;
        assert!(!directory_identity_fields_supported(
            &wrong,
            root.path(),
            uid,
            gid,
            tmp_device
        ));
        wrong = identity;
        wrong.device = wrong.device.saturating_add(1);
        assert!(!directory_identity_fields_supported(
            &wrong,
            root.path(),
            uid,
            gid,
            tmp_device
        ));
        let link = root.path().with_extension("capacity-link");
        std::os::unix::fs::symlink(root.path(), &link).unwrap();
        assert!(capture_capacity_directory_identity(&link, uid, gid).is_err());
        fs::remove_file(link).unwrap();
    }

    #[test]
    fn path_contract_freezes_every_child_path_under_its_exact_root() {
        let prepared = Path::new("/tmp/nemor-capacity-benchmark-3-prepared");
        let output = Path::new("/tmp/nemor-capacity-benchmark-3-output");
        let valid = || {
            frozen_child_paths_supported(
                prepared,
                output,
                &prepared.join(CAPACITY_BENCHMARK_MANIFEST_NAME),
                &output.join("capacity-benchmark.report.json"),
                &output.join("capacity-evaluation.json"),
                &output.join("capacity-composition.sqlite"),
                &output.join("capacity-composition.report.json"),
                &output.join("runs"),
            )
        };
        assert!(valid());
        let foreign = Path::new("/tmp/foreign");
        for position in 0..6 {
            let mut paths = [
                prepared.join(CAPACITY_BENCHMARK_MANIFEST_NAME),
                output.join("capacity-benchmark.report.json"),
                output.join("capacity-evaluation.json"),
                output.join("capacity-composition.sqlite"),
                output.join("capacity-composition.report.json"),
                output.join("runs"),
            ];
            paths[position] = foreign.join("alias");
            assert!(!frozen_child_paths_supported(
                prepared, output, &paths[0], &paths[1], &paths[2], &paths[3], &paths[4], &paths[5],
            ));
        }
    }

    #[test]
    fn path_contract_contains_no_component_prefix_naming_check() {
        let source = include_str!("capacity_benchmark.rs");
        assert!(!source.contains("starts_with(Path::new(\"/tmp/nemor-capacity-benchmark-\")"));
        assert!(source.contains("strip_prefix(\"nemor-capacity-benchmark-\")"));
    }

    #[test]
    fn preparation_file_is_create_new_private_synced_and_output_can_remain_empty() {
        let root = fixture_root();
        let manifest = root.path().join(CAPACITY_BENCHMARK_MANIFEST_NAME);
        let mut created = false;
        create_new_private_synced_file(&manifest, b"manifest\n", &mut created).unwrap();
        assert!(created);
        let metadata = fs::symlink_metadata(&manifest).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(fs::read(&manifest).unwrap(), b"manifest\n");
        let mut collision_created = false;
        assert!(
            create_new_private_synced_file(&manifest, b"replacement", &mut collision_created)
                .is_err()
        );
        assert!(!collision_created);
        let output = tempfile::tempdir().unwrap();
        assert!(fs::read_dir(output.path()).unwrap().next().is_none());
    }

    #[test]
    fn readiness_is_the_conjunction_of_every_reported_user_gate() {
        let ready = CapacityBenchmarkPreflight {
            schema_version: CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION,
            prerequisite_status_contract_version: CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION,
            path_contract_version: CAPACITY_PATH_CONTRACT_VERSION,
            manifest_verified: true,
            source_and_binaries_verified: true,
            material_environment_match: true,
            external_target_prerequisite_verified: true,
            composition_prerequisite_verified: true,
            prerequisite_status_contract_supported: true,
            prerequisite_lineage_link_verified: true,
            exact_profile_supported: true,
            search_policy_supported: true,
            run_plan_supported: true,
            level_ladder_supported: true,
            safe_search_ceiling_supported: true,
            headroom_safe: true,
            memory_max_safe: true,
            path_contract_supported: true,
            prepared_root_identity_verified: true,
            output_root_identity_verified: true,
            frozen_child_paths_verified: true,
            ownership_plan_supported: true,
            output_fresh: true,
            stale_resources_clear: true,
            report_lifecycle_version_supported: true,
            legacy_global_report_absent: true,
            validator_state_absent: true,
            all_non_authorization_gates_pass: true,
            user_preflight_passed: true,
            current_identity_authorized: false,
            bounded_capacity_benchmark_entry_ready: false,
            execution_ready: false,
            preflight_mutated: false,
        };
        assert!(ready.all_non_authorization_gates_pass());
        ready.verify_readiness_consistency().unwrap();
        macro_rules! reject_false_gate {
            ($($field:ident),+ $(,)?) => {
                $(
                    let mut candidate = ready.clone();
                    candidate.$field = false;
                    candidate.all_non_authorization_gates_pass = false;
                    candidate.user_preflight_passed = false;
                    assert!(!candidate.all_non_authorization_gates_pass(), stringify!($field));
                    candidate.verify_readiness_consistency().unwrap();
                )+
            };
        }
        reject_false_gate!(
            manifest_verified,
            source_and_binaries_verified,
            material_environment_match,
            external_target_prerequisite_verified,
            composition_prerequisite_verified,
            prerequisite_status_contract_supported,
            prerequisite_lineage_link_verified,
            exact_profile_supported,
            search_policy_supported,
            run_plan_supported,
            level_ladder_supported,
            safe_search_ceiling_supported,
            headroom_safe,
            memory_max_safe,
            path_contract_supported,
            prepared_root_identity_verified,
            output_root_identity_verified,
            frozen_child_paths_verified,
            ownership_plan_supported,
            output_fresh,
            stale_resources_clear,
            report_lifecycle_version_supported,
            legacy_global_report_absent,
            validator_state_absent,
        );
        let mut root_ready = ready;
        root_ready.current_identity_authorized = true;
        root_ready.bounded_capacity_benchmark_entry_ready = true;
        root_ready.execution_ready = true;
        root_ready.verify_readiness_consistency().unwrap();
        let round_trip: CapacityBenchmarkPreflight =
            serde_json::from_slice(&serde_json::to_vec(&root_ready).unwrap()).unwrap();
        round_trip.verify_readiness_consistency().unwrap();
    }

    #[test]
    fn readiness_requires_exact_sudo_uid_and_gid_independently() {
        assert!(identity_context_supported(
            true,
            0,
            0,
            Some(1000),
            Some(1000),
            1000,
            1000,
        ));
        assert!(!identity_context_supported(
            true,
            0,
            0,
            Some(1001),
            Some(1000),
            1000,
            1000,
        ));
        assert!(!identity_context_supported(
            true,
            0,
            0,
            Some(1000),
            Some(1001),
            1000,
            1000,
        ));
        assert!(identity_context_supported(
            false, 1000, 1000, None, None, 1000, 1000,
        ));
    }

    #[test]
    fn readiness_serialization_rejects_a_true_summary_with_a_false_displayed_gate() {
        let mut report = CapacityBenchmarkPreflight {
            schema_version: CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION,
            prerequisite_status_contract_version: CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION,
            path_contract_version: CAPACITY_PATH_CONTRACT_VERSION,
            manifest_verified: false,
            source_and_binaries_verified: true,
            material_environment_match: true,
            external_target_prerequisite_verified: true,
            composition_prerequisite_verified: true,
            prerequisite_status_contract_supported: true,
            prerequisite_lineage_link_verified: true,
            exact_profile_supported: true,
            search_policy_supported: true,
            run_plan_supported: true,
            level_ladder_supported: true,
            safe_search_ceiling_supported: true,
            headroom_safe: true,
            memory_max_safe: true,
            path_contract_supported: true,
            prepared_root_identity_verified: true,
            output_root_identity_verified: true,
            frozen_child_paths_verified: true,
            ownership_plan_supported: true,
            output_fresh: true,
            stale_resources_clear: true,
            report_lifecycle_version_supported: true,
            legacy_global_report_absent: true,
            validator_state_absent: true,
            all_non_authorization_gates_pass: true,
            user_preflight_passed: true,
            current_identity_authorized: true,
            bounded_capacity_benchmark_entry_ready: true,
            execution_ready: true,
            preflight_mutated: false,
        };
        let encoded = serde_json::to_vec(&report).unwrap();
        report = serde_json::from_slice(&encoded).unwrap();
        assert!(!report.all_non_authorization_gates_pass());
        assert!(report.verify_readiness_consistency().is_err());
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
        assert_eq!(CAPACITY_BENCHMARK_CONTRACT_VERSION, 1);
        assert_eq!(CAPACITY_BENCHMARK_MANIFEST_SCHEMA_VERSION, 4);
        assert_eq!(CAPACITY_BENCHMARK_PREFLIGHT_SCHEMA_VERSION, 4);
        assert_eq!(CAPACITY_BENCHMARK_EXECUTION_SCHEMA_VERSION, 3);
        assert_eq!(CAPACITY_BENCHMARK_RUN_VERSION, 3);
        assert_eq!(CAPACITY_BENCHMARK_LEVEL_VERSION, 3);
        assert_eq!(CAPACITY_PREREQUISITE_STATUS_CONTRACT_VERSION, 1);
        assert_eq!(CAPACITY_PATH_CONTRACT_VERSION, 1);
        assert_eq!(CAPACITY_EVALUATION_VERSION, 2);
        assert_eq!(CapacitySearchPolicy::v1().version, 1);
        assert_eq!(FAVORABLE_CAPACITY_TARGET_PERCENT, 30);
        assert_eq!(CAPACITY_LEVEL_TIMEOUT_MS, 30_000);
        assert_eq!(CAPACITY_RUN_TIMEOUT_MS, 280_000);
        assert_eq!(crate::pressure_worker::PRESSURE_WORKER_PROTOCOL_VERSION, 1);
        assert_eq!(
            crate::capacity_external_target::CAPACITY_EXTERNAL_TARGET_PROTOCOL_VERSION,
            1
        );
        assert_eq!(
            crate::capacity_composition::COMPOSITION_TARGET_EVIDENCE_VERSION,
            2
        );
    }

    #[test]
    fn versioning_rejects_historical_lineage2_schema_v3_as_manifest_v4() {
        let path = Path::new(
            "/home/oliver/.local/share/nemor/validation-history/phase10-capacity-benchmark-2-user-preflight-blocked/manifest.json",
        );
        if path.exists() {
            assert!(serde_json::from_slice::<PreparedCapacityBenchmarkManifest>(
                &fs::read(path).unwrap()
            )
            .is_err());
        }
        let legacy = serde_json::json!({
            "payload": {"schema_version": 3},
            "payload_sha256": "legacy"
        });
        assert!(serde_json::from_value::<PreparedCapacityBenchmarkManifest>(legacy).is_err());
    }

    #[test]
    fn versioning_manifest_v4_round_trip_preserves_new_frozen_contract_fields() {
        let path = Path::new(
            "/home/oliver/.local/share/nemor/validation-history/phase10-capacity-benchmark-2-user-preflight-blocked/manifest.json",
        );
        if !path.exists() {
            return;
        }
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let payload = value["payload"].as_object_mut().unwrap();
        payload.insert("schema_version".into(), serde_json::json!(4));
        payload.insert(
            "manifest_path".into(),
            serde_json::json!(
                "/tmp/nemor-capacity-benchmark-2-prepared/capacity-benchmark.manifest.json"
            ),
        );
        for (field, path, inode) in [
            (
                "prepared_root_identity",
                "/tmp/nemor-capacity-benchmark-2-prepared",
                1,
            ),
            (
                "output_root_identity",
                "/tmp/nemor-capacity-benchmark-2-output",
                2,
            ),
        ] {
            payload.insert(
                field.into(),
                serde_json::json!({
                    "canonical_path": path,
                    "device": 53,
                    "inode": inode,
                    "uid": 1000,
                    "gid": 1000,
                    "mode": 448
                }),
            );
        }
        for (field, kind) in [
            ("external_target_prerequisite", "external_target"),
            ("composition_prerequisite", "composition"),
        ] {
            let prerequisite = payload[field].as_object_mut().unwrap();
            prerequisite.insert("kind".into(), serde_json::json!(kind));
            prerequisite.insert("status_contract_version".into(), serde_json::json!(1));
            prerequisite.insert("status_sha256".into(), serde_json::json!("0".repeat(64)));
        }
        let manifest: PreparedCapacityBenchmarkManifest = serde_json::from_value(value).unwrap();
        let round_trip: PreparedCapacityBenchmarkManifest =
            serde_json::from_slice(&serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert_eq!(round_trip.payload.schema_version, 4);
        assert_eq!(
            round_trip.payload.external_target_prerequisite.kind,
            CapacityPrerequisiteKind::ExternalTarget
        );
        assert_eq!(round_trip.payload.prepared_root_identity.mode, 0o700);
        assert_eq!(
            round_trip.payload.manifest_path,
            Path::new("/tmp/nemor-capacity-benchmark-2-prepared/capacity-benchmark.manifest.json")
        );
    }
}
