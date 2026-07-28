use crate::harness::{CgroupHarnessPlan, HarnessOptions, ObserverLaunch};
use crate::observer_service::ObserverServiceBackend;
use crate::{
    deterministic_order, run_relative_counter_deltas, summarize, BenchmarkVariant, BuildProvenance,
    EnvironmentFingerprint, EvaluationState, EvidenceKind, StructuralSnapshot, SummaryStatistics,
    BENCHMARK_SCHEMA_VERSION, MIN_REPETITIONS,
};
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CHECKPOINT3A_SCENARIO: &str = "synthetic_compressible";
pub const CHECKPOINT3A_MAX_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
pub const CHECKPOINT3A_DEFAULT_PAYLOAD_BYTES: u64 = 128 * 1024 * 1024;
pub const CHECKPOINT3A_MIN_MEASUREMENT_MS: u64 = 20_000;
pub const CHECKPOINT3A_SAMPLE_INTERVAL_MS: u64 = 1_000;
pub const CHECKPOINT3A_STABILIZATION_MS: u64 = 2_000;
pub const CHECKPOINT3A_OBSERVER_WARMUP_MS: u64 = 5_000;
pub const CHECKPOINT3A_COOLDOWN_MS: u64 = 2_000;
pub const CHECKPOINT3A_WORKER_MARGIN_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonPurpose {
    ObserverOverhead,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PerformanceProfile {
    pub logical_payload_bytes: u64,
    pub worker_memory_max_bytes: u64,
    pub pre_measurement_hold_ms: u64,
    pub observer_warmup_ms: u64,
    pub stabilization_ms: u64,
    pub measurement_ms: u64,
    pub sample_interval_ms: u64,
    pub cooldown_ms: u64,
    pub request_oom: bool,
    pub pressure_mode: bool,
}

impl PerformanceProfile {
    pub fn checkpoint3a(payload_bytes: u64) -> Result<Self> {
        if payload_bytes == 0 || payload_bytes > CHECKPOINT3A_MAX_PAYLOAD_BYTES {
            bail!(
                "Checkpoint 3A payload must be within 1..={CHECKPOINT3A_MAX_PAYLOAD_BYTES} bytes"
            );
        }
        let profile = Self {
            logical_payload_bytes: payload_bytes,
            worker_memory_max_bytes: payload_bytes
                .checked_add(CHECKPOINT3A_WORKER_MARGIN_BYTES)
                .context("worker cgroup envelope overflow")?,
            pre_measurement_hold_ms: CHECKPOINT3A_OBSERVER_WARMUP_MS,
            observer_warmup_ms: CHECKPOINT3A_OBSERVER_WARMUP_MS,
            stabilization_ms: CHECKPOINT3A_STABILIZATION_MS,
            measurement_ms: CHECKPOINT3A_MIN_MEASUREMENT_MS,
            sample_interval_ms: CHECKPOINT3A_SAMPLE_INTERVAL_MS,
            cooldown_ms: CHECKPOINT3A_COOLDOWN_MS,
            request_oom: false,
            pressure_mode: false,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<()> {
        if self.logical_payload_bytes > CHECKPOINT3A_MAX_PAYLOAD_BYTES
            || self.worker_memory_max_bytes
                < self.logical_payload_bytes + CHECKPOINT3A_WORKER_MARGIN_BYTES
            || self.measurement_ms < CHECKPOINT3A_MIN_MEASUREMENT_MS
            || self.stabilization_ms < CHECKPOINT3A_STABILIZATION_MS
            || self.pre_measurement_hold_ms != CHECKPOINT3A_OBSERVER_WARMUP_MS
            || self.observer_warmup_ms != self.pre_measurement_hold_ms
            || self.sample_interval_ms < 250
            || self.sample_interval_ms > 5_000
            || self.request_oom
            || self.pressure_mode
        {
            bail!("unsafe Checkpoint 3A performance profile");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryIdentity {
    pub path_role: String,
    pub sha256: String,
    pub build_profile: String,
    pub source_state_id: String,
    pub embedded_git_head: String,
}

impl BinaryIdentity {
    pub fn capture(
        path_role: &str,
        path: &Path,
        source_state_id: &str,
        expected_git_head: &str,
    ) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("cannot hash {path_role} binary {}", path.display()))?;
        let marker = expected_git_head.as_bytes();
        if !bytes.windows(marker.len()).any(|window| window == marker) {
            bail!("{path_role} binary does not embed expected Git commit");
        }
        Ok(Self {
            path_role: path_role.into(),
            sha256: hex::encode(Sha256::digest(bytes)),
            build_profile: if path
                .components()
                .any(|component| component.as_os_str() == "release")
            {
                "release"
            } else {
                "unknown_or_nonrelease"
            }
            .into(),
            source_state_id: source_state_id.into(),
            embedded_git_head: expected_git_head.into(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentPlan {
    pub schema_version: u32,
    pub experiment_id: String,
    pub scenario: String,
    pub scenario_version: u32,
    pub evidence_kind: EvidenceKind,
    pub comparison_purpose: ComparisonPurpose,
    pub variants: Vec<BenchmarkVariant>,
    pub repetitions: usize,
    pub experiment_seed: u64,
    pub randomized_order: Vec<PlannedRun>,
    pub profile: PerformanceProfile,
    pub provenance: BuildProvenance,
    pub benchmark_binary: BinaryIdentity,
    pub observer_binary: BinaryIdentity,
    pub config_hash: String,
    pub environment: EnvironmentFingerprint,
    pub environment_hash: String,
    pub thermal_state_unverified: bool,
    pub performance_claim_eligible: bool,
    pub capacity_gain_percent: EvaluationState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedRun {
    pub order_index: usize,
    pub variant: BenchmarkVariant,
    pub repetition_index: usize,
    pub run_seed: u64,
    pub state: PlannedRunState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlannedRunState {
    Planned,
    Completed,
    Invalid,
    SafetyAbort,
    NotExecutedAfterAbort,
}

#[derive(Debug, Clone)]
pub struct ExperimentInputs<'a> {
    pub scenario: &'a str,
    pub variants: &'a [BenchmarkVariant],
    pub repetitions: usize,
    pub seed: u64,
    pub payload_bytes: u64,
    pub config_hash: &'a str,
    pub benchmark_binary_path: &'a Path,
    pub observer_binary_path: &'a Path,
}

pub const PREPARED_EXPERIMENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedExperimentPayload {
    pub schema_version: u32,
    pub experiment_id: String,
    pub evidence_kind: EvidenceKind,
    pub comparison_purpose: ComparisonPurpose,
    pub performance_claim_eligible: bool,
    pub preparing_uid: u32,
    pub preparing_gid: u32,
    pub repository: PathBuf,
    pub config_path: PathBuf,
    pub runner_path: PathBuf,
    pub observer_path: PathBuf,
    pub output_root: PathBuf,
    pub database_path: PathBuf,
    pub report_path: PathBuf,
    pub runs_dir: PathBuf,
    pub observer_property_contract_version: u32,
    pub observer_runs: Vec<PreparedObserveRun>,
    pub plan: ExperimentPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedObserveRun {
    pub order_index: usize,
    pub repetition_index: usize,
    pub run_id: String,
    pub service_plan: crate::observer_service::ObserverServicePlan,
    pub prepared_config_path: PathBuf,
    pub prepared_config_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedExperimentManifest {
    pub payload: PreparedExperimentPayload,
    pub payload_sha256: String,
}

impl PreparedExperimentManifest {
    pub fn verify(&self, path: &Path) -> Result<()> {
        if self.payload.schema_version != PREPARED_EXPERIMENT_SCHEMA_VERSION
            || self.payload.observer_property_contract_version
                != crate::observer_service::OBSERVER_PROPERTY_CONTRACT_VERSION
        {
            bail!("unsupported Checkpoint 3A prepared experiment manifest")
        }
        let bytes = serde_json::to_vec(&self.payload)?;
        let hash = hex::encode(Sha256::digest(bytes));
        if hash != self.payload_sha256 {
            bail!("prepared experiment manifest integrity mismatch")
        }
        let manifest_meta = fs::symlink_metadata(path)?;
        if !path.is_absolute()
            || manifest_meta.file_type().is_symlink()
            || !manifest_meta.is_file()
            || manifest_meta.nlink() != 1
            || manifest_meta.uid() != self.payload.preparing_uid
            || manifest_meta.permissions().mode() & 0o022 != 0
            || manifest_meta.len() > 2 * 1024 * 1024
        {
            bail!("prepared experiment manifest must be a regular absolute file")
        }
        let prepared_dir = path
            .parent()
            .context("prepared manifest directory missing")?;
        let prepared_meta = fs::symlink_metadata(prepared_dir)?;
        if prepared_meta.file_type().is_symlink()
            || !prepared_meta.is_dir()
            || prepared_meta.uid() != self.payload.preparing_uid
            || prepared_meta.permissions().mode() & 0o022 != 0
        {
            bail!("prepared experiment directory ownership or mode is unsafe")
        }
        self.payload.plan.profile.validate()?;
        if self.payload.plan.scenario != CHECKPOINT3A_SCENARIO
            || self.payload.plan.scenario_version != 1
            || self.payload.plan.repetitions != 3
            || self.payload.plan.variants
                != [
                    BenchmarkVariant::CachyosBaseline,
                    BenchmarkVariant::NemorObserve,
                ]
            || self.payload.plan.randomized_order.len() != 6
        {
            bail!("prepared plan is not the exact Checkpoint 3A experiment contract")
        }
        let expected_profile =
            PerformanceProfile::checkpoint3a(self.payload.plan.profile.logical_payload_bytes)?;
        if self.payload.plan.profile != expected_profile {
            bail!("prepared performance profile differs from Checkpoint 3A defaults")
        }
        let expected_order = deterministic_order(
            &self.payload.plan.variants,
            self.payload.plan.repetitions,
            self.payload.plan.experiment_seed,
        );
        if self
            .payload
            .plan
            .randomized_order
            .iter()
            .enumerate()
            .any(|(index, run)| {
                run.order_index != index
                    || expected_order.get(index) != Some(&(run.variant, run.repetition_index))
                    || run.run_seed
                        != derive_run_seed(
                            self.payload.plan.experiment_seed,
                            run.variant,
                            run.repetition_index,
                        )
            })
        {
            bail!("prepared randomized order or run seeds differ from deterministic Checkpoint 3A plan")
        }
        if !self.payload.config_path.is_absolute()
            || !self.payload.runner_path.is_absolute()
            || !self.payload.observer_path.is_absolute()
            || !self.payload.output_root.is_absolute()
            || !self.payload.database_path.is_absolute()
            || !self.payload.report_path.is_absolute()
            || !self.payload.runs_dir.is_absolute()
        {
            bail!("prepared experiment paths must be absolute")
        }
        {
            let path = &self.payload.config_path;
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != self.payload.preparing_uid
                || metadata.permissions().mode() & 0o022 != 0
                || metadata.len() == 0
                || metadata.len() > 128 * 1024 * 1024
            {
                bail!("prepared experiment input is not a regular file")
            }
        }
        for path in [&self.payload.runner_path, &self.payload.observer_path] {
            let metadata = fs::symlink_metadata(path)?;
            let filename = path.file_name().and_then(|value| value.to_str());
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != self.payload.preparing_uid
                || metadata.permissions().mode() & 0o022 != 0
                || metadata.len() == 0
                || metadata.len() > 128 * 1024 * 1024
                || path
                    .parent()
                    .and_then(|parent| parent.file_name())
                    .and_then(|value| value.to_str())
                    != Some("release")
                || !matches!(filename, Some("nemor-benchmark") | Some("nemord"))
            {
                bail!("prepared release binary role or metadata is unsafe")
            }
        }
        if self
            .payload
            .runner_path
            .file_name()
            .and_then(|value| value.to_str())
            != Some("nemor-benchmark")
            || self
                .payload
                .observer_path
                .file_name()
                .and_then(|value| value.to_str())
                != Some("nemord")
            || self.payload.runner_path.parent() != self.payload.observer_path.parent()
        {
            bail!("prepared release binary sibling roles are invalid")
        }
        if hex::encode(Sha256::digest(fs::read(&self.payload.config_path)?))
            != self.payload.plan.config_hash
            || hex::encode(Sha256::digest(fs::read(&self.payload.runner_path)?))
                != self.payload.plan.benchmark_binary.sha256
            || hex::encode(Sha256::digest(fs::read(&self.payload.observer_path)?))
                != self.payload.plan.observer_binary.sha256
        {
            bail!("prepared experiment input hash differs from frozen identity")
        }
        if self.payload.plan.benchmark_binary.embedded_git_head
            != self.payload.plan.provenance.git_head
            || self.payload.plan.observer_binary.embedded_git_head
                != self.payload.plan.provenance.git_head
        {
            bail!("prepared experiment embedded commit identity mismatch")
        }
        if self.payload.observer_runs.len()
            != self
                .payload
                .plan
                .randomized_order
                .iter()
                .filter(|run| run.variant == BenchmarkVariant::NemorObserve)
                .count()
        {
            bail!("prepared observer service plan count does not match observe repetitions")
        }
        for run in &self.payload.observer_runs {
            let planned = self
                .payload
                .plan
                .randomized_order
                .iter()
                .find(|planned| planned.order_index == run.order_index)
                .context("observer plan order is not present in frozen run order")?;
            if planned.variant != BenchmarkVariant::NemorObserve
                || planned.repetition_index != run.repetition_index
                || run.run_id
                    != format!(
                        "{}-run-{}",
                        self.payload.plan.experiment_id, run.order_index
                    )
            {
                bail!("frozen observer run mapping differs from deterministic plan")
            }
            run.service_plan.validate()?;
            if run.service_plan.runtime_max_usec <= 20_000_000 {
                bail!("performance observer service plan retained validation-only RuntimeMax")
            }
            if run.service_plan.database
                != Path::new("/run")
                    .join(&run.service_plan.runtime_directory)
                    .join("nemor-observer.sqlite")
            {
                bail!("observer database is not the frozen RuntimeDirectory database")
            }
            if hex::encode(Sha256::digest(fs::read(&run.prepared_config_path)?))
                != run.prepared_config_sha256
            {
                bail!("prepared observer config hash differs from frozen identity")
            }
            let metadata = fs::symlink_metadata(&run.prepared_config_path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != self.payload.preparing_uid
                || metadata.permissions().mode() & 0o022 != 0
            {
                bail!("prepared observer config ownership or mode is unsafe")
            }
            let loaded = common::LoadedConfig::load(&run.prepared_config_path)?;
            if loaded.config.general.database_path != run.service_plan.database {
                bail!("prepared observer config database differs from frozen service plan")
            }
        }
        if self
            .payload
            .output_root
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
            || self
                .payload
                .database_path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || self
                .payload
                .report_path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || self
                .payload
                .runs_dir
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || self.payload.database_path != self.payload.output_root.join("experiment.sqlite")
            || self.payload.report_path != self.payload.output_root.join("experiment.json")
            || self.payload.runs_dir != self.payload.output_root.join("runs")
        {
            bail!("experiment output roles do not match the prepared output root")
        }
        let output_meta = fs::symlink_metadata(&self.payload.output_root)?;
        if output_meta.file_type().is_symlink()
            || !output_meta.is_dir()
            || output_meta.uid() != self.payload.preparing_uid
            || output_meta.permissions().mode() & 0o022 != 0
        {
            bail!("prepared output root ownership or mode is unsafe")
        }
        if self.payload.plan.evidence_kind != EvidenceKind::PerformanceBenchmark
            || self.payload.plan.comparison_purpose != ComparisonPurpose::ObserverOverhead
            || self.payload.plan.variants
                != [
                    BenchmarkVariant::CachyosBaseline,
                    BenchmarkVariant::NemorObserve,
                ]
        {
            bail!("prepared experiment does not match Checkpoint 3A observer-overhead contract")
        }
        require_live_eligibility(&self.payload.plan)?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_experiment_manifest(
    repository: &Path,
    config: &Path,
    observer_binary: &Path,
    destination: &Path,
    output_root: &Path,
    seed: u64,
    payload_bytes: u64,
) -> Result<PathBuf> {
    if nix::unistd::geteuid().is_root() {
        bail!("Checkpoint 3A preparation must run unprivileged")
    }
    let repository = repository.canonicalize()?;
    if std::env::current_dir()?.canonicalize()? != repository || !repository.join(".git").exists() {
        bail!("preparation repository root is not the explicit current repository")
    }
    let config = config.canonicalize()?;
    let observer_binary = observer_binary.canonicalize()?;
    if destination.exists() {
        bail!("prepared experiment directory already exists; refusing reuse")
    }
    let loaded = common::LoadedConfig::load(&config)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let variants = [
        BenchmarkVariant::CachyosBaseline,
        BenchmarkVariant::NemorObserve,
    ];
    let inputs = ExperimentInputs {
        scenario: CHECKPOINT3A_SCENARIO,
        variants: &variants,
        repetitions: 3,
        seed,
        payload_bytes,
        config_hash: &loaded.sha256,
        benchmark_binary_path: &executable,
        observer_binary_path: &observer_binary,
    };
    let plan = plan_experiment(&inputs)?;
    if !output_root.is_absolute() || output_root.exists() {
        bail!("experiment output root must be a fresh absolute path")
    }
    let database = output_root.join("experiment.sqlite");
    let report_path = output_root.join("experiment.json");
    let runs_dir = output_root.join("runs");
    let output_root = output_root.to_path_buf();
    fs::create_dir(&output_root)?;
    fs::set_permissions(&output_root, fs::Permissions::from_mode(0o755))?;
    fs::create_dir(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o755))?;
    let observer_runs = plan
        .randomized_order
        .iter()
        .filter(|run| run.variant == BenchmarkVariant::NemorObserve)
        .map(|run| {
            let run_id = format!("{}-run-{}", plan.experiment_id, run.order_index);
            let suffix: String = run_id
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .take(32)
                .collect();
            let service_plan = crate::observer_service::ObserverServicePlan::new_with_runtime(
                &run_id,
                PathBuf::from(format!("/run/nemor-benchmark-observer-bin-{suffix}")),
                PathBuf::from(format!(
                    "/run/nemor-benchmark-observer-config-{suffix}.toml"
                )),
                performance_runtime_max_usec(&plan.profile),
            )?;
            let prepared_config_path =
                destination.join(format!("observe-{}.toml", run.order_index));
            let prepared_config_sha256 =
                write_inspection_config(&config, &service_plan.database, &prepared_config_path)?;
            observer_invariant(&common::LoadedConfig::load(&prepared_config_path)?.config)
                .validate()?;
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
    let payload = PreparedExperimentPayload {
        schema_version: PREPARED_EXPERIMENT_SCHEMA_VERSION,
        experiment_id: plan.experiment_id.clone(),
        evidence_kind: EvidenceKind::PerformanceBenchmark,
        comparison_purpose: ComparisonPurpose::ObserverOverhead,
        performance_claim_eligible: plan.performance_claim_eligible,
        preparing_uid: nix::unistd::getuid().as_raw(),
        preparing_gid: nix::unistd::getgid().as_raw(),
        repository,
        config_path: config,
        runner_path: executable,
        observer_path: observer_binary,
        output_root,
        database_path: database,
        report_path,
        runs_dir,
        observer_property_contract_version:
            crate::observer_service::OBSERVER_PROPERTY_CONTRACT_VERSION,
        observer_runs,
        plan,
    };
    let payload_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&payload)?));
    let manifest = PreparedExperimentManifest {
        payload,
        payload_sha256,
    };
    let path = destination.join("experiment.manifest.json");
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    drop(file);
    fs::write(&path, serde_json::to_vec_pretty(&manifest)?)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    Ok(path)
}

pub fn execute_prepared_experiment(manifest_path: &Path) -> Result<ExperimentOutcome> {
    if !nix::unistd::geteuid().is_root() {
        bail!("Checkpoint 3A execution requires privileged execution")
    }
    let manifest: PreparedExperimentManifest = serde_json::from_slice(&fs::read(manifest_path)?)?;
    manifest.verify(manifest_path)?;
    let payload = &manifest.payload;
    let sudo_uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .context("Checkpoint 3A execution requires sudo by the preparing user")?;
    if sudo_uid != payload.preparing_uid
        || std::env::var("SUDO_GID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            != Some(payload.preparing_gid)
    {
        bail!("sudo invoking identity differs from manifest preparing identity")
    }
    if fs::read_dir(&payload.output_root)?.next().is_some() {
        bail!("prepared output root contains unexpected pre-existing evidence")
    }
    let output_meta = fs::symlink_metadata(&payload.output_root)
        .map_err(|_| anyhow::anyhow!("prepared output root is absent"))?;
    if output_meta.file_type().is_symlink()
        || !output_meta.is_dir()
        || output_meta.uid() != payload.preparing_uid
        || output_meta.permissions().mode() & 0o022 != 0
    {
        bail!("prepared output root ownership or mode is unsafe")
    }
    if payload.database_path.exists() || payload.report_path.exists() || payload.runs_dir.exists() {
        bail!("prepared experiment database already exists; refusing evidence overwrite")
    }
    if hex::encode(Sha256::digest(fs::read(&payload.config_path)?)) != payload.plan.config_hash {
        bail!("prepared experiment config changed")
    }
    let mut backend = LiveCheckpoint3aBackend {
        config: payload.config_path.clone(),
        report_dir: payload.runs_dir.clone(),
        observer_binary: payload.observer_path.clone(),
        observer_runs: payload.observer_runs.clone(),
        output_root: payload.output_root.clone(),
    };
    let mut outcome = execute_planned_experiment(payload.plan.clone(), &mut backend)?;
    outcome.comparison =
        compare_observer_overhead(&outcome.runs, &comparison_metric_inputs(&outcome.runs)).ok();
    persist_experiment(
        &payload.database_path,
        include_str!("../../../migrations/0008_benchmark.sql"),
        include_str!("../../../migrations/0009_benchmark_performance.sql"),
        &outcome,
    )?;
    let report_bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "manifest_sha256": manifest.payload_sha256,
        "plan": &outcome.plan,
        "runs": &outcome.runs,
        "aborted_after_order": outcome.aborted_after_order,
        "comparison": &outcome.comparison,
        "capacity_gain_percent": "not_evaluated",
        "performance_claim_eligible": payload.performance_claim_eligible,
        "execution_error": outcome.execution_error
    }))?;
    let mut report_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&payload.report_path)?;
    report_file.write_all(&report_bytes)?;
    report_file.sync_all()?;
    drop(report_file);
    fs::set_permissions(&payload.report_path, fs::Permissions::from_mode(0o644))?;
    Ok(outcome)
}

pub fn preflight_prepared_experiment(manifest_path: &Path) -> Result<serde_json::Value> {
    let bytes = fs::read(manifest_path)?;
    let manifest: PreparedExperimentManifest = serde_json::from_slice(&bytes)?;
    manifest.verify(manifest_path)?;
    let payload = &manifest.payload;
    let environment = EnvironmentFingerprint::capture(&payload.plan.config_hash)?;
    let environment_match = environment.hash()? == payload.plan.environment_hash;
    let foreign = detect_nemord_processes(&payload.observer_path, None);
    let foreign_nemord_clear = reject_foreign_nemord(&foreign, None).is_ok();
    let observer_contract_supported =
        crate::observer_service::SystemdObserverServiceBackend::system()
            .and_then(|backend| backend.preflight())
            .is_ok();
    let cgroup_capable = fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
        .map(|controllers| controllers.split_whitespace().any(|v| v == "memory"))
        .unwrap_or(false);
    let output_fresh = fs::read_dir(&payload.output_root)
        .map(|entries| entries.count() == 0)
        .unwrap_or(false)
        && !payload.database_path.exists()
        && !payload.report_path.exists()
        && !payload.runs_dir.exists();
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let meminfo_value = |key: &str| {
        meminfo.lines().find_map(|line| {
            line.strip_prefix(key)?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
    };
    let available = meminfo_value("MemAvailable:")
        .unwrap_or(0)
        .saturating_mul(1024);
    let total = meminfo_value("MemTotal:").unwrap_or(0).saturating_mul(1024);
    let headroom_sufficient = CgroupHarnessPlan::checkpoint3a(
        payload.plan.profile.logical_payload_bytes,
        payload.plan.profile.worker_memory_max_bytes,
        available,
        total,
        PathBuf::from("/sys/fs/cgroup"),
        "preflight",
        payload.plan.profile.measurement_ms,
        payload.plan.profile.stabilization_ms,
    )
    .is_ok();
    let benchmark_transient_units_clear = crate::systemd::SystemdDbusBackend::system()
        .and_then(|backend| backend.list_owned_benchmark_units())
        .map(|units| units.is_empty())
        .unwrap_or(false);
    let performance_claim_eligible = payload.performance_claim_eligible;
    let release_binary_provenance_verified = true;
    let manifest_verified = true;
    let current_identity_authorized = nix::unistd::geteuid().is_root();
    Ok(serde_json::json!({
        "manifest_verified": manifest_verified,
        "release_binary_provenance_verified": true,
        "preflight_mutated": false,
        "performance_claim_eligible": payload.performance_claim_eligible,
        "foreign_nemord_clear": foreign_nemord_clear,
        "environment_match": environment_match,
        "observer_contract_supported": observer_contract_supported,
        "observer_property_contract_version": payload.observer_property_contract_version,
        "cgroup_capable": cgroup_capable,
        "headroom_sufficient": headroom_sufficient,
        "benchmark_transient_units_clear": benchmark_transient_units_clear,
        "output_fresh": output_fresh,
        "requires_privileged_execution": true,
        "current_identity_authorized": current_identity_authorized,
        "execution_ready_except_authorization": manifest_verified && release_binary_provenance_verified && performance_claim_eligible && environment_match && foreign_nemord_clear && observer_contract_supported && cgroup_capable && headroom_sufficient && benchmark_transient_units_clear && output_fresh
    }))
}

pub fn plan_experiment(inputs: &ExperimentInputs<'_>) -> Result<ExperimentPlan> {
    if inputs.scenario != CHECKPOINT3A_SCENARIO {
        bail!("Checkpoint 3A supports only synthetic_compressible");
    }
    if inputs.variants
        != [
            BenchmarkVariant::CachyosBaseline,
            BenchmarkVariant::NemorObserve,
        ]
    {
        bail!("Checkpoint 3A requires exactly cachyos_baseline,nemor_observe");
    }
    if inputs.repetitions < MIN_REPETITIONS {
        bail!("at least {MIN_REPETITIONS} repetitions per variant are required");
    }
    let provenance = BuildProvenance::capture()?;
    let benchmark_binary = BinaryIdentity::capture(
        "nemor_benchmark",
        inputs.benchmark_binary_path,
        &provenance.source_state_id,
        &provenance.git_head,
    )?;
    if benchmark_binary.sha256 != provenance.binary_sha256 {
        bail!("benchmark binary hash does not match running executable");
    }
    let observer_binary = BinaryIdentity::capture(
        "nemord",
        inputs.observer_binary_path,
        &provenance.source_state_id,
        &provenance.git_head,
    )?;
    let environment = EnvironmentFingerprint::capture(inputs.config_hash)?;
    let environment_hash = environment.hash()?;
    let randomized_order = deterministic_order(inputs.variants, inputs.repetitions, inputs.seed)
        .into_iter()
        .enumerate()
        .map(|(order_index, (variant, repetition_index))| PlannedRun {
            order_index,
            variant,
            repetition_index,
            run_seed: derive_run_seed(inputs.seed, variant, repetition_index),
            state: PlannedRunState::Planned,
        })
        .collect();
    let performance_claim_eligible = EvidenceKind::PerformanceBenchmark
        .performance_claim_eligible(&provenance)
        && provenance.build_profile == "release"
        && benchmark_binary.build_profile == "release"
        && observer_binary.build_profile == "release";
    Ok(ExperimentPlan {
        schema_version: BENCHMARK_SCHEMA_VERSION,
        experiment_id: format!("checkpoint3a-{}", now_ns()),
        scenario: inputs.scenario.into(),
        scenario_version: 1,
        evidence_kind: EvidenceKind::PerformanceBenchmark,
        comparison_purpose: ComparisonPurpose::ObserverOverhead,
        variants: inputs.variants.to_vec(),
        repetitions: inputs.repetitions,
        experiment_seed: inputs.seed,
        randomized_order,
        profile: PerformanceProfile::checkpoint3a(inputs.payload_bytes)?,
        provenance,
        benchmark_binary,
        observer_binary,
        config_hash: inputs.config_hash.into(),
        thermal_state_unverified: environment.thermal_state_unverified,
        environment,
        environment_hash,
        performance_claim_eligible,
        capacity_gain_percent: EvaluationState::NotEvaluated,
    })
}

pub fn require_live_eligibility(plan: &ExperimentPlan) -> Result<()> {
    if !plan.performance_claim_eligible
        || plan.provenance.git_dirty
        || plan.provenance.build_profile != "release"
        || plan.benchmark_binary.build_profile != "release"
        || plan.observer_binary.build_profile != "release"
        || plan.benchmark_binary.source_state_id != plan.provenance.source_state_id
        || plan.observer_binary.source_state_id != plan.provenance.source_state_id
        || plan.benchmark_binary.embedded_git_head != plan.provenance.git_head
        || plan.observer_binary.embedded_git_head != plan.provenance.git_head
    {
        bail!("performance execution requires exact clean release source and binaries");
    }
    Ok(())
}

pub fn require_validated_observer_service_boundary() -> Result<()> {
    if crate::observer_service::OBSERVER_PROPERTY_CONTRACT_VERSION != 2 {
        bail!("unsupported validated observer service contract version")
    }
    Ok(())
}

pub fn performance_runtime_max_usec(profile: &PerformanceProfile) -> u64 {
    let lifecycle_ms = 2_000u64
        .saturating_add(8_000)
        .saturating_add(profile.pre_measurement_hold_ms)
        .saturating_add(profile.stabilization_ms)
        .saturating_add(profile.measurement_ms)
        .saturating_add(8_000)
        .saturating_add(5_000)
        .saturating_add(5_000); // explicit scheduler margin; cooldown is post-stop
    lifecycle_ms.saturating_mul(1_000).clamp(
        crate::observer_service::PERFORMANCE_SERVICE_RUNTIME_MAX_USEC / 2,
        crate::observer_service::PERFORMANCE_SERVICE_RUNTIME_MAX_USEC,
    )
}

fn derive_run_seed(seed: u64, _variant: BenchmarkVariant, repetition: usize) -> u64 {
    seed.rotate_left(17) ^ repetition as u64
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectedNemorProcess {
    pub identity: ProcessIdentity,
    pub executable_matches_expected: bool,
    pub owned_by_transaction: bool,
}

pub fn reject_foreign_nemord(
    detected: &[DetectedNemorProcess],
    owned: Option<&ProcessIdentity>,
) -> Result<()> {
    if detected.iter().any(|process| {
        !process.owned_by_transaction
            || owned.is_none()
            || owned != Some(&process.identity)
            || !process.executable_matches_expected
    }) {
        bail!("foreign or ambiguous nemord process contaminates performance run");
    }
    if owned.is_none() && !detected.is_empty() {
        bail!("baseline requires no nemord observer");
    }
    if owned.is_some() && detected.len() != 1 {
        bail!("observe requires exactly one owned nemord observer");
    }
    Ok(())
}

pub fn observer_cleanup_allowed(expected: &ProcessIdentity, observed: &ProcessIdentity) -> bool {
    expected == observed
}

pub fn detect_nemord_processes(
    expected_binary: &Path,
    owned: Option<&ProcessIdentity>,
) -> Vec<DetectedNemorProcess> {
    let expected = fs::canonicalize(expected_binary).ok();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
            let comm = fs::read_to_string(entry.path().join("comm")).ok()?;
            if comm.trim() != "nemord" {
                return None;
            }
            let start_ticks = read_start_ticks(pid)?;
            let executable = fs::canonicalize(entry.path().join("exe")).ok();
            let identity = ProcessIdentity { pid, start_ticks };
            Some(DetectedNemorProcess {
                executable_matches_expected: executable == expected,
                owned_by_transaction: owned == Some(&identity),
                identity,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObserverInvariant {
    pub mode_observe: bool,
    pub automatic_actions_disabled: bool,
    pub cgroup_moves_disabled: bool,
    pub zram_mutation_disabled: bool,
    pub zswap_mutation_disabled: bool,
    pub ksm_live_apply_disabled: bool,
    pub damon_monitor_only: bool,
    pub damos_live_apply_disabled: bool,
}

impl ObserverInvariant {
    pub fn validate(&self) -> Result<()> {
        if !self.mode_observe
            || !self.automatic_actions_disabled
            || !self.cgroup_moves_disabled
            || !self.zram_mutation_disabled
            || !self.zswap_mutation_disabled
            || !self.ksm_live_apply_disabled
            || !self.damon_monitor_only
            || !self.damos_live_apply_disabled
        {
            bail!("observer configuration permits a memory-management mutation");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObserverEvidence {
    pub identity: ProcessIdentity,
    pub binary_sha256: String,
    pub config_hash: String,
    pub started_monotonic_ns: u64,
    pub measurement_started_monotonic_ns: u64,
    pub measurement_ended_monotonic_ns: u64,
    pub stopped_monotonic_ns: u64,
    pub exit_status: Option<i32>,
    pub setup_wall_seconds: f64,
    pub setup_cpu_seconds: f64,
    pub measurement_cpu_seconds: f64,
    pub measurement_cpu_percent: f64,
    pub rss_mean_bytes: Option<f64>,
    pub rss_peak_bytes: Option<u64>,
    pub pss_mean_bytes: Option<f64>,
    pub pss_peak_bytes: Option<u64>,
    pub outside_worker_scope: bool,
    pub isolated_storage_closed: bool,
    #[serde(default)]
    pub service_unit: Option<String>,
    #[serde(default)]
    pub control_group: Option<String>,
    #[serde(default)]
    pub effective_uid: Option<u32>,
    #[serde(default)]
    pub effective_gid: Option<u32>,
    #[serde(default)]
    pub settling: Option<crate::observer_service::ExecIdentitySettlingEvidence>,
    #[serde(default)]
    pub readiness_duration_seconds: Option<f64>,
}

impl ObserverEvidence {
    pub fn validate(&self, measurement_ms: u64) -> Result<()> {
        if self.measurement_started_monotonic_ns < self.started_monotonic_ns
            || self.measurement_ended_monotonic_ns <= self.measurement_started_monotonic_ns
            || self.stopped_monotonic_ns < self.measurement_ended_monotonic_ns
            || !self.outside_worker_scope
            || !self.isolated_storage_closed
            || measurement_ms < CHECKPOINT3A_MIN_MEASUREMENT_MS
        {
            bail!("invalid owned observer lifecycle evidence");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CounterSnapshot {
    pub vmstat: BTreeMap<String, u64>,
    pub psi_totals_usec: BTreeMap<String, u64>,
    pub cpu: BTreeMap<String, u64>,
    pub io: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CounterDeltas {
    pub vmstat: BTreeMap<String, u64>,
    pub psi_totals_usec: BTreeMap<String, u64>,
    pub cpu: BTreeMap<String, u64>,
    pub io: BTreeMap<String, u64>,
}

pub fn derive_performance_deltas(
    before: &CounterSnapshot,
    after: &CounterSnapshot,
) -> Result<CounterDeltas> {
    Ok(CounterDeltas {
        vmstat: run_relative_counter_deltas(&before.vmstat, &after.vmstat)?,
        psi_totals_usec: run_relative_counter_deltas(
            &before.psi_totals_usec,
            &after.psi_totals_usec,
        )?,
        cpu: run_relative_counter_deltas(&before.cpu, &after.cpu)?,
        io: run_relative_counter_deltas(&before.io, &after.io)?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEvidence {
    pub run_id: String,
    pub experiment_id: String,
    pub planned: PlannedRun,
    pub valid: bool,
    pub invalid_reason: Option<String>,
    pub safety_failure: bool,
    pub environment_hash: String,
    pub benchmark_binary_sha256: String,
    pub observer_binary_sha256: Option<String>,
    pub worker_manifest_hash: String,
    pub worker_cgroup_memory_max: u64,
    pub logical_payload_bytes: u64,
    pub measurement_ms: u64,
    pub sample_interval_ms: u64,
    pub sample_count: usize,
    pub raw_samples: Vec<crate::harness::CgroupSample>,
    pub worker_cpu_seconds: Option<f64>,
    pub worker_memory_mean_bytes: Option<f64>,
    pub worker_memory_peak_bytes: Option<u64>,
    pub runner_cpu_seconds: Option<f64>,
    pub observer: Option<ObserverEvidence>,
    pub deltas: Option<CounterDeltas>,
    pub watchdog_triggered: bool,
    pub oom: u64,
    pub oom_kill: u64,
    pub worker_integrity_valid: bool,
    pub restore_passed: bool,
    pub structural_before: StructuralSnapshot,
    pub structural_after: StructuralSnapshot,
}

impl RunEvidence {
    pub fn validate(&self, plan: &ExperimentPlan) -> Result<()> {
        if self.environment_hash != plan.environment_hash
            || self.benchmark_binary_sha256 != plan.benchmark_binary.sha256
            || self.worker_cgroup_memory_max != plan.profile.worker_memory_max_bytes
            || self.logical_payload_bytes != plan.profile.logical_payload_bytes
            || self.measurement_ms < CHECKPOINT3A_MIN_MEASUREMENT_MS
            || self.sample_count
                < usize::try_from(self.measurement_ms / self.sample_interval_ms)
                    .unwrap_or(usize::MAX)
            || self.watchdog_triggered
            || self.oom != 0
            || self.oom_kill != 0
            || !self.worker_integrity_valid
            || !self.restore_passed
            || !self.structural_before.matches(&self.structural_after)
        {
            bail!("run evidence violates Checkpoint 3A validity requirements");
        }
        match self.planned.variant {
            BenchmarkVariant::CachyosBaseline if self.observer.is_some() => {
                bail!("baseline run cannot own an observer")
            }
            BenchmarkVariant::NemorObserve => {
                let observer = self
                    .observer
                    .as_ref()
                    .context("observe run requires exact owned observer evidence")?;
                if self.observer_binary_sha256.as_deref()
                    != Some(plan.observer_binary.sha256.as_str())
                {
                    bail!("observer binary hash mismatch");
                }
                observer.validate(self.measurement_ms)?;
            }
            BenchmarkVariant::CachyosBaseline => {}
            _ => bail!("pending variant cannot execute in Checkpoint 3A"),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExperimentOutcome {
    pub plan: ExperimentPlan,
    pub runs: Vec<RunEvidence>,
    pub aborted_after_order: Option<usize>,
    pub comparison: Option<ObserverOverheadComparison>,
    pub capacity_gain_percent: EvaluationState,
    #[serde(default)]
    pub execution_error: Option<String>,
}

pub trait ExperimentRunBackend {
    fn preflight_run(&mut self, plan: &ExperimentPlan, planned: &PlannedRun) -> Result<()>;
    fn execute_run(&mut self, plan: &ExperimentPlan, planned: &PlannedRun) -> Result<RunEvidence>;
    fn verify_between_run_restore(
        &mut self,
        plan: &ExperimentPlan,
        run: &RunEvidence,
    ) -> Result<()>;
    fn cooldown(&mut self, milliseconds: u64) -> Result<()>;
}

pub fn execute_planned_experiment(
    plan: ExperimentPlan,
    backend: &mut impl ExperimentRunBackend,
) -> Result<ExperimentOutcome> {
    require_live_eligibility(&plan)?;
    let mut outcome = ExperimentOutcome {
        plan,
        runs: Vec::new(),
        aborted_after_order: None,
        comparison: None,
        capacity_gain_percent: EvaluationState::NotEvaluated,
        execution_error: None,
    };
    let planned_order = outcome.plan.randomized_order.clone();
    for planned in planned_order {
        if let Err(error) = backend.preflight_run(&outcome.plan, &planned) {
            outcome.execution_error = Some(error.to_string());
            outcome.aborted_after_order = Some(planned.order_index);
            for pending in outcome
                .plan
                .randomized_order
                .iter_mut()
                .filter(|pending| pending.order_index >= planned.order_index)
            {
                pending.state = PlannedRunState::NotExecutedAfterAbort;
            }
            break;
        }
        let mut run = match backend.execute_run(&outcome.plan, &planned) {
            Ok(run) => run,
            Err(error) => {
                outcome.execution_error = Some(error.to_string());
                outcome.aborted_after_order = Some(planned.order_index);
                for pending in outcome
                    .plan
                    .randomized_order
                    .iter_mut()
                    .filter(|pending| pending.order_index >= planned.order_index)
                {
                    pending.state = PlannedRunState::NotExecutedAfterAbort;
                }
                break;
            }
        };
        if let Err(error) = run.validate(&outcome.plan) {
            run.valid = false;
            run.invalid_reason = Some(error.to_string());
        }
        if let Err(error) = backend.verify_between_run_restore(&outcome.plan, &run) {
            run.valid = false;
            run.safety_failure = true;
            run.restore_passed = false;
            run.invalid_reason = Some(format!("between_run_restore_failed: {error}"));
        }
        let state = if run.safety_failure {
            PlannedRunState::SafetyAbort
        } else if run.valid {
            PlannedRunState::Completed
        } else {
            PlannedRunState::Invalid
        };
        run.planned.state = state;
        if let Some(stored) = outcome
            .plan
            .randomized_order
            .get_mut(run.planned.order_index)
        {
            stored.state = state;
        }
        let safety_failure = run.safety_failure;
        outcome.record_run(run);
        if safety_failure {
            break;
        }
        backend.cooldown(outcome.plan.profile.cooldown_ms)?;
    }
    Ok(outcome)
}

pub struct LiveCheckpoint3aBackend {
    pub config: PathBuf,
    pub report_dir: PathBuf,
    pub observer_binary: PathBuf,
    pub observer_runs: Vec<PreparedObserveRun>,
    pub output_root: PathBuf,
}

pub fn write_inspection_config(
    base_config: &Path,
    database: &Path,
    destination: &Path,
) -> Result<String> {
    let source = fs::read_to_string(base_config)?;
    let loaded = common::LoadedConfig::load(base_config)?;
    let original = format!(
        "database_path = \"{}\"",
        loaded.config.general.database_path.display()
    );
    let replacement = format!("database_path = \"{}\"", database.display());
    if source.matches(&original).count() != 1 {
        bail!("inspection config database path replacement is ambiguous");
    }
    fs::write(destination, source.replacen(&original, &replacement, 1))?;
    Ok(common::LoadedConfig::load(destination)?.sha256)
}

impl LiveCheckpoint3aBackend {
    fn prepared_observer_run(&self, planned: &PlannedRun) -> Result<&PreparedObserveRun> {
        self.observer_runs
            .iter()
            .find(|run| run.order_index == planned.order_index)
            .with_context(|| {
                format!(
                    "missing frozen observer plan for order {}",
                    planned.order_index
                )
            })
    }
}

impl ExperimentRunBackend for LiveCheckpoint3aBackend {
    fn preflight_run(&mut self, plan: &ExperimentPlan, _planned: &PlannedRun) -> Result<()> {
        let environment = EnvironmentFingerprint::capture(&plan.config_hash)?;
        if environment.hash()? != plan.environment_hash {
            bail!("material environment changed before repetition");
        }
        let detected = detect_nemord_processes(&self.observer_binary, None);
        reject_foreign_nemord(&detected, None)
    }

    fn execute_run(&mut self, plan: &ExperimentPlan, planned: &PlannedRun) -> Result<RunEvidence> {
        fs::create_dir_all(&self.report_dir)?;
        let run_dir = self.report_dir.join(format!(
            "{}-run-{}",
            plan.experiment_id, planned.order_index
        ));
        fs::create_dir(&run_dir)?;
        let observer = if planned.variant == BenchmarkVariant::NemorObserve {
            let frozen = self.prepared_observer_run(planned)?;
            Some(ObserverLaunch {
                binary: self.observer_binary.clone(),
                config: frozen.prepared_config_path.clone(),
                binary_sha256: plan.observer_binary.sha256.clone(),
                config_hash: frozen.prepared_config_sha256.clone(),
                warmup_ms: plan.profile.observer_warmup_ms,
                run_id: frozen.run_id.clone(),
                runtime_max_usec: frozen.service_plan.runtime_max_usec,
                service_plan: frozen.service_plan.clone(),
            })
        } else {
            None
        };
        let harness_database = run_dir.join("owned-harness.sqlite");
        let options = HarnessOptions {
            config: self.config.clone(),
            database: harness_database,
            report_dir: run_dir,
            worker_bytes: plan.profile.logical_payload_bytes,
            performance_profile: Some(plan.profile.clone()),
            observer,
            worker_seed: planned.run_seed,
        };
        let (report, _) =
            crate::harness::run_live_with_provenance(&options, Some(&plan.provenance))?;
        let deltas = report
            .samples
            .first()
            .zip(report.samples.last())
            .map(|(before, after)| derive_harness_sample_deltas(before, after))
            .transpose()?;
        let memory = report
            .samples
            .iter()
            .filter_map(|sample| sample.memory_current)
            .collect::<Vec<_>>();
        let worker_manifest_hash =
            hex::encode(Sha256::digest(serde_json::to_vec(&serde_json::json!({
                "scenario": plan.scenario,
                "scenario_version": plan.scenario_version,
                "payload": plan.profile.logical_payload_bytes,
                "memory_max": plan.profile.worker_memory_max_bytes,
                "pre_measurement_hold_ms": plan.profile.pre_measurement_hold_ms,
                "measurement_ms": plan.profile.measurement_ms,
                "sample_interval_ms": plan.profile.sample_interval_ms,
                "worker_generator_version": 1
            }))?));
        let oom = report
            .samples
            .last()
            .and_then(|sample| sample.memory_events.get("oom"))
            .copied()
            .unwrap_or(0);
        let oom_kill = report
            .samples
            .last()
            .and_then(|sample| sample.memory_events.get("oom_kill"))
            .copied()
            .unwrap_or(0);
        let observer = report.observer;
        let observer_cleanup_failed =
            planned.variant == BenchmarkVariant::NemorObserve && observer.is_none();
        let invalid_reason = report
            .observer_cleanup_error
            .clone()
            .or(report.outcome.failure_reason.clone());
        Ok(RunEvidence {
            run_id: report.run_id,
            experiment_id: plan.experiment_id.clone(),
            planned: planned.clone(),
            valid: report.outcome.required_gates_passed,
            invalid_reason,
            safety_failure: observer_cleanup_failed
                || report.observer_cleanup_error.is_some()
                || report
                    .outcome
                    .failure_class
                    .as_deref()
                    .is_some_and(|class| class == "safety_failure" || class == "cleanup_failure"),
            environment_hash: plan.environment_hash.clone(),
            benchmark_binary_sha256: plan.benchmark_binary.sha256.clone(),
            observer_binary_sha256: observer
                .as_ref()
                .map(|evidence| evidence.binary_sha256.clone()),
            worker_manifest_hash,
            worker_cgroup_memory_max: report.plan.memory_max_bytes,
            logical_payload_bytes: report.plan.worker_bytes,
            measurement_ms: report.plan.measurement_ms,
            sample_interval_ms: CHECKPOINT3A_SAMPLE_INTERVAL_MS,
            sample_count: report.sample_count,
            raw_samples: report.samples.clone(),
            worker_cpu_seconds: report.worker_cpu_seconds,
            worker_memory_mean_bytes: mean_u64(&memory),
            worker_memory_peak_bytes: memory.iter().copied().max(),
            runner_cpu_seconds: report.runner_measurement_cpu_seconds,
            observer,
            deltas,
            watchdog_triggered: report.watchdog.triggered,
            oom,
            oom_kill,
            worker_integrity_valid: report.worker_result.as_ref().is_some_and(|result| {
                result.fingerprint_valid && result.full_rewrite_passes_during_measurement == 0
            }),
            restore_passed: !observer_cleanup_failed
                && report.structural_restore_passed
                && report.outcome.required_gates_passed,
            structural_before: report.baseline,
            structural_after: report.final_snapshot,
        })
    }

    fn verify_between_run_restore(
        &mut self,
        _plan: &ExperimentPlan,
        run: &RunEvidence,
    ) -> Result<()> {
        if !run.restore_passed || !run.structural_before.matches(&run.structural_after) {
            bail!("structural restore failed");
        }
        if !detect_nemord_processes(&self.observer_binary, None).is_empty() {
            bail!("owned observer remains after repetition");
        }
        if run.planned.variant == BenchmarkVariant::NemorObserve {
            let frozen = self.prepared_observer_run(&run.planned)?;
            if Path::new("/run")
                .join(&frozen.service_plan.runtime_directory)
                .exists()
                || crate::observer_service::performance_observer_unit_exists(
                    &frozen.service_plan.unit_name,
                )?
                || frozen.service_plan.binary.exists()
                || frozen.service_plan.config.exists()
            {
                bail!("frozen observer transaction residue remains after repetition");
            }
        }
        Ok(())
    }

    fn cooldown(&mut self, milliseconds: u64) -> Result<()> {
        std::thread::sleep(std::time::Duration::from_millis(milliseconds));
        Ok(())
    }
}

pub(crate) fn observer_invariant(config: &common::Config) -> ObserverInvariant {
    ObserverInvariant {
        mode_observe: config.general.mode == "observe",
        automatic_actions_disabled: !config.general.allow_automatic_actions,
        cgroup_moves_disabled: !config.cgroups.enabled
            && config.cgroups.dry_run
            && !config.cgroups.allow_move,
        zram_mutation_disabled: config.compression.dry_run
            && !config.compression.allow_runtime_reconfigure
            && !config.compression.allow_persistent_reconfigure,
        zswap_mutation_disabled: config.tiering.dry_run
            && !config.tiering.allow_runtime_reconfigure
            && !config.tiering.allow_persistent_reconfigure
            && !config.tiering.allow_swapfile_create,
        ksm_live_apply_disabled: !config.ksm.live_apply,
        damon_monitor_only: config.damon.mode == "monitor_only",
        damos_live_apply_disabled: !config.damos.live_apply,
    }
}

fn derive_harness_sample_deltas(
    before: &crate::harness::CgroupSample,
    after: &crate::harness::CgroupSample,
) -> Result<CounterDeltas> {
    let host_counter = |sample: &crate::harness::CgroupSample, names: &[&str]| {
        sample
            .host_metrics
            .iter()
            .filter(|metric| names.contains(&metric.name.as_str()))
            .filter_map(|metric| {
                metric
                    .value
                    .and_then(|value| (value >= 0.0).then_some((metric.name.clone(), value as u64)))
            })
            .collect::<BTreeMap<_, _>>()
    };
    let psi = |sample: &crate::harness::CgroupSample| {
        let mut values = BTreeMap::new();
        if let Some(pressure) = &sample.memory_pressure {
            values.insert("worker_memory_some".into(), pressure.some.total_us);
            if let Some(full) = &pressure.full {
                values.insert("worker_memory_full".into(), full.total_us);
            }
        }
        if let Some(pressure) = &sample.host_memory_pressure {
            values.insert("host_memory_some".into(), pressure.some.total_us);
            if let Some(full) = &pressure.full {
                values.insert("host_memory_full".into(), full.total_us);
            }
        }
        values
    };
    let before_snapshot = CounterSnapshot {
        vmstat: host_counter(before, &["major_faults", "swap_in_pages", "swap_out_pages"]),
        psi_totals_usec: psi(before),
        cpu: before.cpu_stat.clone(),
        io: before.io_stat.clone().unwrap_or_default(),
    };
    let after_snapshot = CounterSnapshot {
        vmstat: host_counter(after, &["major_faults", "swap_in_pages", "swap_out_pages"]),
        psi_totals_usec: psi(after),
        cpu: after.cpu_stat.clone(),
        io: after.io_stat.clone().unwrap_or_default(),
    };
    derive_performance_deltas(&before_snapshot, &after_snapshot)
}

fn read_start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end = stat.rfind(')')?;
    stat[end + 2..].split_whitespace().nth(19)?.parse().ok()
}

fn mean_u64(values: &[u64]) -> Option<f64> {
    (!values.is_empty())
        .then(|| values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64)
}

impl ExperimentOutcome {
    pub fn record_run(&mut self, run: RunEvidence) {
        if run.safety_failure {
            self.aborted_after_order = Some(run.planned.order_index);
            for planned in self
                .plan
                .randomized_order
                .iter_mut()
                .skip(run.planned.order_index + 1)
            {
                planned.state = PlannedRunState::NotExecutedAfterAbort;
            }
        }
        self.runs.push(run);
    }

    pub fn may_continue(&self) -> bool {
        self.aborted_after_order.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserverOverheadComparison {
    pub purpose: ComparisonPurpose,
    pub baseline_valid_repetitions: usize,
    pub observe_valid_repetitions: usize,
    pub comparable: bool,
    pub invalid_reason: Option<String>,
    pub metrics: BTreeMap<String, VariantMetricComparison>,
    pub observer_metrics: BTreeMap<String, SummaryStatistics>,
    pub significance_claimed: bool,
    pub capacity_gain_percent: EvaluationState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantMetricComparison {
    pub baseline: SummaryStatistics,
    pub observe: SummaryStatistics,
    pub percent_change_observe_vs_baseline: Option<f64>,
    pub denominator: String,
    pub direction: String,
}

pub fn compare_observer_overhead(
    runs: &[RunEvidence],
    metrics: &BTreeMap<String, Vec<(String, BenchmarkVariant, f64)>>,
) -> Result<ObserverOverheadComparison> {
    let valid = runs.iter().filter(|run| run.valid).collect::<Vec<_>>();
    let baseline_valid_repetitions = valid
        .iter()
        .filter(|run| run.planned.variant == BenchmarkVariant::CachyosBaseline)
        .count();
    let observe_valid_repetitions = valid
        .iter()
        .filter(|run| run.planned.variant == BenchmarkVariant::NemorObserve)
        .count();
    if baseline_valid_repetitions < MIN_REPETITIONS || observe_valid_repetitions < MIN_REPETITIONS {
        bail!("observer-overhead comparison requires three valid runs per variant");
    }
    let environment_hashes = valid
        .iter()
        .map(|run| run.environment_hash.as_str())
        .collect::<BTreeSet<_>>();
    let worker_manifests = valid
        .iter()
        .map(|run| run.worker_manifest_hash.as_str())
        .collect::<BTreeSet<_>>();
    if environment_hashes.len() != 1 || worker_manifests.len() != 1 {
        bail!("material environment or worker manifest mismatch");
    }
    let mut paired_seeds = BTreeMap::<usize, BTreeMap<BenchmarkVariant, u64>>::new();
    for run in &valid {
        paired_seeds
            .entry(run.planned.repetition_index)
            .or_default()
            .insert(run.planned.variant, run.planned.run_seed);
    }
    if paired_seeds.len() < MIN_REPETITIONS
        || paired_seeds.values().any(|pair| {
            pair.get(&BenchmarkVariant::CachyosBaseline)
                != pair.get(&BenchmarkVariant::NemorObserve)
        })
    {
        bail!("baseline and observe repetitions do not have paired run seeds");
    }
    let mut comparisons = BTreeMap::new();
    let mut observer_metrics = BTreeMap::new();
    for (name, values) in metrics {
        let baseline = values
            .iter()
            .filter(|(_, variant, _)| *variant == BenchmarkVariant::CachyosBaseline)
            .map(|(_, _, value)| *value)
            .collect::<Vec<_>>();
        let observe = values
            .iter()
            .filter(|(_, variant, _)| *variant == BenchmarkVariant::NemorObserve)
            .map(|(_, _, value)| *value)
            .collect::<Vec<_>>();
        if baseline.is_empty() && observe.len() >= MIN_REPETITIONS {
            observer_metrics.insert(name.clone(), summarize(&observe)?);
            continue;
        }
        if baseline.len() < MIN_REPETITIONS || observe.len() < MIN_REPETITIONS {
            continue;
        }
        let baseline_summary = summarize(&baseline)?;
        let observe_summary = summarize(&observe)?;
        let percent_change = (baseline_summary.mean != 0.0).then(|| {
            (observe_summary.mean - baseline_summary.mean) / baseline_summary.mean * 100.0
        });
        comparisons.insert(
            name.clone(),
            VariantMetricComparison {
                baseline: baseline_summary,
                observe: observe_summary,
                percent_change_observe_vs_baseline: percent_change,
                denominator: "baseline arithmetic mean".into(),
                direction: "positive means observe is higher".into(),
            },
        );
    }
    Ok(ObserverOverheadComparison {
        purpose: ComparisonPurpose::ObserverOverhead,
        baseline_valid_repetitions,
        observe_valid_repetitions,
        comparable: true,
        invalid_reason: None,
        metrics: comparisons,
        observer_metrics,
        significance_claimed: false,
        capacity_gain_percent: EvaluationState::NotEvaluated,
    })
}

pub fn comparison_metric_inputs(
    runs: &[RunEvidence],
) -> BTreeMap<String, Vec<(String, BenchmarkVariant, f64)>> {
    let mut metrics: BTreeMap<String, Vec<(String, BenchmarkVariant, f64)>> = BTreeMap::new();
    for run in runs.iter().filter(|run| run.valid) {
        for (name, value) in [
            ("worker_cpu_seconds", run.worker_cpu_seconds),
            ("worker_memory_mean_bytes", run.worker_memory_mean_bytes),
            (
                "worker_memory_peak_bytes",
                run.worker_memory_peak_bytes.map(|value| value as f64),
            ),
            ("benchmark_runner_cpu_seconds", run.runner_cpu_seconds),
            (
                "observer_cpu_seconds",
                run.observer
                    .as_ref()
                    .map(|observer| observer.measurement_cpu_seconds),
            ),
            (
                "observer_rss_mean_bytes",
                run.observer
                    .as_ref()
                    .and_then(|observer| observer.rss_mean_bytes),
            ),
            (
                "observer_pss_mean_bytes",
                run.observer
                    .as_ref()
                    .and_then(|observer| observer.pss_mean_bytes),
            ),
        ] {
            if let Some(value) = value {
                metrics.entry(name.into()).or_default().push((
                    run.run_id.clone(),
                    run.planned.variant,
                    value,
                ));
            }
        }
    }
    metrics
}

pub fn persist_experiment(
    database: &Path,
    migration_0008: &str,
    migration_0009: &str,
    outcome: &ExperimentOutcome,
) -> Result<()> {
    let mut connection = Connection::open(database)?;
    connection.execute_batch("PRAGMA foreign_keys=ON;")?;
    let benchmark_schema_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='benchmark_experiments')",
        [],
        |row| row.get(0),
    )?;
    if !benchmark_schema_exists {
        connection.execute_batch(migration_0008)?;
    }
    let performance_schema_exists = connection
        .prepare("PRAGMA table_info(benchmark_experiments)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(|row| row.ok())
        .any(|name| name == "comparison_purpose");
    if !performance_schema_exists {
        connection.execute_batch(migration_0009)?;
    }
    let tx = connection.transaction()?;
    tx.execute(
        "INSERT INTO benchmark_experiments(id,scenario_id,scenario_version,seed,repetition_count,host_fingerprint_hash,nemor_commit,config_hash,evidence_kind,source_state_id,binary_sha256,development_build,performance_claim_eligible,created_at_ns,status,comparison_purpose,manifest_json,ended_at_ns,valid)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'performance_benchmark',?9,?10,?11,?12,?13,?14,'observer_overhead',?15,?16,?17)",
        params![
            outcome.plan.experiment_id,
            outcome.plan.scenario,
            outcome.plan.scenario_version,
            outcome.plan.experiment_seed as i64,
            outcome.plan.repetitions as i64,
            outcome.plan.environment_hash,
            outcome.plan.provenance.git_head,
            outcome.plan.config_hash,
            outcome.plan.provenance.source_state_id,
            outcome.plan.benchmark_binary.sha256,
            outcome.plan.provenance.development_build,
            outcome.plan.performance_claim_eligible,
            now_ns() as i64,
            if outcome.aborted_after_order.is_some() { "safety_aborted" } else { "completed" },
            serde_json::to_string(&outcome.plan)?,
            now_ns() as i64,
            outcome.comparison.as_ref().is_some_and(|comparison| comparison.comparable),
        ],
    )?;
    for planned in &outcome.plan.randomized_order {
        let actual = outcome
            .runs
            .iter()
            .find(|run| run.planned.order_index == planned.order_index);
        let run_id = actual.map(|run| run.run_id.clone()).unwrap_or_else(|| {
            format!(
                "{}-planned-{}",
                outcome.plan.experiment_id, planned.order_index
            )
        });
        let manifest = actual
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or_else(|| serde_json::to_value(planned).expect("serializable planned run"));
        tx.execute(
            "INSERT INTO benchmark_run_manifests(id,experiment_id,variant,repetition,run_order,status,valid,invalid_reason,logical_workload_bytes,physical_memory_bytes,requested_variant,resolved_variant_state,effective_state_hash,variant_diff_summary,cgroup_ownership_json,restore_evidence_json,started_monotonic_ns,ended_monotonic_ns,manifest_json,run_seed,benchmark_binary_sha256,observer_binary_sha256,config_hash)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,?3,'executable',?10,?11,?12,?13,NULL,NULL,?14,?15,?16,?17,?18)",
            params![
                run_id,
                outcome.plan.experiment_id,
                format!("{:?}", planned.variant).to_lowercase(),
                planned.repetition_index as i64,
                planned.order_index as i64,
                format!("{:?}", planned.state).to_lowercase(),
                actual.is_some_and(|run| run.valid),
                actual.and_then(|run| run.invalid_reason.clone()),
                outcome.plan.profile.logical_payload_bytes as i64,
                outcome.plan.environment_hash,
                if planned.variant == BenchmarkVariant::NemorObserve {
                    "owned observe telemetry process only"
                } else {
                    "observed CachyOS host baseline; no observer"
                },
                actual.map(|run| serde_json::to_string(&run.worker_cgroup_memory_max)).transpose()?,
                actual.map(|run| serde_json::to_string(&run.restore_passed)).transpose()?,
                serde_json::to_string(&manifest)?,
                planned.run_seed as i64,
                outcome.plan.benchmark_binary.sha256,
                (planned.variant == BenchmarkVariant::NemorObserve)
                    .then_some(outcome.plan.observer_binary.sha256.as_str()),
                outcome.plan.config_hash,
            ],
        )?;
        if let Some(run) = actual {
            for (sequence, sample) in run.raw_samples.iter().enumerate().take(4_096) {
                let mut values = Vec::new();
                values.push((
                    "worker_memory_current",
                    sample.memory_current.map(|value| value as f64),
                    "bytes",
                    "cgroup",
                    "memory.current",
                ));
                values.push((
                    "worker_memory_peak",
                    sample.memory_peak.map(|value| value as f64),
                    "bytes",
                    "cgroup",
                    "memory.peak",
                ));
                if let Some(pressure) = &sample.memory_pressure {
                    values.push((
                        "worker_memory_psi_some_avg10",
                        Some(pressure.some.avg10),
                        "percent",
                        "cgroup",
                        "memory.pressure",
                    ));
                    values.push((
                        "worker_memory_psi_some_total",
                        Some(pressure.some.total_us as f64),
                        "microseconds",
                        "cgroup",
                        "memory.pressure",
                    ));
                }
                if let Some(pressure) = &sample.host_memory_pressure {
                    values.push((
                        "host_memory_psi_some_avg10",
                        Some(pressure.some.avg10),
                        "percent",
                        "host",
                        "/proc/pressure/memory",
                    ));
                    values.push((
                        "host_memory_psi_some_total",
                        Some(pressure.some.total_us as f64),
                        "microseconds",
                        "host",
                        "/proc/pressure/memory",
                    ));
                }
                for (metric, value, unit, scope, source) in values {
                    tx.execute(
                        "INSERT INTO benchmark_samples(run_id,sequence,timestamp_monotonic_ns,phase,metric,value,unit,scope,source,available,unavailable_reason)
                         VALUES (?1,?2,?3,'measuring',?4,?5,?6,?7,?8,?9,?10)",
                        params![
                            run_id,
                            sequence as i64,
                            sample.timestamp_ns as i64,
                            metric,
                            value,
                            unit,
                            scope,
                            source,
                            value.is_some(),
                            value.is_none().then_some("provider unavailable"),
                        ],
                    )?;
                }
                for metric in &sample.host_metrics {
                    tx.execute(
                        "INSERT INTO benchmark_samples(run_id,sequence,timestamp_monotonic_ns,phase,metric,value,unit,scope,source,available,unavailable_reason)
                         VALUES (?1,?2,?3,'measuring',?4,?5,?6,'host',?7,?8,?9)",
                        params![
                            run_id,
                            sequence as i64,
                            sample.timestamp_ns as i64,
                            metric.name,
                            metric.value,
                            metric.unit,
                            metric.source,
                            metric.available,
                            metric.reason,
                        ],
                    )?;
                }
                for (prefix, source, counters) in [
                    ("worker_cpu", "cpu.stat", Some(&sample.cpu_stat)),
                    ("worker_io", "io.stat", sample.io_stat.as_ref()),
                ] {
                    for (name, value) in counters.into_iter().flatten() {
                        tx.execute(
                            "INSERT INTO benchmark_samples(run_id,sequence,timestamp_monotonic_ns,phase,metric,value,unit,scope,source,available,unavailable_reason)
                             VALUES (?1,?2,?3,'measuring',?4,?5,'kernel_native','cgroup',?6,1,NULL)",
                            params![
                                run_id,
                                sequence as i64,
                                sample.timestamp_ns as i64,
                                format!("{prefix}_{name}"),
                                *value as f64,
                                source,
                            ],
                        )?;
                    }
                }
            }
            for (metric, value, unit, scope) in [
                (
                    "worker_cpu_seconds",
                    run.worker_cpu_seconds,
                    "seconds",
                    "cgroup",
                ),
                (
                    "worker_memory_mean_bytes",
                    run.worker_memory_mean_bytes,
                    "bytes",
                    "cgroup",
                ),
                (
                    "runner_cpu_seconds",
                    run.runner_cpu_seconds,
                    "seconds",
                    "process",
                ),
                (
                    "observer_cpu_seconds",
                    run.observer
                        .as_ref()
                        .map(|observer| observer.measurement_cpu_seconds),
                    "seconds",
                    "nemor",
                ),
            ] {
                tx.execute(
                    "INSERT INTO benchmark_summaries(run_id,metric,unit,scope,summary_json)
                     VALUES (?1,?2,?3,?4,?5)",
                    params![
                        run_id,
                        metric,
                        unit,
                        scope,
                        serde_json::to_string(&serde_json::json!({
                            "value": value,
                            "available": value.is_some()
                        }))?,
                    ],
                )?;
            }
        }
    }
    if let Some(comparison) = &outcome.comparison {
        tx.execute(
            "INSERT INTO benchmark_comparisons(id,experiment_id,baseline_variant,candidate_variant,comparable,invalid_reason,comparison_json,acceptance_json,created_at_ns,comparison_purpose)
             VALUES (?1,?2,'cachyos_baseline','nemor_observe',?3,?4,?5,?6,?7,'observer_overhead')",
            params![
                format!("{}-observer-overhead", outcome.plan.experiment_id),
                outcome.plan.experiment_id,
                comparison.comparable,
                comparison.invalid_reason,
                serde_json::to_string(comparison)?,
                serde_json::to_string(&serde_json::json!({
                    "capacity_gain_percent": "not_evaluated",
                    "gaming": "not_evaluated",
                    "oom_avoided": "not_evaluated",
                    "overall_phase10": "not_evaluated"
                }))?,
                now_ns() as i64,
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
