#![forbid(unsafe_code)]
#![recursion_limit = "256"]

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod capacity_benchmark;
pub mod capacity_compatibility;
pub mod capacity_composition;
pub mod capacity_external_target;
pub mod capacity_external_validation;
pub mod capacity_orchestration;
pub mod harness;
pub mod observer_service;
pub mod performance;
pub mod pressure;
pub mod pressure_live;
pub mod pressure_prepare;
pub mod pressure_worker;
pub mod systemd;
pub mod validator_report;
pub mod validator_report_recovery;

pub const BENCHMARK_SCHEMA_VERSION: u32 = 1;
pub const MATERIAL_ENVIRONMENT_SCHEMA_VERSION: u32 = 1;
pub const MIN_REPETITIONS: usize = 3;
pub const DEFAULT_MAX_SAMPLES: usize = 4_096;
pub const SMOKE_MAX_BYTES: u64 = 32 * 1024 * 1024;
pub const HARNESS_DEFAULT_WORKER_BYTES: u64 = 64 * 1024 * 1024;
pub const HARNESS_MAX_WORKER_BYTES: u64 = 128 * 1024 * 1024;
pub const BUILD_GIT_HEAD: &str = env!("NEMOR_BUILD_GIT_HEAD");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    FrameworkSmoke,
    HarnessValidation,
    PerformanceBenchmark,
}

impl EvidenceKind {
    #[must_use]
    pub fn performance_claim_eligible(self, provenance: &BuildProvenance) -> bool {
        self == Self::PerformanceBenchmark && !provenance.git_dirty
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildProvenance {
    pub git_head: String,
    pub git_dirty: bool,
    pub source_state_id: String,
    pub binary_sha256: String,
    pub build_profile: String,
    pub benchmark_schema_version: u32,
    pub development_build: bool,
}

impl BuildProvenance {
    pub fn capture() -> Result<Self> {
        let git_head = fixed_git(&["rev-parse", "HEAD"])?;
        let status = fixed_git(&["status", "--porcelain=v1", "--untracked-files=all"])?;
        let git_dirty = BUILD_GIT_HEAD != git_head
            || status
                .lines()
                .any(|line| status_entry_is_relevant(Path::new("."), line));
        let diff = fixed_git_bytes(&["diff", "--binary", "HEAD"])?;
        let mut extra_sources = Vec::new();
        for line in status.lines() {
            let relative = line.get(3..).unwrap_or_default();
            if relative.starts_with("target/") || is_known_validation_artifact(Path::new(relative))
            {
                continue;
            }
            if line.starts_with("?? ") {
                if let Ok(bytes) = fs::read(relative) {
                    extra_sources.push((relative.to_owned(), hex::encode(Sha256::digest(bytes))));
                } else if Path::new(relative).is_dir() {
                    let mut digest = Sha256::new();
                    hash_directory(Path::new(relative), &mut digest)?;
                    extra_sources.push((relative.to_owned(), hex::encode(digest.finalize())));
                }
            }
        }
        let source_state_id = calculate_source_state_id(&git_head, &diff, &extra_sources);
        let executable = std::env::current_exe().context("cannot resolve benchmark binary")?;
        let binary_sha256 = hex::encode(Sha256::digest(
            fs::read(&executable).context("cannot hash benchmark binary")?,
        ));
        let build_profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        Ok(Self {
            git_head,
            git_dirty,
            source_state_id,
            binary_sha256,
            build_profile: build_profile.into(),
            benchmark_schema_version: BENCHMARK_SCHEMA_VERSION,
            development_build: git_dirty,
        })
    }

    #[must_use]
    pub fn clean_release_eligible(&self) -> bool {
        !self.git_dirty && self.build_profile == "release" && !self.development_build
    }
}

pub fn is_known_validation_artifact(path: &Path) -> bool {
    is_known_validation_artifact_at(Path::new("."), path)
}

pub fn is_known_validation_artifact_at(root: &Path, path: &Path) -> bool {
    if path.parent().is_some_and(|parent| parent != Path::new("")) {
        return false;
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    recognized_validation_artifact_name(name)
        && fs::read(root.join(path))
            .ok()
            .is_some_and(|bytes| validation_artifact_content_is_bounded_json(&bytes))
}

pub fn status_entry_is_relevant(root: &Path, status_line: &str) -> bool {
    let relative = status_line.get(3..).unwrap_or_default();
    !relative.starts_with("target/") && !is_known_validation_artifact_at(root, Path::new(relative))
}

pub fn recognized_validation_artifact_name(name: &str) -> bool {
    name.strip_prefix("ksm-attempt")
        .and_then(|rest| rest.strip_suffix("-report.json"))
        .is_some_and(|attempt| !attempt.is_empty() && attempt.chars().all(|c| c.is_ascii_digit()))
        || name == "phase10-checkpoint2-report.json"
        || name
            .strip_prefix("phase10-checkpoint2-attempt")
            .and_then(|rest| rest.strip_suffix("-report.json"))
            .is_some_and(|attempt| {
                !attempt.is_empty() && attempt.chars().all(|c| c.is_ascii_digit())
            })
}

pub fn validation_artifact_content_is_bounded_json(bytes: &[u8]) -> bool {
    bytes.len() <= 16 * 1024 * 1024
        && serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|value| value.is_object())
}

pub fn calculate_source_state_id(
    git_head: &str,
    tracked_diff: &[u8],
    extra_sources: &[(String, String)],
) -> String {
    let mut digest = Sha256::new();
    digest.update(git_head.as_bytes());
    digest.update(tracked_diff);
    let mut sources = extra_sources.to_vec();
    sources.sort();
    for (name, content_hash) in sources {
        digest.update(name.as_bytes());
        digest.update(content_hash.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn fixed_git(arguments: &[&str]) -> Result<String> {
    Ok(String::from_utf8(fixed_git_bytes(arguments)?)?
        .trim()
        .to_owned())
}

fn fixed_git_bytes(arguments: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("/usr/bin/git")
        .args(arguments)
        .output()
        .context("cannot execute fixed git provenance command")?;
    if !output.status.success() {
        bail!("git provenance command failed");
    }
    Ok(output.stdout)
}

fn hash_directory(path: &Path, digest: &mut Sha256) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(path)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        if path.file_name().is_some_and(|name| name == "target") {
            continue;
        }
        digest.update(path.to_string_lossy().as_bytes());
        if path.is_dir() {
            hash_directory(&path, digest)?;
        } else {
            digest.update(Sha256::digest(fs::read(path)?));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioId {
    BrowserManyTabs,
    GamingBackground,
    CompileRustCpp,
    IdeContainers,
    MultipleVms,
    SyntheticCompressible,
    SyntheticIncompressible,
    ProgressiveMemoryPressure,
}

impl ScenarioId {
    pub const ALL: [Self; 8] = [
        Self::BrowserManyTabs,
        Self::GamingBackground,
        Self::CompileRustCpp,
        Self::IdeContainers,
        Self::MultipleVms,
        Self::SyntheticCompressible,
        Self::SyntheticIncompressible,
        Self::ProgressiveMemoryPressure,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::BrowserManyTabs => "browser_many_tabs",
            Self::GamingBackground => "gaming_background",
            Self::CompileRustCpp => "compile_rust_cpp",
            Self::IdeContainers => "ide_containers",
            Self::MultipleVms => "multiple_vms",
            Self::SyntheticCompressible => "synthetic_compressible",
            Self::SyntheticIncompressible => "synthetic_incompressible",
            Self::ProgressiveMemoryPressure => "progressive_memory_pressure",
        }
    }
}

impl std::str::FromStr for ScenarioId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|item| item.as_str() == value)
            .with_context(|| format!("unknown benchmark scenario {value:?}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomationLevel {
    AutomaticOwned,
    ManualCooperative,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadSource {
    Synthetic,
    ManualExternal,
    OwnedProcess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioDefinition {
    pub scenario_id: ScenarioId,
    pub schema_version: u32,
    pub scenario_version: u32,
    pub category: String,
    pub description: String,
    pub workload_source: WorkloadSource,
    pub automation_level: AutomationLevel,
    pub required_capabilities: Vec<String>,
    pub supported_variants: Vec<BenchmarkVariant>,
    pub warmup_ms: u64,
    pub stabilization_ms: u64,
    pub measurement_interval_ms: u64,
    pub maximum_duration_ms: u64,
    pub cooldown_ms: u64,
    pub repetition_count: usize,
    pub logical_workload_unit: String,
    pub load_level_definition: String,
    pub stop_conditions: Vec<String>,
    pub safety_limits: BTreeMap<String, f64>,
    pub required_metrics: Vec<String>,
    pub optional_metrics: Vec<String>,
    pub manual_preparation: Vec<String>,
    pub manual_completion_criteria: Vec<String>,
    pub freeze_watchdog_threshold_ms: Option<u64>,
}

pub fn required_scenarios() -> Vec<ScenarioDefinition> {
    use AutomationLevel::{AutomaticOwned, ManualCooperative};
    use BenchmarkVariant::{CachyosBaseline, NemorCapacity, NemorGaming, NemorObserve, NemorSafe};
    use ScenarioId::*;
    use WorkloadSource::{ManualExternal, OwnedProcess, Synthetic};
    let common = vec![CachyosBaseline, NemorObserve, NemorSafe];
    vec![
        scenario(
            BrowserManyTabs,
            "interactive",
            ManualExternal,
            ManualCooperative,
            common.clone(),
            "tab_workload_unit",
        ),
        scenario(
            GamingBackground,
            "gaming",
            ManualExternal,
            ManualCooperative,
            vec![CachyosBaseline, NemorObserve, NemorGaming],
            "background_workload_unit",
        ),
        scenario(
            CompileRustCpp,
            "cpu_bound",
            OwnedProcess,
            AutomaticOwned,
            common.clone(),
            "fixture_scale",
        ),
        scenario(
            IdeContainers,
            "development",
            ManualExternal,
            ManualCooperative,
            common.clone(),
            "container_workload_unit",
        ),
        scenario(
            MultipleVms,
            "virtualization",
            ManualExternal,
            ManualCooperative,
            vec![CachyosBaseline, NemorObserve, NemorSafe, NemorCapacity],
            "configured_guest_byte",
        ),
        scenario(
            SyntheticCompressible,
            "synthetic",
            Synthetic,
            AutomaticOwned,
            vec![CachyosBaseline, NemorObserve, NemorSafe, NemorCapacity],
            "declared_prefaulted_byte",
        ),
        scenario(
            SyntheticIncompressible,
            "synthetic",
            Synthetic,
            AutomaticOwned,
            vec![CachyosBaseline, NemorObserve, NemorSafe, NemorCapacity],
            "declared_prefaulted_byte",
        ),
        scenario(
            ProgressiveMemoryPressure,
            "capacity",
            Synthetic,
            AutomaticOwned,
            vec![CachyosBaseline, NemorObserve, NemorSafe, NemorCapacity],
            "tested_load_level",
        ),
    ]
}

fn scenario(
    id: ScenarioId,
    category: &str,
    source: WorkloadSource,
    automation: AutomationLevel,
    variants: Vec<BenchmarkVariant>,
    unit: &str,
) -> ScenarioDefinition {
    let external = matches!(source, WorkloadSource::ManualExternal);
    ScenarioDefinition {
        scenario_id: id,
        schema_version: BENCHMARK_SCHEMA_VERSION,
        scenario_version: 1,
        category: category.to_owned(),
        description: format!("Versioned {} benchmark", id.as_str()),
        workload_source: source,
        automation_level: automation,
        required_capabilities: if id == ScenarioId::ProgressiveMemoryPressure {
            vec![
                "cgroup_v2".into(),
                "memory_controller".into(),
                "privileged_harness".into(),
            ]
        } else {
            vec!["procfs".into(), "psi_memory".into()]
        },
        supported_variants: variants,
        warmup_ms: 5_000,
        stabilization_ms: 5_000,
        measurement_interval_ms: 500,
        maximum_duration_ms: 300_000,
        cooldown_ms: 5_000,
        repetition_count: MIN_REPETITIONS,
        logical_workload_unit: unit.to_owned(),
        load_level_definition: "explicit tested level; never inferred from RSS".into(),
        stop_conditions: vec![
            "workload_complete".into(),
            "timeout".into(),
            "safety_abort".into(),
        ],
        safety_limits: BTreeMap::from([("max_duration_ms".into(), 300_000.0)]),
        required_metrics: vec!["memory".into(), "psi".into(), "cpu".into(), "faults".into()],
        optional_metrics: vec!["energy".into(), "frametime".into()],
        manual_preparation: if external {
            vec!["operator starts the declared workload without exposing content".into()]
        } else {
            vec![]
        },
        manual_completion_criteria: if external {
            vec!["operator supplies ready and completion markers".into()]
        } else {
            vec![]
        },
        freeze_watchdog_threshold_ms: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkVariant {
    CachyosBaseline,
    NemorObserve,
    NemorSafe,
    NemorGaming,
    NemorCapacity,
    Zram,
    Zswap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    Available,
    Unavailable,
    PendingValidation,
    Incompatible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantAvailability {
    pub variant: BenchmarkVariant,
    pub state: AvailabilityState,
    pub reason: Option<String>,
    pub requires_reboot: bool,
}

pub fn default_variant_availability() -> Vec<VariantAvailability> {
    use AvailabilityState::{Available, PendingValidation};
    use BenchmarkVariant::*;
    [CachyosBaseline, NemorObserve]
    .into_iter()
    .map(|variant| VariantAvailability {
        variant,
        state: Available,
        reason: None,
        requires_reboot: false,
    })
    .chain([NemorSafe, NemorGaming, NemorCapacity].into_iter().map(|variant| {
        VariantAvailability {
            variant,
            state: PendingValidation,
            reason: Some("no validated Phase 10 execution orchestration".into()),
            requires_reboot: false,
        }
    }))
    .chain(std::iter::once(VariantAvailability {
        variant: Zram,
        state: PendingValidation,
        reason: Some(
            "host baseline may already contain the same zram state; effective resolution required"
                .into(),
        ),
        requires_reboot: false,
    }))
    .chain(std::iter::once(VariantAvailability {
        variant: Zswap,
        state: PendingValidation,
        reason: Some("Phase 6 boot zswap+NVMe validation is pending".into()),
        requires_reboot: true,
    }))
    .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedVariantState {
    Executable,
    Alias,
    PendingValidation,
    Unavailable,
    Incompatible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantResolution {
    pub requested_variant: BenchmarkVariant,
    pub resolved_variant_state: ResolvedVariantState,
    pub effective_state_hash: String,
    pub availability: AvailabilityState,
    pub reason: Option<String>,
    pub variant_diff_summary: String,
    pub observer_overhead_only: bool,
}

#[derive(Debug, Clone)]
pub struct VariantResolutionContext {
    pub baseline_state: BTreeMap<String, String>,
    pub observe_executable: bool,
    pub safe_executable: bool,
    pub gaming_executable: bool,
    pub capacity_executable: bool,
    pub distinct_zram_configuration: Option<BTreeMap<String, String>>,
    pub zswap_boot_validated: bool,
}

pub fn resolve_variant(
    variant: BenchmarkVariant,
    context: &VariantResolutionContext,
) -> VariantResolution {
    let baseline_hash = hash_map(&context.baseline_state);
    let pending = |reason: &str| VariantResolution {
        requested_variant: variant,
        resolved_variant_state: ResolvedVariantState::PendingValidation,
        effective_state_hash: baseline_hash.clone(),
        availability: AvailabilityState::PendingValidation,
        reason: Some(reason.into()),
        variant_diff_summary: "no executable validated state transition".into(),
        observer_overhead_only: false,
    };
    match variant {
        BenchmarkVariant::CachyosBaseline => VariantResolution {
            requested_variant: variant,
            resolved_variant_state: ResolvedVariantState::Executable,
            effective_state_hash: baseline_hash,
            availability: AvailabilityState::Available,
            reason: None,
            variant_diff_summary: "host baseline; no Nemor process".into(),
            observer_overhead_only: false,
        },
        BenchmarkVariant::NemorObserve if context.observe_executable => {
            let mut state = context.baseline_state.clone();
            state.insert("nemord".into(), "observe".into());
            VariantResolution {
                requested_variant: variant,
                resolved_variant_state: ResolvedVariantState::Executable,
                effective_state_hash: hash_map(&state),
                availability: AvailabilityState::Available,
                reason: None,
                variant_diff_summary: "nemord observe instrumentation only".into(),
                observer_overhead_only: true,
            }
        }
        BenchmarkVariant::NemorObserve => pending("observe orchestration unavailable"),
        BenchmarkVariant::NemorSafe if context.safe_executable => executable_profile(
            variant,
            &context.baseline_state,
            "validated Nemor safe orchestration",
        ),
        BenchmarkVariant::NemorSafe => pending("safe orchestration pending validation"),
        BenchmarkVariant::NemorGaming if context.gaming_executable => executable_profile(
            variant,
            &context.baseline_state,
            "validated Nemor gaming orchestration",
        ),
        BenchmarkVariant::NemorGaming => pending("gaming orchestration pending validation"),
        BenchmarkVariant::NemorCapacity if context.capacity_executable => executable_profile(
            variant,
            &context.baseline_state,
            "validated Nemor capacity orchestration",
        ),
        BenchmarkVariant::NemorCapacity => pending("capacity orchestration pending validation"),
        BenchmarkVariant::Zram => match &context.distinct_zram_configuration {
            Some(state) if hash_map(state) != baseline_hash => VariantResolution {
                requested_variant: variant,
                resolved_variant_state: ResolvedVariantState::PendingValidation,
                effective_state_hash: hash_map(state),
                availability: AvailabilityState::PendingValidation,
                reason: Some("distinct zram transition is not validated for Phase 10".into()),
                variant_diff_summary: "proposed distinct zram configuration".into(),
                observer_overhead_only: false,
            },
            _ => VariantResolution {
                requested_variant: variant,
                resolved_variant_state: ResolvedVariantState::Alias,
                effective_state_hash: baseline_hash,
                availability: AvailabilityState::Incompatible,
                reason: Some("host baseline already contains the effective zram state".into()),
                variant_diff_summary: "no effective difference from cachyos_baseline".into(),
                observer_overhead_only: false,
            },
        },
        BenchmarkVariant::Zswap if context.zswap_boot_validated => pending(
            "zswap boot state validated but Phase 10 transition orchestration is unavailable",
        ),
        BenchmarkVariant::Zswap => pending("Phase 6 zswap+NVMe boot validation is pending"),
    }
}

fn executable_profile(
    variant: BenchmarkVariant,
    baseline: &BTreeMap<String, String>,
    summary: &str,
) -> VariantResolution {
    let mut state = baseline.clone();
    state.insert("nemor_profile".into(), format!("{variant:?}"));
    VariantResolution {
        requested_variant: variant,
        resolved_variant_state: ResolvedVariantState::Executable,
        effective_state_hash: hash_map(&state),
        availability: AvailabilityState::Available,
        reason: None,
        variant_diff_summary: summary.into(),
        observer_overhead_only: false,
    }
}

fn hash_map(values: &BTreeMap<String, String>) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(values).expect("string map serialization"),
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariantComparisonValidity {
    pub valid: bool,
    pub reason: Option<String>,
    pub variant_diff_summary: String,
}

pub fn validate_variant_comparison(
    baseline: &VariantResolution,
    candidate: &VariantResolution,
    observer_overhead_comparison: bool,
) -> VariantComparisonValidity {
    if baseline.resolved_variant_state != ResolvedVariantState::Executable
        || candidate.resolved_variant_state != ResolvedVariantState::Executable
    {
        return VariantComparisonValidity {
            valid: false,
            reason: Some("variant_not_executable".into()),
            variant_diff_summary: candidate.variant_diff_summary.clone(),
        };
    }
    if baseline.effective_state_hash == candidate.effective_state_hash {
        return VariantComparisonValidity {
            valid: false,
            reason: Some("equivalent_effective_state".into()),
            variant_diff_summary: "no relevant effective state difference".into(),
        };
    }
    if candidate.observer_overhead_only && !observer_overhead_comparison {
        return VariantComparisonValidity {
            valid: false,
            reason: Some("observer_overhead_scope_required".into()),
            variant_diff_summary: candidate.variant_diff_summary.clone(),
        };
    }
    VariantComparisonValidity {
        valid: true,
        reason: None,
        variant_diff_summary: candidate.variant_diff_summary.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Created,
    Preflight,
    Warmup,
    Stabilizing,
    Measuring,
    Cooldown,
    Restoring,
    Completed,
    Invalid,
    Aborted,
    SafetyAbort,
    Failed,
}

impl RunState {
    pub fn transition(self, next: Self) -> Result<Self> {
        let allowed = matches!(
            (self, next),
            (Self::Created, Self::Preflight)
                | (Self::Preflight, Self::Warmup)
                | (Self::Warmup, Self::Stabilizing)
                | (Self::Stabilizing, Self::Measuring)
                | (Self::Measuring, Self::Cooldown)
                | (Self::Cooldown, Self::Restoring)
                | (Self::Restoring, Self::Completed)
                | (
                    _,
                    Self::Invalid | Self::Aborted | Self::SafetyAbort | Self::Failed
                )
        );
        if !allowed {
            bail!("illegal benchmark state transition {self:?} -> {next:?}");
        }
        Ok(next)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricScope {
    Host,
    Cgroup,
    Process,
    Nemor,
    KernelHelper,
    Workload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricValue {
    pub name: String,
    pub value: Option<f64>,
    pub unit: String,
    pub scope: MetricScope,
    pub source: String,
    pub available: bool,
    pub reason: Option<String>,
    pub semantics: String,
}

impl MetricValue {
    pub fn measured(name: &str, value: f64, unit: &str, scope: MetricScope, source: &str) -> Self {
        Self {
            name: name.into(),
            value: Some(value),
            unit: unit.into(),
            scope,
            source: source.into(),
            available: true,
            reason: None,
            semantics: "direct observation".into(),
        }
    }

    pub fn unavailable(
        name: &str,
        unit: &str,
        scope: MetricScope,
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
            semantics: "missing is not zero".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsiSnapshot {
    pub some: PsiLine,
    pub full: Option<PsiLine>,
}

pub fn parse_psi(input: &str) -> Result<PsiSnapshot> {
    let mut some = None;
    let mut full = None;
    for line in input.lines() {
        let mut words = line.split_whitespace();
        let kind = words.next().context("PSI line has no kind")?;
        let mut fields = BTreeMap::new();
        for word in words {
            let (key, value) = word.split_once('=').context("invalid PSI field")?;
            fields.insert(key, value);
        }
        let parsed = PsiLine {
            avg10: parse_field(&fields, "avg10")?,
            avg60: parse_field(&fields, "avg60")?,
            avg300: parse_field(&fields, "avg300")?,
            total_us: fields.get("total").context("missing PSI total")?.parse()?,
        };
        match kind {
            "some" => some = Some(parsed),
            "full" => full = Some(parsed),
            _ => bail!("unknown PSI category {kind}"),
        }
    }
    Ok(PsiSnapshot {
        some: some.context("missing PSI some line")?,
        full,
    })
}

fn parse_field(fields: &BTreeMap<&str, &str>, key: &str) -> Result<f64> {
    Ok(fields
        .get(key)
        .with_context(|| format!("missing {key}"))?
        .parse()?)
}

pub fn parse_key_u64(input: &str) -> BTreeMap<String, u64> {
    input
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            Some((
                parts.next()?.trim_end_matches(':').into(),
                parts.next()?.parse().ok()?,
            ))
        })
        .collect()
}

pub fn checked_counter_delta(before: u64, after: u64) -> Result<u64> {
    after
        .checked_sub(before)
        .context("counter decreased or wrapped")
}

/// Derive the only counter form eligible for performance summaries.
///
/// Raw snapshots remain useful evidence, but boot/session-absolute cumulative
/// counters must never be compared directly across A/B runs.
pub fn run_relative_counter_deltas(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
) -> Result<BTreeMap<String, u64>> {
    if before.keys().ne(after.keys()) {
        bail!("counter snapshots have different fields");
    }
    before
        .iter()
        .map(|(name, value)| Ok((name.clone(), checked_counter_delta(*value, after[name])?)))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapEntry {
    pub kind: String,
    pub size_kib: u64,
    pub used_kib: u64,
    pub priority: i64,
}

pub fn parse_swaps(input: &str) -> Result<Vec<SwapEntry>> {
    input
        .lines()
        .skip(1)
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 5 {
                bail!("invalid /proc/swaps row");
            }
            Ok(SwapEntry {
                kind: fields[1].into(),
                size_kib: fields[2].parse()?,
                used_kib: fields[3].parse()?,
                priority: fields[4].parse()?,
            })
        })
        .collect()
}

pub fn parse_cgroup_key_values(input: &str) -> Result<BTreeMap<String, u64>> {
    let mut values = BTreeMap::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let key = fields.next().context("missing cgroup metric key")?;
        let value = fields.next().context("missing cgroup metric value")?;
        if fields.next().is_some() {
            bail!("unexpected cgroup scalar fields");
        }
        values.insert(key.into(), value.parse()?);
    }
    Ok(values)
}

pub fn parse_io_stat(input: &str) -> Result<BTreeMap<String, u64>> {
    let mut totals = BTreeMap::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let _device = fields.next().context("missing io.stat device")?;
        for field in fields {
            let (key, value) = field.split_once('=').context("invalid io.stat field")?;
            *totals.entry(key.into()).or_default() += value.parse::<u64>()?;
        }
    }
    Ok(totals)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadOnlyMetrics {
    pub timestamp_ns: u64,
    pub values: Vec<MetricValue>,
}

pub fn collect_read_only_metrics() -> ReadOnlyMetrics {
    let mut values = Vec::new();
    let meminfo = fs::read_to_string("/proc/meminfo")
        .ok()
        .map(|value| parse_key_u64(&value));
    for (field, metric) in [
        ("MemAvailable", "memory_available"),
        ("MemTotal", "memory_total"),
    ] {
        values.push(
            meminfo
                .as_ref()
                .and_then(|map| map.get(field))
                .map(|value| {
                    MetricValue::measured(
                        metric,
                        (*value * 1024) as f64,
                        "bytes",
                        MetricScope::Host,
                        "/proc/meminfo",
                    )
                })
                .unwrap_or_else(|| {
                    MetricValue::unavailable(
                        metric,
                        "bytes",
                        MetricScope::Host,
                        "/proc/meminfo",
                        "field unavailable",
                    )
                }),
        );
    }
    let vmstat = fs::read_to_string("/proc/vmstat")
        .ok()
        .map(|value| parse_key_u64(&value));
    for (field, metric) in [
        ("pgmajfault", "major_faults"),
        ("pswpin", "swap_in_pages"),
        ("pswpout", "swap_out_pages"),
    ] {
        values.push(
            vmstat
                .as_ref()
                .and_then(|map| map.get(field))
                .map(|value| {
                    let mut metric = MetricValue::measured(
                        metric,
                        *value as f64,
                        "count",
                        MetricScope::Host,
                        "/proc/vmstat",
                    );
                    metric.semantics =
                        "raw monotonic cumulative counter; derive run-relative delta for summaries"
                            .into();
                    metric
                })
                .unwrap_or_else(|| {
                    MetricValue::unavailable(
                        metric,
                        "count",
                        MetricScope::Host,
                        "/proc/vmstat",
                        "field unavailable",
                    )
                }),
        );
    }
    for (name, path) in [
        ("ksm_pages_sharing", "/sys/kernel/mm/ksm/pages_sharing"),
        ("ksm_general_profit", "/sys/kernel/mm/ksm/general_profit"),
        ("zram_compr_data_size", "/sys/block/zram0/mm_stat"),
    ] {
        let scalar = read_trim(path).and_then(|text| {
            text.split_whitespace()
                .next()
                .and_then(|value| value.parse::<f64>().ok())
        });
        values.push(
            scalar
                .map(|value| {
                    MetricValue::measured(name, value, "kernel_native", MetricScope::Host, path)
                })
                .unwrap_or_else(|| {
                    MetricValue::unavailable(
                        name,
                        "kernel_native",
                        MetricScope::Host,
                        path,
                        "provider unavailable",
                    )
                }),
        );
    }
    ReadOnlyMetrics {
        timestamp_ns: now_ns(),
        values,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryStatistics {
    pub count: usize,
    pub mean: f64,
    pub median: f64,
    pub minimum: f64,
    pub maximum: f64,
    pub standard_deviation: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
}

pub fn summarize(values: &[f64]) -> Result<SummaryStatistics> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        bail!("statistics require finite non-empty input");
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let variance = sorted
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / sorted.len() as f64;
    Ok(SummaryStatistics {
        count: sorted.len(),
        mean,
        median: percentile(&sorted, 0.5),
        minimum: sorted[0],
        maximum: sorted[sorted.len() - 1],
        standard_deviation: variance.sqrt(),
        p50: percentile(&sorted, 0.5),
        p95: percentile(&sorted, 0.95),
        p99: percentile(&sorted, 0.99),
    })
}

fn percentile(sorted: &[f64], percentile: f64) -> f64 {
    let index = ((sorted.len() - 1) as f64 * percentile).ceil() as usize;
    sorted[index]
}

pub fn capacity_comparison(baseline: u64, candidate: u64) -> Result<(f64, f64)> {
    if baseline == 0 {
        bail!("baseline sustainable capacity must be non-zero");
    }
    let ratio = candidate as f64 / baseline as f64;
    Ok((ratio, (ratio - 1.0) * 100.0))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunValue {
    pub run_id: String,
    pub valid: bool,
    pub invalid_reason: Option<String>,
    pub value: Option<f64>,
}

pub fn aggregate_runs(runs: &[RunValue]) -> Result<(SummaryStatistics, usize)> {
    let valid: Vec<f64> = runs
        .iter()
        .filter(|run| run.valid)
        .filter_map(|run| run.value)
        .collect();
    if valid.len() < MIN_REPETITIONS {
        bail!("at least {MIN_REPETITIONS} valid repetitions are required");
    }
    Ok((summarize(&valid)?, runs.len() - valid.len()))
}

#[derive(Debug, Clone)]
pub struct EvidenceRun {
    pub evidence_kind: EvidenceKind,
    pub run: RunValue,
}

pub fn aggregate_performance_runs(runs: &[EvidenceRun]) -> Result<(SummaryStatistics, usize)> {
    if runs
        .iter()
        .any(|run| run.evidence_kind != EvidenceKind::PerformanceBenchmark)
    {
        bail!("non-performance evidence cannot enter a performance aggregate");
    }
    aggregate_runs(&runs.iter().map(|run| run.run.clone()).collect::<Vec<_>>())
}

pub fn deterministic_order(
    variants: &[BenchmarkVariant],
    repetitions: usize,
    seed: u64,
) -> Vec<(BenchmarkVariant, usize)> {
    let mut items: Vec<_> = (0..repetitions)
        .flat_map(|rep| variants.iter().copied().map(move |variant| (variant, rep)))
        .collect();
    let mut state = seed;
    for index in (1..items.len()).rev() {
        state = splitmix64(state);
        items.swap(index, state as usize % (index + 1));
    }
    items
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut mixed = value;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentFingerprint {
    pub schema_version: u32,
    pub nemor_commit: String,
    pub nemor_version: String,
    pub config_hash: String,
    pub kernel_release: String,
    pub distro_id: String,
    pub distro_version: String,
    pub cpu_model: String,
    pub logical_cpus: usize,
    pub total_ram_bytes: u64,
    pub swap_topology: Vec<String>,
    pub zram_inventory: Vec<String>,
    pub zswap_state: String,
    pub root_filesystem: String,
    pub storage_class: String,
    pub gpu_identity: Option<String>,
    pub cgroup_v2: bool,
    pub psi: bool,
    pub damon: bool,
    pub ksm: bool,
    pub ksm_run: Option<u64>,
    pub cpu_governor: Option<String>,
    pub power_profile: Option<String>,
    pub thermal_sensor_available: bool,
    pub energy_provider: Option<String>,
    pub thermal_state_unverified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaterialEnvironmentFingerprint {
    pub schema_version: u32,
    pub config_hash: String,
    pub kernel_release: String,
    pub distro_id: String,
    pub distro_version: String,
    pub cpu_model: String,
    pub logical_cpus: usize,
    pub total_ram_bytes: u64,
    pub swap_topology: Vec<String>,
    pub zram_inventory: Vec<String>,
    pub zswap_state: String,
    pub root_filesystem: String,
    pub storage_class: String,
    pub gpu_identity: Option<String>,
    pub cgroup_v2: bool,
    pub psi: bool,
    pub damon: bool,
    pub ksm: bool,
    pub ksm_run: Option<u64>,
    pub cpu_governor: Option<String>,
    pub power_profile: Option<String>,
}

impl EnvironmentFingerprint {
    pub fn capture(config_hash: &str) -> Result<Self> {
        Self::capture_with_commit(config_hash, None)
    }

    pub fn capture_for_performance(config_hash: &str, frozen_commit: &str) -> Result<Self> {
        Self::capture_with_commit(config_hash, Some(frozen_commit))
    }

    fn capture_with_commit(config_hash: &str, frozen_commit: Option<&str>) -> Result<Self> {
        let os = parse_os_release(&fs::read_to_string("/etc/os-release").unwrap_or_default());
        let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let cpu_model = cpuinfo
            .lines()
            .find_map(|line| {
                line.strip_prefix("model name")
                    .and_then(|v| v.split_once(':'))
                    .map(|(_, v)| v.trim().to_owned())
            })
            .unwrap_or_else(|| "unknown".into());
        let mem = parse_key_u64(&fs::read_to_string("/proc/meminfo").unwrap_or_default());
        let swap_topology = fs::read_to_string("/proc/swaps")
            .unwrap_or_default()
            .lines()
            .skip(1)
            .map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                format!(
                    "type={} size_kib={} priority={}",
                    fields.get(1).unwrap_or(&"?"),
                    fields.get(2).unwrap_or(&"?"),
                    fields.get(4).unwrap_or(&"?")
                )
            })
            .collect();
        let mut zram_inventory = Vec::new();
        if let Ok(entries) = fs::read_dir("/sys/block") {
            for name in entries
                .flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
            {
                if name.starts_with("zram") {
                    zram_inventory.push(name);
                }
            }
        }
        zram_inventory.sort();
        let commit = frozen_commit
            .map(str::to_owned)
            .or_else(|| read_git_head(Path::new(".")))
            .unwrap_or_else(|| "unknown".into());
        let ksm_run = fs::read_to_string("/sys/kernel/mm/ksm/run")
            .ok()
            .and_then(|v| v.trim().parse().ok());
        let governor = fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
            .ok()
            .map(|v| v.trim().into());
        let energy = has_energy_counter("/sys/class/powercap").then(|| "powercap".into());
        Ok(Self {
            schema_version: BENCHMARK_SCHEMA_VERSION,
            nemor_commit: commit,
            nemor_version: env!("CARGO_PKG_VERSION").into(),
            config_hash: config_hash.into(),
            kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap_or_else(|_| "unknown".into())
                .trim()
                .into(),
            distro_id: os.get("ID").cloned().unwrap_or_else(|| "unknown".into()),
            distro_version: os
                .get("VERSION_ID")
                .cloned()
                .unwrap_or_else(|| "unknown".into()),
            cpu_model,
            logical_cpus: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
            total_ram_bytes: mem
                .get("MemTotal")
                .copied()
                .unwrap_or(0)
                .saturating_mul(1024),
            swap_topology,
            zram_inventory,
            zswap_state: read_trim("/sys/module/zswap/parameters/enabled")
                .unwrap_or_else(|| "unavailable".into()),
            root_filesystem: root_filesystem().unwrap_or_else(|| "unknown".into()),
            storage_class: detect_storage_class(),
            gpu_identity: detect_gpu(),
            cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
            psi: Path::new("/proc/pressure/memory").is_file(),
            damon: Path::new("/sys/kernel/mm/damon").exists(),
            ksm: Path::new("/sys/kernel/mm/ksm").exists(),
            ksm_run,
            cpu_governor: governor,
            power_profile: read_trim("/sys/firmware/acpi/platform_profile"),
            thermal_sensor_available: Path::new("/sys/class/thermal").is_dir(),
            energy_provider: energy,
            thermal_state_unverified: true,
        })
    }

    pub fn hash(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    pub fn material(&self) -> MaterialEnvironmentFingerprint {
        MaterialEnvironmentFingerprint {
            schema_version: MATERIAL_ENVIRONMENT_SCHEMA_VERSION,
            config_hash: self.config_hash.clone(),
            kernel_release: self.kernel_release.clone(),
            distro_id: self.distro_id.clone(),
            distro_version: self.distro_version.clone(),
            cpu_model: self.cpu_model.clone(),
            logical_cpus: self.logical_cpus,
            total_ram_bytes: self.total_ram_bytes,
            swap_topology: self.swap_topology.clone(),
            zram_inventory: self.zram_inventory.clone(),
            zswap_state: self.zswap_state.clone(),
            root_filesystem: self.root_filesystem.clone(),
            storage_class: self.storage_class.clone(),
            gpu_identity: self.gpu_identity.clone(),
            cgroup_v2: self.cgroup_v2,
            psi: self.psi,
            damon: self.damon,
            ksm: self.ksm,
            ksm_run: self.ksm_run,
            cpu_governor: self.cpu_governor.clone(),
            power_profile: self.power_profile.clone(),
        }
    }

    pub fn material_hash(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(serde_json::to_vec(
            &self.material(),
        )?)))
    }

    pub fn material_diff(&self, other: &Self) -> Result<Vec<String>> {
        let left = self.material();
        let right = other.material();
        let mut differences = Vec::new();
        macro_rules! compare {
            ($field:ident) => {
                if left.$field != right.$field {
                    differences.push(stringify!($field).to_owned());
                }
            };
        }
        compare!(schema_version);
        compare!(config_hash);
        compare!(kernel_release);
        compare!(distro_id);
        compare!(distro_version);
        compare!(cpu_model);
        compare!(logical_cpus);
        compare!(total_ram_bytes);
        compare!(swap_topology);
        compare!(zram_inventory);
        compare!(zswap_state);
        compare!(root_filesystem);
        compare!(storage_class);
        compare!(gpu_identity);
        compare!(cgroup_v2);
        compare!(psi);
        compare!(damon);
        compare!(ksm);
        compare!(ksm_run);
        compare!(cpu_governor);
        compare!(power_profile);
        Ok(differences)
    }

    pub fn comparable_with(&self, other: &Self) -> Result<()> {
        let differences = self.material_diff(other)?;
        if !differences.is_empty() {
            bail!(
                "material host fingerprint mismatch: {}",
                differences.join(", ")
            );
        }
        Ok(())
    }
}

fn parse_os_release(input: &str) -> BTreeMap<String, String> {
    input
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.into(), value.trim_matches('"').into()))
        })
        .collect()
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn read_git_head(root: &Path) -> Option<String> {
    let head = fs::read_to_string(root.join(".git/HEAD")).ok()?;
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref: ") {
        fs::read_to_string(root.join(".git").join(reference))
            .ok()
            .map(|v| v.trim().into())
    } else {
        Some(head.into())
    }
}

fn root_filesystem() -> Option<String> {
    fs::read_to_string("/proc/mounts")
        .ok()?
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.get(1) == Some(&"/"))
                .then(|| format!("source={} type={}", fields[0], fields[2]))
        })
}

fn detect_storage_class() -> String {
    if Path::new("/sys/class/nvme").exists() {
        "nvme_present".into()
    } else {
        "non_nvme_or_unknown".into()
    }
}

fn detect_gpu() -> Option<String> {
    let root = Path::new("/sys/class/drm");
    let entries = fs::read_dir(root).ok()?;
    let count = entries
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("card"))
        .count();
    (count > 0).then(|| format!("drm_cards={count}"))
}

fn has_energy_counter(root: &str) -> bool {
    fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            let path = entry.path();
            path.join("energy_uj").exists()
                || fs::read_dir(path)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .any(|child| child.path().join("energy_uj").exists())
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralSnapshot {
    /// Raw read-only evidence.  It is never used directly for restore equality.
    pub swaps: String,
    pub swap_topology: Vec<SwapTopologyEntry>,
    pub swap_runtime_used_kib: BTreeMap<String, u64>,
    pub zram_configuration: BTreeMap<String, String>,
    pub zram_runtime: BTreeMap<String, String>,
    pub zswap_enabled: Option<String>,
    pub ksm_configuration: BTreeMap<String, String>,
    pub damon_tree_shape: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SwapTopologyEntry {
    pub identity: String,
    pub kind: String,
    pub size_kib: u64,
    pub priority: i32,
}

pub fn parse_swap_snapshot(input: &str) -> Result<(Vec<SwapTopologyEntry>, BTreeMap<String, u64>)> {
    let mut topology = Vec::new();
    let mut runtime = BTreeMap::new();
    for line in input.lines().skip(1).filter(|line| !line.trim().is_empty()) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 {
            bail!("invalid /proc/swaps row");
        }
        let identity = fields[0].to_owned();
        topology.push(SwapTopologyEntry {
            identity: identity.clone(),
            kind: fields[1].to_owned(),
            size_kib: fields[2].parse()?,
            priority: fields[4].parse()?,
        });
        runtime.insert(identity, fields[3].parse()?);
    }
    topology.sort();
    Ok((topology, runtime))
}

fn capture_zram_state() -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut configuration = BTreeMap::new();
    let mut runtime = BTreeMap::new();
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return (configuration, runtime);
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("zram") {
            continue;
        }
        let path = entry.path();
        for field in ["disksize", "comp_algorithm", "mem_limit"] {
            if let Ok(value) = fs::read_to_string(path.join(field)) {
                configuration.insert(format!("{name}.{field}"), value.trim().into());
            }
        }
        for field in ["mm_stat", "stat", "io_stat", "bd_stat"] {
            if let Ok(value) = fs::read_to_string(path.join(field)) {
                runtime.insert(format!("{name}.{field}"), value.trim().into());
            }
        }
    }
    (configuration, runtime)
}

impl StructuralSnapshot {
    pub fn capture() -> Self {
        let ksm_configuration = [
            "run",
            "pages_to_scan",
            "sleep_millisecs",
            "advisor_mode",
            "merge_across_nodes",
            "use_zero_pages",
            "max_page_sharing",
            "stable_node_chains_prune_millisecs",
        ]
        .into_iter()
        .filter_map(|name| {
            read_trim(&format!("/sys/kernel/mm/ksm/{name}")).map(|value| (name.into(), value))
        })
        .collect();
        let swaps = fs::read_to_string("/proc/swaps").unwrap_or_default();
        let (swap_topology, swap_runtime_used_kib) =
            parse_swap_snapshot(&swaps).unwrap_or_default();
        let (zram_configuration, zram_runtime) = capture_zram_state();
        Self {
            swaps,
            swap_topology,
            swap_runtime_used_kib,
            zram_configuration,
            zram_runtime,
            zswap_enabled: read_trim("/sys/module/zswap/parameters/enabled"),
            ksm_configuration,
            damon_tree_shape: directory_names("/sys/kernel/mm/damon/admin/kdamonds"),
        }
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.swap_topology == other.swap_topology
            && self.zram_configuration == other.zram_configuration
            && self.zswap_enabled == other.zswap_enabled
            && self.ksm_configuration == other.ksm_configuration
            && self.damon_tree_shape == other.damon_tree_shape
    }

    pub fn runtime_counter_deltas(&self, other: &Self) -> BTreeMap<String, i128> {
        let mut deltas = BTreeMap::new();
        for identity in self
            .swap_runtime_used_kib
            .keys()
            .chain(other.swap_runtime_used_kib.keys())
        {
            let before = self
                .swap_runtime_used_kib
                .get(identity)
                .copied()
                .unwrap_or(0);
            let after = other
                .swap_runtime_used_kib
                .get(identity)
                .copied()
                .unwrap_or(0);
            deltas.insert(
                format!("swap_used_kib:{identity}"),
                i128::from(after) - i128::from(before),
            );
        }
        deltas
    }
}

fn directory_names(path: &str) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticPattern {
    Compressible,
    Incompressible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticEvidence {
    pub pattern: SyntheticPattern,
    pub seed: u64,
    pub logical_bytes: u64,
    pub touched_bytes: u64,
    pub pages: usize,
    pub fingerprint: String,
    pub encoded_sanity_bytes: usize,
    pub heartbeat_count: u64,
    pub integrity_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticWorkerPhase {
    Allocating,
    Generating,
    Prefaulting,
    Ready,
    Stabilizing,
    Measuring,
    Stopping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTiming {
    pub phase: SyntheticWorkerPhase,
    pub wall_seconds: f64,
    pub cpu_seconds: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticCpuAccounting {
    pub setup: Vec<PhaseTiming>,
    pub measurement_worker_cpu_seconds: Option<f64>,
    pub benchmark_runner_cpu_seconds: Option<f64>,
    pub nemord_cpu_seconds: Option<f64>,
    pub kernel_helper_cpu_seconds: Option<f64>,
    pub measurement_started_after_ready_and_stabilization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SteadyWorkerState {
    pub allocation_bytes: u64,
    pub full_generation_passes: u64,
    pub full_prefault_passes: u64,
    pub heartbeat_count: u64,
    pub bounded_integrity_pages_checked: u64,
    pub full_rewrite_passes_during_measurement: u64,
}

impl SteadyWorkerState {
    pub fn validate(&self) -> Result<()> {
        if self.allocation_bytes == 0
            || self.full_generation_passes != 1
            || self.full_prefault_passes != 1
            || self.heartbeat_count == 0
            || self.full_rewrite_passes_during_measurement != 0
        {
            bail!("synthetic worker did not remain in bounded steady state");
        }
        Ok(())
    }
}

pub fn run_synthetic(
    pattern: SyntheticPattern,
    bytes: u64,
    seed: u64,
) -> Result<(SyntheticEvidence, Vec<u8>)> {
    if bytes == 0 || bytes > SMOKE_MAX_BYTES {
        bail!("synthetic smoke allocation must be within 1..={SMOKE_MAX_BYTES} bytes");
    }
    let page_size = 4096usize;
    let length = usize::try_from(bytes)?;
    let mut data = vec![0u8; length];
    for (index, byte) in data.iter_mut().enumerate() {
        *byte = match pattern {
            SyntheticPattern::Compressible => {
                ((index / page_size + seed as usize) % 4) as u8 * 0x11
            }
            SyntheticPattern::Incompressible => synthetic_byte(pattern, seed, index),
        };
    }
    let fingerprint = hex::encode(Sha256::digest(&data));
    let evidence = SyntheticEvidence {
        pattern,
        seed,
        logical_bytes: bytes,
        touched_bytes: bytes,
        pages: length.div_ceil(page_size),
        fingerprint: fingerprint.clone(),
        encoded_sanity_bytes: rle_size(&data),
        heartbeat_count: 1,
        integrity_valid: hex::encode(Sha256::digest(&data)) == fingerprint,
    };
    Ok((evidence, data))
}

pub fn synthetic_byte(pattern: SyntheticPattern, seed: u64, index: usize) -> u8 {
    match pattern {
        SyntheticPattern::Compressible => ((index / 4096 + seed as usize) % 4) as u8 * 0x11,
        SyntheticPattern::Incompressible => {
            splitmix64(seed ^ index as u64).to_le_bytes()[index % 8]
        }
    }
}

fn rle_size(data: &[u8]) -> usize {
    if data.is_empty() {
        return 0;
    }
    let mut runs = 1usize;
    for pair in data.windows(2) {
        if pair[0] != pair[1] {
            runs += 1;
        }
    }
    runs.saturating_mul(2)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuResolution {
    pub clk_tck: u64,
    pub tick_seconds: f64,
    pub window_seconds: f64,
    pub tick_delta: u64,
    pub cpu_seconds: f64,
    pub cpu_percent: f64,
    pub resolution_percent: f64,
}

pub fn cpu_observation(
    clk_tck: u64,
    tick_delta: u64,
    window_seconds: f64,
) -> Result<CpuResolution> {
    if clk_tck == 0 || window_seconds <= 0.0 {
        bail!("CLK_TCK and observation window must be positive");
    }
    let tick_seconds = 1.0 / clk_tck as f64;
    let cpu_seconds = tick_delta as f64 * tick_seconds;
    Ok(CpuResolution {
        clk_tck,
        tick_seconds,
        window_seconds,
        tick_delta,
        cpu_seconds,
        cpu_percent: 100.0 * cpu_seconds / window_seconds,
        resolution_percent: 100.0 * tick_seconds / window_seconds,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrametimeSummary {
    pub provider: String,
    pub clock_domain: String,
    pub unit: String,
    pub sample_count: usize,
    pub mean_ms: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub one_percent_low_fps: f64,
}

pub fn summarize_frametimes(provider: &str, samples_ms: &[f64]) -> Result<FrametimeSummary> {
    let stats = summarize(samples_ms)?;
    let mut descending = samples_ms.to_vec();
    descending.sort_by(|a, b| b.total_cmp(a));
    let worst_count = descending.len().div_ceil(100).max(1);
    let worst_mean = descending[..worst_count].iter().sum::<f64>() / worst_count as f64;
    Ok(FrametimeSummary {
        provider: provider.into(),
        clock_domain: "provider_declared".into(),
        unit: "milliseconds".into(),
        sample_count: samples_ms.len(),
        mean_ms: stats.mean,
        p50_ms: stats.p50,
        p95_ms: stats.p95,
        p99_ms: stats.p99,
        one_percent_low_fps: 1000.0 / worst_mean,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OomOutcome {
    None,
    HostOom,
    ControlledCgroupOom,
    ApplicationCrash,
    AllocationFailure,
    BenchmarkAbort,
}

impl OomOutcome {
    pub fn safety_failure(self) -> bool {
        self == Self::HostOom
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrashingThresholds {
    pub psi_full_avg10: f64,
    pub major_faults_per_second: f64,
    pub swap_in_pages_per_second: f64,
    pub swap_out_pages_per_second: f64,
    pub response_latency_ms: f64,
}

pub fn detect_thrashing(
    values: &BTreeMap<String, f64>,
    limits: &ThrashingThresholds,
) -> (bool, Vec<String>) {
    let tests = [
        ("psi_full_avg10", limits.psi_full_avg10),
        ("major_faults_per_second", limits.major_faults_per_second),
        ("swap_in_pages_per_second", limits.swap_in_pages_per_second),
        (
            "swap_out_pages_per_second",
            limits.swap_out_pages_per_second,
        ),
        ("response_latency_ms", limits.response_latency_ms),
    ];
    let reasons: Vec<_> = tests
        .into_iter()
        .filter(|(name, limit)| values.get(*name).copied().unwrap_or(0.0) > *limit)
        .map(|(name, _)| name.into())
        .collect();
    (reasons.len() >= 4, reasons)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationState {
    Pass,
    Fail,
    NotEvaluated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceResult {
    pub favorable_capacity: EvaluationState,
    pub gaming_capacity: EvaluationState,
    pub cpu_bound: EvaluationState,
    pub gaming_frametime: EvaluationState,
    pub incompressible_regression: EvaluationState,
    pub restore: EvaluationState,
}

pub fn evaluate_threshold(value: Option<f64>, threshold: f64, at_least: bool) -> EvaluationState {
    match value {
        None => EvaluationState::NotEvaluated,
        Some(value) if (at_least && value >= threshold) || (!at_least && value <= threshold) => {
            EvaluationState::Pass
        }
        Some(_) => EvaluationState::Fail,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub schema_version: u32,
    pub evidence_kind: EvidenceKind,
    pub provenance: BuildProvenance,
    pub performance_claim_eligible: bool,
    pub run_id: String,
    pub scenario: ScenarioDefinition,
    pub variant: BenchmarkVariant,
    pub variant_resolution: VariantResolution,
    pub repetition: usize,
    pub seed: u64,
    pub run_order: usize,
    pub state: RunState,
    pub valid: bool,
    pub invalid_reason: Option<String>,
    pub environment: EnvironmentFingerprint,
    pub environment_hash: String,
    pub metrics: Vec<MetricValue>,
    pub synthetic: Option<SyntheticEvidence>,
    pub synthetic_cpu: Option<SyntheticCpuAccounting>,
    pub logical_workload_bytes: u64,
    pub physical_memory_bytes: Option<u64>,
    pub restore_verified: bool,
    pub limitations: Vec<String>,
    pub acceptance: AcceptanceResult,
    pub started_monotonic_ns: u64,
    pub ended_monotonic_ns: u64,
}

pub struct BenchmarkStore {
    connection: Connection,
    max_samples: usize,
}

impl BenchmarkStore {
    pub fn create(path: &Path, migration: &str, max_samples: usize) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA foreign_keys=ON;")?;
        connection.execute_batch(migration)?;
        Ok(Self {
            connection,
            max_samples,
        })
    }

    pub fn open_read_only(path: &Path) -> Result<Self> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        Ok(Self {
            connection,
            max_samples: DEFAULT_MAX_SAMPLES,
        })
    }

    pub fn persist_smoke(&mut self, report: &BenchmarkReport) -> Result<()> {
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT INTO benchmark_experiments(id,scenario_id,scenario_version,seed,repetition_count,host_fingerprint_hash,nemor_commit,config_hash,evidence_kind,source_state_id,binary_sha256,development_build,performance_claim_eligible,created_at_ns,status)
             VALUES (?1,?2,?3,?4,1,?5,?6,?7,?8,?9,?10,?11,?12,?13,'checkpoint_smoke')",
            params![format!("experiment-{}", report.run_id), report.scenario.scenario_id.as_str(), report.scenario.scenario_version, report.seed as i64, report.environment_hash, report.environment.nemor_commit, report.environment.config_hash, evidence_kind_name(report.evidence_kind), report.provenance.source_state_id, report.provenance.binary_sha256, report.provenance.development_build, report.performance_claim_eligible, now_ns() as i64],
        )?;
        tx.execute(
            "INSERT INTO benchmark_run_manifests(id,experiment_id,variant,repetition,run_order,status,valid,invalid_reason,logical_workload_bytes,physical_memory_bytes,requested_variant,resolved_variant_state,effective_state_hash,variant_diff_summary,cgroup_ownership_json,restore_evidence_json,started_monotonic_ns,ended_monotonic_ns,manifest_json)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,NULL,?15,?16,?17,?18)",
            params![
                report.run_id,
                format!("experiment-{}", report.run_id),
                format!("{:?}", report.variant).to_lowercase(),
                report.repetition as i64,
                report.run_order as i64,
                format!("{:?}", report.state).to_lowercase(),
                report.valid,
                report.invalid_reason,
                report.logical_workload_bytes as i64,
                report.physical_memory_bytes.map(|v| v as i64),
                format!("{:?}", report.variant).to_lowercase(),
                format!("{:?}", report.variant_resolution.resolved_variant_state).to_lowercase(),
                report.variant_resolution.effective_state_hash,
                report.variant_resolution.variant_diff_summary,
                serde_json::to_string(&serde_json::json!({"restore_verified": report.restore_verified}))?,
                report.started_monotonic_ns as i64,
                report.ended_monotonic_ns as i64,
                serde_json::to_string(report)?,
            ],
        )?;
        for (sequence, metric) in report.metrics.iter().take(self.max_samples).enumerate() {
            tx.execute(
                "INSERT INTO benchmark_samples(run_id,sequence,timestamp_monotonic_ns,phase,metric,value,unit,scope,source,available,unavailable_reason)
                 VALUES (?1,?2,?3,'measuring',?4,?5,?6,?7,?8,?9,?10)",
                params![report.run_id, sequence as i64, report.ended_monotonic_ns as i64, metric.name, metric.value, metric.unit, format!("{:?}", metric.scope).to_lowercase(), metric.source, metric.available, metric.reason],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn list_summaries(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let mut statement = self.connection.prepare(
            "SELECT manifest_json FROM benchmark_run_manifests ORDER BY ended_monotonic_ns DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit as i64], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    pub fn report(&self, run_id: &str) -> Result<serde_json::Value> {
        let raw: String = self.connection.query_row(
            "SELECT manifest_json FROM benchmark_run_manifests WHERE id=?1",
            [run_id],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn experiment_runs(&self, experiment_id: &str) -> Result<Vec<serde_json::Value>> {
        let mut statement = self.connection.prepare(
            "SELECT manifest_json FROM benchmark_run_manifests
             WHERE experiment_id=?1 ORDER BY run_order",
        )?;
        let rows = statement.query_map([experiment_id], |row| row.get::<_, String>(0))?;
        rows.map(|row| Ok(serde_json::from_str(&row?)?)).collect()
    }

    pub fn comparison(&self, experiment_id: &str) -> Result<serde_json::Value> {
        let raw: String = self.connection.query_row(
            "SELECT comparison_json FROM benchmark_comparisons
             WHERE experiment_id=?1 ORDER BY created_at_ns DESC LIMIT 1",
            [experiment_id],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn latest(&self) -> Result<serde_json::Value> {
        let raw: String = self.connection.query_row(
            "SELECT manifest_json FROM benchmark_run_manifests ORDER BY ended_monotonic_ns DESC LIMIT 1",
            [],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&raw)?)
    }
}

fn evidence_kind_name(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::FrameworkSmoke => "framework_smoke",
        EvidenceKind::HarnessValidation => "harness_validation",
        EvidenceKind::PerformanceBenchmark => "performance_benchmark",
    }
}

pub fn safe_smoke(
    scenario_id: ScenarioId,
    bytes: u64,
    seed: u64,
    database: &Path,
    report_dir: &Path,
) -> Result<(BenchmarkReport, PathBuf)> {
    let pattern = match scenario_id {
        ScenarioId::SyntheticCompressible => SyntheticPattern::Compressible,
        ScenarioId::SyntheticIncompressible => SyntheticPattern::Incompressible,
        _ => bail!("Checkpoint 1 smoke supports only owned synthetic scenarios"),
    };
    let mem_available = parse_key_u64(&fs::read_to_string("/proc/meminfo")?)
        .get("MemAvailable")
        .copied()
        .unwrap_or(0)
        .saturating_mul(1024);
    if bytes.saturating_mul(4) > mem_available {
        bail!("insufficient safety headroom for bounded smoke allocation");
    }
    let before = StructuralSnapshot::capture();
    let start = Instant::now();
    let started_ns = monotonic_ns(start, start);
    let (synthetic, data) = run_synthetic(pattern, bytes, seed)?;
    let psi = fs::read_to_string("/proc/pressure/memory")
        .ok()
        .and_then(|value| parse_psi(&value).ok());
    let physical = process_rss_bytes();
    let mut metrics = vec![
        MetricValue::measured(
            "logical_workload_bytes",
            bytes as f64,
            "bytes",
            MetricScope::Workload,
            "owned_synthetic",
        ),
        physical
            .map(|value| {
                MetricValue::measured(
                    "runner_rss",
                    value as f64,
                    "bytes",
                    MetricScope::Process,
                    "/proc/self/status",
                )
            })
            .unwrap_or_else(|| {
                MetricValue::unavailable(
                    "runner_rss",
                    "bytes",
                    MetricScope::Process,
                    "/proc/self/status",
                    "VmRSS unavailable",
                )
            }),
        psi.and_then(|value| value.full.map(|line| line.avg10))
            .map(|value| {
                MetricValue::measured(
                    "psi_memory_full_avg10",
                    value,
                    "percent",
                    MetricScope::Host,
                    "/proc/pressure/memory",
                )
            })
            .unwrap_or_else(|| {
                MetricValue::unavailable(
                    "psi_memory_full_avg10",
                    "percent",
                    MetricScope::Host,
                    "/proc/pressure/memory",
                    "full PSI unavailable",
                )
            }),
        MetricValue::unavailable(
            "energy",
            "joules",
            MetricScope::Host,
            "powercap",
            "optional provider not sampled in smoke",
        ),
        MetricValue::unavailable(
            "frametime_p95",
            "milliseconds",
            MetricScope::Workload,
            "external_import",
            "no frametime provider attached",
        ),
    ];
    metrics.extend(collect_read_only_metrics().values);
    metrics.push(MetricValue::measured(
        "runner_wall_time",
        start.elapsed().as_secs_f64(),
        "seconds",
        MetricScope::Process,
        "CLOCK_MONOTONIC",
    ));
    std::hint::black_box(&data);
    drop(data);
    let after = StructuralSnapshot::capture();
    let definition = required_scenarios()
        .into_iter()
        .find(|item| item.scenario_id == scenario_id)
        .context("scenario registry incomplete")?;
    let environment = EnvironmentFingerprint::capture("checkpoint-smoke")?;
    let environment_hash = environment.hash()?;
    let run_id = format!("smoke-{}-{}-{}", scenario_id.as_str(), seed, now_ns());
    let provenance = BuildProvenance::capture()?;
    let variant_resolution = resolve_variant(
        BenchmarkVariant::CachyosBaseline,
        &VariantResolutionContext {
            baseline_state: BTreeMap::from([
                ("zram".into(), environment.zram_inventory.join(",")),
                ("zswap".into(), environment.zswap_state.clone()),
            ]),
            observe_executable: true,
            safe_executable: false,
            gaming_executable: false,
            capacity_executable: false,
            distinct_zram_configuration: None,
            zswap_boot_validated: false,
        },
    );
    let report = BenchmarkReport {
        schema_version: BENCHMARK_SCHEMA_VERSION,
        evidence_kind: EvidenceKind::FrameworkSmoke,
        performance_claim_eligible: EvidenceKind::FrameworkSmoke
            .performance_claim_eligible(&provenance),
        provenance,
        run_id,
        scenario: definition,
        variant: BenchmarkVariant::CachyosBaseline,
        variant_resolution,
        repetition: 0,
        seed,
        run_order: 0,
        state: RunState::Completed,
        valid: true,
        invalid_reason: None,
        environment,
        environment_hash,
        metrics,
        synthetic: Some(synthetic),
        synthetic_cpu: Some(SyntheticCpuAccounting {
            setup: vec![
                PhaseTiming {
                    phase: SyntheticWorkerPhase::Generating,
                    wall_seconds: start.elapsed().as_secs_f64(),
                    cpu_seconds: None,
                },
                PhaseTiming {
                    phase: SyntheticWorkerPhase::Prefaulting,
                    wall_seconds: 0.0,
                    cpu_seconds: None,
                },
            ],
            measurement_worker_cpu_seconds: None,
            benchmark_runner_cpu_seconds: None,
            nemord_cpu_seconds: None,
            kernel_helper_cpu_seconds: None,
            measurement_started_after_ready_and_stabilization: true,
        }),
        logical_workload_bytes: bytes,
        physical_memory_bytes: physical,
        restore_verified: before.matches(&after),
        limitations: vec![
            "instrumentation smoke only; no capacity claim".into(),
            "no privileged or production memory mechanism activated".into(),
        ],
        acceptance: AcceptanceResult {
            favorable_capacity: EvaluationState::NotEvaluated,
            gaming_capacity: EvaluationState::NotEvaluated,
            cpu_bound: EvaluationState::NotEvaluated,
            gaming_frametime: EvaluationState::NotEvaluated,
            incompressible_regression: EvaluationState::NotEvaluated,
            restore: if before.matches(&after) {
                EvaluationState::Pass
            } else {
                EvaluationState::Fail
            },
        },
        started_monotonic_ns: started_ns,
        ended_monotonic_ns: monotonic_ns(start, Instant::now()),
    };
    fs::create_dir_all(report_dir)?;
    let report_path = report_dir.join(format!("{}.json", report.run_id));
    fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    let migration = include_str!("../../../migrations/0008_benchmark.sql");
    let mut store = BenchmarkStore::create(database, migration, DEFAULT_MAX_SAMPLES)?;
    store.persist_smoke(&report)?;
    Ok((report, report_path))
}

fn process_rss_bytes() -> Option<u64> {
    parse_key_u64(&fs::read_to_string("/proc/self/status").ok()?)
        .get("VmRSS")
        .copied()
        .map(|value| value * 1024)
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_nanos() as u64
}

fn monotonic_ns(origin: Instant, now: Instant) -> u64 {
    now.duration_since(origin).as_nanos() as u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedCommand {
    pub executable: PathBuf,
    pub argv: Vec<String>,
}

impl AllowedCommand {
    pub fn validate(&self, allowlist: &BTreeSet<PathBuf>) -> Result<()> {
        if !self.executable.is_absolute() || !allowlist.contains(&self.executable) {
            bail!("external adapter executable is not explicitly allow-listed");
        }
        if self.argv.iter().any(|arg| arg.contains('\0')) {
            bail!("external adapter argument contains NUL");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlledPressurePlan {
    pub owned_cgroup: String,
    pub memory_max_bytes: u64,
    pub host_headroom_bytes: u64,
    pub watchdog_ms: u64,
    pub timeout_ms: u64,
    pub privileged_execution_required: bool,
    pub host_oom_forbidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestedLoadLevel {
    pub logical_bytes: u64,
    pub touched_bytes: u64,
    pub sustainable: bool,
    pub reason: String,
    pub duration_ms: u64,
    pub health_metrics_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacitySearchPlan {
    pub coarse_levels: Vec<u64>,
    pub refinement_levels: Vec<u64>,
    pub highest_sustainable: Option<u64>,
    pub lowest_failed: Option<u64>,
    pub interpolation_allowed: bool,
    pub owned_cgroup_required: bool,
}

pub fn plan_capacity_search(
    tested: &[TestedLoadLevel],
    coarse_step: u64,
    minimum_step: u64,
) -> Result<CapacitySearchPlan> {
    if coarse_step == 0 || minimum_step == 0 || minimum_step > coarse_step {
        bail!("capacity search steps are invalid");
    }
    let highest_sustainable = tested
        .iter()
        .filter(|level| level.sustainable)
        .map(|level| level.logical_bytes)
        .max();
    let lowest_failed = tested
        .iter()
        .filter(|level| !level.sustainable)
        .map(|level| level.logical_bytes)
        .min();
    let refinement_levels = match (highest_sustainable, lowest_failed) {
        (Some(low), Some(high)) if high > low + minimum_step => {
            let midpoint = low + (high - low) / 2;
            vec![midpoint]
        }
        _ => Vec::new(),
    };
    Ok(CapacitySearchPlan {
        coarse_levels: tested.iter().map(|level| level.logical_bytes).collect(),
        refinement_levels,
        highest_sustainable,
        lowest_failed,
        interpolation_allowed: false,
        owned_cgroup_required: true,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairnessManifest {
    pub generator_hash: String,
    pub logical_loads: Vec<u64>,
    pub seeds: Vec<u64>,
    pub worker_binary_sha256: String,
    pub warmup_ms: u64,
    pub stabilization_ms: u64,
    pub cgroup_memory_max: u64,
    pub kernel: String,
    pub host_fingerprint_hash: String,
    pub thermal_procedure: String,
}

impl FairnessManifest {
    pub fn comparable_with(&self, other: &Self) -> Result<()> {
        if self.generator_hash != other.generator_hash
            || self.logical_loads != other.logical_loads
            || self.seeds != other.seeds
            || self.worker_binary_sha256 != other.worker_binary_sha256
            || self.warmup_ms != other.warmup_ms
            || self.stabilization_ms != other.stabilization_ms
            || self.cgroup_memory_max != other.cgroup_memory_max
            || self.kernel != other.kernel
            || self.host_fingerprint_hash != other.host_fingerprint_hash
            || self.thermal_procedure != other.thermal_procedure
        {
            bail!("baseline and candidate benchmark envelopes differ");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheState {
    Warm,
    Cold,
    NotControlled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileAdapterPlan {
    pub fixture_id: String,
    pub fixture_hash: String,
    pub language: String,
    pub build_type: String,
    pub parallelism: usize,
    pub cache_state: CacheState,
    pub command: AllowedCommand,
    pub required_metrics: Vec<String>,
}

impl CompileAdapterPlan {
    pub fn validate(&self, allowlist: &BTreeSet<PathBuf>) -> Result<()> {
        if self.fixture_id.is_empty()
            || self.fixture_hash.len() != 64
            || !matches!(self.language.as_str(), "rust" | "cpp")
            || self.parallelism == 0
        {
            bail!("compile fixture manifest is invalid");
        }
        self.command.validate(allowlist)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleSample {
    pub timestamp_monotonic_ns: u64,
    pub phase: RunState,
    pub metric: MetricValue,
}

pub fn measurement_samples(samples: &[LifecycleSample]) -> Result<Vec<&LifecycleSample>> {
    if samples
        .windows(2)
        .any(|pair| pair[0].timestamp_monotonic_ns > pair[1].timestamp_monotonic_ns)
    {
        bail!("benchmark samples are not monotonic");
    }
    Ok(samples
        .iter()
        .filter(|sample| sample.phase == RunState::Measuring)
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEvent {
    pub event_type: String,
    pub probe_version: u32,
    pub started_monotonic_ns: u64,
    pub completed_monotonic_ns: u64,
}

impl ResponseEvent {
    pub fn latency_ms(&self) -> Result<f64> {
        let delta = self
            .completed_monotonic_ns
            .checked_sub(self.started_monotonic_ns)
            .context("response event completed before it started")?;
        Ok(delta as f64 / 1_000_000.0)
    }
}

pub fn oom_avoided(
    baseline: OomOutcome,
    candidate: OomOutcome,
    same_logical_demand: bool,
    comparable: bool,
) -> EvaluationState {
    if !same_logical_demand || !comparable {
        return EvaluationState::NotEvaluated;
    }
    if baseline == OomOutcome::ControlledCgroupOom && candidate == OomOutcome::None {
        EvaluationState::Pass
    } else {
        EvaluationState::Fail
    }
}

impl ControlledPressurePlan {
    pub fn validate(&self) -> Result<()> {
        if self.memory_max_bytes == 0
            || self.memory_max_bytes >= self.host_headroom_bytes
            || self.watchdog_ms == 0
            || self.timeout_ms == 0
        {
            bail!("controlled pressure plan is not safely bounded");
        }
        if !self.privileged_execution_required || !self.host_oom_forbidden {
            bail!("pressure execution must be explicit and host OOM must be forbidden");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
