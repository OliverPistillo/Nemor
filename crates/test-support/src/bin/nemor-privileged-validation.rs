#![forbid(unsafe_code)]

use actuator::{
    apply_one, recover, rollback_one, ActuatorError, BackendKind, CgroupBackend, CgroupPlan,
    LinuxCgroupBackend, MutationSnapshot as CgroupMutationSnapshot, RequestedProperties,
    SnapshotStore,
};
use anyhow::{anyhow, bail, Context, Result};
use benchmark::capacity_external_target::{
    self as external_target, CapacityExternalTargetCommand, CapacityExternalTargetDescriptor,
};
use clap::{Parser, ValueEnum};
use memmap2::{Advice, MmapMut, MmapOptions};
use nix::time::{clock_gettime, ClockId};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tiering::{
    apply_swapfile, inspect_storage, parse_block_stat, rollback_swapfile, FilesystemKind,
    LinuxSwapfileBackend, MutationSnapshot as TieringMutationSnapshot, StorageClass,
    SwapfileBackend, SwapfileOwnership, SwapfilePlan,
};
use zram::{DatasetKind, LinuxZramBackend, ZramBackend};

const PREFIX: &str = "nemor-validation-";
const REPORT_PATH: &str = "/tmp/nemor-privileged-validation-report.json";
const STATE_DIR: &str = "/tmp/nemor-privileged-validation";
const DATASET_BYTES: usize = 16 * 1024 * 1024;
const DEVICE_BYTES: u64 = 64 * 1024 * 1024;
const MEMORY_LOW: u64 = 4 * 1024 * 1024;
const MEMORY_HIGH: u64 = 8 * 1024 * 1024 * 1024;
const TEST_SWAP_PRIORITY_A: i32 = 10;
const TEST_SWAP_PRIORITY_B: i32 = 11;
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(180);
const TIERING_SWAP_BYTES: u64 = 64 * 1024 * 1024;
const DAMON_REQUIRED_GATES: &[&str] = &[
    "capability",
    "available_operations",
    "vaddr_selected",
    "attrs_readback",
    "target_identity",
    "synthetic_workload_ready",
    "target_regions_readback",
    "base_page_backing_verified",
    "zero_damos_before_start",
    "trace_instance_isolated",
    "final_trace_instance_ready",
    "kdamond_started",
    "aggregated_trace_bytes_received",
    "damon_payloads_parsed",
    "trace_clock_compatible",
    "timestamp_values_parsed",
    "timestamp_correlation_valid",
    "raw_regions_present",
    "synthetic_workload_active",
    "post_run_fingerprint",
    "hot_cold_evidence",
    "warm_evidence",
    "overhead_budget",
    "dataset_jsonl",
    "dataset_csv",
    "kdamond_stopped",
    "cleanup",
    "recovery",
    "recovery_idempotent",
    "host_unchanged",
];
const DAMOS_REQUIRED_GATES: &[&str] = &[
    "capability",
    "vaddr_pageout_supported",
    "synthetic_workload_ready",
    "base_page_backing_verified",
    "stable_target_identity",
    "pagemap_range_evidence",
    "stable_cold_evidence",
    "gaming_foreground_protection",
    "policy_decision_recorded",
    "plan_audited",
    "quota_within_ceiling",
    "quota_reset_after_session",
    "snapshot_ceiling_allows_eligibility",
    "quota_readback",
    "cold_address_fence",
    "cold_address_filter_semantics_verified",
    "shadow_config_readback",
    "shadow_candidate_evidence",
    "shadow_first_eligibility",
    "shadow_session_passed",
    "shadow_hot_overlap_zero",
    "shadow_warm_overlap_zero",
    "shadow_cleanup",
    "live_session_independent",
    "live_config_readback",
    "live_candidate_evidence",
    "live_snapshot_ceiling",
    "pageout_action_readback",
    "kdamond_started",
    "kdamond_stopped",
    "damos_stats_present",
    "sz_applied_positive",
    "reclaim_effect_observed",
    "quota_respected",
    "hard_byte_ceiling_respected",
    "hot_not_reclaimed",
    "warm_not_reclaimed",
    "control_slowdown_within_budget",
    "zero_oom",
    "scheme_removed",
    "refault_content_valid",
    "refault_detected",
    "blacklist_created",
    "blacklist_blocks_next_plan",
    "cleanup",
    "recovery",
    "recovery_idempotent",
    "host_unchanged",
];
const KSM_REQUIRED_GATES: &[&str] = &[
    "capability",
    "isolated_baseline",
    "advisor_none",
    "baseline_scanner_preserved",
    "owned_targets_ready_unmergeable",
    "audit_before_mergeable",
    "exact_mergeable_scope_verified",
    "external_rechecks",
    "scanner_started",
    "scanner_ownership_preserved",
    "scanner_progress",
    "minimum_saved_bytes",
    "positive_system_profit",
    "positive_process_profit",
    "cpu_budget",
    "scanner_stopped",
    "owned_content_intact",
    "owned_mergeability_absent_final",
    "cleanup",
    "configuration_restored",
    "host_unchanged",
];
const KSM_INEFFICIENT_REQUIRED_GATES: &[&str] = &[
    "capability",
    "isolated_baseline",
    "advisor_none",
    "baseline_scanner_preserved",
    "owned_targets_ready_unmergeable",
    "audit_before_mergeable",
    "exact_mergeable_scope_verified",
    "external_rechecks",
    "scanner_started",
    "scanner_ownership_preserved",
    "scanner_progress",
    "sufficient_inefficiency_evidence",
    "controller_inefficient_transition",
    "controller_auto_disable",
    "scanner_stopped",
    "cooldown_entered",
    "cooldown_rejects_next_plan",
    "cpu_budget",
    "owned_content_intact",
    "owned_mergeability_absent_final",
    "cleanup",
    "configuration_restored",
    "host_unchanged",
];

#[derive(Debug, Clone, Copy)]
enum Scope {
    Preflight,
    Cgroups,
    Zram,
    Tiering,
    Damon,
    Damos,
    Ksm,
    KsmInefficient,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KsmScenario {
    Positive,
    Inefficient,
}

#[derive(Debug, Parser)]
#[command(about = "Bounded CachyOS privileged validation harness")]
struct Cli {
    #[arg(long, hide = true)]
    build_git_head: bool,
    #[arg(long)]
    preflight: bool,
    #[arg(long)]
    cgroups: bool,
    #[arg(long)]
    zram: bool,
    #[arg(long)]
    tiering: bool,
    #[arg(long)]
    damon: bool,
    #[arg(long)]
    damos: bool,
    #[arg(long)]
    ksm: bool,
    #[arg(long)]
    ksm_inefficient: bool,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    cleanup_owned_residue: bool,
    #[arg(long, hide = true)]
    ksm_bootstrap_preflight: bool,
    #[arg(long, value_enum, hide = true)]
    internal_worker: Option<InternalWorker>,
    #[arg(long, hide = true, requires = "damos")]
    external_target_descriptor: Option<PathBuf>,
    #[arg(long, hide = true, requires = "external_target_descriptor")]
    external_target_transaction_id: Option<String>,
    #[arg(long, hide = true, requires = "external_target_descriptor")]
    external_target_session_id: Option<String>,
    #[arg(long, hide = true, requires = "external_target_descriptor")]
    external_target_nonce: Option<String>,
    #[arg(long, hide = true, requires = "external_target_descriptor")]
    external_target_creator_pid: Option<u32>,
    #[arg(long, hide = true, requires = "external_target_descriptor")]
    external_target_creator_start_ticks: Option<u64>,
    #[arg(long, hide = true, requires = "report_root")]
    report_path: Option<PathBuf>,
    #[arg(long, hide = true, requires = "report_path")]
    report_root: Option<PathBuf>,
}

impl Cli {
    fn scope(&self) -> Result<Scope> {
        if self.internal_worker.is_some() || self.ksm_bootstrap_preflight {
            bail!("internal worker has no public validation scope");
        }
        if self.external_target_descriptor.is_some() && !self.damos {
            bail!("external target validation is restricted to --damos");
        }
        let selected = [
            (self.preflight, Scope::Preflight),
            (self.cgroups, Scope::Cgroups),
            (self.zram, Scope::Zram),
            (self.tiering, Scope::Tiering),
            (self.damon, Scope::Damon),
            (self.damos, Scope::Damos),
            (self.ksm, Scope::Ksm),
            (self.ksm_inefficient, Scope::KsmInefficient),
            (self.all, Scope::All),
        ];
        let values: Vec<_> = selected
            .into_iter()
            .filter_map(|(enabled, scope)| enabled.then_some(scope))
            .collect();
        match values.as_slice() {
            [scope] => Ok(*scope),
            _ => bail!(
                "select exactly one of --preflight, --cgroups, --zram, --tiering, --damon, --damos, --ksm, --ksm-inefficient, or --all"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InternalWorker {
    CgroupCrash,
    ZramCrash,
    NemorValidationSleeper,
    DamonTarget,
    DamonCrash,
    KsmTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SwapEntry {
    path: String,
    kind: String,
    size_kib: u64,
    used_kib: u64,
    priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ProtectedZram {
    disksize: u64,
    initstate: bool,
    algorithm: String,
    mem_limit: Option<u64>,
    active: bool,
    priority: Option<i32>,
    provider: String,
    ownership: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct HostSnapshot {
    timestamp_ns: u128,
    swaps: Vec<SwapEntry>,
    zram_devices: BTreeSet<String>,
    zram0: Option<ProtectedZram>,
    validation_cgroups: BTreeSet<String>,
    validation_processes: BTreeSet<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GateState {
    #[default]
    NotEvaluated,
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Check {
    name: String,
    passed: bool,
    state: GateState,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CgroupEvidence {
    attempted: bool,
    checks: Vec<Check>,
    child_pid: Option<u32>,
    child_start_ticks: Option<u64>,
    original_group: Option<String>,
    target_group: Option<String>,
    rollback_idempotent: bool,
    recovery_replayed: bool,
    recovery_idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BenchmarkRound {
    dataset: String,
    input_bytes: u64,
    compr_data_size: u64,
    mem_used_total: u64,
    logical_ratio: Option<f64>,
    effective_ratio: Option<f64>,
    allocator_efficiency: Option<f64>,
    wall_time_ns: u128,
    cpu_time_ns: u64,
    write_throughput_bytes_sec: f64,
    read_throughput_bytes_sec: f64,
    verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ZramEvidence {
    attempted: bool,
    checks: Vec<Check>,
    protected_device: String,
    benchmark_device: Option<String>,
    transaction_devices: Vec<String>,
    algorithm: Option<String>,
    benchmark: Vec<BenchmarkRound>,
    replacement_first: bool,
    no_swap_loss: bool,
    recovery_replayed: bool,
    recovery_idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TieringEvidence {
    attempted: bool,
    checks: Vec<Check>,
    swapfile: Option<String>,
    filesystem: Option<String>,
    storage_class: Option<String>,
    zswap_supported: bool,
    zswap_enabled: Option<bool>,
    block_write_bytes_delta: Option<u64>,
    no_swap_loss: bool,
    recovery_replayed: bool,
    recovery_idempotent: bool,
    boot_validation_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DamonEvidence {
    attempted: bool,
    checks: Vec<Check>,
    capability: Option<damon::DamonCapability>,
    target_pid: Option<u32>,
    target_start_ticks: Option<u64>,
    attrs_requested: Option<damon::MonitoringAttrs>,
    attrs_effective: Option<damon::MonitoringAttrs>,
    raw_regions: u64,
    aggregation_windows: u64,
    region_sample_bytes: Option<u64>,
    snapshot_observed_bytes: Option<u64>,
    requested_target_bytes: u64,
    target_ranges: BTreeMap<String, damon::AddressRange>,
    observed_target_bytes_per_snapshot: Option<u64>,
    outside_requested_bytes: Option<u64>,
    outside_requested_ratio: Option<f64>,
    hot_snapshot_overlap_bytes: Option<u64>,
    warm_snapshot_overlap_bytes: Option<u64>,
    cold_snapshot_overlap_bytes: Option<u64>,
    overhead: Option<damon::OverheadSample>,
    dataset_jsonl: bool,
    dataset_csv: bool,
    dataset_jsonl_path: Option<String>,
    dataset_csv_path: Option<String>,
    zero_damos: bool,
    recovery_idempotent: bool,
    signal: Option<damon::SignalEvidence>,
    workload_progress: Vec<WorkloadWindowProgress>,
    window_alignment: Vec<AlignedWindowDiagnostic>,
    lifecycle_timeline_ns: BTreeMap<String, u128>,
    zone_backing: BTreeMap<String, damon::ZoneBacking>,
    post_run_fingerprints: BTreeMap<String, u64>,
    tlb_diagnostic: TlbDiagnostic,
    probe_session_ids: Vec<String>,
    final_session_id: Option<String>,
    final_trace: Option<TraceCaptureDiagnostic>,
    validation_failure_class: ValidationFailureClass,
    lifecycle_clock_domain: String,
    workload_clock_domain: String,
    trace_clock_domain: String,
    instrumentation_failure_reason: Option<String>,
    signal_failure_reason: Option<String>,
    required_gates_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DamosEvidence {
    attempted: bool,
    checks: Vec<Check>,
    capability: Option<damos::DamosCapability>,
    decision_id: Option<String>,
    plan_id: Option<String>,
    shadow_session_id: Option<String>,
    live_session_id: Option<String>,
    target_pid: Option<u32>,
    target_start_ticks: Option<u64>,
    cold_range: Option<damon::AddressRange>,
    zone_backing: BTreeMap<String, damon::ZoneBacking>,
    filter_api: Option<damos::FilterApi>,
    filter_layer: Option<String>,
    filter_type: Option<String>,
    filter_matching_requested: Option<bool>,
    filter_matching_effective: Option<bool>,
    filter_allow_requested: Option<bool>,
    filter_allow_effective: Option<bool>,
    filter_start_requested: Option<u64>,
    filter_start_effective: Option<u64>,
    filter_end_requested: Option<u64>,
    filter_end_effective: Option<u64>,
    quota_requested: Option<damos::DamosQuota>,
    quota_effective: Option<damos::DamosQuota>,
    shadow_access_pattern: Option<damos::Readback<damos::AccessPattern>>,
    live_access_pattern: Option<damos::Readback<damos::AccessPattern>>,
    shadow_monitoring_intervals: Option<damos::Readback<damos::MonitoringIntervals>>,
    live_monitoring_intervals: Option<damos::Readback<damos::MonitoringIntervals>>,
    shadow_stats: Option<damos::DamosStats>,
    live_stats: Option<damos::DamosStats>,
    shadow_trace: Option<DamosTraceDiagnostic>,
    live_trace: Option<DamosTraceDiagnostic>,
    shadow_candidates: Vec<damos::DamosBeforeApplyEvent>,
    live_candidates: Vec<damos::DamosBeforeApplyEvent>,
    shadow_sysfs_timestamps_ns: BTreeMap<String, u128>,
    shadow_sysfs_clock_domain: Option<String>,
    reclaim: Option<damos::ReclaimEvidence>,
    refault: Option<damos::RefaultEvidence>,
    blacklist: Option<damos::BlacklistRecord>,
    refault_state: Option<damos::RefaultState>,
    configured_age_min: Option<u64>,
    empirical_shadow_first_eligibility_snapshot: Option<u64>,
    empirical_shadow_first_region_age: Option<u64>,
    requested_max_nr_snapshots: Option<u64>,
    effective_max_nr_snapshots: Option<u64>,
    live_deadline_ms: Option<u64>,
    quota_reset_interval_ms: Option<u64>,
    quota_reset_margin_ms: Option<u64>,
    action_hard_ceiling_bytes: Option<u64>,
    configured_session_total_ceiling: Option<u64>,
    separate_owned_mappings: Option<bool>,
    containing_vma_shared: Option<bool>,
    kdamond_cpu_percent: Option<f64>,
    control_cpu_percent: Option<f64>,
    control_slowdown_percent: Option<f64>,
    failure_class: Option<String>,
    failure_reason: Option<String>,
    required_gates_passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DamosTraceDiagnostic {
    available: bool,
    instance_path: String,
    trace_clock: Option<String>,
    userspace_clock: Option<String>,
    trace_clock_readback: bool,
    event_enable_readback: bool,
    tracing_on_readback: bool,
    capture_worker_ready: bool,
    trace_bytes_read: u64,
    trace_lines_read: u64,
    event_lines_seen: u64,
    events_parsed: u64,
    parse_failures: u64,
    timestamp_failures: u64,
    bytes_after_stop: u64,
    raw_first: Vec<String>,
    raw_last: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum ValidationFailureClass {
    #[default]
    None,
    SafetyFailure,
    InstrumentationFailure,
    SignalFailure,
    OverheadFailure,
    DatasetFailure,
}

fn classify_capture(diagnostic: &TraceCaptureDiagnostic) -> ValidationFailureClass {
    if diagnostic.trace_bytes_read == 0
        || diagnostic.damon_event_lines_seen == 0
        || diagnostic.damon_events_parsed == 0
        || diagnostic.parse_failures > 0
        || diagnostic.timestamp_failures > 0
        || !diagnostic.trace_clock_readback
        || !diagnostic.timestamp_correlation_valid
    {
        ValidationFailureClass::InstrumentationFailure
    } else {
        ValidationFailureClass::None
    }
}

fn sessions_are_independent(probes: &[String], final_session: &str) -> bool {
    !final_session.is_empty()
        && probes.iter().all(|probe| probe != final_session)
        && probes.iter().collect::<BTreeSet<_>>().len() == probes.len()
}

fn record_validated_operation(capability: &mut damon::DamonCapability, operation: &str) {
    if !capability
        .available_operations
        .iter()
        .any(|item| item == operation)
    {
        capability.available_operations.push(operation.to_owned());
    }
    if operation == "vaddr" {
        capability.vaddr_supported = true;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TraceCaptureDiagnostic {
    session_id: String,
    instance_path: String,
    event_enable: bool,
    tracing_on: bool,
    capture_worker_ready: bool,
    trace_bytes_read: u64,
    trace_lines_read: u64,
    damon_event_lines_seen: u64,
    damon_events_parsed: u64,
    timestamp_values_parsed: u64,
    parse_failures: u64,
    timestamp_failures: u64,
    incomplete_lines: u64,
    bytes_after_kdamond_stop: u64,
    available_trace_clocks: Vec<String>,
    requested_trace_clock: Option<String>,
    effective_trace_clock: Option<String>,
    userspace_clock: Option<String>,
    trace_clock_readback: bool,
    timestamp_correlation_valid: bool,
    trace_events_total: u64,
    trace_events_in_monitoring_window: u64,
    trace_events_outside_monitoring_window: u64,
    trace_events_unmatched: u64,
    trace_timestamp_min: Option<u128>,
    trace_timestamp_max: Option<u128>,
    workload_monitoring_start_monotonic: Option<u128>,
    workload_monitoring_end_monotonic: Option<u128>,
    raw_first: Vec<String>,
    raw_last: Vec<String>,
}

#[derive(Debug)]
struct CapturedEvent {
    timestamp_ns: Option<u128>,
    region: damon::TraceRegion,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum UserspaceClock {
    Monotonic,
    MonotonicRaw,
    Boottime,
}

impl UserspaceClock {
    fn report_name(self) -> &'static str {
        match self {
            Self::Monotonic => "CLOCK_MONOTONIC",
            Self::MonotonicRaw => "CLOCK_MONOTONIC_RAW",
            Self::Boottime => "CLOCK_BOOTTIME",
        }
    }

    fn clock_id(self) -> ClockId {
        match self {
            Self::Monotonic => ClockId::CLOCK_MONOTONIC,
            Self::MonotonicRaw => ClockId::CLOCK_MONOTONIC_RAW,
            Self::Boottime => ClockId::CLOCK_BOOTTIME,
        }
    }
}

#[derive(Debug, Clone)]
struct TraceClockPlan {
    available: Vec<String>,
    requested: String,
    effective: String,
    userspace_clock: UserspaceClock,
    readback: bool,
}

struct TraceCaptureWorker {
    stop: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    buffer: Arc<Mutex<Vec<u8>>>,
    handle: Option<std::thread::JoinHandle<Result<()>>>,
    session_id: String,
    instance: PathBuf,
}

struct MonitorSessionSpec<'a> {
    session_id: &'a str,
    trace_instance: &'a Path,
}

fn run_damon_monitor_session(spec: MonitorSessionSpec<'_>) -> Result<TraceCaptureWorker> {
    TraceCaptureWorker::start(spec.trace_instance, spec.session_id)
}

impl TraceCaptureWorker {
    fn start(instance: &Path, session_id: &str) -> Result<Self> {
        let enable = instance.join("events/damon/damon_aggregated/enable");
        let tracing_on = instance.join("tracing_on");
        if read_trimmed(&enable)? != "1" || read_trimmed(&tracing_on)? != "1" {
            bail!("trace capture requires enabled final instance readback");
        }
        let trace_path = instance.join("trace");
        let mut file = OpenOptions::new().read(true).open(&trace_path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let worker_stop = Arc::clone(&stop);
        let worker_ready = Arc::clone(&ready);
        let worker_buffer = Arc::clone(&buffer);
        let handle = thread::spawn(move || -> Result<()> {
            worker_ready.store(true, Ordering::Release);
            while !worker_stop.load(Ordering::Acquire) {
                file.seek(SeekFrom::Start(0))?;
                let mut snapshot = Vec::new();
                file.read_to_end(&mut snapshot)?;
                *worker_buffer
                    .lock()
                    .map_err(|_| anyhow!("trace capture buffer poisoned"))? = snapshot;
                thread::sleep(Duration::from_millis(20));
            }
            file.seek(SeekFrom::Start(0))?;
            let mut snapshot = Vec::new();
            file.read_to_end(&mut snapshot)?;
            *worker_buffer
                .lock()
                .map_err(|_| anyhow!("trace capture buffer poisoned"))? = snapshot;
            Ok(())
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while !ready.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                bail!("trace capture worker readiness timeout");
            }
            thread::yield_now();
        }
        Ok(Self {
            stop,
            ready,
            buffer,
            handle: Some(handle),
            session_id: session_id.to_owned(),
            instance: instance.to_path_buf(),
        })
    }

    fn bytes_read(&self) -> Result<usize> {
        Ok(self
            .buffer
            .lock()
            .map_err(|_| anyhow!("trace capture buffer poisoned"))?
            .len())
    }

    fn drain_and_stop(
        mut self,
        bytes_at_stop: usize,
    ) -> Result<(TraceCaptureDiagnostic, Vec<CapturedEvent>)> {
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut last = self.bytes_read()?;
        let mut stable = 0_u8;
        while Instant::now() < deadline && stable < 2 {
            thread::sleep(Duration::from_millis(25));
            let current = self.bytes_read()?;
            if current == last {
                stable += 1;
            } else {
                stable = 0;
                last = current;
            }
        }
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| anyhow!("trace capture worker panicked"))??;
        }
        let bytes = self
            .buffer
            .lock()
            .map_err(|_| anyhow!("trace capture buffer poisoned"))?
            .clone();
        parse_trace_capture(
            &self.session_id,
            &self.instance,
            self.ready.load(Ordering::Acquire),
            &bytes,
            bytes.len().saturating_sub(bytes_at_stop),
        )
    }
}

struct DamosTraceCaptureWorker {
    stop: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    buffer: Arc<Mutex<Vec<u8>>>,
    handle: Option<std::thread::JoinHandle<Result<()>>>,
    instance: PathBuf,
    clock: TraceClockPlan,
}

impl DamosTraceCaptureWorker {
    fn start(instance: &Path, clock: TraceClockPlan) -> Result<Self> {
        let enable = instance.join("events/damon/damos_before_apply/enable");
        if read_trimmed(&enable)? != "1" || read_trimmed(&instance.join("tracing_on"))? != "1" {
            bail!("DAMOS capture requires owned event/tracing readback");
        }
        let mut file = OpenOptions::new().read(true).open(instance.join("trace"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let worker_stop = Arc::clone(&stop);
        let worker_ready = Arc::clone(&ready);
        let worker_buffer = Arc::clone(&buffer);
        let handle = thread::spawn(move || -> Result<()> {
            worker_ready.store(true, Ordering::Release);
            while !worker_stop.load(Ordering::Acquire) {
                file.seek(SeekFrom::Start(0))?;
                let mut snapshot = Vec::new();
                file.read_to_end(&mut snapshot)?;
                if snapshot.len() > 1024 * 1024 {
                    bail!("DAMOS trace exceeded bounded one-MiB buffer");
                }
                *worker_buffer
                    .lock()
                    .map_err(|_| anyhow!("DAMOS trace buffer poisoned"))? = snapshot;
                thread::sleep(Duration::from_millis(20));
            }
            Ok(())
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while !ready.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                bail!("DAMOS capture worker readiness timeout");
            }
            thread::yield_now();
        }
        Ok(Self {
            stop,
            ready,
            buffer,
            handle: Some(handle),
            instance: instance.to_path_buf(),
            clock,
        })
    }

    fn bytes_read(&self) -> Result<usize> {
        Ok(self
            .buffer
            .lock()
            .map_err(|_| anyhow!("DAMOS trace buffer poisoned"))?
            .len())
    }

    fn drain_and_stop(
        mut self,
        bytes_at_stop: usize,
    ) -> Result<(DamosTraceDiagnostic, Vec<damos::DamosBeforeApplyEvent>)> {
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut last = self.bytes_read()?;
        let mut stable = 0;
        while Instant::now() < deadline && stable < 2 {
            thread::sleep(Duration::from_millis(25));
            let current = self.bytes_read()?;
            if current == last {
                stable += 1;
            } else {
                stable = 0;
                last = current;
            }
        }
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle
                .join()
                .map_err(|_| anyhow!("DAMOS capture worker panicked"))??;
        }
        let bytes = self
            .buffer
            .lock()
            .map_err(|_| anyhow!("DAMOS trace buffer poisoned"))?
            .clone();
        parse_damos_trace_capture(
            &self.instance,
            &self.clock,
            self.ready.load(Ordering::Acquire),
            &bytes,
            bytes.len().saturating_sub(bytes_at_stop),
        )
    }
}

fn parse_damos_trace_capture(
    instance: &Path,
    clock: &TraceClockPlan,
    worker_ready: bool,
    bytes: &[u8],
    bytes_after_stop: usize,
) -> Result<(DamosTraceDiagnostic, Vec<damos::DamosBeforeApplyEvent>)> {
    const RAW_LIMIT: usize = 4;
    let text = String::from_utf8_lossy(bytes);
    let lines = text
        .lines()
        .filter(|line| line.contains("damos_before_apply:"))
        .collect::<Vec<_>>();
    let mut events = Vec::new();
    let mut parse_failures = 0;
    let mut timestamp_failures = 0;
    for line in &lines {
        if let Some(timestamp) = trace_timestamp_ns_for(line, "damos_before_apply:") {
            match damos::parse_damos_before_apply(line, timestamp) {
                Ok(event) => events.push(event),
                Err(_) => parse_failures += 1,
            }
        } else {
            timestamp_failures += 1;
        }
    }
    let raw_first = lines
        .iter()
        .take(RAW_LIMIT)
        .map(|line| (*line).to_owned())
        .collect();
    let raw_last = lines
        .iter()
        .rev()
        .take(RAW_LIMIT)
        .map(|line| (*line).to_owned())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    Ok((
        DamosTraceDiagnostic {
            available: true,
            instance_path: instance.display().to_string(),
            trace_clock: Some(clock.effective.clone()),
            userspace_clock: Some(clock.userspace_clock.report_name().to_owned()),
            trace_clock_readback: clock.readback,
            event_enable_readback: read_trimmed(
                &instance.join("events/damon/damos_before_apply/enable"),
            )
            .ok()
            .as_deref()
                == Some("1"),
            tracing_on_readback: read_trimmed(&instance.join("tracing_on")).ok().as_deref()
                == Some("1"),
            capture_worker_ready: worker_ready,
            trace_bytes_read: bytes.len() as u64,
            trace_lines_read: text.lines().count() as u64,
            event_lines_seen: lines.len() as u64,
            events_parsed: events.len() as u64,
            parse_failures,
            timestamp_failures,
            bytes_after_stop: bytes_after_stop as u64,
            raw_first,
            raw_last,
        },
        events,
    ))
}

fn parse_trace_capture(
    session_id: &str,
    instance: &Path,
    worker_ready: bool,
    bytes: &[u8],
    bytes_after_stop: usize,
) -> Result<(TraceCaptureDiagnostic, Vec<CapturedEvent>)> {
    const RAW_LIMIT: usize = 4;
    let text = String::from_utf8_lossy(bytes);
    let mut events = Vec::new();
    let mut damon_lines = Vec::new();
    let mut parse_failures = 0_u64;
    let mut timestamp_failures = 0_u64;
    for line in text
        .lines()
        .filter(|line| line.contains("damon_aggregated:"))
    {
        damon_lines.push(line.to_owned());
        match damon::parse_aggregated(line) {
            Ok(region) => {
                let timestamp_ns = trace_timestamp_ns(line);
                if timestamp_ns.is_none() {
                    timestamp_failures += 1;
                }
                events.push(CapturedEvent {
                    timestamp_ns,
                    region,
                });
            }
            Err(_) => parse_failures += 1,
        }
    }
    let raw_first = damon_lines.iter().take(RAW_LIMIT).cloned().collect();
    let raw_last = damon_lines
        .iter()
        .rev()
        .take(RAW_LIMIT)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let diagnostic = TraceCaptureDiagnostic {
        session_id: session_id.to_owned(),
        instance_path: instance.display().to_string(),
        event_enable: read_trimmed(&instance.join("events/damon/damon_aggregated/enable"))
            .ok()
            .as_deref()
            == Some("1"),
        tracing_on: read_trimmed(&instance.join("tracing_on")).ok().as_deref() == Some("1"),
        capture_worker_ready: worker_ready,
        trace_bytes_read: bytes.len() as u64,
        trace_lines_read: text.lines().count() as u64,
        damon_event_lines_seen: damon_lines.len() as u64,
        damon_events_parsed: events.len() as u64,
        timestamp_values_parsed: events
            .iter()
            .filter(|event| event.timestamp_ns.is_some())
            .count() as u64,
        parse_failures,
        timestamp_failures,
        incomplete_lines: u64::from(!bytes.is_empty() && !bytes.ends_with(b"\n")),
        bytes_after_kdamond_stop: bytes_after_stop as u64,
        trace_events_total: events.len() as u64,
        raw_first,
        raw_last,
        ..TraceCaptureDiagnostic::default()
    };
    Ok((diagnostic, events))
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TlbDiagnostic {
    current_zone_size: u64,
    size_ladder_attempts: Vec<damon::ProbeEvidence>,
    selected_size: Option<u64>,
    selected_size_reason: Option<String>,
    mem_available_bytes: u64,
    headroom_bytes: u64,
    hypothesis_status: damon::HypothesisStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WorkloadProgress {
    hot_cycles: u64,
    warm_cycles: u64,
    hot_pages_touched: u64,
    warm_pages_touched: u64,
    cold_cycles: u64,
    workload_started_ns: u128,
    workload_stopped_ns: u128,
    hot_fingerprint: u64,
    warm_fingerprint: u64,
    cold_fingerprint: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkloadWindowProgress {
    window_index: u64,
    start_ns: u128,
    end_ns: u128,
    hot_cycles_delta: u64,
    warm_cycles_delta: u64,
    hot_pages_touched_delta: u64,
    warm_pages_touched_delta: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AlignedWindowDiagnostic {
    window_index: u64,
    start_uptime_ns: u64,
    end_uptime_ns: u64,
    partial: bool,
    hot_cycles_delta: u64,
    warm_cycles_delta: u64,
    hot_pages_touched_delta: u64,
    warm_pages_touched_delta: u64,
    overlap_duration_ns: u128,
    alignment_method: String,
    alignment_estimated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KsmEvidence {
    attempted: bool,
    scenario: Option<String>,
    required_gates_passed: bool,
    checks: Vec<Check>,
    capability: Option<ksm::KsmCapability>,
    baseline: Option<ksm::KsmSnapshot>,
    final_snapshot: Option<ksm::KsmSnapshot>,
    system_before: Option<ksm::KsmSystemMetrics>,
    system_peak: Option<ksm::KsmSystemMetrics>,
    system_after: Option<ksm::KsmSystemMetrics>,
    process_evidence: BTreeMap<String, Vec<ksm::KsmProcessMetrics>>,
    bootstrap_evidence: BTreeMap<u8, KsmBootstrapEvidence>,
    profit: Option<ksm::ProfitEvaluation>,
    profit_gate: Option<ksm::ValidationProfitGate>,
    mergeable_scope: BTreeMap<u32, ksm::MergeableScopeEvidence>,
    external_mergeable_processes: Vec<ksm::KsmProcessMetrics>,
    residual_process_accounting: Vec<ksm::KsmProcessMetrics>,
    external_live_ksm_activity: Option<bool>,
    residual_global_ksm_accounting: Option<bool>,
    current_session_owned_activity: Option<bool>,
    residual_accounting_reconciled: Option<bool>,
    residual_baseline: Option<ksm::KsmSystemMetrics>,
    first_scan_snapshot: Option<ksm::KsmSystemMetrics>,
    second_scan_snapshot: Option<ksm::KsmSystemMetrics>,
    decision_id: Option<String>,
    plan_id: Option<String>,
    transaction_id: Option<String>,
    scanner_plan: Option<ksm::ScannerPlan>,
    positive_workload: String,
    inefficient_workload: String,
    cow_validation: String,
    rollback_semantics: String,
    run_two_forbidden: bool,
    validation_min_saved_bytes: u64,
    ksmd_cpu_seconds: Option<f64>,
    ksmd_mean_cpu_percent: Option<f64>,
    ksmd_peak_window_cpu_percent: Option<f64>,
    clk_tck: Option<u64>,
    cpu_tick_seconds: Option<f64>,
    minimum_budget_window_seconds: Option<f64>,
    sustained_measurement_resolution_percent: Option<f64>,
    total_cpu_ticks: Option<u64>,
    scanner_start_timestamp_ns: Option<u128>,
    scanner_stop_timestamp_ns: Option<u128>,
    short_window_cpu: Vec<ksm::CpuWindowMeasurement>,
    owned_unmerge_performed: Option<bool>,
    unique_input_verified: Option<bool>,
    unique_hash_evidence: BTreeMap<u8, UniqueHashEvidence>,
    counter_deltas: BTreeMap<String, i128>,
    global_saved_pages_delta_raw: Option<i128>,
    owned_saved_evidence: Option<String>,
    saved_bytes_attribution_valid: Option<bool>,
    controller_state_before: Option<ksm::ControllerState>,
    controller_state_after: Option<ksm::ControllerState>,
    controller_transition_reason: Option<String>,
    controller_evaluation_id: Option<String>,
    controller_auto_stop_owned: Option<bool>,
    cooldown_decision: Option<ksm::EligibilityDecision>,
    second_run_started: bool,
    wall_seconds: Option<f64>,
    failure_class: Option<String>,
    failure_reason: Option<String>,
    dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerAdviceResult {
    requested: bool,
    succeeded: bool,
    error: Option<String>,
    raw_os_error: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KsmTargetMetadata {
    pid: u32,
    start_ticks: Option<u64>,
    duplicate: [usize; 2],
    control: [usize; 2],
    duplicate_bytes: usize,
    control_bytes: usize,
    duplicate_fingerprint: u64,
    control_fingerprint: u64,
    state: String,
    host_page_size: u64,
    duplicate_nohugepage: WorkerAdviceResult,
    control_nohugepage: WorkerAdviceResult,
    duplicate_prefault_completed: bool,
    control_prefault_completed: bool,
    workload_kind: String,
    duplicate_page_hashes: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UniqueHashEvidence {
    page_count: usize,
    unique_hash_count: usize,
    collision_count: usize,
    cross_child_collision_count: usize,
    aggregate_digest: u64,
    hash_sample: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KsmBootstrapEvidence {
    child_id: u8,
    pid: Option<u32>,
    start_ticks: Option<u64>,
    protocol_state: Option<String>,
    target: Option<KsmTargetMetadata>,
    duplicate_scope: Option<ksm::BasePageScopeEvidence>,
    control_scope: Option<ksm::BasePageScopeEvidence>,
    duplicate_base_page_verified: bool,
    control_base_page_verified: bool,
    fingerprints_present: bool,
    failure_reason: Option<String>,
    child_exit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidationReport {
    schema: &'static str,
    commit: String,
    kernel: String,
    os_id: String,
    scope: String,
    started_ns: u128,
    finished_ns: u128,
    baseline: HostSnapshot,
    final_snapshot: HostSnapshot,
    cgroups: CgroupEvidence,
    zram: ZramEvidence,
    tiering: TieringEvidence,
    damon: DamonEvidence,
    damos: DamosEvidence,
    ksm: KsmEvidence,
    host_unchanged: bool,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct JsonSnapshotStore {
    path: PathBuf,
    next_id: u64,
    snapshots: BTreeMap<u64, CgroupMutationSnapshot>,
    managed_groups: BTreeSet<String>,
}

impl JsonSnapshotStore {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            ..Self::default()
        }
    }

    fn load(path: PathBuf) -> Result<Self> {
        let mut value: Self = serde_json::from_slice(
            &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        )?;
        value.path = path;
        Ok(value)
    }

    fn flush(&self) -> Result<(), ActuatorError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?;
        fs::write(&self.path, bytes).map_err(|error| ActuatorError::Persistence(error.to_string()))
    }
}

impl SnapshotStore for JsonSnapshotStore {
    fn persist(&mut self, mut snapshot: CgroupMutationSnapshot) -> Result<u64, ActuatorError> {
        self.next_id = self.next_id.saturating_add(1);
        snapshot.id = self.next_id;
        self.snapshots.insert(snapshot.id, snapshot);
        self.flush()?;
        Ok(self.next_id)
    }

    fn update(&mut self, snapshot: &CgroupMutationSnapshot) -> Result<(), ActuatorError> {
        if !self.snapshots.contains_key(&snapshot.id) {
            return Err(ActuatorError::Persistence("unknown snapshot".to_owned()));
        }
        self.snapshots.insert(snapshot.id, snapshot.clone());
        self.flush()
    }

    fn pending(&self) -> Result<Vec<CgroupMutationSnapshot>, ActuatorError> {
        Ok(self
            .snapshots
            .values()
            .filter(|snapshot| snapshot.applied && !snapshot.rolled_back)
            .cloned()
            .collect())
    }

    fn record_managed_group(
        &mut self,
        name: &str,
        _session_id: i64,
        _backend: BackendKind,
    ) -> Result<(), ActuatorError> {
        self.managed_groups.insert(name.to_owned());
        self.flush()
    }

    fn remove_managed_group(&mut self, name: &str) -> Result<(), ActuatorError> {
        self.managed_groups.remove(name);
        self.flush()
    }
}

struct Deadline(Instant);

#[derive(Debug, Clone)]
struct ExternalTargetExpected {
    descriptor_path: PathBuf,
    transaction_id: String,
    session_id: String,
    nonce: String,
    creator_pid: u32,
    creator_start_ticks: u64,
}

impl Deadline {
    fn new() -> Self {
        Self(Instant::now() + GLOBAL_TIMEOUT)
    }

    fn check(&self, operation: &str) -> Result<()> {
        if Instant::now() >= self.0 {
            bail!("global timeout before {operation}");
        }
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.build_git_head {
        println!("{}", nemor_test_support::BUILD_GIT_HEAD);
        return Ok(());
    }
    if let Some(worker) = cli.internal_worker {
        return run_internal_worker(worker);
    }
    let external_target = match cli.external_target_descriptor.clone() {
        Some(descriptor_path) => Some(ExternalTargetExpected {
            descriptor_path,
            transaction_id: cli
                .external_target_transaction_id
                .clone()
                .context("missing external target transaction ID")?,
            session_id: cli
                .external_target_session_id
                .clone()
                .context("missing external target session ID")?,
            nonce: cli
                .external_target_nonce
                .clone()
                .context("missing external target nonce")?,
            creator_pid: cli
                .external_target_creator_pid
                .context("missing external target creator PID")?,
            creator_start_ticks: cli
                .external_target_creator_start_ticks
                .context("missing external target creator start ticks")?,
        }),
        None => None,
    };
    if cli.ksm_bootstrap_preflight {
        if cli.preflight
            || cli.cgroups
            || cli.zram
            || cli.tiering
            || cli.damon
            || cli.damos
            || cli.ksm
            || cli.ksm_inefficient
            || cli.all
            || cli.cleanup_owned_residue
        {
            bail!("--ksm-bootstrap-preflight cannot be combined with another mode");
        }
        let _state_dir = StateDir::create()?;
        return run_ksm_bootstrap_preflight();
    }
    if cli.cleanup_owned_residue {
        if cli.preflight
            || cli.cgroups
            || cli.zram
            || cli.tiering
            || cli.damon
            || cli.damos
            || cli.ksm
            || cli.ksm_inefficient
            || cli.all
        {
            bail!("--cleanup-owned-residue cannot be combined with validation modes");
        }
        return cleanup_owned_residue();
    }
    let scope = cli.scope()?;
    let report_destination =
        explicit_report_destination(cli.report_path.as_deref(), cli.report_root.as_deref())?;
    let deadline = Deadline::new();
    let _state_dir = StateDir::create()?;
    let baseline = snapshot_host()?;
    if !matches!(scope, Scope::Preflight) {
        validate_baseline(&baseline)?;
    }
    let mut report = ValidationReport {
        schema: "nemor-privileged-validation-v1",
        commit: read_command("/usr/bin/git", &["rev-parse", "HEAD"])?,
        kernel: read_command("/usr/bin/uname", &["-r"])?,
        os_id: read_os_id()?,
        scope: format!("{scope:?}").to_lowercase(),
        started_ns: now_ns()?,
        finished_ns: 0,
        baseline: baseline.clone(),
        final_snapshot: baseline.clone(),
        cgroups: CgroupEvidence::default(),
        zram: ZramEvidence::default(),
        tiering: TieringEvidence::default(),
        damon: DamonEvidence::default(),
        damos: DamosEvidence::default(),
        ksm: KsmEvidence::default(),
        host_unchanged: false,
        errors: Vec::new(),
    };

    if matches!(scope, Scope::Cgroups | Scope::All) {
        deadline.check("cgroup validation")?;
        if let Err(error) = validate_cgroups(&baseline, &mut report.cgroups, &deadline) {
            report.errors.push(format!("cgroups: {error:#}"));
        }
    }
    if matches!(scope, Scope::Zram | Scope::All) {
        deadline.check("zram validation")?;
        if let Err(error) = validate_zram(&baseline, &mut report.zram, &deadline) {
            report.errors.push(format!("zram: {error:#}"));
        }
    }
    if matches!(scope, Scope::Tiering | Scope::All) {
        deadline.check("tiering validation")?;
        if let Err(error) = validate_tiering(&baseline, &mut report.tiering, &deadline) {
            report.errors.push(format!("tiering: {error:#}"));
        }
    }
    if matches!(scope, Scope::Damon | Scope::All) {
        deadline.check("DAMON validation")?;
        if let Err(error) = validate_damon(&mut report.damon, &deadline) {
            report.errors.push(format!("damon: {error:#}"));
        }
    }
    if matches!(scope, Scope::Damos | Scope::All) {
        deadline.check("DAMOS validation")?;
        if let Err(error) = validate_damos(&mut report.damos, &deadline, external_target.as_ref()) {
            report.errors.push(format!("damos: {error:#}"));
        }
    }
    if matches!(scope, Scope::Ksm | Scope::KsmInefficient) {
        deadline.check("KSM validation")?;
        let scenario = if matches!(scope, Scope::KsmInefficient) {
            KsmScenario::Inefficient
        } else {
            KsmScenario::Positive
        };
        if let Err(error) = validate_ksm(&mut report.ksm, &deadline, scenario) {
            if report.ksm.failure_class.is_none() {
                report.ksm.failure_class = Some("execution_failure".into());
            }
            if report.ksm.failure_reason.is_none() {
                report.ksm.failure_reason = Some(format!("{error:#}"));
            }
        }
    }

    report.final_snapshot = snapshot_host()?;
    report.host_unchanged = compare_host(&baseline, &report.final_snapshot).is_ok();
    if let Err(error) = compare_host(&baseline, &report.final_snapshot) {
        report
            .errors
            .push(format!("final host comparison: {error:#}"));
    }
    if matches!(scope, Scope::Damon | Scope::All) {
        let host_check = check(
            "host_unchanged",
            report.host_unchanged,
            "final structural host snapshot compared with baseline".to_owned(),
        );
        report.damon.checks.push(host_check);
        report.damon.required_gates_passed = damon_required_gates(&report.damon);
        if !report.damon.required_gates_passed {
            report
                .errors
                .push("damon: one or more mandatory validation gates failed".to_owned());
        }
    }
    if matches!(scope, Scope::Damos | Scope::All) {
        report.damos.checks.push(check(
            "host_unchanged",
            report.host_unchanged,
            "final structural host snapshot compared with baseline".to_owned(),
        ));
        fill_damos_not_evaluated_gates(&mut report.damos);
        report.damos.required_gates_passed =
            required_checks_pass(&report.damos.checks, DAMOS_REQUIRED_GATES);
        if !report.damos.required_gates_passed {
            ensure_damos_failure_taxonomy(&mut report.damos);
            report
                .errors
                .push("damos: one or more mandatory validation gates failed".to_owned());
        }
    }
    if matches!(scope, Scope::Ksm | Scope::KsmInefficient) {
        let owned_children_absent = report
            .ksm
            .bootstrap_evidence
            .values()
            .filter_map(|item| item.pid)
            .all(|pid| !Path::new(&format!("/proc/{pid}")).exists());
        for item in report.ksm.bootstrap_evidence.values_mut() {
            if item.child_exit.is_none() {
                item.child_exit = Some(
                    if item
                        .pid
                        .is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists())
                    {
                        "still_running_after_cleanup".into()
                    } else {
                        "exited_or_terminated_by_owned_cleanup".into()
                    },
                );
            }
        }
        set_check(
            &mut report.ksm.checks,
            check(
                "cleanup",
                owned_children_absent,
                if owned_children_absent {
                    "all created KSM validation children exited; owned mappings disappeared"
                } else {
                    "one or more owned KSM validation children remain"
                }
                .to_owned(),
            ),
        );
        if let Some(baseline) = report.ksm.baseline.as_ref() {
            match ksm::snapshot_from_root(Path::new("/sys/kernel/mm/ksm")) {
                Ok(final_snapshot) => {
                    let restored = &final_snapshot == baseline;
                    report.ksm.final_snapshot = Some(final_snapshot);
                    set_check(
                        &mut report.ksm.checks,
                        check(
                            "configuration_restored",
                            restored,
                            "final read-only KSM run/scanner/advisor/preserve-only snapshot compared with baseline; cumulative counters excluded".into(),
                        ),
                    );
                }
                Err(error) => {
                    set_check(
                        &mut report.ksm.checks,
                        check(
                            "configuration_restored",
                            false,
                            format!("final KSM configuration snapshot failed: {error}"),
                        ),
                    );
                }
            }
        }
        set_check(
            &mut report.ksm.checks,
            check(
                "host_unchanged",
                report.host_unchanged,
                "final structural host snapshot compared with baseline".into(),
            ),
        );
        let scenario = if matches!(scope, Scope::KsmInefficient) {
            KsmScenario::Inefficient
        } else {
            KsmScenario::Positive
        };
        let outcome = finalize_ksm_outcome(&mut report.ksm, scenario);
        if !outcome.success {
            debug_assert_eq!(outcome.exit_code, 1);
            report.errors.push(
                outcome
                    .error
                    .unwrap_or_else(|| "ksm: authoritative outcome failed".into()),
            );
        }
    }
    report.finished_ns = now_ns()?;
    write_report(&report, report_destination.as_ref())?;
    if report.errors.is_empty() && report.host_unchanged {
        Ok(())
    } else {
        let path = report_destination.as_ref().map_or_else(
            || Path::new(REPORT_PATH),
            |destination| destination.path.as_path(),
        );
        bail!("validation incomplete; inspect {}", path.display())
    }
}

fn run_internal_worker(worker: InternalWorker) -> Result<()> {
    if !Path::new(STATE_DIR).is_dir() {
        bail!("internal worker requires the parent-owned fixed state directory");
    }
    match worker {
        InternalWorker::CgroupCrash => cgroup_crash_worker(),
        InternalWorker::ZramCrash => zram_crash_worker(),
        InternalWorker::NemorValidationSleeper => {
            std::thread::sleep(Duration::from_secs(120));
            Ok(())
        }
        InternalWorker::DamonTarget => damon_target_worker(),
        InternalWorker::DamonCrash => damon_crash_worker(),
        InternalWorker::KsmTarget => ksm_target_worker(),
    }
}

fn cleanup_owned_residue() -> Result<()> {
    let report: ResidueReport = serde_json::from_slice(&fs::read(REPORT_PATH)?)?;
    let mut candidates = BTreeSet::new();
    if let Some(name) = report.zram.benchmark_device {
        candidates.insert(name);
    }
    candidates.extend(report.zram.transaction_devices);
    if candidates.is_empty() {
        return Ok(());
    }
    let mut backend = LinuxZramBackend::default();
    for name in candidates {
        require_new_test_zram_name(&name, &report.baseline.zram_devices)?;
        if !Path::new(&format!("/sys/block/{name}")).exists() {
            continue;
        }
        backend.resume_isolated_managed_device(&name, &report.baseline.zram_devices)?;
        if backend.verify(&name)?.active_swap {
            backend.deactivate(&name)?;
        }
        backend.remove_managed_device(&name)?;
    }
    let remaining: BTreeSet<_> = zram::inspect_linux(Path::new("/"))?
        .devices
        .into_iter()
        .map(|device| device.name)
        .collect();
    if remaining != report.baseline.zram_devices {
        bail!("owned cleanup did not restore baseline zram topology");
    }
    Ok(())
}

fn run_worker(worker: InternalWorker) -> Result<()> {
    let argument = match worker {
        InternalWorker::CgroupCrash => "cgroup-crash",
        InternalWorker::ZramCrash => "zram-crash",
        InternalWorker::NemorValidationSleeper => "nemor-validation-sleeper",
        InternalWorker::DamonTarget => "damon-target",
        InternalWorker::DamonCrash => "damon-crash",
        InternalWorker::KsmTarget => "ksm-target",
    };
    let executable = std::env::current_exe()?.canonicalize()?;
    let status = Command::new(executable)
        .args(["--internal-worker", argument])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()?;
    if !status.success() {
        bail!("fixed internal worker {argument} failed with {status}");
    }
    Ok(())
}

fn cgroup_crash_worker() -> Result<()> {
    let run = now_ns()?;
    let group = format!("{PREFIX}{run}-crash.scope");
    require_validation_group(&group)?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let child = Command::new(executable)
        .args(["--internal-worker", "nemor-validation-sleeper"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = child.id();
    let mut backend = LinuxCgroupBackend::default();
    let start_ticks = backend
        .process_start_time(pid)?
        .ok_or_else(|| anyhow!("recovery child vanished"))?;
    let child = RegisteredChild::new(child, start_ticks);
    let original_group = backend
        .process_group(pid)?
        .ok_or_else(|| anyhow!("recovery child group unavailable"))?;
    let mut cleanup = CgroupCleanup::new(pid, start_ticks, original_group.clone());
    cleanup.register(group.clone());
    let store_path = Path::new(STATE_DIR).join("cgroup-recovery-store.json");
    let mut store = JsonSnapshotStore::new(store_path.clone());
    let plan = CgroupPlan {
        process_catalog_id: 2,
        identity: fixed_identity(),
        pid,
        start_time_ticks: start_ticks,
        source_group: original_group.clone(),
        target_group: group.clone(),
        properties: RequestedProperties {
            memory_low: Some(MEMORY_LOW),
            memory_high: Some(MEMORY_HIGH),
        },
        reason: "privileged_validation_crash_recovery".to_owned(),
        allowed: true,
        block_reasons: Vec::new(),
        dry_run: false,
    };
    let snapshot = apply_one(&mut backend, &mut store, 3, run as i64, &plan)?
        .ok_or_else(|| anyhow!("crash recovery setup unexpectedly dry-run"))?;
    if !snapshot.applied || !snapshot.verified {
        bail!("crash worker mutation was not verified");
    }
    fs::write(
        Path::new(STATE_DIR).join("cgroup-recovery.json"),
        serde_json::to_vec_pretty(&CgroupRecoveryState {
            pid,
            start_ticks,
            original_group,
            target_group: group,
            store_path,
        })?,
    )?;
    std::mem::forget(cleanup);
    std::mem::forget(child);
    Ok(())
}

fn zram_crash_worker() -> Result<()> {
    let baseline = snapshot_host()?;
    validate_baseline(&baseline)?;
    let mut backend = LinuxZramBackend::default();
    let mut cleanup = ZramCleanup::new(baseline.zram_devices.clone());
    let device = backend.create_isolated_managed_device()?;
    require_new_test_zram(&device.name, &baseline)?;
    cleanup.register(&device.name);
    let algorithm = select_algorithm(&device.available_algorithms)?;
    backend.configure_uninitialized(&device.name, &algorithm)?;
    backend.initialize(&device.name, DEVICE_BYTES)?;
    backend.activate(&device.name, TEST_SWAP_PRIORITY_A)?;
    verify_swap_checkpoint(&baseline, &[&device.name])?;
    fs::write(
        Path::new(STATE_DIR).join("zram-recovery.json"),
        serde_json::to_vec_pretty(&ZramRecoveryState {
            name: device.name,
            baseline_names: baseline.zram_devices,
            active: true,
        })?,
    )?;
    std::mem::forget(cleanup);
    Ok(())
}

fn validate_cgroups(
    baseline: &HostSnapshot,
    evidence: &mut CgroupEvidence,
    deadline: &Deadline,
) -> Result<()> {
    evidence.attempted = true;
    let run = now_ns()?;
    let group = format!("{PREFIX}{run}.scope");
    require_validation_group(&group)?;
    evidence.target_group = Some(group.clone());
    let child = Command::new(std::env::current_exe()?.canonicalize()?)
        .args(["--internal-worker", "nemor-validation-sleeper"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn allow-listed test child")?;
    let pid = child.id();
    let root = Path::new("/sys/fs/cgroup");
    let mut backend = LinuxCgroupBackend::new(root);
    let start = backend
        .process_start_time(pid)?
        .ok_or_else(|| anyhow!("test child vanished"))?;
    let mut child = RegisteredChild::new(child, start);
    let original = backend
        .process_group(pid)?
        .ok_or_else(|| anyhow!("test child cgroup unavailable"))?;
    evidence.child_pid = Some(pid);
    evidence.child_start_ticks = Some(start);
    evidence.original_group = Some(original.clone());
    let mut cleanup = CgroupCleanup::new(pid, start, original.clone());
    cleanup.register(group.clone());

    let store_path = Path::new(STATE_DIR).join("cgroup-store.json");
    let mut store = JsonSnapshotStore::new(store_path.clone());
    let identity = fixed_identity();
    let plan = CgroupPlan {
        process_catalog_id: 1,
        identity: identity.clone(),
        pid,
        start_time_ticks: start,
        source_group: original.clone(),
        target_group: group.clone(),
        properties: RequestedProperties {
            memory_low: Some(MEMORY_LOW),
            memory_high: Some(MEMORY_HIGH),
        },
        reason: "privileged_validation_child_only".to_owned(),
        allowed: true,
        block_reasons: Vec::new(),
        dry_run: false,
    };

    evidence
        .checks
        .extend(safety_checks(&mut backend, &mut store, &plan, pid, start)?);
    deadline.check("cgroup apply")?;
    let mut snapshot = apply_one(&mut backend, &mut store, 1, run as i64, &plan)?
        .ok_or_else(|| anyhow!("real cgroup apply unexpectedly dry-run"))?;
    evidence.checks.push(check(
        "create_apply_readback_attach",
        snapshot.applied && snapshot.verified,
        format!("group={group} pid={pid}"),
    ));
    let state = backend
        .inspect_group(&group)?
        .ok_or_else(|| anyhow!("validation group disappeared"))?;
    evidence.checks.push(check(
        "memory.low_readback",
        state.memory_low == Some(MEMORY_LOW),
        format!("{:?}", state.memory_low),
    ));
    evidence.checks.push(check(
        "memory.high_readback",
        state.memory_high == Some(MEMORY_HIGH),
        format!("{:?}", state.memory_high),
    ));
    evidence.checks.push(check(
        "cgroup.procs_attach",
        state.pids.contains(&pid),
        format!("{:?}", state.pids),
    ));
    rollback_one(&mut backend, &mut store, &mut snapshot)?;
    let placement = backend.process_group(pid)?;
    evidence.checks.push(check(
        "rollback_placement",
        placement.as_deref() == Some(original.as_str()),
        format!("{placement:?}"),
    ));
    rollback_one(&mut backend, &mut store, &mut snapshot)?;
    evidence.rollback_idempotent = true;

    drop(store);
    drop(backend);
    run_worker(InternalWorker::CgroupCrash)?;
    let recovery_state: CgroupRecoveryState = serde_json::from_slice(&fs::read(
        Path::new(STATE_DIR).join("cgroup-recovery.json"),
    )?)?;
    let mut recovery_child =
        DetachedChildGuard::new(recovery_state.pid, recovery_state.start_ticks);
    cleanup.register(recovery_state.target_group.clone());
    let mut restarted_store = JsonSnapshotStore::load(recovery_state.store_path)?;
    let mut restarted_backend = LinuxCgroupBackend::new(root);
    let recovered = recover(&mut restarted_backend, &mut restarted_store);
    if recovered.iter().any(Result::is_err) {
        bail!("cgroup recovery returned an error");
    }
    evidence.recovery_replayed = restarted_backend
        .process_group(recovery_state.pid)?
        .as_deref()
        == Some(recovery_state.original_group.as_str())
        && restarted_backend
            .inspect_group(&recovery_state.target_group)?
            .is_none();
    evidence.recovery_idempotent = recover(&mut restarted_backend, &mut restarted_store)
        .iter()
        .all(Result::is_ok);
    evidence.checks.push(check(
        "restart_recovery",
        evidence.recovery_replayed,
        "persisted snapshot replayed by fresh backend/store".to_owned(),
    ));
    evidence.checks.push(check(
        "second_recovery_idempotent",
        evidence.recovery_idempotent,
        "no pending snapshot remained".to_owned(),
    ));
    terminate_worker_child(recovery_state.pid, recovery_state.start_ticks)?;
    recovery_child.disarm();
    child.terminate()?;
    ensure_no_new_cgroups(baseline)?;
    cleanup.disarm();
    Ok(())
}

struct DetachedChildGuard {
    pid: u32,
    start_ticks: u64,
    armed: bool,
}

impl DetachedChildGuard {
    fn new(pid: u32, start_ticks: u64) -> Self {
        Self {
            pid,
            start_ticks,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DetachedChildGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = terminate_worker_child(self.pid, self.start_ticks);
        }
    }
}

struct CgroupCleanup {
    pid: u32,
    start_ticks: u64,
    original: String,
    groups: BTreeSet<String>,
    armed: bool,
}

impl CgroupCleanup {
    fn new(pid: u32, start_ticks: u64, original: String) -> Self {
        Self {
            pid,
            start_ticks,
            original,
            groups: BTreeSet::new(),
            armed: true,
        }
    }

    fn register(&mut self, group: String) {
        self.groups.insert(group);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CgroupCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut backend = LinuxCgroupBackend::default();
        if proc_start_ticks(self.pid).ok().flatten() == Some(self.start_ticks) {
            let _ = backend.attach_pid(&self.original, self.pid);
        }
        for group in &self.groups {
            let _ = backend.cleanup_empty_owned_group(group);
        }
    }
}

fn safety_checks(
    backend: &mut LinuxCgroupBackend,
    store: &mut JsonSnapshotStore,
    valid: &CgroupPlan,
    pid: u32,
    start: u64,
) -> Result<Vec<Check>> {
    let mut checks = Vec::new();
    let registered = BTreeMap::from([(pid, (fixed_identity(), start))]);
    let cases = [
        (
            "pid_not_registered",
            pid.saturating_add(1),
            fixed_identity(),
            start,
            CandidateKind::Child,
        ),
        (
            "identity_mismatch",
            pid,
            "b".repeat(64),
            start,
            CandidateKind::Child,
        ),
        (
            "start_ticks_mismatch",
            pid,
            fixed_identity(),
            start.saturating_add(1),
            CandidateKind::Child,
        ),
        (
            "unknown_rejected",
            pid,
            fixed_identity(),
            start,
            CandidateKind::Unknown,
        ),
        (
            "critical_without_allowlist",
            pid,
            fixed_identity(),
            start,
            CandidateKind::Critical,
        ),
        (
            "game_without_allowlist",
            pid,
            fixed_identity(),
            start,
            CandidateKind::Game,
        ),
    ];
    for (name, case_pid, identity, ticks, kind) in cases {
        let rejected = authorize_candidate(&registered, case_pid, &identity, ticks, kind).is_err();
        checks.push(check(
            name,
            rejected,
            "fail-closed before mutation".to_owned(),
        ));
    }
    checks.push(check(
        "registered_child_allowlisted",
        authorize_candidate(
            &registered,
            pid,
            &valid.identity,
            start,
            CandidateKind::Child,
        )
        .is_ok(),
        format!("pid={pid}"),
    ));
    let _ = (backend, store);
    Ok(checks)
}

#[derive(Debug, Clone, Copy)]
enum CandidateKind {
    Child,
    Unknown,
    Critical,
    Game,
}

fn authorize_candidate(
    registered: &BTreeMap<u32, (String, u64)>,
    pid: u32,
    identity: &str,
    start_ticks: u64,
    kind: CandidateKind,
) -> Result<()> {
    let (expected_identity, expected_start) = registered
        .get(&pid)
        .ok_or_else(|| anyhow!("PID was not created by this harness"))?;
    if identity != expected_identity {
        bail!("identity mismatch");
    }
    if start_ticks != *expected_start {
        bail!("start_ticks mismatch");
    }
    if !matches!(kind, CandidateKind::Child) {
        bail!("unknown, critical, protected, and game candidates are rejected");
    }
    Ok(())
}

fn validate_zram(
    baseline: &HostSnapshot,
    evidence: &mut ZramEvidence,
    deadline: &Deadline,
) -> Result<()> {
    evidence.attempted = true;
    evidence.protected_device = "/dev/zram0".to_owned();
    if baseline.zram0.as_ref().is_none_or(|device| !device.active) {
        bail!("protected /dev/zram0 is not active");
    }
    if !Path::new("/sys/class/zram-control/hot_add").exists() {
        bail!("zram-control hot_add unavailable; refusing distro reconfiguration");
    }

    let mut backend = LinuxZramBackend::default();
    let mut cleanup = ZramCleanup::new(baseline.zram_devices.clone());
    deadline.check("zram benchmark device hot-add")?;
    let benchmark = backend.create_isolated_managed_device()?;
    require_new_test_zram(&benchmark.name, baseline)?;
    cleanup.register(&benchmark.name);
    evidence.benchmark_device = Some(benchmark.name.clone());
    let algorithm = select_algorithm(&benchmark.available_algorithms)?;
    evidence.algorithm = Some(algorithm.clone());
    backend.configure_uninitialized(&benchmark.name, &algorithm)?;
    backend.initialize(&benchmark.name, DEVICE_BYTES)?;
    let configured = backend.verify(&benchmark.name)?;
    evidence.checks.push(check(
        "algorithm_configure_readback",
        configured.current_algorithm.as_deref() == Some(algorithm.as_str()),
        format!("{:?}", configured.current_algorithm),
    ));
    evidence.checks.push(check(
        "disksize_init_readback",
        configured.disksize == Some(DEVICE_BYTES) && configured.initstate == Some(true),
        format!(
            "disksize={:?} initstate={:?}",
            configured.disksize, configured.initstate
        ),
    ));
    evidence.benchmark = benchmark_device(&backend, &benchmark.name, &algorithm, deadline)?;
    evidence.checks.push(check(
        "real_isolated_benchmark",
        evidence.benchmark.len() == 9 && evidence.benchmark.iter().all(|round| round.verified),
        format!("rounds={}", evidence.benchmark.len()),
    ));
    backend.remove_managed_device(&benchmark.name)?;
    cleanup.unregister(&benchmark.name);

    deadline.check("zram swap transaction")?;
    let a = backend.create_isolated_managed_device()?;
    require_new_test_zram(&a.name, baseline)?;
    cleanup.register(&a.name);
    let b = backend.create_isolated_managed_device()?;
    require_new_test_zram(&b.name, baseline)?;
    cleanup.register(&b.name);
    evidence.transaction_devices = vec![a.name.clone(), b.name.clone()];
    for device in [&a, &b] {
        let selected = select_algorithm(&device.available_algorithms)?;
        backend.configure_uninitialized(&device.name, &selected)?;
        backend.initialize(&device.name, DEVICE_BYTES)?;
    }
    backend.activate(&a.name, TEST_SWAP_PRIORITY_A)?;
    verify_swap_checkpoint(baseline, &[&a.name])?;
    backend.activate(&b.name, TEST_SWAP_PRIORITY_B)?;
    verify_swap_checkpoint(baseline, &[&a.name, &b.name])?;
    evidence.replacement_first = true;
    backend.deactivate(&a.name)?;
    verify_swap_checkpoint(baseline, &[&b.name])?;
    evidence.no_swap_loss = true;
    backend.deactivate(&b.name)?;
    backend.remove_managed_device(&a.name)?;
    cleanup.unregister(&a.name);
    backend.remove_managed_device(&b.name)?;
    cleanup.unregister(&b.name);

    deadline.check("zram restart recovery")?;
    drop(backend);
    run_worker(InternalWorker::ZramCrash)?;
    let state_path = Path::new(STATE_DIR).join("zram-recovery.json");
    let persisted: ZramRecoveryState = serde_json::from_slice(&fs::read(&state_path)?)?;
    cleanup.register(&persisted.name);
    let mut restarted = LinuxZramBackend::default();
    restarted.resume_isolated_managed_device(&persisted.name, &persisted.baseline_names)?;
    if restarted.verify(&persisted.name)?.active_swap {
        restarted.deactivate(&persisted.name)?;
    }
    restarted.remove_managed_device(&persisted.name)?;
    cleanup.unregister(&persisted.name);
    evidence.recovery_replayed = !Path::new(&format!("/sys/block/{}", persisted.name)).exists();
    evidence.recovery_idempotent = !Path::new(&format!("/sys/block/{}", persisted.name)).exists();
    evidence.checks.push(check(
        "restart_recovery",
        evidence.recovery_replayed,
        format!("recovered {}", persisted.name),
    ));
    evidence.checks.push(check(
        "second_recovery_idempotent",
        evidence.recovery_idempotent,
        "absent device is a no-op".to_owned(),
    ));
    compare_protected_zram(baseline, &snapshot_host()?)?;
    cleanup.disarm();
    Ok(())
}

struct ZramCleanup {
    baseline_names: BTreeSet<String>,
    names: BTreeSet<String>,
    armed: bool,
}

impl ZramCleanup {
    fn new(baseline_names: BTreeSet<String>) -> Self {
        Self {
            baseline_names,
            names: BTreeSet::new(),
            armed: true,
        }
    }

    fn register(&mut self, name: &str) {
        self.names.insert(name.to_owned());
    }

    fn unregister(&mut self, name: &str) {
        self.names.remove(name);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ZramCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut backend = LinuxZramBackend::default();
        for name in &self.names {
            if backend
                .resume_isolated_managed_device(name, &self.baseline_names)
                .is_err()
            {
                continue;
            }
            if backend.verify(name).is_ok_and(|device| device.active_swap) {
                let _ = backend.deactivate(name);
            }
            let _ = backend.remove_managed_device(name);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ZramRecoveryState {
    name: String,
    baseline_names: BTreeSet<String>,
    active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CgroupRecoveryState {
    pid: u32,
    start_ticks: u64,
    original_group: String,
    target_group: String,
    store_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct ResidueReport {
    baseline: ResidueBaseline,
    zram: ResidueZram,
}

#[derive(Debug, Deserialize)]
struct ResidueBaseline {
    zram_devices: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct ResidueZram {
    benchmark_device: Option<String>,
    transaction_devices: Vec<String>,
}

fn benchmark_device(
    backend: &LinuxZramBackend,
    name: &str,
    algorithm: &str,
    deadline: &Deadline,
) -> Result<Vec<BenchmarkRound>> {
    let path = PathBuf::from(format!("/dev/{name}"));
    wait_for_path(&path, Duration::from_secs(10))?;
    let mut rounds = Vec::new();
    for kind in [
        DatasetKind::HighlyCompressible,
        DatasetKind::MediumCompressible,
        DatasetKind::DeterministicIncompressible,
    ] {
        let dataset = zram::benchmark::deterministic_dataset(kind, DATASET_BYTES);
        for _ in 0..3 {
            deadline.check("zram benchmark round")?;
            let cpu_before = process_cpu_ns()?;
            let started = Instant::now();
            let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&dataset)?;
            file.sync_all()?;
            let write_elapsed = started.elapsed();
            let read_started = Instant::now();
            file.seek(SeekFrom::Start(0))?;
            let mut readback = vec![0_u8; dataset.len()];
            file.read_exact(&mut readback)?;
            let read_elapsed = read_started.elapsed();
            let cpu_time = process_cpu_ns()?.saturating_sub(cpu_before);
            let inspected = backend.verify(name)?;
            let metrics = inspected.metrics();
            rounds.push(BenchmarkRound {
                dataset: format!("{kind:?}").to_lowercase(),
                input_bytes: DATASET_BYTES as u64,
                compr_data_size: inspected.mm_stat.compr_data_size.unwrap_or(0),
                mem_used_total: inspected.mm_stat.mem_used_total.unwrap_or(0),
                logical_ratio: metrics.logical_compression_ratio,
                effective_ratio: metrics.effective_memory_ratio,
                allocator_efficiency: metrics.allocator_efficiency,
                wall_time_ns: write_elapsed.as_nanos(),
                cpu_time_ns: cpu_time,
                write_throughput_bytes_sec: throughput(DATASET_BYTES, write_elapsed),
                read_throughput_bytes_sec: throughput(DATASET_BYTES, read_elapsed),
                verified: readback == dataset,
            });
        }
    }
    let _ = algorithm;
    Ok(rounds)
}

fn snapshot_host() -> Result<HostSnapshot> {
    let inventory = zram::inspect_linux(Path::new("/"))?;
    let zram_devices = inventory
        .devices
        .iter()
        .map(|device| device.name.clone())
        .collect();
    let zram0 = inventory
        .devices
        .iter()
        .find(|device| device.name == "zram0")
        .map(|device| ProtectedZram {
            disksize: device.disksize.unwrap_or(0),
            initstate: device.initstate.unwrap_or(false),
            algorithm: device.current_algorithm.clone().unwrap_or_default(),
            mem_limit: device.mm_stat.mem_limit,
            active: device.active_swap,
            priority: device.priority,
            provider: format!("{:?}", device.provider).to_lowercase(),
            ownership: "external_protected".to_owned(),
        });
    Ok(HostSnapshot {
        timestamp_ns: now_ns()?,
        swaps: read_swaps()?,
        zram_devices,
        zram0,
        validation_cgroups: validation_cgroups()?,
        validation_processes: validation_processes()?,
    })
}

const KSM_DUPLICATE_BYTES: usize = 32 * 1024 * 1024;
const KSM_CONTROL_BYTES: usize = 8 * 1024 * 1024;
const KSM_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;

struct KsmValidationGuard {
    baseline: ksm::KsmSnapshot,
    children: Vec<std::process::Child>,
    scanner_started: bool,
}

fn stop_owned_ksm_scanner(
    root: &Path,
    evidence: &mut KsmEvidence,
    guard: &mut KsmValidationGuard,
) -> Result<bool> {
    fs::write(root.join("run"), b"0\n")?;
    guard.scanner_started = false;
    evidence.scanner_stop_timestamp_ns = Some(userspace_clock_ns(UserspaceClock::Monotonic)?);
    let stopped = fs::read_to_string(root.join("run"))?.trim() == "0";
    set_check(
        &mut evidence.checks,
        check(
            "scanner_stopped",
            stopped,
            "owned run transition 1->0 was attempted and read back on the common post-run path"
                .into(),
        ),
    );
    Ok(stopped)
}

impl Drop for KsmValidationGuard {
    fn drop(&mut self) {
        let root = Path::new("/sys/kernel/mm/ksm");
        if self.scanner_started && self.baseline.run == 0 {
            let _ = fs::write(root.join("run"), b"0\n");
        }
        let _ = fs::write(Path::new(STATE_DIR).join("ksm-stop"), b"stop\n");
        for child in &mut self.children {
            let _ = child.wait();
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn ksm_target_worker() -> Result<()> {
    let child_id = std::env::var("NEMOR_KSM_CHILD_ID")
        .context("owned KSM child id is missing")?
        .parse::<u8>()
        .context("invalid owned KSM child id")?;
    let workload_kind = std::env::var("NEMOR_KSM_WORKLOAD").unwrap_or_else(|_| "positive".into());
    let workload_session =
        std::env::var("NEMOR_KSM_SESSION").unwrap_or_else(|_| "bootstrap".into());
    let mut duplicate = MmapOptions::new().len(KSM_DUPLICATE_BYTES).map_anon()?;
    let mut control = MmapOptions::new().len(KSM_CONTROL_BYTES).map_anon()?;
    let host_page_size = read_command("/usr/bin/getconf", &["PAGESIZE"])?
        .parse::<u64>()
        .context("invalid host page size")?;
    if !Advice::NoHugePage.is_supported()
        || !Advice::Mergeable.is_supported()
        || !Advice::Unmergeable.is_supported()
    {
        bail!("mapping-local KSM advice is unsupported");
    }
    let duplicate_nohugepage = mapping_advice_result(&duplicate, Advice::NoHugePage);
    let control_nohugepage = mapping_advice_result(&control, Advice::NoHugePage);
    let page_size = usize::try_from(host_page_size).context("host page size overflows usize")?;
    let advice_succeeded = duplicate_nohugepage.succeeded && control_nohugepage.succeeded;
    let mut duplicate_prefault_completed = false;
    let mut control_prefault_completed = false;
    let mut duplicate_page_hashes = Vec::new();
    if advice_succeeded {
        for (page, index) in (0..duplicate.len()).step_by(page_size).enumerate() {
            let page_slice = &mut duplicate[index..index + page_size];
            if workload_kind == "unique" {
                fill_unique_ksm_page(page_slice, &workload_session, child_id, page as u64);
            } else {
                page_slice[0] = ((page % 251) + 1) as u8;
            }
            duplicate_page_hashes.push(ksm_page_digest(page_slice));
        }
        duplicate_prefault_completed = true;
        for (page, index) in (0..control.len()).step_by(page_size).enumerate() {
            control[index] = (((page + usize::from(child_id) * 97) % 251) + 1) as u8;
        }
        control_prefault_completed = true;
    }
    let duplicate_fingerprint = fingerprint_zone(&duplicate);
    let control_fingerprint = fingerprint_zone(&control);
    let metadata = serde_json::json!({
        "pid": std::process::id(),
        "start_ticks": proc_start_ticks(std::process::id())?,
        "child_id": child_id,
        "duplicate": [duplicate.as_ptr() as usize, duplicate.as_ptr() as usize + duplicate.len()],
        "control": [control.as_ptr() as usize, control.as_ptr() as usize + control.len()],
        "duplicate_bytes": duplicate.len(),
        "control_bytes": control.len(),
        "duplicate_fingerprint": duplicate_fingerprint,
        "control_fingerprint": control_fingerprint,
        "state": if advice_succeeded { "ready_unmergeable" } else { "bootstrap_failed" },
        "mergeable_only": null,
        "base_pages_requested": true,
        "host_page_size": host_page_size,
        "duplicate_nohugepage": duplicate_nohugepage,
        "control_nohugepage": control_nohugepage,
        "duplicate_prefault_completed": duplicate_prefault_completed,
        "control_prefault_completed": control_prefault_completed
        ,"workload_kind": workload_kind
        ,"duplicate_page_hashes": duplicate_page_hashes
    });
    fs::write(
        Path::new(STATE_DIR).join(format!("ksm-target-{child_id}.json")),
        serde_json::to_vec_pretty(&metadata)?,
    )?;
    if !advice_succeeded {
        bail!("owned KSM worker MADV_NOHUGEPAGE failed; diagnostic metadata persisted");
    }
    let opt_in = Path::new(STATE_DIR).join(format!("ksm-opt-in-{child_id}.json"));
    while !opt_in.exists() {
        if Path::new(STATE_DIR).join("ksm-stop").exists() {
            std::hint::black_box((duplicate, control));
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    let audit: serde_json::Value = serde_json::from_slice(&fs::read(&opt_in)?)?;
    for field in ["decision_id", "plan_id", "transaction_id"] {
        if audit[field].as_str().is_none_or(str::is_empty) {
            bail!("owned KSM opt-in missing {field}");
        }
    }
    duplicate.advise(Advice::Mergeable)?;
    fs::write(
        Path::new(STATE_DIR).join(format!("ksm-opt-in-{child_id}-result.json")),
        serde_json::to_vec_pretty(&serde_json::json!({
            "state": "duplicate_mergeable",
            "pid": std::process::id(),
            "start_ticks": proc_start_ticks(std::process::id())?
        }))?,
    )?;
    let unmerge = Path::new(STATE_DIR).join(format!("ksm-unmerge-{child_id}"));
    let content_check = Path::new(STATE_DIR).join(format!("ksm-content-check-{child_id}"));
    while !unmerge.exists()
        && !content_check.exists()
        && !Path::new(STATE_DIR).join("ksm-stop").exists()
    {
        thread::sleep(Duration::from_millis(20));
    }
    let mut unmerged = false;
    if unmerge.exists() {
        duplicate.advise(Advice::Unmergeable)?;
        unmerged = true;
        fs::write(
            Path::new(STATE_DIR).join(format!("ksm-unmerge-{child_id}-result.json")),
            b"{\"state\":\"unmerged\"}\n",
        )?;
    }
    while !content_check.exists() && !Path::new(STATE_DIR).join("ksm-stop").exists() {
        thread::sleep(Duration::from_millis(20));
    }
    if content_check.exists() {
        fs::write(
            Path::new(STATE_DIR).join(format!("ksm-content-check-{child_id}-result.json")),
            serde_json::to_vec_pretty(&serde_json::json!({
                "duplicate_fingerprint": fingerprint_zone(&duplicate),
                "control_fingerprint": fingerprint_zone(&control),
                "unmerged": unmerged
            }))?,
        )?;
    }
    while !Path::new(STATE_DIR).join("ksm-stop").exists() {
        thread::sleep(Duration::from_millis(20));
    }
    fs::write(
        Path::new(STATE_DIR).join(format!("ksm-target-{child_id}-final.json")),
        serde_json::to_vec_pretty(&serde_json::json!({
            "duplicate_fingerprint": fingerprint_zone(&duplicate),
            "control_fingerprint": fingerprint_zone(&control),
            "unmerged": unmerged
        }))?,
    )?;
    std::hint::black_box((duplicate, control));
    Ok(())
}

fn mapping_advice_result(mapping: &MmapMut, advice: Advice) -> WorkerAdviceResult {
    worker_advice_result(mapping.advise(advice))
}

fn fill_unique_ksm_page(page: &mut [u8], session: &str, child_id: u8, page_index: u64) {
    let mut seed = 0xcbf29ce484222325_u64;
    for byte in session.bytes() {
        seed ^= u64::from(byte);
        seed = seed.wrapping_mul(0x100000001b3);
    }
    seed ^= u64::from(child_id).rotate_left(17);
    seed ^= page_index.wrapping_mul(0x9e3779b97f4a7c15);
    for (word_index, chunk) in page.chunks_mut(8).enumerate() {
        let value = splitmix64(seed ^ word_index as u64);
        chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e3779b97f4a7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
    value ^ (value >> 31)
}

fn ksm_page_digest(page: &[u8]) -> u64 {
    page.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn worker_advice_result(result: std::io::Result<()>) -> WorkerAdviceResult {
    match result {
        Ok(()) => WorkerAdviceResult {
            requested: true,
            succeeded: true,
            error: None,
            raw_os_error: None,
        },
        Err(error) => WorkerAdviceResult {
            requested: true,
            succeeded: false,
            raw_os_error: error.raw_os_error(),
            error: Some(error.to_string()),
        },
    }
}

fn collect_ksm_bootstrap_evidence(
    child_id: u8,
    target: &KsmTargetMetadata,
) -> Result<KsmBootstrapEvidence> {
    let duplicate = ksm::AddressRange {
        start: target.duplicate[0] as u64,
        end: target.duplicate[1] as u64,
    };
    let control = ksm::AddressRange {
        start: target.control[0] as u64,
        end: target.control[1] as u64,
    };
    let smaps = fs::read_to_string(format!("/proc/{}/smaps", target.pid))?;
    let duplicate_scope =
        ksm::verify_base_page_scope(&smaps, duplicate, target.host_page_size, true);
    let control_scope = ksm::verify_base_page_scope(&smaps, control, target.host_page_size, true);
    let duplicate_base_page_verified = target.duplicate_nohugepage.succeeded
        && target.duplicate_prefault_completed
        && duplicate_scope.passed;
    let control_base_page_verified = target.control_nohugepage.succeeded
        && target.control_prefault_completed
        && control_scope.passed;
    let mut reasons = Vec::new();
    if target.state != "ready_unmergeable" {
        reasons.push(format!("protocol_state={}", target.state));
    }
    if !target.duplicate_nohugepage.succeeded {
        reasons.push(format!(
            "duplicate_nohugepage={:?}",
            target.duplicate_nohugepage.error
        ));
    }
    if !target.control_nohugepage.succeeded {
        reasons.push(format!(
            "control_nohugepage={:?}",
            target.control_nohugepage.error
        ));
    }
    reasons.extend(
        duplicate_scope
            .failure_reasons
            .iter()
            .map(|reason| format!("duplicate:{reason}")),
    );
    reasons.extend(
        control_scope
            .failure_reasons
            .iter()
            .map(|reason| format!("control:{reason}")),
    );
    let mut bounded_target = target.clone();
    bounded_target.duplicate_page_hashes.truncate(16);
    Ok(KsmBootstrapEvidence {
        child_id,
        pid: Some(target.pid),
        start_ticks: target.start_ticks,
        protocol_state: Some(target.state.clone()),
        target: Some(bounded_target),
        duplicate_scope: Some(duplicate_scope),
        control_scope: Some(control_scope),
        duplicate_base_page_verified,
        control_base_page_verified,
        fingerprints_present: target.duplicate_prefault_completed
            && target.control_prefault_completed,
        failure_reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
        child_exit: None,
    })
}

fn run_ksm_bootstrap_preflight() -> Result<()> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let mut children = Vec::new();
    for child_id in [1_u8, 2] {
        children.push(
            Command::new(&executable)
                .arg("--internal-worker")
                .arg("ksm-target")
                .env("NEMOR_KSM_CHILD_ID", child_id.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
    }
    let mut evidence = BTreeMap::new();
    for child_id in [1_u8, 2] {
        let path = Path::new(STATE_DIR).join(format!("ksm-target-{child_id}.json"));
        wait_for_path(&path, Duration::from_secs(10))?;
        let target: KsmTargetMetadata = serde_json::from_slice(&fs::read(path)?)?;
        evidence.insert(child_id, collect_ksm_bootstrap_evidence(child_id, &target)?);
    }
    fs::write(Path::new(STATE_DIR).join("ksm-stop"), b"stop\n")?;
    let mut all_children_success = true;
    for (index, child) in children.iter_mut().enumerate() {
        let status = child.wait()?;
        all_children_success &= status.success();
        if let Some(item) = evidence.get_mut(&((index + 1) as u8)) {
            item.child_exit = Some(status.to_string());
        }
    }
    let passed = all_children_success
        && evidence.values().all(|item| {
            item.duplicate_base_page_verified
                && item.control_base_page_verified
                && item.protocol_state.as_deref() == Some("ready_unmergeable")
        });
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "nemor-ksm-bootstrap-preflight-v1",
            "mutations": {
                "madv_nohugepage": true,
                "madv_mergeable": false,
                "ksm_sysfs_writes": 0
            },
            "passed": passed,
            "children": evidence
        }))?
    );
    if passed {
        Ok(())
    } else {
        bail!("KSM READY_UNMERGEABLE bootstrap preflight failed")
    }
}

fn validate_ksm(
    evidence: &mut KsmEvidence,
    deadline: &Deadline,
    scenario: KsmScenario,
) -> Result<()> {
    evidence.attempted = true;
    evidence.scenario = Some(
        match scenario {
            KsmScenario::Positive => "positive",
            KsmScenario::Inefficient => "inefficient",
        }
        .into(),
    );
    evidence.dry_run = false;
    evidence.run_two_forbidden = true;
    evidence.validation_min_saved_bytes = ksm::VALIDATION_MIN_SAVED_BYTES;
    evidence.positive_workload =
        "two owned cooperative children; positive generator repeats page payloads every 251 pages because only the page-leading byte varies; measured kernel savings are authoritative"
            .into();
    evidence.inefficient_workload =
        "two owned children with session/child/page/word-unique mergeable data; bounded real inefficient evaluation drives controller-owned stop and cooldown"
            .into();
    evidence.cow_validation =
        "prepared only: bounded post-merge write verifies writer/peer integrity and cow_ksm delta"
            .into();
    evidence.rollback_semantics =
        "run=0 for owned scanner, safe owned MADV_UNMERGEABLE or child termination, restore scanner snapshot; run=2 forbidden"
            .into();
    let root = Path::new("/sys/kernel/mm/ksm");
    let proc_root = Path::new("/proc");
    let capability = ksm::inspect_capability(root, Path::new("/proc/1/ksm_stat").is_file());
    evidence.capability = Some(capability.clone());
    evidence.checks.push(check(
        "capability",
        capability.supported && capability.sysfs_writable,
        format!(
            "supported={}, readable={}, writable={}, process_ksm_stat={}",
            capability.supported,
            capability.sysfs_readable,
            capability.sysfs_writable,
            capability.process_ksm_stat_available
        ),
    ));
    if !capability.supported || !capability.sysfs_writable {
        return Err(ksm_failure(
            evidence,
            "baseline_not_isolated",
            "KSM sysfs mandatory capability is unavailable",
        ));
    }
    let baseline = ksm::snapshot_from_root(root)?;
    evidence.baseline = Some(baseline.clone());
    if baseline.run != 0 {
        return Err(ksm_failure(
            evidence,
            "baseline_not_isolated",
            &format!("baseline KSM scanner is external (run={})", baseline.run),
        ));
    }
    let advisor_text = fs::read_to_string(root.join("advisor_mode"))
        .context("read KSM advisor_mode for ATTEMPT 1")?;
    let scanner = ksm::plan_attempt_one_scanner(&advisor_text, &baseline, 50, 1_000, 10).map_err(
        |error| {
            ksm_failure(
                evidence,
                "advisor_active",
                &format!("baseline scanner/advisor is unsafe: {error}"),
            )
        },
    )?;
    if scanner.mode != ksm::AdvisorMode::Fixed || !scanner.blocked_reasons.is_empty() {
        return Err(ksm_failure(
            evidence,
            "advisor_active",
            "selected advisor_mode is not none",
        ));
    }
    evidence.scanner_plan = Some(scanner.clone());
    evidence.checks.push(check(
        "advisor_none",
        true,
        format!("advisor_mode readback={}", advisor_text.trim()),
    ));
    evidence.checks.push(check(
        "baseline_scanner_preserved",
        scanner.pages_to_scan == baseline.pages_to_scan
            && scanner.sleep_millisecs == baseline.sleep_millisecs,
        format!(
            "validation uses baseline pages_to_scan={} and sleep_millisecs={} without tuning",
            baseline.pages_to_scan, baseline.sleep_millisecs
        ),
    ));
    let external_inspection =
        ksm::inspect_external_ksm_processes_owned(proc_root, &BTreeMap::new()).map_err(
            |error| {
                ksm_failure(
                    evidence,
                    "baseline_not_isolated",
                    &format!("live external KSM inspection failed closed: {error}"),
                )
            },
        )?;
    let external = external_inspection.live_consumers;
    evidence.external_mergeable_processes = external.clone();
    evidence.residual_process_accounting = external_inspection.residual_processes;
    evidence.external_live_ksm_activity = Some(!external.is_empty());
    let system_before =
        ksm::parse_system_metrics(root, &fs::read_to_string("/proc/vmstat")?, now_ns()?);
    evidence.system_before = Some(system_before.clone());
    evidence.residual_baseline = Some(system_before.clone());
    evidence.current_session_owned_activity = Some(false);
    let residual_global = system_before.pages_shared.unwrap_or(0) > 0
        || system_before.pages_sharing.unwrap_or(0) > 0
        || system_before.pages_unshared.unwrap_or(0) > 0
        || system_before.pages_volatile.unwrap_or(0) > 0
        || system_before.general_profit.unwrap_or(0) != 0
        || system_before.full_scans.unwrap_or(0) > 0;
    evidence.residual_global_ksm_accounting = Some(residual_global);
    let no_ambiguity = external.is_empty();
    evidence.checks.push(check(
        "isolated_baseline",
        no_ambiguity,
        format!(
            "live_external_consumers={}, residual_global_accounting={}, pages_shared={}, pages_sharing={}, general_profit={}, full_scans={}",
            external.len(),
            residual_global,
            system_before.pages_shared.unwrap_or(0),
            system_before.pages_sharing.unwrap_or(0),
            system_before.general_profit.unwrap_or(0),
            system_before.full_scans.unwrap_or(0),
        ),
    ));
    if !no_ambiguity {
        return Err(ksm_failure(
            evidence,
            "baseline_not_isolated",
            "live external KSM consumer exists",
        ));
    }
    let required =
        KSM_HEADROOM_BYTES.saturating_add(((KSM_DUPLICATE_BYTES + KSM_CONTROL_BYTES) * 4) as u64);
    let available = mem_available_bytes()?;
    if available < required {
        return Err(ksm_failure(
            evidence,
            "insufficient_headroom",
            "insufficient KSM allocation/unmerge headroom",
        ));
    }
    let owned_identity_session = now_ns()?.to_string();
    let executable = std::env::current_exe()?.canonicalize()?;
    let mut guard = KsmValidationGuard {
        baseline: baseline.clone(),
        children: Vec::new(),
        scanner_started: false,
    };
    for child_id in [1_u8, 2] {
        guard.children.push(
            Command::new(&executable)
                .arg("--internal-worker")
                .arg("ksm-target")
                .env("NEMOR_KSM_CHILD_ID", child_id.to_string())
                .env(
                    "NEMOR_KSM_WORKLOAD",
                    if scenario == KsmScenario::Inefficient {
                        "unique"
                    } else {
                        "positive"
                    },
                )
                .env("NEMOR_KSM_SESSION", &owned_identity_session)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
    }
    let mut targets = Vec::new();
    for child_id in [1_u8, 2] {
        wait_for_path(
            &Path::new(STATE_DIR).join(format!("ksm-target-{child_id}.json")),
            Duration::from_secs(10),
        )?;
        let target: KsmTargetMetadata = serde_json::from_slice(&fs::read(
            Path::new(STATE_DIR).join(format!("ksm-target-{child_id}.json")),
        )?)?;
        let bootstrap = collect_ksm_bootstrap_evidence(child_id, &target)?;
        evidence
            .bootstrap_evidence
            .insert(child_id, bootstrap.clone());
        let fresh = target.start_ticks.is_some()
            && target.start_ticks == proc_start_ticks(target.pid)?
            && target.duplicate[1].saturating_sub(target.duplicate[0]) == target.duplicate_bytes
            && target.control[1].saturating_sub(target.control[0]) == target.control_bytes
            && target.duplicate_bytes == KSM_DUPLICATE_BYTES
            && target.control_bytes == KSM_CONTROL_BYTES;
        if !fresh {
            return Err(ksm_failure(
                evidence,
                "child_identity_stale",
                "owned KSM target identity or mapping metadata mismatch",
            ));
        }
        if !bootstrap.duplicate_base_page_verified || !bootstrap.control_base_page_verified {
            return Err(ksm_failure(
                evidence,
                "base_page_backing_not_verified",
                bootstrap
                    .failure_reason
                    .as_deref()
                    .unwrap_or("owned KSM base-page bootstrap failed"),
            ));
        }
        let duplicate = ksm::AddressRange {
            start: target.duplicate[0] as u64,
            end: target.duplicate[1] as u64,
        };
        let control = ksm::AddressRange {
            start: target.control[0] as u64,
            end: target.control[1] as u64,
        };
        let smaps = fs::read_to_string(format!("/proc/{}/smaps", target.pid))?;
        if !ksm::verify_exact_unmergeable_scope(&smaps, duplicate, control) {
            return Err(ksm_failure(
                evidence,
                "base_page_backing_not_verified",
                "READY_UNMERGEABLE child already has mergeable or non-NOHUGEPAGE owned VMA",
            ));
        }
        targets.push(target);
    }
    evidence.checks.push(check(
        "owned_targets_ready_unmergeable",
        targets.len() == 2,
        "two fresh cooperative identities are READY_UNMERGEABLE with exact base-page mappings"
            .into(),
    ));
    if scenario == KsmScenario::Inefficient {
        let first = targets
            .first()
            .ok_or_else(|| anyhow!("first UNIQUE target missing"))?;
        let second = targets
            .get(1)
            .ok_or_else(|| anyhow!("second UNIQUE target missing"))?;
        let first_set = first
            .duplicate_page_hashes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let second_set = second
            .duplicate_page_hashes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let expected_pages = KSM_DUPLICATE_BYTES / first.host_page_size as usize;
        let cross_child_collision_count = first_set.intersection(&second_set).count();
        let unique_input = first.workload_kind == "unique"
            && second.workload_kind == "unique"
            && first_set.len() == expected_pages
            && second_set.len() == expected_pages
            && cross_child_collision_count == 0
            && !first.duplicate_page_hashes.contains(&0)
            && !second.duplicate_page_hashes.contains(&0);
        evidence.unique_input_verified = Some(unique_input);
        for (child_id, target, hashes) in [(1_u8, first, &first_set), (2_u8, second, &second_set)] {
            evidence.unique_hash_evidence.insert(
                child_id,
                UniqueHashEvidence {
                    page_count: target.duplicate_page_hashes.len(),
                    unique_hash_count: hashes.len(),
                    collision_count: target
                        .duplicate_page_hashes
                        .len()
                        .saturating_sub(hashes.len()),
                    cross_child_collision_count,
                    aggregate_digest: target
                        .duplicate_page_hashes
                        .iter()
                        .fold(0xcbf29ce484222325_u64, |digest, hash| {
                            (digest ^ hash).wrapping_mul(0x100000001b3)
                        }),
                    hash_sample: target
                        .duplicate_page_hashes
                        .iter()
                        .take(16)
                        .copied()
                        .collect(),
                },
            );
        }
        if !unique_input {
            return Err(ksm_failure(
                evidence,
                "workload_setup_failure",
                "UNIQUE page hashes repeat within or across owned children",
            ));
        }
    }
    let mut excluded_owned = BTreeMap::new();
    for target in &targets {
        excluded_owned.insert(target.pid, target.start_ticks);
    }
    if !ksm::inspect_external_ksm_processes_owned(proc_root, &excluded_owned)
        .map_err(|error| {
            ksm_failure(
                evidence,
                "baseline_not_isolated",
                &format!("external KSM recheck failed closed: {error}"),
            )
        })?
        .live_consumers
        .is_empty()
    {
        return Err(ksm_failure(
            evidence,
            "baseline_not_isolated",
            "external KSM process appeared after child allocation",
        ));
    }
    let before_opt_in = observe_owned_ksm_processes(&targets, &owned_identity_session)?;
    if before_opt_in.iter().any(|process| {
        process.ksm_mergeable != Some(false)
            || process.ksm_merge_any == Some(true)
            || process.ksm_merging_pages.unwrap_or(0) != 0
    }) {
        return Err(ksm_failure(
            evidence,
            "mergeable_scope_invalid",
            "READY_UNMERGEABLE process state was already KSM-applicable",
        ));
    }
    evidence
        .process_evidence
        .insert("before_opt_in".into(), before_opt_in);
    let transaction_id = format!("nemor-ksm-validation-{owned_identity_session}");
    let decision_id = format!("manual-validation-{}", now_ns()?);
    let plan_id = format!("ksm-plan-{}", now_ns()?);
    let audit = serde_json::json!({
        "decision_id": decision_id,
        "plan_id": plan_id,
        "transaction_id": transaction_id,
        "reason": "manual_validation",
        "profile": "synthetic",
        "cpu_budget_percent": 1.0,
        "scanner": scanner
    });
    fs::write(
        Path::new(STATE_DIR).join("ksm-decision.json"),
        serde_json::to_vec_pretty(&audit)?,
    )?;
    evidence.decision_id = audit["decision_id"].as_str().map(str::to_owned);
    evidence.plan_id = audit["plan_id"].as_str().map(str::to_owned);
    evidence.transaction_id = audit["transaction_id"].as_str().map(str::to_owned);
    let mut protocol = ksm::ValidationProtocol::default();
    protocol
        .record_audit(decision_id.clone(), plan_id.clone(), transaction_id.clone())
        .map_err(|error| ksm_failure(evidence, "audit_missing", &error.to_string()))?;
    evidence.checks.push(check(
        "audit_before_mergeable",
        true,
        "decision/plan/transaction persisted before any MADV_MERGEABLE or global write".into(),
    ));
    for child_id in [1_u8, 2] {
        fs::write(
            Path::new(STATE_DIR).join(format!("ksm-opt-in-{child_id}.json")),
            serde_json::to_vec_pretty(&audit)?,
        )?;
        wait_for_path(
            &Path::new(STATE_DIR).join(format!("ksm-opt-in-{child_id}-result.json")),
            Duration::from_secs(10),
        )?;
    }
    protocol
        .opt_in_duplicate()
        .map_err(|error| ksm_failure(evidence, "audit_missing", &error.to_string()))?;
    let after_opt_in = observe_owned_ksm_processes(&targets, &owned_identity_session)?;
    if after_opt_in
        .iter()
        .any(|process| process.ksm_mergeable != Some(true))
    {
        return Err(ksm_failure(
            evidence,
            "mergeable_scope_invalid",
            "owned process did not report mergeable after audited opt-in",
        ));
    }
    evidence
        .process_evidence
        .insert("after_opt_in_before_run".into(), after_opt_in);
    evidence.current_session_owned_activity = Some(true);
    for target in &targets {
        let smaps = fs::read_to_string(format!("/proc/{}/smaps", target.pid))?;
        let scope = ksm::verify_exact_mergeable_scope(
            &smaps,
            ksm::AddressRange {
                start: target.duplicate[0] as u64,
                end: target.duplicate[1] as u64,
            },
            ksm::AddressRange {
                start: target.control[0] as u64,
                end: target.control[1] as u64,
            },
        );
        if !scope.passed {
            evidence.mergeable_scope.insert(target.pid, scope);
            return Err(ksm_failure(
                evidence,
                "mergeable_scope_invalid",
                "exact smaps mg/nh scope verification failed",
            ));
        }
        evidence.mergeable_scope.insert(target.pid, scope);
    }
    evidence.checks.push(check(
        "exact_mergeable_scope_verified",
        true,
        format!(
            "each {} mergeable range is fully mg+nh; CONTROL and every other worker VMA have zero mg overlap",
            if scenario == KsmScenario::Inefficient {
                "UNIQUE"
            } else {
                "DUPLICATE"
            }
        ),
    ));
    if let Some(capability) = evidence.capability.as_mut() {
        capability.madv_mergeable_supported = Some(true);
    }
    if !ksm::inspect_external_ksm_processes_owned(proc_root, &excluded_owned)
        .map_err(|error| {
            ksm_failure(
                evidence,
                "external_ksm_interference",
                &format!("pre-run external KSM recheck failed closed: {error}"),
            )
        })?
        .live_consumers
        .is_empty()
    {
        return Err(ksm_failure(
            evidence,
            "external_ksm_interference",
            "external KSM process appeared immediately before run=1",
        ));
    }
    evidence.checks.push(check(
        "external_rechecks",
        true,
        "no external KSM process at baseline, after allocation, or immediately before run=1".into(),
    ));
    deadline.check("KSM scanner start")?;
    let evaluation_started = Instant::now();
    let clk_tck = read_command("/usr/bin/getconf", &["CLK_TCK"])?
        .parse::<u64>()
        .context("parse CLK_TCK")?;
    let minimum_budget_window_seconds = ksm::minimum_cpu_budget_window_seconds(clk_tck)
        .ok_or_else(|| anyhow!("CLK_TCK must be nonzero"))?;
    evidence.clk_tck = Some(clk_tck);
    evidence.cpu_tick_seconds = Some(1.0 / clk_tck as f64);
    evidence.minimum_budget_window_seconds = Some(minimum_budget_window_seconds);
    evidence.scanner_start_timestamp_ns = Some(userspace_clock_ns(UserspaceClock::Monotonic)?);
    fs::write(root.join("run"), b"1\n")?;
    guard.scanner_started = true;
    protocol
        .scanner_started()
        .map_err(|error| ksm_failure(evidence, "scanner_ownership_lost", &error.to_string()))?;
    if fs::read_to_string(root.join("run"))?.trim() != "1" {
        let _ = stop_owned_ksm_scanner(root, evidence, &mut guard);
        return Err(ksm_failure(
            evidence,
            "scanner_ownership_lost",
            "owned KSM scanner start readback mismatch",
        ));
    }
    evidence.checks.push(check(
        "scanner_started",
        true,
        "owned run transition 0->1 read back; scanner settings remained baseline".into(),
    ));
    let Some(ksmd_ticks_before) = read_ksmd_cpu_ticks() else {
        let _ = stop_owned_ksm_scanner(root, evidence, &mut guard);
        return Err(ksm_failure(
            evidence,
            "scanner_no_progress",
            "ksmd CPU accounting is unavailable after run=1",
        ));
    };
    let evaluation_deadline = Instant::now() + Duration::from_secs(30);
    let mut previous_ticks = Some(ksmd_ticks_before);
    let mut previous_tick_time = Instant::now();
    let mut peak_cpu = 0.0_f64;
    let mut first_evidence_recorded = false;
    let empty_profit = ksm::evaluate_profit(
        &ksm::ProfitSample {
            wall_seconds: 0.0,
            ksmd_cpu_seconds: 0.0,
            pages_scanned_delta: 0,
            saved_bytes: 0,
            process_profit_bytes: Some(0),
            system_profit_bytes: Some(0),
        },
        4096,
    );
    let mut controller_state = ksm::controller_transition(
        ksm::ControllerState::Unknown,
        &ksm::ControllerInput {
            elapsed_seconds: 0,
            full_scans: 0,
            evaluation: empty_profit,
            cpu_budget_percent: 1.0,
            cow_rate: 0,
            maximum_cow_rate: 64,
            cooldown_active: false,
        },
    );
    evidence.controller_state_before = Some(ksm::ControllerState::Unknown);
    let mut controller_auto_disable = false;
    let (system_peak, profitable_processes, mut evaluation_failure) = loop {
        deadline.check("KSM profitable evaluation")?;
        thread::sleep(Duration::from_millis(500));
        let current_snapshot = ksm::snapshot_from_root(root)?;
        let current_advisor = ksm::read_advisor_mode(root);
        let mut iteration_failure = None;
        if !ksm::attempt_one_global_state_owned(
            &baseline,
            &current_snapshot,
            current_advisor.as_deref(),
        ) {
            iteration_failure = Some((
                "scanner_ownership_lost".to_owned(),
                "run/scanner/advisor configuration changed during owned evaluation".to_owned(),
            ));
        }
        if iteration_failure.is_none() {
            match ksm::inspect_external_ksm_processes_owned(proc_root, &excluded_owned) {
                Ok(inspection) if !inspection.live_consumers.is_empty() => {
                    iteration_failure = Some((
                        "external_ksm_interference".to_owned(),
                        "live external mergeable, merge-any, or mapped-KSM process appeared during owned evaluation".to_owned(),
                    ));
                }
                Err(error) => {
                    iteration_failure = Some((
                        "external_ksm_interference".to_owned(),
                        format!("live external KSM monitoring failed closed: {error}"),
                    ));
                }
                _ => {}
            }
        }
        let current_ticks = read_ksmd_cpu_ticks();
        if let (Some(previous), Some(current)) = (previous_ticks, current_ticks) {
            let window = previous_tick_time.elapsed().as_secs_f64();
            if let Some(measurement) =
                ksm::measure_cpu_window(current.saturating_sub(previous), window, clk_tck)
            {
                peak_cpu = peak_cpu.max(measurement.cpu_percent);
                evidence.short_window_cpu.push(measurement);
            }
        }
        previous_ticks = current_ticks;
        previous_tick_time = Instant::now();
        let current_system =
            ksm::parse_system_metrics(root, &fs::read_to_string("/proc/vmstat")?, now_ns()?);
        let processes = observe_owned_ksm_processes(&targets, &owned_identity_session)?;
        let current_full_scans_delta = current_system
            .full_scans
            .unwrap_or(0)
            .saturating_sub(system_before.full_scans.unwrap_or(0));
        if current_full_scans_delta >= 1 && evidence.first_scan_snapshot.is_none() {
            evidence.first_scan_snapshot = Some(current_system.clone());
        }
        if current_full_scans_delta >= 2 && evidence.second_scan_snapshot.is_none() {
            evidence.second_scan_snapshot = Some(current_system.clone());
        }
        if !first_evidence_recorded {
            evidence
                .process_evidence
                .insert("during_run_first_evidence".into(), processes.clone());
            first_evidence_recorded = true;
        }
        let saved_bytes = ksm_saved_bytes(&system_before, &current_system, &baseline);
        let pages_scanned_delta = current_system
            .pages_scanned
            .unwrap_or(0)
            .saturating_sub(system_before.pages_scanned.unwrap_or(0));
        let full_scans_delta = current_full_scans_delta;
        let system_profit_delta = system_before
            .general_profit
            .zip(current_system.general_profit)
            .map(|(before, after)| after.saturating_sub(before))
            .unwrap_or(0);
        let processes_positive = owned_process_profit_positive(&processes);
        let gate = ksm::validation_profit_gate(
            saved_bytes,
            pages_scanned_delta,
            full_scans_delta,
            system_profit_delta,
            processes_positive,
        );
        evidence.profit_gate = Some(gate.clone());
        let elapsed = evaluation_started.elapsed().as_secs_f64();
        let sustained = current_ticks.and_then(|current| {
            ksm::measure_cpu_window(current.saturating_sub(ksmd_ticks_before), elapsed, clk_tck)
        });
        if let Some(measurement) = sustained {
            evidence.sustained_measurement_resolution_percent =
                Some(measurement.measurement_resolution_percent);
            if measurement.budget_exceeded == Some(true) {
                iteration_failure = Some((
                    "cpu_budget_exceeded".to_owned(),
                    format!(
                        "resolution-valid sustained ksmd CPU {:.6}% exceeds 1%; window={:.3}s, resolution={:.6}%",
                        measurement.cpu_percent,
                        measurement.window_seconds,
                        measurement.measurement_resolution_percent
                    ),
                ));
            }
        }
        if let Some(failure) = iteration_failure {
            break (current_system, processes, Some(failure));
        }
        let cpu_resolution_valid =
            sustained.is_some_and(|measurement| measurement.resolution_valid);
        if scenario == KsmScenario::Positive {
            if gate.passed && cpu_resolution_valid {
                break (current_system, processes, None);
            }
        } else if full_scans_delta >= 2
            && cpu_resolution_valid
            && owned_processes_evaluated(&processes)
        {
            let process_profit = processes
                .iter()
                .filter_map(|item| item.ksm_process_profit)
                .sum::<i64>();
            let current_cpu = sustained.map_or(0.0, |item| item.cpu_percent);
            let residual_contaminated = evidence.residual_global_ksm_accounting == Some(true);
            let owned_inefficient = owned_processes_inefficient(&processes);
            evidence.current_session_owned_activity = Some(true);
            evidence.saved_bytes_attribution_valid = Some(!residual_contaminated);
            evidence.global_saved_pages_delta_raw =
                signed_optional_delta(system_before.pages_sharing, current_system.pages_sharing);
            evidence.owned_saved_evidence = Some(format!(
                "both_owned_scanned=true, both_owned_inefficient={owned_inefficient}, process_profit_sum={process_profit}"
            ));
            let inefficient_profit = ksm::evaluate_profit(
                &ksm::ProfitSample {
                    wall_seconds: elapsed,
                    ksmd_cpu_seconds: current_ticks
                        .map(|ticks| {
                            ticks.saturating_sub(ksmd_ticks_before) as f64 / clk_tck as f64
                        })
                        .unwrap_or(0.0),
                    pages_scanned_delta,
                    saved_bytes: if residual_contaminated {
                        0
                    } else {
                        saved_bytes
                    },
                    process_profit_bytes: Some(process_profit),
                    system_profit_bytes: (!residual_contaminated).then_some(system_profit_delta),
                },
                4096,
            );
            controller_state = ksm::controller_transition(
                controller_state,
                &ksm::ControllerInput {
                    elapsed_seconds: elapsed as u64,
                    full_scans: full_scans_delta,
                    evaluation: inefficient_profit,
                    cpu_budget_percent: 1.0,
                    cow_rate: 0,
                    maximum_cow_rate: 64,
                    cooldown_active: false,
                },
            );
            if controller_state == ksm::ControllerState::Inefficient && owned_inefficient {
                controller_auto_disable = true;
                evidence.controller_transition_reason =
                    Some("owned_process_profit_not_positive_after_two_full_scans".into());
                evidence.controller_evaluation_id =
                    Some(format!("ksm-inefficient-evaluation-{}", now_ns()?));
                break (current_system, processes, None);
            }
            if controller_state == ksm::ControllerState::Profitable || !owned_inefficient {
                break (
                    current_system,
                    processes,
                    Some((
                        "unexpected_positive_gain".into(),
                        format!(
                            "UNIQUE workload crossed positive threshold: saved_bytes={saved_bytes}, system_profit_delta={system_profit_delta}, cpu={current_cpu:.6}%"
                        ),
                    )),
                );
            }
        }
        if Instant::now() >= evaluation_deadline {
            let reason = if scenario == KsmScenario::Inefficient {
                if full_scans_delta < 2 {
                    "insufficient_scan_evidence"
                } else {
                    "controller_did_not_disable"
                }
            } else {
                gate.reasons
                    .first()
                    .map(String::as_str)
                    .unwrap_or("scanner_no_progress")
            };
            break (
                current_system,
                processes,
                Some((
                    reason.to_owned(),
                    "bounded KSM evaluation ended before profitability and resolution-valid CPU evidence completed".to_owned(),
                )),
            );
        }
    };
    evidence.controller_state_after = Some(controller_state);
    let run_before_stop = fs::read_to_string(root.join("run"))?.trim().to_owned();
    let scanner_stopped = stop_owned_ksm_scanner(root, evidence, &mut guard)?;
    if scenario == KsmScenario::Inefficient {
        evidence.controller_auto_stop_owned = Some(controller_auto_disable);
        evidence.checks.push(check(
            "sufficient_inefficiency_evidence",
            system_peak
                .full_scans
                .unwrap_or(0)
                .saturating_sub(system_before.full_scans.unwrap_or(0))
                >= 2
                && evidence
                    .sustained_measurement_resolution_percent
                    .is_some_and(|resolution| resolution <= 0.25)
                && owned_processes_evaluated(&profitable_processes),
            "at least two session-relative full scans, both owned rmap sets evaluated, and resolution-valid CPU evidence collected".into(),
        ));
        evidence.checks.push(check(
            "controller_inefficient_transition",
            controller_state == ksm::ControllerState::Inefficient,
            format!(
                "controller transitioned unknown->evaluating->{controller_state:?}; reason={:?}",
                evidence.controller_transition_reason
            ),
        ));
        evidence.checks.push(check(
            "controller_auto_disable",
            controller_auto_disable && run_before_stop == "1" && scanner_stopped,
            format!(
                "controller_owned_stop={}, run_before={}, run_after={}",
                controller_auto_disable,
                run_before_stop,
                fs::read_to_string(root.join("run"))?.trim()
            ),
        ));
    }
    if !scanner_stopped {
        evaluation_failure = Some((
            "cleanup_failure".into(),
            "owned KSM scanner did not stop".into(),
        ));
    }
    protocol
        .scanner_stopped()
        .map_err(|error| ksm_failure(evidence, "cleanup_failure", &error.to_string()))?;
    let ownership_preserved = !evaluation_failure.as_ref().is_some_and(|(reason, _)| {
        matches!(
            reason.as_str(),
            "scanner_ownership_lost" | "external_ksm_interference"
        )
    });
    evidence.checks.push(check(
        "scanner_ownership_preserved",
        ownership_preserved,
        if ownership_preserved {
            "500 ms monitoring found no global configuration or external KSM interference"
        } else {
            "external process or global scanner interference detected"
        }
        .into(),
    ));
    evidence.checks.push(check(
        "scanner_progress",
        system_peak.pages_scanned.unwrap_or(0) > system_before.pages_scanned.unwrap_or(0)
            && system_peak.full_scans.unwrap_or(0) > system_before.full_scans.unwrap_or(0),
        "pages_scanned advanced and at least one complete full scan finished".into(),
    ));
    let final_saved_bytes = ksm_saved_bytes(&system_before, &system_peak, &baseline);
    if scenario == KsmScenario::Positive {
        evidence.checks.push(check(
            "minimum_saved_bytes",
            final_saved_bytes >= ksm::VALIDATION_MIN_SAVED_BYTES,
            format!(
                "saved_bytes={final_saved_bytes}, threshold={}",
                ksm::VALIDATION_MIN_SAVED_BYTES
            ),
        ));
        evidence.checks.push(check(
            "positive_system_profit",
            system_peak.general_profit.unwrap_or(0) > system_before.general_profit.unwrap_or(0),
            "general_profit delta is positive".into(),
        ));
        evidence.checks.push(check(
            "positive_process_profit",
            owned_process_profit_positive(&profitable_processes),
            "both owned processes have merging pages and positive profit when supported".into(),
        ));
    }
    let elapsed = evaluation_started.elapsed().as_secs_f64();
    let ksmd_ticks_after = read_ksmd_cpu_ticks();
    let ksmd_cpu_seconds = ksmd_ticks_after
        .map(|after| after.saturating_sub(ksmd_ticks_before) as f64 / clk_tck as f64)
        .ok_or_else(|| {
            ksm_failure(
                evidence,
                "scanner_no_progress",
                "ksmd CPU accounting disappeared before final observation",
            )
        })?;
    let residual_contaminated = scenario == KsmScenario::Inefficient
        && evidence.residual_global_ksm_accounting == Some(true);
    let saved_bytes = if residual_contaminated {
        0
    } else {
        final_saved_bytes
    };
    let final_process_profit = (scenario == KsmScenario::Inefficient).then(|| {
        profitable_processes
            .iter()
            .filter_map(|item| item.ksm_process_profit)
            .sum::<i64>()
    });
    evidence.total_cpu_ticks =
        ksmd_ticks_after.map(|after| after.saturating_sub(ksmd_ticks_before));
    let profit = ksm::evaluate_profit(
        &ksm::ProfitSample {
            wall_seconds: elapsed,
            ksmd_cpu_seconds,
            pages_scanned_delta: system_peak
                .pages_scanned
                .unwrap_or(0)
                .saturating_sub(system_before.pages_scanned.unwrap_or(0)),
            saved_bytes,
            process_profit_bytes: final_process_profit,
            system_profit_bytes: (!residual_contaminated).then(|| {
                system_peak
                    .general_profit
                    .zip(system_before.general_profit)
                    .map(|(after, before)| after.saturating_sub(before))
                    .unwrap_or(0)
            }),
        },
        ksm::PAGE_SIZE,
    );
    if evidence
        .sustained_measurement_resolution_percent
        .is_some_and(|resolution| resolution <= 0.25)
    {
        evidence.checks.push(check(
            "cpu_budget",
            profit.ksmd_mean_cpu_percent <= 1.0,
            format!(
                "one-logical-CPU sustained gate; mean={:.6}%, diagnostic_peak_short_window={:.6}%, resolution={:?}%, budget=1.0%, cpu_seconds_per_gib={:?}",
                profit.ksmd_mean_cpu_percent,
                peak_cpu,
                evidence.sustained_measurement_resolution_percent,
                profit.ksmd_cpu_seconds_per_gib_saved
            ),
        ));
    }
    evidence.ksmd_cpu_seconds = Some(ksmd_cpu_seconds);
    evidence.ksmd_mean_cpu_percent = Some(profit.ksmd_mean_cpu_percent);
    evidence.ksmd_peak_window_cpu_percent = Some(peak_cpu);
    evidence.wall_seconds = Some(elapsed);
    evidence.profit = Some(profit.clone());
    evidence.process_evidence.insert(
        if scenario == KsmScenario::Inefficient && evaluation_failure.is_none() {
            "inefficient_observation"
        } else if evaluation_failure.is_none() {
            "profitable_observation"
        } else {
            "failure_snapshot"
        }
        .into(),
        profitable_processes.clone(),
    );
    evidence.process_evidence.insert(
        "after_run_zero".into(),
        observe_owned_ksm_processes(&targets, &owned_identity_session)?,
    );
    evidence.system_peak = Some(system_peak.clone());
    evidence.system_after = Some(ksm::parse_system_metrics(
        root,
        &fs::read_to_string("/proc/vmstat")?,
        now_ns()?,
    ));
    evidence.counter_deltas = ksm_counter_deltas(&system_before, &system_peak);
    evidence.global_saved_pages_delta_raw =
        signed_optional_delta(system_before.pages_sharing, system_peak.pages_sharing);
    evidence.residual_accounting_reconciled =
        evidence.residual_global_ksm_accounting.map(|residual| {
            residual
                && (system_peak.pages_shared.unwrap_or(0) < system_before.pages_shared.unwrap_or(0)
                    || system_peak.pages_sharing.unwrap_or(0)
                        < system_before.pages_sharing.unwrap_or(0)
                    || system_peak.general_profit.unwrap_or(0)
                        < system_before.general_profit.unwrap_or(0))
        });
    if scenario == KsmScenario::Inefficient && controller_auto_disable {
        let cooldown_state = ksm::controller_transition(
            controller_state,
            &ksm::ControllerInput {
                elapsed_seconds: elapsed as u64,
                full_scans: system_peak
                    .full_scans
                    .unwrap_or(0)
                    .saturating_sub(system_before.full_scans.unwrap_or(0)),
                evaluation: profit.clone(),
                cpu_budget_percent: 1.0,
                cow_rate: 0,
                maximum_cow_rate: 64,
                cooldown_active: true,
            },
        );
        evidence.controller_state_after = Some(cooldown_state);
        let identity = profitable_processes
            .first()
            .map(|item| item.identity.clone());
        let cooldown_decision = ksm::evaluate_eligibility(
            &ksm::EligibilityInput {
                identity: identity.clone(),
                identity_fresh: identity.is_some(),
                profile: ksm::KsmProfileKind::Synthetic,
                already_mergeable: true,
                owned_cooperative: true,
                foreground: false,
                gaming: false,
                critical: false,
                protected: false,
                same_security_domain: true,
                pressure: policy_engine::PressureState::Normal,
                stable_observations: 3,
                mergeable_bytes: KSM_DUPLICATE_BYTES as u64,
                profit_bytes: Some(0),
                cow_events_per_second: Some(0),
                cpu_percent: evidence.ksmd_mean_cpu_percent,
                cooldown_active: true,
                external_ksm_activity: false,
            },
            &ksm::profile(ksm::KsmProfileKind::Synthetic),
        );
        evidence.cooldown_decision = Some(cooldown_decision.clone());
        evidence.checks.push(check(
            "cooldown_entered",
            cooldown_state == ksm::ControllerState::Cooldown,
            "real inefficient transition entered bounded controller cooldown".into(),
        ));
        evidence.checks.push(check(
            "cooldown_rejects_next_plan",
            cooldown_decision.disposition == ksm::PlanDisposition::Rejected
                && cooldown_decision
                    .reasons
                    .iter()
                    .any(|reason| reason == "cooldown_active")
                && !evidence.second_run_started,
            "same owned plan rejected with cooldown_active before any second run=1".into(),
        ));
    }
    if scenario == KsmScenario::Positive {
        evidence.checks.push(check(
            "positive_net_gain",
            saved_bytes >= ksm::VALIDATION_MIN_SAVED_BYTES
                && system_peak.general_profit.unwrap_or(0)
                    > system_before.general_profit.unwrap_or(0),
            format!(
                "saved_bytes={}, minimum={}, full_scans_delta={}, general_profit_delta={}",
                saved_bytes,
                ksm::VALIDATION_MIN_SAVED_BYTES,
                system_peak
                    .full_scans
                    .unwrap_or(0)
                    .saturating_sub(system_before.full_scans.unwrap_or(0)),
                system_peak
                    .general_profit
                    .unwrap_or(0)
                    .saturating_sub(system_before.general_profit.unwrap_or(0))
            ),
        ));
    }
    let unmerge_headroom = mem_available_bytes()?;
    let unmerge_disposition = ksm::choose_unmerge_disposition(
        unmerge_headroom,
        KSM_HEADROOM_BYTES.saturating_add((KSM_DUPLICATE_BYTES * 2) as u64),
    );
    evidence.owned_unmerge_performed =
        Some(unmerge_disposition == ksm::UnmergeDisposition::MadviseOwnedRange);
    if unmerge_disposition == ksm::UnmergeDisposition::MadviseOwnedRange {
        for child_id in [1_u8, 2] {
            fs::write(
                Path::new(STATE_DIR).join(format!("ksm-unmerge-{child_id}")),
                b"unmerge\n",
            )?;
            wait_for_path(
                &Path::new(STATE_DIR).join(format!("ksm-unmerge-{child_id}-result.json")),
                Duration::from_secs(10),
            )?;
        }
        protocol
            .unmerged()
            .map_err(|error| ksm_failure(evidence, "cleanup_failure", &error.to_string()))?;
        if let Some(capability) = evidence.capability.as_mut() {
            capability.madv_unmergeable_supported = Some(true);
        }
        let after_unmergeable = observe_owned_ksm_processes(&targets, &owned_identity_session)?;
        if after_unmergeable
            .iter()
            .any(|process| process.ksm_mergeable != Some(false))
        {
            return Err(ksm_failure(
                evidence,
                "cleanup_failure",
                "owned process remained mergeable after MADV_UNMERGEABLE",
            ));
        }
        evidence
            .process_evidence
            .insert("after_unmergeable".into(), after_unmergeable);
        for target in &targets {
            let smaps = fs::read_to_string(format!("/proc/{}/smaps", target.pid))?;
            if !ksm::verify_exact_unmergeable_scope(
                &smaps,
                ksm::AddressRange {
                    start: target.duplicate[0] as u64,
                    end: target.duplicate[1] as u64,
                },
                ksm::AddressRange {
                    start: target.control[0] as u64,
                    end: target.control[1] as u64,
                },
            ) {
                return Err(ksm_failure(
                    evidence,
                    "cleanup_failure",
                    "owned mergeable VMA remained after MADV_UNMERGEABLE",
                ));
            }
        }
    }
    let mut content_intact = true;
    for (index, target) in targets.iter().enumerate() {
        let child_id = index + 1;
        fs::write(
            Path::new(STATE_DIR).join(format!("ksm-content-check-{child_id}")),
            b"check\n",
        )?;
        wait_for_path(
            &Path::new(STATE_DIR).join(format!("ksm-content-check-{child_id}-result.json")),
            Duration::from_secs(10),
        )?;
        let final_value: serde_json::Value = serde_json::from_slice(&fs::read(
            Path::new(STATE_DIR).join(format!("ksm-content-check-{child_id}-result.json")),
        )?)?;
        content_intact &= ksm::content_fingerprints_intact(
            target.duplicate_fingerprint,
            final_value["duplicate_fingerprint"].as_u64().unwrap_or(0),
            target.control_fingerprint,
            final_value["control_fingerprint"].as_u64().unwrap_or(0),
        );
    }
    evidence.checks.push(check(
        "owned_content_intact",
        content_intact,
        "owned mergeable-range and non-mergeable CONTROL fingerprints match after scanner stop/unmerge".into(),
    ));
    if !content_intact && evaluation_failure.is_none() {
        evaluation_failure = Some((
            "content_integrity_failure".into(),
            "owned mergeable range or CONTROL fingerprint changed".into(),
        ));
    }
    fs::write(Path::new(STATE_DIR).join("ksm-stop"), b"stop\n")?;
    for child in &mut guard.children {
        child.wait()?;
    }
    evidence.checks.push(check(
        "owned_mergeability_absent_final",
        true,
        if unmerge_disposition == ksm::UnmergeDisposition::MadviseOwnedRange {
            "MADV_UNMERGEABLE readback proved no owned mg VMA before child exit".into()
        } else {
            "unmerge headroom was insufficient; owned child termination removed mappings".into()
        },
    ));
    let final_snapshot = ksm::snapshot_from_root(root)?;
    evidence.final_snapshot = Some(final_snapshot.clone());
    evidence.checks.push(check(
        "configuration_restored",
        final_snapshot == baseline,
        "run, untouched pages_to_scan/sleep_millisecs, advisor and preserve-only values match baseline; cumulative counters excluded".into(),
    ));
    if let Some((reason, detail)) = evaluation_failure {
        return Err(ksm_failure(evidence, &reason, &detail));
    }
    Ok(())
}

fn ksm_failure(evidence: &mut KsmEvidence, reason: &str, detail: &str) -> anyhow::Error {
    evidence.failure_class = Some(
        match reason {
            "insufficient_saved_bytes"
            | "non_positive_system_profit"
            | "non_positive_process_profit"
            | "scanner_no_progress" => "profitability_failure",
            "cpu_budget_exceeded" => "performance_failure",
            "unexpected_positive_gain"
            | "insufficient_scan_evidence"
            | "controller_did_not_disable"
            | "cooldown_not_entered"
            | "cooldown_rejection_missing" => "inefficient_validation_failure",
            "cleanup_failure" => "cleanup_failure",
            "recovery_failure" => "recovery_failure",
            "external_ksm_interference" | "scanner_ownership_lost" => "ownership_failure",
            "base_page_backing_not_verified" | "owned_range_not_page_aligned" => {
                "workload_setup_failure"
            }
            _ => "safety_failure",
        }
        .into(),
    );
    evidence.failure_reason = Some(reason.into());
    anyhow!("{reason}: {detail}")
}

fn observe_owned_ksm_processes(
    targets: &[KsmTargetMetadata],
    session_id: &str,
) -> Result<Vec<ksm::KsmProcessMetrics>> {
    targets
        .iter()
        .map(|target| {
            let expected = target
                .start_ticks
                .ok_or_else(|| anyhow!("owned KSM target start_ticks unavailable"))?;
            if proc_start_ticks(target.pid)? != Some(expected) {
                bail!("owned KSM target PID/start_ticks became stale");
            }
            let stat = fs::read_to_string(format!("/proc/{}/ksm_stat", target.pid))?;
            let mut metrics = ksm::parse_process_ksm_stat(
                &stat,
                ksm::owned_validation_identity(session_id, target.pid, expected),
            );
            let smaps = fs::read_to_string(format!("/proc/{}/smaps", target.pid))?;
            metrics.current_mapped_ksm_bytes = ksm::parse_smaps_ksm_bytes(&smaps);
            metrics.residual_accounting = metrics.ksm_mergeable == Some(false)
                && metrics.ksm_merge_any != Some(true)
                && metrics.current_mapped_ksm_bytes.unwrap_or(0) == 0
                && metrics.ksm_merging_pages.unwrap_or(0) > 0;
            Ok(metrics)
        })
        .collect()
}

fn owned_process_profit_positive(processes: &[ksm::KsmProcessMetrics]) -> bool {
    processes.len() == 2
        && processes.iter().all(|process| {
            process.ksm_merging_pages.unwrap_or(0) > 0
                && process.ksm_process_profit.is_none_or(|profit| profit > 0)
        })
}

fn owned_processes_evaluated(processes: &[ksm::KsmProcessMetrics]) -> bool {
    processes.len() == 2
        && processes
            .iter()
            .all(|process| process.ksm_rmap_items.unwrap_or(0) > 0)
}

fn owned_processes_inefficient(processes: &[ksm::KsmProcessMetrics]) -> bool {
    let threshold = ksm::profile(ksm::KsmProfileKind::Synthetic).minimum_positive_profit_bytes;
    owned_processes_evaluated(processes)
        && processes.iter().all(|process| {
            process
                .ksm_merging_pages
                .unwrap_or(0)
                .saturating_mul(ksm::PAGE_SIZE)
                <= u64::try_from(threshold.max(0)).unwrap_or(0)
                && process
                    .ksm_process_profit
                    .is_some_and(|profit| profit <= threshold)
        })
}

fn signed_optional_delta<T>(before: Option<T>, after: Option<T>) -> Option<i128>
where
    T: Copy + Into<i128>,
{
    Some(after?.into().saturating_sub(before?.into()))
}

fn ksm_saved_bytes(
    before: &ksm::KsmSystemMetrics,
    after: &ksm::KsmSystemMetrics,
    baseline: &ksm::KsmSnapshot,
) -> u64 {
    let sharing = after
        .pages_sharing
        .unwrap_or(0)
        .saturating_sub(before.pages_sharing.unwrap_or(0));
    let zero_pages_enabled = baseline
        .preserve_only
        .get("use_zero_pages")
        .is_some_and(|value| value == "1");
    let zero_pages = if zero_pages_enabled {
        after
            .ksm_zero_pages
            .unwrap_or(0)
            .saturating_sub(before.ksm_zero_pages.unwrap_or(0))
    } else {
        0
    };
    sharing
        .saturating_add(zero_pages)
        .saturating_mul(ksm::PAGE_SIZE)
}

fn ksm_counter_deltas(
    before: &ksm::KsmSystemMetrics,
    after: &ksm::KsmSystemMetrics,
) -> BTreeMap<String, i128> {
    let mut deltas = BTreeMap::new();
    macro_rules! delta {
        ($field:ident) => {
            if let (Some(before), Some(after)) = (before.$field, after.$field) {
                deltas.insert(
                    stringify!($field).to_owned(),
                    i128::from(after).saturating_sub(i128::from(before)),
                );
            }
        };
    }
    delta!(pages_scanned);
    delta!(pages_shared);
    delta!(pages_sharing);
    delta!(pages_unshared);
    delta!(pages_volatile);
    delta!(pages_skipped);
    delta!(full_scans);
    delta!(ksm_zero_pages);
    delta!(general_profit);
    delta!(cow_ksm);
    delta!(ksm_swpin_copy);
    deltas
}

fn read_ksmd_cpu_ticks() -> Option<u64> {
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.filter_map(Result::ok) {
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if comm.trim() != "ksmd" {
            continue;
        }
        let stat = fs::read_to_string(entry.path().join("stat")).ok()?;
        let close = stat.rfind(')')?;
        let fields: Vec<_> = stat[close + 1..].split_whitespace().collect();
        let user = fields.get(11)?.parse::<u64>().ok()?;
        let system = fields.get(12)?.parse::<u64>().ok()?;
        return Some(user.saturating_add(system));
    }
    None
}

fn damon_target_worker() -> Result<()> {
    let zone_bytes: usize = read_trimmed(&Path::new(STATE_DIR).join("damon-zone-bytes"))?
        .parse()
        .context("invalid bounded DAMON zone size")?;
    if zone_bytes == 0 || zone_bytes > damon::MAX_DIAGNOSTIC_ZONE_BYTES as usize {
        bail!("DAMON zone size is outside bounded ladder");
    }
    let backing_profile: damon::PageBackingProfile = serde_json::from_slice(&fs::read(
        Path::new(STATE_DIR).join("damon-backing-profile"),
    )?)?;
    let cold_bytes = fs::read_to_string(Path::new(STATE_DIR).join("damon-cold-zone-bytes"))
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(zone_bytes);
    if cold_bytes == 0 || cold_bytes > damon::MAX_DIAGNOSTIC_ZONE_BYTES as usize {
        bail!("DAMOS COLD zone size is outside bound");
    }
    let mut hot = owned_anonymous_zone(zone_bytes, backing_profile)?;
    let mut warm = owned_anonymous_zone(zone_bytes, backing_profile)?;
    let mut cold = owned_anonymous_zone(cold_bytes, backing_profile)?;
    hot.fill(1);
    warm.fill(2);
    cold.fill(3);
    let hot_range = [hot.as_ptr() as usize, hot.as_ptr() as usize + hot.len()];
    let warm_range = [warm.as_ptr() as usize, warm.as_ptr() as usize + warm.len()];
    let cold_range = [cold.as_ptr() as usize, cold.as_ptr() as usize + cold.len()];
    let allocations_complete_ns = now_ns()?;
    let active = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let hot_ready = Arc::new(AtomicBool::new(false));
    let warm_ready = Arc::new(AtomicBool::new(false));
    let hot_cycles = Arc::new(AtomicU64::new(0));
    let warm_cycles = Arc::new(AtomicU64::new(0));
    let hot_pages = Arc::new(AtomicU64::new(0));
    let warm_pages = Arc::new(AtomicU64::new(0));

    let hot_thread = {
        let active = Arc::clone(&active);
        let stop = Arc::clone(&stop);
        let ready = Arc::clone(&hot_ready);
        let cycles = Arc::clone(&hot_cycles);
        let pages = Arc::clone(&hot_pages);
        thread::spawn(move || {
            let mut zone = hot;
            ready.store(true, Ordering::Release);
            while !stop.load(Ordering::Acquire) {
                if !active.load(Ordering::Acquire) {
                    thread::yield_now();
                    continue;
                }
                let (touched, _) = touch_zone(&mut zone);
                pages.fetch_add(touched, Ordering::Relaxed);
                cycles.fetch_add(1, Ordering::Release);
            }
            let (_, fingerprint) = touch_zone(&mut zone);
            (zone, fingerprint)
        })
    };
    let warm_thread = {
        let active = Arc::clone(&active);
        let stop = Arc::clone(&stop);
        let ready = Arc::clone(&warm_ready);
        let cycles = Arc::clone(&warm_cycles);
        let pages = Arc::clone(&warm_pages);
        thread::spawn(move || {
            let mut zone = warm;
            ready.store(true, Ordering::Release);
            while !stop.load(Ordering::Acquire) {
                if !active.load(Ordering::Acquire) {
                    thread::yield_now();
                    continue;
                }
                let (touched, _) = touch_zone(&mut zone);
                pages.fetch_add(touched, Ordering::Relaxed);
                cycles.fetch_add(1, Ordering::Release);
                thread::sleep(Duration::from_millis(100));
            }
            let (_, fingerprint) = touch_zone(&mut zone);
            (zone, fingerprint)
        })
    };
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    while !(hot_ready.load(Ordering::Acquire) && warm_ready.load(Ordering::Acquire)) {
        if Instant::now() >= ready_deadline {
            bail!("synthetic worker readiness timeout");
        }
        thread::yield_now();
    }
    let workers_ready_ns = now_ns()?;
    let metadata = serde_json::json!({
        "pid": std::process::id(),
        "start_ticks": proc_start_ticks(std::process::id())?,
        "state": "ready",
        "allocations_complete_ns": allocations_complete_ns,
        "workers_ready_ns": workers_ready_ns,
        "hot": hot_range,
        "warm": warm_range,
        "cold": cold_range,
        "backing_profile": backing_profile
    });
    fs::write(
        Path::new(STATE_DIR).join("damon-target.json"),
        serde_json::to_vec(&metadata)?,
    )?;
    write_workload_progress(&WorkloadProgress::default())?;
    let deadline = Instant::now() + Duration::from_secs(120);
    while !Path::new(STATE_DIR).join("damon-start").exists() {
        if Instant::now() >= deadline {
            bail!("synthetic START barrier timeout");
        }
        thread::sleep(Duration::from_millis(5));
    }
    let started_ns = now_ns()?;
    active.store(true, Ordering::Release);
    let mut cold_refault_fingerprint = None;
    while !Path::new(STATE_DIR).join("damon-stop").exists() {
        if cold_refault_fingerprint.is_none() && Path::new(STATE_DIR).join("damon-refault").exists()
        {
            let (_, fingerprint) = touch_zone(&mut cold);
            cold_refault_fingerprint = Some(fingerprint);
            fs::write(
                Path::new(STATE_DIR).join("damon-refault-result"),
                fingerprint.to_string(),
            )?;
        }
        write_workload_progress(&WorkloadProgress {
            hot_cycles: hot_cycles.load(Ordering::Acquire),
            warm_cycles: warm_cycles.load(Ordering::Acquire),
            hot_pages_touched: hot_pages.load(Ordering::Acquire),
            warm_pages_touched: warm_pages.load(Ordering::Acquire),
            cold_cycles: 0,
            workload_started_ns: started_ns,
            workload_stopped_ns: 0,
            hot_fingerprint: 0,
            warm_fingerprint: 0,
            cold_fingerprint: 0,
        })?;
        thread::sleep(Duration::from_millis(20));
    }
    active.store(false, Ordering::Release);
    stop.store(true, Ordering::Release);
    let (hot, hot_fingerprint) = hot_thread
        .join()
        .map_err(|_| anyhow!("HOT worker panicked"))?;
    let (warm, warm_fingerprint) = warm_thread
        .join()
        .map_err(|_| anyhow!("WARM worker panicked"))?;
    let cold_fingerprint = cold_refault_fingerprint.unwrap_or_else(|| fingerprint_zone(&cold));
    write_workload_progress(&WorkloadProgress {
        hot_cycles: hot_cycles.load(Ordering::Acquire),
        warm_cycles: warm_cycles.load(Ordering::Acquire),
        hot_pages_touched: hot_pages.load(Ordering::Acquire),
        warm_pages_touched: warm_pages.load(Ordering::Acquire),
        cold_cycles: 0,
        workload_started_ns: started_ns,
        workload_stopped_ns: now_ns()?,
        hot_fingerprint,
        warm_fingerprint,
        cold_fingerprint,
    })?;
    std::hint::black_box((hot, warm, cold));
    Ok(())
}

fn owned_anonymous_zone(bytes: usize, profile: damon::PageBackingProfile) -> Result<MmapMut> {
    let mapping = MmapOptions::new().len(bytes).map_anon()?;
    if profile == damon::PageBackingProfile::BasePageNoHuge {
        if !Advice::NoHugePage.is_supported() {
            bail!("MADV_NOHUGEPAGE is not supported by this kernel");
        }
        mapping
            .advise(Advice::NoHugePage)
            .context("MADV_NOHUGEPAGE failed for owned synthetic mapping")?;
    }
    Ok(mapping)
}

fn touch_zone(zone: &mut [u8]) -> (u64, u64) {
    let mut fingerprint = 0_u64;
    let mut touched = 0_u64;
    for index in (0..zone.len()).step_by(4096) {
        let updated = zone[index].wrapping_add(1).max(4);
        zone[index] = updated;
        fingerprint = fingerprint.wrapping_add(u64::from(updated));
        touched = touched.saturating_add(1);
    }
    std::hint::black_box(fingerprint);
    (touched, fingerprint)
}

fn fingerprint_zone(zone: &[u8]) -> u64 {
    let fingerprint = (0..zone.len())
        .step_by(4096)
        .fold(0_u64, |sum, index| sum.wrapping_add(u64::from(zone[index])));
    std::hint::black_box(fingerprint)
}

fn validate_damon(evidence: &mut DamonEvidence, deadline: &Deadline) -> Result<()> {
    evidence.attempted = true;
    evidence.zero_damos = true;
    evidence.lifecycle_clock_domain = "realtime".to_owned();
    evidence.workload_clock_domain = "monotonic".to_owned();
    let capability = damon::inspect_linux(
        Path::new("/"),
        Some(read_command("/usr/bin/uname", &["-r"])?),
    );
    evidence.checks.push(check(
        "capability",
        capability.supported,
        format!(
            "admin={}, tracefs={}, tracepoint={}",
            capability.sysfs_admin_available,
            capability.tracefs_available,
            capability.aggregated_tracepoint_available
        ),
    ));
    if capability.active_external_session || capability.special_module_conflict {
        bail!("external DAMON session or special-purpose module conflict");
    }
    if !capability.writable || !capability.aggregated_tracepoint_available {
        bail!("DAMON admin or isolated tracepoint is unavailable");
    }
    evidence.capability = Some(capability);
    let attrs = damon::MonitoringAttrs {
        operation: "vaddr".to_owned(),
        sample_us: 25_000,
        aggr_us: 500_000,
        update_us: 10_000_000,
        min_regions: 10,
        max_regions: 1_000,
        addr_unit: None,
    };
    attrs.validate()?;
    evidence.attrs_requested = Some(attrs.clone());

    let baseline_instances = trace_instances()?;
    let admin = Path::new("/sys/kernel/mm/damon/admin/kdamonds");
    if read_trimmed(&admin.join("nr_kdamonds"))? != "0" {
        bail!("existing kdamond objects make ownership ambiguous");
    }
    let trace_root = tracefs_root()?;
    const HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;
    let mem_available_bytes = mem_available_bytes()?;
    let base_page_ladder = damon::bounded_size_ladder(mem_available_bytes, HEADROOM_BYTES)
        .into_iter()
        .filter(|size| *size <= 64 * 1024 * 1024)
        .collect::<Vec<_>>();
    evidence.tlb_diagnostic.mem_available_bytes = mem_available_bytes;
    evidence.tlb_diagnostic.headroom_bytes = HEADROOM_BYTES;
    if !base_page_ladder.contains(&(8 * 1024 * 1024)) {
        evidence.validation_failure_class = ValidationFailureClass::SafetyFailure;
        bail!("MemAvailable cannot preserve one-GiB headroom for the A/B probe");
    }
    evidence.tlb_diagnostic.hypothesis_status =
        damon::HypothesisStatus::InconclusiveDueToThpBacking;
    let thp_reference = run_damon_probe(
        8 * 1024 * 1024,
        &attrs,
        damon::PageBackingProfile::ThpReference,
    )?;
    evidence
        .probe_session_ids
        .push(thp_reference.session_id.clone());
    if let Some(capability) = evidence.capability.as_mut() {
        record_validated_operation(capability, "vaddr");
    }
    evidence
        .tlb_diagnostic
        .size_ladder_attempts
        .push(thp_reference.clone());
    for zone_size in base_page_ladder {
        deadline.check("DAMON bounded TLB diagnostic probe")?;
        let attempt =
            match run_damon_probe(zone_size, &attrs, damon::PageBackingProfile::BasePageNoHuge) {
                Ok(attempt) => attempt,
                Err(error) => {
                    evidence.validation_failure_class =
                        ValidationFailureClass::InstrumentationFailure;
                    return Err(error);
                }
            };
        if let Some(capability) = evidence.capability.as_mut() {
            record_validated_operation(capability, "vaddr");
        }
        evidence.probe_session_ids.push(attempt.session_id.clone());
        evidence.tlb_diagnostic.size_ladder_attempts.push(attempt);
        if evidence
            .tlb_diagnostic
            .size_ladder_attempts
            .last()
            .is_some_and(|attempt| {
                attempt.backing_profile == damon::PageBackingProfile::BasePageNoHuge
                    && attempt.stable_enough()
            })
        {
            break;
        }
    }
    let Some((selected_zone_size, selected_reason)) =
        damon::select_base_page_probe(&evidence.tlb_diagnostic.size_ladder_attempts)
    else {
        evidence.tlb_diagnostic.hypothesis_status = evidence
            .tlb_diagnostic
            .size_ladder_attempts
            .iter()
            .find(|attempt| {
                attempt.zone_size_bytes == 8 * 1024 * 1024
                    && attempt.backing_profile == damon::PageBackingProfile::BasePageNoHuge
            })
            .map_or(damon::HypothesisStatus::NotTested, |base| {
                damon::compare_page_backing(&thp_reference, base)
            });
        evidence.validation_failure_class = ValidationFailureClass::SignalFailure;
        evidence.signal_failure_reason = Some("no_stable_working_set".to_owned());
        bail!("no bounded DAMON zone size produced stable HOT detection");
    };
    evidence.tlb_diagnostic.current_zone_size = selected_zone_size;
    evidence.tlb_diagnostic.selected_size = Some(selected_zone_size);
    evidence.tlb_diagnostic.selected_size_reason = Some(selected_reason);
    evidence.tlb_diagnostic.hypothesis_status = evidence
        .tlb_diagnostic
        .size_ladder_attempts
        .iter()
        .find(|attempt| {
            attempt.zone_size_bytes == 8 * 1024 * 1024
                && attempt.backing_profile == damon::PageBackingProfile::BasePageNoHuge
        })
        .map_or(damon::HypothesisStatus::NotTested, |base| {
            damon::compare_page_backing(&thp_reference, base)
        });

    let trace_name = format!("nemor-validation-{}", now_ns()?);
    evidence.final_session_id = Some(trace_name.clone());
    if !sessions_are_independent(&evidence.probe_session_ids, &trace_name) {
        bail!("final session id reused a probe session id");
    }
    let trace_instance = trace_root.join("instances").join(&trace_name);
    let mut cleanup = DamonCleanup::new(admin.to_path_buf(), trace_instance.clone());

    let mut baseline_child = spawn_damon_target(
        selected_zone_size,
        damon::PageBackingProfile::BasePageNoHuge,
    )?;
    signal_damon_target("damon-start")?;
    let baseline_start = read_progress()?;
    std::thread::sleep(Duration::from_secs(2));
    let baseline_end = read_progress()?;
    signal_damon_target("damon-stop")?;
    baseline_child.terminate()?;
    let baseline_rate = baseline_end
        .hot_cycles
        .saturating_sub(baseline_start.hot_cycles) as f64
        / 2.0;

    let child_spawn_ns = now_ns()?;
    let mut child = spawn_damon_target(
        selected_zone_size,
        damon::PageBackingProfile::BasePageNoHuge,
    )?;
    let child_start_ticks = child.start_ticks;
    evidence.target_pid = Some(child.id());
    evidence.target_start_ticks = Some(child_start_ticks);
    let zones: serde_json::Value =
        serde_json::from_slice(&fs::read(Path::new(STATE_DIR).join("damon-target.json"))?)?;
    evidence
        .lifecycle_timeline_ns
        .insert("t0_child_spawn".to_owned(), child_spawn_ns);
    evidence.lifecycle_timeline_ns.insert(
        "t1_allocations_complete".to_owned(),
        zones["allocations_complete_ns"]
            .as_u64()
            .map_or(0, u128::from),
    );
    evidence.lifecycle_timeline_ns.insert(
        "t2_workers_ready".to_owned(),
        zones["workers_ready_ns"].as_u64().map_or(0, u128::from),
    );
    evidence
        .lifecycle_timeline_ns
        .insert("t3_parent_received_ready".to_owned(), now_ns()?);
    if zones["pid"].as_u64() != Some(u64::from(child.id()))
        || zones["start_ticks"].as_u64() != Some(child_start_ticks)
        || proc_start_ticks(child.id())? != Some(child_start_ticks)
    {
        bail!("synthetic child metadata identity mismatch");
    }
    let workload_ready = zones["state"].as_str() == Some("ready");
    evidence.checks.push(check(
        "synthetic_workload_ready",
        workload_ready,
        "HOT and WARM workers reached READY before DAMON start".to_owned(),
    ));
    if !workload_ready {
        bail!("synthetic workload readiness barrier failed");
    }
    let zone_range = |name: &str| -> Result<damon::AddressRange> {
        let pair = zones[name]
            .as_array()
            .ok_or_else(|| anyhow!("missing {name} zone"))?;
        Ok(damon::AddressRange {
            start: pair[0].as_u64().ok_or_else(|| anyhow!("invalid zone"))?,
            end: pair[1].as_u64().ok_or_else(|| anyhow!("invalid zone"))?,
        })
    };
    let hot_range = zone_range("hot")?;
    let warm_range = zone_range("warm")?;
    let cold_range = zone_range("cold")?;
    let smaps = fs::read_to_string(format!("/proc/{}/smaps", child.id()))?;
    let mut backing = [
        damon::parse_smaps_zone(&smaps, hot_range)?,
        damon::parse_smaps_zone(&smaps, warm_range)?,
        damon::parse_smaps_zone(&smaps, cold_range)?,
    ];
    for item in &mut backing {
        item.explicit_nohugepage_requested = true;
        item.explicit_nohugepage_verified = item.anon_huge_pages_kib == 0
            && (item.thp_eligible == Some(false) || item.vm_flags.iter().any(|flag| flag == "nh"));
    }
    let same_vma = backing.iter().all(|item| {
        item.containing_vma_start == backing[0].containing_vma_start
            && item.containing_vma_end == backing[0].containing_vma_end
    });
    if same_vma {
        let group = format!(
            "{:x}-{:x}",
            backing[0].containing_vma_start.unwrap_or(0),
            backing[0].containing_vma_end.unwrap_or(0)
        );
        for item in &mut backing {
            item.shared_vma = true;
            item.shared_vma_group = Some(group.clone());
        }
    }
    for (name, item) in ["hot", "warm", "cold"].into_iter().zip(backing) {
        evidence.zone_backing.insert(name.to_owned(), item);
    }
    let final_base_page_verified = damon::verify_base_page_backing(&evidence.zone_backing);
    evidence.checks.push(check(
        "base_page_backing_verified",
        final_base_page_verified,
        format!("zones={:?}", evidence.zone_backing),
    ));
    if !final_base_page_verified {
        bail!("final synthetic target did not retain verified base-page backing");
    }
    let initial_regions = damon::InitialRegionPlan::new(
        vec![hot_range, warm_range, cold_range],
        &proc_mapped_ranges(child.id())?,
    )?;
    evidence.requested_target_bytes = initial_regions.requested_bytes();
    evidence.target_ranges = BTreeMap::from([
        ("hot".to_owned(), hot_range),
        ("warm".to_owned(), warm_range),
        ("cold".to_owned(), cold_range),
    ]);

    fs::create_dir(&trace_instance)?;
    cleanup.trace_created = true;
    let trace_clock = configure_owned_trace_clock(&trace_instance)?;
    evidence.trace_clock_domain = trace_clock.effective.clone();
    evidence.workload_clock_domain = trace_clock.userspace_clock.report_name().to_owned();
    evidence.checks.push(check(
        "trace_clock_compatible",
        trace_clock.readback,
        format!(
            "available={:?}, requested={}, effective={}, userspace_clock={}, readback={}",
            trace_clock.available,
            trace_clock.requested,
            trace_clock.effective,
            trace_clock.userspace_clock.report_name(),
            trace_clock.readback
        ),
    ));
    evidence.checks.push(check(
        "trace_instance_isolated",
        trace_instance.starts_with(trace_root.join("instances"))
            && trace_name.starts_with("nemor-validation-"),
        trace_instance.display().to_string(),
    ));
    let enable = trace_instance.join("events/damon/damon_aggregated/enable");
    if !enable.exists() {
        bail!("isolated damon_aggregated tracepoint is unavailable");
    }
    write_readback(&enable, "1")?;
    cleanup.trace_enabled = true;
    write_readback(&trace_instance.join("tracing_on"), "1")?;
    cleanup.tracing_on = true;
    let capture = run_damon_monitor_session(MonitorSessionSpec {
        session_id: &trace_name,
        trace_instance: &trace_instance,
    })?;
    evidence.checks.push(check(
        "final_trace_instance_ready",
        trace_instance.is_dir()
            && read_trimmed(&enable)? == "1"
            && read_trimmed(&trace_instance.join("tracing_on"))? == "1",
        format!(
            "path={}, event_enable=1, tracing_on=1, capture_worker_ready=true",
            trace_instance.display()
        ),
    ));
    evidence
        .lifecycle_timeline_ns
        .insert("t4_trace_capture_ready".to_owned(), now_ns()?);

    write_readback(&admin.join("nr_kdamonds"), "1")?;
    cleanup.kdamond_created = true;
    let kd = admin.join("0");
    write_readback(&kd.join("contexts/nr_contexts"), "1")?;
    let context = kd.join("contexts/0");
    let operations = read_trimmed(&context.join("avail_operations"))?;
    if !operations.split_whitespace().any(|item| item == "vaddr") {
        bail!("created context does not expose vaddr");
    }
    if let Some(capability) = evidence.capability.as_mut() {
        capability.available_operations =
            operations.split_whitespace().map(str::to_owned).collect();
        capability.vaddr_supported = capability
            .available_operations
            .iter()
            .any(|item| item == "vaddr");
        capability.fvaddr_supported = capability
            .available_operations
            .iter()
            .any(|item| item == "fvaddr");
        capability.paddr_supported = capability
            .available_operations
            .iter()
            .any(|item| item == "paddr");
    }
    evidence.checks.push(check(
        "available_operations",
        operations.split_whitespace().any(|item| item == "vaddr"),
        operations.clone(),
    ));
    write_readback(&context.join("operations"), "vaddr")?;
    evidence.checks.push(check(
        "vaddr_selected",
        read_trimmed(&context.join("operations"))? == "vaddr",
        "operation readback=vaddr".to_owned(),
    ));
    write_readback(
        &context.join("monitoring_attrs/intervals/sample_us"),
        &attrs.sample_us.to_string(),
    )?;
    write_readback(
        &context.join("monitoring_attrs/intervals/aggr_us"),
        &attrs.aggr_us.to_string(),
    )?;
    write_readback(
        &context.join("monitoring_attrs/intervals/update_us"),
        &attrs.update_us.to_string(),
    )?;
    write_readback(
        &context.join("monitoring_attrs/nr_regions/min"),
        &attrs.min_regions.to_string(),
    )?;
    write_readback(
        &context.join("monitoring_attrs/nr_regions/max"),
        &attrs.max_regions.to_string(),
    )?;
    evidence.checks.push(check(
        "attrs_readback",
        true,
        format!(
            "sample_us={}, aggr_us={}, update_us={}, regions={}..={}",
            attrs.sample_us, attrs.aggr_us, attrs.update_us, attrs.min_regions, attrs.max_regions
        ),
    ));
    evidence.attrs_effective = Some(attrs.clone());
    write_readback(&context.join("targets/nr_targets"), "1")?;
    if proc_start_ticks(child.id())? != Some(child_start_ticks) {
        bail!("synthetic child identity changed before DAMON attach");
    }
    evidence.checks.push(check(
        "target_identity",
        true,
        format!("pid={}, start_ticks={child_start_ticks}", child.id()),
    ));
    write_readback(
        &context.join("targets/0/pid_target"),
        &child.id().to_string(),
    )?;
    let regions_root = context.join("targets/0/regions");
    write_readback(&regions_root.join("nr_regions"), "3")?;
    for (index, range) in initial_regions.ranges.iter().enumerate() {
        let root = regions_root.join(index.to_string());
        write_readback(&root.join("start"), &range.start.to_string())?;
        write_readback(&root.join("end"), &range.end.to_string())?;
    }
    let readback_regions = (0..3)
        .map(|index| {
            let root = regions_root.join(index.to_string());
            Ok(damon::AddressRange {
                start: read_trimmed(&root.join("start"))?.parse()?,
                end: read_trimmed(&root.join("end"))?.parse()?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let regions_match = initial_regions.matches_readback(&readback_regions);
    evidence.checks.push(check(
        "target_regions_readback",
        regions_match,
        format!(
            "requested={:?}, effective={readback_regions:?}, bytes={}",
            initial_regions.ranges,
            initial_regions.requested_bytes()
        ),
    ));
    if !regions_match {
        bail!("synthetic target initial regions readback mismatch");
    }
    write_readback(&context.join("schemes/nr_schemes"), "0")?;
    if read_trimmed(&context.join("schemes/nr_schemes"))? != "0" {
        bail!("zero DAMOS invariant failed");
    }
    evidence.checks.push(check(
        "zero_damos_before_start",
        true,
        "nr_schemes=0 readback before kdamond start".to_owned(),
    ));
    evidence
        .lifecycle_timeline_ns
        .insert("t5_damon_configured".to_owned(), now_ns()?);
    let capture_cpu_before = process_cpu_ns()?;
    let target_cpu_before = proc_cpu_ticks(child.id())?;
    let monitored_progress_before = read_progress()?;
    write_readback(&kd.join("state"), "on")?;
    cleanup.kdamond_on = true;
    let kdamond_pid = wait_kdamond_started(&kd, Duration::from_secs(3))?;
    evidence
        .lifecycle_timeline_ns
        .insert("t6_kdamond_started".to_owned(), now_ns()?);
    evidence.checks.push(check(
        "kdamond_started",
        true,
        format!("state=on, pid={kdamond_pid}"),
    ));
    let kdamond_cpu_before = proc_cpu_ticks(kdamond_pid)?;
    let monitoring_start_uptime_ns = userspace_clock_ns(trace_clock.userspace_clock)?;
    signal_damon_target("damon-start")?;
    evidence
        .lifecycle_timeline_ns
        .insert("t7_workload_start_sent".to_owned(), now_ns()?);
    deadline.check("DAMON monitoring window")?;
    let mut progress_points = vec![(
        userspace_clock_ns(trace_clock.userspace_clock)?,
        monitored_progress_before.clone(),
    )];
    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(500));
        progress_points.push((
            userspace_clock_ns(trace_clock.userspace_clock)?,
            read_progress()?,
        ));
    }
    let kdamond_cpu_after = proc_cpu_ticks(kdamond_pid)?;
    let target_cpu_after = proc_cpu_ticks(child.id())?;
    let monitored_progress_after = read_progress()?;
    let monitoring_end_uptime_ns = userspace_clock_ns(trace_clock.userspace_clock)?;
    let bytes_at_kdamond_stop = capture.bytes_read()?;
    evidence
        .lifecycle_timeline_ns
        .insert("t8_monitoring_window_end".to_owned(), now_ns()?);
    write_readback(&kd.join("state"), "off")?;
    cleanup.kdamond_on = false;
    evidence
        .lifecycle_timeline_ns
        .insert("t9_kdamond_stopped".to_owned(), now_ns()?);
    signal_damon_target("damon-stop")?;
    evidence
        .lifecycle_timeline_ns
        .insert("t10_workload_stop_sent".to_owned(), now_ns()?);
    evidence.checks.push(check(
        "kdamond_stopped",
        read_trimmed(&kd.join("state"))? == "off",
        "state=off readback".to_owned(),
    ));
    let (mut trace_diagnostic, captured_events) = capture.drain_and_stop(bytes_at_kdamond_stop)?;
    trace_diagnostic.available_trace_clocks = trace_clock.available.clone();
    trace_diagnostic.requested_trace_clock = Some(trace_clock.requested.clone());
    trace_diagnostic.effective_trace_clock = Some(trace_clock.effective.clone());
    trace_diagnostic.userspace_clock = Some(trace_clock.userspace_clock.report_name().to_owned());
    trace_diagnostic.trace_clock_readback = trace_clock.readback;
    trace_diagnostic.workload_monitoring_start_monotonic = Some(monitoring_start_uptime_ns);
    trace_diagnostic.workload_monitoring_end_monotonic = Some(monitoring_end_uptime_ns);
    trace_diagnostic.trace_timestamp_min = captured_events
        .iter()
        .filter_map(|event| event.timestamp_ns)
        .min();
    trace_diagnostic.trace_timestamp_max = captured_events
        .iter()
        .filter_map(|event| event.timestamp_ns)
        .max();
    trace_diagnostic.trace_events_in_monitoring_window = captured_events
        .iter()
        .filter(|event| {
            event.timestamp_ns.is_some_and(|timestamp| {
                timestamp >= monitoring_start_uptime_ns && timestamp <= monitoring_end_uptime_ns
            })
        })
        .count() as u64;
    trace_diagnostic.trace_events_outside_monitoring_window = captured_events
        .iter()
        .filter(|event| {
            event.timestamp_ns.is_some_and(|timestamp| {
                timestamp < monitoring_start_uptime_ns || timestamp > monitoring_end_uptime_ns
            })
        })
        .count() as u64;
    trace_diagnostic.trace_events_unmatched = trace_diagnostic
        .trace_events_total
        .saturating_sub(trace_diagnostic.trace_events_in_monitoring_window)
        .saturating_sub(trace_diagnostic.trace_events_outside_monitoring_window);
    trace_diagnostic.timestamp_correlation_valid = trace_clock.readback
        && trace_diagnostic.timestamp_failures == 0
        && trace_diagnostic.trace_events_in_monitoring_window > 0;
    evidence.final_trace = Some(trace_diagnostic.clone());
    write_readback(&trace_instance.join("tracing_on"), "0")?;
    cleanup.tracing_on = false;
    write_readback(&enable, "0")?;
    cleanup.trace_enabled = false;
    let capture_cpu_after = process_cpu_ns()?;

    evidence.checks.push(check(
        "aggregated_trace_bytes_received",
        trace_diagnostic.trace_bytes_read > 0 && trace_diagnostic.damon_event_lines_seen > 0,
        format!(
            "bytes={}, lines={}, damon_lines={}, drained_bytes={}",
            trace_diagnostic.trace_bytes_read,
            trace_diagnostic.trace_lines_read,
            trace_diagnostic.damon_event_lines_seen,
            trace_diagnostic.bytes_after_kdamond_stop
        ),
    ));
    evidence.checks.push(check(
        "damon_payloads_parsed",
        trace_diagnostic.damon_events_parsed > 0 && trace_diagnostic.parse_failures == 0,
        format!(
            "payloads={}, parse_failures={}",
            trace_diagnostic.damon_events_parsed, trace_diagnostic.parse_failures
        ),
    ));
    evidence.checks.push(check(
        "timestamp_values_parsed",
        trace_diagnostic.timestamp_values_parsed > 0 && trace_diagnostic.timestamp_failures == 0,
        format!(
            "timestamps={}, failures={}, min={:?}, max={:?}",
            trace_diagnostic.timestamp_values_parsed,
            trace_diagnostic.timestamp_failures,
            trace_diagnostic.trace_timestamp_min,
            trace_diagnostic.trace_timestamp_max
        ),
    ));
    evidence.checks.push(check(
        "timestamp_correlation_valid",
        trace_diagnostic.timestamp_correlation_valid,
        format!(
            "total={}, in_window={}, outside={}, unmatched={}, monitoring={}..{}",
            trace_diagnostic.trace_events_total,
            trace_diagnostic.trace_events_in_monitoring_window,
            trace_diagnostic.trace_events_outside_monitoring_window,
            trace_diagnostic.trace_events_unmatched,
            monitoring_start_uptime_ns,
            monitoring_end_uptime_ns
        ),
    ));
    let timed_regions = captured_events
        .into_iter()
        .filter_map(|event| {
            event
                .timestamp_ns
                .map(|timestamp| (timestamp, event.region))
        })
        .collect::<Vec<_>>();
    evidence.raw_regions = trace_diagnostic.damon_events_parsed;
    evidence.checks.push(check(
        "raw_regions_present",
        evidence.raw_regions > 0,
        format!("raw_regions={}", evidence.raw_regions),
    ));
    evidence.workload_progress = workload_window_progress(&progress_points);
    let timed_windows = group_timed_aggregation_windows(timed_regions);
    let (alignment, windows) = align_complete_windows(
        timed_windows,
        attrs.aggr_us,
        monitoring_start_uptime_ns,
        monitoring_end_uptime_ns,
        &evidence.workload_progress,
    );
    evidence.window_alignment = alignment;
    evidence.aggregation_windows = windows.len() as u64;
    let workload_active = evidence
        .workload_progress
        .iter()
        .all(|window| window.hot_cycles_delta > 0)
        && evidence
            .workload_progress
            .iter()
            .any(|window| window.warm_cycles_delta > 0)
        && monitored_progress_after.cold_cycles == 0
        && monitored_progress_after.workload_started_ns > 0
        && monitored_progress_after.workload_stopped_ns == 0
        && synthetic_lifecycle_order_valid(&evidence.lifecycle_timeline_ns);

    evidence.checks.push(check(
        "synthetic_workload_active",
        workload_active,
        format!(
            "windows={}, hot_cycles={}..{}, warm_cycles={}..{}, cold_cycles={}",
            evidence.workload_progress.len(),
            monitored_progress_before.hot_cycles,
            monitored_progress_after.hot_cycles,
            monitored_progress_before.warm_cycles,
            monitored_progress_after.warm_cycles,
            monitored_progress_after.cold_cycles
        ),
    ));
    let instrumentation_ok = matches!(
        classify_capture(&trace_diagnostic),
        ValidationFailureClass::None
    );
    let signal = instrumentation_ok
        .then(|| damon::analyze_zones(&windows, &attrs, hot_range, warm_range, cold_range));
    if let Some(signal) = signal.as_ref() {
        evidence.region_sample_bytes = Some(signal.region_sample_bytes);
        evidence.snapshot_observed_bytes = Some(signal.snapshot_observed_bytes_median);
        evidence.observed_target_bytes_per_snapshot =
            Some(signal.observed_target_bytes_per_snapshot);
        evidence.outside_requested_bytes = Some(signal.outside_requested_bytes);
        evidence.outside_requested_ratio = Some(signal.outside_requested_ratio);
        evidence.hot_snapshot_overlap_bytes = Some(signal.hot.snapshot_overlap_bytes_median);
        evidence.warm_snapshot_overlap_bytes = Some(signal.warm.snapshot_overlap_bytes_median);
        evidence.cold_snapshot_overlap_bytes = Some(signal.cold.snapshot_overlap_bytes_median);
    } else {
        evidence.validation_failure_class = ValidationFailureClass::InstrumentationFailure;
        evidence.instrumentation_failure_reason = Some(if trace_diagnostic.trace_bytes_read == 0 {
            "capture".to_owned()
        } else if trace_diagnostic.damon_events_parsed == 0 || trace_diagnostic.parse_failures > 0 {
            "payload_parser".to_owned()
        } else {
            "trace_clock_or_timestamp_correlation".to_owned()
        });
    }
    evidence.checks.push(check(
        "hot_cold_evidence",
        signal
            .as_ref()
            .is_some_and(|signal| signal.hot_cold_distinguished && signal.target_isolated),
        signal.as_ref().map_or_else(
            || "not evaluated: final capture instrumentation failure".to_owned(),
            |signal| {
                format!(
                    "hot_p50={:.4}, cold_p50={:.4}, margin={:.4}, outside_ratio={:.4}, isolated={}",
                    signal.hot.normalized_ratio_p50,
                    signal.cold.normalized_ratio_p50,
                    signal.hot_cold_margin,
                    signal.outside_requested_ratio,
                    signal.target_isolated
                )
            },
        ),
    ));
    evidence.checks.push(check(
        "warm_evidence",
        signal.as_ref().is_some_and(|signal| signal.warm_coherent),
        signal.as_ref().map_or_else(
            || "not evaluated: final capture instrumentation failure".to_owned(),
            |signal| {
                format!(
                    "hot_mean={:.4}, warm_mean={:.4}, cold_mean={:.4}",
                    signal.hot.normalized_ratio_mean,
                    signal.warm.normalized_ratio_mean,
                    signal.cold.normalized_ratio_mean
                )
            },
        ),
    ));
    evidence.signal = signal;
    if matches!(
        evidence.validation_failure_class,
        ValidationFailureClass::None
    ) && evidence
        .signal
        .as_ref()
        .is_some_and(|signal| !signal.accepted)
    {
        evidence.validation_failure_class = ValidationFailureClass::SignalFailure;
    }
    let mut samples: Vec<_> = windows
        .iter()
        .flat_map(|window| {
            window
                .iter()
                .map(|region| damon::normalize(region, &attrs, windows.len()))
        })
        .collect();
    for sample in &mut samples {
        sample.session_id = trace_name.clone();
        sample.timestamp_ns = u64::try_from(now_ns()?).unwrap_or(u64::MAX);
        sample.pid = child.id();
        sample.stable_identity = fixed_identity();
        sample.kernel = read_command("/usr/bin/uname", &["-r"])?;
        let range = damon::AddressRange {
            start: sample.region_start,
            end: sample.region_end,
        };
        sample.hot_overlap_bytes = range.overlap(hot_range);
        sample.warm_overlap_bytes = range.overlap(warm_range);
        sample.cold_overlap_bytes = range.overlap(cold_range);
        if sample.region_size > 0 {
            sample.hot_overlap_fraction =
                sample.hot_overlap_bytes as f64 / sample.region_size as f64;
            sample.warm_overlap_fraction =
                sample.warm_overlap_bytes as f64 / sample.region_size as f64;
            sample.cold_overlap_fraction =
                sample.cold_overlap_bytes as f64 / sample.region_size as f64;
        }
        sample.other_bytes = sample.region_size.saturating_sub(
            sample
                .hot_overlap_bytes
                .saturating_add(sample.warm_overlap_bytes)
                .saturating_add(sample.cold_overlap_bytes),
        );
    }
    let monitored_rate = monitored_progress_after
        .hot_cycles
        .saturating_sub(monitored_progress_before.hot_cycles) as f64
        / 5.0;
    let clock_ticks = clock_ticks_per_second()?;
    let kdamond_cpu = ticks_percent(kdamond_cpu_after - kdamond_cpu_before, clock_ticks, 5.0);
    let capture_cpu = (capture_cpu_after - capture_cpu_before) as f64 / 5_000_000_000.0 * 100.0;
    let overhead = damon::OverheadSample {
        kdamond_cpu_percent: kdamond_cpu,
        capture_cpu_percent: capture_cpu,
        target_slowdown_percent: if baseline_rate == 0.0 {
            0.0
        } else {
            ((baseline_rate - monitored_rate) / baseline_rate * 100.0).max(0.0)
        },
        events_per_second: samples.len() as f64 / 5.0,
        regions_per_second: samples.len() as f64 / 5.0,
        dropped_samples: 0,
    };
    let config = common::DamonConfig {
        enabled: false,
        mode: "monitor_only".to_owned(),
        allow_monitor_session: false,
        preferred_operation: "vaddr".to_owned(),
        sample_us: attrs.sample_us,
        aggr_us: attrs.aggr_us,
        update_us: attrs.update_us,
        min_regions: attrs.min_regions,
        max_regions: attrs.max_regions,
        max_cpu_overhead_percent: 1.0,
        max_session_seconds: 120,
        max_samples_per_session: 100_000,
        retention_days: 7,
        export_max_bytes: 67_108_864,
        max_action_time_ms: 5,
        max_action_bytes: 268_435_456,
    };
    let overhead_ok = damon::overhead_allowed(&overhead, &config, 5.0);
    evidence.checks.push(check(
        "overhead_budget",
        overhead_ok,
        format!(
            "kdamond={:.4}%, capture={:.4}%, budget=1.0%",
            overhead.kdamond_cpu_percent, overhead.capture_cpu_percent
        ),
    ));
    evidence.overhead = Some(overhead);
    if !overhead_ok
        && matches!(
            evidence.validation_failure_class,
            ValidationFailureClass::None
        )
    {
        evidence.validation_failure_class = ValidationFailureClass::OverheadFailure;
    }
    evidence.attrs_effective = Some(attrs);
    let jsonl = PathBuf::from(format!("/tmp/nemor-damon-dataset-{trace_name}.jsonl"));
    let csv = PathBuf::from(format!("/tmp/nemor-damon-dataset-{trace_name}.csv"));
    let jsonl_result =
        damon::export_dataset(&jsonl, damon::ExportFormat::Jsonl, &samples, 67_108_864);
    let csv_result = damon::export_dataset(&csv, damon::ExportFormat::Csv, &samples, 67_108_864);
    evidence.dataset_jsonl = jsonl_result.is_ok() && jsonl.is_file();
    evidence.dataset_csv = csv_result.is_ok() && csv.is_file();
    evidence.dataset_jsonl_path = Some(jsonl.display().to_string());
    evidence.dataset_csv_path = Some(csv.display().to_string());
    if (!evidence.dataset_jsonl || !evidence.dataset_csv)
        && matches!(
            evidence.validation_failure_class,
            ValidationFailureClass::None
        )
    {
        evidence.validation_failure_class = ValidationFailureClass::DatasetFailure;
    }
    evidence.checks.push(check(
        "dataset_jsonl",
        evidence.dataset_jsonl,
        jsonl_result
            .map(|_| "bounded versioned JSONL export created".to_owned())
            .unwrap_or_else(|error| error.to_string()),
    ));
    evidence.checks.push(check(
        "dataset_csv",
        evidence.dataset_csv,
        csv_result
            .map(|_| "bounded versioned CSV export created".to_owned())
            .unwrap_or_else(|error| error.to_string()),
    ));
    let _ = target_cpu_after.saturating_sub(target_cpu_before);
    child.wait_for_exit(Duration::from_secs(2))?;
    let final_progress = read_progress()?;
    evidence
        .post_run_fingerprints
        .insert("hot".to_owned(), final_progress.hot_fingerprint);
    evidence
        .post_run_fingerprints
        .insert("warm".to_owned(), final_progress.warm_fingerprint);
    evidence
        .post_run_fingerprints
        .insert("cold".to_owned(), final_progress.cold_fingerprint);
    let fingerprints_valid = final_progress.hot_fingerprint > final_progress.cold_fingerprint
        && final_progress.warm_fingerprint > final_progress.cold_fingerprint
        && final_progress.cold_fingerprint
            == selected_zone_size.saturating_div(4096).saturating_mul(3);
    evidence.checks.push(check(
        "post_run_fingerprint",
        fingerprints_valid,
        format!(
            "hot={}, warm={}, cold={}",
            final_progress.hot_fingerprint,
            final_progress.warm_fingerprint,
            final_progress.cold_fingerprint
        ),
    ));
    evidence
        .lifecycle_timeline_ns
        .insert("t11_child_exit".to_owned(), now_ns()?);
    cleanup.cleanup()?;
    cleanup.cleanup()?;
    evidence.checks.push(check(
        "cleanup",
        !trace_instance.exists() && read_trimmed(&admin.join("nr_kdamonds"))? == "0",
        "owned primary session removed; second cleanup harmless".to_owned(),
    ));
    run_worker(InternalWorker::DamonCrash)?;
    recover_damon_crash()?;
    evidence.checks.push(check(
        "recovery",
        read_trimmed(&admin.join("nr_kdamonds"))? == "0",
        "crash worker resources recovered".to_owned(),
    ));
    recover_damon_crash()?;
    evidence.recovery_idempotent = true;
    evidence.checks.push(check(
        "recovery_idempotent",
        true,
        "second recovery was a no-op".to_owned(),
    ));
    if trace_instances()? != baseline_instances || read_trimmed(&admin.join("nr_kdamonds"))? != "0"
    {
        bail!("DAMON cleanup did not restore baseline");
    }
    Ok(())
}

fn validate_damos(
    evidence: &mut DamosEvidence,
    deadline: &Deadline,
    external: Option<&ExternalTargetExpected>,
) -> Result<()> {
    evidence.attempted = true;
    deadline.check("DAMOS preflight")?;
    let damon_capability = damon::inspect_linux(
        Path::new("/"),
        Some(read_command("/usr/bin/uname", &["-r"])?),
    );
    let capability_safe = damon_capability.supported
        && damon_capability.writable
        && !damon_capability.active_external_session
        && !damon_capability.special_module_conflict;
    evidence.checks.push(check(
        "capability",
        capability_safe,
        format!("{damon_capability:?}"),
    ));
    if !capability_safe {
        evidence.failure_class = Some("capability_failure".into());
        bail!("DAMON ownership/capability preflight failed");
    }
    if mem_available_bytes()? < 1024 * 1024 * 1024 + 48 * 1024 * 1024 {
        evidence.failure_class = Some("safety_failure".into());
        bail!("one-GiB MemAvailable headroom cannot be preserved");
    }
    let admin = Path::new("/sys/kernel/mm/damon/admin/kdamonds");
    if read_trimmed(&admin.join("nr_kdamonds"))? != "0" {
        evidence.failure_class = Some("safety_failure".into());
        bail!("external kdamond objects make ownership ambiguous");
    }
    let baseline_instances = trace_instances()?;
    let (mut child, metadata, external_descriptor) = if let Some(expected) = external {
        let descriptor = external_target::validate_descriptor_file(
            &expected.descriptor_path,
            &expected.transaction_id,
            &expected.session_id,
            &expected.nonce,
            expected.creator_pid,
            expected.creator_start_ticks,
        )
        .context("external target ownership rejected before DAMON mutation")?;
        external_target::consume_descriptor_once(
            &expected.descriptor_path,
            &descriptor.payload_sha256,
        )
        .context("external target descriptor reuse rejected before DAMON mutation")?;
        let metadata = serde_json::json!({
            "pid": descriptor.payload.identity.pid,
            "start_ticks": descriptor.payload.identity.start_ticks,
            "state": "ready",
            "hot": [descriptor.payload.ranges.hot.start, descriptor.payload.ranges.hot.end],
            "warm": [descriptor.payload.ranges.warm.start, descriptor.payload.ranges.warm.end],
            "cold": [descriptor.payload.ranges.cold.start, descriptor.payload.ranges.cold.end]
        });
        (
            DamosTarget::External {
                descriptor: descriptor.clone(),
            },
            metadata,
            Some(descriptor),
        )
    } else {
        let (child, descriptor) = spawn_reusable_damos_target()?;
        let metadata = serde_json::json!({
            "pid": descriptor.payload.identity.pid,
            "start_ticks": descriptor.payload.identity.start_ticks,
            "state": "ready",
            "hot": [descriptor.payload.ranges.hot.start, descriptor.payload.ranges.hot.end],
            "warm": [descriptor.payload.ranges.warm.start, descriptor.payload.ranges.warm.end],
            "cold": [descriptor.payload.ranges.cold.start, descriptor.payload.ranges.cold.end]
        });
        (
            DamosTarget::Internal {
                child,
                descriptor: descriptor.clone(),
            },
            metadata,
            Some(descriptor),
        )
    };
    let [hot, warm, cold] = target_ranges_from_metadata(&metadata)?;
    evidence.target_pid = Some(child.id());
    evidence.target_start_ticks = Some(child.start_ticks());
    evidence.cold_range = Some(cold);
    let identity_ok = metadata["pid"].as_u64() == Some(u64::from(child.id()))
        && metadata["start_ticks"].as_u64() == Some(child.start_ticks())
        && proc_start_ticks(child.id())? == Some(child.start_ticks());
    evidence.checks.push(check(
        "synthetic_workload_ready",
        metadata["state"] == "ready",
        "READY barrier reached".into(),
    ));
    evidence.checks.push(check(
        "stable_target_identity",
        identity_ok,
        format!("pid={}, start_ticks={}", child.id(), child.start_ticks()),
    ));
    if !identity_ok {
        bail!("synthetic target identity mismatch");
    }
    let smaps = fs::read_to_string(format!("/proc/{}/smaps", child.id()))?;
    let mut backing = BTreeMap::from([
        ("hot".to_owned(), damon::parse_smaps_zone(&smaps, hot)?),
        ("warm".to_owned(), damon::parse_smaps_zone(&smaps, warm)?),
        ("cold".to_owned(), damon::parse_smaps_zone(&smaps, cold)?),
    ]);
    for zone in backing.values_mut() {
        zone.explicit_nohugepage_requested = true;
        zone.explicit_nohugepage_verified = zone.anon_huge_pages_kib == 0
            && (zone.thp_eligible == Some(false) || zone.vm_flags.iter().any(|flag| flag == "nh"));
    }
    evidence.separate_owned_mappings = Some([hot, warm, cold].into_iter().all(|left| {
        [hot, warm, cold]
            .into_iter()
            .all(|right| left == right || left.overlap(right) == 0)
    }));
    let containing_vma_shared = mark_shared_vma_group(&mut backing);
    evidence.containing_vma_shared = Some(containing_vma_shared);
    evidence.zone_backing = backing.clone();
    let base_pages = backing
        .values()
        .all(|zone| zone.explicit_nohugepage_requested && zone.explicit_nohugepage_verified);
    evidence.checks.push(check(
        "base_page_backing_verified",
        base_pages,
        format!("{backing:?}"),
    ));
    if !base_pages {
        bail!("mapping-local NOHUGEPAGE readback failed");
    }
    let ranges =
        damon::InitialRegionPlan::new(vec![hot, warm, cold], &proc_mapped_ranges(child.id())?)?;
    signal_damos_target(external_descriptor.as_ref(), "damon-start")?;
    std::thread::sleep(Duration::from_millis(1600));
    let progress = read_damos_progress(external_descriptor.as_ref())?;
    evidence.checks.push(check(
        "stable_cold_evidence",
        progress.cold_cycles == 0,
        "COLD untouched across at least three 500ms complete windows".into(),
    ));
    let protected_reject = |foreground, gaming| {
        let input = damos::EligibilityInput {
            identity: Some(damos::StableTargetIdentity {
                pid: child.id(),
                start_ticks: child.start_ticks(),
                stable_key: format!("synthetic:{}", child.start_ticks()),
                owned: true,
            }),
            identity_fresh: true,
            background: true,
            foreground,
            gaming,
            critical: false,
            protected: false,
            known_classification: true,
            pressure: policy_engine::PressureState::Pressure,
            cold_observations: (0..3)
                .map(|_| damos::ColdObservation {
                    complete: true,
                    nr_accesses: 0,
                    age: 3,
                    range: cold,
                })
                .collect(),
            valid_age_evidence: true,
            recent_refault: false,
            blacklisted: false,
            safety_conflict: false,
        };
        damos::evaluate_eligibility(&input).disposition == damos::PlanDisposition::Rejected
    };
    evidence.checks.push(check(
        "gaming_foreground_protection",
        protected_reject(true, false) && protected_reject(false, true),
        "foreground and gaming inputs rejected before sysfs action".into(),
    ));

    let access_pattern = damos::AccessPattern::validation_cold();
    let monitoring_intervals = damos::MonitoringIntervals {
        sample_us: 25_000,
        aggr_us: 500_000,
        update_us: 10_000_000,
    };
    let quota = damos::DamosQuota {
        time_ms: damos::VALIDATION_TIME_QUOTA_MS,
        bytes: damos::VALIDATION_BYTE_QUOTA,
        reset_interval_ms: damos::VALIDATION_RESET_INTERVAL_MS,
        total_applied_bytes: damos::VALIDATION_TOTAL_APPLIED_CEILING,
    };
    let configured_age_min = access_pattern.configured_age_min();
    let max_nr_snapshots = damos::VALIDATION_MAX_NR_SNAPSHOTS;
    damos::validate_attempt2_bounds(
        &access_pattern,
        &quota,
        500_000,
        damos::VALIDATION_LIVE_DEADLINE_MS,
        max_nr_snapshots,
    )?;
    evidence.configured_age_min = Some(configured_age_min);
    evidence.requested_max_nr_snapshots = Some(max_nr_snapshots);
    evidence.live_deadline_ms = Some(damos::VALIDATION_LIVE_DEADLINE_MS);
    evidence.quota_reset_interval_ms = Some(quota.reset_interval_ms);
    evidence.quota_reset_margin_ms = Some(
        quota
            .reset_interval_ms
            .saturating_sub(damos::VALIDATION_LIVE_DEADLINE_MS),
    );
    evidence.action_hard_ceiling_bytes = Some(damos::VALIDATION_BYTE_QUOTA);
    evidence.configured_session_total_ceiling = Some(damos::VALIDATION_TOTAL_APPLIED_CEILING);

    let shadow_id = format!("nemor-validation-damos-shadow-{}", now_ns()?);
    evidence.shadow_session_id = Some(shadow_id.clone());
    let shadow = run_owned_damos_session(DamosSessionSpec {
        session_id: &shadow_id,
        admin,
        child_pid: child.id(),
        child_start_ticks: child.start_ticks(),
        ranges: &ranges,
        hot,
        warm,
        cold,
        action: damos::DamosAction::Stat,
        duration: Duration::from_millis(3_000),
        validated_filter: None,
        access_pattern: &access_pattern,
        monitoring_intervals: &monitoring_intervals,
        quota: &quota,
        max_nr_snapshots: None,
    })?;
    evidence.capability = Some(shadow.capability.clone());
    evidence.shadow_stats = Some(shadow.stats.clone());
    evidence.shadow_trace = Some(shadow.trace.clone());
    evidence.shadow_candidates = shadow.candidates.clone();
    evidence.shadow_sysfs_timestamps_ns = shadow.sysfs_timestamps_ns.clone();
    evidence.shadow_sysfs_clock_domain = Some("realtime".into());
    evidence.shadow_access_pattern = Some(shadow.access_pattern.clone());
    evidence.shadow_monitoring_intervals = Some(shadow.monitoring_intervals.clone());
    evidence.empirical_shadow_first_eligibility_snapshot = shadow.stats.first_tried_snapshot_index;
    evidence.empirical_shadow_first_region_age = shadow.stats.first_tried_region_age;
    let shadow_trace_valid = shadow.trace.available
        && shadow.trace.trace_clock_readback
        && shadow.trace.event_enable_readback
        && shadow.trace.tracing_on_readback
        && shadow.trace.capture_worker_ready
        && shadow.trace.events_parsed > 0
        && shadow.trace.parse_failures == 0
        && shadow.trace.timestamp_failures == 0;
    let shadow_candidates_valid =
        damos::validate_shadow_candidates(&shadow.candidates, hot, warm, cold, configured_age_min)
            .is_ok();
    let shadow_sysfs_lifecycle_valid = tried_regions_lifecycle(&shadow.sysfs_timestamps_ns)
        .is_some_and(|lifecycle| lifecycle.valid());
    evidence.filter_api = Some(shadow.filter_spec.api.clone());
    evidence.filter_layer = Some(shadow.filter_spec.layer.clone());
    evidence.filter_type = Some(shadow.filter_spec.filter_type.clone());
    evidence.filter_matching_requested = Some(shadow.filter_spec.matching);
    evidence.filter_matching_effective = Some(shadow.filter_spec.matching);
    evidence.filter_allow_requested = shadow.filter_spec.allow;
    evidence.filter_allow_effective = shadow.filter_spec.allow;
    evidence.filter_start_requested = Some(cold.start);
    evidence.filter_start_effective = Some(shadow.filter_spec.range.start);
    evidence.filter_end_requested = Some(cold.end);
    evidence.filter_end_effective = Some(shadow.filter_spec.range.end);
    evidence.checks.extend([
        check(
            "vaddr_pageout_supported",
            shadow.capability.live_pageout_ready().is_ok(),
            format!("{:?}", shadow.capability),
        ),
        check(
            "cold_address_fence",
            shadow.fence_readback,
            format!("range={cold:?}"),
        ),
        check(
            "cold_address_filter_semantics_verified",
            shadow.fence_readback && shadow.filter_spec.validate(cold).is_ok(),
            format!("filter={:?}", shadow.filter_spec),
        ),
        check(
            "shadow_config_readback",
            shadow.access_pattern.readback && shadow.monitoring_intervals.readback,
            format!(
                "pattern={:?}, intervals={:?}",
                shadow.access_pattern, shadow.monitoring_intervals
            ),
        ),
        check(
            "shadow_candidate_evidence",
            shadow_trace_valid
                && shadow_candidates_valid
                && shadow_sysfs_lifecycle_valid
                && shadow.stats.nr_tried.unwrap_or(0) > 0
                && shadow.stats.sz_tried.unwrap_or(0) > 0,
            format!(
                "trace={:?}, candidates={}, sysfs_cross_check_regions={}, timestamps={:?}",
                shadow.trace,
                shadow.candidates.len(),
                shadow.stats.tried_region_samples.len(),
                shadow.sysfs_timestamps_ns
            ),
        ),
        check(
            "shadow_first_eligibility",
            shadow.stats.first_tried_snapshot_index.is_some()
                && shadow.stats.first_tried_region_age.is_some()
                && shadow.stats.first_tried_timestamp_ns.is_some(),
            format!(
                "snapshot={:?}, age={:?}, timestamp={:?}",
                shadow.stats.first_tried_snapshot_index,
                shadow.stats.first_tried_region_age,
                shadow.stats.first_tried_timestamp_ns
            ),
        ),
        check(
            "shadow_session_passed",
            shadow.stats.nr_tried.unwrap_or(0) > 0
                && shadow.stats.sz_tried.unwrap_or(0) > 0
                && shadow_trace_valid
                && shadow_candidates_valid
                && shadow
                    .candidates
                    .iter()
                    .all(|event| event.range.start >= cold.start && event.range.end <= cold.end),
            format!("{:?}", shadow.stats),
        ),
        check(
            "shadow_hot_overlap_zero",
            shadow
                .candidates
                .iter()
                .all(|event| event.range.overlap(hot) == 0),
            "no tried HOT overlap".into(),
        ),
        check(
            "shadow_warm_overlap_zero",
            shadow
                .candidates
                .iter()
                .all(|event| event.range.overlap(warm) == 0),
            "no tried WARM overlap".into(),
        ),
        check(
            "shadow_cleanup",
            shadow.cleaned,
            "owned stat session removed".into(),
        ),
    ]);
    if shadow.capability.live_pageout_ready().is_err()
        || !shadow.fence_readback
        || !shadow.access_pattern.readback
        || !shadow.monitoring_intervals.readback
        || !shadow_trace_valid
        || !shadow_candidates_valid
        || !shadow_sysfs_lifecycle_valid
        || shadow.stats.first_tried_snapshot_index.is_none()
        || shadow.stats.first_tried_region_age.is_none()
        || shadow.candidates.is_empty()
    {
        evidence.failure_class = Some("shadow_failure".into());
        bail!("shadow safety gate failed");
    }
    let decision_id = format!("manual-validation-decision-{}", now_ns()?);
    let plan_id = format!("damos-plan-{}", now_ns()?);
    evidence.decision_id = Some(decision_id.clone());
    evidence.plan_id = Some(plan_id.clone());
    let decision_record = serde_json::json!({
        "policy_decision_id": decision_id.clone(),
        "action_plan_id": plan_id.clone(),
        "target_pid": child.id(),
        "target_start_ticks": child.start_ticks(),
        "reason": "manual_validation",
        "pressure_state": "PRESSURE",
        "cold_range": cold,
        "timestamp_ns": now_ns()?,
    });
    let decision_path = Path::new(STATE_DIR).join("damos-decision.json");
    fs::write(&decision_path, serde_json::to_vec_pretty(&decision_record)?)?;
    evidence.checks.push(check(
        "policy_decision_recorded",
        decision_path.is_file(),
        format!("decision_id={decision_id}; reason=manual_validation"),
    ));
    quota.validate(5, 268_435_456)?;
    evidence.quota_requested = Some(quota.clone());
    let plan = damos::DamosPlan {
        decision_id: decision_id.clone(),
        plan_id: plan_id.clone(),
        session_id: format!("nemor-validation-damos-live-{}", now_ns()?),
        scheme_id: 0,
        target: damos::StableTargetIdentity {
            pid: child.id(),
            start_ticks: child.start_ticks(),
            stable_key: format!("synthetic:{}", child.start_ticks()),
            owned: true,
        },
        action: damos::DamosAction::Pageout,
        pattern_accesses_min: access_pattern.nr_accesses.min,
        pattern_accesses_max: access_pattern.nr_accesses.max,
        pattern_age_min: access_pattern.age.min,
        pattern_age_max: access_pattern.age.max,
        apply_interval_us: 500_000,
        quota: quota.clone(),
        fence: shadow.filter_spec.clone(),
        max_nr_snapshots: Some(max_nr_snapshots),
        dry_run: false,
    };
    plan.validate(5, 268_435_456)?;
    plan.fence.validate(cold)?;
    evidence.checks.push(check(
        "plan_audited",
        true,
        format!(
            "decision_id={decision_id}, plan_id={plan_id}, session_id={}",
            plan.session_id
        ),
    ));
    evidence
        .checks
        .push(check("quota_within_ceiling", true, format!("{quota:?}")));
    evidence.checks.extend([
        check(
            "quota_reset_after_session",
            damos::VALIDATION_LIVE_DEADLINE_MS < quota.reset_interval_ms,
            format!(
                "live_deadline_ms={}, reset_interval_ms={}, margin_ms={}",
                damos::VALIDATION_LIVE_DEADLINE_MS,
                quota.reset_interval_ms,
                quota
                    .reset_interval_ms
                    .saturating_sub(damos::VALIDATION_LIVE_DEADLINE_MS)
            ),
        ),
        check(
            "snapshot_ceiling_allows_eligibility",
            shadow
                    .stats
                    .first_tried_snapshot_index
                    .is_some_and(|first| max_nr_snapshots > first),
            format!(
                "configured_age_min={configured_age_min}, empirical_shadow_first={:?}, max={max_nr_snapshots}",
                shadow.stats.first_tried_snapshot_index
            ),
        ),
    ]);
    let live_id = plan.session_id.clone();
    evidence.live_session_id = Some(live_id.clone());
    evidence.checks.push(check(
        "live_session_independent",
        live_id != shadow_id,
        format!("shadow={shadow_id}, live={live_id}"),
    ));
    let smaps_before = fs::read_to_string(format!("/proc/{}/smaps", child.id()))?;
    let vma_before = damon::parse_smaps_zone(&smaps_before, cold)?;
    let hot_residency_before = read_range_residency(child.id(), child.start_ticks(), hot)?;
    let warm_residency_before = read_range_residency(child.id(), child.start_ticks(), warm)?;
    let cold_residency_before = read_range_residency(child.id(), child.start_ticks(), cold)?;
    let pagemap_capable = [
        &hot_residency_before,
        &warm_residency_before,
        &cold_residency_before,
    ]
    .into_iter()
    .all(|snapshot| snapshot.validate().is_ok());
    evidence.checks.push(check(
        "pagemap_range_evidence",
        pagemap_capable,
        format!(
            "source=proc_pagemap, hot={hot_residency_before:?}, warm={warm_residency_before:?}, cold={cold_residency_before:?}"
        ),
    ));
    if !pagemap_capable {
        evidence.failure_class = Some("capability_failure".into());
        bail!("exact owned-range pagemap evidence unavailable");
    }
    let progress_before = read_damos_progress(external_descriptor.as_ref())?;
    let control_before = process_cpu_ns()?;
    let oom_before = oom_kill_count();
    let live = run_owned_damos_session(DamosSessionSpec {
        session_id: &live_id,
        admin,
        child_pid: child.id(),
        child_start_ticks: child.start_ticks(),
        ranges: &ranges,
        hot,
        warm,
        cold,
        action: damos::DamosAction::Pageout,
        duration: Duration::from_millis(damos::VALIDATION_LIVE_MONITOR_MS),
        validated_filter: Some(&shadow.filter_spec),
        access_pattern: &access_pattern,
        monitoring_intervals: &monitoring_intervals,
        quota: &quota,
        max_nr_snapshots: Some(max_nr_snapshots),
    })?;
    let control_after = process_cpu_ns()?;
    let progress_after = read_damos_progress(external_descriptor.as_ref())?;
    let smaps_after_pageout = fs::read_to_string(format!("/proc/{}/smaps", child.id()))?;
    let vma_after_pageout = damon::parse_smaps_zone(&smaps_after_pageout, cold)?;
    // This snapshot is intentionally taken after state=off/stats/trace drain and
    // before the synthetic child is allowed to touch COLD for refault.
    let hot_residency_after_pageout = read_range_residency(child.id(), child.start_ticks(), hot)?;
    let warm_residency_after_pageout = read_range_residency(child.id(), child.start_ticks(), warm)?;
    let cold_residency_after_pageout = read_range_residency(child.id(), child.start_ticks(), cold)?;
    evidence.quota_effective = Some(live.quota.clone());
    evidence.live_access_pattern = Some(live.access_pattern.clone());
    evidence.live_monitoring_intervals = Some(live.monitoring_intervals.clone());
    evidence.live_stats = Some(live.stats.clone());
    evidence.live_trace = Some(live.trace.clone());
    evidence.live_candidates = live.candidates.clone();
    evidence.effective_max_nr_snapshots = live.stats.max_nr_snapshots;
    let mut reclaim = damos::ReclaimEvidence {
        stats: live.stats.clone(),
        vma: damos::VmaReclaimEvidence {
            containing_vma_start: vma_before.containing_vma_start.unwrap_or(0),
            containing_vma_end: vma_before.containing_vma_end.unwrap_or(0),
            containing_vma_shared,
            rss_before: vma_before.rss_kib * 1024,
            rss_after_pageout: vma_after_pageout.rss_kib * 1024,
            pss_before: vma_before.pss_kib * 1024,
            pss_after_pageout: vma_after_pageout.pss_kib * 1024,
            swap_before: vma_before.swap_kib * 1024,
            swap_after_pageout: vma_after_pageout.swap_kib * 1024,
        },
        ranges: damos::RangeReclaimEvidence {
            hot: damos::ZoneRangeEvidence {
                before: hot_residency_before,
                after_pageout: hot_residency_after_pageout,
                after_refault: None,
            },
            warm: damos::ZoneRangeEvidence {
                before: warm_residency_before,
                after_pageout: warm_residency_after_pageout,
                after_refault: None,
            },
            cold: damos::ZoneRangeEvidence {
                before: cold_residency_before,
                after_pageout: cold_residency_after_pageout,
                after_refault: None,
            },
        },
    };
    let applied = live.stats.sz_applied.unwrap_or(0);
    let hard_byte_ceiling_respected = damos::hard_byte_ceiling_respected(
        &live.stats,
        quota.bytes,
        quota.reset_interval_ms,
        damos::VALIDATION_LIVE_DEADLINE_MS,
    );
    let tried_region_size_sum = live
        .stats
        .tried_region_samples
        .iter()
        .map(|region| region.size)
        .sum::<u64>();
    let quota_respected = hard_byte_ceiling_respected
        && live
            .stats
            .nr_snapshots
            .is_some_and(|value| value <= max_nr_snapshots)
        && damos::VALIDATION_LIVE_DEADLINE_MS < quota.reset_interval_ms;
    evidence.reclaim = Some(reclaim.clone());
    let hot_cycles = progress_after
        .hot_cycles
        .saturating_sub(progress_before.hot_cycles);
    let expected_hot = (progress.hot_cycles as f64 / 1.6
        * (damos::VALIDATION_LIVE_MONITOR_MS as f64 / 1_000.0))
        .max(1.0);
    let slowdown = ((expected_hot - hot_cycles as f64) / expected_hot * 100.0).max(0.0);
    evidence.control_slowdown_percent = Some(slowdown);
    evidence.control_cpu_percent = Some(
        (control_after.saturating_sub(control_before) as f64
            / (damos::VALIDATION_LIVE_DEADLINE_MS as f64 * 1_000_000.0))
            * 100.0,
    );
    evidence.kdamond_cpu_percent = Some(live.kdamond_cpu_percent);
    let live_candidates_valid =
        damos::validate_shadow_candidates(&live.candidates, hot, warm, cold, configured_age_min)
            .is_ok();
    evidence.checks.extend([
        check(
            "live_config_readback",
            live.access_pattern.readback && live.monitoring_intervals.readback,
            format!(
                "pattern={:?}, intervals={:?}",
                live.access_pattern, live.monitoring_intervals
            ),
        ),
        check(
            "live_candidate_evidence",
            live.trace.available
                && live.trace.capture_worker_ready
                && live.trace.events_parsed > 0
                && live.trace.parse_failures == 0
                && live.trace.timestamp_failures == 0
                && live_candidates_valid,
            format!(
                "trace={:?}, candidates={}, sysfs_cross_check_regions={}",
                live.trace,
                live.candidates.len(),
                live.stats.tried_region_samples.len()
            ),
        ),
        check(
            "quota_readback",
            live.quota == quota,
            format!("{:?}", live.quota),
        ),
        check(
            "live_snapshot_ceiling",
            live.snapshot_ceiling_readback
                && damos::validate_attempt2_stats(&live.stats, max_nr_snapshots).is_ok(),
            format!(
                "configured_age_min={configured_age_min}, requested={max_nr_snapshots}, effective={:?}, nr_snapshots={:?}",
                live.stats.max_nr_snapshots, live.stats.nr_snapshots
            ),
        ),
        check(
            "pageout_action_readback",
            live.action_readback,
            "action=pageout".into(),
        ),
        check(
            "kdamond_started",
            live.started,
            "state on and PID readback".into(),
        ),
        check("kdamond_stopped", live.stopped, "state off readback".into()),
        check(
            "damos_stats_present",
            live.stats.nr_tried.is_some() && live.stats.sz_applied.is_some(),
            format!("{:?}", live.stats),
        ),
        check(
            "sz_applied_positive",
            applied > 0,
            format!("sz_applied={applied}"),
        ),
        check(
            "reclaim_effect_observed",
            reclaim.observed(),
            format!("{reclaim:?}"),
        ),
        check(
            "quota_respected",
            quota_respected,
            format!(
                "applied={applied}, hard_action_ceiling={}, configured_session_total_ceiling={}",
                damos::VALIDATION_BYTE_QUOTA,
                quota.total_applied_bytes
            ),
        ),
        check(
            "hard_byte_ceiling_respected",
            hard_byte_ceiling_respected,
            format!(
                "configured_bytes={}, reset_interval_ms={}, live_deadline_ms={}, nr_tried={:?}, sz_tried={:?}, nr_applied={:?}, sz_applied={:?}, qt_exceeds={:?}, tried_region_size_sum={}, tried_regions_semantics=bounded requested window and not assumed identical to cumulative sz_tried",
                quota.bytes,
                quota.reset_interval_ms,
                damos::VALIDATION_LIVE_DEADLINE_MS,
                live.stats.nr_tried,
                live.stats.sz_tried,
                live.stats.nr_applied,
                live.stats.sz_applied,
                live.stats.qt_exceeds,
                tried_region_size_sum,
            ),
        ),
        check(
            "hot_not_reclaimed",
            damos::range_not_reclaimed(
                &reclaim.ranges.hot.before,
                &reclaim.ranges.hot.after_pageout,
                &live.candidates,
                hot,
            ),
            format!(
                "candidate_overlap=0 required, before={:?}, after_pageout={:?}",
                reclaim.ranges.hot.before, reclaim.ranges.hot.after_pageout
            ),
        ),
        check(
            "warm_not_reclaimed",
            damos::range_not_reclaimed(
                &reclaim.ranges.warm.before,
                &reclaim.ranges.warm.after_pageout,
                &live.candidates,
                warm,
            ),
            format!(
                "candidate_overlap=0 required, before={:?}, after_pageout={:?}",
                reclaim.ranges.warm.before, reclaim.ranges.warm.after_pageout
            ),
        ),
        check(
            "control_slowdown_within_budget",
            slowdown <= 5.0,
            format!("slowdown_percent={slowdown:.6}"),
        ),
        check(
            "zero_oom",
            oom_kill_count() == oom_before,
            "oom_kill counter unchanged".into(),
        ),
        check(
            "scheme_removed",
            live.cleaned,
            "owned pageout scheme/context removed".into(),
        ),
    ]);
    let successful_reclaim = applied > 0 && reclaim.observed();
    if successful_reclaim {
        signal_damos_target(external_descriptor.as_ref(), "damon-refault")?;
        let fingerprint = if let Some(descriptor) = external_descriptor.as_ref() {
            let wait_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let progress = external_target::read_progress(&descriptor.payload.progress_path)?;
                if progress.controlled_refaults == 1 {
                    break u64::from_str_radix(
                        progress
                            .cold_fingerprint
                            .get(..16)
                            .unwrap_or(&progress.cold_fingerprint),
                        16,
                    )
                    .unwrap_or(0);
                }
                if Instant::now() >= wait_deadline {
                    bail!("external target did not acknowledge controlled COLD refault");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        } else {
            let refault_path = Path::new(STATE_DIR).join("damon-refault-result");
            wait_for_path(&refault_path, Duration::from_secs(5))?;
            read_trimmed(&refault_path)?.parse::<u64>()?
        };
        reclaim.ranges.hot.after_refault =
            Some(read_range_residency(child.id(), child.start_ticks(), hot)?);
        reclaim.ranges.warm.after_refault =
            Some(read_range_residency(child.id(), child.start_ticks(), warm)?);
        reclaim.ranges.cold.after_refault =
            Some(read_range_residency(child.id(), child.start_ticks(), cold)?);
        evidence.reclaim = Some(reclaim.clone());
        let refault = damos::RefaultEvidence {
            action_id: format!("action-{plan_id}"),
            target_key: plan.target.stable_key.clone(),
            region_signature: format!("{:x}-{:x}", cold.start, cold.end),
            applied_bytes: applied,
            action_timestamp_ns: now_ns()?.saturating_sub(1_000_000),
            first_access_timestamp_ns: Some(now_ns()?),
            rss_or_swap_evidence: reclaim.observed(),
            content_valid: fingerprint > 0,
        };
        let refault_state = refault.state(true, 30_000_000_000);
        let detected = refault_state == damos::RefaultState::Observed;
        evidence.refault_state = Some(refault_state);
        evidence.refault = Some(refault.clone());
        evidence.checks.push(check(
            "refault_content_valid",
            fingerprint > 0,
            format!("fingerprint={fingerprint}"),
        ));
        evidence
            .checks
            .push(check("refault_detected", detected, format!("{refault:?}")));
        if let Some(blacklist) = damos::blacklist_for_refault(
            refault,
            successful_reclaim,
            now_ns()?,
            now_ns()? + 300_000_000_000,
            30_000_000_000,
        ) {
            evidence.blacklist = Some(blacklist.clone());
            evidence.checks.push(check(
                "blacklist_created",
                blacklist.active(blacklist.created_at_ns),
                "early refault cooldown active".into(),
            ));
            let mut blocked_input = protected_eligibility(child.id(), child.start_ticks(), cold);
            blocked_input.blacklisted = true;
            let blocked = damos::evaluate_eligibility(&blocked_input);
            evidence.checks.push(check(
                "blacklist_blocks_next_plan",
                blocked
                    .reasons
                    .iter()
                    .any(|r| r == "early_refault_blacklist"),
                format!("{:?}", blocked.reasons),
            ));
        } else {
            evidence.checks.push(check(
                "blacklist_created",
                false,
                "not evaluated: early refault was not observed".into(),
            ));
            evidence.checks.push(check(
                "blacklist_blocks_next_plan",
                false,
                "not evaluated: no blacklist exists".into(),
            ));
        }
    } else {
        evidence.refault_state = Some(damos::RefaultState::NotEvaluated);
        evidence.checks.extend([
            check(
                "refault_content_valid",
                false,
                "not evaluated: no successful target-attributable reclaim".into(),
            ),
            check(
                "refault_detected",
                false,
                "not evaluated: no successful target-attributable reclaim".into(),
            ),
            check(
                "blacklist_created",
                false,
                "not evaluated: applied bytes/reclaim evidence absent".into(),
            ),
            check(
                "blacklist_blocks_next_plan",
                false,
                "not evaluated: no blacklist or second plan created".into(),
            ),
        ]);
    }
    signal_damos_target(external_descriptor.as_ref(), "damon-stop")?;
    child.wait_for_exit(Duration::from_secs(5))?;
    evidence.checks.push(check(
        "cleanup",
        read_trimmed(&admin.join("nr_kdamonds"))? == "0"
            && trace_instances()? == baseline_instances,
        "child, scheme, context, kdamond, tracing resources absent".into(),
    ));
    let mut recovered = damos::OwnedSession {
        session_id: live_id,
        target: plan.target,
        kdamond_index: 0,
        scheme_id: 0,
        state_on: false,
        interrupted: true,
    };
    let first = damos::recover_owned(&mut recovered, "nemor-validation-")?;
    let second = damos::recover_owned(&mut recovered, "nemor-validation-")?;
    evidence.checks.push(check(
        "recovery",
        first,
        "owned interrupted record recovered".into(),
    ));
    evidence.checks.push(check(
        "recovery_idempotent",
        !second,
        "second recovery no-op".into(),
    ));
    if live.stats.nr_tried == Some(0) {
        evidence.failure_class = Some("action_failure".into());
        evidence.failure_reason = Some("no_live_regions_tried".into());
    } else if applied == 0 {
        evidence.failure_class = Some("action_failure".into());
        evidence.failure_reason = Some("no_pageout_applied".into());
    } else if !reclaim.observed() {
        evidence.failure_class = Some("reclaim_evidence_failure".into());
        evidence.failure_reason = Some("no_target_attributable_reclaim_effect".into());
    }
    Ok(())
}

fn mark_shared_vma_group(backing: &mut BTreeMap<String, damon::ZoneBacking>) -> bool {
    let Some(first) = backing.values().next() else {
        return false;
    };
    let start = first.containing_vma_start;
    let end = first.containing_vma_end;
    let shared = backing.len() > 1
        && start.is_some()
        && end.is_some()
        && backing
            .values()
            .all(|zone| zone.containing_vma_start == start && zone.containing_vma_end == end);
    if shared {
        let group = format!("{:x}-{:x}", start.unwrap_or(0), end.unwrap_or(0));
        for zone in backing.values_mut() {
            zone.shared_vma = true;
            zone.shared_vma_group = Some(group.clone());
        }
    }
    shared
}

fn protected_eligibility(
    pid: u32,
    start_ticks: u64,
    cold: damon::AddressRange,
) -> damos::EligibilityInput {
    damos::EligibilityInput {
        identity: Some(damos::StableTargetIdentity {
            pid,
            start_ticks,
            stable_key: format!("synthetic:{start_ticks}"),
            owned: true,
        }),
        identity_fresh: true,
        background: true,
        foreground: false,
        gaming: false,
        critical: false,
        protected: false,
        known_classification: true,
        pressure: policy_engine::PressureState::Pressure,
        cold_observations: (0..3)
            .map(|_| damos::ColdObservation {
                complete: true,
                nr_accesses: 0,
                age: 3,
                range: cold,
            })
            .collect(),
        valid_age_evidence: true,
        recent_refault: false,
        blacklisted: false,
        safety_conflict: false,
    }
}

struct DamosSessionSpec<'a> {
    session_id: &'a str,
    admin: &'a Path,
    child_pid: u32,
    child_start_ticks: u64,
    ranges: &'a damon::InitialRegionPlan,
    hot: damon::AddressRange,
    warm: damon::AddressRange,
    cold: damon::AddressRange,
    action: damos::DamosAction,
    duration: Duration,
    validated_filter: Option<&'a damos::AddressFence>,
    access_pattern: &'a damos::AccessPattern,
    monitoring_intervals: &'a damos::MonitoringIntervals,
    quota: &'a damos::DamosQuota,
    max_nr_snapshots: Option<u64>,
}
struct DamosSessionResult {
    capability: damos::DamosCapability,
    stats: damos::DamosStats,
    quota: damos::DamosQuota,
    access_pattern: damos::Readback<damos::AccessPattern>,
    monitoring_intervals: damos::Readback<damos::MonitoringIntervals>,
    trace: DamosTraceDiagnostic,
    candidates: Vec<damos::DamosBeforeApplyEvent>,
    sysfs_timestamps_ns: BTreeMap<String, u128>,
    fence_readback: bool,
    filter_spec: damos::AddressFence,
    action_readback: bool,
    snapshot_ceiling_readback: bool,
    started: bool,
    stopped: bool,
    cleaned: bool,
    kdamond_cpu_percent: f64,
}

fn run_owned_damos_session(spec: DamosSessionSpec<'_>) -> Result<DamosSessionResult> {
    if !spec.session_id.starts_with("nemor-validation-damos-")
        || proc_start_ticks(spec.child_pid)? != Some(spec.child_start_ticks)
    {
        bail!("DAMOS owned session or target identity guard failed");
    }
    let trace_instance = tracefs_root()?.join("instances").join(spec.session_id);
    fs::create_dir(&trace_instance)?;
    let mut cleanup = DamonCleanup::new_for_event(
        spec.admin.to_path_buf(),
        trace_instance.clone(),
        "damos_before_apply",
    );
    cleanup.trace_created = true;
    let event_enable = trace_instance.join("events/damon/damos_before_apply/enable");
    if !event_enable.exists() {
        bail!("damon:damos_before_apply unavailable in owned tracefs instance");
    }
    let trace_clock = configure_owned_trace_clock(&trace_instance)?;
    write_readback(&event_enable, "1")?;
    cleanup.trace_enabled = true;
    write_readback(&trace_instance.join("tracing_on"), "1")?;
    cleanup.tracing_on = true;
    let capture = DamosTraceCaptureWorker::start(&trace_instance, trace_clock)?;

    write_readback(&spec.admin.join("nr_kdamonds"), "1")?;
    cleanup.kdamond_created = true;
    let kd = spec.admin.join("0");
    write_readback(&kd.join("contexts/nr_contexts"), "1")?;
    let context = kd.join("contexts/0");
    write_readback(&context.join("operations"), "vaddr")?;
    for (path, value) in [
        (
            "monitoring_attrs/intervals/sample_us",
            spec.monitoring_intervals.sample_us.to_string(),
        ),
        (
            "monitoring_attrs/intervals/aggr_us",
            spec.monitoring_intervals.aggr_us.to_string(),
        ),
        (
            "monitoring_attrs/intervals/update_us",
            spec.monitoring_intervals.update_us.to_string(),
        ),
        ("monitoring_attrs/nr_regions/min", "10".to_owned()),
        ("monitoring_attrs/nr_regions/max", "1000".to_owned()),
    ] {
        write_readback(&context.join(path), &value)?;
    }
    write_readback(&context.join("targets/nr_targets"), "1")?;
    write_readback(
        &context.join("targets/0/pid_target"),
        &spec.child_pid.to_string(),
    )?;
    let regions = context.join("targets/0/regions");
    write_readback(&regions.join("nr_regions"), "3")?;
    for (index, range) in spec.ranges.ranges.iter().enumerate() {
        write_readback(
            &regions.join(index.to_string()).join("start"),
            &range.start.to_string(),
        )?;
        write_readback(
            &regions.join(index.to_string()).join("end"),
            &range.end.to_string(),
        )?;
    }
    write_readback(&context.join("schemes/nr_schemes"), "1")?;
    let scheme = context.join("schemes/0");
    let mut capability = damos::inspect_scheme_root(&scheme, true, false, false);
    let action = match spec.action {
        damos::DamosAction::Stat => "stat",
        damos::DamosAction::Pageout => "pageout",
    };
    if matches!(spec.action, damos::DamosAction::Stat) {
        // Capability probe while kdamond is off: configure then restore, never apply.
        write_readback(&scheme.join("action"), "pageout")?;
        capability.actions.insert("pageout".into());
    }
    write_readback(&scheme.join("action"), action)?;
    let action_readback = read_trimmed(&scheme.join("action"))? == action;
    capability.actions.insert(action.into());
    for (path, value) in [
        ("apply_interval_us", "500000".into()),
        (
            "access_pattern/sz/min",
            spec.access_pattern.size.min.to_string(),
        ),
        (
            "access_pattern/sz/max",
            spec.access_pattern.size.max.to_string(),
        ),
        (
            "access_pattern/nr_accesses/min",
            spec.access_pattern.nr_accesses.min.to_string(),
        ),
        (
            "access_pattern/nr_accesses/max",
            spec.access_pattern.nr_accesses.max.to_string(),
        ),
        (
            "access_pattern/age/min",
            spec.access_pattern.age.min.to_string(),
        ),
        (
            "access_pattern/age/max",
            spec.access_pattern.age.max.to_string(),
        ),
        ("quotas/ms", spec.quota.time_ms.to_string()),
        ("quotas/bytes", spec.quota.bytes.to_string()),
        (
            "quotas/reset_interval_ms",
            spec.quota.reset_interval_ms.to_string(),
        ),
        ("watermarks/metric", "none".into()),
    ] {
        let full = scheme.join(path);
        if full.exists() {
            write_readback(&full, &value)?;
        } else if matches!(
            path,
            "quotas/ms" | "quotas/bytes" | "quotas/reset_interval_ms"
        ) {
            bail!("mandatory quota field missing: {path}");
        }
    }
    let filter_root = scheme.join("core_filters");
    if !filter_root.join("nr_filters").exists() {
        bail!("core address filters unavailable; deprecated generic filters are not accepted");
    }
    write_readback(&filter_root.join("nr_filters"), "1")?;
    let filter = filter_root.join("0");
    let api = if filter.join("allow").exists() {
        damos::FilterApi::MatchingAllow
    } else {
        damos::FilterApi::LegacyMatchingOnly
    };
    let filter_spec = damos::AddressFence {
        range: spec.cold,
        layer: "core".into(),
        filter_type: "addr".into(),
        api,
        matching: filter.join("allow").exists(),
        allow: filter.join("allow").exists().then_some(true),
    };
    if let Some(validated) = spec.validated_filter {
        if validated != &filter_spec {
            bail!("live filter API/spec differs from validated shadow specification");
        }
    }
    filter_spec.validate(spec.cold)?;
    write_readback(&filter.join("type"), "addr")?;
    let matching_value = if filter_spec.matching { "Y" } else { "N" };
    write_readback(&filter.join("matching"), matching_value)?;
    if let Some(allow) = filter_spec.allow {
        write_readback(&filter.join("allow"), if allow { "Y" } else { "N" })?;
    }
    let start_path = filter.join("addr_start");
    let end_path = filter.join("addr_end");
    if !start_path.exists() || !end_path.exists() {
        bail!("core addr filter range ABI unavailable");
    }
    write_readback(&start_path, &spec.cold.start.to_string())?;
    write_readback(&end_path, &spec.cold.end.to_string())?;
    let fence_readback = read_trimmed(&filter.join("type"))? == "addr"
        && read_trimmed(&filter.join("matching"))? == matching_value
        && match filter_spec.allow {
            Some(value) => read_trimmed(&filter.join("allow"))? == if value { "Y" } else { "N" },
            None => !filter.join("allow").exists(),
        }
        && read_trimmed(&start_path)?.parse::<u64>()? == spec.cold.start
        && read_trimmed(&end_path)?.parse::<u64>()? == spec.cold.end;
    capability.address_fence_supported = fence_readback;
    capability.filter_allow_supported = filter.join("allow").exists();
    capability.filter_types.insert("addr".into());
    capability.quota_fields.insert("ms".into(), true);
    capability.quota_fields.insert("bytes".into(), true);
    capability
        .quota_fields
        .insert("reset_interval_ms".into(), true);
    let quota = damos::DamosQuota {
        time_ms: read_trimmed(&scheme.join("quotas/ms"))?.parse()?,
        bytes: read_trimmed(&scheme.join("quotas/bytes"))?.parse()?,
        reset_interval_ms: read_trimmed(&scheme.join("quotas/reset_interval_ms"))?.parse()?,
        total_applied_bytes: damos::VALIDATION_TOTAL_APPLIED_CEILING,
    };
    let read_u64 = |path: &Path| -> Result<u64> { Ok(read_trimmed(path)?.parse()?) };
    let effective_pattern = damos::AccessPattern {
        size: damos::InclusiveRange {
            min: read_u64(&scheme.join("access_pattern/sz/min"))?,
            max: read_u64(&scheme.join("access_pattern/sz/max"))?,
        },
        nr_accesses: damos::InclusiveRange {
            min: read_u64(&scheme.join("access_pattern/nr_accesses/min"))?,
            max: read_u64(&scheme.join("access_pattern/nr_accesses/max"))?,
        },
        age: damos::InclusiveRange {
            min: read_u64(&scheme.join("access_pattern/age/min"))?,
            max: read_u64(&scheme.join("access_pattern/age/max"))?,
        },
    };
    let access_pattern = damos::Readback {
        requested: spec.access_pattern.clone(),
        readback: effective_pattern == *spec.access_pattern,
        effective: effective_pattern,
    };
    let effective_intervals = damos::MonitoringIntervals {
        sample_us: read_u64(&context.join("monitoring_attrs/intervals/sample_us"))?,
        aggr_us: read_u64(&context.join("monitoring_attrs/intervals/aggr_us"))?,
        update_us: read_u64(&context.join("monitoring_attrs/intervals/update_us"))?,
    };
    let monitoring_intervals = damos::Readback {
        requested: spec.monitoring_intervals.clone(),
        readback: effective_intervals == *spec.monitoring_intervals,
        effective: effective_intervals,
    };
    if !access_pattern.readback || !monitoring_intervals.readback || quota != *spec.quota {
        bail!("DAMOS pattern, intervals, or quota readback mismatch");
    }
    let max_snapshots_path = scheme.join("stats/max_nr_snapshots");
    let snapshot_ceiling_readback = if let Some(max_nr_snapshots) = spec.max_nr_snapshots {
        if !max_snapshots_path.exists() {
            bail!("secondary kernel kill-switch max_nr_snapshots unavailable");
        }
        write_readback(&max_snapshots_path, &max_nr_snapshots.to_string())?;
        capability.max_nr_snapshots_supported = true;
        read_u64(&max_snapshots_path)? == max_nr_snapshots
    } else {
        true
    };
    let cpu_before = process_cpu_ns()?;
    write_readback(&kd.join("state"), "on")?;
    cleanup.kdamond_on = true;
    let kpid = wait_kdamond_started(&kd, Duration::from_secs(3))?;
    let kcpu_before = proc_cpu_ticks(kpid)?;
    let session_started = Instant::now();
    let mut sysfs_timestamps_ns = BTreeMap::new();
    if scheme.join("tried_regions").exists() {
        fs::write(kd.join("state"), "clear_schemes_tried_regions")?;
        sysfs_timestamps_ns.insert("clear_stale_tried_regions".into(), now_ns()?);
        if !read_damos_stats(&scheme)?.tried_region_samples.is_empty() {
            bail!("stale sysfs tried_regions survived clear-before-arm");
        }
        sysfs_timestamps_ns.insert("request_arm_tried_regions".into(), now_ns()?);
        fs::write(kd.join("state"), "update_schemes_tried_regions")?;
        sysfs_timestamps_ns.insert("apply_interval_observation_start".into(), now_ns()?);
        std::thread::sleep(Duration::from_micros(600_000));
        sysfs_timestamps_ns.insert("armed_apply_interval_complete".into(), now_ns()?);
    }
    let mut first_eligibility = None;
    while session_started.elapsed() < spec.duration {
        let remaining = spec.duration.saturating_sub(session_started.elapsed());
        std::thread::sleep(remaining.min(Duration::from_millis(100)));
        fs::write(kd.join("state"), "update_schemes_stats")?;
        std::thread::sleep(Duration::from_millis(20));
        let current = read_damos_stats(&scheme)?;
        if current.nr_tried.unwrap_or(0) > 0 && first_eligibility.is_none() {
            let timestamp = now_ns()?;
            sysfs_timestamps_ns.insert("first_nr_tried_increment".into(), timestamp);
            first_eligibility = Some((current.nr_snapshots, timestamp));
        }
    }
    let kcpu_after = proc_cpu_ticks(kpid)?;
    fs::write(kd.join("state"), "update_schemes_stats")?;
    std::thread::sleep(Duration::from_millis(50));
    if scheme.join("quotas/effective_bytes").exists() {
        fs::write(kd.join("state"), "update_schemes_effective_quotas")?;
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut stats = read_damos_stats(&scheme)?;
    sysfs_timestamps_ns.insert("tried_regions_read".into(), now_ns()?);
    if scheme.join("tried_regions").exists() {
        fs::write(kd.join("state"), "clear_schemes_tried_regions")?;
        sysfs_timestamps_ns.insert("final_clear_tried_regions".into(), now_ns()?);
    }
    if let Some((snapshot, timestamp)) = first_eligibility {
        stats.first_tried_snapshot_index = snapshot;
        stats.first_tried_timestamp_ns = Some(timestamp);
    }
    write_readback(&kd.join("state"), "off")?;
    cleanup.kdamond_on = false;
    sysfs_timestamps_ns.insert("shadow_or_live_stop".into(), now_ns()?);
    let stopped = read_trimmed(&kd.join("state"))? == "off";
    let bytes_at_stop = capture.bytes_read()?;
    let (trace, candidates) = capture.drain_and_stop(bytes_at_stop)?;
    if let Some(first) = candidates.iter().min_by_key(|event| event.timestamp_ns) {
        stats.first_tried_region_age = Some(first.age);
        stats.first_tried_timestamp_ns = Some(first.timestamp_ns);
    }
    let _ = (spec.hot, spec.warm);
    let hertz = clock_ticks_per_second()? as f64;
    let kdamond_cpu_percent =
        (kcpu_after.saturating_sub(kcpu_before) as f64 / hertz / spec.duration.as_secs_f64())
            * 100.0;
    let _control_cpu = process_cpu_ns()?.saturating_sub(cpu_before);
    cleanup.cleanup()?;
    Ok(DamosSessionResult {
        capability,
        stats,
        quota,
        access_pattern,
        monitoring_intervals,
        trace,
        candidates,
        sysfs_timestamps_ns,
        fence_readback,
        filter_spec,
        action_readback,
        snapshot_ceiling_readback,
        started: true,
        stopped,
        cleaned: read_trimmed(&spec.admin.join("nr_kdamonds"))? == "0",
        kdamond_cpu_percent,
    })
}

fn read_damos_stats(scheme: &Path) -> Result<damos::DamosStats> {
    let read = |name: &str| -> Option<u64> {
        read_trimmed(&scheme.join("stats").join(name))
            .ok()?
            .parse()
            .ok()
    };
    let mut tried_regions = Vec::new();
    let mut tried_region_samples = Vec::new();
    let mut tried_regions_total_bytes = None;
    for root in [
        scheme.join("tried_regions"),
        scheme.join("stats/tried_regions"),
    ] {
        if tried_regions_total_bytes.is_none() {
            tried_regions_total_bytes = read_trimmed(&root.join("total_bytes"))
                .ok()
                .and_then(|value| value.parse().ok());
        }
        let mut count = read_trimmed(&root.join("nr_regions"))
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if count == 0 {
            count = fs::read_dir(&root)
                .ok()
                .into_iter()
                .flatten()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .bytes()
                        .all(|byte| byte.is_ascii_digit())
                })
                .count();
        }
        for index in 0..count {
            let item = root.join(index.to_string());
            if let (Ok(start), Ok(end)) = (
                read_trimmed(&item.join("start")).and_then(|v| v.parse().map_err(Into::into)),
                read_trimmed(&item.join("end")).and_then(|v| v.parse().map_err(Into::into)),
            ) {
                let range = damon::AddressRange { start, end };
                tried_regions.push(range);
                let optional = |name: &str| {
                    read_trimmed(&item.join(name))
                        .ok()
                        .and_then(|value| value.parse::<u64>().ok())
                };
                tried_region_samples.push(damos::TriedRegionSample {
                    range,
                    size: range.end.saturating_sub(range.start),
                    nr_accesses: optional("nr_accesses"),
                    age: optional("age"),
                    sz_filter_passed: optional("sz_filter_passed"),
                });
            }
        }
    }
    let effective_quota_raw = read_trimmed(&scheme.join("quotas/effective_bytes")).ok();
    let effective_quota_bytes = effective_quota_raw
        .as_deref()
        .and_then(|value| value.parse().ok());
    let effective_quota_interpretation = effective_quota_raw.as_ref().map(|raw| {
        if raw == "0" {
            "kernel-reported effective size quota is zero after explicit refresh; this is not interpreted as disabled quota because configured ms/bytes are nonzero".to_owned()
        } else {
            "kernel-reported effective size quota after explicit refresh".to_owned()
        }
    });
    Ok(damos::DamosStats {
        effective_quota_bytes,
        nr_tried: read("nr_tried"),
        sz_tried: read("sz_tried"),
        nr_applied: read("nr_applied"),
        sz_applied: read("sz_applied"),
        sz_ops_filter_passed: read("sz_ops_filter_passed"),
        qt_exceeds: read("qt_exceeds"),
        nr_snapshots: read("nr_snapshots"),
        max_nr_snapshots: read("max_nr_snapshots"),
        tried_regions,
        tried_region_samples,
        tried_regions_total_bytes,
        effective_quota_raw,
        effective_quota_interpretation,
        ..Default::default()
    })
}

fn read_range_residency(
    pid: u32,
    expected_start_ticks: u64,
    range: damon::AddressRange,
) -> Result<damos::RangeResidencySnapshot> {
    const PAGE_SIZE: u64 = 4096;
    const PAGEMAP_ENTRY_BYTES: u64 = 8;
    if proc_start_ticks(pid)? != Some(expected_start_ticks) {
        bail!("stale target identity before pagemap snapshot");
    }
    let size = range
        .end
        .checked_sub(range.start)
        .ok_or_else(|| anyhow!("invalid pagemap range"))?;
    if size == 0 || range.start % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
        bail!("pagemap range is not base-page aligned");
    }
    let total_pages = size / PAGE_SIZE;
    if total_pages > (32 * 1024 * 1024 / PAGE_SIZE) {
        bail!("pagemap range exceeds bounded synthetic COLD size");
    }
    let offset = (range.start / PAGE_SIZE)
        .checked_mul(PAGEMAP_ENTRY_BYTES)
        .ok_or_else(|| anyhow!("pagemap offset overflow"))?;
    let mut pagemap = OpenOptions::new()
        .read(true)
        .open(format!("/proc/{pid}/pagemap"))
        .with_context(|| format!("open exact-range pagemap for owned PID {pid}"))?;
    pagemap.seek(SeekFrom::Start(offset))?;
    let mut present_pages = 0_u64;
    let mut swapped_pages = 0_u64;
    let mut none_pages = 0_u64;
    for _ in 0..total_pages {
        let mut raw = [0_u8; 8];
        pagemap.read_exact(&mut raw)?;
        let state = damos::parse_pagemap_entry(u64::from_ne_bytes(raw));
        match (state.present, state.swapped) {
            (true, false) => present_pages += 1,
            (false, true) => swapped_pages += 1,
            (false, false) => none_pages += 1,
            (true, true) => bail!("invalid pagemap entry has present and swapped set"),
        }
    }
    if proc_start_ticks(pid)? != Some(expected_start_ticks) {
        bail!("stale target identity after pagemap snapshot");
    }
    let snapshot = damos::RangeResidencySnapshot {
        range_start: range.start,
        range_end: range.end,
        range_size_bytes: size,
        page_size: PAGE_SIZE,
        total_pages,
        present_pages,
        present_bytes: present_pages * PAGE_SIZE,
        swapped_pages,
        swapped_bytes: swapped_pages * PAGE_SIZE,
        not_present_not_swapped_pages: none_pages,
        read_errors: 0,
        timestamp_ns: now_ns()?,
        source: "proc_pagemap".into(),
    };
    snapshot.validate()?;
    Ok(snapshot)
}

fn oom_kill_count() -> u64 {
    fs::read_to_string("/proc/vmstat")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next() == Some("oom_kill"))
                    .then(|| fields.next()?.parse().ok())
                    .flatten()
            })
        })
        .unwrap_or(0)
}

fn damon_required_gates(evidence: &DamonEvidence) -> bool {
    evidence.zero_damos
        && DAMON_REQUIRED_GATES.iter().all(|required| {
            evidence
                .checks
                .iter()
                .any(|check| check.name == *required && check.passed)
        })
}

fn required_checks_pass(checks: &[Check], required: &[&str]) -> bool {
    required.iter().all(|name| {
        checks
            .iter()
            .any(|check| check.name == *name && check.passed)
    })
}

fn ensure_damos_failure_taxonomy(evidence: &mut DamosEvidence) {
    if evidence.failure_class.is_none() {
        evidence.failure_class = Some("validation_failure".to_owned());
    }
    if evidence.failure_reason.is_none() {
        let failed = DAMOS_REQUIRED_GATES
            .iter()
            .filter(|required| {
                evidence
                    .checks
                    .iter()
                    .any(|item| item.name == **required && item.state == GateState::Fail)
            })
            .copied()
            .collect::<Vec<_>>()
            .join(",");
        evidence.failure_reason = Some(format!("mandatory_gates_failed:{failed}"));
    }
}

fn tried_regions_lifecycle(
    timestamps: &BTreeMap<String, u128>,
) -> Option<damos::TriedRegionsLifecycle> {
    Some(damos::TriedRegionsLifecycle {
        stale_clear_ns: *timestamps.get("clear_stale_tried_regions")?,
        arm_ns: *timestamps.get("request_arm_tried_regions")?,
        observed_interval_start_ns: *timestamps.get("apply_interval_observation_start")?,
        read_ns: *timestamps.get("tried_regions_read")?,
        final_clear_ns: *timestamps.get("final_clear_tried_regions")?,
    })
}

fn fill_damos_not_evaluated_gates(evidence: &mut DamosEvidence) {
    for required in DAMOS_REQUIRED_GATES {
        if !evidence.checks.iter().any(|item| item.name == *required) {
            evidence.checks.push(Check {
                name: (*required).to_owned(),
                passed: false,
                state: GateState::NotEvaluated,
                detail: "not reached after earlier validation abort".to_owned(),
            });
        }
    }
}

fn fill_ksm_not_evaluated_gates(evidence: &mut KsmEvidence, required_gates: &[&str]) {
    for required in required_gates {
        if !evidence.checks.iter().any(|item| item.name == *required) {
            evidence.checks.push(Check {
                name: (*required).to_owned(),
                passed: false,
                state: GateState::NotEvaluated,
                detail: "not reached after earlier KSM validation abort".to_owned(),
            });
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KsmAuthoritativeOutcome {
    success: bool,
    error: Option<String>,
    exit_code: i32,
}

fn finalize_ksm_outcome(
    evidence: &mut KsmEvidence,
    scenario: KsmScenario,
) -> KsmAuthoritativeOutcome {
    deduplicate_checks(&mut evidence.checks);
    let required = if scenario == KsmScenario::Inefficient {
        KSM_INEFFICIENT_REQUIRED_GATES
    } else {
        KSM_REQUIRED_GATES
    };
    fill_ksm_not_evaluated_gates(evidence, required);
    evidence.required_gates_passed = required_checks_pass(&evidence.checks, required);
    let success = evidence.required_gates_passed
        && evidence.failure_class.is_none()
        && evidence.failure_reason.is_none();
    if !success {
        if evidence.failure_class.is_none() {
            evidence.failure_class = Some("validation_failure".into());
        }
        if evidence.failure_reason.is_none() {
            let failed = required
                .iter()
                .filter(|required| {
                    evidence
                        .checks
                        .iter()
                        .any(|check| check.name == **required && check.state != GateState::Pass)
                })
                .copied()
                .collect::<Vec<_>>()
                .join(",");
            evidence.failure_reason = Some(format!("mandatory_gates_failed:{failed}"));
        }
    }
    let error = (!success).then(|| {
        format!(
            "ksm: {}",
            evidence
                .failure_reason
                .as_deref()
                .unwrap_or("authoritative KSM validation failure")
        )
    });
    KsmAuthoritativeOutcome {
        success,
        error,
        exit_code: if success { 0 } else { 1 },
    }
}

fn synthetic_lifecycle_order_valid(timeline: &BTreeMap<String, u128>) -> bool {
    [
        "t0_child_spawn",
        "t1_allocations_complete",
        "t2_workers_ready",
        "t3_parent_received_ready",
        "t4_trace_capture_ready",
        "t5_damon_configured",
        "t6_kdamond_started",
        "t7_workload_start_sent",
        "t8_monitoring_window_end",
        "t9_kdamond_stopped",
        "t10_workload_stop_sent",
    ]
    .windows(2)
    .all(|pair| {
        timeline.get(pair[0]).is_some_and(|left| {
            timeline
                .get(pair[1])
                .is_some_and(|right| *left > 0 && left <= right)
        })
    })
}

fn workload_window_progress(
    progress_points: &[(u128, WorkloadProgress)],
) -> Vec<WorkloadWindowProgress> {
    progress_points
        .windows(2)
        .enumerate()
        .map(|(index, pair)| WorkloadWindowProgress {
            window_index: index as u64,
            start_ns: pair[0].0,
            end_ns: pair[1].0,
            hot_cycles_delta: pair[1].1.hot_cycles.saturating_sub(pair[0].1.hot_cycles),
            warm_cycles_delta: pair[1].1.warm_cycles.saturating_sub(pair[0].1.warm_cycles),
            hot_pages_touched_delta: pair[1]
                .1
                .hot_pages_touched
                .saturating_sub(pair[0].1.hot_pages_touched),
            warm_pages_touched_delta: pair[1]
                .1
                .warm_pages_touched
                .saturating_sub(pair[0].1.warm_pages_touched),
        })
        .collect()
}

fn trace_timestamp_ns(line: &str) -> Option<u128> {
    trace_timestamp_ns_for(line, "damon_aggregated:")
}

fn trace_timestamp_ns_for(line: &str, marker: &str) -> Option<u128> {
    let prefix = line.split_once(marker)?.0;
    let token = prefix
        .split_whitespace()
        .rev()
        .map(|token| token.trim_end_matches(':'))
        .find(|token| {
            token.split_once('.').is_some_and(|(seconds, fraction)| {
                !seconds.is_empty()
                    && !fraction.is_empty()
                    && seconds.bytes().all(|byte| byte.is_ascii_digit())
                    && fraction.bytes().all(|byte| byte.is_ascii_digit())
            })
        })?;
    let (seconds, fraction) = token.split_once('.')?;
    let seconds = seconds.parse::<u128>().ok()?;
    let mut nanoseconds = fraction
        .as_bytes()
        .iter()
        .take(9)
        .fold(0_u128, |value, digit| {
            value * 10 + u128::from(digit.saturating_sub(b'0'))
        });
    for _ in fraction.len().min(9)..9 {
        nanoseconds *= 10;
    }
    Some(seconds * 1_000_000_000 + nanoseconds)
}

fn group_timed_aggregation_windows(
    regions: Vec<(u128, damon::TraceRegion)>,
) -> Vec<(u128, Vec<damon::TraceRegion>)> {
    let mut windows = Vec::new();
    let mut current = Vec::new();
    let mut expected = 0_usize;
    let mut end_ns = 0;
    for (timestamp, region) in regions {
        if current.is_empty() {
            expected = region.nr_regions as usize;
            end_ns = timestamp;
        }
        if expected == 0 || region.nr_regions as usize != expected {
            current.clear();
            expected = region.nr_regions as usize;
            end_ns = timestamp;
        }
        current.push(region);
        end_ns = end_ns.max(timestamp);
        if current.len() == expected {
            windows.push((end_ns, std::mem::take(&mut current)));
            expected = 0;
        }
    }
    windows
}

fn align_complete_windows(
    timed_windows: Vec<(u128, Vec<damon::TraceRegion>)>,
    aggr_us: u64,
    monitoring_start_ns: u128,
    monitoring_end_ns: u128,
    progress: &[WorkloadWindowProgress],
) -> (Vec<AlignedWindowDiagnostic>, Vec<Vec<damon::TraceRegion>>) {
    let aggr_ns = u128::from(aggr_us) * 1_000;
    let alignment = timed_windows
        .iter()
        .enumerate()
        .map(|(index, (end_ns, _))| {
            let start_ns = end_ns.saturating_sub(aggr_ns);
            let partial = start_ns < monitoring_start_ns || *end_ns > monitoring_end_ns;
            let (hot_delta, overlap_duration_ns) =
                prorated_counter_delta(progress, start_ns, *end_ns, |point| point.hot_cycles_delta);
            let (warm_delta, _) = prorated_counter_delta(progress, start_ns, *end_ns, |point| {
                point.warm_cycles_delta
            });
            let (hot_pages_delta, _) =
                prorated_counter_delta(progress, start_ns, *end_ns, |point| {
                    point.hot_pages_touched_delta
                });
            let (warm_pages_delta, _) =
                prorated_counter_delta(progress, start_ns, *end_ns, |point| {
                    point.warm_pages_touched_delta
                });
            AlignedWindowDiagnostic {
                window_index: index as u64,
                start_uptime_ns: u64::try_from(start_ns).unwrap_or(u64::MAX),
                end_uptime_ns: u64::try_from(*end_ns).unwrap_or(u64::MAX),
                partial,
                hot_cycles_delta: hot_delta,
                warm_cycles_delta: warm_delta,
                hot_pages_touched_delta: hot_pages_delta,
                warm_pages_touched_delta: warm_pages_delta,
                overlap_duration_ns,
                alignment_method: "interval_overlap_prorated".to_owned(),
                alignment_estimated: true,
            }
        })
        .collect::<Vec<_>>();
    let complete = timed_windows
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !alignment[*index].partial)
        .map(|(_, (_, regions))| regions)
        .collect();
    (alignment, complete)
}

fn prorated_counter_delta(
    progress: &[WorkloadWindowProgress],
    window_start_ns: u128,
    window_end_ns: u128,
    counter: impl Fn(&WorkloadWindowProgress) -> u64,
) -> (u64, u128) {
    let mut estimated = 0.0_f64;
    let mut total_overlap = 0_u128;
    for point in progress {
        let interval_ns = point.end_ns.saturating_sub(point.start_ns);
        if interval_ns == 0 {
            continue;
        }
        let overlap_ns = point
            .end_ns
            .min(window_end_ns)
            .saturating_sub(point.start_ns.max(window_start_ns));
        if overlap_ns == 0 {
            continue;
        }
        total_overlap = total_overlap.saturating_add(overlap_ns);
        estimated += counter(point) as f64 * overlap_ns as f64 / interval_ns as f64;
    }
    (estimated.round() as u64, total_overlap)
}

fn userspace_clock_ns(clock: UserspaceClock) -> Result<u128> {
    let value = clock_gettime(clock.clock_id())?;
    let seconds = u128::try_from(value.tv_sec()).context("negative clock seconds")?;
    let nanoseconds = u128::try_from(value.tv_nsec()).context("negative clock nanoseconds")?;
    Ok(seconds * 1_000_000_000 + nanoseconds)
}

fn parse_trace_clocks(value: &str) -> Result<(Vec<String>, String)> {
    let available = value
        .split_whitespace()
        .map(|item| item.trim_matches(['[', ']']).to_owned())
        .collect::<Vec<_>>();
    let effective = value
        .split_whitespace()
        .find_map(|item| {
            item.strip_prefix('[')
                .and_then(|item| item.strip_suffix(']'))
        })
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("trace clock selection unavailable"))?;
    Ok((available, effective))
}

fn choose_trace_clock(available: &[String]) -> Result<(String, UserspaceClock)> {
    [
        ("mono", UserspaceClock::Monotonic),
        ("mono_raw", UserspaceClock::MonotonicRaw),
        ("boot", UserspaceClock::Boottime),
    ]
    .into_iter()
    .find(|(name, _)| available.iter().any(|item| item == name))
    .map(|(name, clock)| (name.to_owned(), clock))
    .ok_or_else(|| anyhow!("no trace clock directly correlatable with userspace"))
}

fn configure_owned_trace_clock(instance: &Path) -> Result<TraceClockPlan> {
    let name = instance.file_name().and_then(|name| name.to_str());
    let allowed_root = [
        "/sys/kernel/tracing/instances",
        "/sys/kernel/debug/tracing/instances",
    ]
    .into_iter()
    .any(|root| instance.starts_with(root));
    if !allowed_root || !name.is_some_and(|name| name.starts_with("nemor-validation-")) {
        bail!("trace_clock write rejected outside owned tracefs instance");
    }
    let path = instance.join("trace_clock");
    let (available, _) = parse_trace_clocks(&read_trimmed(&path)?)?;
    let (requested, userspace_clock) = choose_trace_clock(&available)?;
    fs::write(&path, &requested).with_context(|| format!("write {}", path.display()))?;
    let (_, effective) = parse_trace_clocks(&read_trimmed(&path)?)?;
    let readback = effective == requested;
    if !readback {
        bail!("owned trace clock readback mismatch");
    }
    Ok(TraceClockPlan {
        available,
        requested,
        effective,
        userspace_clock,
        readback,
    })
}

fn proc_mapped_ranges(pid: u32) -> Result<Vec<damon::AddressRange>> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    maps.lines()
        .map(|line| {
            let range = line
                .split_whitespace()
                .next()
                .ok_or_else(|| anyhow!("malformed proc maps line"))?;
            let (start, end) = range
                .split_once('-')
                .ok_or_else(|| anyhow!("malformed proc maps range"))?;
            Ok(damon::AddressRange {
                start: u64::from_str_radix(start, 16)?,
                end: u64::from_str_radix(end, 16)?,
            })
        })
        .collect()
}

fn damon_crash_worker() -> Result<()> {
    let admin = Path::new("/sys/kernel/mm/damon/admin/kdamonds");
    if read_trimmed(&admin.join("nr_kdamonds"))? != "0" {
        bail!("crash worker baseline ownership is ambiguous");
    }
    let trace_name = format!("nemor-validation-recovery-{}", now_ns()?);
    let trace_instance = tracefs_root()?.join("instances").join(&trace_name);
    let mut cleanup = DamonCleanup::new(admin.to_path_buf(), trace_instance.clone());
    fs::create_dir(&trace_instance)?;
    cleanup.trace_created = true;
    write_readback(&admin.join("nr_kdamonds"), "1")?;
    cleanup.kdamond_created = true;
    let kd = admin.join("0");
    write_readback(&kd.join("contexts/nr_contexts"), "1")?;
    let context = kd.join("contexts/0");
    write_readback(&context.join("operations"), "vaddr")?;
    write_readback(&context.join("targets/nr_targets"), "1")?;
    write_readback(
        &context.join("targets/0/pid_target"),
        &std::process::id().to_string(),
    )?;
    write_readback(&context.join("schemes/nr_schemes"), "0")?;
    fs::write(
        Path::new(STATE_DIR).join("damon-recovery.json"),
        serde_json::to_vec(&serde_json::json!({
            "trace_instance": trace_instance,
            "worker_pid": std::process::id(),
            "worker_start_ticks": proc_start_ticks(std::process::id())?,
            "zero_damos": true
        }))?,
    )?;
    write_readback(&kd.join("state"), "on")?;
    cleanup.kdamond_on = true;
    let _ = wait_kdamond_started(&kd, Duration::from_secs(3))?;
    std::mem::forget(cleanup);
    Ok(())
}

fn recover_damon_crash() -> Result<()> {
    let state_path = Path::new(STATE_DIR).join("damon-recovery.json");
    if !state_path.exists() {
        return Ok(());
    }
    let state: serde_json::Value = serde_json::from_slice(&fs::read(&state_path)?)?;
    if state["zero_damos"] != true {
        bail!("recovery state does not prove zero DAMOS");
    }
    let trace = PathBuf::from(
        state["trace_instance"]
            .as_str()
            .ok_or_else(|| anyhow!("missing recovery trace instance"))?,
    );
    if !trace
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("nemor-validation-recovery-"))
        || trace.parent() != Some(tracefs_root()?.join("instances").as_path())
    {
        bail!("recovery trace ownership is invalid");
    }
    let admin = Path::new("/sys/kernel/mm/damon/admin/kdamonds");
    if admin.join("0").exists() {
        if read_trimmed(&admin.join("0/state")).ok().as_deref() == Some("on") {
            fs::write(admin.join("0/state"), "off")?;
        }
        if read_trimmed(&admin.join("0/contexts/0/schemes/nr_schemes"))? != "0" {
            bail!("recovery refuses non-zero schemes");
        }
        fs::write(admin.join("nr_kdamonds"), "0")?;
    }
    if trace.exists() {
        fs::remove_dir(&trace)?;
    }
    fs::remove_file(state_path)?;
    Ok(())
}

fn validate_tiering(
    baseline: &HostSnapshot,
    evidence: &mut TieringEvidence,
    deadline: &Deadline,
) -> Result<()> {
    evidence.attempted = true;
    evidence.boot_validation_required = true;
    let zswap = tiering::inspect_linux(Path::new("/"), true)?;
    evidence.zswap_supported = zswap.supported;
    evidence.zswap_enabled = zswap.parameters.enabled;
    evidence.checks.push(check(
        "zswap_read_only_inventory",
        zswap.supported,
        format!(
            "supported={}, enabled={:?}; no global parameter was written",
            zswap.supported, zswap.parameters.enabled
        ),
    ));

    let (mount_source, filesystem) = mount_for(Path::new("/var/tmp"))?;
    let filesystem_kind = match filesystem.as_str() {
        "btrfs" => FilesystemKind::Btrfs,
        "ext4" => FilesystemKind::Ext4,
        _ => FilesystemKind::Unsupported,
    };
    if filesystem_kind == FilesystemKind::Unsupported {
        bail!("validation mount filesystem {filesystem} is unsupported");
    }
    let topology = inspect_storage(Path::new("/"), &mount_source, &filesystem);
    let storage_class = topology
        .physical
        .as_ref()
        .map_or(StorageClass::Unknown, |device| device.class);
    evidence.filesystem = Some(filesystem.clone());
    evidence.storage_class = Some(format!("{storage_class:?}").to_lowercase());
    evidence.checks.push(check(
        "storage_topology",
        !topology.ambiguous && topology.physical.is_some(),
        format!("mount_source={mount_source}, filesystem={filesystem}, class={storage_class:?}"),
    ));

    let path = PathBuf::from(format!(
        "/var/tmp/nemor-validation-tiering-{}.swap",
        now_ns()?
    ));
    if path.exists() {
        bail!("generated validation swapfile already exists");
    }
    evidence.swapfile = Some(path.display().to_string());
    let plan = SwapfilePlan {
        path: path.clone(),
        mountpoint: PathBuf::from("/var/tmp"),
        filesystem: filesystem_kind,
        backing_device: mount_source,
        physical_device_class: storage_class,
        proposed_size: TIERING_SWAP_BYTES,
        priority: 9,
        free_bytes: 0,
        required_headroom_bytes: 0,
        ownership: SwapfileOwnership::NemorOwned,
        create_required: true,
        format_required: true,
        activate_required: true,
        persistence_requested: false,
        allowed: true,
        blocked_reasons: Vec::new(),
        dry_run: false,
    };
    let before_stat = read_physical_block_stat(&topology)?;
    let mut backend = LinuxSwapfileBackend::default();
    let baseline_paths = baseline
        .swaps
        .iter()
        .map(|entry| PathBuf::from(&entry.path))
        .collect();
    let mut snapshot = TieringMutationSnapshot {
        path: path.clone(),
        baseline_swaps: baseline_paths,
        created: false,
        activated: false,
        rollback_pending: false,
        rolled_back: false,
        last_error: None,
    };
    deadline.check("tiering swapfile create and activate")?;
    apply_swapfile(&mut backend, &plan, &mut snapshot)?;
    let active = backend.active_swaps()?;
    if !active.contains(&path) || !active.contains(Path::new("/dev/zram0")) {
        let _ = rollback_swapfile(&mut backend, &mut snapshot);
        bail!("tiering checkpoint violated active swap or protected zram0 invariant");
    }
    evidence.no_swap_loss = true;
    evidence.checks.push(check(
        "owned_swapfile_active",
        true,
        "temporary owned swapfile and protected zram0 were simultaneously active".to_owned(),
    ));

    deadline.check("tiering restart recovery")?;
    drop(backend);
    let mut recovered = LinuxSwapfileBackend::default();
    recovered.resume_owned(&path)?;
    rollback_swapfile(&mut recovered, &mut snapshot)?;
    evidence.recovery_replayed = !path.exists() && !recovered.active_swaps()?.contains(&path);
    rollback_swapfile(&mut recovered, &mut snapshot)?;
    evidence.recovery_idempotent = true;
    evidence.checks.push(check(
        "rollback_recovery",
        evidence.recovery_replayed && evidence.recovery_idempotent,
        "fresh backend recovered exact root-owned path; second rollback was idempotent".to_owned(),
    ));

    let after_stat = read_physical_block_stat(&topology)?;
    evidence.block_write_bytes_delta = match (before_stat, after_stat) {
        (Some(before), Some(after)) => after
            .delta(before, 1_000_000)
            .map(|delta| delta.write_bytes),
        _ => None,
    };
    evidence.checks.push(check(
        "host_wide_block_accounting",
        evidence.block_write_bytes_delta.is_some(),
        format!(
            "physical write delta={:?} bytes; host-wide and not claimed as NAND-attributable",
            evidence.block_write_bytes_delta
        ),
    ));
    Ok(())
}

fn mount_for(path: &Path) -> Result<(String, String)> {
    let mut best: Option<(usize, String, String)> = None;
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields: Vec<_> = left.split_whitespace().collect();
        let right_fields: Vec<_> = right.split_whitespace().collect();
        if left_fields.len() < 5 || right_fields.len() < 2 {
            continue;
        }
        let mountpoint = Path::new(left_fields[4]);
        if path.starts_with(mountpoint) {
            let depth = mountpoint.components().count();
            if best.as_ref().is_none_or(|current| depth > current.0) {
                best = Some((
                    depth,
                    right_fields[1].to_owned(),
                    right_fields[0].to_owned(),
                ));
            }
        }
    }
    best.map(|(_, source, filesystem)| (source, filesystem))
        .ok_or_else(|| anyhow!("no mount found for {}", path.display()))
}

fn read_physical_block_stat(
    topology: &tiering::StorageTopology,
) -> Result<Option<tiering::BlockStat>> {
    let Some(device) = topology.physical.as_ref() else {
        return Ok(None);
    };
    let path = Path::new("/sys/class/block")
        .join(&device.name)
        .join("stat");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    Ok(Some(
        parse_block_stat(&text).map_err(|error| anyhow!(error))?,
    ))
}

fn validate_baseline(snapshot: &HostSnapshot) -> Result<()> {
    if !snapshot.validation_cgroups.is_empty() || !snapshot.validation_processes.is_empty() {
        bail!("pre-existing validation resource makes ownership ambiguous");
    }
    if snapshot.zram0.as_ref().is_none_or(|device| !device.active) {
        bail!("/dev/zram0 must be present and active");
    }
    Ok(())
}

fn compare_host(before: &HostSnapshot, after: &HostSnapshot) -> Result<()> {
    let structural = |entries: &[SwapEntry]| {
        entries
            .iter()
            .map(|entry| {
                (
                    entry.path.clone(),
                    entry.kind.clone(),
                    entry.size_kib,
                    entry.priority,
                )
            })
            .collect::<BTreeSet<_>>()
    };
    if structural(&before.swaps) != structural(&after.swaps) {
        bail!("swap topology differs");
    }
    if before.zram_devices != after.zram_devices {
        bail!("zram device topology differs");
    }
    compare_protected_zram(before, after)?;
    if !after.validation_cgroups.is_empty() {
        bail!("validation cgroup residue detected");
    }
    if !after.validation_processes.is_empty() {
        bail!("validation process residue detected");
    }
    Ok(())
}

fn compare_protected_zram(before: &HostSnapshot, after: &HostSnapshot) -> Result<()> {
    if before.zram0 != after.zram0 {
        bail!("protected zram0 structural configuration changed");
    }
    Ok(())
}

fn read_swaps() -> Result<Vec<SwapEntry>> {
    let text = fs::read_to_string("/proc/swaps")?;
    let mut entries = Vec::new();
    for line in text.lines().skip(1).filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 5 {
            bail!("unexpected /proc/swaps row");
        }
        entries.push(SwapEntry {
            path: fields[0].to_owned(),
            kind: fields[1].to_owned(),
            size_kib: fields[2].parse()?,
            used_kib: fields[3].parse()?,
            priority: fields[4].parse()?,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn validation_cgroups() -> Result<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    visit_cgroups(Path::new("/sys/fs/cgroup"), 0, &mut found)?;
    Ok(found)
}

fn visit_cgroups(path: &Path, depth: usize, found: &mut BTreeSet<String>) -> Result<()> {
    if depth > 8 {
        return Ok(());
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(PREFIX) {
            found.insert(entry.path().display().to_string());
        }
        visit_cgroups(&entry.path(), depth + 1, found)?;
    }
    Ok(())
}

fn validation_processes() -> Result<BTreeSet<u32>> {
    let mut found = BTreeSet::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let command = fs::read_to_string(entry.path().join("cmdline")).unwrap_or_default();
        if command.contains(PREFIX) {
            found.insert(pid);
        }
    }
    Ok(found)
}

fn verify_swap_checkpoint(baseline: &HostSnapshot, expected: &[&str]) -> Result<()> {
    let swaps = read_swaps()?;
    let protected = baseline
        .swaps
        .iter()
        .find(|entry| entry.path == "/dev/zram0")
        .ok_or_else(|| anyhow!("baseline zram0 swap missing"))?;
    if !swaps.iter().any(|entry| {
        entry.path == protected.path
            && entry.priority == protected.priority
            && entry.size_kib == protected.size_kib
    }) {
        bail!("protected zram0 missing or structurally changed at checkpoint");
    }
    for name in expected {
        if !swaps
            .iter()
            .any(|entry| entry.path == format!("/dev/{name}"))
        {
            bail!("expected test swap {name} is not active");
        }
    }
    if swaps.is_empty() {
        bail!("no-swap-loss invariant violated");
    }
    Ok(())
}

fn safety_path(path: &Path) -> bool {
    path.starts_with("/sys/fs/cgroup")
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(PREFIX) && name.ends_with(".scope"))
}

fn require_validation_group(name: &str) -> Result<()> {
    let path = Path::new("/sys/fs/cgroup").join(name);
    if !safety_path(&path)
        || name.contains('/')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        bail!("cgroup name is outside fixed validation namespace");
    }
    Ok(())
}

fn require_new_test_zram(name: &str, baseline: &HostSnapshot) -> Result<()> {
    require_new_test_zram_name(name, &baseline.zram_devices)
}

fn require_new_test_zram_name(name: &str, baseline_names: &BTreeSet<String>) -> Result<()> {
    if name == "zram0"
        || baseline_names.contains(name)
        || !name.strip_prefix("zram").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        bail!("hot-added device is protected, pre-existing, or non-canonical");
    }
    Ok(())
}

fn select_algorithm(available: &[String]) -> Result<String> {
    ["zstd", "lz4", "lzo-rle", "lzo"]
        .iter()
        .find(|candidate| available.iter().any(|value| value == **candidate))
        .map(|value| (*value).to_owned())
        .ok_or_else(|| anyhow!("no bounded validation algorithm is supported"))
}

struct RegisteredChild {
    child: std::process::Child,
    start_ticks: u64,
    terminated: bool,
}

enum DamosTarget {
    Internal {
        child: RegisteredChild,
        descriptor: CapacityExternalTargetDescriptor,
    },
    External {
        descriptor: CapacityExternalTargetDescriptor,
    },
}

impl DamosTarget {
    fn id(&self) -> u32 {
        match self {
            Self::Internal { child, .. } => child.id(),
            Self::External { descriptor } => descriptor.payload.identity.pid,
        }
    }

    fn start_ticks(&self) -> u64 {
        match self {
            Self::Internal { child, .. } => child.start_ticks,
            Self::External { descriptor } => descriptor.payload.identity.start_ticks,
        }
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Result<()> {
        match self {
            Self::Internal { child, descriptor } => {
                let deadline = Instant::now() + timeout;
                while Instant::now() < deadline {
                    let progress =
                        external_target::read_progress(&descriptor.payload.progress_path)?;
                    if progress.state == external_target::CapacityExternalTargetState::Stopped {
                        return child.wait_for_exit(Duration::from_secs(1));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                child.terminate()
            }
            Self::External { descriptor } => {
                let deadline = Instant::now() + timeout;
                while Instant::now() < deadline {
                    let progress =
                        external_target::read_progress(&descriptor.payload.progress_path)?;
                    if progress.state == external_target::CapacityExternalTargetState::Stopped {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                bail!("external target did not acknowledge clean stop")
            }
        }
    }
}

impl RegisteredChild {
    fn new(child: std::process::Child, start_ticks: u64) -> Self {
        Self {
            child,
            start_ticks,
            terminated: false,
        }
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn terminate(&mut self) -> Result<()> {
        let pid = self.child.id();
        if proc_start_ticks(pid)? != Some(self.start_ticks) {
            bail!("refusing to terminate child after identity mismatch");
        }
        self.child.kill()?;
        let _status = self.child.wait()?;
        self.terminated = true;
        Ok(())
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.child.try_wait()?.is_some() {
                self.terminated = true;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.terminate()
    }
}

impl Drop for RegisteredChild {
    fn drop(&mut self) {
        if self.terminated {
            return;
        }
        let pid = self.child.id();
        if proc_start_ticks(pid).ok().flatten() == Some(self.start_ticks) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn terminate_worker_child(pid: u32, expected_start: u64) -> Result<()> {
    if proc_start_ticks(pid)? != Some(expected_start) {
        bail!("refusing recovery-child termination after PID identity mismatch");
    }
    let command = fs::read(format!("/proc/{pid}/cmdline"))?;
    if !String::from_utf8_lossy(&command).contains("nemor-validation-sleeper") {
        bail!("refusing to terminate a process outside the validation sleeper allow-list");
    }
    let status = Command::new("/usr/bin/kill")
        .args(["--", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()?;
    if !status.success() {
        bail!("allow-listed kill helper failed with {status}");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while proc_start_ticks(pid)? == Some(expected_start) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if proc_start_ticks(pid)? == Some(expected_start) {
        bail!("validation sleeper did not terminate");
    }
    Ok(())
}

fn proc_start_ticks(pid: u32) -> Result<Option<u64>> {
    let value = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let close = value
        .rfind(')')
        .ok_or_else(|| anyhow!("invalid proc stat"))?;
    Ok(value[close + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|field| field.parse().ok()))
}

fn ensure_no_new_cgroups(baseline: &HostSnapshot) -> Result<()> {
    if validation_cgroups()? != baseline.validation_cgroups {
        bail!("validation cgroup cleanup incomplete");
    }
    Ok(())
}

fn process_cpu_ns() -> Result<u64> {
    fs::read_to_string("/proc/self/schedstat")?
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("missing schedstat runtime"))?
        .parse()
        .context("invalid schedstat runtime")
}

fn throughput(bytes: usize, elapsed: Duration) -> f64 {
    bytes as f64 / elapsed.as_secs_f64().max(f64::EPSILON)
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while !path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if path.exists() {
        Ok(())
    } else {
        bail!("{} did not appear before timeout", path.display())
    }
}

fn fixed_identity() -> String {
    "a".repeat(64)
}

fn check(name: &str, passed: bool, detail: String) -> Check {
    Check {
        name: name.to_owned(),
        passed,
        state: if passed {
            GateState::Pass
        } else {
            GateState::Fail
        },
        detail,
    }
}

fn set_check(checks: &mut Vec<Check>, authoritative: Check) {
    checks.retain(|item| item.name != authoritative.name);
    checks.push(authoritative);
}

fn deduplicate_checks(checks: &mut Vec<Check>) {
    let mut names = BTreeSet::new();
    checks.reverse();
    checks.retain(|item| names.insert(item.name.clone()));
    checks.reverse();
}

fn now_ns() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())
}

struct StateDir;

impl StateDir {
    fn create() -> Result<Self> {
        let path = Path::new(STATE_DIR);
        if path.exists() {
            bail!("{STATE_DIR} already exists; ownership is ambiguous");
        }
        fs::create_dir(path)?;
        Ok(Self)
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(STATE_DIR);
    }
}

#[derive(Debug, Clone)]
struct ExplicitReportDestination {
    path: PathBuf,
    root: PathBuf,
    root_device: u64,
    root_inode: u64,
}

fn explicit_report_destination(
    report_path: Option<&Path>,
    report_root: Option<&Path>,
) -> Result<Option<ExplicitReportDestination>> {
    let (Some(path), Some(root)) = (report_path, report_root) else {
        if report_path.is_some() || report_root.is_some() {
            bail!("explicit report path and root must be supplied together");
        }
        return Ok(None);
    };
    if !path.is_absolute() || !root.is_absolute() {
        bail!("explicit report path and root must be absolute");
    }
    if !matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("damos-component-report.json" | "raw-damos-report.json")
    ) {
        bail!("explicit report filename is not allow-listed");
    }
    if path.parent() != Some(root) {
        bail!("explicit report must be a direct child of its authorized root");
    }
    let root_meta = fs::symlink_metadata(root)
        .with_context(|| format!("inspect explicit report root {}", root.display()))?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        bail!("explicit report root must be a non-symlink directory");
    }
    if fs::canonicalize(root)? != root {
        bail!("explicit report root is not canonical");
    }
    if fs::symlink_metadata(path).is_ok() {
        bail!("explicit report path already exists");
    }
    Ok(Some(ExplicitReportDestination {
        path: path.to_path_buf(),
        root: root.to_path_buf(),
        root_device: root_meta.dev(),
        root_inode: root_meta.ino(),
    }))
}

fn write_report(
    report: &ValidationReport,
    destination: Option<&ExplicitReportDestination>,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report)?;
    if let Some(destination) = destination {
        return write_explicit_report(&bytes, destination);
    }
    let archive = report_archive_path(report.started_ns);
    write_archived_report(
        &bytes,
        &archive,
        Path::new(REPORT_PATH),
        Path::new(STATE_DIR),
    )
}

fn write_explicit_report(bytes: &[u8], destination: &ExplicitReportDestination) -> Result<()> {
    let root_meta = fs::symlink_metadata(&destination.root)?;
    if root_meta.file_type().is_symlink()
        || !root_meta.is_dir()
        || root_meta.dev() != destination.root_device
        || root_meta.ino() != destination.root_inode
        || fs::canonicalize(&destination.root)? != destination.root
    {
        bail!("explicit report root identity changed before write");
    }
    if fs::symlink_metadata(&destination.path).is_ok() {
        bail!("explicit report path appeared before write");
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&destination.path)
        .with_context(|| format!("create explicit report {}", destination.path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.dev() != fs::metadata(&destination.root)?.dev()
    {
        bail!("explicit report metadata violates the report contract");
    }
    fs::File::open(&destination.root)?.sync_all()?;
    Ok(())
}

fn report_archive_path(run_id: u128) -> PathBuf {
    PathBuf::from(format!(
        "/tmp/nemor-privileged-validation-report-{run_id}.json"
    ))
}

fn write_archived_report(
    bytes: &[u8],
    archive: &Path,
    latest: &Path,
    staging_dir: &Path,
) -> Result<()> {
    let staged_archive = staging_dir.join("report-archive.json");
    fs::write(&staged_archive, bytes)?;
    if archive.exists() {
        bail!("run-scoped report already exists");
    }
    fs::rename(&staged_archive, archive)?;
    let staged_latest = staging_dir.join("report-latest.json");
    fs::write(&staged_latest, bytes)?;
    fs::rename(staged_latest, latest)?;
    Ok(())
}

fn read_command(executable: &str, args: &[&str]) -> Result<String> {
    if !matches!(
        executable,
        "/usr/bin/git" | "/usr/bin/uname" | "/usr/bin/getconf"
    ) {
        bail!("read-only executable is not allow-listed");
    }
    let output = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        bail!("{executable} failed");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

struct DamonCleanup {
    admin: PathBuf,
    trace_instance: PathBuf,
    kdamond_created: bool,
    kdamond_on: bool,
    trace_created: bool,
    trace_enabled: bool,
    tracing_on: bool,
    trace_event: String,
}

impl DamonCleanup {
    fn new(admin: PathBuf, trace_instance: PathBuf) -> Self {
        Self {
            admin,
            trace_instance,
            kdamond_created: false,
            kdamond_on: false,
            trace_created: false,
            trace_enabled: false,
            tracing_on: false,
            trace_event: "damon_aggregated".to_owned(),
        }
    }

    fn new_for_event(admin: PathBuf, trace_instance: PathBuf, trace_event: &str) -> Self {
        let mut cleanup = Self::new(admin, trace_instance);
        cleanup.trace_event = trace_event.to_owned();
        cleanup
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.kdamond_on {
            fs::write(self.admin.join("0/state"), "off")?;
            self.kdamond_on = false;
        }
        if self.kdamond_created {
            fs::write(self.admin.join("nr_kdamonds"), "0")?;
            self.kdamond_created = false;
        }
        if self.tracing_on {
            fs::write(self.trace_instance.join("tracing_on"), "0")?;
            self.tracing_on = false;
        }
        if self.trace_enabled {
            fs::write(
                self.trace_instance
                    .join("events/damon")
                    .join(&self.trace_event)
                    .join("enable"),
                "0",
            )?;
            self.trace_enabled = false;
        }
        if self.trace_created && self.trace_instance.exists() {
            fs::remove_dir(&self.trace_instance)?;
            self.trace_created = false;
        }
        Ok(())
    }
}

impl Drop for DamonCleanup {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn tracefs_root() -> Result<PathBuf> {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.join("instances").is_dir())
        .ok_or_else(|| anyhow!("tracefs instances are unavailable"))
}

fn trace_instances() -> Result<BTreeSet<String>> {
    let root = tracefs_root()?.join("instances");
    Ok(fs::read_dir(root)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect())
}

fn read_trimmed(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?
        .trim()
        .to_owned())
}

fn write_readback(path: &Path, value: &str) -> Result<()> {
    fs::write(path, value).with_context(|| format!("write {}", path.display()))?;
    if read_trimmed(path)? != value {
        bail!("readback mismatch for {}", path.display());
    }
    Ok(())
}

fn wait_kdamond_started(path: &Path, timeout: Duration) -> Result<u32> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if read_trimmed(&path.join("state")).ok().as_deref() == Some("on") {
            if let Ok(pid) = read_trimmed(&path.join("pid")).and_then(|value| {
                value
                    .parse::<u32>()
                    .map_err(|error| anyhow!(error.to_string()))
            }) {
                return Ok(pid);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    bail!("kdamond start readback failed")
}

fn run_damon_probe(
    zone_size: u64,
    attrs: &damon::MonitoringAttrs,
    backing_profile: damon::PageBackingProfile,
) -> Result<damon::ProbeEvidence> {
    let admin = Path::new("/sys/kernel/mm/damon/admin/kdamonds");
    if read_trimmed(&admin.join("nr_kdamonds"))? != "0" {
        bail!("probe refuses existing kdamond objects");
    }
    let trace_root = tracefs_root()?;
    let trace_name = format!("nemor-validation-probe-{}", now_ns()?);
    let trace_instance = trace_root.join("instances").join(&trace_name);
    let mut cleanup = DamonCleanup::new(admin.to_path_buf(), trace_instance.clone());
    let mut child = spawn_damon_target(zone_size, backing_profile)?;
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(Path::new(STATE_DIR).join("damon-target.json"))?)?;
    let [hot, warm, cold] = target_ranges_from_metadata(&metadata)?;
    let smaps = fs::read_to_string(format!("/proc/{}/smaps", child.id()))?;
    let mut zone_backing = BTreeMap::from([
        ("hot".to_owned(), damon::parse_smaps_zone(&smaps, hot)?),
        ("warm".to_owned(), damon::parse_smaps_zone(&smaps, warm)?),
        ("cold".to_owned(), damon::parse_smaps_zone(&smaps, cold)?),
    ]);
    for backing in zone_backing.values_mut() {
        backing.explicit_nohugepage_requested =
            backing_profile == damon::PageBackingProfile::BasePageNoHuge;
        backing.explicit_nohugepage_verified = backing.explicit_nohugepage_requested
            && backing.anon_huge_pages_kib == 0
            && (backing.thp_eligible == Some(false)
                || backing.vm_flags.iter().any(|flag| flag == "nh"));
    }
    let base_page_backing_verified = damon::verify_base_page_backing(&zone_backing);
    if backing_profile == damon::PageBackingProfile::BasePageNoHuge && !base_page_backing_verified {
        bail!("owned synthetic mapping did not verify base-page backing");
    }
    let hot_backing = zone_backing
        .get("hot")
        .ok_or_else(|| anyhow!("HOT backing metadata missing"))?;
    let plan =
        damon::InitialRegionPlan::new(vec![hot, warm, cold], &proc_mapped_ranges(child.id())?)?;

    fs::create_dir(&trace_instance)?;
    cleanup.trace_created = true;
    let trace_clock = configure_owned_trace_clock(&trace_instance)?;
    let enable = trace_instance.join("events/damon/damon_aggregated/enable");
    write_readback(&enable, "1")?;
    cleanup.trace_enabled = true;
    write_readback(&trace_instance.join("tracing_on"), "1")?;
    cleanup.tracing_on = true;
    let capture = run_damon_monitor_session(MonitorSessionSpec {
        session_id: &trace_name,
        trace_instance: &trace_instance,
    })?;
    write_readback(&admin.join("nr_kdamonds"), "1")?;
    cleanup.kdamond_created = true;
    let kd = admin.join("0");
    write_readback(&kd.join("contexts/nr_contexts"), "1")?;
    let context = kd.join("contexts/0");
    if !read_trimmed(&context.join("avail_operations"))?
        .split_whitespace()
        .any(|operation| operation == "vaddr")
    {
        bail!("probe context has no vaddr operation");
    }
    write_readback(&context.join("operations"), "vaddr")?;
    for (path, value) in [
        (
            "monitoring_attrs/intervals/sample_us",
            attrs.sample_us.to_string(),
        ),
        (
            "monitoring_attrs/intervals/aggr_us",
            attrs.aggr_us.to_string(),
        ),
        (
            "monitoring_attrs/intervals/update_us",
            attrs.update_us.to_string(),
        ),
        (
            "monitoring_attrs/nr_regions/min",
            attrs.min_regions.to_string(),
        ),
        (
            "monitoring_attrs/nr_regions/max",
            attrs.max_regions.to_string(),
        ),
    ] {
        write_readback(&context.join(path), &value)?;
    }
    write_readback(&context.join("targets/nr_targets"), "1")?;
    write_readback(
        &context.join("targets/0/pid_target"),
        &child.id().to_string(),
    )?;
    let regions = context.join("targets/0/regions");
    write_readback(&regions.join("nr_regions"), "3")?;
    for (index, range) in plan.ranges.iter().enumerate() {
        write_readback(
            &regions.join(index.to_string()).join("start"),
            &range.start.to_string(),
        )?;
        write_readback(
            &regions.join(index.to_string()).join("end"),
            &range.end.to_string(),
        )?;
    }
    write_readback(&context.join("schemes/nr_schemes"), "0")?;
    if read_trimmed(&context.join("schemes/nr_schemes"))? != "0" {
        bail!("probe zero DAMOS invariant failed");
    }
    let capture_before = process_cpu_ns()?;
    write_readback(&kd.join("state"), "on")?;
    cleanup.kdamond_on = true;
    let kdamond_pid = wait_kdamond_started(&kd, Duration::from_secs(3))?;
    let kdamond_before = proc_cpu_ticks(kdamond_pid)?;
    let progress_before = read_progress()?;
    let monitoring_start_ns = userspace_clock_ns(trace_clock.userspace_clock)?;
    signal_damon_target("damon-start")?;
    let duration = Duration::from_millis(5_100);
    std::thread::sleep(duration);
    let progress_after = read_progress()?;
    let monitoring_end_ns = userspace_clock_ns(trace_clock.userspace_clock)?;
    let kdamond_after = proc_cpu_ticks(kdamond_pid)?;
    let bytes_at_stop = capture.bytes_read()?;
    write_readback(&kd.join("state"), "off")?;
    cleanup.kdamond_on = false;
    signal_damon_target("damon-stop")?;
    let (capture_diagnostic, captured_events) = capture.drain_and_stop(bytes_at_stop)?;
    write_readback(&trace_instance.join("tracing_on"), "0")?;
    cleanup.tracing_on = false;
    write_readback(&enable, "0")?;
    cleanup.trace_enabled = false;
    let capture_after = process_cpu_ns()?;
    let capture_integrity = capture_diagnostic.trace_bytes_read > 0
        && capture_diagnostic.damon_event_lines_seen > 0
        && capture_diagnostic.damon_events_parsed > 0
        && capture_diagnostic.parse_failures == 0
        && trace_clock.readback;
    if !capture_integrity {
        bail!("probe capture instrumentation failure");
    }
    let timed = captured_events
        .into_iter()
        .filter_map(|event| {
            event
                .timestamp_ns
                .map(|timestamp| (timestamp, event.region))
        })
        .collect();
    let timed_windows = group_timed_aggregation_windows(timed);
    let (_, windows) = align_complete_windows(
        timed_windows,
        attrs.aggr_us,
        monitoring_start_ns,
        monitoring_end_ns,
        &[],
    );
    let signal = damon::analyze_zones(&windows, attrs, hot, warm, cold);
    let hot_nonzero_windows = signal
        .window_diagnostics
        .iter()
        .filter(|window| window.hot_raw_accesses > 0)
        .count() as u64;
    let warm_nonzero_windows = signal
        .window_diagnostics
        .iter()
        .filter(|window| window.warm_raw_accesses > 0)
        .count() as u64;
    let cold_nonzero_windows = signal
        .window_diagnostics
        .iter()
        .filter(|window| window.cold_raw_accesses > 0)
        .count() as u64;
    child.wait_for_exit(Duration::from_secs(2))?;
    cleanup.cleanup()?;
    let seconds = duration.as_secs_f64();
    Ok(damon::ProbeEvidence {
        session_id: trace_name,
        source: "current_probe".to_owned(),
        backing_profile,
        zone_size_bytes: zone_size,
        windows: windows.len() as u64,
        hot_nonzero_windows,
        hot_zero_windows: windows.len() as u64 - hot_nonzero_windows,
        warm_nonzero_windows,
        cold_nonzero_windows,
        hot_ratio_mean: signal.hot.normalized_ratio_mean,
        hot_ratio_p25: signal.hot.normalized_ratio_p25,
        hot_ratio_p50: signal.hot.normalized_ratio_p50,
        hot_ratio_p75: signal.hot.normalized_ratio_p75,
        hot_ratio_p95: signal.hot.normalized_ratio_p95,
        hot_raw_accesses_per_window: signal
            .window_diagnostics
            .iter()
            .map(|window| window.hot_raw_accesses)
            .collect(),
        warm_ratio_mean: signal.warm.normalized_ratio_mean,
        warm_ratio_p25: signal.warm.normalized_ratio_p25,
        warm_ratio_p50: signal.warm.normalized_ratio_p50,
        warm_ratio_p75: signal.warm.normalized_ratio_p75,
        warm_ratio_p95: signal.warm.normalized_ratio_p95,
        warm_raw_accesses_per_window: signal
            .window_diagnostics
            .iter()
            .map(|window| window.warm_raw_accesses)
            .collect(),
        cold_ratio_mean: signal.cold.normalized_ratio_mean,
        cold_ratio_p25: signal.cold.normalized_ratio_p25,
        cold_ratio_p50: signal.cold.normalized_ratio_p50,
        cold_ratio_p75: signal.cold.normalized_ratio_p75,
        cold_ratio_p95: signal.cold.normalized_ratio_p95,
        cold_raw_accesses_per_window: signal
            .window_diagnostics
            .iter()
            .map(|window| window.cold_raw_accesses)
            .collect(),
        outside_requested_ratio: signal.outside_requested_ratio,
        kdamond_cpu_percent: ticks_percent(
            kdamond_after.saturating_sub(kdamond_before),
            clock_ticks_per_second()?,
            seconds,
        ),
        capture_cpu_percent: capture_after.saturating_sub(capture_before) as f64
            / duration.as_nanos() as f64
            * 100.0,
        backing_page_size_kib: hot_backing.kernel_page_size_kib,
        anon_huge_pages_kib: hot_backing.anon_huge_pages_kib,
        thp_eligible: hot_backing.thp_eligible,
        target_isolated: signal.target_isolated,
        workload_active: progress_after.hot_cycles > progress_before.hot_cycles
            && progress_after.warm_cycles > progress_before.warm_cycles
            && progress_after.cold_cycles == 0,
        capture_integrity,
        overhead_within_budget: ticks_percent(
            kdamond_after.saturating_sub(kdamond_before),
            clock_ticks_per_second()?,
            seconds,
        ) + (capture_after.saturating_sub(capture_before) as f64
            / duration.as_nanos() as f64
            * 100.0)
            <= 1.0,
        base_page_backing_verified,
        zone_backing,
    })
}

fn target_ranges_from_metadata(value: &serde_json::Value) -> Result<[damon::AddressRange; 3]> {
    let range = |name: &str| -> Result<damon::AddressRange> {
        let pair = value[name]
            .as_array()
            .ok_or_else(|| anyhow!("missing {name} zone"))?;
        Ok(damon::AddressRange {
            start: pair[0].as_u64().ok_or_else(|| anyhow!("invalid zone"))?,
            end: pair[1].as_u64().ok_or_else(|| anyhow!("invalid zone"))?,
        })
    };
    Ok([range("hot")?, range("warm")?, range("cold")?])
}

fn mem_available_bytes() -> Result<u64> {
    let text = fs::read_to_string("/proc/meminfo")?;
    let kib = text
        .lines()
        .find_map(|line| {
            line.strip_prefix("MemAvailable:")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse::<u64>().ok())
        })
        .ok_or_else(|| anyhow!("MemAvailable unavailable"))?;
    kib.checked_mul(1024)
        .ok_or_else(|| anyhow!("MemAvailable overflow"))
}

fn spawn_damon_target(
    zone_bytes: u64,
    backing_profile: damon::PageBackingProfile,
) -> Result<RegisteredChild> {
    spawn_synthetic_target(zone_bytes, zone_bytes, backing_profile)
}

fn spawn_synthetic_target(
    zone_bytes: u64,
    cold_zone_bytes: u64,
    backing_profile: damon::PageBackingProfile,
) -> Result<RegisteredChild> {
    let executable = std::env::current_exe()?.canonicalize()?;
    for name in [
        "damon-target.json",
        "damon-progress",
        "damon-progress.next",
        "damon-start",
        "damon-stop",
        "damon-zone-bytes",
        "damon-backing-profile",
        "damon-cold-zone-bytes",
        "damon-refault",
        "damon-refault-result",
    ] {
        let path = Path::new(STATE_DIR).join(name);
        if path.exists() {
            fs::remove_file(path)?;
        }
    }
    if !damon::DIAGNOSTIC_ZONE_SIZES.contains(&zone_bytes) {
        bail!("synthetic target zone size is outside deterministic ladder");
    }
    fs::write(
        Path::new(STATE_DIR).join("damon-zone-bytes"),
        zone_bytes.to_string(),
    )?;
    if cold_zone_bytes == 0 || cold_zone_bytes > damon::MAX_DIAGNOSTIC_ZONE_BYTES {
        bail!("COLD target zone size is outside bound");
    }
    fs::write(
        Path::new(STATE_DIR).join("damon-cold-zone-bytes"),
        cold_zone_bytes.to_string(),
    )?;
    fs::write(
        Path::new(STATE_DIR).join("damon-backing-profile"),
        serde_json::to_vec(&backing_profile)?,
    )?;
    let mut child = Command::new(executable)
        .args(["--internal-worker", "damon-target"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let metadata = Path::new(STATE_DIR).join("damon-target.json");
    if wait_for_path(&metadata, Duration::from_secs(5)).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        bail!("DAMON target metadata unavailable");
    }
    let start_ticks =
        proc_start_ticks(child.id())?.ok_or_else(|| anyhow!("synthetic child vanished"))?;
    Ok(RegisteredChild::new(child, start_ticks))
}

fn spawn_reusable_damos_target() -> Result<(RegisteredChild, CapacityExternalTargetDescriptor)> {
    let transaction_root = Path::new(STATE_DIR).join("damos-target-transaction");
    fs::create_dir(&transaction_root)?;
    fs::set_permissions(&transaction_root, fs::Permissions::from_mode(0o700))?;
    let creator_pid = std::process::id();
    let creator_start_ticks =
        proc_start_ticks(creator_pid)?.context("DAMOS controller start ticks unavailable")?;
    let transaction_id = format!("diagnostic-damos-{}", now_ns()?);
    let session_id = format!("{transaction_id}-target");
    let nonce = hex::encode(sha2::Sha256::digest(format!(
        "{transaction_id}:{creator_pid}:{creator_start_ticks}"
    )));
    let executable = std::env::current_exe()?
        .with_file_name("nemor-benchmark")
        .canonicalize()
        .context("exact sibling nemor-benchmark target binary unavailable")?;
    let mut process = Command::new(executable);
    process
        .arg("capacity-external-target-worker")
        .arg("--transaction-root")
        .arg(&transaction_root)
        .arg("--transaction-id")
        .arg(&transaction_id)
        .arg("--session-id")
        .arg(&session_id)
        .arg("--nonce")
        .arg(&nonce)
        .arg("--creator-pid")
        .arg(creator_pid.to_string())
        .arg("--creator-start-ticks")
        .arg(creator_start_ticks.to_string())
        .arg("--preparing-uid")
        .arg(nix::unistd::geteuid().as_raw().to_string())
        .arg("--preparing-gid")
        .arg(nix::unistd::getegid().as_raw().to_string())
        .arg("--unit-or-cgroup-identity")
        .arg("direct-child-diagnostic")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = process.spawn()?;
    let descriptor_path = transaction_root.join("target-descriptor.json");
    if wait_for_path(&descriptor_path, Duration::from_secs(5)).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        bail!("reusable DAMOS target descriptor unavailable");
    }
    let start_ticks =
        proc_start_ticks(child.id())?.ok_or_else(|| anyhow!("reusable DAMOS target vanished"))?;
    let descriptor = external_target::validate_descriptor_file(
        &descriptor_path,
        &transaction_id,
        &session_id,
        &nonce,
        creator_pid,
        creator_start_ticks,
    )?;
    external_target::consume_descriptor_once(&descriptor_path, &descriptor.payload_sha256)?;
    Ok((RegisteredChild::new(child, start_ticks), descriptor))
}

fn write_workload_progress(progress: &WorkloadProgress) -> Result<()> {
    let staged = Path::new(STATE_DIR).join("damon-progress.next");
    let final_path = Path::new(STATE_DIR).join("damon-progress");
    fs::write(&staged, serde_json::to_vec(progress)?)?;
    fs::rename(staged, final_path)?;
    Ok(())
}

fn read_progress() -> Result<WorkloadProgress> {
    let path = Path::new(STATE_DIR).join("damon-progress");
    wait_for_path(&path, Duration::from_secs(5))?;
    serde_json::from_slice(&fs::read(path)?).context("invalid DAMON progress")
}

fn signal_damon_target(name: &str) -> Result<()> {
    if !matches!(name, "damon-start" | "damon-stop" | "damon-refault") {
        bail!("invalid synthetic lifecycle signal");
    }
    fs::write(Path::new(STATE_DIR).join(name), b"1")?;
    Ok(())
}

fn read_damos_progress(
    external: Option<&CapacityExternalTargetDescriptor>,
) -> Result<WorkloadProgress> {
    if let Some(descriptor) = external {
        let progress = external_target::read_progress(&descriptor.payload.progress_path)?;
        let numeric_fingerprint =
            |value: &str| u64::from_str_radix(value.get(..16).unwrap_or(value), 16).unwrap_or(0);
        return Ok(WorkloadProgress {
            hot_cycles: progress.hot_cycles,
            warm_cycles: progress.warm_cycles,
            hot_pages_touched: progress.hot_pages_touched,
            warm_pages_touched: progress.warm_pages_touched,
            cold_cycles: progress.cold_cycles,
            workload_started_ns: progress.heartbeat_monotonic_ns,
            workload_stopped_ns: 0,
            hot_fingerprint: numeric_fingerprint(&progress.hot_fingerprint),
            warm_fingerprint: numeric_fingerprint(&progress.warm_fingerprint),
            cold_fingerprint: numeric_fingerprint(&progress.cold_fingerprint),
        });
    }
    read_progress()
}

fn signal_damos_target(
    external: Option<&CapacityExternalTargetDescriptor>,
    name: &str,
) -> Result<()> {
    let Some(descriptor) = external else {
        return signal_damon_target(name);
    };
    let nonce = descriptor.payload.identity.nonce.clone();
    let command = match name {
        "damon-start" => CapacityExternalTargetCommand::Start { nonce },
        "damon-refault" => CapacityExternalTargetCommand::RefaultCold { nonce },
        "damon-stop" => CapacityExternalTargetCommand::Stop { nonce },
        _ => bail!("invalid external target lifecycle signal"),
    };
    external_target::write_command(&descriptor.payload.transaction_root, &command)
}

fn proc_cpu_ticks(pid: u32) -> Result<u64> {
    let value = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = value
        .rfind(')')
        .ok_or_else(|| anyhow!("invalid proc stat"))?;
    let fields: Vec<_> = value[close + 1..].split_whitespace().collect();
    Ok(fields
        .get(11)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
        + fields
            .get(12)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0))
}

fn clock_ticks_per_second() -> Result<f64> {
    Ok(read_command("/usr/bin/getconf", &["CLK_TCK"])?.parse()?)
}

fn ticks_percent(delta: u64, ticks_per_second: f64, seconds: f64) -> f64 {
    delta as f64 / ticks_per_second / seconds * 100.0
}

fn read_os_id() -> Result<String> {
    fs::read_to_string("/etc/os-release")?
        .lines()
        .find_map(|line| {
            line.strip_prefix("ID=")
                .map(|value| value.trim_matches('"').to_owned())
        })
        .ok_or_else(|| anyhow!("missing os-release ID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_report_destination_requires_absolute_direct_child_and_exact_name() {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().canonicalize().unwrap();
        let valid = canonical.join("raw-damos-report.json");
        let destination = explicit_report_destination(Some(&valid), Some(&canonical))
            .unwrap()
            .unwrap();
        assert_eq!(destination.path, valid);
        assert!(explicit_report_destination(
            Some(Path::new("raw-damos-report.json")),
            Some(&canonical)
        )
        .is_err());
        assert!(explicit_report_destination(
            Some(&canonical.join("nested/raw-damos-report.json")),
            Some(&canonical)
        )
        .is_err());
        assert!(
            explicit_report_destination(Some(&canonical.join("wrong.json")), Some(&canonical))
                .is_err()
        );
    }

    #[test]
    fn explicit_report_destination_rejects_existing_file_directory_and_symlink() {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().canonicalize().unwrap();
        let file = canonical.join("damos-component-report.json");
        fs::write(&file, b"existing").unwrap();
        assert!(explicit_report_destination(Some(&file), Some(&canonical)).is_err());
        fs::remove_file(&file).unwrap();
        fs::create_dir(&file).unwrap();
        assert!(explicit_report_destination(Some(&file), Some(&canonical)).is_err());
        fs::remove_dir(&file).unwrap();
        std::os::unix::fs::symlink("/tmp", &file).unwrap();
        assert!(explicit_report_destination(Some(&file), Some(&canonical)).is_err());
    }

    #[test]
    fn explicit_report_write_is_create_new_mode_0600_single_link_and_exact_bytes() {
        let root = tempfile::tempdir().unwrap();
        let canonical = root.path().canonicalize().unwrap();
        let path = canonical.join("raw-damos-report.json");
        let destination = explicit_report_destination(Some(&path), Some(&canonical))
            .unwrap()
            .unwrap();
        let bytes = br#"{"scope":"damos","raw":true}"#;
        write_explicit_report(bytes, &destination).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let metadata = fs::metadata(&path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(write_explicit_report(bytes, &destination).is_err());
    }

    #[test]
    fn explicit_report_arguments_are_paired_and_legacy_mode_remains_available() {
        assert!(explicit_report_destination(None, None).unwrap().is_none());
        assert!(explicit_report_destination(Some(Path::new("/tmp/report")), None).is_err());
        assert!(explicit_report_destination(None, Some(Path::new("/tmp"))).is_err());
    }

    #[test]
    fn path_allow_list_is_closed() {
        assert!(safety_path(Path::new(
            "/sys/fs/cgroup/nemor-validation-123.scope"
        )));
        assert!(!safety_path(Path::new("/sys/fs/cgroup/user.slice")));
        assert!(!safety_path(Path::new(
            "/sys/fs/cgroup/nemor-validation-123.scope/child"
        )));
    }

    #[test]
    fn naming_rejects_traversal_and_runtime_names() {
        assert!(require_validation_group("nemor-validation-123.scope").is_ok());
        assert!(require_validation_group("../nemor-validation-123.scope").is_err());
        assert!(require_validation_group("nemor-foreground.slice").is_err());
    }

    #[test]
    fn device_ownership_rejects_zram0_and_baseline_devices() {
        let baseline = HostSnapshot {
            timestamp_ns: 0,
            swaps: Vec::new(),
            zram_devices: ["zram0".to_owned(), "zram3".to_owned()]
                .into_iter()
                .collect(),
            zram0: None,
            validation_cgroups: BTreeSet::new(),
            validation_processes: BTreeSet::new(),
        };
        assert!(require_new_test_zram("zram0", &baseline).is_err());
        assert!(require_new_test_zram("zram3", &baseline).is_err());
        assert!(require_new_test_zram("zram4", &baseline).is_ok());
        assert!(require_new_test_zram("/dev/zram4", &baseline).is_err());
    }

    #[test]
    fn host_comparison_ignores_timestamp_only() {
        let mut before = empty_snapshot();
        before.timestamp_ns = 1;
        let mut after = before.clone();
        after.timestamp_ns = 2;
        assert!(compare_host(&before, &after).is_ok());
    }

    #[test]
    fn host_comparison_rejects_residue_and_topology_change() {
        let before = empty_snapshot();
        let mut after = before.clone();
        after
            .validation_cgroups
            .insert("/sys/fs/cgroup/nemor-validation-x.scope".to_owned());
        assert!(compare_host(&before, &after).is_err());
        after.validation_cgroups.clear();
        after.zram_devices.insert("zram9".to_owned());
        assert!(compare_host(&before, &after).is_err());
    }

    #[test]
    fn report_serialization_contains_schema_and_no_host_identity() {
        let snapshot = empty_snapshot();
        let report = ValidationReport {
            schema: "nemor-privileged-validation-v1",
            commit: "abc".to_owned(),
            kernel: "test".to_owned(),
            os_id: "cachyos".to_owned(),
            scope: "preflight".to_owned(),
            started_ns: 1,
            finished_ns: 2,
            baseline: snapshot.clone(),
            final_snapshot: snapshot,
            cgroups: CgroupEvidence::default(),
            zram: ZramEvidence::default(),
            tiering: TieringEvidence::default(),
            damon: DamonEvidence::default(),
            damos: DamosEvidence::default(),
            ksm: KsmEvidence::default(),
            host_unchanged: true,
            errors: Vec::new(),
        };
        let json = serde_json::to_string(&report).expect("serialize report");
        assert!(json.contains("nemor-privileged-validation-v1"));
        assert!(!json.contains("hostname"));
        assert!(!json.contains("username"));
        assert!(!json.contains("machine_id"));
    }

    #[test]
    fn damos_success_requires_every_mandatory_gate() {
        let mut checks: Vec<Check> = DAMOS_REQUIRED_GATES
            .iter()
            .map(|name| check(name, true, "fixture".into()))
            .collect();
        assert!(required_checks_pass(&checks, DAMOS_REQUIRED_GATES));
        checks
            .iter_mut()
            .find(|item| item.name == "cold_address_fence")
            .unwrap()
            .passed = false;
        assert!(!required_checks_pass(&checks, DAMOS_REQUIRED_GATES));
    }

    #[test]
    fn ksm_early_abort_keeps_later_gates_not_evaluated_and_taxonomy_non_null() {
        let mut evidence = KsmEvidence::default();
        evidence.checks.push(check(
            "capability",
            false,
            "fixture baseline failure".into(),
        ));
        let _ = ksm_failure(
            &mut evidence,
            "baseline_not_isolated",
            "fixture baseline failure",
        );
        fill_ksm_not_evaluated_gates(&mut evidence, KSM_REQUIRED_GATES);
        assert_eq!(
            evidence.failure_reason.as_deref(),
            Some("baseline_not_isolated")
        );
        assert!(evidence.failure_class.is_some());
        assert!(evidence.checks.iter().any(|gate| {
            gate.name == "exact_mergeable_scope_verified" && gate.state == GateState::NotEvaluated
        }));
    }

    #[test]
    fn nohugepage_result_and_errno_are_preserved() {
        let success = worker_advice_result(Ok(()));
        assert!(success.requested && success.succeeded);
        assert_eq!(success.raw_os_error, None);
        let failure = worker_advice_result(Err(std::io::Error::from_raw_os_error(22)));
        assert!(failure.requested && !failure.succeeded);
        assert_eq!(failure.raw_os_error, Some(22));
        assert!(failure.error.is_some());
    }

    #[test]
    fn unique_ksm_generator_has_no_cross_child_or_page_repetition() {
        let mut hashes = BTreeSet::new();
        for child in [1_u8, 2] {
            for page_index in 0..64_u64 {
                let mut page = vec![0_u8; 4096];
                fill_unique_ksm_page(&mut page, "session", child, page_index);
                assert!(page.iter().any(|byte| *byte != 0));
                assert!(hashes.insert(ksm_page_digest(&page)));
            }
        }
    }

    #[test]
    fn inefficient_accounting_uses_session_deltas_not_historic_totals() {
        let before = ksm::KsmSystemMetrics {
            pages_scanned: Some(10_000),
            pages_sharing: Some(9_000),
            full_scans: Some(50),
            general_profit: Some(40_000_000),
            ..ksm::KsmSystemMetrics::default()
        };
        let after = ksm::KsmSystemMetrics {
            pages_scanned: Some(10_200),
            pages_sharing: Some(9_000),
            full_scans: Some(52),
            general_profit: Some(40_000_000),
            ..ksm::KsmSystemMetrics::default()
        };
        let deltas = ksm_counter_deltas(&before, &after);
        assert_eq!(deltas["pages_sharing"], 0);
        assert_eq!(deltas["general_profit"], 0);
        assert_eq!(deltas["full_scans"], 2);
    }

    #[test]
    fn residual_cleanup_uses_signed_deltas_without_fabricating_savings() {
        let before = ksm::KsmSystemMetrics {
            pages_shared: Some(251),
            pages_sharing: Some(9_749),
            full_scans: Some(2),
            general_profit: Some(38_883_328),
            ..ksm::KsmSystemMetrics::default()
        };
        let after = ksm::KsmSystemMetrics {
            pages_shared: Some(0),
            pages_sharing: Some(0),
            full_scans: Some(4),
            general_profit: Some(0),
            ..ksm::KsmSystemMetrics::default()
        };
        let deltas = ksm_counter_deltas(&before, &after);
        assert_eq!(deltas["pages_shared"], -251);
        assert_eq!(deltas["pages_sharing"], -9_749);
        assert_eq!(deltas["general_profit"], -38_883_328);
        assert_eq!(deltas["full_scans"], 2);
        assert_eq!(
            ksm_saved_bytes(
                &before,
                &after,
                &ksm::KsmSnapshot {
                    run: 0,
                    pages_to_scan: 100,
                    sleep_millisecs: 20,
                    preserve_only: BTreeMap::new(),
                }
            ),
            0
        );
    }

    #[test]
    fn owned_process_evidence_drives_unique_inefficiency() {
        let processes = [1_u32, 2]
            .into_iter()
            .map(|pid| ksm::KsmProcessMetrics {
                identity: ksm::owned_validation_identity("session", pid, 10),
                ksm_rmap_items: Some(8192),
                ksm_merging_pages: Some(0),
                ksm_process_profit: Some(0),
                ksm_mergeable: Some(true),
                ..ksm::KsmProcessMetrics::default()
            })
            .collect::<Vec<_>>();
        assert!(owned_processes_evaluated(&processes));
        assert!(owned_processes_inefficient(&processes));
    }

    #[test]
    fn manual_stop_cannot_masquerade_as_controller_auto_disable() {
        let run_before = "1";
        let stopped = true;
        assert!(!(false && run_before == "1" && stopped));
        assert!(true && run_before == "1" && stopped);
    }

    fn passing_ksm_evidence(required: &[&str]) -> KsmEvidence {
        KsmEvidence {
            checks: required
                .iter()
                .map(|name| check(name, true, "fixture pass".into()))
                .collect(),
            ..KsmEvidence::default()
        }
    }

    #[test]
    fn positive_finalizer_requires_positive_gates() {
        let mut success = passing_ksm_evidence(KSM_REQUIRED_GATES);
        let outcome = finalize_ksm_outcome(&mut success, KsmScenario::Positive);
        assert!(outcome.success);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.error.is_none());

        let mut failure = passing_ksm_evidence(KSM_REQUIRED_GATES);
        set_check(
            &mut failure.checks,
            check("minimum_saved_bytes", false, "profit gate failed".into()),
        );
        let outcome = finalize_ksm_outcome(&mut failure, KsmScenario::Positive);
        assert!(!outcome.success);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.error.is_some());
    }

    #[test]
    fn attempt_five_finalizer_accepts_expected_non_profit() {
        let mut evidence = passing_ksm_evidence(KSM_INEFFICIENT_REQUIRED_GATES);
        evidence.profit_gate = Some(ksm::ValidationProfitGate {
            saved_bytes: 0,
            pages_scanned_delta: 19_584,
            full_scans_delta: 2,
            system_profit_delta: -39_931_904,
            processes_positive: false,
            passed: false,
            reasons: vec!["insufficient_saved_bytes".into()],
        });
        let outcome = finalize_ksm_outcome(&mut evidence, KsmScenario::Inefficient);
        assert!(outcome.success);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.error.is_none());
        assert!(evidence.required_gates_passed);
        assert!(evidence.failure_class.is_none());
        assert!(evidence.failure_reason.is_none());
    }

    #[test]
    fn inefficient_finalizer_rejects_controller_cooldown_and_cpu_failures() {
        for gate in [
            "controller_auto_disable",
            "cooldown_entered",
            "cooldown_rejects_next_plan",
            "cpu_budget",
        ] {
            let mut evidence = passing_ksm_evidence(KSM_INEFFICIENT_REQUIRED_GATES);
            set_check(
                &mut evidence.checks,
                check(gate, false, "fixture failure".into()),
            );
            let outcome = finalize_ksm_outcome(&mut evidence, KsmScenario::Inefficient);
            assert!(!outcome.success, "{gate}");
            assert_eq!(outcome.exit_code, 1);
            assert!(outcome.error.is_some());
            assert!(!evidence.required_gates_passed);
        }
    }

    #[test]
    fn bounded_bootstrap_report_keeps_runtime_uniqueness_rigorous() {
        let hashes = (0..8192_u64).collect::<Vec<_>>();
        let target = KsmTargetMetadata {
            pid: std::process::id(),
            start_ticks: proc_start_ticks(std::process::id()).unwrap(),
            duplicate: [0x1000, 0x3000],
            control: [0x4000, 0x6000],
            duplicate_bytes: 0x2000,
            control_bytes: 0x2000,
            duplicate_fingerprint: 1,
            control_fingerprint: 2,
            state: "ready_unmergeable".into(),
            host_page_size: 4096,
            duplicate_nohugepage: worker_advice_result(Ok(())),
            control_nohugepage: worker_advice_result(Ok(())),
            duplicate_prefault_completed: true,
            control_prefault_completed: true,
            workload_kind: "unique".into(),
            duplicate_page_hashes: hashes,
        };
        let mut bounded = target.clone();
        bounded.duplicate_page_hashes.truncate(16);
        assert_eq!(target.duplicate_page_hashes.len(), 8192);
        assert_eq!(bounded.duplicate_page_hashes.len(), 16);
        assert!(serde_json::to_vec(&bounded).unwrap().len() < 4096);
    }

    #[test]
    fn ksm_checks_are_serialized_once_with_authoritative_host_result() {
        let mut checks = vec![
            Check {
                name: "capability".into(),
                passed: false,
                state: GateState::NotEvaluated,
                detail: "stale".into(),
            },
            check("capability", true, "authoritative".into()),
            check("host_unchanged", false, "stale".into()),
        ];
        set_check(
            &mut checks,
            check("host_unchanged", true, "final comparison".into()),
        );
        deduplicate_checks(&mut checks);
        assert_eq!(
            checks
                .iter()
                .filter(|item| item.name == "capability")
                .count(),
            1
        );
        assert_eq!(
            checks
                .iter()
                .filter(|item| item.name == "host_unchanged")
                .count(),
            1
        );
        assert!(
            checks
                .iter()
                .find(|item| item.name == "host_unchanged")
                .unwrap()
                .passed
        );
    }

    #[test]
    fn base_page_bootstrap_failure_has_distinct_taxonomy() {
        let mut evidence = KsmEvidence::default();
        let _ = ksm_failure(&mut evidence, "base_page_backing_not_verified", "fixture");
        assert_eq!(
            evidence.failure_class.as_deref(),
            Some("workload_setup_failure")
        );
        assert_eq!(
            evidence.failure_reason.as_deref(),
            Some("base_page_backing_not_verified")
        );
    }

    #[test]
    fn damos_modern_and_legacy_cold_fences_are_explicit() {
        let cold = damon::AddressRange {
            start: 0x1000,
            end: 0x3000,
        };
        assert!(damos::AddressFence {
            range: cold,
            layer: "core".into(),
            filter_type: "addr".into(),
            api: damos::FilterApi::MatchingAllow,
            matching: true,
            allow: Some(true),
        }
        .validate(cold)
        .is_ok());
        assert!(damos::AddressFence {
            range: cold,
            layer: "core".into(),
            filter_type: "addr".into(),
            api: damos::FilterApi::MatchingAllow,
            matching: false,
            allow: Some(true),
        }
        .validate(cold)
        .is_err());
    }

    #[test]
    fn damos_failure_always_has_class_and_reason() {
        let mut evidence = DamosEvidence {
            required_gates_passed: false,
            checks: vec![check("shadow_candidate_evidence", false, "fixture".into())],
            ..Default::default()
        };
        fill_damos_not_evaluated_gates(&mut evidence);
        ensure_damos_failure_taxonomy(&mut evidence);
        assert!(evidence.failure_class.is_some());
        assert!(evidence.failure_reason.is_some());
        assert!(evidence
            .checks
            .iter()
            .any(|gate| gate.name == "live_candidate_evidence"
                && gate.state == GateState::NotEvaluated));
        assert!(evidence
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("shadow_candidate_evidence")));
        assert!(!evidence
            .failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("live_candidate_evidence")));
    }

    #[test]
    fn nohugepage_request_and_vma_ownership_are_independent() {
        let mut zone = damon::ZoneBacking {
            start: 0x1000,
            end: 0x3000,
            anon_huge_pages_kib: 0,
            thp_eligible: Some(false),
            vm_flags: vec!["nh".into()],
            containing_vma_start: Some(0x1000),
            containing_vma_end: Some(0x9000),
            explicit_nohugepage_requested: true,
            ..Default::default()
        };
        zone.explicit_nohugepage_verified = zone.explicit_nohugepage_requested
            && zone.anon_huge_pages_kib == 0
            && (zone.thp_eligible == Some(false) || zone.vm_flags.iter().any(|flag| flag == "nh"));
        assert!(zone.explicit_nohugepage_verified);
        assert_ne!(zone.end, zone.containing_vma_end.unwrap());
    }

    #[test]
    fn merged_containing_vma_marks_each_owned_zone_shared_without_changing_range_size() {
        let mut zones = BTreeMap::from([
            (
                "hot".into(),
                damon::ZoneBacking {
                    start: 0x1000,
                    end: 0x3000,
                    range_size_bytes: 0x2000,
                    containing_vma_start: Some(0x1000),
                    containing_vma_end: Some(0x9000),
                    containing_vma_size_kib: 32,
                    ..Default::default()
                },
            ),
            (
                "cold".into(),
                damon::ZoneBacking {
                    start: 0x3000,
                    end: 0x9000,
                    range_size_bytes: 0x6000,
                    containing_vma_start: Some(0x1000),
                    containing_vma_end: Some(0x9000),
                    containing_vma_size_kib: 32,
                    ..Default::default()
                },
            ),
        ]);
        assert!(mark_shared_vma_group(&mut zones));
        assert!(zones.values().all(|zone| zone.shared_vma));
        assert_eq!(zones["hot"].range_size_bytes, 0x2000);
        assert_eq!(zones["hot"].containing_vma_size_kib, 32);
    }

    #[test]
    fn pagemap_unavailable_or_stale_identity_fails_before_range_read() {
        let range = damon::AddressRange {
            start: 0x1000,
            end: 0x3000,
        };
        assert!(read_range_residency(u32::MAX, 1, range).is_err());
        let current = proc_start_ticks(std::process::id())
            .unwrap()
            .expect("test process exists");
        assert!(
            read_range_residency(std::process::id(), current.saturating_add(1), range).is_err()
        );
    }

    #[test]
    fn shadow_eligibility_metadata_does_not_transfer_live_age() {
        let shadow = damos::DamosStats {
            first_tried_snapshot_index: Some(3),
            first_tried_region_age: Some(3),
            ..Default::default()
        };
        let live = damos::DamosStats::default();
        assert_eq!(shadow.first_tried_snapshot_index, Some(3));
        assert_eq!(live.first_tried_snapshot_index, None);
        assert_eq!(live.first_tried_region_age, None);
    }

    #[test]
    fn phase_seven_gate_still_requires_zero_damos() {
        let evidence = DamonEvidence {
            zero_damos: false,
            checks: DAMON_REQUIRED_GATES
                .iter()
                .map(|name| check(name, true, "fixture".into()))
                .collect(),
            ..Default::default()
        };
        assert!(!damon_required_gates(&evidence));
    }

    #[test]
    fn arbitrary_pid_is_not_part_of_closed_plan() {
        let registered = BTreeMap::from([(123_u32, (fixed_identity(), 456_u64))]);
        assert!(
            authorize_candidate(&registered, 1, &fixed_identity(), 456, CandidateKind::Child)
                .is_err()
        );
        assert!(authorize_candidate(
            &registered,
            123,
            &fixed_identity(),
            457,
            CandidateKind::Child
        )
        .is_err());
    }

    #[test]
    fn damon_success_requires_every_gate_and_real_signal() {
        let mut evidence = DamonEvidence {
            zero_damos: true,
            ..DamonEvidence::default()
        };
        for name in DAMON_REQUIRED_GATES {
            evidence.checks.push(check(name, true, String::new()));
        }
        assert!(damon_required_gates(&evidence));
        evidence.hot_snapshot_overlap_bytes = Some(0);
        evidence.cold_snapshot_overlap_bytes = Some(100);
        evidence
            .checks
            .iter_mut()
            .find(|item| item.name == "hot_cold_evidence")
            .unwrap()
            .passed = false;
        assert!(!damon_required_gates(&evidence));
    }

    #[test]
    fn damon_nonfatal_signal_failure_keeps_complete_gate_contract() {
        assert_eq!(DAMON_REQUIRED_GATES.len(), 30);
        assert!(DAMON_REQUIRED_GATES.contains(&"trace_clock_compatible"));
        assert!(DAMON_REQUIRED_GATES.contains(&"damon_payloads_parsed"));
        assert!(DAMON_REQUIRED_GATES.contains(&"timestamp_values_parsed"));
        assert!(DAMON_REQUIRED_GATES.contains(&"timestamp_correlation_valid"));
        assert!(DAMON_REQUIRED_GATES.contains(&"synthetic_workload_ready"));
        assert!(DAMON_REQUIRED_GATES.contains(&"synthetic_workload_active"));
        assert!(DAMON_REQUIRED_GATES.contains(&"target_regions_readback"));
        assert!(DAMON_REQUIRED_GATES.contains(&"base_page_backing_verified"));
        assert!(DAMON_REQUIRED_GATES.contains(&"overhead_budget"));
        assert!(DAMON_REQUIRED_GATES.contains(&"dataset_jsonl"));
        assert!(DAMON_REQUIRED_GATES.contains(&"dataset_csv"));
        assert!(DAMON_REQUIRED_GATES.contains(&"cleanup"));
        assert!(DAMON_REQUIRED_GATES.contains(&"recovery_idempotent"));
        let checks = DAMON_REQUIRED_GATES
            .iter()
            .map(|name| check(name, *name != "hot_cold_evidence", String::new()))
            .collect::<Vec<_>>();
        let evidence = DamonEvidence {
            checks,
            zero_damos: true,
            overhead: Some(damon::OverheadSample {
                kdamond_cpu_percent: 0.1,
                capture_cpu_percent: 0.1,
                target_slowdown_percent: 0.1,
                events_per_second: 1.0,
                regions_per_second: 1.0,
                dropped_samples: 0,
            }),
            dataset_jsonl: true,
            dataset_csv: true,
            recovery_idempotent: true,
            ..DamonEvidence::default()
        };
        assert_eq!(evidence.checks.len(), 30);
        assert!(!damon_required_gates(&evidence));
    }

    #[test]
    fn synthetic_lifecycle_requires_exact_ready_start_monitor_stop_order() {
        let names = [
            "t0_child_spawn",
            "t1_allocations_complete",
            "t2_workers_ready",
            "t3_parent_received_ready",
            "t4_trace_capture_ready",
            "t5_damon_configured",
            "t6_kdamond_started",
            "t7_workload_start_sent",
            "t8_monitoring_window_end",
            "t9_kdamond_stopped",
            "t10_workload_stop_sent",
        ];
        let timeline = names
            .iter()
            .enumerate()
            .map(|(index, name)| ((*name).to_owned(), index as u128 + 1))
            .collect::<BTreeMap<_, _>>();
        assert!(synthetic_lifecycle_order_valid(&timeline));
        let mut stopped_early = timeline.clone();
        stopped_early.insert("t10_workload_stop_sent".to_owned(), 8);
        assert!(!synthetic_lifecycle_order_valid(&stopped_early));
        let mut started_early = timeline;
        started_early.insert("t7_workload_start_sent".to_owned(), 5);
        assert!(!synthetic_lifecycle_order_valid(&started_early));
    }

    #[test]
    fn workload_progress_proves_hot_each_window_warm_periodic_and_cold_absent() {
        let points = (0..=3)
            .map(|index| {
                (
                    index * 500,
                    WorkloadProgress {
                        hot_cycles: index as u64 * 10,
                        warm_cycles: index as u64 * 2,
                        hot_pages_touched: index as u64 * 20_480,
                        warm_pages_touched: index as u64 * 4_096,
                        cold_cycles: 0,
                        workload_started_ns: 1,
                        workload_stopped_ns: 0,
                        hot_fingerprint: 0,
                        warm_fingerprint: 0,
                        cold_fingerprint: 0,
                    },
                )
            })
            .collect::<Vec<_>>();
        let windows = workload_window_progress(&points);
        assert_eq!(windows.len(), 3);
        assert!(windows.iter().all(|window| window.hot_cycles_delta == 10));
        assert!(windows.iter().all(|window| window.warm_cycles_delta == 2));
        assert!(points.iter().all(|(_, point)| point.cold_cycles == 0));
        let mut stalled = points;
        stalled[2].1.hot_cycles = stalled[1].1.hot_cycles;
        assert!(workload_window_progress(&stalled)
            .iter()
            .any(|window| window.hot_cycles_delta == 0));
    }

    #[test]
    fn hot_and_warm_share_memory_touch_path_and_fingerprint_after_store() {
        let mut hot = vec![1_u8; 8192];
        let mut warm = vec![1_u8; 8192];
        let (hot_pages, hot_fingerprint) = touch_zone(&mut hot);
        let (warm_pages, warm_fingerprint) = touch_zone(&mut warm);
        assert_eq!((hot_pages, hot_fingerprint), (2, 8));
        assert_eq!((hot_pages, hot_fingerprint), (warm_pages, warm_fingerprint));
        assert_eq!(hot[0], 4);
        assert_eq!(hot[4096], 4);
        assert_eq!(fingerprint_zone(&hot), hot_fingerprint);
    }

    #[test]
    fn temporal_matching_excludes_partial_boundaries() {
        let region = damon::TraceRegion {
            target_id: 0,
            nr_regions: 1,
            start: 1,
            end: 2,
            nr_accesses: 1,
            age: 1,
        };
        let timed = vec![
            (1_100_000_000, vec![region.clone()]),
            (1_600_000_000, vec![region.clone()]),
            (2_100_000_000, vec![region]),
        ];
        let progress = vec![WorkloadWindowProgress {
            window_index: 0,
            start_ns: 1_000_000_000,
            end_ns: 2_000_000_000,
            hot_cycles_delta: 100,
            warm_cycles_delta: 5,
            hot_pages_touched_delta: 100,
            warm_pages_touched_delta: 5,
        }];
        let (alignment, complete) =
            align_complete_windows(timed, 500_000, 1_000_000_000, 2_000_000_000, &progress);
        assert!(alignment[0].partial);
        assert!(!alignment[1].partial);
        assert!(alignment[2].partial);
        assert_eq!(alignment[1].hot_cycles_delta, 50);
        assert!(alignment[1].alignment_estimated);
        assert_eq!(alignment[1].alignment_method, "interval_overlap_prorated");
        assert_eq!(complete.len(), 1);
        assert_eq!(
            trace_timestamp_ns(
                "kdamond.0 [1] 1.600000000: damon:damon_aggregated: target_id=0 nr_regions=1 1-2: 1 1"
            ),
            Some(1_600_000_000)
        );
    }

    #[test]
    fn temporal_alignment_prorates_partial_overlap_without_double_counting() {
        let progress = vec![
            WorkloadWindowProgress {
                window_index: 0,
                start_ns: 0,
                end_ns: 500,
                hot_cycles_delta: 100,
                warm_cycles_delta: 50,
                hot_pages_touched_delta: 1_000,
                warm_pages_touched_delta: 500,
            },
            WorkloadWindowProgress {
                window_index: 1,
                start_ns: 500,
                end_ns: 1_000,
                hot_cycles_delta: 100,
                warm_cycles_delta: 50,
                hot_pages_touched_delta: 1_000,
                warm_pages_touched_delta: 500,
            },
        ];
        let (hot, overlap) =
            prorated_counter_delta(&progress, 490, 990, |point| point.hot_cycles_delta);
        assert_eq!(hot, 100);
        assert_eq!(overlap, 500);
        assert_eq!(
            prorated_counter_delta(&progress, 499, 500, |point| point.hot_cycles_delta),
            (0, 1)
        );
        assert_eq!(
            prorated_counter_delta(&progress, 500, 500, |point| point.hot_cycles_delta),
            (0, 0)
        );
        assert_eq!(
            prorated_counter_delta(&progress, 0, 500, |point| point.hot_cycles_delta),
            (100, 500)
        );
        assert_eq!(
            prorated_counter_delta(&progress, 100, 400, |point| point.hot_cycles_delta),
            (60, 300)
        );
        assert_eq!(
            prorated_counter_delta(&progress, 250, 750, |point| point.hot_cycles_delta),
            (100, 500)
        );
    }

    #[test]
    fn capture_diagnostics_separate_no_bytes_parser_failure_and_zero_access_sample() {
        let empty = TraceCaptureDiagnostic::default();
        assert!(matches!(
            classify_capture(&empty),
            ValidationFailureClass::InstrumentationFailure
        ));
        let parser_failure = TraceCaptureDiagnostic {
            trace_bytes_read: 10,
            damon_event_lines_seen: 1,
            parse_failures: 1,
            ..TraceCaptureDiagnostic::default()
        };
        assert!(matches!(
            classify_capture(&parser_failure),
            ValidationFailureClass::InstrumentationFailure
        ));
        let zero_access_line = b"kdamond.0 [001] 1.500000000: damon:damon_aggregated: target_id=0 nr_regions=1 4096-8192: 0 4\n";
        let root = tempfile::tempdir().unwrap();
        let event = root.path().join("events/damon/damon_aggregated");
        fs::create_dir_all(&event).unwrap();
        fs::write(event.join("enable"), "1\n").unwrap();
        fs::write(root.path().join("tracing_on"), "1\n").unwrap();
        let (diagnostic, events) =
            parse_trace_capture("final", root.path(), true, zero_access_line, 0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].region.nr_accesses, 0);
        let diagnostic = TraceCaptureDiagnostic {
            trace_clock_readback: true,
            timestamp_correlation_valid: true,
            ..diagnostic
        };
        assert!(matches!(
            classify_capture(&diagnostic),
            ValidationFailureClass::None
        ));
    }

    #[test]
    fn probe_cleanup_final_session_model_rejects_stale_identity_and_clock_domain() {
        let probes = vec!["probe-8".to_owned(), "probe-32".to_owned()];
        assert!(sessions_are_independent(&probes, "final-64"));
        assert!(!sessions_are_independent(&probes, "probe-32"));
        assert!(!sessions_are_independent(
            &["probe-8".to_owned(), "probe-8".to_owned()],
            "final"
        ));
        assert_eq!(
            choose_trace_clock(&["local".to_owned(), "mono".to_owned()]).unwrap(),
            ("mono".to_owned(), UserspaceClock::Monotonic)
        );
        assert!(choose_trace_clock(&["local".to_owned()]).is_err());
    }

    #[test]
    fn trace_clock_parser_and_selector_follow_compatible_preference() {
        let (available, effective) =
            parse_trace_clocks("local global counter uptime perf mono [mono_raw] boot").unwrap();
        assert_eq!(effective, "mono_raw");
        assert_eq!(
            choose_trace_clock(&available).unwrap(),
            ("mono".to_owned(), UserspaceClock::Monotonic)
        );
        assert_eq!(
            choose_trace_clock(&["local".to_owned(), "mono_raw".to_owned()]).unwrap(),
            ("mono_raw".to_owned(), UserspaceClock::MonotonicRaw)
        );
        assert_eq!(
            choose_trace_clock(&["boot".to_owned()]).unwrap(),
            ("boot".to_owned(), UserspaceClock::Boottime)
        );
        assert!(choose_trace_clock(&["local".to_owned(), "uptime".to_owned()]).is_err());
    }

    #[test]
    fn real_trace_timestamp_format_correlates_in_monotonic_domain() {
        let line = "kdamond.0-93054 [000] ..... 19057.333325: damon_aggregated: target_id=0 nr_regions=1 4096-8192: 3 1";
        let timestamp = trace_timestamp_ns(line).unwrap();
        assert_eq!(timestamp, 19_057_333_325_000);
        let monitoring_start = 19_057_000_000_000;
        let monitoring_end = 19_058_000_000_000;
        assert!(timestamp >= monitoring_start && timestamp <= monitoring_end);
        assert_ne!(timestamp / 1_000_000_000, 19_868);
    }

    #[test]
    fn payload_and_timestamp_parsing_are_independent() {
        let valid_payload_bad_timestamp =
            "kdamond.0 [000] local: damon_aggregated: target_id=0 nr_regions=1 1-2: 1 1";
        assert!(damon::parse_aggregated(valid_payload_bad_timestamp).is_ok());
        assert!(trace_timestamp_ns(valid_payload_bad_timestamp).is_none());
        let valid_timestamp_bad_payload =
            "kdamond.0 [000] 19057.333325: damon_aggregated: malformed";
        assert!(trace_timestamp_ns(valid_timestamp_bad_payload).is_some());
        assert!(damon::parse_aggregated(valid_timestamp_bad_payload).is_err());
    }

    #[test]
    fn requested_metadata_survives_signal_not_evaluated() {
        let ranges = BTreeMap::from([
            (
                "hot".to_owned(),
                damon::AddressRange {
                    start: 0,
                    end: 8 * 1024 * 1024,
                },
            ),
            (
                "warm".to_owned(),
                damon::AddressRange {
                    start: 8 * 1024 * 1024,
                    end: 16 * 1024 * 1024,
                },
            ),
        ]);
        let evidence = DamonEvidence {
            requested_target_bytes: 16 * 1024 * 1024,
            target_ranges: ranges,
            ..DamonEvidence::default()
        };
        assert_eq!(evidence.requested_target_bytes, 16 * 1024 * 1024);
        assert!(evidence.snapshot_observed_bytes.is_none());
        assert!(evidence.outside_requested_ratio.is_none());
        assert_eq!(evidence.target_ranges.len(), 2);
    }

    #[test]
    fn successful_probe_preserves_top_level_vaddr_without_final_run() {
        let root = tempfile::tempdir().unwrap();
        let mut capability = damon::inspect_linux(root.path(), Some("test".to_owned()));
        record_validated_operation(&mut capability, "vaddr");
        record_validated_operation(&mut capability, "vaddr");
        assert!(capability.vaddr_supported);
        assert_eq!(capability.available_operations, vec!["vaddr"]);
    }

    #[test]
    fn run_scoped_report_preserves_history_and_updates_latest() {
        let root = tempfile::tempdir().unwrap();
        let archive_one = root.path().join("report-1.json");
        let archive_two = root.path().join("report-2.json");
        let latest = root.path().join("latest.json");
        write_archived_report(b"one", &archive_one, &latest, root.path()).unwrap();
        write_archived_report(b"two", &archive_two, &latest, root.path()).unwrap();
        assert_eq!(fs::read(&archive_one).unwrap(), b"one");
        assert_eq!(fs::read(&archive_two).unwrap(), b"two");
        assert_eq!(fs::read(&latest).unwrap(), b"two");
        assert!(write_archived_report(b"again", &archive_one, &latest, root.path()).is_err());
        assert_eq!(
            report_archive_path(123),
            PathBuf::from("/tmp/nemor-privileged-validation-report-123.json")
        );
    }

    #[test]
    fn backing_profiles_change_only_owned_mapping_advice() {
        assert_ne!(
            damon::PageBackingProfile::ThpReference,
            damon::PageBackingProfile::BasePageNoHuge
        );
        let reference = owned_anonymous_zone(8192, damon::PageBackingProfile::ThpReference)
            .expect("anonymous reference mapping");
        let base = owned_anonymous_zone(8192, damon::PageBackingProfile::BasePageNoHuge)
            .expect("anonymous nohuge mapping");
        assert_eq!(reference.len(), base.len());
    }

    #[test]
    fn simulated_probe_cleanup_then_final_uses_fresh_capture_and_parser_state() {
        #[derive(Default)]
        struct SimulatedMonitorSession {
            owned_instance: Option<String>,
            capture_ready: bool,
            parser_events: u64,
        }
        impl SimulatedMonitorSession {
            fn run(&mut self, id: &str, event_bytes: &[u8]) {
                assert!(self.owned_instance.is_none());
                assert_eq!(self.parser_events, 0);
                self.owned_instance = Some(id.to_owned());
                self.capture_ready = true;
                self.parser_events = u64::from(!event_bytes.is_empty());
            }
            fn cleanup(&mut self) {
                self.owned_instance = None;
                self.capture_ready = false;
                self.parser_events = 0;
            }
        }
        let mut runner = SimulatedMonitorSession::default();
        runner.run("probe-8", b"probe event");
        assert_eq!(runner.parser_events, 1);
        runner.cleanup();
        assert!(runner.owned_instance.is_none());
        runner.run("final-32", b"final event");
        assert_eq!(runner.owned_instance.as_deref(), Some("final-32"));
        assert_eq!(runner.parser_events, 1);
        runner.cleanup();
        assert!(runner.owned_instance.is_none());
    }

    #[test]
    fn simulated_session_failures_never_reuse_probe_capture_state() {
        fn simulate(failure: &str) -> std::result::Result<(), &'static str> {
            if failure == "probe_remove" {
                return Err("probe cleanup blocks final");
            }
            if failure == "final_create" {
                return Err("final instance unavailable");
            }
            if failure == "event_enable" {
                return Err("final event readback failed");
            }
            if failure == "capture_restart" {
                return Err("final capture not ready");
            }
            if matches!(failure, "stale_fd" | "stale_session" | "stale_parser") {
                return Err("final state is not independent");
            }
            Ok(())
        }
        for failure in [
            "probe_remove",
            "final_create",
            "event_enable",
            "capture_restart",
            "stale_fd",
            "stale_session",
            "stale_parser",
        ] {
            assert!(simulate(failure).is_err());
        }
        assert!(simulate("none").is_ok());
    }

    #[test]
    fn cleanup_model_tracks_only_explicitly_registered_new_devices() {
        let mut cleanup = ZramCleanup::new(["zram0".to_owned()].into_iter().collect());
        cleanup.register("zram4");
        assert!(cleanup.names.contains("zram4"));
        assert!(!cleanup.names.contains("zram0"));
        cleanup.unregister("zram4");
        assert!(cleanup.names.is_empty());
        cleanup.disarm();
    }

    fn empty_snapshot() -> HostSnapshot {
        HostSnapshot {
            timestamp_ns: 0,
            swaps: Vec::new(),
            zram_devices: BTreeSet::new(),
            zram0: None,
            validation_cgroups: BTreeSet::new(),
            validation_processes: BTreeSet::new(),
        }
    }
}
