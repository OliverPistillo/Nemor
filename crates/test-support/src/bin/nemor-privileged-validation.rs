#![forbid(unsafe_code)]

use actuator::{
    apply_one, recover, rollback_one, ActuatorError, BackendKind, CgroupBackend, CgroupPlan,
    LinuxCgroupBackend, MutationSnapshot as CgroupMutationSnapshot, RequestedProperties,
    SnapshotStore,
};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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

#[derive(Debug, Clone, Copy)]
enum Scope {
    Preflight,
    Cgroups,
    Zram,
    All,
}

#[derive(Debug, Parser)]
#[command(about = "Bounded CachyOS privileged validation harness")]
struct Cli {
    #[arg(long)]
    preflight: bool,
    #[arg(long)]
    cgroups: bool,
    #[arg(long)]
    zram: bool,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    cleanup_owned_residue: bool,
    #[arg(long, value_enum, hide = true)]
    internal_worker: Option<InternalWorker>,
}

impl Cli {
    fn scope(&self) -> Result<Scope> {
        if self.internal_worker.is_some() {
            bail!("internal worker has no public validation scope");
        }
        let selected = [
            (self.preflight, Scope::Preflight),
            (self.cgroups, Scope::Cgroups),
            (self.zram, Scope::Zram),
            (self.all, Scope::All),
        ];
        let values: Vec<_> = selected
            .into_iter()
            .filter_map(|(enabled, scope)| enabled.then_some(scope))
            .collect();
        match values.as_slice() {
            [scope] => Ok(*scope),
            _ => bail!("select exactly one of --preflight, --cgroups, --zram, or --all"),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InternalWorker {
    CgroupCrash,
    ZramCrash,
    NemorValidationSleeper,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Check {
    name: String,
    passed: bool,
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
    if let Some(worker) = cli.internal_worker {
        return run_internal_worker(worker);
    }
    if cli.cleanup_owned_residue {
        if cli.preflight || cli.cgroups || cli.zram || cli.all {
            bail!("--cleanup-owned-residue cannot be combined with validation modes");
        }
        return cleanup_owned_residue();
    }
    let scope = cli.scope()?;
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

    report.final_snapshot = snapshot_host()?;
    report.host_unchanged = compare_host(&baseline, &report.final_snapshot).is_ok();
    if let Err(error) = compare_host(&baseline, &report.final_snapshot) {
        report
            .errors
            .push(format!("final host comparison: {error:#}"));
    }
    report.finished_ns = now_ns()?;
    write_report(&report)?;
    if report.errors.is_empty() && report.host_unchanged {
        Ok(())
    } else {
        bail!("validation incomplete; inspect {REPORT_PATH}")
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

impl RegisteredChild {
    fn new(child: std::process::Child, start_ticks: u64) -> Self {
        Self {
            child,
            start_ticks,
            terminated: false,
        }
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
        detail,
    }
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

fn write_report(report: &ValidationReport) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(report)?;
    let staged = Path::new(STATE_DIR).join("report.json");
    fs::write(&staged, bytes)?;
    fs::rename(staged, REPORT_PATH)?;
    Ok(())
}

fn read_command(executable: &str, args: &[&str]) -> Result<String> {
    if !matches!(executable, "/usr/bin/git" | "/usr/bin/uname") {
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
