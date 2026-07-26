use super::*;
use crate::inventory::{MmStat, WritableCapabilities};
use crate::transaction::MutationPhase;
use common::Config;
use policy_engine::PressureState;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use tempfile::tempdir;

fn device(name: &str, active: bool, ownership: Ownership) -> DeviceInventory {
    DeviceInventory {
        name: name.to_owned(),
        sysfs_path: format!("/sys/block/{name}").into(),
        device_path: format!("/dev/{name}").into(),
        active_swap: active,
        priority: Some(100),
        disksize: Some(1_000),
        initstate: Some(true),
        current_algorithm: Some("zstd".to_owned()),
        available_algorithms: vec!["lz4".to_owned(), "zstd".to_owned()],
        mm_stat: MmStat {
            orig_data_size: Some(600),
            compr_data_size: Some(200),
            mem_used_total: Some(250),
            mem_limit: Some(0),
            mem_used_max: Some(300),
            same_pages: Some(2),
            pages_compacted: Some(3),
            huge_pages: Some(4),
            huge_pages_since: Some(5),
        },
        io_stat: Some(vec![0, 0, 0, 0]),
        block_stat: Some(vec![0; 17]),
        bd_stat: Some(vec![0, 0, 0]),
        recompression_available: true,
        provider: Provider::Manual,
        ownership,
        writable: WritableCapabilities {
            hot_add: true,
            hot_remove: true,
            algorithm: true,
            disksize: true,
            reset: true,
        },
    }
}

fn config() -> Config {
    Config::from_toml(include_str!("../../../config/default.toml")).expect("config")
}

fn evidence(algorithm: &str, speed: f64, ratio: f64, cpu: u64) -> BenchmarkEvidence {
    BenchmarkEvidence {
        algorithm: algorithm.to_owned(),
        median_write_throughput_bytes_sec: Some(speed),
        median_effective_ratio: Some(ratio),
        median_cpu_time_ns: Some(cpu),
        cpu_overhead_percent: Some(0.5),
        datasets: 3,
        real: true,
    }
}

fn context<'a>(
    target: &'a DeviceInventory,
    benchmarks: &'a [BenchmarkEvidence],
    profile: ZramProfile,
) -> ProfileContext<'a> {
    ProfileContext {
        requested: profile,
        device: target,
        benchmarks,
        total_ram_bytes: 10_000,
        mem_available_bytes: 5_000,
        current_used_bytes: 250,
        pressure_state: PressureState::Normal,
        psi_full_avg10: Some(0.0),
        swap_in_per_second: Some(0.0),
        gaming: false,
        pressure_worsening: false,
        safety_events: 0,
        rollback_pending: false,
        provider_matches_snapshot: true,
    }
}

#[test]
fn parses_algorithm_current_available_and_rejects_malformed() {
    let (current, available) =
        inventory::parse_algorithms("lzo lz4 [zstd] 842").expect("algorithms");
    assert_eq!(current.as_deref(), Some("zstd"));
    assert_eq!(available, vec!["842", "lz4", "lzo", "zstd"]);
    assert!(inventory::parse_algorithms("[zstd] [lz4]").is_err());
    assert!(inventory::parse_algorithms("[../bad]").is_err());
}

#[test]
fn parses_complete_partial_and_overflowing_statistics() {
    let complete = inventory::parse_mm_stat("600 200 250 0 300 2 3 4 5").expect("complete mm_stat");
    assert_eq!(complete.huge_pages_since, Some(5));
    let partial = inventory::parse_mm_stat("1 2 3").expect("partial");
    assert_eq!(partial.mem_limit, None);
    assert!(inventory::parse_mm_stat("1 nope 3").is_err());
    assert!(inventory::parse_mm_stat("18446744073709551616").is_err());
}

#[test]
fn metrics_are_zero_safe_and_never_non_finite() {
    let metrics = device("zram0", true, Ownership::External).metrics();
    assert_eq!(metrics.logical_compression_ratio, Some(3.0));
    assert_eq!(metrics.effective_memory_ratio, Some(2.4));
    assert_eq!(metrics.allocator_efficiency, Some(0.8));
    assert_eq!(metrics.memory_saved_bytes, Some(350));
    let empty = CompressionMetrics::from_mm_stat(&MmStat::default(), None);
    assert_eq!(empty.logical_compression_ratio, None);
    let zero = CompressionMetrics::from_mm_stat(
        &MmStat {
            orig_data_size: Some(1),
            compr_data_size: Some(0),
            mem_used_total: Some(0),
            ..MmStat::default()
        },
        Some(0),
    );
    assert_eq!(zero.logical_compression_ratio, None);
    assert_eq!(zero.effective_memory_ratio, None);
    assert_eq!(zero.utilization_percent, None);
}

#[test]
fn rooted_inventory_handles_multiple_partial_and_no_devices() {
    let root = tempdir().expect("tempdir");
    fs::create_dir_all(root.path().join("sys/block")).expect("sys block");
    fs::create_dir_all(root.path().join("proc")).expect("proc");
    fs::write(
        root.path().join("proc/swaps"),
        "Filename Type Size Used Priority\n/dev/zram0 partition 100 10 100\n",
    )
    .expect("swaps");
    for name in ["zram0", "zram1"] {
        fs::create_dir_all(root.path().join(format!("sys/block/{name}"))).expect("device");
    }
    fs::write(root.path().join("sys/block/zram0/disksize"), "102400").expect("size");
    fs::write(
        root.path().join("sys/block/zram0/comp_algorithm"),
        "lz4 [zstd]",
    )
    .expect("algo");
    fs::write(root.path().join("sys/block/zram0/mm_stat"), "100 50 60").expect("stat");
    let inventory = inspect_linux(root.path()).expect("inventory");
    assert_eq!(inventory.devices.len(), 2);
    assert!(inventory.devices[0].active_swap);
    assert_eq!(inventory.devices[0].priority, Some(100));
    assert_eq!(inventory.devices[1].disksize, None);

    let empty = tempdir().expect("empty");
    let none = inspect_linux(empty.path()).expect("absent");
    assert!(!none.available);
}

#[test]
fn deterministic_datasets_and_benchmark_bounds_are_stable() {
    for kind in [
        DatasetKind::HighlyCompressible,
        DatasetKind::MediumCompressible,
        DatasetKind::DeterministicIncompressible,
    ] {
        assert_eq!(
            benchmark::deterministic_dataset(kind, 4096),
            benchmark::deterministic_dataset(kind, 4096)
        );
    }
    assert!(BenchmarkPlan::new(vec!["zstd".to_owned()], 0, 1024, true).is_err());
    let plan = BenchmarkPlan::new(vec!["zstd".to_owned()], 1024, 2048, true).expect("plan");
    assert!(plan.dry_run);
    assert_eq!(plan.measured_rounds, 5);
}

#[test]
fn aggregation_excludes_simulated_invalid_and_single_round_results() {
    let result = BenchmarkResult {
        algorithm: "zstd".to_owned(),
        dataset: DatasetKind::MediumCompressible,
        input_bytes: 100,
        compressed_bytes: 50,
        memory_used_bytes: 60,
        cpu_time_ns: 10,
        wall_time_ns: 20,
        write_throughput_bytes_sec: Some(5.0),
        read_throughput_bytes_sec: None,
        logical_ratio: Some(2.0),
        effective_ratio: Some(1.6),
        real_isolated_device: true,
        rounds: 5,
        error: None,
    };
    assert_eq!(benchmark::aggregate(std::slice::from_ref(&result)).len(), 1);
    let mut simulated = result;
    simulated.real_isolated_device = false;
    assert!(benchmark::aggregate(&[simulated]).is_empty());
}

#[test]
fn safe_profile_preserves_current_without_benchmark() {
    let target = device("zram0", true, Ownership::External);
    let plan = plan_profile(
        &context(&target, &[], ZramProfile::Safe),
        &config().compression,
        "observe",
    );
    assert_eq!(plan.selected_algorithm.as_deref(), Some("zstd"));
    assert!(plan.dry_run);
    assert!(plan.blocked_reasons.contains(&"observe_mode".to_owned()));
    assert!(plan
        .blocked_reasons
        .contains(&"ownership_not_explicit".to_owned()));
}

#[test]
fn measured_gaming_and_capacity_winners_are_not_name_preferences() {
    let target = device("zram0", false, Ownership::NemorOwned);
    let benchmarks = vec![
        evidence("zstd", 100.0, 3.0, 30),
        evidence("lz4", 200.0, 2.0, 10),
    ];
    let mut cfg = config().compression;
    cfg.allow_runtime_reconfigure = true;
    cfg.dry_run = false;
    let gaming = plan_profile(
        &context(&target, &benchmarks, ZramProfile::Gaming),
        &cfg,
        "apply",
    );
    assert_eq!(gaming.selected_algorithm.as_deref(), Some("lz4"));
    let capacity = plan_profile(
        &context(&target, &benchmarks, ZramProfile::Capacity),
        &cfg,
        "apply",
    );
    assert_eq!(capacity.selected_algorithm.as_deref(), Some("zstd"));
}

#[test]
fn insufficient_gain_unavailable_preference_and_ties_are_deterministic() {
    let mut target = device("zram0", false, Ownership::NemorOwned);
    target.available_algorithms = vec!["lzo".to_owned(), "zstd".to_owned()];
    let benchmarks = vec![
        evidence("zstd", 100.0, 2.0, 10),
        evidence("lzo", 100.0, 2.0, 10),
    ];
    let mut cfg = config().compression;
    cfg.preferred_capacity = "unavailable".to_owned();
    cfg.min_capacity_gain_percent = 50.0;
    assert_eq!(
        plan_profile(
            &context(&target, &benchmarks, ZramProfile::Capacity),
            &cfg,
            "observe"
        )
        .selected_algorithm
        .as_deref(),
        Some("zstd")
    );
}

#[test]
fn profile_rejects_cpu_over_budget_and_unavailable_algorithm() {
    let target = device("zram0", false, Ownership::NemorOwned);
    let mut expensive = evidence("lz4", 1_000.0, 4.0, 10);
    expensive.cpu_overhead_percent = Some(9.0);
    let benchmarks = vec![expensive, evidence("unavailable", 2_000.0, 8.0, 1)];
    let plan = plan_profile(
        &context(&target, &benchmarks, ZramProfile::Capacity),
        &config().compression,
        "apply",
    );
    assert_eq!(plan.selected_algorithm.as_deref(), Some("zstd"));
    assert!(plan.benchmark_evidence.is_empty());
}

#[test]
fn planner_guards_pressure_gaming_headroom_provider_and_rollback() {
    let target = device("zram0", true, Ownership::NemorOwned);
    let benchmarks = vec![evidence("lz4", 200.0, 2.0, 10)];
    let mut ctx = context(&target, &benchmarks, ZramProfile::Gaming);
    ctx.pressure_state = PressureState::Emergency;
    ctx.gaming = true;
    ctx.mem_available_bytes = 1;
    ctx.rollback_pending = true;
    ctx.provider_matches_snapshot = false;
    let plan = plan_profile(&ctx, &config().compression, "observe");
    for reason in [
        "insufficient_headroom",
        "pressure_state_blocks_reconfiguration",
        "rollback_pending",
        "provider_mismatch",
    ] {
        assert!(plan.blocked_reasons.contains(&reason.to_owned()));
    }
}

#[derive(Clone)]
struct FakeBackend {
    devices: BTreeMap<String, DeviceInventory>,
    owned: BTreeSet<String>,
    operations: Vec<String>,
    capacities: Vec<u64>,
    fail_at: Option<usize>,
    failed: bool,
}

impl FakeBackend {
    fn new() -> Self {
        let original = device("zram0", true, Ownership::NemorOwned);
        Self {
            devices: [(original.name.clone(), original)].into_iter().collect(),
            owned: ["zram0".to_owned()].into_iter().collect(),
            operations: Vec::new(),
            capacities: vec![1_000],
            fail_at: None,
            failed: false,
        }
    }

    fn operation(&mut self, name: &str) -> Result<(), ZramError> {
        self.operations.push(name.to_owned());
        if !self.failed && self.fail_at == Some(self.operations.len()) {
            self.failed = true;
            return Err(ZramError::Backend {
                operation: "fake",
                message: name.to_owned(),
            });
        }
        Ok(())
    }

    fn record_capacity(&mut self) {
        let capacity = self
            .devices
            .values()
            .filter(|device| device.active_swap)
            .map(|device| device.disksize.unwrap_or(0))
            .sum();
        self.capacities.push(capacity);
    }
}

impl ZramBackend for FakeBackend {
    fn inspect(&self) -> Result<Inventory, ZramError> {
        Ok(Inventory {
            available: true,
            devices: self.devices.values().cloned().collect(),
            unavailable: Vec::new(),
        })
    }

    fn create_isolated_managed_device(&mut self) -> Result<DeviceInventory, ZramError> {
        self.operation("create")?;
        let mut replacement = device("zram1", false, Ownership::NemorOwned);
        replacement.initstate = Some(false);
        replacement.disksize = Some(0);
        replacement.current_algorithm = None;
        self.owned.insert(replacement.name.clone());
        self.devices
            .insert(replacement.name.clone(), replacement.clone());
        self.record_capacity();
        Ok(replacement)
    }

    fn configure_uninitialized(&mut self, name: &str, algorithm: &str) -> Result<(), ZramError> {
        self.operation("algorithm")?;
        let device = self
            .devices
            .get_mut(name)
            .ok_or_else(|| ZramError::Verification("missing fake device".to_owned()))?;
        if device.initstate == Some(true) {
            return Err(ZramError::Blocked("initialized".to_owned()));
        }
        device.current_algorithm = Some(algorithm.to_owned());
        Ok(())
    }

    fn initialize(&mut self, name: &str, disksize: u64) -> Result<(), ZramError> {
        self.operation("initialize")?;
        let device = self.devices.get_mut(name).expect("fake device");
        device.disksize = Some(disksize);
        device.initstate = Some(true);
        Ok(())
    }

    fn activate(&mut self, name: &str, _priority: i32) -> Result<(), ZramError> {
        self.operation("activate")?;
        self.devices.get_mut(name).expect("fake device").active_swap = true;
        self.record_capacity();
        Ok(())
    }

    fn deactivate(&mut self, name: &str) -> Result<(), ZramError> {
        self.operation("deactivate")?;
        self.devices.get_mut(name).expect("fake device").active_swap = false;
        self.record_capacity();
        Ok(())
    }

    fn verify(&self, name: &str) -> Result<DeviceInventory, ZramError> {
        self.devices
            .get(name)
            .cloned()
            .ok_or_else(|| ZramError::Verification("missing fake device".to_owned()))
    }

    fn reset_managed_device(&mut self, name: &str) -> Result<(), ZramError> {
        self.operation("reset")?;
        if self
            .devices
            .get(name)
            .is_some_and(|device| device.active_swap)
        {
            return Err(ZramError::Blocked("active reset".to_owned()));
        }
        Ok(())
    }

    fn remove_managed_device(&mut self, name: &str) -> Result<(), ZramError> {
        self.operation("remove")?;
        if !self.owned.contains(name) {
            return Err(ZramError::Blocked("external".to_owned()));
        }
        self.devices.remove(name);
        self.owned.remove(name);
        self.record_capacity();
        Ok(())
    }

    fn effective_valid_swap_capacity(&self) -> Result<u64, ZramError> {
        Ok(self
            .devices
            .values()
            .filter(|device| device.active_swap)
            .map(|device| device.disksize.unwrap_or(0))
            .sum())
    }

    fn is_owned(&self, name: &str) -> bool {
        self.owned.contains(name)
    }
}

fn mutation_plan(original: &DeviceInventory) -> ZramProfilePlan {
    ZramProfilePlan {
        profile: ZramProfile::Gaming,
        target_device: original.name.clone(),
        current_algorithm: original.current_algorithm.clone(),
        selected_algorithm: Some("lz4".to_owned()),
        current_disksize: original.disksize,
        proposed_disksize: Some(1_000),
        current_priority: original.priority,
        proposed_priority: Some(101),
        benchmark_evidence: vec![evidence("lz4", 200.0, 2.0, 10)],
        reason: "fixture".to_owned(),
        confidence: 0.9,
        requires_reinitialization: true,
        requires_swap_migration: true,
        allowed: true,
        blocked_reasons: Vec::new(),
        dry_run: false,
        rule_version: PROFILE_RULE_VERSION.to_owned(),
    }
}

fn snapshot(backend: &FakeBackend) -> MutationSnapshot {
    let original = backend.verify("zram0").expect("original");
    MutationSnapshot {
        session_id: 1,
        timestamp_ns: 1,
        provider: original.provider,
        requested_plan: mutation_plan(&original),
        original,
        replacement_name: None,
        phase: MutationPhase::Snapshot,
        rollback_pending: false,
        last_error: None,
    }
}

#[test]
fn observe_transaction_has_zero_mutating_calls() {
    let mut backend = FakeBackend::new();
    let mut snapshot = snapshot(&backend);
    snapshot.requested_plan.dry_run = true;
    let outcome = apply_plan(&mut backend, &mut snapshot).expect("dry run");
    assert!(!outcome.applied);
    assert!(backend.operations.is_empty());
}

#[test]
fn replacement_transaction_never_loses_swap_and_rollback_is_idempotent() {
    let mut backend = FakeBackend::new();
    let mut snapshot = snapshot(&backend);
    let outcome = apply_plan(&mut backend, &mut snapshot).expect("apply");
    assert!(outcome.verified);
    assert!(backend.capacities.iter().all(|capacity| *capacity > 0));
    rollback(&mut backend, &mut snapshot).expect("rollback");
    rollback(&mut backend, &mut snapshot).expect("second rollback");
    assert!(backend.verify("zram0").expect("old").active_swap);
    assert!(!backend.devices.contains_key("zram1"));
    assert!(backend.capacities.iter().all(|capacity| *capacity > 0));
}

#[test]
fn every_transaction_failure_rolls_back_without_swap_loss() {
    for failure in 1..=5 {
        let mut backend = FakeBackend::new();
        backend.fail_at = Some(failure);
        let mut snapshot = snapshot(&backend);
        assert!(apply_plan(&mut backend, &mut snapshot).is_err());
        assert!(backend.capacities.iter().all(|capacity| *capacity > 0));
        assert!(backend.verify("zram0").expect("old").active_swap);
    }
}

#[test]
fn recovery_is_safe_and_idempotent_after_each_persistent_phase() {
    for phase in [
        MutationPhase::Snapshot,
        MutationPhase::ReplacementCreated,
        MutationPhase::AlgorithmConfigured,
        MutationPhase::Initialized,
        MutationPhase::Activated,
        MutationPhase::OriginalDeactivated,
    ] {
        let mut backend = FakeBackend::new();
        let mut snapshot = snapshot(&backend);
        snapshot.phase = phase;
        snapshot.rollback_pending = true;
        if phase >= MutationPhase::ReplacementCreated {
            backend
                .create_isolated_managed_device()
                .expect("replacement");
            snapshot.replacement_name = Some("zram1".to_owned());
        }
        recover_pending(&mut backend, &mut snapshot).expect("recover");
        recover_pending(&mut backend, &mut snapshot).expect("second recover");
        assert!(backend.verify("zram0").expect("old").active_swap);
        assert!(backend.capacities.iter().all(|capacity| *capacity > 0));
    }
}

#[test]
fn linux_backend_inspects_real_host_read_only() {
    if cfg!(target_os = "linux") {
        let inventory = LinuxZramBackend::default()
            .inspect()
            .expect("real inventory");
        assert_eq!(inventory.available, !inventory.devices.is_empty());
        assert!(inventory
            .devices
            .iter()
            .all(|item| item.ownership != Ownership::NemorOwned));
        for device in &inventory.devices {
            assert!(device.name.starts_with("zram"));
            assert!(device
                .current_algorithm
                .as_ref()
                .is_none_or(|algorithm| device.available_algorithms.contains(algorithm)));
        }
    }
}
