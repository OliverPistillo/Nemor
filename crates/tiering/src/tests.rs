use super::*;
use crate::boot_validation::*;
use common::Config;
use policy_engine::PressureState;
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

const DEFAULT: &str = include_str!("../../../config/default.toml");

fn config() -> common::TieringConfig {
    Config::from_toml(DEFAULT).expect("config").tiering
}

fn write(root: &Path, path: &str, value: &str) {
    let path = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, value).expect("write");
}

fn inventory_fixture(enabled: &str) -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    for (name, value) in [
        ("enabled", enabled),
        ("compressor", "zstd"),
        ("zpool", "zsmalloc"),
        ("max_pool_percent", "20"),
        ("accept_threshold_percent", "90"),
        ("shrinker_enabled", "N"),
    ] {
        write(root, &format!("/sys/module/zswap/parameters/{name}"), value);
    }
    write(root, "/proc/cmdline", "quiet zswap.enabled=0");
    write(root, "/usr/lib/systemd/zram-generator.conf", "[zram0]\n");
    write(
        root,
        "/usr/lib/udev/rules.d/30-zram.rules",
        "/sys/module/zswap/parameters/enabled",
    );
    write(root, "/etc/kernel/cmdline", "quiet");
    directory
}

#[test]
fn zswap_supported_and_missing_are_typed() {
    let fixture = inventory_fixture("N");
    let found = inspect_linux(fixture.path(), true).expect("inspect");
    assert!(found.supported);
    assert_eq!(found.parameters.enabled, Some(false));
    assert_eq!(found.parameters.compressor.as_deref(), Some("zstd"));
    let missing = tempfile::tempdir().expect("tempdir");
    let found = inspect_linux(missing.path(), true).expect("missing inspect");
    assert!(!found.supported);
    assert!(found.parameters.enabled.is_none());
}

#[test]
fn optional_parameters_and_dynamic_debugfs_are_safe() {
    let fixture = inventory_fixture("Y");
    write(
        fixture.path(),
        "/sys/kernel/debug/zswap/pool_total_size",
        "4096",
    );
    write(fixture.path(), "/sys/kernel/debug/zswap/new_counter", "bad");
    let found = inspect_linux(fixture.path(), true).expect("inspect");
    assert!(found.debugfs_available);
    assert_eq!(found.debug_counters.len(), 2);
    assert_eq!(found.debug_counters[0].name, "new_counter");
    assert_eq!(found.debug_counters[0].value, None);
    assert!(found.parameters.same_filled_pages_enabled.is_none());
}

#[test]
fn provider_conflict_and_bootloader_are_detected() {
    let fixture = inventory_fixture("N");
    let found = inspect_linux(fixture.path(), true).expect("inspect");
    assert!(found.provider.conflict);
    assert_eq!(
        found.provider.bootloader.as_deref(),
        Some("kernel-install/uki")
    );
    assert!(found.provider.cachyos_zswap_disable_rule);
}

#[test]
fn block_stat_uses_fixed_512_byte_sectors_and_detects_reset() {
    let before = parse_block_stat("1 0 10 0 2 0 20 3 0 4 0").expect("before");
    let after = parse_block_stat("2 0 11 0 5 0 28 9 0 12 0").expect("after");
    let delta = after.delta(before, 2_000_000_000).expect("delta");
    assert_eq!(delta.write_sectors, 8);
    assert_eq!(delta.write_bytes, 4096);
    assert_eq!(delta.writes_completed, 3);
    assert_eq!(delta.write_iops, 1.5);
    assert!(before.delta(after, 1).is_none());
    assert!(parse_block_stat("1 2 3").is_err());
}

#[test]
fn rolling_and_daily_budgets_block_without_disabling_swap() {
    let budget = WriteBudget {
        max_mib_per_second: 1,
        daily_budget_gib: 1,
    };
    let now = 100_000_000_000;
    let decision = budget.evaluate(
        &[WriteSample {
            timestamp_ns: now,
            bytes: 2 * 1_048_576,
            attributable: true,
        }],
        now,
    );
    assert!(!decision.allowed);
    assert!(decision
        .reasons
        .contains(&"instantaneous_write_budget_exceeded".to_owned()));
}

#[test]
fn tbw_never_invents_rating_and_labels_noise() {
    let no_rating =
        estimate_tbw(1_000_000_000, 86_400.0, None, "block_delta", false).expect("estimate");
    assert_eq!(no_rating.decimal_tb_per_year, 0.365);
    assert!(no_rating.endurance_percent_per_year.is_none());
    assert_eq!(no_rating.confidence, "host_wide_noisy");
    let rated =
        estimate_tbw(1_000_000_000, 86_400.0, Some(600.0), "benchmark", true).expect("rated");
    assert!(rated.endurance_percent_per_year.is_some());
}

fn topology(class: StorageClass) -> StorageTopology {
    let profile = match class {
        StorageClass::Nvme => StorageProfile::NvmeSsd,
        StorageClass::SolidStateNonNvme => StorageProfile::SataSsd,
        StorageClass::Rotational => StorageProfile::Rotational,
        StorageClass::Unknown => StorageProfile::Ambiguous,
    };
    StorageTopology {
        mount_source: "/dev/test".to_owned(),
        filesystem: "ext4".to_owned(),
        chain: vec!["test".to_owned()],
        physical: Some(BlockDevice {
            name: "test".to_owned(),
            class,
            rotational: Some(false),
            logical_block_size: Some(512),
            physical_block_size: Some(4096),
            discard_max_bytes: Some(1),
            model: None,
            transport: Some(
                match class {
                    StorageClass::Nvme => "nvme",
                    StorageClass::SolidStateNonNvme => "sata",
                    StorageClass::Rotational | StorageClass::Unknown => "unknown",
                }
                .to_owned(),
            ),
            serial: Some("serial".to_owned()),
            wwn: Some("wwn".to_owned()),
            capacity_bytes: Some(1_000_000),
        }),
        ambiguous: false,
        profile_version: STORAGE_PROFILE_VERSION.to_owned(),
        profile: Some(profile),
        device_identity: Some("test:serial:wwn:1000000".to_owned()),
        filesystem_identity: Some("ext4:/dev/test".to_owned()),
    }
}

fn swap_context(
    path: &Path,
    filesystem: FilesystemKind,
    class: StorageClass,
) -> SwapfileContext<'_> {
    SwapfileContext {
        path,
        parent_canonical: path.parent().expect("parent"),
        mountpoint: path.parent().expect("parent"),
        filesystem,
        topology: topology(class),
        total_ram_bytes: 16 * 1_073_741_824,
        zram_size_bytes: 16 * 1_073_741_824,
        free_bytes: 500 * 1_073_741_824,
        filesystem_size_bytes: 1_000 * 1_073_741_824,
        capacity_target_bytes: 16 * 1_073_741_824,
        btrfs_nocow: true,
        btrfs_preallocated: true,
        has_holes: false,
        active_external: false,
        ownership: SwapfileOwnership::NemorOwned,
        gaming: false,
        severe_pressure: false,
    }
}

#[test]
fn swapfile_path_ownership_and_filesystems_fail_closed() {
    let path = Path::new("/var/lib/nemor/swap/nemor-tiering.swap");
    assert!(validate_candidate_path(path, path.parent().expect("parent")).is_ok());
    assert!(validate_candidate_path(
        Path::new("/var/lib/nemor/../external.swap"),
        Path::new("/var/lib")
    )
    .is_err());
    let mut cfg = config();
    cfg.allow_swapfile_create = true;
    let ext4 = plan_swapfile(
        &swap_context(path, FilesystemKind::Ext4, StorageClass::Nvme),
        &cfg,
    );
    assert!(ext4.allowed);
    let unsupported = plan_swapfile(
        &swap_context(path, FilesystemKind::Unsupported, StorageClass::Nvme),
        &cfg,
    );
    assert!(!unsupported.allowed);
}

#[test]
fn btrfs_requires_nocow_preallocation_and_no_holes() {
    let path = Path::new("/var/lib/nemor/swap/nemor-tiering.swap");
    let mut cfg = config();
    cfg.allow_swapfile_create = true;
    let mut context = swap_context(path, FilesystemKind::Btrfs, StorageClass::Nvme);
    context.btrfs_nocow = false;
    context.has_holes = true;
    let plan = plan_swapfile(&context, &cfg);
    assert!(!plan.allowed);
    assert!(plan
        .blocked_reasons
        .iter()
        .any(|reason| reason.contains("nocow")));
}

#[test]
fn swapfile_requires_nvme_space_and_non_external_ownership() {
    let path = Path::new("/var/lib/nemor/swap/nemor-tiering.swap");
    let mut cfg = config();
    cfg.allow_swapfile_create = true;
    let mut context = swap_context(path, FilesystemKind::Ext4, StorageClass::SolidStateNonNvme);
    context.free_bytes = 1;
    context.ownership = SwapfileOwnership::External;
    let plan = plan_swapfile(&context, &cfg);
    assert!(!plan.allowed);
    assert!(!plan
        .blocked_reasons
        .contains(&"storage_profile_not_authorized".to_owned()));
    assert!(plan
        .blocked_reasons
        .contains(&"insufficient_disk_headroom".to_owned()));
}

fn budget(allowed: bool) -> BudgetDecision {
    BudgetDecision {
        allowed,
        instantaneous_mib_per_second: 0.0,
        rolling_minute_mib_per_second: 0.0,
        rolling_hour_gib: 0.0,
        daily_gib: 0.0,
        annual_tb: 0.0,
        reasons: Vec::new(),
    }
}

fn benchmark(backend: BackendKind) -> BenchmarkEvidence {
    BenchmarkEvidence {
        backend,
        real: true,
        cpu_time_ns: 1,
        wall_time_ns: 2,
        compression_ratio: Some(2.0),
        swap_latency_ns: Some(3),
        backing_write_bytes: Some(4),
        oom: false,
    }
}

#[test]
fn selector_defaults_to_zram_for_missing_or_unsafe_evidence() {
    for (gaming, pressure, class, allowed) in [
        (false, PressureState::Normal, StorageClass::Nvme, true),
        (true, PressureState::Normal, StorageClass::Nvme, true),
        (false, PressureState::Critical, StorageClass::Nvme, true),
        (false, PressureState::Normal, StorageClass::Rotational, true),
        (false, PressureState::Normal, StorageClass::Nvme, false),
    ] {
        let storage = topology(class);
        let decision = recommend_backend(&RecommendationInput {
            current: BackendKind::Zram,
            gaming,
            pressure,
            storage: &storage,
            zram_benchmark: None,
            zswap_benchmark: None,
            profile_evidence: None,
            same_host_zram_baseline: None,
            same_host_profile_evidence: None,
            budget: &budget(allowed),
            safety_events: 0,
            source_state: "clean",
            environment_identity: "same-host",
        });
        assert_eq!(decision.selected, BackendKind::Zram);
    }
}

#[test]
fn selector_chooses_only_matching_profile_evidence_deterministically() {
    let storage = topology(StorageClass::Nvme);
    let zram = benchmark(BackendKind::Zram);
    let zswap = benchmark(BackendKind::ZswapStorageBacked);
    let profile = ProfileBenchmarkEvidence {
        contract_version: TIERING_RULE_VERSION.to_owned(),
        profile: StorageProfile::NvmeSsd,
        device_identity: "test:serial:wwn:1000000".to_owned(),
        filesystem_identity: "ext4:/dev/test".to_owned(),
        source_state: "clean".to_owned(),
        environment_identity: "same-host".to_owned(),
        real: true,
        cleanup_passed: true,
        restore_passed: true,
        safety_failure: false,
        compression_ratio: Some(2.0),
        swap_latency_ns: Some(3),
        backing_write_bytes: Some(4),
        oom: false,
    };
    let (same_host_baseline, same_host_profile) = same_host_evidence(StorageProfile::NvmeSsd);
    let input = RecommendationInput {
        current: BackendKind::Zram,
        gaming: false,
        pressure: PressureState::Watch,
        storage: &storage,
        zram_benchmark: Some(&zram),
        zswap_benchmark: Some(&zswap),
        profile_evidence: Some(&profile),
        same_host_zram_baseline: Some(&same_host_baseline),
        same_host_profile_evidence: Some(&same_host_profile),
        budget: &budget(true),
        safety_events: 0,
        source_state: "clean",
        environment_identity: "same-host",
    };
    assert_eq!(
        recommend_backend(&input),
        recommend_backend(&input),
        "tie and evidence handling must be deterministic"
    );
    assert_eq!(
        recommend_backend(&input).selected,
        BackendKind::ZswapStorageBacked
    );
}

#[test]
fn pool_shrinker_is_preserved_off_without_all_guards() {
    let fixture = inventory_fixture("N");
    let inventory = inspect_linux(fixture.path(), true).expect("inventory");
    let path = Path::new("/var/lib/nemor/swap/nemor-tiering.swap");
    let mut cfg = config();
    cfg.allow_swapfile_create = true;
    let swap = plan_swapfile(
        &swap_context(path, FilesystemKind::Ext4, StorageClass::Nvme),
        &cfg,
    );
    let plan = plan_pool(
        &PoolContext {
            intent: PoolIntent::Capacity,
            inventory: &inventory,
            swapfile: &swap,
            benchmark: Some(&benchmark(BackendKind::ZswapNvme)),
            budget: &budget(true),
            pressure: PressureState::Normal,
            gaming: false,
        },
        &cfg,
    );
    assert!(!plan.shrinker_enabled);
    assert!(plan.requires_reboot);
}

#[test]
fn boot_plan_requires_approval_and_never_targets_usr_lib() {
    let fixture = inventory_fixture("N");
    let inventory = inspect_linux(fixture.path(), true).expect("inventory");
    let path = Path::new("/var/lib/nemor/swap/nemor-tiering.swap");
    let mut cfg = config();
    cfg.allow_swapfile_create = true;
    let swap = plan_swapfile(
        &swap_context(path, FilesystemKind::Ext4, StorageClass::Nvme),
        &cfg,
    );
    let plan = boot_plan(&inventory, &swap);
    assert!(plan.requires_user_approval);
    assert!(plan
        .files
        .iter()
        .all(|file| !file.path.starts_with("/usr/lib")));
    assert_eq!(
        plan.cachyos_udev_override.as_deref(),
        Some(Path::new("/etc/udev/rules.d/30-zram.rules"))
    );
}

#[test]
fn observe_configuration_forbids_every_mutating_capability() {
    let cfg = config();
    assert!(cfg.dry_run);
    assert_eq!(cfg.supported_storage_profiles, ["nvme_ssd", "sata_ssd"]);
    assert!(!cfg.allow_runtime_reconfigure);
    assert!(!cfg.allow_persistent_reconfigure);
    assert!(!cfg.allow_swapfile_create);
    assert!(!cfg.allow_shrinker);
}

#[test]
fn legacy_zswap_nvme_is_readable_but_cannot_authorize_sata() {
    let legacy: BackendKind = serde_json::from_str("\"zswap_nvme\"").expect("legacy");
    assert_eq!(legacy, BackendKind::ZswapNvme);
    let storage = topology(StorageClass::SolidStateNonNvme);
    let zram = benchmark(BackendKind::Zram);
    let legacy_benchmark = benchmark(BackendKind::ZswapNvme);
    let decision = recommend_backend(&RecommendationInput {
        current: BackendKind::Zram,
        gaming: false,
        pressure: PressureState::Normal,
        storage: &storage,
        zram_benchmark: Some(&zram),
        zswap_benchmark: Some(&legacy_benchmark),
        profile_evidence: None,
        same_host_zram_baseline: None,
        same_host_profile_evidence: None,
        budget: &budget(true),
        safety_events: 0,
        source_state: "clean",
        environment_identity: "same-host",
    });
    assert_eq!(decision.selected, BackendKind::Zram);
    assert!(decision
        .reasons
        .contains(&"sata_boot_validation_missing".to_owned()));
}

fn profile_evidence(profile: StorageProfile) -> ProfileBenchmarkEvidence {
    ProfileBenchmarkEvidence {
        contract_version: TIERING_RULE_VERSION.to_owned(),
        profile,
        device_identity: "test:serial:wwn:1000000".to_owned(),
        filesystem_identity: "ext4:/dev/test".to_owned(),
        source_state: "clean".to_owned(),
        environment_identity: "same-host".to_owned(),
        real: true,
        cleanup_passed: true,
        restore_passed: true,
        safety_failure: false,
        compression_ratio: Some(2.0),
        swap_latency_ns: Some(3),
        backing_write_bytes: Some(4),
        oom: false,
    }
}

fn same_host_evidence(
    profile: StorageProfile,
) -> (SameHostZramBaselineEvidenceV2, SameHostProfileEvidenceV3) {
    let baseline = SameHostZramBaselineEvidenceV2 {
        schema: ZRAM_BASELINE_EVIDENCE_V2.to_owned(),
        validation_id: "same-host-validation".to_owned(),
        source_commit: "a".repeat(40),
        source_state_sha256: "1".repeat(64),
        environment_sha256: "2".repeat(64),
        topology_sha256: "3".repeat(64),
        workload_sha256: "4".repeat(64),
        real: true,
        oom: false,
        safety_failure: false,
        cleanup_passed: true,
        final_restore_passed: true,
        archive_sha256: "5".repeat(64),
        raw_evidence_sha256: "7".repeat(64),
        workload_protocol: WORKLOAD_PROTOCOL_V1.to_owned(),
    };
    let evidence = SameHostProfileEvidenceV3 {
        schema: PROFILE_BENCHMARK_EVIDENCE_V3.to_owned(),
        validation_id: baseline.validation_id.clone(),
        profile,
        source_commit: baseline.source_commit.clone(),
        source_state_sha256: baseline.source_state_sha256.clone(),
        environment_sha256: baseline.environment_sha256.clone(),
        topology_sha256: baseline.topology_sha256.clone(),
        workload_sha256: baseline.workload_sha256.clone(),
        real: true,
        oom: false,
        safety_failure: false,
        cleanup_passed: true,
        final_restore_passed: true,
        write_budget_passed: true,
        backing_write_bytes: Some(4),
        latency_ns: Some(3),
        archive_sha256: "6".repeat(64),
        raw_evidence_sha256: "8".repeat(64),
        workload_protocol: WORKLOAD_PROTOCOL_V1.to_owned(),
        backing_write_confidence: "bounded-physical-device-attributed".to_owned(),
    };
    (baseline, evidence)
}

#[test]
fn sata_and_nvme_evidence_bind_only_the_exact_profile() {
    let zram = benchmark(BackendKind::Zram);
    for (class, profile) in [
        (StorageClass::SolidStateNonNvme, StorageProfile::SataSsd),
        (StorageClass::Nvme, StorageProfile::NvmeSsd),
    ] {
        let storage = topology(class);
        let matching = profile_evidence(profile);
        let (same_host_baseline, same_host_profile) = same_host_evidence(profile);
        let selected = recommend_backend(&RecommendationInput {
            current: BackendKind::Zram,
            gaming: false,
            pressure: PressureState::Normal,
            storage: &storage,
            zram_benchmark: Some(&zram),
            zswap_benchmark: None,
            profile_evidence: Some(&matching),
            same_host_zram_baseline: Some(&same_host_baseline),
            same_host_profile_evidence: Some(&same_host_profile),
            budget: &budget(true),
            safety_events: 0,
            source_state: "clean",
            environment_identity: "same-host",
        });
        assert_eq!(selected.selected, BackendKind::ZswapStorageBacked);
        let wrong = profile_evidence(if profile == StorageProfile::SataSsd {
            StorageProfile::NvmeSsd
        } else {
            StorageProfile::SataSsd
        });
        let (_, mut wrong_same_host_profile) = same_host_evidence(profile);
        wrong_same_host_profile.environment_sha256 = "7".repeat(64);
        let rejected = recommend_backend(&RecommendationInput {
            current: BackendKind::Zram,
            gaming: false,
            pressure: PressureState::Normal,
            storage: &storage,
            zram_benchmark: Some(&zram),
            zswap_benchmark: None,
            profile_evidence: Some(&wrong),
            same_host_zram_baseline: Some(&same_host_baseline),
            same_host_profile_evidence: Some(&wrong_same_host_profile),
            budget: &budget(true),
            safety_events: 0,
            source_state: "clean",
            environment_identity: "same-host",
        });
        assert_eq!(rejected.selected, BackendKind::Zram);
    }
}

#[cfg(unix)]
#[test]
fn transport_profiles_require_transport_evidence_not_model_spoofing() {
    for (transport, expected) in [
        ("sata", StorageProfile::SataSsd),
        ("sas", StorageProfile::SasSsd),
        ("usb", StorageProfile::UsbSsd),
    ] {
        let fixture = tempfile::tempdir().unwrap();
        write(fixture.path(), "/sys/class/block/sda/queue/rotational", "0");
        write(
            fixture.path(),
            "/sys/class/block/sda/device/transport",
            transport,
        );
        write(
            fixture.path(),
            "/sys/class/block/sda/device/model",
            "NVMe spoof",
        );
        write(fixture.path(), "/sys/class/block/sda/size", "2048");
        let found = inspect_storage(fixture.path(), "/dev/sda", "btrfs");
        assert_eq!(found.profile, Some(expected));
        assert_ne!(found.profile, Some(StorageProfile::NvmeSsd));
    }
}

#[test]
fn rotational_virtual_composite_and_ambiguous_profiles_fail_closed() {
    let rotational = topology(StorageClass::Rotational);
    assert_eq!(rotational.profile, Some(StorageProfile::Rotational));
    assert!(!rotational.profile.unwrap().boot_supported());
    let fixture = tempfile::tempdir().unwrap();
    write(fixture.path(), "/sys/class/block/dm-0/slaves/a/marker", "");
    write(fixture.path(), "/sys/class/block/dm-0/slaves/b/marker", "");
    let composite = inspect_storage(fixture.path(), "/dev/dm-0", "btrfs");
    assert_eq!(composite.profile, Some(StorageProfile::Composite));
    let missing = inspect_storage(fixture.path(), "/dev/missing", "btrfs");
    assert_eq!(missing.profile, Some(StorageProfile::Ambiguous));
}

#[derive(Default)]
struct FakeBootBackend {
    artifacts: std::collections::BTreeSet<PathBuf>,
    one_shot: Option<String>,
    booted: Option<String>,
    mutate_calls: usize,
    unsafe_path: bool,
}

impl BootValidationBackend for FakeBootBackend {
    fn source_matches(&self, _: &TieringBootValidationManifest) -> bool {
        true
    }
    fn storage_matches(&self, _: &TieringBootValidationManifest) -> bool {
        true
    }
    fn bootloader_matches(&self, _: &TieringBootValidationManifest) -> bool {
        true
    }
    fn entries_preserved(&self, _: &TieringBootValidationManifest) -> bool {
        true
    }
    fn boot_order_matches(&self, _: &TieringBootValidationManifest) -> bool {
        true
    }
    fn artifact_absent_and_safe(&self, artifact: &BootArtifact) -> bool {
        !self.unsafe_path && !self.artifacts.contains(&artifact.path)
    }
    fn package_update_absent(&self) -> bool {
        true
    }
    fn secure_boot_compatible(&self) -> bool {
        true
    }
    fn create_new_artifact(&mut self, artifact: &BootArtifact) -> bool {
        self.mutate_calls += 1;
        self.artifacts.insert(artifact.path.clone())
    }
    fn artifact_matches(&self, artifact: &BootArtifact) -> bool {
        self.artifacts.contains(&artifact.path)
    }
    fn sync_artifact_parents(&mut self) -> bool {
        self.mutate_calls += 1;
        true
    }
    fn set_one_shot(&mut self, entry: &str) -> bool {
        self.mutate_calls += 1;
        self.one_shot = Some(entry.to_owned());
        true
    }
    fn booted_entry(&self) -> Option<String> {
        self.booted.clone()
    }
    fn remove_exact_artifact(&mut self, artifact: &BootArtifact) -> bool {
        self.mutate_calls += 1;
        self.artifacts.remove(&artifact.path)
    }
    fn temporary_swapfile_absent(&self, _: &TieringBootValidationManifest) -> bool {
        true
    }
    fn baseline_zswap_restored(&self, _: &TieringBootValidationManifest) -> bool {
        true
    }
    fn baseline_zram_restored(&self, _: &TieringBootValidationManifest) -> bool {
        true
    }
}

fn boot_manifest(profile: StorageProfile) -> TieringBootValidationManifest {
    let validation_id = "phase6-sata-1".to_owned();
    let path = PathBuf::from("/boot/loader/entries/nemor-validation-phase6-sata-1.conf");
    TieringBootValidationManifest {
        contract_version: BOOT_VALIDATION_CONTRACT_VERSION.to_owned(),
        rule_version: TIERING_RULE_VERSION.to_owned(),
        validation_id: validation_id.clone(),
        source_commit: "a".repeat(40),
        source_state: "clean".to_owned(),
        binary_identities: Default::default(),
        config_sha256: "b".repeat(64),
        environment_identity: "host".to_owned(),
        storage_profile: profile,
        physical_device_identity: "test:serial:wwn:1000000".to_owned(),
        filesystem_identity: "btrfs:uuid".to_owned(),
        swapfile_path: PathBuf::from("/var/lib/nemor/swap/nemor-tiering.swap"),
        swapfile_size: 64 * 1024 * 1024,
        swap_priority: 9,
        protected_zram_active: true,
        protected_zram_priority: Some(100),
        baseline_zswap_enabled: false,
        experimental_zswap_parameters: [("enabled".to_owned(), "1".to_owned())].into(),
        bootloader: "systemd-boot/kernel-install-uki".to_owned(),
        current_entry: "linux-cachyos.conf".to_owned(),
        default_entry: "linux-cachyos.conf".to_owned(),
        boot_order: vec!["0003".to_owned(), "0004".to_owned()],
        esp_identity: "esp".to_owned(),
        kernel_identity: "kernel".to_owned(),
        initrd_or_uki_identities: Default::default(),
        current_command_line: "zswap.enabled=0".to_owned(),
        experimental_command_line: "zswap.enabled=1 root=uuid".to_owned(),
        experimental_entry: "nemor-validation-phase6-sata-1.conf".to_owned(),
        owned_artifacts: vec![BootArtifact {
            content: "title Nemor Phase 6 validation\nlinux /EFI/Linux/nemor-validation.efi\n"
                .to_owned(),
            sha256: crate::boot_validation::sha256_bytes(
                b"title Nemor Phase 6 validation\nlinux /EFI/Linux/nemor-validation.efi\n",
            ),
            path,
            mode: 0o600,
            owner_uid: 0,
            owner_gid: 0,
        }],
        one_shot_method: "bootctl-set-oneshot".to_owned(),
        rollback_entry: "linux-cachyos.conf".to_owned(),
        maximum_write_bytes: 64 * 1024 * 1024,
        timeout_seconds: 300,
        recovery_plan: vec!["select baseline one-shot".to_owned()],
        production_activation: false,
    }
}

#[test]
fn boot_preflights_are_non_mutating_and_apply_is_exact_owned() {
    let manifest = boot_manifest(StorageProfile::SataSsd);
    let mut backend = FakeBootBackend::default();
    let user = user_preflight(&manifest, &backend);
    let root = root_preflight(&manifest, &backend);
    assert!(user.ready && root.ready && user.non_mutating && root.non_mutating);
    assert_eq!(backend.mutate_calls, 0);
    let mut applied = apply_boot_validation(&manifest, &root, &mut backend).unwrap();
    verify_applied(&manifest, &applied, &backend).unwrap();
    assert!(!applied.one_shot_selected);
    select_one_shot(&manifest, &mut applied, &mut backend).unwrap();
    assert_eq!(
        backend.one_shot.as_deref(),
        Some(manifest.experimental_entry.as_str())
    );
    assert_eq!(manifest.default_entry, "linux-cachyos.conf");
}

#[test]
fn boot_command_surface_separates_authorization_and_has_no_production_command() {
    assert!(!BootValidationCommand::Prepare.mutating());
    assert!(!BootValidationCommand::UserPreflight.mutating());
    assert!(BootValidationCommand::RootPreflight.requires_authenticated_root());
    assert!(BootValidationCommand::Apply.mutating());
    let json = serde_json::to_string(&[
        BootValidationCommand::Prepare,
        BootValidationCommand::UserPreflight,
        BootValidationCommand::RootPreflight,
        BootValidationCommand::Apply,
        BootValidationCommand::VerifyApplied,
        BootValidationCommand::SelectOneShot,
        BootValidationCommand::PostBootValidate,
        BootValidationCommand::SelectBaselineRollback,
        BootValidationCommand::VerifyFinalRestore,
        BootValidationCommand::Recover,
        BootValidationCommand::VerifyIdempotence,
    ])
    .unwrap();
    assert!(!json.contains("production"));
}

#[test]
fn boot_paths_existing_symlink_equivalent_and_vendor_paths_fail_closed() {
    let mut manifest = boot_manifest(StorageProfile::SataSsd);
    manifest.owned_artifacts[0].path = PathBuf::from("/usr/lib/nemor-validation-x");
    assert_eq!(
        manifest.validate(),
        Err(BootValidationError::PathOutsideNamespace)
    );
    let manifest = boot_manifest(StorageProfile::SataSsd);
    let mut backend = FakeBootBackend {
        unsafe_path: true,
        ..Default::default()
    };
    let preflight = root_preflight(&manifest, &backend);
    assert!(!preflight.ready);
    assert_eq!(
        apply_boot_validation(&manifest, &preflight, &mut backend),
        Err(BootValidationError::PreflightRejected)
    );
}

#[test]
fn boot_artifact_owner_mode_and_checksum_are_integrity_bound() {
    let mut manifest = boot_manifest(StorageProfile::SataSsd);
    manifest.owned_artifacts[0].owner_uid = 1000;
    assert_eq!(
        manifest.validate(),
        Err(BootValidationError::InvalidArtifactIdentity)
    );
    let mut manifest = boot_manifest(StorageProfile::SataSsd);
    manifest.owned_artifacts[0].mode = 0o666;
    assert_eq!(
        manifest.validate(),
        Err(BootValidationError::InvalidArtifactIdentity)
    );
    let mut manifest = boot_manifest(StorageProfile::SataSsd);
    manifest.owned_artifacts[0].content.push_str("tampered");
    assert_eq!(
        manifest.validate(),
        Err(BootValidationError::InvalidArtifactIdentity)
    );
}

#[test]
fn post_boot_profile_oom_and_write_budget_are_mandatory() {
    let manifest = boot_manifest(StorageProfile::NvmeSsd);
    let complete = TieringPostBootEvidence {
        stage: BootValidationStage::OneShotSelected,
        profile: StorageProfile::NvmeSsd,
        booted_entry: manifest.experimental_entry.clone(),
        kernel_matches: true,
        command_line_matches: true,
        zswap_readback_matches: true,
        swapfile_identity_matches: true,
        swap_priority_matches: true,
        zram_policy_matches: true,
        storage_identity_matches: true,
        counters_available: true,
        backing_write_bytes: Some(4096),
        latency_ns: Some(1),
        throughput_bytes_per_second: Some(1),
        compression_ratio_milli: Some(2000),
        refault_passed: true,
        write_budget_passed: true,
        host_oom: false,
        oom_kill: false,
        daemon_observe_only: true,
        production_activation: false,
        valid: false,
    };
    assert!(
        post_boot_validate(&manifest, complete.clone())
            .unwrap()
            .valid
    );
    let mut oom = complete.clone();
    oom.host_oom = true;
    assert_eq!(
        post_boot_validate(&manifest, oom),
        Err(BootValidationError::PostBootRejected)
    );
    let mut wrong = complete;
    wrong.profile = StorageProfile::SataSsd;
    assert_eq!(
        post_boot_validate(&manifest, wrong),
        Err(BootValidationError::PostBootRejected)
    );
}

#[test]
fn rollback_waits_for_baseline_then_recovery_is_idempotent() {
    let manifest = boot_manifest(StorageProfile::SataSsd);
    let mut backend = FakeBootBackend::default();
    let preflight = root_preflight(&manifest, &backend);
    let _ = apply_boot_validation(&manifest, &preflight, &mut backend).unwrap();
    let rollback = prepare_baseline_rollback(&manifest, &mut backend).unwrap();
    assert!(rollback.experimental_artifacts_preserved_until_baseline);
    assert!(backend.artifact_matches(&manifest.owned_artifacts[0]));
    backend.booted = Some(manifest.rollback_entry.clone());
    let restored = verify_final_restore(&manifest, &mut backend).unwrap();
    assert!(restored.exact_owned_artifacts_absent);
    let recovered = recover_boot_validation(&manifest, &mut backend).unwrap();
    assert!(recovered.idempotent);
}

#[test]
fn storage_topology_marks_missing_and_multi_mapper_ambiguous() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let missing = inspect_storage(fixture.path(), "/dev/missing", "ext4");
    assert!(missing.ambiguous);
    write(fixture.path(), "/sys/class/block/dm-0/slaves/a/marker", "");
    write(fixture.path(), "/sys/class/block/dm-0/slaves/b/marker", "");
    let multi = inspect_storage(fixture.path(), "/dev/dm-0", "btrfs");
    assert!(multi.ambiguous);
}

#[cfg(unix)]
#[test]
fn storage_topology_classifies_nvme_only_with_sysfs_evidence() {
    let fixture = tempfile::tempdir().expect("tempdir");
    let root = fixture.path();
    write(root, "/sys/devices/nvme0n1/queue/rotational", "0");
    write(root, "/sys/devices/nvme0n1/queue/logical_block_size", "512");
    write(
        root,
        "/sys/devices/nvme0n1/queue/physical_block_size",
        "4096",
    );
    write(root, "/sys/devices/nvme0n1/device/subsystem", "nvme");
    fs::create_dir_all(root.join("sys/class/block")).expect("class");
    symlink(
        root.join("sys/devices/nvme0n1"),
        root.join("sys/class/block/nvme0n1"),
    )
    .expect("symlink");
    let found = inspect_storage(root, "/dev/nvme0n1", "ext4");
    assert!(!found.ambiguous);
    assert_eq!(found.physical.expect("physical").class, StorageClass::Nvme);
}

#[test]
fn cgroup_and_debug_counter_maps_do_not_assume_fixed_fields() {
    let fixture = inventory_fixture("N");
    write(fixture.path(), "/sys/fs/cgroup/memory.zswap.writeback", "1");
    write(
        fixture.path(),
        "/sys/kernel/debug/zswap/written_back_pages",
        "8",
    );
    let found = inspect_linux(fixture.path(), true).expect("inspect");
    assert_eq!(
        found.cgroup_values.get("memory.zswap.writeback"),
        Some(&"1".to_owned())
    );
    assert_eq!(found.debug_counters[0].value, Some(8));
}

#[test]
fn malformed_optional_values_become_none_without_panic() {
    let fixture = inventory_fixture("maybe");
    write(
        fixture.path(),
        "/sys/module/zswap/parameters/max_pool_percent",
        "999",
    );
    let found = inspect_linux(fixture.path(), true).expect("inspect");
    assert!(found.parameters.enabled.is_none());
    assert!(found.parameters.max_pool_percent.is_none());
}

#[test]
fn logical_writeback_is_distinct_from_physical_block_writes() {
    let page_size = 4096_u64;
    let counters = BTreeMap::from([("written_back_pages", 10_u64)]);
    let logical = counters["written_back_pages"] * page_size;
    let physical = 80_u64 * 512;
    assert_eq!(logical, 40_960);
    assert_eq!(physical, 40_960);
    assert_ne!("logical_zswap_writeback", "physical_block_delta");
}

#[derive(Default)]
struct FakeSwapfileBackend {
    active: std::collections::BTreeSet<std::path::PathBuf>,
    owned: std::collections::BTreeSet<std::path::PathBuf>,
    calls: Vec<String>,
    fail: Option<&'static str>,
}

impl SwapfileBackend for FakeSwapfileBackend {
    fn active_swaps(
        &self,
    ) -> Result<std::collections::BTreeSet<std::path::PathBuf>, super::backend::BackendError> {
        Ok(self.active.clone())
    }

    fn create_owned(
        &mut self,
        path: &Path,
        _filesystem: FilesystemKind,
        _size: u64,
    ) -> Result<(), super::backend::BackendError> {
        self.calls.push("create".to_owned());
        if self.fail == Some("create") {
            return Err(super::backend::BackendError::Verification(
                "create".to_owned(),
            ));
        }
        self.owned.insert(path.to_path_buf());
        Ok(())
    }

    fn activate_owned(
        &mut self,
        path: &Path,
        _priority: i32,
    ) -> Result<(), super::backend::BackendError> {
        self.calls.push("activate".to_owned());
        if self.fail == Some("activate") {
            return Err(super::backend::BackendError::Verification(
                "activate".to_owned(),
            ));
        }
        self.active.insert(path.to_path_buf());
        Ok(())
    }

    fn deactivate_owned(&mut self, path: &Path) -> Result<(), super::backend::BackendError> {
        self.calls.push("deactivate".to_owned());
        if self.fail == Some("deactivate") {
            return Err(super::backend::BackendError::Verification(
                "deactivate".to_owned(),
            ));
        }
        self.active.remove(path);
        Ok(())
    }

    fn remove_owned(&mut self, path: &Path) -> Result<(), super::backend::BackendError> {
        self.calls.push("remove".to_owned());
        if self.fail == Some("remove") {
            return Err(super::backend::BackendError::Verification(
                "remove".to_owned(),
            ));
        }
        self.owned.remove(path);
        Ok(())
    }

    fn is_owned(&self, path: &Path) -> bool {
        self.owned.contains(path)
    }
}

fn transaction_plan() -> SwapfilePlan {
    SwapfilePlan {
        path: "/var/tmp/nemor-validation-tiering-test.swap".into(),
        mountpoint: "/var/tmp".into(),
        filesystem: FilesystemKind::Btrfs,
        backing_device: "/dev/nvme0n1p2".to_owned(),
        physical_device_class: StorageClass::Nvme,
        proposed_size: 64 * 1_048_576,
        priority: 10,
        free_bytes: 1_000_000_000,
        required_headroom_bytes: 100_000_000,
        ownership: SwapfileOwnership::NemorOwned,
        create_required: true,
        format_required: true,
        activate_required: true,
        persistence_requested: false,
        allowed: true,
        blocked_reasons: Vec::new(),
        dry_run: false,
    }
}

#[test]
fn observe_transaction_makes_zero_mutating_calls() {
    let mut backend = FakeSwapfileBackend::default();
    let mut plan = transaction_plan();
    plan.dry_run = true;
    let mut snapshot = MutationSnapshot {
        path: plan.path.clone(),
        baseline_swaps: ["/dev/zram0".into()].into_iter().collect(),
        created: false,
        activated: false,
        rollback_pending: false,
        rolled_back: false,
        last_error: None,
    };
    let outcome = apply_swapfile(&mut backend, &plan, &mut snapshot).expect("dry-run");
    assert!(!outcome.created);
    assert!(backend.calls.is_empty());
}

#[test]
fn swapfile_transaction_preserves_baseline_and_rolls_back_idempotently() {
    let plan = transaction_plan();
    let mut backend = FakeSwapfileBackend::default();
    backend.active.insert("/dev/zram0".into());
    let mut snapshot = MutationSnapshot {
        path: plan.path.clone(),
        baseline_swaps: backend.active.clone(),
        created: false,
        activated: false,
        rollback_pending: false,
        rolled_back: false,
        last_error: None,
    };
    let outcome = apply_swapfile(&mut backend, &plan, &mut snapshot).expect("apply");
    assert!(outcome.verified);
    rollback_swapfile(&mut backend, &mut snapshot).expect("rollback");
    rollback_swapfile(&mut backend, &mut snapshot).expect("idempotent");
    assert_eq!(backend.active, ["/dev/zram0".into()].into_iter().collect());
    assert!(!backend.owned.contains(&plan.path));
}

#[test]
fn transaction_failure_injection_never_removes_external_swap() {
    for failure in ["create", "activate"] {
        let plan = transaction_plan();
        let mut backend = FakeSwapfileBackend {
            fail: Some(failure),
            ..FakeSwapfileBackend::default()
        };
        backend.active.insert("/dev/zram0".into());
        let mut snapshot = MutationSnapshot {
            path: plan.path.clone(),
            baseline_swaps: backend.active.clone(),
            created: false,
            activated: false,
            rollback_pending: false,
            rolled_back: false,
            last_error: None,
        };
        assert!(apply_swapfile(&mut backend, &plan, &mut snapshot).is_err());
        assert!(backend.active.contains(Path::new("/dev/zram0")));
    }
}

#[test]
fn linux_backend_rejects_arbitrary_paths_without_mutation() {
    let mut backend = LinuxSwapfileBackend::default();
    assert!(backend
        .create_owned(
            Path::new("/home/user/external.swap"),
            FilesystemKind::Ext4,
            1_048_576
        )
        .is_err());
}

#[test]
fn zswap_linux_backend_is_observe_only_and_rejects_arbitrary_inputs() {
    use crate::{LinuxZswapBackend, StorageMetricsBackend, ZswapBackend};
    let mut backend = LinuxZswapBackend::observe();
    assert!(backend.set_parameter("enabled", "Y").is_err());
    assert!(backend.read_parameter("../../enabled").is_err());
    assert!(backend.read_block_stat("../sda").is_err());
}
