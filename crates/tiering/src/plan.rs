use crate::{
    matching_same_host_evidence_v2, BudgetDecision, SameHostProfileEvidenceV2,
    SameHostZramBaselineEvidenceV1, StorageProfile, StorageTopology, SwapfilePlan, ZswapInventory,
};
use common::TieringConfig;
use policy_engine::PressureState;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const TIERING_RULE_VERSION: &str = "tiering-rules-v2-storage-profile";
pub const TIERING_AUDIT_REASON: &str = "tiering_observe_audit";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Zram,
    ZswapStorageBacked,
    /// Historical v1 evidence only. It never authorizes a v2 profile.
    ZswapNvme,
    External,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    Nvme,
    SolidStateNonNvme,
    Rotational,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolIntent {
    Conservative,
    Gaming,
    Capacity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkEvidence {
    pub backend: BackendKind,
    pub real: bool,
    pub cpu_time_ns: u64,
    pub wall_time_ns: u64,
    pub compression_ratio: Option<f64>,
    pub swap_latency_ns: Option<u64>,
    pub backing_write_bytes: Option<u64>,
    pub oom: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileBenchmarkEvidence {
    pub contract_version: String,
    pub profile: StorageProfile,
    pub device_identity: String,
    pub filesystem_identity: String,
    pub source_state: String,
    pub environment_identity: String,
    pub real: bool,
    pub cleanup_passed: bool,
    pub restore_passed: bool,
    pub safety_failure: bool,
    pub compression_ratio: Option<f64>,
    pub swap_latency_ns: Option<u64>,
    pub backing_write_bytes: Option<u64>,
    pub oom: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolPlan {
    pub intent: PoolIntent,
    pub compressor: Option<String>,
    pub zpool: Option<String>,
    pub max_pool_percent: u8,
    pub accept_threshold_percent: u8,
    pub shrinker_enabled: bool,
    pub backing_swapfile: Option<PathBuf>,
    pub rule_version: String,
    pub blocked_reasons: Vec<String>,
    pub requires_reboot: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone)]
pub struct PoolContext<'a> {
    pub intent: PoolIntent,
    pub inventory: &'a ZswapInventory,
    pub swapfile: &'a SwapfilePlan,
    pub benchmark: Option<&'a BenchmarkEvidence>,
    pub budget: &'a BudgetDecision,
    pub pressure: PressureState,
    pub gaming: bool,
}

#[must_use]
pub fn plan_pool(context: &PoolContext<'_>, config: &TieringConfig) -> PoolPlan {
    let mut blocked = Vec::new();
    if !context.inventory.supported {
        blocked.push("zswap_unsupported".to_owned());
    }
    if !context.swapfile.allowed {
        blocked.push("backing_swapfile_unavailable".to_owned());
    }
    if context.gaming {
        blocked.push("gaming_defers_global_zswap_change".to_owned());
    }
    if matches!(
        context.pressure,
        PressureState::Critical | PressureState::Emergency
    ) {
        blocked.push("severe_pressure_blocks_global_change".to_owned());
    }
    if !context.budget.allowed {
        blocked.push("write_budget_exceeded".to_owned());
    }
    if !config.allow_runtime_reconfigure {
        blocked.push("runtime_reconfigure_disabled".to_owned());
    }
    let benchmark_ready = context
        .benchmark
        .is_some_and(|value| value.real && !value.oom && value.backing_write_bytes.is_some());
    let shrinker_enabled = config.allow_shrinker
        && context.intent == PoolIntent::Capacity
        && benchmark_ready
        && context.budget.allowed
        && !context.gaming
        && matches!(
            context.pressure,
            PressureState::Normal | PressureState::Watch
        );
    PoolPlan {
        intent: context.intent,
        compressor: context.inventory.parameters.compressor.clone(),
        zpool: context.inventory.parameters.zpool.clone(),
        max_pool_percent: config
            .zswap_pool_max_percent
            .clamp(config.zswap_pool_min_percent, 100),
        accept_threshold_percent: context
            .inventory
            .parameters
            .accept_threshold_percent
            .unwrap_or(90),
        shrinker_enabled,
        backing_swapfile: context
            .swapfile
            .allowed
            .then(|| context.swapfile.path.clone()),
        rule_version: TIERING_RULE_VERSION.to_owned(),
        blocked_reasons: blocked,
        requires_reboot: context.inventory.provider.conflict
            || !context.inventory.parameters.enabled.unwrap_or(false),
        dry_run: config.dry_run,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootFilePlan {
    pub path: PathBuf,
    pub action: String,
    pub backup_required: bool,
    pub checksum_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootTieringPlan {
    pub bootloader: Option<String>,
    pub zram_disable_requirement: bool,
    pub zswap_kernel_params: Vec<String>,
    pub cachyos_udev_override: Option<PathBuf>,
    pub backing_swapfile: PathBuf,
    pub files: Vec<BootFilePlan>,
    pub post_reboot_validation: Vec<String>,
    pub rollback: Vec<String>,
    pub requires_user_approval: bool,
    pub allowed: bool,
    pub blocked_reasons: Vec<String>,
}

#[must_use]
pub fn boot_plan(inventory: &ZswapInventory, swapfile: &SwapfilePlan) -> BootTieringPlan {
    let mut blocked = Vec::new();
    if inventory.provider.bootloader.is_none() {
        blocked.push("bootloader_unknown".to_owned());
    }
    if !swapfile.allowed {
        blocked.push("swapfile_plan_blocked".to_owned());
    }
    if !matches!(
        swapfile.physical_device_class,
        StorageClass::Nvme | StorageClass::SolidStateNonNvme
    ) {
        blocked.push("storage_profile_unsupported".to_owned());
    }
    let cmdline_path = match inventory.provider.bootloader.as_deref() {
        Some("grub") => Some(PathBuf::from("/etc/default/grub")),
        Some("systemd-boot") => Some(PathBuf::from("/boot/loader/loader.conf")),
        Some("kernel-install/uki") => Some(PathBuf::from("/etc/kernel/cmdline")),
        Some("systemd-boot/kernel-install-uki") => None,
        _ => None,
    };
    let mut files = Vec::new();
    if let Some(path) = cmdline_path {
        files.push(BootFilePlan {
            path,
            action: "add bounded zswap kernel parameters".to_owned(),
            backup_required: true,
            checksum_required: true,
        });
    }
    if inventory.provider.bootloader.as_deref() == Some("systemd-boot/kernel-install-uki") {
        blocked.push("validation_only_manifest_required".to_owned());
    }
    let override_path = inventory
        .provider
        .cachyos_zswap_disable_rule
        .then(|| PathBuf::from("/etc/udev/rules.d/30-zram.rules"));
    if let Some(path) = &override_path {
        files.push(BootFilePlan {
            path: path.clone(),
            action: "Nemor-owned override; never modify /usr/lib".to_owned(),
            backup_required: true,
            checksum_required: true,
        });
    }
    if files.iter().any(|file| file.path.starts_with("/usr/lib")) {
        blocked.push("vendor_path_forbidden".to_owned());
    }
    BootTieringPlan {
        bootloader: inventory.provider.bootloader.clone(),
        zram_disable_requirement: inventory.provider.systemd_zram,
        zswap_kernel_params: vec![
            "zswap.enabled=1".to_owned(),
            "zswap.max_pool_percent=<planned>".to_owned(),
            "zswap.accept_threshold_percent=<planned>".to_owned(),
        ],
        cachyos_udev_override: override_path,
        backing_swapfile: swapfile.path.clone(),
        files,
        post_reboot_validation: vec![
            "verify zswap parameter readback".to_owned(),
            "verify exact profile-bound storage-backed swapfile".to_owned(),
            "verify daemon remains observe-only".to_owned(),
        ],
        rollback: vec![
            "restore checksummed backups".to_owned(),
            "remove only Nemor-owned override".to_owned(),
            "reboot and verify CachyOS baseline".to_owned(),
        ],
        requires_user_approval: true,
        allowed: blocked.is_empty(),
        blocked_reasons: blocked,
    }
}

#[derive(Debug, Clone)]
pub struct RecommendationInput<'a> {
    pub current: BackendKind,
    pub gaming: bool,
    pub pressure: PressureState,
    pub storage: &'a StorageTopology,
    pub zram_benchmark: Option<&'a BenchmarkEvidence>,
    pub zswap_benchmark: Option<&'a BenchmarkEvidence>,
    pub profile_evidence: Option<&'a ProfileBenchmarkEvidence>,
    /// V1 generic evidence is retained for report compatibility but cannot
    /// authorize the storage-backed backend. These two sealed, same-host
    /// records are the sole v2 authorization path.
    pub same_host_zram_baseline: Option<&'a SameHostZramBaselineEvidenceV1>,
    pub same_host_profile_evidence: Option<&'a SameHostProfileEvidenceV2>,
    pub budget: &'a BudgetDecision,
    pub safety_events: usize,
    pub source_state: &'a str,
    pub environment_identity: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendRecommendation {
    pub selected: BackendKind,
    pub alternative: BackendKind,
    pub confidence: String,
    pub reasons: Vec<String>,
    pub evidence: Vec<String>,
    pub blocked: bool,
    pub requires_reboot: bool,
    pub rule_version: String,
    #[serde(default)]
    pub production_activation: bool,
}

#[must_use]
pub fn recommend_backend(input: &RecommendationInput<'_>) -> BackendRecommendation {
    let mut reasons = Vec::new();
    let mut evidence = Vec::new();
    let severe = matches!(
        input.pressure,
        PressureState::Critical | PressureState::Emergency
    );
    let profile = input.storage.profile;
    let supported = profile.is_some_and(StorageProfile::boot_supported);
    let baseline_ready = input.same_host_zram_baseline.is_some_and(|baseline| {
        input
            .same_host_profile_evidence
            .is_some_and(|profile_evidence| {
                profile.is_some_and(|profile| {
                    matching_same_host_evidence_v2(baseline, profile_evidence, profile)
                })
            })
    });
    let mut selected = BackendKind::Zram;
    if input.gaming {
        reasons.push("gaming_preserves_low_write_current_zram".to_owned());
    } else if severe {
        reasons.push("severe_pressure_blocks_structural_switch".to_owned());
    } else if input.safety_events > 0 {
        reasons.push("recent_safety_event".to_owned());
    } else if !input.budget.allowed {
        reasons.push("write_budget_exceeded".to_owned());
    } else if !supported {
        reasons.push("storage_profile_unsupported".to_owned());
    } else if !baseline_ready {
        reasons.push("same_host_zram_baseline_missing".to_owned());
        reasons.push(match profile {
            Some(StorageProfile::SataSsd) => "sata_boot_validation_missing".to_owned(),
            Some(StorageProfile::NvmeSsd) => "nvme_boot_validation_missing".to_owned(),
            _ => "profile_boot_validation_missing".to_owned(),
        });
    } else {
        selected = BackendKind::ZswapStorageBacked;
        reasons.push("matching_same_host_profile_evidence".to_owned());
        evidence.push(format!("profile={:?}", profile.expect("supported profile")));
    }
    if input.zram_benchmark.is_some_and(|value| value.real) {
        evidence.push("zram_real_baseline".to_owned());
    }
    BackendRecommendation {
        selected,
        alternative: if selected == BackendKind::Zram {
            BackendKind::ZswapStorageBacked
        } else {
            BackendKind::Zram
        },
        confidence: if selected == BackendKind::ZswapStorageBacked {
            "measured".to_owned()
        } else if input.current == BackendKind::Zram {
            "conservative".to_owned()
        } else {
            "low".to_owned()
        },
        blocked: selected == BackendKind::Zram && input.current != BackendKind::Zram,
        requires_reboot: selected != input.current,
        reasons,
        evidence,
        rule_version: TIERING_RULE_VERSION.to_owned(),
        production_activation: false,
    }
}
