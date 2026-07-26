use crate::{BenchmarkEvidence, DeviceInventory, Ownership};
use common::CompressionConfig;
use policy_engine::PressureState;
use serde::{Deserialize, Serialize};

pub const PROFILE_RULE_VERSION: &str = "zram-profile-rules-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZramProfile {
    Safe,
    Gaming,
    Capacity,
}

impl ZramProfile {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "safe" => Some(Self::Safe),
            "gaming" => Some(Self::Gaming),
            "capacity" => Some(Self::Capacity),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ProfileContext<'a> {
    pub requested: ZramProfile,
    pub device: &'a DeviceInventory,
    pub benchmarks: &'a [BenchmarkEvidence],
    pub total_ram_bytes: u64,
    pub mem_available_bytes: u64,
    pub current_used_bytes: u64,
    pub pressure_state: PressureState,
    pub psi_full_avg10: Option<f64>,
    pub swap_in_per_second: Option<f64>,
    pub gaming: bool,
    pub pressure_worsening: bool,
    pub safety_events: usize,
    pub rollback_pending: bool,
    pub provider_matches_snapshot: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZramProfilePlan {
    pub profile: ZramProfile,
    pub target_device: String,
    pub current_algorithm: Option<String>,
    pub selected_algorithm: Option<String>,
    pub current_disksize: Option<u64>,
    pub proposed_disksize: Option<u64>,
    pub current_priority: Option<i32>,
    pub proposed_priority: Option<i32>,
    pub benchmark_evidence: Vec<BenchmarkEvidence>,
    pub reason: String,
    pub confidence: f64,
    pub requires_reinitialization: bool,
    pub requires_swap_migration: bool,
    pub allowed: bool,
    pub blocked_reasons: Vec<String>,
    pub dry_run: bool,
    pub rule_version: String,
}

#[must_use]
pub fn plan_profile(
    context: &ProfileContext<'_>,
    config: &CompressionConfig,
    mode: &str,
) -> ZramProfilePlan {
    let device = context.device;
    let mut blocks = Vec::new();
    let selected = select_algorithm(context, config);
    let current = device.current_algorithm.clone();
    let proposed_size = proposed_disksize(context, config);
    let requires_reinitialization =
        selected.is_some() && selected != current || proposed_size != device.disksize;
    let requires_swap_migration = device.active_swap && requires_reinitialization;
    let observe = mode == "observe";
    let dry_run = observe || config.dry_run || !config.enabled;

    if !matches!(device.ownership, Ownership::NemorOwned | Ownership::Adopted) {
        blocks.push("ownership_not_explicit".to_owned());
    }
    if device.provider == crate::Provider::Unknown {
        blocks.push("provider_unknown".to_owned());
    }
    if !context.provider_matches_snapshot {
        blocks.push("provider_mismatch".to_owned());
    }
    if context.rollback_pending {
        blocks.push("rollback_pending".to_owned());
    }
    if context.safety_events > 0 {
        blocks.push("recent_safety_event".to_owned());
    }
    if !headroom_sufficient(context, config) {
        blocks.push("insufficient_headroom".to_owned());
    }
    if matches!(
        context.pressure_state,
        PressureState::Critical | PressureState::Emergency
    ) {
        blocks.push("pressure_state_blocks_reconfiguration".to_owned());
    }
    if context.pressure_worsening
        || context.psi_full_avg10.is_some_and(|value| value >= 2.0)
        || context.swap_in_per_second.is_some_and(|value| value > 0.0)
    {
        blocks.push("pressure_trend_unsafe".to_owned());
    }
    if context.gaming && requires_reinitialization {
        blocks.push("gaming_blocks_reinitialization".to_owned());
    }
    if requires_reinitialization && !config.allow_runtime_reconfigure {
        blocks.push("runtime_reconfiguration_disabled".to_owned());
    }
    if device.active_swap && requires_reinitialization && !device.writable.reset {
        blocks.push("active_system_device_protected".to_owned());
    }
    if observe {
        blocks.push("observe_mode".to_owned());
    }

    blocks.sort();
    blocks.dedup();
    let evidence = selected.as_ref().map_or_else(Vec::new, |algorithm| {
        context
            .benchmarks
            .iter()
            .filter(|item| &item.algorithm == algorithm)
            .cloned()
            .collect()
    });
    let reason = match context.requested {
        ZramProfile::Safe => "preserve_current_configuration_without_strong_evidence",
        ZramProfile::Gaming => "select_measured_low_cpu_latency_candidate",
        ZramProfile::Capacity => "select_measured_effective_capacity_candidate",
    };
    ZramProfilePlan {
        profile: context.requested,
        target_device: device.name.clone(),
        current_algorithm: current,
        selected_algorithm: selected,
        current_disksize: device.disksize,
        proposed_disksize: proposed_size,
        current_priority: device.priority,
        proposed_priority: device.priority,
        benchmark_evidence: evidence,
        reason: reason.to_owned(),
        confidence: confidence(context),
        requires_reinitialization,
        requires_swap_migration,
        allowed: blocks.is_empty(),
        blocked_reasons: blocks,
        dry_run,
        rule_version: PROFILE_RULE_VERSION.to_owned(),
    }
}

fn select_algorithm(context: &ProfileContext<'_>, config: &CompressionConfig) -> Option<String> {
    let current = context.device.current_algorithm.clone();
    if context.requested == ZramProfile::Safe {
        return current;
    }
    let valid: Vec<_> = context
        .benchmarks
        .iter()
        .filter(|item| {
            item.real
                && item.datasets >= 3
                && context
                    .device
                    .available_algorithms
                    .contains(&item.algorithm)
                && item.median_cpu_time_ns.is_some()
                && item.cpu_overhead_percent.is_none_or(|value| {
                    value.is_finite() && value >= 0.0 && value <= config.max_cpu_overhead_percent
                })
        })
        .collect();
    if valid.is_empty() {
        return current;
    }
    match context.requested {
        ZramProfile::Gaming => valid
            .into_iter()
            .filter(|item| item.median_write_throughput_bytes_sec.is_some())
            .min_by(|left, right| {
                left.median_cpu_time_ns
                    .cmp(&right.median_cpu_time_ns)
                    .then_with(|| left.algorithm.cmp(&right.algorithm))
            })
            .map(|item| item.algorithm.clone()),
        ZramProfile::Capacity => {
            let current_ratio = context
                .benchmarks
                .iter()
                .find(|item| Some(&item.algorithm) == current.as_ref())
                .and_then(|item| item.median_effective_ratio)
                .unwrap_or(1.0);
            valid
                .into_iter()
                .filter(|item| {
                    item.median_effective_ratio.is_some_and(|ratio| {
                        ratio >= current_ratio * (1.0 + config.min_capacity_gain_percent / 100.0)
                    })
                })
                .max_by(|left, right| {
                    left.median_effective_ratio
                        .partial_cmp(&right.median_effective_ratio)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| right.algorithm.cmp(&left.algorithm))
                })
                .map(|item| item.algorithm.clone())
                .or(current)
        }
        ZramProfile::Safe => current,
    }
}

fn proposed_disksize(context: &ProfileContext<'_>, config: &CompressionConfig) -> Option<u64> {
    let maximum = context
        .total_ram_bytes
        .saturating_mul(u64::from(config.max_zram_percent_ram))
        / 100;
    let current = context.device.disksize?;
    Some(match context.requested {
        ZramProfile::Safe | ZramProfile::Gaming => current,
        ZramProfile::Capacity => current
            .max(context.current_used_bytes.saturating_mul(2))
            .min(maximum),
    })
}

fn headroom_sufficient(context: &ProfileContext<'_>, config: &CompressionConfig) -> bool {
    let minimum = context
        .total_ram_bytes
        .saturating_mul(u64::from(config.safe_headroom_percent))
        / 100;
    context.mem_available_bytes >= minimum.saturating_add(context.current_used_bytes)
}

fn confidence(context: &ProfileContext<'_>) -> f64 {
    if context.requested == ZramProfile::Safe {
        1.0
    } else if context.benchmarks.iter().any(|item| item.real) {
        0.9
    } else {
        0.4
    }
}
