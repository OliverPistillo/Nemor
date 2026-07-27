#![forbid(unsafe_code)]

use common::DamonConfig;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

pub const LABEL_RULE_VERSION: &str = "damon-labels-v1";
pub const DATASET_SCHEMA_VERSION: &str = "nemor-damon-dataset-v1";
pub const AUDIT_REASON: &str = "damon_observe_audit";
pub const MAX_DIAGNOSTIC_ZONE_BYTES: u64 = 160 * 1024 * 1024;
pub const DIAGNOSTIC_ZONE_SIZES: [u64; 5] = [
    8 * 1024 * 1024,
    32 * 1024 * 1024,
    64 * 1024 * 1024,
    128 * 1024 * 1024,
    MAX_DIAGNOSTIC_ZONE_BYTES,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    #[default]
    NotTested,
    Plausible,
    InconclusiveDueToThpBacking,
    SupportedByBasePageComparison,
    NotSupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PageBackingProfile {
    #[default]
    ThpReference,
    BasePageNoHuge,
}

#[derive(Debug, Error)]
pub enum DamonError {
    #[error("DAMON input is invalid: {0}")]
    Invalid(String),
    #[error("DAMON I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("DAMON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DamonCapability {
    pub supported: bool,
    pub sysfs_admin_available: bool,
    pub tracefs_available: bool,
    pub aggregated_tracepoint_available: bool,
    pub available_operations: Vec<String>,
    pub vaddr_supported: bool,
    pub fvaddr_supported: bool,
    pub paddr_supported: bool,
    pub existing_kdamond_count: Option<u32>,
    pub existing_kdamond_pids: Vec<u32>,
    pub active_external_session: bool,
    pub special_module_conflict: bool,
    pub optional_features: BTreeMap<String, bool>,
    pub readable: bool,
    pub writable: bool,
    pub kernel: Option<String>,
    pub notes: Vec<String>,
    pub dry_run: bool,
}

pub fn inspect_linux(root: &Path, kernel: Option<String>) -> DamonCapability {
    let admin = resolve(root, "/sys/kernel/mm/damon/admin");
    let kdamonds = admin.join("kdamonds");
    let tracefs = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(|path| resolve(root, path))
        .find(|path| path.is_dir());
    let nr = read_u32(&kdamonds.join("nr_kdamonds"));
    let mut operations = Vec::new();
    let mut pids = Vec::new();
    let mut active = false;
    if let Some(count) = nr {
        for index in 0..count {
            let base = kdamonds.join(index.to_string());
            if let Some(pid) = read_u32(&base.join("pid")) {
                pids.push(pid);
            }
            active |=
                fs::read_to_string(base.join("state")).is_ok_and(|value| value.trim() == "on");
            let available = base.join("contexts/0/avail_operations");
            if let Ok(value) = fs::read_to_string(available) {
                operations.extend(value.split_whitespace().map(str::to_owned));
            }
        }
    }
    operations.sort();
    operations.dedup();
    let tracepoint = tracefs
        .as_ref()
        .is_some_and(|path| path.join("events/damon/damon_aggregated").is_dir());
    let special = ["damon_reclaim", "damon_lru_sort", "damon_stat"]
        .into_iter()
        .any(|name| {
            let parameters = resolve(root, &format!("/sys/module/{name}/parameters"));
            read_bool(&parameters.join("enabled")).unwrap_or(false)
                || read_u32(&parameters.join("kdamond_pid")).is_some_and(|pid| pid > 0)
        });
    let readable = fs::read_to_string(kdamonds.join("nr_kdamonds")).is_ok();
    let writable = OpenOptions::new()
        .write(true)
        .open(kdamonds.join("nr_kdamonds"))
        .is_ok();
    let mut notes = Vec::new();
    if admin.is_dir() && !readable {
        notes.push("sysfs_admin_present_but_not_readable".to_owned());
    }
    if tracefs.is_some() && !tracepoint {
        notes.push("damon_aggregated_not_visible".to_owned());
    }
    DamonCapability {
        supported: admin.is_dir(),
        sysfs_admin_available: admin.is_dir(),
        tracefs_available: tracefs.is_some(),
        aggregated_tracepoint_available: tracepoint,
        vaddr_supported: operations.iter().any(|value| value == "vaddr"),
        fvaddr_supported: operations.iter().any(|value| value == "fvaddr"),
        paddr_supported: operations.iter().any(|value| value == "paddr"),
        available_operations: operations,
        existing_kdamond_count: nr,
        existing_kdamond_pids: pids,
        active_external_session: active,
        special_module_conflict: special,
        optional_features: BTreeMap::from([
            (
                "refresh_ms".to_owned(),
                contains_file(&kdamonds, "refresh_ms"),
            ),
            (
                "addr_unit".to_owned(),
                contains_file(&kdamonds, "addr_unit"),
            ),
            (
                "intervals_goal".to_owned(),
                contains_file(&kdamonds, "intervals_goal"),
            ),
        ]),
        readable,
        writable,
        kernel,
        notes,
        dry_run: true,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitoringAttrs {
    pub operation: String,
    pub sample_us: u64,
    pub aggr_us: u64,
    pub update_us: u64,
    pub min_regions: u32,
    pub max_regions: u32,
    pub addr_unit: Option<u64>,
}

impl MonitoringAttrs {
    pub fn validate(&self) -> Result<(), DamonError> {
        if self.operation != "vaddr" {
            return Err(DamonError::Invalid(
                "Phase 7 owned sessions require vaddr".to_owned(),
            ));
        }
        if self.sample_us < 100 || self.aggr_us < self.sample_us || self.update_us < self.aggr_us {
            return Err(DamonError::Invalid(
                "intervals must satisfy 100 <= sample <= aggregation <= update".to_owned(),
            ));
        }
        if self.min_regions == 0
            || self.min_regions > self.max_regions
            || self.max_regions > 100_000
        {
            return Err(DamonError::Invalid("region bounds are invalid".to_owned()));
        }
        Ok(())
    }

    #[must_use]
    pub fn expected_samples(&self) -> u64 {
        self.aggr_us / self.sample_us
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceRegion {
    pub target_id: u64,
    pub nr_regions: u32,
    pub start: u64,
    pub end: u64,
    pub nr_accesses: u64,
    pub age: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    #[must_use]
    pub fn overlap(self, other: Self) -> u64 {
        self.end
            .min(other.end)
            .saturating_sub(self.start.max(other.start))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialRegionPlan {
    pub ranges: Vec<AddressRange>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProbeEvidence {
    pub session_id: String,
    pub source: String,
    pub backing_profile: PageBackingProfile,
    pub zone_size_bytes: u64,
    pub windows: u64,
    pub hot_nonzero_windows: u64,
    pub hot_zero_windows: u64,
    pub warm_nonzero_windows: u64,
    pub cold_nonzero_windows: u64,
    pub hot_ratio_mean: f64,
    pub hot_ratio_p25: f64,
    pub hot_ratio_p50: f64,
    pub hot_ratio_p75: f64,
    pub hot_ratio_p95: f64,
    pub hot_raw_accesses_per_window: Vec<u64>,
    pub warm_ratio_mean: f64,
    pub warm_ratio_p25: f64,
    pub warm_ratio_p50: f64,
    pub warm_ratio_p75: f64,
    pub warm_ratio_p95: f64,
    pub warm_raw_accesses_per_window: Vec<u64>,
    pub cold_ratio_mean: f64,
    pub cold_ratio_p25: f64,
    pub cold_ratio_p50: f64,
    pub cold_ratio_p75: f64,
    pub cold_ratio_p95: f64,
    pub cold_raw_accesses_per_window: Vec<u64>,
    pub outside_requested_ratio: f64,
    pub kdamond_cpu_percent: f64,
    pub capture_cpu_percent: f64,
    pub backing_page_size_kib: Option<u64>,
    pub anon_huge_pages_kib: u64,
    pub thp_eligible: Option<bool>,
    pub target_isolated: bool,
    pub workload_active: bool,
    pub capture_integrity: bool,
    pub overhead_within_budget: bool,
    pub base_page_backing_verified: bool,
    pub zone_backing: BTreeMap<String, ZoneBacking>,
}

impl ProbeEvidence {
    #[must_use]
    pub fn stable_enough(&self) -> bool {
        self.source == "current_probe"
            && self.windows >= 8
            && self.hot_nonzero_windows == self.windows
            && self.cold_nonzero_windows == 0
            && self.hot_ratio_mean > self.cold_ratio_mean
            && self.hot_ratio_p50 > self.cold_ratio_p50
            && self.target_isolated
            && self.workload_active
            && self.capture_integrity
            && self.overhead_within_budget
    }
}

#[must_use]
pub fn verify_base_page_backing(backing: &BTreeMap<String, ZoneBacking>) -> bool {
    ["hot", "warm", "cold"].iter().all(|name| {
        backing.get(*name).is_some_and(|zone| {
            zone.kernel_page_size_kib == Some(4)
                && zone.mmu_page_size_kib == Some(4)
                && zone.anon_huge_pages_kib == 0
                && zone.explicit_nohugepage_requested
                && zone.explicit_nohugepage_verified
                && (zone.thp_eligible == Some(false)
                    || zone.vm_flags.iter().any(|flag| flag == "nh"))
        })
    })
}

#[must_use]
pub fn select_base_page_probe(attempts: &[ProbeEvidence]) -> Option<(u64, String)> {
    attempts
        .iter()
        .find(|attempt| {
            attempt.backing_profile == PageBackingProfile::BasePageNoHuge
                && attempt.base_page_backing_verified
                && attempt.stable_enough()
        })
        .map(|attempt| {
            (
                attempt.zone_size_bytes,
                format!(
                    "first robust base-page size: {}/{} HOT nonzero windows",
                    attempt.hot_nonzero_windows, attempt.windows
                ),
            )
        })
}

#[must_use]
pub fn compare_page_backing(thp: &ProbeEvidence, base: &ProbeEvidence) -> HypothesisStatus {
    if thp.zone_size_bytes != base.zone_size_bytes
        || base.backing_profile != PageBackingProfile::BasePageNoHuge
        || !base.base_page_backing_verified
    {
        return HypothesisStatus::NotTested;
    }
    let improved = base.hot_zero_windows < thp.hot_zero_windows
        && base.hot_nonzero_windows as f64 / base.windows.max(1) as f64
            > thp.hot_nonzero_windows as f64 / thp.windows.max(1) as f64;
    if improved && base.stable_enough() {
        HypothesisStatus::SupportedByBasePageComparison
    } else if improved {
        HypothesisStatus::Plausible
    } else {
        HypothesisStatus::NotSupported
    }
}

#[must_use]
pub fn bounded_size_ladder(mem_available_bytes: u64, headroom_bytes: u64) -> Vec<u64> {
    DIAGNOSTIC_ZONE_SIZES
        .into_iter()
        .filter(|size| size.saturating_mul(3).saturating_add(headroom_bytes) <= mem_available_bytes)
        .collect()
}

#[must_use]
pub fn select_probe_size(attempts: &[ProbeEvidence]) -> Option<(u64, String)> {
    attempts
        .iter()
        .find(|attempt| attempt.stable_enough())
        .map(|attempt| {
            (
                attempt.zone_size_bytes,
                format!(
                    "first stable ladder size: {}/{} HOT nonzero windows and HOT mean {:.6} > COLD {:.6}",
                    attempt.hot_nonzero_windows,
                    attempt.windows,
                    attempt.hot_ratio_mean,
                    attempt.cold_ratio_mean
                ),
            )
        })
}

#[must_use]
pub fn size_scaling_supports_tlb_hypothesis(attempts: &[ProbeEvidence]) -> bool {
    attempts.windows(2).any(|pair| {
        let left_fraction = pair[0].hot_nonzero_windows as f64 / pair[0].windows.max(1) as f64;
        let right_fraction = pair[1].hot_nonzero_windows as f64 / pair[1].windows.max(1) as f64;
        pair[1].zone_size_bytes > pair[0].zone_size_bytes
            && pair[1].hot_zero_windows < pair[0].hot_zero_windows
            && right_fraction > left_fraction
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ZoneBacking {
    pub start: u64,
    pub end: u64,
    pub range_size_bytes: u64,
    pub size_kib: u64,
    pub containing_vma_size_kib: u64,
    pub rss_kib: u64,
    pub pss_kib: u64,
    pub swap_kib: u64,
    pub kernel_page_size_kib: Option<u64>,
    pub mmu_page_size_kib: Option<u64>,
    pub anon_huge_pages_kib: u64,
    pub thp_eligible: Option<bool>,
    pub vm_flags: Vec<String>,
    pub backing: String,
    pub containing_vma_start: Option<u64>,
    pub containing_vma_end: Option<u64>,
    pub shared_vma: bool,
    pub shared_vma_group: Option<String>,
    pub explicit_nohugepage_requested: bool,
    pub explicit_nohugepage_verified: bool,
}

pub fn parse_smaps_zone(text: &str, zone: AddressRange) -> Result<ZoneBacking, DamonError> {
    let mut result = ZoneBacking {
        start: zone.start,
        end: zone.end,
        range_size_bytes: zone.end.saturating_sub(zone.start),
        ..ZoneBacking::default()
    };
    let mut current = None;
    let mut overlaps = false;
    for line in text.lines() {
        if let Some(range) = parse_smaps_header(line) {
            current = Some(range);
            overlaps = range.overlap(zone) > 0;
            if overlaps && result.containing_vma_start.is_none() {
                result.containing_vma_start = Some(range.start);
                result.containing_vma_end = Some(range.end);
            }
            continue;
        }
        if !overlaps || current.is_none() {
            continue;
        }
        let (key, value) = line.split_once(':').unwrap_or((line, ""));
        let kib = || {
            value
                .split_whitespace()
                .next()
                .and_then(|item| item.parse().ok())
        };
        match key {
            "Size" => result.size_kib = result.size_kib.saturating_add(kib().unwrap_or(0)),
            "Rss" => result.rss_kib = result.rss_kib.saturating_add(kib().unwrap_or(0)),
            "Pss" => result.pss_kib = result.pss_kib.saturating_add(kib().unwrap_or(0)),
            "Swap" => result.swap_kib = result.swap_kib.saturating_add(kib().unwrap_or(0)),
            "KernelPageSize" => result.kernel_page_size_kib = kib(),
            "MMUPageSize" => result.mmu_page_size_kib = kib(),
            "AnonHugePages" => {
                result.anon_huge_pages_kib = result
                    .anon_huge_pages_kib
                    .saturating_add(kib().unwrap_or(0));
            }
            "THPeligible" => {
                result.thp_eligible = value.split_whitespace().next().map(|item| item == "1");
            }
            "VmFlags" => {
                result
                    .vm_flags
                    .extend(value.split_whitespace().map(str::to_owned));
            }
            _ => {}
        }
    }
    result.vm_flags.sort();
    result.vm_flags.dedup();
    result.containing_vma_size_kib = result.size_kib;
    result.backing = (if result.anon_huge_pages_kib > 0 {
        if result.kernel_page_size_kib == Some(4) {
            "mixed_or_thp"
        } else {
            "thp"
        }
    } else if result.kernel_page_size_kib == Some(4) && result.mmu_page_size_kib == Some(4) {
        "4k"
    } else {
        "unknown"
    })
    .to_owned();
    Ok(result)
}

fn parse_smaps_header(line: &str) -> Option<AddressRange> {
    let token = line.split_whitespace().next()?;
    let (start, end) = token.split_once('-')?;
    Some(AddressRange {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
    })
}

impl InitialRegionPlan {
    pub fn new(
        mut ranges: Vec<AddressRange>,
        mapped_ranges: &[AddressRange],
    ) -> Result<Self, DamonError> {
        if ranges.len() != 3 {
            return Err(DamonError::Invalid(
                "validation requires exactly three initial regions".to_owned(),
            ));
        }
        ranges.sort_by_key(|range| range.start);
        for (index, range) in ranges.iter().enumerate() {
            if range.start >= range.end {
                return Err(DamonError::Invalid("initial region is empty".to_owned()));
            }
            if index > 0 && ranges[index - 1].end > range.start {
                return Err(DamonError::Invalid(
                    "initial regions must not overlap".to_owned(),
                ));
            }
            if !mapped_ranges
                .iter()
                .any(|mapping| mapping.start <= range.start && mapping.end >= range.end)
            {
                return Err(DamonError::Invalid(
                    "initial region is outside target mappings".to_owned(),
                ));
            }
        }
        Ok(Self { ranges })
    }

    #[must_use]
    pub fn matches_readback(&self, readback: &[AddressRange]) -> bool {
        self.ranges == readback
    }

    #[must_use]
    pub fn requested_bytes(&self) -> u64 {
        self.ranges.iter().fold(0_u64, |sum, range| {
            sum.saturating_add(range.end - range.start)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZoneStatistics {
    pub windows_observed: u64,
    pub region_samples: u64,
    pub overlap_sample_bytes: u64,
    pub snapshot_overlap_bytes_median: u64,
    pub normalized_ratio_mean: f64,
    pub normalized_ratio_p25: f64,
    pub normalized_ratio_p50: f64,
    pub normalized_ratio_p75: f64,
    pub normalized_ratio_p95: f64,
    pub age_mean: f64,
    pub confidence: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowZoneDiagnostic {
    pub window_index: u64,
    pub region_count: u64,
    pub observed_bytes: u64,
    pub target_overlap_bytes: u64,
    pub outside_requested_bytes: u64,
    pub hot_overlap_bytes: u64,
    pub warm_overlap_bytes: u64,
    pub cold_overlap_bytes: u64,
    pub hot_normalized_ratio: f64,
    pub warm_normalized_ratio: f64,
    pub cold_normalized_ratio: f64,
    pub hot_raw_accesses: u64,
    pub warm_raw_accesses: u64,
    pub cold_raw_accesses: u64,
    pub hot_overlapping_regions: u64,
    pub warm_overlapping_regions: u64,
    pub cold_overlapping_regions: u64,
    pub expected_samples_per_region: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalEvidence {
    pub hot: ZoneStatistics,
    pub warm: ZoneStatistics,
    pub cold: ZoneStatistics,
    pub other_region_samples: u64,
    pub region_sample_bytes: u64,
    pub snapshot_observed_bytes_median: u64,
    pub requested_target_bytes: u64,
    pub observed_target_bytes_per_snapshot: u64,
    pub outside_requested_bytes: u64,
    pub outside_requested_ratio: f64,
    pub target_isolated: bool,
    pub window_diagnostics: Vec<WindowZoneDiagnostic>,
    pub hot_cold_margin: f64,
    pub warm_cold_margin: f64,
    pub hot_cold_distinguished: bool,
    pub warm_coherent: bool,
    pub accepted: bool,
    pub reasons: Vec<String>,
}

pub fn analyze_zones(
    windows: &[Vec<TraceRegion>],
    attrs: &MonitoringAttrs,
    hot: AddressRange,
    warm: AddressRange,
    cold: AddressRange,
) -> SignalEvidence {
    let requested_target_bytes = [hot, warm, cold].iter().fold(0_u64, |sum, range| {
        sum.saturating_add(range.end.saturating_sub(range.start))
    });
    let mut hot_acc = ZoneAccumulator::default();
    let mut warm_acc = ZoneAccumulator::default();
    let mut cold_acc = ZoneAccumulator::default();
    let mut other = 0_u64;
    let mut region_sample_bytes = 0_u64;
    let mut footprints = Vec::new();
    let mut target_footprints = Vec::new();
    let mut outside_footprints = Vec::new();
    let mut window_diagnostics = Vec::new();
    for (window_index, window) in windows.iter().enumerate() {
        let mut footprint = 0_u64;
        let mut hot_snapshot = 0_u64;
        let mut warm_snapshot = 0_u64;
        let mut cold_snapshot = 0_u64;
        let mut hot_window = WindowAccumulator::default();
        let mut warm_window = WindowAccumulator::default();
        let mut cold_window = WindowAccumulator::default();
        for region in window {
            let range = AddressRange {
                start: region.start,
                end: region.end,
            };
            let size = region.end.saturating_sub(region.start);
            footprint = footprint.saturating_add(size);
            region_sample_bytes = region_sample_bytes.saturating_add(size);
            let ratio = normalized_ratio(region.nr_accesses, attrs.expected_samples());
            let hot_overlap = range.overlap(hot);
            let warm_overlap = range.overlap(warm);
            let cold_overlap = range.overlap(cold);
            if hot_overlap + warm_overlap + cold_overlap == 0 {
                other = other.saturating_add(1);
            }
            hot_acc.push(hot_overlap, size, ratio, region.age);
            warm_acc.push(warm_overlap, size, ratio, region.age);
            cold_acc.push(cold_overlap, size, ratio, region.age);
            hot_window.push(hot_overlap, size, ratio, region.nr_accesses);
            warm_window.push(warm_overlap, size, ratio, region.nr_accesses);
            cold_window.push(cold_overlap, size, ratio, region.nr_accesses);
            hot_snapshot = hot_snapshot.saturating_add(hot_overlap);
            warm_snapshot = warm_snapshot.saturating_add(warm_overlap);
            cold_snapshot = cold_snapshot.saturating_add(cold_overlap);
        }
        footprints.push(footprint);
        let target = hot_snapshot
            .saturating_add(warm_snapshot)
            .saturating_add(cold_snapshot);
        let outside = footprint.saturating_sub(target);
        target_footprints.push(target);
        outside_footprints.push(outside);
        window_diagnostics.push(WindowZoneDiagnostic {
            window_index: window_index as u64,
            region_count: window.len() as u64,
            observed_bytes: footprint,
            target_overlap_bytes: target,
            outside_requested_bytes: outside,
            hot_overlap_bytes: hot_snapshot,
            warm_overlap_bytes: warm_snapshot,
            cold_overlap_bytes: cold_snapshot,
            hot_normalized_ratio: hot_window.ratio(),
            warm_normalized_ratio: warm_window.ratio(),
            cold_normalized_ratio: cold_window.ratio(),
            hot_raw_accesses: hot_window.raw_accesses,
            warm_raw_accesses: warm_window.raw_accesses,
            cold_raw_accesses: cold_window.raw_accesses,
            hot_overlapping_regions: hot_window.regions,
            warm_overlapping_regions: warm_window.regions,
            cold_overlapping_regions: cold_window.regions,
            expected_samples_per_region: attrs.expected_samples(),
        });
        hot_acc.window_ratios.push(hot_window.ratio());
        warm_acc.window_ratios.push(warm_window.ratio());
        cold_acc.window_ratios.push(cold_window.ratio());
        hot_acc.snapshots.push(hot_snapshot);
        warm_acc.snapshots.push(warm_snapshot);
        cold_acc.snapshots.push(cold_snapshot);
    }
    let hot = hot_acc.finish(windows.len());
    let warm = warm_acc.finish(windows.len());
    let cold = cold_acc.finish(windows.len());
    let snapshot_observed_bytes_median = median_u64(&mut footprints);
    let observed_target_bytes_per_snapshot = median_u64(&mut target_footprints);
    let outside_requested_bytes = median_u64(&mut outside_footprints);
    let outside_requested_ratio = if snapshot_observed_bytes_median == 0 {
        0.0
    } else {
        outside_requested_bytes as f64 / snapshot_observed_bytes_median as f64
    };
    let target_isolated = observed_target_bytes_per_snapshot > 0 && outside_requested_ratio <= 0.50;
    let hot_cold_margin = hot.normalized_ratio_p50 - cold.normalized_ratio_p50;
    let warm_cold_margin = warm.normalized_ratio_mean - cold.normalized_ratio_mean;
    let enough_windows = windows.len() >= 3;
    let all_overlap = hot.region_samples > 0 && warm.region_samples > 0 && cold.region_samples > 0;
    let hot_cold_distinguished =
        hot_cold_margin >= 0.10 && hot.normalized_ratio_mean > cold.normalized_ratio_mean + 0.10;
    let warm_coherent =
        warm_cold_margin >= 0.02 && hot.normalized_ratio_mean > warm.normalized_ratio_mean;
    let mut reasons = Vec::new();
    if !enough_windows {
        reasons.push("missing_aggregation_windows".to_owned());
    }
    if !all_overlap {
        reasons.push("missing_zone_overlap".to_owned());
    }
    if !target_isolated {
        reasons.push("target_regions_not_isolated".to_owned());
    }
    if !hot_cold_distinguished {
        reasons.push("hot_not_distinguished_from_cold".to_owned());
    }
    if !warm_coherent {
        reasons.push("warm_not_coherent".to_owned());
    }
    SignalEvidence {
        hot,
        warm,
        cold,
        other_region_samples: other,
        region_sample_bytes,
        snapshot_observed_bytes_median,
        requested_target_bytes,
        observed_target_bytes_per_snapshot,
        outside_requested_bytes,
        outside_requested_ratio,
        target_isolated,
        window_diagnostics,
        hot_cold_margin,
        warm_cold_margin,
        hot_cold_distinguished,
        warm_coherent,
        accepted: reasons.is_empty(),
        reasons,
    }
}

pub fn group_aggregation_windows(regions: Vec<TraceRegion>) -> Vec<Vec<TraceRegion>> {
    let mut windows = Vec::new();
    let mut current = Vec::new();
    let mut expected = 0_usize;
    for region in regions {
        if current.is_empty() {
            expected = region.nr_regions as usize;
        }
        if expected == 0 || region.nr_regions as usize != expected {
            current.clear();
            expected = region.nr_regions as usize;
        }
        current.push(region);
        if current.len() == expected {
            windows.push(std::mem::take(&mut current));
            expected = 0;
        }
    }
    windows
}

#[derive(Default)]
struct ZoneAccumulator {
    weighted_ratio: f64,
    weighted_age: f64,
    quality_weight: f64,
    overlap_bytes: u64,
    samples: u64,
    window_ratios: Vec<f64>,
    snapshots: Vec<u64>,
}

impl ZoneAccumulator {
    fn push(&mut self, overlap: u64, region_size: u64, ratio: f64, age: u64) {
        if overlap == 0 || region_size == 0 {
            return;
        }
        // A tiny intersection with a large adaptive region is weak evidence.
        // Multiplying by overlap_fraction prevents that region-wide access
        // frequency from dominating a synthetic zone.
        let quality_weight = overlap as f64 * overlap as f64 / region_size as f64;
        self.weighted_ratio += ratio * quality_weight;
        self.weighted_age += age as f64 * quality_weight;
        self.overlap_bytes = self.overlap_bytes.saturating_add(overlap);
        self.quality_weight += quality_weight;
        self.samples = self.samples.saturating_add(1);
    }

    fn finish(mut self, windows: usize) -> ZoneStatistics {
        self.window_ratios.sort_by(f64::total_cmp);
        ZoneStatistics {
            windows_observed: windows as u64,
            region_samples: self.samples,
            overlap_sample_bytes: self.overlap_bytes,
            snapshot_overlap_bytes_median: median_u64(&mut self.snapshots),
            normalized_ratio_mean: if self.quality_weight == 0.0 {
                0.0
            } else {
                self.weighted_ratio / self.quality_weight
            },
            normalized_ratio_p25: percentile(&self.window_ratios, 25),
            normalized_ratio_p50: percentile(&self.window_ratios, 50),
            normalized_ratio_p75: percentile(&self.window_ratios, 75),
            normalized_ratio_p95: percentile(&self.window_ratios, 95),
            age_mean: if self.quality_weight == 0.0 {
                0.0
            } else {
                self.weighted_age / self.quality_weight
            },
            confidence: if windows >= 5 && self.samples >= 5 {
                "bounded"
            } else {
                "low"
            }
            .to_owned(),
        }
    }
}

#[derive(Default)]
struct WindowAccumulator {
    weighted_ratio: f64,
    quality_weight: f64,
    raw_accesses: u64,
    regions: u64,
}

impl WindowAccumulator {
    fn push(&mut self, overlap: u64, region_size: u64, ratio: f64, raw_accesses: u64) {
        if overlap == 0 || region_size == 0 {
            return;
        }
        let quality_weight = overlap as f64 * overlap as f64 / region_size as f64;
        self.weighted_ratio += ratio * quality_weight;
        self.quality_weight += quality_weight;
        self.raw_accesses = self.raw_accesses.saturating_add(raw_accesses);
        self.regions = self.regions.saturating_add(1);
    }

    fn ratio(&self) -> f64 {
        if self.quality_weight == 0.0 {
            0.0
        } else {
            self.weighted_ratio / self.quality_weight
        }
    }
}

fn normalized_ratio(accesses: u64, expected: u64) -> f64 {
    if expected == 0 {
        0.0
    } else {
        (accesses as f64 / expected as f64).clamp(0.0, 1.0)
    }
}

fn percentile(values: &[f64], percentile: usize) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values[(values.len() - 1) * percentile / 100]
}

fn median_u64(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[(values.len() - 1) / 2]
}

pub fn parse_aggregated(line: &str) -> Result<TraceRegion, DamonError> {
    let payload = line
        .split_once("damon_aggregated:")
        .map_or(line, |(_, value)| value);
    let mut values = BTreeMap::new();
    for token in payload.split_whitespace() {
        if let Some((key, value)) = token.trim_matches(',').split_once('=') {
            values.insert(key, value.trim_matches(','));
        }
    }
    let number = |names: &[&str]| -> Result<u64, DamonError> {
        let value = names
            .iter()
            .find_map(|name| values.get(name))
            .ok_or_else(|| DamonError::Invalid(format!("missing {}", names[0])))?;
        if let Some(hex) = value.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
        } else {
            value.parse::<u64>()
        }
        .map_err(|_| DamonError::Invalid(format!("invalid {}", names[0])))
    };
    if !values.contains_key("start") {
        return parse_positional_aggregated(payload, &values);
    }
    let result = TraceRegion {
        target_id: number(&["target_id", "target_idx"])?,
        nr_regions: u32::try_from(number(&["nr_regions"])?)
            .map_err(|_| DamonError::Invalid("nr_regions overflow".to_owned()))?,
        start: number(&["start"])?,
        end: number(&["end"])?,
        nr_accesses: number(&["nr_accesses", "accesses"])?,
        age: number(&["age"])?,
    };
    if result.end <= result.start {
        return Err(DamonError::Invalid("region range is empty".to_owned()));
    }
    Ok(result)
}

fn parse_positional_aggregated(
    payload: &str,
    values: &BTreeMap<&str, &str>,
) -> Result<TraceRegion, DamonError> {
    let target_id = values
        .get("target_id")
        .or_else(|| values.get("target_idx"))
        .ok_or_else(|| DamonError::Invalid("missing target_id".to_owned()))?
        .parse()
        .map_err(|_| DamonError::Invalid("invalid target_id".to_owned()))?;
    let nr_regions = values
        .get("nr_regions")
        .ok_or_else(|| DamonError::Invalid("missing nr_regions".to_owned()))?
        .parse()
        .map_err(|_| DamonError::Invalid("invalid nr_regions".to_owned()))?;
    let tokens: Vec<_> = payload.split_whitespace().collect();
    let range_index = tokens
        .iter()
        .position(|token| token.ends_with(':') && token.contains('-'))
        .ok_or_else(|| DamonError::Invalid("missing region range".to_owned()))?;
    let range = tokens[range_index].trim_end_matches(':');
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| DamonError::Invalid("invalid region range".to_owned()))?;
    let parse_address = |value: &str| {
        value
            .parse::<u64>()
            .or_else(|_| u64::from_str_radix(value.trim_start_matches("0x"), 16))
            .map_err(|_| DamonError::Invalid("invalid region address".to_owned()))
    };
    let result = TraceRegion {
        target_id,
        nr_regions,
        start: parse_address(start)?,
        end: parse_address(end)?,
        nr_accesses: tokens
            .get(range_index + 1)
            .ok_or_else(|| DamonError::Invalid("missing nr_accesses".to_owned()))?
            .parse()
            .map_err(|_| DamonError::Invalid("invalid nr_accesses".to_owned()))?,
        age: tokens
            .get(range_index + 2)
            .ok_or_else(|| DamonError::Invalid("missing age".to_owned()))?
            .parse()
            .map_err(|_| DamonError::Invalid("invalid age".to_owned()))?,
    };
    if result.end <= result.start {
        return Err(DamonError::Invalid("region range is empty".to_owned()));
    }
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationalLabel {
    Hot,
    Warm,
    Cold,
    InsufficientHistory,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DamonRegionSample {
    pub schema_version: String,
    pub session_id: String,
    pub timestamp_ns: u64,
    pub target_id: u64,
    pub pid: u32,
    pub stable_identity: String,
    pub region_start: u64,
    pub region_end: u64,
    pub region_size: u64,
    pub hot_overlap_bytes: u64,
    pub warm_overlap_bytes: u64,
    pub cold_overlap_bytes: u64,
    pub hot_overlap_fraction: f64,
    pub warm_overlap_fraction: f64,
    pub cold_overlap_fraction: f64,
    pub other_bytes: u64,
    pub nr_accesses: u64,
    pub age: u64,
    pub sample_us: u64,
    pub aggr_us: u64,
    pub update_us: u64,
    pub expected_samples: u64,
    pub normalized_access_ratio: f64,
    pub observational_label: ObservationalLabel,
    pub label_rule_version: String,
    pub confidence: String,
    pub evidence: Vec<String>,
    pub source: String,
    pub kernel: String,
    pub operation_set: String,
}

pub fn normalize(
    region: &TraceRegion,
    attrs: &MonitoringAttrs,
    history_windows: usize,
) -> DamonRegionSample {
    let expected = attrs.expected_samples();
    let ratio = if expected == 0 {
        0.0
    } else {
        (region.nr_accesses as f64 / expected as f64).clamp(0.0, 1.0)
    };
    let label = if history_windows < 3 {
        ObservationalLabel::InsufficientHistory
    } else if ratio >= 0.70 {
        ObservationalLabel::Hot
    } else if ratio >= 0.20 {
        ObservationalLabel::Warm
    } else {
        ObservationalLabel::Cold
    };
    DamonRegionSample {
        schema_version: DATASET_SCHEMA_VERSION.to_owned(),
        session_id: String::new(),
        timestamp_ns: 0,
        target_id: region.target_id,
        pid: 0,
        stable_identity: String::new(),
        region_start: region.start,
        region_end: region.end,
        region_size: region.end - region.start,
        hot_overlap_bytes: 0,
        warm_overlap_bytes: 0,
        cold_overlap_bytes: 0,
        hot_overlap_fraction: 0.0,
        warm_overlap_fraction: 0.0,
        cold_overlap_fraction: 0.0,
        other_bytes: region.end - region.start,
        nr_accesses: region.nr_accesses,
        age: region.age,
        sample_us: attrs.sample_us,
        aggr_us: attrs.aggr_us,
        update_us: attrs.update_us,
        expected_samples: expected,
        normalized_access_ratio: ratio,
        observational_label: label,
        label_rule_version: LABEL_RULE_VERSION.to_owned(),
        confidence: if history_windows >= 3 {
            "bounded"
        } else {
            "low"
        }
        .to_owned(),
        evidence: vec![format!("history_windows={history_windows}")],
        source: "damon_aggregated".to_owned(),
        kernel: String::new(),
        operation_set: attrs.operation.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverheadSample {
    pub kdamond_cpu_percent: f64,
    pub capture_cpu_percent: f64,
    pub target_slowdown_percent: f64,
    pub events_per_second: f64,
    pub regions_per_second: f64,
    pub dropped_samples: u64,
}

pub fn overhead_allowed(
    sample: &OverheadSample,
    config: &DamonConfig,
    safety_ceiling: f64,
) -> bool {
    let total = sample.kdamond_cpu_percent + sample.capture_cpu_percent;
    total.is_finite()
        && total <= config.max_cpu_overhead_percent
        && config.max_cpu_overhead_percent <= safety_ceiling
        && sample.dropped_samples == 0
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DamonReport {
    pub capability: DamonCapability,
    pub source: String,
    pub session_state: String,
    pub attrs_requested: Option<MonitoringAttrs>,
    pub attrs_effective: Option<MonitoringAttrs>,
    pub snapshots: u64,
    pub regions: u64,
    pub observed_bytes: u64,
    pub hot_bytes: u64,
    pub warm_bytes: u64,
    pub cold_bytes: u64,
    pub stable_cold_fraction: Option<f64>,
    pub event_rate: Option<f64>,
    pub overhead: Option<OverheadSample>,
    pub dropped_samples: u64,
    pub confidence: String,
    pub errors: Vec<String>,
    pub zero_damos: bool,
    pub dry_run: bool,
}

pub fn observe_report(config: &DamonConfig, kernel: Option<String>) -> DamonReport {
    let capability = inspect_linux(Path::new("/"), kernel);
    DamonReport {
        source: if capability.aggregated_tracepoint_available {
            "available_not_owned"
        } else {
            "capability_inventory"
        }
        .to_owned(),
        session_state: if capability.active_external_session {
            "external"
        } else {
            "not_configured"
        }
        .to_owned(),
        capability,
        attrs_requested: None,
        attrs_effective: None,
        snapshots: 0,
        regions: 0,
        observed_bytes: 0,
        hot_bytes: 0,
        warm_bytes: 0,
        cold_bytes: 0,
        stable_cold_fraction: None,
        event_rate: None,
        overhead: None,
        dropped_samples: 0,
        confidence: "none".to_owned(),
        errors: if config.enabled {
            vec!["normal daemon never starts a DAMON session".to_owned()]
        } else {
            Vec::new()
        },
        zero_damos: true,
        dry_run: true,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Jsonl,
    Csv,
}

pub fn export_dataset(
    path: &Path,
    format: ExportFormat,
    records: &[DamonRegionSample],
    max_bytes: u64,
) -> Result<u64, DamonError> {
    validate_export_path(path)?;
    let mut output = Vec::new();
    match format {
        ExportFormat::Jsonl => {
            for record in records {
                serde_json::to_writer(&mut output, record)?;
                output.push(b'\n');
            }
        }
        ExportFormat::Csv => {
            output.extend_from_slice(b"schema_version,session_id,timestamp_ns,target_id,pid,stable_identity,region_start,region_end,region_size,hot_overlap_bytes,warm_overlap_bytes,cold_overlap_bytes,hot_overlap_fraction,warm_overlap_fraction,cold_overlap_fraction,other_bytes,nr_accesses,age,sample_us,aggr_us,update_us,expected_samples,normalized_access_ratio,label,rule_version,confidence,source,kernel,operation_set\n");
            for value in records {
                let line = format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{:.6},{:.6},{:.6},{},{},{},{},{},{},{},{:.6},{:?},{},{},{},{},{}\n",
                    value.schema_version,
                    value.session_id,
                    value.timestamp_ns,
                    value.target_id,
                    value.pid,
                    value.stable_identity,
                    value.region_start,
                    value.region_end,
                    value.region_size,
                    value.hot_overlap_bytes,
                    value.warm_overlap_bytes,
                    value.cold_overlap_bytes,
                    value.hot_overlap_fraction,
                    value.warm_overlap_fraction,
                    value.cold_overlap_fraction,
                    value.other_bytes,
                    value.nr_accesses,
                    value.age,
                    value.sample_us,
                    value.aggr_us,
                    value.update_us,
                    value.expected_samples,
                    value.normalized_access_ratio,
                    value.observational_label,
                    value.label_rule_version,
                    value.confidence,
                    value.source,
                    value.kernel,
                    value.operation_set
                );
                output.extend_from_slice(line.as_bytes());
            }
        }
    }
    if output.len() as u64 > max_bytes {
        return Err(DamonError::Invalid(
            "export exceeds configured bound".to_owned(),
        ));
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&output)?;
    Ok(output.len() as u64)
}

fn validate_export_path(path: &Path) -> Result<(), DamonError> {
    if !path.is_absolute()
        || path.exists()
        || path
            .components()
            .any(|item| matches!(item, Component::ParentDir | Component::CurDir))
    {
        return Err(DamonError::Invalid("unsafe export path".to_owned()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| DamonError::Invalid("export parent is missing".to_owned()))?;
    let canonical = fs::canonicalize(parent)?;
    if canonical != parent {
        return Err(DamonError::Invalid(
            "export parent is not canonical".to_owned(),
        ));
    }
    Ok(())
}

fn resolve(root: &Path, absolute: &str) -> PathBuf {
    root.join(absolute.trim_start_matches('/'))
}

fn read_u32(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn read_bool(path: &Path) -> Option<bool> {
    match fs::read_to_string(path).ok()?.trim() {
        "Y" | "y" | "1" => Some(true),
        "N" | "n" | "0" => Some(false),
        _ => None,
    }
}

fn contains_file(root: &Path, name: &str) -> bool {
    fn visit(path: &Path, name: &str, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        fs::read_dir(path).ok().is_some_and(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                entry.file_name() == name
                    || (entry.file_type().is_ok_and(|kind| kind.is_dir())
                        && visit(&entry.path(), name, depth + 1))
            })
        })
    }
    visit(root, name, 0)
}

#[cfg(test)]
mod tests;
