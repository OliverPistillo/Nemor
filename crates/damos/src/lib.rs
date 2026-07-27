#![forbid(unsafe_code)]

use nemor_damon::AddressRange;
use policy_engine::PressureState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

pub const RULE_VERSION: &str = "damos-controlled-reclaim-v1";
pub const REPORT_SCHEMA: &str = "nemor-damos-report-v1";
pub const AUDIT_REASON: &str = "damos_plan_only_audit";
pub const VALIDATION_TIME_QUOTA_MS: u64 = 5;
pub const VALIDATION_BYTE_QUOTA: u64 = 8 * 1024 * 1024;
pub const VALIDATION_RESET_INTERVAL_MS: u64 = 10_000;
pub const VALIDATION_TOTAL_APPLIED_CEILING: u64 = 16 * 1024 * 1024;
pub const VALIDATION_LIVE_MONITOR_MS: u64 = 4_000;
pub const VALIDATION_LIVE_DEADLINE_MS: u64 = 5_000;
pub const VALIDATION_MAX_NR_SNAPSHOTS: u64 = 5;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DamosError {
    #[error("invalid DAMOS plan: {0}")]
    Invalid(String),
    #[error("mandatory DAMOS capability missing: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DamosAction {
    Stat,
    Pageout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DamosCapability {
    pub supported: bool,
    pub vaddr: Option<bool>,
    pub actions: BTreeSet<String>,
    pub scheme_fields: BTreeMap<String, bool>,
    pub quota_fields: BTreeMap<String, bool>,
    pub filter_types: BTreeSet<String>,
    pub stats_fields: BTreeMap<String, bool>,
    pub address_fence_supported: bool,
    pub filter_allow_supported: bool,
    pub max_nr_snapshots_supported: bool,
    pub external_session_conflict: bool,
    pub special_module_conflict: bool,
    pub notes: Vec<String>,
}

impl DamosCapability {
    pub fn live_pageout_ready(&self) -> Result<(), DamosError> {
        if !self.supported || self.vaddr != Some(true) || !self.actions.contains("pageout") {
            return Err(DamosError::Unsupported("vaddr pageout".into()));
        }
        for field in ["ms", "bytes", "reset_interval_ms"] {
            if !self.quota_fields.get(field).copied().unwrap_or(false) {
                return Err(DamosError::Unsupported(format!("quota.{field}")));
            }
        }
        if !self.address_fence_supported {
            return Err(DamosError::Unsupported("core addr filter".into()));
        }
        if self.external_session_conflict || self.special_module_conflict {
            return Err(DamosError::Unsupported("external DAMON conflict".into()));
        }
        Ok(())
    }
}

#[must_use]
pub fn inspect_scheme_root(
    root: &Path,
    vaddr: bool,
    external: bool,
    conflict: bool,
) -> DamosCapability {
    let exists = |relative: &str| root.join(relative).exists();
    let read_words = |relative: &str| -> BTreeSet<String> {
        std::fs::read_to_string(root.join(relative))
            .map(|value| value.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default()
    };
    let mut actions = read_words("avail_actions");
    if actions.is_empty() {
        actions = read_words("action")
            .into_iter()
            .map(|word| word.trim_matches(['[', ']']).to_owned())
            .collect();
    }
    let filter_types = read_words("filters/avail_types");
    let scheme_fields = [
        "action",
        "apply_interval_us",
        "access_pattern",
        "quotas",
        "watermarks",
        "filters",
        "stats",
    ]
    .into_iter()
    .map(|name| (name.into(), exists(name)))
    .collect();
    let quota_fields = [
        "ms",
        "bytes",
        "reset_interval_ms",
        "effective_bytes",
        "weights",
        "goals",
    ]
    .into_iter()
    .map(|name| (name.into(), exists(&format!("quotas/{name}"))))
    .collect();
    let stats_fields = [
        "nr_tried",
        "sz_tried",
        "nr_applied",
        "sz_applied",
        "sz_ops_filter_passed",
        "qt_exceeds",
        "nr_snapshots",
        "max_nr_snapshots",
    ]
    .into_iter()
    .map(|name| (name.into(), exists(&format!("stats/{name}"))))
    .collect();
    DamosCapability {
        supported: root.is_dir(),
        vaddr: Some(vaddr),
        actions,
        scheme_fields,
        quota_fields,
        address_fence_supported: filter_types.contains("addr"),
        filter_allow_supported: [
            "core_filters/0/allow",
            "ops_filters/0/allow",
            "filters/0/allow",
        ]
        .into_iter()
        .any(&exists),
        filter_types,
        stats_fields,
        max_nr_snapshots_supported: exists("stats/max_nr_snapshots"),
        external_session_conflict: external,
        special_module_conflict: conflict,
        notes: Vec::new(),
    }
}

#[must_use]
pub fn observe_capability(damon: &nemor_damon::DamonCapability) -> DamosCapability {
    DamosCapability {
        supported: damon.supported,
        vaddr: (!damon.available_operations.is_empty()).then_some(damon.vaddr_supported),
        external_session_conflict: damon.active_external_session,
        special_module_conflict: damon.special_module_conflict,
        notes: vec![
            "scheme/action/filter capability requires an owned manual validation allocation".into(),
        ],
        ..DamosCapability::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StableTargetIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub stable_key: String,
    pub owned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdObservation {
    pub complete: bool,
    pub nr_accesses: u64,
    pub age: u64,
    pub range: AddressRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DamosQuota {
    pub time_ms: u64,
    pub bytes: u64,
    pub reset_interval_ms: u64,
    pub total_applied_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusiveRange {
    pub min: u64,
    pub max: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPattern {
    pub size: InclusiveRange,
    pub nr_accesses: InclusiveRange,
    pub age: InclusiveRange,
}

impl AccessPattern {
    #[must_use]
    pub fn validation_cold() -> Self {
        Self {
            size: InclusiveRange {
                min: 0,
                max: u64::MAX,
            },
            nr_accesses: InclusiveRange { min: 0, max: 0 },
            age: InclusiveRange {
                min: 3,
                max: u64::MAX,
            },
        }
    }

    #[must_use]
    pub fn configured_age_min(&self) -> u64 {
        self.age.min
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringIntervals {
    pub sample_us: u64,
    pub aggr_us: u64,
    pub update_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Readback<T> {
    pub requested: T,
    pub effective: T,
    pub readback: bool,
}

impl DamosQuota {
    pub fn validate(&self, max_time_ms: u64, max_bytes: u64) -> Result<(), DamosError> {
        if self.time_ms == 0 && self.bytes == 0 {
            return Err(DamosError::Invalid(
                "time and byte quotas cannot both be zero".into(),
            ));
        }
        if self.time_ms > max_time_ms || self.bytes > max_bytes {
            return Err(DamosError::Invalid(
                "quota exceeds absolute configuration ceiling".into(),
            ));
        }
        if self.reset_interval_ms == 0 || self.total_applied_bytes < self.bytes {
            return Err(DamosError::Invalid("invalid reset/total quota".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityInput {
    pub identity: Option<StableTargetIdentity>,
    pub identity_fresh: bool,
    pub background: bool,
    pub foreground: bool,
    pub gaming: bool,
    pub critical: bool,
    pub protected: bool,
    pub known_classification: bool,
    pub pressure: PressureState,
    pub cold_observations: Vec<ColdObservation>,
    pub valid_age_evidence: bool,
    pub recent_refault: bool,
    pub blacklisted: bool,
    pub safety_conflict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanDisposition {
    Eligible,
    Rejected,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EligibilityDecision {
    pub disposition: PlanDisposition,
    pub reasons: Vec<String>,
    pub rule_version: String,
}

#[must_use]
pub fn evaluate_eligibility(input: &EligibilityInput) -> EligibilityDecision {
    let mut reasons = Vec::new();
    match &input.identity {
        Some(identity)
            if identity.owned && identity.pid != 1 && !identity.stable_key.is_empty() => {}
        _ => reasons.push("unknown_identity".into()),
    }
    if !input.identity_fresh {
        reasons.push("stale_identity".into());
    }
    if !input.known_classification || !input.background {
        reasons.push("unknown_or_non_background".into());
    }
    if input.foreground {
        reasons.push("foreground_protected".into());
    }
    if input.gaming {
        reasons.push("gaming_protected".into());
    }
    if input.critical {
        reasons.push("critical_protected".into());
    }
    if input.protected {
        reasons.push("protected_target".into());
    }
    if matches!(
        input.pressure,
        PressureState::Normal | PressureState::Watch | PressureState::Stabilizing
    ) {
        reasons.push("not_under_eligible_pressure".into());
    }
    let consecutive = input
        .cold_observations
        .iter()
        .rev()
        .take_while(|item| item.complete && item.nr_accesses == 0)
        .count();
    if consecutive < 3 || !input.valid_age_evidence {
        reasons.push("insufficient_cold_evidence".into());
    }
    if input.recent_refault || input.blacklisted {
        reasons.push("early_refault_blacklist".into());
    }
    if input.safety_conflict {
        reasons.push("safety_conflict".into());
    }
    EligibilityDecision {
        disposition: if reasons.is_empty() {
            PlanDisposition::Eligible
        } else {
            PlanDisposition::Rejected
        },
        reasons,
        rule_version: RULE_VERSION.into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterApi {
    LegacyMatchingOnly,
    MatchingAllow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressFence {
    pub range: AddressRange,
    pub layer: String,
    pub filter_type: String,
    pub api: FilterApi,
    pub matching: bool,
    pub allow: Option<bool>,
}

impl AddressFence {
    pub fn validate(&self, cold: AddressRange) -> Result<(), DamosError> {
        let semantics = match self.api {
            FilterApi::MatchingAllow => self.matching && self.allow == Some(true),
            FilterApi::LegacyMatchingOnly => !self.matching && self.allow.is_none(),
        };
        if self.layer != "core" || self.filter_type != "addr" || !semantics || self.range != cold {
            return Err(DamosError::Invalid(
                "address fence does not exactly match COLD".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn allows(&self, address: u64) -> bool {
        self.validate(self.range).is_ok() && self.range.start <= address && address < self.range.end
    }
}

pub fn validate_attempt2_bounds(
    _pattern: &AccessPattern,
    quota: &DamosQuota,
    apply_interval_us: u64,
    live_deadline_ms: u64,
    max_nr_snapshots: u64,
) -> Result<(), DamosError> {
    if live_deadline_ms == 0 || live_deadline_ms >= quota.reset_interval_ms {
        return Err(DamosError::Invalid(
            "quota reset interval must outlive live session".into(),
        ));
    }
    if max_nr_snapshots == 0 {
        return Err(DamosError::Invalid(
            "snapshot ceiling must be nonzero".into(),
        ));
    }
    let snapshot_runtime_us = max_nr_snapshots
        .checked_mul(apply_interval_us)
        .ok_or_else(|| DamosError::Invalid("snapshot runtime overflow".into()))?;
    if snapshot_runtime_us > live_deadline_ms.saturating_mul(1_000) {
        return Err(DamosError::Invalid(
            "snapshot ceiling does not fit live deadline".into(),
        ));
    }
    Ok(())
}

pub fn validate_attempt2_stats(
    stats: &DamosStats,
    max_nr_snapshots: u64,
) -> Result<(), DamosError> {
    if stats.max_nr_snapshots != Some(max_nr_snapshots) {
        return Err(DamosError::Unsupported(
            "secondary kernel snapshot ceiling readback".into(),
        ));
    }
    if stats
        .nr_snapshots
        .is_none_or(|value| value > max_nr_snapshots)
    {
        return Err(DamosError::Invalid(
            "kernel exceeded or did not report snapshot ceiling".into(),
        ));
    }
    if stats
        .sz_applied
        .is_some_and(|bytes| bytes > VALIDATION_BYTE_QUOTA)
    {
        return Err(DamosError::Invalid(
            "applied bytes exceed hard validation byte ceiling".into(),
        ));
    }
    Ok(())
}

#[must_use]
pub fn hard_byte_ceiling_respected(
    stats: &DamosStats,
    configured_bytes: u64,
    reset_interval_ms: u64,
    live_deadline_ms: u64,
) -> bool {
    let Some(sz_tried) = stats.sz_tried else {
        return false;
    };
    let Some(sz_applied) = stats.sz_applied else {
        return false;
    };
    reset_interval_ms > live_deadline_ms
        && sz_tried <= configured_bytes
        && sz_applied <= sz_tried
        && sz_applied <= configured_bytes
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DamosPlan {
    pub decision_id: String,
    pub plan_id: String,
    pub session_id: String,
    pub scheme_id: u32,
    pub target: StableTargetIdentity,
    pub action: DamosAction,
    pub pattern_accesses_min: u64,
    pub pattern_accesses_max: u64,
    pub pattern_age_min: u64,
    pub pattern_age_max: u64,
    pub apply_interval_us: u64,
    pub quota: DamosQuota,
    pub fence: AddressFence,
    pub max_nr_snapshots: Option<u64>,
    pub dry_run: bool,
}

impl DamosPlan {
    pub fn validate(&self, max_time_ms: u64, max_bytes: u64) -> Result<(), DamosError> {
        if self.decision_id.is_empty() || self.plan_id.is_empty() || self.session_id.is_empty() {
            return Err(DamosError::Invalid(
                "decision/plan/session link required".into(),
            ));
        }
        if !self.target.owned || self.target.pid == 1 || self.target.stable_key.is_empty() {
            return Err(DamosError::Invalid("stable owned target required".into()));
        }
        if self.pattern_accesses_min != 0
            || self.pattern_accesses_max != 0
            || self.pattern_age_min < 3
            || self.pattern_age_max < self.pattern_age_min
            || self.apply_interval_us == 0
        {
            return Err(DamosError::Invalid("unsafe access pattern".into()));
        }
        self.quota.validate(max_time_ms, max_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DamosStats {
    pub effective_quota_bytes: Option<u64>,
    pub nr_tried: Option<u64>,
    pub sz_tried: Option<u64>,
    pub nr_applied: Option<u64>,
    pub sz_applied: Option<u64>,
    pub sz_ops_filter_passed: Option<u64>,
    pub qt_exceeds: Option<u64>,
    pub nr_snapshots: Option<u64>,
    pub max_nr_snapshots: Option<u64>,
    pub tried_regions: Vec<AddressRange>,
    pub tried_region_samples: Vec<TriedRegionSample>,
    pub tried_regions_total_bytes: Option<u64>,
    pub first_tried_snapshot_index: Option<u64>,
    pub first_tried_region_age: Option<u64>,
    pub first_tried_timestamp_ns: Option<u128>,
    pub effective_quota_raw: Option<String>,
    pub effective_quota_interpretation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriedRegionSample {
    pub range: AddressRange,
    pub size: u64,
    pub nr_accesses: Option<u64>,
    pub age: Option<u64>,
    pub sz_filter_passed: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DamosBeforeApplyEvent {
    pub timestamp_ns: u128,
    pub context_idx: u32,
    pub scheme_idx: u32,
    pub target_idx: u32,
    pub nr_regions: u32,
    pub range: AddressRange,
    pub size: u64,
    pub nr_accesses: u64,
    pub age: u64,
}

pub fn parse_damos_before_apply(
    line: &str,
    timestamp_ns: u128,
) -> Result<DamosBeforeApplyEvent, DamosError> {
    let payload = line
        .split_once("damos_before_apply:")
        .map(|(_, payload)| payload.trim())
        .ok_or_else(|| DamosError::Invalid("missing damos_before_apply marker".into()))?;
    let mut fields = payload.split_whitespace();
    let parse_named = |token: Option<&str>, name: &str| -> Result<u64, DamosError> {
        token
            .and_then(|token| token.strip_prefix(&format!("{name}=")))
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| DamosError::Invalid(format!("invalid {name}")))
    };
    let context_idx = parse_named(fields.next(), "ctx_idx")?;
    let scheme_idx = parse_named(fields.next(), "scheme_idx")?;
    let target_idx = parse_named(fields.next(), "target_idx")?;
    let nr_regions = parse_named(fields.next(), "nr_regions")?;
    let range = fields
        .next()
        .and_then(|token| token.strip_suffix(':'))
        .and_then(|token| token.split_once('-'))
        .and_then(|(start, end)| Some((start.parse().ok()?, end.parse().ok()?)))
        .map(|(start, end)| AddressRange { start, end })
        .ok_or_else(|| DamosError::Invalid("invalid candidate range".into()))?;
    if range.start >= range.end {
        return Err(DamosError::Invalid("empty candidate range".into()));
    }
    let nr_accesses = fields
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| DamosError::Invalid("invalid candidate nr_accesses".into()))?;
    let age = fields
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| DamosError::Invalid("invalid candidate age".into()))?;
    Ok(DamosBeforeApplyEvent {
        timestamp_ns,
        context_idx: u32::try_from(context_idx)
            .map_err(|_| DamosError::Invalid("context index overflow".into()))?,
        scheme_idx: u32::try_from(scheme_idx)
            .map_err(|_| DamosError::Invalid("scheme index overflow".into()))?,
        target_idx: u32::try_from(target_idx)
            .map_err(|_| DamosError::Invalid("target index overflow".into()))?,
        nr_regions: u32::try_from(nr_regions)
            .map_err(|_| DamosError::Invalid("region count overflow".into()))?,
        range,
        size: range.end - range.start,
        nr_accesses,
        age,
    })
}

pub fn validate_shadow_candidates(
    candidates: &[DamosBeforeApplyEvent],
    hot: AddressRange,
    warm: AddressRange,
    cold: AddressRange,
    age_min: u64,
) -> Result<(), DamosError> {
    if candidates.is_empty() {
        return Err(DamosError::Invalid(
            "cumulative counters cannot replace candidate evidence".into(),
        ));
    }
    for candidate in candidates {
        if candidate.context_idx != 0 || candidate.scheme_idx != 0 || candidate.target_idx != 0 {
            return Err(DamosError::Invalid("external DAMOS event rejected".into()));
        }
        if candidate.range.start < cold.start
            || candidate.range.end > cold.end
            || candidate.range.overlap(hot) > 0
            || candidate.range.overlap(warm) > 0
            || candidate.nr_accesses != 0
            || candidate.age < age_min
        {
            return Err(DamosError::Invalid(
                "candidate violates COLD fence or access pattern".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriedRegionsLifecycle {
    pub stale_clear_ns: u128,
    pub arm_ns: u128,
    pub observed_interval_start_ns: u128,
    pub read_ns: u128,
    pub final_clear_ns: u128,
}

impl TriedRegionsLifecycle {
    #[must_use]
    pub fn valid(&self) -> bool {
        self.stale_clear_ns <= self.arm_ns
            && self.arm_ns <= self.observed_interval_start_ns
            && self.observed_interval_start_ns < self.read_ns
            && self.read_ns <= self.final_clear_ns
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReclaimEvidence {
    pub stats: DamosStats,
    pub vma: VmaReclaimEvidence,
    pub ranges: RangeReclaimEvidence,
}

impl ReclaimEvidence {
    #[must_use]
    pub fn observed(&self) -> bool {
        self.stats.sz_applied.unwrap_or(0) > 0
            && range_reclaim_observed(&self.ranges.cold.before, &self.ranges.cold.after_pageout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagemapPageState {
    pub present: bool,
    pub swapped: bool,
}

#[must_use]
pub fn parse_pagemap_entry(entry: u64) -> PagemapPageState {
    PagemapPageState {
        present: entry & (1_u64 << 63) != 0,
        swapped: entry & (1_u64 << 62) != 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeResidencySnapshot {
    pub range_start: u64,
    pub range_end: u64,
    pub range_size_bytes: u64,
    pub page_size: u64,
    pub total_pages: u64,
    pub present_pages: u64,
    pub present_bytes: u64,
    pub swapped_pages: u64,
    pub swapped_bytes: u64,
    pub not_present_not_swapped_pages: u64,
    pub read_errors: u64,
    pub timestamp_ns: u128,
    pub source: String,
}

impl RangeResidencySnapshot {
    pub fn validate(&self) -> Result<(), DamosError> {
        if self.range_start >= self.range_end
            || self.page_size == 0
            || self.range_size_bytes != self.range_end - self.range_start
            || self.total_pages != self.range_size_bytes / self.page_size
            || self.present_pages + self.swapped_pages + self.not_present_not_swapped_pages
                != self.total_pages
            || self.present_bytes != self.present_pages * self.page_size
            || self.swapped_bytes != self.swapped_pages * self.page_size
            || self.read_errors != 0
            || self.source != "proc_pagemap"
        {
            return Err(DamosError::Invalid(
                "invalid exact-range pagemap snapshot".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneRangeEvidence {
    pub before: RangeResidencySnapshot,
    pub after_pageout: RangeResidencySnapshot,
    pub after_refault: Option<RangeResidencySnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeReclaimEvidence {
    pub hot: ZoneRangeEvidence,
    pub warm: ZoneRangeEvidence,
    pub cold: ZoneRangeEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmaReclaimEvidence {
    pub containing_vma_start: u64,
    pub containing_vma_end: u64,
    pub containing_vma_shared: bool,
    pub rss_before: u64,
    pub rss_after_pageout: u64,
    pub pss_before: u64,
    pub pss_after_pageout: u64,
    pub swap_before: u64,
    pub swap_after_pageout: u64,
}

#[must_use]
pub fn range_reclaim_observed(
    before: &RangeResidencySnapshot,
    after: &RangeResidencySnapshot,
) -> bool {
    after.present_bytes < before.present_bytes || after.swapped_bytes > before.swapped_bytes
}

#[must_use]
pub fn range_not_reclaimed(
    before: &RangeResidencySnapshot,
    after: &RangeResidencySnapshot,
    candidates: &[DamosBeforeApplyEvent],
    range: AddressRange,
) -> bool {
    candidates
        .iter()
        .all(|candidate| candidate.range.overlap(range) == 0)
        && after.present_bytes >= before.present_bytes
        && after.swapped_bytes <= before.swapped_bytes
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefaultEvidence {
    pub action_id: String,
    pub target_key: String,
    pub region_signature: String,
    pub applied_bytes: u64,
    pub action_timestamp_ns: u128,
    pub first_access_timestamp_ns: Option<u128>,
    pub rss_or_swap_evidence: bool,
    pub content_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefaultState {
    NotEvaluated,
    NotObserved,
    Observed,
}

impl RefaultEvidence {
    #[must_use]
    pub fn early(&self, window_ns: u128) -> bool {
        self.applied_bytes > 0
            && self.content_valid
            && self.first_access_timestamp_ns.is_some_and(|at| {
                at >= self.action_timestamp_ns && at - self.action_timestamp_ns <= window_ns
            })
            && self.rss_or_swap_evidence
    }

    #[must_use]
    pub fn state(&self, successful_reclaim: bool, window_ns: u128) -> RefaultState {
        if !successful_reclaim {
            RefaultState::NotEvaluated
        } else if self.early(window_ns) {
            RefaultState::Observed
        } else {
            RefaultState::NotObserved
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlacklistRecord {
    pub key: String,
    pub reason: String,
    pub created_at_ns: u128,
    pub expires_at_ns: u128,
    pub source_action_id: String,
    pub evidence: RefaultEvidence,
}

impl BlacklistRecord {
    #[must_use]
    pub fn active(&self, now_ns: u128) -> bool {
        self.created_at_ns <= now_ns && now_ns < self.expires_at_ns
    }
}

#[must_use]
pub fn blacklist_for_refault(
    evidence: RefaultEvidence,
    successful_reclaim: bool,
    created_at_ns: u128,
    expires_at_ns: u128,
    refault_window_ns: u128,
) -> Option<BlacklistRecord> {
    (evidence.state(successful_reclaim, refault_window_ns) == RefaultState::Observed).then(|| {
        BlacklistRecord {
            key: format!("{}:{}", evidence.target_key, evidence.region_signature),
            reason: "early_refault_blacklist".into(),
            created_at_ns,
            expires_at_ns,
            source_action_id: evidence.action_id.clone(),
            evidence,
        }
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedSession {
    pub session_id: String,
    pub target: StableTargetIdentity,
    pub kdamond_index: u32,
    pub scheme_id: u32,
    pub state_on: bool,
    pub interrupted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionStage {
    DecisionRecorded,
    KdamondAllocated,
    SchemeAllocated,
    SchemeConfigured,
    StateOn,
    FirstPageout,
    BeforeStop,
    Cleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryOutcome {
    pub stopped_owned_kdamond: bool,
    pub removed_owned_scheme: bool,
    pub external_untouched: bool,
    pub pageout_not_undone: bool,
    pub recorded_interrupted: bool,
}

#[must_use]
pub fn simulated_crash_recovery(stage: TransactionStage) -> RecoveryOutcome {
    RecoveryOutcome {
        stopped_owned_kdamond: matches!(
            stage,
            TransactionStage::StateOn
                | TransactionStage::FirstPageout
                | TransactionStage::BeforeStop
                | TransactionStage::Cleanup
        ),
        removed_owned_scheme: !matches!(stage, TransactionStage::DecisionRecorded),
        external_untouched: true,
        pageout_not_undone: true,
        recorded_interrupted: true,
    }
}

pub fn recover_owned(
    session: &mut OwnedSession,
    expected_prefix: &str,
) -> Result<bool, DamosError> {
    if !session.session_id.starts_with(expected_prefix) || !session.target.owned {
        return Err(DamosError::Invalid(
            "refusing recovery of non-owned session".into(),
        ));
    }
    let changed = session.state_on || session.interrupted;
    session.state_on = false;
    session.interrupted = false;
    Ok(changed)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DamosReport {
    pub schema: String,
    pub capability: DamosCapability,
    pub plan: Option<DamosPlan>,
    pub shadow_stats: Option<DamosStats>,
    pub live_stats: Option<DamosStats>,
    pub reclaim: Option<ReclaimEvidence>,
    pub refault: Option<RefaultEvidence>,
    pub refault_state: RefaultState,
    pub blacklist: Option<BlacklistRecord>,
    pub cleanup: bool,
    pub recovery: bool,
    pub recovery_idempotent: bool,
    pub host_unchanged: bool,
    pub dry_run: bool,
    pub blocked_reasons: Vec<String>,
}

#[cfg(test)]
mod tests;
