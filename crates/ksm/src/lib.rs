#![forbid(unsafe_code)]

use policy_engine::PressureState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const RULE_VERSION: &str = "selective-ksm-v1";
pub const REPORT_SCHEMA: &str = "nemor-ksm-report-v1";
pub const AUDIT_REASON: &str = "ksm_observe_audit";
pub const PAGE_SIZE: u64 = 4096;
pub const VALIDATION_MIN_SAVED_BYTES: u64 = 8 * 1024 * 1024;
pub const VALIDATION_CPU_BUDGET_PERCENT: f64 = 1.0;
pub const VALIDATION_CPU_RESOLUTION_PERCENT: f64 = 0.25;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CpuWindowMeasurement {
    pub window_seconds: f64,
    pub cpu_tick_delta: u64,
    pub cpu_seconds_delta: f64,
    pub cpu_percent: f64,
    pub measurement_resolution_percent: f64,
    pub resolution_valid: bool,
    pub budget_exceeded: Option<bool>,
}

pub fn minimum_cpu_budget_window_seconds(clk_tck: u64) -> Option<f64> {
    (clk_tck > 0).then(|| 100.0 / (clk_tck as f64 * VALIDATION_CPU_RESOLUTION_PERCENT))
}

pub fn measure_cpu_window(
    tick_delta: u64,
    window_seconds: f64,
    clk_tck: u64,
) -> Option<CpuWindowMeasurement> {
    if clk_tck == 0 || !window_seconds.is_finite() || window_seconds <= 0.0 {
        return None;
    }
    let cpu_tick_seconds = 1.0 / clk_tck as f64;
    let cpu_seconds_delta = tick_delta as f64 * cpu_tick_seconds;
    let cpu_percent = cpu_seconds_delta / window_seconds * 100.0;
    let measurement_resolution_percent = 100.0 * cpu_tick_seconds / window_seconds;
    let resolution_valid = measurement_resolution_percent <= VALIDATION_CPU_RESOLUTION_PERCENT;
    Some(CpuWindowMeasurement {
        window_seconds,
        cpu_tick_delta: tick_delta,
        cpu_seconds_delta,
        cpu_percent,
        measurement_resolution_percent,
        resolution_valid,
        budget_exceeded: resolution_valid.then_some(cpu_percent > VALIDATION_CPU_BUDGET_PERCENT),
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KsmError {
    #[error("unsupported KSM capability: {0}")]
    Unsupported(String),
    #[error("unsafe KSM request: {0}")]
    Unsafe(String),
    #[error("invalid KSM data: {0}")]
    Invalid(String),
    #[error("KSM I/O: {0}")]
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KsmCapability {
    pub supported: bool,
    pub sysfs_available: bool,
    pub sysfs_readable: bool,
    pub sysfs_writable: bool,
    pub run_supported: bool,
    pub scanner_fields: BTreeMap<String, bool>,
    pub advisor_fields: BTreeMap<String, bool>,
    pub metric_fields: BTreeMap<String, bool>,
    pub process_ksm_stat_available: bool,
    pub madv_mergeable_supported: Option<bool>,
    pub madv_unmergeable_supported: Option<bool>,
    pub prctl_memory_merge_supported: Option<bool>,
    pub existing_run_state: Option<u8>,
    pub existing_external_mergeable_processes: u64,
    pub existing_pages_shared: Option<u64>,
    pub existing_pages_sharing: Option<u64>,
    pub external_live_ksm_activity: bool,
    pub residual_global_ksm_accounting: bool,
    pub external_ksm_activity: bool,
    pub notes: Vec<String>,
}

fn read_optional_u64(root: &Path, name: &str) -> Option<u64> {
    fs::read_to_string(root.join(name))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn current_selection(value: &str) -> String {
    value
        .split_whitespace()
        .find_map(|item| item.strip_prefix('[')?.strip_suffix(']'))
        .unwrap_or(value.trim())
        .to_owned()
}

fn effective_uid() -> Option<u32> {
    fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn path_writable_by_current_user(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let Some(uid) = effective_uid() else {
        return false;
    };
    let mode = metadata.mode();
    uid == 0 || (uid == metadata.uid() && mode & 0o200 != 0) || mode & 0o002 != 0
}

#[must_use]
pub fn inspect_capability(root: &Path, process_stat_available: bool) -> KsmCapability {
    let fields = fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<BTreeSet<_>>();
    let present = |name: &str| fields.contains(name);
    let run = read_optional_u64(root, "run").and_then(|value| u8::try_from(value).ok());
    let pages_shared = read_optional_u64(root, "pages_shared");
    let pages_sharing = read_optional_u64(root, "pages_sharing");
    let mut scanner_fields = BTreeMap::new();
    for name in ["pages_to_scan", "sleep_millisecs", "smart_scan"] {
        scanner_fields.insert(name.into(), present(name));
    }
    let mut advisor_fields = BTreeMap::new();
    for name in [
        "advisor_mode",
        "advisor_max_cpu",
        "advisor_target_scan_time",
        "advisor_min_pages_to_scan",
        "advisor_max_pages_to_scan",
    ] {
        advisor_fields.insert(name.into(), present(name));
    }
    let mut metric_fields = BTreeMap::new();
    for name in [
        "general_profit",
        "pages_scanned",
        "pages_shared",
        "pages_sharing",
        "pages_unshared",
        "pages_volatile",
        "pages_skipped",
        "full_scans",
        "stable_node_chains",
        "stable_node_dups",
        "ksm_zero_pages",
    ] {
        metric_fields.insert(name.into(), present(name));
    }
    KsmCapability {
        supported: root.is_dir() && present("run"),
        sysfs_available: root.is_dir(),
        sysfs_readable: root.join("run").is_file() && fs::read_to_string(root.join("run")).is_ok(),
        sysfs_writable: path_writable_by_current_user(&root.join("run")),
        run_supported: present("run"),
        scanner_fields,
        advisor_fields,
        metric_fields,
        process_ksm_stat_available: process_stat_available,
        madv_mergeable_supported: None,
        madv_unmergeable_supported: None,
        prctl_memory_merge_supported: None,
        existing_run_state: run,
        existing_external_mergeable_processes: 0,
        existing_pages_shared: pages_shared,
        existing_pages_sharing: pages_sharing,
        external_live_ksm_activity: false,
        residual_global_ksm_accounting: run == Some(0)
            && (pages_shared.unwrap_or(0) > 0 || pages_sharing.unwrap_or(0) > 0),
        external_ksm_activity: run != Some(0),
        notes: Vec::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KsmSystemMetrics {
    pub timestamp_ns: u128,
    pub run: Option<u64>,
    pub pages_to_scan: Option<u64>,
    pub sleep_millisecs: Option<u64>,
    pub pages_scanned: Option<u64>,
    pub pages_shared: Option<u64>,
    pub pages_sharing: Option<u64>,
    pub pages_unshared: Option<u64>,
    pub pages_volatile: Option<u64>,
    pub pages_skipped: Option<u64>,
    pub full_scans: Option<u64>,
    pub ksm_zero_pages: Option<u64>,
    pub general_profit: Option<i64>,
    pub stable_node_chains: Option<u64>,
    pub stable_node_dups: Option<u64>,
    pub cow_ksm: Option<u64>,
    pub ksm_swpin_copy: Option<u64>,
    pub ksmd_cpu_ticks: Option<u64>,
}

pub fn parse_system_metrics(root: &Path, vmstat: &str, timestamp_ns: u128) -> KsmSystemMetrics {
    let signed = |name: &str| {
        fs::read_to_string(root.join(name))
            .ok()?
            .trim()
            .parse::<i64>()
            .ok()
    };
    let vm = parse_vmstat_ksm(vmstat);
    KsmSystemMetrics {
        timestamp_ns,
        run: read_optional_u64(root, "run"),
        pages_to_scan: read_optional_u64(root, "pages_to_scan"),
        sleep_millisecs: read_optional_u64(root, "sleep_millisecs"),
        pages_scanned: read_optional_u64(root, "pages_scanned"),
        pages_shared: read_optional_u64(root, "pages_shared"),
        pages_sharing: read_optional_u64(root, "pages_sharing"),
        pages_unshared: read_optional_u64(root, "pages_unshared"),
        pages_volatile: read_optional_u64(root, "pages_volatile"),
        pages_skipped: read_optional_u64(root, "pages_skipped"),
        full_scans: read_optional_u64(root, "full_scans"),
        ksm_zero_pages: read_optional_u64(root, "ksm_zero_pages"),
        general_profit: signed("general_profit"),
        stable_node_chains: read_optional_u64(root, "stable_node_chains"),
        stable_node_dups: read_optional_u64(root, "stable_node_dups"),
        cow_ksm: vm.get("cow_ksm").copied(),
        ksm_swpin_copy: vm.get("ksm_swpin_copy").copied(),
        ksmd_cpu_ticks: None,
    }
}

#[must_use]
pub fn parse_vmstat_ksm(text: &str) -> BTreeMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            if !matches!(key, "cow_ksm" | "ksm_swpin_copy") {
                return None;
            }
            Some((key.to_owned(), fields.next()?.parse().ok()?))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StableProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub stable_key: String,
}

#[must_use]
pub fn owned_validation_identity(
    session_id: &str,
    pid: u32,
    start_ticks: u64,
) -> StableProcessIdentity {
    StableProcessIdentity {
        pid,
        start_ticks,
        stable_key: format!("nemor-owned:{session_id}:{pid}:{start_ticks}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct KsmProcessMetrics {
    pub identity: StableProcessIdentity,
    pub profile: Option<KsmProfileKind>,
    pub ksm_rmap_items: Option<u64>,
    pub ksm_zero_pages: Option<u64>,
    pub ksm_merging_pages: Option<u64>,
    pub ksm_process_profit: Option<i64>,
    pub ksm_merge_any: Option<bool>,
    pub ksm_mergeable: Option<bool>,
    pub current_mapped_ksm_bytes: Option<u64>,
    pub residual_accounting: bool,
    pub rss_bytes: Option<u64>,
    pub pss_bytes: Option<u64>,
}

#[must_use]
pub fn parse_smaps_ksm_bytes(text: &str) -> Option<u64> {
    let mut found = false;
    let mut total = 0_u64;
    for line in text.lines() {
        let Some(value) = line.strip_prefix("KSM:") else {
            continue;
        };
        let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
        total = total.saturating_add(kib.saturating_mul(1024));
        found = true;
    }
    found.then_some(total)
}

fn parse_yes_no(value: &str) -> Option<bool> {
    match value.trim() {
        "yes" | "1" | "Y" => Some(true),
        "no" | "0" | "N" => Some(false),
        _ => None,
    }
}

#[must_use]
pub fn parse_process_ksm_stat(text: &str, identity: StableProcessIdentity) -> KsmProcessMetrics {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let normalized = line.replace(':', " ");
        let mut fields = normalized.split_whitespace();
        if let (Some(key), Some(value)) = (fields.next(), fields.next()) {
            values.insert(key.to_owned(), value.to_owned());
        }
    }
    let unsigned = |key: &str| values.get(key)?.parse().ok();
    let signed = |key: &str| values.get(key)?.parse().ok();
    KsmProcessMetrics {
        identity,
        ksm_rmap_items: unsigned("ksm_rmap_items"),
        ksm_zero_pages: unsigned("ksm_zero_pages"),
        ksm_merging_pages: unsigned("ksm_merging_pages"),
        ksm_process_profit: signed("ksm_process_profit"),
        ksm_merge_any: values.get("ksm_merge_any").and_then(|v| parse_yes_no(v)),
        ksm_mergeable: values.get("ksm_mergeable").and_then(|v| parse_yes_no(v)),
        ..KsmProcessMetrics::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KsmProfileKind {
    Vm,
    Browser,
    Electron,
    Synthetic,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KsmProfile {
    pub kind: KsmProfileKind,
    pub expected_sharing_suitability: u8,
    pub foreground_sensitive: bool,
    pub gaming_sensitive: bool,
    pub minimum_stable_observations: u32,
    pub minimum_mergeable_bytes: u64,
    pub maximum_scanner_cpu_percent: f64,
    pub minimum_positive_profit_bytes: i64,
    pub maximum_cow_events_per_second: u64,
    pub inefficiency_windows: u32,
    pub cooldown_seconds: u64,
}

#[must_use]
pub fn profile(kind: KsmProfileKind) -> KsmProfile {
    let suitability = match kind {
        KsmProfileKind::Vm => 70,
        KsmProfileKind::Browser => 35,
        KsmProfileKind::Electron => 45,
        KsmProfileKind::Synthetic => 100,
        KsmProfileKind::Unknown => 0,
    };
    KsmProfile {
        kind,
        expected_sharing_suitability: suitability,
        foreground_sensitive: true,
        gaming_sensitive: true,
        minimum_stable_observations: 3,
        minimum_mergeable_bytes: 32 * 1024 * 1024,
        maximum_scanner_cpu_percent: 1.0,
        minimum_positive_profit_bytes: 4096,
        maximum_cow_events_per_second: 64,
        inefficiency_windows: 3,
        cooldown_seconds: 300,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EligibilityInput {
    pub identity: Option<StableProcessIdentity>,
    pub identity_fresh: bool,
    pub profile: KsmProfileKind,
    pub already_mergeable: bool,
    pub owned_cooperative: bool,
    pub foreground: bool,
    pub gaming: bool,
    pub critical: bool,
    pub protected: bool,
    pub same_security_domain: bool,
    pub pressure: PressureState,
    pub stable_observations: u32,
    pub mergeable_bytes: u64,
    pub profit_bytes: Option<i64>,
    pub cow_events_per_second: Option<u64>,
    pub cpu_percent: Option<f64>,
    pub cooldown_active: bool,
    pub external_ksm_activity: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
pub fn evaluate_eligibility(input: &EligibilityInput, bounds: &KsmProfile) -> EligibilityDecision {
    let mut reasons = Vec::new();
    if input.profile == KsmProfileKind::Unknown {
        reasons.push("unknown_profile".into());
    }
    if input.identity.is_none() {
        reasons.push("unknown_identity".into());
    } else if !input.identity_fresh {
        reasons.push("stale_identity".into());
    }
    if input.foreground {
        reasons.push("foreground_protected".into());
    }
    if input.gaming {
        reasons.push("gaming_protected".into());
    }
    if input.critical || input.protected {
        reasons.push("critical_process".into());
    }
    if !input.same_security_domain {
        reasons.push("external_security_domain".into());
    }
    if !input.already_mergeable && !input.owned_cooperative {
        reasons.push("cooperation_required".into());
    }
    if input.external_ksm_activity {
        reasons.push("external_ksm_activity".into());
    }
    if input.stable_observations < bounds.minimum_stable_observations {
        reasons.push("insufficient_observation".into());
    }
    if input.mergeable_bytes < bounds.minimum_mergeable_bytes {
        reasons.push("ksm_not_mergeable".into());
    }
    if matches!(
        input.pressure,
        PressureState::Critical | PressureState::Emergency | PressureState::Stabilizing
    ) {
        reasons.push("global_state_not_safe".into());
    }
    if input.cooldown_active {
        reasons.push("cooldown_active".into());
    }
    if input.profit_bytes.is_some_and(|profit| profit <= 0) {
        reasons.push("profit_not_positive".into());
    }
    if input
        .cow_events_per_second
        .is_some_and(|rate| rate > bounds.maximum_cow_events_per_second)
    {
        reasons.push("cow_rate_excessive".into());
    }
    if input
        .cpu_percent
        .is_some_and(|cpu| cpu > bounds.maximum_scanner_cpu_percent)
    {
        reasons.push("cpu_budget_exceeded".into());
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorMode {
    Fixed,
    ScanTime,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationProtocolState {
    ReadyUnmergeable,
    Audited,
    DuplicateMergeable,
    ScannerRunning,
    ScannerStopped,
    Unmerged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProtocol {
    pub state: ValidationProtocolState,
    pub decision_id: Option<String>,
    pub plan_id: Option<String>,
    pub transaction_id: Option<String>,
}

impl Default for ValidationProtocol {
    fn default() -> Self {
        Self {
            state: ValidationProtocolState::ReadyUnmergeable,
            decision_id: None,
            plan_id: None,
            transaction_id: None,
        }
    }
}

impl ValidationProtocol {
    pub fn record_audit(
        &mut self,
        decision_id: String,
        plan_id: String,
        transaction_id: String,
    ) -> Result<(), KsmError> {
        if self.state != ValidationProtocolState::ReadyUnmergeable
            || decision_id.is_empty()
            || plan_id.is_empty()
            || transaction_id.is_empty()
        {
            return Err(KsmError::Unsafe("audit_missing".into()));
        }
        self.decision_id = Some(decision_id);
        self.plan_id = Some(plan_id);
        self.transaction_id = Some(transaction_id);
        self.state = ValidationProtocolState::Audited;
        Ok(())
    }

    pub fn opt_in_duplicate(&mut self) -> Result<(), KsmError> {
        if self.state != ValidationProtocolState::Audited
            || self.decision_id.is_none()
            || self.plan_id.is_none()
            || self.transaction_id.is_none()
        {
            return Err(KsmError::Unsafe("audit_missing".into()));
        }
        self.state = ValidationProtocolState::DuplicateMergeable;
        Ok(())
    }

    pub fn scanner_started(&mut self) -> Result<(), KsmError> {
        if self.state != ValidationProtocolState::DuplicateMergeable {
            return Err(KsmError::Unsafe("mergeable_scope_invalid".into()));
        }
        self.state = ValidationProtocolState::ScannerRunning;
        Ok(())
    }

    pub fn scanner_stopped(&mut self) -> Result<(), KsmError> {
        if self.state != ValidationProtocolState::ScannerRunning {
            return Err(KsmError::Unsafe("scanner_ownership_lost".into()));
        }
        self.state = ValidationProtocolState::ScannerStopped;
        Ok(())
    }

    pub fn unmerged(&mut self) -> Result<(), KsmError> {
        if self.state != ValidationProtocolState::ScannerStopped {
            return Err(KsmError::Unsafe("cleanup_failure".into()));
        }
        self.state = ValidationProtocolState::Unmerged;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerPlan {
    pub mode: AdvisorMode,
    pub pages_to_scan: u64,
    pub sleep_millisecs: u64,
    pub owned_validation_only: bool,
    pub blocked_reasons: Vec<String>,
}

pub fn plan_scanner(
    mode_text: &str,
    requested_pages: u64,
    requested_sleep: u64,
    min_pages: u64,
    max_pages: u64,
    min_sleep: u64,
) -> Result<ScannerPlan, KsmError> {
    let mode = match current_selection(mode_text).as_str() {
        "none" => AdvisorMode::Fixed,
        "scan-time" => AdvisorMode::ScanTime,
        _ => AdvisorMode::Unknown,
    };
    if requested_pages < min_pages || requested_pages > max_pages || requested_sleep < min_sleep {
        return Err(KsmError::Unsafe("scanner bounds".into()));
    }
    let mut blocked = Vec::new();
    if mode != AdvisorMode::Fixed {
        blocked.push("advisor_mode_not_fixed".into());
    }
    Ok(ScannerPlan {
        mode,
        pages_to_scan: requested_pages,
        sleep_millisecs: requested_sleep,
        owned_validation_only: true,
        blocked_reasons: blocked,
    })
}

pub fn plan_attempt_one_scanner(
    advisor_text: &str,
    baseline: &KsmSnapshot,
    min_pages: u64,
    max_pages: u64,
    min_sleep: u64,
) -> Result<ScannerPlan, KsmError> {
    plan_scanner(
        advisor_text,
        baseline.pages_to_scan,
        baseline.sleep_millisecs,
        min_pages,
        max_pages,
        min_sleep,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(self) -> bool {
        !self.is_valid()
    }

    pub fn is_valid(self) -> bool {
        self.start < self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmapsArea {
    range: AddressRange,
    mergeable: bool,
    no_hugepage: bool,
    kernel_page_size_bytes: Option<u64>,
    mmu_page_size_bytes: Option<u64>,
    anon_huge_pages_bytes: Option<u64>,
    thp_eligible: Option<bool>,
    vm_flags: Vec<String>,
}

fn parse_hex_range(line: &str) -> Option<AddressRange> {
    let token = line.split_whitespace().next()?;
    let (start, end) = token.split_once('-')?;
    Some(AddressRange {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
    })
}

fn parse_smaps_areas(text: &str) -> Vec<SmapsArea> {
    let mut areas = Vec::new();
    let mut current: Option<SmapsArea> = None;
    for line in text.lines() {
        if let Some(range) = parse_hex_range(line) {
            if let Some(area) = current.take() {
                areas.push(area);
            }
            current = Some(SmapsArea {
                range,
                mergeable: false,
                no_hugepage: false,
                kernel_page_size_bytes: None,
                mmu_page_size_bytes: None,
                anon_huge_pages_bytes: None,
                thp_eligible: None,
                vm_flags: Vec::new(),
            });
        } else if let Some(value) = line.strip_prefix("KernelPageSize:") {
            if let Some(area) = current.as_mut() {
                area.kernel_page_size_bytes = parse_smaps_kib(value);
            }
        } else if let Some(value) = line.strip_prefix("MMUPageSize:") {
            if let Some(area) = current.as_mut() {
                area.mmu_page_size_bytes = parse_smaps_kib(value);
            }
        } else if let Some(value) = line.strip_prefix("AnonHugePages:") {
            if let Some(area) = current.as_mut() {
                area.anon_huge_pages_bytes = parse_smaps_kib(value);
            }
        } else if let Some(value) = line.strip_prefix("THPeligible:") {
            if let Some(area) = current.as_mut() {
                area.thp_eligible = value
                    .split_whitespace()
                    .next()
                    .and_then(|item| item.parse::<u8>().ok())
                    .map(|item| item != 0);
            }
        } else if let Some(flags) = line.strip_prefix("VmFlags:") {
            if let Some(area) = current.as_mut() {
                area.vm_flags = flags.split_whitespace().map(str::to_owned).collect();
                let flags: BTreeSet<_> = area.vm_flags.iter().map(String::as_str).collect();
                area.mergeable = flags.contains("mg");
                area.no_hugepage = flags.contains("nh");
            }
        }
    }
    if let Some(area) = current {
        areas.push(area);
    }
    areas
}

fn parse_smaps_kib(value: &str) -> Option<u64> {
    let mut parts = value.split_whitespace();
    let amount = parts.next()?.parse::<u64>().ok()?;
    (parts.next()? == "kB").then(|| amount.saturating_mul(1024))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmapsRangeOverlap {
    pub vma_start: u64,
    pub vma_end: u64,
    pub overlap_start: u64,
    pub overlap_end: u64,
    pub overlap_bytes: u64,
    pub kernel_page_size_bytes: Option<u64>,
    pub mmu_page_size_bytes: Option<u64>,
    pub anon_huge_pages_bytes: Option<u64>,
    pub thp_eligible: Option<bool>,
    pub vm_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasePageScopeEvidence {
    pub range: AddressRange,
    pub host_page_size: u64,
    pub start_aligned: bool,
    pub end_aligned: bool,
    pub length_aligned: bool,
    pub covered_bytes: u64,
    pub full_coverage: bool,
    pub no_hugepage: bool,
    pub non_mergeable: bool,
    pub base_page_sizes: bool,
    pub anon_huge_pages_zero: bool,
    pub overlaps: Vec<SmapsRangeOverlap>,
    pub passed: bool,
    pub failure_reasons: Vec<String>,
}

#[must_use]
pub fn verify_base_page_scope(
    smaps: &str,
    range: AddressRange,
    host_page_size: u64,
    require_non_mergeable: bool,
) -> BasePageScopeEvidence {
    let areas = parse_smaps_areas(smaps);
    let mut overlaps = areas
        .iter()
        .filter_map(|area| {
            let start = area.range.start.max(range.start);
            let end = area.range.end.min(range.end);
            (start < end).then(|| SmapsRangeOverlap {
                vma_start: area.range.start,
                vma_end: area.range.end,
                overlap_start: start,
                overlap_end: end,
                overlap_bytes: end - start,
                kernel_page_size_bytes: area.kernel_page_size_bytes,
                mmu_page_size_bytes: area.mmu_page_size_bytes,
                anon_huge_pages_bytes: area.anon_huge_pages_bytes,
                thp_eligible: area.thp_eligible,
                vm_flags: area.vm_flags.clone(),
            })
        })
        .collect::<Vec<_>>();
    overlaps.sort_by_key(|item| item.overlap_start);

    let start_aligned = host_page_size > 0 && range.start % host_page_size == 0;
    let end_aligned = host_page_size > 0 && range.end % host_page_size == 0;
    let length_aligned = host_page_size > 0 && range.len() % host_page_size == 0;
    let mut cursor = range.start;
    let mut covered_bytes = 0_u64;
    for overlap in &overlaps {
        if overlap.overlap_start > cursor {
            break;
        }
        let newly_covered_start = cursor.max(overlap.overlap_start);
        if overlap.overlap_end > newly_covered_start {
            covered_bytes = covered_bytes.saturating_add(overlap.overlap_end - newly_covered_start);
            cursor = overlap.overlap_end;
        }
    }
    let full_coverage = range.is_valid() && cursor >= range.end && covered_bytes == range.len();
    let no_hugepage = !overlaps.is_empty()
        && overlaps
            .iter()
            .all(|item| item.vm_flags.iter().any(|flag| flag == "nh"));
    let non_mergeable = !overlaps.is_empty()
        && overlaps
            .iter()
            .all(|item| !item.vm_flags.iter().any(|flag| flag == "mg"));
    let base_page_sizes = !overlaps.is_empty()
        && overlaps.iter().all(|item| {
            item.kernel_page_size_bytes == Some(host_page_size)
                && item.mmu_page_size_bytes == Some(host_page_size)
        });
    let anon_huge_pages_zero = !overlaps.is_empty()
        && overlaps
            .iter()
            .all(|item| item.anon_huge_pages_bytes == Some(0));
    let mut failure_reasons = Vec::new();
    if !(start_aligned && end_aligned && length_aligned) {
        failure_reasons.push("owned_range_not_page_aligned".into());
    }
    if !full_coverage {
        failure_reasons.push("smaps_range_coverage_gap".into());
    }
    if !base_page_sizes {
        failure_reasons.push("base_page_size_mismatch".into());
    }
    if !anon_huge_pages_zero {
        failure_reasons.push("anon_huge_pages_nonzero_or_missing".into());
    }
    if !no_hugepage {
        failure_reasons.push("nohugepage_flag_missing".into());
    }
    if require_non_mergeable && !non_mergeable {
        failure_reasons.push("mergeable_before_audit".into());
    }
    BasePageScopeEvidence {
        range,
        host_page_size,
        start_aligned,
        end_aligned,
        length_aligned,
        covered_bytes,
        full_coverage,
        no_hugepage,
        non_mergeable,
        base_page_sizes,
        anon_huge_pages_zero,
        overlaps,
        passed: failure_reasons.is_empty(),
        failure_reasons,
    }
}

fn fully_covered_with(
    requested: AddressRange,
    areas: &[SmapsArea],
    predicate: impl Fn(&SmapsArea) -> bool,
) -> bool {
    if !requested.is_valid() {
        return false;
    }
    let mut cursor = requested.start;
    let mut relevant: Vec<_> = areas
        .iter()
        .filter(|area| area.range.end > requested.start && area.range.start < requested.end)
        .collect();
    relevant.sort_by_key(|area| area.range.start);
    for area in relevant {
        if area.range.start > cursor || !predicate(area) {
            return false;
        }
        cursor = cursor.max(area.range.end.min(requested.end));
        if cursor == requested.end {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeableScopeEvidence {
    pub duplicate_fully_mergeable: bool,
    pub duplicate_fully_nohugepage: bool,
    pub control_fully_non_mergeable: bool,
    pub control_fully_nohugepage: bool,
    pub unexpected_mergeable_bytes: u64,
    pub passed: bool,
}

#[must_use]
pub fn verify_exact_mergeable_scope(
    smaps: &str,
    duplicate: AddressRange,
    control: AddressRange,
) -> MergeableScopeEvidence {
    let areas = parse_smaps_areas(smaps);
    let duplicate_fully_mergeable = fully_covered_with(duplicate, &areas, |area| area.mergeable);
    let duplicate_fully_nohugepage = fully_covered_with(duplicate, &areas, |area| area.no_hugepage);
    let control_fully_non_mergeable = fully_covered_with(control, &areas, |area| !area.mergeable);
    let control_fully_nohugepage = fully_covered_with(control, &areas, |area| area.no_hugepage);
    let unexpected_mergeable_bytes = areas
        .iter()
        .filter(|area| area.mergeable)
        .map(|area| {
            let duplicate_overlap = area
                .range
                .end
                .min(duplicate.end)
                .saturating_sub(area.range.start.max(duplicate.start));
            area.range.len().saturating_sub(duplicate_overlap)
        })
        .sum();
    MergeableScopeEvidence {
        duplicate_fully_mergeable,
        duplicate_fully_nohugepage,
        control_fully_non_mergeable,
        control_fully_nohugepage,
        unexpected_mergeable_bytes,
        passed: duplicate_fully_mergeable
            && duplicate_fully_nohugepage
            && control_fully_non_mergeable
            && control_fully_nohugepage
            && unexpected_mergeable_bytes == 0,
    }
}

#[must_use]
pub fn verify_exact_unmergeable_scope(
    smaps: &str,
    duplicate: AddressRange,
    control: AddressRange,
) -> bool {
    let areas = parse_smaps_areas(smaps);
    fully_covered_with(duplicate, &areas, |area| {
        !area.mergeable && area.no_hugepage
    }) && fully_covered_with(control, &areas, |area| !area.mergeable && area.no_hugepage)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationProfitGate {
    pub saved_bytes: u64,
    pub pages_scanned_delta: u64,
    pub full_scans_delta: u64,
    pub system_profit_delta: i64,
    pub processes_positive: bool,
    pub passed: bool,
    pub reasons: Vec<String>,
}

#[must_use]
pub fn validation_profit_gate(
    saved_bytes: u64,
    pages_scanned_delta: u64,
    full_scans_delta: u64,
    system_profit_delta: i64,
    processes_positive: bool,
) -> ValidationProfitGate {
    let mut reasons = Vec::new();
    if saved_bytes < VALIDATION_MIN_SAVED_BYTES {
        reasons.push("insufficient_saved_bytes".into());
    }
    if pages_scanned_delta == 0 || full_scans_delta == 0 {
        reasons.push("scanner_no_progress".into());
    }
    if system_profit_delta <= 0 {
        reasons.push("non_positive_system_profit".into());
    }
    if !processes_positive {
        reasons.push("non_positive_process_profit".into());
    }
    ValidationProfitGate {
        saved_bytes,
        pages_scanned_delta,
        full_scans_delta,
        system_profit_delta,
        processes_positive,
        passed: reasons.is_empty(),
        reasons,
    }
}

#[must_use]
pub fn attempt_one_global_state_owned(
    baseline: &KsmSnapshot,
    current: &KsmSnapshot,
    advisor_selected: Option<&str>,
) -> bool {
    current.run == 1
        && current.pages_to_scan == baseline.pages_to_scan
        && current.sleep_millisecs == baseline.sleep_millisecs
        && advisor_selected == Some("none")
        && current.preserve_only == baseline.preserve_only
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmergeDisposition {
    MadviseOwnedRange,
    TerminateOwnedChild,
}

#[must_use]
pub fn choose_unmerge_disposition(
    mem_available_bytes: u64,
    required_headroom_bytes: u64,
) -> UnmergeDisposition {
    if mem_available_bytes >= required_headroom_bytes {
        UnmergeDisposition::MadviseOwnedRange
    } else {
        UnmergeDisposition::TerminateOwnedChild
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveSafetyDecision {
    Continue,
    StopOwnedScannerAndFail,
}

#[must_use]
pub fn evaluate_live_safety(
    external_mergeable_processes: usize,
    global_state_owned: bool,
) -> LiveSafetyDecision {
    if external_mergeable_processes > 0 || !global_state_owned {
        LiveSafetyDecision::StopOwnedScannerAndFail
    } else {
        LiveSafetyDecision::Continue
    }
}

#[must_use]
pub fn content_fingerprints_intact(
    initial_duplicate: u64,
    final_duplicate: u64,
    initial_control: u64,
    final_control: u64,
) -> bool {
    initial_duplicate == final_duplicate && initial_control == final_control
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfitSample {
    pub wall_seconds: f64,
    pub ksmd_cpu_seconds: f64,
    pub pages_scanned_delta: u64,
    pub saved_bytes: u64,
    pub process_profit_bytes: Option<i64>,
    pub system_profit_bytes: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfitEvaluation {
    pub ksmd_mean_cpu_percent: f64,
    pub ksmd_cpu_seconds_per_gib_saved: Option<f64>,
    pub pages_scanned_per_saved_page: Option<f64>,
    pub net_positive: bool,
}

#[must_use]
pub fn evaluate_profit(sample: &ProfitSample, meaningful_saved_bytes: u64) -> ProfitEvaluation {
    let saved_pages = sample.saved_bytes / PAGE_SIZE;
    ProfitEvaluation {
        ksmd_mean_cpu_percent: if sample.wall_seconds > 0.0 {
            sample.ksmd_cpu_seconds / sample.wall_seconds * 100.0
        } else {
            0.0
        },
        ksmd_cpu_seconds_per_gib_saved: (sample.saved_bytes >= meaningful_saved_bytes
            && sample.saved_bytes > 0)
            .then(|| sample.ksmd_cpu_seconds / (sample.saved_bytes as f64 / (1_u64 << 30) as f64)),
        pages_scanned_per_saved_page: (saved_pages > 0)
            .then(|| sample.pages_scanned_delta as f64 / saved_pages as f64),
        net_positive: sample.saved_bytes >= meaningful_saved_bytes
            && sample.process_profit_bytes.is_none_or(|profit| profit > 0)
            && sample.system_profit_bytes.is_none_or(|profit| profit > 0),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerState {
    Unknown,
    Evaluating,
    Profitable,
    Inefficient,
    Cooldown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerInput {
    pub elapsed_seconds: u64,
    pub full_scans: u64,
    pub evaluation: ProfitEvaluation,
    pub cpu_budget_percent: f64,
    pub cow_rate: u64,
    pub maximum_cow_rate: u64,
    pub cooldown_active: bool,
}

#[must_use]
pub fn controller_transition(state: ControllerState, input: &ControllerInput) -> ControllerState {
    if input.cooldown_active {
        return ControllerState::Cooldown;
    }
    match state {
        ControllerState::Unknown => ControllerState::Evaluating,
        ControllerState::Evaluating if input.elapsed_seconds < 2 || input.full_scans == 0 => {
            ControllerState::Evaluating
        }
        ControllerState::Evaluating
            if input.evaluation.ksmd_mean_cpu_percent > input.cpu_budget_percent
                || input.cow_rate > input.maximum_cow_rate
                || !input.evaluation.net_positive =>
        {
            ControllerState::Inefficient
        }
        ControllerState::Evaluating => ControllerState::Profitable,
        other => other,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScannerOwnership {
    External,
    NemorOwnedValidation,
    NotRunning,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KsmSnapshot {
    pub run: u8,
    pub pages_to_scan: u64,
    pub sleep_millisecs: u64,
    pub preserve_only: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KsmTransaction {
    pub transaction_id: String,
    pub decision_id: String,
    pub plan_id: String,
    pub ownership: ScannerOwnership,
    pub baseline: KsmSnapshot,
    pub child_identities: Vec<StableProcessIdentity>,
    pub scanner_started: bool,
    pub recovered: bool,
}

pub trait KsmBackend {
    fn snapshot(&self) -> Result<KsmSnapshot, KsmError>;
    fn set_run(&mut self, value: u8) -> Result<(), KsmError>;
    fn set_scanner(&mut self, pages: u64, sleep_ms: u64) -> Result<(), KsmError>;
    fn restore(&mut self, snapshot: &KsmSnapshot) -> Result<(), KsmError>;
    fn mutations(&self) -> u64;
}

#[derive(Debug, Clone)]
pub struct SimulatedBackend {
    pub current: KsmSnapshot,
    pub mutation_count: u64,
    pub fail_after: Option<u64>,
}

impl SimulatedBackend {
    fn mutate(&mut self) -> Result<(), KsmError> {
        if self.fail_after == Some(self.mutation_count) {
            return Err(KsmError::Io("injected failure".into()));
        }
        self.mutation_count += 1;
        Ok(())
    }
}

impl KsmBackend for SimulatedBackend {
    fn snapshot(&self) -> Result<KsmSnapshot, KsmError> {
        Ok(self.current.clone())
    }

    fn set_run(&mut self, value: u8) -> Result<(), KsmError> {
        if value == 2 {
            return Err(KsmError::Unsafe("run=2 is globally forbidden".into()));
        }
        self.mutate()?;
        self.current.run = value;
        Ok(())
    }

    fn set_scanner(&mut self, pages: u64, sleep_ms: u64) -> Result<(), KsmError> {
        self.mutate()?;
        self.current.pages_to_scan = pages;
        self.current.sleep_millisecs = sleep_ms;
        Ok(())
    }

    fn restore(&mut self, snapshot: &KsmSnapshot) -> Result<(), KsmError> {
        self.set_run(0)?;
        self.set_scanner(snapshot.pages_to_scan, snapshot.sleep_millisecs)?;
        self.set_run(snapshot.run)?;
        Ok(())
    }

    fn mutations(&self) -> u64 {
        self.mutation_count
    }
}

pub fn recover_owned<B: KsmBackend>(
    transaction: &mut KsmTransaction,
    backend: &mut B,
) -> Result<bool, KsmError> {
    if transaction.recovered {
        return Ok(false);
    }
    if transaction.ownership != ScannerOwnership::NemorOwnedValidation
        || !transaction.transaction_id.starts_with("nemor-validation-")
    {
        return Err(KsmError::Unsafe("uncertain recovery ownership".into()));
    }
    backend.restore(&transaction.baseline)?;
    transaction.scanner_started = false;
    transaction.recovered = true;
    Ok(true)
}

pub fn write_run_value<B: KsmBackend>(backend: &mut B, value: u8) -> Result<(), KsmError> {
    if value == 2 {
        return Err(KsmError::Unsafe("run=2 is globally forbidden".into()));
    }
    backend.set_run(value)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KsmReport {
    pub schema: String,
    pub capability: KsmCapability,
    pub system: KsmSystemMetrics,
    pub processes: Vec<KsmProcessMetrics>,
    pub profiles: Vec<KsmProfile>,
    pub plan: Option<EligibilityDecision>,
    pub profit: Option<ProfitEvaluation>,
    pub controller: ControllerState,
    pub dry_run: bool,
    pub notes: Vec<String>,
}

pub fn inspect_linux(root: &Path, proc_root: &Path, timestamp_ns: u128) -> KsmReport {
    let process_available = fs::read_dir(proc_root).ok().is_some_and(|entries| {
        entries
            .filter_map(Result::ok)
            .any(|entry| entry.path().join("ksm_stat").is_file())
    });
    let mut capability = inspect_capability(root, process_available);
    let processes = external_mergeable_processes(proc_root, &BTreeSet::new());
    capability.existing_external_mergeable_processes = processes.len() as u64;
    capability.external_live_ksm_activity = !processes.is_empty();
    capability.external_ksm_activity |= capability.external_live_ksm_activity;
    let vmstat = fs::read_to_string(proc_root.join("vmstat")).unwrap_or_default();
    let system = parse_system_metrics(root, &vmstat, timestamp_ns);
    KsmReport {
        schema: REPORT_SCHEMA.into(),
        capability,
        system,
        processes,
        profiles: [
            KsmProfileKind::Vm,
            KsmProfileKind::Browser,
            KsmProfileKind::Electron,
        ]
        .into_iter()
        .map(profile)
        .collect(),
        plan: None,
        profit: None,
        controller: ControllerState::Unknown,
        dry_run: true,
        notes: vec![
            "external processes are observe/plan-only; cooperation is required".into(),
            "run=2 is forbidden".into(),
        ],
    }
}

pub fn external_mergeable_processes(
    proc_root: &Path,
    excluded: &BTreeSet<u32>,
) -> Vec<KsmProcessMetrics> {
    let excluded_owned = excluded
        .iter()
        .map(|pid| (*pid, None))
        .collect::<BTreeMap<_, _>>();
    external_mergeable_processes_owned(proc_root, &excluded_owned)
}

fn proc_start_ticks_from_root(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let close = stat.rfind(')')?;
    stat[close + 1..].split_whitespace().nth(19)?.parse().ok()
}

pub fn external_mergeable_processes_owned(
    proc_root: &Path,
    excluded_owned: &BTreeMap<u32, Option<u64>>,
) -> Vec<KsmProcessMetrics> {
    inspect_external_ksm_processes_owned(proc_root, excluded_owned)
        .map(|inspection| inspection.live_consumers)
        .unwrap_or_default()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ExternalKsmInspection {
    pub live_consumers: Vec<KsmProcessMetrics>,
    pub residual_processes: Vec<KsmProcessMetrics>,
    pub inspected_processes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessKsmActivity {
    LiveExternal,
    ResidualAccounting,
    Inactive,
}

#[must_use]
pub fn classify_process_ksm_activity(metrics: &KsmProcessMetrics) -> ProcessKsmActivity {
    if metrics.ksm_mergeable == Some(true)
        || metrics.ksm_merge_any == Some(true)
        || metrics.current_mapped_ksm_bytes.unwrap_or(0) > 0
    {
        ProcessKsmActivity::LiveExternal
    } else if metrics.ksm_merging_pages.unwrap_or(0) > 0 {
        ProcessKsmActivity::ResidualAccounting
    } else {
        ProcessKsmActivity::Inactive
    }
}

pub fn inspect_external_ksm_processes_owned(
    proc_root: &Path,
    excluded_owned: &BTreeMap<u32, Option<u64>>,
) -> Result<ExternalKsmInspection, KsmError> {
    let Ok(entries) = fs::read_dir(proc_root) else {
        return Err(KsmError::Io(format!(
            "cannot enumerate {}",
            proc_root.display()
        )));
    };
    let mut inspection = ExternalKsmInspection::default();
    for entry in entries.filter_map(Result::ok).take(4096) {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let start_ticks = proc_start_ticks_from_root(proc_root, pid);
        if exact_owned_tuple(excluded_owned, pid, start_ticks) {
            continue;
        }
        let stat_path = entry.path().join("ksm_stat");
        let text = match fs::read_to_string(&stat_path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => {
                return Err(KsmError::Io(format!(
                    "read {}: {error}",
                    stat_path.display()
                )));
            }
        };
        let smaps_path = entry.path().join("smaps");
        let smaps = match fs::read_to_string(&smaps_path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(KsmError::Io(format!(
                    "read {}: {error}",
                    smaps_path.display()
                )));
            }
        };
        if smaps.is_empty() {
            continue;
        }
        inspection.inspected_processes = inspection.inspected_processes.saturating_add(1);
        let mut metrics = parse_process_ksm_stat(
            &text,
            StableProcessIdentity {
                pid,
                start_ticks: start_ticks.unwrap_or(0),
                stable_key: "redacted".into(),
            },
        );
        metrics.current_mapped_ksm_bytes = parse_smaps_ksm_bytes(&smaps);
        match classify_process_ksm_activity(&metrics) {
            ProcessKsmActivity::LiveExternal => inspection.live_consumers.push(metrics),
            ProcessKsmActivity::ResidualAccounting => {
                metrics.residual_accounting = true;
                inspection.residual_processes.push(metrics);
            }
            ProcessKsmActivity::Inactive => {}
        }
    }
    Ok(inspection)
}

#[must_use]
pub fn exact_owned_tuple(
    excluded_owned: &BTreeMap<u32, Option<u64>>,
    pid: u32,
    start_ticks: Option<u64>,
) -> bool {
    matches!(
        (excluded_owned.get(&pid).copied().flatten(), start_ticks),
        (Some(expected), Some(actual)) if expected == actual
    )
}

pub fn read_advisor_mode(root: &Path) -> Option<String> {
    fs::read_to_string(root.join("advisor_mode"))
        .ok()
        .map(|value| current_selection(&value))
}

pub fn snapshot_from_root(root: &Path) -> Result<KsmSnapshot, KsmError> {
    let required = |name: &str| {
        read_optional_u64(root, name)
            .ok_or_else(|| KsmError::Unsupported(format!("missing {name}")))
    };
    let run =
        u8::try_from(required("run")?).map_err(|_| KsmError::Invalid("run overflow".into()))?;
    if run > 1 {
        return Err(KsmError::Unsafe("baseline run=2 is unsupported".into()));
    }
    let mut preserve_only = BTreeMap::new();
    for name in [
        "merge_across_nodes",
        "use_zero_pages",
        "max_page_sharing",
        "stable_node_chains_prune_millisecs",
        "smart_scan",
        "advisor_mode",
    ] {
        if let Ok(value) = fs::read_to_string(root.join(name)) {
            preserve_only.insert(name.into(), value.trim().into());
        }
    }
    Ok(KsmSnapshot {
        run,
        pages_to_scan: required("pages_to_scan")?,
        sleep_millisecs: required("sleep_millisecs")?,
        preserve_only,
    })
}

pub fn report_path() -> PathBuf {
    PathBuf::from("/tmp/nemor-privileged-validation-report.json")
}

#[cfg(test)]
mod tests;
