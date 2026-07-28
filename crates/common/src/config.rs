#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub general: GeneralConfig,
    pub cgroups: CgroupsConfig,
    pub telemetry: TelemetryConfig,
    pub classification: ClassificationConfig,
    pub safety: SafetyConfig,
    pub pressure: PressureConfig,
    pub policy: PolicyConfig,
    pub compression: CompressionConfig,
    pub tiering: TieringConfig,
    pub ksm: KsmConfig,
    pub damon: DamonConfig,
    pub damos: DamosConfig,
    pub gaming: GamingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupsConfig {
    pub enabled: bool,
    pub dry_run: bool,
    pub allow_move: bool,
    pub rollback_on_exit: bool,
    pub recover_unclean_session: bool,
    pub foreground_min_percent: u8,
    pub foreground_max_percent: u8,
    pub background_high_min_percent: u8,
    pub background_high_max_percent: u8,
    pub minimum_headroom_percent: u8,
    pub allowed_identities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassificationConfig {
    pub interval_ms: u64,
    pub minimum_confidence: f64,
    pub confirmation_samples: u32,
    pub browser_heavy_process_count: usize,
    pub browser_heavy_memory_percent: f64,
    pub virtualization_memory_percent: f64,
    pub gaming_background_memory_percent: f64,
    pub protected_executables: Vec<String>,
    pub critical_executables: Vec<String>,
    pub game_executables: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    pub process_sample_interval_ms: u64,
    pub smaps_rollup_interval_ms: u64,
    pub smaps_rollup_budget: usize,
    pub retention_days: u64,
    pub retention_interval_ms: u64,
    pub sqlite_batch_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralConfig {
    pub mode: String,
    pub sample_interval_ms: u64,
    pub database_path: PathBuf,
    pub allow_automatic_actions: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyConfig {
    pub max_cpu_overhead_percent: f64,
    pub max_io_write_mib_per_second: u64,
    pub rollback_on_daemon_exit: bool,
    pub rollback_on_error: bool,
    pub protect_foreground: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PressureConfig {
    pub watch_available_percent: u8,
    pub pressure_available_percent: u8,
    pub critical_available_percent: u8,
    pub emergency_available_percent: u8,
    pub psi_some_avg10_threshold: f64,
    pub psi_full_avg10_threshold: f64,
    pub emergency_psi_full_avg10_threshold: f64,
    pub major_fault_rate_threshold: f64,
    pub swap_in_rate_threshold: f64,
    pub swap_out_rate_threshold: f64,
    pub state_hold_seconds: u64,
    pub recovery_hold_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub enabled: bool,
    pub evaluation_interval_ms: u64,
    pub decision_heartbeat_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfig {
    pub backend: String,
    pub preferred_low_latency: String,
    pub preferred_capacity: String,
    pub enabled: bool,
    pub active_profile: String,
    pub dry_run: bool,
    pub allow_runtime_reconfigure: bool,
    pub allow_persistent_reconfigure: bool,
    pub max_zram_percent_ram: u8,
    pub safe_headroom_percent: u8,
    pub benchmark_enabled: bool,
    pub benchmark_max_bytes: u64,
    pub max_cpu_overhead_percent: f64,
    pub min_capacity_gain_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TieringConfig {
    pub enabled: bool,
    pub dry_run: bool,
    pub preferred_backend: String,
    pub allow_runtime_reconfigure: bool,
    pub allow_persistent_reconfigure: bool,
    pub allow_swapfile_create: bool,
    pub require_nvme: bool,
    pub max_swapfile_percent_disk: u8,
    pub min_free_disk_gib: u64,
    pub max_write_mib_per_second: u64,
    pub daily_write_budget_gib: u64,
    pub benchmark_enabled: bool,
    pub benchmark_max_bytes: u64,
    pub zswap_pool_min_percent: u8,
    pub zswap_pool_max_percent: u8,
    pub allow_shrinker: bool,
    pub rated_tbw: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KsmConfig {
    pub enabled: bool,
    pub live_apply: bool,
    pub profiles: Vec<String>,
    pub min_observation_seconds: u64,
    pub min_mergeable_bytes: u64,
    pub max_cpu_overhead_percent: f64,
    pub min_process_profit_bytes: i64,
    pub min_system_profit_bytes: i64,
    pub max_cow_events_per_second: u64,
    pub inefficiency_windows: u32,
    pub cooldown_seconds: u64,
    pub scanner_pages_to_scan_min: u64,
    pub scanner_pages_to_scan_max: u64,
    pub scanner_sleep_millisecs_min: u64,
    pub validation_max_seconds: u64,
    pub validation_max_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DamonConfig {
    pub enabled: bool,
    pub mode: String,
    pub allow_monitor_session: bool,
    pub preferred_operation: String,
    pub sample_us: u64,
    pub aggr_us: u64,
    pub update_us: u64,
    pub min_regions: u32,
    pub max_regions: u32,
    pub max_cpu_overhead_percent: f64,
    pub max_session_seconds: u64,
    pub max_samples_per_session: u64,
    pub retention_days: u64,
    pub export_max_bytes: u64,
    pub max_action_time_ms: u64,
    pub max_action_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DamosConfig {
    pub enabled: bool,
    pub live_apply: bool,
    pub min_complete_cold_windows: u32,
    pub refault_window_seconds: u64,
    pub blacklist_seconds: u64,
    pub max_total_applied_bytes: u64,
    pub apply_interval_us: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GamingConfig {
    pub auto_detect: bool,
    pub protect_gamescope: bool,
    pub protect_steam: bool,
    pub background_reclaim: bool,
}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub config: Config,
    pub sha256: String,
    pub path: PathBuf,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration at {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot parse configuration at {path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("configuration at {path} is not valid UTF-8: {source}")]
    Utf8 {
        path: PathBuf,
        source: std::str::Utf8Error,
    },
    #[error("invalid configuration field `{field}`: {message}")]
    Validation {
        field: &'static str,
        message: String,
    },
}

impl Config {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("<memory>"),
            source: Box::new(source),
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.general.mode != "observe" {
            return Err(validation(
                "general.mode",
                "must be exactly `observe` during Phase 3",
            ));
        }
        if self.general.allow_automatic_actions {
            return Err(validation(
                "general.allow_automatic_actions",
                "must be false during Phase 3",
            ));
        }
        for (field, value) in [
            (
                "cgroups.foreground_min_percent",
                self.cgroups.foreground_min_percent,
            ),
            (
                "cgroups.foreground_max_percent",
                self.cgroups.foreground_max_percent,
            ),
            (
                "cgroups.background_high_min_percent",
                self.cgroups.background_high_min_percent,
            ),
            (
                "cgroups.background_high_max_percent",
                self.cgroups.background_high_max_percent,
            ),
            (
                "cgroups.minimum_headroom_percent",
                self.cgroups.minimum_headroom_percent,
            ),
        ] {
            validate_percentage(field, f64::from(value))?;
        }
        if self.cgroups.foreground_min_percent > self.cgroups.foreground_max_percent {
            return Err(validation(
                "cgroups.foreground_min_percent",
                "must not exceed cgroups.foreground_max_percent",
            ));
        }
        if self.cgroups.background_high_min_percent > self.cgroups.background_high_max_percent {
            return Err(validation(
                "cgroups.background_high_min_percent",
                "must not exceed cgroups.background_high_max_percent",
            ));
        }
        if u16::from(self.cgroups.foreground_max_percent)
            + u16::from(self.cgroups.minimum_headroom_percent)
            > 100
        {
            return Err(validation(
                "cgroups.minimum_headroom_percent",
                "foreground maximum plus headroom must not exceed 100 percent",
            ));
        }
        for identity in &self.cgroups.allowed_identities {
            if identity.len() != 64
                || !identity
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(validation(
                    "cgroups.allowed_identities",
                    "entries must be lowercase SHA-256 identities",
                ));
            }
        }
        if self.general.database_path.as_os_str().is_empty() {
            return Err(validation("general.database_path", "must not be empty"));
        }
        if self.general.sample_interval_ms < 100 {
            return Err(validation(
                "general.sample_interval_ms",
                "must be at least 100",
            ));
        }
        if self.telemetry.process_sample_interval_ms < 1_000 {
            return Err(validation(
                "telemetry.process_sample_interval_ms",
                "must be at least 1000",
            ));
        }
        if self.telemetry.smaps_rollup_interval_ms < 5_000 {
            return Err(validation(
                "telemetry.smaps_rollup_interval_ms",
                "must be at least 5000",
            ));
        }
        if self.telemetry.smaps_rollup_interval_ms < self.telemetry.process_sample_interval_ms {
            return Err(validation(
                "telemetry.smaps_rollup_interval_ms",
                "must not be shorter than telemetry.process_sample_interval_ms",
            ));
        }
        if self.telemetry.smaps_rollup_budget > 10_000 {
            return Err(validation(
                "telemetry.smaps_rollup_budget",
                "must not exceed 10000 processes",
            ));
        }
        if !(1..=3_650).contains(&self.telemetry.retention_days) {
            return Err(validation(
                "telemetry.retention_days",
                "must be between 1 and 3650",
            ));
        }
        if self.telemetry.retention_interval_ms < 60_000 {
            return Err(validation(
                "telemetry.retention_interval_ms",
                "must be at least 60000",
            ));
        }
        if !(1..=10_000).contains(&self.telemetry.sqlite_batch_size) {
            return Err(validation(
                "telemetry.sqlite_batch_size",
                "must be between 1 and 10000",
            ));
        }
        if self.classification.interval_ms < 1_000 {
            return Err(validation(
                "classification.interval_ms",
                "must be at least 1000",
            ));
        }
        if self.classification.interval_ms < self.telemetry.process_sample_interval_ms {
            return Err(validation(
                "classification.interval_ms",
                "must not be shorter than telemetry.process_sample_interval_ms",
            ));
        }
        if !self.classification.minimum_confidence.is_finite()
            || !(0.5..=1.0).contains(&self.classification.minimum_confidence)
        {
            return Err(validation(
                "classification.minimum_confidence",
                "must be between 0.5 and 1.0 inclusive",
            ));
        }
        if !(1..=20).contains(&self.classification.confirmation_samples) {
            return Err(validation(
                "classification.confirmation_samples",
                "must be between 1 and 20",
            ));
        }
        if !(1..=10_000).contains(&self.classification.browser_heavy_process_count) {
            return Err(validation(
                "classification.browser_heavy_process_count",
                "must be between 1 and 10000",
            ));
        }
        for (field, value) in [
            (
                "classification.browser_heavy_memory_percent",
                self.classification.browser_heavy_memory_percent,
            ),
            (
                "classification.virtualization_memory_percent",
                self.classification.virtualization_memory_percent,
            ),
            (
                "classification.gaming_background_memory_percent",
                self.classification.gaming_background_memory_percent,
            ),
        ] {
            validate_percentage(field, value)?;
        }
        for (field, values) in [
            (
                "classification.protected_executables",
                &self.classification.protected_executables,
            ),
            (
                "classification.critical_executables",
                &self.classification.critical_executables,
            ),
            (
                "classification.game_executables",
                &self.classification.game_executables,
            ),
        ] {
            for value in values {
                if value.is_empty()
                    || value.len() > 255
                    || value.contains(['/', '\\'])
                    || !value.chars().all(|character| {
                        character.is_ascii_alphanumeric() || "._+-".contains(character)
                    })
                {
                    return Err(validation(
                        field,
                        "entries must be executable basenames without paths or patterns",
                    ));
                }
            }
        }
        validate_percentage(
            "safety.max_cpu_overhead_percent",
            self.safety.max_cpu_overhead_percent,
        )?;
        validate_percentage(
            "pressure.watch_available_percent",
            f64::from(self.pressure.watch_available_percent),
        )?;
        validate_percentage(
            "pressure.pressure_available_percent",
            f64::from(self.pressure.pressure_available_percent),
        )?;
        validate_percentage(
            "pressure.critical_available_percent",
            f64::from(self.pressure.critical_available_percent),
        )?;
        validate_percentage(
            "pressure.emergency_available_percent",
            f64::from(self.pressure.emergency_available_percent),
        )?;
        if !(self.pressure.watch_available_percent > self.pressure.pressure_available_percent
            && self.pressure.pressure_available_percent > self.pressure.critical_available_percent
            && self.pressure.critical_available_percent > self.pressure.emergency_available_percent)
        {
            return Err(validation(
                "pressure.watch_available_percent",
                "memory thresholds must satisfy watch > pressure > critical > emergency",
            ));
        }
        validate_percentage(
            "pressure.psi_some_avg10_threshold",
            self.pressure.psi_some_avg10_threshold,
        )?;
        validate_percentage(
            "pressure.psi_full_avg10_threshold",
            self.pressure.psi_full_avg10_threshold,
        )?;
        validate_percentage(
            "pressure.emergency_psi_full_avg10_threshold",
            self.pressure.emergency_psi_full_avg10_threshold,
        )?;
        for (field, value) in [
            (
                "pressure.major_fault_rate_threshold",
                self.pressure.major_fault_rate_threshold,
            ),
            (
                "pressure.swap_in_rate_threshold",
                self.pressure.swap_in_rate_threshold,
            ),
            (
                "pressure.swap_out_rate_threshold",
                self.pressure.swap_out_rate_threshold,
            ),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(validation(field, "must be finite and non-negative"));
            }
        }
        if self.pressure.emergency_psi_full_avg10_threshold
            <= self.pressure.psi_full_avg10_threshold
        {
            return Err(validation(
                "pressure.emergency_psi_full_avg10_threshold",
                "must exceed pressure.psi_full_avg10_threshold",
            ));
        }
        if self.policy.evaluation_interval_ms < 1_000 {
            return Err(validation(
                "policy.evaluation_interval_ms",
                "must be at least 1000",
            ));
        }
        if self.policy.decision_heartbeat_seconds == 0 {
            return Err(validation(
                "policy.decision_heartbeat_seconds",
                "must be greater than zero",
            ));
        }
        if self.compression.backend != "detect" {
            return Err(validation(
                "compression.backend",
                "must be exactly `detect` during Phase 5",
            ));
        }
        if !matches!(
            self.compression.active_profile.as_str(),
            "safe" | "gaming" | "capacity"
        ) {
            return Err(validation(
                "compression.active_profile",
                "must be safe, gaming, or capacity",
            ));
        }
        for (field, value) in [
            (
                "compression.max_zram_percent_ram",
                f64::from(self.compression.max_zram_percent_ram),
            ),
            (
                "compression.safe_headroom_percent",
                f64::from(self.compression.safe_headroom_percent),
            ),
            (
                "compression.max_cpu_overhead_percent",
                self.compression.max_cpu_overhead_percent,
            ),
            (
                "compression.min_capacity_gain_percent",
                self.compression.min_capacity_gain_percent,
            ),
        ] {
            validate_percentage(field, value)?;
        }
        if self.compression.max_zram_percent_ram == 0 {
            return Err(validation(
                "compression.max_zram_percent_ram",
                "must be greater than zero",
            ));
        }
        if self.compression.benchmark_max_bytes == 0
            || self.compression.benchmark_max_bytes > 268_435_456
        {
            return Err(validation(
                "compression.benchmark_max_bytes",
                "must be between 1 and 268435456 bytes",
            ));
        }
        if !matches!(
            self.tiering.preferred_backend.as_str(),
            "detect" | "zram" | "zswap_nvme"
        ) {
            return Err(validation(
                "tiering.preferred_backend",
                "must be detect, zram, or zswap_nvme",
            ));
        }
        for (field, value) in [
            (
                "tiering.max_swapfile_percent_disk",
                self.tiering.max_swapfile_percent_disk,
            ),
            (
                "tiering.zswap_pool_min_percent",
                self.tiering.zswap_pool_min_percent,
            ),
            (
                "tiering.zswap_pool_max_percent",
                self.tiering.zswap_pool_max_percent,
            ),
        ] {
            validate_percentage(field, f64::from(value))?;
        }
        if self.tiering.max_swapfile_percent_disk == 0 {
            return Err(validation(
                "tiering.max_swapfile_percent_disk",
                "must be greater than zero",
            ));
        }
        if self.tiering.zswap_pool_min_percent == 0
            || self.tiering.zswap_pool_min_percent > self.tiering.zswap_pool_max_percent
        {
            return Err(validation(
                "tiering.zswap_pool_min_percent",
                "must be non-zero and not exceed the maximum",
            ));
        }
        if self.tiering.max_write_mib_per_second == 0
            || self.tiering.max_write_mib_per_second > self.safety.max_io_write_mib_per_second
        {
            return Err(validation(
                "tiering.max_write_mib_per_second",
                "must be non-zero and not exceed the global safety limit",
            ));
        }
        if self.tiering.daily_write_budget_gib == 0 {
            return Err(validation(
                "tiering.daily_write_budget_gib",
                "must be greater than zero",
            ));
        }
        if self.tiering.benchmark_max_bytes == 0 || self.tiering.benchmark_max_bytes > 268_435_456 {
            return Err(validation(
                "tiering.benchmark_max_bytes",
                "must be between 1 and 268435456",
            ));
        }
        if self
            .tiering
            .rated_tbw
            .is_some_and(|value| !value.is_finite() || value <= 0.0)
        {
            return Err(validation(
                "tiering.rated_tbw",
                "must be finite and positive when provided",
            ));
        }
        if self.ksm.enabled {
            return Err(validation(
                "ksm.enabled",
                "must remain false in the current implementation",
            ));
        }
        if self.ksm.live_apply {
            return Err(validation(
                "ksm.live_apply",
                "normal runtime must remain plan-only",
            ));
        }
        let allowed_profiles = ["vm", "browser", "electron"];
        if self.ksm.profiles.is_empty()
            || self
                .ksm
                .profiles
                .iter()
                .any(|profile| !allowed_profiles.contains(&profile.as_str()))
        {
            return Err(validation(
                "ksm.profiles",
                "must contain only vm, browser, and electron",
            ));
        }
        if self.ksm.min_observation_seconds == 0
            || self.ksm.min_mergeable_bytes == 0
            || self.ksm.inefficiency_windows == 0
            || self.ksm.cooldown_seconds == 0
            || self.ksm.validation_max_seconds == 0
            || self.ksm.validation_max_bytes == 0
        {
            return Err(validation("ksm", "bounded values must be non-zero"));
        }
        if !self.ksm.max_cpu_overhead_percent.is_finite()
            || self.ksm.max_cpu_overhead_percent <= 0.0
            || self.ksm.max_cpu_overhead_percent > self.safety.max_cpu_overhead_percent
        {
            return Err(validation(
                "ksm.max_cpu_overhead_percent",
                "must be positive and at most the global safety ceiling",
            ));
        }
        if self.ksm.scanner_pages_to_scan_min == 0
            || self.ksm.scanner_pages_to_scan_min > self.ksm.scanner_pages_to_scan_max
            || self.ksm.scanner_sleep_millisecs_min == 0
        {
            return Err(validation("ksm.scanner", "invalid scanner bounds"));
        }
        if self.damon.enabled {
            return Err(validation(
                "damon.enabled",
                "must remain false in the current implementation",
            ));
        }
        if self.damon.mode != "monitor_only" {
            return Err(validation(
                "damon.mode",
                "must be exactly `monitor_only` in the current implementation",
            ));
        }
        if self.damon.allow_monitor_session {
            return Err(validation(
                "damon.allow_monitor_session",
                "normal runtime must not start a monitoring session",
            ));
        }
        if self.damon.preferred_operation != "vaddr" {
            return Err(validation(
                "damon.preferred_operation",
                "must be vaddr for Phase 7",
            ));
        }
        if self.damon.sample_us < 100
            || self.damon.aggr_us < self.damon.sample_us
            || self.damon.update_us < self.damon.aggr_us
        {
            return Err(validation(
                "damon.sample_us",
                "must satisfy 100 <= sample <= aggregation <= update",
            ));
        }
        if self.damon.min_regions == 0
            || self.damon.min_regions > self.damon.max_regions
            || self.damon.max_regions > 100_000
        {
            return Err(validation("damon.min_regions", "invalid region bounds"));
        }
        if !self.damon.max_cpu_overhead_percent.is_finite()
            || self.damon.max_cpu_overhead_percent < 0.0
            || self.damon.max_cpu_overhead_percent > self.safety.max_cpu_overhead_percent
        {
            return Err(validation(
                "damon.max_cpu_overhead_percent",
                "must not exceed the global safety ceiling",
            ));
        }
        if self.damon.max_session_seconds == 0
            || self.damon.max_session_seconds > 180
            || self.damon.max_samples_per_session == 0
            || self.damon.retention_days == 0
            || self.damon.export_max_bytes == 0
        {
            return Err(validation(
                "damon.max_session_seconds",
                "session, sample, retention, and export bounds must be non-zero and bounded",
            ));
        }
        if self.damos.enabled || self.damos.live_apply {
            return Err(validation(
                "damos.live_apply",
                "Phase 8 production DAMOS must remain disabled and plan-only",
            ));
        }
        if self.damos.min_complete_cold_windows < 3
            || self.damos.refault_window_seconds == 0
            || self.damos.blacklist_seconds < self.damos.refault_window_seconds
            || self.damos.max_total_applied_bytes == 0
            || self.damos.max_total_applied_bytes > self.damon.max_action_bytes
            || self.damos.apply_interval_us == 0
        {
            return Err(validation(
                "damos",
                "invalid cold evidence, cooldown, total ceiling, or apply interval",
            ));
        }
        Ok(())
    }
}

impl LoadedConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let text = std::str::from_utf8(&bytes).map_err(|source| ConfigError::Utf8 {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Config = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
        config.validate()?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        Ok(Self {
            config,
            sha256,
            path: path.to_path_buf(),
        })
    }
}

fn validation(field: &'static str, message: impl Into<String>) -> ConfigError {
    ConfigError::Validation {
        field,
        message: message.into(),
    }
}

fn validate_percentage(field: &'static str, value: f64) -> Result<(), ConfigError> {
    if value.is_finite() && (0.0..=100.0).contains(&value) {
        Ok(())
    } else {
        Err(validation(field, "must be between 0 and 100 inclusive"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: &str = include_str!("../../../config/default.toml");

    fn changed(from: &str, to: &str) -> String {
        DEFAULT.replacen(from, to, 1)
    }

    #[test]
    fn parses_default_configuration() {
        let config = Config::from_toml(DEFAULT).expect("default configuration should parse");
        assert_eq!(config.general.mode, "observe");
        assert!(!config.general.allow_automatic_actions);
        assert!(!config.cgroups.enabled);
        assert!(config.cgroups.dry_run);
        assert!(!config.cgroups.allow_move);
    }

    #[test]
    fn rejects_invalid_cgroup_bounds_and_allow_list() {
        for (from, to, field) in [
            (
                "foreground_min_percent = 5",
                "foreground_min_percent = 41",
                "cgroups.foreground_min_percent",
            ),
            (
                "minimum_headroom_percent = 10",
                "minimum_headroom_percent = 61",
                "cgroups.minimum_headroom_percent",
            ),
            (
                "allowed_identities = []",
                "allowed_identities = [\"pid-123\"]",
                "cgroups.allowed_identities",
            ),
        ] {
            let error = Config::from_toml(&changed(from, to)).expect_err("must reject value");
            assert!(error.to_string().contains(field));
        }
    }

    #[test]
    fn rejects_non_observe_mode_with_field_name() {
        let error = Config::from_toml(&changed("mode = \"observe\"", "mode = \"safe\""))
            .expect_err("safe mode must be rejected");
        assert!(error.to_string().contains("general.mode"));
    }

    #[test]
    fn rejects_automatic_actions_with_field_name() {
        let error = Config::from_toml(&changed(
            "allow_automatic_actions = false",
            "allow_automatic_actions = true",
        ))
        .expect_err("automatic actions must be rejected");
        assert!(error
            .to_string()
            .contains("general.allow_automatic_actions"));
    }

    #[test]
    fn rejects_zero_interval_with_field_name() {
        let error = Config::from_toml(&changed(
            "sample_interval_ms = 1000",
            "sample_interval_ms = 0",
        ))
        .expect_err("zero interval must be rejected");
        assert!(error.to_string().contains("general.sample_interval_ms"));
    }

    #[test]
    fn rejects_aggressive_telemetry_intervals_with_field_names() {
        for (from, to, field) in [
            (
                "process_sample_interval_ms = 5000",
                "process_sample_interval_ms = 999",
                "telemetry.process_sample_interval_ms",
            ),
            (
                "smaps_rollup_interval_ms = 60000",
                "smaps_rollup_interval_ms = 4999",
                "telemetry.smaps_rollup_interval_ms",
            ),
            (
                "retention_interval_ms = 3600000",
                "retention_interval_ms = 59999",
                "telemetry.retention_interval_ms",
            ),
        ] {
            let error = Config::from_toml(&changed(from, to)).expect_err("must reject interval");
            assert!(error.to_string().contains(field));
        }
    }

    #[test]
    fn rejects_invalid_retention_batch_and_smaps_budget() {
        for (from, to, field) in [
            (
                "retention_days = 7",
                "retention_days = 0",
                "telemetry.retention_days",
            ),
            (
                "sqlite_batch_size = 512",
                "sqlite_batch_size = 0",
                "telemetry.sqlite_batch_size",
            ),
            (
                "smaps_rollup_budget = 32",
                "smaps_rollup_budget = 10001",
                "telemetry.smaps_rollup_budget",
            ),
        ] {
            let error = Config::from_toml(&changed(from, to)).expect_err("must reject value");
            assert!(error.to_string().contains(field));
        }
    }

    #[test]
    fn rejects_aggressive_or_ambiguous_classification_configuration() {
        for (from, to, field) in [
            (
                "[classification]\ninterval_ms = 5000",
                "[classification]\ninterval_ms = 999",
                "classification.interval_ms",
            ),
            (
                "minimum_confidence = 0.65",
                "minimum_confidence = 0.49",
                "classification.minimum_confidence",
            ),
            (
                "confirmation_samples = 3",
                "confirmation_samples = 0",
                "classification.confirmation_samples",
            ),
            (
                "protected_executables = []",
                "protected_executables = [\"/usr/bin/process\"]",
                "classification.protected_executables",
            ),
        ] {
            let error = Config::from_toml(&changed(from, to)).expect_err("must reject value");
            assert!(error.to_string().contains(field));
        }
    }

    #[test]
    fn rejects_empty_database_path() {
        let error = Config::from_toml(&changed(
            "database_path = \"/var/lib/nemor/nemor.db\"",
            "database_path = \"\"",
        ))
        .expect_err("empty database path must be rejected");
        assert!(error.to_string().contains("general.database_path"));
    }

    #[test]
    fn rejects_out_of_order_memory_thresholds() {
        let error = Config::from_toml(&changed(
            "watch_available_percent = 20",
            "watch_available_percent = 10",
        ))
        .expect_err("out-of-order thresholds must be rejected");
        assert!(error
            .to_string()
            .contains("pressure.watch_available_percent"));
    }

    #[test]
    fn rejects_invalid_phase_four_pressure_thresholds() {
        for (from, to, field) in [
            (
                "emergency_available_percent = 3",
                "emergency_available_percent = 7",
                "pressure.watch_available_percent",
            ),
            (
                "emergency_psi_full_avg10_threshold = 10.0",
                "emergency_psi_full_avg10_threshold = 1.0",
                "pressure.emergency_psi_full_avg10_threshold",
            ),
            (
                "major_fault_rate_threshold = 100.0",
                "major_fault_rate_threshold = -1.0",
                "pressure.major_fault_rate_threshold",
            ),
        ] {
            let error = Config::from_toml(&changed(from, to)).expect_err("must reject threshold");
            assert!(error.to_string().contains(field));
        }
    }

    #[test]
    fn rejects_invalid_policy_frequency_and_heartbeat() {
        for (from, to, field) in [
            (
                "evaluation_interval_ms = 5000",
                "evaluation_interval_ms = 999",
                "policy.evaluation_interval_ms",
            ),
            (
                "decision_heartbeat_seconds = 300",
                "decision_heartbeat_seconds = 0",
                "policy.decision_heartbeat_seconds",
            ),
        ] {
            let error = Config::from_toml(&changed(from, to)).expect_err("must reject interval");
            assert!(error.to_string().contains(field));
        }
    }

    #[test]
    fn validates_phase_five_compression_configuration() {
        for (from, to, field) in [
            (
                "active_profile = \"safe\"",
                "active_profile = \"fast\"",
                "compression.active_profile",
            ),
            (
                "max_zram_percent_ram = 100",
                "max_zram_percent_ram = 0",
                "compression.max_zram_percent_ram",
            ),
            (
                "benchmark_max_bytes = 67108864",
                "benchmark_max_bytes = 0",
                "compression.benchmark_max_bytes",
            ),
            (
                "max_cpu_overhead_percent = 2.0",
                "max_cpu_overhead_percent = nan",
                "compression.max_cpu_overhead_percent",
            ),
        ] {
            let error = Config::from_toml(&changed(from, to)).expect_err("must reject zram field");
            assert!(error.to_string().contains(field), "{error}");
        }
    }

    #[test]
    fn validates_phase_six_tiering_safety_bounds() {
        for (from, to, field) in [
            (
                "preferred_backend = \"detect\"",
                "preferred_backend = \"magic\"",
                "tiering.preferred_backend",
            ),
            (
                "max_write_mib_per_second = 100",
                "max_write_mib_per_second = 201",
                "tiering.max_write_mib_per_second",
            ),
            (
                "zswap_pool_min_percent = 5",
                "zswap_pool_min_percent = 21",
                "tiering.zswap_pool_min_percent",
            ),
        ] {
            let error = Config::from_toml(&changed(from, to))
                .expect_err("unsafe tiering configuration must be rejected");
            assert!(error.to_string().contains(field), "{error}");
        }
    }

    #[test]
    fn rejects_invalid_percentage_with_field_name() {
        let error = Config::from_toml(&changed(
            "max_cpu_overhead_percent = 5.0",
            "max_cpu_overhead_percent = 101.0",
        ))
        .expect_err("invalid percentage must be rejected");
        assert!(error
            .to_string()
            .contains("safety.max_cpu_overhead_percent"));
    }

    #[test]
    fn rejects_non_monitor_damon_mode() {
        let error = Config::from_toml(&changed("mode = \"monitor_only\"", "mode = \"reclaim\""))
            .expect_err("DAMON action mode must be rejected");
        assert!(error.to_string().contains("damon.mode"));
    }

    #[test]
    fn rejects_enabled_ksm() {
        let error = Config::from_toml(&changed("[ksm]\nenabled = false", "[ksm]\nenabled = true"))
            .expect_err("KSM must remain disabled");
        assert!(error.to_string().contains("ksm.enabled"));
    }

    #[test]
    fn phase_nine_ksm_is_always_plan_only_and_bounded() {
        let live = changed("live_apply=false", "live_apply=true");
        let error = Config::from_toml(&live).expect_err("KSM live apply must remain forbidden");
        assert!(error.to_string().contains("ksm.live_apply"));

        let cpu = changed(
            "max_cpu_overhead_percent = 0.8",
            "max_cpu_overhead_percent = 6.0",
        );
        let error = Config::from_toml(&cpu).expect_err("KSM CPU ceiling must be bounded");
        assert!(error.to_string().contains("ksm.max_cpu_overhead_percent"));

        let scanner = changed(
            "scanner_pages_to_scan_min = 50",
            "scanner_pages_to_scan_min = 1001",
        );
        let error = Config::from_toml(&scanner).expect_err("KSM scanner bounds must be ordered");
        assert!(error.to_string().contains("ksm.scanner"));
    }

    #[test]
    fn rejects_enabled_damon() {
        let error = Config::from_toml(&changed(
            "[damon]\nenabled = false",
            "[damon]\nenabled = true",
        ))
        .expect_err("DAMON must remain disabled");
        assert!(error.to_string().contains("damon.enabled"));
    }

    #[test]
    fn phase_eight_production_damos_is_always_plan_only() {
        for (from, to) in [
            ("[damos]\nenabled = false", "[damos]\nenabled = true"),
            ("live_apply = false", "live_apply = true"),
        ] {
            let error = Config::from_toml(&changed(from, to))
                .expect_err("production DAMOS mutation must be rejected");
            assert!(error.to_string().contains("damos.live_apply"));
        }
    }

    #[test]
    fn validates_phase_seven_damon_bounds() {
        for (from, to, field) in [
            (
                "preferred_operation = \"vaddr\"",
                "preferred_operation = \"paddr\"",
                "damon.preferred_operation",
            ),
            ("sample_us = 5000", "sample_us = 99", "damon.sample_us"),
            (
                "max_cpu_overhead_percent = 1.0",
                "max_cpu_overhead_percent = 6.0",
                "damon.max_cpu_overhead_percent",
            ),
            (
                "max_session_seconds = 120",
                "max_session_seconds = 181",
                "damon.max_session_seconds",
            ),
        ] {
            let error =
                Config::from_toml(&changed(from, to)).expect_err("unsafe DAMON bounds must fail");
            assert!(error.to_string().contains(field), "{error}");
        }
    }
}
