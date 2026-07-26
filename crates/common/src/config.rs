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
    pub compression: CompressionConfig,
    pub ksm: KsmConfig,
    pub damon: DamonConfig,
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
    pub psi_some_avg10_threshold: f64,
    pub psi_full_avg10_threshold: f64,
    pub state_hold_seconds: u64,
    pub recovery_hold_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfig {
    pub backend: String,
    pub preferred_low_latency: String,
    pub preferred_capacity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KsmConfig {
    pub enabled: bool,
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DamonConfig {
    pub enabled: bool,
    pub mode: String,
    pub max_action_time_ms: u64,
    pub max_action_bytes: u64,
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
        if !(self.pressure.watch_available_percent > self.pressure.pressure_available_percent
            && self.pressure.pressure_available_percent > self.pressure.critical_available_percent)
        {
            return Err(validation(
                "pressure.watch_available_percent",
                "memory thresholds must satisfy watch > pressure > critical",
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
        if self.ksm.enabled {
            return Err(validation("ksm.enabled", "must be false during Phase 3"));
        }
        if self.damon.enabled {
            return Err(validation("damon.enabled", "must be false during Phase 3"));
        }
        if self.damon.mode != "monitor_only" {
            return Err(validation(
                "damon.mode",
                "must be exactly `monitor_only` during Phase 3",
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
    fn rejects_enabled_damon() {
        let error = Config::from_toml(&changed(
            "[damon]\nenabled = false",
            "[damon]\nenabled = true",
        ))
        .expect_err("DAMON must remain disabled");
        assert!(error.to_string().contains("damon.enabled"));
    }
}
