#![forbid(unsafe_code)]

mod config;
mod host;
mod output;
mod paths;

pub use config::{
    ClassificationConfig, Config, ConfigError, LoadedConfig, PressureConfig, TelemetryConfig,
};
pub use host::{HostMetadata, HostMetadataError};
pub use output::{
    CheckResult, CheckStatus, DoctorReport, HostSummary, SessionSummary, StatusReport, StatusState,
};
pub use paths::LinuxPaths;
