#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub checks: Vec<CheckResult>,
}

impl DoctorReport {
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail)
    }

    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.has_failures() {
            2
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSummary {
    pub id: i64,
    pub machine_id: String,
    pub hostname: String,
    pub distro: String,
    pub distro_version: Option<String>,
    pub kernel_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: i64,
    pub host_id: i64,
    pub mode: String,
    pub daemon_version: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub clean_shutdown: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusState {
    DatabaseMissing,
    NoSessions,
    SessionOpen,
    ClosedClean,
    ClosedUnclean,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    pub database_path: PathBuf,
    pub database_present: bool,
    pub schema_version: Option<i64>,
    pub last_host: Option<HostSummary>,
    pub last_session: Option<SessionSummary>,
    pub state: StatusState,
    pub state_description: String,
}
