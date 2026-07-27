#![forbid(unsafe_code)]

use actuator::{BackendKind, CgroupBackend, CgroupStatus, LinuxCgroupBackend};
use anyhow::{Context, Result};
use common::{
    CheckResult, CheckStatus, DoctorReport, LinuxPaths, LoadedConfig, StatusReport, StatusState,
};
use policy_engine::{
    PlannedAction, PolicyEvidence, PressureState, RejectedAction, POLICY_NAME, RULE_VERSION,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::Path;
use zram::{CompressionMetrics, ZramAuditReport, ZramProfile, ZramProfilePlan};

#[derive(Debug, Clone)]
pub struct DoctorEnvironment {
    pub paths: LinuxPaths,
    pub operating_system: String,
}

impl Default for DoctorEnvironment {
    fn default() -> Self {
        Self {
            paths: LinuxPaths::default(),
            operating_system: std::env::consts::OS.to_owned(),
        }
    }
}

pub fn doctor(config_path: &Path, environment: &DoctorEnvironment) -> Result<DoctorReport> {
    let loaded = LoadedConfig::load(config_path).with_context(|| {
        format!(
            "doctor input configuration {} is invalid",
            config_path.display()
        )
    })?;
    let mut checks = Vec::new();

    checks.push(if environment.operating_system == "linux" {
        pass("operating_system", "running on Linux")
    } else {
        fail(
            "operating_system",
            format!(
                "Linux is required; detected {}",
                environment.operating_system
            ),
        )
    });
    checks.push(readable_file(
        "kernel",
        &environment.paths.kernel_release(),
        CheckStatus::Fail,
        "kernel release is identifiable",
    ));
    checks.push(readable_directory(
        "proc",
        &environment.paths.proc_dir(),
        CheckStatus::Fail,
        "/proc is available and readable",
    ));
    checks.push(readable_file(
        "proc_meminfo",
        &environment.paths.meminfo(),
        CheckStatus::Fail,
        "/proc/meminfo is readable",
    ));
    checks.push(readable_file(
        "proc_vmstat",
        &environment.paths.vmstat(),
        CheckStatus::Fail,
        "/proc/vmstat is readable",
    ));
    checks.push(readable_file(
        "psi_memory",
        &environment.paths.psi_memory(),
        CheckStatus::Warn,
        "memory PSI is available",
    ));
    checks.push(readable_file(
        "psi_cpu",
        &environment.paths.psi_cpu(),
        CheckStatus::Warn,
        "CPU PSI is available",
    ));
    checks.push(readable_file(
        "psi_io",
        &environment.paths.psi_io(),
        CheckStatus::Warn,
        "I/O PSI is available",
    ));
    checks.push(readable_file(
        "cgroups_v2",
        &environment.paths.cgroup_controllers(),
        CheckStatus::Warn,
        "cgroups v2 controllers are detectable",
    ));
    checks.push(readable_file(
        "os_release",
        &environment.paths.os_release(),
        CheckStatus::Fail,
        "/etc/os-release is readable",
    ));
    checks.push(distribution_check(&environment.paths.os_release()));
    checks.push(readable_file(
        "machine_id",
        &environment.paths.machine_id(),
        CheckStatus::Fail,
        "/etc/machine-id is readable",
    ));
    checks.push(readable_file(
        "configuration",
        config_path,
        CheckStatus::Fail,
        "configuration is readable and valid",
    ));
    checks.extend(database_path_checks(&loaded.config.general.database_path));

    Ok(DoctorReport { checks })
}

pub fn status(config_path: &Path) -> Result<StatusReport> {
    let loaded = LoadedConfig::load(config_path).with_context(|| {
        format!(
            "status input configuration {} is invalid",
            config_path.display()
        )
    })?;
    storage::inspect_status(&loaded.config.general.database_path)
}

pub fn report_latest(config_path: &Path) -> Result<storage::LatestTelemetryReport> {
    let loaded = LoadedConfig::load(config_path).with_context(|| {
        format!(
            "report input configuration {} is invalid",
            config_path.display()
        )
    })?;
    storage::latest_telemetry_report(&loaded.config.general.database_path)
}

pub fn workload_latest(config_path: &Path) -> Result<storage::LatestWorkloadReport> {
    let loaded = LoadedConfig::load(config_path).with_context(|| {
        format!(
            "workload input configuration {} is invalid",
            config_path.display()
        )
    })?;
    storage::latest_workload_report(&loaded.config.general.database_path)
}

pub fn cgroups_status(config_path: &Path) -> Result<CgroupStatus> {
    let loaded = LoadedConfig::load(config_path).with_context(|| {
        format!(
            "cgroups status input configuration {} is invalid",
            config_path.display()
        )
    })?;
    let backend = LinuxCgroupBackend::default();
    let capabilities = backend.capabilities()?;
    let stored = storage::inspect_cgroup_status(&loaded.config.general.database_path)?;
    Ok(CgroupStatus {
        cgroup_v2: capabilities.cgroup_v2,
        memory_controller: capabilities.memory_controller,
        enabled: loaded.config.cgroups.enabled,
        dry_run: loaded.config.general.mode == "observe"
            || loaded.config.cgroups.dry_run
            || !loaded.config.cgroups.enabled,
        backend: BackendKind::LinuxCgroupfs,
        managed_groups: stored.managed_groups,
        assignments: stored.assignments,
        rollback_pending: stored.rollback_pending,
        stale_recovery_state: stored.stale_recovery_state,
        last_safety_error: stored.last_safety_error,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyStatus {
    pub enabled: bool,
    pub policy_name: String,
    pub rule_version: String,
    pub current_state: PressureState,
    pub previous_state: Option<PressureState>,
    pub state_since_ns: i64,
    pub candidate_state: Option<PressureState>,
    pub dry_run: bool,
    pub evidence: Vec<PolicyEvidence>,
    pub planned_actions: Vec<PlannedAction>,
    pub rejected_actions: Vec<RejectedAction>,
}

pub fn policy_latest(config_path: &Path) -> Result<storage::LatestPolicyDecision> {
    let loaded = LoadedConfig::load(config_path).with_context(|| {
        format!(
            "policy latest input configuration {} is invalid",
            config_path.display()
        )
    })?;
    storage::latest_policy_decision(&loaded.config.general.database_path)
}

pub fn policy_status(config_path: &Path) -> Result<PolicyStatus> {
    let loaded = LoadedConfig::load(config_path).with_context(|| {
        format!(
            "policy status input configuration {} is invalid",
            config_path.display()
        )
    })?;
    let latest = storage::latest_policy_decision(&loaded.config.general.database_path)?;
    Ok(PolicyStatus {
        enabled: loaded.config.policy.enabled,
        policy_name: POLICY_NAME.to_owned(),
        rule_version: RULE_VERSION.to_owned(),
        current_state: latest.pressure_state,
        previous_state: latest.audit.previous_state,
        state_since_ns: latest.audit.state_since_ns,
        candidate_state: latest.audit.candidate_state,
        dry_run: latest.audit.dry_run,
        evidence: latest.audit.evidence,
        planned_actions: latest.audit.planned_actions,
        rejected_actions: latest.audit.rejected_actions,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZramDeviceStatus {
    pub inventory: zram::DeviceInventory,
    pub metrics: CompressionMetrics,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZramStatus {
    pub available: bool,
    pub devices: Vec<ZramDeviceStatus>,
    pub enabled: bool,
    pub dry_run: bool,
    pub rollback_pending: bool,
    pub recovery_pending: bool,
}

pub fn zram_status(config_path: &Path) -> Result<ZramStatus> {
    let loaded = LoadedConfig::load(config_path).context("invalid zram status configuration")?;
    let inventory = zram::inspect_linux(Path::new("/"))?;
    Ok(ZramStatus {
        available: inventory.available,
        devices: inventory
            .devices
            .into_iter()
            .map(|inventory| ZramDeviceStatus {
                metrics: inventory.metrics(),
                inventory,
            })
            .collect(),
        enabled: loaded.config.compression.enabled,
        dry_run: loaded.config.general.mode == "observe" || loaded.config.compression.dry_run,
        rollback_pending: false,
        recovery_pending: false,
    })
}

pub fn zram_profiles(config_path: &Path) -> Result<Vec<ZramProfilePlan>> {
    let loaded = LoadedConfig::load(config_path).context("invalid zram profile configuration")?;
    let inventory = zram::inspect_linux(Path::new("/"))?;
    let (total_ram_bytes, available_bytes) = read_memory_capacity()?;
    Ok(inventory
        .devices
        .iter()
        .flat_map(|device| {
            [
                ZramProfile::Safe,
                ZramProfile::Gaming,
                ZramProfile::Capacity,
            ]
            .map(|requested| {
                zram::plan_profile(
                    &zram::ProfileContext {
                        requested,
                        device,
                        benchmarks: &[],
                        total_ram_bytes,
                        mem_available_bytes: available_bytes,
                        current_used_bytes: device.mm_stat.mem_used_total.unwrap_or(0),
                        pressure_state: PressureState::Watch,
                        psi_full_avg10: None,
                        swap_in_per_second: None,
                        gaming: requested == ZramProfile::Gaming,
                        pressure_worsening: false,
                        safety_events: 0,
                        rollback_pending: false,
                        provider_matches_snapshot: true,
                    },
                    &loaded.config.compression,
                    &loaded.config.general.mode,
                )
            })
        })
        .collect())
}

pub fn zram_report_latest(config_path: &Path) -> Result<ZramAuditReport> {
    let loaded = LoadedConfig::load(config_path).context("invalid zram report configuration")?;
    let snapshot = storage::latest_configuration_snapshot(
        &loaded.config.general.database_path,
        zram::AUDIT_REASON,
    )?;
    serde_json::from_str(&snapshot.system_values_json).context("invalid stored zram audit JSON")
}

pub fn tiering_status(config_path: &Path) -> Result<tiering::TieringAuditReport> {
    let loaded = LoadedConfig::load(config_path).context("invalid tiering status configuration")?;
    tiering::inspect_host(&loaded.config.tiering, 0).map_err(anyhow::Error::msg)
}

pub fn tiering_recommend(config_path: &Path) -> Result<tiering::BackendRecommendation> {
    Ok(tiering_status(config_path)?.recommendation)
}

pub fn tiering_report_latest(config_path: &Path) -> Result<tiering::TieringAuditReport> {
    let loaded = LoadedConfig::load(config_path).context("invalid tiering report configuration")?;
    let snapshot = storage::latest_configuration_snapshot(
        &loaded.config.general.database_path,
        tiering::TIERING_AUDIT_REASON,
    )?;
    serde_json::from_str(&snapshot.system_values_json).context("invalid stored tiering audit JSON")
}

pub fn damon_status(config_path: &Path) -> Result<damon::DamonReport> {
    let loaded = LoadedConfig::load(config_path).context("invalid DAMON status configuration")?;
    Ok(damon::observe_report(
        &loaded.config.damon,
        Some(
            std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .unwrap_or_default()
                .trim()
                .to_owned(),
        ),
    ))
}

pub fn damon_report_latest(config_path: &Path) -> Result<damon::DamonReport> {
    let loaded = LoadedConfig::load(config_path).context("invalid DAMON report configuration")?;
    let snapshot = storage::latest_configuration_snapshot(
        &loaded.config.general.database_path,
        damon::AUDIT_REASON,
    )?;
    serde_json::from_str(&snapshot.system_values_json).context("invalid stored DAMON audit JSON")
}

pub fn damon_sessions(config_path: &Path) -> Result<Vec<String>> {
    let loaded = LoadedConfig::load(config_path).context("invalid DAMON sessions configuration")?;
    let latest = storage::latest_configuration_snapshot(
        &loaded.config.general.database_path,
        damon::AUDIT_REASON,
    );
    Ok(latest
        .ok()
        .map(|snapshot| vec![snapshot.created_at])
        .unwrap_or_default())
}

pub fn damon_export(config_path: &Path, format: damon::ExportFormat, output: &Path) -> Result<u64> {
    let loaded = LoadedConfig::load(config_path).context("invalid DAMON export configuration")?;
    damon::export_dataset(output, format, &[], loaded.config.damon.export_max_bytes)
        .map_err(anyhow::Error::msg)
}

pub fn damos_status(config_path: &Path) -> Result<damos::DamosReport> {
    let loaded = LoadedConfig::load(config_path).context("invalid DAMOS status configuration")?;
    let damon_capability = damon::inspect_linux(
        Path::new("/"),
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|value| value.trim().to_owned()),
    );
    Ok(damos::DamosReport {
        schema: damos::REPORT_SCHEMA.into(),
        capability: damos::observe_capability(&damon_capability),
        plan: None,
        shadow_stats: None,
        live_stats: None,
        reclaim: None,
        refault: None,
        refault_state: damos::RefaultState::NotEvaluated,
        blacklist: None,
        cleanup: true,
        recovery: true,
        recovery_idempotent: true,
        host_unchanged: true,
        dry_run: true,
        blocked_reasons: vec![if loaded.config.damos.live_apply {
            "production_live_apply_forbidden"
        } else {
            "validation_harness_only"
        }
        .into()],
    })
}

pub fn damos_history(config_path: &Path) -> Result<Vec<storage::DamosHistoryEntry>> {
    let loaded = LoadedConfig::load(config_path).context("invalid DAMOS history configuration")?;
    storage::damos_history(&loaded.config.general.database_path, 20).or_else(|_| Ok(Vec::new()))
}

pub fn damos_plan_latest(config_path: &Path) -> Result<Option<storage::DamosHistoryEntry>> {
    Ok(damos_history(config_path)?.into_iter().next())
}

pub fn damos_blacklist(config_path: &Path) -> Result<Vec<damos::BlacklistRecord>> {
    let loaded =
        LoadedConfig::load(config_path).context("invalid DAMOS blacklist configuration")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| i64::try_from(value.as_nanos()).unwrap_or(i64::MAX))
        .unwrap_or_default();
    storage::damos_blacklist(&loaded.config.general.database_path, now).or_else(|_| Ok(Vec::new()))
}

fn read_memory_capacity() -> Result<(u64, u64)> {
    let input = fs::read_to_string("/proc/meminfo").context("cannot read /proc/meminfo")?;
    let read = |name: &str| -> Result<u64> {
        input
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.split_whitespace().next())
            .context("required meminfo field is unavailable")?
            .parse::<u64>()
            .context("invalid meminfo value")?
            .checked_mul(1024)
            .context("meminfo value overflow")
    };
    Ok((read("MemTotal:")?, read("MemAvailable:")?))
}

pub fn render_doctor(report: &DoctorReport, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(report).context("cannot serialize doctor report");
    }
    let mut output = String::new();
    for check in &report.checks {
        let status = match check.status {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        };
        output.push_str(&format!("[{status}] {}: {}\n", check.name, check.message));
        if let Some(details) = &check.details {
            output.push_str(&format!("       {details}\n"));
        }
    }
    Ok(output)
}

pub fn render_status(report: &StatusReport, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(report).context("cannot serialize status report");
    }
    let mut lines = vec![
        format!("Database: {}", report.database_path.display()),
        format!("Database present: {}", report.database_present),
        format!(
            "Schema version: {}",
            report
                .schema_version
                .map_or_else(|| "n/a".to_owned(), |value| value.to_string())
        ),
        format!("State: {}", state_name(report.state)),
        format!("Description: {}", report.state_description),
    ];
    if let Some(host) = &report.last_host {
        lines.push(format!(
            "Last host: {} ({}, kernel {})",
            host.hostname, host.distro, host.kernel_version
        ));
    } else {
        lines.push("Last host: n/a".to_owned());
    }
    if let Some(session) = &report.last_session {
        lines.extend([
            format!("Session id: {}", session.id),
            format!("Mode: {}", session.mode),
            format!("Started: {}", session.started_at),
            format!("Ended: {}", session.ended_at.as_deref().unwrap_or("n/a")),
            format!("Clean shutdown: {}", session.clean_shutdown),
            format!("Daemon version: {}", session.daemon_version),
        ]);
    } else {
        lines.push("Last session: n/a".to_owned());
    }
    Ok(format!("{}\n", lines.join("\n")))
}

pub fn render_report(report: &storage::LatestTelemetryReport, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(report).context("cannot serialize telemetry report");
    }
    let unavailable = if report.capabilities_unavailable.is_empty() {
        "none".to_owned()
    } else {
        report.capabilities_unavailable.join(", ")
    };
    Ok(format!(
        "Session id: {}\nStarted: {}\nEnded: {}\nSystem samples: {}\nProcess samples: {}\nMinimum MemAvailable: {}\nMaximum swap used: {}\nMaximum PSI memory some avg10: {}\nMaximum PSI memory full avg10: {}\nDelta major faults: {}\nDelta swap-in: {}\nDelta swap-out: {}\nZram observed: {}\nZswap observed: {}\nCapabilities unavailable: {}\n",
        report.session_id,
        report.started_at,
        report.ended_at.as_deref().unwrap_or("n/a"),
        report.system_samples,
        report.process_samples,
        optional_u64(report.min_mem_available_bytes),
        optional_u64(report.max_swap_used_bytes),
        optional_f64(report.max_psi_memory_some_avg10),
        optional_f64(report.max_psi_memory_full_avg10),
        optional_u64(report.delta_major_faults),
        optional_u64(report.delta_swap_in_pages),
        optional_u64(report.delta_swap_out_pages),
        report.zram_observed,
        report.zswap_observed,
        unavailable,
    ))
}

pub fn render_workload(report: &storage::LatestWorkloadReport, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(report).context("cannot serialize workload report");
    }
    let current = report
        .current_class
        .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
    let confidence = report
        .confidence
        .map_or_else(|| "n/a".to_owned(), |value| format!("{value:.2}"));
    let timestamp = report
        .last_change_timestamp_ns
        .map_or_else(|| "n/a".to_owned(), |value| value.to_string());
    let reasons = if report.top_reasons.is_empty() {
        "none".to_owned()
    } else {
        report.top_reasons.join("; ")
    };
    let gaming = if report.gaming_signals.is_empty() {
        "none".to_owned()
    } else {
        report.gaming_signals.join(", ")
    };
    Ok(format!(
        "Session id: {}\nClassification available: {}\nCurrent workload: {}\nConfidence: {}\nRule version: {}\nLast change timestamp_ns: {}\nTop reasons: {}\nGaming signals: {}\nPressure signal: {}\nGame processes: {}\nCritical processes: {}\nUnknown processes: {}\nStatus: {}\n",
        report.session_id,
        report.available,
        current,
        confidence,
        report.rule_version.as_deref().unwrap_or("n/a"),
        timestamp,
        reasons,
        gaming,
        report.pressure_signal.as_deref().unwrap_or("none"),
        report.game_processes,
        report.critical_processes,
        report.unknown_processes,
        report.message,
    ))
}

pub fn render_cgroups_status(report: &CgroupStatus, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(report)
            .context("cannot serialize cgroup status report");
    }
    Ok(format!(
        "Cgroup v2: {}\nMemory controller: {}\nEnabled: {}\nDry run: {}\nBackend: {:?}\nManaged groups: {}\nAssignments: {}\nRollback pending: {}\nStale recovery state: {}\nLast safety error: {}\n",
        report.cgroup_v2,
        report.memory_controller,
        report.enabled,
        report.dry_run,
        report.backend,
        report.managed_groups,
        report.assignments,
        report.rollback_pending,
        report.stale_recovery_state,
        report.last_safety_error.as_deref().unwrap_or("none"),
    ))
}

pub fn render_policy_status(report: &PolicyStatus, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(report).context("cannot serialize policy status");
    }
    Ok(format!(
        "Enabled: {}\nPolicy: {}\nRule version: {}\nCurrent state: {:?}\nPrevious state: {:?}\nState since: {}\nCandidate state: {:?}\nDry run: {}\nEvidence: {}\nPlanned actions: {}\nRejected actions: {}\n",
        report.enabled,
        report.policy_name,
        report.rule_version,
        report.current_state,
        report.previous_state,
        report.state_since_ns,
        report.candidate_state,
        report.dry_run,
        report.evidence.len(),
        report.planned_actions.len(),
        report.rejected_actions.len(),
    ))
}

pub fn render_policy_latest(report: &storage::LatestPolicyDecision, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(report)
            .context("cannot serialize latest policy decision");
    }
    Ok(format!(
        "Decision id: {}\nSession id: {}\nTimestamp: {}\nState: {:?}\nPolicy: {}\nRule version: {}\nDry run: {}\nModel version: {}\n",
        report.id,
        report.session_id,
        report.timestamp_ns,
        report.pressure_state,
        report.policy_name,
        report.rule_version,
        report.audit.dry_run,
        report.model_version.as_deref().unwrap_or("none"),
    ))
}

pub fn render_zram<T: Serialize + std::fmt::Debug>(report: &T, json: bool) -> Result<String> {
    if json {
        return serde_json::to_string_pretty(report).context("cannot serialize zram output");
    }
    Ok(format!("{report:#?}\n"))
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |value| value.to_string())
}

fn optional_f64(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |value| format!("{value:.2}"))
}

fn database_path_checks(database_path: &Path) -> Vec<CheckResult> {
    let database = if database_path.exists() {
        readable_file(
            "database_path",
            database_path,
            CheckStatus::Fail,
            "database file exists and is readable",
        )
    } else {
        warn(
            "database_path",
            "database file does not exist yet",
            Some(database_path.display().to_string()),
        )
    };
    let parent = database_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = readable_directory(
        "database_directory",
        parent,
        CheckStatus::Fail,
        "database parent directory exists and is readable",
    );
    vec![database, directory]
}

fn distribution_check(path: &Path) -> CheckResult {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let distribution = contents.lines().find_map(|line| {
                let (key, value) = line.split_once('=')?;
                (key.trim() == "ID")
                    .then(|| value.trim().trim_matches('"').trim_matches('\'').to_owned())
            });
            match distribution.filter(|value| !value.is_empty()) {
                Some(distribution) => pass_with_details(
                    "distribution",
                    "Linux distribution is identifiable",
                    Some(format!("id={distribution}")),
                ),
                None => fail("distribution", "os-release does not contain a valid ID"),
            }
        }
        Err(error) => result(
            "distribution",
            CheckStatus::Fail,
            "Linux distribution is not identifiable",
            Some(format!("path={}, error={error}", path.display())),
        ),
    }
}

fn readable_file(
    name: &str,
    path: &Path,
    missing_status: CheckStatus,
    success: &str,
) -> CheckResult {
    match File::open(path) {
        Ok(file) => match file.metadata() {
            Ok(metadata) if metadata.is_file() => {
                pass_with_details(name, success, Some(format!("path={}", path.display())))
            }
            Ok(_) => result(
                name,
                missing_status,
                "path is not a regular file",
                Some(format!("path={}", path.display())),
            ),
            Err(error) => result(
                name,
                missing_status,
                "cannot inspect opened path",
                Some(format!("path={}, error={error}", path.display())),
            ),
        },
        Err(error) => result(
            name,
            missing_status,
            "required path is unavailable or unreadable",
            Some(format!("path={}, error={error}", path.display())),
        ),
    }
}

fn readable_directory(
    name: &str,
    path: &Path,
    missing_status: CheckStatus,
    success: &str,
) -> CheckResult {
    match fs::read_dir(path) {
        Ok(_) => pass_with_details(name, success, Some(format!("path={}", path.display()))),
        Err(error) => result(
            name,
            missing_status,
            "directory is unavailable or unreadable",
            Some(format!("path={}, error={error}", path.display())),
        ),
    }
}

fn state_name(state: StatusState) -> &'static str {
    match state {
        StatusState::DatabaseMissing => "database_missing",
        StatusState::NoSessions => "no_sessions",
        StatusState::SessionOpen => "session_open",
        StatusState::ClosedClean => "closed_clean",
        StatusState::ClosedUnclean => "closed_unclean",
    }
}

fn pass(name: &str, message: impl Into<String>) -> CheckResult {
    pass_with_details(name, message, None)
}

fn pass_with_details(
    name: &str,
    message: impl Into<String>,
    details: Option<String>,
) -> CheckResult {
    result(name, CheckStatus::Pass, message, details)
}

fn warn(name: &str, message: impl Into<String>, details: Option<String>) -> CheckResult {
    result(name, CheckStatus::Warn, message, details)
}

fn fail(name: &str, message: impl Into<String>) -> CheckResult {
    result(name, CheckStatus::Fail, message, None)
}

fn result(
    name: &str,
    status: CheckStatus,
    message: impl Into<String>,
    details: Option<String>,
) -> CheckResult {
    CheckResult {
        name: name.to_owned(),
        status,
        message: message.into(),
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{CheckStatus, StatusState};
    use storage::Storage;
    use test_support::{snapshot_files, LinuxFixture};

    fn environment(fixture: &LinuxFixture) -> DoctorEnvironment {
        DoctorEnvironment {
            paths: fixture.paths(),
            operating_system: "linux".to_owned(),
        }
    }

    #[test]
    fn compatible_fixture_has_no_failures_and_valid_json() {
        let fixture = LinuxFixture::compatible().expect("fixture");
        let report = doctor(fixture.config_path(), &environment(&fixture)).expect("doctor");
        assert!(!report.has_failures());
        assert_eq!(report.exit_code(), 0);
        let json = render_doctor(&report, true).expect("JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed["checks"].is_array());
        let distribution = report
            .checks
            .iter()
            .find(|check| check.name == "distribution")
            .expect("distribution result");
        assert_eq!(distribution.details.as_deref(), Some("id=cachyos"));
    }

    #[test]
    fn cgroup_status_is_read_only_and_reports_safe_defaults() {
        let fixture = LinuxFixture::compatible().expect("fixture");
        let before = snapshot_files(fixture.root()).expect("before");
        let report = cgroups_status(fixture.config_path()).expect("cgroup status");
        assert!(!report.enabled);
        assert!(report.dry_run);
        assert_eq!(report.managed_groups, 0);
        assert_eq!(report.assignments, 0);
        let json = render_cgroups_status(&report, true).expect("JSON");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["backend"], "linux_cgroupfs");
        let after = snapshot_files(fixture.root()).expect("after");
        assert_eq!(before, after);
    }

    #[test]
    fn missing_psi_is_a_controlled_warning() {
        let fixture = LinuxFixture::compatible().expect("fixture");
        fixture
            .remove("proc/pressure/memory")
            .expect("remove PSI fixture");
        let report = doctor(fixture.config_path(), &environment(&fixture)).expect("doctor");
        let psi = report
            .checks
            .iter()
            .find(|check| check.name == "psi_memory")
            .expect("PSI result");
        assert_eq!(psi.status, CheckStatus::Warn);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn missing_cgroups_v2_is_a_controlled_warning() {
        let fixture = LinuxFixture::compatible().expect("fixture");
        fixture
            .remove("sys/fs/cgroup/cgroup.controllers")
            .expect("remove cgroup fixture");
        let report = doctor(fixture.config_path(), &environment(&fixture)).expect("doctor");
        let cgroup = report
            .checks
            .iter()
            .find(|check| check.name == "cgroups_v2")
            .expect("cgroup result");
        assert_eq!(cgroup.status, CheckStatus::Warn);
    }

    #[test]
    fn missing_machine_id_is_a_controlled_failure_with_exit_two() {
        let fixture = LinuxFixture::compatible().expect("fixture");
        fixture.remove("etc/machine-id").expect("remove machine-id");
        let report = doctor(fixture.config_path(), &environment(&fixture)).expect("doctor");
        let machine = report
            .checks
            .iter()
            .find(|check| check.name == "machine_id")
            .expect("machine result");
        assert_eq!(machine.status, CheckStatus::Fail);
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn doctor_does_not_modify_fixture_files() {
        let fixture = LinuxFixture::compatible().expect("fixture");
        let before = snapshot_files(fixture.root()).expect("before snapshot");
        let report = doctor(fixture.config_path(), &environment(&fixture)).expect("doctor");
        assert!(!report.has_failures());
        let after = snapshot_files(fixture.root()).expect("after snapshot");
        assert_eq!(before, after);
    }

    #[test]
    fn status_json_covers_missing_empty_open_clean_and_unclean_states() {
        let fixture = LinuxFixture::compatible().expect("fixture");
        let missing = status(fixture.config_path()).expect("missing status");
        assert_eq!(missing.state, StatusState::DatabaseMissing);
        assert_valid_status_json(&missing);

        let mut database = Storage::open(fixture.database_path()).expect("database");
        let empty = status(fixture.config_path()).expect("empty status");
        assert_eq!(empty.state, StatusState::NoSessions);
        assert_valid_status_json(&empty);

        let host = common::HostMetadata {
            machine_id: "fixture".to_owned(),
            hostname: "fixture".to_owned(),
            distro: "cachyos".to_owned(),
            distro_version: None,
            kernel_version: "6.12".to_owned(),
            cpu_model: None,
            cpu_cores: Some(1),
            ram_total_bytes: 1024,
            swap_total_bytes: 0,
            gpu_model: None,
            storage_model: None,
        };
        let host_id = database.upsert_host(&host).expect("host");
        let open_id = database
            .open_session(host_id, "0.1.0", "hash")
            .expect("open session");
        let open = status(fixture.config_path()).expect("open status");
        assert_eq!(open.state, StatusState::SessionOpen);
        assert!(open.state_description.contains("does not prove"));
        assert_valid_status_json(&open);

        database.close_session(open_id, true).expect("clean close");
        let clean = status(fixture.config_path()).expect("clean status");
        assert_eq!(clean.state, StatusState::ClosedClean);
        assert_valid_status_json(&clean);

        let unclean_id = database
            .open_session(host_id, "0.1.0", "hash")
            .expect("unclean session");
        database
            .close_session(unclean_id, false)
            .expect("unclean close");
        let unclean = status(fixture.config_path()).expect("unclean status");
        assert_eq!(unclean.state, StatusState::ClosedUnclean);
        assert_valid_status_json(&unclean);
    }

    #[test]
    fn latest_report_json_is_valid_correct_and_read_only() {
        let fixture = LinuxFixture::compatible().expect("fixture");
        let database = Storage::open(fixture.database_path()).expect("database");
        let host = common::HostMetadata {
            machine_id: "report-fixture".to_owned(),
            hostname: "fixture".to_owned(),
            distro: "cachyos".to_owned(),
            distro_version: None,
            kernel_version: "6.12".to_owned(),
            cpu_model: None,
            cpu_cores: Some(1),
            ram_total_bytes: 1024,
            swap_total_bytes: 0,
            gpu_model: None,
            storage_model: None,
        };
        let host_id = database.upsert_host(&host).expect("host");
        let session = database
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        for (timestamp, available, swap, faults) in [(1_i64, 900_i64, 1_i64, 3_i64), (2, 800, 4, 9)]
        {
            database
                .connection()
                .execute(
                    "INSERT INTO system_samples (
                        session_id, timestamp_ns, mem_total_bytes,
                        mem_available_bytes, swap_used_bytes, major_faults,
                        swap_in_pages, swap_out_pages, psi_memory_some_avg10,
                        psi_memory_full_avg10, zram_present, zswap_present,
                        capabilities_unavailable_json
                     ) VALUES (?1, ?2, 1000, ?3, ?4, ?5, ?5, ?5, 1.5, 0.5, 1, 0, '[\"psi_cpu\"]')",
                    (session, timestamp, available, swap, faults),
                )
                .expect("system row");
        }
        database
            .connection()
            .execute(
                "INSERT INTO process_samples (
                    session_id, timestamp_ns, pid, foreground
                 ) VALUES (?1, 1, 42, 0)",
                [session],
            )
            .expect("process row");
        drop(database);
        let before = std::fs::read(fixture.database_path()).expect("database before report");
        let report = report_latest(fixture.config_path()).expect("report");
        assert_eq!(report.system_samples, 2);
        assert_eq!(report.process_samples, 1);
        assert_eq!(report.min_mem_available_bytes, Some(800));
        assert_eq!(report.max_swap_used_bytes, Some(4));
        assert_eq!(report.delta_major_faults, Some(6));
        let json = render_report(&report, true).expect("JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["session_id"], session);
        let after = std::fs::read(fixture.database_path()).expect("database after report");
        assert_eq!(before, after);
    }

    fn assert_valid_status_json(report: &StatusReport) {
        let json = render_status(report, true).expect("status JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid status JSON");
        assert!(parsed["state"].is_string());
    }
}
