#![forbid(unsafe_code)]

use actuator::{ActuatorError, BackendKind, MutationSnapshot, SnapshotStore};
use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use classifier::{
    ForegroundState, ProcessClassification, WorkloadClass, WorkloadExplanation, WorkloadTransition,
};
use collector::{ProcessSample, SystemSample};
use common::{HostMetadata, HostSummary, SessionSummary, StatusReport, StatusState};
use policy_engine::{
    CandidateRejection, PlannedAction, PolicyDecision, PolicyEvidence, PolicyInput, PressureState,
    RejectedAction,
};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const MIGRATION_VERSION: i64 = 7;
pub const INITIAL_MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../migrations/0001_initial.sql"
));
pub const TELEMETRY_MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../migrations/0002_telemetry_baseline.sql"
));
pub const CLASSIFIER_MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../migrations/0003_workload_classifier.sql"
));
pub const CGROUP_MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../migrations/0004_cgroups.sql"
));
pub const DAMON_MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../migrations/0005_damon.sql"
));
pub const DAMOS_MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../migrations/0006_damos.sql"
));
pub const KSM_MIGRATION: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../migrations/0007_ksm.sql"
));

pub struct Storage {
    connection: Connection,
    path: PathBuf,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "cannot create database parent directory {}",
                    parent.display()
                )
            })?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("cannot open SQLite database {}", path.display()))?;
        initialize_connection(&connection)?;
        let mut storage = Self {
            connection,
            path: path.to_path_buf(),
        };
        storage.migrate()?;
        Ok(storage)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn insert_configuration_snapshot<T: Serialize, U: Serialize>(
        &self,
        session_id: i64,
        reason: &str,
        configuration: &T,
        system_values: &U,
    ) -> Result<i64> {
        if reason.is_empty() || reason.len() > 64 {
            bail!("invalid configuration snapshot reason");
        }
        let config_json =
            serde_json::to_string(configuration).context("cannot serialize snapshot plan")?;
        let system_values_json =
            serde_json::to_string(system_values).context("cannot serialize snapshot state")?;
        self.connection.execute(
            "INSERT INTO configuration_snapshots (
                session_id, reason, config_json, system_values_json
             ) VALUES (?1, ?2, ?3, ?4)",
            params![session_id, reason, config_json, system_values_json],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn insert_zram_benchmark<T: Serialize>(
        &self,
        host_id: i64,
        profile: &str,
        real_isolated_device: bool,
        results: &T,
    ) -> Result<i64> {
        if !matches!(profile, "safe" | "gaming" | "capacity") {
            bail!("invalid zram benchmark profile");
        }
        let parameters =
            serde_json::to_string(results).context("cannot serialize zram benchmark results")?;
        let status = if real_isolated_device {
            "completed_real"
        } else {
            "simulated_fixture"
        };
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        self.connection.execute(
            "INSERT INTO benchmark_runs (
                host_id, name, workload, profile, baseline, started_at,
                ended_at, status, parameters_json, notes
             ) VALUES (?1, 'zram-isolated', 'deterministic-fixtures', ?2, 0,
                       ?3, ?3, ?4, ?5, 'Phase 5 bounded benchmark')",
            params![host_id, profile, now, status, parameters],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn insert_policy_decision(
        &self,
        session_id: i64,
        decision: &PolicyDecision,
        heartbeat_seconds: u64,
    ) -> Result<bool> {
        let features = serde_json::to_string(&decision.input_features)
            .context("cannot serialize policy input features")?;
        let audit = PolicyActionAudit::from(decision);
        let actions =
            serde_json::to_string(&audit).context("cannot serialize policy action audit")?;
        let previous: Option<(i64, String, String)> = self
            .connection
            .query_row(
                "SELECT timestamp_ns, pressure_state, actions_json
                 FROM policy_decisions WHERE session_id=?1
                 ORDER BY timestamp_ns DESC, id DESC LIMIT 1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context("cannot read previous policy decision")?;
        let state = state_text(decision.current_state);
        let heartbeat_ns =
            i64::try_from(u128::from(heartbeat_seconds).saturating_mul(1_000_000_000))
                .unwrap_or(i64::MAX);
        if let Some((timestamp, old_state, old_actions)) = previous {
            let old_audit: PolicyActionAudit =
                serde_json::from_str(&old_actions).context("invalid previous policy audit JSON")?;
            let same_plan = old_audit.planned_actions == audit.planned_actions
                && old_audit.rejected_actions == audit.rejected_actions;
            if old_state == state
                && same_plan
                && decision.timestamp_ns.saturating_sub(timestamp) < heartbeat_ns
            {
                return Ok(false);
            }
        }
        self.connection.execute(
            "INSERT INTO policy_decisions (
                session_id, timestamp_ns, pressure_state, policy_name,
                input_features_json, actions_json, expected_gain_bytes,
                expected_cost_score, model_version, rule_version
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL, ?7)",
            params![
                session_id,
                decision.timestamp_ns,
                state,
                decision.policy_name,
                features,
                actions,
                decision.rule_version,
            ],
        )?;
        Ok(true)
    }

    pub fn policy_history_counts(&self, timestamp_ns: i64) -> Result<(usize, usize)> {
        let decision_count = self.connection.query_row(
            "SELECT COUNT(*) FROM (
                SELECT id FROM policy_decisions ORDER BY timestamp_ns DESC, id DESC LIMIT 20
             )",
            [],
            |row| row.get::<_, usize>(0),
        )?;
        let cutoff = timestamp_ns.saturating_sub(300_000_000_000);
        let safety_count = self.connection.query_row(
            "SELECT COUNT(*) FROM (
                SELECT id FROM safety_events
                WHERE timestamp_ns >= ?1 AND event_type LIKE 'cgroup_%'
                ORDER BY timestamp_ns DESC, id DESC LIMIT 20
             )",
            [cutoff],
            |row| row.get::<_, usize>(0),
        )?;
        Ok((decision_count, safety_count))
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn record_cgroup_safety_event(
        &self,
        session_id: Option<i64>,
        timestamp_ns: i64,
        severity: &str,
        event_type: &str,
        message: &str,
        context_json: Option<&str>,
    ) -> Result<()> {
        if !matches!(severity, "info" | "warning" | "error") || !event_type.starts_with("cgroup_") {
            bail!("invalid cgroup safety event");
        }
        self.connection.execute(
            "INSERT INTO safety_events (
                session_id, timestamp_ns, severity, event_type, message, context_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                session_id,
                timestamp_ns,
                severity,
                event_type,
                message,
                context_json
            ],
        )?;
        Ok(())
    }

    pub fn migrate(&mut self) -> Result<()> {
        self.apply_migration(1, INITIAL_MIGRATION, true)?;
        self.apply_migration(2, TELEMETRY_MIGRATION, false)?;
        self.apply_migration(3, CLASSIFIER_MIGRATION, false)?;
        self.apply_migration(4, CGROUP_MIGRATION, false)?;
        self.apply_migration(5, DAMON_MIGRATION, false)?;
        self.apply_migration(6, DAMOS_MIGRATION, false)?;
        self.apply_migration(7, KSM_MIGRATION, false)
    }

    pub fn migrate_source(&mut self, source: &str) -> Result<()> {
        self.verify_migration_source(1, source)
    }

    fn verify_migration_source(&self, version: i64, source: &str) -> Result<()> {
        let checksum = migration_checksum(source);
        let stored: Option<String> = self
            .connection
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = ?1",
                [version],
                |row| row.get(0),
            )
            .optional()
            .with_context(|| format!("cannot read migration version {version}"))?;
        match stored {
            Some(stored) if stored == checksum => Ok(()),
            Some(stored) => {
                bail!(
                    "migration version {version} checksum mismatch: stored {stored}, expected {checksum}"
                )
            }
            None => bail!("required migration version {version} is not recorded"),
        }
    }

    fn apply_migration(&mut self, version: i64, source: &str, creates_table: bool) -> Result<()> {
        let schema_table_exists: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'table' AND name = 'schema_migrations'
                )",
                [],
                |row| row.get(0),
            )
            .context("cannot inspect schema_migrations table")?;
        if schema_table_exists {
            let stored: Option<String> = self
                .connection
                .query_row(
                    "SELECT checksum FROM schema_migrations WHERE version = ?1",
                    [version],
                    |row| row.get(0),
                )
                .optional()
                .with_context(|| format!("cannot read migration version {version}"))?;
            if let Some(stored) = stored {
                let expected = migration_checksum(source);
                if stored == expected {
                    return Ok(());
                }
                bail!(
                    "migration version {version} checksum mismatch: stored {stored}, expected {expected}"
                );
            }
            if creates_table {
                bail!(
                    "schema_migrations exists but required migration version {version} is not recorded"
                );
            }
        } else if !creates_table {
            bail!("cannot apply migration version {version} before migration version 1");
        }

        let checksum = migration_checksum(source);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .with_context(|| format!("cannot begin migration version {version} transaction"))?;
        transaction
            .execute_batch(source)
            .with_context(|| format!("cannot apply migration version {version} DDL"))?;
        transaction
            .execute(
                "INSERT INTO schema_migrations(version, checksum) VALUES (?1, ?2)",
                params![version, checksum],
            )
            .with_context(|| format!("cannot record migration version {version}"))?;
        transaction
            .commit()
            .with_context(|| format!("cannot commit migration version {version}"))?;
        Ok(())
    }

    pub fn upsert_host(&self, host: &HostMetadata) -> Result<i64> {
        self.connection
            .execute(
                "INSERT INTO hosts (
                    machine_id, hostname, distro, distro_version, kernel_version,
                    cpu_model, cpu_cores, ram_total_bytes, swap_total_bytes,
                    gpu_model, storage_model
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                ON CONFLICT(machine_id) DO UPDATE SET
                    hostname = excluded.hostname,
                    distro = excluded.distro,
                    distro_version = excluded.distro_version,
                    kernel_version = excluded.kernel_version,
                    cpu_model = excluded.cpu_model,
                    cpu_cores = excluded.cpu_cores,
                    ram_total_bytes = excluded.ram_total_bytes,
                    swap_total_bytes = excluded.swap_total_bytes,
                    gpu_model = excluded.gpu_model,
                    storage_model = excluded.storage_model,
                    updated_at = CURRENT_TIMESTAMP",
                params![
                    host.machine_id,
                    host.hostname,
                    host.distro,
                    host.distro_version,
                    host.kernel_version,
                    host.cpu_model,
                    host.cpu_cores,
                    host.ram_total_bytes,
                    host.swap_total_bytes,
                    host.gpu_model,
                    host.storage_model,
                ],
            )
            .with_context(|| format!("cannot upsert host {}", host.machine_id))?;
        self.connection
            .query_row(
                "SELECT id FROM hosts WHERE machine_id = ?1",
                [&host.machine_id],
                |row| row.get(0),
            )
            .with_context(|| format!("cannot retrieve host {}", host.machine_id))
    }

    pub fn open_session(
        &self,
        host_id: i64,
        daemon_version: &str,
        config_hash: &str,
    ) -> Result<i64> {
        let started_at = utc_now();
        self.connection
            .execute(
                "INSERT INTO sessions (
                    host_id, mode, daemon_version, config_hash, started_at
                ) VALUES (?1, 'observe', ?2, ?3, ?4)",
                params![host_id, daemon_version, config_hash, started_at],
            )
            .context("cannot create daemon session")?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn close_session(&mut self, session_id: i64, clean_shutdown: bool) -> Result<()> {
        let ended_at = utc_now();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .with_context(|| {
                format!("cannot begin closure transaction for session {session_id}")
            })?;
        let changed = transaction
            .execute(
                "UPDATE sessions
                 SET ended_at = ?1, clean_shutdown = ?2
                 WHERE id = ?3 AND ended_at IS NULL",
                params![ended_at, clean_shutdown, session_id],
            )
            .with_context(|| format!("cannot close session {session_id}"))?;
        if changed != 1 {
            bail!("session {session_id} was not open or did not exist");
        }
        transaction
            .commit()
            .with_context(|| format!("cannot commit closure of session {session_id}"))?;
        Ok(())
    }

    pub fn insert_system_sample(&self, session_id: i64, sample: &SystemSample) -> Result<()> {
        let memory_some = sample
            .psi_memory
            .as_ref()
            .and_then(|value| value.some)
            .map(|value| value.avg10);
        let memory_full = sample
            .psi_memory
            .as_ref()
            .and_then(|value| value.full)
            .map(|value| value.avg10);
        let cpu_some = sample
            .psi_cpu
            .as_ref()
            .and_then(|value| value.some)
            .map(|value| value.avg10);
        let cpu_full = sample
            .psi_cpu
            .as_ref()
            .and_then(|value| value.full)
            .map(|value| value.avg10);
        let io_some = sample
            .psi_io
            .as_ref()
            .and_then(|value| value.some)
            .map(|value| value.avg10);
        let zram_original = checked_sum(
            sample
                .zram
                .devices
                .iter()
                .filter_map(|device| device.original_data_bytes),
            "zram original data",
        )?;
        let zram_compressed = checked_sum(
            sample
                .zram
                .devices
                .iter()
                .filter_map(|device| device.compressed_data_bytes),
            "zram compressed data",
        )?;
        let zram_memory = checked_sum(
            sample
                .zram
                .devices
                .iter()
                .filter_map(|device| device.memory_used_bytes),
            "zram memory used",
        )?;
        let swap_entries_json =
            serde_json::to_string(&sample.swap.entries).context("cannot serialize swap entries")?;
        let zram_devices_json =
            serde_json::to_string(&sample.zram.devices).context("cannot serialize zram devices")?;
        let capabilities_json = serde_json::to_string(&sample.capabilities_unavailable)
            .context("cannot serialize unavailable capabilities")?;

        self.connection
            .execute(
                "INSERT INTO system_samples (
                    session_id, timestamp_ns, mem_total_bytes, mem_available_bytes,
                    anon_bytes, file_cache_bytes, slab_bytes, swap_used_bytes,
                    swap_in_pages, swap_out_pages, major_faults, minor_faults,
                    pgscan, pgsteal, workingset_refault,
                    psi_memory_some_avg10, psi_memory_full_avg10,
                    psi_io_some_avg10, zram_orig_bytes, zram_compressed_bytes,
                    zswap_stored_pages, zswap_pool_bytes,
                    psi_cpu_some_avg10, psi_cpu_full_avg10,
                    swap_configuration, swap_entries_json, zram_present,
                    zram_memory_used_bytes, zram_devices_json, zswap_present,
                    zswap_enabled, capabilities_unavailable_json
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                    ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22,
                    ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32
                )",
                params![
                    session_id,
                    sample.timestamp_ns,
                    sql_u64(sample.mem_total_bytes, "mem_total_bytes")?,
                    sql_u64(sample.mem_available_bytes, "mem_available_bytes")?,
                    sql_optional_u64(sample.anon_bytes, "anon_bytes")?,
                    sql_optional_u64(sample.file_cache_bytes, "file_cache_bytes")?,
                    sql_optional_u64(sample.slab_bytes, "slab_bytes")?,
                    sql_optional_u64(sample.swap_used_bytes, "swap_used_bytes")?,
                    sql_optional_u64(sample.swap_in_pages, "swap_in_pages")?,
                    sql_optional_u64(sample.swap_out_pages, "swap_out_pages")?,
                    sql_optional_u64(sample.major_faults, "major_faults")?,
                    sql_optional_u64(sample.minor_faults, "minor_faults")?,
                    sql_optional_u64(sample.pgscan, "pgscan")?,
                    sql_optional_u64(sample.pgsteal, "pgsteal")?,
                    sql_optional_u64(sample.workingset_refault, "workingset_refault")?,
                    memory_some,
                    memory_full,
                    io_some,
                    sql_optional_u64(zram_original, "zram_orig_bytes")?,
                    sql_optional_u64(zram_compressed, "zram_compressed_bytes")?,
                    sql_optional_u64(sample.zswap.stored_pages, "zswap_stored_pages")?,
                    sql_optional_u64(sample.zswap.pool_bytes, "zswap_pool_bytes")?,
                    cpu_some,
                    cpu_full,
                    serde_json::to_string(&sample.swap.configuration)
                        .context("cannot serialize swap configuration")?
                        .trim_matches('"')
                        .to_owned(),
                    swap_entries_json,
                    sample.zram.available,
                    sql_optional_u64(zram_memory, "zram_memory_used_bytes")?,
                    zram_devices_json,
                    sample.zswap.available,
                    sample.zswap.enabled,
                    capabilities_json,
                ],
            )
            .with_context(|| {
                format!("cannot insert system telemetry sample for session {session_id}")
            })?;
        Ok(())
    }

    pub fn insert_process_samples(
        &mut self,
        session_id: i64,
        samples: &[ProcessSample],
    ) -> Result<usize> {
        if samples.is_empty() {
            return Ok(0);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .with_context(|| {
                format!("cannot begin process sample batch for session {session_id}")
            })?;
        {
            let mut statement = transaction
                .prepare_cached(
                    "INSERT INTO process_samples (
                        session_id, process_catalog_id, timestamp_ns, pid,
                        cgroup_path, rss_bytes, pss_bytes, uss_bytes, swap_bytes,
                        minor_faults, major_faults, cpu_percent, io_read_bytes,
                        io_write_bytes, foreground
                    ) VALUES (
                        ?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                        ?11, ?12, ?13, 0
                    )",
                )
                .context("cannot prepare process telemetry batch")?;
            for sample in samples {
                statement
                    .execute(params![
                        session_id,
                        sample.timestamp_ns,
                        i64::from(sample.pid),
                        sample.cgroup_path,
                        sql_optional_u64(sample.rss_bytes, "rss_bytes")?,
                        sql_optional_u64(sample.pss_bytes, "pss_bytes")?,
                        sql_optional_u64(sample.uss_bytes, "uss_bytes")?,
                        sql_optional_u64(sample.swap_bytes, "swap_bytes")?,
                        sql_optional_u64(sample.minor_faults, "minor_faults")?,
                        sql_optional_u64(sample.major_faults, "major_faults")?,
                        sample.cpu_percent,
                        sql_optional_u64(sample.io_read_bytes, "io_read_bytes")?,
                        sql_optional_u64(sample.io_write_bytes, "io_write_bytes")?,
                    ])
                    .with_context(|| {
                        format!(
                            "cannot insert process {} telemetry for session {session_id}",
                            sample.pid
                        )
                    })?;
            }
        }
        transaction
            .commit()
            .with_context(|| format!("cannot commit process batch for session {session_id}"))?;
        Ok(samples.len())
    }

    pub fn insert_classification_batch(
        &mut self,
        session_id: i64,
        processes: &[ProcessClassification],
        transition: Option<&WorkloadTransition>,
    ) -> Result<usize> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .with_context(|| {
                format!("cannot begin classification batch for session {session_id}")
            })?;
        for process in processes {
            let persisted_category = if process.confidence >= 0.5 {
                process.category
            } else {
                classifier::ProcessCategory::Unknown
            };
            transaction
                .execute(
                    "INSERT INTO process_catalog (
                        executable, command_signature, application_name, category,
                        is_game, is_critical, default_priority
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 50)
                     ON CONFLICT(executable, command_signature) DO UPDATE SET
                        application_name = COALESCE(
                            excluded.application_name, process_catalog.application_name
                        ),
                        category = CASE
                            WHEN excluded.category <> 'unknown' THEN excluded.category
                            ELSE process_catalog.category
                        END,
                        is_game = MAX(process_catalog.is_game, excluded.is_game),
                        is_critical = MAX(process_catalog.is_critical, excluded.is_critical)",
                    params![
                        process.executable,
                        process.command_signature,
                        process.application_name,
                        persisted_category.to_string(),
                        process.is_game,
                        process.is_critical,
                    ],
                )
                .with_context(|| {
                    format!(
                        "cannot upsert process catalog entry for PID {}",
                        process.sample.pid
                    )
                })?;
            let catalog_id: i64 = transaction
                .query_row(
                    "SELECT id FROM process_catalog
                     WHERE executable = ?1 AND command_signature = ?2",
                    params![process.executable, process.command_signature],
                    |row| row.get(0),
                )
                .context("cannot retrieve process catalog entry")?;
            let foreground = process.foreground == ForegroundState::Foreground;
            transaction
                .execute(
                    "INSERT INTO process_samples (
                        session_id, process_catalog_id, timestamp_ns, pid,
                        cgroup_path, rss_bytes, pss_bytes, uss_bytes, swap_bytes,
                        minor_faults, major_faults, cpu_percent, io_read_bytes,
                        io_write_bytes, foreground, foreground_state
                    ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                        ?12, ?13, ?14, ?15, ?16
                    )",
                    params![
                        session_id,
                        catalog_id,
                        process.sample.timestamp_ns,
                        i64::from(process.sample.pid),
                        process.sample.cgroup_path,
                        sql_optional_u64(process.sample.rss_bytes, "rss_bytes")?,
                        sql_optional_u64(process.sample.pss_bytes, "pss_bytes")?,
                        sql_optional_u64(process.sample.uss_bytes, "uss_bytes")?,
                        sql_optional_u64(process.sample.swap_bytes, "swap_bytes")?,
                        sql_optional_u64(process.sample.minor_faults, "minor_faults")?,
                        sql_optional_u64(process.sample.major_faults, "major_faults")?,
                        process.sample.cpu_percent,
                        sql_optional_u64(process.sample.io_read_bytes, "io_read_bytes")?,
                        sql_optional_u64(process.sample.io_write_bytes, "io_write_bytes")?,
                        foreground,
                        process.foreground.to_string(),
                    ],
                )
                .with_context(|| {
                    format!(
                        "cannot insert classified process {} for session {session_id}",
                        process.sample.pid
                    )
                })?;
        }
        if let Some(transition) = transition {
            let last_class: Option<String> = transaction
                .query_row(
                    "SELECT new_class FROM workload_events
                     WHERE session_id = ?1 ORDER BY timestamp_ns DESC, id DESC LIMIT 1",
                    [session_id],
                    |row| row.get(0),
                )
                .optional()
                .context("cannot inspect latest workload event")?;
            if last_class.as_deref() != Some(&transition.new_class.to_string()) {
                let reason_json = serde_json::to_string(&transition.explanation)
                    .context("cannot serialize workload explanation")?;
                transaction
                    .execute(
                        "INSERT INTO workload_events (
                            session_id, timestamp_ns, previous_class, new_class,
                            confidence, reason_json
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            session_id,
                            transition.timestamp_ns,
                            transition.previous_class.map(|value| value.to_string()),
                            transition.new_class.to_string(),
                            transition.confidence,
                            reason_json,
                        ],
                    )
                    .context("cannot insert workload transition")?;
            }
        }
        transaction.commit().with_context(|| {
            format!("cannot commit classification batch for session {session_id}")
        })?;
        Ok(processes.len())
    }

    pub fn enforce_retention(&mut self, cutoff_timestamp_ns: i64) -> Result<RetentionResult> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("cannot begin telemetry retention transaction")?;
        let process_samples = transaction
            .execute(
                "DELETE FROM process_samples WHERE timestamp_ns < ?1",
                [cutoff_timestamp_ns],
            )
            .context("cannot delete expired process samples")?;
        let system_samples = transaction
            .execute(
                "DELETE FROM system_samples WHERE timestamp_ns < ?1",
                [cutoff_timestamp_ns],
            )
            .context("cannot delete expired system samples")?;
        transaction
            .commit()
            .context("cannot commit telemetry retention transaction")?;
        Ok(RetentionResult {
            system_samples,
            process_samples,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionResult {
    pub system_samples: usize,
    pub process_samples: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatestTelemetryReport {
    pub session_id: i64,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub system_samples: u64,
    pub process_samples: u64,
    pub min_mem_available_bytes: Option<u64>,
    pub max_swap_used_bytes: Option<u64>,
    pub max_psi_memory_some_avg10: Option<f64>,
    pub max_psi_memory_full_avg10: Option<f64>,
    pub delta_major_faults: Option<u64>,
    pub delta_swap_in_pages: Option<u64>,
    pub delta_swap_out_pages: Option<u64>,
    pub zram_observed: bool,
    pub zswap_observed: bool,
    pub capabilities_unavailable: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatestWorkloadReport {
    pub session_id: i64,
    pub available: bool,
    pub current_class: Option<WorkloadClass>,
    pub confidence: Option<f64>,
    pub rule_version: Option<String>,
    pub last_change_timestamp_ns: Option<i64>,
    pub top_reasons: Vec<String>,
    pub gaming_signals: Vec<String>,
    pub pressure_signal: Option<String>,
    pub game_processes: u64,
    pub critical_processes: u64,
    pub unknown_processes: u64,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyActionAudit {
    pub previous_state: Option<PressureState>,
    pub state_changed: bool,
    pub state_since_ns: i64,
    pub candidate_state: Option<PressureState>,
    pub evidence: Vec<PolicyEvidence>,
    pub rejected_candidates: Vec<CandidateRejection>,
    pub planned_actions: Vec<PlannedAction>,
    pub rejected_actions: Vec<RejectedAction>,
    pub dry_run: bool,
    pub transition_reason: String,
}

impl From<&PolicyDecision> for PolicyActionAudit {
    fn from(value: &PolicyDecision) -> Self {
        Self {
            previous_state: value.previous_state,
            state_changed: value.state_changed,
            state_since_ns: value.state_since_ns,
            candidate_state: value.candidate_state,
            evidence: value.evidence.clone(),
            rejected_candidates: value.rejected_candidates.clone(),
            planned_actions: value.planned_actions.clone(),
            rejected_actions: value.rejected_actions.clone(),
            dry_run: value.dry_run,
            transition_reason: value.transition_reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LatestPolicyDecision {
    pub id: i64,
    pub session_id: i64,
    pub timestamp_ns: i64,
    pub pressure_state: PressureState,
    pub policy_name: String,
    pub input_features: PolicyInput,
    pub audit: PolicyActionAudit,
    pub expected_gain_bytes: Option<u64>,
    pub expected_cost_score: Option<f64>,
    pub model_version: Option<String>,
    pub rule_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatestConfigurationSnapshot {
    pub id: i64,
    pub session_id: Option<i64>,
    pub created_at: String,
    pub reason: String,
    pub config_json: String,
    pub system_values_json: String,
}

pub fn latest_configuration_snapshot(
    path: impl AsRef<Path>,
    reason: &str,
) -> Result<LatestConfigurationSnapshot> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection
        .query_row(
            "SELECT id, session_id, created_at, reason, config_json, system_values_json
             FROM configuration_snapshots WHERE reason=?1 ORDER BY id DESC LIMIT 1",
            [reason],
            |row| {
                Ok(LatestConfigurationSnapshot {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    created_at: row.get(2)?,
                    reason: row.get(3)?,
                    config_json: row.get(4)?,
                    system_values_json: row.get(5)?,
                })
            },
        )
        .optional()?
        .context("no matching configuration snapshot is available")
}

pub fn latest_policy_decision(path: impl AsRef<Path>) -> Result<LatestPolicyDecision> {
    let path = path.as_ref();
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("cannot open database {} read-only", path.display()))?;
    query_policy_decisions(&connection, 1)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("database contains no policy decisions"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DamosHistoryEntry {
    pub plan_id: String,
    pub decision_id: String,
    pub session_id: String,
    pub disposition: String,
    pub reasons_json: String,
    pub created_at: String,
}

pub fn damos_history(path: impl AsRef<Path>, limit: usize) -> Result<Vec<DamosHistoryEntry>> {
    if limit == 0 || limit > 100 {
        bail!("DAMOS history limit must be between 1 and 100");
    }
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement = connection.prepare(
        "SELECT plan_id, decision_id, session_id, disposition, reason_codes_json, created_at
         FROM damos_action_plans ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = statement
        .query_map([i64::try_from(limit)?], |row| {
            Ok(DamosHistoryEntry {
                plan_id: row.get(0)?,
                decision_id: row.get(1)?,
                session_id: row.get(2)?,
                disposition: row.get(3)?,
                reasons_json: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

pub fn damos_blacklist(path: impl AsRef<Path>, now_ns: i64) -> Result<Vec<damos::BlacklistRecord>> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement = connection.prepare(
        "SELECT evidence_json, stable_identity, region_signature, reason, created_at_ns,
                expires_at_ns, source_action_id
         FROM damos_refault_blacklist WHERE expires_at_ns > ?1 ORDER BY expires_at_ns",
    )?;
    let rows = statement
        .query_map([now_ns], |row| {
            let evidence: String = row.get(0)?;
            let evidence = serde_json::from_str(&evidence).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
            let stable: String = row.get(1)?;
            let region: String = row.get(2)?;
            Ok(damos::BlacklistRecord {
                key: format!("{stable}:{region}"),
                reason: row.get(3)?,
                created_at_ns: u128::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                expires_at_ns: u128::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
                source_action_id: row.get(6)?,
                evidence,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}

pub fn recent_policy_decisions(
    path: impl AsRef<Path>,
    limit: usize,
) -> Result<Vec<LatestPolicyDecision>> {
    let path = path.as_ref();
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("cannot open database {} read-only", path.display()))?;
    query_policy_decisions(&connection, limit.clamp(1, 100))
}

fn query_policy_decisions(
    connection: &Connection,
    limit: usize,
) -> Result<Vec<LatestPolicyDecision>> {
    let mut statement = connection.prepare(
        "SELECT id, session_id, timestamp_ns, pressure_state, policy_name,
                input_features_json, actions_json, expected_gain_bytes,
                expected_cost_score, model_version, rule_version
         FROM policy_decisions ORDER BY timestamp_ns DESC, id DESC LIMIT ?1",
    )?;
    let rows = statement.query_map([i64::try_from(limit).unwrap_or(100)], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Option<f64>>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, Option<String>>(10)?,
        ))
    })?;
    rows.map(|row| {
        let (
            id,
            session_id,
            timestamp_ns,
            state,
            policy_name,
            features,
            actions,
            gain,
            cost,
            model,
            rules,
        ) = row?;
        Ok(LatestPolicyDecision {
            id,
            session_id,
            timestamp_ns,
            pressure_state: parse_pressure_state(&state)?,
            policy_name,
            input_features: serde_json::from_str(&features).context("invalid policy input JSON")?,
            audit: serde_json::from_str(&actions).context("invalid policy action JSON")?,
            expected_gain_bytes: optional_i64_to_u64(gain, "expected gain")?,
            expected_cost_score: cost,
            model_version: model,
            rule_version: rules.unwrap_or_else(|| "unknown".to_owned()),
        })
    })
    .collect()
}

fn state_text(state: PressureState) -> &'static str {
    match state {
        PressureState::Normal => "NORMAL",
        PressureState::Watch => "WATCH",
        PressureState::Pressure => "PRESSURE",
        PressureState::Critical => "CRITICAL",
        PressureState::Emergency => "EMERGENCY",
        PressureState::Stabilizing => "STABILIZING",
    }
}

fn parse_pressure_state(value: &str) -> Result<PressureState> {
    match value {
        "NORMAL" => Ok(PressureState::Normal),
        "WATCH" => Ok(PressureState::Watch),
        "PRESSURE" => Ok(PressureState::Pressure),
        "CRITICAL" => Ok(PressureState::Critical),
        "EMERGENCY" => Ok(PressureState::Emergency),
        "STABILIZING" => Ok(PressureState::Stabilizing),
        _ => bail!("unknown pressure state `{value}`"),
    }
}

pub fn latest_telemetry_report(path: impl AsRef<Path>) -> Result<LatestTelemetryReport> {
    let path = path.as_ref();
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("cannot open database {} read-only", path.display()))?;
    let (session_id, started_at, ended_at): (i64, String, Option<String>) = connection
        .query_row(
            "SELECT id, started_at, ended_at FROM sessions ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .context("cannot read latest telemetry session")?
        .ok_or_else(|| anyhow::anyhow!("database contains no sessions"))?;
    let system_samples = query_count(
        &connection,
        "SELECT COUNT(*) FROM system_samples WHERE session_id = ?1",
        session_id,
    )?;
    let process_samples = query_count(
        &connection,
        "SELECT COUNT(*) FROM process_samples WHERE session_id = ?1",
        session_id,
    )?;
    let (
        min_mem_available,
        max_swap_used,
        max_memory_some,
        max_memory_full,
        zram_observed,
        zswap_observed,
    ): (
        Option<i64>,
        Option<i64>,
        Option<f64>,
        Option<f64>,
        bool,
        bool,
    ) = connection
        .query_row(
            "SELECT
                MIN(mem_available_bytes),
                MAX(swap_used_bytes),
                MAX(psi_memory_some_avg10),
                MAX(psi_memory_full_avg10),
                COALESCE(MAX(zram_present), 0),
                COALESCE(MAX(zswap_present), 0)
             FROM system_samples WHERE session_id = ?1",
            [session_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .context("cannot aggregate latest telemetry session")?;
    let mut capabilities = Vec::new();
    let mut statement = connection
        .prepare(
            "SELECT capabilities_unavailable_json
             FROM system_samples
             WHERE session_id = ?1 AND capabilities_unavailable_json IS NOT NULL",
        )
        .context("cannot prepare capability report query")?;
    let rows = statement
        .query_map([session_id], |row| row.get::<_, String>(0))
        .context("cannot query unavailable capabilities")?;
    for row in rows {
        let json = row.context("cannot read unavailable capability row")?;
        let values: Vec<String> =
            serde_json::from_str(&json).context("invalid capability JSON in database")?;
        capabilities.extend(values);
    }
    capabilities.sort();
    capabilities.dedup();

    Ok(LatestTelemetryReport {
        session_id,
        started_at,
        ended_at,
        system_samples,
        process_samples,
        min_mem_available_bytes: optional_i64_to_u64(min_mem_available, "minimum memory")?,
        max_swap_used_bytes: optional_i64_to_u64(max_swap_used, "maximum swap")?,
        max_psi_memory_some_avg10: max_memory_some,
        max_psi_memory_full_avg10: max_memory_full,
        delta_major_faults: query_counter_delta(&connection, session_id, "major_faults")?,
        delta_swap_in_pages: query_counter_delta(&connection, session_id, "swap_in_pages")?,
        delta_swap_out_pages: query_counter_delta(&connection, session_id, "swap_out_pages")?,
        zram_observed,
        zswap_observed,
        capabilities_unavailable: capabilities,
    })
}

pub fn latest_workload_report(path: impl AsRef<Path>) -> Result<LatestWorkloadReport> {
    let path = path.as_ref();
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("cannot open database {} read-only", path.display()))?;
    let session_id: i64 = connection
        .query_row(
            "SELECT id FROM sessions ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("cannot read latest session")?
        .ok_or_else(|| anyhow::anyhow!("database contains no sessions"))?;
    let event: Option<(i64, String, f64, String)> = connection
        .query_row(
            "SELECT timestamp_ns, new_class, confidence, reason_json
             FROM workload_events
             WHERE session_id = ?1
             ORDER BY timestamp_ns DESC, id DESC LIMIT 1",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .context("cannot read latest workload event")?;
    let counts = latest_process_category_counts(&connection, session_id)?;
    let Some((timestamp_ns, class_text, confidence, reason_json)) = event else {
        return Ok(LatestWorkloadReport {
            session_id,
            available: false,
            current_class: None,
            confidence: None,
            rule_version: None,
            last_change_timestamp_ns: None,
            top_reasons: Vec::new(),
            gaming_signals: Vec::new(),
            pressure_signal: None,
            game_processes: counts.0,
            critical_processes: counts.1,
            unknown_processes: counts.2,
            message: "no stabilized workload classification is available".to_owned(),
        });
    };
    let current_class = parse_workload_class(&class_text)?;
    let explanation: WorkloadExplanation =
        serde_json::from_str(&reason_json).context("invalid workload explanation JSON")?;
    let top_reasons = explanation
        .evidence
        .iter()
        .map(|evidence| format!("{}: {}", evidence.code, evidence.observed))
        .collect::<Vec<_>>();
    let gaming_signals = explanation
        .evidence
        .iter()
        .filter(|evidence| evidence.code.contains("game"))
        .map(|evidence| evidence.code.clone())
        .chain(
            explanation
                .protection_reasons
                .iter()
                .filter(|reason| reason.contains("game"))
                .cloned(),
        )
        .collect::<Vec<_>>();
    let pressure_signal = explanation
        .evidence
        .iter()
        .find(|evidence| evidence.code.contains("pressure"))
        .map(|evidence| format!("{}: {}", evidence.code, evidence.observed));
    Ok(LatestWorkloadReport {
        session_id,
        available: true,
        current_class: Some(current_class),
        confidence: Some(confidence),
        rule_version: Some(explanation.rule_version),
        last_change_timestamp_ns: Some(timestamp_ns),
        top_reasons,
        gaming_signals,
        pressure_signal,
        game_processes: counts.0,
        critical_processes: counts.1,
        unknown_processes: counts.2,
        message: "latest stabilized deterministic workload classification".to_owned(),
    })
}

fn latest_process_category_counts(
    connection: &Connection,
    session_id: i64,
) -> Result<(u64, u64, u64)> {
    let timestamp: Option<i64> = connection
        .query_row(
            "SELECT MAX(timestamp_ns) FROM process_samples WHERE session_id = ?1",
            [session_id],
            |row| row.get(0),
        )
        .context("cannot read latest process timestamp")?;
    let Some(timestamp) = timestamp else {
        return Ok((0, 0, 0));
    };
    let mut counts = (0_u64, 0_u64, 0_u64);
    let mut statement = connection
        .prepare(
            "SELECT pc.category, COUNT(*)
             FROM process_samples ps
             JOIN process_catalog pc ON pc.id = ps.process_catalog_id
             WHERE ps.session_id = ?1 AND ps.timestamp_ns = ?2
             GROUP BY pc.category",
        )
        .context("cannot prepare process category count query")?;
    let rows = statement
        .query_map(params![session_id, timestamp], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .context("cannot query process category counts")?;
    for row in rows {
        let (category, count) = row.context("cannot read process category count")?;
        let count = u64::try_from(count).context("negative process category count")?;
        match category.as_str() {
            "game" => counts.0 = count,
            "critical" => counts.1 = count,
            "unknown" => counts.2 = count,
            _ => {}
        }
    }
    Ok(counts)
}

fn parse_workload_class(value: &str) -> Result<WorkloadClass> {
    match value {
        "idle" => Ok(WorkloadClass::Idle),
        "desktop" => Ok(WorkloadClass::Desktop),
        "browser_heavy" => Ok(WorkloadClass::BrowserHeavy),
        "development" => Ok(WorkloadClass::Development),
        "gaming" => Ok(WorkloadClass::Gaming),
        "gaming_background_heavy" => Ok(WorkloadClass::GamingBackgroundHeavy),
        "virtualization" => Ok(WorkloadClass::Virtualization),
        "memory_pressure" => Ok(WorkloadClass::MemoryPressure),
        "critical_pressure" => Ok(WorkloadClass::CriticalPressure),
        _ => bail!("unknown workload class `{value}` in database"),
    }
}

fn query_count(connection: &Connection, sql: &str, session_id: i64) -> Result<u64> {
    let count: i64 = connection
        .query_row(sql, [session_id], |row| row.get(0))
        .context("cannot count telemetry samples")?;
    u64::try_from(count).context("telemetry count is negative")
}

fn query_counter_delta(
    connection: &Connection,
    session_id: i64,
    column: &str,
) -> Result<Option<u64>> {
    let sql = format!(
        "SELECT {column} FROM system_samples
         WHERE session_id = ?1 AND {column} IS NOT NULL
         ORDER BY timestamp_ns ASC, id ASC"
    );
    let mut statement = connection
        .prepare(&sql)
        .with_context(|| format!("cannot prepare `{column}` delta query"))?;
    let values = statement
        .query_map([session_id], |row| row.get::<_, i64>(0))
        .with_context(|| format!("cannot query `{column}` delta"))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .with_context(|| format!("cannot read `{column}` delta rows"))?;
    let (Some(first), Some(last)) = (values.first(), values.last()) else {
        return Ok(None);
    };
    let first = u64::try_from(*first).with_context(|| format!("negative `{column}` counter"))?;
    let last = u64::try_from(*last).with_context(|| format!("negative `{column}` counter"))?;
    Ok(last.checked_sub(first))
}

fn checked_sum(values: impl Iterator<Item = u64>, field: &'static str) -> Result<Option<u64>> {
    let mut seen = false;
    let mut total = 0_u64;
    for value in values {
        seen = true;
        total = total
            .checked_add(value)
            .with_context(|| format!("{field} aggregate overflows"))?;
    }
    Ok(seen.then_some(total))
}

fn sql_u64(value: u64, field: &'static str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("`{field}` exceeds SQLite INTEGER range"))
}

fn sql_optional_u64(value: Option<u64>, field: &'static str) -> Result<Option<i64>> {
    value.map(|value| sql_u64(value, field)).transpose()
}

fn optional_i64_to_u64(value: Option<i64>, field: &'static str) -> Result<Option<u64>> {
    value
        .map(|value| u64::try_from(value).with_context(|| format!("{field} is negative")))
        .transpose()
}

pub fn migration_checksum(source: &str) -> String {
    hex::encode(Sha256::digest(source.as_bytes()))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupStorageStatus {
    pub managed_groups: usize,
    pub assignments: usize,
    pub rollback_pending: usize,
    pub stale_recovery_state: usize,
    pub last_safety_error: Option<String>,
}

pub fn inspect_cgroup_status(path: impl AsRef<Path>) -> Result<CgroupStorageStatus> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(CgroupStorageStatus::default());
    }
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("cannot open database {} read-only", path.display()))?;
    let has_schema: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='cgroup_snapshots')",
        [],
        |row| row.get(0),
    )?;
    if !has_schema {
        return Ok(CgroupStorageStatus::default());
    }
    let managed_groups = connection.query_row(
        "SELECT COUNT(*) FROM cgroup_managed_groups WHERE owned_by_nemor = 1",
        [],
        |row| row.get::<_, usize>(0),
    )?;
    let assignments = connection.query_row(
        "SELECT COUNT(*) FROM cgroup_snapshots WHERE applied = 1 AND rolled_back = 0",
        [],
        |row| row.get::<_, usize>(0),
    )?;
    let rollback_pending = connection.query_row(
        "SELECT COUNT(*) FROM cgroup_snapshots WHERE applied = 1 AND rolled_back = 0",
        [],
        |row| row.get::<_, usize>(0),
    )?;
    let stale_recovery_state = connection.query_row(
        "SELECT COUNT(*) FROM cgroup_snapshots
         WHERE rolled_back = 0 AND last_error IS NOT NULL",
        [],
        |row| row.get::<_, usize>(0),
    )?;
    let last_safety_error = connection
        .query_row(
            "SELECT message FROM safety_events
             WHERE event_type LIKE 'cgroup_%' AND severity IN ('warning', 'error')
             ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(CgroupStorageStatus {
        managed_groups,
        assignments,
        rollback_pending,
        stale_recovery_state,
        last_safety_error,
    })
}

impl SnapshotStore for Storage {
    fn persist(&mut self, snapshot: MutationSnapshot) -> Result<u64, ActuatorError> {
        let original_properties = serde_json::to_string(&snapshot.original_properties)
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?;
        let requested_properties = serde_json::to_string(&snapshot.requested_properties)
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?;
        self.connection
            .execute(
                "INSERT INTO cgroup_snapshots (
                    session_id, timestamp_ns, process_catalog_id, identity, pid,
                    start_time_ticks, original_group, target_group,
                    original_properties_json, requested_properties_json, reason,
                    applied, verified, rolled_back, last_error
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    snapshot.session_id,
                    snapshot.timestamp_ns,
                    snapshot.process_catalog_id,
                    snapshot.identity,
                    i64::from(snapshot.pid),
                    i64::try_from(snapshot.start_time_ticks).map_err(|_| {
                        ActuatorError::Persistence("start ticks overflow".to_owned())
                    })?,
                    snapshot.original_group,
                    snapshot.target_group,
                    original_properties,
                    requested_properties,
                    snapshot.reason,
                    snapshot.applied,
                    snapshot.verified,
                    snapshot.rolled_back,
                    snapshot.last_error,
                ],
            )
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?;
        u64::try_from(self.connection.last_insert_rowid())
            .map_err(|_| ActuatorError::Persistence("snapshot id is negative".to_owned()))
    }

    fn update(&mut self, snapshot: &MutationSnapshot) -> Result<(), ActuatorError> {
        self.connection
            .execute(
                "UPDATE cgroup_snapshots SET applied=?1, verified=?2, rolled_back=?3,
                    last_error=?4 WHERE id=?5",
                params![
                    snapshot.applied,
                    snapshot.verified,
                    snapshot.rolled_back,
                    snapshot.last_error,
                    i64::try_from(snapshot.id).map_err(|_| ActuatorError::Persistence(
                        "snapshot id overflow".to_owned()
                    ))?,
                ],
            )
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?;
        Ok(())
    }

    fn pending(&self) -> Result<Vec<MutationSnapshot>, ActuatorError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, session_id, timestamp_ns, process_catalog_id, identity, pid,
                    start_time_ticks, original_group, target_group,
                    original_properties_json, requested_properties_json, reason,
                    applied, verified, rolled_back, last_error
                 FROM cgroup_snapshots WHERE applied=1 AND rolled_back=0 ORDER BY id",
            )
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?;
        let mut rows = statement
            .query([])
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?;
        let mut snapshots = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?
        {
            let original: String = row.get(9).map_err(db_persistence)?;
            let requested: String = row.get(10).map_err(db_persistence)?;
            snapshots.push(MutationSnapshot {
                id: row.get(0).map_err(db_persistence)?,
                session_id: row.get(1).map_err(db_persistence)?,
                timestamp_ns: row.get(2).map_err(db_persistence)?,
                process_catalog_id: row.get(3).map_err(db_persistence)?,
                identity: row.get(4).map_err(db_persistence)?,
                pid: row.get(5).map_err(db_persistence)?,
                start_time_ticks: row.get(6).map_err(db_persistence)?,
                original_group: row.get(7).map_err(db_persistence)?,
                target_group: row.get(8).map_err(db_persistence)?,
                original_properties: serde_json::from_str(&original)
                    .map_err(|error| ActuatorError::Persistence(error.to_string()))?,
                requested_properties: serde_json::from_str(&requested)
                    .map_err(|error| ActuatorError::Persistence(error.to_string()))?,
                reason: row.get(11).map_err(db_persistence)?,
                applied: row.get(12).map_err(db_persistence)?,
                verified: row.get(13).map_err(db_persistence)?,
                rolled_back: row.get(14).map_err(db_persistence)?,
                last_error: row.get(15).map_err(db_persistence)?,
            });
        }
        Ok(snapshots)
    }

    fn record_managed_group(
        &mut self,
        name: &str,
        session_id: i64,
        backend: BackendKind,
    ) -> Result<(), ActuatorError> {
        let backend = serde_json::to_value(backend)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| ActuatorError::Persistence("invalid backend kind".to_owned()))?;
        self.connection
            .execute(
                "INSERT INTO cgroup_managed_groups (
                    name, session_id, backend, owned_by_nemor, state
                 ) VALUES (?1, ?2, ?3, 1, 'active')
                 ON CONFLICT(name) DO UPDATE SET
                    session_id=excluded.session_id, backend=excluded.backend,
                    owned_by_nemor=1, state='active', updated_at=CURRENT_TIMESTAMP",
                params![name, session_id, backend],
            )
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?;
        Ok(())
    }

    fn remove_managed_group(&mut self, name: &str) -> Result<(), ActuatorError> {
        self.connection
            .execute("DELETE FROM cgroup_managed_groups WHERE name=?1", [name])
            .map_err(|error| ActuatorError::Persistence(error.to_string()))?;
        Ok(())
    }
}

fn db_persistence(error: rusqlite::Error) -> ActuatorError {
    ActuatorError::Persistence(error.to_string())
}

pub fn inspect_status(path: impl AsRef<Path>) -> Result<StatusReport> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(StatusReport {
            database_path: path.to_path_buf(),
            database_present: false,
            schema_version: None,
            last_host: None,
            last_session: None,
            state: StatusState::DatabaseMissing,
            state_description: "the configured database file does not exist".to_owned(),
        });
    }

    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("cannot open database {} read-only", path.display()))?;
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .context("cannot enable foreign keys on status connection")?;
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .context("cannot read SQLite journal mode")?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        bail!(
            "database {} is not in WAL mode (reported {journal_mode})",
            path.display()
        );
    }

    let schema_version = connection
        .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .context("cannot read schema version")?;
    let last_host = connection
        .query_row(
            "SELECT id, machine_id, hostname, distro, distro_version, kernel_version
             FROM hosts ORDER BY updated_at DESC, id DESC LIMIT 1",
            [],
            map_host,
        )
        .optional()
        .context("cannot read latest host")?;
    let last_session = connection
        .query_row(
            "SELECT id, host_id, mode, daemon_version, started_at, ended_at, clean_shutdown
             FROM sessions ORDER BY id DESC LIMIT 1",
            [],
            map_session,
        )
        .optional()
        .context("cannot read latest session")?;

    let (state, state_description) = match &last_session {
        None => (
            StatusState::NoSessions,
            "the database is initialized but contains no sessions".to_owned(),
        ),
        Some(session) if session.ended_at.is_none() => (
            StatusState::SessionOpen,
            "the latest session record has no end time; this does not prove the daemon is running"
                .to_owned(),
        ),
        Some(session) if session.clean_shutdown => (
            StatusState::ClosedClean,
            "the latest session was closed cleanly".to_owned(),
        ),
        Some(_) => (
            StatusState::ClosedUnclean,
            "the latest session has an end time but was not marked as a clean shutdown".to_owned(),
        ),
    };

    Ok(StatusReport {
        database_path: path.to_path_buf(),
        database_present: true,
        schema_version,
        last_host,
        last_session,
        state,
        state_description,
    })
}

fn initialize_connection(connection: &Connection) -> Result<()> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .context("cannot enable SQLite WAL journal mode")?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        bail!("SQLite refused WAL journal mode and reported {journal_mode}");
    }
    connection
        .execute_batch("PRAGMA foreign_keys = ON;")
        .context("cannot enable SQLite foreign keys")?;
    Ok(())
}

fn map_host(row: &rusqlite::Row<'_>) -> rusqlite::Result<HostSummary> {
    Ok(HostSummary {
        id: row.get(0)?,
        machine_id: row.get(1)?,
        hostname: row.get(2)?,
        distro: row.get(3)?,
        distro_version: row.get(4)?,
        kernel_version: row.get(5)?,
    })
}

fn map_session(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionSummary> {
    Ok(SessionSummary {
        id: row.get(0)?,
        host_id: row.get(1)?,
        mode: row.get(2)?,
        daemon_version: row.get(3)?,
        started_at: row.get(4)?,
        ended_at: row.get(5)?,
        clean_shutdown: row.get(6)?,
    })
}

fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const TABLES: &[&str] = &[
        "action_results",
        "benchmark_metrics",
        "benchmark_runs",
        "cgroup_managed_groups",
        "cgroup_snapshots",
        "configuration_snapshots",
        "damon_overhead_samples",
        "damon_region_samples",
        "damon_sessions",
        "damos_action_plans",
        "damos_action_results",
        "damos_refault_blacklist",
        "hosts",
        "ksm_evaluations",
        "ksm_process_samples",
        "ksm_system_samples",
        "model_registry",
        "policy_decisions",
        "process_catalog",
        "process_samples",
        "safety_events",
        "schema_migrations",
        "sessions",
        "system_samples",
        "workload_events",
    ];

    fn host(hostname: &str) -> HostMetadata {
        HostMetadata {
            machine_id: "machine-1".to_owned(),
            hostname: hostname.to_owned(),
            distro: "cachyos".to_owned(),
            distro_version: Some("test".to_owned()),
            kernel_version: "6.12-test".to_owned(),
            cpu_model: None,
            cpu_cores: Some(8),
            ram_total_bytes: 16 * 1024 * 1024,
            swap_total_bytes: 2 * 1024 * 1024,
            gpu_model: None,
            storage_model: None,
        }
    }

    fn system_sample(timestamp_ns: i64, counter: u64) -> SystemSample {
        let psi = collector::psi::PsiSample {
            some: Some(collector::psi::PsiLine {
                avg10: counter as f64,
                avg60: 0.0,
                avg300: 0.0,
                total_us: 0,
            }),
            full: Some(collector::psi::PsiLine {
                avg10: counter as f64 / 2.0,
                avg60: 0.0,
                avg300: 0.0,
                total_us: 0,
            }),
        };
        SystemSample {
            timestamp_ns,
            mem_total_bytes: 1_000,
            mem_available_bytes: 900 - counter,
            anon_bytes: Some(10),
            file_cache_bytes: Some(20),
            slab_bytes: Some(30),
            swap_used_bytes: Some(counter),
            swap_in_pages: Some(counter),
            swap_out_pages: Some(counter * 2),
            major_faults: Some(counter * 3),
            minor_faults: Some(counter * 4),
            pgscan: Some(counter),
            pgsteal: Some(counter),
            workingset_refault: Some(counter),
            psi_memory: Some(psi.clone()),
            psi_cpu: Some(psi.clone()),
            psi_io: Some(psi),
            swap: collector::swap::SwapState {
                entries: Vec::new(),
                configuration: collector::swap::SwapConfiguration::None,
            },
            zram: collector::zram::ZramState {
                available: counter > 1,
                devices: Vec::new(),
            },
            zswap: collector::zswap::ZswapState {
                available: counter > 1,
                enabled: Some(true),
                stored_pages: Some(counter),
                pool_bytes: Some(counter),
            },
            capabilities_unavailable: vec!["fixture_capability".to_owned()],
        }
    }

    fn process_sample(timestamp_ns: i64, pid: u32) -> ProcessSample {
        ProcessSample {
            timestamp_ns,
            pid,
            executable: Some(format!("/usr/bin/fixture-{pid}")),
            executable_name: Some(format!("fixture-{pid}")),
            parent_pid: Some(1),
            process_group_id: Some(i32::try_from(pid).expect("fixture PID")),
            session_id: Some(1),
            tty_nr: None,
            foreground_process_group_id: None,
            start_time_ticks: Some(1),
            cgroup_path: Some("/fixture".to_owned()),
            rss_bytes: Some(100),
            pss_bytes: Some(80),
            uss_bytes: Some(60),
            swap_bytes: Some(10),
            minor_faults: Some(2),
            major_faults: Some(1),
            cpu_percent: Some(5.0),
            io_read_bytes: Some(3),
            io_write_bytes: Some(4),
        }
    }

    #[test]
    fn creates_database_tables_indexes_and_migration_record() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("nested/memory.db");
        let storage = Storage::open(&path).expect("database should open");
        assert!(path.exists());

        let mut statement = storage
            .connection()
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("table query");
        let tables: Vec<String> = statement
            .query_map([], |row| row.get(0))
            .expect("table rows")
            .collect::<rusqlite::Result<_>>()
            .expect("table names");
        assert_eq!(tables, TABLES);

        for index in [
            "idx_process_samples_session_time",
            "idx_system_samples_session_time",
            "idx_workload_events_session_time",
        ] {
            let exists: bool = storage
                .connection()
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1
                    )",
                    [index],
                    |row| row.get(0),
                )
                .expect("index query");
            assert!(exists, "missing index {index}");
        }

        let migrations: Vec<(i64, String)> = storage
            .connection()
            .prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")
            .expect("migration statement")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("migration rows")
            .collect::<rusqlite::Result<_>>()
            .expect("migrations");
        assert_eq!(
            migrations,
            vec![
                (1, migration_checksum(INITIAL_MIGRATION)),
                (2, migration_checksum(TELEMETRY_MIGRATION)),
                (3, migration_checksum(CLASSIFIER_MIGRATION)),
                (4, migration_checksum(CGROUP_MIGRATION)),
                (5, migration_checksum(DAMON_MIGRATION)),
                (6, migration_checksum(DAMOS_MIGRATION)),
                (7, migration_checksum(KSM_MIGRATION)),
            ]
        );
    }

    #[test]
    fn second_open_is_idempotent_and_pragmas_are_active() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("memory.db");
        drop(Storage::open(&path).expect("first open"));
        let storage = Storage::open(&path).expect("second open");
        let count: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("migration count");
        assert_eq!(count, MIGRATION_VERSION);
        let journal: String = storage
            .connection()
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        let foreign_keys: i64 = storage
            .connection()
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .expect("foreign keys");
        assert_eq!(journal.to_ascii_lowercase(), "wal");
        assert_eq!(foreign_keys, 1);
    }

    #[test]
    fn rejects_changed_migration_checksum() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("memory.db");
        let mut storage = Storage::open(&path).expect("database");
        let changed = format!("{INITIAL_MIGRATION}\n-- changed");
        let error = storage
            .migrate_source(&changed)
            .expect_err("changed migration must fail");
        assert!(error.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn rejects_changed_telemetry_migration_checksum() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("memory.db");
        let storage = Storage::open(&path).expect("database");
        storage
            .connection()
            .execute(
                "UPDATE schema_migrations SET checksum = 'changed' WHERE version = 2",
                [],
            )
            .expect("corrupt fixture checksum");
        drop(storage);
        let error = Storage::open(&path)
            .err()
            .expect("changed telemetry migration must fail");
        assert!(error
            .to_string()
            .contains("migration version 2 checksum mismatch"));
    }

    #[test]
    fn rejects_changed_classifier_migration_checksum() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("memory.db");
        let storage = Storage::open(&path).expect("database");
        storage
            .connection()
            .execute(
                "UPDATE schema_migrations SET checksum = 'changed' WHERE version = 3",
                [],
            )
            .expect("corrupt fixture checksum");
        drop(storage);
        let error = Storage::open(&path)
            .err()
            .expect("changed classifier migration must fail");
        assert!(error
            .to_string()
            .contains("migration version 3 checksum mismatch"));
    }

    #[test]
    fn rejects_changed_cgroup_migration_checksum() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("memory.db");
        let storage = Storage::open(&path).expect("database");
        storage
            .connection()
            .execute(
                "UPDATE schema_migrations SET checksum = 'changed' WHERE version = 4",
                [],
            )
            .expect("corrupt fixture checksum");
        drop(storage);
        let error = Storage::open(&path)
            .err()
            .expect("changed cgroup migration must fail");
        assert!(error
            .to_string()
            .contains("migration version 4 checksum mismatch"));
    }

    #[test]
    fn upserts_host_by_machine_id() {
        let directory = tempdir().expect("temporary directory");
        let mut storage = Storage::open(directory.path().join("memory.db")).expect("database");
        let first_id = storage.upsert_host(&host("first")).expect("first host");
        let second_id = storage.upsert_host(&host("second")).expect("updated host");
        assert_eq!(first_id, second_id);
        let hostname: String = storage
            .connection()
            .query_row(
                "SELECT hostname FROM hosts WHERE id = ?1",
                [first_id],
                |row| row.get(0),
            )
            .expect("hostname");
        assert_eq!(hostname, "second");

        let session_id = storage
            .open_session(first_id, "0.1.0", "hash")
            .expect("open session");
        storage
            .close_session(session_id, true)
            .expect("clean close");
        let report = inspect_status(storage.path()).expect("status");
        assert_eq!(report.state, StatusState::ClosedClean);
        assert!(report.last_session.expect("session").clean_shutdown);
    }

    #[test]
    fn distinguishes_open_clean_and_unclean_sessions() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("memory.db");
        let mut storage = Storage::open(&path).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");

        let open = storage
            .open_session(host_id, "0.1.0", "hash")
            .expect("open session");
        assert_eq!(
            inspect_status(&path).expect("open status").state,
            StatusState::SessionOpen
        );
        storage.close_session(open, true).expect("clean close");
        assert_eq!(
            inspect_status(&path).expect("clean status").state,
            StatusState::ClosedClean
        );

        let unclean = storage
            .open_session(host_id, "0.1.0", "hash")
            .expect("second session");
        storage
            .close_session(unclean, false)
            .expect("unclean close marker");
        assert_eq!(
            inspect_status(&path).expect("unclean status").state,
            StatusState::ClosedUnclean
        );
    }

    #[test]
    fn status_handles_missing_database_and_no_sessions() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("memory.db");
        assert_eq!(
            inspect_status(&path).expect("missing status").state,
            StatusState::DatabaseMissing
        );
        drop(Storage::open(&path).expect("database"));
        assert_eq!(
            inspect_status(&path).expect("empty status").state,
            StatusState::NoSessions
        );
    }

    #[test]
    fn inserts_system_and_batched_process_samples() {
        let directory = tempdir().expect("temporary directory");
        let mut storage = Storage::open(directory.path().join("memory.db")).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        storage
            .insert_system_sample(session, &system_sample(10, 1))
            .expect("system insert");
        let inserted = storage
            .insert_process_samples(session, &[process_sample(10, 1), process_sample(10, 2)])
            .expect("process batch");
        assert_eq!(inserted, 2);
        let counts: (i64, i64) = (
            storage
                .connection()
                .query_row("SELECT COUNT(*) FROM system_samples", [], |row| row.get(0))
                .expect("system count"),
            storage
                .connection()
                .query_row("SELECT COUNT(*) FROM process_samples", [], |row| row.get(0))
                .expect("process count"),
        );
        assert_eq!(counts, (1, 2));
    }

    #[test]
    fn retention_deletes_only_samples_older_than_cutoff() {
        let directory = tempdir().expect("temporary directory");
        let mut storage = Storage::open(directory.path().join("memory.db")).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        for timestamp in [99, 100, 101] {
            storage
                .insert_system_sample(session, &system_sample(timestamp, 1))
                .expect("system insert");
            storage
                .insert_process_samples(session, &[process_sample(timestamp, 1)])
                .expect("process insert");
        }
        let removed = storage.enforce_retention(100).expect("retention");
        assert_eq!(
            removed,
            RetentionResult {
                system_samples: 1,
                process_samples: 1,
            }
        );
        let earliest: (i64, i64) = (
            storage
                .connection()
                .query_row("SELECT MIN(timestamp_ns) FROM system_samples", [], |row| {
                    row.get(0)
                })
                .expect("system earliest"),
            storage
                .connection()
                .query_row("SELECT MIN(timestamp_ns) FROM process_samples", [], |row| {
                    row.get(0)
                })
                .expect("process earliest"),
        );
        assert_eq!(earliest, (100, 100));
    }

    #[test]
    fn process_batch_rolls_back_on_mid_batch_error() {
        let directory = tempdir().expect("temporary directory");
        let mut storage = Storage::open(directory.path().join("memory.db")).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        storage
            .connection()
            .execute_batch(
                "CREATE TRIGGER reject_pid_two
                 BEFORE INSERT ON process_samples
                 WHEN NEW.pid = 2
                 BEGIN SELECT RAISE(ABORT, 'fixture rejection'); END;",
            )
            .expect("trigger");
        assert!(storage
            .insert_process_samples(session, &[process_sample(1, 1), process_sample(1, 2)])
            .is_err());
        let count: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM process_samples", [], |row| row.get(0))
            .expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn latest_report_handles_data_and_empty_session_read_only() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("memory.db");
        let mut storage = Storage::open(&path).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");
        let data_session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        storage
            .insert_system_sample(data_session, &system_sample(10, 1))
            .expect("first");
        storage
            .insert_system_sample(data_session, &system_sample(20, 3))
            .expect("last");
        storage
            .insert_process_samples(data_session, &[process_sample(10, 1)])
            .expect("process");
        drop(storage);
        let report = latest_telemetry_report(&path).expect("report");
        assert_eq!(report.system_samples, 2);
        assert_eq!(report.process_samples, 1);
        assert_eq!(report.min_mem_available_bytes, Some(897));
        assert_eq!(report.max_swap_used_bytes, Some(3));
        assert_eq!(report.delta_major_faults, Some(6));
        assert_eq!(report.delta_swap_in_pages, Some(2));
        assert_eq!(report.delta_swap_out_pages, Some(4));
        assert!(report.zram_observed);
        assert!(report.zswap_observed);
        assert_eq!(report.capabilities_unavailable, ["fixture_capability"]);
        serde_json::to_string(&report).expect("valid JSON");

        let storage = Storage::open(&path).expect("reopen");
        storage
            .open_session(host_id, "0.1", "hash")
            .expect("empty session");
        drop(storage);
        let empty = latest_telemetry_report(&path).expect("empty report");
        assert_eq!(empty.system_samples, 0);
        assert_eq!(empty.min_mem_available_bytes, None);
    }

    fn classified_process(
        sample: ProcessSample,
        executable: &str,
        category: classifier::ProcessCategory,
        foreground: ForegroundState,
    ) -> ProcessClassification {
        ProcessClassification {
            sample,
            executable: executable.to_owned(),
            command_signature: migration_checksum(&format!("identity-v1:{executable}")),
            application_name: Some(executable.to_owned()),
            category,
            is_game: category == classifier::ProcessCategory::Game,
            is_critical: category == classifier::ProcessCategory::Critical,
            protected: matches!(
                category,
                classifier::ProcessCategory::Game
                    | classifier::ProcessCategory::Critical
                    | classifier::ProcessCategory::Unknown
            ),
            protected_game: category == classifier::ProcessCategory::Game,
            cold_candidate: false,
            foreground,
            foreground_confidence: if foreground == ForegroundState::Unknown {
                0.0
            } else {
                0.9
            },
            confidence: 0.9,
            reasons: Vec::new(),
        }
    }

    fn transition(timestamp_ns: i64, class: WorkloadClass) -> WorkloadTransition {
        WorkloadTransition {
            timestamp_ns,
            previous_class: None,
            new_class: class,
            confidence: 0.9,
            explanation: WorkloadExplanation {
                rule_version: classifier::RULE_VERSION.to_owned(),
                selected_class: class.to_string(),
                confidence: 0.9,
                evidence: vec![classifier::Evidence {
                    code: "fixture_evidence".to_owned(),
                    description: "fixture".to_owned(),
                    observed: "fixture value".to_owned(),
                    threshold: None,
                    contribution: 0.9,
                }],
                rejected_candidates: Vec::new(),
                protection_reasons: Vec::new(),
            },
        }
    }

    #[test]
    fn classified_batch_upserts_catalog_links_samples_and_preserves_tri_state() {
        let directory = tempdir().expect("temporary directory");
        let mut storage = Storage::open(directory.path().join("memory.db")).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        let first = classified_process(
            process_sample(10, 1),
            "code",
            classifier::ProcessCategory::Development,
            ForegroundState::Unknown,
        );
        storage
            .insert_classification_batch(session, std::slice::from_ref(&first), None)
            .expect("classification");
        let mut uncertain = first.clone();
        uncertain.sample.timestamp_ns = 20;
        uncertain.sample.pid = 99;
        uncertain.sample.start_time_ticks = Some(999);
        uncertain.category = classifier::ProcessCategory::Unknown;
        storage
            .insert_classification_batch(session, &[uncertain], None)
            .expect("uncertain refresh");
        let (catalog_count, linked_count, category, foreground): (i64, i64, String, String) =
            storage
                .connection()
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM process_catalog),
                        (SELECT COUNT(*) FROM process_samples
                         WHERE process_catalog_id IS NOT NULL),
                        (SELECT category FROM process_catalog LIMIT 1),
                        (SELECT foreground_state FROM process_samples ORDER BY id LIMIT 1)",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .expect("catalog state");
        assert_eq!(catalog_count, 1);
        assert_eq!(linked_count, 2);
        assert_eq!(category, "development");
        assert_eq!(foreground, "unknown");
    }

    #[test]
    fn catalog_identity_avoids_same_basename_path_collisions_and_duplicates() {
        let directory = tempdir().expect("temporary directory");
        let mut storage = Storage::open(directory.path().join("nemor.db")).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        let config = common::Config::from_toml(include_str!("../../../config/default.toml"))
            .expect("config");
        let classifier =
            classifier::Classifier::new(config.classification.clone(), config.pressure.clone());
        let mut first = process_sample(10, 1);
        first.executable = Some("/usr/bin/shared-name".to_owned());
        first.executable_name = Some("shared-name".to_owned());
        let mut second = process_sample(10, 2);
        second.executable = Some("/opt/vendor/shared-name".to_owned());
        second.executable_name = Some("shared-name".to_owned());
        let classified = classifier.classify_processes(&[first.clone(), second]);
        storage
            .insert_classification_batch(session, &classified, None)
            .expect("two identities");
        let repeated = classifier.classify_processes(&[first]);
        storage
            .insert_classification_batch(session, &repeated, None)
            .expect("repeated identity");
        let count: i64 = storage
            .connection()
            .query_row("SELECT COUNT(*) FROM process_catalog", [], |row| row.get(0))
            .expect("catalog count");
        assert_eq!(count, 2);
    }

    #[test]
    fn workload_events_are_written_only_for_real_class_changes() {
        let directory = tempdir().expect("temporary directory");
        let mut storage = Storage::open(directory.path().join("memory.db")).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        let desktop = transition(10, WorkloadClass::Desktop);
        storage
            .insert_classification_batch(session, &[], Some(&desktop))
            .expect("first event");
        storage
            .insert_classification_batch(
                session,
                &[],
                Some(&transition(20, WorkloadClass::Desktop)),
            )
            .expect("duplicate suppressed");
        let mut gaming = transition(30, WorkloadClass::Gaming);
        gaming.previous_class = Some(WorkloadClass::Desktop);
        storage
            .insert_classification_batch(session, &[], Some(&gaming))
            .expect("change");
        let events: Vec<(i64, Option<String>, String)> = storage
            .connection()
            .prepare(
                "SELECT timestamp_ns, previous_class, new_class
                 FROM workload_events ORDER BY timestamp_ns",
            )
            .expect("statement")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("rows")
            .collect::<rusqlite::Result<_>>()
            .expect("events");
        assert_eq!(
            events,
            [
                (10, None, "desktop".to_owned()),
                (30, Some("desktop".to_owned()), "gaming".to_owned()),
            ]
        );
    }

    #[test]
    fn classification_batch_rolls_back_catalog_sample_and_event_together() {
        let directory = tempdir().expect("temporary directory");
        let mut storage = Storage::open(directory.path().join("memory.db")).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        storage
            .connection()
            .execute_batch(
                "CREATE TRIGGER reject_classified_process
                 BEFORE INSERT ON process_samples
                 BEGIN SELECT RAISE(ABORT, 'fixture rejection'); END;",
            )
            .expect("trigger");
        let value = classified_process(
            process_sample(10, 1),
            "game",
            classifier::ProcessCategory::Game,
            ForegroundState::Foreground,
        );
        assert!(storage
            .insert_classification_batch(
                session,
                &[value],
                Some(&transition(10, WorkloadClass::Gaming)),
            )
            .is_err());
        for table in ["process_catalog", "process_samples", "workload_events"] {
            let count: i64 = storage
                .connection()
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("count");
            assert_eq!(count, 0, "{table} must roll back");
        }
    }

    #[test]
    fn latest_workload_report_handles_data_and_no_stabilized_event_read_only() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("memory.db");
        let mut storage = Storage::open(&path).expect("database");
        let host_id = storage.upsert_host(&host("host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        let process = classified_process(
            process_sample(10, 1),
            "game",
            classifier::ProcessCategory::Game,
            ForegroundState::Foreground,
        );
        storage
            .insert_classification_batch(
                session,
                &[process],
                Some(&transition(10, WorkloadClass::Gaming)),
            )
            .expect("classification");
        drop(storage);
        let bytes_before = fs::read(&path).expect("database bytes");
        let report = latest_workload_report(&path).expect("workload report");
        let bytes_after = fs::read(&path).expect("database bytes");
        assert_eq!(
            bytes_before, bytes_after,
            "read-only report changed database"
        );
        assert!(report.available);
        assert_eq!(report.current_class, Some(WorkloadClass::Gaming));
        assert_eq!(report.game_processes, 1);
        serde_json::to_string(&report).expect("valid JSON");

        let storage = Storage::open(&path).expect("database");
        storage
            .open_session(host_id, "0.1", "hash")
            .expect("empty session");
        drop(storage);
        let empty = latest_workload_report(&path).expect("controlled empty report");
        assert!(!empty.available);
        assert_eq!(empty.current_class, None);
    }

    #[test]
    fn policy_audit_deduplicates_and_reads_limited_history() {
        use actuator::CgroupCapabilities;
        use policy_engine::{PolicyEngine, PolicyInput};

        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("policy.db");
        let storage = Storage::open(&path).expect("database");
        let host_id = storage.upsert_host(&host("policy-host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        let config = common::Config::from_toml(include_str!("../../../config/default.toml"))
            .expect("config");
        let mut engine = PolicyEngine::new(config.pressure, 0);
        let make_input = |timestamp_ns| PolicyInput {
            timestamp_ns,
            ram_total_bytes: 1_000,
            mem_available_bytes: 500,
            available_percent: 50.0,
            swap_total_bytes: Some(100),
            swap_used_bytes: Some(0),
            swap_in_per_second: Some(0.0),
            swap_out_per_second: Some(0.0),
            major_faults_per_second: Some(0.0),
            pgscan_per_second: Some(0.0),
            pgsteal_per_second: Some(0.0),
            psi_memory_some_avg10: Some(0.0),
            psi_memory_full_avg10: Some(0.0),
            workload_class: Some(WorkloadClass::Desktop),
            workload_confidence: Some(0.9),
            gaming: false,
            critical_processes: 0,
            protected_processes: 0,
            unknown_processes: 0,
            foreground: ForegroundState::Unknown,
            cgroup_capabilities: Some(CgroupCapabilities {
                cgroup_v2: true,
                memory_controller: true,
                hierarchy: "/sys/fs/cgroup".into(),
                writable: false,
                memory_low: true,
                memory_high: true,
                attach: false,
            }),
            actuator_available: false,
            recent_safety_events: 0,
            recent_decisions: 0,
        };
        let first = engine.evaluate(make_input(1), true).expect("decision");
        assert!(storage
            .insert_policy_decision(session, &first, 300)
            .expect("insert"));
        let duplicate = engine.evaluate(make_input(2), true).expect("duplicate");
        assert!(!storage
            .insert_policy_decision(session, &duplicate, 300)
            .expect("dedupe"));
        let heartbeat = engine
            .evaluate(make_input(301_000_000_001), true)
            .expect("heartbeat");
        assert!(storage
            .insert_policy_decision(session, &heartbeat, 300)
            .expect("heartbeat insert"));
        drop(storage);

        let latest = latest_policy_decision(&path).expect("latest");
        assert_eq!(latest.rule_version, policy_engine::RULE_VERSION);
        assert_eq!(latest.model_version, None);
        assert!(latest.audit.dry_run);
        serde_json::to_string(&latest).expect("valid JSON");
        assert_eq!(
            recent_policy_decisions(&path, 1_000)
                .expect("history")
                .len(),
            2
        );
    }

    #[test]
    fn zram_snapshot_and_benchmark_preserve_real_simulated_label() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("zram-audit.db");
        let storage = Storage::open(&path).expect("database");
        let host_id = storage.upsert_host(&host("zram-host")).expect("host");
        let session = storage
            .open_session(host_id, "0.1", "hash")
            .expect("session");
        let plan = serde_json::json!({"profile": "safe", "dry_run": true});
        let state = serde_json::json!({"devices": [], "rollback_pending": false});
        storage
            .insert_configuration_snapshot(session, "zram_observe_audit", &plan, &state)
            .expect("snapshot");
        let simulated = storage
            .insert_zram_benchmark(host_id, "safe", false, &Vec::<u8>::new())
            .expect("benchmark");
        let status: String = storage
            .connection()
            .query_row(
                "SELECT status FROM benchmark_runs WHERE id=?1",
                [simulated],
                |row| row.get(0),
            )
            .expect("status");
        assert_eq!(status, "simulated_fixture");
        drop(storage);
        let latest = latest_configuration_snapshot(&path, "zram_observe_audit").expect("latest");
        assert_eq!(latest.session_id, Some(session));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&latest.system_values_json)
                .expect("valid JSON"),
            state
        );
    }
}
