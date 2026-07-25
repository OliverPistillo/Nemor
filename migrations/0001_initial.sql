CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checksum TEXT NOT NULL
);

CREATE TABLE hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_id TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    distro TEXT NOT NULL,
    distro_version TEXT,
    kernel_version TEXT NOT NULL,
    cpu_model TEXT,
    cpu_cores INTEGER,
    ram_total_bytes INTEGER NOT NULL,
    swap_total_bytes INTEGER NOT NULL,
    gpu_model TEXT,
    storage_model TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    mode TEXT NOT NULL,
    daemon_version TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    clean_shutdown INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE process_catalog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    executable TEXT NOT NULL,
    command_signature TEXT,
    application_name TEXT,
    category TEXT NOT NULL DEFAULT 'unknown',
    is_game INTEGER NOT NULL DEFAULT 0,
    is_critical INTEGER NOT NULL DEFAULT 0,
    default_priority INTEGER NOT NULL DEFAULT 50,
    UNIQUE(executable, command_signature)
);

CREATE TABLE process_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    process_catalog_id INTEGER,
    timestamp_ns INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    cgroup_path TEXT,
    rss_bytes INTEGER,
    pss_bytes INTEGER,
    uss_bytes INTEGER,
    swap_bytes INTEGER,
    minor_faults INTEGER,
    major_faults INTEGER,
    cpu_percent REAL,
    io_read_bytes INTEGER,
    io_write_bytes INTEGER,
    foreground INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(session_id) REFERENCES sessions(id),
    FOREIGN KEY(process_catalog_id) REFERENCES process_catalog(id)
);

CREATE INDEX idx_process_samples_session_time
ON process_samples(session_id, timestamp_ns);

CREATE TABLE system_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    mem_total_bytes INTEGER NOT NULL,
    mem_available_bytes INTEGER NOT NULL,
    anon_bytes INTEGER,
    file_cache_bytes INTEGER,
    slab_bytes INTEGER,
    swap_used_bytes INTEGER,
    swap_in_pages INTEGER,
    swap_out_pages INTEGER,
    major_faults INTEGER,
    minor_faults INTEGER,
    pgscan INTEGER,
    pgsteal INTEGER,
    workingset_refault INTEGER,
    psi_memory_some_avg10 REAL,
    psi_memory_full_avg10 REAL,
    psi_io_some_avg10 REAL,
    cpu_total_percent REAL,
    load1 REAL,
    zram_orig_bytes INTEGER,
    zram_compressed_bytes INTEGER,
    zswap_stored_pages INTEGER,
    zswap_pool_bytes INTEGER,
    ksm_pages_shared INTEGER,
    ksm_pages_sharing INTEGER,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

CREATE INDEX idx_system_samples_session_time
ON system_samples(session_id, timestamp_ns);

CREATE TABLE workload_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    previous_class TEXT,
    new_class TEXT NOT NULL,
    confidence REAL NOT NULL,
    reason_json TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

CREATE TABLE policy_decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    pressure_state TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    input_features_json TEXT NOT NULL,
    actions_json TEXT NOT NULL,
    expected_gain_bytes INTEGER,
    expected_cost_score REAL,
    model_version TEXT,
    rule_version TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

CREATE TABLE action_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT,
    previous_value TEXT,
    requested_value TEXT,
    applied_value TEXT,
    success INTEGER NOT NULL,
    error_code TEXT,
    error_message TEXT,
    duration_us INTEGER,
    reverted_at TEXT,
    FOREIGN KEY(decision_id) REFERENCES policy_decisions(id)
);

CREATE TABLE benchmark_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    workload TEXT NOT NULL,
    profile TEXT NOT NULL,
    baseline INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    notes TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);

CREATE TABLE benchmark_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    benchmark_run_id INTEGER NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value REAL NOT NULL,
    unit TEXT NOT NULL,
    percentile TEXT,
    FOREIGN KEY(benchmark_run_id) REFERENCES benchmark_runs(id)
);

CREATE TABLE model_registry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL UNIQUE,
    model_type TEXT NOT NULL,
    feature_schema_version TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    checksum TEXT NOT NULL,
    trained_at TEXT NOT NULL,
    training_dataset_hash TEXT NOT NULL,
    validation_metrics_json TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE safety_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    timestamp_ns INTEGER NOT NULL,
    severity TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    context_json TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

CREATE TABLE configuration_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reason TEXT NOT NULL,
    config_json TEXT NOT NULL,
    system_values_json TEXT NOT NULL,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

