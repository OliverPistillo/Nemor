CREATE TABLE benchmark_experiments (
    id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    scenario_version INTEGER NOT NULL,
    seed INTEGER NOT NULL,
    repetition_count INTEGER NOT NULL CHECK (repetition_count >= 1),
    host_fingerprint_hash TEXT NOT NULL,
    nemor_commit TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    evidence_kind TEXT NOT NULL,
    source_state_id TEXT NOT NULL,
    binary_sha256 TEXT NOT NULL,
    development_build INTEGER NOT NULL CHECK (development_build IN (0, 1)),
    performance_claim_eligible INTEGER NOT NULL CHECK (performance_claim_eligible IN (0, 1)),
    created_at_ns INTEGER NOT NULL,
    status TEXT NOT NULL
);
CREATE INDEX idx_benchmark_experiments_scenario
    ON benchmark_experiments(scenario_id, created_at_ns);

CREATE TABLE benchmark_run_manifests (
    id TEXT PRIMARY KEY,
    experiment_id TEXT REFERENCES benchmark_experiments(id) ON DELETE CASCADE,
    variant TEXT NOT NULL,
    repetition INTEGER NOT NULL,
    run_order INTEGER NOT NULL,
    status TEXT NOT NULL,
    valid INTEGER NOT NULL CHECK (valid IN (0, 1)),
    invalid_reason TEXT,
    logical_workload_bytes INTEGER,
    physical_memory_bytes INTEGER,
    requested_variant TEXT NOT NULL,
    resolved_variant_state TEXT NOT NULL,
    effective_state_hash TEXT NOT NULL,
    variant_diff_summary TEXT NOT NULL,
    cgroup_ownership_json TEXT,
    restore_evidence_json TEXT,
    started_monotonic_ns INTEGER,
    ended_monotonic_ns INTEGER,
    manifest_json TEXT NOT NULL
);
CREATE INDEX idx_benchmark_run_manifests_experiment
    ON benchmark_run_manifests(experiment_id, run_order);

CREATE TABLE benchmark_samples (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES benchmark_run_manifests(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL,
    timestamp_monotonic_ns INTEGER NOT NULL,
    phase TEXT NOT NULL,
    metric TEXT NOT NULL,
    value REAL,
    unit TEXT NOT NULL,
    scope TEXT NOT NULL,
    source TEXT NOT NULL,
    available INTEGER NOT NULL CHECK (available IN (0, 1)),
    unavailable_reason TEXT,
    UNIQUE(run_id, sequence, metric)
);
CREATE INDEX idx_benchmark_samples_run_time
    ON benchmark_samples(run_id, timestamp_monotonic_ns);

CREATE TABLE benchmark_events (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES benchmark_run_manifests(id) ON DELETE CASCADE,
    timestamp_monotonic_ns INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    value_json TEXT NOT NULL
);
CREATE INDEX idx_benchmark_events_run_time
    ON benchmark_events(run_id, timestamp_monotonic_ns);

CREATE TABLE benchmark_summaries (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES benchmark_run_manifests(id) ON DELETE CASCADE,
    metric TEXT NOT NULL,
    unit TEXT NOT NULL,
    scope TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    UNIQUE(run_id, metric, scope)
);

CREATE TABLE benchmark_comparisons (
    id TEXT PRIMARY KEY,
    experiment_id TEXT NOT NULL REFERENCES benchmark_experiments(id) ON DELETE CASCADE,
    baseline_variant TEXT NOT NULL,
    candidate_variant TEXT NOT NULL,
    comparable INTEGER NOT NULL CHECK (comparable IN (0, 1)),
    invalid_reason TEXT,
    comparison_json TEXT NOT NULL,
    acceptance_json TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL
);
CREATE INDEX idx_benchmark_comparisons_experiment
    ON benchmark_comparisons(experiment_id, created_at_ns);
