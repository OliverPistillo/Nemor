CREATE TABLE damon_sessions (
    id INTEGER PRIMARY KEY,
    host_session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    external_session INTEGER NOT NULL CHECK (external_session IN (0, 1)),
    source TEXT NOT NULL,
    kernel TEXT,
    operation_set TEXT,
    attrs_json TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at TEXT,
    clean_shutdown INTEGER CHECK (clean_shutdown IN (0, 1)),
    zero_damos INTEGER NOT NULL CHECK (zero_damos = 1),
    dropped_samples INTEGER NOT NULL DEFAULT 0 CHECK (dropped_samples >= 0)
);

CREATE TABLE damon_region_samples (
    id INTEGER PRIMARY KEY,
    damon_session_id INTEGER NOT NULL REFERENCES damon_sessions(id) ON DELETE CASCADE,
    timestamp_ns INTEGER NOT NULL CHECK (timestamp_ns >= 0),
    target_id INTEGER NOT NULL,
    pid INTEGER,
    stable_identity TEXT NOT NULL,
    region_start INTEGER NOT NULL,
    region_end INTEGER NOT NULL,
    region_size INTEGER NOT NULL CHECK (region_size > 0),
    nr_accesses INTEGER NOT NULL CHECK (nr_accesses >= 0),
    age INTEGER NOT NULL CHECK (age >= 0),
    normalized_access_ratio REAL NOT NULL CHECK (
        normalized_access_ratio >= 0.0 AND normalized_access_ratio <= 1.0
    ),
    observational_label TEXT NOT NULL,
    sample_json TEXT NOT NULL
);

CREATE TABLE damon_overhead_samples (
    id INTEGER PRIMARY KEY,
    damon_session_id INTEGER NOT NULL REFERENCES damon_sessions(id) ON DELETE CASCADE,
    timestamp_ns INTEGER NOT NULL CHECK (timestamp_ns >= 0),
    kdamond_cpu_percent REAL NOT NULL,
    capture_cpu_percent REAL NOT NULL,
    target_slowdown_percent REAL NOT NULL,
    events_per_second REAL NOT NULL,
    regions_per_second REAL NOT NULL,
    dropped_samples INTEGER NOT NULL CHECK (dropped_samples >= 0)
);

CREATE INDEX idx_damon_sessions_host_time
    ON damon_sessions(host_session_id, started_at DESC);
CREATE INDEX idx_damon_regions_session_time
    ON damon_region_samples(damon_session_id, timestamp_ns);
CREATE INDEX idx_damon_overhead_session_time
    ON damon_overhead_samples(damon_session_id, timestamp_ns);
