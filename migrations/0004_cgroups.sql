CREATE TABLE cgroup_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    timestamp_ns INTEGER NOT NULL,
    process_catalog_id INTEGER NOT NULL,
    identity TEXT NOT NULL,
    pid INTEGER NOT NULL,
    start_time_ticks INTEGER NOT NULL,
    original_group TEXT NOT NULL,
    target_group TEXT NOT NULL,
    original_properties_json TEXT NOT NULL,
    requested_properties_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    applied INTEGER NOT NULL DEFAULT 0,
    verified INTEGER NOT NULL DEFAULT 0,
    rolled_back INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id),
    FOREIGN KEY(process_catalog_id) REFERENCES process_catalog(id)
);

CREATE INDEX idx_cgroup_snapshots_recovery
ON cgroup_snapshots(rolled_back, applied, session_id);

CREATE TABLE cgroup_managed_groups (
    name TEXT PRIMARY KEY,
    session_id INTEGER NOT NULL,
    backend TEXT NOT NULL,
    owned_by_nemor INTEGER NOT NULL,
    state TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);
