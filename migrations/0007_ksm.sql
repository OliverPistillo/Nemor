CREATE TABLE ksm_system_samples (
    id INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp_ns INTEGER NOT NULL,
    metrics_json TEXT NOT NULL
);
CREATE INDEX idx_ksm_system_samples_session_time
    ON ksm_system_samples(session_id, timestamp_ns);

CREATE TABLE ksm_process_samples (
    id INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp_ns INTEGER NOT NULL,
    stable_identity TEXT NOT NULL,
    profile TEXT,
    metrics_json TEXT NOT NULL
);
CREATE INDEX idx_ksm_process_samples_session_time
    ON ksm_process_samples(session_id, timestamp_ns);

CREATE TABLE ksm_evaluations (
    id INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    timestamp_ns INTEGER NOT NULL,
    decision_id TEXT,
    plan_id TEXT,
    transaction_id TEXT,
    profile TEXT,
    controller_state TEXT NOT NULL,
    profit_json TEXT,
    reason_json TEXT NOT NULL,
    dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1))
);
CREATE INDEX idx_ksm_evaluations_session_time
    ON ksm_evaluations(session_id, timestamp_ns);
