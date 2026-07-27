CREATE TABLE damos_action_plans (
    id INTEGER PRIMARY KEY,
    decision_id TEXT NOT NULL,
    plan_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    scheme_id INTEGER NOT NULL CHECK (scheme_id >= 0),
    target_identity TEXT NOT NULL,
    pressure_state TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK (disposition IN ('eligible', 'rejected', 'unsupported')),
    reason_codes_json TEXT NOT NULL,
    plan_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE damos_action_results (
    id INTEGER PRIMARY KEY,
    plan_id TEXT NOT NULL REFERENCES damos_action_plans(plan_id),
    action_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    scheme_id INTEGER NOT NULL CHECK (scheme_id >= 0),
    outcome TEXT NOT NULL,
    stats_json TEXT NOT NULL,
    reclaim_json TEXT,
    interrupted INTEGER NOT NULL CHECK (interrupted IN (0, 1)),
    recovered INTEGER NOT NULL CHECK (recovered IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE damos_refault_blacklist (
    id INTEGER PRIMARY KEY,
    stable_identity TEXT NOT NULL,
    region_signature TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason = 'early_refault_blacklist'),
    source_action_id TEXT NOT NULL REFERENCES damos_action_results(action_id),
    evidence_json TEXT NOT NULL,
    created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
    expires_at_ns INTEGER NOT NULL CHECK (expires_at_ns > created_at_ns),
    UNIQUE(stable_identity, region_signature, source_action_id)
);
CREATE INDEX idx_damos_plans_created ON damos_action_plans(created_at DESC);
CREATE INDEX idx_damos_results_plan ON damos_action_results(plan_id, created_at DESC);
CREATE INDEX idx_damos_blacklist_active ON damos_refault_blacklist(expires_at_ns, stable_identity);
