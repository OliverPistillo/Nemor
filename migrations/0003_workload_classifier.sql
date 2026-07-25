ALTER TABLE process_samples ADD COLUMN foreground_state TEXT;

CREATE INDEX idx_workload_events_session_time
ON workload_events(session_id, timestamp_ns);
