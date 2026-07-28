ALTER TABLE benchmark_experiments ADD COLUMN comparison_purpose TEXT;
ALTER TABLE benchmark_experiments ADD COLUMN manifest_json TEXT;
ALTER TABLE benchmark_experiments ADD COLUMN ended_at_ns INTEGER;
ALTER TABLE benchmark_experiments ADD COLUMN valid INTEGER
    CHECK (valid IS NULL OR valid IN (0, 1));

ALTER TABLE benchmark_run_manifests ADD COLUMN run_seed INTEGER;
ALTER TABLE benchmark_run_manifests ADD COLUMN benchmark_binary_sha256 TEXT;
ALTER TABLE benchmark_run_manifests ADD COLUMN observer_binary_sha256 TEXT;
ALTER TABLE benchmark_run_manifests ADD COLUMN config_hash TEXT;

ALTER TABLE benchmark_comparisons ADD COLUMN comparison_purpose TEXT;
