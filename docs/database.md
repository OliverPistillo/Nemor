# Database contract

The database path comes exclusively from the validated configuration. A normal
daemon connection requests `journal_mode = WAL` and enables
`foreign_keys = ON` before migration work. These PRAGMAs are connection
initialization, not transactional DDL. `status` opens an existing database
read-only, enables its own foreign-key enforcement, and verifies that the
persistent journal mode is WAL.

## Migrations

`migrations/0001_initial.sql` remains the unchanged Phase 0 migration. The storage crate
computes SHA-256 over its exact bytes. On a new database, all DDL and the
`schema_migrations` record are committed in one immediate transaction. On later
opens, version 1 is applied zero additional times and its stored checksum must
match. A missing version record or changed checksum rejects startup rather than
silently accepting schema drift.

Migration 2 (`0002_telemetry_baseline.sql`) is applied in its own immediate
transaction and checksum-verified identically. It adds only Phase 1 fields that
the original schema lacked: CPU PSI, observed swap/zram/zswap detail and
presence, zram backend memory, and unavailable-capability JSON. Migration 1 is
never rewritten.

Migration 3 (`0003_workload_classifier.sql`) is checksum-verified and
transactional. It adds only nullable `process_samples.foreground_state`, needed
to distinguish `foreground`, `background`, and `unknown`, plus the
session/time workload-event index. Migrations 1 and 2 remain unchanged.

Migration 4 (`0004_cgroups.sql`) adds `cgroup_snapshots` and
`cgroup_managed_groups`. It records session, stable catalog identity,
PID/start ticks, original placement and properties, requested properties,
verification, error, recovery, and rollback state. Migrations 0001–0003 remain
unchanged, and no Phase 4 policy record is synthesized.

## Active records

`hosts` stores one logical record per `machine_id`. Each valid startup refreshes
the permitted one-time metadata without inventing unavailable GPU, storage, or
CPU model values.

`sessions` records one daemon run. New sessions are `observe`, initially have no
end time, and have `clean_shutdown = 0`. Graceful SIGINT/SIGTERM closure writes
an end time and changes the flag to one in a transaction.

## Active telemetry tables

`system_samples` receives one row per successful system tick. Byte-valued Linux
inputs are stored as SQLite integers; PSI averages are real values; kernel
counters remain cumulative. Swap and zram device details use JSON solely because
their cardinality varies by host. Capability JSON is a sorted set of names known
to be unavailable for that sample.

`process_samples` is inserted in configured transaction batches. Classifier
samples link to an upserted `process_catalog` identity and store the foreground
tri-state; legacy `foreground` is true only for confirmed foreground. A
temporary unknown result cannot overwrite a stable catalog category. Retention deletes rows with
`timestamp_ns < cutoff` from both sample tables in one transaction and never
deletes a row exactly at the cutoff.

The report connection uses SQLite read-only flags and aggregates the most recent
session without writing report state.

`workload_events` receives only stabilized class changes. Repeated observations
of the current class create no duplicate. `reason_json` contains the rule
version, selected class, confidence, stable evidence, rejected candidates, and
protection reasons. Catalog entries, process samples, and an optional event are
written transactionally per batch. The workload CLI opens SQLite read-only.

## Reserved contract tables

Policy decision, action result, benchmark, and model registry tables remain
reserved parts of the supplied schema contract. Phase 3 does not synthesize
policy decisions.
