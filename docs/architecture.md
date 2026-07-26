# Phase 4 architecture

## Crate boundaries

`common` owns configuration data, strict observe-only validation, shared output
contracts, the injectable Linux path map, and a one-shot reader for mandatory
host metadata. It has no periodic collector and no policy logic.

`collector` owns read-only Linux parsing and sampling. `FsSource::production`
always resolves from `/`; tests inject a rooted source that resolves the same
absolute interface names inside a fixture. No daemon flag or environment
override exposes fixture roots.

`classifier` consumes immutable Phase 1 samples. It owns identity normalization,
safe signatures, process categories, foreground tri-state, gaming evidence,
workload precedence, explanations, confidence, and transition stabilization.
It has no filesystem writes and no actuator dependency.

`actuator` owns cgroup v2 capability inspection, explainable authorization
plans, the fixed Nemor group namespace, a deterministic fake backend, guarded
Linux primitives, snapshots, readback verification, rollback, and recovery.
It does not select policies.

`policy-engine` consumes normalized immutable inputs and explicit logical time.
It owns counter rates, six pressure states, hysteresis, versioned rules, the
closed action planner, explanations, and restart state. It has no Linux
filesystem or clock access.

`storage` owns SQLite connections. It enables WAL and foreign keys, verifies
four versioned migrations, inserts system samples, atomically upserts process
catalog entries with classified samples and workload changes, executes
transactional retention, produces read-only latest-session reports, and
deduplicates Phase 4 policy audits.

`nemord` is the foreground process. It parses `--config`, loads and
validates the file, initializes JSON structured logs, opens storage, records the
host and session, waits for SIGINT or SIGTERM, and closes the session.

`nemorctl` is read-only. `doctor` inspects prerequisites through
injectable paths; `status` opens an existing database read-only. Both commands
serialize their JSON output with Serde.

`test-support` contains temporary directories, simulated Linux files, and
snapshot helpers used only by tests. It contains no production behavior.

## Startup flow

1. Parse command-line arguments.
2. Read the selected configuration bytes and validate every Phase 2 safety
   invariant.
3. Compute SHA-256 over those exact bytes.
4. Initialize structured stdout/stderr logging.
5. Open SQLite, set connection PRAGMAs, and transactionally verify or apply
   migrations 1 through 4.
6. Read mandatory host metadata once and upsert it by machine ID.
7. Insert an `observe` session with the real crate version, configuration hash,
   UTC start time, and `clean_shutdown = 0`.
8. Start the telemetry loop only after the session exists.
9. Sample system, process, and retention schedules using monotonic timers.
10. Classify immutable process/system snapshots on the classification schedule.
11. Build policy input, evaluate state, plan, reject observe-mode mutations,
    and persist a deduplicated audit.
12. Persist catalog links and stabilized changes; uncertain outcomes create no
    workload event.
13. On SIGINT/SIGTERM, stop scheduling, close the session, and exit.

If mandatory host metadata cannot be read, startup stops before a session is
created. Errors retain operation and path context.

## Shutdown flow

SIGINT and SIGTERM are handled by the asynchronous signal API. The daemon writes
the UTC end time and `clean_shutdown = 1` in one transaction and exits zero only
after that commit succeeds. A crash, forced kill, or error before the closure
commit leaves the session unclosed, making abnormal termination distinguishable.

## Scheduling and errors

The system interval, process interval, classification interval, heavy `smaps_rollup` interval, retention
interval, batch size, and heavy-read budget are independently validated. Missing
optional PSI/zram/zswap capabilities produce nullable values and structured
capability events. A disappearing or unreadable PID affects only that process.
A temporarily unreadable mandatory system input skips that sample. SQLite batch
or retention failure terminates the loop in a controlled way so telemetry is not
silently lost indefinitely.

## Phase boundary

Phase 4 chooses only among existing Phase 3 intents and records dry-run audit.
It does not invoke actuator apply, add a mutating public mode, tune compression,
run models, or implement Phase 5.
