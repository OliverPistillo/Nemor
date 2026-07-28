# Nemor architecture

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

`zram` owns Linux zram inventory and parsing, zero-safe compression metrics,
three deterministic profile plans, bounded benchmark evidence, ownership and
pressure guards, and replacement-first apply/verify/rollback/recovery
primitives. It does not read policy thresholds or grant itself ownership.

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
12. Inspect zram read-only, translate the selected profile intent into a
    blocked/dry-run technical plan, and persist its typed snapshot.
13. Persist catalog links and stabilized changes; uncertain outcomes create no
    workload event.
14. On SIGINT/SIGTERM, stop scheduling, close the session, and exit.

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

Phase 5 adds zram-only planning and guarded primitives. Observe mode never
invokes them. It does not configure zswap, backing devices, writeback, disk
tiering, KSM, DAMON, or any Phase 6 mechanism.

## Phase 6 tiering boundary

`nemor-tiering` is the eleventh workspace crate. The policy engine emits only a
backend-selection intent; the tiering crate validates evidence and safety.
`nemord` performs read-only inventory and persists audit snapshots. Runtime
swapfile and zswap mutation is unavailable through the daemon and `nemorctl`.
The separately compiled privileged harness owns bounded validation resources.
See [tiering.md](tiering.md).

## Phase 7 DAMON boundary

`nemor-damon` is the twelfth workspace crate. It models capability discovery,
monitoring attributes, raw adaptive regions, normalized observational labels,
overhead, bounded persistence and dataset export. Normal `nemord` observe mode
does not create or configure `kdamond` or mutate tracefs. The manual privileged
harness alone owns bounded synthetic `vaddr` sessions with zero schemes.

The pipeline is process identity → target plan → owned monitor-only session →
`damon:damon_aggregated` → normalized hot/warm/cold evidence → SQLite/export.
No DAMOS or memory-management action exists in Phase 7. See
[damon.md](damon.md).
## Phase 8 action boundary

`nemor-damos` owns DAMOS capability, fail-closed eligibility, exact address
fences, quotas, stat-shadow/pageout transaction models, refault cooldown, and
owned recovery. `nemor-damon` remains observational. Production is plan-only;
kernel mutation exists only in the manual privileged validation binary. That
controlled owned-target path is validated on CachyOS with exact pagemap
evidence; it is not an automatic production reclaim path.

## Phase 9 KSM boundary

`nemor-ksm` is the fourteenth workspace crate. It owns KSM capability and
metrics, conservative VM/browser/Electron profiles, scanner planning,
profit/CPU-cost evaluation, the auto-disable controller and owned validation
transactions. Normal daemon integration is read-only and plan-only. The
validated mutating paths are manual `--ksm` and `--ksm-inefficient` scopes with
cooperative synthetic children; they
cannot opt arbitrary external processes into KSM and hard-rejects global
`run=2`. See [Selective KSM](ksm.md).

## Phase 10 benchmark boundary

`nemor-benchmark` is the fifteenth workspace crate. It owns versioned scenario
and variant definitions, manifests, fingerprinting, metric semantics,
statistics, comparison/acceptance, report persistence, restore proof and the
explicit safe runner. It orchestrates validated component APIs but cannot
write KSM, DAMON/DAMOS, zram, zswap or cgroup sysfs behind those boundaries.
Checkpoint 1 runner execution is restricted to tiny owned non-pressure
synthetic smoke workloads. `nemorctl` exposes read-only benchmark inspection;
normal `nemord` production behavior is unchanged.

Checkpoint 2 uses a narrowly scoped `zbus` system-bus backend for systemd
transient scopes. Only fixed systemd destination/interface/method/property
identifiers are exposed. The backend is not a generic systemd control API and
does not invoke systemd command-line tools. It creates fixed `Unit` and
`Scope` proxies for the same systemd-returned object path. Generic identity
and lifecycle state is read from `org.freedesktop.systemd1.Unit`; bounded
resource-control state and `ControlGroup` are read from
`org.freedesktop.systemd1.Scope`. A fixed property/interface/type contract is
checked during read-only capability discovery.

`Manager.Subscribe()` and the `JobRemoved` match precede
`StartTransientUnit(mode=fail)`. The exact returned job path must complete
with `result=done`; `GetUnit(expected unit)` and `GetUnitByPID(exact worker)`
must resolve the same object. `StopUnit` is likewise asynchronous and bounded.
Systemd is the cgroup writer. Nemor does not write controller, limit or
membership files; create/remove systemd cgroups; restructure `user.slice`; or
migrate foreign processes. ATTEMPT 5 validated this architecture and its
common exact-owned cleanup path on CachyOS.

Checkpoint 3A reuses that worker boundary identically for baseline and observe,
but does not run the observer as a child of the privileged runner. Checkpoint
3A-P adds a second system-manager role: the synthetic worker remains the
validated transient `.scope`, while the observer is an exact benchmark-owned
transient `.service` because PID 1 must create the release `nemord` with
`DynamicUser=true`.

The service uses fixed typed properties and argv, `mode=fail`, subscribed
asynchronous job completion, an ephemeral `RuntimeDirectory`, and read-only
binds of root-staged, hash-approved executable/config inputs. Its
database is inside that runtime directory, never the production database.
`Service.MainPID`, numeric effective UID/GID, start ticks, `/proc/PID/exe`
hash, `GetUnitByPID`, and the systemd-derived service `ControlGroup` form the
runtime identity. DynamicUser numeric IDs need not be stable.

Source provenance is prepared unprivileged from a clean release build. The
privileged validation consumes an integrity-bound manifest, re-hashes its own
binary, `nemord`, and config, and never calls Git. Cargo's source `nemord` may
have multiple hard links; it is opened no-follow and read through the verified
descriptor, then copied byte-identically to an exact root-owned, single-link
`/run` executable. Config uses the same fixed-role staging boundary. Systemd
binds only those staged inputs, closing the user-owned path and hard-link
TOCTOU window. Checkpoint 3A-P remains pending one bounded live validation.

The application-level provenance command is authoritative for cleanliness;
shell emptiness of `git status` is intentionally not used because bounded
validation reports remain preserved as untracked non-source evidence.

Build identity is supplied by one shared build-time Git resolver used by both
`nemor-benchmark` and `nemord`. It registers Cargo dependencies on Git's
resolved worktree HEAD plus the active loose ref, or packed refs and the
bounded ref directory needed to observe loose-ref creation. It supports
detached HEAD and linked worktrees without assuming `.git` is a directory.
This compile-time read-only Git step is separate from privileged execution,
which remains entirely manifest/hash driven and invokes no Git.
