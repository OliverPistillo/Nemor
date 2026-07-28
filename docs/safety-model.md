# Nemor safety model

The only valid mode is exactly `observe`.
`general.allow_automatic_actions`, `ksm.enabled`, and `damon.enabled` must all be
false, while `damon.mode` must remain `monitor_only`. Invalid values stop startup
before the database or a session is created.

The actuator crate adds controlled primitives but no alternate profile.
Production
collection opens Linux telemetry files with read-only standard-library calls.
It enumerates `/proc` and `/sys/block` and reads `/proc/<pid>/exe` links, but
never opens a kernel interface for
write, never mounts debugfs, and has no fixture override in the installed
daemon. Observe mode writes neither cgroupfs nor any other kernel interface.

The systemd unit uses a dynamic unprivileged user, an empty capability and
ambient-capability set, no-new-privileges, a strict read-only filesystem, and a
single writable state directory. Home, devices, kernel modules, kernel tunables,
and cgroups are protected, and IP networking is denied. This privilege model
must be explicitly reconsidered before a privileged cgroup deployment; Phase 3
grants no dormant privilege.

PID moves require an explicit stable SHA-256 identity allow-list entry and a
fresh PID/starttime match. Unknown identities are never moved. Only fixed
Nemor-owned groups and `memory.low`/`memory.high` are mutable. Rollback never
signals, freezes, suspends, or terminates a process.

Phase 3 never writes `memory.max`, `memory.swap.max`, `memory.reclaim`, freezer,
sysctl, zram/zswap, KSM, or DAMON state and never shells out to system
administration commands.

The Phase 5 zram backend treats every discovered system device as external.
Observe performs inventory, metrics, planning, and audit only. A transaction
requires explicit ownership, a snapshot, available headroom, safe pressure,
replacement-first activation, readback verification, and rollback. It never
resets active system zram and never disables the only valid swap backend before
a verified replacement exists. Ambiguity blocks the operation.

Potential mutation helpers are an internal allow-list of absolute
`mkswap`/`swapon`/`swapoff` paths with separate validated arguments and an
owned canonical `/dev/zramN` only. No shell or config-controlled executable is
accepted. There is no zswap, writeback/backing device, sysctl, reclaim, freezer,
KSM, DAMON, arbitrary signal, or network operation.

Classification is data-only. It cannot signal a process, change priority,
reclaim memory, create a cgroup, or write a kernel setting. Unknown identities,
critical processes, confirmed games, and confirmed foreground processes are
protected in the model. The invariant
`is_game || protected_game => cold_candidate == false` is enforced directly;
critical and unknown identities are also never cold candidates.

The policy engine is data-only and receives normalized input plus explicit
logical time. Its action allow-list contains only existing Phase 3 intents.
Unsupported, unsafe, unknown-target, or observe-incompatible actions become
audit rejections and never reach actuator apply. Gaming can coexist with severe
pressure, but games remain protected. Invalid or incomplete input retains a
conservative state and emits no mutation.

No full command line or environment is read. Persistent signatures are SHA-256
over a versioned normalized executable basename, never arguments or personal
directory names. Explanations contain stable codes and aggregate observations,
not raw sensitive strings.

Configuration, metadata, migration, and session errors are returned with
context. The daemon reports them and exits nonzero; it does not panic in its
normal control flow. A session is marked clean only after the closure
transaction commits.

Manual uninstallation may remove the binary, unit, and configuration. Historical
data is isolated under `/var/lib/nemor` and can be removed separately
when retention is no longer desired. Retention affects only telemetry rows in
the configured SQLite database. There is no kernel-parameter rollback
because no kernel parameter is ever changed.

Phase 6 preserves observe-mode zero mutation. Swapfile ownership, normalized
paths, helper executable/argv allow-lists, no-swap-loss, write budgets and
rollback are fail-closed. `/dev/zram0` remains external and protected. Zswap is
kernel-global, so live desktop validation never enables it merely to satisfy a
test. Persistent boot plans require separate explicit approval.

Phase 7 preserves the same observe invariant: the daemon never creates,
configures, starts or stops `kdamond`, never enables tracepoints and never
writes DAMON sysfs. The manual validation path accepts only its synthetic child
and owned `nemor-validation-*` objects. It verifies `nr_schemes=0`; there is no
DAMOS, reclaim, pageout, LRU or migration implementation. Mapping-local
`MADV_NOHUGEPAGE` is restricted to the synthetic A/B validation control and is
not a runtime workload policy.
## Controlled DAMOS boundary

Phase 8 adds no production mutation. Manual `--damos` is restricted to an
owned synthetic PID/start-time identity and exact COLD fence. Unknown
capability, identity, filter, quota, or ownership blocks action. Foreground,
gaming, critical, and protected targets always reject. Pageout rollback stops
future actions; it cannot undo reclaimed pages byte-for-byte. The controlled
path is validated on CachyOS with COLD-only trace candidates and exact-range
pagemap proof that HOT/WARM remained resident.

## Selective KSM boundary

Phase 9 normal runtime remains observation and planning only. KSM is a global
cross-process deduplication facility, so unknown identity, foreign security
domain, foreground, gaming and critical candidates are rejected. Nemor cannot
remotely apply `MADV_MERGEABLE`; only an owned cooperative validation child may
opt in its exact mappings. The global unmerge value `run=2` is prohibited in
all paths. Owned rollback uses `run=0`, headroom-guarded child unmerge or child
termination, scanner snapshot restoration and idempotent owned recovery.
Real profitable and inefficient-controller paths are validated only for owned
synthetic targets; normal runtime remains non-mutating.

## Benchmark safety

Phase 10 never turns measurement into an authority bypass. The normal CLI is
read-only and the explicit runner only permits small owned synthetic smoke
workloads at Checkpoint 1. No configuration-supplied shell command is
executed. Future memory-pressure validation is confined to an owned cgroup
whose limit is below measured host headroom, with watchdog, timeout, structural
snapshot and restore proof. Host OOM and restore mismatch are safety failures.
Unavailable or unknown capability fails closed.

Checkpoint 2 adds one explicit privileged-capable transient-scope lifecycle,
validated explicitly in ATTEMPT 5 but never executed automatically. Systemd
PID 1 is the sole cgroup
writer. Audit precedes `StartTransientUnit`; the request contains one exact
PID, 128 MiB `MemoryMax`, accounting and a 15 second bound. Nemor resolves the
kernel path only from systemd's `ControlGroup` property and performs read-only
metric collection there. It never writes `memory.max`, `cgroup.procs` or
`cgroup.subtree_control`, and never adopts or replaces an unknown unit.
PID/start-ticks remain authoritative through cleanup. Every spawned-worker
path evaluates worker cleanup; every post-mutation path evaluates scope
cleanup. Only the exact owned worker, unit and transaction may be affected,
and `host_unchanged` requires all three resources to be absent.

Checkpoint 3A adds no pressure or optimizer mutation. It hard-caps touched
payload at 256 MiB, uses dynamic host reserve, rejects any foreign `nemord`,
and never stops or adopts it. Every repetition must remove its worker, scope,
observer and isolated storage handles and reproduce the structural snapshot.
A safety or restore failure aborts the remaining randomized plan. Dirty or
stale release binaries cannot produce eligible performance evidence.

Checkpoint 3A-P authorizes only one additional validation mutation surface:
`StartTransientUnit` and `StopUnit` for an exact
`nemor-benchmark-observer-*.service`, plus exact transaction files under
`/run`: a root-staged single-link observer executable, staged config,
RuntimeDirectory and isolated database. The Cargo release binary remains an
unprivileged source artifact and is never executed by the transient service;
its descriptor-read bytes must hash-identically match the staged executable.
It never manipulates production `nemord.service`. A foreign `nemord`
is a preflight failure and never grants signal or stop authority. Readiness
requires a real telemetry sample in the isolated database.

Validation compares swap topology, zram configuration, zswap state, KSM
configuration, DAMON tree shape, bounded cgroup topology, and production Nemor
config/database metadata. The observer service cgroup, RuntimeDirectory files
and SQLite writes are the only authorized temporary differences. Common
cleanup requires MainPID, unit, cgroup and runtime-directory absence.
Only after process absence may exact hash/owner/mode-verified staged inputs be
removed; either staging residue makes restore fail.
