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
