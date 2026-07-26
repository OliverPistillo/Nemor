# CachyOS validation of phases 0–2

Date: 2026-07-26

## Environment and scope

Validation was performed natively on CachyOS Linux (`x86_64`), kernel
`7.1.4-1-cachyos`, with approximately 15.5 GiB of RAM. Rust and Cargo were
both version 1.97.1. Hostname, user name, machine ID, home paths, and process
command lines are intentionally omitted.

Only the observe-only implementation from phases 0–2 was exercised. No
actuator, policy engine, mutable cgroup operation, kernel setting, swap change,
or phase 3 feature was introduced or tested.

## Host capabilities

- `/proc/meminfo`, `/proc/vmstat`, and PSI memory/CPU/I/O were readable.
- The unified hierarchy was `cgroup2fs`; its controllers included `memory`.
- Swap was provided by one zram device. zram telemetry was observed.
- zswap was present in sysfs but disabled; optional zswap statistics were not
  available.
- Steam was installed, but no game, Proton, Wine, or Gamescope runtime was
  deliberately started. Gaming runtime evidence therefore remains fixture
  based.

All capability probes were read-only.

## Build and automated tests

The native validation ran:

```text
cargo fmt --check
cargo build --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo metadata --no-deps --format-version 1
```

The Linux production collector tests read the real `/proc` and `/sys`.
Automatic Unix lifecycle tests sent real SIGTERM and SIGINT. Collector tests
covered real Linux interfaces, disappearing processes, unit conversion, PSI,
swap, zram/zswap, process CPU baselines and PID reuse. Storage tests covered
all three migration checksums, transactions, retention, WAL/foreign-key
connection pragmas, reports, workload events, and clean/unclean session state.

## Runtime lifecycle and SQLite

A temporary observe-only configuration retained
`allow_automatic_actions = false` and changed only the database path. The
release daemon read real machine, distro, kernel, RAM and swap metadata, opened
SQLite, applied migrations 0001/0002/0003, registered the host, opened a
session, and sampled real system and process state in the foreground.

The primary 32-second SIGTERM session produced 33 system samples and 28
process samples. A separate SIGINT session produced 7 system samples and 8
process samples. Both signals returned exit code zero, populated `ended_at`,
set `clean_shutdown = 1`, and produced `closed_clean` status. Integrity and
foreign-key checks reported no violations, migration checksums were 64
hexadecimal characters, and no partial session remained.

SQLite used WAL while open and checkpointed the WAL on clean close. Storage
opens every connection with foreign keys enabled; the dedicated Rust pragma
test verified `journal_mode = wal` and `foreign_keys = 1`.

## Telemetry plausibility

The real samples satisfied:

- `MemAvailable <= MemTotal`;
- swap used did not exceed configured swap;
- byte-valued database fields matched the collector's explicit KiB-to-byte
  conversion tests;
- counters and byte values were non-negative;
- memory, CPU and I/O PSI were independently populated;
- anonymous memory, file cache, slab, page faults, major faults, pgscan,
  pgsteal, workingset refault, swap-in and swap-out were populated.

The latest report returned valid JSON and included session ID, sample counts,
minimum MemAvailable, maximum swap use, memory PSI, major-fault and swap
deltas, zram observed, zswap not observed, and unavailable capabilities.

Real process rows contained PID, catalog link, RSS, swap, faults, CPU, I/O,
cgroup, and start ticks. PSS/USS were obtained within the configured smaps
budget. Process disappearance and permission races remained local partial
samples rather than global collection failures. The runtime report does not
expose command lines.

## Process identity, foreground, and workload

Persistent process identity uses normalized executable paths when available,
a versioned `nemor-process-identity-v2` SHA-256 representation, and a basename
fallback. Private executable paths are not displayed. Tests demonstrate that
different paths with the same basename do not collide, repeated identities do
not duplicate, and PID reuse resets CPU identity baselines.

A CachyOS runtime finding showed that generic desktop `app-*.scope` cgroups
were being treated as Steam evidence. The detector now requires Steam context
for that scope form, with a regression test. After the fix the real release
session detected zero game processes and emitted no false gaming event.

All sampled processes lacked decisive TTY foreground evidence in the
non-interactive validation environment and remained `unknown`; none was
misclassified as background. Fixture tests cover TTY foreground, TTY
background, and unknown behavior.

The real light workload did not accumulate evidence for a safe stable class.
`workload latest --json` therefore returned a valid controlled
`available=false` result with four unknown processes and no workload event.
This is the intended conservative behavior: unknown did not become idle.
Stabilization and event-on-real-transition behavior remain demonstrated by
the deterministic tests.

## Resource overhead and database growth

The release daemon was sampled 15 times at two-second intervals using
`/proc/<pid>/stat`, `status`, and `smaps_rollup`.

- Mean CPU: 0.2637% of one logical CPU.
- Maximum interval CPU: 0.9705%.
- Peak RSS: 7,454,720 bytes (about 7.11 MiB).
- Last PSS: 5,004,288 bytes (about 4.77 MiB).

The development profile measured 2.8453% mean and was excluded from the
shipping overhead criterion because it is unoptimized.

During the primary release session, the main database grew from a 4,096-byte
file with a 193,672-byte active WAL to a checkpointed 122,880-byte database
and zero-byte/absent WAL after clean close. With 61 samples this corresponds
to approximately 2,014 allocated database bytes per sample for this short,
schema-dominated run. Growth is controlled by transactional retention of
system and process samples older than the configured seven days; synthetic
tests demonstrate that old rows are removed and recent rows are preserved.

## systemd and security

`systemd-analyze verify` succeeded against a temporary filesystem root
containing the built executable, using `--recursive-errors=no` so unrelated
host target units were not required. Nothing was installed or enabled.

The unit is `Type=simple`, runs `/usr/bin/nemord` with
`/etc/nemor/config.toml`, uses `DynamicUser` and `StateDirectory=nemor`, and
enables `NoNewPrivileges`, kernel/cgroup protections, filesystem restrictions,
an empty capability set, and network denial.

Every Rust crate forbids unsafe code. The implementation performs no writes to
procfs, sysfs, cgroupfs, sysctl, swap, zram, or zswap; invokes no sudo,
systemctl, arbitrary shell command, or runtime IP networking; and contains no
phase 3 behavior.

## Result

```text
FASE 0 — VALIDATA SU CACHYOS
FASE 1 — VALIDATA SU CACHYOS
FASE 2 — VALIDATA SU CACHYOS
```

The open environmental limitation is direct observation of an active Steam,
Proton, Wine, or Gamescope game. Their detector logic remains covered by
fixtures and absence of an active game is not a phase 2 failure.

## Phase 3 follow-up

Phase 3 performs real read-only cgroup v2 and memory-controller inspection on
this CachyOS host. The default service remains observe-only and receives no
cgroup delegation. If the hierarchy is not writable without administrative
elevation, kernel mutations remain explicitly unvalidated rather than being
simulated as real.
