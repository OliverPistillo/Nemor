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

## Phase 4 validation

Phase 4 was validated on the same CachyOS host on 2026-07-26 without sudo or
cgroup mutation. The workspace contains nine crates. The complete suite defines
and executes 122 tests: all passed, none failed or were ignored. New tests cover
the six pressure states, escalation and recovery through `STABILIZING`,
hysteresis holds, rate derivation/reset, invalid and non-finite input,
1,000 identical serialized evaluations, gaming/unknown invariants, observe
rejections, relevant safety-event suppression, SQLite audit deduplication,
heartbeat, nullable model/gain/cost fields, and bounded history.

A final release daemon ran for 16 seconds with a temporary database and unchanged
`mode = "observe"`. It read real telemetry, classified current processes,
evaluated `nemor-policy-v1` / `pressure-rules-v1`, persisted three explainable
policy audits, and transitioned conservatively from restart `WATCH` to
`NORMAL`. `nemorctl policy status --json` and `policy latest --json` returned
valid typed JSON. The latest input contained real RAM, swap, PSI and counter
rates; unknown processes remained explicitly rejected. `model_version`,
expected gain and expected cost were null.

The session received real SIGTERM, exited zero, and reported `closed_clean`.
There were zero `action_results`. A read-only search found no `nemor-*` cgroup
before or after the run. No cgroup, sysctl, swap, zram, zswap, DAMON, KSM,
reclaim, freezer, process signal, network, or ML operation was performed.

Release overhead was sampled 15 times at two-second intervals:

- mean CPU: 0.199249% of one logical CPU;
- maximum interval CPU: 0.996093%;
- maximum RSS: 7,696,384 bytes (about 7.34 MiB);
- PSS: 5,233,664 bytes (about 4.99 MiB).

Compared with Phase 3, mean CPU was effectively unchanged. The maximum
interval varied upward and resident memory increased by about 0.31 MiB; neither
is a material regression. Phase 3 remains development-complete with privileged
mutation validation pending.

## Phase 5 validation

Phase 5 was exercised on 2026-07-26 on CachyOS kernel
`7.1.4-1-cachyos`, Rust/Cargo 1.97.1, without sudo. The ten-crate workspace
defines 140 tests: all passed, none failed or were ignored; the 122 Phase 4
tests remain intact.

The real read-only inventory found one active 16,640,901,120-byte zram swap
device at priority 100, managed by the systemd zram generator and classified
external. Its active algorithm was `zstd`; available algorithms were `842`,
`deflate`, `lz4`, `lz4hc`, `lzo`, `lzo-rle`, and `zstd`. At the final read it
held 1,414,635,520 original bytes, 320,925,071 compressed bytes, and
329,650,176 allocated bytes: logical ratio 4.4080, effective ratio 4.2913,
allocator efficiency 0.9735, and 1,084,985,344 bytes saved. These values are a
momentary host observation, not a universal benchmark. CPU cost is unavailable
because no isolated algorithm benchmark was permitted.

The current user could read `hot_add` but had no delegated zram-control or
device access. Nemor made no real zram mutation and did not run `sudo`. The
system device was never adopted, reset, deactivated, or written. The simulated
backend demonstrated replacement-first apply/verify/rollback, failure
injection, retry, crash recovery, and no-swap-loss. Privileged mutation
validation therefore remains pending.

A release daemon ran in `observe` with a temporary database, persisted four
typed zram audit snapshots and zero action results or benchmark runs, received
SIGTERM, exited zero, and closed cleanly. All Phase 0–5 CLI commands returned
valid JSON. Fifteen samples at two-second intervals measured mean CPU
0.212940%, maximum interval 0.496909%, maximum RSS 7,675,904 bytes (~7.32 MiB),
and final PSS 5,244,928 bytes (~5.00 MiB), without a material Phase 4
regression.

## Phase 6 development validation

On 2026-07-27 CachyOS kernel `7.1.4-1-cachyos` exposed zswap but booted with it
disabled. The root Btrfs filesystem resolves to a non-rotational SATA SSD, not
NVMe. Read-only inventory detected the kernel command-line and CachyOS provider
conflict without changing either.

The release privileged harness completed the bounded Btrfs swapfile lifecycle
with exit code zero. `/dev/zram0` stayed active and structurally unchanged;
rollback/recovery was idempotent and no resource remained. Full zswap+NVMe boot
validation is pending separate approval and suitable NVMe evidence.

A release observe daemon sampled over 15 two-second intervals exited cleanly
after SIGTERM. Mean CPU was 0.232293%, maximum interval CPU 0.995682%, RSS
8,040,448 bytes and PSS 5,599,232 bytes. These host-specific values are a
modest increase over Phase 5, not a universal performance claim.

## Phase 7 privileged DAMON validation

On CachyOS kernel `7.1.4-1-cachyos`, the release harness completed a real
monitor-only `vaddr` session with exit code zero. All 30 mandatory gates passed,
the report contained no errors, and the structural host baseline was unchanged.
Nine complete aggregation windows measured HOT mean/P50 1.0, WARM mean
0.261111/P50 0.25 and COLD mean/P50 zero. No DAMOS scheme existed.

The controlled 8 MiB-per-zone A/B showed unreliable HOT detection with
default THP backing (2/9 nonzero windows, mean about 0.00444) and stable
detection with mapping-local `MADV_NOHUGEPAGE` (9/9, mean 1.0). This is a
host-specific validation-harness finding, not a global THP policy. Final
`kdamond` CPU was 0.0%, capture CPU 0.02308834%, and synthetic target slowdown
about 3.00004%; the slowdown remains a Phase 10 real-workload benchmark item.

## Phase 8 controlled DAMOS validation

On the same CachyOS kernel, ATTEMPT 4 passed every mandatory controlled-reclaim
gate for a synthetic child owned by the privileged harness. The profile used
an exact COLD core address allow filter, `nr_accesses=0`, `age.min=3`, 5 ms and
8 MiB quotas, a 10 s reset interval, 5 s live deadline and five-snapshot
secondary fence.

Two live COLD candidates totaling 8,388,608 bytes were tried and applied.
Exact pagemap evidence showed HOT and WARM unchanged at 8 MiB present and zero
swapped. COLD changed from 32 MiB present/zero swapped to 24 MiB present/8 MiB
swapped, then returned to 32 MiB present/zero swapped after controlled refault;
the content fingerprint remained valid. The early-refault blacklist blocked
the next plan. Cleanup/recovery were idempotent, no OOM occurred and the host
structure was unchanged.

`kdamond` CPU was 0.25%, validation-control CPU approximately 0.25876444% and
control slowdown 0%. This validates only the controlled synthetic owned-target
path. The normal daemon remains observe-only, and Phase 6 dedicated
zswap+NVMe boot validation remains pending.

## Phase 9 selective KSM validation

On CachyOS kernel `7.1.4-1-cachyos`, read-only inspection found KSM sysfs with
`run=0`, `pages_to_scan=100`, `sleep_millisecs=20`, `smart_scan=1`, fixed
advisor selection (`[none] scan-time`) and the optional advisor controls.
System KSM counters, `cow_ksm` and `ksm_swpin_copy` were zero; process
`ksm_stat` was readable and no external mergeable activity was observed.
The inventory was followed by a successful owned cooperative `--ksm`
positive-path validation in ATTEMPT 3 and a successful real
`--ksm-inefficient` behavioral validation in ATTEMPT 5.

ATTEMPT 3 measured 39,931,904 saved bytes, a 39,651,328-byte positive
system-profit delta, two full scans and about 0.538% sustained `ksmd` CPU.
ATTEMPT 5 measured two new full scans, zero attributable current-session
savings, 8,192 rmap items, zero merging pages and `-524288` bytes process
profit for each owned child. The controller transitioned to INEFFICIENT,
stopped its owned scanner, entered COOLDOWN and rejected the same plan.
Sustained CPU was about 0.480%. Both runs preserved content, configuration and
host structure. These are host-specific synthetic results, not application
benchmarks.
