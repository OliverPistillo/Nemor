# Safe zram backend

Phase 5 adds read-only inventory, compression metrics, deterministic profile
planning, bounded benchmark machinery, and a replacement-first transaction
backend. The normal daemon remains `observe`: it inspects `/proc/swaps` and
`/sys/block/zram*`, records a dry-run audit, and performs no kernel mutation.

## Kernel model and inventory

`comp_algorithm` is parsed as a set of available algorithms plus the bracketed
active algorithm. Nemor never treats an algorithm name as benchmark evidence.
`mm_stat` supplies original bytes, compressed bytes, allocated memory, limits,
peak use, same pages, compacted pages, and huge-page counters. Optional
`io_stat`, block `stat`, `bd_stat`, `mem_limit`, and read-only recompression
capability remain nullable.

Provider detection is best-effort (`systemd` generator/unit, distro/udev,
manual, or unknown). A detected desktop device is external; detection never
grants ownership. Only a freshly created Nemor device or an explicitly adopted,
verified device can enter a mutating transaction.

The zero-safe metrics are:

- logical ratio = original data / compressed data;
- effective ratio = original data / total allocated memory;
- allocator efficiency = compressed data / total allocated memory;
- saved bytes = max(original data - total allocated memory, 0).

Zero or missing denominators produce `null`, never NaN or infinity.

## Profiles and evidence

Exactly three intents exist. `safe` preserves the current configuration when
evidence is insufficient. `gaming` selects a measured low-CPU candidate.
`capacity` selects a measured effective-ratio improvement only when the
configured CPU budget and minimum gain are met. Preferences such as `lz4` and
`zstd` are not automatic winners. Profile rules are versioned as
`zram-profile-rules-v1`.

Disk size is bounded from total RAM, current size/use, available memory, and
configured headroom; no universal byte value is embedded. Critical/emergency
pressure, worsening pressure, high full-memory PSI, swap-in activity, gaming
that would require reinitialization, recent safety errors, provider mismatch,
ambiguous ownership, or pending rollback block risky reconfiguration.

## Benchmark model

Live reporting is read-only and reports the active algorithm and actual ratios.
The isolated benchmark plan uses a dedicated Nemor-owned device, bounded
deterministic high/medium/incompressible datasets, one warmup, five measured
rounds, equal byte counts, and median aggregation. CPU and wall time,
write/read throughput, logical/effective ratio, and allocated memory are
nullable measured outputs. Fixtures carry an explicit simulated marker and
cannot qualify as real evidence.

The dedicated privileged harness validated this model on a hot-added 64 MiB
device with three deterministic 16 MiB datasets and three measured rounds per
dataset. The normal daemon never invokes `sudo` and remains read-only; the
privileged evidence belongs only to the isolated validation harness.

## Transaction and recovery

The transaction is replacement-first: inspect, persist snapshot, validate
ownership/headroom/capabilities, allocate a replacement, select its algorithm
before initialization, set its bounded disk size, verify, activate and verify
valid swap, and only then consider deactivating an old device. If effective
valid swap capacity began above zero, every step must keep it above zero.

An active system zram device is never reset. `hot_add` follows the kernel read
semantics. The only external helpers are fixed absolute `mkswap`, `swapon`, and
`swapoff` executables with separated validated arguments, a canonical
Nemor-owned `/dev/zramN` target, timeout, and captured status. There is no shell.

Snapshots contain provider, ownership, device configuration, activity,
priority, memory statistics, target profile, transaction phase, and verification
state. Rollback and restart recovery are idempotent. External or ambiguous
devices are left unchanged and produce a structured safety error.

## Phase boundary

Phase 5 does not configure zswap, swap files, writeback/backing devices, disk
tiering, sysctl, reclaim, freezer, KSM, or DAMON. Recompression is detected
read-only only. The public CLI has status, profile, and latest-report reads; it
has no apply command. Disk-backed compression belongs to Phase 6 and is not
implemented.

Zram remains a distinct backend in Phase 6. Zswap in front of `/dev/zram0` is
not accepted as evidence for the requested NVMe tier because it may introduce
double compression. The principal comparison is validated zram versus zswap
with real disk-backed NVMe swap.
