# Baseline telemetry

## Sources and units

The collector reads `/proc/meminfo`, `/proc/vmstat`, `/proc/stat`,
`/proc/pressure/{memory,cpu,io}`, `/proc/swaps`, `/proc/<pid>/*`,
`/sys/block/zram*`, `/sys/module/zswap/parameters/enabled`, and already
accessible zswap statistics. It never mounts debugfs and never writes a procfs
or sysfs file.

All Linux `kB` values are converted with `1 kB = 1024 bytes` before storage.
`AnonPages` represents anonymous memory. File cache is `Cached + Buffers`.
`Slab` is stored directly. Swap used is `SwapTotal - SwapFree`.

The vmstat families `pgscan*`, `pgsteal*`, and `workingset_refault*` are sums of
all matching keys. This preserves one stable total across kernels that expose
different anon/file or direct/kswapd variants. Unknown keys are ignored.

PSI parsing retains `some` and optional `full`, including `avg10`, `avg60`,
`avg300`, and cumulative `total` microseconds. The database stores the Phase 1
avg10 fields while the collector model retains all parsed values.

## Process samples and CPU

Basic process data comes from `stat`, `status`, `io`, `cgroup`, and the
read-only `exe` link. Phase 2 also retains comm, parent PID, process/session
group, TTY foreground group, and start ticks in memory for identity, ancestry,
foreground, and PID-reuse-safe decisions. It never reads `environ` or persists
a full command line.
`smaps_rollup` is separately scheduled and limited to a rotating process budget;
defaults are 60 seconds and 32 PIDs. PSS is the kernel `Pss` value. USS is
created only when both `Private_Clean` and `Private_Dirty` exist, as their sum.
Missing or denied rollups remain `NULL`.

CPU is never inferred from one reading. For the same PID and unchanged process
start time, consecutive `/proc/<pid>/stat` process ticks and `/proc/stat`
aggregate ticks produce:

`cpu_percent = process_tick_delta / system_tick_delta * logical_cpu_count * 100`

The first sample, zero/invalid deltas, and PID reuse produce `NULL`. Completed
PIDs are removed from the tracker.

## Time and scheduling

`timestamp_ns` always means signed nanoseconds since the Unix epoch. It is used
only for persistent ordering, report deltas, and retention. Sampling intervals,
heavy-read due times, and shutdown scheduling use Tokio's monotonic clock; the
two clock domains are never mixed in one field.

Defaults:

- system: 1000 ms;
- processes: 5000 ms;
- classification: 5000 ms with three confirmations for non-critical changes;
- `smaps_rollup`: 60000 ms, 32 PIDs per heavy pass;
- retention: 7 days, executed hourly;
- SQLite process batch: 512 rows.

All values are validated. System sampling cannot be below 100 ms, process
sampling below 1000 ms, heavy sampling below 5000 ms, or retention execution
below 60000 ms.

## Optional capabilities

Missing PSI, zram, zswap, or zswap statistics are represented by nullable values
and capability names. zram devices are observed whether or not `/proc/swaps`
lists them. zswap enabled state and statistics are best effort. No unavailable
metric is synthesized.

## Retention and failure behavior

Process rows use transaction batches. Retention deletes expired process and
system rows together in one transaction at scheduled intervals. SQLite write or
retention errors are fatal to the telemetry loop and are logged as controlled
storage errors. Mandatory collector read errors skip the affected tick; optional
and per-process failures produce partial samples.

## CachyOS validation pending

Fixtures and portable tests validate parsing, scheduling, storage, reporting,
and error behavior. Real `/proc`, `/sys`, PSI, swap, zram, and zswap behavior;
idle CPU below 1%; daemon memory below 100 MB; and long-session database behavior
remain `CACHYOS VALIDATION PENDING`.
