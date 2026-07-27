# DAMON monitor-only telemetry

Phase 7 uses DAMON only as an observational source. It creates no DAMOS
schemes and performs no reclaim, pageout, LRU manipulation, migration, or
other memory-management action. Normal `nemord` observe mode does not create,
configure, start, or stop a `kdamond`.

## Access detection and the TLB limitation

The `vaddr` operations set observes access state derived from page-table
Accessed/Young information. DAMON clears that state for sampling while its
low-overhead production design does not flush the TLB after every sample.
An access served by an existing TLB entry can therefore avoid a new page-table
walk and fail to set the cleared page-table state again.

This is especially visible in small synthetic working sets that remain within
the effective TLB reach. It is a possible false negative in a test workload,
not evidence of a kernel bug and not a reason for Nemor to flush TLBs or patch
DAMON. Larger, production-like working sets naturally cause more translation
turnover.

RETRY 7 showed that byte-size scaling was confounded by nearly complete THP
backing, so it cannot confirm or reject the TLB explanation. The validation
model uses one non-contradictory hypothesis enum and records this result as
`inconclusive_due_to_thp_backing`.

The successful controlled validation created three owned anonymous mappings with
`memmap2` 0.9.11. This version is MIT/Apache-2.0 licensed and includes the fix
for RUSTSEC-2026-0186. Anonymous mapping construction and whole-map advice are
safe APIs. The reference profile uses default kernel backing; the base-page
profile applies `Advice::NoHugePage` before initialization and prefault.
No global THP interface is modified.

Both profiles used eight MiB per zone and otherwise identical
workload and DAMON attributes. Each probe needs at least eight complete
aggregation windows. Base-page results are interpreted only after `smaps`
proves 4-KiB kernel/MMU pages, zero `AnonHugePages`, and a no-huge-page marker
for HOT, WARM, and COLD. If eight MiB is unstable, the bounded base-page-only
fallback tries 32 then 64 MiB per zone, retaining a one-GiB headroom guard.
No larger working set was needed.

The default/THP reference produced HOT observations in 2/9 windows, seven
HOT-zero windows, HOT mean about 0.00444 and P50 zero. WARM remained about
0.25944 and COLD zero; the mapping reported about 24 MiB of anonymous huge
pages and was THP-eligible. With mapping-local `MADV_NOHUGEPAGE`, the otherwise
identical run produced HOT mean/P50 1.0 in all nine windows, WARM mean
0.261111 and COLD zero. `smaps` verified zero anonymous huge pages,
`THPeligible: 0`, `VmFlags: nh`, and base-page backing for every zone.

The final hypothesis state is `supported_by_base_page_comparison`: on this
specific CachyOS validation system, THP backing made the small synthetic DAMON
access-frequency benchmark unreliable while base-page backing gave stable
HOT/WARM/COLD separation. This is not a universal hardware, kernel, workload
or production conclusion. THP is not treated as broken, and Nemor never
applies `MADV_NOHUGEPAGE` to real workloads; it is only a validation-harness
control.

Each probe and the final run use three explicit initial `vaddr` regions, an
isolated tracefs instance, `damon:damon_aggregated`, and zero DAMOS schemes.
Every probe owns and cleans up its child, kdamond object, context, trace
instance, and temporary files before the next size is attempted.

Probe and final sessions use the same capture implementation. Every session
has a distinct identifier, trace instance, file descriptor, capture worker,
buffer, and parser state. Capture readiness requires readback of the event
enable and `tracing_on`. After `kdamond` is stopped, a bounded drain completes
before capture is stopped and the instance is removed. Reports distinguish
trace bytes, lines, DAMON event lines, parsed events, parse failures,
timestamp failures, incomplete lines, and bytes obtained during drain.
No-event instrumentation failure is distinct from a valid event whose
`nr_accesses` is zero.

## Page backing diagnostics

Before monitoring, the harness reads the synthetic child's `/proc/PID/smaps`
and records `Size`, `Rss`, `Pss`, `KernelPageSize`, `MMUPageSize`,
`AnonHugePages`, `THPeligible`, and `VmFlags` for HOT, WARM, and COLD ranges.
This distinguishes 4 KiB, THP, mixed, and unknown backing without changing the
host THP policy. When multiple synthetic zones belong to one encompassing VMA,
the report records the containing VMA range and a shared-VMA group so its THP
statistics are not presented as three independent allocations.

## Workload and evidence

HOT and WARM use the same safe page-touch function. HOT calls it continuously;
WARM changes only the cadence. COLD is initialized before monitoring and has
no monitoring worker. Atomic operations are limited to synchronization and
counters. After `kdamond` stops, bounded fingerprints confirm that HOT and
WARM were modified and COLD retained its expected contents.

Trace timestamps are matched against workload progress intervals by temporal
overlap. The harness feature-detects the clocks exposed by the owned tracefs
instance and selects `mono`, then `mono_raw`, then `boot`. It writes and reads
back only `instances/nemor-validation-*/trace_clock`, before event enable or
capture because changing the clock clears the instance buffer. Userspace reads
the matching `CLOCK_MONOTONIC`, `CLOCK_MONOTONIC_RAW`, or `CLOCK_BOOTTIME`
through a safe system-call wrapper. `local` is never accepted and no estimated
offset is applied.

Partial first and last aggregation windows remain diagnostic records but are
excluded from final signal evidence. Raw `nr_accesses`, effective monitoring
attributes, overlap weights, normalized ratios, region age, and worker
progress are retained so a workload-active/DAMON-zero observation is reported
as a false-negative diagnostic rather than a lifecycle failure. Lifecycle
timestamps use realtime only for ordering/audit. Payload parsing, trace
timestamp parsing, and timestamp correlation have separate validation gates;
epoch timestamps are never compared with monotonic timestamps.

Workload progress is sampled as timestamped cumulative counters. Deltas are
formed between adjacent samples. When a DAMON aggregation window crosses a
sample boundary, each interval delta is prorated by
`overlap_duration / interval_duration`; the report marks these correlated
counts as estimated and records the overlap duration. An interval that
overlaps by only a fraction is never counted in full.

## Architecture and capability discovery

`nemor-damon`, the twelfth workspace crate, owns the serializable capability,
attribute, region, normalization, label, overhead, report and export models.
It does not duplicate process identity, telemetry, policy or actuator code.
Linux discovery feature-detects the DAMON sysfs admin tree, operation sets,
existing `kdamond` objects, special-purpose DAMON modules, tracefs instances,
`damon:damon_aggregated`, optional kernel fields and read/write permissions.
Missing or malformed optional files remain unavailable rather than causing a
panic.

The normal daemon path is read-only: collect capability, ingest an already
safe available source, normalize, persist and report. Unknown, unsupported,
externally owned or conflicting state produces no action. Only the separately
compiled manual validation harness may create an owned monitor-only session.

## Sysfs ownership and monitor-only transaction

The harness accepts only a synthetic child with verified PID, start ticks and
Nemor identity. It allocates a new owned `kdamond`, one `vaddr` context,
requested/effective monitoring attributes, three sorted non-overlapping
initial regions, and exactly zero schemes. Each write has readback. Existing
sessions and special-purpose modules are never adopted or disabled.

The tracepoint is enabled only in an owned
`instances/nemor-validation-*` tracefs instance. Its clock is selected and
read back before capture; `mono` maps directly to userspace
`CLOCK_MONOTONIC`. Global tracing and the global trace clock are untouched.

## Aggregation, regions and normalization

DAMON may split and merge adaptive regions, so samples do not receive invented
persistent identities. Each aggregation snapshot retains raw range,
`nr_accesses`, age and requested/effective intervals. Access frequency is
normalized against effective sampling opportunities and zone evidence is
overlap- and size-weighted. Repeated ranges across windows count as temporal
samples, not additional memory footprint. Partial first/last windows are
diagnostic only.

Hot, warm and cold labels are deterministic, versioned and observational.
They never trigger reclaim or another memory action. One observation cannot
become high-confidence stable cold evidence.

## Dataset and persistence

SQLite migration `0005_damon.sql` adds bounded session, region and overhead
records. Retention, batch limits and drop counters prevent unbounded daemon
growth. Explicit CLI export supports versioned bounded JSONL and CSV:

```text
nemorctl damon export --format jsonl --output <new-path>
nemorctl damon export --format csv --output <new-path>
```

Records contain session metadata, raw region observations, aggregation and
normalized metrics, zone overlaps, timestamps, kernel/operation metadata and
observational labels. Validation reports additionally contain page-backing
and overhead evidence. They never contain RAM contents, environment variables,
secrets or user payloads. Validation reports and datasets use run/session
scoped `/tmp` paths; the fixed report path is only the latest copy.

## Real CachyOS validation

On CachyOS kernel `7.1.4-1-cachyos`, the manual release harness completed with
exit code zero and all 30 mandatory gates passed. The final five-second
`vaddr` session used 25 ms sampling, 500 ms aggregation, 10 s region updates,
10–1000 regions and a 100 ms WARM cadence. Nine complete windows measured:

- HOT mean/P25/P50/P75/P95 = 1.0, with 80 raw accesses in every window;
- WARM mean 0.261111, P25/P50/P75 0.25 and P95 0.30;
- COLD mean and all reported percentiles = 0.

`kdamond` CPU measured 0.0% and capture CPU 0.02308834%, within the hard 1%
monitor CPU budget. Synthetic target slowdown measured about 3.00004%. DAMON
is not zero-cost: slowdown must be reevaluated with real workloads and the
Phase 10 benchmark framework, and these host-specific numbers are not a
production promise.

## Safety, recovery and phase boundary

The real run verified PID/start-time identity, initial-region readback,
per-instance tracing, zero `nr_schemes`, stop/readback, cleanup, crash recovery,
second-recovery idempotence and an unchanged host baseline. It performed no
DAMOS, reclaim, pageout, LRU promotion/deprioritization, migration, zram,
zswap, tiering or persistent boot mutation. `/dev/zram0` remained
external/protected.

Phase 7 measures only. Phase 8 may introduce separately controlled DAMOS
reclaim, but it is planned and not started; no Phase 8 action exists in this
code.
