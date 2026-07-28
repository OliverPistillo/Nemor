# Phase 10 benchmark framework

Phase 10 demonstrates results with reproducible A/B experiments. The framework,
safe instrumentation smoke path, and Checkpoint 2 privileged harness are
validated; real A/B validation is pending. Smoke and harness-validation results
are never capacity, gaming, OOM-avoidance or production performance evidence.

## Scenarios and execution level

| Scenario | Workload unit | Checkpoint 1 execution |
|---|---|---|
| `browser_many_tabs` | calibrated tab workload unit | manual/cooperative |
| `gaming_background` | background unit at fixed foreground load | manual/cooperative |
| `compile_rust_cpp` | deterministic fixture scale | owned adapter, planned |
| `ide_containers` | container workload unit | manual/cooperative |
| `multiple_vms` | configured guest bytes/VM unit | manual/cooperative |
| `synthetic_compressible` | declared prefaulted bytes | tiny owned smoke |
| `synthetic_incompressible` | declared prefaulted bytes | tiny owned smoke |
| `progressive_memory_pressure` | explicitly tested load level | privileged cgroup design only |

The real validation order is synthetic compressible, synthetic
incompressible, controlled progressive pressure, deterministic Rust/C++
compile, browser, IDE/containers, VMs, then gaming. That safety ordering is
separate from seeded randomization inside a comparable experiment.

Variants are `cachyos_baseline`, `nemor_observe`, `nemor_safe`,
`nemor_gaming`, `nemor_capacity`, `zram`, and `zswap`. Availability is
capability-driven. Zswap remains `pending_validation` because Phase 6
zswap+NVMe boot validation is pending; the framework never substitutes a
different backend.

## Run and comparison semantics

A run manifest fixes scenario/schema version, host fingerprint, kernel, Nemor
commit, configuration hash, seed, repetition, order and providers. Lifecycle
states separate completion from validity. Invalid runs and their reasons are
retained, and no automatic outlier removal occurs. An aggregate needs at least
three valid repetitions. Seeded ordering is reproducible; reboot-only variants
form explicit non-randomizable blocks.

Logical workload bytes/units are independent of observed physical memory.
Maximum sustainable load is the highest actually tested level satisfying the
scenario constraints. Capacity gain is
`candidate_max / baseline_max - 1`; untested interpolation is not capacity.
Different kernels, configurations, or material host fingerprints block a
comparison.

Metrics preserve source, unit, scope and availability. Missing is not zero.
Providers cover procfs memory/vmstat/swaps/PSI/CPU, process metrics, cgroup v2
models, zram/zswap, KSM, DAMON/DAMOS summaries, block writes, optional imported
frametimes, cooperative latency events and optional powercap energy. Host-wide
and workload-scoped counters are never presented as interchangeable.
Raw samples may retain absolute monotonic kernel observations such as
`pgmajfault`, `pswpin`, `pswpout`, cgroup cumulative counters, CPU/I/O totals
and PSI total stall time. Performance summaries and A/B comparisons use only
run/session-relative deltas for those counters; boot-absolute totals are never
acceptance inputs.

Statistics retain all run values and expose count, mean, median, min, max,
population standard deviation, P50, P95 and P99. Three repetitions do not
establish statistical significance. The 1% low is the inverse of mean frame
time for the worst one percent of samples.

## Safety boundary

The dedicated `nemor-benchmark` runner has no default or “run all” action.
Checkpoint 1 can only run bounded owned compressible/incompressible smoke
allocations. It invokes no shell, sudo, KSM, DAMON/DAMOS, zram, zswap or
privileged cgroup mutation. External adapters require an absolute executable
from an explicit allow-list plus an argv vector; configuration cannot provide
shell text.

The progressive-pressure performance runner remains future work. Checkpoint 2
validated the explicit privileged owned-cgroup transaction without applying
performance pressure. `MemoryMax` must remain below measured host headroom, a
watchdog and timeout are mandatory, and host OOM is always a safety failure.
Controlled cgroup OOM is a distinct outcome. Structural
snapshots compare swap, zswap, KSM and DAMON state; restore mismatch invalidates
the result.

The runner does not bypass component ownership, audit, headroom, rollback or
recovery guards. Normal `nemord` semantics remain unchanged. `nemorctl`
benchmark commands list, plan, inspect, compare and export stored evidence
only.

## Acceptance

The versioned engine models favorable capacity gain of at least 30%, gaming
background capacity gain of at least 15%, CPU-bound regression at most 5%,
gaming P95 frametime regression at most 10%, an explicit scenario threshold
for incompressible regression, and successful restore.

Insufficient evidence is `not_evaluated`, never pass or fail. At Checkpoint 1
all effectiveness targets remain not evaluated.

## Checkpoint 2 provenance and evidence

Every report records Git HEAD, dirty state, a deterministic source-state hash,
binary SHA-256, build profile, benchmark/scenario version and configuration
hash. The source-state hash covers tracked changes and hashes of relevant
untracked sources without embedding a diff or identifying path. Dirty builds
are development builds. They may produce `framework_smoke` or
`harness_validation` evidence, but never performance claims.

Evidence kinds are `framework_smoke`, `harness_validation` and
`performance_benchmark`. Only clean committed `performance_benchmark` runs can
enter capacity, gaming or CPU acceptance aggregates.

Variant resolution records requested variant, executable/alias/pending state,
effective-state hash, reason and exact difference. Baseline and observe are
executable for an explicit observer-overhead comparison. Safe, gaming and
capacity orchestration remain pending. A zram name that resolves to the
existing CachyOS zram configuration is an alias, not an A/B variant. Zswap
remains pending Phase 6.

## Owned-cgroup harness

`nemor-benchmark validate-cgroup` is an explicit privileged-capable safety
validation command. It accepts no arbitrary PID, cgroup path, capacity mode or
OOM mode. It creates one `nemor-benchmark-*.scope` using systemd PID 1's
`StartTransientUnit` D-Bus API. Systemd is the only cgroup writer: Nemor does
not create/remove the scope directory or write `memory.max`/`cgroup.procs`.
The scope is atomically configured with the exact worker PID, 128 MiB
`MemoryMax`, memory/CPU/I/O accounting and a 15 second runtime bound.

The worker starts outside the cgroup without allocating the payload. After
PID/start-ticks verification and durable audit, the harness asks systemd to
create the scope, reads back its properties and `ControlGroup`, verifies the
kernel `memory.max` and exclusive membership, then signals allocation.
Both `StartTransientUnit` and `StopUnit` are asynchronous. The backend
calls the manager's `Subscribe()` method, installs the `JobRemoved` match, and
only then issues either call,
matches the returned job object path and exact unit, requires `result=done`,
and enforces a three-second completion timeout. A successful method reply is
never treated as completed lifecycle work.
The live profile is fixed at 64 MiB touched memory with a 128 MiB limit,
subject to a dynamic reserve of worker bytes plus rollback bytes plus the
larger of 1 GiB or ten percent of host RAM. It does not approach the limit or
request OOM.

Lifecycle CPU is separated into allocation, generation, prefault, READY,
stabilization and measurement. During measurement the worker only holds
memory, emits heartbeats and checks one bounded page per heartbeat; it performs
no full rewrite.

The watchdog independently checks heartbeat age, PID/start-ticks, exclusive
membership, memory.current, OOM counters, host emergency PSI, ownership and
timeout. Cleanup acts only on the child handle and owned group. The final
structural comparison separates configuration/topology from cumulative
counters.

ATTEMPT 5 validated the complete lifecycle on CachyOS. The bounded
non-identifying harness evidence was: 67,108,864 payload bytes; 134,217,728
`MemoryMax`; eight samples; 3.385759915 seconds wall time; 0.07 runner CPU
seconds; 0.000786 measurement worker CPU seconds; 0.312314019 seconds worker
setup; 2.608798296 seconds worker measurement; 26 heartbeats and 26 bounded
integrity checks; one generation pass; one prefault pass; zero full rewrites
during measurement; valid fingerprint; watchdog clear; zero OOM and OOM kills;
structural restore PASS; and zero KiB runtime swap-used delta. These values
validate harness behavior only and are not Phase 10 performance results.

ATTEMPT 2 safely reached the audited `StartTransientUnit` request but the
client timed out waiting for `JobRemoved`. Read-only boot-journal evidence
shows that systemd actually started and later deactivated the exact scope.
Forensics found that the client installed a signal match but had omitted the
systemd Manager `Subscribe()` call required to enable manager job signals for
that connection. The transient property request itself was accepted. The
corrected backend calls `Subscribe()` before the match and request, retains
method/job/post-start failure taxonomy, and persists bounded D-Bus diagnostics.

Structural restore compares parsed swap topology (entry, type, size and
priority) and zram configuration independently from runtime usage. Swap
`Used`, zram occupancy and cumulative counters are retained as runtime
evidence but cannot make configuration restore fail. ATTEMPT 2 changed the
visible `/dev/zram0` `Used` field by -32 KiB while its topology and all other
configuration remained unchanged; this is incidental runtime state, not
benchmark evidence.

ATTEMPT 4 proved the complete asynchronous start and common post-start
recovery paths: the start job completed with `done`, `GetUnit` and
`GetUnitByPID` resolved the same object, and `Unit.Id` matched. It then stopped
before payload allocation because `ControlGroup` was incorrectly requested
from `org.freedesktop.systemd1.Unit`. The exact scope and worker were removed
and structural restore passed. The corrected backend uses fixed typed
interfaces on the same object: identity/lifecycle properties from `Unit`, and
resource-control properties (including `MemoryMax` and `ControlGroup`) from
`Scope`. Required readback properties are capability-checked and allow-listed;
optional telemetry remains explicitly optional.

ATTEMPT 3 completed the subscribed start job but failed during post-start
readback before payload allocation. Forensics identified the exact issue:
systemd 261.2 no longer exposes the deprecated `CPUAccounting` D-Bus property
on scope units because CPU accounting is always available on unified cgroup
v2. The harness repeatedly attempted that removed property and discarded the
specific error until its two-second composite-read deadline. The corrected
readback verifies the effective kernel `cpu.stat` interface instead.

The ATTEMPT 3 report retained a transaction-owned unit and worker at its final
snapshot, so full host restore failed even though general kernel
configuration/topology was restored. The journal shows later scope
deactivation, and subsequent read-only checks prove both exact unit and
historical PID absent. This self-cleanup does not retroactively validate the
attempt. Post-start evidence is now persisted incrementally; `GetUnit` and
`GetUnitByPID` must reconcile to the same object, and every post-mutation
failure enters the common worker/scope cleanup path.

ATTEMPT 1 safely aborted under the superseded raw-child model after
owned-directory creation and before
`memory.max` verification. The terminal leaf exposed `memory` in
`cgroup.controllers` but not in `cgroup.subtree_control`, so it could not
delegate the memory interface to a child. Directory creation alone is not a
controller-capability proof.

ATTEMPT 5 corrected the fixed `Unit`/`Scope` interface routing and passed the
full privileged lifecycle: subscribed asynchronous start job `done`, exact
unit/PID identity, typed readback, kernel cross-checks, payload-after-limit,
metrics, watchdog, integrity, common cleanup, final owned-resource absence and
full host restore.

Succinctly: ATTEMPT 1 exposed missing terminal-leaf memory delegation and
aborted safely; ATTEMPT 2 introduced the transient-scope design but omitted
`Manager.Subscribe()`; ATTEMPT 3 fixed subscription, exposed deprecated
`CPUAccounting` readback and a recovery defect, and later self-cleaned;
ATTEMPT 4 corrected async recovery and validated common cleanup but queried
`ControlGroup` through the wrong interface; ATTEMPT 5 corrected typed routing
and passed. Attempts 1–4 are harness development history, not performance
failures.

Checkpoint 2 now uses the transient scope itself as the resource boundary, so
no subtree delegation is required. Dedicated `Delegate=` support remains
deferred until a future benchmark needs Nemor-managed nested cgroups.

Later capacity search will use explicit coarse load levels followed by bounded
refinement only between the highest tested sustainable level and lowest tested
failure. Every level retains logical/touched bytes, duration, outcome, reason
and health evidence. It cannot interpolate beyond tested levels or seek host
failure. Baseline and candidate must use identical generator and worker hashes,
loads, seeds, warmup/stabilization, cgroup ceiling, kernel, host fingerprint
and thermal procedure; a candidate never receives a larger cgroup envelope.
