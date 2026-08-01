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

The Checkpoint 3C progressive-pressure scheduler and evidence contracts are
implemented as a model-only framework; live preparation/execution remains
pending. Checkpoint 2 validated the explicit privileged owned-cgroup
transaction without applying performance pressure. `MemoryMax` must remain
below measured host headroom, a watchdog and timeout are mandatory, and host
OOM is always a safety failure. Controlled cgroup OOM is a distinct outcome.
Structural snapshots compare swap, zswap, KSM and DAMON state; restore
mismatch invalidates the result.

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

## Checkpoint 3A baseline versus observe

Checkpoint 3A implements the first real `performance_benchmark` path, limited
to `synthetic_compressible` at one fixed non-pressure load and exactly
`cachyos_baseline,nemor_observe`. Its comparison purpose is
`observer_overhead`, never capacity. At least three valid repetitions per
variant are required. A seeded shuffle persists the complete six-run order,
variant, repetition and per-run seed; invalid attempts remain evidence and a
safety failure leaves the remaining planned order explicitly unexecuted.

The default pilot uses 128 MiB of touched payload beneath an identical 256 MiB
worker `MemoryMax` for both variants. Payload is hard-capped at 256 MiB.
Observer warmup is five seconds, stabilization is at least two seconds,
measurement is at least twenty seconds, sampling is one second, and cooldown
is explicit. Dynamic headroom retains the worker, runtime/rollback margin and
the larger of one GiB or ten percent of host RAM. OOM and pressure modes are
not available.

Baseline is the observed CachyOS host—including its existing zram, swap, KSM
configuration and kernel tuning—with no Nemor observer. Observe adds only one
exact-owned normal production `nemord` process. The runner writes an isolated
config whose sole intended difference is its experiment-local SQLite path,
validates observe/no-mutation settings, records PID/start ticks and independent
binary/config hashes, warms it up after worker scope verification, keeps it
outside the worker cgroup, measures CPU and RSS/PSS, and stops only that exact
identity. Any pre-existing `nemord` contaminates either variant and is never
adopted or stopped.

Eligibility requires a clean relevant source tree, release runner and observer
binaries, independently embedded matching Git commits, SHA-256 hashes, config
hash and source-state identity. Recognized root-level Checkpoint 2/KSM JSON
validation reports are non-source evidence only when their narrowly
allow-listed names and bounded JSON content both match. Unknown JSON, nested
artifacts, relevant untracked inputs and tracked changes remain dirty.

Each repetition uses the validated systemd transient-scope worker boundary,
records raw bounded samples and run-relative vmstat, CPU, I/O and PSI total
deltas, verifies exact-owned absence and structural restore, and refuses to
continue after a safety/restore failure. The experiment persists one
experiment, all six manifests (including unexecuted ones), samples, summaries
and the comparison. Percent changes use the baseline arithmetic mean as
denominator and positive means observe is higher; no significance is claimed
from three repetitions.

Checkpoint 3A-P is validated and the 3A execution bridge reuses its transient
observer-service lifecycle. Checkpoint 3A is CLOSED / PASS. Preparation is unprivileged and
freezes an integrity-bound manifest; privileged execution consumes only that
manifest. The bridge now freezes one prepared observer config and service plan
per observe repetition; each config points at that plan's isolated
RuntimeDirectory database. A read-only `experiment-preflight --manifest`
command verifies manifest ownership, hashes, environment, systemd/cgroup
capability, foreign-process absence and output freshness before authorization.
Final pre-live gates also require exact Checkpoint 3A plan/profile reconstruction,
safe output roles, conservative headroom parity with the live cgroup plan, and
an empty set of pre-existing benchmark transient units. Live execution must be
invoked through `sudo` by the same UID/GID that prepared the manifest.
Capacity, maximum sustainable load, `capacity_gain_percent`, gaming, OOM
avoidance and effectiveness remain `not_evaluated`.

The execution bridge is explicit: an unprivileged `prepare-experiment` command
freezes the release identities, environment, six-run seeded order, profile,
property contract and output destinations. Privileged execution uses only
`execute-experiment --manifest`; the legacy `experiment --execute` path is
retired. No Git or shell inspection is performed during privileged execution.

Checkpoint 3A Experiment 1 Preparation V1 is retained as negative preparation
history: it was rejected before host preflight because bounded transaction
suffix sanitization discarded the order-specific identity and collided all
three observe transactions. No host preflight, sudo, A/B execution, or
performance evidence occurred. Preparation V2 will use fresh paths after the
transaction-ID fix.

Preparation V2 passed preparation and the real-host read-only preflight. Its
first privileged execution attempt was rejected before run 0 because the
full observational environment hash differed by privilege-sensitive energy
provider visibility (`null` as the preparing user versus `powercap` as root).
No performance run occurred. The performance gate now uses an explicit,
versioned material environment projection while retaining the full snapshot
for evidence; energy counter accessibility is observational and does not
change A/B environment identity.

Preparation V3 passed both user and root read-only preflight and was executed
once as Checkpoint 3A Experiment 1 Execution Attempt 2. Six real runs
completed. The released runner originally marked all six invalid because
RunEvidence compared the material environment hash with the full observational
plan hash. The immutable report and SQLite evidence were preserved. After the
hash-domain validator fix, exact bounded offline revalidation of that evidence
returned `REVALIDATED_PASS`: three baseline and three observe repetitions are
valid and the observer-overhead comparison is comparable. Three repetitions
do not support a significance claim. No V4 is required.

### Checkpoint 3B incompressible baseline versus observe

Checkpoint 3B reuses the complete validated 3A architecture for
`synthetic_incompressible`: clean release provenance, prepared manifests,
user/root identity and material-environment contracts, per-run preflight,
transient worker scope, DynamicUser observer, unique transactions, fresh
outputs, raw samples, run-relative counters, watchdog, worker integrity,
structural restore, failure persistence and observer-overhead statistics.

The generator is `nemor.synthetic.splitmix64` version 1. It deterministically
derives every byte from the persisted run seed, touches/prefaults the full
declared payload before measurement, and records a workload identity derived
from scenario, generator identity/version, seed and payload. The worker
manifest separately binds scenario and generator identity/version. During the
measurement window the worker performs only bounded integrity reads and
heartbeats; it performs no full rewrite or artificial sustained CPU load.
Baseline and observe use the same repetition seed, workload identity, logical
payload, algorithm/version and cgroup envelope. Payload identity is not a
compression-effectiveness claim; zram/zswap observations are telemetry only.

The initial profile remains the conservative non-pressure pilot: 128 MiB
payload, 256 MiB `MemoryMax`, five-second observer warmup, at least two seconds
stabilization, at least twenty seconds measurement, one-second sampling,
two-second cooldown and three repetitions per variant. OOM requests and
pressure mode are rejected.

Only `cachyos_baseline,nemor_observe` and `observer_overhead` are in scope.
Comparison requires all three valid runs per variant with paired seeds and
workload identities, the same generator/manifest, payload, envelope and
material environment. No significance claim is made from three repetitions.
Experiment `checkpoint3b-1785272587990631899` completed all six planned runs:
three valid `cachyos_baseline` and three valid `nemor_observe` repetitions.
Each paired repetition has the exact same persisted workload identity and
actual payload SHA-256 fingerprint. All runs recorded twenty samples over
twenty seconds with zero watchdog triggers, OOMs and OOM kills, valid worker
integrity and structural restore. Baseline runs had no observer; observe runs
had the expected exact-owned observer. The observer-overhead comparison is
`comparable=true`.

Worker CPU means were 0.008017 seconds baseline and 0.008377 seconds observe,
a +4.486% change. Worker mean memory changed by -0.112% and peak memory by
-0.110%, approximately unchanged. The observer used 0.11 CPU-seconds per
twenty-second measurement window; its mean RSS was 8,959,317 bytes and mean
PSS was 6,538,923 bytes.

The benchmark runner CPU diagnostic is retained explicitly: baseline mean
0.03 seconds and observe mean 0.72 seconds, or about +0.69 absolute
CPU-seconds during a twenty-second window. The computed +2300% relative change
uses an extremely small baseline and must not be described as a 2300% system
CPU regression. It does not invalidate the six valid comparable runs.

Only three repetitions were collected, so no statistical significance is
claimed. `capacity_gain_percent`, capacity, gaming, OOM avoidance and
optimization effectiveness remain `not_evaluated`. Checkpoint 3B is CLOSED /
PASS. Phase 10 remains in development; controlled progressive memory pressure
is the next live validation target.

### Checkpoint 3C controlled progressive pressure

Checkpoint 3C adds an explicit version-1 `progressive_memory_pressure`
contract with comparison purpose `pressure_framework_validation`. It remains
limited to `cachyos_baseline,nemor_observe` and reuses the 3A/3B provenance,
material-environment, owned systemd scope, DynamicUser observer, watchdog,
restore, counter, persistence and immutable-failure architecture.

V1 is **STATIC PREPARATION VALIDATED / NOT EXECUTION-CAPABLE**. Commit
`0ca43a654585aeed45bf6426f73694b67a3e9508` produced a valid static pressure
manifest but had no pressure-specific preflight/executor and its worker was
still in-process. V1 remains immutable. No V1 preflight or live experiment
occurred, so this is not an experiment failure.

`ProgressivePressurePlan` freezes the SplitMix64 incompressible generator v1,
experiment seed, exact ordered byte levels, hold/stabilization/sample timing,
one identical `MemoryMax` for both variants, watchdog and total-duration
bounds, health/emergency policies, stop policy, refinement granularity/count,
maximum levels and explicit headroom reserve/effective maximum. Development
policy may express a small conservative sequence as fractions of a future
effective maximum, but preparation must derive, align and freeze exact byte
values from then-current headroom. No development-host free-memory value is
embedded as a live schedule.

Each level moves through planned, sustainable, unsustainable, safety-abort or
not-executed-after-abort states. Versioned `LevelEvidence` retains planned and
actual touched bytes plus the worker's exact delta acknowledgement and PID
identity. The evidence also retains generator/workload/integrity identities,
monotonic timing, samples, memory/CPU, separately scoped host and cgroup PSI,
relative fault/swap/I/O activity, watchdog/OOM observations, every health
gate, classification and failure reason. These versioned serializable records
are the JSON/SQLite persistence contract for a future live backend; no failed
level may be overwritten. Missing optional measurements remain unavailable,
not zero. Swap topology is configuration evidence and is distinct from runtime
swap or block-write deltas.

Sustainable means every mandatory health and integrity contract passed; worker
liveness alone is insufficient. Unsustainable health is a measured non-safety
boundary. Emergency classes include host PSI/OOM, ownership or identity loss,
heartbeat/watchdog timeout, broken memory/observer contracts and restore
failure. An emergency retains current evidence, marks later levels unexecuted,
enters only the existing exact-owned cleanup design and can never be an
unsustainable capacity endpoint. Host OOM is prohibited and `request_oom`
remains false.

Refinement is a deterministic aligned midpoint and is eligible only inside a
tested sustainable-lower/unsustainable-upper bracket. It cannot repeat a
tested point, exceed its persisted count or extrapolate. Reported maximum
sustainable capacity is the highest level actually tested successfully; no
interpolation is capacity. Capacity gain remains `not_evaluated` until both
variants have comparable completed non-aborted searches under identical
scenario, generator, schedule, timing, envelope, material environment and
worker implementation contracts.

The unprivileged simulator allocates no workload memory and performs no
privileged operation. It deterministically covers all-sustainable,
unsustainable, PSI/OOM/worker/observer/watchdog/restore abort, touched-byte
mismatch, refinement and comparison-mismatch paths. Checkpoint 3C remains
**OPEN**, not PASS.

The live worker is a separate process whose payload begins at zero bytes. The
runner binds its PID/start ticks to the audited transient systemd D-Bus scope,
verifies membership and frozen `MemoryMax`, and only then sends level zero
over a versioned mode-0600 AF_UNIX protocol. Fixed messages bind protocol,
experiment, run and worker identity; level requests also bind seed, prior
bytes, delta, target and generator. Foreign, duplicate and out-of-order
messages fail closed.

V3 experiment `checkpoint3c-1785312245488429386` is permanently classified
**SAFETY ABORT / EXECUTOR DEFECT / NOT PERFORMANCE EVIDENCE**. Its final
freeze and user/root preflights passed, but run 0 entered execution and the
executor used the fixed-load `workload_identity` domain for
`progressive_memory_pressure`. That fallible post-hold construction failed,
leaving zero completed `LevelEvidence`; this does not establish that no first
level payload was allocated or that the level passed scientifically. Runs 1–5
were not executed. Structural restore matched, scope absence was false, and
the command incorrectly exited zero. The immutable report SHA-256 is
`b06671794cd0179f6d9ebd5545b785e9df892f03ca49d99c97a4bbabe4a10c76`;
the database SHA-256 is
`b8f8974327450451e2256911f39d97460a4e85256861126fdc6dfb0e9e29ecf7`.
V3 is never rerun, reconstructed, or offline-revalidated into performance
evidence and makes no capacity claim.

The corrected schema freezes a separate versioned pressure workload identity
for every run/level before execution. It binds scenario/version,
SplitMix64/version, run seed, level index, planned logical/touched bytes,
pressure-plan version and worker implementation identity. Transition start,
worker acknowledgement, stabilization/hold state and bounded samples persist
incrementally, independently of final completed-level construction. Scope
cleanup now records stopped, zero-member and removed states separately and
uses a bounded transient-unit garbage-collection wait; timeout is explicitly
`TRANSIENT_SCOPE_REMOVAL_TIMEOUT`. Pressure execution exits zero only for
`completed_framework_validation`.

V4 experiment `checkpoint3c-1785315276506307352` is permanently classified
**SAFETY ABORT / TRANSITION WATCHDOG + CLEANUP CLASSIFICATION DEFECT / PARTIAL
VALID LEVEL EVIDENCE ONLY**. Final freeze and root pressure preflight passed.
Run 0 baseline levels 704,643,072 and 1,426,063,360 bytes completed as valid
Sustainable evidence: transitions were 3,988 ms and 7,016 ms, holds were
5,007 ms and 5,011 ms with five samples each, every mandatory health gate
passed, and OOM/OOM-kill/watchdog observations were zero. Those facts apply
only to those exact per-level baseline results.

Level 2 targeted 2,130,706,432 bytes and persisted `transition_starting`, but
received no ACK and entered no stabilization or hold. It is not an
unsustainable or capacity boundary. The worker had generated each appended
delta and then SHA-256 hashed the entire cumulative payload; the observed
growth is structurally consistent with that repeated full-prefix scan. The
corrected worker incrementally feeds bounded newly generated SplitMix64 chunks
to a running SHA-256 state and clones/finalizes it for the unchanged exact
full-prefix digest. Transition timeout remains an 8-second safety watchdog,
not a performance threshold, and now persists an explicit terminal progress
record with target, delta, elapsed time, deadline and frozen workload identity.

Cleanup observed absent worker, zero members, absent observer/runtime state and
matching structure, but `StopUnit` returned `NoSuchUnit` because the transient
scope had already been collected. The corrected exact-owned state machine
distinguishes `already_absent`, `stop_unit_requested`,
`stop_unit_no_such_unit_reconciled` and `stop_failed`. It never stops an
ambiguous unit and reconciles `NoSuchUnit` only when worker, exact unit and
cgroup membership are all absent. V4 correctly exited status 1 and is never
rerun. Its immutable report SHA-256 is
`c1cf090c517ad7ef4fa6badc3138c6f13f8a507f246f8ff73c1ab2a2676c2d54`
and database SHA-256 is
`dddf2a47a84f6a3c634d7d56c5837ed9078fad766a4e93d321356ba1d3d9f8f2`.
It provides no capacity, maximum, observe comparison or Checkpoint 3C PASS.

The transition IPC taxonomy remediation is integrated in commit
`96dc1b4fede9b772b929f1e3c94f1a6564480c44`. Genuine transition socket
deadlines map to `TransitionTimeout`, `SafetyAbort` and `WATCHDOG_TIMEOUT`;
non-timeout IPC failures map separately to `TransitionIpcFailure`, `Invalid`
and `ExecutionError`. Neither path is an unsustainable or capacity boundary.
The current contracts are pressure execution evidence schema 4, prepared
pressure manifest schema 6 and worker protocol 1. The remediation passed
independent static acceptance, the accepted local integration suite passed
589 tests with zero failures, and GitHub CI run `30454663806`, job
`90585052557`, concluded successfully for that exact commit. These results do
not constitute live or performance validation. V5 is frozen historical
lineage and is not reusable; no post-remediation pressure preflight,
execution, or new pressure lineage exists. Checkpoint 3C therefore remains
OPEN and Phase 11 has not started.

`pressure-preflight` accepts only `PreparedPressureManifest` and is read-only.
It reports manifest/provenance/scenario/run/worker/observer support,
material-environment match, cgroup and PSI availability, foreign-process and
stale-unit clearance, output freshness, headroom safety and authorization.
Preparation `MemAvailable` remains evidence; current availability may differ
when it still covers shared `MemoryMax` plus frozen reserves. Linux PSI
`avg10` values use the percentage units emitted by the kernel directly:
`0.20` and `0.10` mean 0.20% and 0.10%, without rescaling.

`execute-pressure-experiment` accepts only pressure manifests and requires
root plus exact preparing `SUDO_UID:SUDO_GID`; fixed-load commands reject
pressure manifests. It persists the six-run plan before run zero and updates
JSON, SQLite and `runs/` after every level/state transition. Host OOM uses the
host-wide `/proc/vmstat` `oom_kill` delta, separately from cgroup-local
`memory.events`; because attribution is limited, any increase fails safe.
Emergency checks precede the next level. Cleanup addresses only the owned
PID/start ticks, scope and observer transaction.

The earlier flow produced V2 from its exact CI-approved commit and completed
static review. No pressure preflight or execution followed.

V2 is now classified **STATIC REVIEWED / LIVE EXECUTOR HARDENING REQUIRED**.
It was never preflighted or executed and is preserved unchanged. Final
hardening versions the prepared manifest and pressure plan again rather than
reinterpreting V1/V2. Readiness now requires the canonical current executable
to equal the frozen runner path, its SHA-256 to equal the frozen runner and
provenance hashes, and its embedded commit/schema/release profile to match the
clean prepared identity. The worker is spawned from that verified frozen path.

The frozen per-level lifecycle separately budgets transition/allocation,
stabilization, measurement hold and IPC/heartbeat allowance. AF_UNIX HELLO,
boundary verification, level acknowledgement, hold, heartbeat/integrity and
STOP operations all have socket deadlines. For the conservative pilot the
bounds are 8 seconds transition, 2 seconds stabilization, 5 seconds hold and
2 seconds IPC margin: 17 seconds per level and 51 seconds for three levels.
Observer `RuntimeMaxUSec` includes every transition plus bounded startup,
cleanup and scheduler margins, yielding 58 seconds under the existing
60-second hard maximum. The 10/20/30 policy therefore remains unchanged.

Touched-byte mismatch produces protocol-invalid evidence with no
stabilization or hold. Each health gate records its own observation. A later
run is allowed only after backend cleanup, worker/scope/observer/runtime
absence and structural snapshot equality all pass. Execution errors retain
cleanup evidence; cleanup or structural failure becomes a restore safety
failure instead of being hidden by the workload error.

The external review is now incorporated. A sustainable level must contain the
complete variant-applicable gate set, with every gate mandatory and passing;
absence is never PASS. Completed evidence must cover the frozen hold at the
frozen sample interval within one explicit interval of scheduler tolerance,
and its recorded and monotonic durations must agree. Restore/ownership is
explicitly retained as a lifecycle-completion gate.

A worker that does not reach its exact requested touched total produces
`invalid_level_evidence`, not an unsustainable capacity boundary. It stops the
run, disables refinement and capacity, and leaves later levels
`not_executed_after_invalid`. Normal health boundaries and emergency aborts
instead leave distinct `not_executed_after_unsustainable` and
`not_executed_after_safety_abort` states. V1 requires
`stop_after_first_unsustainable=true`; safety abort always stops immediately.

Watchdogs cover stabilization, hold and heartbeat allowance for every possible
frozen level. The total watchdog cannot be shorter than that path. PSI
thresholds must be finite percentages in `[0,100]`; numeric activity limits
are explicit and zero means zero tolerance, never disabled. Capacity summaries
are integrity-bound to actual valid level evidence, and gain refuses
inconsistent or incomplete summaries.

The typed worker-step protocol begins with zero allocation. Only after the
future executor verifies the exact-owned scope and `MemoryMax` may the same
worker accept the next fixed command, touch only the planned delta using the
existing SplitMix64 v1 generator, acknowledge the complete experiment/run/
seed/PID/start-ticks/generator/integrity identity, stabilize, hold and perform
bounded integrity checks. Emergency gates are checked before any next-level
command.

`prepare-pressure-experiment` is the dedicated unprivileged preparation
command. It accepts only repository, config, observer binary, fresh
prepared/output roots and seed. V1 freezes three baseline and three observe
runs with paired seeds; aligned 10%, 20% and 30% levels derived from captured
available memory; explicit host, runner, observer, rollback and OS-variance
reserves; one shared target-plus-margin `MemoryMax`; three unique DynamicUser
observer transactions; and refinement `disabled_for_framework_pilot`. The
manifest is versioned and payload-hashed and binds release provenance, binary,
config, environment, worker, output and transaction identities. Preparation
rejects root and path reuse and performs no systemd/cgroup action, observer
startup, workload allocation or pressure. This pilot is not a capacity search:
`search_complete=false` and `capacity_gain_percent=not_evaluated`.

### Checkpoint 3A-P DynamicUser observer boundary

Checkpoint 3A-P now proves the observer boundary through one bounded
`harness_validation`. The worker continues to use the validated transient
`.scope`; the observer uses an exact benchmark-owned transient `.service`
created by PID 1 through the direct system D-Bus manager.

Production `nemord.service` uses `DynamicUser=true`, `StateDirectory=nemor`
mode `0700`, `/var/lib/nemor` as working directory, `UMask=0077`, empty
bounding and ambient capability sets, `NoNewPrivileges`, strict
filesystem/home/device/kernel/control-group protection, AF_UNIX-only
networking with IP denied, native syscall architecture, and foreground
`/usr/bin/nemord --config /etc/nemor/config.toml`. It defines no
`RuntimeDirectory` or `SystemCallFilter`.

The transient validation preserves the runtime identity, UMask, capability
removal, foreground behavior and hardening. Deliberate differences are an
ephemeral `RuntimeDirectory` instead of persistent `StateDirectory`, no
restart, bounded start/stop/runtime backstops, read-only bind mounts for
root-staged hash-identical executable/config inputs, and an isolated working
directory and SQLite database below `/run`. These differences prevent
production-state mutation and growing `/var/lib` validation state.

This difference is classified
`INTENTIONALLY_DIFFERENT_FOR_EPHEMERAL_STATE_ISOLATION`. Identity and
hardening remain required-equivalent. `RuntimeDirectoryPreserve=no` is sent
and read back explicitly, and validation still requires final directory
absence.

The fixed typed request calls `Manager.Subscribe()` before
`StartTransientUnit(mode=fail)`, requires the exact returned
`JobRemoved(result=done)`, and routes lifecycle properties through `Unit` and
process/resource properties through `Service`. Readiness requires a real
system telemetry sample persisted by the normal daemon loop. Stop uses the
same asynchronous contract. Final validity requires process, unit, cgroup and
runtime-directory absence plus structural restore.

`JobRemoved(result=done)` is only `START_JOB_COMPLETE`. With the deliberately
representative `Type=simple` contract, systemd completes that job after fork
and may do so before the executor has applied credentials and called `execve`.
It is not `EXEC_IDENTITY_SETTLED`. After obtaining the authoritative
`Service.MainPID`, validation therefore polls the same PID and start ticks at
20 ms intervals for at most two seconds. The exact unit, D-Bus object,
`GetUnitByPID`, cgroup membership, running service state and `DynamicUser`
contract must remain valid throughout. A root-owned `systemd-executor`
identity is diagnostic intermediate state only. Readiness starts only after
the same process is non-root and its final `/proc/PID/exe` path and SHA-256
match the root-staged observer. Settling time is observer setup time and is
outside the matched five-second hold and sustained measurement.

Preparation runs unprivileged and records clean Git/source identity, release
binary hashes, embedded commit and config hash in an integrity-bound manifest.
Privileged execution invokes no Git and re-hashes every input before mutation.
This validation remains `evidence_kind=harness_validation` and
`performance_claim_eligible=false`.

`nemor-benchmark provenance --require-clean-release` is the authoritative
future source barrier. It uses the same Rust classification as preparation:
tracked changes and relevant untracked inputs are dirty, while only
recognized, bounded, valid, root-level Checkpoint 2/KSM report JSON is
non-source evidence. Shell-level `git status --porcelain` emptiness is not an
equivalent policy.

The prepared directory must be absolute, non-symlink, owned by the preparing
UID and not group/world writable. Manifest and config must be bounded,
regular, single-link files with matching ownership and safe modes. The
observer source must be the exact sibling Cargo release binary, owned by the
preparing UID and not group/world writable. Cargo may legitimately hard-link
that source inode into `target/release/deps`; its link count is recorded but
is not treated as final execution authority.

Privileged execution opens the source with no-follow semantics, verifies
descriptor metadata, reads and hashes those exact bytes against the manifest,
and creates a root-owned mode `0755`, single-link executable with
`create_new` beneath `/run`. It applies the same descriptor-bound hash staging
to the explicit config. The service binds and executes only these
transaction-owned staged inputs, never the mutable user-owned Cargo inode.
Both staged files are synced, re-hashed, verified and removed only after the
service process is absent. This narrowly permits a multi-link build artifact
because content hash and root staging—not generic hard-link trust—form the
privileged execution boundary.

The first preparation against commit
`d0e9aa031a050770d8455464a3fbf407fdd9e164` stopped before manifest creation
because Cargo produced the normal two-link observer artifact. This was a
pre-live preparation blocker, not Checkpoint 3A-P ATTEMPT 1; no privileged
validation occurred.

A second pre-live build at
`6030547debe4ea3877b9f1804622e79c7425cb36` exposed an independent incremental
build-stamp defect: both build scripts watched only `.git/HEAD`. On symbolic
`main`, that file continues to name `refs/heads/main` while the branch ref
advances, so Cargo could reuse an older `NEMOR_BUILD_GIT_HEAD`. The shared
build-time resolver now asks Git for the actual worktree HEAD path, active
symbolic-ref path, packed-ref state and a bounded ref-parent directory that
covers packed-to-loose creation. Detached HEAD and linked-worktree metadata
therefore use their real Git paths. `git rev-parse --verify HEAD^{commit}`
remains the stamp source, while runtime provenance independently rejects any
embedded-commit mismatch or dirty relevant source.

Neither preparation blocker counts as live ATTEMPT 1. The historical V1
directory remains untouched and V2 was never created. V3 prepared
successfully but its single permitted read-only preflight exposed a property
contract defect before foreign-process checking or mutation:
`ProtectHome=true` in unit-file syntax had incorrectly been modeled as a
D-Bus boolean. On systemd 261 the transient request and effective
`org.freedesktop.systemd1.Service` readback are the canonical string
`"yes"` (`s`). The corrected fixed contract retains boolean `b` for the
legacy `PrivateTmp` and `ProtectControlGroups` properties, whose effective
production settings are simple true values.

Host introspection now verifies the complete fixed request/readback map and
reports missing property, wrong interface, wrong signature, value-contract
mismatch, and unsupported-required-property failures distinctly. The
preparation schema and observer property-contract version were advanced, so
the historical V3 manifest is deterministically rejected by corrected
binaries. V3 remains untouched; the next preparation lineage uses V4. This
was pre-live capability discovery, not live ATTEMPT 1.

Checkpoint 3A-P ATTEMPT 1 was the first real privileged live validation. The
transient service was created successfully and reached
`loaded/active/running`; staging and every intended property/hardening
readback passed. The first identity sample for `MainPID=75843`,
`start_ticks=1718566` observed effective UID/GID `0/0` and executable SHA-256
`b5199b96a1bfc9e6d843e6b075521f1909492327893f592a9abfc045ae451fae`.
That hash exactly identifies this systemd 261 host's
`/usr/lib/systemd/systemd-executor`. The harness correctly failed closed
before readiness. Cleanup and structural restore passed, including process,
unit, cgroup, runtime state, staged binary and staged config absence.

ATTEMPT 1 is classified
`FAILED_CLOSED_STARTUP_IDENTITY_TRANSITION`: `Type=simple` start-job
completion was sampled before final exec/credential identity settled. It is
not a DynamicUser failure and not a cleanup failure. The preserved canonical
report SHA-256 is
`069c2c05018ea3b090749ad53688e9892a50de24efedbffa5a4f48dd4ae7eff0`.
It counts as ATTEMPT 1; the next live validation was ATTEMPT 2. No additional
ATTEMPT 1 run is permitted.

Checkpoint 3A-P ATTEMPT 2 was the second real privileged live validation. The
identity-settling gate passed: the same `MainPID=92007`, `ExecMainPID=92007`
and `start_ticks=1974847` transitioned from the root-owned
`/usr/lib/systemd/systemd-executor` (`UID/GID=0/0`) to the staged `nemord`
with `DynamicUser=true`, effective `UID/GID=64618/64618`, and SHA-256
`9fe91a0680e273c5abbf229daf20fb1f12897747676714b699d0c8d82e84e1f9`.
Settling took three polls and 0.08667416 seconds, with the pre-exec root
state observed. This positively validates the settling implementation.

ATTEMPT 2 then failed closed after settling and before telemetry readiness:
the effective `Service.IPAddressDeny` readback contained exactly the required
IPv4-any and IPv6-any deny rules, but systemd returned them in IPv6/IPv4
order while the request and verifier used IPv4/IPv6 order. This is a
false-negative collection comparison, not an identity or DynamicUser failure.
Systemd documents these entries as address matching rules; their order has no
network-policy meaning. Nemor now compares only this deny collection as an
exact canonicalized multiset, preserving the raw observed order in evidence.
Missing, extra, duplicate, wrong-prefix, and wrong-address entries remain
fail-closed. Other collections retain their semantic ordering rules; in
particular `ExecStart` argv order is never normalized.

ATTEMPT 2 classification is
`FAILED_CLOSED_DECLARED_CONTRACT_COLLECTION_ORDER`; identity settling,
staging, cleanup, and structural restore all passed. The preserved report
SHA-256 is
`25ab2144ce7acf74b8da1fa2eacb5378cb42db250509246d426bcf5ddd7ddc66`.
The next live validation was ATTEMPT 3.

Checkpoint 3A-P ATTEMPT 3 was the third real privileged live validation and
passed on CachyOS. Run `checkpoint3ap1785249727703055971` returned exit code
0. The same `MainPID=100352`, `ExecMainPID=100352` and `start_ticks=2167042`
settled from the root-owned systemd executor (`UID/GID=0/0`, SHA-256
`b5199b96a1bfc9e6d843e6b075521f1909492327893f592a9abfc045ae451fae`) to
`DynamicUser=true`, effective `UID/GID=63871/63871`, and staged observer
SHA-256 `ce4d8270905211480b1a454abeeafed1277569aac2e3d45cbb6115c82859dafa`.
Settling passed after three polls in 0.088228478 seconds. The declared
service contract, real telemetry readiness, and bounded observer-alive/
zero-mutation window passed. Cleanup and structural restore passed with no
errors. The canonical and preserved report SHA-256 is
`aaa4a44e80b55e84a302a1109b68208b6a55270b106f2f6eb4a68930794d580a`.
The report is `harness_validation` and
`performance_claim_eligible=false`; this closes 3A-P but does not produce
performance evidence.

The later matched 3A timeline is fixed: after worker-scope verification,
observe performs separately-accounted service setup; both variants then
receive the same five-second hold—idle for baseline and observer-alive warmup
for observe—before worker allocation, generation and prefault. READY is
followed by at least two seconds stabilization, at least twenty seconds
measurement, cleanup and two seconds cooldown. Observer setup wall/CPU remains
outside sustained measurement CPU.

## Checkpoint 3C closure

Checkpoint 3C is **CLOSED / PASS** on V6 experiment
`checkpoint3c-1785334549398553284`. The immutable execution returned
`completed_framework_validation`: all six planned baseline/observe runs
completed, all eighteen conservative levels were Sustainable, every run
restored, and no watchdog, cgroup OOM or OOM-kill occurred. The durable local
archive is
`~/.local/share/nemor/validation-history/phase10-checkpoint3c-exp1-v6`;
its `SHA256SUMS` verifies the frozen manifest, report, database, six run files
and complete evidence tar.

This is framework live-validation evidence, not a capacity result:
`search_complete=false` and `capacity_gain_percent=not_evaluated`. The
incremental transition and cleanup/restore positive paths are live validated;
every level-2 transition acknowledged within the frozen eight-second bound.
No IPC failure occurred, so timeout versus non-timeout failure taxonomy
remains implemented, locally tested, static-accepted and exact-commit
CI-tested, but not live-exercised. V3, V4 and V5 retain their immutable
historical classifications.

## `nemor_capacity` orchestration contract

The policy engine and cgroup actuator expose deterministic planning and owned
apply/rollback/recovery primitives. Zram and tiering expose owned
transaction/rollback APIs, but Phase 6 zswap+NVMe boot validation is still
pending and the host-equivalent zram state is not an independent candidate.
DAMON monitor-only, controlled DAMOS and selective KSM have real host
validation only within their specific ownership boundaries; DAMOS/KSM live
paths remain controlled harness capabilities, not a production combined
profile.

Contract version 2 is implemented in the benchmark crate as a pure,
serializable planner/validator. It models cgroup protection, zram compression,
zswap/tiering, DAMON telemetry, DAMOS reclaim and KSM eligibility without
calling Linux or authorizing execution. Components are explicitly Eligible,
Unavailable, Disallowed or Deferred; a required component fails closed when
capability, evidence, dependency or exact ownership is missing.

Apply order is canonical and rollback is its exact reverse. DAMOS depends on
DAMON, DAMOS and KSM cannot share the same exact-owned target, and more than
one mutating component requires independent combined-profile compatibility
evidence—isolated harness results alone are insufficient. That evidence is a
versioned integrity-bound artifact tied to the exact component set, component
contract versions, ownership identities, capabilities, prerequisite evidence,
apply/rollback order, source state, binary, configuration and material
environment. A caller-provided enum flag cannot authorize a combination. The
contract
requires production mode `observe`, requires
`allow_automatic_actions=false`, prohibits host OOM, invalidates results on
restore failure and always emits `activation_authorized=false` with capacity
and effectiveness `not_evaluated`.

This foundation does not make `NemorCapacity` executable in variant
resolution and does not alter normal `nemord`. The bounded compatibility
executor is validation-only and cannot activate production or establish a
capacity/effectiveness claim.

The first compatibility harness freezes only `DamonTelemetry` plus
`DamosReclaim`, because the existing bounded DAMOS validation already owns and
restores the dependent DAMON session. `StorageTiering` is unavailable while
`ZswapNvmeBoot` evidence remains pending; cgroup, zram and KSM are deferred
until their combined lifecycle/target ownership is separately proven. The
workflow is `prepare-capacity-compatibility`,
`capacity-compatibility-preflight`, then one privileged
`validate-capacity-compatibility`. It produces compatibility evidence only:
production activation remains false and capacity/effectiveness remain
`not_evaluated`.

Preflight schema version 5 separates static contract support from typed
privilege-sensitive observations. DAMON probes distinguish observed,
privilege-hidden, absent, and inspection-error states; permission denial is
never collapsed into unsupported. An unprivileged report may pass all
user-observable gates while returning
`deferred_to_privileged_preflight`; when no kdamond context exists, the root
report uses `requires_owned_context_validation` and the bounded exact-owned
validator performs the context-dependent bootstrap. Neither state means
verified before validation, and both keep
`execution_ready=false`. A root preflight with the exact preparing
`SUDO_UID:SUDO_GID` repeats the inspection and may set runtime capability to
`verified` only when current DAMON/DAMOS support, access, conflicts, identities,
environment, ownership, freshness, and authorization all pass. Unexpected
inspection errors fail closed. The command can exit successfully after
emitting a negative report; readiness is defined only by its typed fields.

### Exact DAMON + DAMOS compatibility validation

Lineage 6 completed the single combined live validation for the exact
`DamonTelemetry` + `DamosReclaim` component set. Source
`d67fedb648ce8542aa72fdec4ff6327fdeae049b`, preflight schema 5, and validation
ID `capacity-compatibility-1785407816237007228` were used. The user preflight
passed with `deferred_to_privileged_preflight`; the root preflight passed with
`requires_owned_context_validation` and
`bounded_validation_entry_ready=true`.

The raw DAMOS report independently passed
`vaddr_pageout_supported`, `shadow_session_passed`, `shadow_cleanup`, and
`cold_address_fence`. The live result, cleanup, recovery, idempotent recovery,
and structural restore all passed with final `nr_kdamonds=0`. Evidence is
archived at
`~/.local/share/nemor/validation-history/phase10-capacity-compatibility-6-completed`;
its `SHA256SUMS` file hashes to
`40d474027e8ee9fd5360cbc386926feeac6ecca28672ac68e9a07437f2b96005`.

Storage tiering remains unavailable pending `ZswapNvmeBoot`; cgroup
protection, zram, and KSM remain deferred from this component set. Capacity and
effectiveness remain `not_evaluated`, and production activation remains
false. This result does not mean that `nemor_capacity` is fully validated.

## Capacity composition framework validation

Source `61d6a4e56efc52730114d34ea19e5cb25ad392d1` corrected the composition
scope-cleanup contract without changing pressure manifest schema 6, pressure
execution schema 4, external-target contract/protocol version 1, or production
behavior. Composition execution and run evidence are version 2. Cleanup now
preserves the frozen unit, object, cgroup and worker identities; it accepts a
naturally collected scope only after proving the exact worker absent, the unit
absent, and the original cgroup absent or empty. A typed systemd
`NoSuchUnit` race is reconciled only after the same final checks, with no
second `StopUnit`; unreadable, ambiguous, foreign, membered, timed-out, or
other-error states remain fail-closed.

Fresh prerequisite external-target Lineage 3
`capacity-external-target-1785423683895606795` passed one live invocation:
all four direct shadow gates and all 48 required DAMOS checks passed, HOT/WARM
service and COLD-only reclaim/refault passed, and cleanup, recovery,
idempotent recovery, structural restore, final zero-kdamond state, and
no-residue checks passed. Its immutable archive is
`~/.local/share/nemor/validation-history/phase10-capacity-external-target-3-completed`;
manifest SHA-256 is
`a186f4f32b12a67e6a65c168fa2a45b0abd9c1457da3d5f0fba6729ae84c551b`,
evidence payload SHA-256 is
`e2b4d1ff346f86a973946c0eae3fc43f79d7ecd07ed017616f09d17a975c0cbb`,
and `SHA256SUMS` SHA-256 is
`d1015607787c62fc4696d6d8317d47fb5d6057c49094ba9bdf65338777f4c889`.

Composition Lineage 2
`capacity-composition-1785423981758528689` then completed its single live
invocation. All six planned runs and all eighteen conservative levels were
Sustainable: three baseline runs proved no validator, DAMON, DAMOS, or trace
mutation; three `nemor_capacity` framework runs passed the direct shadow
gates, required DAMOS gates, COLD-only 8 MiB action, HOT/WARM preservation,
controlled refault, cleanup, recovery, and restore. All six pressure scopes
were naturally collected and persisted as `AlreadyAbsent`, with exact worker
absence, unit removal, zero final cgroup members, and `Clean` classification.
There were zero typed `NoSuchUnit` reconciliations in this live run, zero host
OOM, zero cgroup OOM-kill, no watchdog, final `nr_kdamonds=0`, and no owned
residue.

The immutable composition archive is
`~/.local/share/nemor/validation-history/phase10-capacity-composition-2-completed`.
Its manifest SHA-256 is
`10e87b04647071c2ce7793ee99f9a24fe4b84018ae816bbd93377f510918cd90`,
manifest payload SHA-256 is
`60eef52bf7736dc2db65cf0dbfd65f0c10928ab1f46c1c670e8761c86e3ac9b0`,
execution payload SHA-256 is
`0423ecfada33ff195e7efc1879aa7395faee26e13f7ff3770f0725daf3e8e84c`,
and `SHA256SUMS` SHA-256 is
`c4d79f475bf1d05fe7aea906f07bc53b20324e61995e6055395629293a03a893`.

This is composition framework validation only: it provides no capacity
estimate, maximum, gain, gaming-effectiveness result, or production
authorization. Capacity and effectiveness remain `NotEvaluated`,
`search_complete=false`, and production activation remains false. It does not
validate cgroup protection, zram, storage tiering, or KSM composition.

## First valid capacity benchmark: Lineage 3

Capacity Benchmark Lineage 3
`capacity-benchmark-1785524018540371036` executed once on exact source
`648dd849e102598efb45a8da585b5db8a5f801a1`, after source-bound
External-target Lineage 7 and Composition Lineage 6 completed and their full
archive ledgers verified. Benchmark contract, search policy, prerequisite
STATUS contract and path contract are version 1; manifest/preflight are schema
4, execution/run/level evidence schema 3, and evaluation schema 2.

The lineage was prepared once. Its first user preflight stopped without
mutation on volatile headroom. After natural headroom recovered, the
authorized second user preflight passed every non-authorization gate. The
first root preflight passed, but its later execution wrapper timed out waiting
for interactive sudo before Nemor started. A final natural-headroom check then
passed; the second authenticated wrapper used `sudo -v`, and root preflight
attempt 2 passed every semantic gate with `preflight_mutated=false`. Exactly
one real benchmark invocation followed. The earlier wrapper is not an
invocation and did not consume the lineage.

The fixed ascending ladder was 687,865,856; 1,392,508,928; 2,097,152,000;
2,785,017,856; 3,489,660,928; 4,194,304,000; 4,882,169,856; 5,586,812,928;
6,291,456,000; and 6,996,099,072 bytes. All three baseline runs and all three
matched `nemor_capacity` runs completed all ten levels as Sustainable. Every
run therefore has a demonstrated lower bound of 6,996,099,072 bytes, no
observed upper bound, and `safe_ceiling_reached` right-censoring.

All three matched pairs are valid. Each has baseline and capacity lower bounds
of 6,996,099,072 bytes, unknown upper bounds, and a demonstrated delta of zero
bytes. Median demonstrated baseline and capacity are both 6,996,099,072
bytes; median paired demonstrated delta is zero. Because both sides are
right-censored at the same safe ceiling, neither a finite conservative gain
lower bound nor a finite possible gain upper bound is supported. No exact
maximum or zero-gain conclusion is inferred. The authoritative 30% target is
therefore `Indeterminate`. The experiment has only three matched pairs and
supports no broad statistical-significance claim.

All 60/60 levels had exact touched-byte acknowledgement, pressure heartbeat
and integrity, verified cgroup membership and MemoryMax, zero OOM, zero
OOM-kill, no watchdog, target cleanup, scope cleanup and structural restore.
The 30 baseline levels invoked no validator and performed no DAMON/DAMOS
mutation. The 30 capacity levels produced 30 unique transaction-scoped raw
reports and canonical identities; every report lifecycle passed, all four
direct shadow gates and all required DAMOS gates passed, HOT/WARM service was
preserved, only COLD was reclaimed, and controlled refault passed. SQLite
integrity is `ok` with one experiment and sixty levels. Final
`nr_kdamonds=0`; no process, report/state, socket, transaction, unit, cgroup,
DAMON, DAMOS or trace residue remained.

The immutable result archive is
`~/.local/share/nemor/validation-history/phase10-capacity-benchmark-3-censored`.
The experiment report SHA-256 is
`8597aa0bb8f1ebefc2c34e56ac10c7c88f3a3dfbc7e4bb1bd5dd70afffae03f3`;
evaluation SHA-256 is
`8599af57a354442d8fc5f6a820e745c970dc87a056b646fa3d4722a8726a69ee`;
SQLite SHA-256 is
`af059f290e25a2643e4abce07768e9cb3cbe326a5ce4c8bb65f8da49797e852a`;
STATUS SHA-256 is
`4b679e0b1d9322b0f7712229d831ae5bf95cadc8ae5a5e4d8688028d6f7d4d61`;
`SHA256SUMS` SHA-256 is
`82f5eb427930051c640859fc1953e7eff6dd86c59de2592e7fc66e43fa52809c`;
and the complete evidence tar SHA-256 is
`c76b28b073706f79a990349277cac637cf8793e0264ef949c27b265427117f61`.
Every ledger entry verifies.

This result evaluates capacity only within the frozen component set, host,
source, environment, ladder and ceiling. It does not evaluate gaming
effectiveness, excluded mechanisms, or production behavior; effectiveness
remains `NotEvaluated`, production activation remains false, and it is not a
Phase 11 result.
