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

Checkpoint 3A is implemented but not yet live validated. Capacity, maximum
sustainable load, `capacity_gain_percent`, gaming, OOM avoidance,
incompressible regression and overall Phase 10 acceptance remain
`not_evaluated`.

### Checkpoint 3A-P DynamicUser observer boundary

Checkpoint 3A remains blocked until one bounded `harness_validation` proves
the observer boundary. The worker continues to use the validated transient
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
It counts as ATTEMPT 1; the next live validation is ATTEMPT 2. No live
ATTEMPT 2 is part of this fix.

The later matched 3A timeline is fixed: after worker-scope verification,
observe performs separately-accounted service setup; both variants then
receive the same five-second hold—idle for baseline and observer-alive warmup
for observe—before worker allocation, generation and prefault. READY is
followed by at least two seconds stabilization, at least twenty seconds
measurement, cleanup and two seconds cooldown. Observer setup wall/CPU remains
outside sustained measurement CPU.

## `nemor_capacity` readiness gap

The policy engine and cgroup actuator expose deterministic planning and owned
apply/rollback/recovery primitives. Zram and tiering expose owned
transaction/rollback APIs, but Phase 6 zswap+NVMe boot validation is still
pending and the host-equivalent zram state is not an independent candidate.
DAMON monitor-only, controlled DAMOS and selective KSM have real host
validation only within their specific ownership boundaries; DAMOS/KSM live
paths remain controlled harness capabilities, not a production combined
profile.

What is missing is one versioned `nemor_capacity` orchestration contract that
selects an evidence-backed subset, proves compatible ownership and ordering,
defines a single audit/rollback/recovery transaction, resolves the resulting
effective state, and validates it live before becoming executable. Arbitrarily
enabling every optimizer would violate the existing boundaries. The minimum
next step is a plan-only candidate manifest and simulated failure matrix for
one conservative component set, followed by a separate bounded owned-host
orchestration validation. Checkpoint 3A does not implement that candidate.
