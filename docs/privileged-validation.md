# Privileged validation on CachyOS

Date: 2026-07-27

## Environment and scope

The Phase 3 and Phase 5 mutation paths were validated natively on CachyOS
Linux (`x86_64`), kernel `7.1.4-1-cachyos`, against baseline commit
`fcb21a9f9423496f25397cf89b5868d55c961df8`. Hostname, user name, machine ID,
home paths, and unrelated process data are omitted.

This was a validation gate, not a new functional phase. Phase 6, zswap, NVMe,
writeback, persistent configuration, system services, existing cgroups, and
real user workloads were outside scope and untouched. The daemon remains
observe-only by default.

## Privilege and ownership model

The harness is the dedicated
`nemor-test-support` binary `nemor-privileged-validation`. It is compiled as
the ordinary user and only the resulting binary is executed with root
privileges. Its public modes are `--preflight`, `--cgroups`, `--zram`, and
`--all`; it is not exposed by `nemorctl`.

The validator uses the same shared build-time Git stamp as `nemor-benchmark`
and `nemord`. Its hidden read-only `--build-git-head` identity query returns
the full embedded commit, while preparation independently hashes the binary
and requires that exact commit to occur in its bytes. The shared build script
watches the worktree HEAD, active symbolic ref, packed refs, and the nearest
ref directory, so a normal branch advance invalidates Cargo's cached stamp.
Privileged execution never queries live Git state.

The privileged surface is closed:

- cgroups must match `nemor-validation-*.scope`;
- PIDs must be children created and registered by the same run, with matching
  start ticks and identity;
- zram devices must be returned by `zram-control/hot_add` in the same run and
  absent from the baseline;
- `/dev/zram0` is always external, protected, and ineligible for ownership;
- helpers are fixed absolute executables with separate validated arguments and
  timeouts; no shell, arbitrary command, path, PID, or device is accepted;
- global execution is bounded to 180 seconds;
- guards perform ownership-checked cleanup on errors, with a final independent
  host comparison;
- the structured report is written atomically to
  `/tmp/nemor-privileged-validation-report.json`.

## Host baseline

The baseline contained one zram device and one swap backend:

| Property | Value |
|---|---|
| Device | `/dev/zram0` |
| Provider/ownership | systemd generator / external protected |
| Active swap | yes |
| Priority | 100 |
| Disksize | 16,640,901,120 bytes |
| Algorithm | `zstd` |
| Memory limit | 0 |
| Test cgroups/processes | none |

The root cgroup v2 controller list included `memory`. No existing cgroup
topology was restructured.

## Phase 3 real cgroup validation

A bounded validation child was created with PID and start ticks recorded
before mutation. Its original placement was snapshotted. On an exclusively
temporary `nemor-validation-*.scope` group, the real Linux actuator:

1. created the group;
2. wrote and read back `memory.low = 4,194,304`;
3. wrote and read back `memory.high = 8,589,934,592`;
4. attached the registered child and verified it in `cgroup.procs`;
5. restored the child's original placement;
6. restored properties and removed the empty group;
7. accepted a second rollback as an idempotent no-op.

The harness also proved before mutation that an unregistered PID, identity
mismatch, start-tick mismatch, unknown candidate, critical candidate without
allow-list, and game candidate without allow-list are rejected. Only the
registered validation child was accepted.

For restart recovery, worker A created a separate child and cgroup, persisted
the actuator snapshot, and exited without normal cleanup. Worker B loaded the
snapshot through a fresh backend/store instance, restored placement and
properties, removed the group, and terminated only the registered child.
A second recovery found no pending work and was harmless.

Result:

```text
FASE 3 — VALIDATA SU CACHYOS
```

## Phase 5 real isolated benchmark

The harness hot-added an isolated 64 MiB device absent from the baseline,
selected supported `zstd` before initialization, wrote the bounded disksize,
and verified algorithm, disksize, and initstate. It used three deterministic
16 MiB datasets and three measured rounds per dataset. Reads matched every
written dataset.

Median real measurements:

| Dataset | Write throughput | Read throughput | Wall time | CPU time | Logical ratio | Effective ratio | Allocator efficiency |
|---|---:|---:|---:|---:|---:|---:|---:|
| Highly compressible | 2.91 GB/s | 6.96 GB/s | 5.76 ms | 7.96 ms | n/a | n/a | n/a |
| Medium | 1.31 GB/s | 6.34 GB/s | 12.77 ms | 15.89 ms | 102.4 | 80.31 | 0.784 |
| Deterministic incompressible | 428.94 MB/s | 7.27 GB/s | 39.11 ms | 40.78 ms | 1.0 | 1.0 | 1.0 |

For the highly compressible repeated-page dataset, zram reported zero
compressed and allocated bytes, so zero-safe ratios correctly remained null
instead of producing infinity. CPU time came from the kernel's process
scheduler runtime counter. Results are host-specific validation evidence, not
general performance claims.

## Phase 5 swap transaction and recovery

Two fresh 64 MiB devices, A and B, were created and registered as
Nemor-owned. Checkpoints from `/proc/swaps` proved this sequence:

1. protected `/dev/zram0` active;
2. A initialized, activated, and verified alongside `zram0`;
3. B initialized, activated, and verified alongside A and `zram0`;
4. A deactivated only after B was ready;
5. B and `zram0` remained active;
6. test swaps were deactivated, reset, and hot-removed.

Thus a valid swap backend was continuously available, `zram0` was never
deactivated, and replacement-first/no-swap-loss behavior was exercised on the
real kernel.

For restart recovery, worker A hot-added, configured, and activated another
registered test device, persisted ownership, and exited without cleanup.
Worker B recovered only that absent-at-baseline device, performed swapoff,
reset, and hot-remove. Repeating recovery was a no-op.

Result:

```text
FASE 5 — VALIDATA SU CACHYOS
```

## Cleanup and final host comparison

The final structured snapshot matched the baseline topology:

- `/dev/zram0` remained present, active at priority 100, with the same
  disksize, algorithm, initstate, memory limit, provider, and ownership;
- no test swap or extra zram device remained;
- no `nemor-validation-*` cgroup or child remained;
- no persistent file, unit, service, sysctl, or kernel feature was configured.

The used KiB value of the active system swap changed naturally during the run
and is deliberately not an identity criterion. `mm_stat` equality is likewise
not required.

An initial validation attempt exposed a bounded cleanup retry issue after the
raw benchmark. The report proved the extra device's ownership; the closed
report-driven recovery mode removed it, and an independent read-only check
confirmed baseline restoration before the successful full rerun. No external
resource was touched.

## Residual limitations

The validation proves the privileged primitives through a dedicated test
harness; it does not enable general daemon mutation. The default service has
no cgroup or zram mutation privileges. Live Steam/Proton/Wine/Gamescope
coverage remains separate. Phase 6 development and live-safe validation are
complete, while dedicated boot validation with real zswap+NVMe remains
pending.

## Phase 6 live-safe validation

On 2026-07-27 the release harness `--tiering` completed with exit code zero.
It inventoried supported-but-disabled zswap read-only, resolved Btrfs on a
non-rotational SATA SSD, created and activated a 64 MiB Nemor-owned temporary
swapfile while `/dev/zram0` remained active, recorded a host-wide 4096-byte
physical block write delta, recovered with a fresh backend, rolled back twice
idempotently and removed all resources. Baseline and final swap topology and
protected zram structure were identical.

This proves the live-safe swapfile lifecycle and accounting path, not the full
zswap+NVMe backend. Dedicated boot validation remains pending and requires
separate explicit approval.

## Phase 7 monitor-only validation

The `--damon` path completed successfully on CachyOS
`7.1.4-1-cachyos`. It owned only a synthetic child, temporary DAMON sysfs
objects, an isolated tracefs instance and run-scoped report/dataset files.
The final `vaddr` session captured nine complete aggregation windows with HOT
1.0, WARM about 0.2611 and COLD zero. Monitor CPU stayed below the 1% budget;
synthetic target slowdown was about 3%.

Readback proved three initial target regions and `nr_schemes=0`. Stop, cleanup,
crash recovery and a second idempotent recovery restored the structural host
baseline. No external session, `/dev/zram0`, zswap/tiering state, persistent
configuration or boot setting was changed.
## Phase 8 DAMOS gate

`--damos` is separate from monitor-only `--damon`. It runs an owned stat shadow,
proves no HOT/WARM range overlap, cleans it, then creates an independent bounded
pageout session. Gates cover quota/fence readback, target-attributable reclaim,
collateral slowdown, refault integrity, blacklist rejection, cleanup, recovery,
idempotence, and structural host equality.

The final ATTEMPT 4 completed successfully on CachyOS
`7.1.4-1-cachyos`. With an exact modern COLD allow filter, the kernel tried and
applied two age-three zero-access candidates totaling 8,388,608 bytes.
Exact-range pagemap snapshots showed HOT and WARM unchanged at 8 MiB present
and zero swapped, while COLD changed from 32 MiB present/zero swapped to 24 MiB
present/8 MiB swapped. After the scheme was stopped, controlled refault
restored COLD to 32 MiB present/zero swapped with valid content.

The refault blacklist blocked the next plan; cleanup, recovery, idempotence,
zero OOM and structural host equality passed. `kdamond` CPU was 0.25%,
validation-control CPU approximately 0.25876444%, and control slowdown 0%.
These results apply only to the bounded owned synthetic target. Normal
`nemord` and `nemorctl` cannot execute pageout.

## Phase 9 KSM gates (validated)

`--ksm` is a separate explicit scope. It requires an isolated baseline
(`run=0`, no external mergeable processes or ambiguous shared pages), fixed
scanner control, sufficient allocation/unmerge headroom and audited owned
children. Only the children mark their duplicate ranges mergeable. The harness
persists the audit before opt-in, verifies exact `smaps` `mg` scope, and for
ATTEMPT 1 writes only `run=0→1→0`. Baseline `pages_to_scan` and
`sleep_millisecs` are validated but never changed. It continuously detects
external mergeable processes and global setting changes, never uses `run=2`,
and leaves DAMON/DAMOS, swap, zram, zswap, THP globals,
NUMA KSM policy and boot state untouched. CI performs no live KSM mutation.

The non-root `--ksm-bootstrap-preflight` diagnostic exercises the same worker
allocation path without `MADV_MERGEABLE` or KSM sysfs writes. It verifies
runtime page alignment and exact range-based `smaps` coverage, including
`KernelPageSize`, `MMUPageSize`, `AnonHugePages`, `nh` and absence of `mg`.
This diagnostic is not a privileged KSM validation.

KSM CPU samples use the measured `CLK_TCK`. Short 500 ms samples and their
quantization resolution are diagnostic only. The 1% one-logical-CPU gate is
evaluated only after a sustained window reaches 0.25% or finer resolution.
Every post-`run=1` exit follows a common stop/evidence/content/cleanup path.

`--ksm-inefficient` is the separately validated manual scope for real
controller auto-disable. It uses deterministic unique page payloads, evaluates
signed baseline-relative counters and exact owned-process evidence, requires
two new full scans, and accepts success only when insufficient owned profit—not
CPU, residual global accounting or safety failure—causes the owned controller
stop and cooldown rejection. Non-zero historical KSM counters are recorded but
do not imply a live external consumer; current process `smaps` `KSM:` bytes and
mergeability flags provide that evidence. It is never included in `--all`.

## Phase 10 benchmark validation

Checkpoint 1 executes no privileged benchmark. Future performance pressure
workloads will bind to an owned cgroup v2 with a measured bounded
`memory.max`, host-headroom guard, watchdog, timeout, audit, rollback,
recovery and before/after structural snapshots. It must never intentionally
trigger host OOM. Real application scenarios remain manual/cooperative and
the zswap/NVMe variant remains pending Phase 6 boot validation.

The first Phase 10 privileged checkpoint is only
`nemor-benchmark validate-cgroup`. It validates a 64 MiB owned steady worker
inside one derived owned cgroup with a 128 MiB non-OOM ceiling, dynamic host
reserve, exact identity, durable pre-mutation audit, exclusive membership,
metrics, watchdog and complete removal. It is harness evidence, not a
performance or capacity benchmark. No other Phase 10 privileged scenario is
enabled at this checkpoint.

Checkpoint 2 uses a systemd transient scope through the fixed system D-Bus
destination `org.freedesktop.systemd1`. It uses `StartTransientUnit` with
collision-failing mode and later `StopUnit` only for the exact audited unit.
The client invokes Manager `Subscribe()`, installs the `JobRemoved` match, and
then issues the method. Each returned job is awaited through that signal;
only `result=done` permits the next lifecycle stage.
The actual cgroup path comes exclusively from systemd's `ControlGroup`
property. No `Delegate=`, subtree-controller write, systemd command-line tool,
or locally derived unit path is used.
The D-Bus object is read through two fixed interfaces: `Unit` for
`Id`/`LoadState`/`ActiveState`/`SubState`, and `Scope` for `MemoryMax`,
`ControlGroup`, accounting flags, and the runtime bound. The kernel
`memory.max` and exact PID/start-ticks membership remain independent mandatory
cross-checks before the worker receives `ALLOCATE`.

For the Checkpoint 3A-P transient observer service, the asynchronous
`Type=simple` start job has a second, distinct bounded gate. Systemd 261 may
report the start job complete after fork while the same MainPID is still its
root-owned executor and before credential setup and `execve`. Nemor records
that state as `EXEC_IDENTITY_SETTLING`, never as readiness. It holds the
authoritative MainPID/start-ticks, exact unit/object/cgroup ownership and
running state fixed while polling for no more than two seconds. Only a
simultaneous non-root DynamicUser identity and final staged-binary SHA-256
produces `EXEC_IDENTITY_SETTLED=PASS`; timeout, disappearance, replacement,
ownership change, service failure, expected binary under root, or any wrong
final binary fails closed and enters common cleanup.

Checkpoint 3A-P ATTEMPT 1 is retained as a real live failed-closed validation.
Service creation, staging and all hardening readbacks passed. Its first
identity sample was PID 75843/start ticks 1718566, effective UID/GID 0/0,
with SHA-256
`b5199b96a1bfc9e6d843e6b075521f1909492327893f592a9abfc045ae451fae`,
which exactly matches the host's `/usr/lib/systemd/systemd-executor`.
Readiness never started. Process/unit/cgroup/runtime cleanup and structural
restore all passed. The classification is
`FAILED_CLOSED_STARTUP_IDENTITY_TRANSITION`; the next live run was ATTEMPT 2,
after a clean release, fresh V5 preparation and preflight.

Checkpoint 3A-P ATTEMPT 2 positively validated identity settling before
failing closed at the declared effective-service contract. MainPID and
ExecMainPID were both 92007 with start ticks 1974847; the root systemd
executor transitioned to the staged `nemord` at effective UID/GID
64618/64618, with `DynamicUser=true` and the expected observer SHA-256
`9fe91a0680e273c5abbf229daf20fb1f12897747676714b699d0c8d82e84e1f9`.
Settling passed after three polls in 0.08667416 seconds and recorded the
intermediate root state. Readiness did not start because `IPAddressDeny`
read back the exact IPv4-any and IPv6-any rules in the reverse order from the
request; the old raw-vector comparison rejected that semantically equivalent
deny set. This is classified
`FAILED_CLOSED_DECLARED_CONTRACT_COLLECTION_ORDER`, not an identity or
DynamicUser failure. Cleanup and restore passed. The verifier now
canonicalizes only this address deny multiset, rejects missing/extra/
duplicate/wrong-prefix/wrong-address entries, retains raw evidence order,
and reports bounded field/category diagnostics. ATTEMPT 2 report SHA-256:
`25ab2144ce7acf74b8da1fa2eacb5378cb42db250509246d426bcf5ddd7ddc66`.

Checkpoint 3A-P ATTEMPT 3 completed successfully on real CachyOS. Run
`checkpoint3ap1785249727703055971` returned `validation_exit_code=0`; the
report is `harness_validation` and is ineligible for performance claims. The
same PID 100352, ExecMainPID 100352 and start ticks 2167042 settled from
systemd-executor UID/GID 0/0 to DynamicUser UID/GID 63871/63871 after three
polls in 0.088228478 seconds. The final staged observer SHA-256 was
`ce4d8270905211480b1a454abeeafed1277569aac2e3d45cbb6115c82859dafa`.
The declared service contract, real telemetry readiness, bounded
observer-alive/zero-mutation validation, cleanup and structural restore all
passed with `errors=[]`. The canonical and preserved report SHA-256 is
`aaa4a44e80b55e84a302a1109b68208b6a55270b106f2f6eb4a68930794d580a`.

This closes the privileged Checkpoint 3A-P observer pipeline. ATTEMPT 1 and
ATTEMPT 2 remain permanent negative history; no ATTEMPT 4 is planned. The
Checkpoint 3A execution bridge now reuses this DynamicUser systemd service;
the raw child observer path is not reachable for performance evidence.
Unprivileged preparation freezes an integrity-bound manifest and privileged
execution consumes only that manifest. Real Checkpoint 3A baseline-versus-
observe A/B performance validation is CLOSED / PASS. Six V3 runs completed;
the original invalid classification came from the full-environment versus
material-environment hash-domain validator defect. Immutable evidence was
preserved, and exact bounded offline revalidation returned
`REVALIDATED_PASS` for three baseline and three observe repetitions. The
observer-overhead comparison is comparable, with no significance claim from
only three repetitions. The bridge hardening also requires a read-only manifest host
preflight before authorization, exact transaction/output roles, and execution
via `sudo` by the preparing user identity. Phase 6 zswap+NVMe boot
validation remains pending on dedicated hardware.

Checkpoint 3A Experiment 1 execution attempt 1 was rejected before run 0 due
to privilege-sensitive environment fingerprinting. The performance path now
freezes and compares a versioned material environment contract without reading
repository `.git` state under privilege; the full observational snapshot is
retained separately.

Checkpoint 3A Experiment 1 Execution Attempt 2 completed six real runs. The
historical report recorded all six invalid because the released RunEvidence
validator compared material and full environment hash domains. The original
report, manifest, and SQLite evidence are immutable; only the new unprivileged
offline revalidator may derive a corrected result. That bounded revalidation
has now returned `REVALIDATED_PASS`, closing Checkpoint 3A without a V4.
Capacity, gaming, OOM avoidance and effectiveness remain `not_evaluated`.

Checkpoint 3B Experiment `checkpoint3b-1785272587990631899` reused this exact
boundary for a bounded `synthetic_incompressible` baseline/observe pilot with
SplitMix64 generator version 1. Three baseline and three observe runs completed
validly with exact paired workload/payload identities, zero watchdog/OOM/
OOM-kill events, worker integrity PASS and restore PASS. The observer-overhead
comparison is `comparable=true`. Worker CPU changed by +4.486%; mean/peak
memory were approximately unchanged. Observer means were 0.11 CPU-seconds,
8,959,317 bytes RSS and 6,538,923 bytes PSS per twenty-second window.

The runner diagnostic is retained separately: 0.03 seconds baseline versus
0.72 seconds observe, about +0.69 absolute CPU-seconds. Its +2300% relative
change uses a tiny denominator and is not a 2300% system CPU regression.
Three repetitions support no significance claim, and capacity remains
`not_evaluated`. Final read-only inspection found no benchmark unit, observer
service, transaction runtime directory or benchmark-owned process residue;
production Nemor state was not adopted. Checkpoint 3B is CLOSED / PASS.
Phase 10 remains in development, with controlled progressive memory pressure
as the next framework/design target.

Checkpoint 3C now provides the model, manifest-ready plan, versioned level/run
evidence, scoped health gates, conservative headroom calculation, emergency
taxonomy and deterministic simulated scheduler for controlled progressive
pressure. Baseline and observe runs must
share the exact systemd-owned `MemoryMax`, schedule and worker implementation;
no raw cgroup writer or arbitrary PID/unit target is introduced.

The framework forbids host-OOM search and intentional OOM requests. Host PSI
emergency, host OOM, ownership/identity loss, heartbeat/watchdog timeout,
memory/observer contract failure and restore failure stop level growth
immediately, preserve evidence and leave later levels unexecuted. Safety abort
is never a capacity boundary. Refinement is permitted only within an actually
tested healthy/unhealthy bracket and never publishes an untested value.

V1 is **STATIC PREPARATION VALIDATED / NOT EXECUTION-CAPABLE** and remains
immutable. Commit `0ca43a654585aeed45bf6426f73694b67a3e9508` created a valid
static manifest but did not include a separate scoped worker or
pressure-specific preflight/executor. No V1 experiment occurred; V1 is not a
failed experiment.

The pre-live review hardening is fail-closed: sustainable evidence requires
the complete gate set and valid sample/duration coverage; an unacknowledged
target is protocol-invalid rather than a capacity boundary; normal
unsustainable, invalid and safety-abort stops remain distinct; watchdogs cover
the full frozen path; PSI thresholds reject non-finite/negative values; and
capacity summaries must validate against actual level evidence.

The dedicated `prepare-pressure-experiment` bridge is unprivileged and has no
execution branch. It captures read-only host inputs, derives explicit reserves,
freezes aligned 10/20/30% pilot levels and a shared bounded `MemoryMax`, and
creates immutable run/observer transaction plans in fresh directories. It
rejects root, reuse and unsafe provenance. Future systemd remains the sole
cgroup writer. No preflight or cleanup action is part of preparation.

The live bridge adds `pressure-preflight` and
`execute-pressure-experiment`; neither accepts a fixed-load manifest, and the
fixed-load path rejects pressure manifests. Preflight is read-only, compares
material hash with material hash, treats preparation `MemAvailable` as
historical evidence, and checks current availability against shared
`MemoryMax` plus frozen reserves. User and root share all non-authorization
results.

The executor requires root and exact preparing `SUDO_UID:SUDO_GID`. It starts
a separate zero-allocation worker, attaches its exact PID/start ticks through
the audited systemd D-Bus scope, verifies membership and `MemoryMax`, then
permits the first typed mode-0600 AF_UNIX level request. Only observe runs
start their prepared DynamicUser transaction. Evidence is persisted before
run zero and after each level; emergency checks occur before another
allocation. Exact-owned cleanup never targets foreign processes or units.

Host OOM is detected separately from cgroup events using the host-wide
`/proc/vmstat` `oom_kill` delta; its attribution limitation is retained and
any increase is a safety abort. Linux PSI `avg10` thresholds use the kernel's
percentage units directly (`0.20` means 0.20%). Restore is a post-cleanup run
gate. Observer `RuntimeMaxUSec` is derived from all three level lifecycles plus
bounded startup/cleanup margins under a hard maximum.

At that point Checkpoint 3C was **LIVE PATH IMPLEMENTED / V2 PREPARATION
NEXT**, not PASS. V2 was then prepared once unprivileged and statically
reviewed; no preflight followed.

V2 is subsequently classified **STATIC REVIEWED / LIVE EXECUTOR HARDENING
REQUIRED**. It was never preflighted or executed and remains immutable. The
final hardening uses a new prepared schema/pressure-plan version so V1/V2 are
not silently reinterpreted.

Pressure readiness and the final execution freeze check now verify canonical
`current_exe` path equality, exact executable SHA-256, embedded Git commit,
release profile, schema and frozen source/provenance linkage. No live Git
query is used in the privileged path, and the worker is spawned from the
verified manifest runner.

AF_UNIX HELLO, boundary, transition acknowledgement, hold, heartbeat,
integrity and STOP exchanges use real bounded socket deadlines. The frozen
level lifecycle is transition/allocation (8 seconds), stabilization (2
seconds), hold (5 seconds) and IPC/heartbeat allowance (2 seconds), producing
a 17-second level bound and 51-second three-level run bound. Observer runtime
derivation includes transition time and is 58 seconds, below the fixed
60-second hard ceiling.

Continuation requires exact-owned cleanup, absence of the worker, scope,
observer and RuntimeDirectory, plus structural before/after equality.
Workload errors preserve cleanup results; cleanup failure or structural drift
is `RESTORE_FAILURE`/safety abort. Touched-byte mismatch persists invalid
zero-hold evidence and cleans up immediately. Mandatory health gates are
derived independently from their actual liveness, identity, integrity,
cgroup, `MemoryMax`, PSI, fault, swap, I/O, CPU, observer and timing evidence.

Checkpoint 3C V3 experiment `checkpoint3c-1785312245488429386` passed the
static freeze and both user/root preflights, then its single execution attempt
was consumed by an executor defect. Run 0 entered execution, but completed
level construction called the fixed-load-only workload identity domain with
`progressive_memory_pressure`; the report therefore contains no completed
`LevelEvidence`. That absence does not prove that no payload was allocated.
Runs 1–5 are `not_executed_after_stop`. Structural state matched, while
`worker_scope_absent=false`, and the CLI incorrectly returned status 0. The
immutable report SHA-256 is
`b06671794cd0179f6d9ebd5545b785e9df892f03ca49d99c97a4bbabe4a10c76`
and database SHA-256 is
`b8f8974327450451e2256911f39d97460a4e85256861126fdc6dfb0e9e29ecf7`.
Official classification is **SAFETY ABORT / EXECUTOR DEFECT / NOT PERFORMANCE
EVIDENCE**. V3 is never rerun or revalidated and supports no capacity,
incompressible-workload, Nemor-performance, OOM, PSI or integrity conclusion.

The corrected live contract uses a pressure-owned, versioned workload identity
frozen per run/level during preparation; fixed-load 3A/3B identity semantics
remain unchanged. Incremental partial evidence persists transition start,
level acknowledgement, identity, transition duration and bounded hold samples
before final `LevelEvidence` validation. Exact scope cleanup separately proves
stopped, zero-member and removed states, boundedly waits for transient-unit
garbage collection, and reports `TRANSIENT_SCOPE_REMOVAL_TIMEOUT` explicitly.
Execution and cleanup diagnostics are both retained, and only completed
framework validation returns CLI status 0.

Checkpoint 3C V4 experiment `checkpoint3c-1785315276506307352` passed final
freeze and root preflight, then its sole execution attempt ended **SAFETY
ABORT / TRANSITION WATCHDOG + CLEANUP CLASSIFICATION DEFECT / PARTIAL VALID
LEVEL EVIDENCE ONLY**. Run 0 baseline levels 704,643,072 and 1,426,063,360
bytes were valid Sustainable results. Their transitions were 3,988 ms and
7,016 ms; each hold produced five samples, all mandatory gates passed, and
OOM/OOM-kill/watchdog observations were zero. Level 2 targeted 2,130,706,432
bytes but recorded only `transition_starting`: no ACK, stabilization, hold or
completed evidence exists, so it is not an unsustainable or capacity point.

The transition defect was cumulative SHA-256 work after every append. The
worker now fills only the new SplitMix64 slice in bounded chunks and updates a
running SHA-256 with those chunks; cloning/finalizing yields exactly the same
full-payload-prefix digest without rescanning old bytes. The unchanged
8-second transition watchdog remains a bounded infrastructure safety deadline,
and timeout now persists target, delta, elapsed time, configured deadline and
expected workload identity explicitly.

Transition IPC evidence distinguishes a genuine socket deadline
(`TimedOut`/`WouldBlock`) from non-timeout peer, framing, serialization, and
read/write failures. Only the former is `transition_timeout` /
`WATCHDOG_TIMEOUT`; the latter is a terminal `transition_ipc_failure` and
incomplete execution error. Neither is an unsustainable or capacity boundary.

V4 cleanup already proved worker absence, zero members, observer/runtime
absence and structural equality, but the exact transient scope had naturally
disappeared and `StopUnit` returned `NoSuchUnit`; this was incorrectly
classified `StopFailed`. Cleanup now inspects exact ownership first, accepts
an already absent scope only with absent worker and zero/absent cgroup, and
reconciles a between-check `NoSuchUnit` race under the same strict evidence.
Ambiguous or foreign units are never stopped. V4 correctly returned status 1,
is never rerun, and provides no capacity or comparison. Immutable report and
database SHA-256 values are respectively
`c1cf090c517ad7ef4fa6badc3138c6f13f8a507f246f8ff73c1ab2a2676c2d54`
and
`dddf2a47a84f6a3c634d7d56c5837ed9078fad766a4e93d321356ba1d3d9f8f2`.

Historical Checkpoint 2 ATTEMPT 5 validated this complete harness lifecycle on
CachyOS; it is unrelated to the prepared-only Checkpoint 3C V5 lineage. It
passed all required gates with no OOM, no watchdog trigger, exact-owned
cleanup, scope collection, worker/unit/cgroup final absence, structural
restore and full host restore. The validation was a dirty development build
and is explicitly
`harness_validation`; it is ineligible for performance claims. Attempts 1–4
were safe harness-development iterations, not performance failures. At that
historical point real Phase 10 A/B validation remained pending.

Checkpoint 3C V6 experiment `checkpoint3c-1785334549398553284` subsequently
completed pressure-framework validation and is **CLOSED / PASS**. Updated user
and authenticated-root read-only preflights passed, then one execution
completed all six planned runs and all eighteen conservative levels with
restore PASS, zero watchdog, zero cgroup OOM and zero cgroup OOM-kill. The
manifest, report, SQLite database, six run files and complete tar are preserved
under
`~/.local/share/nemor/validation-history/phase10-checkpoint3c-exp1-v6` with a
verified `SHA256SUMS`.

V6 positively validates the incremental transition and exact cleanup/restore
paths for this framework pilot. It did not exercise an IPC failure branch, and
it is not capacity or effectiveness evidence:
`search_complete=false`, `capacity_gain_percent=not_evaluated`. V3/V4/V5
remain immutable history. The new `nemor_capacity` orchestration contract is
plan-only and cannot invoke these privileged paths or activate normal
`nemord`.

The capacity compatibility boundary is separate from production and from the
pressure executor. Its first frozen component set is exact-owned
`DamonTelemetry` plus `DamosReclaim`, using the existing bounded DAMOS
validator and its dependent DAMON session. Preparation is unprivileged,
preflight is read-only, execution requires the preparing `SUDO_UID:SUDO_GID`,
and the validator remains bounded to 180 seconds with reverse cleanup and
structural host comparison. The resulting version-1 evidence cannot authorize
another component set, ownership, contract version, source, binary,
configuration or material environment. It never evaluates capacity or
effectiveness and never enables production `nemord`.

Compatibility preflight schema version 5 uses typed DAMON observability:
observed, privilege-hidden, absent, or inspection-error. Opening
`nr_kdamonds` with write access remains an open-only readiness probe: it writes
no bytes and changes no sysfs value. When an ordinary user can observe the
admin and trace interfaces but cannot open that node or traverse the
tracepoint, the report defers runtime capability to the root read-only
preflight instead of declaring the kernel unsupported. Deferred capability
cannot authorize execution; root must repeat the complete current inspection
and either produce `verified` or explicitly authorize the bounded
`requires_owned_context_validation` bootstrap when `nr_kdamonds=0`.
Unexpected I/O inspection errors fail closed; the bootstrap is not production
activation and cannot authorize another component set.

The capacity external-target workflow is a separate benchmark-only validation
boundary. `prepare-capacity-external-target-validation` freezes contract and
protocol version 1, exact runner/target/validator binaries, the
`DamonTelemetry` plus `DamosReclaim` component set, and the existing bounded
DAMOS action envelope. `capacity-external-target-preflight` is read-only;
`validate-capacity-external-target` is a one-shot privileged entry.

The controller cannot accept a PID by itself. The runner creates an exact
direct-child HOT/WARM/COLD target in a private transaction directory. Its
single-link descriptor binds the transaction and session IDs, nonce, PID and
start ticks, executable path and SHA-256, embedded source commit, creator
identity, three non-overlapping ranges, content identities, and private
control-channel identity. The validator verifies and consumes that descriptor
before DAMON mutation. It then uses the same Stat-shadow-before-Pageout
lifecycle as the diagnostic DAMOS validator, including the four direct gates,
cleanup, recovery, and structural restore.

This workflow validates ownership handoff and lifecycle only. It does not
compose progressive pressure search, calculate capacity or effectiveness, or
authorize production `nemor_capacity`.
