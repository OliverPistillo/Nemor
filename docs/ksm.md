# Selective KSM

Phase 9 adds a validated plan-first KSM boundary in `nemor-ksm`. Normal `nemord` and
`nemorctl` only inspect capability, scanner state, system/process metrics and
plans; they never write KSM sysfs or apply memory advice to external processes.

## Kernel and trust boundary

KSM scans anonymous private pages that a process has registered as mergeable.
`MADV_MERGEABLE` is therefore cooperation, not remote process control.
`process_madvise` cannot be used to opt arbitrary remote processes into KSM.
Nemor does not ptrace, inject into, preload, or modify browser, Electron, VM, or
other foreign processes. Those workloads are observation/planning candidates
unless already mergeable or explicitly owned and cooperative.

KSM is global and can deduplicate across participating processes. Phase 9
rejects unknown identities, stale PIDs, foreign users/security domains,
credential-sensitive or critical processes, foreground-sensitive workloads and
gaming sessions. Classification alone never grants mutation permission.

`run=2` is forbidden in the model, simulated backend, validation transaction,
rollback and recovery. It globally unmerges pages that may belong to external
consumers. Rollback instead stops a Nemor-owned scanner with `run=0`, requests
`MADV_UNMERGEABLE` only from owned children when sufficient headroom exists (or
terminates those children), and restores the owned scanner settings.

## Capability and metrics

Discovery feature-detects `/sys/kernel/mm/ksm` fields rather than inferring them
from a kernel version. It models `run`, fixed scanner controls, `smart_scan`,
scan-time advisor controls, system counters and profit, plus `/proc/vmstat`
`cow_ksm` and `ksm_swpin_copy`. Optional fields remain unavailable instead of
causing a panic.

When readable, `/proc/<pid>/ksm_stat` supplies mergeability, rmap items, zero
pages, merging pages and process profit. PID plus start ticks form the stable
identity guard. No memory content or PFN is collected or persisted.

Kernel `general_profit` and `ksm_process_profit` are preferred. Diagnostic
derived values include saved bytes, pages scanned per saved page, ksmd CPU
seconds and CPU seconds per GiB saved. The latter is `null` when savings are too
small to evaluate; it is never reported as infinity or a fabricated zero.

## Profiles and planning

VM, browser and Electron profiles are conservative policy templates, not
profitability claims. They define minimum stable observation/mergeable memory,
scanner CPU budget, positive-profit threshold, maximum COW rate, inefficiency
window and cooldown. All retain foreground and gaming protection.

The deterministic planner returns eligible, rejected or unsupported with
versioned reasons such as `cooperation_required`, `external_ksm_activity`,
`profit_unknown`, `cpu_budget_exceeded` and `cooldown_active`. NORMAL may plan a
known candidate; WATCH only continues known-profitable work. PRESSURE does not
start unknown work, and CRITICAL, EMERGENCY, STABILIZING and gaming modes start
none. Phase 9 production configuration rejects `live_apply=true`.

The scanner planner distinguishes fixed mode from `advisor_mode=scan-time`.
The validated runs used baseline `pages_to_scan=100` and
`sleep_millisecs=20`; they did
not change NUMA merging, zero-page use, maximum page sharing or stable-node
pruning.

## Controller

The controller progresses through UNKNOWN, EVALUATING, PROFITABLE, INEFFICIENT
and COOLDOWN. It waits for bounded minimum evidence before judging a workload.
No savings, non-positive attributable profit, excessive unshared/volatile
pages, scanner CPU above budget or excessive COW rate can make an owned plan
inefficient and stop further owned scanning. External scanners are only
reported.

## Manual validation design

`nemor-privileged-validation --ksm` and the separate `--ksm-inefficient` are
the only Phase 9 live paths. Before any global write they require a writable
capability, baseline `run=0`, no external live mergeable/merge-any/KSM-mapped
process, fixed
advisor mode, memory headroom, fresh owned child identities, a persisted
baseline and a recorded manual decision/plan.

Two cooperative children allocate separate anonymous base-page mappings and
first report `READY_UNMERGEABLE`:

- an identical 32 MiB non-zero, page-index-dependent DUPLICATE zone;
- an 8 MiB child-specific CONTROL zone that remains non-mergeable.

The parent verifies PID/start ticks, exact mappings, `nh` backing, fingerprints,
headroom and the isolated KSM baseline, then persists decision, plan and
transaction. Only after that audit does each child receive
`OPT_IN_DUPLICATE` and apply `MADV_MERGEABLE` to the exact DUPLICATE range.
`smaps` must prove complete `mg` coverage there, zero `mg` overlap with CONTROL
and no other mergeable worker VMA.

Bootstrap validation is range-based rather than dependent on VMA boundaries.
For every VMA overlapping an owned range it records the overlap, kernel/MMU
page size, `AnonHugePages`, `THPeligible` and `VmFlags`. The overlap union must
cover the range without gaps, use the runtime host page size, have zero huge
pages, contain `nh`, and contain no `mg` before the audit. Linux may merge the
two compatible mappings before opt-in and split them again after opt-in.

ATTEMPT 1 aborted safely before its audit because the original gate tested an
`explicit_nohugepage_verified` report field that the generic parser left at its
default false value. The worker's real advice result was not preserved. The
corrected protocol records the `MADV_NOHUGEPAGE` result and errno, alignment,
prefault and fingerprints before `READY_UNMERGEABLE`; early failures retain
this bootstrap evidence and are classified as workload setup failures.

ATTEMPT 1 never tunes the scanner. It validates and preserves the baseline
`pages_to_scan` and `sleep_millisecs`, requires selected advisor mode `none`,
and changes only `run` from 0 to 1 and back. During the run it polls external
process state and global configuration every 500 ms; interference immediately
stops the owned scanner and fails validation.

Success requires at least one full scan, at least 8 MiB saved, positive system
profit, merging/positive-profit evidence for both children when supported,
ksmd mean and bounded-window CPU at most 1% of one logical CPU, intact
DUPLICATE/CONTROL contents, cleanup and exact configuration restoration.
Monotonic KSM counters are evidence and are not expected to reset.

CPU accounting uses the host `CLK_TCK`. Every sample records tick delta,
seconds, CPU percentage and quantization resolution. The 500 ms polling loop
remains useful for ownership and diagnostic peaks, but it cannot fail the 1%
budget unless its resolution is at most 0.25%. The mandatory sustained gate
therefore waits for a dynamically derived resolution-valid window
(`400 / CLK_TCK` seconds) and preserves all short-window measurements.

Owned identity is the typed PID/start-ticks pair plus the validation session in
the stable key. Equal start ticks for two processes are valid and never cause
map or evidence collisions. External-process exclusion requires an exact
PID/start-ticks match; missing or stale identity fails closed.

ATTEMPT 2 reached audited opt-in, exact `mg` scope and `run=1`, then stopped
safely after a single CPU tick in a 500 ms window was incorrectly treated as a
hard 1% violation. That attempt proves selective activation, not inefficiency.
The common post-run path now always stops and reads back `run=0`, captures
system/process/CPU evidence, checks fingerprints, and either verifies owned
`MADV_UNMERGEABLE` or proves owned mappings absent after child termination.

ATTEMPT 3 validated the positive path on CachyOS 7.1.4-1-cachyos. Two full
scans examined 26,384 pages; the kernel reported 39,931,904 saved bytes and a
39,651,328-byte positive system-profit delta. Sustained `ksmd` CPU was about
0.538% of one logical CPU over 5.577 seconds, or about 0.807 CPU seconds/GiB
saved. These are bounded synthetic host measurements, not real-application
claims. The diagnostic 500 ms peak of about 1.975% remained below the
measurement resolution needed for a hard judgement.
The two owned process snapshots reported respectively 8,192/8,192
`ksm_rmap_items`/`ksm_merging_pages` with 33,030,144-byte profit, and
8,192/1,808 with 6,881,280-byte profit. Exact scope, content, unmerge,
configuration restoration and host equality all passed.

The positive generator intentionally changes only the first byte of each page
with a 251-page period. Page payloads therefore repeat within the registered
ranges, so 32 MiB is not a theoretical maximum saving. Kernel counters are the
authoritative measurement.

The explicit `--ksm-inefficient` scenario uses per-session, per-child, per-page mixed
non-zero payloads have no expected repeated page hash. After at least two full
scans and a resolution-valid CPU window, insufficient session-relative gain
drives `UNKNOWN -> EVALUATING -> INEFFICIENT`, causes the owned controller
to stop `run`, enter cooldown, and reject the same plan without a second
activation. This validated scenario is manual-only and excluded from `--all`.

The first real inefficient-path run, ATTEMPT 4, aborted safely before worker
allocation, audit, `MADV_MERGEABLE` or `run=1`. Its baseline contained the
residual ATTEMPT 3 values `pages_shared=251`, `pages_sharing=9749`,
`full_scans=2` and `general_profit=38883328`. The old isolation check
incorrectly treated those global counters as proof of a live external
consumer. ATTEMPT 4 therefore tested neither the UNIQUE generator nor scanner
progress, controller inefficiency, auto-disable or cooldown.

Linux can defer removal and accounting reconciliation of KSM `rmap_item`
state until a later `ksmd` pass even after an owned VMA was made unmergeable
and destroyed. The validation model now separates live external consumers,
residual global accounting and current owned-session activity. A live external
consumer requires a current `ksm_mergeable`/`ksm_merge_any` indication or
non-zero `KSM:` bytes in that process's `smaps`; stale
`ksm_merging_pages` without either is reported as residual evidence. Failure
to read required live-process evidence fails closed.

Global counter changes are stored as signed baseline-relative deltas because a
new scan can reconcile old accounting and make `pages_shared`,
`pages_sharing`, or `general_profit` decrease. Such a decrease is never
converted into current-session saved bytes. When residual accounting
contaminates global attribution, the UNIQUE controller decision uses the two
exact owned `PID+start_ticks` observations: both must have non-zero
`ksm_rmap_items`, negligible merging and profit no greater than the configured
positive threshold after two new full scans. Global deltas remain diagnostic.

ATTEMPT 5 validated this inefficient scenario on CachyOS. Its two owned
children each exposed 8,192 evaluated rmap items, zero merging pages and
`-524288` bytes process profit after two new full scans. Residual global
accounting was reconciled, so current-session saved-byte attribution correctly
remained unavailable/zero. The controller stopped its owned `run=1`, entered
COOLDOWN, and rejected the same plan with `cooldown_active`. Sustained `ksmd`
CPU was about 0.480% of one logical CPU; content, unmerge, cleanup,
configuration restoration and host equality passed.

The ATTEMPT 5 CLI returned 1 despite every mandatory behavioral gate passing
because the harness evaluated the full gate set before final cleanup and host
checks were attached, then retained that premature generic error. The
scenario-aware finalizer was fixed afterward without changing workers, KSM
advice, sysfs writes, scanner control, thresholds, ownership or recovery; no
additional privileged run was required.

A bounded COW integrity scenario remains designed: after statistics are
captured, one child modifies a small merged subset while the peer retains
original data. It is not run by ordinary tests or CI.

`MADV_UNMERGEABLE` can need memory to split pages, so cleanup stops `run`,
captures final process/system evidence while children remain alive, and rechecks
`MemAvailable`. If headroom is insufficient, terminating the owned child removes
its mappings safely. Recovery is owned-only and idempotent; uncertain ownership
requires manual inspection.

## Persistence and privacy

Migration 0007 stores bounded system/process samples, evaluations, plans and
controller transitions with decision, plan and transaction links. Retention
follows existing storage policy. Datasets never include RAM contents,
environment data, secrets, PFNs or hardware identifiers.

## Limitations

The synthetic validations do not prove universal benefits for real VM, browser
or Electron workloads. Those require Phase 10 workload benchmarks.
Phase 9 does not enable aggressive global KSM, does not mutate external
processes and does not provide production automatic activation. Live dynamic
scanner tuning is implemented but was deliberately not exercised by ATTEMPT 3
or ATTEMPT 5.
