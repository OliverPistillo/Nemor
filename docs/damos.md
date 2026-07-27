# DAMOS controlled reclaim

Phase 8 keeps observation in `nemor-damon` and places every action concept in
the separate `nemor-damos` crate. Production remains `mode=observe`,
`damos.enabled=false`, and `damos.live_apply=false`. The daemon may persist an
explained dry-run report; neither it nor the normal CLI writes DAMON sysfs.

## Eligibility and fencing

The deterministic `damos-controlled-reclaim-v1` planner rejects unknown,
stale, PID 1, non-owned, foreground, gaming, critical, protected, or
unclassified targets. NORMAL, WATCH, and STABILIZING reject new pageout.
PRESSURE, CRITICAL, and EMERGENCY can only produce a plan for an identified
background target with three consecutive complete zero-access observations,
valid age evidence, no safety conflict, and no early-refault blacklist.

The manual validation path uses one verified synthetic PID/start-time identity
and three explicit mappings. A core `addr` filter fences the exact COLD range.
On the modern ABI, the harness requires `matching=Y`, `allow=Y`, and exact
COLD `addr_start`/`addr_end`: matching bytes are explicitly allowed and the
unmatched remainder is excluded by the final allow filter. A legacy
matching-only ABI is modelled separately and never selected silently when
`allow` exists. Missing or ambiguous filtering blocks live pageout.

## Scheme, quotas, and evidence

Phase 8 supports only `stat` for shadow selection and `pageout` for the
independent live transaction. It does not implement LRU changes, migration, or
hugepage actions. Validation uses `nr_accesses=0..0`, an age minimum of three
complete aggregation windows, 5 ms and 8 MiB per 10,000 ms reset interval, and
a 16 MiB configured policy ceiling. Both time and byte quota can never be zero.
The monitor interval is 4,000 ms and the complete live deadline is 5,000 ms,
so the byte quota cannot reset during the session and the hard live action
ceiling remains 8 MiB.

`max_nr_snapshots` limits scheme application snapshots; it is not a pageout
operation counter or byte quota. The configured region `age.min=3` is an access
pattern value, not an assertion that eligibility begins at snapshot index
three. The five-snapshot secondary lifecycle fence fits inside the live
deadline. Shadow and live retain independent DAMON age state. The shadow
records the empirical first tried snapshot, candidate region age, and timestamp
so the live ceiling can be checked for eligibility headroom.

Reports preserve requested/effective/readback values for size, access-count,
age, sampling, aggregation, update, quota, and snapshot fields. Tried-region
records include their raw access count and age. A raw `effective_bytes=0` is
kept verbatim and is not interpreted as disabled quota: both configured time
and size quotas are nonzero, and the kernel value is explicitly refreshed.

The hard byte safety gate uses cumulative kernel `sz_tried`, not merely
`sz_applied`: `sz_tried` must be at most 8 MiB, `sz_applied` must not exceed
`sz_tried`, and both must remain within the configured byte quota. A zero
`sz_applied` can therefore pass quota safety while still failing action
efficacy. Tried-region sizes are also summed diagnostically, but that
window-scoped sysfs view is not assumed to equal cumulative `sz_tried`.

Candidate ranges are primarily captured from `damon:damos_before_apply` in an
owned tracefs instance with a per-instance monotonic trace clock. The shadow
fails closed unless parsed context 0, scheme 0, target 0 candidates are wholly
inside COLD, have zero HOT/WARM overlap, `nr_accesses=0`, and age at least the
configured minimum. The sysfs `tried_regions` interface is cleared, armed
before the observed apply interval, read after that bounded interval, and
cleared again as a cross-check; it is not treated as a retrospective query.

The stat shadow must report zero HOT/WARM overlap. It is removed before a new
session, context, target, scheme, and `pageout` action are created. Live success
requires `sz_applied > 0`, live candidates exclusively inside COLD, and an
exact-range COLD residency change from `/proc/<pid>/pagemap`: fewer present
pages and/or more swapped pages. The harness reads only bits 63 (present) and
62 (swapped) for the bounded owned ranges; it neither reads nor persists PFNs.
HOT/WARM safety requires both zero candidate overlap and no exact-range
present/swapped evidence of reclaim. Host-wide swap change is insufficient.
The report keeps tried/applied bytes, quota-exceed counters, snapshot counts,
ranges, kdamond/control CPU, and HOT/WARM slowdown. The slowdown gate is 5%.

`smaps` remains VMA-level supporting evidence. When Linux merges the three
compatible owned mappings, the containing VMA RSS/PSS/Swap values are reported
once and are never duplicated as HOT, WARM, or COLD metrics. Exact pagemap
snapshots are recorded before live pageout, after the scheme is stopped and
trace drained, and—only after that critical snapshot—after controlled COLD
refault.

ATTEMPT 3 is retained as the first confirmed Nemor DAMOS pageout: two owned
COLD candidates totaling 8 MiB were tried and applied, the shared VMA RSS fell
by 8 MiB, target swap rose by 8 MiB, refault content was valid, the blacklist
blocked the next plan, and the host was structurally unchanged. It was not a
Phase 8 validation pass because its HOT/WARM gates incorrectly duplicated
shared-VMA RSS/Swap as if those aggregates were per-range measurements.

## CachyOS privileged validation

Phase 8 was validated on CachyOS kernel `7.1.4-1-cachyos` for one controlled
synthetic owned target. This is not universal production validation, and
normal `nemord` remains observe-only.

The final profile used 8 MiB HOT, 8 MiB WARM and 32 MiB COLD with `vaddr`,
`pageout`, `nr_accesses=0`, `age.min=3`, a 5 ms/8 MiB quota, 10,000 ms reset,
5,000 ms deadline, five maximum snapshots and 500,000 µs apply interval. Two
owned `damos_before_apply` candidates, both age three and fully inside COLD,
totalled 8,388,608 bytes. Kernel stats reported two regions and 8,388,608
bytes both tried and applied, with `qt_exceeds=0`.

Exact pagemap evidence was:

| Range | Before pageout | After pageout | After refault |
|---|---|---|---|
| HOT | 8 MiB present, 0 swapped | unchanged | diagnostic only |
| WARM | 8 MiB present, 0 swapped | unchanged | diagnostic only |
| COLD | 32 MiB present, 0 swapped | 24 MiB present, 8 MiB swapped | 32 MiB present, 0 swapped |

The content fingerprint remained valid. Controlled COLD access produced an
early-refault record, created a cooldown blacklist and caused the next planner
request to be rejected as `early_refault_blacklist`. Cleanup, recovery,
second-recovery idempotence and structural host comparison passed.

Action-specific measurements were 0.25% `kdamond` CPU, approximately
0.25876444% validation-control CPU and 0% control-workload slowdown. They are
synthetic host-specific results, not production guarantees.

Validation history is intentionally retained:

- **ATTEMPT 1:** no pageout; `max_nr_snapshots=1` prevented live COLD aging.
- **ATTEMPT 2:** no live pageout; shadow tried counters were valid, but sysfs
  tried-region acquisition was incorrectly treated as retroactive.
- **ATTEMPT 3:** first real 8 MiB COLD pageout and successful refault; final
  gates failed because shared-VMA smaps values were attributed to each range.
- **ATTEMPT 4:** PASS; exact pagemap evidence proved 8 MiB COLD-only reclaim
  and no HOT/WARM reclaim.

## Refault, blacklist, and rollback

Only after the scheme is off does the child touch COLD. Content/fingerprint
integrity and RSS/swap evidence are recorded with action ID, stable identity,
range generation, and latency. Early refault creates a bounded blacklist keyed
by stable identity plus region signature; a new plan must be rejected before
sysfs mutation.

Refault has three explicit states: `not_evaluated`, `not_observed`, and
`observed`. It is not evaluated unless nonzero applied bytes also produced a
target-attributable COLD reclaim effect. Only `observed` can create a blacklist
or cause the next plan to be rejected.

Pageout has no byte-for-byte rollback. Rollback stops the owned scheme and
kdamond, removes owned DAMON configuration, prevents further reclaim, and
restores planner state. Reclaimed pages fault in naturally. Recovery preserves
external sessions, is ownership guarded, and is idempotent.

## Validation-only memory layout

The manual harness uses separate 8 MiB HOT, 8 MiB WARM, and 32 MiB COLD
anonymous mappings with at least 1 GiB `MemAvailable` headroom. Mapping-local
`MADV_NOHUGEPAGE` is validation-only. Nemor never changes global THP or advises
real workloads. The report distinguishes the three separately owned mappings
from their containing VMAs; Linux may merge compatible adjacent VMAs without
changing ownership or explicit target ranges. The harness makes no persistent
changes and does not mutate
cgroups, zram, zswap, swap topology, sysctls, boot configuration, or external
DAMON sessions. Phase 7 `--damon` remains monitor-only with `nr_schemes=0`.

Migration `0006_damos.sql` stores bounded linked plans, results, and refault
blacklists without memory contents or secrets. Normal read-only commands are:

```text
nemorctl damos status
nemorctl damos plan latest
nemorctl damos history
nemorctl damos blacklist
```

There is no normal apply/pageout/reclaim/start/enable command. Phase 9 is
outside this work.
