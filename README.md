# Nemor

Nemor is an experimental Linux runtime for increasing sustainable memory
capacity by coordinating kernel mechanisms conservatively. Its primary target
is CachyOS/Linux. It does not promise a universal RAM multiplier: current
operation is observe-only, and its policy decisions are deterministic rules,
not AI.

## Project Status

| Phase | Scope | Status |
|---|---|---|
| Phase 0 | daemon, config, SQLite, lifecycle | ✅ Validated on CachyOS |
| Phase 1 | Linux telemetry and reporting | ✅ Validated on CachyOS |
| Phase 2 | process/workload classification | ✅ Validated on CachyOS |
| Phase 3 | cgroup v2 protection primitives | ✅ Validated on CachyOS |
| Phase 4 | deterministic policy engine | ✅ Validated on CachyOS |
| Phase 5 | safe zram backend and profiles | ✅ Validated on CachyOS |
| Phase 6 | zswap + NVMe tiering backend | 🟡 Dev complete / boot validation pending |
| Phase 7 | DAMON monitor-only telemetry | ✅ Validated on CachyOS |
| Phase 8 | controlled DAMOS reclaim | ✅ Validated on CachyOS |
| Phase 9 | selective KSM | ✅ Validated on CachyOS |
| Phase 10 | reproducible A/B benchmark framework | 🔵 3A/3B CLOSED / PASS; 3C OPEN — IPC-taxonomy remediation integrated and CI-tested, not live-validated |
| Phase 11 | predictive optimization | ⚪ Not started |

Legend: ✅ validated; 🟡 development complete with validation pending; 🔵 in
development; ⚪ planned.

## Current validated snapshot

| Item | Result |
|---|---|
| Platform | CachyOS Linux, x86_64 |
| Kernel | 7.1.4-1-cachyos |
| Rust / Cargo | 1.97.1 / 1.97.1 |
| Workspace crates | 15 |
| Tests defined / executed | 589 / 589 (accepted local integration suite) |
| Passed / failed / ignored | 589 / 0 / 0 locally; exact-commit GitHub CI test step PASS |
| Phase 10 validation | 3A/3B CLOSED / PASS; 3C OPEN — no post-remediation live validation or new pressure lineage |
| Checkpoint 3A-P | privileged observer pipeline validated on CachyOS; ATTEMPT 1/2 negative history retained |
| Checkpoint 3A | CLOSED / PASS — six V3 runs preserved and exact bounded offline revalidation returned `REVALIDATED_PASS` |
| Checkpoint 3B | CLOSED / PASS — Experiment `checkpoint3b-1785272587990631899`, 3 baseline + 3 observe runs valid and comparable |
| Checkpoint 3C | V4 immutable partial evidence; IPC taxonomy integrated at `96dc1b4` with exact-commit CI PASS; V5 frozen/non-reusable |
| Runtime mode | `observe` |
| Host zram | `/dev/zram0`, `zstd`, systemd generator, external/protected |
| Host zswap | supported, disabled by kernel/provider configuration |
| Host storage | Btrfs, non-rotational SATA SSD; no NVMe evidence |
| Phase 6 validation | read-only + live-safe swapfile; dedicated boot pending |
| Phase 7 validation | real `vaddr` monitor-only session; 30/30 gates; host unchanged |
| Phase 8 validation | owned-target DAMOS pageout; 8 MiB COLD reclaimed; host unchanged |
| Phase 9 validation | profitable and inefficient auto-disable paths validated on owned synthetic targets; host unchanged |

Linux tests include real `/proc`/`/sys` reads and real SIGINT/SIGTERM delivery.
The dedicated bounded harness additionally validates isolated privileged
cgroup and zram mutations; the normal runtime remains observe-only.
The Phase 6 harness additionally validated a bounded owned Btrfs swapfile
lifecycle, write accounting and recovery without changing zswap or zram0.
The Phase 7 harness validated an owned synthetic DAMON session, isolated
tracefs capture, zero DAMOS, bounded datasets, cleanup and crash recovery.
The Phase 8 harness validated controlled DAMOS pageout on an owned synthetic
target with exact-range pagemap evidence; this does not enable production
pageout.

## Performance snapshot

Release `nemord` was sampled on the validation host 15 times at two-second
intervals using `/proc/<pid>/stat`, `status`, and `smaps_rollup`.

| Metric | Phase 3 | Phase 4 | Phase 5 | Phase 6 | Phase 8 observe | Phase 9 observe |
|---|---:|---:|---:|---:|---:|---:|
| Mean CPU (one logical CPU) | 0.1990% | 0.199249% | 0.212940% | 0.232293% | 0.200000% | 0.200000% |
| Maximum interval CPU | 0.4976% | 0.996093% | 0.496909% | 0.995682% | 0.500000% | 0.500000% |
| Maximum RSS | ~7.03 MiB | ~7.34 MiB | ~7.32 MiB | ~7.67 MiB | ~7.86 MiB | ~8.00 MiB |
| PSS | ~4.70 MiB | ~4.99 MiB | ~5.00 MiB | ~5.34 MiB | ~5.54 MiB | ~5.67 MiB |

These are host-specific validation measurements, not universal benchmarks.
Phase 6 used the same 15 two-second interval method. Mean CPU and memory
increased modestly; storage inventory is bounded by the normal sampling loop.
The Phase 8 observe measurement also used 15 two-second intervals with no
owned DAMON/DAMOS session; it measures only the unchanged observe runtime.
The Phase 9 measurement used the same method with KSM `run=0` and no owned KSM
session. Its exact maximum RSS was 8,392,704 bytes and final PSS 5,943,296
bytes.

Phase 7 measured the owned monitor session separately from normal daemon
observe performance:

| Phase 7 monitor metric | Result |
|---|---:|
| Complete aggregation windows | 9 |
| HOT / WARM / COLD normalized mean | 1.0 / 0.261111 / 0 |
| `kdamond` CPU | 0.0% |
| capture CPU | 0.02308834% |
| synthetic target slowdown | ~3.00004% |

The hard Phase 7 gate covers combined `kdamond` and capture CPU against a 1%
budget. The separately measured ~3% synthetic target slowdown is not hidden
and is not a production overhead promise; Phase 10 must compare real workloads
and stock behavior.

Phase 8 measured its privileged synthetic action separately:

| Phase 8 controlled reclaim metric | Result |
|---|---:|
| COLD tried / applied | 8 MiB / 8 MiB |
| HOT present/swapped before → after | 8 MiB/0 → 8 MiB/0 |
| WARM present/swapped before → after | 8 MiB/0 → 8 MiB/0 |
| COLD present/swapped before → after | 32 MiB/0 → 24 MiB/8 MiB |
| COLD after controlled refault | 32 MiB present, 0 swapped |
| `kdamond` CPU | 0.25% |
| validation control CPU | ~0.25876444% |
| control workload slowdown | 0.0% |

These are synthetic results from this validation host, not universal
production performance claims.

## Implemented capabilities

- read-only Linux memory, swap, PSI, process, zram and zswap telemetry;
- process identity, foreground tri-state, gaming protection and workload
  classification;
- cgroup v2 capability inspection, guarded planning, snapshot, rollback and
  crash-recovery machinery, validated on temporary real kernel cgroups;
- deterministic six-state pressure engine with explicit time, hysteresis,
  versioned explanations and a closed action planner;
- zram inventory, real compression metrics, safe/gaming/capacity plans,
  real isolated bounded benchmark, ownership/headroom guards, replacement-first
  swap transaction, rollback and recovery;
- SQLite WAL audit, retention, deduplicated policy decisions, and bounded
  read-only history;
- foreground daemon with clean SIGINT/SIGTERM lifecycle;
- read-only JSON/text CLI.
- zswap capability/provider inventory, swapfile filesystem and topology
  validation, pool planning, block-I/O accounting, write budgets and TBW
  estimates without invented endurance ratings;
- deterministic zram versus zswap+NVMe recommendation, boot-plan generation,
  owned swapfile rollback/recovery and live-safe privileged validation.
- DAMON capability discovery, `vaddr` monitor-only planning, dynamic tracepoint
  parsing, overlap-aware region normalization, hot/warm/cold observational
  labels, bounded SQLite persistence and JSONL/CSV export;
- an owned privileged validation path with explicit target regions,
  per-instance monotonic trace clock, zero DAMOS, overhead accounting and
  idempotent cleanup/recovery.
- a separate DAMOS controlled-reclaim planner with stable-cold eligibility,
  exact COLD address fencing, hard quotas, stat-shadow/pageout transaction
  models, decision audit, exact-range residency evidence, refault blacklist,
  truthful stop-only rollback and owned recovery. The real kernel path is
  validated only for the owned synthetic harness target; production remains
  plan-only.
- selective KSM capability/system/process metrics, conservative
  VM/browser/Electron profiles, fixed/advisor-aware scanner planning,
  profit/CPU-per-GiB evaluation, an ineffective-plan cooldown controller and
  owned rollback/recovery. Normal runtime is read-only; live KSM is confined
  to the validated explicit cooperative synthetic harness scopes.
- a versioned A/B benchmark framework with eight scenarios, capability-aware
  variants, anonymized host comparability, scoped metrics, deterministic
  statistics, bounded SQLite/JSON evidence, restore proof and an explicit
  non-privileged owned-synthetic smoke runner. Fixed-load compressible and
  incompressible baseline/observe validation is complete; controlled
  progressive pressure remains future work.
- an explicit Checkpoint 2 owned-cgroup harness with dirty-source provenance,
  evidence-kind isolation, effective-state variant resolution, audited
  PID/start-ticks ownership, a 64 MiB steady worker, watchdog and restore
  model. Its full privileged transient-scope lifecycle passed on CachyOS in
  ATTEMPT 5; this is harness validation, not performance evidence.
- an explicit Checkpoint 3A fixed-load `synthetic_compressible`
  `cachyos_baseline`/`nemor_observe` pipeline with clean release-binary
  provenance, deterministic six-run ordering, isolated exact-owned production
  observer lifecycle, run-relative counters, per-run restore and
  observer-overhead comparison. Preparation is unprivileged and freezes an
  integrity-bound manifest; privileged execution consumes only that manifest.
  Six real V3 runs completed (three baseline and three observe). Their original
  invalid state was caused solely by the fixed full-environment versus material-
  environment hash-domain validator defect. The immutable evidence was preserved
  and exact bounded offline revalidation returned `REVALIDATED_PASS`; the
  observer-overhead comparison is comparable. With only three repetitions no
  significance claim is made. Checkpoint 3A is CLOSED / PASS.
- a Checkpoint 3B `synthetic_incompressible` extension of the same prepared-
  manifest, transient worker, DynamicUser observer, evidence, restore and
  comparison architecture. Its deterministic SplitMix64 generator is bound by
  scenario, generator identity/version, seed, payload, and worker-manifest
  evidence; generation and prefault finish before measurement, with bounded
  integrity reads and no sustained rewrite. Experiment
  `checkpoint3b-1785272587990631899` completed three baseline and three observe
  repetitions with exact paired workload/payload identities. All runs passed
  integrity, watchdog, OOM/OOM-kill and restore gates; the observer-overhead
  comparison is comparable. Worker CPU changed by +4.486%; mean and peak
  worker memory were approximately unchanged (-0.112%/-0.110%). Observe used
  0.11 CPU-seconds per 20-second window with mean RSS/PSS of
  8,959,317/6,538,923 bytes. Runner CPU changed from 0.03 to 0.72 seconds
  (about +0.69 CPU-seconds); the 2300% relative figure has a tiny baseline and
  is not a system CPU regression claim. Three repetitions support no
  significance claim, and capacity remains `not_evaluated`. Checkpoint 3B is
  CLOSED / PASS.
- a Checkpoint 3A-P boundary for one benchmark-owned transient
  `nemor-benchmark-observer-*.service`. PID 1 creates the real release
  `nemord` with `DynamicUser=true`, an ephemeral `RuntimeDirectory`, fixed
  typed argv, production-equivalent hardening and isolated storage. The
  privileged runner copies descriptor-verified Cargo bytes into a
  root-owned, single-link `/run` executable, and the service never executes
  the user-owned Cargo inode directly. Its
  privileged pipeline validation passed on CachyOS in Checkpoint 3A-P ATTEMPT
  3. The three-attempt history is retained, and this harness evidence makes
  no performance claim; its boundary is reused by the closed Checkpoint 3A and
  the closed Checkpoint 3B experiment.
- a Checkpoint 3C model-only controlled progressive-pressure framework. Its
  versioned manifest contract freezes exact increasing byte levels, the
  SplitMix64 incompressible generator, a shared baseline/observe `MemoryMax`,
  timing/watchdog bounds, material environment, conservative headroom
  reserves, scoped health gates, emergency stop policy and deterministic
  bracket-only refinement. Sustainable capacity is always the highest
  actually tested healthy level; safety aborts are retained but never become
  capacity bounds. Host OOM is forbidden. A zero-allocation, zero-privilege
  simulator covers negative levels, aborts, restore failure and refinement.
  V1 is preserved as valid static preparation evidence, but commit
  `0ca43a654585aeed45bf6426f73694b67a3e9508` did not contain the separate
  worker process or pressure-specific preflight/executor. V1 is therefore
  **STATIC PREPARATION VALIDATED / NOT EXECUTION-CAPABLE**, not a failed
  experiment; no live experiment occurred.
- Checkpoint 3C pre-live hardening makes the mandatory health-gate set
  complete, enforces coherent hold/sample/monotonic timing, separates
  protocol-invalid touched-byte evidence from valid unsustainable boundaries,
  distinguishes later-level stop states, validates watchdog/PSI policies and
  integrity-binds capacity summaries. The typed progressive worker starts
  unallocated, accepts a fixed level delta only after scope/`MemoryMax`
  verification, reuses the SplitMix64 v1 generator and binds acknowledgements
  to the complete run/worker/generator identity.
- `prepare-pressure-experiment` is a separate unprivileged, fresh-path-only
  bridge. It freezes three paired baseline/observe repetitions, conservative
  aligned 10/20/30% levels derived from captured `MemAvailable` after explicit
  reserves, one shared bounded `MemoryMax`, observer transactions, and
  `disabled_for_framework_pilot` refinement. Preparation starts no service,
  writes no cgroup, and allocates no workload. The resulting pilot remains
  framework validation: `search_complete=false` and capacity is
  `not_evaluated`.
- `pressure-preflight` parses only the pressure manifest and is read-only. It
  checks current headroom against frozen `MemoryMax` plus reserves without
  requiring volatile `MemAvailable` equality, compares material hash only to
  material hash, and reports user/root authorization separately.
  `execute-pressure-experiment` accepts only pressure manifests and requires
  root plus the exact preparing `SUDO_UID:SUDO_GID`.
- V3 experiment `checkpoint3c-1785312245488429386` passed its final freeze
  and both user/root preflights, then its one execution attempt safety-aborted
  in run 0. The executor incorrectly sent `progressive_memory_pressure` to the
  fixed-load workload-identity function, so no completed `LevelEvidence` was
  persisted; this does not prove that no payload was allocated. Structural
  state matched, but scope removal was reported false, runs 1–5 were not
  executed, and the CLI incorrectly returned zero. The immutable report
  (`b06671794cd0179f6d9ebd5545b785e9df892f03ca49d99c97a4bbabe4a10c76`)
  and database
  (`b8f8974327450451e2256911f39d97460a4e85256861126fdc6dfb0e9e29ecf7`)
  are authoritative negative evidence. V3 is never rerun or revalidated into
  performance evidence and supports no capacity claim.
- V4 experiment `checkpoint3c-1785315276506307352` passed final freeze and
  root preflight, then its one execution attempt returned the correct nonzero
  status. Baseline levels 704,643,072 and 1,426,063,360 bytes were valid
  Sustainable results with 3,988 ms and 7,016 ms transitions, five samples,
  zero OOM/OOM-kill and every mandatory gate passing. Level 2 reached
  `transition_starting` for 2,130,706,432 bytes but timed out before ACK, so it
  is not an unsustainable or capacity point. The cumulative full-payload hash
  made each append transition increasingly expensive; cleanup also
  misclassified a naturally collected exact scope as `StopFailed` after
  `NoSuchUnit`. V4 remains immutable partial evidence, never rerun, with report
  SHA-256
  `c1cf090c517ad7ef4fa6badc3138c6f13f8a507f246f8ff73c1ab2a2676c2d54`
  and database SHA-256
  `dddf2a47a84f6a3c634d7d56c5837ed9078fad766a4e93d321356ba1d3d9f8f2`.
- The transition IPC taxonomy remediation is integrated in commit
  `96dc1b4fede9b772b929f1e3c94f1a6564480c44`. Genuine socket deadlines map
  to `TransitionTimeout` / `SafetyAbort` / `WATCHDOG_TIMEOUT`; other IPC
  failures map to `TransitionIpcFailure` / `Invalid` / `ExecutionError`.
  Execution evidence schema 4, prepared pressure schema 6 and worker protocol
  1 are the current contracts. The accepted local integration suite passed
  589 tests with zero failures, and GitHub CI run `30454663806`, job
  `90585052557`, passed on that exact commit. This is implementation, static
  acceptance and CI evidence only: it is not live or performance validation,
  creates no capacity or unsustainable boundary, and does not close
  Checkpoint 3C. V5 is frozen historical lineage and cannot be reused; no new
  pressure lineage has been prepared.
- The live worker is a separate initially unallocated process controlled by a
  versioned mode-0600 AF_UNIX protocol. Systemd D-Bus attaches its exact
  PID/start-ticks identity to the frozen scope and verifies `MemoryMax` before
  level zero. Evidence is persisted after each level, emergency gates precede
  every next allocation, and cleanup targets only owned resources.
- V2 is **STATIC REVIEWED / LIVE EXECUTOR HARDENING REQUIRED**. It was never
  preflighted or executed and remains unchanged. The final live contract
  verifies the canonical current executable path, SHA-256 and embedded clean
  release identity before readiness and again before execution; the worker is
  spawned only from that frozen executable.
- Every AF_UNIX exchange has a frozen deadline. The version-2 pressure plan
  explicitly budgets transition/allocation separately from stabilization and
  hold, and derives the level, total, worker-scope and observer RuntimeMax
  bounds from that lifecycle. Exact touched-byte mismatch persists an invalid
  zero-hold level and immediately cleans up.
- Run continuation now requires successful exact-owned cleanup, absence of
  every owned worker/scope/observer/runtime directory, and structural
  before/after equality. Workload errors retain cleanup evidence; cleanup or
  structural failure escalates to `RESTORE_FAILURE`. Health gates are
  populated from their individual observations rather than copied from the
  final classification.

Phase 9 real CachyOS validation covers two synthetic, host-specific paths. The
profitable path measured 39,931,904 saved bytes, positive system/process
profit, two full scans and about 0.538% sustained `ksmd` CPU. The UNIQUE path
measured two new full scans, zero attributable savings, 8,192 rmap items,
zero merging pages and `-524288` bytes process profit per child; the controller
transitioned EVALUATING→INEFFICIENT, stopped its owned scanner, entered
COOLDOWN and rejected the same plan. Sustained CPU was about 0.480%. Both
paths preserved content, configuration and host structure. These figures are
not production application benchmarks.

## Safety model

- `observe` means zero system mutations;
- PID movement requires stable identity allow-list and fresh start ticks;
- unknown means “do not touch”;
- game, critical, protected and foreground workloads remain protected;
- actuator writes require snapshot, one mutation, readback, verify and rollback;
- policy dry-run stops before actuator apply;
- every crate forbids unsafe Rust;
- `/dev/zram0` is external/protected and never eligible for validation
  ownership;
- no privileged mutation is exposed through the daemon or `nemorctl`.
- zswap kernel-global changes and persistent boot plans require separate manual
  approval; write-budget events never turn off an active swap.
- normal observe mode never creates, configures, starts or stops `kdamond` and
  never mutates tracefs; unavailable or unknown DAMON capability means no
  action.
- normal daemon and CLI cannot apply DAMOS; only the explicit manual
  `--damos` validation scope can page out its owned synthetic COLD mapping.
- normal daemon and CLI cannot start, tune or stop KSM or mark memory
  mergeable; `run=2` is forbidden. Only explicit manual `--ksm` and
  `--ksm-inefficient` validation scopes may operate on cooperative children
  after a persisted audit. They preserve baseline scanner settings and mutate
  only `run=0→1→0`.

See [the safety model](docs/safety-model.md).

## Available CLI

```text
nemorctl doctor
nemorctl status
nemorctl report latest
nemorctl workload latest
nemorctl cgroups status
nemorctl policy status
nemorctl policy latest
nemorctl zram status
nemorctl zram profiles
nemorctl zram report latest
nemorctl tiering status
nemorctl tiering recommend
nemorctl tiering report latest
nemorctl damon status
nemorctl damon sessions
nemorctl damon report latest
nemorctl damon export --format jsonl --output <new-path>
nemorctl damon export --format csv --output <new-path>
nemorctl damos status
nemorctl damos plan latest
nemorctl damos history
nemorctl damos blacklist
nemorctl ksm status
nemorctl ksm processes
nemorctl ksm plan latest
nemorctl ksm report latest
nemorctl ksm history
```

Read commands accept `--json` at their terminal command position. DAMON export
is an explicit bounded userspace database export to a new safe path; it never
configures the kernel or overwrites an existing file.

## Build and local observe run

```bash
cargo fmt --check
cargo build --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Use an owned temporary database by copying `config/default.toml` and changing
only `general.database_path`, then run:

```bash
cargo run -p nemord -- --config /path/to/config.toml
cargo run -p nemorctl -- --config /path/to/config.toml policy status --json
cargo run -p nemorctl -- --config /path/to/config.toml policy latest --json
```

The daemon stays in the foreground. SIGINT or SIGTERM commits `ended_at` and
`clean_shutdown = 1`.

## Known limitations

- privileged cgroup/zram validation is available only through the dedicated
  test harness and is not enabled by the default service;
- gaming detection is not validated against every live
  Steam/Proton/Wine/Gamescope combination;
- SteamOS is not supported;
- policy operation is dry-run only;
- no ML or GUI exists;
- the current host has no NVMe backing device and zswap is disabled by its
  CachyOS boot/provider configuration;
- full zswap+NVMe pool, writeback and comparative benchmark validation requires
  a separately approved dedicated boot;
- the daemon and normal CLI intentionally expose no tiering apply command.
- small synthetic DAMON access-frequency tests can be distorted by THP/TLB
  behavior; the validation harness uses mapping-local `MADV_NOHUGEPAGE` only
  to establish a controlled base-page comparison;
- the validated ~3% synthetic target slowdown requires reevaluation on real
  workloads and is not a production guarantee;
- Phase 8 pageout is validated only on a controlled synthetic owned target and
  remains unavailable to normal `nemord` and `nemorctl`; rollback stops further
  reclaim but cannot undo pages already paged out byte-for-byte;
- no LRU, migration, arbitrary-process, foreground, or gaming reclaim exists.
- KSM profiles are conservative planning templates, not permission or
  profitability proof; Nemor cannot remotely opt arbitrary processes into KSM.
- Phase 9 live validation preserved the host scanner settings
  (`pages_to_scan=100`, `sleep_millisecs=20`); dynamic scanner tuning is not
  separately validated.

## Roadmap

- Completed and validated on CachyOS: Phases 0–5 and Phases 7–9.
- Phase 6 implementation and live-safe swapfile validation are complete;
  dedicated zswap+NVMe boot validation remains pending.
- The runtime default remains observe-only despite isolated privileged
  validation of Phases 3, 5, 6, 7 and 8.
- Phase 9 validated both profitable selective KSM and real ineffective-workload
  auto-disable/cooldown on cooperative owned targets.
- Phase 10 remains in development: the benchmark framework, privileged
  owned-cgroup harness, and privileged observer service pipeline are
  validated; real A/B evidence is pending.
- Phase 11 is not started.

## Documentation

- [Architecture](docs/architecture.md)
- [Telemetry](docs/telemetry.md)
- [Classification](docs/classification.md)
- [Cgroups](docs/cgroups.md)
- [Policy engine](docs/policy-engine.md)
- [Zram backend](docs/zram.md)
- [Zswap and storage tiering](docs/tiering.md)
- [DAMON monitor-only telemetry](docs/damon.md)
- [DAMOS controlled reclaim](docs/damos.md)
- [Selective KSM](docs/ksm.md)
- [Benchmark framework](docs/benchmark.md)
- [Safety model](docs/safety-model.md)
- [Database](docs/database.md)
- [CachyOS validation](docs/cachyos-validation.md)
- [Privileged validation](docs/privileged-validation.md)

## Validation history

| Phase | Tests after phase | Platform validation | Commit |
|---|---:|---|---|
| 0–2 | 90 | CachyOS | `ae06b19` |
| 3 | 106 | CachyOS read-only baseline | `b335e2c` |
| 4 | 122 | CachyOS observe validation | `7a1d180` |
| 5 | 140 | CachyOS read-only baseline | `fcb21a9` |
| 3 + 5 gate | 148 | CachyOS privileged isolated validation | current validation commit |
| 6 development | 173 | CachyOS read-only + live-safe swapfile; boot pending | current development |
| 7 | 213 | CachyOS real `vaddr`, 9 windows, zero DAMOS, host unchanged | current Phase 7 commit |
| 8 | 268 | CachyOS controlled synthetic DAMOS pageout; 8 MiB COLD-only reclaim, refault/recovery, host unchanged | current Phase 8 commit |
| 9 | 316 | CachyOS selective KSM: profitable path plus ineffective auto-disable/cooldown; host unchanged | current Phase 9 commit |
| 10 checkpoint 3A-P | 491 | Framework, privileged worker harness, and observer service pipeline validated on CachyOS; real A/B pending | `2bf9cce` |
