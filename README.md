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

Legend: ✅ validated; 🟡 development complete with validation pending; 🔵 in
development; ⚪ planned.

## Current validated snapshot

| Item | Result |
|---|---|
| Platform | CachyOS Linux, x86_64 |
| Kernel | 7.1.4-1-cachyos |
| Rust / Cargo | 1.97.1 / 1.97.1 |
| Workspace crates | 11 |
| Tests defined / executed | 173 / 173 |
| Passed / failed / ignored | 173 / 0 / 0 |
| Runtime mode | `observe` |
| Host zram | `/dev/zram0`, `zstd`, systemd generator, external/protected |
| Host zswap | supported, disabled by kernel/provider configuration |
| Host storage | Btrfs, non-rotational SATA SSD; no NVMe evidence |
| Phase 6 validation | read-only + live-safe swapfile; dedicated boot pending |

Linux tests include real `/proc`/`/sys` reads and real SIGINT/SIGTERM delivery.
The dedicated bounded harness additionally validates isolated privileged
cgroup and zram mutations; the normal runtime remains observe-only.
The Phase 6 harness additionally validated a bounded owned Btrfs swapfile
lifecycle, write accounting and recovery without changing zswap or zram0.

## Performance snapshot

Release `nemord` was sampled on the validation host 15 times at two-second
intervals using `/proc/<pid>/stat`, `status`, and `smaps_rollup`.

| Metric | Phase 3 | Phase 4 | Phase 5 | Phase 6 |
|---|---:|---:|---:|---:|
| Mean CPU (one logical CPU) | 0.1990% | 0.199249% | 0.212940% | 0.232293% |
| Maximum interval CPU | 0.4976% | 0.996093% | 0.496909% | 0.995682% |
| Maximum RSS | ~7.03 MiB | ~7.34 MiB | ~7.32 MiB | ~7.67 MiB |
| PSS | ~4.70 MiB | ~4.99 MiB | ~5.00 MiB | ~5.34 MiB |

These are host-specific validation measurements, not universal benchmarks.
Phase 6 used the same 15 two-second interval method. Mean CPU and memory
increased modestly; storage inventory is bounded by the normal sampling loop.

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
```

Every command accepts `--json` at its terminal command position and reads only
configuration, Linux capability files, or SQLite.

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

## Roadmap

- Completed and validated on CachyOS: Phases 0–5.
- Phase 6 implementation and live-safe swapfile validation are complete;
  dedicated zswap+NVMe boot validation remains pending.
- The runtime default remains observe-only despite isolated privileged
  validation of Phases 3 and 5.
- Phase 7 remains planned and was not started.

## Documentation

- [Architecture](docs/architecture.md)
- [Telemetry](docs/telemetry.md)
- [Classification](docs/classification.md)
- [Cgroups](docs/cgroups.md)
- [Policy engine](docs/policy-engine.md)
- [Zram backend](docs/zram.md)
- [Zswap and storage tiering](docs/tiering.md)
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
