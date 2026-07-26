# Nemor

Nemor is an experimental Linux runtime for increasing sustainable memory
capacity by coordinating kernel mechanisms conservatively. Its primary target
is CachyOS/Linux. It does not promise a universal RAM multiplier: current
operation is observe-only, and its Phase 4 decisions are deterministic rules,
not AI.

## Project Status

| Phase | Scope | Status |
|---|---|---|
| Phase 0 | daemon, config, SQLite, lifecycle | ✅ Validated on CachyOS |
| Phase 1 | Linux telemetry and reporting | ✅ Validated on CachyOS |
| Phase 2 | process/workload classification | ✅ Validated on CachyOS |
| Phase 3 | cgroup v2 protection primitives | 🟡 Dev complete — privileged mutation validation pending |
| Phase 4 | deterministic policy engine | ✅ Validated on CachyOS |
| Phase 5 | compression experiments | ⚪ Planned |

Legend: ✅ validated; 🟡 development complete with validation pending; 🔵 in
development; ⚪ planned.

## Current validated snapshot

| Item | Result |
|---|---|
| Platform | CachyOS Linux, x86_64 |
| Kernel | 7.1.4-1-cachyos |
| Rust / Cargo | 1.97.1 / 1.97.1 |
| Workspace crates | 9 |
| Tests defined / executed | 122 / 122 |
| Passed / failed / ignored | 122 / 0 / 0 |
| Runtime mode | `observe` |
| Validated implementation | current `main` (Phase 4 implementation commit) |

Linux tests include real `/proc`/`/sys` reads and real SIGINT/SIGTERM delivery.
Privileged cgroup mutation is explicitly outside this validated snapshot.

## Performance snapshot

Release `nemord` was sampled on the validation host 15 times at two-second
intervals using `/proc/<pid>/stat`, `status`, and `smaps_rollup`.

| Metric | Phase 3 | Phase 4 |
|---|---:|---:|
| Mean CPU (one logical CPU) | 0.1990% | 0.199249% |
| Maximum interval CPU | 0.4976% | 0.996093% |
| Maximum RSS | ~7.03 MiB | ~7.34 MiB |
| PSS | ~4.70 MiB | ~4.99 MiB |

These are host-specific validation measurements, not universal benchmarks.
The mean CPU is unchanged within measurement noise; memory increased modestly.

## Implemented capabilities

- read-only Linux memory, swap, PSI, process, zram and zswap telemetry;
- process identity, foreground tri-state, gaming protection and workload
  classification;
- cgroup v2 capability inspection, guarded planning, snapshot, rollback and
  crash-recovery machinery;
- deterministic six-state pressure engine with explicit time, hysteresis,
  versioned explanations and a closed action planner;
- SQLite WAL audit, retention, deduplicated policy decisions, and bounded
  read-only history;
- foreground daemon with clean SIGINT/SIGTERM lifecycle;
- read-only JSON/text CLI.

## Safety model

- `observe` means zero system mutations;
- PID movement requires stable identity allow-list and fresh start ticks;
- unknown means “do not touch”;
- game, critical, protected and foreground workloads remain protected;
- actuator writes require snapshot, one mutation, readback, verify and rollback;
- policy dry-run stops before actuator apply;
- every crate forbids unsafe Rust;
- no destructive or unvalidated action is exposed.

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

- Phase 3 privileged systemd/cgroup mutations have not been validated and are
  not enabled by the default service;
- gaming detection is not validated against every live
  Steam/Proton/Wine/Gamescope combination;
- SteamOS is not supported;
- policy operation is dry-run only;
- no ML, GUI, or Phase 5 compression experiment exists.

## Roadmap

- Completed and validated: Phases 0–2 and deterministic Phase 4 observe logic.
- Validation pending: isolated privileged Phase 3 cgroup mutation.
- Next: Phase 5 only after a separate approved scope.
- Future work remains unavailable until implemented and measured.

## Documentation

- [Architecture](docs/architecture.md)
- [Telemetry](docs/telemetry.md)
- [Classification](docs/classification.md)
- [Cgroups](docs/cgroups.md)
- [Policy engine](docs/policy-engine.md)
- [Safety model](docs/safety-model.md)
- [Database](docs/database.md)
- [CachyOS validation](docs/cachyos-validation.md)

## Validation history

| Phase | Tests after phase | Platform validation | Commit |
|---|---:|---|---|
| 0–2 | 90 | CachyOS | `ae06b19` |
| 3 | 106 | Partial — privileged mutations pending | `b335e2c` |
| 4 | 122 | CachyOS observe validation | current `main` |
