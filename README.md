# Nemor

Nemor is an observe-only telemetry service for CachyOS and other Arch
Linux systems. Phase 2 adds deterministic workload classification to the
read-only Phase 1 telemetry pipeline. It records explainable process categories
and stabilized session workload changes, but does not choose policies, optimize
memory, or change Linux state.

## Phase 2 status

The workspace contains seven Rust crates:

- `common`: configuration, validation, shared serializable types, injectable
  Linux paths, and one-time host metadata reads.
- `collector`: read-only `/proc` and `/sys` parsers, system samples, process
  samples, non-sensitive process identity signals, swap/zram/zswap detection,
  and per-process CPU deltas.
- `classifier`: deterministic process categorization, foreground tri-state,
  gaming evidence, nine workload classes, explanations, and stabilization.
- `storage`: SQLite connection setup, migration verification, and host/session
  plus telemetry/catalog/workload-event/retention repositories.
- `nemord`: foreground daemon, sampling loop, and signal-driven shutdown.
- `nemorctl`: read-only `doctor`, `status`, `report latest`, and
  `workload latest` commands.
- `test-support`: Linux fixtures and temporary test resources only.

The only accepted operating mode is `observe`, and
`allow_automatic_actions` must be `false`.

## Prerequisites

- Linux (CachyOS/Arch Linux is the initial target)
- stable Rust with `cargo`, `rustfmt`, and `clippy`
- readable `/proc`, `/etc/machine-id`, and `/etc/os-release`
- SQLite requires no system package because the workspace builds a bundled copy

No network access is required by the binaries at runtime.

## Build, lint, and test

```bash
cargo build --workspace --all-targets --all-features
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Local run without privileges

Copy the sample configuration and replace `database_path` with a location owned
by the current user:

```bash
workdir="$(mktemp -d)"
sed "s|/var/lib/nemor/nemor.db|$workdir/nemor.db|" \
  config/default.toml > "$workdir/config.toml"
cargo run -p nemord -- --config "$workdir/config.toml"
```

The process remains in the foreground. `Ctrl-C` (SIGINT) or SIGTERM closes the
current session transactionally, sets `ended_at`, marks `clean_shutdown = 1`,
and exits with code zero. An abnormal process termination deliberately leaves
the record open with `clean_shutdown = 0`.

In another terminal, the read-only commands can use the same configuration:

```bash
cargo run -p nemorctl -- --config "$workdir/config.toml" doctor
cargo run -p nemorctl -- --config "$workdir/config.toml" doctor --json
cargo run -p nemorctl -- --config "$workdir/config.toml" status
cargo run -p nemorctl -- --config "$workdir/config.toml" status --json
cargo run -p nemorctl -- --config "$workdir/config.toml" report latest
cargo run -p nemorctl -- --config "$workdir/config.toml" report latest --json
cargo run -p nemorctl -- --config "$workdir/config.toml" workload latest
cargo run -p nemorctl -- --config "$workdir/config.toml" workload latest --json
```

`doctor` reports `pass`, `warn`, or `fail` for Linux prerequisites. Missing PSI
or cgroups v2 support is a warning in Phase 2: PSI is an optional collector
capability and cgroups are only observed as process paths. Missing mandatory
identity or `/proc` inputs is a failure. Exit code
zero means no failures, code two means at least one critical check failed, and
code one means invalid input or an internal command error.

`status` reports database presence, schema version, the most recently registered
host, and the latest session. `session_open` describes only the database record;
it is not proof that a daemon process is alive.

`report latest` aggregates only the most recent recorded session: sample counts,
memory/swap/PSI extrema, counter deltas, observed zram/zswap presence, and known
missing capabilities. It makes no workload or optimization claims.

`workload latest` reports the latest stabilized deterministic class, confidence,
rule version, non-sensitive reasons, relevant gaming/pressure signals, and
current category counts. Before confirmation it returns a controlled
unknown/unavailable state and creates no event.

## Manual systemd installation example

These commands are examples only; the unit is not installed or enabled by this
repository:

```bash
install -Dm0755 target/release/nemord /usr/bin/nemord
install -Dm0644 config/default.toml /etc/nemor/config.toml
install -Dm0644 packaging/systemd/nemord.service \
  /etc/systemd/system/nemord.service
systemctl daemon-reload
systemctl start nemord.service
```

Stop it with `systemctl stop nemord.service`. SIGTERM is used and the
unit allows 30 seconds for clean session closure.

For manual removal, first stop the service, then remove the installed binary,
configuration, and unit. Run `systemctl daemon-reload` after removing the unit.
The state database is under `/var/lib/nemor`; remove that directory only
when its historical host/session records are no longer needed. The unit is not
enabled automatically, so no enable/disable action is part of Phase 2.

## Limitations

Phase 2 intentionally does not implement:

- policy decisions or a pressure state machine;
- memory actuators or automatic actions;
- kernel, sysctl, cgroup, zram, zswap, DAMON, or KSM changes;
- AI training, inference, or model activation;
- benchmarks;
- safe, gaming, or capacity operating profiles.

The classifier is heuristic, versioned `heuristic-v1`, and deliberately permits
an uncertain outcome rather than inventing `idle`. Real foreground and
Steam/Proton/Gamescope accuracy, false-positive/negative rates, classifier
overhead, daemon memory use, and long-session behavior remain to be validated on
CachyOS.
