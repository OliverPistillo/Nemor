# Cgroups v2 foreground protection

Phase 3 adds controlled cgroup v2 primitives without changing Nemor's public
operating mode. The production default remains `mode = "observe"` with
`cgroups.enabled = false`, `dry_run = true`, and `allow_move = false`.
Observe mode always forces a dry-run plan and performs no directory creation,
property write, PID migration, transient-unit call, rollback mutation, or
cleanup.

## Topology and ownership

Nemor recognizes only these managed groups:

```text
nemor-foreground.slice
nemor-background.slice
nemor-test-<sanitized>.scope
nemor-validation-<sanitized>.scope
```

They are separate from `nemord.service`, so stopping the daemon cannot kill
managed applications. Names are internally fixed or strictly sanitized.
Nemor refuses ownership of `system.slice`, `user.slice`, session slices,
Steam/Gamescope units, and external groups.

The Linux backend supports a delegated writable cgroup v2 hierarchy directly.
It does not shell out to `systemctl`, `systemd-run`, or `busctl`. The current
observe-only service is deliberately not granted delegation or broad
privileges. A future explicitly authorized deployment may use a dedicated
systemd D-Bus integration or delegation, but that privilege decision is not
enabled by the Phase 3 default unit.

## Planning and authorization

Every `CgroupPlan` records stable catalog identity, PID, start ticks, original
and target groups, requested properties, reason, allow/block reasons, and
dry-run state. Authorization uses the Phase 2 SHA-256 identity allow-list,
never PID alone. Identity, PID, start ticks, and current classification must
all agree.

Unknown processes are never movable. Without an explicit identity allow-list
entry, foreground, protected, game, critical, and background candidates are
all blocked. With authorization, recognized protected workloads target the
foreground group and confirmed non-protected background workloads target the
background group.

## Memory properties

Foreground protection uses only `memory.low`. It is calculated from total RAM,
current protected workload memory, configured headroom, and configured
minimum/maximum percentages. It is capped below total RAM.

Background limiting uses only `memory.high`. It reserves foreground
protection and minimum headroom, then applies configured conservative bounds.
Phase 3 never requests `memory.max`, `memory.swap.max`, `memory.reclaim`,
freezer, CPU/IO weights, nice levels, or OOM score changes.

## Apply, snapshot, verification, and rollback

The mutation sequence is:

```text
inspect → validate identity/starttime → persist snapshot
→ apply one operation → read back → verify → persist result
```

Migration `0004_cgroups.sql` stores the original placement, target, original
and requested properties, session owner, catalog identity, PID/start ticks,
verification state, rollback state, and errors. It does not add a Phase 4
policy decision.

Rollback restores placement only when PID/start ticks still match, restores
previous properties, and removes only empty Nemor-owned groups. A terminated
or reused PID is left untouched. Missing or ambiguous external groups are not
adopted or deleted. Rollback is idempotent and sends no process signals.

Crash recovery replays pending snapshots conservatively. It is safe to retry:
completed rollbacks disappear from the pending set, while ambiguous state is
left intact for read-only status and safety reporting.

## Backends and validation

The simulated backend provides deterministic capability, failure injection,
readback, rollback, recovery, ownership, and observe-invariant tests. It is a
Rust test utility and cannot be selected by production configuration.

The Linux backend performs real capability inspection of CachyOS cgroup v2.
The dedicated privileged harness validated create, `memory.low`,
`memory.high`, child attachment, readback, rollback, idempotence, and
cross-process recovery on temporary `nemor-validation-*` groups. Normal daemon
mutations still require a complete memory interface and writable hierarchy;
the default service has neither delegation nor mutation enabled.

`nemorctl cgroups status [--json]` is read-only and reports capabilities,
configuration, backend, managed state, pending rollback, stale recovery state,
and the latest relevant safety error. There is intentionally no CLI apply
command.

Phase 4 can request foreground protection or a background soft limit, but
cannot bypass this design. Concrete targets still pass identity,
PID/start-tick, classification, ownership, and bounds checks. In `observe`,
policy records a rejection and never calls apply. Phase 3 continues to supply
authorized primitives, plans, persistence, verification, and recovery.
