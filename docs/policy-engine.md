# Deterministic policy engine

Phase 4 adds a pure rule-based decision layer. It consumes normalized
telemetry and classifications; it never reads `/proc`, `/sys`, a clock, or the
network. The caller supplies logical time, so equal state, input, history and
time produce byte-identical serialized decisions.

The states are `NORMAL`, `WATCH`, `PRESSURE`, `CRITICAL`, `EMERGENCY`, and
`STABILIZING`; they are independent of Phase 2 workload classes. Escalation is
held for `state_hold_seconds`. An emergency jump requires critically low
available memory plus emergency full-memory PSI or multiple severe signals.
Recovery requires `recovery_hold_seconds` before `STABILIZING`, then another
complete hold before `NORMAL`. Candidate state/time prevents threshold flap.
Restart without trustworthy continuity begins conservatively in `WATCH`.

`PolicyInput` contains RAM/swap facts, available percentage, memory PSI,
workload class/confidence, gaming/foreground/protection aggregates, cgroup
capabilities, actuator state, and bounded history counts. Missing metrics stay
`null`. Cumulative swap, major-fault, pgscan and pgsteal counters become rates
from consecutive samples. First sample, reset, zero interval, or missing input
yields an unavailable rate; irregular intervals use their actual duration.
Invalid, non-finite, negative, impossible, or time-regressing input is rejected.
Insufficient input retains state and emits no mutation.

The policy version is `nemor-policy-v1`; its rules are
`pressure-rules-v1`. Serde decisions contain their feature snapshot, evidence,
thresholds, candidates, plans, rejections, and reasons. `model_version`,
expected gain, and expected cost remain `NULL`; Phase 4 contains no ML.

The closed action vocabulary is `NoAction`, `PrepareForegroundProtection`,
`ProtectForeground`, `ApplyBackgroundSoftLimit`, and
`RollbackCgroupMeasures`, plus `SelectZramProfile` with exactly
`safe`/`gaming`/`capacity`. The latter is a non-mutating intent; `nemor-zram`
performs its own evidence, ownership, headroom and pressure validation.
Unsupported actions are structured rejections.
There is no zswap tuning, sysctl, reclaim, freezer, process signal,
`MemoryMax`, `MemorySwapMax`, KSM, DAMON, or future placeholder.

Policy expresses intent; concrete targets still pass the Phase 3 actuator’s
stable identity allow-list, PID/start-tick, classification, ownership, and
memory bounds. Unknown processes are rejected in every state. Gaming does not
mask pressure, but games remain protected and cannot become background.

The only public mode remains `observe`. Evaluation reaches feature extraction,
transition, planning, validation and audit, then stops before actuator apply.
No unit creation, property write, PID move, rollback write, or mutating D-Bus
call occurs.

`policy_decisions` records the first decision, state/action-audit changes, and
a configured heartbeat. Identical audits are deduplicated deterministically.
`action_results` receives no simulated successes. History reads are capped at
100 rows. `nemorctl policy status` and `policy latest` are read-only.

Normal selects safe/current, gaming selects the gaming intent without allowing
a risky live switch, pressure may request capacity analysis, and
critical/emergency/stabilizing retain safe/current. Observe stops after typed
planning and persistence. No learning system or Phase 6 mechanism is present.
