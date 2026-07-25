# Deterministic workload classification

## Taxonomy

Phase 2 separates process category, activity relation, and session workload.
Process categories are `unknown`, `system`, `critical`, `desktop`, `browser`,
`development`, `game`, `virtualization`, and `background`. Activity is
`foreground`, `background`, or `unknown`.

The nine workload classes are `idle`, `desktop`, `browser_heavy`,
`development`, `gaming`, `gaming_background_heavy`, `virtualization`,
`memory_pressure`, and `critical_pressure`. An uncertain result is an outcome,
not a tenth class: it is not persisted and is never silently converted to
`idle`.

## Identity and privacy

Identity uses a normalized executable path when available, `/proc/<pid>/stat`
comm as fallback, parent/ancestry, cgroup context, and start ticks. PID is not a
permanent catalog identity. `command_signature` is SHA-256 over the centralized
versioned representation `nemor-process-identity-v2`, identity kind, and
normalized path or fallback basename. Trusted system paths may be stored;
untrusted/home paths are persisted only as `private:<basename>` while their
normalized path contributes only to the one-way hash. Full command lines and
environments are never read; arguments and personal directory paths are absent
from persisted identity text and explanations.

A temporary unknown observation cannot overwrite a stable catalog category.
Configured rules accept exact executable basenames only: paths, regexes, globs,
and scripts are rejected.

## Foreground and gaming

The strongest portable foreground detector compares process group with TTY
foreground process group. Gamescope ancestry may confirm a game child.
Unavailable evidence yields `unknown`, never `background`. There is no GUI
scraping. Detector confidence is explicit: TTY group matches are strongest,
Gamescope support is high-confidence contextual evidence, and unavailable
evidence has zero confidence.

Gaming evidence may include an exact configured native executable, Steam AppID
cgroup context, Steam ancestry, Proton/Wine combined with Steam context, or a
non-helper child under Gamescope. Steam, Wine, or Proton alone are insufficient.
Known browsers remain browsers even below Gamescope.

Every confirmed game is protected. The invariant
`is_game || protected_game => cold_candidate == false` is unconditional.
Critical, unknown, and confirmed foreground processes are also protected and
never cold candidates.

## Confidence, precedence, and stabilization

Rules are deterministic and versioned `heuristic-v1`. Confidence is
`0.0..=1.0`; the default minimum is `0.65`. Browser-heavy requires both process
count and memory share. Development requires multiple development tools, so a
shell alone is insufficient. Virtualization requires a known VM runtime and a
quantitative memory share; containers are not automatically VMs.

Pressure uses Phase 1 `MemAvailable` and memory PSI against configured
thresholds. It does not implement a policy pressure state machine. Precedence
is:

1. `critical_pressure`
2. `memory_pressure`
3. `gaming_background_heavy`
4. `gaming`
5. `virtualization`
6. `browser_heavy`
7. `development`
8. `desktop`
9. `idle`

Rejected candidates remain in the explanation. Non-critical changes require the
configured number of consecutive observations; critical pressure is immediate.
Re-observing the current class creates no duplicate event.

## Explanation model

Each persisted explanation contains `rule_version`, selected class, confidence,
stable evidence code/description/observed value/threshold/contribution, rejected
candidates, and non-sensitive protection reasons. Serde produces the JSON. No
full command line, environment, network observation, or personal path is
included.

## Limits and CachyOS validation

Basename heuristics can produce false positives for unrelated programs with the
same name and false negatives for renamed or newly packaged applications. TTY
evidence does not cover every graphical desktop, and Gamescope/Steam/Proton
layouts vary by launcher and release.

Real desktop foreground accuracy, Steam/Proton/Gamescope gaming accuracy,
application false-positive/negative rates, classifier overhead, and behavior
over real CachyOS sessions remain `CACHYOS VALIDATION PENDING`.
