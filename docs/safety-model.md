# Phase 2 safety model

The only valid mode is exactly `observe`.
`general.allow_automatic_actions`, `ksm.enabled`, and `damon.enabled` must all be
false, while `damon.mode` must remain `monitor_only`. Invalid values stop startup
before the database or a session is created.

There is no actuator crate, trait, command, or alternate profile. Production
collection opens Linux telemetry files with read-only standard-library calls.
It enumerates `/proc` and `/sys/block` and reads `/proc/<pid>/exe` links, but
never opens a kernel interface for
write, never mounts debugfs, and has no fixture override in the installed
daemon. Nothing writes `/proc`,
`/sys`, cgroupfs, sysctl, zram, zswap, DAMON, KSM, or any kernel parameter.

The systemd unit uses a dynamic unprivileged user, an empty capability and
ambient-capability set, no-new-privileges, a strict read-only filesystem, and a
single writable state directory. Home, devices, kernel modules, kernel tunables,
and cgroups are protected, and IP networking is denied. This privilege model
must be explicitly reconsidered before a future actuator or cgroup feature;
Phase 2 grants no dormant privilege for them.

Classification is data-only. It cannot signal a process, change priority,
reclaim memory, create a cgroup, or write a kernel setting. Unknown identities,
critical processes, confirmed games, and confirmed foreground processes are
protected in the model. The invariant
`is_game || protected_game => cold_candidate == false` is enforced directly;
critical and unknown identities are also never cold candidates.

No full command line or environment is read. Persistent signatures are SHA-256
over a versioned normalized executable basename, never arguments or personal
directory names. Explanations contain stable codes and aggregate observations,
not raw sensitive strings.

Configuration, metadata, migration, and session errors are returned with
context. The daemon reports them and exits nonzero; it does not panic in its
normal control flow. A session is marked clean only after the closure
transaction commits.

Manual uninstallation may remove the binary, unit, and configuration. Historical
data is isolated under `/var/lib/nemor` and can be removed separately
when retention is no longer desired. Retention affects only telemetry rows in
the configured SQLite database. There is no kernel-parameter rollback in Phase 2
because no kernel parameter is ever changed.
