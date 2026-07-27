# Phase 6 tiering

Phase 6 models `RAM -> zswap compressed cache -> disk-backed swap` without
turning the normal daemon into a privileged mutation service. The production
default remains `mode = "observe"` and `[tiering].dry_run = true`.

## Backend model

`ZRAM` and `ZSWAP_NVME` are different backends. Zram is compressed RAM acting
as swap; zswap is a compressed cache in front of a real backing swap device.
Eviction from zswap writes to backing swap. Disabling new zswap stores does not
empty the existing pool, and changing compressor does not recompress pages
already stored.

`nemor-tiering` owns capability inventory, swapfile and storage validation,
pool planning, block accounting, write budgets, TBW estimates, deterministic
backend recommendations, transactions, recovery and boot-plan generation. It
does not duplicate the zram backend, actuator, classifier or policy engine.

## CachyOS inventory

The Phase 6 development host runs CachyOS with kernel `7.1.4-1-cachyos`.
Zswap is supported but disabled by the active kernel command line. The current
parameters are discoverable dynamically; unavailable parameters remain
`None`. The CachyOS vendor udev rule that disables zswap when the generated
zram device appears is reported as a provider conflict.

The live root is Btrfs on a non-rotational SATA SSD. It is not classified as
NVMe. `/dev/zram0` is an external, protected systemd-generator device and is
never used as proof of the requested NVMe tier.

No hardware serial, machine identifier, hostname or user name is persisted.

## Swapfile safety

Candidates must be absolute and normalized, must not be symlinks, and must
remain in the closed Nemor namespace. Existing or external swapfiles are never
adopted automatically. Ext4 and Btrfs have separate validation models;
unknown filesystems are blocked. Btrfs creation uses its swapfile-specific
helper so NOCOW, preallocation and hole constraints are enforced by the
filesystem.

The Linux transaction uses only allow-listed executables with separate argv,
timeouts and verified exit status. It performs create/format, activation,
`/proc/swaps` verification, deactivation and removal only for a file registered
as Nemor-owned in the same run. Existing swaps must remain available at every
checkpoint.

## Storage metrics and write budget

Linux block statistics are parsed dynamically. Sector counters are always
converted with 512 bytes per sector, independently of device block size.
Reset, wrap and device changes invalidate a delta.

Zswap logical writeback, physical block-device deltas, benchmark-attributable
writes and host background noise are distinct evidence sources. The live
privileged validation observed a 4096-byte physical-device delta; it is
reported as host-wide and is not claimed as NAND-attributable.

Budgets cover instantaneous MiB/s, rolling minute, rolling hour and daily GiB.
Exceeding a budget blocks new write-increasing actions and shrinker escalation;
it never disables an active swap. Annual writes use decimal TB/year. Rated TBW
and endurance percentage are only computed when the user supplies a rating.

## Pool planning and selection

Conservative, gaming and capacity intents generate deterministic plans from
the algorithms and pools actually exposed by the kernel. Pool percentage
bounds are configuration-controlled. The shrinker defaults to preserved/off
and requires a real zswap+NVMe backend, metrics, budget headroom, benchmark
evidence, non-severe pressure, no gaming and rollback readiness.

The selector compares the validated zram baseline with real zswap+NVMe
evidence. Missing evidence, gaming, severe pressure, unknown or slow storage,
or excessive writes select the current zram backend. A zswap candidate requires
measured NVMe-backed evidence and safety headroom. No machine learning is used.

## Observe mode and CLI

The observe pipeline inventories capabilities and topology, records a tiering
audit snapshot, and produces a recommendation. It makes zero swapfile, sysfs,
boot or udev mutations.

Read-only commands:

```text
nemorctl tiering status [--json]
nemorctl tiering recommend [--json]
nemorctl tiering report latest [--json]
```

There is intentionally no normal `tiering apply` command.

## Live-safe privileged validation

The separately compiled validation harness supports `--tiering`. On 2026-07-27
it created a bounded 64 MiB Btrfs swapfile under `/var/tmp`, activated it while
the protected `/dev/zram0` remained active, measured the physical block counter,
recovered ownership with a fresh backend instance, rolled back, repeated
rollback idempotently and removed the file.

The report recorded exit code zero, no errors, no swap/cgroup/process residue,
and structurally identical protected zram state. It did not enable zswap or
change boot configuration.

## Boot plan and remaining validation

Boot plans are serializable recommendations only. They identify the provider,
backing swapfile, kernel parameters, `/etc` overrides, checksums, backups,
post-reboot checks and rollback. They always require explicit user approval,
never target `/usr/lib`, and are not applied by the daemon.

A real zswap+NVMe benchmark cannot be demonstrated on the current SATA host or
inside the current desktop boot. Dedicated boot validation remains pending. It
requires separate approval before any persistent change and must validate pool
readback, zswap writeback, bounded workload evidence, rollback and restoration
of the CachyOS baseline.
