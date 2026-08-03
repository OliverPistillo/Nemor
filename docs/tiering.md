# Phase 6 tiering

Phase 6 models `RAM -> zswap compressed cache -> disk-backed swap` without
turning the normal daemon into a privileged mutation service. The production
default remains `mode = "observe"` and `[tiering].dry_run = true`.

## Backend model

`ZRAM` and `ZSWAP_STORAGE_BACKED` are different backends. Zram is compressed RAM acting
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

The v1 storage-profile contract distinguishes NVMe, SATA, SAS, USB, other
non-rotational, rotational, composite, virtual and ambiguous storage from
transport, rotational, complete parent/slave-chain and filesystem evidence.
Model or device-name strings alone never establish a profile. Device identity
is evidence-bound for validation; normal telemetry does not persist machine or
user identity.

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

The v2 selector compares a same-host validated zram baseline with real
profile-bound zswap+storage evidence. Missing evidence, gaming, severe
pressure, unsupported storage,
or excessive writes select the current zram backend. A zswap candidate requires
measured latency, backing writes, cleanup and restore, matching source and
environment identity, and safety headroom. SATA and NVMe evidence are not
interchangeable. Historical serialized `zswap_nvme` values remain readable but
cannot authorize a v2 decision. No machine learning is used.

## Observe mode and CLI

The observe pipeline inventories capabilities and topology, records a tiering
audit snapshot, and produces a recommendation. It makes zero swapfile, sysfs,
boot or udev mutations.

Read-only commands:

```text
nemorctl tiering status [--json]
nemorctl tiering recommend [--json]
nemorctl tiering report latest [--json]
nemorctl tiering boot-contract [--json]
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

## Validation-only boot contract

`tiering-boot-validation-v1` and `tiering-boot-validation-v2` remain readable
historical schemas and never authorize mutation. V1 trusted caller-supplied
authority. V2 added host preparation and durable transactions but failed
static acceptance because its unit executed a user-controlled path, activation
was not stage-bound, recovery could reset a failed stage, and its workload
metrics were not sufficiently attributable.

`tiering-boot-validation-v3` is a new authority. Unprivileged `prepare`
derives an unambiguous SATA or NVMe topology, complete boot/ESP identity,
known-good Type #1 entry, source/config/binary hashes, exact artifact paths and
a typed staged-binary plan. Type #2 UKI still fails closed. Preparation is
read-only apart from its fresh private manifest directory.

The first authorized root stage creates the allow-listed hierarchy one
component at a time and stages the exact validator bytes at
`/var/lib/nemor/validation/phase6/<id>/bin/`. The destination is create-new,
root:root, mode 0755, single-link, hash/embedded-commit verified and fsynced.
Every service and bounded worker executes only this staged path. It remains
until the baseline boot is fully proven.

A separately authorized `measure-baseline` stage seals a same-validation,
same-source, same-environment zram workload record before loader entry, unit,
swapfile or zswap mutation. Apply then creates only the exact Btrfs swapfile,
Type #1 clone and marker-conditioned unit. The experimental entry preserves
the frozen kernel/initrd identities and changes only its options. It never
edits `/etc/fstab`, `/etc/kernel/cmdline` or `/usr/lib`.

Activation requires the selected entry, new boot ID, marker, staged helper,
unit cgroup, default, BootOrder and inactive swap UUID. Durable stages record
intent and readback for zswap disable, every allowed parameter, zswap enable
and exact swapon. Partial failure preserves the primary error, records
secondary cleanup errors, restores the current-boot baseline where safe and
selects the baseline one-shot.

Post-boot results cannot be supplied by a caller. The staged worker performs a
ready/start/terminal handshake and reports exact PID/start-ticks, cgroup path,
progress, deterministic content integrity, bytes touched, service latency,
refault content, scoped `memory.events`, memory/swap peaks and PSI where
available. Zswap and physical counters are pre/post deltas; host-wide physical
writes are labelled noisy and cannot authorize a recommendation. Actual
nemord identity/effective ExecStart and production-unit absence accompany the
configuration evidence.

Rollback proves the full baseline before deleting any artifact. Recovery is
defined for activation and measurement stages, reconciles a stale atomic
`.new` file only when it is an integrity-valid monotonic successor, never
rewrites Failed to an unaudited prior stage, and seals a recovery ledger.
Terminal STATUS/SHA256SUMS use exact required membership, safe relative names,
single-link root-owned regular files and strict SHA-256 grammar.

Version decisions are explicit: boot authority, prepared manifest, durable
transaction, preflight, activation, post-boot, final restore and recovery are
v3; same-host zram baseline is v2; profile evidence is v3; the workload
protocol is v1. Storage profile v1 and tiering rule v2 are unchanged, as are
historical `zswap_nvme` deserialization and normal telemetry schemas.

A real zswap+SATA boot benchmark has not been performed, and this host cannot
demonstrate NVMe. V3 remains pending independent static acceptance before any
manifest preparation or boot mutation. Production activation is false.
