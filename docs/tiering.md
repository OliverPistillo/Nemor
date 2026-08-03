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

`tiering-boot-validation-v1` is retained only as failed historical source. Its
caller-supplied manifest/evidence paths, self-consistent artifact strings and
caller-supplied post-boot booleans never authorize a v2 transaction.

`tiering-boot-validation-v2` adds separate prepared-manifest, durable
transaction, preflight, apply, one-shot, post-boot and final-restore schemas.
Unprivileged `prepare` takes bounded inputs, reads the host, verifies the clean
source and embedded release identity, requires an unambiguous SATA or NVMe
topology with stable physical and filesystem identities, parses a known-good
systemd-boot Type #1 entry and derives a create-new entry. Type #2 UKI and
EFI-only entries fail closed because no binary UKI builder is authorized.

The experimental Type #1 entry preserves the known-good kernel and initrd
hashes and changes only its frozen options. Those options carry an exact
validation marker, exact zswap parameters and an entry-scoped `systemd.wants`
unit. The unit runs only with that marker, waits for CachyOS zram setup,
reapplies and reads back the exact zswap state, keeps protected zram as the
fallback, and activates the pre-created validation swap at a higher priority.
The baseline entry does not request the unit. No `/etc/fstab`,
`/etc/kernel/cmdline` or `/usr/lib` file is edited.

Authenticated root stages require exact `SUDO_UID` and `SUDO_GID`. Apply first
creates a mode-0700 root transaction under
`/var/lib/nemor/validation/phase6/<validation-id>`, persists the sealed
manifest and root preflight, then records and fsyncs each mutation intent and
completion. Mutating stages accept only the validation ID and derive evidence
and artifact paths from that transaction. Partial apply preserves its primary
error, attempts only reverse exact-owned cleanup and records secondary errors.

One-shot selection requires `bootctl` readback and rechecks the permanent
default and firmware BootOrder. Post-boot validation accepts no result JSON:
it collects the boot ID, entry, command line, zswap/zram/swap identities,
storage topology, counters, bounded workload, physical writes, safety state
and observe-only production configuration itself. Rollback preserves all
artifacts until a different baseline boot proves the full command line,
zswap, zram, swap set, default, BootOrder and one-shot baseline. Recovery is
stage-aware and idempotence verification does not share its mutation path.

Profile recommendation now requires matching versioned same-host zram and
storage-backed evidence, including source, environment, topology, workload,
safety, cleanup, final restore and archive identities. Historical generic
benchmark evidence remains readable but cannot authorize SATA or NVMe.

Version decisions are explicit: the boot contract and its prepared,
transaction, preflight, apply, post-boot and final-restore evidence are v2;
profile benchmark evidence is v2 and same-host zram baseline evidence starts at
v1. Storage profile v1 is unchanged because its serialized class meanings did
not change. Tiering rule v2, historical `zswap_nvme` deserialization and normal
telemetry/report schemas are also unchanged. None of those historical schemas
is reinterpreted as v2 boot authority.

A real zswap+SATA boot benchmark has not yet been performed, and this host
cannot demonstrate NVMe. The v2 source remains pending independent static
acceptance before even manifest preparation. Dedicated profile-specific boot validation remains pending. It
requires separate approval before any persistent change and must validate pool
readback, zswap writeback, bounded workload evidence, rollback and restoration
of the CachyOS baseline.
