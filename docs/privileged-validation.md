# Privileged validation on CachyOS

Date: 2026-07-27

## Environment and scope

The Phase 3 and Phase 5 mutation paths were validated natively on CachyOS
Linux (`x86_64`), kernel `7.1.4-1-cachyos`, against baseline commit
`fcb21a9f9423496f25397cf89b5868d55c961df8`. Hostname, user name, machine ID,
home paths, and unrelated process data are omitted.

This was a validation gate, not a new functional phase. Phase 6, zswap, NVMe,
writeback, persistent configuration, system services, existing cgroups, and
real user workloads were outside scope and untouched. The daemon remains
observe-only by default.

## Privilege and ownership model

The harness is the dedicated
`nemor-test-support` binary `nemor-privileged-validation`. It is compiled as
the ordinary user and only the resulting binary is executed with root
privileges. Its public modes are `--preflight`, `--cgroups`, `--zram`, and
`--all`; it is not exposed by `nemorctl`.

The privileged surface is closed:

- cgroups must match `nemor-validation-*.scope`;
- PIDs must be children created and registered by the same run, with matching
  start ticks and identity;
- zram devices must be returned by `zram-control/hot_add` in the same run and
  absent from the baseline;
- `/dev/zram0` is always external, protected, and ineligible for ownership;
- helpers are fixed absolute executables with separate validated arguments and
  timeouts; no shell, arbitrary command, path, PID, or device is accepted;
- global execution is bounded to 180 seconds;
- guards perform ownership-checked cleanup on errors, with a final independent
  host comparison;
- the structured report is written atomically to
  `/tmp/nemor-privileged-validation-report.json`.

## Host baseline

The baseline contained one zram device and one swap backend:

| Property | Value |
|---|---|
| Device | `/dev/zram0` |
| Provider/ownership | systemd generator / external protected |
| Active swap | yes |
| Priority | 100 |
| Disksize | 16,640,901,120 bytes |
| Algorithm | `zstd` |
| Memory limit | 0 |
| Test cgroups/processes | none |

The root cgroup v2 controller list included `memory`. No existing cgroup
topology was restructured.

## Phase 3 real cgroup validation

A bounded validation child was created with PID and start ticks recorded
before mutation. Its original placement was snapshotted. On an exclusively
temporary `nemor-validation-*.scope` group, the real Linux actuator:

1. created the group;
2. wrote and read back `memory.low = 4,194,304`;
3. wrote and read back `memory.high = 8,589,934,592`;
4. attached the registered child and verified it in `cgroup.procs`;
5. restored the child's original placement;
6. restored properties and removed the empty group;
7. accepted a second rollback as an idempotent no-op.

The harness also proved before mutation that an unregistered PID, identity
mismatch, start-tick mismatch, unknown candidate, critical candidate without
allow-list, and game candidate without allow-list are rejected. Only the
registered validation child was accepted.

For restart recovery, worker A created a separate child and cgroup, persisted
the actuator snapshot, and exited without normal cleanup. Worker B loaded the
snapshot through a fresh backend/store instance, restored placement and
properties, removed the group, and terminated only the registered child.
A second recovery found no pending work and was harmless.

Result:

```text
FASE 3 — VALIDATA SU CACHYOS
```

## Phase 5 real isolated benchmark

The harness hot-added an isolated 64 MiB device absent from the baseline,
selected supported `zstd` before initialization, wrote the bounded disksize,
and verified algorithm, disksize, and initstate. It used three deterministic
16 MiB datasets and three measured rounds per dataset. Reads matched every
written dataset.

Median real measurements:

| Dataset | Write throughput | Read throughput | Wall time | CPU time | Logical ratio | Effective ratio | Allocator efficiency |
|---|---:|---:|---:|---:|---:|---:|---:|
| Highly compressible | 2.91 GB/s | 6.96 GB/s | 5.76 ms | 7.96 ms | n/a | n/a | n/a |
| Medium | 1.31 GB/s | 6.34 GB/s | 12.77 ms | 15.89 ms | 102.4 | 80.31 | 0.784 |
| Deterministic incompressible | 428.94 MB/s | 7.27 GB/s | 39.11 ms | 40.78 ms | 1.0 | 1.0 | 1.0 |

For the highly compressible repeated-page dataset, zram reported zero
compressed and allocated bytes, so zero-safe ratios correctly remained null
instead of producing infinity. CPU time came from the kernel's process
scheduler runtime counter. Results are host-specific validation evidence, not
general performance claims.

## Phase 5 swap transaction and recovery

Two fresh 64 MiB devices, A and B, were created and registered as
Nemor-owned. Checkpoints from `/proc/swaps` proved this sequence:

1. protected `/dev/zram0` active;
2. A initialized, activated, and verified alongside `zram0`;
3. B initialized, activated, and verified alongside A and `zram0`;
4. A deactivated only after B was ready;
5. B and `zram0` remained active;
6. test swaps were deactivated, reset, and hot-removed.

Thus a valid swap backend was continuously available, `zram0` was never
deactivated, and replacement-first/no-swap-loss behavior was exercised on the
real kernel.

For restart recovery, worker A hot-added, configured, and activated another
registered test device, persisted ownership, and exited without cleanup.
Worker B recovered only that absent-at-baseline device, performed swapoff,
reset, and hot-remove. Repeating recovery was a no-op.

Result:

```text
FASE 5 — VALIDATA SU CACHYOS
```

## Cleanup and final host comparison

The final structured snapshot matched the baseline topology:

- `/dev/zram0` remained present, active at priority 100, with the same
  disksize, algorithm, initstate, memory limit, provider, and ownership;
- no test swap or extra zram device remained;
- no `nemor-validation-*` cgroup or child remained;
- no persistent file, unit, service, sysctl, or kernel feature was configured.

The used KiB value of the active system swap changed naturally during the run
and is deliberately not an identity criterion. `mm_stat` equality is likewise
not required.

An initial validation attempt exposed a bounded cleanup retry issue after the
raw benchmark. The report proved the extra device's ownership; the closed
report-driven recovery mode removed it, and an independent read-only check
confirmed baseline restoration before the successful full rerun. No external
resource was touched.

## Residual limitations

The validation proves the privileged primitives through a dedicated test
harness; it does not enable general daemon mutation. The default service has
no cgroup or zram mutation privileges. Live Steam/Proton/Wine/Gamescope
coverage remains separate. Phase 6 development and live-safe validation are
complete, while dedicated boot validation with real zswap+NVMe remains
pending.

## Phase 6 live-safe validation

On 2026-07-27 the release harness `--tiering` completed with exit code zero.
It inventoried supported-but-disabled zswap read-only, resolved Btrfs on a
non-rotational SATA SSD, created and activated a 64 MiB Nemor-owned temporary
swapfile while `/dev/zram0` remained active, recorded a host-wide 4096-byte
physical block write delta, recovered with a fresh backend, rolled back twice
idempotently and removed all resources. Baseline and final swap topology and
protected zram structure were identical.

This proves the live-safe swapfile lifecycle and accounting path, not the full
zswap+NVMe backend. Dedicated boot validation remains pending and requires
separate explicit approval.

## Phase 7 monitor-only validation

The `--damon` path completed successfully on CachyOS
`7.1.4-1-cachyos`. It owned only a synthetic child, temporary DAMON sysfs
objects, an isolated tracefs instance and run-scoped report/dataset files.
The final `vaddr` session captured nine complete aggregation windows with HOT
1.0, WARM about 0.2611 and COLD zero. Monitor CPU stayed below the 1% budget;
synthetic target slowdown was about 3%.

Readback proved three initial target regions and `nr_schemes=0`. Stop, cleanup,
crash recovery and a second idempotent recovery restored the structural host
baseline. No external session, `/dev/zram0`, zswap/tiering state, persistent
configuration or boot setting was changed.
