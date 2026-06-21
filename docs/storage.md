# Storage

litevirt provisions VM disks through a pluggable Driver interface. Each
*pool* is a (driver, source, target, options) tuple declared in compose
or the host config; every VM disk references a pool by name.

## Drivers

| Driver | Source | Target | Notes |
|---|---|---|---|
| `local` (default) | unused | dir override | qcow2 files under `<dataDir>/disks` |
| `dir` | unused | required | qcow2 files in an arbitrary directory (e.g. an externally-mounted SAN LUN) |
| `nfs` | `host:/export` | mountpoint override | mounted lazily by the daemon; survives restarts |
| `iscsi` | IQN | unused | LUNs are pre-provisioned on the SAN; we discover and login |
| `ceph` | pool name | unused | `rbd` CLI shell-out; CGO-free build supported |
| `zfs` | parent dataset (`tank/litevirt`) | unused | zvol per disk; `volblocksize` tunable via options |
| `btrfs` | absolute path on btrfs | unused | one subvolume per disk; qcow2 inside |
| `lvm-thin` | volume group | unused | `options.thinpool` is required; one thin LV per disk |

`SupportedDrivers` in `internal/storage/storage.go` is the authoritative
list; adding a new backend is one entry there plus a per-driver file
implementing the `Driver` interface.

## Pool management

Pools can be declared statically in `/etc/litevirt/config.yaml` under
`storage_pools:` (see [configuration.md](configuration.md)) OR added
at runtime via the `lv pool` CLI:

```bash
# Register a new NFS pool — the daemon runs Prepare() (mount, ping,
# fs check) before persisting, so a misconfigured pool fails fast
# instead of at first VM create.
lv pool create warm \
    --driver nfs \
    --source nas.internal:/srv/exports/litevirt \
    --target /mnt/litevirt-warm \
    --option options=vers=4.2,hard,intr

lv pool ls
# HOST       NAME    DRIVER  SOURCE                                  TARGET                  STATE
# host-a     warm    nfs     nas.internal:/srv/exports/litevirt      /mnt/litevirt-warm      active
# host-a     default local                                           /var/lib/litevirt/disks active

lv pool inspect warm
lv pool delete warm
```

`--option k=v` is repeatable for driver-specific flags (Ceph keyring
paths, ZFS volblocksize, iSCSI portal addresses, …). The full
schema lives in `internal/storage/storage.go`'s `Config.Options` —
each driver pulls its own keys out of the map.

`lv pool delete` soft-deletes the row from cluster state. The
driver is asked to tear down (unmount NFS, log out of iSCSI) on a
best-effort basis but failure does not block the delete — operators
who hit "rm" likely want the pool gone regardless. The underlying
mount, if any, stays until manually cleaned up.

## Compose example

```yaml
volumes:
  hot:
    driver: zfs
    source: tank/litevirt
    options:
      volblocksize: 16k
      compression: lz4

  warm:
    driver: nfs
    source: nas.internal:/srv/exports/litevirt
    target: /mnt/litevirt-warm
    options:
      options: vers=4.2,hard,intr

vms:
  web-1:
    image: ubuntu-24.04
    disks:
      root: { size: 40G, volume: hot }
      data: { size: 200G, volume: warm }
```

## Storage motion

Move a VM's disk to a different pool on the same host:

```
lv move-volume web-1 root warm --delete-source
```

**Stopped VMs** — `qemu-img convert` between source and destination,
then atomic DB pivot.

**Running VMs** — libvirt `BlockCopy` mirrors writes into
the destination while the VM keeps running, then `BlockJobAbort PIVOT`
swaps the source file atomically. Operator-visible downtime: zero.
The orchestrator preallocates the destination, polls progress every
~250 ms, cancels on context-cancel or pivot failure, and updates the
disk record only after a successful pivot.

> **Note:** `lv replicate-volume`'s copy step uses `qemu-img convert`, which
> needs the source disk quiescent — replicate a **stopped** VM (or a disk no
> running VM holds open), otherwise the convert fails on the disk lock. Online
> `move-volume` has no such restriction: it mirrors via libvirt `BlockCopy`
> while the VM keeps running.

Both paths support file-based pools (local / nfs / dir / btrfs).
Block backends use Replication below.

### Migrating a whole stack

`lv stack migrate-volumes` moves every disk of every VM in a stack to a
different pool. It orchestrates the per-disk `move-volume` primitive: it
enumerates the stack's VMs, resolves a target pool per disk, runs a
preflight, then rolls the moves out **one VM at a time** by default so a
stateful service (e.g. a 3-node postgres cluster) keeps serving. Each per-disk
move is dispatched to the VM's owning host, so a stack spread across hosts is
handled in one command.

```
# Whole stack to one pool:
lv stack migrate-volumes postgres --to fast

# Per-VM / per-disk overrides (most-specific wins: vm/disk > vm > --to):
lv stack migrate-volumes postgres --to fast \
    --map pg-1/data=archive --map pg-2=warm

# Preview the resolved plan without moving anything:
lv stack migrate-volumes postgres --to fast --dry-run
```

- **Online by default** — running VMs migrate via blockdev-mirror (no
  downtime); stopped VMs use the offline convert path. The choice is per VM,
  based on its state.
- **Rolling** — `--parallel 1` (default) migrates one VM at a time and
  health-gates between VMs; raise `--parallel N` for stateless stacks. Use
  `--order replica-1,replica-2,primary` to fix the sequence.
- **Preflight** validates, before any data moves, that each target pool exists
  on the VM's owning host and that source + target are file-based pools;
  capacity shortfalls are surfaced as warnings. Block-driver pools
  (ceph/zfs/iscsi/lvm-thin) are rejected — use Replication below.
- **Resumable** — disks already on their target pool are skipped, so a run that
  stops on an error can simply be re-run to completion.
- `--delete-source` reaps each original after its successful cutover — but
  only if no other disk still references that file (a disk shared with another
  VM, or a base/backing image). If something else depends on it the source is
  kept and the reason is reported; the delete is never the thing that breaks
  another VM.

The same operation is available in the web UI (stack detail → **Migrate
volumes**) and over REST (`POST /api/v1/stacks/{name}/migrate-volumes`, SSE).

## Replication

```
lv replicate-volume web-1 root dr-pool
```

**Native send/recv** — when the source driver implements the
`Replicator` interface, replication uses the backend's native
primitive instead of qemu-img convert:

- **ZFS** — `zfs snapshot` then `zfs send | zfs recv`. Incremental
  (`-I` since the prior `litevirt-replicate-prev` snapshot) when
  `Incremental: true`.
- **Ceph RBD** — `rbd export-diff | rbd import-diff`. Incremental
  uses `--from-snap`. Cross-cluster via SSH wrap on the receive side.
- **BTRFS** — `btrfs send | btrfs receive`. Incremental via `-p` against
  the prior replicate snapshot.

Cross-host replication wraps the receive in `ssh <user@host>` so the
sender pipes straight into the remote CLI. Same-host uses a local pipe.

Crash-consistent by default; quiesce-via-guest-agent for application
consistency is a planned follow-up.

## Backend matrix

|  | local | nfs | dir | btrfs | zfs | ceph | iscsi | lvm-thin |
|---|---|---|---|---|---|---|---|---|
| Snapshots | qcow2 | qcow2 | qcow2 | atomic (subvol) | atomic (zvol) | atomic (rbd snap) | external | atomic (LV snap) |
| Move (offline) | ✓ | ✓ | ✓ | ✓ | — | — | — | — |
| Move (live) | ✓ | ✓ | ✓ | ✓ | — | — | — | — |
| Replicate via qemu-img | ✓ | ✓ | ✓ | ✓ | fallback | fallback | — | — |
| Native send / receive | n/a | n/a | n/a | btrfs s/r | zfs s/r | rbd export-diff | n/a | n/a |
| HA-friendly cluster store | no | yes | depends | no (host-local) | no (host-local) | yes | yes | no |

The **Snapshots** row describes each backend's *native* snapshot capability
(what the driver could do). It is not the `lv snapshot create` code path: that
command always goes through libvirt — an external qcow2 overlay for disk
snapshots, plus `DomainSaveFlags` for the RAM state of a `--memory` snapshot —
regardless of the underlying pool driver.

For HA scenarios use NFS, Ceph RBD, or iSCSI — the disk must survive any
single host failing.
