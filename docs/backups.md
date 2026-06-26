# Backups

litevirt's backup system mirrors Proxmox PBS in shape: a
content-addressed deduped chunk store, BLAKE3 hashing, dirty-bitmap
incrementals, AES-256-GCM encryption, mark-and-sweep GC, retention,
cross-repo sync, and live restore.

## Application consistency (guest fs-freeze)

`lv backup snapshot` takes a `--quiesce` mode (default `auto`). With `auto`, if the
VM advertises a QEMU guest agent, litevirt freezes the guest's filesystems
(`fs-freeze`) for the brief moment the pull-mode session establishes its
point-in-time, then thaws — yielding an **application-consistent** backup. Without a
guest agent (or with `--quiesce off`) the backup is crash-consistent, as before.
A freeze failure is logged and the backup proceeds crash-consistent — it never fails
an otherwise-good backup. Scheduled backups inherit the `auto` default.

The implementation lives in `internal/pbsstore` (chunk store +
manifest + GC) and `internal/nbd` (live-restore NBD source). Operator
surface:

| Surface | What |
|---|---|
| `lv backup repo …` | local repo management — init, ls, gc, verify, prune, sync |
| `lv backup snapshot <vm>` | push a VM disk into a repo via the daemon (gRPC) |
| `lv backup restore-from` | offline restore: stream chunks to a target disk path |
| `lv backup restore-live` | live restore: serve manifest over NBD while the VM boots against a qcow2 overlay |
| `lv backup schedule …` | cron-driven backups, scoped per-VM, per-pool, per-project, or cluster-wide |
| compose `backup:` block | deploy-time hook that reconciles a `backup_schedules` row from the stack |
| `/backups` UI page | read-only manifest list per configured repo |

## Repository

A *repository* is a directory on a host (typically NFS-mounted on a
dedicated backup host). One litevirt cluster can talk to many repos.

```bash
lv backup repo init /srv/backup/main
```

For a fresh encrypted repo:

```bash
# 32 hex bytes = 256 bits.
openssl rand -hex 32 > /etc/litevirt/backup.key
chmod 600 /etc/litevirt/backup.key

lv backup repo init /srv/backup/main \
    --encrypted --key-file /etc/litevirt/backup.key
```

Repos can be exposed to the UI's `/backups` page by registering them
in `/etc/litevirt/config.yaml`:

```yaml
backup_repos:
  main:    /srv/backup/main
  offsite: /mnt/dr/offsite
```

When set, `/backups` (no query string) lists each repo with snapshot
count + total size; click through to see manifests. Without the
config block, the page still works via `?repo=<path>` for one-off
exploration.

The on-disk layout:

```
/srv/backup/main/
├── repo.json                 # schema-version, encryption mode
├── chunks/
│   ├── 0a/0a1b2c…/           # one file per chunk; filename = BLAKE3(plaintext)
│   └── …
└── snapshots/<vm>/<ts>-<disk>.manifest.json
```

## How chunks dedupe

A 4 MiB rolling window over the source disk is BLAKE3-hashed. The hex
digest is the chunk's stable id and on-disk path. Two snapshots that
share even a single 4 MiB region (a guest OS image, a database WAL
segment, untouched filesystem regions) share the chunk file — the
second snapshot's manifest just references the existing chunk.

Compression is left to the underlying filesystem. Most backup hosts
already run on ZFS or btrfs with native lz4; layering Go-side
compression would just contend.

## Incremental backups

```bash
lv backup snapshot postgres-1 --repo /srv/backup/main --incremental
```

For a **running** VM, the daemon reads guest-visible content over a
pull-mode libvirt NBD export — this is the default backup path (wired
in `internal/daemon/daemon.go` via `SetBackupSource`, see
`internal/grpcapi/backup_snapshot.go`). `--incremental` resolves the
most-recent manifest for `(vm, disk)` via
`pbsstore.Repo.LatestManifestFor`, opens the session against that
parent's checkpoint, and queries the NBD `qemu:dirty-bitmap` meta-context
so only changed extents are read off disk; unchanged regions inherit the
parent manifest's chunk refs verbatim. A full (non-incremental) push uses
the `base:allocation` meta-context to skip holes and zero regions.

When no parent manifest exists yet, the daemon emits a progress note
("first incremental degrades to full") and does a full push so the
chain has a root. Subsequent runs go incremental.

**Fallback for stopped VMs / no libvirt / a missing parent checkpoint:**
the daemon backs up the qcow2 container file directly with
`pbsstore.PushFile`. The chunk store still dedups by content and the
manifest chain stays intact, but no read I/O is saved and an
`--incremental` request degrades to a full container backup. Operators
see the fallback reason in the progress stream. (Container backup only
works on file-based pools; a stopped VM on a block/object backend such as
Ceph must be backed up running, via the guest-content path.)

## Encryption

Encrypted repos seal each chunk with AES-256-GCM. The chunk ID stays
the BLAKE3 of the *plaintext* so dedup survives key rotation —
re-encrypting only the on-disk blob, not the metadata.

```bash
lv backup repo init … --encrypted --key-file /path/to/key
```

Wrong-key reads return a clear `ErrKeyMismatch`. Repository metadata
records the encryption mode in `repo.json`, so a downgraded binary
without the key will refuse to read rather than silently treat
ciphertext as garbage chunks.

Cluster-wide secrets management will move the key into the cluster's
KV store and replace `--key-file` with per-tenant keying.

## Garbage collection

```bash
lv backup repo gc /srv/backup/main
```

Mark-and-sweep: walk every manifest, collect the union of chunk IDs,
delete every chunk file not in that set. GC is safe to run alongside
*reads* but must not run alongside another writer in the same repo —
the snapshot scheduler takes a per-repo lease so its own pushes
serialize with operator-triggered GC.

## Retention

Proxmox-shaped buckets (last / daily / weekly / monthly / yearly)
applied per `(VM, disk)` pair:

```bash
lv backup repo prune /srv/backup/main \
    --keep-last 3 --keep-daily 7 --keep-weekly 4 \
    --keep-monthly 12 --keep-yearly 5
```

Defaults to dry-run; pass `--apply` to actually delete the manifests.
Run `lv backup repo gc` afterwards to reclaim chunk space.

The snapshot scheduler applies the same retention policy after each
successful push so an unattended cluster never grows without bound.

## Verify

```bash
lv backup repo verify /srv/backup/main
```

Every chunk referenced by any manifest is read, decrypted (if needed),
and re-hashed. Mismatches indicate bit-rot; missing chunks indicate a
botched copy from another repo.

## Sync (off-site DR)

Local-to-local copy of all snapshots that exist in `src` but not `dst`:

```bash
lv backup repo sync /srv/backup/main /mnt/dr/main-mirror
```

Dedup means re-running the sync is cheap. Encryption modes must match
on both ends — pushing plaintext chunks into an encrypted repo is
refused to prevent silently leaving cleartext data on a DR host.

## Schedules

`lv backup schedule` manages cron-driven backups. The scheduler ticks
every 60 s per host (no cluster-wide leader gate — a VM is owned by
exactly one host so the host-local model has no double-firing
exposure), pulls every active schedule row, evaluates the cron, and
fans out matching jobs.

The schedule scope is inferred from which target you supply (`--pool`,
`--project`, or a `<vm>` positional arg) unless you set `--scope` explicitly:

```bash
# Per-VM schedule (VM is a positional arg)
lv backup schedule add postgres-1 \
    --repo main \
    --cron "15 2 * * *" \
    --keep-daily 7 --keep-weekly 4 --keep-monthly 12

# Pool-level schedule (fans out to every VM on the named pool that
# this host owns; replaces the boilerplate of one schedule per VM)
lv backup schedule add \
    --pool fast-ssd \
    --repo main \
    --cron "0 3 * * *"

# Per-project (every VM in a tenancy project) and cluster-wide:
lv backup schedule add --project /acme/web --repo main --cron "0 4 * * *"
lv backup schedule add --scope cluster      --repo main --cron "0 5 * * *"

lv backup schedule ls
lv backup schedule rm postgres-1 --repo main
lv backup schedule rm --pool fast-ssd --repo main      # match the scope on removal
```

Pool-mode is per-host, not leader-gated for the same reason per-VM
mode isn't: each host fires for its own slice of the pool.

Repos referenced by schedules resolve through the cluster's repo map: a
top-level compose `backup-repos:` block (see below) or daemon config
`backup_repos:` (a flat `name: /path` map). When both define the same name,
daemon config wins.

## Replication schedules

The same scheduler also drives **volume replication** (`backup_schedules`
rows with `type='replication'`). Each run copies the VM's root disk to a
target pool as a timestamped, self-contained point-in-time copy, keeping the
newest `keep_replicas`. It is **crash-consistent** (no guest quiesce) — a
fast-recovery layer, not a backup replacement, so keep backups too.

Manage it from the **Replication** section of the `/schedules` UI or the CLI:

```bash
lv replication schedule add web-1 \
    --cron "0 */4 * * *" --target-pool dr --target-host hostB \
    --keep 6 --incremental --auto-promote
lv replication schedule ls
lv replication schedule rm web-1 --target-pool dr
```

(RPCs `Create/List/DeleteReplicationSchedule`.)

Target model: an explicit **target host**, a **shared pool** (nfs/ceph/iscsi),
or — when neither is set — an auto-selected **healthy peer** that has the pool.
**Cross-host replication to a peer's non-shared local pool is supported**: the
source replicates to a scratch (or streams dirty extents), streams to the peer's
pool, and prunes old replicas there.

**Incremental** (`--incremental`): instead of a full copy each run, the daemon
reads only the dirty extents since the last run (via a libvirt backup
session/dirty-bitmap) and applies them into a sparse **raw** replica forked from
the previous one on the target — only changed extents cross the wire. Falls back
to a full copy for a stopped VM / old libvirt / broken chain.

### Promotion (disaster recovery)

A replica is inert until promoted. `lv replication promote <vm>` brings a VM up
from its newest replica — locating it (from the VM's schedule, or `--pool`/
`--host`), copying it into a self-contained live disk on the host that holds it,
and defining + starting the VM there:

```bash
lv replication promote web-1                 # take over the name (host-loss case)
lv replication promote web-1 --new-name web-1-dr   # bring up alongside the original
lv replication promote web-1 --no-localize   # fast: boot off an overlay (pins the replica)
```

A split-brain guard refuses to take over the name while the original is on a
healthy host (`--force` overrides). The same action is on the VM detail page
("Promote replica").

**Automatic promotion** (`--auto-promote` on the schedule): after the failover
coordinator **confirms a fence**, it promotes the freshest replica for opted-in
VMs onto a healthy peer (so a VM on lost local storage resumes), falling back to
a bare reschedule on failure. Default off. Promotion uses the newest
(crash-consistent, possibly lagging) replica — enable only where a small lag
window is acceptable.

## Live restore

`lv backup restore-live` exposes a manifest as an NBD source so a VM
can boot in seconds against a qcow2 overlay, while data migrates to
the overlay on-demand:

`--vm`, `--disk`, and `--timestamp` (exact RFC3339, as shown by
`lv backup repo ls <path>`) are required; the manifest is not resolved
by "latest".

The daemon can define and start the VM for you against the overlay
(`--auto-start`) and then localize the disk in the background and tear down
the NBD server (`--blockpull`):

```bash
lv backup restore-live \
    --repo /srv/backup/main \
    --vm postgres-1 --disk root \
    --timestamp 2026-05-11T02:15:00Z \
    --target-path /var/lib/libvirt/images/postgres-live.qcow2 \
    --name postgres-restored \
    --auto-start --blockpull
```

The overlay's backing is the NBD export, declared as a **raw** backing
(the export serves guest-visible content), so qemu opens it directly. With
`--blockpull` the command returns once the disk is fully local and
self-contained; without it the NBD server stays up until you Ctrl+C (after
running `virsh blockpull <vm> <dev> --wait` yourself).

If you prefer to drive it manually, omit `--auto-start`/`--blockpull` and
`virsh define && virsh start` against the overlay, then blockpull. Use
`--from-existing` to source the domain spec from the existing `vms` record
when the manifest has none.

The NBD server is read-only and rejects writes with `EPERM` — guests
that try to write straight to the backing source get a clear error
rather than silent corruption. All writes land in the qcow2 overlay.

## Containers

Containers back up to the same chunk store as VM disks:

```bash
lv ct backup web --repo /srv/backup/main          # freeze + archive rootfs+config
lv ct restore web --repo /srv/backup/main --timestamp <ts> [--start]
```

`lv ct backup` freezes a running container (consistent point-in-time), tars its
rootfs **and** LXC config, and pushes a content-addressed, **dedup'd** manifest
that embeds the container spec — so `lv ct restore` rebuilds it from the repo
alone, even after `lv ct rm` or if the original image is gone. Full-only (no
dirty-bitmap incremental); the chunk store's dedup gives storage-side
incrementality. Host-local like VM backup (run against the owning host); a
container's footprint counts toward the project's `backup_gib` quota. See
[containers.md](containers.md#backup--restore). (Local point-in-time snapshots
without a repo are `lv ct snapshot` — see that doc.)

## Compose integration

Per-VM scheduled backup, configured directly in the stack:

```yaml
backup-repos:
  main:
    path: /srv/backup/main
  offsite:
    path: /mnt/dr/offsite

vms:
  postgres-1:
    image: ubuntu-24.04
    disks:
      data: { size: 200G, volume: hot }
    backup:
      repo: main
      schedule: "15 2 * * *"        # cron
      encryption: aes256gcm
      retention:
        keep-daily:   7
        keep-weekly:  4
        keep-monthly: 12
        keep-yearly:  5
```

`lv compose up` reconciles a `backup_schedules` row from each VM's
`backup:` block on every deploy. Removing the block soft-deletes the
schedule.

## Deprecated: raw full-disk backup/restore

The legacy raw-stream RPCs `BackupVM`/`RestoreVM` (streaming a whole disk
to/from the client) are **deprecated** and now return `Unimplemented`. Use the
snapshot path instead — it is incremental, deduplicated, repo-backed, scoped to
the VM's project via path RBAC, and quota-aware:

- back up with **`lv backup snapshot`** (→ `BackupSnapshot`);
- restore with **`lv backup restore-from`** (→ `RestoreFromBackup`) or
  **`lv backup restore-live`** (→ `RestoreLive`).

Restore destinations are a pool-relative filename by default; a custom absolute
`target_path` (and a custom absolute `repo_path`) require the **admin** role.

## gRPC + WebUI

- **gRPC `BackupSnapshot` + `RestoreFromBackup` + `RestoreLive`** —
  the CLI commands are thin wrappers; programmatic clients can call
  the RPCs directly. Cross-host VMs return `FailedPrecondition` with
  the host name to retry against (point `LV_HOST` at the VM's owning
  daemon).
- **WebUI `/backups`** — read-only manifest list. With `backup_repos:`
  configured, lists every configured repo and its snapshot count +
  total size. Click through to drill into one repo's manifests.

## What's still in flight

- `lv backup repo sync` over mTLS gRPC (the package-level helper
  works; the wire variant lands alongside federation).
- Application-aware quiesce (PostgreSQL/MySQL/MongoDB) on top of
  guest-agent hooks.
