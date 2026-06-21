# Federation: regions and anycast

litevirt's federation model labels every host with a **region** name
and exposes regions as a first-class operator concept: `lv region` for
discovery and cross-region migration, plus anycast service endpoints
that the embedded DNS server publishes with weighted round-robin
records.

The CRDT replicator (Crescent) is already WAN-native — no 5 ms-LAN
constraint — so federation is built on top of normal cluster state
rather than a separate "PDM" layer. A litevirt cluster IS the federation
unit.

## Regions

A region is a string tag on `hosts.region`. Single-region clusters
keep working unchanged — every host defaults to region `default`.

Set (or change) the region on a host:

```bash
lv host config eu-west-1 --region eu-west
```

List + inspect:

```bash
lv region ls
# REGION    HOSTS  HEALTHY  VMS
# eu-west   3      3        42
# us-east   3      3        37
# default   1      1        2

lv region status --region eu-west
# REGION   HOSTS  ACTIVE  VMS  LAST UPDATED
# eu-west  3      3       42   2026-06-06T12:00:00Z
```

(Omit `--region` to show a rollup for every region.)

### Region is a label, not a placement constraint

A region is purely a host label (`hosts.region`) plus the anycast-DNS
concept below. The placement engine does **not** filter on region:
there is no `--region` flag on `lv run` and no
`placement.region:` compose key. To pin a VM to hosts in a region, use
the existing placement controls keyed off labels — `placement.host`,
`placement.require`/`prefer` against host labels you set with
`lv host label set`. See `docs/placement.md`.

## Cross-region migration

```bash
lv region migrate <vm> <target-host>            # storage assumed shared
lv region migrate <vm> <target-host> \
    --with-storage --target-pool <pool>         # replicate disks first
```

The second positional argument is the **target host** (the destination
region is inferred from that host's `region` label). The handler drives
`ReplicateVolume` per disk into `--target-pool` before invoking
`MigrateVM(WithStorage=false)` against that host. The replication uses the storage driver's
native primitive when available — `zfs send | zfs recv`,
`rbd export-diff | rbd import-diff`, `btrfs send | btrfs receive` —
falling back to `qemu-img convert` otherwise.

Constraint today: `target-pool` MUST be reachable from the source
host (typical for shared Ceph RBD or NFS, or anywhere a replication
peer is preconfigured). Truly source-local storage requires in-band
streaming across regions, which is a planned follow-up
(truly-local cross-region disk transport).

## Anycast service endpoints

A *service endpoint* is a named (service, region) → IP mapping with
a weight. The embedded DNS server (`internal/dns/`) reads
`service_endpoints` on every query and returns rows in a
weight-respecting round-robin so a multi-region service surfaces
under one DNS record.

Each call registers (or replaces) one endpoint:

```bash
lv region anycast add --name api --ip 10.10.0.5 --region eu-west
lv region anycast add --name api --ip 10.20.0.5 --region us-east

lv region anycast ls
# SERVICE  IP           REGION    WEIGHT
# api      10.10.0.5    eu-west   1
# api      10.20.0.5    us-east   1

# Bias traffic 4:1 toward eu-west (re-add the same endpoint with a weight)
lv region anycast add --name api --ip 10.10.0.5 --region eu-west --weight 4

lv region anycast rm --name api --ip 10.10.0.5
```

The DNS server resolves `<service>.<dns_domain>` (default
`litevirt.local`) to one of the configured IPs. Internal callers
must use the cluster's DNS resolver — `dns_port` in daemon config,
typically delegated from the host's primary resolver.

Note: anycast at the *network fabric layer* (FRR/BGP/ECMP) is out of
scope for this slice — what ships is DNS-weighted round-robin, which
covers most internal-service use cases without router cooperation.

## gRPC surface

```
ListRegions          → list regions and their host counts/health
RegionStatus(name)   → per-host detail
CrossRegionMigrate   → drive ReplicateVolume + MigrateVM
UpsertServiceEndpoint, ListServiceEndpoints, DeleteServiceEndpoint
```

REST surface (see `docs/rest-api.md`):

- `GET /api/v1/regions` (`?region=`) → `RegionStatus`
- `GET /api/v1/regions/list` → `ListRegions`
- `POST /api/v1/regions/migrate` → `CrossRegionMigrate` (SSE for progress)
- `GET|POST|DELETE /api/v1/services` → the service-endpoint RPCs
  (DELETE takes a `{service_name, ip}` JSON body)

## When NOT to use multiple regions

- The CRDT replicator works fine across regions but every
  cross-region write pays the replication latency. If your workload
  is chatty and consistency-sensitive, a single region with a
  high-availability layout is simpler.
- HA quorum is cluster-wide, not region-local. A 4-node cluster split
  2/2 across regions has the same quorum-stall risk as a 4-node LAN
  cluster split 2/2 — both sides compute `quorum=3` and neither
  fences. Use 3+ regions OR a witness host (`--role witness`) to
  break ties.
- Cross-region migrate copies the entire disk for source-local
  storage today; for VMs with many TB on local NVMe, plan for the
  copy time. Shared Ceph or NFS sidesteps the bandwidth question
  entirely.
