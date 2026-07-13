# Ceph (hyperconverged install)

litevirt brings up Ceph on the same hosts that run litevirt, mirroring
Proxmox's "Ceph from the UI" experience. The implementation is a thin
shell-out wrapper around `cephadm` (Ceph's modern deployer) so the
litevirt binary stays CGO-free.

The package lives at `internal/cephdeploy/`. CLI surface is
`lv host ceph …`; the dashboard is at `/storage/ceph`.

## Prerequisites

- `cephadm` binary on PATH on every host that will run a Ceph daemon.
  On Debian/Ubuntu this is the `cephadm` package; on RHEL/Rocky it's
  in the Ceph repo. We don't bundle it because Ceph upgrades happen
  on a different cadence than litevirt upgrades.
- A storage network — a dedicated VLAN / VXLAN for Ceph traffic
  separate from the general cluster network. Ceph's published latency
  characteristics assume this.
- One unused block device per OSD on each host. Cephadm wipes the
  device on add — back up anything important first.

## Bootstrap (first MON)

Run on the first host to host a MON:

```
lv host ceph init \
    --mon-ip 10.10.0.5 \
    --network 10.10.0.0/24
```

Output:

```
Bootstrap complete. FSID: 7e1c5e2a-aaaa-bbbb-cccc-dddddddddddd

Next steps:
  - lv host ceph add-mon <host>     # add a 2nd / 3rd MON
  - lv host ceph add-osd <h> <dev>  # add an OSD per spinner
```

Cephadm:

- creates `/etc/ceph/ceph.conf` and the admin keyring,
- starts the first MON + MGR + crashes container,
- registers the host as a cephadm-managed cluster member.

## Grow the cluster

```
# Add a 2nd and 3rd MON (Ceph requires odd MON counts for quorum).
lv host ceph add-mon host-b
lv host ceph add-mon host-c

# Add a Mgr standby on each non-MON host.
lv host ceph add-mgr host-b
lv host ceph add-mgr host-c

# Add an OSD per host (one per data device).
lv host ceph add-osd host-a /dev/sdb
lv host ceph add-osd host-a /dev/sdc
lv host ceph add-osd host-b /dev/sdb
…
```

Each `add-*` call routes through `cephadm shell -- ceph orch daemon add`,
so SSH access from the bootstrap host to each new host is required —
cephadm sets up an authorised public key on bootstrap.

## Status

```
lv host ceph status
```

Outputs:

```
FSID:        7e1c5e2a-…
Health:      HEALTH_OK
MONs:        3
OSDs:        12 total / 12 up / 12 in
PGs:         128
Capacity:    214748364800 used / 21474836480000 available
```

Or `lv host ceph osd-tree` for the per-host OSD layout (mirrors
`ceph osd tree`).

## UI dashboard

`/storage/ceph` renders the same data: health card, MON / OSD / PG
counts, and the CRUSH tree. When cephadm isn't installed yet (the
homelab default), the page renders a friendly empty-state with the
exact CLI commands needed to bootstrap — so a brand-new cluster never
sees a 500.

## Using a Ceph pool from litevirt

Once the cluster is healthy, declare a `ceph` storage pool in compose:

```yaml
volumes:
  rbd-fast:
    driver: ceph
    source: rbd                 # Ceph pool name
    options:
      conf: /etc/ceph/ceph.conf
      keyring: /etc/ceph/ceph.client.admin.keyring
      id: admin
```

VMs reference it by name:

```yaml
vms:
  db-1:
    image: ubuntu-24.04
    disks:
      data: { size: 500G, storage: rbd-fast, format: raw }
```

`format: raw` is required for Ceph RBD — qcow2 over rbd costs you the
zero-copy and snapshot guarantees. The package automatically maps the
RBD image to a `rbd:pool/image` spec libvirt understands.

## What's still in flight

- The dashboard is read-only; the deploy wizard (point-and-click
  add-host / add-OSD) is a stretch goal.
- Cluster-wide cephadm orchestration over gRPC so the UI can drive
  bootstrap from any host, not just the first MON.
- Native go-ceph (`-tags ceph`) build for clusters that want a
  pure-library client instead of `rbd` shell-out.
