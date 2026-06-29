# Containers (LXC + OCI)

litevirt's container subsystem runs Linux containers via the
LXC family of tools. OCI images (Docker registries, etc.) are pulled via
`skopeo` and converted to an LXC rootfs via `umoci`. Both binaries are
host bootstrap dependencies.

The runtime API mirrors the VM lifecycle (Create / Start / Stop / Delete
/ Exec / List) so a single scheduler hosts both kinds of
workload — that's the structural advantage compared to running
Kubernetes alongside a VM platform.

## Why LXC, not OCI as a first-class runtime

Three reasons:

1. **System containers** (LXC) are the natural fit alongside VMs:
   they share the same lifecycle vocabulary (start, stop, snapshot,
   migrate), the same networking primitives (veth into a bridge), and
   the same scheduler placement decisions. OCI's "one process per
   container" model needs a separate runtime layer to host long-lived
   services.
2. **OCI images run inside LXC** via umoci-extracted rootfs. So we
   support OCI images without giving up LXC's system-container model.
3. **CGO-free**: shelling out to `lxc-*` keeps litevirt a single
   static binary, exactly like the libvirt VM path.

## CLI quickstart

```
# Pull an image into the container's directory. umoci unpacks the flattened
# rootfs to <dest>/rootfs, so point --dest at /var/lib/lxc/<name>.
# (add --local to unpack on the host you're on, without the daemon)
lv ct pull docker.io/library/nginx:1.27 --dest /var/lib/lxc/web

# Create the container from the unpacked rootfs. --template accepts the bundle
# dir (descends into rootfs/) or a rootfs path; the LXC config is generated.
lv ct create web --template /var/lib/lxc/web

# Start, exec, stop, delete
lv ct start web
lv ct exec web -- nginx -t
lv ct stop web --timeout 10
lv ct rm web
```

For a download-template container (no OCI image required):

```
lv ct create alpine-1 --distro alpine --release 3.21
lv ct start alpine-1
```

## Private registry credentials

Pulling a private image (a private Docker Hub repo, `ghcr.io`, a self-hosted
registry) needs a registry login. Credentials are stored cluster-wide and come
in two scopes:

- **Per-user** — owned by the authenticated caller; only used for that user's
  pulls.
- **Global** — cluster-wide, operator-managed; applies to anyone.

At pull time the daemon resolves the credential for the image's registry with
this precedence: **the caller's per-user credential wins → else the global
credential → else an anonymous pull** (unchanged behaviour). Resolution happens
on the node you're connected to (the only place your identity is known) and the
resolved secret is carried along if the pull is forwarded to another host.

```
# Store a per-user credential (prefer --password-stdin so the token never
# lands in your shell history or the process arg list)
echo "$GHCR_TOKEN" | lv registry add ghcr.io --username me --password-stdin

# Store a global, cluster-wide credential (operator-only)
echo "$ORG_TOKEN" | lv registry add ghcr.io --username org --password-stdin --global

# List credentials — your own + global (secrets are never shown);
# --all shows every user's (operator-only); --global shows global only
lv registry ls

# Remove one (your own by default; --global for the cluster-wide one)
lv registry rm ghcr.io

# Pull a private image — credentials are resolved automatically
lv ct pull ghcr.io/acme/api:1.4 --dest /var/lib/lxc/api
```

The registry argument is a host (`docker.io`, `ghcr.io`,
`registry.example.com:5000`); Docker Hub short names like `alpine` resolve to
`docker.io`, so a credential stored against `docker.io` covers them.

For a one-off authenticated pull without storing anything, pass the credential
inline — this is also the only way to authenticate under `--local`, where there
is no daemon to resolve a stored credential:

```
echo "$TOKEN" | lv ct pull ghcr.io/acme/api:1.4 \
    --dest /var/lib/lxc/api --username me --password-stdin
```

Credentials can also be managed from the web UI at **Account → Registry
Credentials** (the global section is shown to operators). Secrets are stored in
the cluster database; the wire/API and UI never return them after they're set.

## Compose integration

The new unified `workloads:` map carries a `kind:` discriminator. Stacks
can mix VMs and containers freely, with the same network attachments,
labels, and placement strategy.

```yaml
networks:
  prod:
    type: bridge
    interface: br0

workloads:
  web-vm:
    kind: vm
    image: ubuntu-24.04
    cpu: 4
    memory: 4G
    network: [{ name: prod, ip: 10.0.0.5 }]

  web-ct:
    kind: lxc
    image: alpine:3.21          # download template (distro:release) or a rootfs path
    cpu: 2
    memory: 512
    network: [{ name: prod, ip: 10.0.0.6 }]
```

Containers are full compose citizens: `lv compose up` creates **and starts** each
container on an LXC-capable host (placement is capability-aware, so a container
never lands on a node without the runtime); re-apply is idempotent (unchanged
containers are left alone, a changed spec recreates); and `lv compose down`
removes them and every trace they created (rootfs, the stack's network bridge +
dnsmasq, and any load balancer processes). The legacy `vms:` map still parses —
every entry there gets `kind: vm` applied implicitly so existing stacks need no
changes.

Containers attach to a stack's networks the same way VMs do — give the NIC a
static `ip:` (litevirt assigns it and writes the guest's `/etc/network/interfaces`),
or omit it for DHCP off the network's dnsmasq.

**Load balancer backends.** A stack `loadbalancer:` discovers containers as
backends alongside VMs, so a single LB can front a mix of both. Use a static NIC
`ip:` for the container (recorded cluster-wide); a DHCP-assigned address is also
resolved when the container runs on the LB's own host. (A DHCP container on a
*different* host than the LB isn't auto-discovered yet — a follow-up.)

Current limits: an OCI **registry ref** (`kind: oci`, `image:
docker.io/library/nginx:1.27`) isn't auto-pulled by compose yet — pre-pull it
(`lv ct pull <ref> --dest <dir>`) and set `image:` to that rootfs path. A cpu/mem
change recreates the container (no in-place reconfigure). `lv compose ps` lists
VMs only. Containers have no **live/CRIU** migration; **cold migration**
(`lv ct migrate`, stop → transfer → start) exists — see the Cold migration
section below. Per-NIC security-group provisioning for containers is a follow-up.

## Networking

LXC's native `veth` driver attaches into a bridge. Containers inherit the same
network primitives the VM side uses (bridge, vxlan, isolated), so a container can
sit on a VXLAN-overlaid VNet alongside VMs.

A NIC is attached one of two ways:

- **`network=<managed-net>`** — a *managed* NIC on a litevirt logical network. It
  gets a tracked `container_interfaces` row, a deterministic host veth and MAC, an
  IPAM lease, DNS, and security-group enforcement (see below). This is the
  first-class path and the one tenants use.
- **`bridge=<br>`** — a *raw* NIC straight onto a host bridge, with no managed
  state. The legacy/admin escape hatch (see *Project isolation* below).

```
# Managed NIC on logical network "app-net", with security groups:
lv ct create web --distro alpine --release 3.21 \
    --network network=app-net,name=eth0,security-groups=web;db \
    --cpu 2 --memory 512

# Raw bridge NIC with a static IP:
lv ct create edge --distro alpine --release 3.21 \
    --network bridge=br0,name=eth0,ip=10.0.0.6/24
```

Stacks attach the same way: a compose `kind: lxc` workload's `network:` names a
managed network. With no `--network`, the container gets a single raw veth on the
host's default `lxcbr0` bridge (NAT to the outside).

When `ip=` is given (or a managed network assigns a static address), litevirt also
writes the guest's `/etc/network/interfaces` (ifupdown) so the address survives
boot — otherwise the stock image's DHCP client would flush it. `internal/lxc/
network.go` renders the config snippet, emitting the deterministic veth pair so the
host side is trackable:

```
lxc.net.0.type = veth
lxc.net.0.link = br-app-net
lxc.net.0.veth.pair = lvc1a2b3c4d5e6f
lxc.net.0.hwaddr = 52:1a:2b:3c:4d:5e
lxc.net.0.flags = up
lxc.net.0.name = eth0
lxc.net.0.ipv4.address = 10.0.0.6/24
```

### Managed-NIC identity, IPAM, DNS, security groups, load balancing

A managed NIC (one naming a `network=`) reaches **VM parity**:

- **Interface row + deterministic identity.** Every managed NIC gets a
  `container_interfaces` row keyed `(host, ct, ordinal)`, a deterministic host veth
  (`lvc` + a hash, ≤15 bytes / IFNAMSIZ) and a generated locally-administered MAC
  (`52:` + a 40-bit host-scoped hash, so two same-named containers on different
  hosts sharing an L2 don't collide). The veth/MAC are stable across
  restart/restore/migrate/clone.
- **IPAM.** A static IP reserves that exact address; a subnet-backed network
  auto-allocates one; a subnet-less network is DHCP (the IP is discovered later).
  Leases are non-aliasing across VMs and same-named containers.
- **DNS.** A managed container with a known IP is resolvable at
  `ct.stack.domain` (the container analogue of VM DNS). The per-host IP scanner
  discovers a DHCP address, persists it, and (re)writes the record; delete/migrate
  remove it.
- **Security groups.** `security-groups=` binds SGs to the container's veth with
  the same per-NIC nftables enforcement VMs get on their tap. (Bound at
  create/recreate time; a day-2 CT-aware rebind API is a follow-up.)
- **Load balancing.** A stack's `loadbalancer:` resolves managed containers as
  backends, including a container running on a **remote** host (resolved via a
  peer lookup).

### Project isolation

A container in a tenancy project may attach only to a network that is **global**
(unowned) or **owned by its own project** — attaching to another project's network
is denied. A *raw* bridge (`bridge=`) is outside isolation, so it requires
cluster-root network authority: a **project-scoped** caller must use a managed
`network=`; a cluster admin keeps the raw-bridge escape hatch. See
[tenancy.md](tenancy.md) and [networking.md](networking.md).

## Resource limits

`lv ct create --cpu <shares> --memory <MiB>` (and compose `cpu:`/`memory:`)
translate to cgroup limits written into the container's config at create time.
We emit both v1 and v2 keys so the same config works on either kernel —
irrelevant keys are simply ignored:

```
lxc.cgroup2.cpu.max = 2000 100000
lxc.cgroup.cpu.shares = 2048
lxc.cgroup2.memory.max = 512M
lxc.cgroup.memory.limit_in_bytes = 512M
```

## Restart policy

`lv ct create --restart {none|on-failure|always}` (and compose `restart:`) makes a
container auto-restart when it stops **unexpectedly**:

```
lv ct create web --distro alpine --release 3.21 \
    --restart on-failure --restart-max-attempts 5 --restart-delay 5s
```

A per-host reconciler reconciles each container's cluster-state row against the LXC
runtime every ~15s and restarts a down container per its policy, honouring
`max-attempts`/`window`/`delay`. The cluster row is also synced to the runtime's
reality, so `lv ct ls` and the detail view never disagree.

**Caveat (coarser than VMs):** LXC reports only `RUNNING`/`STOPPED`/`FROZEN` — no
stop *reason*. A container therefore cannot distinguish a clean in-guest shutdown
from a crash. Only an operator `lv ct stop` is guaranteed-stick (it records
`operator-stop`); any other stop is treated as unexpected and restarted per policy.
A `FROZEN` (paused) container maps to running and is never restarted.

> On-host restart-policy handles a container that stops while its host is alive.
> If the whole host is fenced, **host-loss relocation** (see below) rebuilds the
> container on a surviving peer when it carries an `on_host_failure` policy.

## Tenancy, audit & metrics

Containers are first-class tenancy citizens, at parity with VMs:

- **Project** — `lv ct create --project <name>` places a container in a tenancy
  project (default `_default`); per-container RBAC and quota use it. Set once at
  create; shown in `lv ct ls`.
- **Quota** — container creation is admitted against the project's quota and
  **shares the same vCPU/memory budget as VMs** (one joint tenant limit). A
  container created with `--cpu`/`--memory` counts toward the budget whether
  running or stopped; an unlimited container (no `--cpu`/`--memory`) contributes
  nothing to that dimension. Exceeding the budget fails with `ResourceExhausted`.
- **Audit** — `create / start / stop / delete / exec` are written to the
  tamper-evident audit hash-chain (`ct.*` actions, with the project and result);
  permission-denied attempts are recorded too. View with `lv audit`.
- **Metrics** — the Prometheus exporter emits `litevirt_container_state` (1=running),
  `litevirt_container_cpu_limit`, `litevirt_container_memory_limit_mib`, and
  `litevirt_host_container_count`; running containers also count toward
  `litevirt_host_pressure`. For **live cgroup usage**, running containers also emit
  `litevirt_container_cpu_seconds_total` (cumulative CPU seconds, cgroup-v2
  `cpu.stat`) and `litevirt_container_memory_bytes` (cgroup-v2 `memory.current`).
  Usage metrics require cgroup-v2 (the modern default); on a cgroup-v1-only host
  they are quietly omitted (limits/state are still reported).

## Backup & restore

Containers back up to the same PBS-equivalent chunk store as VMs (BLAKE3
content-addressed dedup), so re-running a backup only writes what changed.

```bash
# Freeze the container, archive its rootfs + LXC config, and push to a repo.
lv ct backup web --repo /srv/backups

# Rebuild it later from the repo alone — even after `lv ct rm web` and even
# if the original image/template is gone. --start brings it up.
lv ct restore web --repo /srv/backups --timestamp 2026-06-23T10:00:00Z --start
```

How it works and what to expect:

- **Full, crash-/app-consistent.** A *running* container is frozen
  (`lxc-freeze`) for the duration of the read so the archive is a consistent
  point-in-time, then unfrozen — always, even if the backup fails midway. A
  stopped container is archived as-is. There is no dirty-bitmap incremental
  (containers are full-only); the chunk store's dedup gives storage-side
  incrementality, so the second backup of an unchanged rootfs writes almost
  nothing.
- **Self-contained manifest.** The manifest embeds the container's spec
  (cpu/memory/labels/restart-policy/project/image) alongside the archived
  rootfs **and** its LXC config, so restore needs only the repo — not the source
  cluster, and not the original OCI image or download template.
- **Restore is non-destructive.** It refuses to overwrite a live container of
  the same name (`AlreadyExists`) — `lv ct rm` it first, or restore onto a host
  that doesn't have it. The restored container comes up `stopped` unless you
  pass `--start`.
- **Host-local, like VM backup.** A container is archived on its owning host;
  run `lv ct backup`/`restore` against that host (`LV_HOST`). Restore runs on
  the **target** host (where the container will live).
- **Quota.** A container's backup footprint draws down the **same `backup_gib`
  project budget** as VM backups.

## Snapshots

```bash
lv ct snapshot create web before-upgrade   # point-in-time snapshot
lv ct snapshot ls web
lv ct snapshot revert web before-upgrade    # roll back to it
lv ct snapshot rm web before-upgrade
```

A snapshot freezes a running container (for a consistent point-in-time), tars
its on-disk dir, and stores it **host-local** under `{dataDir}/ct-snapshots`.

- **Revert** stops the container (replacing the rootfs requires it stopped),
  restores the snapshot in place, and restarts it if it had been running. The
  restore is **crash-safe** — the live dir is set aside and rolled back if the
  snapshot extract fails, so a corrupt snapshot can never lose the container.
- **Host-local**, like the container itself; snapshot ops run on the owning host
  (the daemon forwards there automatically).
- Snapshots are full copies today (no dedup); **COW acceleration** on
  btrfs/zfs/lvm-thin rootfs is a planned follow-up. For space-efficient,
  off-host point-in-time copies use `lv ct backup` (dedup chunk store).

## Templates & clones

```bash
lv ct template ubuntu-base            # mark a stopped container a clone template
lv ct clone ubuntu-base web-01        # full-copy clone with a fresh identity
lv ct clone ubuntu-base web-02 --start
lv ct template ubuntu-base --revert   # back to a normal container
```

A **template** is a stopped container that can't start — a golden clone source.
A **clone** is a full copy (`cp -a`) of a template or stopped container with a
**fresh identity**: new `lxc.uts.name`, a regenerated NIC MAC, and a reset
`/etc/machine-id` + `/etc/hostname`, so it boots clean and doesn't collide with
its source. Clones are created on the source's host (its rootfs lives there) and
admitted against the project quota; they inherit the source's project unless
`--project` overrides. Unlike VMs there are no linked clones (no qcow2 backing) —
every container clone is independent, so reverting a template is always safe.

## Host-loss relocation

Opt a container in at create time: `lv ct create web --on-host-failure
image-recreate` (default is `none` — left in place). If a host is fenced, the
failover coordinator relocates its containers that carry that policy onto a
healthy host (chosen via the placement engine), preferring the most faithful
option available:

1. **Restore from the latest backup** (`ct.relocate.restored`) — when a valid
   backup manifest exists in a repo the survivor can reach and the survivor is
   schema-compatible. The container is restored over peer mTLS (rootfs + the
   create-time spec, so litevirt-managed **networking is preserved**). This is
   driven idempotently: the coordinator marks the source row `relocating` (it
   never pre-creates a target row), and only tombstones the source once the
   restore lands — so a coordinator crash mid-restore re-derives correctly and
   never double-restores or strands the container.
2. **Recreate from image** (`ct.relocate.recreate`) — the fallback when no usable
   backup exists (or the restore failed / the survivor is mid-upgrade). The
   container is re-keyed and the target's reconciler rebuilds it from its
   re-pullable image, reconstructing managed NICs from the persisted create spec.
3. **Skip** (`ct.relocate.skipped`) — when neither is possible (e.g. a hand-built
   rootfs with no re-pullable image and no backup). Loudly audited so an operator
   knows to recover it manually.

Restore-from-backup requires a backup repo reachable from the survivor (a
registered repo name / shared NFS). `container_restore_timeout_sec`
(default 10m) bounds how long a relocate-restore is treated as in-flight before
the coordinator gives up and image-recreates. The create-time networking spec is
persisted from schema **v34** — containers created/backed-up before v34 fall back
to image-recreate (without managed-NIC reconstruction).

## Cold migration

```bash
# Move a container to another host. The repo must be reachable from BOTH hosts.
lv ct migrate web docker-02 --repo /srv/shared/backups
```

Migration **reuses the backup→restore data path** (one tested transport): the
source stops the container, archives its rootfs+config into the staging repo,
the target rebuilds from it, and the source copy is removed. If the container
was running it's restarted on the target.

- **Cold only** — the container is stopped for the transfer (no CRIU / live
  migration). This is the same model as VM cold migration.
- **Atomic re-key.** The owner moves to the target only after the restore
  succeeds; exactly one live row survives the window. **A failure before cutover
  leaves the container intact on the source** (restarted if it had been running).
- **No shared repo required.** The source archives into `--repo` locally and
  **streams the manifest to the target over peer mTLS** (into a per-transfer
  staging repo), so `--repo` need only exist on the source. (An older target
  predating peer streaming falls back to re-opening `--repo` by name, which then
  must be shared/reachable from both hosts.) Run against the source host
  (`LV_HOST`).
- Refuses to migrate onto a host that already has a container of that name.

## gRPC + WebUI

- **gRPC `Containers` service** — `Create / Start / Stop / Delete /
  Exec / List / PullOCIImage / BackupContainer / RestoreContainer /
  MigrateContainer` RPCs. `lv ct …` defaults to gRPC;
  cross-host requests forward via `peerClient` to the named host.
  `--local` flag forces the host-local lxc-* path for bootstrap /
  debug. The `containers` cluster-state table backs cluster-wide
  `lv ct ls`.
- **WebUI `/containers`** — full lifecycle: a create modal (download-template
  distro/release/arch, CPU/memory, bridge, auto-restart policy), per-row
  Start/Stop/Delete + Exec (one-shot command modal), a host filter, and a bulk
  toolbar (start/stop/delete) with select-all.

## What's still in flight

- COW snapshot acceleration — snapshots have shipped (freeze+tar, see above);
  instant copy-on-write snapshots on a btrfs/zfs/lvm-thin rootfs are a follow-up
  (containers have no pool association today, so the rootfs filesystem would be
  detected at snapshot time).
- Cross-host container backup/restore streaming — today, like VM backup,
  a container is archived on its owning host (run against `LV_HOST`); a
  relay so any entry node can drive it is a follow-up.
- Live migration (CRIU). **Cold** migration has shipped (`lv ct migrate`, see
  above — stop → transfer → start, reusing the backup transport); live migration
  with in-flight process state (CRIU) is a follow-up.
- Cross-host backup/restore/migrate today require a repo reachable from the
  hosts involved (run against `LV_HOST`); a peer-streaming relay so any entry
  node can drive them without shared storage is a follow-up.
- OCI image cache reuse — each `lv ct pull` re-fetches from the
  registry; the backup chunk store will eventually absorb image
  layers.
- Compose `workloads:` → Containers RPC dispatch **(shipped)**: `lv compose up`
  routes `kind: lxc` (download template or rootfs path) workloads through
  CreateContainer + StartContainer on the planner-resolved host, so a stack can
  mix VMs and containers.
- Managed container networking **(shipped)**: interface rows, IPAM, deterministic
  veth/MAC, DNS, security-group enforcement on veths, cross-host LB resolution, and
  project-scoped attach isolation — see *Networking* above. Remaining: auto-pull of
  OCI **registry** refs (pre-pull required today); a day-2 CT-aware security-group
  rebind API; a dataplane cross-project L2 firewall deny (admission already enforces
  the isolation invariant).
