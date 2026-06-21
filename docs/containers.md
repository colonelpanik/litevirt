# Containers (LXC + OCI)

litevirt's container subsystem runs Linux containers via the
LXC family of tools. OCI images (Docker registries, etc.) are pulled via
`skopeo` and converted to an LXC rootfs via `umoci`. Both binaries are
host bootstrap dependencies.

The runtime API mirrors the VM lifecycle (Create / Start / Stop / Delete
/ Console / Exec / List) so a single scheduler hosts both kinds of
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
    kind: oci
    image: docker.io/library/nginx:1.27
    cpu: 2
    memory: 512
    network: [{ name: prod, ip: 10.0.0.6 }]
```

The legacy `vms:` map still parses — every entry there gets `kind: vm`
applied implicitly so existing stacks need no changes.

## Networking

LXC's native `veth` driver attaches into an existing bridge. Containers
inherit the same network primitives the VM side uses (bridge, vxlan,
isolated), so a container can sit on a VXLAN-overlaid VNet alongside
VMs without any extra plumbing.

Attach NICs from the CLI with `--network` (repeat it for multiple NICs).
`bridge=` is required; `name=`, `ip=`, and `mac=` are optional:

```
lv ct create web --distro alpine --release 3.21 \
    --network bridge=br0,name=eth0,ip=10.0.0.6/24 \
    --cpu 2 --memory 512
```

With no `--network`, the container gets a single veth on the host's default
`lxcbr0` bridge (NAT to the outside). `internal/lxc/network.go` renders the
config snippet:

```
lxc.net.0.type = veth
lxc.net.0.link = br0
lxc.net.0.flags = up
lxc.net.0.name = eth0
lxc.net.0.ipv4.address = 10.0.0.6/24
```

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

## gRPC + WebUI

- **gRPC `Containers` service** — `Create / Start / Stop / Delete /
  Exec / List / PullOCIImage` RPCs. `lv ct …` defaults to gRPC;
  cross-host requests forward via `peerClient` to the named host.
  `--local` flag forces the host-local lxc-* path for bootstrap /
  debug. The `containers` cluster-state table backs cluster-wide
  `lv ct ls`.
- **WebUI `/containers`** — full lifecycle: a create modal (download-template
  distro/release/arch, CPU/memory, bridge), per-row Start/Stop/Delete + Exec
  (one-shot command modal), a host filter, and a bulk toolbar
  (start/stop/delete) with select-all.

## What's still in flight

- Per-container snapshots (LXC has native snapshot support, but
  litevirt's snapshot RPC is VM-only today).
- Migration + load-balancing for containers — VM-only today; a planned
  follow-up (cold migration via stop→stream rootfs→start; container-name
  LB backends).
- Live migration (CRIU). Cold migration is a copy + start at the
  destination — no different from VM cold migration.
- OCI image cache reuse — each `lv ct pull` re-fetches from the
  registry; the backup chunk store will eventually absorb image
  layers.
- Full compose `workloads:` → Containers RPC dispatch. The parser
  reads the `workloads:` map and `kind:` discriminator today
  (`compose.File.Workloads`); deploy/redeploy currently rejects
  `kind: lxc` and `kind: oci` with a pointer to `lv ct create`. The
  follow-up wires the dispatcher to call into the `Containers`
  service so a single compose stack can mix VMs and containers.
