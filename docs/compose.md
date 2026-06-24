# Compose Stacks

litevirt uses a Docker Compose-inspired YAML format to define multi-VM stacks. Deploy with `lv compose up`.

## Example

```yaml
name: "web-app"

images:
  ubuntu:
    source: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
    format: "qcow2"

networks:
  frontend:
    type: "vxlan"
    vni: 1000
    subnet: "10.0.100.0/24"
    host-isolation: true              # VMs can't reach the hypervisor
    dns: ["1.1.1.1", "8.8.8.8"]      # DNS for isolated VMs (optional, these are defaults)

vms:
  base-vm:
    image: "ubuntu"
    cpu: 2
    memory: "4G"
    replicas: 0                       # Don't deploy the base itself

  db:
    extends: "base-vm"
    cpu: 4
    memory: "8G"
    disks:
      root: "20G"
      data:
        size: "100G"
        bus: "virtio"
    network:
      - name: "frontend"
    placement:
      anti-affinity: ["web"]
    restart:
      condition: "on-failure"
      delay: "10s"
      max-attempts: 5
      window: "1h"

  web:
    extends: "base-vm"
    replicas: 3
    stop-grace-period: "30s"
    disks:
      root: "20G"
    network:
      - name: "frontend"
    cloud-init:
      userdata: |
        #cloud-config
        packages: [nginx]
        runcmd:
          - systemctl enable --now nginx
    placement:
      anti-affinity: ["db"]
      spread: true
      max-per-node: 1
    depends-on:
      db:
        condition: vm_healthy
    loadbalancer:
      vip: "10.0.100.50/24"
      snat: true                    # Outbound VM traffic SNATted to VIP
      ports:
        - listen: 80
          target: 80
    healthcheck:
      type: "http"
      target: "http://localhost:80/"
      interval: "10s"
      retries: 3
      action: "restart"
```

## Deploy and manage

```bash
lv compose up                    # Deploy (reads litevirt-compose.yaml)
lv compose up -f mystack.yaml    # Deploy from specific file
lv compose diff                  # Preview what would change
lv compose ps                    # List VMs in the stack
lv compose down                  # Tear down
```

## VM definition

```yaml
vms:
  <name>:
    image: "ubuntu"           # Base image name (required unless iso is set)
    iso: "/path/to/boot.iso"  # Boot from ISO instead of image
    kind: "vm"                # vm (default) | lxc | oci — see "Workloads" below
    cpu: 2                    # vCPUs (default 2)
    cpu-mode: "host-model"    # host-passthrough | host-model | custom
    memory: "4G"              # Memory: "4G", "4096M", or 4096 (MiB) — boot allocation
    min-memory: "1G"          # Ballooning floor the host may reclaim to (0 = none)
    max-memory: "8G"          # Ballooning ceiling the guest may inflate to (0 = fixed at memory)
    machine: "q35"            # Machine type: q35 (default) or pc
    firmware: "uefi"          # Firmware: uefi (default) or bios
    replicas: 1               # Number of instances (default 1)
    guest-agent: true         # QEMU guest agent (default true for images)
    ip-hint: "10.0.1.50"     # IP hint for non-cloud-init VMs (used by DHCP reservation)
    onboot: true              # Autostart when the host boots (default false)
    startup-order: 10         # Lower starts first among onboot VMs (default 0)
    start-delay: 5            # Seconds to wait after starting this VM before the next
    stop-delay: 0             # Seconds to wait after stopping this VM in an ordered shutdown
```

When `max-memory` exceeds `memory`, the VM gets a virtio memory balloon and can be
inflated/deflated at runtime (`lv set-memory <vm> <MiB>`); `min-memory` is the floor.
`onboot` VMs are started in `startup-order` when their host boots — a plain daemon
restart is a no-op (running VMs are left alone), only an actual host reboot triggers it.

`stop-delay` is the mirror of `start-delay` for an **orderly host shutdown**: running
`lv host shutdown-workloads <host>` stops that host's VMs in *reverse* `startup-order`
(highest first), waiting each VM's `stop-delay` before the next. It is an explicit
operator action — a normal daemon restart/upgrade leaves VMs running, so `stop-delay`
is consumed only by that command, never by routine daemon lifecycle.

`cpu-mode` controls how the guest CPU is exposed: `host-passthrough` (expose the host
CPU verbatim — fastest, but pins live migration to identical hardware), `host-model`
(a portable model close to the host), or `custom`.

With `replicas: 3`, VMs are named `web-1`, `web-2`, `web-3`. With `replicas: 1`, the base name is used directly.

## Workloads (VMs and containers)

The unified `workloads:` map holds VMs *and* containers; the `kind:`
discriminator selects the runtime. Entries without `kind:` (or `kind: vm`)
behave exactly like a `vms:` entry. The legacy `vms:` map still works and is
folded into `workloads` with `kind: vm` at parse time.

```yaml
workloads:
  app-vm:
    kind: vm                  # default; a libvirt-managed VM
    image: "ubuntu"
    cpu: 2

  sidecar:
    kind: lxc                 # a system container (LXC)
    image: "ubuntu"

  nginx:
    kind: oci                 # pull an OCI image and run it as an LXC container
    image: "docker.io/library/nginx:latest"
```

`kind: lxc` and `kind: oci` route to the container runtime (see
[`docs/containers.md`](containers.md)) and are full compose citizens: `lv compose
up` creates **and starts** them, re-apply is idempotent (unchanged containers are
left alone), a changed spec recreates the container, and `lv compose down`
removes them. Placement is **LXC-aware** — containers are only scheduled onto
hosts that advertise the container runtime, so they never land on a node that
can't run them. Image forms: `kind: lxc` takes a download template (`image:
"alpine:3.21"`) or a rootfs path; an OCI **registry ref** must be pre-pulled
today (`lv ct pull <ref> --dest <rootfs-dir>`, then set `image:` to that rootfs
path). Remaining follow-ups: OCI registry-ref auto-pull; in-place reconfigure
(cpu/mem changes recreate the container rather than live-tuning); and full
network/IPAM/security-group provisioning for container NICs (a container sharing
a stack network with a VM uses the bridge the VM path provisions).

## Service inheritance

Use `extends` to inherit fields from a base VM definition, reducing duplication across similar VMs:

```yaml
vms:
  base:
    image: "ubuntu"
    cpu: 2
    memory: "4G"
    replicas: 0               # Don't deploy the base itself

  web:
    extends: "base"
    memory: "8G"              # Override memory
    replicas: 3

  worker:
    extends: "base"
    cpu: 4                    # Override CPU
    labels:
      role: "worker"
```

Merge rules:

- **Scalars** (image, cpu, memory, firmware, etc.) — child wins if non-zero; zero-value inherits from parent.
- **Maps** (labels, disks) — keys are merged, child wins on collision.
- **Slices** (network, devices) — child replaces entirely.
- **Pointer structs** (placement, migrate, healthcheck, etc.) — child `nil` inherits parent; child non-nil replaces the entire struct.

Chained inheritance works: `top extends mid extends base`. Cycles are detected and rejected. Set `replicas: 0` on the base to prevent deploying it.

## Shutdown timeout

```yaml
    stop-grace-period: "30s"  # ACPI shutdown timeout before force-kill
```

When a VM is stopped (via `lv stop`, stack delete, or rolling update), litevirt sends an ACPI shutdown signal and waits up to the specified duration. If the VM hasn't shut down by then, it is force-killed.

Supports `s` (seconds), `m` (minutes), `h` (hours). Defaults to 30 seconds if not set.

## Disks

```yaml
    disks:
      root: "50G"                   # Shorthand: name + size
      data:                         # Full form
        size: "100G"
        bus: "virtio"               # virtio | scsi | sata
        cache: "writeback"          # writeback | writethrough
        storage: "nfs-volume"       # Reference a volume
        cluster_size: "2M"          # qcow2 cluster size (default 64K)
        refcount_bits: 16           # qcow2 refcount width (default 16)
```

## Networks

```yaml
    network:
      - name: "production"
        model: "virtio"             # virtio | e1000
        ip: "10.0.1.10"             # Static IPv4 (optional)
        mac: "52:54:00:12:34:56"    # Fixed MAC (optional)
        gateway: "10.0.1.1"
        trunk: [100, 101]           # VLAN trunk mode
        security-groups: ["web"]    # Per-NIC firewall (see "Firewall" below)
```

IPv6 can be set either by putting a v6 address in the `ip`/`gateway` fields, or
via the dedicated `ipv6:` / `ipv6-gateway:` fields (which also enable dual-stack
when paired with `ip:`):

```yaml
    network:
      - name: "v6lan"
        ip: "10.0.1.10"             # IPv4
        gateway: "10.0.1.1"
        ipv6: "2001:db8:1::42"      # /64 default if no prefix supplied
        ipv6-gateway: "2001:db8:1::1"
```

An empty `ipv6:` uses SLAAC (router advertisement) or DHCPv6 if the network is
configured for it. See [`docs/networking.md`](networking.md) for IPv6 specifics
(RA, dual-stack).

## Graphics

Console devices attached to the VM. Default: VNC enabled, SPICE off.

```yaml
    graphics:
      vnc: true       # default; set false to run headless
      spice: true     # add SPICE alongside (or instead of) VNC
```

Connect with:

```bash
lv vnc <vm>           # VNC connection info
lv spice <vm>         # SPICE connection info
lv spice <vm> --launch  # spawn remote-viewer if installed
```

Today SPICE traffic is not proxied through the daemon; clients must reach
the host's SPICE port directly. Use `ssh -L 5901:127.0.0.1:<port>` to
tunnel if needed. See [`docs/ui.md`](ui.md) for the in-browser console
options (VNC via noVNC; SPICE-in-browser is on the roadmap).

## Cloud-init

```yaml
    cloud-init:
      userdata: |
        #cloud-config
        users:
          - name: ubuntu
            sudo: ALL=(ALL) NOPASSWD:ALL
            ssh_authorized_keys:
              - ssh-rsa AAAA...
      networkconfig: |
        version: 2
        ethernets:
          eth0:
            dhcp4: true
```

## Placement

```yaml
    placement:
      # ── Hard constraints ──
      host: "host-a"                # Pin to specific host
      anti-affinity: ["db"]         # Don't co-locate with these VMs
      affinity: ["cache"]           # Co-locate with these VMs
      max-per-node: 1               # Max replicas on a single host (0 = unlimited)
      require:                      # Host MUST have these labels
        gpu: "true"
      prefer:                       # Host preferably has these labels (+5 score per match)
        zone: "us-east-1a"
      no-migrate: false             # Opt this VM out of all rebalancer-driven moves

      # ── Initial-placement scoring ──
      policy: balance               # balance | bin-pack | spread-strict | cost-aware
                                    # Or use named-mode aliases:
      mode: ha-critical             # performance | savings | ha-critical | spot-cheap

      # ── Day-2 reconciliation ──
      rebalance:
        mode: dry-run               # off | dry-run | on-demand | auto
        threshold: 15               # min % score gain to trigger a proposal (default 15)
        cooldown: 5m                # min interval per VM (default 5m)
        budget:
          max-concurrent: 2         # simultaneous live migrations cluster-wide (default 2)
          max-per-hour: 10
          window: off-hours         # named cluster time-window (planned)

      # Legacy (still works; translates to policy=spread-strict):
      spread: true
```

### Policy axes

litevirt's placement engine has two orthogonal axes (see
[placement.md](placement.md) for the full model):

1. **Policy** — initial-placement scoring strategy:
   - `balance` (cluster default): weighted-sum scorer over CPU/RAM/NUMA/host-gen, spreads via concave pressure curves.
   - `bin-pack`: invert; concentrate to free hosts for maintenance.
   - `spread-strict`: hard 50% per-dim pressure cap; hosts above are excluded entirely.
   - `cost-aware`: divide score by host `cost.hourly` label.

2. **Rebalancer mode** — day-2 reconciliation:
   - `off`: never propose moves.
   - `dry-run` (cluster default): write proposals; operator reviews via `lv rebalance list`.
   - `on-demand`: write proposals; require `lv rebalance approve <id>` before migration.
   - `auto`: write proposals + immediately approve (subject to budget).

The two compose freely; the rebalancer evaluates each VM under **its own** resolved policy, so a single cluster can mix bin-pack batch jobs with spread-strict prod VMs without one's policy influencing the other.

### Named-mode bundles

For the 80% case, named modes expand at parse time:

| Mode | Expands to |
|---|---|
| `performance` | `policy: balance` + `rebalance.mode: dry-run` |
| `savings` | `policy: bin-pack` + `rebalance.mode: auto` (off-hours window, generous budget) |
| `ha-critical` | `policy: spread-strict` + `rebalance.mode: on-demand` |
| `spot-cheap` | `policy: cost-aware` + `rebalance.mode: auto` |

Explicit `policy:` or `rebalance:` fields on the same `placement` block override the alias defaults.

### Hard constraints

`max-per-node` is a hard constraint: the placement engine will not place more than this many replicas of the same VM group on a single host. Use `max-per-node: 1` to ensure each replica runs on a separate host.

`no-migrate: true` opts the VM out of all rebalancer-driven moves and (planned) storage-motion. Set automatically by admission for VMs with non-migratable PCI passthrough.

See [`docs/placement.md`](placement.md) for the cost function, troubleshooting, and worked examples.

## Boot ordering (depends-on)

Control the order VMs are created during deployment. Dependencies are respected: a VM won't be created until its dependencies reach the specified condition.

```yaml
vms:
  db:
    image: "postgres"

  cache:
    image: "redis"

  app:
    image: "myapp"
    depends-on:
      db:
        condition: vm_healthy     # Wait for DB healthcheck to pass
      cache:
        condition: vm_started     # Wait for Redis to be running
```

Shorthand form (all conditions default to `vm_started`):

```yaml
    depends-on: [db, cache]
```

Conditions:

- `vm_started` — VM is in "running" state (default). Timeout: 5 minutes.
- `vm_healthy` — VM is running and healthcheck is passing (requires a `healthcheck` on the dependency). Timeout: 10 minutes.

If a dependency times out, deployment continues with a warning — it does not block the entire stack.

Cycles are detected at parse time and rejected.

## Load balancer

Defining a `loadbalancer` section automatically provisions HAProxy + keepalived on the
designated hosts. The VIP floats between hosts using VRRP (keepalived), and HAProxy
handles traffic distribution to backend VMs.

Standalone load balancers (not tied to a stack) can also be created with `lv lb create`.

```yaml
    loadbalancer:
      enabled: true                     # default false; auto-enabled if vip is set
      vip: "10.0.100.50/24"            # Virtual IP with CIDR (required)
      algorithm: "roundrobin"           # roundrobin | leastconn | source
      sticky-sessions: false            # Source IP sticky sessions
      snat: false                       # SNAT outbound VM traffic to VIP (see below)
      hosts:                            # Hosts to run HAProxy+keepalived on (optional)
        - "node1"                       # First host = VRRP master (priority 100)
        - "node2"                       # Additional hosts = VRRP backup (priority 50)
                                        # Omit to auto-detect: runs on hosts with stack VMs
      ports:
        - listen: 80                    # VIP listener port
          target: 8080                  # Backend VM port
          protocol: "tcp"               # tcp | http
          redirect-https: false         # Redirect HTTP to HTTPS
        - listen: 443
          target: 8443
          protocol: "tcp"
          tls:                          # TLS termination (optional)
            cert: "/path/to/cert.pem"
            key: "/path/to/key.pem"
      health:
        use-vm-healthcheck: true        # Reuse VM healthcheck for backend health
        type: "http"                    # tcp | http
        path: "/health"                 # HTTP health check path
        interval-ms: 2000               # Check interval in milliseconds
```

All VMs in the stack automatically become backends. Backend IPs are discovered via
ARP/DHCP after boot and persisted in the cluster database. **Containers in the stack
are backends too** — a single LB can front a mix of VMs and containers; give a
container NIC a static `ip:` (resolved cluster-wide) or, when the container runs on
the LB's own host, a DHCP address is resolved locally.

**Drain vs disable**: `lv lb drain` puts a backend in drain mode — it stops accepting
new connections but finishes existing ones. `lv lb disable` immediately removes the
backend from rotation. Use drain for graceful maintenance.

**Health & observability**: `lv lb inspect <name>` reports each backend's **real
HAProxy health** (`active`/`down`/`maint`/`draining`), not merely whether the
workload is running — a started VM with nothing listening on the target port shows
`down`. An LB whose VIP isn't actually assigned (keepalived not running on a host
that should run it) is reported as `state: degraded` instead of `active`; this is
checked across the LB's hosts, so `lv lb inspect` is accurate from any node. The
`litevirt_lb_keepalived_up{lb}` gauge (1 = VIP assignable on this host, 0 = not)
exposes the same signal for alerting — see [operating model](operating-model.md).

### SNAT via VIP

On host-isolated networks, VMs have no outbound internet access by default (no MASQUERADE rule). Setting `snat: true` on the load balancer enables outbound NAT: VM traffic destined for external IPs is source-NATted to the VIP address.

```yaml
networks:
  overlay:
    type: "vxlan"
    vni: 1000
    subnet: "10.100.0.0/24"
    host-isolation: true

vms:
  web:
    network:
      - name: "overlay"
    replicas: 3
    loadbalancer:
      vip: "192.168.1.50/24"
      snat: true                    # Outbound VM traffic SNATted to VIP
      ports:
        - listen: 80
          target: 8080
```

How it works:

1. VM sends a packet to an external IP (e.g., `apt update`)
2. The VM's default gateway is the IRB anycast gateway on the bridge (e.g., `10.100.0.1`)
3. The host forwards the packet out the default route interface
4. An nftables SNAT rule rewrites the source from the VM IP to the VIP
5. Return traffic arrives at the VIP → keepalived ensures it lands on the MASTER → conntrack maps it back to the VM

Requirements:

- The VIP must be routable from the upstream network
- IP forwarding is enabled automatically
- The IRB gateway on the bridge is set up by the VXLAN provisioner

**Conntrackd for failover**: When `snat: true` is set, litevirt automatically runs `conntrackd` alongside keepalived to replicate conntrack state between VRRP peers. On failover, the new MASTER imports synced entries so existing SNAT'd connections survive. This is managed automatically — no additional configuration is needed.

## Health checks

```yaml
    healthcheck:
      type: "http"          # tcp | http | ping | exec
      target: "http://localhost:8080/health"
      interval: "10s"
      timeout: "5s"
      retries: 3
      action: "restart"     # restart | migrate | alert
```

## Restart policy

Auto-restart VMs that crash or stop unexpectedly. This is distinct from healthcheck actions: healthcheck `action: restart` restarts a *running* VM that fails probes, while restart policy restarts a *stopped or crashed* VM.

```yaml
    restart:
      condition: "on-failure"     # none | on-failure | always
      delay: "10s"                # Wait before restarting
      max-attempts: 5             # Give up after 5 restarts (0 = unlimited)
      window: "1h"                # Reset attempt counter after this duration
```

litevirt decides whether to restart from *why* the workload stopped (the libvirt
shutoff reason), not merely that it is stopped:

- `none` — never auto-restart (default).
- `on-failure` — restart on an **unexpected** stop: a crash, a failed start, or a
  fence/external `destroy`. A clean guest-initiated shutdown (ACPI poweroff from
  inside the guest) or an operator `lv stop` is **never** restarted.
- `always` — same triggers as `on-failure` in litevirt: a clean guest shutdown
  and an operator stop always "stick". This is the **guest-stick** rule — unlike
  literal Docker `always`, litevirt will not fight a guest that asked to power off.
  Only an unexpected stop is restarted.

A suspended VM (managed-save / RAM snapshot) or a paused VM is never cold-booted
by the restart engine — it would discard saved RAM; resume it instead.

The attempt counter tracks restarts within the sliding `window`. Once `max-attempts`
is reached, the VM stays stopped until the window elapses (resetting the counter)
or an operator intervenes.

The same policy applies to **containers** (`lv ct create --restart …`), with one
caveat: LXC reports no stop *reason*, so a container cannot distinguish a clean
in-guest shutdown from a crash. Only an operator `lv ct stop` is guaranteed-stick;
any other stop is treated as unexpected and restarted per policy. A frozen
(paused) container is treated as running and never restarted.

## Update strategy

Control how VMs are updated when a compose file changes. The strategy determines how instances are replaced during `compose up`:

```yaml
    update:
      strategy: "rolling"          # in-place | recreate | rolling | all-at-once | blue-green
      max-unavailable: 1
      max-surge: 1
      order: "start-first"         # start-first | stop-first
      health-wait: "30s"
      rollback-on-failure: true
      pause-between: "5s"          # Delay between instances during rolling updates
```

Strategies:

- `recreate` — (default) Delete then create each VM sequentially. Simple but has downtime.
- `rolling` / `stop-first` — Update VMs one at a time: stop old, create new, wait for health check, continue.
- `start-first` — Create new VM first, wait for health check, then stop old. Minimizes downtime.
- `all-at-once` — Recreate all VMs simultaneously. Fast but risky. Supports `rollback-on-failure`.
- `blue-green` — Create a parallel set of new VMs ("-green" suffix), verify health, then cut over.
- `in-place` — Try live CPU/memory hot-add without restart. Falls back to recreate for non-hot-modifiable changes.

During a rolling update, creates (scale-up) execute first, then updates are processed according to the strategy, then deletes (scale-down) execute last.

## Migration policy

```yaml
    migrate:
      strategy: "live"              # live | cold | none
      max-downtime: "100ms"
      auto-converge: true
      with-storage: false           # Copy local disks during live migration
      on-host-failure: "restart-any"  # restart-any | restart-same | none
      fence-strategy: "best-effort" # best-effort | ipmi | manual | watchdog
      priority: 0                   # Higher priority VMs are migrated/rescued first
      bandwidth-mib-sec: 0          # Migration bandwidth limit (0 = unlimited)
      timeout-sec: 0                # Migration timeout (0 = no timeout)
```

## Backup

Attach a VM to the backup scheduler. The scheduler ticks every minute and
pushes a PBS-equivalent dedup snapshot on the `schedule` cron, then applies
`retention`.

```yaml
    backup:
      repo: "main"                # logical repo name (see "Backup repositories" below)
      schedule: "0 2 * * *"       # 5-field cron
      encryption: "aes256gcm"     # "" | "aes256gcm" | "tenant-key"
      retention:
        keep-last: 7
        keep-daily: 14
        keep-weekly: 8
        keep-monthly: 12
        keep-yearly: 3
```

When `backup:` is unset the VM is not backed up by the scheduler — operators can
still take ad-hoc snapshots via `lv backup`. See [`docs/backups.md`](backups.md).

## PCI device passthrough

```yaml
    devices:
      - type: "gpu"
        vendor: "10de"              # NVIDIA vendor ID
        count: 1
      - type: "network"
        sriov: true
        parent: "eth1"
      - mapping: "gpu-a100"         # cluster-wide resource mapping (see below)
```

A `mapping` references a cluster-wide **resource mapping** (`lv mapping`) — a named
alias for an equivalent passthrough device registered on one or more hosts. At
placement/start time litevirt resolves the mapping to the concrete PCI address on
the target host, so a passthrough VM can land on (or migrate to) any host that has a
device under that mapping. See [pci-passthrough.md](pci-passthrough.md#resource-mappings).

## Resource tuning

```yaml
    resources:
      hugepages: true               # Use huge pages for VM memory
      cpu-pinning: [0, 1, 2, 3]    # Pin vCPUs to specific host CPUs
      numa-topology: "strict"       # NUMA memory placement
      io-threads: 2                 # Number of I/O threads for disk operations
```

## Lifecycle hooks

```yaml
    hooks:
      pre-start: "#!/bin/bash\necho starting"
      post-start: "#!/bin/bash\ncurl -X POST http://webhook/started"
      pre-stop: "#!/bin/bash\necho stopping"
      post-stop: "#!/bin/bash\necho stopped"
      pre-migrate: "#!/bin/bash\necho migrating"
      post-migrate: "#!/bin/bash\necho migrated"
```

> **Security:** lifecycle hooks run as **root** on whichever host the VM is
> placed on, and re-run on every start/stop/migrate (including system-driven
> events like failover). Because that is effectively host-root authority that
> ignores the project/tenant boundary, **defining** a hook requires the
> `admin` role — creating a VM with a `hooks:` block as a mere `operator` is
> rejected. (Hook *execution* is not gated on the caller's role, so already-
> defined hooks keep firing on automated events.)

## Network definitions

```yaml
networks:
  production:
    type: "bridge"          # bridge | vxlan | isolated | sriov | direct
    interface: "br0"        # For bridge type
    vni: 1000               # For VXLAN type
    subnet: "10.0.1.0/24"
    dhcp: true
    nat: true               # Enable outbound NAT/masquerade (default true)
    learning: true          # MAC learning on bridge (default false)

  overlay:
    type: "vxlan"
    vni: 2000
    subnet: "10.200.0.0/24"
    host-isolation: true              # Block VM→host management traffic
    dns: ["1.1.1.1", "8.8.8.8"]      # DNS resolvers for isolated VMs

  mgmt:
    type: "direct"
    interface: "bond0.206"        # Host interface to attach VMs to via macvtap

  existing-bridge:
    external: true          # Use pre-existing network, don't create/destroy
```

### Host isolation

Setting `host-isolation: true` on a network blocks all traffic from VMs to the hypervisor's management plane (SSH, gRPC, metrics, etc.) while preserving VM-to-VM communication, including across hosts via VXLAN.

This follows the cloud provider model (AWS, DigitalOcean, GCP): the hypervisor is invisible to VMs. When host isolation is enabled:

- **No dnsmasq** — DHCP/DNS does not run on the bridge. No host process listens.
- **Static IPs via cloud-init** — IPAM still allocates IPs, but they are delivered via cloud-init V1 network-config (distro-agnostic: works on Ubuntu, CentOS, Debian, Arch, Alpine).
- **DNS from config** — resolvers come from the `dns` field (defaults to `["1.1.1.1", "8.8.8.8"]`).
- **IRB gateway stays** — the host keeps a gateway IP on the bridge for routing (FORWARD). VMs still have a default route. But no host *services* are reachable (INPUT is dropped).
- **No implicit NAT** — outbound internet access requires explicit `snat: true` on a load balancer (see below).

Under the hood, litevirt creates a per-bridge nftables chain on the `input` hook that drops all traffic from the bridge interface. VM-to-VM traffic uses the `forward` hook and is unaffected. VXLAN underlay (UDP 4789) arrives on the physical NIC, not the bridge, so it is also unaffected.

```yaml
networks:
  secure-overlay:
    type: "vxlan"
    vni: 1000
    subnet: "10.100.0.0/24"
    host-isolation: true
    dns: ["1.1.1.1", "8.8.8.8"]
```

Host isolation is optional and defaults to `false`. Existing behavior (DHCP, DNS, NAT from host) is unchanged when not set.

#### Host isolation with load balancers

When a load balancer VIP lives on an isolated network, litevirt automatically adds exceptions for:

- **VRRP** (IP protocol 112) — keepalived peer communication
- **VIP ports** — only the declared listener ports on the VIP address

All other traffic from VMs to the host remains blocked. These exceptions are managed automatically when LBs are applied or removed.

### External networks

Mark a network as `external: true` to reference a network that already exists in the cluster. litevirt will verify the network exists during deployment but will not create or destroy it.

External networks must not set `subnet`, `dhcp`, `vni`, or `type` — these are properties of the existing network.

This is useful for shared infrastructure networks managed outside of compose stacks, or for connecting VMs in different stacks to the same network.

## Volume definitions

```yaml
volumes:
  shared-storage:
    driver: "nfs"           # local | nfs | ceph | iscsi
    source: "10.0.10.1:/exports/vms"
    target: "/var/lib/litevirt/mounts/shared"  # override disk directory path
    options:
      vers: "3"
```

Compose volumes take priority over host-level storage pools (defined in `config.yaml`). If a disk's `storage:` name matches a compose volume, that definition is used. Otherwise, the daemon falls back to host pools, then to the default local driver. See [storage.md](storage.md) for host-level pool configuration.

## Stack-level settings

### DNS

Override the DNS domain for VMs in this stack. VM DNS records are registered as `<vm>.<stack>.<domain>`.

```yaml
dns:
  domain: "myapp.internal"
```

### Notifications

Send webhook notifications on stack lifecycle events (deploy, update, teardown):

```yaml
notifications:
  webhook: "https://hooks.example.com/litevirt"
```

### Backup repositories

Register logical backup-repo name → on-disk path mappings for the cluster, so a
VM's `backup: { repo: <name> }` resolves without editing daemon config. These
are CRDT-replicated and removed when the stack is deleted. A repo of the same
name in the daemon config (`backup_repos:`) takes precedence.

```yaml
backup-repos:
  main:
    path: /srv/backup/main
  offsite:
    path: /mnt/dr/offsite
```

### Firewall

litevirt's distributed firewall is driven from compose: top-level
`security-groups:` and `ipsets:` define reusable rule sets and named CIDR lists,
`firewall:` sets cluster-tier rules and the default policy, and a NIC references
security groups by name. All of this is persisted on deploy and enforced by the
per-host reconciler.

```yaml
# Reusable rule bundles referenced per-NIC by name.
security-groups:
  web:
    description: "public web tier"
    rules:
      - direction: ingress
        proto: tcp
        port: "80"
        cidr: "0.0.0.0/0"
        action: accept
      - direction: ingress
        proto: tcp
        port: "443"
        action: accept

# Named CIDR lists; reference one from a rule with cidr: "@office".
ipsets:
  office:
    description: "corporate egress ranges"
    cidrs: ["203.0.113.0/24", "198.51.100.0/24"]

# Cluster-tier rules + default policy for this stack.
firewall:
  default-deny: true            # drop anything not explicitly accepted
  cluster-rules:                # applied before per-NIC rules, on every NIC
    - direction: ingress
      proto: icmp
      action: accept
    - direction: ingress
      proto: tcp
      port: "22"
      cidr: "@office"
      action: accept

vms:
  web:
    network:
      - name: "frontend"
        security-groups: ["web"]   # attach the SG to this NIC
```

Per-NIC security groups can also be bound at runtime with
`lv sg bind <vm> --network <name> --sg <name>`. See
[`docs/firewall.md`](firewall.md) for the three-tier model and CLI surface.
