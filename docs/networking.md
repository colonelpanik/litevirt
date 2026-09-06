# Networking

litevirt attaches VMs to Linux bridges on the host. It does not manage the physical network fabric — your switches, routers, and underlay are your responsibility.

## Network types

### Bridge (default)

Attaches VMs directly to a Linux bridge. The simplest option for flat datacenter networks.

```yaml
networks:
  lan:
    type: "bridge"
    interface: "br0"
```

litevirt auto-creates the bridge if it doesn't already exist. If you need to attach a physical uplink, create the bridge manually beforehand:

```bash
ip link add br0 type bridge
ip link set br0 up
ip link set eth0 master br0    # attach uplink
```

### VXLAN

Creates overlay networks between hosts using VXLAN encapsulation. Useful when you need L2 connectivity across L3 boundaries.

```yaml
networks:
  overlay:
    type: "vxlan"
    vni: 1000
    underlay: "eth0"
    port: 4789
    subnet: "10.10.0.0/24"
    dhcp: true
```

litevirt manages VTEP and forwarding-database (FDB) state itself — there is no
BGP or EVPN control plane, and no routing daemon to install. When a host
provisions the network it records its VTEP address in the replicated cluster
database, then reads that table back and installs an all-zeros
`00:00:00:00:00:00` flood entry for each peer VTEP already listed, so BUM
traffic is head-end replicated to the peers it knows about; a peer that
provisions later can also push its VTEP straight to this host, which adds the
entry on the spot. Those kernel flood entries are only ever added — an
individual entry is never withdrawn when a host leaves the network (they go away
only with the local VXLAN device), and nothing re-derives the set from the
database outside a provisioning pass, so a newly-joined host may stay absent
from an existing peer's entries until that peer next provisions, which a daemon
restart does. Unicast MAC→VTEP entries are programmed explicitly rather than
learned: when a VM's address is discovered, and again when that VM migrates or
is deleted, its host fans a `bridge fdb` add/delete out to every peer over the
cluster's mTLS gRPC, so remote hosts point the MAC at whichever host now owns
it. Setting `subnet:` also gives every host the same anycast gateway — the first
usable address in the subnet — on the VNI bridge, so a VM's default route is
host-local.

### Isolated

A host-local bridge with no external connectivity. VMs on the same host can communicate, but there is no path to the outside.

```yaml
networks:
  internal:
    type: "isolated"
    subnet: "172.16.0.0/24"
    dhcp: true
```

The host bridge for an isolated network is `br-iso-<name>`; when that would
exceed Linux's 15-char interface-name limit it is automatically shortened to a
stable hashed form, so network names of any length work.

### SR-IOV

Passes a virtual function (VF) from an SR-IOV-capable NIC directly to the VM for near-native network performance.

```yaml
networks:
  fast:
    type: "sriov"
    pf: "eth1"
    spoof-check: true
```

Requires:

- IOMMU enabled in BIOS and kernel (`intel_iommu=on` or `amd_iommu=on`)
- SR-IOV capable NIC with VFs created
- `vfio-pci` kernel module loaded

### Direct (macvtap)

Attaches VMs directly to a host interface using macvtap, without creating a bridge. This is useful when the host interface carries the host's management IP (e.g., a VLAN sub-interface) and enslaving it to a bridge would disrupt connectivity.

```yaml
networks:
  mgmt:
    type: "direct"
    interface: "bond0.206"
```

The VM gets L2 access to the same network as the parent interface. No bridge, DHCP, or NAT is created by litevirt — the interface must already exist on the host.

When to use direct mode:

- **Management VLANs** — the host IP lives on a VLAN interface (e.g., `bond0.206`) and moving it to a bridge is impractical or risky.
- **Simple flat attachment** — you just need VMs on the same L2 segment as the host, with no overlay or isolation.

Limitations:

- **No VM-to-host communication** — macvtap in bridge mode does not allow the guest to reach the host's IP on the parent interface. This is a kernel-level restriction of macvtap. VMs can reach other devices on the network, but not the hypervisor itself via that interface.
- **No DHCP from litevirt** — IP assignment must come from an external DHCP server or be configured statically via cloud-init.
- **Interface must exist** — litevirt does not create the parent interface. It must be present on the host before deployment.

## VM network attachment

```yaml
vms:
  web:
    network:
      - name: "lan"
        model: "virtio"           # virtio (default) or e1000
        ip: "10.0.1.50"           # optional, DHCP if omitted
        mac: "52:54:00:ab:cd:ef"  # optional, auto-generated if omitted
        gateway: "10.0.1.1"       # optional
```

Multiple networks can be attached to a single VM:

```yaml
    network:
      - name: "frontend"
      - name: "backend"
        ip: "172.16.0.10"
```

## Container network attachment

Containers attach to the same logical networks as VMs and reach parity on the
managed path. A *managed* NIC (`network=<name>` on the CLI, or a compose `kind:
lxc` workload's `network:`) gets a tracked `container_interfaces` row, a
deterministic host veth + locally-administered MAC, an IPAM lease, a DNS record,
and per-NIC security-group enforcement on its veth. A *raw* NIC (`bridge=<br>`)
attaches straight onto a host bridge with no managed state (the admin escape
hatch).

```bash
lv ct create web --network network=app-net,name=eth0,security-groups=web;db
```

Bridge-family networks (bridge / vxlan / isolated) are supported; `direct` and
`sriov` are VM-only. See [containers.md](containers.md) for the full container
networking model.

## Network ownership (project isolation)

A network is either **global** (the default — usable by every project) or **owned
by a project**:

```bash
lv network create app-net --type bridge --project acme   # owned + isolated
lv network create mgmt --type bridge                     # global (shared)
```

A workload may attach only to a global network or one its own project owns;
attaching to another project's network is denied at create/attach time. A raw
bridge is outside isolation, so it requires cluster-root authority (a project
workload must use a managed network). See [tenancy.md](tenancy.md).

## VLAN trunk mode

For VMs that need to handle multiple VLANs (e.g., virtual routers):

```yaml
    network:
      - name: "trunk-port"
        trunk: [100, 101, 200]
```

## VM IP addressing

How a VM gets its address depends on when and how you set it:

- **Static IP at create.** Set a per-NIC IP (and optional gateway) when creating the VM. For a cloud image, litevirt writes a cloud-init NoCloud `network-config` (attached as a read-only cdrom) so the guest applies the static address at first boot. This requires a cloud-init-capable guest image; it is not applied to images that do not run cloud-init.
- **DHCP.** Leave the IP blank to use the network's addressing. On a DHCP-enabled managed network the guest gets a dynamic lease; litevirt then observes the address (ARP / DHCP leases) and records it back for display.
- **Recorded (post-create) IP.** `lv config <vm> --ip <ip>` records the IP in inventory and, when a DNS domain is configured, makes a best-effort attempt to publish a DNS record (a DNS failure is logged, not fatal). It does **not** reconfigure a running guest, take a DHCP reservation, or change the guest's actual address — to change a running VM's IP, reconfigure it in the guest (or recreate it with the desired static IP).

```yaml
# Static IP at create (cloud image), via the compose spec or the web UI:
    network:
      - name: "lan"
        ip: "10.0.1.50"       # optional: gateway, ipv6
```

```bash
# Record an IP for an existing VM (inventory / DNS only — does not touch the guest):
lv config my-vm --ip 10.0.1.50 --network lan
```

### Binding a network to NetBox

`lv network create <name> --netbox-prefix-id <id>` binds a network to a NetBox
prefix. VM NICs on a bound network claim their address from NetBox instead of
requiring an operator-supplied IP.

Binding requires:

- the `netbox_ipam_v1` capability latch, DURABLY — persisted to disk, not just
  active in this process's memory — which requires `netbox.enabled` on every
  node;
- the prefix to live in a VRF with `enforce_unique` set — global-table prefixes
  are refused, because NetBox does not expose the global uniqueness setting;
- the prefix not to be bound to another litevirt network already.

While NetBox is unreachable, creating a VM on a bound network fails. Existing
VMs are unaffected, and unbound networks are unaffected.

### Suspended bindings

Bind-time validation is re-run continuously, because it goes stale: a prefix can
be re-CIDRed, moved out of its VRF, or have that VRF's `enforce_unique` switched
off, all in NetBox and none of it announced to litevirt. The prefix ID keeps
naming the same object, so a binding never silently follows a change — but when
the prefix no longer satisfies what the bind checked, the binding is
**suspended**:

- new allocations on that network refuse, with the reason in the message;
- running VMs are untouched, and keep the addresses they hold.

An unreachable NetBox is *not* drift and never suspends a binding — silence is
not a change.

Suspension is deliberately sticky: nothing lifts it automatically. Which command
lifts it depends on what drifted — see the two sections below.

### Resuming a suspended binding

Repair the prefix in NetBox, then:

```bash
lv netbox resume <network>
```

Resume rewrites nothing. It re-runs every bind-time check against the facts the
binding pinned and clears the suspension only when all of them agree again; while
the drift is still present the command is refused, naming the reason, and the
binding stays suspended.

Repairable in place, by fixing NetBox and running `lv netbox resume`:

| Drift | Repair |
|---|---|
| the prefix's VRF stopped enforcing uniqueness | set `enforce_unique` on the VRF again |
| the prefix was moved to the global table | move it back into a VRF with `enforce_unique` |
| the prefix was re-CIDRed | revert the CIDR to the one the binding recorded |

A suspension caused by a **cluster CA replacement** is not repaired in NetBox and
`lv netbox resume` will not lift it — the identities have to be rewritten first
with `lv netbox rekey` (below). The refusal message says so.

**Re-CIDRing a bound prefix is not supported in v1.** Resume validates against the
CIDR the binding recorded and writes it back unchanged, so a prefix NetBox now
reports under a different CIDR stays suspended however many times the command is
run. That is deliberate: the addresses already handed out do not move with the
prefix, and both the orphan sweeper and lease repair enumerate NetBox by the
recorded CIDR — adopting a new range would make every address claimed from it
invisible to the reclaim proof. Either revert the CIDR in NetBox, or delete and
recreate the litevirt network, which releases the binding and re-claims it
against the new range.

### Recovering from a CA replacement

The cluster fingerprint in every NetBox identity is derived from the cluster CA
certificate — that is what stops two litevirt clusters sharing one NetBox from
reclaiming each other's addresses. Replacing the CA changes it, so bindings
suspend and new allocations refuse until the existing objects are re-stamped:

```bash
lv netbox rekey <network>
```

Running VMs are unaffected by the suspension. The command rewrites the identity
on every address the binding owns and then resumes the binding — in that order,
so a run that fails partway leaves the binding suspended rather than live with
half its objects unrecognisable. Re-running finishes the job; objects already
rewritten are skipped. Complete a re-key before replacing the CA again.

A re-key answers the fingerprint pin and nothing else. If the prefix had ALSO
drifted — re-CIDRed, say — the rewrite still happens, but the binding is left
suspended under the remaining reason and the command reports it. Repair that in
NetBox and run `lv netbox rekey` again.

Both commands are admin-only and both write an audit record (`netbox.rekey`,
`netbox.resume`), so `lv audit verify` carries a trace of every identity rewrite
and every lifted suspension.

### Maintenance and reclamation

Every node configured for NetBox runs a maintenance pass on the
`netbox.sweep_interval_sec` cadence (900 seconds by default). One pass does two
things, in this order:

1. **Re-validate every binding** against NetBox, suspending any that has drifted.
   Nothing lifts a suspension on its own: `lv netbox resume` clears one whose
   drift you have repaired in NetBox, and `lv netbox rekey` rewrites the
   identities a CA replacement invalidated so a resume can then succeed.
2. **Reclaim orphans** — addresses NetBox still holds under this cluster's
   identity that nothing claims any more.

The order is the safety property. A binding suspended by step 1 is out of scope
for step 2 in that same pass, and a revalidation that could not COMPLETE — an
unreadable cluster database, a suspension that could not be recorded — skips the
sweep entirely. A binding litevirt could not check is not one it will delete
against.

Reclamation is the only thing in litevirt that deletes an address from NetBox,
so it happens only under a whole-cluster proof:

- exactly one node sweeps, elected through a cluster-wide lease;
- **every** eligible host must answer, and answer with a complete scan. One
  unreachable host, one incomplete answer, or a membership change mid-proof and
  the address is left alone;
- an address any host still claims, or that a live local lease references, is
  never touched;
- an address younger than 30 minutes is never touched, so an in-flight create is
  not swept out from under itself.

Nothing here is best-effort. Leaking an address the next pass can reclaim is
always preferable to freeing one a running guest is using, so every doubt leaves
the address allocated. Expect reclamation to pause whenever the cluster is not
whole — that is the design, not a fault.

**After a permanent host loss the sweeper stays inert** until an operator
attests the machine is off:

```bash
lv host fence-confirm <host>
```

Without that, the lost host is simply unreachable, every proof is incomplete,
and nothing is ever reclaimed. The attestation counts for 24 hours — long enough
that a confirmation does not expire between passes — and only for a host that is
still unreachable: a host that comes back is never excluded from the proof set,
whatever the fencing record says.

Two things follow from that, and both are deliberate. During those 24 hours a
host that is unreachable but alive is out of the proof set, so an address only it
holds could be reclaimed — confirm a fence only for a machine you know is off.
And the attestation cannot be revoked early; if it was given in error, the way
back is to make the host reachable again.

**During a rolling upgrade, reclamation pauses.** A peer running a build that
does not implement the proof RPC counts as unreachable, so no proof is complete
until every node has been upgraded. Nothing needs doing about it — the sweep
resumes on its own once the upgrade finishes.

### Stuck leases

A **stuck lease** is an address a rolled-back create queued for release in NetBox
while a live local allocation row still references it — what a compensating
release that did not land leaves behind. It is not an orphan: something still
holds the address locally, so nothing may delete the NetBox object.

The sweeper reports it and never acts on it: the counter
`litevirt_netbox_stuck_leases_total` rises and an error log names the address.
It is deleted from neither system automatically, because a lease that disagrees
with the workload record is exactly the case where an automatic deletion could
free an address something is really using. Reconcile it by hand — confirm no
guest holds the address, then delete the allocation and let the next pass
reclaim the NetBox object.

## NAT

By default, litevirt enables IP masquerading (NAT) for networks with a subnet defined. This gives VMs outbound internet access through the host.

To disable NAT on a network:

```yaml
networks:
  internal:
    type: "bridge"
    interface: "br-internal"
    subnet: "10.0.5.0/24"
    dhcp: true
    nat: false
```

NAT is ignored on isolated networks (no uplink) and on host-isolated networks (use `snat: true` on a load balancer instead — see [compose.md](compose.md#snat-via-vip)).

## IPv6

Network subnets accept IPv6 CIDRs. The IPAM allocator, dnsmasq DHCP/RA
configuration, and cloud-init network-config all handle v4 and v6
identically:

```yaml
networks:
  v6lan:
    type: "bridge"
    interface: "br0"
    subnet: "2001:db8:1::/64"
    dhcp: true     # enables DHCPv6 + Router Advertisements via dnsmasq
```

Notes:

- For v6, the gateway is `<network>::1` (e.g., `2001:db8:1::1`) and IP
  allocation starts at `<network>::2`. Up to 65 535 host addresses are
  enumerable per subnet (caps the IPAM scan; SLAAC-only deployments
  bypass this entirely).
- When `dhcp: true` on a v6 subnet, dnsmasq runs with `--enable-ra` so
  SLAAC-only guests still get a default route.
- VMs can have static v6 addresses via `ip:` on the network attachment
  (cloud-init network-config v1 handles them as `address: 2001:db8::42/64`),
  or via the dedicated `ipv6:` / `ipv6-gateway:` fields when running dual-stack
  alongside a v4 `ip:`:

  ```yaml
      network:
        - name: "v6lan"
          ip: "10.0.1.50"
          gateway: "10.0.1.1"
          ipv6: "2001:db8:1::42"
          ipv6-gateway: "2001:db8:1::1"
  ```

  An empty `ipv6:` falls back to SLAAC / DHCPv6 if the network is configured
  for it.
- Mixed dual-stack works: declare both v4 and v6 subnets on the same
  bridge if your guest expects both.

## DNS

litevirt runs a lightweight DNS server (default port 5354) that resolves VM **and managed-container** names to IP addresses. Records are created and removed automatically as workloads get an IP, move, or are deleted.

Name format: `<name>.<stack>.<domain>` in a stack, or `<name>.<domain>` standalone — the same namespace for VMs and containers. For example, with the default domain `litevirt.local`, `web-1` in the `myapp` stack resolves as `web-1.myapp.litevirt.local`. A managed container's record is maintained by the per-host IP scanner (which discovers a DHCP address, persists it, and writes the record); a migrate re-creates it on the target.

Configure the domain in `config.yaml`:

```yaml
dns_domain: "litevirt.local"
dns_port: 5354
```

## Security groups

Security groups **are implemented and enforced.** They provide per-VM
firewall rules via nftables, applied by the per-host firewall reconciler
that polls cluster state every 30 s. See [firewall.md](firewall.md) for
the full three-tier model (cluster / host / VM), the `lv sg` CLI, and
the AWS/GCP/Proxmox direction semantics.

Compose syntax (top-level `security-groups:`, referenced per-NIC):

```yaml
security-groups:
  web-sg:
    rules:
      - direction: "ingress"
        proto: "tcp"
        port: "80"
        cidr: "0.0.0.0/0"
        action: "accept"
      - direction: "ingress"
        proto: "tcp"
        port: "22"
        cidr: "10.0.0.0/8"
        action: "accept"

vms:
  web:
    network:
      - name: "lan"
        security-groups: [web-sg]
```

## Host network configuration

`lv host network` manages the **host's own wiring** — bridges, bonds (including
LACP), VLAN interfaces, and physical-NIC addressing — the layer underneath the
managed VM networks above. Intent is recorded per host and rendered by that
host into a single litevirt-owned netplan file (`/etc/netplan/90-litevirt.yaml`);
litevirt never edits any other netplan file, and refuses to manage an interface
another file already defines.

The flow is deliberately two-step — record, then apply behind a rollback:

```bash
# Record intent: a bridge over eth1 with a static address.
lv host network set vmbr0 --host node-2 --kind bridge --member eth1 \
    --address 10.0.10.2/24 --gateway 10.0.10.1 --nameserver 10.0.10.1

# An LACP bond and a VLAN on top of it.
lv host network set bond0 --host node-2 --kind bond --member eth2 --member eth3 \
    --bond-mode 802.3ad --lacp-rate fast --hash-policy layer3+4 --mtu 9000
lv host network set vlan40 --host node-2 --kind vlan --vlan-link bond0 --vlan-id 40 --dhcp4

# See exactly what would change on the host (writes nothing).
lv host network plan --host node-2

# Apply behind the timed rollback.
lv host network apply --host node-2

lv host network ls --host node-2
lv host network rm vlan40 --host node-2   # takes effect on the next apply
```

`apply` runs `netplan try`: the change is reverted — kernel-side, even if the
daemon dies mid-window — unless the host confirms its own connectivity
(advertise address still assigned, its own gRPC listener answering, and the
prior default gateway still reachable). A failed confirm restores the previous
file and records the intent as `rolled_back` with the cause, visible
cluster-wide in `lv host network ls`.

A plan that would touch the interface carrying the **cluster LAN** —
reconfiguring it, enslaving it into a bridge/bond, or moving the advertise
address — is refused unless you name that interface with
`--force-interface <iface>` (the name is shown by `plan`). Naming it is the
confirmation that you understand you may be disconnecting the node.

Removal is two-step as well: `rm` tombstones the intent, and the next `apply`
renders the file without it. Note netplan does not delete an existing virtual
device when its definition disappears: the interface stays up (unconfigured)
until the next reboot, or until the operator removes it with `ip link del`.
The persistent config is gone either way — it will not return after a reboot.
