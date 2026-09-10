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
`sriov` are VM-only, and so is any network **bound to a NetBox prefix** whatever
its type — a container on one is refused at create rather than allocated around
the external IPAM (see [Binding a network to NetBox](#binding-a-network-to-netbox)
below). See
[containers.md](containers.md) for the full container networking model.

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
- **Recorded (post-create) IP.** `lv config <vm> --ip <ip>` records the IP in inventory and, when a DNS domain is configured, makes a best-effort attempt to publish a DNS record (a DNS failure is logged, not fatal). It does **not** reconfigure a running guest, take a DHCP reservation, or change the guest's actual address — to change a running VM's IP, reconfigure it in the guest (or recreate it with the desired static IP). It is **refused on a network bound to a NetBox prefix**: there the address of record is NetBox's — allocated by the binding and kept assigned by the inventory mirror — so a recorded value would describe an address litevirt does not hold.

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

### What to set up in NetBox first

Two things have to exist in NetBox before litevirt can use it, and neither is
created for you.

**An API token.** `netbox.token_path` points at a file holding it. On NetBox 4.5
and later a deployment cannot issue any token at all until its configuration
defines `API_TOKEN_PEPPERS` — a dict of id to secret, each secret at least 50
characters — so an otherwise healthy new install answers every token creation
with `API_TOKEN_PEPPERS is not defined`. That is NetBox's own prerequisite, not
litevirt's, but it is the first thing to hit. Either token scheme works: 4.5
issues `nbt_`-prefixed tokens by default and litevirt authenticates with those
and with the older 40-character form, as long as the file holds the whole value
the UI showed.

**A custom field named `litevirt_identity`,** of type text, on all three of
`ipam.ipaddress`, `virtualization.virtualmachine` and
`virtualization.vminterface`. This is the field that makes an object litevirt's:
the orphan sweeper proves an address unclaimed by matching on it, and re-keying
rewrites it. NetBox rejects a write naming a custom field it does not have, so
without it every address claim fails with
`Custom field 'litevirt_identity' does not exist for this object type` — a 400,
which litevirt reports as NetBox refusing the write rather than as a
misconfiguration. Create it before the first bind. Only the three object types
above need it; the field's label, description and default may be anything.

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
- the prefix not to be bound to another litevirt network already;
- litevirt's own DHCP server not to serve the network's subnet — see below;
- the `litevirt_identity` custom field to exist — see above.

While NetBox is unreachable, creating a VM on a bound network fails. Existing
VMs are unaffected, and unbound networks are unaffected.

`lv run` is the only path that claims an address, so the paths that would
otherwise hand a guest an address litevirt never reserved are refused on a bound
network: clone, live-restore, import, rebuild, and a renamed promote. Converting
a VM to a **template** is refused too, for the opposite reason — a template is
invisible to the inventory mirror, so the address it kept holding would be
reclaimable by neither the mirror nor the orphan sweep. Detach the NIC first;
that releases the address, and the conversion then goes through.

#### litevirt's own DHCP server is refused over a bound prefix

When litevirt starts `dnsmasq` for a network it derives the gateway as the
subnet's first host and leases a pool spanning essentially the whole subnet.
**None of that is a database row.** There is no lease, no allocation, nothing
NetBox is ever told — so if a bound prefix overlaps that subnet, NetBox's
`/available-ips/` and `dnsmasq` allocate from the same range with no knowledge
of each other, and NetBox will eventually offer a VM the gateway address itself.

So a bind is **refused** when litevirt would serve DHCP for a subnet that
overlaps the prefix. That refusal is not a reservation, and could not be: the
gateway is one address and could be reserved, but the pool is dynamic and spans
the prefix, so reserving it would leave NetBox nothing to allocate.

Whether `dnsmasq` runs depends on the network definition:

| Network shape | litevirt serves DHCP | Bindable |
|---|---|---|
| No `--subnet` | never | yes |
| `--type bridge` on a bridge litevirt creates | yes | **no** |
| `--type bridge` on a bridge that already exists, no `--dhcp` | no | yes |
| `--type bridge` with `--dhcp` | yes | **no** |
| `--type bridge --vlan N` (tagged physical network) | never | yes |
| `--type direct` (macvtap) or `--type sriov` | never | yes |
| `--type isolated` with a subnet | yes, on every host | **no** |
| `--type vxlan` with a subnet | yes, on the elected gateway host | **no** |
| `host-isolation: true` | never | yes |
| Subnet disjoint from the bound prefix | (irrelevant) | yes |

The usual production shape — a NetBox-bound network on an existing
infrastructure bridge, with the subnet recorded so guests get the right prefix
length and default gateway — is bindable, and stays bindable. A tagged physical
VLAN (`--vlan`) and macvtap (`--type direct`) are bindable too.

**Whether the bridge already exists is a fact about ONE host.** The same network
definition starts `dnsmasq` on a host where litevirt has to create the bridge
and not on a host that already has it, so a bind validated on one node cannot
speak for the rest. Two things follow:

- The bind refuses on the two grounds it can establish: shapes that serve DHCP
  on *every* host (or on an elected host) whatever the local state, and the
  binding node's own answer for the bridge case. The error message says which of
  the two it was.
- **Provisioning refuses as well.** A host that would start `dnsmasq` for a
  network bound to a NetBox prefix fails the provision instead, with a message
  naming **that host**, the network, the prefix and the bridge. That is where the
  host-local fact is finally known, and it is what stops a node added later — or
  a node that never had the bridge — from standing up a second allocator over a
  prefix NetBox believes it owns. No `dnsmasq` is started over the bound prefix
  on any host, under any local state: that part is unconditional.

  The refusal happens **before** the bridge is created, so it is idempotent: a
  retry reads the same host state and refuses identically. (It used to create the
  bridge and then refuse, so the second attempt read a pre-existing bridge,
  concluded litevirt was not the DHCP authority, and provisioned with no DHCP
  server at all — guests with no addresses and no explanation.)

  **It does not stop the placement.** Every caller of provisioning logs the
  refusal and falls back to the network name as the bridge, then creates that
  bridge itself — VM create, clone-from-template, the reconciler restarting a VM
  after a failover, and NIC hot-attach all behave this way, and always have. So
  a VM *is* placed on the host the refusal named, on a bridge litevirt just
  made: no DHCP server, nothing enslaved to carry traffic off the host, and no
  gateway, while the guest holds an address NetBox believes is routable. The
  refusal's message says so. Fix the network definition — a bridge with no
  uplink is not a working configuration for a bound network.

  It is also **discoverable before anybody hits it**. Every configured node
  checks its own bridge state against every bound network on each maintenance
  pass and raises `netbox_dhcp_would_race` in `lv health`, naming the network
  and both remedies: create an **uplinked** bridge on that host, or define the
  network so litevirt serves no DHCP on it. The two remedies are interchangeable
  — an infrastructure bridge litevirt did not create gets no DHCP server — but
  the first one only counts if the bridge actually enslaves something (a NIC, a
  bond, a VLAN sub-interface, another bridge). A bridge that exists and carries
  nothing but guest taps is the one a placement auto-created, so the finding
  **stays raised** on it rather than resolving itself while the guest sits
  there with no route.

##### What this does NOT cover

- **Load-balancer VIPs are not reserved.** A VIP never takes a lease, so no
  `ip_address` object is created for it and NetBox will offer it to the next VM
  that claims an address from an overlapping prefix. A VIP can also be
  configured long after the bind, so no bind-time check could catch it. Record
  VIP addresses in NetBox by hand before binding a prefix that contains them.
- **The gateway is still not reserved on the shapes this permits.** On an
  infrastructure bridge the gateway belongs to a router litevirt does not
  manage, and litevirt creates no `ip_address` object for it. Record the gateway
  (and any other infrastructure address inside the prefix) in NetBox before
  binding, or reserve that part of the range in NetBox. Removing litevirt's own
  DHCP server as a competing allocator is what the refusal does; it does not
  make the prefix exclusively litevirt's.
- **A foreign DHCP server on the same subnet** is outside litevirt's knowledge
  entirely.
- **A second litevirt network sharing the subnet.** The bind inspects the
  definition being bound; an unbound network with the same subnet, serving DHCP
  from its own `dnsmasq`, is not visible to it.

### Binding a subnet that already has VMs on it

This is the ordinary way a bind happens on a cluster that is already running, and
the bind handles it: **the addresses your guests already hold are adopted into
NetBox as part of the bind**, before the binding ever serves a claim.

It has to be. NetBox's notion of an available address is "no `ip_address` object
exists", so an address a guest holds that NetBox has never been told about is one
NetBox will offer to the next VM created on that network — two guests, one
address. Nothing else in litevirt ever tells NetBox about such an address: the
inventory mirror only assigns and clears objects that already carry a NetBox id,
and those ids come only from a claim.

The bind therefore creates the binding **suspended**, records every existing
address, and only then resumes it. While it is suspended the network serves no
address claims, so a half-finished adoption can never hand out an address that
has not been recorded yet.

An address is adopted from the guest's **NIC record** — the address `lv run
--ip`, a compose file or the IP scanner put there — for every VM whose address
falls inside the bound prefix. An address outside the prefix is left alone: the
network's own subnet and the bound prefix need not be identical, and NetBox will
never offer an address it does not contain. Re-running a bind is safe: an address
litevirt has already recorded against that prefix is skipped, and issues no
NetBox request at all.

#### What is not adopted

Adoption can only record an address litevirt actually **has** written down, so
being explicit about the rest matters more than the happy path:

- **A NIC with no recorded address is not adopted** — there is nothing to claim.
  If its VM is anything other than **stopped**, the bind is **refused** instead:
  that guest may already be using an address inside the prefix, and NetBox would
  offer the same one to the next VM created here. Usually the fix is simply to
  wait — the IP scanner records a running guest's DHCP address within 30 seconds,
  and then the bind adopts it. Stopping the VM or detaching the NIC also clears
  it.
- **A stopped VM with no recorded address is stepped over**, and the bind
  proceeds. Its guest is holding nothing right now, so there is nothing to
  collide with, and refusing here would refuse the bind on almost every real
  cluster. What covers it afterwards is the
  [discovery gate](#addresses-discovered-after-the-bind): when it is next started
  and its address is discovered, recording that address becomes a *claim*.
- **A container's address is never adopted** — it refuses the bind, from any of
  the places a container NIC is recorded (its address lease, or its managed NIC
  row on a subnet-less/DHCP network where there is no lease at all). Containers
  are not supported on a bound network, so an adopted container lease could never
  be renegotiated.
- **A legacy raw-bridge container NIC is invisible**, and cannot be otherwise. It
  attaches to a host *device* rather than to a litevirt network, so litevirt
  cannot attribute it to the network being bound, and a DHCP one records its
  address nowhere at all. (A raw bridge that resolves to exactly one managed
  network is *not* in this class: it becomes a managed NIC, and is then covered by
  the refusal above.) Such a NIC is in the same position as any non-litevirt host
  on the same L2 — a physical server, another hypervisor — and NetBox is the
  authority for those: an `ip_address` object in NetBox is what keeps its address
  out of `/available-ips/`. If you have raw-bridge containers or external hosts
  sharing a bound prefix, record them in NetBox.

#### Binding from a node that is still replicating

Adoption reads **this node's** copy of the replicated database, and what that
copy says is not proof of what the cluster holds. A node that has just joined, or
one rebuilt after a database loss, reports no VMs in exactly the same way as a
cluster that genuinely has none — and a node that has received *some* rows and
not others reports a list that looks entirely ordinary while the guest holding
the first address in the prefix is missing from it. Nothing in the schema records
how much of a table a node has actually received, so no local read can tell the
difference.

So on **every** bind litevirt asks the cluster. Each host reports its digest of
the four tables an address can be recorded in — `vms`, `vm_nics`,
`vm_interfaces` and `container_interfaces`; the address itself lives on the NIC
rows, not in `vms` — and the local inventory is corroborated only when **every**
host **agrees** on **every** one of them, by the same comparison anti-entropy
repairs on. That costs one small request per peer. Fewer rows on a peer is not
agreement: a peer holding one guest while this node holds two unrelated ones is
not "behind", it is a peer holding a row this node has never seen.

The agreement has to be about **the read the plan was built from**, not about
whatever the tables hold a moment later. litevirt samples those four digests
before it reads anything, builds the plan, and then proves that sample: every
host agrees with it *and* this node's own rows still are it. A guest's row
arriving while the plan is being assembled is therefore never adopted-by-luck —
it is absent from the plan, so the plan is discarded and re-derived on the next
pass rather than activated on a proof about a different read.

If the inventory **cannot** be corroborated — a host that could not be reached, a
host that reports different rows in any of those tables (more, fewer, or the same
number of different ones), a host that says nothing about one of them, a host
that some peer knows about and this node has never heard of, or this node's own
inventory changing while the plan was being built — the bind still succeeds, but
the binding is created **suspended**:

```
$ lv network create prod-a --type bridge --interface br-prod --netbox-prefix 12
Error: network "prod-a" was created and its NetBox binding for prefix 12 is
SUSPENDED, so it serves no address claims yet: ... this node could not
corroborate its VM inventory when NetBox prefix was bound ...
```

Nothing is broken and there is no cause to repair. A suspended binding refuses
every allocation, so no address can be handed out into a prefix whose existing
occupants are unknown, and the periodic NetBox maintenance pass (15 minutes by
default) **re-runs the adoption and resumes the binding by itself** once the read
can be corroborated. To finish it immediately, run `lv netbox resume <network>`
from a node that has been up and replicating. `lv health` shows the suspension as
`netbox_binding_suspended` while it lasts.

Only a **drift** takes this suspension out of that self-resuming class — a
re-CIDRed prefix, a VRF that stopped enforcing uniqueness, a moved fingerprint,
an adoption that NetBox refused. A pass that adopted everything, re-validated
cleanly and then failed on the local write that lifts the flag leaves the reason
exactly as it is, so the next pass retries: an operational failure after the
adoption finished is not an adoption that is owed, and it does not convert an
automatic recovery into one that waits for you.

The suspension is the one thing a bind can do here that is neither wrong: going
live would make NetBox the authority over addresses running guests already hold,
and refusing outright would refuse the first bind on any cluster with a peer that
happens to be down, with no way forward. It is also what makes the strict
comparison affordable — a lagging peer **delays** a bind and never fails one,
because the pass finishes it as soon as the cluster agrees.

Some states refuse the bind rather than being adopted around, and every refusal
names the object so it can be dealt with:

| State | Why it refuses | What to do |
|---|---|---|
| the network holds a **container** NIC or address lease | containers are not supported on a bound network, so an adopted container would hold a lease it could never renegotiate, migrate or recreate. A NIC row whose address is not discovered yet refuses too — the guest may already hold one | move the containers to another network, or delete them |
| a VM that is **not stopped** has a NIC on the network with **no recorded address** | litevirt cannot tell NetBox what that guest is using, and NetBox would offer the same address to the next VM created here | let the address be discovered (30s), or record it, stop the VM, or detach the NIC |
| a **template** holds an address inside the prefix | a template is invisible to the inventory mirror, so its address would be held by nothing and reclaimable by neither the mirror nor the orphan sweep — the same reason converting a bound-network VM to a template is refused | detach that NIC, or revert the template to a VM |
| the address already exists in NetBox under **another identity** | it belongs to another litevirt installation (or to this one before a fingerprint move); taking it would seize another cluster's object | confirm who owns it; if it is genuinely stale, remove it in NetBox |
| the address already exists in NetBox with **no litevirt identity** | an operator-created object or a reservation. litevirt will not stamp its identity onto a record it did not create — that identity is exactly what would later authorize the orphan sweep to delete it | remove the object in NetBox and let the bind create it, or move the workload off that address |
| a lease names a NetBox object in a **different prefix** | the address was recorded against a prefix this network used to be bound to, so the prefix being bound now would never learn about it | retire the stale lease |
| more than **256** addresses are waiting to be adopted | each one is a separate NetBox request inside a single RPC | bind a smaller prefix, or move workloads off the network |

The cap of 256 covers a fully-populated /24, which is the shape a bound prefix
has in practice.

#### If the adoption does not finish

A bind whose adoption stops partway — NetBox became unreachable, or one address
refused — reports the failure and leaves things in a state that is safe and
finishable, never half-live:

- **the network exists**, and its binding is **suspended**, so it serves no
  address claims;
- the addresses that were recorded stay recorded;
- the failure message names the network and the cause.

Repair the cause, then finish it with the same command that lifts any other
suspension:

```bash
lv netbox resume <network>
```

Resume completes exactly the work the failed pass left — the already-recorded
addresses cost nothing — and lifts the suspension only once every one of them is
in NetBox. A resume that still cannot finish refuses and the binding stays
suspended. Deleting the network is the other way out: that releases the prefix.

### Addresses discovered after the bind

litevirt discovers addresses it did not allocate: the IP scanner reads the host's
ARP cache and libvirt's DHCP leases every 30 seconds, and the load-balancer
render does the same when it resolves backends. On an unbound network that
discovery is simply recorded, and that is how every DHCP guest's address reaches
the inventory.

On a **bound** network it is a **claim**. The discovered address is recorded only
once NetBox has granted it to that NIC — the same explicit-claim path `lv run`
uses — because the NIC record is what cloud-init, the inventory mirror and every
"is this address free" answer read, and a row litevirt wrote without holding the
address describes something that is not true.

If NetBox will not grant it, **nothing is recorded**: no NIC address, no DNS
record. Three things surface it:

- an `ERROR` log line naming the VM, the network, the address and the reason;
- `litevirt_netbox_unclaimable_discoveries_total{reason="not_ours"}`, whose
  reason labels are materialised at zero so an alert on them has a series to
  read before the first occurrence;
- a durable `netbox_discovery_unclaimable` health condition on **that host**, so
  `lv health` says so without anyone having to watch a log or scrape a counter.
  It names every affected guest and clears two revalidation passes after the
  address becomes claimable (the scanner re-attempts every 30 seconds).

`reason=not_ours` means what it says — a guest is using an address NetBox holds
for something else, which is what an external DHCP server does when it re-offers
a lease it remembers. litevirt cannot resolve that from here; move the guest off
the address, or reconcile the NetBox object.

The two **read** RPCs that also discover (`lv ls` and `lv inspect`, i.e. ListVMs
and GetVM) still *report* the address — the guest is using it, and hiding it helps
nobody — but they record nothing on a bound network and make no NetBox request.
A list must not POST once per undiscovered NIC; the IP scanner on that same host
covers the same guests within 30 seconds.

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
not a change. Note the asymmetry: the periodic pass tolerates a NetBox it cannot
read, because it can only ever *suspend* and a suspension is sticky, so a
maintenance window must not brick a network. Every path that makes a binding
**live** again refuses that same unreadable answer — see
[Resuming a suspended binding](#resuming-a-suspended-binding).

**A prefix moved between two VRFs is drift even when both enforce uniqueness.**
The binding pins the VRF it validated as its allocation scope, and a move takes
the prefix out of it. litevirt compares the VRF **ID**, not merely whether the
current VRF enforces uniqueness, so a move from one enforcing VRF to another
suspends the binding rather than passing. The pinned VRF is **not** rewritten:
re-pinning would move the allocation scope without establishing that the
addresses this network's guests already hold are unique inside the new VRF, and
those leases were proved against the old one. Move the prefix back in NetBox, or
delete and recreate the litevirt network to bind it against the new VRF (which
re-proves from scratch).

Suspension is deliberately sticky: nothing lifts it automatically. Which command
lifts it depends on what drifted — see the two sections below.

### Resuming a suspended binding

Repair the prefix in NetBox, then:

```bash
lv netbox resume <network>
```

Resume rewrites no binding facts. It re-runs every bind-time check against the
facts the binding pinned and clears the suspension only when all of them agree
again; while the drift is still present the command is refused, naming the
reason, and the binding stays suspended.

**A resume that could not read NetBox is refused, not granted.** Resume does not
take the repair on the operator's word — the re-check *is* its premise — so if
the prefix or its VRF cannot be read, the command refuses (`FailedPrecondition`),
writes nothing, and leaves the binding suspended under its existing reason. Run
it again once NetBox answers. The same rule holds for the tail of
`lv netbox rekey` and for the automatic completion the maintenance pass performs:
a binding goes live only on preconditions something actually read.

**And the check that counts is the one made *after* the adoption.** Adoption
issues up to 256 NetBox requests of its own, and NetBox is a system other people
change: a VRF whose uniqueness enforcement is switched off partway through an
adoption was enforcing it when the operation started and is not when the binding
would go live. So every path that activates a binding — the bind's own finisher,
`lv netbox resume`, the tail of `lv netbox rekey`, and the automatic completion —
re-runs the full check once the last adoption write has landed, and the
suspension comes off only if that check passes. Drift found there re-states the
suspension under the new cause, for you to repair and resume; a check that could
not be read leaves the suspension exactly as it was, for a retry.

Either way **the adopted addresses stay adopted**: the NetBox objects and the
local leases behind them are kept, refusing to activate is not a reason to
un-record a running guest's address, and a re-run skips what is already done.
Both outcomes report `FailedPrecondition` and both say the adoption finished —
so if you see one, do not go looking for un-adopted addresses.

This closes the window during the adoption. It does **not** make a NetBox change
atomic with the local activation, and nothing about it should be read that way:
uniqueness switched off a moment after that final check still leaves the binding
live, and what catches that is the periodic revalidation pass, which suspends it
on its next sweep.

It also finishes any adoption the bind left owed — see
[Binding a subnet that already has VMs on it](#binding-a-subnet-that-already-has-vms-on-it).
That is not a separate mode: the same gate that refuses to lift a suspension over
unrepaired drift refuses to lift one over an address litevirt has not yet
recorded in NetBox. On a binding with nothing owed it makes no NetBox request.

Because finishing an adoption writes to NetBox, a resume is a NetBox **write
pass** and only one of those runs on a node at a time — the same rule the
maintenance pass and `lv netbox rekey` follow. If a mirror or maintenance pass is
in flight the resume is refused, saying so, having written nothing; those passes
end on their own, so run it again in a moment (or from another configured node).
Bind-time adoption is excluded the same way, and neither requires cluster
leadership: binding or resuming a network must work from any configured node.

Repairable in place, by fixing NetBox and running `lv netbox resume`:

| Drift | Repair |
|---|---|
| the prefix's VRF stopped enforcing uniqueness | set `enforce_unique` on the VRF again |
| the prefix was moved to the global table | move it back into a VRF with `enforce_unique` |
| the prefix was moved into a different VRF | move it back into the VRF the binding pinned |
| the prefix was re-CIDRed | revert the CIDR to the one the binding recorded |

A suspension caused by a **moved cluster fingerprint** is not repaired in NetBox
and `lv netbox resume` will not lift it — the identities have to be rewritten
first with `lv netbox rekey` (below). The refusal message says so. Replacing the
cluster CA on disk does not move the fingerprint and so does not produce this
suspension; see
[Recovering from a moved cluster fingerprint](#recovering-from-a-moved-cluster-fingerprint).

**Re-CIDRing a bound prefix is not supported in v1.** Resume validates against the
CIDR the binding recorded and writes it back unchanged, so a prefix NetBox now
reports under a different CIDR stays suspended however many times the command is
run. That is deliberate: the addresses already handed out do not move with the
prefix, and both the orphan sweeper and lease repair enumerate NetBox by the
recorded CIDR — adopting a new range would make every address claimed from it
invisible to the reclaim proof. Either revert the CIDR in NetBox, or delete and
recreate the litevirt network, which releases the binding and re-claims it
against the new range.

#### `netbox.cluster_name` must be identical on every node

`netbox.cluster_name` names the NetBox `virtualization.cluster` the inventory
mirror writes into. The mirror sweep runs on whichever node holds the `netbox`
leader lease, so the value is a **cluster-wide** fact even though each node reads
it from its own config file: set it non-uniformly and whichever node leads
decides that sweep. Objects get created under one cluster and deleted under
another as leadership moves, and the ones left behind are invisible to every
sweep resolving the other name, so nothing reaps them.

Unlike every `enforcement.*` flag it has no capability latch to make it uniform,
because a capability token is a name that is advertised or not and cannot carry a
value. Two checks enforce it instead, and both are needed:

- **The binding pin.** The first bind records the resolved name on the
  `netbox_bindings` row. A node whose own configuration resolves to something
  else refuses to mirror and refuses `lv netbox rekey`, and raises
  `netbox_cluster_name_mismatch`. This catches a cluster-wide change *away from
  what was pinned* — every live node agreeing with each other but not with the
  binding, which would silently re-home an existing inventory.
- **The per-host publication.** Each node publishes the name it resolves, and
  the mirror compares across live hosts. Any disagreement makes **every**
  disagreeing node refuse to mirror and raise
  `netbox_cluster_name_disagreement`, naming both values and the peers holding
  the other one. This catches live disagreement *between nodes*, which is what
  makes inventory flap — and it is the only check a cluster with **no bound
  network** has, since there is no binding row to pin.

Only live hosts count. A host that is offline, in maintenance, fenced or
decommissioned keeps its published row but is not compared, so it cannot stop
mirroring forever by holding a stale value.

**A live host that has published nothing yet also stops the mirror**, under
`netbox_cluster_name_unpublished`, naming the hosts it is waiting for. Uniformity
cannot be established against a set litevirt knows to be incomplete — a peer that
has not spoken may be about to publish a different name, and one pass is enough
to write the whole inventory under the wrong cluster. Every node configured for
NetBox publishes on its first maintenance pass, so this normally clears within
one interval. The one shape that does not clear itself is a live host running
with `netbox.enabled` off: it never publishes, because it runs no NetBox pass at
all. Enable NetBox there, or remove the host.

All of these refusals are mirror-only: address allocation, binds and the orphan
sweep are unaffected. `lv health` shows the condition; the fix is to correct
`netbox.cluster_name` on the node that is wrong and restart it.

### The inventory mirror

`netbox.cluster_name` is **enforced uniform** from the first bind onward. It
names the `virtualization.cluster` the mirror writes into, and the sweep runs on
whichever node holds the `netbox` leader lease — so set it on some nodes only and
whichever node leads decides that sweep: objects appear under one cluster and are
deleted under another as leadership moves, and the ones left behind are invisible
to every later sweep that resolves the other name, so nothing reaps them. Unlike
an `enforcement.*` flag it has no latch, because a capability token carries a
name and not a value.

Instead, the first bind **pins** the name it resolved onto the `netbox_bindings`
row, alongside the CIDR, the VRF and the cluster fingerprint. Any node whose own
configuration resolves to a different name refuses to mirror and refuses
`lv netbox rekey`, and raises a `netbox_cluster_name_mismatch` health condition
about itself naming both values (see `docs/diagnostics.md`). Address allocation
is unaffected — the mismatch endangers the inventory, not the addresses. Leaving
the key unset on every node is fine and is the default: unset resolves to the
local cluster name, so every node resolves the same thing and agrees. Setting it
on one node and not another does not agree, and is refused.

One shape is **not** covered: a cluster running the mirror with no bound network
has no binding row, so it has no pin and nothing to compare against. Set
`netbox.cluster_name` identically by hand there, and compare the
`netbox mirror: starting` log line across the fleet.

The inventory mirror is **opt-in**, and off by default. `netbox.enabled` alone
makes NetBox litevirt's address authority and nothing more: the addresses
litevirt claims exist as `ip_address` objects carrying this cluster's identity in
a custom field, with no `virtual_machine`, no `vminterface`, and no assignment
between them. That is a complete configuration rather than a degraded one. The
identity is what makes an address litevirt's, and the orphan sweeper proves an
address unclaimed by asking every eligible host whether it holds it — a proof
that never reads what the address is assigned to — so binding a prefix, claiming
from it, revalidating a binding and reclaiming an orphan all behave identically
with the mirror off.

Set `netbox.mirror_inventory: true` to turn it on. It must be set **identically
on every node**, and that is enforced rather than asked for: the flag gates
advertisement of a `netbox_mirror_v1` capability token, so the cluster-wide latch
cannot form until every node has opted in, and enabling it on one node changes
nothing. Mirroring additionally requires `netbox_ipam_v1` to be latched, exactly
as binding a prefix does — the mirror writes replicated tables an older build
does not carry, so a node configured ahead of its peers writes nothing. Turning
the flag back off stops mirroring on that node immediately; a latch is monotone
and durable, so the flag, not the latch, is the kill switch.

With mirroring on, a cluster mirrors its inventory whether or not any network is
bound to a prefix. It registers itself as a NetBox cluster (of type `litevirt`,
named after the local cluster or after `netbox.cluster_name`) and mirrors:

- each VM as a `virtual_machine` carrying its vCPUs, memory, disk and status —
  `active` while it runs and `offline` in every other state, because NetBox's
  remaining choices describe an operator's intent for a machine rather than a
  hypervisor's runtime, and writing one would overwrite what an operator put
  there. Disk is written in the unit NetBox counts that field in — **decimal
  megabytes**, 1 MB = 1,000,000 bytes — summed over the VM's disks and rounded
  **up**, so a recorded size never understates the provisioned disk. It is not
  the gibibyte figure project quota charges against, which rounds each disk up
  to a whole GiB;
- each VM NIC as a `vminterface`, keyed by its MAC. Where the MAC is recorded
  depends on the NetBox version and litevirt handles both: up to 4.1 it is the
  interface's own `mac_address` field, while 4.2 made that field read-only and
  moved the value to a `dcim.MACAddress` object the interface points at with
  `primary_mac_address`. A 4.2+ server answers a write of the old field with a
  success and silently drops it, so litevirt checks what came back rather than
  trusting the status code, and records the MAC the other way when it finds the
  field ignored. NetBox stores a MAC upper-cased; comparisons are
  case-insensitive, so that is not drift;
- each address litevirt claimed from NetBox as an `ip_address` assigned to the
  interface that holds it.

If a host is modelled as a DCIM device whose name matches the litevirt host, the
VM links to it; if not, the VM is mirrored without a device link, so an operator
who does not model hosts still gets a working mirror. Templates are never
mirrored — a template is a disk image, not a machine. A VM deleted in litevirt is
deleted from NetBox, as is a detached NIC; NetBox's changelog retains the history.

**Removals need evidence.** The mirror computes them from a read of the local
replicated database, and that read has partial answers a converged cluster is
indistinguishable from. Two things can be taken away — a `delete`, which retires
a `virtual_machine` or a `vminterface`, and a `clear`, which unassigns an
`ip_address` from an interface — and neither runs without positive local
evidence. Creates, updates and assignments are unaffected: they are additive, so
the worst a partial read costs there is an object a later sweep reconciles. One
destructive call sits outside this gate: adopting an identity that NetBox holds
*twice* keeps the lowest object id and deletes the duplicates, from the
create/adopt path rather than the removal phases. It cannot reach an object the
gate would have protected — it fires only on duplicates of an identity that is
in the desired set, so the local record proving that identity necessarily
exists — but it is a real `DELETE`, and the enumeration above does not cover it.

Three conditions withhold, at two different scopes.

**The whole pass** is withheld when the read cannot be trusted at all:

- an **empty** read. A node hydrating after a database loss reports no VMs,
  exactly as a cluster that genuinely holds none does. The two are told apart by
  tombstone history — a deleted VM leaves a soft-deleted row behind — so deleting
  the last VM in a cluster still retires its object, while an unhydrated node
  retires nothing.
- a **skipped** record. A VM whose spec carries no uuid, a NIC with no MAC, or
  two live leases claiming one MAC on one network, are dropped by the reader with
  a warning. For an object never mirrored that is harmless; for one already
  mirrored the skip is indistinguishable from the workload being gone.

**Per object** is the third, and it covers the far more common shape the two
above pass: a database holding *some* of the cluster's rows. A node that just
joined, or one rebuilt from scratch, hydrates row by row, and nothing throttles
it into safety. What stands between such a node and its first destructive sweep
is only a **delay**: the mirror deliberately runs no pass at startup, so its
first lease acquisition and its first sweep both land one
`netbox.sweep_interval_sec` in (15 minutes by default), and the queue poll that
can bring a sweep forward takes no lease, so it cannot lead before then. A wait
is not a proof — it is the same 15 minutes whether the database has hydrated or
not, and a node still replicating when the tick arrives gets no second grace
period. So each removal is asked for its own proof:

- a **VM delete** needs a record of the **incarnation** NetBox holds — the uuid
  inside the object's identity, never the name it sits under — and that record
  has to support the conclusion, not merely name the machine. A **tombstone** for
  that uuid does: litevirt soft-deletes, so a destroyed incarnation leaves one,
  and no cluster runs a VM whose row it has tombstoned. A **live** row for it
  says the opposite — the incarnation exists, so nothing removes its object — with
  one exception, a VM converted to a **template**: the mirror deliberately does
  not represent one, and that is readable off the row. The mirror's **own record
  of having created the object** is the case that needs more, and it is the
  ordinary one after a VM is deleted and recreated under the same name, because
  the re-create drops the old incarnation's tombstone: it identifies the
  incarnation without saying anything about whether it stopped existing, so it
  authorizes a removal only once this node's inventory read is **corroborated as
  the cluster's** — the same digest agreement across the same closed participant
  set that a prefix binding requires before it hands out an address. It is *that*
  read that has to be corroborated, the one the sweep drew the absence from: the
  digests are sampled before the sweep reads anything, and a row arriving while
  the sweep runs withholds the removal for one pass rather than certifying a read
  the plan never saw. With none of those, the removal is withheld.
- an **interface delete** needs a local row for the (VM, MAC) it retires — live
  or tombstoned, in either NIC table.
- a **clear** needs a local lease row naming that NetBox address — again live or
  tombstoned. A release keeps the address id on the row it tombstones, so a
  genuinely stale assignment is always provable. This matters because
  anti-entropy repairs *per table*: with VM and interface rows repaired but
  leases not yet, every NIC resolves to "holds no address", which would otherwise
  route every litevirt-owned address in the cluster into the clear branch.

The VM rule is **one rule for both removals** — the ordinary delete and the
replacement that frees a reused name (below) — because they differ in when they
run, never in what would justify removing an object. Each of them once had a
premise of its own, and each of those premises was answered by the name rather
than by the incarnation.

A pass that withheld a delete withholds its clears too — having proven its
inventory read partial, it does not then act destructively on it. A withheld
clear does not escalate that way; it is proven per address and costs only that
one.

In every case the sweep still applies its creates, updates and assignments, warns
about what it withheld, and does **not** stamp
`litevirt_netbox_mirror_last_success_seconds`. So NetBox may briefly advertise a
machine that is gone, and never loses one that is not, and
`litevirt_netbox_mirror_sweeps_total{result="error"}` climbs while the condition
lasts.

How much the warning tells you depends on the scope. A **per-object** withholding
names the objects: the VM names, the interface MACs, or the NetBox address ids,
sorted so a condition lasting several sweeps logs the same list each time. A
**whole-pass** one — the empty read, the skipped record, or a failure to read the
local record history at all — gives the reason and a *count* of the actions it
dropped, not the list, because at that scope the read it would enumerate from is
the one it has just called untrustworthy. To identify the objects behind a
whole-pass withholding, fix the condition it names and read the next sweep's
per-object warnings.

#### When a withheld removal does not clear itself

For an unreplicated row the condition is transient: the row arrives and the next
sweep converges. It is **permanent** for a NetBox object carrying this cluster's
identity that the local database has no record of and never will — an object
copied by hand, a whole-cluster database rebuild that kept the same identity
fingerprint, a rename that happened while the mirror was down. Every sweep
withholds that one removal, forever: the staleness gauge never advances and the
error counter increments every sweep interval.

Two more shapes are permanent for a different reason — the record exists and
does not support the conclusion:

- an object whose incarnation the cluster holds a **live** row for that is not a
  template. The mirror's inventory read says the VM is not there and its record
  read says it is, which is a contradiction rather than a removal, so it acts on
  neither half.
- an object whose only record is the mirror's own, on a cluster with a
  **permanently lost host**. The corroboration that would turn that record into
  an absence needs a digest from every participant, and a destroyed machine never
  produces one.

Both take the same repair as the rest of this section.

That is the intended direction — the mirror will not remove what it cannot prove
— but the alarm does not stop on its own, and there is no force, prune or
acknowledge flag to silence it. `lv netbox` has `rekey` and `resume`, and neither
addresses this.

**The repair is by hand.** The withheld objects are named in the log line — VM
names and interface MACs for a delete, NetBox address ids for a clear. Find each
one in NetBox, confirm it names a workload this cluster does not hold (its
`litevirt_identity` custom field carries the VM uuid and MAC), and remove it — the
object for a withheld delete, or just the address's assignment for a withheld
clear. NetBox's changelog keeps what was removed. The next sweep then has nothing
to withhold and converges.

If the object *is* this cluster's own, stranded under a fingerprint the cluster
has moved away from, `lv netbox rekey` is the repair instead — see
[Recovering from a moved cluster fingerprint](#recovering-from-a-moved-cluster-fingerprint).

**One node writes.** The mirror runs under the same cluster-wide leader lease as
the orphan sweeper and the re-key, and re-reads it before every batch of writes,
so a handover mid-sweep stops the outgoing leader instead of letting two nodes
write the same objects. It writes only on change: a sweep over inventory that
already matches issues no writes at all.

**A reused VM name converges, whether a create or a rename needs it.** Delete a
VM and recreate it under the same name and the new incarnation has a new uuid, so
a new identity, so the mirror has to create a new object — while the old object
still holds the name NetBox allows only one of. The same collision is reached
without any create at all: rename a VM away, delete it, and rename a second VM
into the name it vacated, all inside one sweep interval. NetBox never saw the
first rename, so its object still holds the original name, and the survivor needs
an **update** onto it — and NetBox's rule constrains the name, so a rename onto a
taken one is refused exactly as a create is.

The mirror resolves both by replacing the occupying object first, and only on
proof taken from the identity: the object holding the name carries **this**
cluster's fingerprint and a uuid that is **not** in the desired set, which makes
it a superseded incarnation of that name. That one removal is the only one that
runs ahead of the creates and updates, and it takes the interfaces under it with
it — NetBox cascades them, so the mirror does not ask for them separately.

Two things it will never touch, both refused twice over (once when the action is
planned, once again before the delete is issued): an object whose identity **is**
in the desired set — a live VM of this cluster, which freeing a name may never
remove — and an object carrying a **different** cluster's fingerprint, which
belongs to another installation.

**A rename cycle is broken through a temporary name, not by removing anything.**
Two VMs swapping names — or any permutation of names among live VMs — is the
first of those two cases on both sides: each object's occupant is the other, both
identities are in the desired set, so the replacement refuses both. There is also
no order that works. Neither rename can land while the other holds the name, so
**waiting does not resolve it**: every sweep computes the same updates and gets
the same refusals, for as long as both VMs exist.

The way out of a permutation is a name outside it. One member of the cycle is
patched onto a temporary name the mirror derives and owns —
`litevirt-renaming-<uuid>` — which turns the cycle into a chain, and a chain
lands one link per sweep. Nothing is deleted, both objects keep their
identities, and the parked object gets its own desired name on a later pass. A
two-VM swap converges in two sweeps, and a cycle of *n* in *n*.

While that is in progress the pass reports itself **unconverged** and logs the
VMs still waiting, so the staleness gauge is not stamped over a fleet that does
not match litevirt's own names — and an object may briefly be visible in NetBox
under its temporary name. The one thing the mirror refuses is a temporary name
that is *itself* taken by some other object in the same NetBox cluster: it
declines to park rather than trade the stall for a failed sweep, and the log line
says so. That is the only case where a rename cycle persists, and the repair is
to free that name in NetBox by hand.

#### A withheld replacement, and the collision it leaves behind

Half the replacement proof is "this uuid is absent from the desired set", which
is only as good as that read is whole. So a sweep that cannot prove its own view
of the cluster is complete withholds the replacement along with its deletes — the
same gate, for the same reason — and the create or rename then collides for that
one VM. That is deliberate: a stalled mirror is fixed by the next healthy sweep,
an object removed on partial evidence is not.

The evidence the gate asks for names the **incarnation being replaced**, not the
name it occupies, and it is the same rule an ordinary delete obeys — see the
removal proofs above. A name cannot answer the question, because the name a
replacement frees is always a name some local row holds: the VM taking it. So a
node that has never held the occupant's incarnation withholds the replacement,
whatever else is sitting under that name.

The **same-name re-create is the case that needs the corroboration**, and it is
the commonest reason a replacement is withheld on a healthy cluster. Recreating a
VM under a name that was used before drops the previous incarnation's tombstone,
so the only record left of it is the mirror's own — which identifies it and does
not say it is gone. The mirror therefore asks the cluster whether this node's
inventory read is the whole of it before concluding the old incarnation exists
nowhere. While rows are in flight the digests disagree, so the replacement waits
and the create or rename collides for another sweep; it converges once
replication settles. A **permanently lost host** can never produce a digest, so
that agreement never comes — the same limitation a binding has, with the same
repair: remove the object in NetBox by hand.

What you see is a failed sweep whose error is a NetBox refusal for a name
litevirt can see is free:

```
netbox mirror: sync failed error="netboxsync: phase 1: netboxsync: update VM 4002:
netbox: HTTP 400: {\"name\":[\"A virtual machine with this name already exists in
this cluster.\"]} — this sweep withheld the replacement of the superseded
object(s) holding [web-01], because this node holds no local record — tombstone
included — for 2 of the NetBox object(s) this sweep would have removed, so its
view of the cluster is partial"
```

The withheld replacement is also logged in its own right, whatever the apply then
does, naming the names it did not free and the incomplete inventory behind it. So
the condition to act on is the **partial read**, not the collision: it is the same
condition the withheld-delete warnings describe, and it clears the same way —
usually on its own, once the missing rows replicate. If it persists past a few
sweeps, treat it as [a withheld removal that does not clear
itself](#when-a-withheld-removal-does-not-clear-itself) and repair it in NetBox by
hand.

**Two litevirt clusters, one NetBox.** Give each one a NetBox cluster of its own
with `netbox.cluster_name`. NetBox allows one VM name per cluster, so two
installations mirroring into a single NetBox cluster cannot both hold a `web-01`
— the second one's create is rejected. The mirror detects that before it writes:
it skips exactly the colliding VM, converges everything else, logs the names it
skipped, and leaves `litevirt_netbox_mirror_last_success_seconds` standing still
so the staleness alert fires. Set the name before the first sweep — changing it
later strands everything written under the previous cluster.

`netbox.cluster_name` **must be uniform cluster-wide**: identical on every node,
or unset on every node. There is no latch mediating it the way there is for the
`enforcement.*` flags, and the mirror sweeps from whichever node holds the
`netbox` lease — so two values in one fleet duplicate the whole inventory into a
second `virtualization.cluster` at the first handover, with nothing failing to
say so. A node cannot read a peer's configured value; what makes a disagreement
findable is the `netbox mirror: starting` line each node logs at startup, which
names the cluster it would mirror into and the sweep cadence it will run at.
Compare it across the fleet.

**Two cadences.** A full sweep on the `netbox.sweep_interval_sec` cadence (900
seconds by default) reconciles everything, and that is the correctness mechanism.
Between sweeps the node holding the lease checks a local queue every 60 seconds
and sweeps early when a VM lifecycle operation has left something in it. The
queue is latency only — a VM whose enqueue never happened, because the node died
mid-operation, is converged by the next full sweep just the same.

The mirror's sweep runs **half an interval offset** from the orphan sweeper's
maintenance pass. They share that cadence and are serialised on each node, so
running them in phase means one of them finds the other still going and skips
its turn — every interval, for as long as the process lives. For the mirror that
is not one lost pass: its sweep is the only thing that takes the leader lease,
and the queue poll only accelerates a lease already held, so a sweep that always
skips leaves the whole inventory unwritten with nothing reporting an error. The
offset is derived from the configured interval and needs no tuning; a pass that
genuinely runs longer than half an interval still yields, which is what yielding
is for.

#### The queue during a NetBox outage

Queued items are acked only after a sweep has **succeeded**. While NetBox is
unreachable every sweep fails, so nothing is acked: `netbox_sync_queue`
accumulates one row per VM lifecycle operation and
`litevirt_netbox_sync_queue_depth` climbs and stays up. Because the queue is not
empty, the leader also retries on the 60-second poll rather than waiting out the
15-minute sweep.

Both are deliberate. Keeping the trigger is what makes a change reach NetBox on
the first poll after recovery instead of a sweep interval later, and the backlog
then clears in a single pass, because the sweep reconciles the whole fleet rather
than replaying the queue item by item — a hundred queued rows are not a hundred
sweeps. Correctness never depends on the queue, so nothing is lost if it is
cleared by hand either.

A queue depth that rises during an outage is therefore expected and self-heals.
What is worth alerting on is a depth that does not return to 0 once NetBox is
reachable again, which means sweeps are still failing:
`litevirt_netbox_mirror_sweeps_total` and
`litevirt_netbox_mirror_last_success_seconds` say whether any sweep is completing
at all, and `litevirt_netbox_api_errors_total` says what NetBox is answering.

### Recovering from a moved cluster fingerprint

The cluster fingerprint in every NetBox identity is derived from the cluster CA
certificate recorded in the replicated `cluster` row — that is what stops two
litevirt clusters sharing one NetBox from reclaiming each other's addresses.

**The fingerprint is minted once and does not track `ca.crt`.** It is derived the
first time any node finds the `cluster` row missing, and nothing in litevirt
rewrites that row afterwards. So replacing the CA on disk does **not** move the
fingerprint, does **not** suspend a binding, and needs no re-key: do not wait for
a suspension that will not arrive. That is deliberate — a fingerprint that
followed the live CA would make the inventory mirror see zero objects it owns the
moment one was replaced, and it would duplicate the whole inventory under fresh
NetBox ids while every binding was suspended.

A binding is suspended on the fingerprint only when the recorded fingerprint and
the cluster's current one genuinely differ, which today means the `cluster` row
itself was rewritten out of band. A supported CA-rotation path that moves the
fingerprint on purpose does not exist yet; when one is added, this is the command
that re-stamps the objects it leaves behind:

```bash
lv netbox rekey <network>
```

Running VMs are unaffected by the suspension. The command re-stamps every object
carrying the old fingerprint and then resumes the binding — in that order, so a
run that fails partway leaves the binding suspended rather than live with half
its objects unrecognisable. Re-running finishes the job; objects already
rewritten are skipped. Complete a re-key before the fingerprint moves again.

Both forms of the command run under the same cluster-wide leader lease as the
orphan sweeper and the inventory mirror, because all three write the objects the
others read. A re-key that cannot take the lease **rewrites nothing** and refuses,
naming the node that holds it — **run the re-key on that node**. Waiting will not
help: the holder renews the lease on every sweep, so it does not lapse while that
node is up. If the lease is lost while a re-key is running, it stops where it is:
the binding stays suspended and re-running finishes what was left. Taking the
lease also stops a mirror sweep already in flight on ANOTHER node, at its next
write batch.

The lease names a node, so it cannot separate two of these operations on the
*same* node — a re-key there renews the very lease its own sweeps read. Each node
therefore admits one NetBox pass at a time: a re-key started while that node's
maintenance or mirror pass is running is refused ("a NetBox … pass is already
running on this node"), and here retrying shortly does work, because a pass ends
on its own. In the other direction a sweep that comes due mid-re-key skips that
tick rather than reconciling against a half-rewritten inventory.

Three sets of objects are re-stamped, in this order:

1. the `ipam.ip-address` objects the bound prefix holds;
2. the `virtual_machine` and `vminterface` objects the inventory mirror writes —
   cluster-wide, not just this network's, because inventory is not per-prefix;
3. litevirt's own local identity index, which is keyed on the identity string.

The order is a safety property, not an implementation detail. NetBox re-stamped
with the local index still stale is recoverable — the mirror resolves the object
from live state and repairs the index on its next pass. The reverse is not: the
mirror would look for objects under an identity NetBox does not carry yet, find
nothing, and try to create inventory NetBox already holds — which it refuses,
because a VM name is unique within a cluster.

A re-key answers the fingerprint pin and nothing else. If the prefix had ALSO
drifted — re-CIDRed, say — the rewrite still happens, but the binding is left
suspended under the remaining reason and the command reports it. Repair that in
NetBox and run `lv netbox rekey` again.

#### Re-keying inventory with no bound network

The form above takes its old fingerprint from the binding row. A cluster can use
NetBox purely for **inventory** — the mirror needs a NetBox client and nothing
else — and then there is no binding to take it from. Run the same command with
no argument:

```bash
lv netbox rekey
```

It re-stamps sets 2 and 3 above, cluster-wide, in the same order and for the
same reason. It touches no `ipam.ip-address` object and resumes no binding, so a
cluster that has bound networks as well still runs `lv netbox rekey <network>`
for each of them afterwards — that run finds the inventory already done and
costs two list calls.

Its pin comes from **litevirt's own local identity index**, whose key IS the
identity string. Those rows are written only by this cluster's mirror, into this
cluster's own replicated database, so a fingerprint appearing in one is provably
this cluster's. If it holds rows under more than one old fingerprint (a re-key
interrupted, then a second fingerprint move) every one of them is re-stamped in
turn.

That also makes this the repair for a cluster whose binding pin was already
advanced by an older build — one that re-stamped addresses only. The per-network
form can do nothing there, because its pin now equals the live fingerprint; the
index still records the old one.

When the index holds **no** row under an old fingerprint, nothing is rewritten.
Either every row already carries the live fingerprint, and the command succeeds
having changed nothing; or the index is empty, and the command **refuses**. The
refusal is deliberate and is the safety property of the whole operation: the
only rule left would be "re-stamp anything that is not the current fingerprint",
and two litevirt installations can share one NetBox and one NetBox cluster
object, so that rule would seize the other installation's inventory. An operator
whose index is genuinely gone removes the stranded objects in NetBox by hand and
lets the mirror rebuild them.

**A single lost index row normally heals itself.** If an object was created in
NetBox but the row recording it never landed — a crash in the moment between the
two — nothing is stranded for long: the mirror diffs against NetBox's ACTUAL
state, not against the index, it searches by identity before creating anything,
and an update re-records the mapping. The very next sweep re-adopts the object
and writes the row again. No operator action, and no re-key.

**It becomes a real gap only if the cluster fingerprint then moves**, which is
the one residual gap in the re-key. (Replacing the CA does not move it — see
above; it takes an out-of-band rewrite of the replicated `cluster` row.) The
searches are exact matches on the full identity, so once the fingerprint moves
the mirror looks under the new one, finds nothing, and tries to create inventory
NetBox already holds under the old — while the re-key cannot reach the object
either, because it only rewrites fingerprints the local index records and this
object's was never recorded. The symptom is a sweep that skips a VM, naming it
as one whose name the NetBox cluster already holds under another identity.

That case fails closed by choice. Repairing it would mean rewriting an object the
cluster cannot prove is its own, which in a shared NetBox is another cluster's
inventory. The repair is by hand: find the object in NetBox under the old
fingerprint — its `litevirt_identity` custom field starts with it, and the
cluster's own objects all carry the new one — confirm it names a VM this cluster
holds, and delete it. The next sweep recreates it correctly and records the index
row. NetBox's changelog keeps what was removed.

Both commands are admin-only and both write an audit record (`netbox.rekey`,
`netbox.resume`), so `lv audit verify` carries a trace of every identity rewrite
and every lifted suspension. A cluster-scoped re-key is audited under the target
`(inventory)` rather than a network name, and — like the per-network form — is
recorded on failure as well as success, because a run that stopped partway has
still rewritten objects.

**`netbox.adopt`** is the third action, and it is written by the paths that
record addresses guests already hold: the tail of a bind, and the revalidation
pass that finishes a bind it could not complete. Its detail carries
`prefix=<id> adopted=<n>`, and — like the re-key — it is recorded on failure as
well as success, because a pass that stopped partway has still created objects in
NetBox and "nothing happened" is the wrong thing for the trail to imply.

### Maintenance and reclamation

Every node configured for NetBox runs a maintenance pass on the
`netbox.sweep_interval_sec` cadence (900 seconds by default). One pass does two
things, in this order:

1. **Re-validate every binding** against NetBox, suspending any that has drifted.
   Nothing lifts a suspension on its own: `lv netbox resume` clears one whose
   drift you have repaired in NetBox, and `lv netbox rekey` rewrites the
   identities a moved fingerprint invalidated so a resume can then succeed.
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
- the set of hosts that must answer is the replicated `hosts` table **unioned
  with gossip membership**, because the replicated table can simply be missing a
  peer — and a peer missing from it would otherwise be absent from both samples,
  making the two samples agree about a cluster neither of them saw whole.
  Membership converges in seconds and independently of every table, so a host it
  names is a host that exists;
- that set is then **closed over every host's own membership view**: each one is
  asked which hosts it knows of at all, the answers are folded in, and the
  fan-out repeats until the set stops growing. A holder any reachable node can
  name is therefore queried by name, whether or not this node's own `hosts` table
  ever received it. Counting host rows is not enough on its own — two nodes can
  each know three hosts without knowing the same three;
- **there are three sets, and what a host owes depends on what it has.** litevirt
  keeps them apart deliberately, because collapsing a pair of them has freed or
  handed out a held address three times. A host that knows *who exists* is asked
  which hosts it knows of — everyone, whatever its role and whatever its power
  state. A host that holds *the replicated rows* must have its inventory digest
  agree — everyone running the daemon, **witnesses included**. A host with *a
  running domain to scan* must answer with a scan — workload hosts only, and a
  witness is excused there and only there;
- **witnesses are asked what they know and asked what rows they hold, and
  excused only from the scan.** A witness runs the daemon, gossips and receives
  every replicated row, so it is a first-class source of membership *and* of
  inventory; what it does not do is host a workload, so scanning it for a guest
  proves nothing. Excluding a witness from the *question* was a bug twice over: a
  host whose role this node had recorded as `witness` but which had since been
  made a worker was never asked, and its stale role could never be corrected — an
  exclusion must not skip the query that would have refuted it — and a genuine
  witness that was the only node able to name a third host was never asked either.
  Excluding it from the *inventory* comparison was a third: it held the only
  replicated copy of a running guest's records, every other node's inventory was
  equally short, they agreed with each other, and a bind went live over a held
  address. A host counts as a witness only while **every** `hosts` row read for it
  agrees; two rows that disagree, or no row anywhere, and it must answer with a
  scan like any worker;
- **an unreachable host of any role pauses reclamation, and a fence attestation
  does not lift that.** Every host is dialled for its membership view, and one
  that cannot say what it knows leaves the set unclosed. `lv host fence-confirm
  <host>` excuses a machine from the runtime **scan** — it cannot be running a
  domain if it is off — and from nothing else: being off says nothing about the
  hosts that machine alone knew existed, or about the rows it holds. A fenced
  witness that was the only node able to name a third, still-running holder is the
  case that settles it;
- a view carries **both** halves of what a node knows, because neither half can
  substitute for the other. Its `hosts` rows include **tombstoned** ones: `lv
  host rm --force` does not power a machine off, so a host whose row a peer has
  soft-deleted may still be running the domain that holds the address. Its
  **gossip members** are the only source that can name a host with no `hosts` row
  anywhere — memberlist converges in seconds, independently of every table — so a
  holder known only to another node's gossip is now covered too, which no
  table-derived answer could ever have reached;
- the same membership proof gates the **bind**, not only the sweep. A node that
  cannot establish the host set does not go live on a prefix: its binding is
  suspended, and the next maintenance pass resumes it by itself. Handing out an
  address a holder already has and freeing one are the same collision from
  opposite sides, so both sides ask the same question;
- **reclamation withholds whenever the membership view cannot be closed**, and
  that is a longer list than an unreachable host. A participant that cannot be
  dialled, one that reports its own enumeration incomplete, one that names no
  hosts at all (a node holds at least its own row, so that is an unhydrated
  database rather than a small cluster), and one **running a version too old to
  answer the question** each leave the set unclosed. The last is the mixed-version
  case, and it is deliberate: during a rolling upgrade the not-yet-upgraded hosts
  cannot report what they know, so reclamation pauses until the roll finishes
  rather than proceeding on a cluster it can only partly see. The skip reason
  names the host, so `lv health` says which one;
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

**While a host is merely unreachable, the sweeper stays inert and there is no
override.** It cannot say which hosts it knew of, so the participant set cannot
be closed and nothing is reclaimed. `lv host fence-confirm <host>` does **not**
change that: it attests that a machine's libvirt cannot be running a domain,
which excuses that host from the runtime scan, while saying nothing about the
hosts it alone knew existed or the replicated rows it held. Excusing a fenced
host from the *question* is what freed a live address, so that escape hatch does
not exist.

The ordinary way back is to make the host answerable again — repair it, or
replace it and let the replacement rejoin under that name. Until then the sweep
withholds and the addresses it would have reclaimed stay allocated, which is the
leak this design prefers to a collision. `lv health` names the host the proof is
waiting on, so the pause is never silent. Bindings behave the same way from the
other side: a node that cannot close the set does not go live on a prefix, its
binding is suspended, and a later pass resumes it by itself once the cluster is
whole.

The fence attestation is time-bounded (24 hours) and ignored for a host that has
come back, because it governs the scan for exactly as long as the machine is
genuinely down.

### Permanent host loss — a known limitation with no operator remedy

A machine that is never coming back is a different problem, and litevirt has no
answer for it today. **Read this before concluding something is broken.**

A permanently lost host cannot answer, so:

* **reclamation stalls.** The membership closure can never close, so the sweeper
  keeps withholding and the addresses it would have reclaimed stay allocated in
  NetBox indefinitely.
* **affected new bindings are suspended.** A bind or adoption has to corroborate
  its inventory against every participant, and the lost host can never produce
  its digest, so the binding is created suspended and stays suspended. Allocation
  on that network refuses while it does.
* **one class of inventory-mirror removal keeps withholding.** The mirror asks
  the same corroboration before concluding that an incarnation whose only local
  record is its own mapping row exists nowhere — the delete-and-recreate-under-
  the-same-name case. Every other removal it makes is proven from a local row and
  is unaffected. See [When a withheld removal does not clear
  itself](#when-a-withheld-removal-does-not-clear-itself) for the repair.

**There is currently no operator remedy, and that is deliberate rather than an
oversight.** In particular:

* `lv host fence-confirm <host>` does **not** unblock either one. It attests that
  a machine's libvirt cannot be running a domain, which excuses that host from the
  *runtime scan* — and says nothing about which hosts it alone knew existed or
  which replicated rows it held. Excusing a fenced host from the *question* is
  precisely what once freed a live guest's address, so power-off evidence is kept
  separate from missing knowledge and can never substitute for it.
* There is no command, flag or record that lets an operator assert what the lost
  machine knew or what became of its rows. Every premise in this subsystem is
  established by machine evidence, and nothing else satisfies one.

**What still works.** Claims a guest already holds are untouched — a suspension
refuses *new* allocation and never disturbs a live address. Existing NetBox
objects are untouched. Networks with no affected binding keep allocating
normally, and `lv health` names the host the proof is waiting on, so the pause is
never silent.

**What to do meanwhile.** If the machine can be made answerable again — repaired,
or replaced and rejoined under that name — everything resumes by itself: the
closure closes, the sweeper reclaims, and the revalidation pass lifts the
suspension without an operator command. If it genuinely cannot, the addresses it
was holding stay leaked in NetBox and the affected bindings stay suspended. That
is the trade this design makes on purpose: leaking an address a later pass can
reclaim is always preferable to handing a running guest's address to a new one.

A supported recovery path is specified — the operator-attested substitution, its
authorization rules, and the withdrawal that takes one back — in
[the frozen trust-recovery lifecycle scope](reviews/2026-09-08-trust-lifecycle-followup-scope.md).
It is **not implemented**. An earlier prerelease build of this work carried one —
a retire-host command under `lv netbox`, with a withdrawal and a listing beside
it — and it was removed before release so that its authorization rules could be
reviewed on their own terms rather than as a rider on an addressing change. No
released version ever had it.

> **If you ran a prerelease build of this feature, upgrading to this one is not
> supported and the daemon refuses to start.** A database that carries the
> prerelease permanent-loss trust schema — the three grant tables, or the removed
> attestation evaluator's leftover `lv health` conditions on a database that was
> already migrated once — is detected before any schema work, and startup stops
> with a message naming what it found. **Nothing is modified**: no table is
> dropped, no binding is suspended, no allocation or NetBox object is touched, and
> no row is written, so every piece of evidence survives intact.
>
> The reason is that a binding never recorded which evidence its inventory proof
> rested on. One that went live on a grant cannot be told apart from one proved
> against every participant, so this build cannot work out which bindings were
> affected — and both automatic answers are worse than stopping. Leaving them
> alone inherits authority nothing can review; rewriting them and dropping the
> grant tables destroys the only surviving account of what was granted, which is
> also the record of what a permanently lost machine was holding.
>
> **What to do.** Take a backup of the cluster database on every node first — it
> is the only remaining record of what was granted. Recovery is then a deliberate
> **offline** procedure against that evidence, decided by an operator who can
> establish what the lost machine held. **`lv netbox resume` is not sufficient
> here** and must not be relied on: it re-proves a binding against the
> participants that answer *now*, which cannot establish what a removed grant once
> authorized — and on a database whose accounting has been dropped it proves a
> smaller universe, which is how a stopped-but-defined guest's address came to be
> reclaimed. There is no flag that skips the check. Until the recovery path in
> [the frozen trust-recovery lifecycle scope](reviews/2026-09-08-trust-lifecycle-followup-scope.md)
> ships, a cluster in this state stays on the prerelease build that wrote those
> rows, which is the only build that understands them. Note also that a
> reclamation that already rested on a grant has already deleted its NetBox
> address and cannot be undone.
>
> No released version ever had this mechanism, so this cannot affect a cluster
> that only ever ran releases.

**During a rolling upgrade, reclamation pauses.** A peer running a build that
does not implement the proof RPC counts as unreachable, so no proof is complete
until every node has been upgraded. Nothing needs doing about it — the sweep
resumes on its own once the upgrade finishes.

**Reclamation requires a NetBox that reports a full RFC3339 `created`
timestamp** — that is NetBox 4.x. NetBox 3.x serializes `created` as a bare date,
which carries no time of day, and reading it as midnight would put every address
created after 00:30 UTC past the 30-minute grace window the moment it was
claimed. litevirt therefore does not interpret it at all: on 3.x every address
has an unknown age, the grace check treats unknown as too young, and the sweeper
reclaims nothing. Everything else — binding revalidation, suspension, re-key,
stuck-lease reporting — works normally; only reclamation is inert, and addresses
are freed by hand (confirm nothing holds the address, then delete it in NetBox).

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

### One leak the sweep cannot close

A release tombstones the local allocation row first and deletes the NetBox object
second, so a NetBox failure in between leaves the object held with no local row
behind it. That state cannot be retried — the row a retry would prove ownership
with is gone — so the identity is queued for the orphan sweep instead.

The sweep closes that where the **workload** is also gone: a delete, a
stale-record cleanup, a cutover or a rebuild leave no host claiming the identity,
the proof completes, and the address is reclaimed.

It does **not** close it for a **NIC detached from a VM that is still running**.
The identity carries the owning VM's uuid, and the proof asks every host whether
it still claims the uuid, the MAC or the address — the surviving VM still claims
the uuid, so the reclamation is declined, on that pass and every pass after it.
This is the safe direction (a leak, never a double-assignment) but nothing raises
a health condition for it: the counter `litevirt_netbox_sweeps_skipped_total`
gains a `host_still_claims` sample and a warning names the address. If a hot
detach reported a failed release, check that address in NetBox and remove it by
hand once the guest no longer holds it.

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
