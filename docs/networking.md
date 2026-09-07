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

`lv run` is the only path that claims an address, so the paths that would
otherwise hand a guest an address litevirt never reserved are refused on a bound
network: clone, live-restore, import, rebuild, and a renamed promote. Converting
a VM to a **template** is refused too, for the opposite reason — a template is
invisible to the inventory mirror, so the address it kept holding would be
reclaimable by neither the mirror nor the orphan sweep. Detach the NIC first;
that releases the address, and the conversion then goes through.

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

### The inventory mirror

A cluster configured for NetBox also mirrors its inventory there, whether or not
any network is bound to a prefix. Mirroring requires the `netbox_ipam_v1`
capability to be latched cluster-wide, exactly as binding a prefix does — the
mirror writes replicated tables an older build does not carry, so a node
configured ahead of its peers writes nothing until every node has opted in. It
registers itself as a NetBox cluster (of type `litevirt`, named after the local
cluster or after `netbox.cluster_name`) and mirrors:

- each VM as a `virtual_machine` carrying its vCPUs, memory, disk and status —
  `active` while it runs and `offline` in every other state, because NetBox's
  remaining choices describe an operator's intent for a machine rather than a
  hypervisor's runtime, and writing one would overwrite what an operator put
  there;
- each VM NIC as a `vminterface`, keyed by its MAC;
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
the worst a partial read costs there is an object a later sweep reconciles.

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
it into safety — it takes the mirror's leader lease immediately and re-latches
within seconds of starting. So each removal is asked for its own proof:

- a **delete** needs a local row for the VM or NIC it retires — live or
  tombstoned. litevirt soft-deletes, so a destroyed workload leaves one; a row
  that has not replicated leaves nothing.
- a **clear** needs a local lease row naming that NetBox address — again live or
  tombstoned. A release keeps the address id on the row it tombstones, so a
  genuinely stale assignment is always provable. This matters because
  anti-entropy repairs *per table*: with VM and interface rows repaired but
  leases not yet, every NIC resolves to "holds no address", which would otherwise
  route every litevirt-owned address in the cluster into the clear branch.

A pass that withheld a delete withholds its clears too — having proven its
inventory read partial, it does not then act destructively on it. A withheld
clear does not escalate that way; it is proven per address and costs only that
one.

In every case the sweep still applies its creates, updates and assignments, logs
exactly what it withheld and why, and does **not** stamp
`litevirt_netbox_mirror_last_success_seconds`. So NetBox may briefly advertise a
machine that is gone, and never loses one that is not, and
`litevirt_netbox_mirror_sweeps_total{result="error"}` climbs while the condition
lasts.

#### When a withheld removal does not clear itself

For an unreplicated row the condition is transient: the row arrives and the next
sweep converges. It is **permanent** for a NetBox object carrying this cluster's
identity that the local database has no record of and never will — an object
copied by hand, a whole-cluster database rebuild that kept the same identity
fingerprint, a rename that happened while the mirror was down. Every sweep
withholds that one removal, forever: the staleness gauge never advances and the
error counter increments every sweep interval.

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
