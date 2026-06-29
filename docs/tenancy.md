# Tenancy: projects, quotas, billing

litevirt's tenancy model carves the cluster into **projects** — named
buckets of resources that admission-gate VM creation, support
hierarchical limits, and emit metered events to an external billing
system.

The implementation lives in `internal/tenancy/` (engine) and
`internal/billing/` (event emitter). Operator surface is `lv project`
plus the `webauthn:` / `billing_webhook_url` keys in
`/etc/litevirt/config.yaml`.

## Projects

A project is an RBAC path with attached quotas. Names are hierarchical:

```
/_default               (implicit; every VM lands here unless re-tagged)
/acme
/acme/team-foo
/acme/team-foo/staging
```

Create one:

```bash
lv project create acme --display "ACME Corp"
lv project create acme/team-foo --parent acme
```

`lv project ls` shows every project with its parent + display name.
`lv project rm <name>` soft-deletes; the VM rows continue to reference
the project name but new creations against it are refused.

## Quotas

Each project can carry quota rows. Six dimensions are enforced today:

| Dimension | Unit | Counts |
|---|---|---|
| `vcpu` | virtual CPUs | sum of vCPU across active VMs **+ containers** |
| `memory_mib` | MiB | sum of memory across active VMs **+ containers** |
| `disk_gib` | GiB | sum of all attached disks across active VMs |
| `nic` | count | sum of network interfaces across active VMs |
| `public_ips` | count | NICs whose address parses as non-private per `net.ParseIP.IsPrivate()` |
| `backup_gib` | GiB | sum of `TotalSize` across manifests for the project's VMs **+ containers** |

**Containers share the same budget as VMs** — `CreateContainer` and
`CloneContainer` are admitted against the project's `vcpu`/`memory_mib` quota
just like `CreateVM`, and a container's `lv ct backup` footprint counts toward
`backup_gib`. A stopped container still counts (allocation, not live usage), and
deleting it frees the budget. A project that still owns containers can't be
deleted (`lv project rm` refuses until they're reassigned/removed).

Set:

```bash
lv project quota acme \
    --vcpu 256 --mem 524288 --disk 8192 \
    --nics 200 --ips 16 --backup 10240
```

(Flag units: `--mem` is MiB, `--disk`/`--backup` are GiB, `--ips` is the
public-IP count. Zero on any flag means unbounded for that dimension.)

Admission applies the binding cap = **min over the project and every
ancestor**. A `/acme` cap of 256 vCPU is binding on `/acme/team-foo`
even if no team-foo cap is set. Each dimension gates on
**used + new > limit**; an over-quota CreateVM is rejected with the
violated dimension(s) named, e.g.:

```
project "/acme/team-foo" quota exceeded: public_ips (used 4 + new 2 > limit 5)
```

Multiple violations are joined with `; `.

Current usage:

```bash
lv project usage acme
# project: acme
#   vCPU used:   132
#   mem (MiB):   262144
#   disk (GiB):  3200
#   NICs:        88
#   public IPs:  4
#   backup (GiB):5120
#   VM count:    37
```

Usage is computed at admission time (cheap join against `vms` +
`vm_disks` + the `vm_backups` size index). It is not cached, so an
external tool that mutates the cluster outside the RPC surface stays
visible immediately.

## Project = RBAC scope

The project name is also the RBAC path under `/projects/`. To grant
a team Operator on their slice:

```bash
lv role grant Operator group:acme-eng@oidc:corp --path /projects/acme --propagate
```

The grant covers every VM, network, and stack created under `acme`
*and* its descendants. See `docs/auth.md`.

## Project-scoped network & storage isolation

A network or storage pool is either **owned by a project** or **global**:

```bash
lv network create app-net --type bridge --project acme   # owned by acme
lv pool create fast --driver zfs --source tank --project acme
lv network create mgmt --type bridge                     # global (shared)
```

- **Global** (the default, and every object that pre-existed this feature) is
  usable by **every** project — the deliberate shared-infrastructure escape hatch.
- **Owned** means isolated: only workloads in that project (or a root operator)
  may attach to it.

Enforcement is at **attach time**, not just display. When a VM or container binds a
NIC or places a disk, litevirt admits the workload's project against the target's
owner: a workload may use a global resource or one its own project owns, never
another project's. This covers create **and** the day-2 paths — disk move,
replicate, import, replication-schedule creation, and replica promotion. A
raw/unmanaged bridge is outside isolation, so attaching to one requires
cluster-root network authority; a project-scoped workload must use a managed
network.

Reads are scoped too: `lv network ls` / `lv pool ls` show global objects plus
those owned by projects the caller can read, and each object shows its owner.
RBAC follows the object — an owned object authorizes under
`/projects/<p>/networks|storage_pools/<name>`, a global one at the root path (so
only a root grant manages shared fabric).

This is logical isolation enforced at the control plane. A *dataplane* cross-project
L2 firewall deny is intentionally **not** part of it: admission already makes its
firing condition unreachable (two different projects can't share a non-global L2,
and a global L2 is shared by design — put a default-deny security group there to
lock it down). VLAN/VXLAN-range and network-namespace separation remain follow-ups.

## Billing events

Every VM lifecycle transition emits a billing event when
`billing_webhook_url` is set in daemon config. The emitter
(`internal/billing`) POSTs JSON:

```json
{
  "kind":       "vm.create",
  "project":    "/acme/team-foo",
  "subject":    "web-1",
  "vcpu":       4,
  "mem_mib":    8192,
  "disk_gib":   100,
  "backup_gib": 0,
  "bytes":      0,
  "timestamp":  "2026-05-12T14:23:51Z"
}
```

The numeric dimension fields (`vcpu`, `mem_mib`, `disk_gib`, `backup_gib`,
`bytes`) are omitted from the payload when zero. `timestamp` is set by the
emitter so retries don't drift.

Event kinds emitted today: `vm.create`, `vm.delete`. The schema is
designed to extend (`vm.resize`, `disk.attach`, `backup.push`)
without breaking consumers — unknown kinds should be ignored.

Delivery is **fire-and-log**:

- 5-second HTTP timeout — a slow consumer never blocks `CreateVM`.
- One in-band retry on a 5xx response, then drop with a slog.Warn.
- No durable queue. If durability matters, point the webhook at a
  lightweight ingest service (Kafka REST proxy, Vector, etc.) and
  scale that.

Empty `billing_webhook_url` activates `NopEmitter` — the call sites
are still exercised but no HTTP traffic is generated. Tests inject
`RecordingEmitter` to assert event shapes.

## What's not yet built

The tenancy design covers more than this slice ships:

- **Dataplane hard isolation** — per-project VLAN/VXLAN ranges, per-project Ceph
  pool/RBD namespace, per-project network-namespace separation on every host, and a
  cross-project L2 firewall deny. Project ownership of networks/pools and
  *attach-time* admission already ship (see *Project-scoped network & storage
  isolation* above); what remains is enforcing separation in the dataplane rather
  than only at the control plane.
- **Per-tenant PKI sub-CA** — cluster CA issues a tenant sub-CA, tenant
  operators get certs from the sub-CA so root-cluster trust isn't
  shared. Today every operator presents a cert from the single
  cluster CA.

Both are planned follow-ups. The data model is already in place —
adding hard isolation is a host-side networking patch, not a schema
change.
