# Proxmox-parity roadmap, under the Nomad/Consul constraint

Status: assessment + roadmap (no implementation). Written 2026-08-05,
audited against the tree at the v50 consolidation head — every "have" below
was verified in code, not recalled.

## The thesis

The largest ROI is litevirt covering everything an operator uses Proxmox VE
for, while staying what Proxmox is not: one static binary, gossip membership,
CRDT state, no external quorum store, reconciler-driven convergence, and a
scriptable CLI. Feature work that compromises that constraint is a net loss
even when it closes a parity box.

## Where parity already holds (verified)

| Proxmox function | litevirt state |
|---|---|
| VM lifecycle, templates, linked/full clones, cloud-init | ✓ |
| LXC containers (create/exec/snapshot/backup/migrate/relocate) | ✓ |
| Live migration | ✓ |
| HA with real fencing (IPMI, watchdog, fail-closed partitions) | ✓ — plus ownership generations, which Proxmox has no analogue of |
| Storage drivers | ✓ dir, NFS, iSCSI, LVM-thin, btrfs, Ceph, ZFS (`internal/storage/`) |
| Storage replication | ✓ (driver-aware runner) |
| Backups | ✓ PBS-class already: chunk-dedup incremental repos, AES-256-GCM, mark-and-sweep GC, retention, `repo init/ls/gc/verify/prune/sync` |
| Snapshots (VM + CT) | ✓ |
| Browser console | ✓ noVNC (VNC page/modal/websocket) + xterm.js serial |
| ISO / images | ✓ `lv image pull/import/push/build`, boot-from-cdrom installer flow |
| SDN | ✓ bridges/bonds/VLAN (declarative host_networks), VXLAN, BGP — cleaner than Proxmox SDN |
| Firewall | ✓ nftables, security groups, IP sets |
| PCI passthrough | ✓ concrete-address + mapped, journaled hotplug |
| vTPM / UEFI | ✓ |
| Users/RBAC/realms/2FA/tokens | ✓ |
| Audit | ✓ signed, tamper-evident — beyond Proxmox |
| Pools/quotas | ✓ projects, with *enforced* serialized admission |
| Placement | ✓ scoring engine (Proxmox: none) |
| Health/monitoring | ✓ v50: durable conditions, one `GetClusterHealth`, effective capacity |
| Guest agent quiesce | ✓ fsfreeze/thaw on snapshot/backup |
| Multi-cluster | ✓ federation/regions |
| API/UI/CLI | ✓ REST, htmx UI, `lv`, MCP (beyond Proxmox) |

Conclusion: this is not a "reach parity" project. It is a short punch list
plus a discipline to keep.

## True gaps, ranked

1. **USB passthrough.** Explicitly unhandled (`xmlgen.go` ignores non-PCI
   hostdevs). Operators pass through license dongles and Zigbee sticks
   constantly. Shape: reuse the PCI intent/realization pattern
   (vendor:product or bus.port selector, journaled attach/detach, no new
   config surface). Moderate effort; the topology-preserving redefine work
   already did the hard part for PCI.
2. **SPICE in the browser.** noVNC covers VNC; SPICE guests still need
   virt-viewer. Either ship a spice-html5 page next to the noVNC one or
   deliberately document VNC-first and close the box. Small.
3. **UI upload affordance for ISOs/images.** `lv image pull/import` covers
   the mechanics; the UI lacks a drag-and-drop → `image import` flow.
   Small, high first-touch value.
4. **Scheduled snapshots** (distinct from scheduled backups) with per-VM
   retention — Proxmox operators use these as cheap local undo. Small:
   the schedule machinery exists for backups; add a snapshot mode.
5. **Bulk/maintenance ergonomics**: `lv host drain` exists; what's missing
   is the Nomad-style *plan* preview ("this drain will move these 7 VMs,
   two don't fit") using the placement engine in dry-run. Small-moderate,
   large operator-trust payoff — and it consumes the v50 capacity model.

Deliberately NOT gaps: corosync-style quorum disks (the CRDT+gates model is
the product), pmxcfs, the applet marketplace, subscription plumbing.

## The elegance criteria (the Nomad/Consul half)

Every parity item above must satisfy all of these, which existing features
already model:

- **One binary, no new daemons.** A feature needing a sidecar is redesigned
  or rejected.
- **Declarative + reconciled.** Desired state in replicated rows; a
  reconciler converges; ad-hoc imperative verbs only as sugar over rows
  (host_networks is the reference shape).
- **Safety behind capability latches.** Anything that can destroy data or
  split-brain ships default-off behind a cluster-wide token with monotone
  latch semantics, like hotplug and the split-brain gates.
- **Scriptable.** Every list/inspect grows `-o json` where it lacks it;
  exit codes are contracts (`lv health` 0/1/2 is the reference).
- **Docs-guarded.** The triangulation test keeps CLI/docs honest — every
  new flag documented, no phantom commands.
- **Lab-verified.** Fleet fakes prove logic; qemu/nftables/LXC claims are
  proven on the nested lab with virsh/lxc/kernel evidence (the v50
  campaign is the template — it caught two bugs the unit fixtures
  structurally could not).

## Sequencing

USB passthrough → drain planning → UI upload + scheduled snapshots → SPICE
decision. Each lands as its own small PR against the v50 substrate; none
blocks, or is blocked by, the consolidation PR. The correctness backlog
inherited from the #126 review rounds (unpinned-create retry, transient
duplicate-name double-reservation, the reconfigure stop→start window,
non-CPU/memory quota dimensions, quota-drift detection) stays ahead of any
parity feature in priority: parity wins users, correctness keeps them.
