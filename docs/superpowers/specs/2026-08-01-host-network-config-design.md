# Host Network Configuration Design (§O Tier 1)

**Date:** 2026-08-01

**Status:** Shape A (netplan manager) approved 2026-08-01; this document is the
detailed design, pending review

## Purpose

`litevirt` can create libvirt networks but cannot wire the host itself. There is
no way — CLI, API, or UI — to create a host bridge (`vmbr*`), a bond/LACP, a
VLAN interface, or to set a physical NIC's addressing. Operators drop to a shell
and edit netplan by hand, which is the single biggest remaining gap against
Proxmox's *Node → System → Network* (§O Tier 1).

The principal safety invariant is:

> A host network change must never be able to strand the node. Every mutation is
> applied behind a timed rollback that restores the previous configuration
> unless the operator (or the cluster) positively confirms the host is still
> reachable, and no mutation may touch the interface carrying the cluster LAN
> unless explicitly forced.

## Shape decision (approved)

**A. Declarative netplan manager.** The daemon owns exactly one file,
`/etc/netplan/90-litevirt.yaml`, rendered from a declarative spec; application
goes through `netplan try` semantics with automatic rollback; the UI is a form
over the spec plus a diff/confirm modal.

Rejected alternatives, recorded so they are not revisited:

- **B. Imperative `ip`/`bridge` commands with state capture.** Immediate effect
  and no netplan dependency, but not reboot-persistent without inventing a
  second persistence layer, and rollback is hand-rolled per command. The one
  thing it buys (distro independence) is not worth two sources of truth.
- **C. UI-only wrapper over `lv network` plus a read-only NIC view.** Cheapest,
  but does not close the gap: the gap *is* host wiring.

Netplan is already the assumed substrate (the lab's cloud-init writes netplan;
`docs/configuration.md` and the bootstrap docs speak netplan), so A adds no new
dependency on the supported path. Non-netplan hosts are detected and the feature
refuses rather than guessing — see *Refusals*.

## Scope

In scope: host bridges, bonds (incl. LACP), VLAN interfaces, and physical-NIC
addressing (static/DHCP, MTU, optional). Out of scope for this slice: routing
policy, WireGuard/VXLAN overlays (already covered by `lv network`), firewall
rules (`lv sg`), and bridge-to-libvirt-network binding (unchanged).

## Model

A new replicated table records *desired* host network intent, and the owning
host renders it:

```
host_networks(
  host_name, name,            -- PK: intent is per host, named
  kind,                       -- bridge | bond | vlan | ethernet
  members,                    -- JSON: member interface names (bond/bridge)
  vlan_id, vlan_link,         -- vlan only
  addressing,                 -- JSON: dhcp4/dhcp6/addresses/gateway/nameservers
  mtu, bond_mode, lacp_rate, hash_policy,
  state,                      -- desired | applying | applied | rolled_back
  generation,                 -- monotone, bumped on every accepted change
  last_error,
  created_at, updated_at, deleted_at
)
```

Schema claims the **next available version** at implementation time (v47 is
current; Phase 4 needed no bump, so this is expected to be **v48**). All columns
are additive with legacy-compatible defaults, and the table joins the
compatibility ledger with its statement shapes registered.

Only the owning host renders its own rows. Ownership is the `host_name` PK
component, so there is no cross-host write contention and no new ownership
generation is introduced — this table is deliberately *not* part of the Phase 4
workload-ownership regime.

## Apply protocol

Rendering and application run as a journaled operation (`internal/opjournal`),
because the crash window between "wrote the file" and "confirmed connectivity"
must be recoverable:

1. **Plan.** Render the full desired file from all live rows for this host into
   a temp path. Diff against the current file; an empty diff is a no-op.
2. **Snapshot.** Capture the current file plus live state (addresses, routes,
   default gateway, and which interface carries the cluster LAN) — reusing the
   `internal/network` safeguard's snapshot/restore approach, which already
   exists for VM network provisioning (`SafeProvision`).
3. **Journal the intent** with the snapshot, so a daemon that dies mid-apply
   restores on restart rather than leaving a half-applied host.
4. **Apply** via `netplan try --timeout=<N>` where available (its own kernel-side
   revert), else `netplan apply` guarded by our timed restore.
5. **Confirm.** Re-verify: default gateway reachable, cluster-LAN address still
   present, and this node still answers its own gRPC listener. Success →
   `state=applied`, `generation++`, journal committed. Failure or timeout →
   restore the snapshot, `state=rolled_back`, `last_error` populated, journal
   committed as rolled back.

The confirmation is deliberately *local and mechanical* (gateway + own listener),
not "an operator clicked OK": an operator who has just lost their SSH session
cannot click anything, which is exactly when rollback matters most.

## Refusals (fail closed)

- **Self-cutoff guard.** A mutation whose plan removes or re-homes the address
  the daemon advertises (`advertise_address`) or the interface carrying the
  cluster LAN is refused, unless `--force` is passed AND the request carries a
  confirmation token naming that interface. This is the "operator about to
  disconnect the node from its cluster" case; the roadmap's multi-homed traps
  (`CLAUDE.md`) exist precisely because that address is load-bearing.
- **Non-netplan host.** No `/etc/netplan` or no `netplan` binary → refuse with a
  clear message. Never fall back to imperative commands.
- **Foreign netplan file conflict.** If another file defines the same interface,
  refuse and name the file. litevirt owns exactly `90-litevirt.yaml`; it never
  edits or deletes an operator's file.
- **In-flight operation.** One apply at a time per host, enforced by the
  operation journal's existing barrier.

## RBAC, audit, and API

- New RPCs: `ListHostNetworks`, `PlanHostNetwork` (returns the rendered diff,
  writes nothing), `ApplyHostNetwork`, `DeleteHostNetwork`. All admin-gated on
  the host's path with a `host.network` verb, and all audited — a host network
  change is exactly the class of action the audit chain exists for.
- CLI: `lv host network ls|plan|apply|rm`. The docs guard requires every new
  flag and config key to be documented, so `docs/networking.md` gains a host
  network section in the same PR.
- UI: a Network panel on the host detail page — table of intents, an add/edit
  modal per kind, and a **plan-then-confirm** flow that shows the rendered diff
  before applying (never apply straight from the form).

## Testing

- Unit: renderer golden tests per kind (bridge, bond+LACP, VLAN, ethernet), the
  self-cutoff detector, and the foreign-file conflict detector.
- Fleet: an apply that loses connectivity must roll back and leave the node
  reachable and its row `rolled_back`; a crash mid-apply must restore from the
  journal on restart.
- Mutation-verify each: drop the self-cutoff guard, drop the rollback, drop the
  conflict check — each must turn a test red, with positive controls proving a
  legitimate change still applies.
- Lab: the only place this is really proven. Create a bridge on a lab node,
  confirm with `ip link`/`bridge link` (not litevirt's own view), reboot the node
  and confirm persistence, then deliberately apply a cutoff change and confirm
  the node comes back. **Stated limits:** the lab has no bond-capable multi-NIC
  topology and no LACP peer, so bond/LACP is renderer-verified only, never
  claimed as live.

## Delivery

Branch `feat/host-network-config`, stacked after the split-brain work. Backend
(schema + renderer + apply protocol + RPCs + CLI) lands first with its own
tests; the UI panel follows in a second commit on the same branch so the
server-side refusals exist before any button can reach them.
