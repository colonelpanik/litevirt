# Split-Brain Ownership Generations Design (Phases 3–6)

**Date:** 2026-08-01

**Status:** Approved direction (numeric epochs, central transfer primitive);
document pending user review

## Purpose

This project closes the residual split-brain risks left open after
`split_brain_gate_v1` and the owner-epoch proof-binding slice: stale
fence replay after a fenced host rejoins, ownership transitions that do
not advance a generation, shared-storage takeover without storage-side
exclusivity, watchdog disarm while ownership remains, and divergence
classes the detector does not yet report.

The principal safety invariant is:

> Every ownership transition of a workload advances exactly one
> authoritative, monotonic generation, recorded in the database and the
> runtime; no fence, proof, or repair may authorize work against any
> generation other than the exact one it superseded.

## Decision: numeric epochs are the sole ownership authority

The v41/v44 numeric columns (`vms.vm_owner_epoch`,
`containers.owner_epoch`) remain the only ownership generation. The old
roadmap's opaque owner IDs are rejected: they are unordered (breaking
the `operation_steps` primary key and the v44 reservation ABA guards),
they would require a large migration against the monotone
capability-latch rollout model, and running both would create two
ownership authorities that can disagree.

The opaque design existed to make independently-minted generations
structurally distinguishable. That property is preserved by three
provisos instead of a representation change:

1. **Quorum-gated mints.** Epoch increments happen only inside
   decision-gated transitions (failover coordinator gate, promote gate,
   audited repair). No un-gated path may increment.
2. **Divergence is a safety fault, not a merge.** The immutable
   `fence_workload_proof` rows treat a conflicting
   `superseded_owner_epoch` for the same (fence, workload) key as
   unresolved, and the Phase 6 detector reports DB↔runtime epoch
   mismatch. A cross-partition duplicate mint therefore surfaces
   instead of silently winning LWW.
3. **Resolver carve (narrow).** `ruleColUnresolved` fires only on
   exact-HLC-timestamp ties; the vms chain already holds
   `host_name`/`pending_action_id` unresolved ahead of
   `ruleNumericMax("vm_owner_epoch")`. An additional carve marks an
   exact-ts tie with equal epochs but divergent owner columns
   unresolved. This layer is best-effort; the load-bearing detection is
   provisos 1–2.

`containers.host_name` is part of the primary key, so a container
ownership split is two live rows the per-PK resolver cannot see. The
detector (Phase 6) and the relocation re-key (Phase 4) cover that shape.

## Phase 4 — ownership generations and runtime markers

### Central transfer primitive

All VM ownership transitions route through one guarded corrosion
primitive:

```go
TransferVMOwner(ctx, c, name, newHost, newState string, expectedEpoch int64) error
```

One transaction: CAS on `vm_owner_epoch = expectedEpoch` (and liveness),
increment the epoch, write `host_name`/`state`. `ErrNoRowsAffected` on
a lost race. Same guarded-batch pattern as `WriteVMRescheduleProof`.

The eight production `UpdateVMHost` call sites split into:

- **genuine transfers** — failover coordinator pending-commit, promote
  commit, migrate commit, repair-owner, owner-assert re-key, vmcheck
  reschedule, host-drain moves — all become `TransferVMOwner` with a
  freshly-read expected epoch;
- **same-host state changes** — remain on a restricted `UpdateVMHost`
  whose new contract forbids changing `host_name` (enforced by the
  writecheck guard so future call sites cannot bypass the primitive).

The container analogue rides the existing relocation PK-change path,
with one ordering constraint the 2026-08-01 lab run proved is load-bearing:
the relocation proof carries the **source** row's epoch, but the executor's
stale check (shipped in the owner-proof slice) compares against the row it
reads at claim time. The target-row insert must therefore be created at
exactly the proof's (source) epoch, guarded on the relocate token, and the
`+1` mint happens only in the completion mutation after the recreate lands.
Creating the target row at any other value (0 today, `source+1` naively)
makes the checker refuse a legitimate relocation forever — observed live:
`proof_epoch=5 current_epoch=0` wedged fail-closed on real LXC. This is the
same read-old → prove → move → mint-new ordering Phase 5 uses for fences.

### Increment sites

Mint on: create (epoch 0→1), migration completion, failover ownership
commit (**after** the move/promote lands, per the strict Phase 5
ordering), replica promotion (including same-name), container
relocation landing, `repair-owner`, owner-assert re-key. Reschedule
completion increments in the same mutation that clears the pending
proof.

### Runtime markers

- **VM:** owner epoch in libvirt domain `<metadata>`; flags conditional
  on state (running ⇒ LIVE|CONFIG, stopped ⇒ CONFIG; read LIVE for a
  running domain). Written by the executor as part of claiming the
  transition; the reconciler converges a missing/stale marker for the
  crash window.
- **Container:** root-owned
  `/var/lib/litevirt/containers/<name>/owner_epoch`, mode 0600,
  written/validated on the same schedule.

### Backfill and readiness

A one-time reconciler stamps every non-deleted workload with a nonzero
epoch and its runtime marker. `owner_epoch_v1` is advertised (added to
`capabilities.supported`; it is already in `all`) only when: no empty
epochs remain, no unresolved owner ties, no dual-run findings, and no
DB↔runtime mismatch — never bless an already-diverged cluster. The
latch follows the standard monotone/durable rules; pre-latch behavior
is unchanged (empty proof epochs stay inert).

## Phase 5 — exact fence-to-owner binding and watchdog shutdown

### fence_workload_proof

New replicated, immutable, append-only table keyed on
`(fence_epoch, owner_kind, owner_name, owner_host)`, carrying
`superseded_owner_epoch` read from the workload row at fence time, plus
coordinator/quorum/lease context. Reuses the `runtime_action_proofs`
custom-merge discipline; a replicated conflict on
`superseded_owner_epoch` is unresolved and reported as a safety fault.
Retention is a convergence-safe tombstone policy, never in-place
mutation.

### Staleness rule

Promote/reschedule of workload W is authorized only when a
fence-workload proof exists whose `superseded_owner_epoch` equals the
**exact** epoch W held on the fenced host. This kills
fenced → rejoin → run-at-new-epoch → stale-fence-replay, which the
current `fence_epoch.go` recency window cannot. Strict per-workload
ordering: read old epoch → write proof → move/promote → mint new epoch.

Manual fence-confirm materializes workload proofs lazily at
reschedule/promote from the recorded pre-fence row; an unestablishable
old epoch refuses with the closed reason `fence_unproven` — never
guessed.

The proof reference is carried through promote and reschedule alongside
the existing `fence_epoch` string; `fence_epoch_v1` gates enforcement.

### Watchdog disarm

The daemon refuses to disarm the hardware watchdog on graceful shutdown
while this host still owns any VM, container, or VIP; disarm requires
zero local ownership or a completed quorum-gated handoff. The existing
hardware-identity checks (softdog rejection, `WDIOC_GETTIMELEFT`
verification) are preserved unchanged. This ships on its own branch
(`fix/watchdog-owned-workload-disarm`) since it does not depend on the
schema work.

## Phase 3 — storage classification and storage-native exclusion

- `storage.HAClass(driver) → {SharedLockCapable, ReplicaOnly,
  Unverified}`: Ceph/RBD and iSCSI are lock-capable (capability, not
  proof — realized only when the lock is acquired at failover);
  local/dir replica-only; NFS/cluster-FS unverified.
- `storage_pools.ha_policy` at the next available schema version
  (not the old roadmap's v39). Default `''` = `legacy_unverified`:
  still fails over but loudly surfaced; new enablement chooses
  verified-safe or an explicit unsafe override.
- Prerequisites are maintained runtime facts re-validated before
  HA-eligibility, not recorded once at attach. RBD: track
  client/watcher identity across reconnects, verify blocklist caps;
  takeover = `rbd lock add` **plus** `ceph osd blocklist add`
  (exclusive-lock alone is cooperative). iSCSI: stable per-host SCSI-3
  PR key re-registered after session churn; takeover = preempt-and-abort
  (`sg_persist`). Both extend the existing command-runner seams.
- HA eligibility is per writable disk and path; any non-exclusive
  writable shared disk blocks auto-start. A missing lock primitive
  fails closed.

## Phase 6 — detector and repair

Extend the existing leader-gated, alert-only dual-run detector rather
than adding a parallel scanner:

- integrate unresolved owner ties from the LWW resolver into the same
  findings stream;
- detect DB owner ≠ sole runtime holder, DB↔runtime epoch mismatch, and
  dual kernel-assigned VIP;
- include containers and partial probe results without hiding positive
  holders;
- `repair-owner` gains exact owner-epoch and fence-proof arguments and
  refuses without them; a true multi-running workload remains
  alert-only, never auto-destroyed.

## Compatibility

All schema changes are additive with legacy-compatible defaults, each
claiming the next schema version at implementation time (current: 47).
The proto field (`owner_epoch = 13`) is already additive and shipped.
Enforcement is gated on `owner_epoch_v1` / `fence_epoch_v1` capability
latches with the uniform config-flag pattern; pre-latch mixed clusters
keep today's behavior, post-latch enforcement fails closed. New
replicated statement shapes are registered in the compatibility ledger
(`stmtshapecheck`).

## Testing

TDD throughout; every claimed security property is mutation-verified
(break, observe red, restore). Multi-node behavior lands in
`tests/fleet/` (stale-proof refusal across real replication, mixed
rollout, latch durability). Lab acceptance inspects the runtimes
directly (`virsh` metadata, container markers, LXC state), and the
final claim must state what the lab could not exercise: real RBD/iSCSI
backends, watchdog hardware, and any absent topology.

## Delivery

PR stack (branches on the fork; upstream PRs only after verification
evidence and user confirmation):

1. `feat/split-brain-owner-proof` — proof-binding slice (committed:
   `da6b63a`).
2. `feat/split-brain-owner-epochs` — Phase 4.
3. `feat/split-brain-fence-epochs` — Phase 5 (depends on 2).
4. `feat/split-brain-storage-exclusion` — Phase 3.
5. `feat/split-brain-detection-repair` — Phase 6.
6. `fix/watchdog-owned-workload-disarm` — independent.
