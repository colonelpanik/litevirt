# Isolation Epoch and Reseed Design (§A)

**Date:** 2026-08-01

**Status:** Direction A (durable schema isolation epoch + epoch-keyed
replication admission + reseed primitive) approved 2026-08-01; this document is
the detailed design, pending review

## Purpose

A node that was rolled back below a capability token the cluster had already
latched — or that was isolated and kept writing — can today rejoin and resume
replicating without ever discarding the state it produced while incompatible.
The 2026-07-29 slice made the *first* half safe: such a node self-detects, WAL-
quarantines, de-advertises its capabilities, and raises
`ha_degraded{rolled_back_latch}`. What is missing is the contract's second half:
nothing *else* refuses that node, and there is no supported way to reseed it.

The principal safety invariant is:

> A node whose local state was produced outside the cluster's current
> compatibility regime must not be able to inject that state back into the
> cluster. It is refused by its peers — not merely self-muted — until an
> operator-driven reseed replaces its state and adopts the current epoch.

Note what the shipped slice does and does not give us, because it is easy to
overread: it fires only on a rollback to a build *containing* the check, so it
makes the NEXT rollback detectable, not any past one; and it is self-enforcement
only. A self-muting node is exactly the node whose self-assessment you cannot
rely on.

## Shape decision (approved)

**A. Durable isolation epoch in the schema + epoch-keyed replication admission
+ an explicit `lv host reseed`.**

Rejected: **B, a host-local marker file only.** It is cheaper, but peers cannot
refuse what they cannot see, which fails the requirement outright — the whole
point is that the *cluster* stops trusting the node, not that the node stops
trusting itself.

## Model

```
hosts.isolation_epoch      INTEGER NOT NULL DEFAULT 0   -- cluster's view per host
hosts.isolation_reason     TEXT                          -- '' | rolled_back_latch | manual | schema_forward
```

Schema claims the **next available version** at implementation time (v47 is
current; the host-network spec is expected to take v48, so this is expected to
be **v49** — whichever is next when it lands). Additive, legacy-compatible
defaults, statement shapes registered in the compatibility ledger.

The epoch is **cluster state about a host**, not host-local state — that is the
whole difference from shape B. It is replicated, so every peer independently
knows a node is under isolation, and a quarantined node cannot clear its own
epoch by editing a local file. The column is monotone: it only ever increases,
and only through the two writers below.

## Protocol

1. **Isolation.** When a node self-detects a rollback below a latched token (the
   shipped detector), it does what it does today AND the cluster records an
   isolation: `isolation_epoch = max(cluster) + 1`, `isolation_reason` set. The
   write is quorum-gated and made by a *healthy peer* observing the degraded
   node, not by the quarantined node itself — a node that cannot be trusted to
   replicate cannot be trusted to record its own quarantine. Manual isolation
   (`lv host isolate`) uses the same path for the operator-driven case.

2. **Admission.** `requireReplicationPeer` (`internal/grpcapi/sync.go`) gains an
   epoch check: a `PushMutations`/state-sync call from a host whose replicated
   `isolation_epoch` is nonzero is refused with a distinct code and reason. This
   is deliberately **not** a version-skew check — mixed-version rolling upgrades
   must keep working, and gating on version would break them. It gates on the
   recorded isolation fact only.

3. **Reseed.** `lv host reseed <host>` (admin-gated, audited, forwarded to the
   target like `repair-owner`) drives: stop local runtime loops → discard local
   replicated state → full state pull from a healthy peer → verify convergence
   (schema version, capability set, and state digest match the source) → adopt
   the current epoch by clearing `isolation_epoch` in the same guarded write
   that records the reseed. Only a *verified* convergence clears it; a partial
   pull leaves the node isolated.

4. **Capability gate.** The whole regime is gated on a new
   `isolation_epoch_v1` token with an `enforcement.isolation_epoch` config flag,
   following the uniform pattern: advertised only while the flag is on, monotone
   durable latch, partition fails closed. Pre-latch clusters behave exactly as
   today, so this is safe to roll out incrementally.

## Refusals and failure modes

- A reseed that cannot verify convergence **refuses to clear** the epoch and
  leaves the node isolated with `last_error` — half a reseed is worse than none.
- A quarantined node's own attempt to write `isolation_epoch` is rejected by the
  guarded writer (the epoch is monotone and peer-written).
- If every peer is unreachable, isolation cannot be recorded — the node stays
  self-quarantined (today's behavior) and `ha_degraded` still fires. The cluster
  never *silently* trusts it; it simply hasn't recorded the fact yet.
- Reseed is refused while the node owns running workloads: discarding state
  under a live VM is the one way this primitive could destroy something. Drain
  first (this mirrors the watchdog disarm rule landed in `5a7b398`).

## Testing

- Unit: monotone epoch writer, the admission predicate, the convergence verifier
  (schema + capabilities + digest), and the owns-workloads refusal.
- Fleet (the real value): a three-node cluster where one node is isolated must
  see its `PushMutations` refused by both peers while the other two keep
  replicating normally; after a reseed its pushes are accepted again. The named
  scenario from the roadmap — rollback → isolated writes → upgrade-without-
  reseed rejected → reseed admitted — lands here.
- Mutation-verify: drop the admission check (isolated node's writes land →
  red), drop the convergence verification (partial reseed clears the epoch →
  red), and a positive control (a healthy node is never refused).
- Lab: isolate a node, confirm from *its peers* that its mutations are refused
  (read the peers' DBs directly, not the isolated node's view), then reseed and
  confirm convergence via `lv cluster converge` plus a direct digest comparison.
  **Stated limit:** the lab cannot exercise a genuine version-rollback
  incompatibility without building an older binary; if that is not done, the
  rollback trigger is unit-tested only and the lab covers the manual-isolation
  path.

## Delivery

Branch `feat/isolation-epoch-reseed`, after the split-brain stack. Schema +
epoch writer + admission gate land first (the safety half), then the reseed
primitive, then the capability flip — so at no point does a half-built reseed
exist that could clear an epoch it hasn't earned.
