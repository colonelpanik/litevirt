# Phase 4 implementation plan — owner epochs (feat/split-brain-owner-epochs)

Per the approved design (2026-08-01-split-brain-ownership-generations-design.md).
TDD throughout; every property mutation-verified with a positive control;
multi-node behavior in tests/fleet/; schema claims the next version (≥48);
new replicated statement shapes into the compatibility ledger.

## Step 1 — TransferVMOwner primitive (corrosion)

`TransferVMOwner(ctx, c, name, newHost, newState string, expectedEpoch int64) error`
One guarded transaction (ExecuteBatchGuarded, same pattern as
WriteVMRescheduleProof): row must be live AND `vm_owner_epoch = expectedEpoch`;
then SET host_name, state, vm_owner_epoch = expectedEpoch+1, cleared
state_detail. ErrNoRowsAffected on a lost race. Register the statement shape.

Failing tests first: transfer succeeds at matching epoch and increments;
stale expectedEpoch writes NOTHING (row unchanged); concurrent-transfer race
loses cleanly. Mutations: drop the epoch guard → stale test red; drop the
increment → increment test red.

## Step 2 — route the eight call sites

Ordering refinement (spec: mint AFTER the move lands): the six
completion-style sites below transfer-and-complete in one write and route
through incrementing TransferVMOwner directly. The reschedule pair is split:
the coordinator's pending write (coordinator.go:1215) moves host_name at the
SAME epoch under a CAS guard (non-incrementing variant), and the executor's
completion mutation — the one that clears pending and sets running — carries
the +1. That is the read-old → prove → move → mint-new ordering.

Genuine transfers → TransferVMOwner with a freshly-read expected epoch:
- internal/failover/coordinator.go:1215 (reschedule pending commit — the
  coordinator already re-reads the row under the gate since da6b63a; reuse
  that row's epoch)
- internal/grpcapi/promote.go:798 (promotion commit)
- internal/grpcapi/migrate.go:1047 (migration commit)
- internal/grpcapi/vm_repair_owner.go:111 (audited repair — fixes the
  "repair-owner does not bump" gap confirmed live)
- internal/health/owner_assert.go:211 (owner-assert re-key)
- internal/health/vmcheck.go:588 (vmcheck reschedule)
- internal/grpcapi/host.go:456 and :497 (drain moves)

UpdateVMHost keeps only same-host state changes: add a guard that returns an
error when hostName differs from the row's current host (writecheck-adjacent
test pins that no production caller can move a VM through it anymore).

Per-site red first: a fleet test per flow asserting the epoch advanced
exactly once across the transfer (and, for the rejoin fight: a stale node's
UpdateVMHost/state write CASes against an epoch it no longer holds and
loses — kills the 3x-observed equal-ts ownership fight).

## Step 3 — container relocation epoch carry (the lab-proven ordering)

Target row is created at the proof's SOURCE epoch (not 0, not source+1) —
today's creators: failover relocation (coordinator startRelocation →
target-row insert), migrate restore, backup restore. The +1 mint happens in
the completion mutation that marks the relocation landed (same mutation that
clears the token). The containercheck claim comparison (shipped in da6b63a)
then holds at claim time and the increment is post-landing — the exact
read-old → prove → move → mint-new ordering.

Fleet test: relocation with nonzero source epoch completes end-to-end (would
WEDGE on the pre-plan code — the live 2026-08-01 failure); epoch on the
landed row = source+1; a second stale relocation proof for the old epoch
refuses.

## Step 4 — runtime markers

- VM: owner epoch in libvirt domain <metadata> (namespace litevirt), written
  by the executor as part of claiming a transition (define/start paths in the
  reconciler + promote + migrate landing), flags LIVE|CONFIG when running,
  CONFIG when stopped; read back via virsh-visible metadata for lab checks.
  internal/libvirt gains SetDomainOwnerEpoch/GetDomainOwnerEpoch.
- Container: root-owned 0600 /var/lib/litevirt/containers/<name>/owner_epoch,
  written at recreate/restore landing, validated by containercheck.
- Reconciler converges a missing/stale marker toward the DB row (crash
  window) — but NEVER starts/stops anything based on the marker alone in
  this phase; enforcement (refusing self-heal restarts on marker/epoch
  mismatch — the dual-run killer) activates only under owner_epoch_v1.

## Step 5 — backfill + readiness + owner_epoch_v1

One-time reconciler pass stamps every non-deleted workload with a nonzero
epoch (0→1) + its runtime marker. Readiness check (all epochs nonzero, no
unresolved owner ties, no dual-run findings, no DB↔runtime mismatch) gates
adding OwnerEpochV1 to capabilities.supported behind an
enforcement.owner_epoch config flag (uniform-latch pattern; add the flag to
docs — the docs guard requires it). Under the latch: the reconciler's
"VM marked running but not in libvirt — attempting restart" and
"stopped out-of-band" sync paths require marker/DB epoch agreement before
acting (bug 3's structural fix).

Fleet tests: mixed rollout (flag on a subset → no latch, behavior unchanged);
latch forms on uniformity, survives restart, partition fails closed;
post-latch a rejoining stale node REFUSES the self-heal restart (the ~9s
dual-run reproduced as a fleet scenario and killed).

## Step 6 — gates, lab, review

Full battery + `make ci-guards` (schema bump to 48 + ledger + stmtshape).
Lab: deploy exact signed commit; scenario matrix = organic failover with
NATURAL epoch increments (no more hand-staging); rejoin of a host whose VM
moved → its stale write loses the CAS + no restart (virsh: domain stays off,
no equal-ts divergence in doctor); repair-owner bumps the epoch; markers
visible via virsh metadata + marker files. State watchdog/IPMI/storage
limits as always. Adversarial review round before any upstream PR.
