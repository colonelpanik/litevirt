# Trust-recovery lifecycle — frozen follow-up scope

Frozen before implementation begins, as required by the review handoff in
`2026-09-08-pr160-trust-lifecycle-review.md`. That document is the contract; this one records
the decisions that must not drift while the work is sequenced, and the boundary the
implementation may not overstate.

**Status: not implemented.** The NetBox IPAM and inventory-mirror work ships without a
permanent-loss recovery mechanism. Recovery is this follow-up.

## Why it is separate

Core IPAM establishes safety without human exceptions. The trust lifecycle then adds a
recovery mechanism whose authorization rules can be reviewed on their own terms, rather than
as a rider on an addressing change. Half of this contract, shipped, is the failure mode the
contract is written against — locally plausible conditions passing tests that assume the
disputed semantics.

## Frozen policy decisions

**Withdrawal wins.** A withdrawal invalidates future reliance, including allocation through
bindings already authorized on that evidence. It never releases an existing claim. It wins
against concurrent or unobserving re-attestation.

**Restoring trust is deliberate.** A grant may authorize a premise only if every known
invalidation for its scope is contained in the invalidation set that grant explicitly
acknowledges. Causality is established by that subset test — **not** by wall-clock time, not by
LWW, not by ID ordering, and not by a per-workload owner epoch. A re-attestation names the
frontier the operator reviewed; if the server's frontier differs, the request is rejected with
the actual frontier rather than silently updated.

**Evidence is not permission.** A complete, explicitly committed grant authorizes a premise. A
manifest alone does not. A grant whose referenced accounting has not arrived, or does not
content-match, is *indeterminate* and authorizes nothing.

**Discovery is monotone.** Membership identities from any validly recorded accounting remain
discovery inputs after withdrawal or supersession. Removing permission to trust a source never
establishes that the hosts it named did not exist.

**A same-certificate rejoin is not a pause.** The machine can acquire new membership and
inventory knowledge, so its old permanent-loss accounting must not silently become applicable
again on a later disappearance. Rejoin invalidates that episode durably; certificate identity
alone cannot distinguish successive loss episodes.

**Premises stay separate.** Membership, inventory and runtime power-off remain distinct.
Fencing evidence excuses a runtime scan and never substitutes for missing knowledge. An
inventory grant never becomes power-off evidence.

**Permissions are asymmetric.** Withdrawing trust is a cluster-scoped operational permission
requiring an attributable actor and a reason, and no evidence check — removing trust needs
none. Granting trust and resuming a trust-invalidated binding stay administrative. A
project-scoped operator must not acquire cluster-wide authority by holding the operator role.

## The distributed-enforcement boundary — do not overstate it

The store offers local transactions and asynchronous replicated state. Its leader row and a
local read-back are **not** a linearizable revocation service. Three statuses stay distinct and
must never be conflated:

- **recorded** — durable on this executor, which has closed dependent admission locally;
- **enforced** — every executor able to perform a dependent operation has durably acknowledged
  the invalidation and closed old admission, with outstanding in-flight operations listed;
- **pending / indeterminate** — completeness could not be established. A read error is not an
  empty executor list.

During propagation, a node that has not learned a withdrawal can still act on its old view.
This design does not claim otherwise. A requirement that no node may admit an operation from
the instant any node accepts a withdrawal needs a linearizable authorization authority or a
distributed read/use barrier on every affected operation — an architectural expansion, not an
extra read inside the sweeper. Availability while propagation is pending must be documented.

A withdrawn membership grant can make the executor universe unprovable. The withdrawal is then
recorded while cluster enforcement is indeterminate, and that very grant must not be reused to
certify completion. Corrected independent accounting can restore provability. This is an
explicit boundary, not a silent bypass.

## Implementation order

As set out in the contract's section 9: freeze semantics; immutable events plus a pure
resolver; writes with idempotency and causal re-attestation; activation certificates and
dependency-aware readiness; admission and invalidation coordination with propagation
acknowledgment and bootstrap gates; one validator for recovery, resume, re-key and repair;
CLI, audit and health derived from that resolver; fail-closed migration that never infers
empty dependency sets for legacy live bindings.

All participating executors must support the enforcement protocol before trust recovery is
enabled, and the capability boundary must be tested against older binaries — a new table alone
does not stop an older allocator ignoring a new gate. Enforcement must not silently downgrade
on rollback.

## Acceptance

The contract's twelve-area matrix, exercised through the real resolver, decoder and applier
paths under controlled schedules, plus property tests: merging an unacknowledged invalidation
cannot increase authority, and delivery order cannot change the converged verdict. Named
mutations complement those properties rather than replacing them.

The merge criterion is that this contract is implemented and its boundary cases exercised —
not that a different set of locally plausible conditions passes.
