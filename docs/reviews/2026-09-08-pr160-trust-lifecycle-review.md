# PR 160: retirement trust lifecycle — review and proposed contract

Reviewed 2026-09-08 at `3748e8716818f70c3144746fa34895f67db958d1`.
This is a design/review handoff, not an implemented fix or a claim of formal verification.

## Decision

Do not merge the recovery/withdrawal lifecycle as it stands. Keep the useful work,
but replace the implicit trust rules with one explicit lifecycle shared by the
resolvers, binding authorization, allocation, reclamation, and health reporting.

The policy choices should be:

- Withdrawal invalidates future reliance, including allocations through bindings
  already authorized using that evidence. It never releases an existing claim.
- Withdrawal wins against concurrent or unobserving re-attestation. A deliberate
  re-attestation that acknowledges the withdrawal may restore trust, but does not
  automatically resume an already-live binding that lost its authorization.
- Evidence is not itself a permission. A complete, explicitly committed grant
  authorizes a premise; a manifest alone does not.
- A same-certificate rejoin is not a harmless pause: the machine can acquire new
  membership and inventory knowledge. Its old permanent-loss accounting must not
  silently become applicable again when it next disappears.
- Withdrawing is a cluster-level operational permission, not evidence creation.
  Permit it to an explicitly authorized cluster operator; keep granting trust and
  resuming a trust-invalidated binding administrative. A project-scoped operator
  must not acquire cluster-wide authority merely by holding the operator role.
- A local write is not synchronous cluster-wide revocation. Report receipt,
  enforcement, outstanding executors, and uncertainty separately. Do not call a
  withdrawal globally effective based on local read-back.

## What the review verified

The existing tests pass:

```sh
go test ./internal/corrosion ./internal/grpcapi ./internal/network ./tests/fleet -count=1
```

Four additional safety assertions fail on the reviewed commit. They are in an
isolated checkout at `/tmp/litevirt-trust-review-OrXFAp`, not in the PR worktree:

```sh
go test ./internal/grpcapi ./tests/fleet -run '^TestReview' -count=1
```

| Priority | Finding | Reproduction |
| --- | --- | --- |
| P1 | An already-live binding remains live after inventory withdrawal and a full revalidation pass. | `TestReviewInventoryWithdrawalSuspendsAnAlreadyLiveBinding` |
| P1 | A distinct historical manifest arriving after withdrawal restores trust without any subsequent human re-attestation. | `TestReviewDelayedHistoricalManifestCannotRestoreTrust` |
| P1 | A retirement supplies membership before its referenced accounting manifest arrives. The missing manifest could name another holder. | `TestReviewGrantWithoutItsManifestCannotSupplyMembership` |
| P2 | After re-attestation, the resolver still returns the withdrawn grant's manifest and actor. The standing advisory consumes that attribution. | `TestReviewReattestationReportsActualAuthorizingManifest` |

Code locations, relative to the reviewed checkout:

- `internal/grpcapi/netbox_revalidate.go:92`: live bindings only undergo binding
  drift checks; `server.go:1687` subsequently relies on the suspension flag.
- `internal/corrosion/netbox_recovery.go:560` and `:623`: every manifest ID becomes
  a grant version; any version without a matching withdrawal restores trust.
- `internal/grpcapi/netbox_retirement.go:268`: a grant is consumed without requiring
  its referenced manifest to be present and included in discovery.
- `internal/grpcapi/netbox_retirement.go:283` and
  `netbox_attestation_advisory.go:354`: applicability returns the original grant
  record, and the advisory attributes current authority to that record.
- `internal/grpcapi/netbox_withdraw_rpc.go:189` and `:247`: withdrawal enumerates
  locally visible versions and reports local read-back, not a replicated barrier.
- `internal/grpcapi/netbox_retirement.go:209`: explicitly documents that a reachable
  host's grant can apply again after another disappearance. That policy does not
  account for knowledge acquired during the intervening activity.

The first three are safety defects, not requests for more mutation coverage. The
fourth undermines the advisory's purpose. The same-incarnation rejoin issue is an
additional lifecycle design finding; the four tests above do not claim to test it.

Keep the existing separation of membership, inventory, and runtime premises; the
monotone discovery inputs; exact certificate-incarnation matching; owner-scoped
claims; tolerant ambiguous-response recovery; and separate advisory/uncertainty
conditions. Those are useful foundations.

## 1. State and identities

Use the scope `(cluster fingerprint, host certificate incarnation, premise)`.
Hostnames are labels and discovery inputs, never the grant key. Bindings also
need a binding-generation identity: deleting and recreating a binding under the
same prefix ID must not inherit an old authorization certificate.

Maintain immutable, idempotent events with unique event IDs and complete payloads:

1. **Grant:** scope, grant ID, accounting, actor, reason, display timestamp,
   acknowledged invalidation-event IDs, and evidence format version.
2. **Withdrawal:** scope, event ID, actor, reason, and display timestamp.
3. **Activity invalidation:** host incarnation, event ID, and attributable positive
   evidence that the host became active again after the accounting it invalidates.
   This invalidates grants for both human-supplied premises, not runtime evidence.

An activity invalidation can reference the grants it invalidates or participate
in the same causal frontier as withdrawals. It must not be a wall-clock comparison
or a per-workload owner epoch. Preserve certificate-incarnation isolation as well.

Do not reuse `INSERT OR IGNORE` on one forever-current retirement row as the
version mechanism. Every grant has its own identity and its own attribution.

Prefer one complete grant row containing its bounded, canonical accounting
payload. If accounting remains in a separate manifest table, a grant is
**indeterminate** until the exact referenced payload is present, validated, and
content-matched. The accounting and grant must be committed atomically locally;
read-side completeness checks remain necessary under partial replication.
Write failure or an orphan manifest must never confer authority.

Membership identities from all validly recorded accounting remain discovery
inputs after withdrawal or supersession. With separate records, evidence-only
manifests may widen discovery but cannot excuse a source. Reject oversize or
malformed payloads; never truncate accounting.

Equal IDs with unequal immutable payloads are corruption/conflict and withhold
permission. Do not resolve trust-event conflicts using LWW timestamps. Register
the immutable merge rules on both incremental replication and full-state repair.
No tombstone, compaction, replay, or restore may erase an invalidation while an
older grant can still return.

## 2. Causal remove-wins resolution

For scope S, let R(S) be the set of known invalidation events. A grant G can
authorize S only if:

```text
complete(G)
AND exact_cluster_and_incarnation_match(G)
AND R(S) is a subset of G.acknowledged_invalidations
AND the host is not currently answering
AND the supporting read is valid
```

The subset test determines causality, not time or lexicographic ID order:

- Old grant replay: it has not acknowledged the withdrawal; remains invalid.
- Previously unseen old grant: same result, regardless of delivery order.
- Concurrent grant: it has not acknowledged the withdrawal; withdrawal wins.
- Deliberate re-attestation: the operator reviews the current invalidation frontier
  and submits a fresh accounting acknowledging it; the new grant can authorize.
- A second withdrawal concurrent with that correction: the correction did not
  acknowledge it; trust remains withheld until another explicit correction.

The re-attestation request includes the reviewed frontier/digest. If it differs
from the server's current view, reject with the actual frontier; do not silently
update the request and grant authority the caller did not review. Revalidate
reachability and incarnation at commit. This local compare-and-swap does not
pretend to be a cluster consensus operation; propagation is covered below.

Withdrawal appends one scope-level invalidation, not one row per locally visible
grant version. It requires identity, authorization, reason, and an idempotency
key, but not current reachability, a current host-row match, a fence, or proof that
the grant currently applies. It can record a denial even when the targeted old
incarnation's grant has not arrived locally. Retrying the same request returns
the same event; a new intentional withdrawal uses a new request ID.

Distinct concurrent valid grants must retain distinct attribution. Return the
complete applicable authority set, sorted only for presentation. Never present
the first historical retirement row as the author of a later grant.

## 3. Rejoin and new knowledge

The old grant describes a permanent-loss episode, not all future knowledge that
certificate might acquire. Positive evidence of rejoin invalidates that episode
durably. While persistence of the invalidation is failing, the observing node
must withhold rather than fall back to the old grant.

Record activity before a restarted/rejoined daemon is allowed to perform
trust-sensitive work. Proof responders must identify their incarnation, and
positive responses that contradict retirement must not be discarded because a
cached health signal says the host is offline. Passive observations can also
invalidate; uncertainty cannot create or restore a grant.

On a later permanent loss, the operator supplies a new accounting acknowledging
that activity/invalidation. The old manifest's discoveries stay in the union.
Certificate replacement separately makes old-incarnation grants inapplicable;
neither replacement nor a subsequent loss authorizes use of the predecessor's
grant. Withdrawal of historical or already-inapplicable grants stays allowed.

## 4. One resolver and explicit dependencies

Have one resolver return `machine_proven`, `attested`, `owed`, or `indeterminate`,
with exact grant IDs, accounting hashes, incarnation, and invalidation frontier.
Each consumer asks for its own premise. Listing and health render this result;
they do not independently reconstruct applicability.

Successful binding activation records an immutable authorization certificate:

- Binding generation, cluster fingerprint, prefix ID, CIDR, and VRF.
- Corroborated participant/incarnation set and relevant inventory-table digests.
- Exact membership **and** inventory grants used to justify the proof.
- Their accounting hashes and invalidation context.
- Adoption completion evidence, including the address-bearing table coverage.

Membership is a binding dependency too: it establishes whose inventory had to be
accounted for. Do not only track the grant used at the final inventory comparison.

The activation certificate must be complete before any allocator can use it.
A binding row arriving before its certificate is suspended/indeterminate, not
an implicitly grandfathered live binding. Build dependencies in the production
proof path, not by scanning whatever grants happen to exist when bind completes.

When any pinned grant is invalidated, the certificate is invalid. A fresh grant
does not rewrite old dependency edges. Re-proving and re-adopting yields a new
certificate. Grants not used by a binding do not suspend it; where provenance is
missing, conservatively require revalidation rather than guess it was independent.

Topology/admission and newly discovered incumbent inventory must also invalidate
or replace affected proof certificates before new allocation. An ordinary peer
outage alone is not proof that a previously completed adoption never happened.
Keep those facts distinct from a positively invalidated accounting dependency.

## 5. Effective binding state and operation admission

Make effective readiness a conjunction, not a writable Boolean:

```text
ready = binding_configuration_valid
        AND adoption_complete
        AND authorization_certificate_complete_and_valid
        AND no_other_suspension_reason
```

Keep suspension reasons separately: trust withdrawn, trust indeterminate,
inventory uncorroborated, adoption incomplete, prefix/VRF drift, identity re-key,
and explicit operator suspension. The persisted status is a projection for
visibility; writing `suspended=false` cannot override invalid dependencies.

Revalidation detects and reports invalidated certificates promptly, but is not
the enforcement boundary. Every new bound-address operation checks effective
authorization immediately before entering the NetBox claim path. A cached
allocator obtained before withdrawal must not bypass that check.

Use a shared scoped admission/invalidation mechanism for claims, bind activation,
resume, re-key completion, adoption, and reclamation. On each executor, applying
an invalidation and admitting a dependent operation must be serialized. The same
rule must apply when the event arrives by replication, not only through the RPC.
Do not hold a SQLite transaction across network calls.

An operation records the authorization certificate/frontier it was admitted
under. Withdrawal closes new admission; it does not imply already-admitted
network calls never happened. Track those calls through definite completion or
an explicit unknown outcome. A second pre-use read alone is not an atomic
check-and-act protocol.

Address treatment:

- Existing guest claims, local owner tuples, and NetBox objects remain intact.
- A POST committed during invalidation is a reserved/in-flight outcome, not an
  excuse to issue another address or automatically free this one. If it has not
  been handed to a guest, retain it as reserved-but-unissued pending safe recovery.
- A timeout remains unknown. A zero-result lookup does not prove non-commit.
- Finding an old NetBox object by identity does not authorize assigning it to a
  new guest under withdrawn trust. Genuine idempotent recovery must establish
  the existing exact owner/NIC operation, not merely find a matching remote row.
- Normal owner-scoped cleanup may continue where its independent release proof
  holds. Withdrawal itself must never trigger cleanup or blanket claim deletion.

Cover VM create, compose, additional NICs, hotplug, discovery/import, retries,
failover paths that allocate, and every direct allocator construction. Preserve
unbound-VM no-allocation behavior and the existing bound-container refusal.

## 6. Distributed completion: explicit, not implied

The current store has local transactions and asynchronous replicated state. Its
leader row and a local read-back are not a linearizable revocation service.
The following two statuses must not be conflated:

1. **Recorded locally:** the event is durable here and this executor has closed
   dependent admission. Broadcast promptly; do not wait for a maintenance tick.
2. **Enforced across the accounted executor set:** each executor that can perform
   a dependent operation has durably acknowledged the invalidation and closed
   old admission. Outstanding already-admitted/unknown operations are listed.

Return event ID, reporting node/incarnation, acknowledged executors, outstanding
executors, unknown membership, and in-flight outcomes. If completeness cannot be
established, report pending/indeterminate, never global success. A read error is
not an empty executor list. Certificate/role changes invalidate stale acknowledgments.

Completing the stronger status requires a real admission barrier, not merely
"the row replicated":

1. Close local admission atomically with accepting the invalidation.
2. Determine the full executor universe, including tombstoned/offline machines
   and any node allowed to become a NetBox writer; roles or `ListHosts` filtering
   cannot silently remove one. Membership accounting and runtime exclusion are
   still different premises.
3. Send the event to every executor. Its acknowledgment certifies durable receipt,
   closed admission, and the state of its old in-flight operations.
4. Revalidate the universe before declaring enforcement complete. Newly admitted
   or restarted executors cannot issue mutations until they synchronize the
   relevant trust state and admission barriers. Stale binding status or a cached
   allocator is insufficient bootstrap authority.
5. Do not excuse an unreachable possible writer on a power-off claim unless the
   exclusion also prevents it from re-entering as a writer without the bootstrap
   synchronization. Do not use fencing as evidence of its missing knowledge.

A withdrawn membership grant may make the executor universe unprovable. That
means the withdrawal is recorded but cluster enforcement is indeterminate; do
not reuse that very grant to certify completion. Corrected independent accounting
can restore provability. This is an explicit boundary, not a silent bypass.

During propagation a node that has not learned a withdrawal can still act on its
old view. The above contract does not claim otherwise. If the requirement is
instead "from the instant any node accepts the request, no other node may admit
an operation", this design must use a linearizable authorization authority or a
distributed read/use barrier on **every** affected operation. The current local
lease/LWW implementation cannot provide that guarantee. Treat that requirement
as an architectural expansion, not an extra read inside the sweeper.

Recommended PR contract: explicit recorded-versus-enforced semantics, immediate
local inhibition, and no claim of global effectiveness until the barrier above
is established. Availability while propagation is pending must be documented;
operators requiring instantaneous global inhibition need the stronger authority.

## 7. Reclamation and recovery

The sweeper still needs closed membership, complete negative runtime/DB evidence,
fresh independent power-off exclusions, stable samples, leader revalidation, and
an unchanged remote object. An inventory grant does not become power-off evidence.

Include the exact membership authority/frontier in the proof certificate, not
only the final hostname set. A grant change can leave the runtime hostname set
identical while invalidating the reasoning. Integrate the final deletion with
operation admission: invalidation before admission aborts it; a deletion already
admitted is reported as in flight, not retrospectively asserted never to occur.

To recover a trust-invalidated live binding:

1. Recover actual membership/inventory, or explicitly re-attest with corrected
   accounting acknowledging the current invalidation frontier.
2. Run administrative `resume` in preview/prove mode, naming all missing premises,
   discoveries, conflicts, and outstanding adoptions.
3. Re-run prefix/VRF validation, closed membership, inventory corroboration, and
   adoption. Retain existing reservations; refuse conflicting incumbent addresses.
4. Publish a new complete activation certificate only if the reviewed trust context
   and binding generation still match. Otherwise keep it suspended and report why.

Re-key, automatic unhydrated-binding completion, repair, and retries must use this
same activation validator. None may clear a trust suspension because its own
unrelated repair succeeded. Previously-live trust-invalidated bindings require
explicit resume; never-live bindings can complete automatically only while their
entire current proof remains valid.

If accounting names a host whose incarnation cannot be established, require
independent identity recovery; do not invent an incarnation, match a wildcard,
or let a correction delete discovered potential holders. With no evidence and
no truthful accounting, withholding is the intended residual limitation.

## 8. RBAC, audit, and health

Introduce a scoped permission such as `netbox.retirement.withdraw` on the cluster
resource. Grant it to cluster-wide operators and administrators, not viewers or
project-only operators. Require an attributable actor and a reason. No evidence
check is needed to remove trust; the remaining risk is cluster-wide availability.
Grant/re-attest and resume remain administrative trust-increasing operations.

Expose exact active grant IDs, authors, accounting, invalidations, and the binding
generations/operations depending on them. Separate history from current authority.
For withdrawal, show recorded versus enforced versus pending/indeterminate, never
infer "someone attested later" merely because an unfamiliar manifest exists.

Keep an in-force-attestation condition at non-paging `info`; keep failed validation
and incomplete enforcement separately visible as warnings. Info not degrading the
roll-up is a reasonable general policy. The advisory must not itself authorize,
revoke, resume, or gate operations. Clearing/acknowledging it changes no trust state.

## 9. Implementation order and acceptance boundary

1. Freeze these semantics and the recorded/enforced consistency contract.
2. Add immutable complete grant/invalidation events and a pure resolver. Test
   permutations of delivery, duplicates, partial replication, payload conflicts,
   and clock skew. Add schema, statement-shape, sync-table, merge, and capability
   coverage; schema-neutrality is not a reason to retain the wrong data model.
3. Wire writes, idempotency, causal re-attestation, durable activity invalidation,
   and exact attribution. A partial multi-premise request reports which independent
   premises committed, or is atomic; it must not ambiguously imply all-or-nothing.
4. Add activation certificates and dependency-aware readiness. Wire every claiming
   and activation path before relying on the new status projection.
5. Add admission/invalidation coordination, replication application handling,
   propagation acknowledgments, bootstrap gates, and pending-operation reporting.
6. Wire manual recovery and all resume/re-key/repair paths through one validator.
7. Derive CLI, audit, and health from the same resolver and enforcement state.
8. Migrate old bindings/grants fail-closed. Do not infer empty dependency sets for
   legacy live bindings. Require re-proving/re-adoption. For existing withdrawal
   history without causal context, require explicit new attestation rather than
   infer ordering from timestamps. Keep claims untouched during migration.

All participating executors must support the enforcement protocol before trust
recovery is enabled. Test the capability boundary against older binaries; a new
table alone does not prevent an older allocator from ignoring the new gate.
Do not silently downgrade enforcement on rollback.

Mandatory acceptance matrix, in addition to preserving the existing tests:

| Area | Required contrast |
| --- | --- |
| Causality | Withdraw vs concurrent grant in both delivery orders; late historical grant; deliberate acknowledged correction; another concurrent withdrawal; duplicate RPC retry |
| Completeness | Grant before accounting; accounting without grant; failed grant commit; conflicting payload under one ID; missing frontier reference |
| Incarnation/activity | Replacement under same hostname; same-incarnation rejoin learns another host/lease then disappears; withdrawal of historical and inapplicable grants |
| Live bindings | Bind on attested inventory, withdraw, refuse allocation before the periodic pass; pass reports suspension; existing claims unchanged |
| Dependencies | Membership-only withdrawal invalidates bindings that relied on it; unrelated bindings remain usable; missing certificate refuses |
| Claims | Cached allocator; withdrawal during POST; delayed/unknown response; recovered object belonging to existing operation versus proposed new owner |
| Enforcement | Withdrawal on node A, mutation on B; held-back replication; B restarts; an executor vanishes; new executor admission; incomplete closure cannot yield global success |
| Proof races | Change authority with identical hostname sets; withdraw after sample B and during final object lookup; correctly distinguish pre-admission abort from already-admitted work |
| Recovery | Corrected grant alone does not resume; explicit resume re-adopts; drift also present; concurrent withdrawal during resume/re-key/automatic completion |
| Surfaces | Active attribution is the actual new grant; unknown is not inactive; pending is not enforced; clearing health changes no permission |
| RBAC | Cluster operator can withdraw but cannot attest/resume; project operator and viewer cannot withdraw cluster trust; denied actions audited |
| Upgrade/repair | Legacy live binding; mixed versions; reordered incremental/full-state repair; event replay after restart/restore; no invalidation lost to GC |

Use real production resolver/decoder/applier paths and controlled schedules.
Property tests should verify that merging an unacknowledged invalidation cannot
increase authority, and that delivery order cannot change the converged verdict.
Named mutations complement those properties; they do not replace them.

No implementation can promise literal absence of gaps from a prose review. The
merge criterion is that this explicit contract is implemented and its boundary
cases exercised, rather than another set of locally plausible conditions passing
tests that assume the disputed semantics.
