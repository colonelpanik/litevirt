package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// orphanGrace guards an in-flight create from being swept out from under it. It
// is a NECESSARY condition, never a sufficient one — age is not evidence a guest
// is gone.
const orphanGrace = 30 * time.Minute

// netBoxLeaseKey elects the single node allowed to reclaim. Two sweepers
// racing would each collect a proof valid at its own instant and both act on
// it; the lease makes "the cluster's answer" a single writer's answer.
const netBoxLeaseKey = "netbox"

// orphanProofTimeout bounds ONE peer's proof RPC so a single hung host cannot
// stretch a pass past the lease TTL. A timeout is an UNREACHABLE host, which
// aborts the reclamation — the fail-closed direction.
const orphanProofTimeout = 5 * time.Second

// orphanProofWorkers bounds the proof fan-out.
const orphanProofWorkers = 4

// orphanQueueBatch is how many sync-queue items one pass drains.
const orphanQueueBatch = 100

// orphanQueueKind is the netbox_sync_queue kind this sweeper owns. The queue is
// shared with the inventory mirror, and each consumer drains ONLY its own kind
// (see corrosion.DrainSyncQueue).
const orphanQueueKind = "orphan"

// orphanCheckMaxAttempts bounds how many passes ONE queued orphan check may
// fail before the sweeper gives up on it. Without a bound, an item whose lookup
// can never succeed — an identity whose prefix is no longer bound, a NetBox that
// answers 500 for it forever — is retried on every pass for the life of the
// cluster and the queue never drains. Giving up is logged at ERROR, never
// silently: the address it names becomes an operator's problem.
const orphanCheckMaxAttempts = 10

// netboxFenceWindow bounds how long an operator's `lv host fence-confirm`
// attestation counts as power-off evidence FOR THIS SWEEPER.
//
// It is deliberately NOT vipManualFenceWindow (5 minutes). Reachability is the
// PRIMARY safety here: hasFreshPowerOffProof consults the live signal first, so
// a host that has rejoined is never excluded from a proof, whatever the fencing
// log says. The window therefore only bounds how long an UNREACHABLE host's
// attestation keeps counting — and it must EXCEED the sweep cadence
// (netbox.sweep_interval_sec, defaultNetBoxSweepInterval when unset), or an
// operator's confirmation expires before the next sweep can honour it: after a
// permanent host loss the sweeper would then be inert forever, with no
// practical escape.
const netboxFenceWindow = 24 * time.Hour

// ── skip reasons ────────────────────────────────────────────────────────────

// skipError carries a BOUNDED metric label alongside the full human-readable
// reason. The reason text names an address and a host, so it belongs in a log
// line, never in a metric label.
type skipError struct {
	reason string
	msg    string
}

func (e *skipError) Error() string { return e.msg }

func skipf(reason, format string, args ...any) error {
	return &skipError{reason: reason, msg: fmt.Sprintf(format, args...)}
}

// skipReason extracts the bounded label, defaulting to "error" for anything
// that did not come from skipf.
func skipReason(err error) string {
	var se *skipError
	if errors.As(err, &se) {
		return se.reason
	}
	return "error"
}

// The bounded set of skip labels.
const (
	skipHostsRead            = "hosts_read"
	skipNoHosts              = "no_eligible_hosts"
	skipUnreachable          = "host_unreachable"
	skipNoProof              = "host_returned_no_proof"
	skipIncomplete           = "incomplete_proof"
	skipHostHolds            = "host_still_claims"
	skipProofCount           = "proof_count_mismatch"
	skipMembership           = "membership_changed"
	skipMembershipUnproven   = "membership_unproven"
	skipLeaseLost            = "leader_lease_lost"
	skipRemoteReread         = "netbox_reread_failed"
	skipObjectChanged        = "netbox_object_changed"
	skipReleaseFailed        = "release_failed"
	skipIdentityUnresolvable = "identity_unresolvable"
)

// ── the sweep ───────────────────────────────────────────────────────────────

// SweepOrphansOnce runs exactly one sweep pass. It exists so a test can drive
// the sweeper deterministically instead of waiting on a ticker; the daemon runs
// the same pass on an interval.
func (s *Server) SweepOrphansOnce(ctx context.Context) error {
	return s.sweepOrphans(ctx, defaultNetBoxSweepInterval)
}

// sweepOrphans reclaims NetBox addresses nothing claims any more.
//
// Reclamation requires a STABLE COMPLETE-CLUSTER proof:
//
//  1. Read the eligible host set A, CLOSED under peer membership — every
//     participant is asked which hosts it knows until the set stops growing.
//  2. Gather complete negative proofs from exactly A.
//  3. Read the eligible host set B, through the same closure.
//  4. Proceed only if A == B, every member answered completely, and the leader
//     lease is still valid.
//  5. Re-read the NetBox object and require it to still match.
//
// Any deviation aborts and leaves the address allocated. Leaking an address the
// next sweep can reclaim is always preferable to freeing one a live guest uses.
func (s *Server) sweepOrphans(ctx context.Context, interval time.Duration) error {
	if s.db == nil || s.netbox == nil {
		return nil // nothing to sweep against
	}
	// The lease TTL is derived from the cadence the CALLER actually runs at, so
	// a cluster that configured a slower sweep does not hand leadership away
	// between its own passes.
	if !s.acquireNetBoxLease(ctx, interval) {
		return nil
	}

	// Arms this pass's skip record, which the health evaluator below folds into
	// the consecutive-blocked-pass streak.
	s.beginSweepPass()

	// The queue is a latency optimisation over the full pass below, and it is
	// also where a failed compensation reports a STUCK lease. Drained first so
	// an operator learns about a stuck lease on the same pass.
	s.drainOrphanChecks(ctx)

	candidates, err := s.orphanCandidates(ctx, orphanGrace)
	if err != nil {
		// The pass never ran, so it is neither a blocked pass nor a clean one:
		// closing the streak here would let a failing candidate read silently
		// clear a standing "the sweep is stuck" finding.
		return fmt.Errorf("list orphan candidates: %w", err)
	}
	for _, cand := range candidates {
		if err := s.reclaimIfProven(ctx, cand); err != nil {
			slog.Warn("netbox sweep: reclamation aborted",
				"address", cand.Address, "identity", cand.Identity, "reason", err)
			s.noteSweepSkip(skipReason(err))
		}
	}
	// Findings last: they describe the pass that just finished.
	s.evaluateNetBoxHealth(ctx, s.closeSweepPass())
	return nil
}

// reclaimIfProven is the ONLY path that deletes a NetBox object.
//
// Every early return leaves the address allocated. There is deliberately no
// "best effort" branch and no partial-evidence branch: a negative proof that is
// not whole is not a proof.
func (s *Server) reclaimIfProven(ctx context.Context, cand orphanCandidate) error {
	// 1. Sample A — from closedParticipantSet: the replicated `hosts` table
	//    UNIONED WITH GOSSIP MEMBERSHIP, then CLOSED under what every reachable
	//    participant says its own membership is.
	//
	//    Neither half is a refinement; each is the difference between a proof
	//    and a coin flip. Built from the `hosts` table alone, a peer whose row
	//    had not hydrated on this node was absent from BOTH samples, so the
	//    samples agreed and the five steps below concluded that nobody held the
	//    address — while that peer's guest still had it on a defined domain. Two
	//    samples establish STABILITY, not COMPLETENESS. And built from the local
	//    union alone it was still only the set of hosts this node happens to
	//    have heard of: a host in neither source is invisible to both samples,
	//    so the closure asks the peers by name instead of comparing sizes.
	setA, unclosed, err := s.closedParticipantSet(ctx)
	if err != nil {
		return skipf(skipHostsRead, "read eligible hosts: %v", err)
	}
	if unclosed != "" {
		return skipf(skipMembershipUnproven, "participant set could not be closed: %s", unclosed)
	}
	if len(setA) == 0 {
		// Nobody to ask. An empty universe would make every proof vacuously
		// complete, which is the one shape that must never authorize a delete.
		return skipf(skipNoHosts, "no eligible hosts to prove absence")
	}

	// 1b. …and the membership view itself has to be corroborated, because the
	//     union is still not a completeness proof: a host in NEITHER the
	//     replicated table nor gossip is invisible to both, and an invisible host
	//     is exactly the one whose guest is about to lose its address. So every
	//     participant is asked how many `hosts` rows IT holds, and a peer that
	//     holds more than this node does says this node's view of the cluster is
	//     short — by at least one host it therefore never asked.
	if reason, cerr := s.membershipViewUncorroborated(ctx, setA); cerr != nil {
		return skipf(skipHostsRead, "read this node's own host digest: %v", cerr)
	} else if reason != "" {
		return skipf(skipMembershipUnproven, "membership view not corroborated: %s", reason)
	}

	// 2. Collect from exactly A, and require EXACTLY ONE response per member,
	//    keyed by hostname. An empty `unreachable` set is not sufficient: a host
	//    that silently returns nothing would otherwise be skipped, and its
	//    silence read as absence.
	proofs, unreachable := s.gatherOrphanProofs(ctx, setA, cand)
	if s.onProofsGathered != nil {
		s.onProofsGathered(proofs)
	}
	if len(unreachable) > 0 {
		return skipf(skipUnreachable, "hosts unreachable: %v", unreachable)
	}
	for _, host := range setA {
		p, ok := proofs[host]
		if !ok {
			return skipf(skipNoProof, "host %s returned no proof", host)
		}
		if !p.Complete {
			return skipf(skipIncomplete, "host %s returned an incomplete scan: %v", host, p.Errors)
		}
		if p.Holds() {
			return skipf(skipHostHolds, "host %s still claims the address", host)
		}
	}
	if len(proofs) != len(setA) {
		// A proof keyed by a host NOT in A — the fan-out answered a question
		// nobody asked, so the mapping cannot be trusted at all.
		return skipf(skipProofCount, "got %d proofs for %d hosts", len(proofs), len(setA))
	}

	if s.onProofCollected != nil {
		s.onProofCollected()
	}

	// 3. Sample B, through the same closure as A — a set read two different ways
	//    would compare two different questions and could never be equal.
	setB, unclosed, err := s.closedParticipantSet(ctx)
	if err != nil {
		return skipf(skipHostsRead, "re-read eligible hosts: %v", err)
	}
	if unclosed != "" {
		return skipf(skipMembershipUnproven,
			"participant set could not be closed on the second sample: %s", unclosed)
	}
	// 4. A == B, and the lease still ours. A host that joined DURING collection
	//    was never asked, so the proof does not cover the cluster it claims to.
	if !sameHostSet(setA, setB) {
		return skipf(skipMembership, "membership changed during proof collection (%v -> %v)", setA, setB)
	}
	if !s.holdsLeaderLease(ctx) {
		return skipf(skipLeaseLost, "leader lease lost during proof collection")
	}

	// 5. Time-of-check to time-of-use. The proof was about an OBJECT, not about
	//    an id: if the object behind the id changed at all — a different
	//    identity, a different address, a new assignment — the proof describes
	//    something that no longer exists.
	live, err := s.netbox.LookupByIdentity(ctx, cand.Identity, cand.VRFID, cand.PrefixCIDR)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		return skipf(skipRemoteReread, "re-read NetBox object: %v", err)
	}
	if len(live) != 1 ||
		live[0].ID != cand.NetBoxID ||
		live[0].Identity != cand.Identity ||
		live[0].Address != cand.NetBoxAddress ||
		live[0].AssignedObjectID != cand.AssignedObjectID {
		return skipf(skipObjectChanged, "NetBox object changed between proof and delete")
	}

	// Revalidated immediately before the destructive call, not merely before the
	// re-read: the re-read is a network round trip, and a lease can expire
	// inside it.
	if !s.holdsLeaderLease(ctx) {
		return skipf(skipLeaseLost, "leader lease lost immediately before delete")
	}
	if err := s.netbox.ReleaseIP(ctx, cand.NetBoxID); err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		return skipf(skipReleaseFailed, "release: %v", err)
	}
	slog.Info("netbox sweep: reclaimed an orphaned address",
		"address", cand.Address, "identity", cand.Identity, "netbox_id", cand.NetBoxID)
	s.nbMetrics().IncOrphansReclaimed()
	return nil
}

// ── corroborating the membership view ───────────────────────────────────────

// membershipViewUncorroborated asks every participant how many `hosts` rows it
// holds and reports the first one that holds MORE than this node does.
//
// IT IS NOT THE COMPLETENESS PROOF, and a round of this review was spent
// learning why it cannot be: equal counts over DIFFERENT members compare as
// agreement. A sweeper that knew a local-only witness while its peer knew a
// third workload host passed this check with both samples stable, never asked
// that host, and freed the address its defined domain held. What establishes
// completeness is closedParticipantSet, which asks each participant WHICH hosts
// it knows and folds the answers in until the set stops growing — identities,
// not cardinality.
//
// WHAT THIS STILL BUYS, and why it stays: the closure learns members from
// ListHosts, which filters `WHERE deleted_at IS NULL`. A host row that is
// TOMBSTONED on a peer and absent here is therefore invisible to the closure —
// and `lv host rm --force` does not power a machine off, so that host may still
// be running the domain. The `hosts` DIGEST counts tombstones, so a peer holding
// one more row than this node still stops the reclamation. Two questions, both
// necessary: "who else exists" and "does anybody hold a row I have never seen".
//
// It returns the operator-facing reason a view is not corroborated, or "" when
// it is. An error is returned only for the failure that is about THIS node — an
// unreadable local digest — because that is the one a caller must report
// differently: everything else is part of the answer, and a participant that
// cannot be asked leaves the view unproven exactly as a participant holding more
// rows does.
//
// WHY A COUNT AND NOT THE FULL DIGEST. The corroboration the NetBox bind makes
// over its address-bearing tables compares content hashes as well, and this
// deliberately does not. `hosts` rows carry per-node timestamps and a per-node
// `version` / `schema_version`, so two nodes agree on the CONTENT of that table
// only when they are converged AND on the same build — during any rolling
// upgrade they are not, and a hash comparison would make the sweeper permanently
// inert for the length of one. A count is monotone under replication and answers
// the narrow question left to it: does somebody hold a host row I have never
// seen, tombstones included?
//
// The asymmetry is deliberate in the other direction too: a peer holding FEWER
// host rows is a peer that is behind, which cannot be the reason THIS node's set
// is short — and the members it does know are asked for by name by the closure
// regardless, so nothing rests on that reading any more.
//
// FAIL CLOSED at every branch, and the cost of doing so is one skipped sweep:
// the address stays allocated and the next pass tries again. Leaking an address
// the next sweep can reclaim is always preferable to freeing one a live guest
// uses.
func (s *Server) membershipViewUncorroborated(ctx context.Context, participants []string) (string, error) {
	local, err := s.localTableDigest(ctx, hostsTableName)
	if err != nil {
		return "", err
	}
	var peers []string
	for _, h := range participants {
		if h != s.hostName {
			peers = append(peers, h)
		}
	}
	if len(peers) == 0 {
		// A single-node cluster's view of its own membership IS the cluster's.
		return "", nil
	}
	for _, a := range s.gatherTableDigests(ctx, peers, []string{hostsTableName}) {
		remote, found := a.digests[hostsTableName]
		switch {
		case a.err != nil:
			return fmt.Sprintf("host %s could not be asked (%v)", a.host, a.err), nil
		case !found:
			// An older peer, or one whose digest set does not carry the table.
			// Silence about `hosts` is not agreement about the cluster's shape.
			return fmt.Sprintf("host %s reported no %s digest", a.host, hostsTableName), nil
		case int(remote.GetCount()) > local.Count:
			return fmt.Sprintf(
				"host %s knows %d %s row(s) to this node's %d, so this node cannot have asked every host",
				a.host, remote.GetCount(), hostsTableName, local.Count), nil
		}
	}
	return "", nil
}

// ── the participant universe ────────────────────────────────────────────────

// proofParticipants is the LOCAL sample of the participant universe: everything
// this node can name without asking anybody. Both cross-cluster proofs in this
// package — the orphan sweeper's negative proof and the bind's inventory
// corroboration — build on it through closedParticipantSet, which asks each of
// these participants what ITS membership is and folds the answers back in until
// the set stops growing. Nothing calls this directly to authorize anything: the
// set of hosts this node happens to have heard of is not the cluster.
//
// ONE helper, not one per proof. There were two, and they differed in exactly
// the way that mattered: the bind's unioned GOSSIP MEMBERSHIP into the
// replicated `hosts` table and the sweeper's did not. So the sweeper built its
// whole universe from the replicated table, a peer whose row had not hydrated on
// this node was absent from BOTH of its samples, the samples agreed — they
// establish stability, not completeness — and it deleted an address that peer's
// guest still held.
//
// THE CANDIDATE SET is the `hosts` table unioned with gossip membership.
//
// It CANNOT reuse the existing helpers: dualRunProbeTargets has the right
// universe but reads from ListHosts, and ListHosts filters WHERE deleted_at IS
// NULL — so it cannot see the tombstoned hosts that may still be running QEMU.
// Gossip is unioned in because the replicated table is CRDT state and can simply
// be missing a peer: memberlist converges in seconds, independently of every
// table, so a host it names is a host that exists whatever the database says.
// corrosion's peer resolver already falls back to the membership address for a
// host whose row has not replicated, so a gossip-only peer is dialable.
//
// THE FILTERS then apply to every candidate identically, whichever source named
// it — a union that skipped them would UNDO them, which is worse than not having
// them: a host excluded by an operator's power-off attestation would be silently
// re-added by gossip, and after a permanent host loss the sweeper would be inert
// forever with no escape.
//
//   - A WITNESS is excluded: it votes and never hosts workloads. Only the
//     `hosts` table carries a role, so a gossip-only candidate has none — and an
//     unknown role is not a statement that it is a witness, so it stays in.
//   - A host is otherwise excluded ONLY with fresh, specific, proof-grade
//     power-off evidence and no sign of a later rejoin. It is NOT excluded
//     because its row vanished or because its state reads offline: an
//     offline-looking host can still be running the domain, and dropping it
//     would manufacture exactly the absence being proven.
//
// This node is always in the set. Its own row could be missing or tombstoned
// while it is demonstrably running — it is executing this code — and a proof
// that omitted the leader would be the easiest possible way to miss a claimant.
func (s *Server) proofParticipants(ctx context.Context) ([]string, error) {
	candidates, err := s.localParticipantCandidates(ctx)
	if err != nil {
		return nil, err
	}
	return s.eligibleParticipants(ctx, candidates)
}

// participantCandidate is one host some source named, plus the only property
// that can exclude it on sight. witness is false for a candidate learned from
// anywhere but the local `hosts` table, because nothing else records a role —
// and an unknown role is not a statement that a host is a witness.
type participantCandidate struct {
	name    string
	witness bool
}

// localParticipantCandidates is the candidate set this node can name WITHOUT
// asking anybody: the replicated `hosts` table unioned with gossip membership.
func (s *Server) localParticipantCandidates(ctx context.Context) ([]participantCandidate, error) {
	// No deleted_at filter, deliberately: a decommissioned row does not power a
	// machine off, and RemoveHost --force does not even check for workloads.
	rows, err := s.db.Query(ctx, `SELECT name, COALESCE(role, '') AS role FROM hosts`)
	if err != nil {
		return nil, err
	}
	var candidates []participantCandidate
	named := map[string]bool{}
	for _, r := range rows {
		name := r.String("name")
		if name == "" || named[name] {
			continue
		}
		named[name] = true
		candidates = append(candidates, participantCandidate{
			name: name, witness: r.String("role") == "witness"})
	}
	for _, m := range s.db.Members() {
		if m.Name == "" || named[m.Name] {
			continue
		}
		named[m.Name] = true
		// No role: nothing but the `hosts` table records one, and this host's
		// row is precisely what has not arrived.
		candidates = append(candidates, participantCandidate{name: m.Name})
	}
	return candidates, nil
}

// eligibleParticipants applies the exclusions to a candidate set and returns the
// sorted participant list.
//
// ONE filter, whichever source named a candidate — the local table, gossip, or a
// peer's membership view. A union that skipped it for the newest source would
// UNDO it, which is worse than not having it: a host excluded by an operator's
// power-off attestation would be silently re-added, and after a permanent host
// loss the sweeper would be inert forever with no escape.
func (s *Server) eligibleParticipants(ctx context.Context, candidates []participantCandidate) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, c := range candidates {
		if c.name != s.hostName {
			if c.witness {
				continue // a witness votes and never hosts workloads
			}
			excluded, err := s.hasFreshPowerOffProof(ctx, c.name)
			if err != nil {
				// An unreadable fencing_log is not permission to exclude.
				return nil, fmt.Errorf("read fence evidence for %s: %w", c.name, err)
			}
			if excluded {
				continue
			}
		}
		seen[c.name] = true
		out = append(out, c.name)
	}
	if !seen[s.hostName] && s.hostName != "" {
		out = append(out, s.hostName)
	}
	sort.Strings(out)
	return out, nil
}

// hostSetClosureRounds bounds the participant-set fixpoint.
//
// The loop terminates on its own — every round asks strictly more hosts and the
// cluster is finite — so this exists only so a pathology cannot spin: a set that
// keeps growing because peers keep naming hosts that name further hosts. Eight
// rounds is far past any real topology (one round closes a converged cluster,
// two closes a node that learned its whole membership second-hand), and running
// out is a REFUSAL, not a truncation: an unclosed set proves nothing.
const hostSetClosureRounds = 8

// closedParticipantSet is proofParticipants CLOSED UNDER PEER MEMBERSHIP: every
// participant is asked which hosts IT knows, the answers are folded back in
// under the same exclusions, and the fan-out repeats until the set stops
// growing.
//
// WHY THE LOCAL UNION IS NOT ENOUGH, which is the third round of this same
// lesson. The candidate set this node can build alone — `hosts` plus gossip — is
// exactly the set of hosts this node happens to have heard of. A host in neither
// source is invisible to both samples of the five-step proof, both samples
// therefore agree, and stability gets mistaken for completeness. Comparing
// `hosts` ROW COUNTS with each peer does not fix it either: equal counts over
// different members compare as agreement, so a sweeper that knew a local-only
// witness while its peer knew a third workload host asked neither about the
// address and freed it.
//
// The answer is not a stricter comparison of this node's set, it is A DIFFERENT
// QUESTION — asked of the peers, about identities: WHICH hosts do you know? Any
// holder that any reachable node knows about is then queried by name, whether or
// not this node's own `hosts` table ever hydrated its row.
//
// It rides ListHosts, an RPC that already exists and that a peer's host cert
// already authorizes (a bearerless trusted host CN authenticates as admin, and
// ListHosts asks for viewer) — so nothing new goes on the wire and no proto
// changes. What ListHosts cannot show is a TOMBSTONED row, because it filters
// `deleted_at IS NULL`; membershipViewUncorroborated covers that residue with
// the `hosts` digest count, which does count tombstones.
//
// FAIL CLOSED on both edges, the same direction the per-host proof already takes
// for an unreachable host. A participant that cannot answer, and one that
// answers with no membership view at all, both leave the set unclosable — and an
// unclosed set cannot support "nobody holds this address". The reason is
// returned rather than an error, because it is part of the ANSWER: nothing about
// THIS node failed.
func (s *Server) closedParticipantSet(ctx context.Context) ([]string, string, error) {
	candidates, err := s.localParticipantCandidates(ctx)
	if err != nil {
		return nil, "", err
	}
	named := map[string]bool{}
	for _, c := range candidates {
		named[c.name] = true
	}
	// This node answers for itself from its own database; it is never dialled.
	asked := map[string]bool{s.hostName: true}

	for round := 0; round < hostSetClosureRounds; round++ {
		set, eerr := s.eligibleParticipants(ctx, candidates)
		if eerr != nil {
			return nil, "", eerr
		}
		var unasked []string
		for _, h := range set {
			if !asked[h] {
				unasked = append(unasked, h)
			}
		}
		if len(unasked) == 0 {
			// Closed: every eligible participant has told us what it knows, and
			// nothing any of them named is outside the set.
			return set, "", nil
		}
		for _, v := range s.gatherHostViews(ctx, unasked) {
			asked[v.host] = true
			if v.err != nil {
				return nil, fmt.Sprintf(
					"host %s could not be asked which hosts it knows (%v)", v.host, v.err), nil
			}
			if len(v.hosts) == 0 {
				// A node knows at least itself, so an empty answer is a node
				// whose own `hosts` table has not hydrated — a view, not the
				// statement that the cluster is empty.
				return nil, fmt.Sprintf(
					"host %s answered without a membership view", v.host), nil
			}
			for _, name := range v.hosts {
				if name == "" || named[name] {
					continue
				}
				named[name] = true
				// No role on the wire (pb.Host carries none), so a peer-learned
				// host is treated exactly as a gossip-learned one: unknown role,
				// and unknown is not "witness".
				candidates = append(candidates, participantCandidate{name: name})
			}
		}
	}
	return nil, fmt.Sprintf(
		"the participant set was still growing after %d rounds of peer membership",
		hostSetClosureRounds), nil
}

// hostView is one participant's answer to "which hosts do you know".
type hostView struct {
	host  string
	hosts []string
	err   error
}

// gatherHostViews asks each peer for its host list over the bounded worker pool
// and per-peer timeout the rest of the proof fan-out already uses.
func (s *Server) gatherHostViews(ctx context.Context, peers []string) []hostView {
	views := make([]hostView, len(peers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, orphanProofWorkers)
	for i, h := range peers {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			views[i] = hostView{host: h}
			pctx, cancel := context.WithTimeout(ctx, orphanProofTimeout)
			defer cancel()
			client, closeConn, derr := s.dialPeer(pctx, h)
			if derr != nil {
				views[i].err = derr
				return
			}
			resp, rerr := client.ListHosts(pctx, &pb.ListHostsRequest{})
			closeConn()
			if rerr != nil {
				views[i].err = rerr
				return
			}
			for _, host := range resp.GetHosts() {
				if host.GetName() != "" {
					views[i].hosts = append(views[i].hosts, host.GetName())
				}
			}
		}(i, h)
	}
	wg.Wait()
	return views
}

// closedProofPeers is closedParticipantSet without this node — the hosts that
// have to be ASKED, as opposed to the one this node answers for itself.
func (s *Server) closedProofPeers(ctx context.Context) ([]string, string, error) {
	hosts, unclosed, err := s.closedParticipantSet(ctx)
	if err != nil || unclosed != "" {
		return nil, unclosed, err
	}
	var peers []string
	for _, h := range hosts {
		if h != s.hostName {
			peers = append(peers, h)
		}
	}
	return peers, "", nil
}

// hasFreshPowerOffProof reports whether a host has proof-grade power-off
// evidence that is still valid.
//
// It mirrors manualFenceConfirmedVIP: the attestation means "this host is
// down", so it is honoured ONLY while the host is not currently reachable. A
// host that has REJOINED has its live state govern, not a past attestation. The
// evidence also expires, and a read error fails closed by propagating — the
// caller aborts the whole reclamation rather than guessing.
func (s *Server) hasFreshPowerOffProof(ctx context.Context, host string) (bool, error) {
	if s.hostIsReachable(ctx, host) {
		return false, nil // rejoined or never down — live state governs
	}
	return s.freshFenceConfirmation(ctx, host)
}

// hostIsReachable reads the SAME live signal manualFenceConfirmedVIP consults:
// a peer this node currently counts toward quorum. Self is always reachable.
//
// With no gate wired nothing is reachable, which is the safe direction: an
// unreachable host is merely a candidate for exclusion, and exclusion still
// requires positive fence evidence on top.
func (s *Server) hostIsReachable(ctx context.Context, host string) bool {
	if host == s.hostName {
		return true
	}
	if s.gate == nil {
		return false
	}
	for _, h := range s.gate.HealthyPeers(ctx) {
		if h == host {
			return true
		}
	}
	return false
}

// freshFenceConfirmation reads the operator's `lv host fence-confirm`
// attestation, within netboxFenceWindow — the sweeper's OWN window, not the VIP
// one, because a sweep pass runs on a far longer cadence than a VIP failover.
// An error is RETURNED, never folded into false: "I could not read the fencing
// log" and "this host was never fenced" lead to opposite decisions here, and
// only one of them is safe.
func (s *Server) freshFenceConfirmation(ctx context.Context, host string) (bool, error) {
	if s.db == nil {
		return false, fmt.Errorf("no local database")
	}
	return corrosion.HostManualFenceConfirmed(ctx, s.db, host, time.Now(), netboxFenceWindow)
}

func sameHostSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── the leader lease ────────────────────────────────────────────────────────

// acquireNetBoxLease takes/renews the sweeper's leader lease. Same guarded
// upsert plus read-back as acquireDualRunLease: the conflict clause refuses to
// steal a lease that has not expired, and the read-back is what makes a lost
// race observable rather than assumed.
func (s *Server) acquireNetBoxLease(ctx context.Context, interval time.Duration) bool {
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().Add(2 * interval).UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at
		   WHERE leader_election.expires_at < ?
		      OR leader_election.holder = excluded.holder`,
		netBoxLeaseKey, s.hostName, expires, now, now); err != nil {
		slog.Warn("netbox sweep: lease write", "error", err)
		return false
	}
	return s.holdsLeaderLease(ctx)
}

// holdsLeaderLease is the read-back alone — no write, no renewal — so it can be
// called immediately before each destructive step without extending a lease
// this node may have already lost. A read failure reads as "not ours".
//
// BOTH halves of the lease are checked. The holder alone catches a lease that
// was STOLEN — a peer wrote its own name — but not one that merely EXPIRED,
// and expiry is the case this is named for: nothing obliges a peer to write the
// moment our TTL runs out, so a holder-only predicate keeps returning true for
// a lease no other node would honour, and the sweeper's destructive steps go on
// resting on it. expires_at is parsed exactly as acquireNetBoxLease formats it
// (RFC3339, UTC).
//
// Fail-closed at every branch: no row, an unreadable row, a missing or
// unparseable expires_at, and an expiry already in the past all read as "not
// ours". A lease we cannot prove we hold is one we do not hold.
func (s *Server) holdsLeaderLease(ctx context.Context) bool {
	if s.db == nil {
		return false
	}
	rows, err := s.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, netBoxLeaseKey)
	if err != nil || len(rows) == 0 {
		return false
	}
	if rows[0].String("holder") != s.hostName {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339, rows[0].String("expires_at"))
	if err != nil {
		return false
	}
	return time.Now().UTC().Before(expiresAt)
}

// ── the proof fan-out ───────────────────────────────────────────────────────

// gatherOrphanProofs asks every host in `hosts` whether it still claims the
// candidate: self in-process, peers over CollectOrphanProof, bounded worker
// pool, one bounded timeout each.
//
// Results are keyed by the host we ASKED, never by the host the response names
// — a peer that answered with someone else's name would otherwise satisfy that
// host's slot and let the real one go unasked.
//
// Any dial or RPC failure lands in `unreachable`, INCLUDING codes.Unimplemented
// from an older peer that has no such handler. gatherRuntime treats that as
// benign version skew because it only alerts; here it is a host whose runtime
// cannot be read, and a delete may not rest on that.
func (s *Server) gatherOrphanProofs(ctx context.Context, hosts []string, cand orphanCandidate) (map[string]OrphanProof, []string) {
	type result struct {
		host  string
		proof OrphanProof
		err   error
	}
	results := make([]result, len(hosts))

	var wg sync.WaitGroup
	sem := make(chan struct{}, orphanProofWorkers)
	for i, h := range hosts {
		if h == s.hostName {
			// Bounded exactly like a peer's. A local libvirt that hangs would
			// otherwise stretch the pass past the lease TTL — the failure
			// orphanProofTimeout exists to prevent — and the self proof is the
			// one probe that never crosses a network timeout of its own.
			pctx, cancel := context.WithTimeout(ctx, orphanProofTimeout)
			p, err := s.collectOrphanProof(pctx, cand.VMUUID, cand.MAC, cand.Address)
			cancel()
			results[i] = result{host: h, proof: p, err: err}
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = result{host: h}
			pctx, cancel := context.WithTimeout(ctx, orphanProofTimeout)
			defer cancel()
			client, closeConn, err := s.dialPeer(pctx, h)
			if err != nil {
				results[i].err = err
				return
			}
			resp, rerr := client.CollectOrphanProof(pctx, &pb.OrphanProofRequest{
				VmUuid:  cand.VMUUID,
				Mac:     cand.MAC,
				Address: cand.Address,
			})
			closeConn()
			if rerr != nil {
				results[i].err = rerr
				return
			}
			results[i].proof = OrphanProof{
				Host:         h,
				Complete:     resp.GetComplete(),
				Errors:       resp.GetErrors(),
				HoldsUUID:    resp.GetHoldsUuid(),
				HoldsMAC:     resp.GetHoldsMac(),
				HoldsAddress: resp.GetHoldsAddress(),
			}
		}(i, h)
	}
	wg.Wait()

	proofs := make(map[string]OrphanProof, len(hosts))
	var unreachable []string
	for _, r := range results {
		if r.err != nil {
			slog.Debug("netbox sweep: proof probe failed", "host", r.host, "error", r.err)
			unreachable = append(unreachable, r.host)
			continue
		}
		proofs[r.host] = r.proof
	}
	return proofs, unreachable
}

// ── candidate enumeration ───────────────────────────────────────────────────

// orphanCandidate is one NetBox address that may no longer be claimed.
type orphanCandidate struct {
	PrefixID   int
	PrefixCIDR string // the binding's ObservedCIDR; NetBox's parent filter needs a CIDR
	VRFID      int
	Network    string // the litevirt network the binding names — the lease's key
	NetBoxID   int
	// Address is the BARE host form, which is what local rows store.
	// NetBoxAddress is the string NetBox itself returned (carrying a prefix
	// length); the pre-delete re-read compares against that one, so a prefix
	// change registers as the object having changed.
	Address          string
	NetBoxAddress    string
	AssignedObjectID int
	Identity         string
	MAC              string
	VMUUID           string
}

// orphanCandidates enumerates addresses NetBox holds under THIS cluster's
// identity that no live local lease references.
//
// Scoping is by cluster fingerprint AND binding prefix. Without the fingerprint
// check, one cluster's sweeper would treat another cluster's addresses in the
// same prefix as orphans and delete them.
func (s *Server) orphanCandidates(ctx context.Context, grace time.Duration) ([]orphanCandidate, error) {
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return nil, err
	}
	bindings, err := corrosion.ListBindings(ctx, s.db)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().UTC().Add(-grace)

	var out []orphanCandidate
	for _, b := range bindings {
		if b.Suspended {
			// A suspended binding is one litevirt has stopped trusting enough to
			// allocate from. Deleting from it anyway would be the most
			// destructive available reading of that doubt.
			continue
		}
		if b.ClusterFingerprint != fp {
			continue // not ours
		}
		remote, err := s.netbox.ListIPsByPrefix(ctx, b.ObservedCIDR, b.VRFID)
		if err != nil {
			// A partial enumeration would make live addresses look absent.
			s.nbMetrics().IncAPIError(netbox.Classify(err))
			return nil, fmt.Errorf("enumerate prefix %d: %w", b.PrefixID, err)
		}
		for _, ip := range remote {
			cand, ok, err := s.candidateFor(ctx, b, fp, ip, cutoff)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, cand)
			}
		}
	}
	return out, nil
}

// candidateFor decides whether one NetBox object is even worth proving about.
// It is a FILTER, not a verdict: everything it lets through still has to
// survive the whole-cluster proof.
func (s *Server) candidateFor(ctx context.Context, b corrosion.BindingRecord, fp string,
	ip netbox.IPAddress, cutoff time.Time) (orphanCandidate, bool, error) {

	cf, uuid, mac, ok := parseIdentity(ip.Identity)
	if !ok || cf != fp {
		return orphanCandidate{}, false, nil // malformed, or another cluster's
	}
	bare, ok := bareAddress(ip.Address)
	if !ok {
		// An address we cannot interpret cannot be checked against a lease, and
		// an unchecked lease is exactly what protects a running guest.
		slog.Warn("netbox sweep: skipping an address that is neither an IP nor a CIDR",
			"address", ip.Address, "netbox_id", ip.ID)
		return orphanCandidate{}, false, nil
	}
	held, err := corrosion.LeaseExistsByIP(ctx, s.db, b.Network, bare)
	if err != nil {
		return orphanCandidate{}, false, fmt.Errorf("read lease %s: %w", bare, err)
	}
	if held {
		// NEVER a candidate. A live lease is litevirt still holding the address,
		// whatever its owner columns say; a lease with no owner is a repair
		// problem for an operator, not an address to free.
		return orphanCandidate{}, false, nil
	}
	if !olderThan(ip.Created, cutoff) {
		return orphanCandidate{}, false, nil // inside the grace window, or age unknown
	}
	return orphanCandidate{
		PrefixID:         b.PrefixID,
		PrefixCIDR:       b.ObservedCIDR,
		VRFID:            b.VRFID,
		Network:          b.Network,
		NetBoxID:         ip.ID,
		Address:          bare,
		NetBoxAddress:    ip.Address,
		AssignedObjectID: ip.AssignedObjectID,
		Identity:         ip.Identity,
		MAC:              mac,
		VMUUID:           uuid,
	}, true, nil
}

// olderThan is the grace predicate. A ZERO creation time means NetBox did not
// tell us when the object appeared, and an object of unknown age is treated as
// too young — the only direction that cannot free a live address.
func olderThan(created, cutoff time.Time) bool {
	return !created.IsZero() && created.Before(cutoff)
}

// parseIdentity is the inverse of netbox.Identity ("lv:<fp>:<uuid>:<mac>") for
// an object that must name a NIC.
//
// A MISSING MAC is refused. Every caller here is reasoning about an address, and
// an address whose identity names no NIC is not one the reclaim proof can ask a
// question about — treating it as parseable would put it on a path that then
// compares against the empty MAC.
func parseIdentity(identity string) (fingerprint, vmUUID, mac string, ok bool) {
	fingerprint, vmUUID, mac, ok = splitIdentity(identity)
	if !ok || mac == "" {
		return "", "", "", false
	}
	return fingerprint, vmUUID, mac, true
}

// splitIdentity is parseIdentity WITHOUT the MAC requirement.
//
// The VM form of an identity is netbox.Identity(fp, uuid, "") — "lv:<fp>:<uuid>:"
// — so a virtual_machine object legitimately carries no MAC. The CA re-key walks
// VM and interface objects through one loop and must parse both; running them
// through parseIdentity instead would make every virtual_machine unparseable and
// the re-key would skip the whole inventory while reporting success.
//
// The MAC is the REMAINING fields rejoined, not the fourth field: a MAC contains
// colons, so a naive four-way split silently truncates it to its first octet and
// every proof would then ask about the wrong NIC.
func splitIdentity(identity string) (fingerprint, vmUUID, mac string, ok bool) {
	parts := strings.Split(identity, ":")
	if len(parts) < 4 || parts[0] != "lv" {
		return "", "", "", false
	}
	fingerprint, vmUUID = parts[1], parts[2]
	mac = strings.Join(parts[3:], ":")
	if fingerprint == "" || vmUUID == "" {
		return "", "", "", false
	}
	return fingerprint, vmUUID, mac, true
}

// bareAddress reduces NetBox's "10.0.5.7/24" to the host form local rows store.
// A value that parses as neither a CIDR nor an IP is refused rather than
// guessed at.
func bareAddress(address string) (string, bool) {
	if ip, _, err := net.ParseCIDR(address); err == nil {
		return ip.String(), true
	}
	if ip := net.ParseIP(strings.SplitN(address, "/", 2)[0]); ip != nil {
		return ip.String(), true
	}
	return "", false
}

// ── the orphan-check queue ──────────────────────────────────────────────────

// drainOrphanChecks handles the "orphan" items a failed create-compensation
// enqueued. It is a latency shortcut over the full pass — and the one place a
// STUCK lease is detected, because only here do we know an identity was
// supposed to have been released.
//
// The drain is SCOPED to "orphan". Items of other kinds belong to the mirror
// reconciler and are never acked here — acking another component's work would
// silently drop it — so an unscoped drain whose batch happened to be all mirror
// items would do nothing at all, every pass, and the stuck-lease detector would
// go quiet with no signal that it had.
func (s *Server) drainOrphanChecks(ctx context.Context) {
	items, err := corrosion.DrainSyncQueue(ctx, s.db, orphanQueueKind, orphanQueueBatch)
	if err != nil {
		slog.Warn("netbox sweep: drain sync queue", "error", err)
		return
	}
	if len(items) == 0 {
		return
	}
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		slog.Warn("netbox sweep: cluster fingerprint", "error", err)
		return
	}
	bindings, err := corrosion.ListBindings(ctx, s.db)
	if err != nil {
		slog.Warn("netbox sweep: list bindings", "error", err)
		return
	}
	for _, it := range items {
		if s.handleOrphanCheck(ctx, it, fp, bindings) {
			if err := corrosion.AckSyncItem(ctx, s.db, it.ID); err != nil {
				slog.Warn("netbox sweep: ack orphan check", "id", it.ID, "error", err)
			}
			continue
		}
		s.countFailedOrphanCheck(ctx, it)
	}
}

// countFailedOrphanCheck records ONE failed resolution and retires an item that
// has failed too many times.
//
// The counter is what makes "keep it queued and retry" bounded: an item nothing
// can ever resolve would otherwise be re-attempted on every pass forever,
// crowding out the items a sweep can actually finish. Retiring it is loud —
// ERROR, naming the identity — because the address behind it is then reachable
// only by hand.
func (s *Server) countFailedOrphanCheck(ctx context.Context, it corrosion.QueueItem) {
	if err := corrosion.BumpSyncAttempts(ctx, s.db, it.ID); err != nil {
		// The count did not land, so this attempt is not held against the item.
		// Retrying forever is the lesser failure: nothing is deleted either way.
		slog.Warn("netbox sweep: count an orphan-check attempt", "id", it.ID, "error", err)
		return
	}
	if it.Attempts+1 < orphanCheckMaxAttempts {
		return
	}
	slog.Error(fmt.Sprintf("netbox sweep: giving up after %d attempts; address may need manual review",
		orphanCheckMaxAttempts), "identity", it.Key, "id", it.ID, "attempts", it.Attempts+1)
	if err := corrosion.AckSyncItem(ctx, s.db, it.ID); err != nil {
		slog.Warn("netbox sweep: ack an exhausted orphan check", "id", it.ID, "error", err)
	}
}

// handleOrphanCheck resolves one queued identity. It reports whether the item is
// FINISHED and may be acked; an item whose lookup failed stays queued so the
// next pass retries it, bounded by orphanCheckMaxAttempts.
//
// An identity carries no prefix, so it is resolved against every non-suspended
// binding of this cluster. That is the only scoping available, and NetBox's
// identity lookup is itself scoped to a VRF and a parent prefix, so a hit
// genuinely belongs to the binding it was found under.
func (s *Server) handleOrphanCheck(ctx context.Context, it corrosion.QueueItem, fp string,
	bindings []corrosion.BindingRecord) bool {

	cf, uuid, mac, ok := parseIdentity(it.Key)
	if !ok || cf != fp {
		slog.Warn("netbox sweep: dropping an orphan check with an unusable identity",
			"identity", it.Key)
		s.noteSweepSkip(skipIdentityUnresolvable)
		return true // nothing this cluster can ever resolve
	}

	resolvedAny := false
	for _, b := range bindings {
		if b.Suspended || b.ClusterFingerprint != fp {
			continue
		}
		found, err := s.netbox.LookupByIdentity(ctx, it.Key, b.VRFID, b.ObservedCIDR)
		if err != nil {
			s.nbMetrics().IncAPIError(netbox.Classify(err))
			slog.Warn("netbox sweep: orphan-check lookup failed; will retry",
				"identity", it.Key, "prefix", b.PrefixID, "error", err)
			return false // keep the item queued
		}
		for _, ip := range found {
			resolvedAny = true
			switch s.resolveQueuedAddress(ctx, b, it.Key, uuid, mac, ip) {
			case queueStuck:
				return true // stuck lease: surfaced, acked, nothing deleted
			case queueRetry:
				return false // undecidable this pass; keep the item queued
			}
		}
	}
	if !resolvedAny {
		// Already gone from NetBox, or never landed. Either way there is
		// nothing left to reclaim.
		return true
	}
	return true
}

// queueOutcome is what ONE resolved address tells the queue to do with its item.
//
// Three outcomes, not two: "finished" and "a stuck lease" both retire the item,
// but "I could not tell" must not — and a single bool cannot say that. The stuck
// lease is the whole reason the queue exists, so an item dropped before its lease
// check ran takes the only signal that address will ever produce with it.
type queueOutcome int

const (
	// queueDone: handled. Reclaimed, refused by the whole-cluster proof, or not
	// interpretable at all — nothing further will change by asking again.
	queueDone queueOutcome = iota
	// queueStuck: a live lease still names the address. Surfaced for an operator
	// and retired, because re-firing the same alarm every sweep buries it.
	queueStuck
	// queueRetry: the decision could not be made — a read failed. The item stays
	// queued for the next pass.
	queueRetry
)

// resolveQueuedAddress handles one address a queued identity resolved to.
//
// It reports queueStuck when the address is a STUCK lease — a live lease still
// names it, so the compensation that enqueued this item never finished locally,
// and deleting the remote object would free an address litevirt still holds.
func (s *Server) resolveQueuedAddress(ctx context.Context, b corrosion.BindingRecord,
	identity, uuid, mac string, ip netbox.IPAddress) queueOutcome {

	bare, ok := bareAddress(ip.Address)
	if !ok {
		slog.Warn("netbox sweep: orphan check resolved an uninterpretable address",
			"address", ip.Address, "identity", identity)
		return queueDone
	}
	held, err := corrosion.LeaseExistsByIP(ctx, s.db, b.Network, bare)
	if err != nil {
		// A read we cannot do is not permission to delete — and it is not
		// permission to FORGET either. Acking here would drop the item on a
		// transient DB error, and with it the stuck-lease check that is the only
		// thing standing between this address and a later, unwitnessed delete.
		slog.Warn("netbox sweep: orphan check could not read the lease table; keeping the item queued",
			"address", bare, "network", b.Network, "identity", identity, "error", err)
		return queueRetry
	}
	if held {
		slog.Error("netbox sweep: STUCK LEASE — a live ip_allocations row still references an address whose NetBox object was queued for release; "+
			"the address is leaked in both systems until an operator retires the lease. Nothing has been deleted.",
			"address", bare, "network", b.Network, "identity", identity, "netbox_id", ip.ID)
		s.nbMetrics().IncStuckLease()
		return queueStuck
	}
	cand := orphanCandidate{
		PrefixID:         b.PrefixID,
		PrefixCIDR:       b.ObservedCIDR,
		VRFID:            b.VRFID,
		Network:          b.Network,
		NetBoxID:         ip.ID,
		Address:          bare,
		NetBoxAddress:    ip.Address,
		AssignedObjectID: ip.AssignedObjectID,
		Identity:         identity,
		MAC:              mac,
		VMUUID:           uuid,
	}
	if err := s.reclaimIfProven(ctx, cand); err != nil {
		slog.Warn("netbox sweep: queued reclamation aborted",
			"address", cand.Address, "identity", identity, "reason", err)
		s.noteSweepSkip(skipReason(err))
	}
	return queueDone
}

// ── test seams ──────────────────────────────────────────────────────────────

// SetOnProofCollected installs a hook that runs BETWEEN the two eligible-host
// samples. It exists so a scenario can change cluster membership inside the
// exact window the two-sample check defends, which nothing above the server can
// otherwise reach. nil in production.
func (s *Server) SetOnProofCollected(fn func()) { s.onProofCollected = fn }

// SetOnProofsGathered installs a hook that may MUTATE the gathered proof map
// before it is checked. It exists to model a host that answers nothing at all
// without failing — a fan-out bug, a dropped response — which no transport-level
// fault can produce, because a transport fault is reported as unreachable.
// nil in production.
func (s *Server) SetOnProofsGathered(fn func(map[string]OrphanProof)) { s.onProofsGathered = fn }
