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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

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
// a host that has rejoined is never excluded from anything, whatever the fencing
// log says. The window therefore only bounds how long an UNREACHABLE host's
// attestation keeps counting — and it must EXCEED the sweep cadence
// (netbox.sweep_interval_sec, defaultNetBoxSweepInterval when unset), or an
// operator's confirmation expires before the next sweep could read it at all.
//
// WHAT THE ATTESTATION BUYS IS NARROWER THAN AN EARLIER ROUND OF THIS CLAIMED.
// It excuses a host from the RUNTIME-PROOF SET and from nothing else — see
// snapshotPowerOffEvidence. It is NOT an escape from the participant closure: a
// machine that is off still knew which hosts existed and still held replicated
// rows, and attesting that it is off recovers neither. So after a permanent host
// loss reclamation stays paused, deliberately, and `lv health` names the host it
// is waiting on.
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
//  1. Read the runtime-proof host set A, CLOSED over EVERY candidate's own
//     membership view — its `hosts` rows, tombstones included, and its gossip
//     members — until the set stops growing. Every candidate is asked whatever
//     its role and whatever its power state; only the set that must SCAN excuses
//     a witness or a machine attested off.
//  2. Gather complete negative proofs from exactly A.
//  3. Read the runtime-proof host set B, through the same closure.
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
	// 1. Sample A — from closedRuntimeProofSet: the replicated `hosts` table
	//    UNIONED WITH GOSSIP MEMBERSHIP, then CLOSED under EVERY participant's
	//    OWN membership view — its `hosts` rows, tombstones included, and the
	//    gossip members only its memberlist can name. Every participant, not
	//    every reachable one: a host that cannot answer leaves the set unclosed
	//    rather than out of it.
	//
	//    No part of that is a refinement; each is the difference between a proof
	//    and a coin flip. Built from the `hosts` table alone, a peer whose row
	//    had not hydrated on this node was absent from BOTH samples, so the
	//    samples agreed and the five steps below concluded that nobody held the
	//    address — while that peer's guest still had it on a defined domain. Two
	//    samples establish STABILITY, not COMPLETENESS. Built from the local
	//    union alone it was still only the set of hosts this node happens to have
	//    heard of. Closed over what each peer's ListHosts REPORTS, it still
	//    missed the rows that query filters out: a holder tombstoned on a peer,
	//    which a local-only witness balanced out of a row-count comparison too.
	//    And closed over each peer's `hosts` ROWS, it still could not see a
	//    holder that only another node's GOSSIP names, because no table
	//    anywhere records one. Closed over the hosts a ROLE FILTER left in, it
	//    still could not see a holder only a WITNESS could name — nor learn that
	//    the role it filtered a holder out on was stale. And closed over the
	//    hosts a POWER-OFF ATTESTATION left in, it could not see a holder only an
	//    attested-off witness could name: being off proves nothing about who that
	//    machine knew existed.
	setA, unclosed, err := s.closedRuntimeProofSet(ctx)
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
	setB, unclosed, err := s.closedRuntimeProofSet(ctx)
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
	// Every reclamation that gets here rested on a whole-cluster proof over
	// machine evidence, so there is one kind of success line and no operator
	// attestation to distinguish.
	slog.Info("netbox sweep: reclaimed an orphaned address",
		"address", cand.Address, "identity", cand.Identity, "netbox_id", cand.NetBoxID)
	s.nbMetrics().IncOrphansReclaimed()
	return nil
}

// ── the participant universe, and the THREE SETS built out of it ────────────

// THE CANDIDATE UNIVERSE is the `hosts` table unioned with gossip membership,
// closed over every candidate's own membership view (closedParticipantSets).
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
// THREE SETS COME OUT OF THAT UNIVERSE AND NO TWO OF THEM ARE THE SAME SET.
// Collapsing a pair of them has now handed out or freed a held address three
// times over, so each is its own function over its own argument type and an AST
// guard (netbox_participant_sets_test.go) fails the collapses — a comment has
// already proved insufficient twice.
//
// WHAT SEPARATES THEM is not what a host is allowed to do. It is WHAT THIS
// PARTICIPANT HAS THAT THE PROOF NEEDS:
//
//   - KNOWLEDGE OF WHO EXISTS → membershipDiscoveryTargets, and EVERYONE has it.
//     A role says what a host may RUN, never what it KNOWS; a power state says
//     what it is doing now, never what it knew before it stopped. So this set has
//     no exclusion at all, and takes NAMES so that none can be expressed.
//   - THE REPLICATED ROWS → inventoryCorroborationParticipants, and EVERYONE
//     RUNNING THE DAEMON has them, WITNESSES INCLUDED. A witness is a full
//     corrosion peer: it receives `vms` and every NIC table while hosting
//     nothing, so its copy is as authoritative as a worker's — and its UNIQUE
//     rows are exactly the ones a short local inventory is missing.
//   - A RUNNING DOMAIN TO SCAN → runtimeProofParticipants, and only a workload
//     host has one. This is the ONLY set with exclusions, and there are two: a
//     corroborated witness, and a machine an operator has attested is off.
//
// EXCLUDING A HOST FROM DISCOVERY IS PRECISELY WHAT PREVENTS LEARNING THE
// EXCLUSION WAS WRONG. A role lives in a replicated row that `lv host config
// --role` mutates, so this node's copy can be stale, and the rule that a host
// counts as a witness only while EVERY row read agrees (candidateSet.addRow) can
// never fire for a host nobody ever queried. An exclusion must not precede the
// query that could refute it: the closure asks every discovery target before any
// other set exists, derives the other two only on the round that closes, and then
// refuses to return a host discovery never actually read
// (participantsThatNeverAnswered).
//
// POWER-OFF EVIDENCE IS ADMISSIBLE IN ONE SET, AND IT IS THE RUNTIME ONE. `lv
// host fence-confirm` proves a machine's libvirt cannot be running a domain. It
// proves nothing about the hosts that machine alone knew existed, and nothing
// about the rows it holds, so it excuses a SCAN and never a MEMORY. A host is
// likewise NOT excluded because its row vanished or because its state reads
// offline — an offline-looking host can still be running the domain, and dropping
// it would manufacture exactly the absence being proven. The cost is stated
// rather than mitigated: an unreachable or fenced host keeps BOTH the sweep and
// the bind blocked for as long as it stays that way, and that trade was chosen.
// Leaking an address the next pass can reclaim beats freeing one a live guest
// holds.
//
// ONE CLOSURE, NOT ONE PER PROOF. Both cross-cluster proofs in this package — the
// sweeper's negative proof and the bind's inventory corroboration — reach a host
// set only through closedParticipantSets, each through the accessor named after
// the set it needs (closedRuntimeProofSet, closedInventoryCorroborationPeers).
// There were two closures once, and they differed in exactly the way that
// mattered: the bind's unioned GOSSIP MEMBERSHIP into the replicated `hosts`
// table and the sweeper's did not. So the sweeper built its whole universe from
// the replicated table, a peer whose row had not hydrated on this node was absent
// from BOTH of its samples, the samples agreed — they establish stability, not
// completeness — and it deleted an address that peer's guest still held. Then one
// closure served both and the bind read the WRONG SET out of it, which is the
// same defect one level over.
//
// THIS NODE IS ALWAYS IN EVERY SET. Its own row could be missing or tombstoned
// while it is demonstrably running — it is executing this code — and a proof
// that omitted the leader would be the easiest possible way to miss a claimant.

// participantCandidate is one host some source named, plus the only property
// that can exclude it on sight.
//
// witness is true only while EVERY `hosts` ROW read for this host says so, and
// false for a host no row anywhere records — see candidateSet.addRow.
type participantCandidate struct {
	name    string
	witness bool
}

// candidateSet accumulates the candidate universe across sources — this node's
// rows, this node's gossip, and every participant's membership view — under ONE
// merge rule, so that no source can be folded in on terms of its own.
//
// It exists because the sources disagree about a host's ROLE, and a role is what
// the witness exclusion turns on. Round three of this review kept the local
// reading and ignored a peer's; that was incoherent (both are the same
// replicated row, read from different nodes, and `lv host config --role` makes it
// mutable) and it was fail-OPEN in one direction: this node's stale
// `role='witness'` excused a host that had since become a worker, and the peer
// row saying so was thrown away.
type candidateSet struct {
	byName map[string]*candidateRole
	order  []string
}

// candidateRole is the accumulated role reading for one candidate. sawRow
// distinguishes "no row anywhere records this host" from "a row records it as a
// worker", which the AND in addRow could not otherwise tell apart: without it,
// whether a gossip naming or a row arrived FIRST would decide the answer, and
// the two arrive in whatever order the fan-out returns.
type candidateRole struct {
	witness bool
	sawRow  bool
}

func newCandidateSet() *candidateSet {
	return &candidateSet{byName: map[string]*candidateRole{}}
}

// addRow folds in a `hosts` ROW reading — a name plus the role that row records.
//
// A host is treated as a witness only while every row read for it agrees. Two
// rows that disagree are one role mid-replication, and there is no timestamp on
// the wire to order them, so the disagreement resolves toward ASKING the host:
// a witness that gets dialled is work, a workload host that does not is a freed
// address someone is using.
func (cs *candidateSet) addRow(name, role string) {
	if name == "" {
		return
	}
	witness := role == "witness"
	if c, ok := cs.byName[name]; ok {
		if !c.sawRow {
			c.witness, c.sawRow = witness, true
			return
		}
		c.witness = c.witness && witness
		return
	}
	cs.byName[name] = &candidateRole{witness: witness, sawRow: true}
	cs.order = append(cs.order, name)
}

// addNamed folds in a source that names a host WITHOUT holding a row for it —
// gossip membership, on this node or a peer.
//
// It never touches an existing candidate's role, and never establishes one:
// naming a host is not a reading of its row, and an unknown role is not the
// statement that a host is a witness.
func (cs *candidateSet) addNamed(name string) {
	if name == "" || cs.byName[name] != nil {
		return
	}
	cs.byName[name] = &candidateRole{}
	cs.order = append(cs.order, name)
}

// all returns the candidates WITH their accumulated role reading, in the order
// they were first named. Only runtimeProofParticipants may consume this: a role
// is what excuses a host from a SCAN, and nothing else.
func (cs *candidateSet) all() []participantCandidate {
	out := make([]participantCandidate, 0, len(cs.order))
	for _, n := range cs.order {
		out = append(out, participantCandidate{name: n, witness: cs.byName[n].witness})
	}
	return out
}

// names returns the candidates as BARE NAMES, in the order they were first
// named — the whole universe, with no role attached to filter on.
//
// It exists so the membership-discovery fan-out cannot see a role. Every host
// here gets asked what it knows, because what a host knows does not depend on
// what it is allowed to run.
func (cs *candidateSet) names() []string {
	out := make([]string, 0, len(cs.order))
	out = append(out, cs.order...)
	return out
}

// hostRoleRow is one `hosts` row reduced to what a membership proof reads: the
// identity, and the role its exclusions turn on. TOMBSTONED rows are included —
// soft-deleting a host row does not power a machine off — and are deliberately
// indistinguishable here, so nothing downstream can branch on the difference.
type hostRoleRow struct {
	name string
	role string
}

// localHostRows reads EVERY `hosts` row this node holds.
//
// No deleted_at filter, deliberately: a decommissioned row does not power a
// machine off, and RemoveHost --force does not even check for workloads. This is
// the one read behind both this node's own candidate set and the membership view
// it serves to peers, so the two cannot drift.
func (s *Server) localHostRows(ctx context.Context) ([]hostRoleRow, error) {
	if s.db == nil {
		return nil, fmt.Errorf("no local database on this host — cannot read its host rows")
	}
	rows, err := s.db.Query(ctx, `SELECT name, COALESCE(role, '') AS role FROM hosts`)
	if err != nil {
		return nil, err
	}
	out := make([]hostRoleRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, hostRoleRow{name: r.String("name"), role: r.String("role")})
	}
	return out, nil
}

// localGossipMembers is this node's memberlist view, which EXCLUDES itself
// exactly as corrosion.Client.Members() does. It is legitimately empty on a
// node with no gossip layer.
func (s *Server) localGossipMembers() []string {
	if s.db == nil {
		return nil
	}
	var out []string
	for _, m := range s.db.Members() {
		if m.Name != "" {
			out = append(out, m.Name)
		}
	}
	return out
}

// localParticipantCandidates is the candidate set this node can name WITHOUT
// asking anybody: the replicated `hosts` table unioned with gossip membership.
func (s *Server) localParticipantCandidates(ctx context.Context) (*candidateSet, error) {
	rows, err := s.localHostRows(ctx)
	if err != nil {
		return nil, err
	}
	cs := newCandidateSet()
	for _, r := range rows {
		cs.addRow(r.name, r.role)
	}
	for _, m := range s.localGossipMembers() {
		// No role: nothing but the `hosts` table records one, and this host's
		// row is precisely what has not arrived.
		cs.addNamed(m)
	}
	return cs, nil
}

// membershipView is one node's WHOLE candidate universe as that node sees it:
// every `hosts` row it holds, tombstones included, plus the gossip members only
// its own memberlist can name.
//
// complete is false when the enumeration was not whole. rows and gossip stay
// meaningful when it is — they are only ever POSITIVE statements, exactly as
// OrphanProof's holds_* flags are — but ABSENCE from an incomplete view is
// worthless, so a caller must withhold rather than read a short list as this
// node's membership.
type membershipView struct {
	host     string
	rows     []hostRoleRow
	gossip   []string
	complete bool
	errors   []string
}

// localMembershipView is what this node answers GetMembershipView with, built
// from the same two reads its own candidate set is built from.
//
// A node whose `hosts` table does not carry a row for ITSELF has an unhydrated
// database, not a small cluster, so its enumeration is reported INCOMPLETE. That
// rule is applied to what this node SERVES and not to what it reads locally, and
// the asymmetry is the point: this node is in its own participant set
// unconditionally (participantsWithThisNode adds it), so its own missing row hides
// nobody from it — while a peer is the only source for its own table, and a peer
// that has not even received its own row is a peer whose rows cannot be read as
// the cluster's.
func (s *Server) localMembershipView(ctx context.Context) membershipView {
	v := membershipView{host: s.hostName, complete: true}
	rows, err := s.localHostRows(ctx)
	if err != nil {
		v.complete = false
		v.errors = append(v.errors, fmt.Sprintf("read this host's `hosts` rows: %v", err))
	}
	v.rows = rows
	v.gossip = s.localGossipMembers()
	if s.hostName != "" && err == nil {
		held := false
		for _, r := range rows {
			if r.name == s.hostName {
				held = true
				break
			}
		}
		if !held {
			v.complete = false
			v.errors = append(v.errors,
				"this host holds no `hosts` row for itself, so its table has not hydrated")
		}
	}
	return v
}

// GetMembershipView serves this host's membership view to a peer: every `hosts`
// row it holds — TOMBSTONES INCLUDED — plus its own gossip membership, which is
// the only source that can name a host with no row anywhere.
//
// Peer-only (host-cert mTLS), the same trust boundary as CollectOrphanProof and
// gathered by the same caller. It applies NO eligibility rule of its own: the
// caller runs every candidate through the one exclusion filter, so a responder
// cannot excuse a host by filtering it out here.
//
// It never returns a non-nil error for a read it could not complete, for
// collectOrphanProof's reason: a failure is part of the ANSWER (complete false
// plus the reason), and an error return would let a caller that only checks err
// treat a failed enumeration as a cluster with nothing in it.
func (s *Server) GetMembershipView(ctx context.Context, _ *emptypb.Empty) (*pb.MembershipViewResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	v := s.localMembershipView(ctx)
	out := &pb.MembershipViewResponse{
		Host:          v.host,
		GossipMembers: v.gossip,
		Complete:      v.complete,
		Errors:        v.errors,
	}
	for _, r := range v.rows {
		out.Hosts = append(out.Hosts, &pb.MembershipHost{Name: r.name, Role: r.role})
	}
	return out, nil
}

// membershipDiscoveryTargets is THE FIRST OF THE THREE SETS: every host that
// gets asked WHICH HOSTS IT KNOWS OF.
//
// EVERYONE. No role, no power state, no reachability. What a participant needs
// in order to belong here is KNOWLEDGE OF WHO EXISTS, and every host that has
// ever been part of this cluster has it — a machine an operator has attested is
// powered off very much included, because before it went off it knew about hosts
// nothing left running has heard of.
//
// It takes NAMES and returns without a ctx and without an error, and neither is
// a stylistic choice. With no role in scope the witness exclusion cannot be
// applied; with no ctx there is no database to read a fencing_log from and no
// gate to sample reachability with, so the power-off exclusion cannot be applied
// either. Teaching this set to exclude ANYBODY means changing its signature,
// which is what TestMembershipDiscoveryTargetsCannotFilterByRole fails on.
func (s *Server) membershipDiscoveryTargets(names []string) []string {
	return s.participantsWithThisNode(names)
}

// inventoryCorroborationParticipants is THE SECOND OF THE THREE SETS: every host
// whose digest of the address-bearing tables must AGREE with this node's before
// a bind may go live.
//
// EVERYONE RUNNING THE DAEMON, WITNESSES VERY MUCH INCLUDED. What a participant
// needs in order to belong here is THE REPLICATED ROWS, and a witness holds the
// whole replicated database while hosting nothing: it is a full corrosion peer
// that votes, gossips and receives every row, so its copy of `vms` and of the NIC
// tables is exactly as authoritative as a worker's.
//
// THIS SET IS THE ROUND-FIVE BUG. The digest check was pointed at the
// runtime-proof set, on the reading that "the hosts that must corroborate" and
// "the hosts that must answer" name the same hosts. They do not: a witness has
// the rows and not the runtime. So a witness holding the ONLY replicated copy of
// an incumbent's VM and NIC rows was never asked, the workers' equally short
// inventories agreed with each other, the bind went live having adopted nothing,
// and the next guest created was handed the incumbent's live address.
//
// It is a SEPARATE FUNCTION from the discovery fan-out even though the two
// currently return the same hosts, because they answer different questions: an
// exclusion that becomes right for one of them must not silently land on the
// other. That is the mistake this is the third fix for.
//
// No power-off exclusion, deliberately — see snapshotPowerOffEvidence for the
// one set where power-off evidence is admissible.
func (s *Server) inventoryCorroborationParticipants(names []string) []string {
	return s.participantsWithThisNode(names)
}

// runtimeProofParticipants is THE THIRD OF THE THREE SETS: every host that must
// return a COMPLETE RUNTIME SCAN before an address can be reclaimed.
//
// WORKLOAD HOSTS ONLY. What a participant needs in order to belong here is A
// RUNNING DOMAIN TO SCAN, which is the one thing a witness does not have and the
// one thing a powered-off machine does not have. So this is the only set that
// excludes anybody, and it excludes on exactly two grounds:
//
//   - A CORROBORATED WITNESS. It hosts no workload, so a scan of it is not
//     evidence — and it runs no libvirt, so dragging it in wedges every
//     reclamation behind a scan that can never complete. Only a `hosts` ROW
//     carries a role, this node's and a peer's being the same replicated datum
//     read from two places, so: a candidate no row anywhere records has no role
//     and stays IN (being named is not a reading of its role), and two rows that
//     disagree leave it IN as well (candidateSet.addRow).
//   - PROOF-GRADE POWER-OFF EVIDENCE, read from a snapshot taken ONCE for the
//     whole closure rather than sampled here. A machine attested off cannot be
//     running a domain — and that is a statement about a RUNTIME and about
//     nothing else, so it excuses no host from membership discovery and no host
//     from inventory corroboration. See snapshotPowerOffEvidence.
//
// Callers must have READ every discovery target's membership view before deriving
// this set, so that a row the host itself holds is part of the role agreement.
// closedParticipantSets is the only caller, and it derives this only on the round
// that closes.
func (s *Server) runtimeProofParticipants(candidates []participantCandidate, off powerOffSnapshot) []string {
	scannable := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if c.name != s.hostName {
			if c.witness {
				continue // hosts no workload: a scan of it is not evidence
			}
			if off[c.name] {
				continue // attested off: its libvirt cannot be running a domain
			}
		}
		scannable = append(scannable, c.name)
	}
	return s.participantsWithThisNode(scannable)
}

// participantsWithThisNode is the leg ALL THREE sets share, and it EXCLUDES
// NOBODY: it dedupes, guarantees this node is present, and sorts.
//
// It takes NAMES and has no ctx, so no exclusion of any kind can be expressed
// here. That is the point of the signature: a filter on the shared leg would
// apply to all three sets at once, which is how they collapsed into one twice
// before. Every exclusion lives in exactly one caller above.
func (s *Server) participantsWithThisNode(names []string) []string {
	seen := make(map[string]bool, len(names)+1)
	out := make([]string, 0, len(names)+1)
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	if !seen[s.hostName] && s.hostName != "" {
		out = append(out, s.hostName)
	}
	sort.Strings(out)
	return out
}

// powerOffSnapshot is ONE evaluation of the power-off input for ONE closure:
// host name → "attested off, and with no sign of a later rejoin".
//
// It exists because the input is LIVE. hasFreshPowerOffProof samples the gate's
// healthy-peer signal, so two calls milliseconds apart can legitimately
// disagree — and while two sets each evaluated it for themselves, a host that
// rejoined between the two calls was excluded from the set that decided who to
// ask and returned by the set the caller acted on. The closure then reported
// success naming a participant whose membership had never been read. Sampling
// once and deriving every set from the snapshot makes that ordering
// unrepresentable rather than unlikely.
type powerOffSnapshot map[string]bool

// snapshotPowerOffEvidence samples the power-off input ONCE per closure, for
// every candidate in the universe.
//
// The evidence is an operator's fresh, specific `lv host fence-confirm`
// attestation with no sign of a later rejoin, and it is admissible in exactly one
// place — the runtime-proof set. Saying so HERE, where the evidence is produced,
// is deliberate: the plausible-sounding opposite is what produced the finding
// this fixes.
//
// POWER-OFF EVIDENCE EXCUSES A RUNTIME, NEVER A MEMORY. Confirming that a
// machine is off proves its libvirt cannot be running a domain. It proves NOTHING
// about the hosts that machine knew existed, and nothing about the replicated
// rows it holds — a witness attested off was the ONLY node that could name a
// third host still running the domain, and excusing it from being asked freed
// that host's live address. So the attestation must never excuse a host from
// membership discovery or from inventory corroboration. An earlier round offered
// it as the escape hatch for an unreachable host blocking the closure; that trade
// was refused. An unreachable or fenced host KEEPS BLOCKING the closure, and so
// both the sweep and the bind withhold until the cluster is whole again. That is
// the designed outcome, and `lv health` names the host it is waiting on.
//
// This node is never sampled: it is demonstrably running, and it is the one host
// that answers for itself out of its own database.
//
// A read error is RETURNED, never folded into "excluded" or "not excluded": an
// unreadable fencing_log is not permission to do either, and the caller abandons
// the whole closure.
func (s *Server) snapshotPowerOffEvidence(ctx context.Context, names []string) (powerOffSnapshot, error) {
	off := make(powerOffSnapshot, len(names))
	for _, name := range names {
		if name == "" || name == s.hostName {
			continue
		}
		if _, sampled := off[name]; sampled {
			continue // one sample per host per closure, never one per set
		}
		excluded, err := s.hasFreshPowerOffProof(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("read fence evidence for %s: %w", name, err)
		}
		off[name] = excluded
	}
	return off, nil
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

// participantSets is what ONE closure produces: the sets derived from the
// candidate universe once every discovery target has answered.
//
// TWO FIELDS, THREE SETS. Membership discovery is deliberately not a field: it is
// the closure's INPUT, spent before either output exists, and a returned
// discovery set would be one more set a caller could reach for by mistake. What
// the closure keeps of it is the `asked` map, which participantsThatNeverAnswered
// checks both outputs against.
//
// The two outputs are separate fields for the same reason they are separate
// functions — a caller has to name the set it wants, and the two are not
// interchangeable. Pointing the bind's database-digest check at the runtime-proof
// field is exactly the round-five finding.
type participantSets struct {
	// corroborating is THE INVENTORY-CORROBORATION SET: every host whose
	// digests of the address-bearing tables must agree with this node's.
	// Witnesses included — they hold the rows.
	corroborating []string
	// runtime is THE RUNTIME-PROOF SET: every host that must return a complete
	// runtime scan. Corroborated witnesses and attested-off machines excused —
	// neither has a domain to scan.
	runtime []string
}

// closedParticipantSets is THE CANDIDATE UNIVERSE CLOSED OVER EVERY DISCOVERY
// TARGET'S OWN MEMBERSHIP VIEW: each one is asked which hosts its `hosts` table
// records — tombstoned rows included — and which hosts its GOSSIP names, the
// answers are folded back in, and the fan-out repeats until the set stops
// growing. It then derives the OTHER TWO SETS, on the round that closes and
// nowhere else.
//
// THE THREE SETS ARE DIFFERENT SETS and this is the only place any of them is
// built (see the section comment above membershipDiscoveryTargets). Everyone is
// asked what it knows — witnesses very much included, since a witness holds the
// whole replicated `hosts` table and gossips like any other node — and only the
// RUNTIME set excuses them. Fanning out over the runtime set instead excluded a
// host on a role reading nothing had corroborated, and excluding it is exactly
// what prevented the corroboration: a stale local `role='witness'` hid a host
// that had since become a worker and still held the address, and a genuine
// witness that was the only node able to name a third holder was never asked.
// Then the bind's DIGEST check was read out of the runtime set, and a witness's
// unique inventory rows went unconsulted for the same kind of reason.
//
// It is the ONE helper both cross-cluster proofs in this package use, and the
// only place either of them establishes membership. What the sweeper needs to
// reclaim, the bind needs to go live: a bind that adopts nothing because it
// could not see a holder is the same defect as a sweep that frees that holder's
// address, so neither may reach its participant set any other way.
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
// QUESTION — asked of the peers, about identities: which hosts do you know of at
// all? Any holder any reachable node can name is then queried by name, whether
// or not this node's own table or gossip ever heard of it.
//
// WHY THE QUESTION IS ITS OWN RPC, WHICH IS THE THIRD SOURCE THIS HAS USED.
// ListHosts filters `deleted_at IS NULL`, so a row TOMBSTONED on a peer is
// missing from its answer — and a forced host removal does not power a machine
// off, so that host may still be running the domain. Closing the set over a
// filtered source establishes closure over the filter, not completeness. Reading
// the peer's ROWS out of the state dump fixed that and left one shape it could
// not reach: a holder in a peer's GOSSIP with no `hosts` row anywhere. Gossip is
// not in any table, so no table-derived answer can carry it, and the dump is
// tables. GetMembershipView asks for both halves of a node's universe at once:
//
//   - its `hosts` rows, tombstones included, each with the role the RUNTIME
//     PROOF's witness exclusion turns on — never the fan-out's, which has none,
//     and never the inventory corroboration's, which has none either;
//   - its gossip members, which memberlist converges on in seconds
//     independently of every table, and which is the ONLY source that can name a
//     host no database anywhere records;
//   - an explicit completeness flag, so a node that could not enumerate itself
//     says so instead of returning a short list that reads as authoritative.
//
// It is also strictly CHEAPER than what it replaces: one small unary call per
// participant, in place of a whole-table digest set plus — on any peer whose
// `hosts` table differed at all — a gzipped dump of the entire replicated
// database. Nothing here pulls a state dump any more.
//
// FAIL CLOSED on every edge, the same direction the per-host proof already takes
// for an unreachable host: a participant that cannot be dialled, one that
// answers Unimplemented because it is an older build, one whose view reports
// itself incomplete, one that names nobody at all, one that names a host with an
// empty name, and one that ends up in a derived set without having answered at
// all, ALL leave the set unclosable — and an unclosed set cannot support "nobody
// holds this address". The reason is returned rather than an error, because it is
// part of the ANSWER: nothing about THIS node failed.
//
// THE MIXED-VERSION STORY IS THE RPC'S OWN NOVELTY, not a capability latch. A
// latch could not carry this: health.CapabilityActive forms every latch from
// corrosion.ListHosts, which is the same `deleted_at IS NULL` read this whole
// finding is about, so a tombstoned or gossip-only host never participates in
// forming one — the premise would be established by the weaker source the
// conclusion exists to repair. An old peer instead answers Unimplemented, which
// is a definite failure, and a definite failure is a refusal.
func (s *Server) closedParticipantSets(ctx context.Context) (participantSets, string, error) {
	candidates, err := s.localParticipantCandidates(ctx)
	if err != nil {
		return participantSets{}, "", err
	}
	// This node answers for itself from its own database; it is never dialled.
	asked := map[string]bool{s.hostName: true}

	for round := 0; round < hostSetClosureRounds; round++ {
		// THE FAN-OUT, over NAMES: every candidate is asked what it knows,
		// whatever its role says it may run and whatever its power state is.
		// Deriving the targets from a set that excludes anybody is what let a
		// host be excluded before the query that would have refuted it.
		targets := s.membershipDiscoveryTargets(candidates.names())
		var unasked []string
		for _, h := range targets {
			if !asked[h] {
				unasked = append(unasked, h)
			}
		}
		if len(unasked) == 0 {
			// Closed: every discovery target's view has been read and nothing
			// any of them knows of is outside the universe, so a role reading
			// can now be acted on — every host that could refute one has spoken.
			// THE OTHER TWO SETS ARE DERIVED HERE AND NOWHERE ELSE, from ONE
			// sample of the power-off input, so that they cannot disagree about
			// a host that rejoined mid-run.
			off, oerr := s.snapshotPowerOffEvidence(ctx, candidates.names())
			if oerr != nil {
				return participantSets{}, "", oerr
			}
			sets := participantSets{
				corroborating: s.inventoryCorroborationParticipants(candidates.names()),
				runtime:       s.runtimeProofParticipants(candidates.all(), off),
			}
			if unanswered := s.participantsThatNeverAnswered(sets, asked); unanswered != "" {
				return participantSets{}, unanswered, nil
			}
			return sets, "", nil
		}
		for _, v := range s.gatherMembershipViews(ctx, unasked) {
			asked[v.host] = true
			if v.unproven != "" {
				return participantSets{}, v.unproven, nil
			}
			// One merge rule for every source (candidateSet.addRow): a peer's
			// row reading counts, and it can only ever keep a host IN — a
			// disagreement about a role resolves toward asking the host.
			for _, r := range v.rows {
				candidates.addRow(r.name, r.role)
			}
			for _, m := range v.gossip {
				candidates.addNamed(m)
			}
		}
	}
	return participantSets{}, fmt.Sprintf(
		"the participant set was still growing after %d rounds of peer membership",
		hostSetClosureRounds), nil
}

// participantsThatNeverAnswered is THE ANSWERED-DISCOVERY GATE: no host may be
// returned in ANY set unless membership discovery actually read its view. It
// returns the operator-facing reason, or "" when every participant has spoken.
//
// WHY IT IS NOT REDUNDANT, WRITTEN DOWN BECAUSE IT WAS DECLINED ONCE AS EXACTLY
// THAT. The redundancy argument is that the closure returns only when every
// discovery target has answered, so a returned host must have been asked. That
// argument is about the EXCLUSIONS, not about the closure: it holds only while
// the three sets have identical membership. The moment one set excludes a host
// another set returns, a participant appears in an output that discovery never
// read — and that is a reproduction, not a hypothetical. With power-off evidence
// applied to discovery, a host attested off was dropped from the fan-out, a
// rejoin a moment later put it back into the derived set, and the closure
// returned success naming a peer whose membership RPC would have answered
// Unimplemented. This gate catches that INDEPENDENTLY of which exclusion is
// applied where, and independently of whether the two derivations sampled the
// same instant.
//
// So: do NOT remove it again on the grounds that the current exclusions make it
// unreachable. That condition is precisely what it exists to keep true, and it
// costs one pass over two short slices.
//
// This node is exempt, and only this node: it answers for itself out of its own
// database and is never dialled. AN ANSWER IS THE ONLY THING THIS ACCEPTS.
// There is no grant, manifest or attestation that can stand in for one — the
// prerelease permanent-loss exception that could is gone, and its absence is
// what makes the gate's subject and the dial decision's subject the same
// question again.
func (s *Server) participantsThatNeverAnswered(sets participantSets, asked map[string]bool) string {
	for _, set := range [][]string{sets.corroborating, sets.runtime} {
		for _, h := range set {
			if h == s.hostName || asked[h] {
				continue
			}
			return fmt.Sprintf(
				"host %s is in the participant set without having answered membership "+
					"discovery, so the hosts and rows it knows of were never read", h)
		}
	}
	return ""
}

// peerMembership is one participant's answer to "which hosts do you know of".
type peerMembership struct {
	host string
	// rows is every `hosts` row that participant holds, TOMBSTONES INCLUDED.
	rows []hostRoleRow
	// gossip is every host that participant's memberlist names. It excludes the
	// participant itself, and is legitimately empty on a node without gossip.
	gossip []string
	// unproven is the operator-facing reason its view could not be established.
	// Non-empty means the participant set cannot be closed at all: it is not one
	// participant's problem, it is the proof's.
	unproven string
}

// gatherMembershipViews reads each participant's membership view over the
// bounded worker pool and per-peer timeout the rest of the proof fan-out already
// uses.
func (s *Server) gatherMembershipViews(ctx context.Context, peers []string) []peerMembership {
	views := make([]peerMembership, len(peers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, orphanProofWorkers)
	for i, h := range peers {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			views[i] = s.membershipViewOf(ctx, h)
		}(i, h)
	}
	wg.Wait()
	return views
}

// membershipViewOf reads ONE participant's membership view over
// GetMembershipView. See closedParticipantSets for why every failure — including
// an older peer's Unimplemented — leaves the set unclosable.
//
// The answer is keyed by the host that was ASKED and never by the host the
// response names, the same rule gatherOrphanProofs follows: a peer that answered
// with someone else's name would otherwise fill that host's slot and let the
// real one go unasked.
func (s *Server) membershipViewOf(ctx context.Context, host string) peerMembership {
	v := peerMembership{host: host}
	unproven := func(format string, args ...any) peerMembership {
		v.unproven = fmt.Sprintf(format, args...)
		return v
	}
	pctx, cancel := context.WithTimeout(ctx, orphanProofTimeout)
	defer cancel()

	client, closeConn, derr := s.dialPeer(pctx, host)
	if derr != nil {
		return unproven("host %s could not be asked which hosts it knows (%v)", host, derr)
	}
	defer closeConn()

	resp, rerr := client.GetMembershipView(pctx, &emptypb.Empty{})
	if rerr != nil {
		if status.Code(rerr) == codes.Unimplemented {
			// An older build with no membership view to report. Named as such
			// rather than folded into the transport failure above, because the
			// repair is an upgrade and not a network: this is the whole of the
			// mixed-version story, and a definite failure is a refusal.
			return unproven("host %s runs a build that cannot report its membership view "+
				"(%v), so the hosts it knows of cannot be read", host, rerr)
		}
		return unproven("host %s could not be asked which hosts it knows (%v)", host, rerr)
	}
	if !resp.GetComplete() {
		return unproven("host %s could not enumerate the hosts it knows of (%v)",
			host, resp.GetErrors())
	}
	if len(resp.GetHosts()) == 0 {
		// A node holds at least its own row, so an answer naming no rows is an
		// unhydrated database — never the claim that the cluster is empty. This
		// is the caller's backstop for a response that claims completeness with
		// nothing in it; the responder refuses the same shape itself.
		return unproven("host %s reported no `hosts` rows at all, so its own table "+
			"cannot have been read whole", host)
	}
	for _, h := range resp.GetHosts() {
		if h.GetName() == "" {
			// A row that names no host cannot be asked, and skipping it would
			// silently shorten this peer's membership.
			return unproven("host %s reported a `hosts` row with an empty name, so its "+
				"membership cannot be read whole", host)
		}
		v.rows = append(v.rows, hostRoleRow{name: h.GetName(), role: h.GetRole()})
	}
	for _, m := range resp.GetGossipMembers() {
		if m == "" {
			return unproven("host %s named a gossip member with an empty name, so its "+
				"membership cannot be read whole", host)
		}
		v.gossip = append(v.gossip, m)
	}
	return v
}

// closedRuntimeProofSet is the RUNTIME-PROOF SET out of one closure: the hosts
// the orphan sweeper must have a complete negative scan from, this node included.
//
// Named after the set it returns rather than after "the proof set", because the
// generic name is what let the bind's digest check be pointed at this one: the
// two accessors read identically at a call site while asking hosts that have
// different things to offer. A witness belongs in the corroboration set and not
// in this one.
func (s *Server) closedRuntimeProofSet(ctx context.Context) ([]string, string, error) {
	sets, unclosed, err := s.closedParticipantSets(ctx)
	if err != nil || unclosed != "" {
		return nil, unclosed, err
	}
	return sets.runtime, "", nil
}

// closedInventoryCorroborationPeers is the INVENTORY-CORROBORATION SET out of one
// closure, WITHOUT this node — the hosts whose address-bearing tables the bind
// must find in agreement with its own before it goes live. This node is dropped
// because it is the side every comparison is made FROM, not a participant in it.
//
// WITNESSES ARE IN, and that is this accessor's whole reason to exist separately
// from closedRuntimeProofSet: a witness holds the replicated rows and hosts no
// workload, so it is authoritative about inventory and useless for a scan. The
// bind reading the runtime set meant a witness's unique VM and NIC rows were
// never consulted.
//
// It carries the WHOLE of the membership closure, not a subset of it: the bind
// reaches a peer set only through here, so the corroboration the sweeper requires
// to reclaim is the same the bind requires to go live. A second route into the
// participant universe is how the two proofs came to differ in the first place.
func (s *Server) closedInventoryCorroborationPeers(ctx context.Context) ([]string, string, error) {
	sets, unclosed, err := s.closedParticipantSets(ctx)
	if err != nil || unclosed != "" {
		return nil, unclosed, err
	}
	var peers []string
	for _, h := range sets.corroborating {
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
//
// It is sampled ONCE PER CLOSURE, by snapshotPowerOffEvidence, and it is
// admissible in ONE SET: the runtime-proof set. Two callers evaluating this for
// themselves is the defect that returned a participant nobody had asked.
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
