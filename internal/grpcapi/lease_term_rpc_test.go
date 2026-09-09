package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// contestedTermNode returns a node holding a REAL contested lease term: it and
// a peer each minted term 1 for the failover lease, and anti-entropy has merged
// the peer's claim in.
//
// Built through the merge rather than by inserting a register entry by hand,
// because the PK spelling under test is whatever the merge produced — a
// hand-built one would keep passing the day that encoding changed.
func contestedTermNode(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	s, _ := cleanAdvertisingNode(t)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	if held, term, err := corrosion.AcquireLeaseWithTerm(ctx, s.db, corrosion.LeaseKeyFailover, s.hostName, 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("local acquire: held=%v term=%d err=%v", held, term, err)
	}
	peer := peerClient(t)
	if held, term, err := corrosion.AcquireLeaseWithTerm(ctx, peer, corrosion.LeaseKeyFailover, "host-peer", 30*time.Second, now); err != nil || !held || term != 1 {
		t.Fatalf("peer acquire: held=%v term=%d err=%v", held, term, err)
	}
	if err := s.db.MergeStateBytesLWW(peer.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy: %v", err)
	}
	if n := s.db.UnresolvedTieCount(); n != 1 {
		t.Fatalf("fixture produced %d ties, want 1 — every assertion would be vacuous", n)
	}
	return s
}

// ackAuditRows returns the (target, detail) of every lease-term-tie
// acknowledgement in the audit log, oldest first.
func ackAuditRows(t *testing.T, s *Server) [][2]string {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT target, detail FROM audit_log
		  WHERE action = 'cluster.lease_term_tie.acknowledge' ORDER BY timestamp, id`)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	out := make([][2]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, [2]string{r.String("target"), r.String("detail")})
	}
	return out
}

// TestAcknowledgeLeaseTermTie_ClearsTheRegisterAndAudits drives the handler
// against a REAL contested-term tie and checks the two things an operator
// depends on: the register clears, and the decision is recorded durably.
func TestAcknowledgeLeaseTermTie_ClearsTheRegisterAndAudits(t *testing.T) {
	s := contestedTermNode(t)

	resp, err := s.AcknowledgeLeaseTermTie(adminCtx(), &pb.AcknowledgeLeaseTermTieRequest{
		Key: corrosion.LeaseKeyFailover, Term: 1,
	})
	if err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if !resp.GetAcknowledged() {
		t.Error("handler reported nothing acknowledged for a tie that was tracked")
	}
	if n := s.db.UnresolvedTieCount(); n != 0 {
		t.Errorf("register still holds %d tie(s)", n)
	}

	// The in-memory record is replaced by a durable one, or the acknowledgement
	// leaves no trace of who silenced a split-brain signal.
	audits := ackAuditRows(t, s)
	if len(audits) != 1 {
		t.Fatalf("audit rows = %d, want exactly 1 naming the key and term", len(audits))
	}
	if got := audits[0][0]; got != "failover:1" {
		t.Errorf("audit target = %q, want %q", got, "failover:1")
	}
}

// TestAcknowledgeLeaseTermTie_ARetryReAuditsSoALostRecordIsRepairable pins a
// deliberate reversal: a retry DOES write a second audit row.
//
// The suppression is durable the moment the store call returns; the audit
// insert happens after it and only warns when it fails. Auditing on "something
// was cleared" alone therefore made a lost record permanent — the retry finds
// no tracked tie, answers false, and audits nothing, so a crash in that gap
// left a silenced conflict with nothing in the chain saying anyone looked at
// it, and no command able to repair it.
//
// A duplicate row naming one decision is noise an auditor reads past. A
// missing row is unrecoverable. Hence the trade, and hence the detail text
// distinguishing the two cases.
func TestAcknowledgeLeaseTermTie_ARetryReAuditsSoALostRecordIsRepairable(t *testing.T) {
	s := contestedTermNode(t)
	req := &pb.AcknowledgeLeaseTermTieRequest{Key: corrosion.LeaseKeyFailover, Term: 1}

	if _, err := s.AcknowledgeLeaseTermTie(adminCtx(), req); err != nil {
		t.Fatalf("first acknowledge: %v", err)
	}
	resp, err := s.AcknowledgeLeaseTermTie(adminCtx(), req)
	if err != nil {
		t.Fatalf("retry must not error: %v", err)
	}
	if resp.GetAcknowledged() {
		t.Error("the retry reported clearing something; the first call already cleared it")
	}

	audits := ackAuditRows(t, s)
	if len(audits) != 2 {
		t.Fatalf("audit rows = %d, want 2: the retry must record the acknowledgement it found, "+
			"or an audit insert lost to a crash can never be repaired", len(audits))
	}
	if !strings.Contains(audits[1][1], "reaffirmed") {
		t.Errorf("the retry's audit detail = %q; it must say it cleared nothing, so an auditor "+
			"can tell one operator decision recorded twice from two decisions", audits[1][1])
	}
}

// TestAcknowledgeLeaseTermTie_AnUntrackedTermIsANoOpAndUnaudited: a term this
// node holds no tie and no acknowledgement for must not error and must not
// write a record of a decision nobody made. This is the boundary of the
// re-audit behaviour above — that repairs a record for an acknowledgement that
// EXISTS; it must not invent one.
func TestAcknowledgeLeaseTermTie_AnUntrackedTermIsANoOpAndUnaudited(t *testing.T) {
	ctx := context.Background()
	s, _ := cleanAdvertisingNode(t)

	// Nothing tracked at all: false, no error, no audit row.
	resp, err := s.AcknowledgeLeaseTermTie(adminCtx(), &pb.AcknowledgeLeaseTermTieRequest{
		Key: corrosion.LeaseKeyFailover, Term: 7,
	})
	if err != nil {
		t.Fatalf("acknowledging an untracked term must not error: %v", err)
	}
	if resp.GetAcknowledged() {
		t.Error("reported acknowledging a tie that was never tracked")
	}
	rows, _ := s.db.Query(ctx,
		`SELECT id FROM audit_log WHERE action = 'cluster.lease_term_tie.acknowledge'`)
	if len(rows) != 0 {
		t.Errorf("a no-op acknowledgement wrote %d audit row(s); the log would fill with "+
			"records of decisions nobody made", len(rows))
	}
}

// TestAcknowledgeLeaseTermTie_RejectsMalformedInput. The key is validated against
// the closed set and the term against what allocation can produce, so the
// handler cannot be used to probe or to acknowledge something meaningless.
func TestAcknowledgeLeaseTermTie_RejectsMalformedInput(t *testing.T) {
	s, _ := cleanAdvertisingNode(t)

	for _, tc := range []struct {
		name string
		req  *pb.AcknowledgeLeaseTermTieRequest
	}{
		{"unknown key", &pb.AcknowledgeLeaseTermTieRequest{Key: "not_a_lease", Term: 1}},
		{"empty key", &pb.AcknowledgeLeaseTermTieRequest{Key: "", Term: 1}},
		{"term zero", &pb.AcknowledgeLeaseTermTieRequest{Key: corrosion.LeaseKeyFailover, Term: 0}},
		{"negative term", &pb.AcknowledgeLeaseTermTieRequest{Key: corrosion.LeaseKeyFailover, Term: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.AcknowledgeLeaseTermTie(adminCtx(), tc.req); status.Code(err) != codes.InvalidArgument {
				t.Errorf("code = %v, want InvalidArgument", status.Code(err))
			}
		})
	}
}

// TestAcknowledgeLeaseTermTie_IsNotPeerCallable pins the authority boundary the
// handler's doc comment claims. A node must never be able to acknowledge its own
// contested term: the whole value of the signal is that a second party saw it.
//
// requirePeerOrRole would have been the wrong gate here — it is for dual-use
// RPCs that peers legitimately invoke — so this asserts the peer path is refused
// rather than merely that an operator is accepted.
func TestAcknowledgeLeaseTermTie_IsNotPeerCallable(t *testing.T) {
	s, _ := cleanAdvertisingNode(t)
	peerCtx := peerCtxFor(t, s, "host-peer")

	_, err := s.AcknowledgeLeaseTermTie(peerCtx, &pb.AcknowledgeLeaseTermTieRequest{
		Key: corrosion.LeaseKeyFailover, Term: 1,
	})
	if err == nil {
		t.Fatal("a cluster peer acknowledged a contested lease term; a node must not be able " +
			"to silence its own split-brain evidence")
	}
	if c := status.Code(err); c != codes.Unauthenticated && c != codes.PermissionDenied {
		t.Errorf("code = %v, want Unauthenticated or PermissionDenied", c)
	}
}
