package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
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

// boundCtx returns a context for a principal actually BOUND to role at "/",
// with the auth engine loaded — the only shape in which RequirePerm consults
// RBAC at all.
//
// The existing positive tests here use adminCtx(), whose principal holds no
// bindings, so HasAnyBinding is false and RequirePerm silently takes its
// legacy RequireRole("operator") fallback. Every one of them passed while the
// handler was gated on a verb no builtin role below Admin held: the RBAC path
// they are meant to cover was never entered. A bound principal is what makes
// the grant load-bearing.
func boundCtx(t *testing.T, s *Server, user, legacyRole, role string) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, user, legacyRole, "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: user + "-root", Path: "/", Role: role,
		Principal: "user:" + user + "@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)

	out := context.WithValue(context.Background(), ctxKeyUsername, user)
	return context.WithValue(out, ctxKeyRole, legacyRole)
}

// TestAcknowledgeLeaseTermTie_ABoundOperatorMayAcknowledge is the test the
// handler's doc comment has been claiming since Task 0c: "an operator
// acknowledges on each host".
//
// It is the whole reason cluster.lww.acknowledge exists. Drop that verb from
// Operator and this fails with PermissionDenied — which is precisely what
// every RBAC cluster did while the gate read cluster.update, leaving the
// ha.lww.unresolved condition with a documented remedy no operator could run.
func TestAcknowledgeLeaseTermTie_ABoundOperatorMayAcknowledge(t *testing.T) {
	s := contestedTermNode(t)
	ctx := boundCtx(t, s, "olive", "operator", "Operator")

	resp, err := s.AcknowledgeLeaseTermTie(ctx, &pb.AcknowledgeLeaseTermTieRequest{
		Key: corrosion.LeaseKeyFailover, Term: 1,
	})
	if err != nil {
		t.Fatalf("a bound Operator could not acknowledge the tie the health condition "+
			"tells them to acknowledge: %v", err)
	}
	if !resp.GetAcknowledged() {
		t.Error("acknowledged = false; the fixture holds a real tracked tie")
	}
	if n := s.db.UnresolvedTieCount(); n != 0 {
		t.Errorf("unresolved ties = %d, want 0 — the register did not clear", n)
	}
}

// TestAcknowledgeLeaseTermTie_ABoundViewerMayNot keeps the new verb narrow in
// the direction that matters: read-only roles carry "*.read", which matches by
// suffix, so a verb named e.g. cluster.lww.read would have handed silencing
// power to every Viewer and Auditor in the cluster.
func TestAcknowledgeLeaseTermTie_ABoundViewerMayNot(t *testing.T) {
	s := contestedTermNode(t)
	ctx := boundCtx(t, s, "vera", "viewer", "Viewer")

	_, err := s.AcknowledgeLeaseTermTie(ctx, &pb.AcknowledgeLeaseTermTieRequest{
		Key: corrosion.LeaseKeyFailover, Term: 1,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if n := s.db.UnresolvedTieCount(); n != 1 {
		t.Errorf("unresolved ties = %d, want 1 — a denied call cleared the register", n)
	}
}

// twoTermLedger seeds a ledger whose newest live term is 2, held by node-b,
// through the REAL allocator rather than by inserting rows.
//
// node-b's acquisition is dated past node-a's expiry, which is what makes it a
// new tenure and mints term 2 — AcquireLeaseWithTerm treats a lapsed lease as a
// new tenure even for its own prior holder, because the lapse is exactly the
// window other nodes were entitled to act in. Hand-inserted rows would assert
// against a shape that can drift from that.
func twoTermLedger(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	ttl := 30 * time.Second

	if held, term, err := corrosion.AcquireLeaseWithTerm(
		ctx, s.db, corrosion.LeaseKeyFailover, "node-a", ttl, now); err != nil || !held || term != 1 {
		t.Fatalf("node-a acquire: held=%v term=%d err=%v", held, term, err)
	}
	if held, term, err := corrosion.AcquireLeaseWithTerm(
		ctx, s.db, corrosion.LeaseKeyFailover, "node-b", ttl, now.Add(2*ttl)); err != nil || !held || term != 2 {
		t.Fatalf("node-b acquire: held=%v term=%d err=%v", held, term, err)
	}
}

// TestGetLeaseTermHighWater_AnswersFromTheLocalLedger.
func TestGetLeaseTermHighWater_AnswersFromTheLocalLedger(t *testing.T) {
	s, _ := cleanAdvertisingNode(t)
	twoTermLedger(t, s)

	resp, err := s.GetLeaseTermHighWater(peerCtxFor(t, s, "host-peer"),
		&pb.GetLeaseTermHighWaterRequest{Key: corrosion.LeaseKeyFailover})
	if err != nil {
		t.Fatalf("rpc: %v", err)
	}
	if resp.GetKey() != corrosion.LeaseKeyFailover {
		t.Errorf("key = %q, want %q — the caller matches on it to detect a peer answering "+
			"about a different ledger", resp.GetKey(), corrosion.LeaseKeyFailover)
	}
	if resp.GetTerm() != 2 || resp.GetHolder() != "node-b" {
		t.Errorf("= (%d, %q), want (2, node-b)", resp.GetTerm(), resp.GetHolder())
	}
}

// TestGetLeaseTermHighWater_EmptyLedgerIsZeroNotAnError: a node that has never
// recorded a term answers 0 with no holder. That is a legitimate answer and
// counts toward quorum; an error would not, and would leave every fresh cluster
// unable to establish a threshold at all.
func TestGetLeaseTermHighWater_EmptyLedgerIsZeroNotAnError(t *testing.T) {
	s, _ := cleanAdvertisingNode(t)
	resp, err := s.GetLeaseTermHighWater(peerCtxFor(t, s, "host-peer"),
		&pb.GetLeaseTermHighWaterRequest{Key: corrosion.LeaseKeyFailover})
	if err != nil {
		t.Fatalf("rpc: %v", err)
	}
	if resp.GetTerm() != 0 || resp.GetHolder() != "" {
		t.Errorf("= (%d, %q), want (0, \"\")", resp.GetTerm(), resp.GetHolder())
	}
}

// TestGetLeaseTermHighWater_AnswersAboutEveryRealLease: the key selects which
// ledger answers, and all three are real. A handler that knew only the failover
// key would answer term 0 for a rebalancer proof, and 0 is the sentinel meaning
// "no term recorded" — so the barrier would read a live rebalancer tenure as
// absent.
func TestGetLeaseTermHighWater_AnswersAboutEveryRealLease(t *testing.T) {
	s, _ := cleanAdvertisingNode(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	// Once, outside the loop: peerCtxFor registers the peer host, and a second
	// call collides on hosts.name.
	peer := peerCtxFor(t, s, "host-peer")

	for _, key := range []string{
		corrosion.LeaseKeyFailover, corrosion.LeaseKeyRebalancer, corrosion.LeaseKeyDualRun,
	} {
		if held, term, err := corrosion.AcquireLeaseWithTerm(
			ctx, s.db, key, "node-a", 30*time.Second, now); err != nil || !held || term != 1 {
			t.Fatalf("%s acquire: held=%v term=%d err=%v", key, held, term, err)
		}
		resp, err := s.GetLeaseTermHighWater(peer, &pb.GetLeaseTermHighWaterRequest{Key: key})
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if resp.GetTerm() != 1 || resp.GetHolder() != "node-a" {
			t.Errorf("%s = (%d, %q), want (1, node-a)", key, resp.GetTerm(), resp.GetHolder())
		}
	}
}

// TestGetLeaseTermHighWater_RejectsAnUnknownKey: accepting an arbitrary string
// lets a caller choose which ledger a fencing decision consults, and the key
// reaches a metric label, where unbounded peer-supplied input is what the
// repo's bounded-label discipline exists to prevent.
func TestGetLeaseTermHighWater_RejectsAnUnknownKey(t *testing.T) {
	s, _ := cleanAdvertisingNode(t)
	peer := peerCtxFor(t, s, "host-peer")
	for _, key := range []string{"../etc/passwd", "", "failover ", "FAILOVER"} {
		_, err := s.GetLeaseTermHighWater(peer, &pb.GetLeaseTermHighWaterRequest{Key: key})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("key %q: code = %v, want InvalidArgument", key, status.Code(err))
		}
	}
}

// TestGetLeaseTermHighWater_RequiresAPeerOrOperator: it reads replicated
// cluster state and is the input to a fencing decision.
func TestGetLeaseTermHighWater_RequiresAPeerOrOperator(t *testing.T) {
	s, _ := cleanAdvertisingNode(t)
	_, err := s.GetLeaseTermHighWater(context.Background(),
		&pb.GetLeaseTermHighWaterRequest{Key: corrosion.LeaseKeyFailover})
	if err == nil {
		t.Fatal("answered an unauthenticated caller")
	}
	if c := status.Code(err); c != codes.Unauthenticated && c != codes.PermissionDenied {
		t.Errorf("code = %v, want Unauthenticated or PermissionDenied", c)
	}
}

// TestGetLeaseTermHighWater_AnUnreadableLedgerIsNotAgreementAtZero.
//
// The distinction is the whole point of the barrier. 0 means "no term
// recorded", which is a real answer that counts toward quorum; a failed read
// means this node does not know, and reporting it as 0 would let a stale
// threshold be computed from nodes that never answered.
func TestGetLeaseTermHighWater_AnUnreadableLedgerIsNotAgreementAtZero(t *testing.T) {
	s, _ := cleanAdvertisingNode(t)
	if err := s.db.Execute(context.Background(), `DROP TABLE leader_lease_terms`); err != nil {
		t.Fatalf("drop ledger: %v", err)
	}
	_, err := s.GetLeaseTermHighWater(peerCtxFor(t, s, "host-peer"),
		&pb.GetLeaseTermHighWaterRequest{Key: corrosion.LeaseKeyFailover})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable — a node that cannot read its ledger must not "+
			"be counted as agreeing at term 0", status.Code(err))
	}
}
