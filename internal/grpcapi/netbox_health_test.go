package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// newNetBoxHealthServer is a bare server with a database and nothing else: the
// health evaluator reads replicated rows and writes replicated rows, so it
// needs no NetBox client and no libvirt.
func newNetBoxHealthServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{hostName: "test-host", db: db}
}

// netboxCondition finds one active condition by code and subject.
func netboxCondition(t *testing.T, s *Server, code, subject string) (corrosion.HealthCondition, bool) {
	t.Helper()
	all, err := corrosion.ListHealthConditions(context.Background(), s.db, true)
	if err != nil {
		t.Fatalf("ListHealthConditions: %v", err)
	}
	for _, h := range all {
		if h.Evaluator == netboxEvaluator && h.Code == code && h.SubjectID == subject {
			return h, true
		}
	}
	return corrosion.HealthCondition{}, false
}

func seedSuspendedBinding(t *testing.T, s *Server, prefixID int, network, reason string) {
	t.Helper()
	ctx := context.Background()
	ok, err := corrosion.ClaimBinding(ctx, s.db, corrosion.BindingRecord{
		PrefixID: prefixID, Network: network, ObservedCIDR: "10.0.5.0/24",
		VRFID: 7, ClusterFingerprint: "fp",
	})
	if err != nil || !ok {
		t.Fatalf("ClaimBinding %s: ok=%v err=%v", network, ok, err)
	}
	if reason != "" {
		if err := corrosion.SuspendBinding(ctx, s.db, prefixID, reason); err != nil {
			t.Fatalf("SuspendBinding %s: %v", network, err)
		}
	}
}

// TestNetBoxHealthRaisesBindingSuspended pins the finding a suspension would
// otherwise make invisible: suspension produces no error and disturbs no
// running workload, so without a health condition the first symptom is a create
// refusing, long after the fact.
func TestNetBoxHealthRaisesBindingSuspended(t *testing.T) {
	s := newNetBoxHealthServer(t)
	ctx := context.Background()
	seedSuspendedBinding(t, s, 11, "net-a", "prefix re-CIDRed from 10.0.5.0/24 to 10.0.5.0/25")
	seedSuspendedBinding(t, s, 12, "net-b", "")

	s.evaluateNetBoxHealth(ctx, 0)

	got, ok := netboxCondition(t, s, condNetBoxBindingSuspended, "net-a")
	if !ok {
		t.Fatal("a suspended binding raised no netbox_binding_suspended condition")
	}
	if got.Lifecycle != corrosion.ConditionObserved {
		t.Errorf("lifecycle = %q, want %q", got.Lifecycle, corrosion.ConditionObserved)
	}
	if got.SubjectKind != "network" {
		t.Errorf("subject_kind = %q, want %q", got.SubjectKind, "network")
	}
	if !strings.Contains(got.Evidence, "re-CIDRed") {
		t.Errorf("evidence %q does not name the suspension reason", got.Evidence)
	}
	if !strings.Contains(got.Evidence, "net-a") {
		t.Errorf("evidence %q does not name the network", got.Evidence)
	}
	if _, ok := netboxCondition(t, s, condNetBoxBindingSuspended, "net-b"); ok {
		t.Error("a healthy binding raised a condition")
	}
}

// TestNetBoxHealthBindingSuspendedConfirmsThenResolves pins both ends of the
// lifecycle: a second consecutive pass confirms, and only two consecutive clean
// passes resolve — an operator's `lv netbox resume` is proved, not assumed.
func TestNetBoxHealthBindingSuspendedConfirmsThenResolves(t *testing.T) {
	s := newNetBoxHealthServer(t)
	ctx := context.Background()
	seedSuspendedBinding(t, s, 11, "net-a", "VRF 7 no longer enforces uniqueness")

	s.evaluateNetBoxHealth(ctx, 0)
	s.evaluateNetBoxHealth(ctx, 0)
	got, ok := netboxCondition(t, s, condNetBoxBindingSuspended, "net-a")
	if !ok || got.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("after two positive passes lifecycle = %q (present=%v), want %q",
			got.Lifecycle, ok, corrosion.ConditionConfirmed)
	}

	// Operator repaired NetBox and resumed the binding.
	if err := corrosion.UpsertBinding(ctx, s.db, corrosion.BindingRecord{
		PrefixID: 11, Network: "net-a", ObservedCIDR: "10.0.5.0/24",
		VRFID: 7, ClusterFingerprint: "fp",
	}); err != nil {
		t.Fatalf("UpsertBinding: %v", err)
	}

	s.evaluateNetBoxHealth(ctx, 0)
	got, _ = netboxCondition(t, s, condNetBoxBindingSuspended, "net-a")
	if got.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("one clean pass resolved the condition; two are required")
	}
	s.evaluateNetBoxHealth(ctx, 0)
	got, _ = netboxCondition(t, s, condNetBoxBindingSuspended, "net-a")
	if got.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("after two clean passes lifecycle = %q, want %q", got.Lifecycle, corrosion.ConditionResolved)
	}
}

// TestNetBoxHealthSweepBlockedNeedsThreeConsecutivePasses pins the threshold. A
// single unreachable host is ordinary — a reboot, a restart — and raising on it
// would make the finding noise. Three consecutive passes is a host that is not
// coming back on its own, and while it is away NOTHING can be reclaimed.
func TestNetBoxHealthSweepBlockedNeedsThreeConsecutivePasses(t *testing.T) {
	s := newNetBoxHealthServer(t)
	ctx := context.Background()

	for pass := 1; pass <= 2; pass++ {
		s.beginSweepPass()
		s.noteSweepSkip(skipUnreachable)
		s.evaluateNetBoxHealth(ctx, s.closeSweepPass())
		if _, ok := netboxCondition(t, s, condNetBoxSweepBlocked, netboxSweepSubject); ok {
			t.Fatalf("pass %d raised netbox_sweep_blocked before the threshold", pass)
		}
	}

	s.beginSweepPass()
	s.noteSweepSkip(skipUnreachable)
	s.evaluateNetBoxHealth(ctx, s.closeSweepPass())
	got, ok := netboxCondition(t, s, condNetBoxSweepBlocked, netboxSweepSubject)
	if !ok {
		t.Fatal("three consecutive unreachable-blocked sweeps raised no condition")
	}
	if got.Lifecycle != corrosion.ConditionObserved {
		t.Errorf("lifecycle = %q, want %q", got.Lifecycle, corrosion.ConditionObserved)
	}
	if !strings.Contains(got.Evidence, "3") {
		t.Errorf("evidence %q does not carry the streak length", got.Evidence)
	}
}

// TestNetBoxHealthSweepBlockedStreakResetsOnACleanPass pins that the streak is
// CONSECUTIVE. Counting cumulatively would raise the finding on any three
// unreachable moments in the cluster's life, which says nothing about now.
func TestNetBoxHealthSweepBlockedStreakResetsOnACleanPass(t *testing.T) {
	s := newNetBoxHealthServer(t)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		s.beginSweepPass()
		s.noteSweepSkip(skipUnreachable)
		s.closeSweepPass()
	}
	// A pass that skipped for an unrelated reason is NOT an unreachable pass.
	s.beginSweepPass()
	s.noteSweepSkip(skipHostHolds)
	if streak := s.closeSweepPass(); streak != 0 {
		t.Fatalf("a clean pass left the streak at %d, want 0", streak)
	}
	s.beginSweepPass()
	s.noteSweepSkip(skipUnreachable)
	s.evaluateNetBoxHealth(ctx, s.closeSweepPass())
	if _, ok := netboxCondition(t, s, condNetBoxSweepBlocked, netboxSweepSubject); ok {
		t.Fatal("the streak survived a clean pass")
	}
}

// TestNetBoxHealthSweepBlockedResolves pins that the finding clears once the
// sweep can complete again — two clean passes, the same proof the suspension
// condition requires.
func TestNetBoxHealthSweepBlockedResolves(t *testing.T) {
	s := newNetBoxHealthServer(t)
	ctx := context.Background()

	for i := 0; i < netboxSweepBlockedPasses; i++ {
		s.beginSweepPass()
		s.noteSweepSkip(skipUnreachable)
		s.evaluateNetBoxHealth(ctx, s.closeSweepPass())
	}
	if _, ok := netboxCondition(t, s, condNetBoxSweepBlocked, netboxSweepSubject); !ok {
		t.Fatal("condition was never raised")
	}

	for i := 0; i < netboxCleanPasses; i++ {
		s.beginSweepPass()
		s.evaluateNetBoxHealth(ctx, s.closeSweepPass())
	}
	got, _ := netboxCondition(t, s, condNetBoxSweepBlocked, netboxSweepSubject)
	if got.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("lifecycle = %q, want %q", got.Lifecycle, corrosion.ConditionResolved)
	}
}

// TestNetBoxHealthWritesNoEvaluatorStatus pins a deliberate omission. The
// maintenance cadence (15 minutes by default) is three times the evaluator
// staleness TTL, so a `netbox` row in health_evaluator_status would report the
// evaluator STALE almost all the time and pin every NetBox cluster at DEGRADED
// forever. The conditions are durable on their own; the status row is not.
func TestNetBoxHealthWritesNoEvaluatorStatus(t *testing.T) {
	s := newNetBoxHealthServer(t)
	ctx := context.Background()
	seedSuspendedBinding(t, s, 11, "net-a", "prefix moved to the global table")
	s.evaluateNetBoxHealth(ctx, 0)

	evals, err := corrosion.ListHealthEvaluatorStatus(ctx, s.db)
	if err != nil {
		t.Fatalf("ListHealthEvaluatorStatus: %v", err)
	}
	for _, e := range evals {
		if e.Evaluator == netboxEvaluator {
			t.Fatalf("the netbox evaluator wrote a status row (%+v); it must not", e)
		}
	}
}
