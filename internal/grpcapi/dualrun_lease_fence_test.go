package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A detector pass has no wall-clock bound but its leadership lease does. The
// self probe is unbounded — ListDomains, DomainState and DumpXML take no
// context — so a leader wedged on hung storage can outlive its own lease by
// minutes and then finish its pass against a snapshot gathered before the
// stall.
//
// That stale pass still writes. The conditions it writes are admission-gating
// and have no operator force-clear, so a stalled EX-leader can resolve a
// dual-run its successor confirmed, emit "resolved: two consecutive complete
// clean scans", and re-open admission to a host that is actively
// split-brained.
//
// Leadership must therefore be re-asserted AFTER the gather and before acting
// on it — the same shape as the coordinator's post-fence lease re-check.
// AcquireLeaseWithTerm already gives the right answer: a lease that lapsed and
// was re-taken, even by its own prior holder, is a NEW tenure with a new term,
// because the lapse is exactly the window in which others were entitled to act.
func TestDualRun_StalePassCannotResolveAfterLosingTheLease(t *testing.T) {
	s := dualRunTestServer(t, 2)
	s.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.OwnerEpochV1: true}})
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "running")

	// Pass 1 + 2: confirm a dual-run. vmA is an active disk-holder on both.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	s.acquireDualRunLease(ctx, time.Minute)
	s.detectDualRunPass(ctx)
	s.acquireDualRunLease(ctx, time.Minute)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("fixture inert: the dual-run was never confirmed")
	}

	// Now this node stalls. Its gather returns a CLEAN snapshot (taken before
	// the stall), and while it is gathering, a successor takes the lease.
	s.gatherRuntimeOverride = func(_ context.Context, hosts []string) (map[string]runtimeSnapshot, []string, []string) {
		// The successor's tenure begins mid-gather.
		if _, _, err := corrosion.AcquireLeaseWithTerm(
			ctx, s.db, dualRunLeaseKey, "successor-host", 2*time.Minute,
			time.Now().Add(10*time.Minute)); err != nil {
			t.Errorf("successor could not take the lease: %v", err)
		}
		return map[string]runtimeSnapshot{"h1": {}, "h2": {}}, nil, nil
	}

	s.acquireDualRunLease(ctx, time.Minute)
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)

	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("a stalled ex-leader resolved a confirmed dual-run from a snapshot taken " +
			"before it lost the lease; admission re-opens to a split-brained host and there " +
			"is no operator force-clear to undo it")
	}
}

// The detector still resolves normally while it genuinely holds the lease —
// the fence must not turn a working resolution path into one that never fires.
func TestDualRun_ResolutionStillWorksUnderAHeldLease(t *testing.T) {
	s := dualRunTestServer(t, 2)
	s.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.OwnerEpochV1: true}})
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "running")

	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	s.acquireDualRunLease(ctx, time.Minute)
	s.detectDualRunPass(ctx)
	s.acquireDualRunLease(ctx, time.Minute)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("fixture inert: never confirmed")
	}

	// The cause is genuinely gone and this node still holds the lease.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {},
	})
	for i := 0; i < conditionCleanScans+1; i++ {
		s.acquireDualRunLease(ctx, time.Minute)
		s.detectDualRunPass(ctx)
	}

	if confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("a genuinely clean scan under a held lease failed to resolve the condition")
	}
}

// If the lease cannot be RE-READ at all, the pass must be discarded. Failing
// open here would reintroduce the whole finding through the one path most
// likely to coincide with it: the same storage stall that wedged the probe is
// what makes the lease read fail.
//
// Discarding a pass costs one interval; applying a stale one re-opens
// admission to a split-brain with no operator force-clear.
func TestDualRun_UnreadableLeaseDiscardsThePass(t *testing.T) {
	s := dualRunTestServer(t, 2)
	s.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.OwnerEpochV1: true}})
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "running")

	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
		"h2": {diskHolderVMs: []string{"vmA"}},
	})
	s.acquireDualRunLease(ctx, time.Minute)
	s.detectDualRunPass(ctx)
	s.acquireDualRunLease(ctx, time.Minute)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("fixture inert: never confirmed")
	}

	// A clean gather, but the lease is now unreadable.
	s.gatherRuntimeOverride = func(_ context.Context, _ []string) (map[string]runtimeSnapshot, []string, []string) {
		if err := s.db.Execute(ctx, `DROP TABLE IF EXISTS leader_election`); err != nil {
			t.Errorf("drop leader_election: %v", err)
		}
		return map[string]runtimeSnapshot{"h1": {}, "h2": {}}, nil, nil
	}
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)

	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("a pass whose lease could not be re-read still resolved a confirmed dual-run; " +
			"the re-assert must fail closed")
	}
}
