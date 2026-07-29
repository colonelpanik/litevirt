package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A reservation must be released even when the request context is already dead.
//
// Found on the lab, not by the fleet tests: a successful VM migration left its
// reservation open forever. `MigrateVM` holds the lease across the whole transfer
// and releases it with `defer`, and by the time that defer runs the STREAM context
// is frequently already cancelled — the client has its result and has hung up. The
// release write then fails against a cancelled context and the capacity is held by
// nothing until the stale-lease sweep collects it up to an hour later.
//
// finalizeMigrationOwnership already knew this: it commits ownership on a detached
// context precisely "because the request context may already be cancelled after
// cutover". The lease release sat right next to it with the same exposure and no
// such protection.
//
// The fix belongs in release() rather than at the migrate call site, because the
// property is general — a release is cleanup, and cleanup that only runs when the
// caller is still listening is not cleanup. Every long-running admitted operation
// (migrate, a large restore) has the same shape.

func TestReservationLease_ReleasesUnderACancelledContext(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	admissionHost(t, s)

	lease, err := s.admitHostWithReservation(ctx, "MigrateVM", "test-host", "_default", 1, 1024)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if cpu, mem, rerr := corrosion.HostReserved(ctx, s.db, "test-host"); rerr != nil || cpu != 1 || mem != 1024 {
		t.Fatalf("after admit HostReserved = %d/%d (err=%v), want 1/1024", cpu, mem, rerr)
	}

	// The client has hung up — exactly the state a streaming migrate's deferred
	// release runs in.
	dead, cancel := context.WithCancel(ctx)
	cancel()

	lease.release(dead)

	cpu, mem, rerr := corrosion.HostReserved(ctx, s.db, "test-host")
	if rerr != nil {
		t.Fatalf("HostReserved: %v", rerr)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("after release under a cancelled context the host still holds %d vCPU/%d MiB; "+
			"a completed migration would hold capacity against nothing until the stale-lease "+
			"sweep runs, up to an hour later", cpu, mem)
	}
}
