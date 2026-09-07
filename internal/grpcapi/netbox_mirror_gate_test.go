package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netboxsync"
)

// The inventory mirror's capability gate, at the wiring level.
//
// The mirror's two tables — `netbox_objects` and `netbox_sync_queue` — are in
// neither ledger of a build that predates them, and the LWW apply path
// back-pressures on a statement it cannot place, stalling the replication
// watermark for the entire stream. So both producers are gated on the SAME
// cluster-wide latch that gates a prefix binding, and on the DURABLE form of
// it: a latch held only in memory does not survive the restart during which an
// old peer is still running.

// mirrorLeaseHolder reports who holds the `netbox` leader lease, or "".
//
// It is the crispest observable for "did the pass get past the gate?": SyncOnce
// acquires the lease before it does anything else, and that acquire is itself a
// replicated write. A gate that refuses AFTER it would already have written.
func mirrorLeaseHolder(t *testing.T, s *Server) string {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT holder FROM leader_election WHERE key = ?`, netBoxLeaseKey)
	if err != nil {
		t.Fatalf("read leader_election: %v", err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].String("holder")
}

// queuedMirrorItems counts the mirror's un-acked queue rows.
func queuedMirrorItems(t *testing.T, s *Server) int {
	t.Helper()
	items, err := corrosion.DrainSyncQueue(context.Background(), s.db, netboxsync.QueueKind, 50)
	if err != nil {
		t.Fatalf("DrainSyncQueue: %v", err)
	}
	return len(items)
}

// TestMirrorPassTakesNoLeaseWithoutTheLatch pins the gate ahead of the acquire.
//
// A node configured for NetBox ahead of its peers must reach the end of a pass
// having written NOTHING — not an object, not a queue row, and not the lease
// row it would have taken to become the writer.
func TestMirrorPassTakesNoLeaseWithoutTheLatch(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{})
	s.SetGate(fakeServerGate{enforced: false})
	ctx := context.Background()

	if err := s.RunNetBoxMirrorOnce(ctx); err != nil {
		t.Fatalf("an ungated pass must decline quietly, not error: %v", err)
	}
	if got := mirrorLeaseHolder(t, s); got != "" {
		t.Fatalf("an unlatched node took the netbox leader lease (holder %q)", got)
	}

	// The positive control. With the latch closed the same pass DOES take the
	// lease — without this, the assertion above is satisfied by a mirror that is
	// broken for some entirely different reason.
	//
	// The pass then fails against this minimal NetBox fake, which is irrelevant
	// here: the lease row is written before the first NetBox call, so its
	// presence already proves the gate let the pass through.
	s.SetGate(fakeServerGate{enforced: true})
	_ = s.RunNetBoxMirrorOnce(ctx)
	if got := mirrorLeaseHolder(t, s); got != s.hostName {
		t.Fatalf("a latched node must take the lease, holder = %q want %q", got, s.hostName)
	}
}

// TestMirrorRefusesAnInMemoryOnlyLatch pins the DURABLE form.
//
// Latched and DurablyLatched differ exactly where it matters: a node that
// latched in memory can restart, reload no marker, and come back believing the
// contract never formed. During a rolling upgrade that is the same node an old
// peer is still replicating with. Binding a prefix already gates on the durable
// form for this reason; the mirror writes replicated statements, so it must
// too.
func TestMirrorRefusesAnInMemoryOnlyLatch(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{})
	s.SetGate(fakeServerGate{
		enforced: true, // Latched(netbox_ipam_v1) is TRUE…
		durablyLatchedTok: map[string]bool{
			capabilities.NetBoxIPAMV1: false,
			// The mirror's own token IS durable here, so the only thing this
			// scenario withholds is netbox_ipam_v1's marker. Left out, the map's
			// zero value would withhold both and the refusal below would no longer
			// say which contract produced it.
			capabilities.NetBoxMirrorV1: true,
		},
	}) // …but the marker was never persisted.
	ctx := context.Background()

	if err := s.RunNetBoxMirrorOnce(ctx); err != nil {
		t.Fatalf("a pass gated on a non-durable latch must decline quietly: %v", err)
	}
	if got := mirrorLeaseHolder(t, s); got != "" {
		t.Fatalf("a latch held only in memory authorized a sweep (lease holder %q)", got)
	}

	s.enqueueMirrorSync(ctx, "vm-1", mirrorOpUpsert)
	if got := queuedMirrorItems(t, s); got != 0 {
		t.Fatalf("a latch held only in memory authorized %d queue row(s)", got)
	}
}

// TestEnqueueMirrorSyncRequiresTheLatch is the enqueue half on its own.
//
// It is a separate producer on a separate code path — every VM delete, rename
// and migration calls it — so a gate on the sweep alone would still put
// `netbox_sync_queue` statements on the wire from a single upgraded node.
func TestEnqueueMirrorSyncRequiresTheLatch(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{})
	s.SetGate(fakeServerGate{enforced: false})
	ctx := context.Background()

	s.enqueueMirrorSync(ctx, "vm-1", mirrorOpDelete)
	if got := queuedMirrorItems(t, s); got != 0 {
		t.Fatalf("%d queue row(s) written before the latch formed", got)
	}

	// The positive control: the shortcut must still work on a latched cluster,
	// or the mirror waits out a whole sweep interval for every change.
	s.SetGate(fakeServerGate{enforced: true})
	s.enqueueMirrorSync(ctx, "vm-1", mirrorOpDelete)
	if got := queuedMirrorItems(t, s); got != 1 {
		t.Fatalf("a latched cluster must record the latency shortcut, got %d row(s)", got)
	}
}
