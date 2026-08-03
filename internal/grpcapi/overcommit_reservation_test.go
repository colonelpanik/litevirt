package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// --allow-overcommit bypasses the capacity CHECK. It must not also bypass the DRAW.
//
// The operator's decision is scoped to the request that carries the flag: an
// overcommit create may exceed the host's limits, but the memory it takes has to be
// visible to everything admitted after it. When it reserved nothing, a concurrent
// NORMAL create — one that never asked to overcommit anything — could be admitted
// against memory already spoken for, because the overcommit VM stayed invisible
// until its workload row committed (an image pull, disk creation and DefineDomain
// later). The bypass leaked out of its own request.
//
// Asserted on HostReserved directly rather than by racing a second create past it.
// The indirect version is the vacuous-test trap this package already documents: ids
// come from newID(), so whether the reservation is even visible to the next
// admission depends on which id sorts first, and a mutation that reserved nothing
// would survive it whenever the probe happened to sort earlier.

// TestReserveWithoutCheck_PublishesTheDraw is the property: the reservation exists
// and holds the memory, even though nothing was verified.
func TestReserveWithoutCheck_PublishesTheDraw(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	admissionHost(t, s)

	_, beforeMem, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}

	// 4096 MiB on a host with 1536 allocatable: far past the limit, which is the
	// point — the check is bypassed, so this must succeed regardless.
	lease, err := s.reserveWithoutCheck(ctx, "CreateVM", "test-host", "_default", "vm:dense", 1, 4096)
	if err != nil {
		t.Fatalf("overcommit reservation was refused: %v — the whole point of the "+
			"flag is that it does not check, so nothing here may fail on capacity", err)
	}

	_, afterMem, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	want := s.capacity.MemChargeFor(4096)
	if got := afterMem - beforeMem; got != want {
		t.Errorf("host memory reserved by an overcommit create = %d MiB, want %d — "+
			"an overcommit draw that reserves nothing is invisible to the next "+
			"admission, so a normal create can be admitted against memory this one "+
			"is already using", got, want)
	}

	// Release is as load-bearing here as on the checked path: this lease spans the
	// same long gap (image pull → DefineDomain), so a leaked one permanently holds
	// capacity no workload is using.
	lease.release(ctx)
	_, releasedMem, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if releasedMem != beforeMem {
		t.Errorf("host memory reserved after release = %d MiB, want %d — a leaked "+
			"overcommit lease holds capacity forever", releasedMem, beforeMem)
	}
}
