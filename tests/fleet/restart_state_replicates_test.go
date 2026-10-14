// Fleet scenario: a restart that follows a window reset reaches the peer.
//
// The VM and container health checks reset an expired restart window and then
// record the restart in the same pass, milliseconds apart: ResetRestartState
// followed by IncrementRestart on the same row. A receiver orders the two by
// updated_at, and on an exact tie keeps its local row (vm_restarts and
// container_restarts are outside anti-entropy, so nothing repairs it later).
// With whole-second stamps the increment tied the reset on every peer and was
// dropped there: the peer kept attempt_count 0 and no last_restart, while the
// writer held 1 — until the next restart in a later second.
//
// The harness runs no replicator discovery loop, so each scenario carries the
// writer's mutation_log to the peer with pumpMutations, over the real
// PushMutations RPC and the receiver's real LWW apply, before reading it.

package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// inOneSecond runs fn until a run starts and ends within one wall-clock
// second, which is the case the old stamps tied on. A run straddling a
// boundary would pass by luck, so it is not counted.
func inOneSecond(t *testing.T, fn func(attempt int)) {
	t.Helper()
	for attempt := 0; attempt < 5; attempt++ {
		before := time.Now().Unix()
		fn(attempt)
		if time.Now().Unix() == before {
			return
		}
	}
	t.Fatal("could not run the reset and the increment within one second")
}

func TestFleet_VMRestartAfterWindowResetReplicates(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	writer, peer := c.Nodes[0], c.Nodes[1]

	var vm string
	inOneSecond(t, func(attempt int) {
		vm = "restart-vm-" + string(rune('a'+attempt))
		if err := corrosion.ResetRestartState(ctx, writer.DB, vm); err != nil {
			t.Fatalf("ResetRestartState: %v", err)
		}
		if err := corrosion.IncrementRestart(ctx, writer.DB, vm); err != nil {
			t.Fatalf("IncrementRestart: %v", err)
		}
	})

	pumpMutations(t, c, writer, peer)
	got, err := corrosion.GetRestartState(ctx, peer.DB, vm)
	if err != nil {
		t.Fatalf("GetRestartState on peer: %v", err)
	}
	if got != nil && got.AttemptCount == 1 && !got.LastRestart.IsZero() {
		return
	}
	t.Fatalf("peer restart state for %s = %+v; the writer recorded attempt_count 1 with a last_restart", vm, got)
}

func TestFleet_ContainerRestartAfterWindowResetReplicates(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	writer, peer := c.Nodes[0], c.Nodes[1]

	var ct string
	inOneSecond(t, func(attempt int) {
		ct = "restart-ct-" + string(rune('a'+attempt))
		if err := corrosion.ResetContainerRestartState(ctx, writer.DB, writer.Name, ct); err != nil {
			t.Fatalf("ResetContainerRestartState: %v", err)
		}
		if err := corrosion.IncrementContainerRestart(ctx, writer.DB, writer.Name, ct); err != nil {
			t.Fatalf("IncrementContainerRestart: %v", err)
		}
	})

	pumpMutations(t, c, writer, peer)
	got, err := corrosion.GetContainerRestartState(ctx, peer.DB, writer.Name, ct)
	if err != nil {
		t.Fatalf("GetContainerRestartState on peer: %v", err)
	}
	if got != nil && got.AttemptCount == 1 && !got.LastRestart.IsZero() {
		return
	}
	t.Fatalf("peer restart state for %s = %+v; the writer recorded attempt_count 1 with a last_restart", ct, got)
}
