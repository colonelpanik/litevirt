package corrosion

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestVMEvents_StampsSortAsTextInTimeOrder holds InsertVMEvent to the promise in
// its own doc comment: "ts gets nanosecond precision so same-second events on
// one VM still sort deterministically".
//
// ts is compared as TEXT — ListVMEvents orders by (ts DESC, id DESC), and the
// per-VM keep-N prune partitions by the same expression — so the stamp's text
// order has to be its time order. time.RFC3339Nano trims trailing zeros, so a
// stamp that lands on a round nanosecond sorts out of place: ".12Z" after the
// later ".125Z", and a whole second "01Z" after "01.5Z". An operator then reads
// a VM's timeline with the transition that mattered in the wrong place, and the
// prune keeps the wrong N.
func TestVMEvents_StampsSortAsTextInTimeOrder(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	instants := []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 120_000_000, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 0, 125_000_000, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 1, 500_000_000, time.UTC),
	}
	for i, at := range instants {
		c.nowFn = func() time.Time { return at }
		if err := InsertVMEvent(ctx, c, VMEventRecord{
			ID: fmt.Sprintf("e-%d", i), VMName: "vm-1", HostName: "node-0",
			Type: "vm.started", Detail: "test",
		}); err != nil {
			t.Fatalf("InsertVMEvent %d: %v", i, err)
		}
	}

	rows, err := c.Query(ctx, `SELECT id, ts FROM vm_events ORDER BY ts ASC, id ASC`)
	if err != nil {
		t.Fatalf("list vm_events: %v", err)
	}
	if len(rows) != len(instants) {
		t.Fatalf("got %d rows, want %d", len(rows), len(instants))
	}
	for i, r := range rows {
		if want := fmt.Sprintf("e-%d", i); r.String("id") != want {
			t.Errorf("position %d in ts order is %s (stamped %q), want %s",
				i, r.String("id"), r.String("ts"), want)
			continue
		}
		got, perr := time.Parse(time.RFC3339Nano, r.String("ts"))
		if perr != nil || !got.Equal(instants[i]) {
			t.Errorf("%s stamped %q, want the client clock's %s",
				r.String("id"), r.String("ts"), instants[i].Format(time.RFC3339Nano))
		}
	}
}
