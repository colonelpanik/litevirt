package corrosion

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
)

// requireWallStamp fails unless ts is a plain RFC3339 instant, which is what a
// reader on any release can compare against an RFC3339 cutoff.
func requireWallStamp(t *testing.T, what, ts string) {
	t.Helper()
	if hlc.IsHLC(ts) {
		t.Errorf("%s: updated_at = %q is an HLC string; an older release's lexical reader sorts it below every RFC3339 cutoff", what, ts)
		return
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("%s: updated_at = %q is not RFC3339: %v", what, ts, err)
	}
}

// latchHLC turns HLC conflict-key emission on, as a cluster that has latched
// hlc_lww with enforcement.hlc_lww set does, and confirms NowTS now emits HLC —
// without that the wall-stamp assertions below would pass for any writer.
func latchHLC(t *testing.T, c *Client) {
	t.Helper()
	c.SetHLCEmit(func() bool { return true })
	if ts := c.NowTS(); !hlc.IsHLC(ts) {
		t.Fatalf("precondition: NowTS = %q with HLC emission on, want an HLC string", ts)
	}
}

// NowWallTS is NowTS without the HLC branch: still strictly monotonic, and
// still above the HLC physical high-water, so a wall stamp written after an
// HLC one on the same row never sorts below it.
func TestNowWallTS_StaysRFC3339WhileNowTSEmitsHLC(t *testing.T) {
	c := testClient(t)
	latchHLC(t, c)

	// A peer's HLC key two seconds ahead of our wall clock, adopted as a
	// receiver adopts one: a wall stamp written after it must still be newer.
	ahead := hlc.Timestamp{PhysicalMS: time.Now().Add(2 * time.Second).UnixMilli(), NodeID: "peer"}
	c.clock.Update(ahead)

	prev := ahead.String()
	for i := 0; i < 50; i++ {
		w := c.NowWallTS()
		requireWallStamp(t, "NowWallTS", w)
		if lwwOrder(w, prev) <= 0 {
			t.Fatalf("NowWallTS %q does not order after the stamp before it, %q", w, prev)
		}
		prev = w
		if i%10 == 0 {
			prev = c.NowTS() // interleave HLC emission: the floor must hold across it
			if !hlc.IsHLC(prev) {
				t.Fatalf("NowTS = %q after NowWallTS, want HLC still", prev)
			}
		}
	}
}

func TestRestartWriters_StampWallTimeUnderHLC(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	latchHLC(t, c)

	stamp := func(table, where string, args ...any) string {
		t.Helper()
		rows, err := c.Query(ctx, `SELECT updated_at FROM `+table+` WHERE `+where, args...)
		if err != nil || len(rows) == 0 {
			t.Fatalf("read %s: err=%v rows=%d", table, err, len(rows))
		}
		return rows[0].String("updated_at")
	}

	if err := ResetRestartState(ctx, c, "vm-a"); err != nil {
		t.Fatal(err)
	}
	requireWallStamp(t, "ResetRestartState", stamp("vm_restarts", "vm_name = ?", "vm-a"))
	if err := IncrementRestart(ctx, c, "vm-a"); err != nil {
		t.Fatal(err)
	}
	requireWallStamp(t, "IncrementRestart", stamp("vm_restarts", "vm_name = ?", "vm-a"))

	if err := ResetContainerRestartState(ctx, c, "h1", "ct-a"); err != nil {
		t.Fatal(err)
	}
	requireWallStamp(t, "ResetContainerRestartState",
		stamp("container_restarts", "host_name = ? AND name = ?", "h1", "ct-a"))
	if err := IncrementContainerRestart(ctx, c, "h1", "ct-a"); err != nil {
		t.Fatal(err)
	}
	requireWallStamp(t, "IncrementContainerRestart",
		stamp("container_restarts", "host_name = ? AND name = ?", "h1", "ct-a"))
}
