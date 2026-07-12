package corrosion

import (
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
)

// TestNowTS_HLCEmissionGated proves the hlc_lww flip: NowTS emits RFC3339 while the
// injected predicate is off, HLC while on, and the switch is monotonic BY INSTANT in
// both directions — so a per-node canary (HLC after a peer's RFC3339) and a flag-off
// rollback (RFC3339 after HLC) both win correctly, no lost update. (2ms gaps cross the
// ms boundary so the HLC physical-ms is strictly ordered vs the RFC3339Nano instant.)
func TestNowTS_HLCEmissionGated(t *testing.T) {
	dir := t.TempDir()
	c, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var emit bool
	c.SetHLCEmit(func() bool { return emit })

	// Off (default): RFC3339, not HLC.
	off1 := c.NowTS()
	if hlc.IsHLC(off1) {
		t.Fatalf("emit off: got HLC %q, want RFC3339", off1)
	}

	time.Sleep(2 * time.Millisecond)
	emit = true // flip on
	on1 := c.NowTS()
	if !hlc.IsHLC(on1) {
		t.Fatalf("emit on: got %q, want HLC", on1)
	}
	if lwwOrder(on1, off1) <= 0 {
		t.Fatalf("HLC emitted after RFC3339 must be newer by instant: lwwOrder(%q,%q) <= 0", on1, off1)
	}

	time.Sleep(2 * time.Millisecond)
	emit = false // rollback
	off2 := c.NowTS()
	if hlc.IsHLC(off2) {
		t.Fatalf("rollback: got HLC %q, want RFC3339", off2)
	}
	if lwwOrder(off2, on1) <= 0 {
		t.Fatalf("RFC3339 emitted after HLC (rollback) must be newer by instant: lwwOrder(%q,%q) <= 0", off2, on1)
	}
}
