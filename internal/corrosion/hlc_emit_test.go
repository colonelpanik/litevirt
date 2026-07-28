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

// TestNowTS_RollbackBridgesFromHLCPhysical: the hard rollback case. After HLC emission
// (or a skewed-peer HLC adoption) the HLC physical high-water can be AHEAD of wall. When
// hlc_lww is turned OFF, a fresh RFC3339 key must NOT sort below existing HLC rows — the
// RFC path bridges from the HLC physical so a rollback write still wins LWW.
func TestNowTS_RollbackBridgesFromHLCPhysical(t *testing.T) {
	dir := t.TempDir()
	c, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Drive the HLC physical an hour AHEAD of wall (simulates post-emission / adoption).
	// The HLC physical is ms-resolution, so the bridge floor is that ms (an HLC key
	// carries ns=0), which is what the RFC key must beat.
	futureMS := time.Now().Add(time.Hour).UnixMilli()
	floor := time.UnixMilli(futureMS).UTC()
	c.clock.SetPersistence(futureMS, func(int64) error { return nil }, nil)

	// hlcEmit is off (never set) → RFC3339 path. It must bridge above the HLC physical.
	rfc := c.NowTS()
	if hlc.IsHLC(rfc) {
		t.Fatalf("expected RFC3339 (hlc_lww off), got HLC %q", rfc)
	}
	inst := parseTS(t, rfc)
	if inst.Before(floor) {
		t.Fatalf("rollback RFC3339 key %s regressed below HLC physical %s — would lose LWW to HLC rows", inst, floor)
	}
	// And it strictly beats an HLC key sitting at that physical floor.
	hlcKey := hlc.Timestamp{PhysicalMS: futureMS, Logical: 0, NodeID: "node-1"}.String()
	if lwwOrder(rfc, hlcKey) <= 0 {
		t.Fatalf("rollback RFC3339 %q must beat the HLC key %q at the physical floor", rfc, hlcKey)
	}
}
