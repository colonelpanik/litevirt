package hlc

import (
	"testing"
	"time"
)

// tsGreater reports whether a sorts strictly after b in HLC order.
func tsGreater(a, b Timestamp) bool {
	if a.PhysicalMS != b.PhysicalMS {
		return a.PhysicalMS > b.PhysicalMS
	}
	return a.Logical > b.Logical
}

// TestClock_PersistFloorNoRegressAcrossRestart: after a restart with the wall clock
// stepped back, a clock loaded with the persisted physical floor must not emit below
// what it emitted before — the HLC side of the backward-clock fix.
func TestClock_PersistFloorNoRegressAcrossRestart(t *testing.T) {
	t0 := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	var ceil int64
	persist := func(ms int64) error { ceil = ms; return nil }

	c1 := NewClock("n")
	c1.nowFn = func() time.Time { return t0 }
	c1.SetPersistence(0, persist)
	before := c1.Now()

	// Restart: fresh clock, loaded with the persisted floor, wall clock an hour back.
	c2 := NewClock("n")
	c2.nowFn = func() time.Time { return t0.Add(-time.Hour) }
	c2.SetPersistence(ceil, persist)
	after := c2.Now()

	if !tsGreater(after, before) {
		t.Fatalf("backward-clock restart regressed HLC: after=%v !> before=%v", after, before)
	}
}

// TestClock_OneMsBurstThenRestartNoDuplicate: many emits within a single physical ms
// climb the logical counter; after a restart the persisted FUTURE physical ceiling must
// put every new timestamp strictly above the whole burst — no duplicate or lower (ms,
// logical) pair even though logical resets to 0.
func TestClock_OneMsBurstThenRestartNoDuplicate(t *testing.T) {
	t0 := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	var ceil int64
	persist := func(ms int64) error { ceil = ms; return nil }

	c1 := NewClock("n")
	c1.nowFn = func() time.Time { return t0 } // clock frozen in one ms
	c1.SetPersistence(0, persist)
	var burstMax Timestamp
	for i := 0; i < 500; i++ {
		ts := c1.Now()
		if tsGreater(ts, burstMax) {
			burstMax = ts
		}
	}

	// Restart with the same (frozen) wall clock; loaded with the persisted ceiling.
	c2 := NewClock("n")
	c2.nowFn = func() time.Time { return t0 }
	c2.SetPersistence(ceil, persist)
	next := c2.Now()

	if !tsGreater(next, burstMax) {
		t.Fatalf("post-restart HLC duplicated/undercut the burst: next=%v !> burstMax=%v (ceil=%d)", next, burstMax, ceil)
	}
}
