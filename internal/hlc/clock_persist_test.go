package hlc

import (
	"errors"
	"testing"
	"time"
)

// TestClock_LogicalOverflowSpillsToPhysical: under a frozen (or backward) wall with a
// persisted-ahead physical, >9999 same-ms emissions must NOT overflow the 4-digit logical
// format (which would make the string unparsable and sort BEFORE ...-9999-...). The
// counter spills into physical so every key parses and strictly increases.
func TestClock_LogicalOverflowSpillsToPhysical(t *testing.T) {
	t0 := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	c := NewClock("n")
	c.nowFn = func() time.Time { return t0 } // frozen — forces the logical counter to climb
	var prev Timestamp
	for i := 0; i < 10_005; i++ {
		ts := c.Now()
		if _, ok := Parse(ts.String()); !ok {
			t.Fatalf("emit %d: %q is not parsable HLC (logical overflowed the 4-digit format)", i, ts.String())
		}
		if i > 0 && !ts.After(prev) {
			t.Fatalf("emit %d: %v not strictly after %v", i, ts, prev)
		}
		prev = ts
	}
}

// TestClock_PersistFailureFailsClosed: a persist failure that can't durably advance the
// ceiling must call persistFatal (production exits) rather than return a value beyond the
// durable ceiling (crash-regresses) or a clamped duplicate.
func TestClock_PersistFailureFailsClosed(t *testing.T) {
	t0 := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	wall := t0
	c := NewClock("n")
	c.nowFn = func() time.Time { return wall }
	var fatal int
	c.SetPersistence(t0.UnixMilli(), func(int64) error { return errors.New("disk full") }, func() { fatal++ })

	_ = c.Now() // at the floor ms → no persist attempt yet
	// Advance wall past the ceiling so the next emit must persist a higher one — which fails.
	wall = t0.Add(time.Duration(hlcPersistAheadMS+1) * time.Millisecond)
	got := c.Now()
	if fatal == 0 {
		t.Fatal("persist failure with no durable advance must call persistFatal (fail closed)")
	}
	// Test-continues path clamps to the durable ceiling — never beyond it.
	if got.PhysicalMS > t0.UnixMilli() {
		t.Fatalf("clamped emit physical %d must not exceed the durable ceiling %d", got.PhysicalMS, t0.UnixMilli())
	}
}

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
	c1.SetPersistence(0, persist, nil)
	before := c1.Now()

	// Restart: fresh clock, loaded with the persisted floor, wall clock an hour back.
	c2 := NewClock("n")
	c2.nowFn = func() time.Time { return t0.Add(-time.Hour) }
	c2.SetPersistence(ceil, persist, nil)
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
	c1.SetPersistence(0, persist, nil)
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
	c2.SetPersistence(ceil, persist, nil)
	next := c2.Now()

	if !tsGreater(next, burstMax) {
		t.Fatalf("post-restart HLC duplicated/undercut the burst: next=%v !> burstMax=%v (ceil=%d)", next, burstMax, ceil)
	}
}
