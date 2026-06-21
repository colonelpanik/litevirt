package ui

import (
	"testing"
	"time"
)

func TestStatsRing_PushAndSnapshot(t *testing.T) {
	r := &StatsRing{}

	// Push 3 samples.
	now := time.Now().Unix()
	r.Push(StatsSample{Ts: now, CPUPct: 10, MemPct: 20}, 100, 200, 300, 400)
	r.Push(StatsSample{Ts: now + 5, CPUPct: 15, MemPct: 25}, 200, 400, 600, 800)
	r.Push(StatsSample{Ts: now + 10, CPUPct: 20, MemPct: 30}, 300, 600, 900, 1200)

	snap := r.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("Snapshot len = %d, want 3", len(snap))
	}

	// First sample has zero rates (no previous).
	if snap[0].DiskRdRate != 0 {
		t.Errorf("first sample DiskRdRate = %f, want 0", snap[0].DiskRdRate)
	}

	// Second sample: delta = (200-100)/5 = 20 bytes/sec.
	if snap[1].DiskRdRate != 20 {
		t.Errorf("second sample DiskRdRate = %f, want 20", snap[1].DiskRdRate)
	}
	if snap[1].DiskWrRate != 40 {
		t.Errorf("second sample DiskWrRate = %f, want 40", snap[1].DiskWrRate)
	}

	// Verify time ordering (oldest first).
	if snap[0].Ts > snap[2].Ts {
		t.Error("Snapshot is not time-ordered")
	}
}

func TestStatsRing_Wrap(t *testing.T) {
	r := &StatsRing{}

	// Fill past capacity.
	for i := 0; i < ringCapacity+10; i++ {
		r.Push(StatsSample{Ts: int64(i), CPUPct: float64(i)}, 0, 0, 0, 0)
	}

	snap := r.Snapshot()
	if len(snap) != ringCapacity {
		t.Fatalf("Snapshot len = %d, want %d", len(snap), ringCapacity)
	}

	// Oldest should be sample #10 (first 10 were overwritten).
	if snap[0].Ts != 10 {
		t.Errorf("oldest Ts = %d, want 10", snap[0].Ts)
	}
	if snap[ringCapacity-1].Ts != int64(ringCapacity+9) {
		t.Errorf("newest Ts = %d, want %d", snap[ringCapacity-1].Ts, ringCapacity+9)
	}
}

func TestStatsRing_CounterReset(t *testing.T) {
	r := &StatsRing{}
	r.Push(StatsSample{Ts: 1}, 1000, 2000, 3000, 4000)
	// Counter resets (e.g., VM restart).
	r.Push(StatsSample{Ts: 6}, 50, 100, 150, 200)

	snap := r.Snapshot()
	if snap[1].DiskRdRate < 0 {
		t.Errorf("DiskRdRate = %f, should be clamped to >= 0", snap[1].DiskRdRate)
	}
	if snap[1].NetRxRate < 0 {
		t.Errorf("NetRxRate = %f, should be clamped to >= 0", snap[1].NetRxRate)
	}
}

func TestStatsRing_EmptySnapshot(t *testing.T) {
	r := &StatsRing{}
	snap := r.Snapshot()
	if len(snap) != 0 {
		t.Fatalf("empty ring Snapshot len = %d, want 0", len(snap))
	}
}
