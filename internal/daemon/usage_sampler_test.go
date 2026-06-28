package daemon

import (
	"testing"
	"time"
)

// TestUsageSampler_BaselineThenRate: the first reading only records a baseline
// (no write); the next produces a rate. Units: IOPS = ops/sec; Mbps = bytes/sec×8/1e6.
func TestUsageSampler_BaselineThenRate(t *testing.T) {
	var s usageSampler
	t0 := time.Now()
	if w, _, _ := s.observe(1000, 8_000_000, t0); w {
		t.Error("first sample must be baseline-only (no write)")
	}
	// +500 ops and +10 MB over 10s → 50 IOPS, (10e6/10)*8/1e6 = 8 Mbps.
	w, iops, mbps := s.observe(1500, 18_000_000, t0.Add(10*time.Second))
	if !w {
		t.Error("first computed rate should write")
	}
	if iops != 50 {
		t.Errorf("iops = %d, want 50", iops)
	}
	if mbps != 8 {
		t.Errorf("mbps = %d, want 8", mbps)
	}
}

// TestUsageSampler_CounterResetClamps: a domain restart resets cumulative
// counters; a negative delta must clamp to 0, not report a bogus rate.
func TestUsageSampler_CounterResetClamps(t *testing.T) {
	var s usageSampler
	t0 := time.Now()
	s.observe(1_000_000, 1_000_000, t0)
	_, iops, mbps := s.observe(10, 10, t0.Add(10*time.Second)) // cur < last
	if iops != 0 || mbps != 0 {
		t.Errorf("counter reset should clamp to 0, got iops=%d mbps=%d", iops, mbps)
	}
}

// TestUsageSampler_TransitionToZeroWrites: a host that sheds all load must
// promptly write 0 (a drop to zero beats the deadband) — never stuck "loaded
// forever" — then a steady zero stops re-writing.
func TestUsageSampler_TransitionToZeroWrites(t *testing.T) {
	var s usageSampler
	t0 := time.Now()
	s.observe(0, 0, t0) // baseline
	if w, iops, _ := s.observe(10_000, 0, t0.Add(10*time.Second)); !w || iops != 1000 {
		t.Fatalf("ramp-up: write=%v iops=%d, want write=true iops=1000", w, iops)
	}
	// No new ops → rate drops to 0; must write despite the small absolute change.
	w, iops, _ := s.observe(10_000, 0, t0.Add(20*time.Second))
	if !w || iops != 0 {
		t.Errorf("drop-to-zero: write=%v iops=%d, want write=true iops=0", w, iops)
	}
	// Steady zero → no re-write.
	if w, _, _ := s.observe(10_000, 0, t0.Add(30*time.Second)); w {
		t.Error("steady zero should not re-write every tick")
	}
}

// TestUsageSampler_DeadbandSuppressesSmallMoves: a tiny move in both rates
// (neither crossing zero nor exceeding the deadband) is not persisted.
func TestUsageSampler_DeadbandSuppressesSmallMoves(t *testing.T) {
	var s usageSampler
	t0 := time.Now()
	s.observe(0, 0, t0) // baseline
	// 1000 IOPS, 80 Mbps (100 MB / 10s × 8 / 1e6 = 80).
	if w, iops, mbps := s.observe(10_000, 100_000_000, t0.Add(10*time.Second)); !w || iops != 1000 || mbps != 80 {
		t.Fatalf("first rate: write=%v iops=%d mbps=%d, want true/1000/80", w, iops, mbps)
	}
	// Next 10s: +10_010 ops (1001 IOPS, Δ1) and +100 MB (80 Mbps, Δ0) → within deadband.
	if w, _, _ := s.observe(20_010, 200_000_000, t0.Add(20*time.Second)); w {
		t.Error("a move within the deadband should not write")
	}
}
