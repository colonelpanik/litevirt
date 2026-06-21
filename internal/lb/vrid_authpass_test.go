package lb

import "testing"

// TestAllocVRIDExcluding_ProbesPastCollision is the F11 regression: when the
// hash slot is taken, a free slot is chosen instead of silently colliding.
func TestAllocVRIDExcluding_ProbesPastCollision(t *testing.T) {
	start := AllocVRID("alpha")

	// No collision → returns the hash slot.
	if got := AllocVRIDExcluding("alpha", map[int]bool{}); got != start {
		t.Errorf("with empty used set, got %d, want hash slot %d", got, start)
	}

	// Hash slot taken → must pick a different, in-range slot.
	used := map[int]bool{start: true}
	got := AllocVRIDExcluding("alpha", used)
	if got == start {
		t.Error("collision not avoided: returned the in-use hash slot")
	}
	if got < 1 || got > 254 {
		t.Errorf("VRID %d out of range 1..254", got)
	}
	if used[got] {
		t.Errorf("returned an in-use VRID %d", got)
	}
}

func TestAllocVRIDExcluding_AllTakenFallsBack(t *testing.T) {
	used := map[int]bool{}
	for i := 1; i <= 254; i++ {
		used[i] = true
	}
	// Everything taken → falls back to the hash slot (caller warns).
	if got := AllocVRIDExcluding("x", used); got != AllocVRID("x") {
		t.Errorf("all-taken fallback = %d, want hash slot %d", got, AllocVRID("x"))
	}
}

// TestDeriveAuthPass is the F6 regression: per-LB, deterministic, 8 chars, and
// not the old hardcoded literal.
func TestDeriveAuthPass(t *testing.T) {
	a := deriveAuthPass("lb-a")
	b := deriveAuthPass("lb-b")
	if a == b {
		t.Error("different LBs must get different auth_pass")
	}
	if a != deriveAuthPass("lb-a") {
		t.Error("auth_pass must be deterministic for a given LB")
	}
	if len(a) != 8 {
		t.Errorf("auth_pass len = %d, want 8 (keepalived truncates)", len(a))
	}
	if a == "litevirt" {
		t.Error("auth_pass must not be the old hardcoded value")
	}
}
