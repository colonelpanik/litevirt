package grpcapi

import (
	"strings"
	"testing"
)

// TestRollbackUnitGatedOnSentinel locks in the fix for the 2026-07-15 outage: the
// systemd OnFailure rollback must roll the binary back ONLY when an upgrade is in
// progress (the .upgrade-pending sentinel is present). A steady-state failure (e.g. a
// needrestart-driven restart storm on a healthy binary) must not downgrade it.
func TestRollbackUnitGatedOnSentinel(t *testing.T) {
	u := litevirtRollbackUnit
	sentinelIdx := strings.Index(u, "litevirt.upgrade-pending")
	if sentinelIdx < 0 {
		t.Fatal("rollback unit no longer checks the .upgrade-pending sentinel — a non-upgrade failure could downgrade a healthy binary")
	}
	mvIdx := strings.Index(u, "mv /usr/local/bin/litevirt.old")
	if mvIdx < 0 {
		t.Fatal("rollback unit no longer restores .old")
	}
	// The sentinel gate MUST precede the binary swap.
	if sentinelIdx > mvIdx {
		t.Error("sentinel check must come BEFORE the .old restore, so a missing sentinel skips the rollback")
	}
	if !strings.Contains(u, "NOT rolling back") {
		t.Error("expected the no-sentinel branch to log that it is not rolling back")
	}
}

// TestMainUnitStartLimitGenerous: a small restart burst must not trip the start limit
// (which fires the rollback unit). Burst must be well above the old value of 3.
func TestMainUnitStartLimitGenerous(t *testing.T) {
	if !strings.Contains(litevirtUnit, "StartLimitBurst=10") {
		t.Errorf("expected a generous StartLimitBurst (>=10) in the main unit:\n%s", litevirtUnit)
	}
	if strings.Contains(litevirtUnit, "StartLimitBurst=3") {
		t.Error("StartLimitBurst is still 3 — a restart burst would trip the rollback")
	}
}

// TestNeedrestartDropinExcludesLitevirt: the shipped drop-in must blacklist litevirt
// from needrestart auto-restart.
func TestNeedrestartDropinExcludesLitevirt(t *testing.T) {
	if !strings.Contains(needrestartDropin, "blacklist_rc") || !strings.Contains(needrestartDropin, `litevirt\.service`) {
		t.Errorf("needrestart drop-in must blacklist litevirt.service:\n%s", needrestartDropin)
	}
}
