package health

import (
	"testing"
	"time"
)

func TestIsCorrelatedFailure_BelowThreshold(t *testing.T) {
	v := &VMChecker{
		failures:      make(map[string]int),
		lastAction:    make(map[string]time.Time),
		actionCount:   make(map[string]int),
		activeActions: make(map[string]int),
	}

	// Only 2 VMs failing (threshold is 3).
	v.failures["vm1"] = 3
	v.failures["vm2"] = 2

	if v.isCorrelatedFailure() {
		t.Error("2 failing VMs should not trigger correlated failure (threshold=3)")
	}
}

func TestIsCorrelatedFailure_AtThreshold(t *testing.T) {
	v := &VMChecker{
		failures:      make(map[string]int),
		lastAction:    make(map[string]time.Time),
		actionCount:   make(map[string]int),
		activeActions: make(map[string]int),
	}

	// 3 VMs with >= 2 consecutive failures.
	v.failures["vm1"] = 2
	v.failures["vm2"] = 5
	v.failures["vm3"] = 3

	if !v.isCorrelatedFailure() {
		t.Error("3 failing VMs should trigger correlated failure")
	}
}

func TestIsCorrelatedFailure_SingleFailuresIgnored(t *testing.T) {
	v := &VMChecker{
		failures:      make(map[string]int),
		lastAction:    make(map[string]time.Time),
		actionCount:   make(map[string]int),
		activeActions: make(map[string]int),
	}

	// 5 VMs with only 1 failure each — these are not "failing" (need >= 2).
	v.failures["vm1"] = 1
	v.failures["vm2"] = 1
	v.failures["vm3"] = 1
	v.failures["vm4"] = 1
	v.failures["vm5"] = 1

	if v.isCorrelatedFailure() {
		t.Error("VMs with only 1 failure each should not count toward correlation")
	}
}

func TestIsCorrelatedFailure_Empty(t *testing.T) {
	v := &VMChecker{
		failures:      make(map[string]int),
		lastAction:    make(map[string]time.Time),
		actionCount:   make(map[string]int),
		activeActions: make(map[string]int),
	}

	if v.isCorrelatedFailure() {
		t.Error("empty failures map should not be correlated")
	}
}

func TestIsCorrelatedFailure_MixedCounts(t *testing.T) {
	v := &VMChecker{
		failures:      make(map[string]int),
		lastAction:    make(map[string]time.Time),
		actionCount:   make(map[string]int),
		activeActions: make(map[string]int),
	}

	// 2 with >= 2 failures, 3 with 1 failure each — only 2 "real" failures.
	v.failures["vm1"] = 4
	v.failures["vm2"] = 2
	v.failures["vm3"] = 1
	v.failures["vm4"] = 1
	v.failures["vm5"] = 1

	if v.isCorrelatedFailure() {
		t.Error("only 2 VMs with >= 2 failures should not trigger (threshold=3)")
	}
}
