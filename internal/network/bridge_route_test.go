package network

import "testing"

// TestRemoveSubnetRoute verifies the idempotent teardown: it issues `ip route del` only when
// the live route's `via` matches the given peer IP, and is a no-op otherwise (so the broad
// per-peer removal wired into stack teardown can't delete an unrelated route).
func TestRemoveSubnetRoute(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()

	run := func(showOutput string) (delIssued bool) {
		execCommand = func(name string, args ...string) ([]byte, error) {
			if len(args) >= 2 && args[1] == "show" {
				return []byte(showOutput), nil
			}
			if len(args) >= 2 && args[1] == "del" {
				delIssued = true
			}
			return nil, nil
		}
		RemoveSubnetRoute("10.20.0.0/24", "10.13.5.9")
		return delIssued
	}

	if !run("10.20.0.0/24 via 10.13.5.9 dev bond0") {
		t.Error("route matching the via must be deleted")
	}
	if run("10.20.0.0/24 via 10.99.99.99 dev bond0") {
		t.Error("route with a different via must NOT be deleted")
	}
	if run("") {
		t.Error("no route present must be a no-op")
	}
}
