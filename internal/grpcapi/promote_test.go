package grpcapi

import (
	"path/filepath"
	"testing"
)

// promoteDomainAlreadyStarted must adopt (never destroy) a RUNNING domain from a prior
// promotion — recognized same-proof (start_attempted) OR cross-proof (marker), since a
// fresh proof each failover cycle carries empty step_state. This is the H4 data-loss guard.
func TestPromoteDomainAlreadyStarted(t *testing.T) {
	cases := []struct {
		name                                                       string
		startedStep, startAttempted, marker, exists, running, want bool
	}{
		{"started checkpoint wins", true, false, false, false, false, true},
		{"same-proof: start_attempted + running", false, true, false, true, true, true},
		{"cross-proof: marker + running (fresh proof, no steps)", false, false, true, true, true, true},
		{"marker but NOT running → not adopted (safe to (re)start)", false, false, true, true, false, false},
		{"running but neither step nor marker → NOT ours, don't adopt", false, false, false, true, true, false},
		{"marker but domain absent", false, false, true, false, false, false},
		{"nothing", false, false, false, false, false, false},
	}
	for _, c := range cases {
		if got := promoteDomainAlreadyStarted(c.startedStep, c.startAttempted, c.marker, c.exists, c.running); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// promoteDiskBuilt honors disk_built only when the live disk actually exists (H5: a
// forward-only checkpoint + an error path that removed the disk would otherwise skip the
// rebuild and loop).
func TestPromoteDiskBuilt(t *testing.T) {
	if !promoteDiskBuilt(true, true) {
		t.Error("disk_built + livePath exists → built")
	}
	if promoteDiskBuilt(true, false) {
		t.Error("disk_built but livePath MISSING → must rebuild (not built)")
	}
	if promoteDiskBuilt(false, true) {
		t.Error("no checkpoint → not built")
	}
}

// The host-local promote marker round-trips and is keyed per target name.
func TestPromoteMarker_RoundTrip(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	if s.promoteMarkerPresent("vm1") {
		t.Fatal("no marker initially")
	}
	if err := s.writePromoteMarker("vm1", "proof-1"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !s.promoteMarkerPresent("vm1") {
		t.Fatal("marker must be present after write")
	}
	if s.promoteMarkerPresent("vm2") {
		t.Fatal("marker is per-name")
	}
	if got := s.promoteMarkerPath("vm1"); filepath.Base(got) != "vm1" {
		t.Fatalf("marker path = %q, want basename vm1", got)
	}
	s.removePromoteMarker("vm1")
	if s.promoteMarkerPresent("vm1") {
		t.Fatal("marker must be gone after remove")
	}
}
