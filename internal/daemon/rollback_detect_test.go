package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// A node that latched a capability token and is then rolled back to a binary
// predating that token has no way to notice.
//
// The durable activation markers are one file per token, and they are loaded by
// iterating capabilities.All() — the token list COMPILED INTO THE RUNNING BINARY —
// and Stat'ing each expected path. Nothing scans the directory. So a rolled-back
// binary has no "latched_hardware_v2" string to look for, never looks, and starts
// clean. There is no cluster-side record either: capabilities travel only in a
// live PingResponse, and no schema column holds them. The schema version is the
// one durable signal, and it is deliberately tolerated so that a schema bump stays
// reversible and a mixed-version rolling upgrade keeps working — so it must not be
// used for this.
//
// The detection therefore has to be the one place that reads the marker DIRECTORY
// rather than the token list: a marker whose token this build has never heard of
// is proof that a newer binary ran here and latched something.

func TestPreflightCapabilityRollback_FlagsAMarkerThisBuildDoesNotKnow(t *testing.T) {
	dir := t.TempDir()
	writeMarker(t, dir, "some_future_token_v9")

	got := preflightCapabilityRollback(dir)
	if len(got) != 1 || got[0] != "some_future_token_v9" {
		t.Fatalf("preflightCapabilityRollback = %v, want [some_future_token_v9]; without this "+
			"the node rejoins and writes with no record that it ever latched anything", got)
	}
}

// TestPreflightCapabilityRollback_IgnoresKnownTokens is the half that stops this
// from being a self-inflicted outage: every healthy node has markers for the
// tokens it has latched, and treating those as a rollback would quarantine the
// entire fleet.
func TestPreflightCapabilityRollback_IgnoresKnownTokens(t *testing.T) {
	dir := t.TempDir()
	known := capabilities.All()
	if len(known) == 0 {
		t.Fatal("capabilities.All() is empty; this test proves nothing")
	}
	for _, tok := range known {
		writeMarker(t, dir, tok)
	}

	if got := preflightCapabilityRollback(dir); len(got) != 0 {
		t.Fatalf("preflightCapabilityRollback = %v on a node holding only tokens this build "+
			"knows; a healthy fleet would be quarantined", got)
	}
}

// TestPreflightCapabilityRollback_CleanNodeIsClean covers the ordinary case.
func TestPreflightCapabilityRollback_CleanNodeIsClean(t *testing.T) {
	if got := preflightCapabilityRollback(t.TempDir()); len(got) != 0 {
		t.Fatalf("preflightCapabilityRollback = %v on a node with no markers at all", got)
	}
}

// TestPreflightCapabilityRollback_ReportsEveryUnknownToken: a rollback across more
// than one release skips more than one token, and the operator needs all of them
// to know what to reseed.
func TestPreflightCapabilityRollback_ReportsEveryUnknownToken(t *testing.T) {
	dir := t.TempDir()
	writeMarker(t, dir, "future_b")
	writeMarker(t, dir, "future_a")
	if len(capabilities.All()) > 0 {
		writeMarker(t, dir, capabilities.All()[0])
	}

	got := preflightCapabilityRollback(dir)
	if len(got) != 2 || got[0] != "future_a" || got[1] != "future_b" {
		t.Fatalf("preflightCapabilityRollback = %v, want [future_a future_b] sorted", got)
	}
}

// TestPreflightCapabilityRollback_OverrideLetsAnOperatorRecover: the quarantine is
// cleared by an operator who has reseeded, and there must be a way to say so
// without deleting marker files by hand.
func TestPreflightCapabilityRollback_OverrideLetsAnOperatorRecover(t *testing.T) {
	dir := t.TempDir()
	writeMarker(t, dir, "some_future_token_v9")
	t.Setenv("LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK", "1")

	if got := preflightCapabilityRollback(dir); len(got) != 0 {
		t.Fatalf("preflightCapabilityRollback = %v with the override set", got)
	}
}

func writeMarker(t *testing.T, dir, token string) {
	t.Helper()
	path := filepath.Join(dir, "split_brain_activated."+token)
	if err := os.WriteFile(path, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("write marker %s: %v", path, err)
	}
}
