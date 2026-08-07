package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The convergence rule is what earns an epoch clear, so it is pinned directly:
// only a reseed that actually converged on shared-authority tables may end a
// quarantine, and per-node evidence tables must never block one.
func TestReseedDigestsConverged(t *testing.T) {
	local := []corrosion.TableDigest{
		{Name: "vms", Hash: "aaa"},
		{Name: "containers", Hash: "bbb"},
		{Name: "audit_log", Hash: "local-only"},
		{Name: "host_health", Hash: "local-only"},
	}

	// Converged: shared authority matches; per-node evidence differs and is
	// NOT counted — requiring it to match would make every reseed fail.
	n, mismatch := reseedDigestsConverged(local, map[string]string{
		"vms": "aaa", "containers": "bbb",
		"audit_log": "source-only", "host_health": "source-only",
	})
	if mismatch != "" || n != 2 {
		t.Fatalf("converged case: n=%d mismatch=%q", n, mismatch)
	}

	// NOT converged: a shared-authority table still differs → no clear, and the
	// message names the table so an operator knows what to look at.
	if _, mismatch := reseedDigestsConverged(local, map[string]string{
		"vms": "aaa", "containers": "DIFFERENT",
	}); mismatch == "" {
		t.Fatal("a differing shared-authority table must block the epoch clear")
	} else if mismatch != "table containers still differs" {
		t.Fatalf("mismatch should name the table: %q", mismatch)
	}

	// The invariant that failed on the lab: every table a reseed KEEPS must
	// also be skipped by the verifier. A kept table was never replaced, so it
	// cannot be expected to match the source — comparing one makes every
	// reseed fail verification and leaves the node permanently quarantined.
	for _, kept := range []string{"audit_log", "audit_signing_keys", "audit_chain_heads", "audit_key_lifecycle", "hosts"} {
		if !corrosion.ReseedKeepsTable(kept) {
			t.Fatalf("%s is expected to be kept by a reseed", kept)
		}
		if _, mismatch := reseedDigestsConverged(
			[]corrosion.TableDigest{{Name: kept, Hash: "local"}},
			map[string]string{kept: "source-differs"},
		); mismatch != "" {
			t.Fatalf("a KEPT table must never block a reseed, but %s did: %q", kept, mismatch)
		}
	}

	// A table the source doesn't report at all (older build) is skipped, not
	// treated as a mismatch — a benign version difference must not block a
	// reseed the node genuinely needs.
	if _, mismatch := reseedDigestsConverged(local, map[string]string{"vms": "aaa"}); mismatch != "" {
		t.Fatalf("a table absent on the source must not block: %q", mismatch)
	}
}
