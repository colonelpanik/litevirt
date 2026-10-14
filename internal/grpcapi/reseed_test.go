package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
	n, mismatch := reseedDigestsConverged(local, v1Digests(map[string]string{
		"vms": "aaa", "containers": "bbb",
		"audit_log": "source-only", "host_health": "source-only",
	}))
	if mismatch != "" || n != 2 {
		t.Fatalf("converged case: n=%d mismatch=%q", n, mismatch)
	}

	// NOT converged: a shared-authority table still differs → no clear, and the
	// message names the table so an operator knows what to look at.
	if _, mismatch := reseedDigestsConverged(local, v1Digests(map[string]string{
		"vms": "aaa", "containers": "DIFFERENT",
	})); mismatch == "" {
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
			v1Digests(map[string]string{kept: "source-differs"}),
		); mismatch != "" {
			t.Fatalf("a KEPT table must never block a reseed, but %s did: %q", kept, mismatch)
		}
	}

	// A table the source doesn't report at all (older build) is skipped, not
	// treated as a mismatch — a benign version difference must not block a
	// reseed the node genuinely needs.
	if _, mismatch := reseedDigestsConverged(local, v1Digests(map[string]string{"vms": "aaa"})); mismatch != "" {
		t.Fatalf("a table absent on the source must not block: %q", mismatch)
	}
}

// v1Digests is a source's answer from a build or a node with digest_v2 off:
// positional hashes only.
func v1Digests(m map[string]string) map[string]*pb.TableDigest {
	out := make(map[string]*pb.TableDigest, len(m))
	for n, h := range m {
		out[n] = &pb.TableDigest{Name: n, Hash: h}
	}
	return out
}

// A reseed refills its tables from the source's dump but keeps its OWN
// schema, so a node founded at an older schema holds the refilled rows in a
// different physical column order from a freshly founded source. The
// positional v1 hashes then differ for vms, containers and the other tables
// an ALTER grew, whatever the rows — and a verification that compared only
// v1 refused the epoch clear on every attempt, leaving the node quarantined.
// Convergence is the anti-entropy question, asked the same way: v2 when both
// sides sent it, v1 otherwise.
//
// Mutation: compare r.GetHash() against t.Hash again — the first case goes red.
func TestReseedDigestsConverged_ColumnOrderIsNotADifference(t *testing.T) {
	local := []corrosion.TableDigest{{Name: "vms", Count: 2, Hash: "v1-upgraded-order", HashV2: "same-rows"}}

	n, mismatch := reseedDigestsConverged(local, map[string]*pb.TableDigest{
		"vms": {Name: "vms", Count: 2, Hash: "v1-fresh-order", HashV2: "same-rows"},
	})
	if mismatch != "" || n != 1 {
		t.Fatalf("identical rows in another column order blocked the epoch clear: n=%d mismatch=%q", n, mismatch)
	}

	// A source that sent no v2 hash (older build, or digest_v2 off) is
	// compared positionally, as before: no v1 hash is ever judged against a
	// v2 one, and a positional difference still blocks.
	if _, mismatch := reseedDigestsConverged(local, map[string]*pb.TableDigest{
		"vms": {Name: "vms", Count: 2, Hash: "v1-fresh-order"},
	}); mismatch == "" {
		t.Fatal("against a v1-only source the comparison must stay positional")
	}

	// v2 is a content comparison, not a pass: different rows still block.
	if _, mismatch := reseedDigestsConverged(local, map[string]*pb.TableDigest{
		"vms": {Name: "vms", Count: 2, Hash: "v1-upgraded-order", HashV2: "other-rows"},
	}); mismatch == "" {
		t.Fatal("rows that differ under v2 must block the epoch clear")
	}
}
