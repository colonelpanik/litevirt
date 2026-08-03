package corrosion

import (
	"context"
	"fmt"
	"testing"
)

func candidateHosts(names ...string) []HostRecord {
	out := make([]HostRecord, 0, len(names))
	for _, n := range names {
		out = append(out, HostRecord{Name: n, State: "active", Role: "worker"})
	}
	return out
}

// TestDeterministicAuthorityCandidate_AgreesAcrossNodes is the property the fix
// depends on: every node computes the SAME candidate from the same host set,
// without coordinating. If they disagree, two nodes mint epoch 1 and
// project_authority_epochs records a permanent immutable_conflict (it keeps both
// sides rather than coin-flipping an immutable row).
func TestDeterministicAuthorityCandidate_AgreesAcrossNodes(t *testing.T) {
	hosts := candidateHosts("node-a", "node-b", "node-c")
	for _, project := range []string{"/acme", "/acme/team", "_default", "", "/z"} {
		want, ok := DeterministicAuthorityCandidate(hosts, project)
		if !ok {
			t.Fatalf("no candidate for %q", project)
		}
		// Order must not matter — ListHosts order is not guaranteed stable.
		for _, perm := range [][]string{
			{"node-c", "node-b", "node-a"},
			{"node-b", "node-a", "node-c"},
		} {
			got, ok := DeterministicAuthorityCandidate(candidateHosts(perm...), project)
			if !ok || got != want {
				t.Errorf("project %q: candidate %q for order %v, want %q — the choice must not "+
					"depend on host enumeration order", project, got, perm, want)
			}
		}
	}
}

// TestDeterministicAuthorityCandidate_SpreadsProjects: a single hardcoded winner
// would technically be deterministic but would funnel every project's admission
// through one node. Rendezvous hashing must actually distribute.
func TestDeterministicAuthorityCandidate_SpreadsProjects(t *testing.T) {
	hosts := candidateHosts("node-a", "node-b", "node-c")
	seen := map[string]int{}
	for _, p := range []string{"/p1", "/p2", "/p3", "/p4", "/p5", "/p6", "/p7", "/p8", "/p9", "/p10"} {
		h, ok := DeterministicAuthorityCandidate(hosts, p)
		if !ok {
			t.Fatalf("no candidate for %q", p)
		}
		seen[h]++
	}
	if len(seen) < 2 {
		t.Errorf("10 projects mapped to %d host(s) (%v) — authority is not distributed", len(seen), seen)
	}
}

// TestDeterministicAuthorityCandidate_SkipsIneligible: a witness never carries
// workloads, so it must not carry admission authority either; and an inactive host
// cannot answer a routed admission.
func TestDeterministicAuthorityCandidate_SkipsIneligible(t *testing.T) {
	hosts := []HostRecord{
		{Name: "witness", State: "active", Role: "witness"},
		{Name: "down", State: "failed", Role: "worker"},
		{Name: "worker", State: "active", Role: "worker"},
	}
	got, ok := DeterministicAuthorityCandidate(hosts, "/acme")
	if !ok || got != "worker" {
		t.Errorf("candidate = %q (ok=%v), want worker — witnesses and non-active hosts are ineligible", got, ok)
	}

	// Nobody eligible → no candidate, and the caller must not mint.
	if _, ok := DeterministicAuthorityCandidate([]HostRecord{
		{Name: "witness", State: "active", Role: "witness"},
	}, "/acme"); ok {
		t.Error("a witness-only fleet returned a candidate; want ok=false so nothing claims authority")
	}
	if _, ok := DeterministicAuthorityCandidate(nil, "/acme"); ok {
		t.Error("empty host list returned a candidate; want ok=false")
	}
}

// TestResolveProjectAuthority_DivergentHostViewsWriteNothing is the regression test
// for the finding that a deterministic candidate is NOT sufficient.
//
// The candidate is deterministic given the same input, but ListHosts is replicated
// asynchronously, so two nodes can legitimately hold different host sets and compute
// DIFFERENT winners. When minting was still involved, both passed their local
// COUNT(*)=0 guard and both inserted epoch 1; the PK (project, authority_epoch) made
// those a facts-conflict, and immutableMergeKeepLocalRow keeps both sides and flags
// immutable_conflict permanently — two holders until an operator intervenes.
//
// The fix is that resolution WRITES NOTHING. This test asserts exactly that: two
// simulated nodes with different host views, both resolving, and the table stays
// empty. Disagreement is then transient and self-correcting rather than durable.
func TestResolveProjectAuthority_DivergentHostViewsWriteNothing(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)

	// Node A's view: two hosts. Node B has not yet replicated node-c.
	for _, h := range []string{"node-a", "node-b"} {
		if err := InsertHost(ctx, c, HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443,
			State: "active", Role: "worker", CertSerial: "s-" + h,
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}

	// Find a project whose derived holder CHANGES when a third host appears — i.e.
	// the exact input on which two differently-informed nodes disagree.
	twoHosts := []HostRecord{
		{Name: "node-a", State: "active", Role: "worker"},
		{Name: "node-b", State: "active", Role: "worker"},
	}
	threeHosts := append(append([]HostRecord{}, twoHosts...),
		HostRecord{Name: "node-c", State: "active", Role: "worker"})
	project := ""
	for i := 0; i < 200; i++ {
		p := fmt.Sprintf("/p%d", i)
		a, _ := DeterministicAuthorityCandidate(twoHosts, p)
		b, _ := DeterministicAuthorityCandidate(threeHosts, p)
		if a != b {
			project = p
			break
		}
	}
	if project == "" {
		t.Skip("no project found where a third host changes the winner")
	}

	// Node A (two-host view) resolves.
	gotA, ok, err := ResolveProjectAuthority(ctx, c, project)
	if err != nil || !ok {
		t.Fatalf("ResolveProjectAuthority (2-host view): ok=%v err=%v", ok, err)
	}

	// Node B's view arrives: node-c replicates in, and the derived winner changes.
	if err := InsertHost(ctx, c, HostRecord{
		Name: "node-c", Address: "10.0.0.3", SSHUser: "root", GRPCPort: 7443,
		State: "active", Role: "worker", CertSerial: "s-node-c",
	}); err != nil {
		t.Fatalf("InsertHost node-c: %v", err)
	}
	gotB, ok, err := ResolveProjectAuthority(ctx, c, project)
	if err != nil || !ok {
		t.Fatalf("ResolveProjectAuthority (3-host view): ok=%v err=%v", ok, err)
	}

	// THE ASSERTION, checked first so a regression reports the real defect: two
	// resolutions from different host views wrote NOTHING, so there is no
	// conflicting epoch-1 pair and nothing for an operator to repair.
	rows, err := c.Query(ctx,
		`SELECT COUNT(*) AS n FROM project_authority_epochs WHERE project = ?`, project)
	if err != nil {
		t.Fatalf("count authority rows: %v", err)
	}
	if n := rows[0].Int("n"); n != 0 {
		t.Fatalf("resolving wrote %d authority row(s); want 0 — an initial authority must never "+
			"be minted. Two nodes with different (asynchronously replicated) host views compute "+
			"different winners and both insert epoch 1; the PK collision is an immutable_conflict "+
			"that is kept-local on both sides forever, leaving the project with two holders.", n)
	}
	// Derived authorities are epoch 0, which is what marks them as not recorded.
	if gotA.Epoch != 0 || gotB.Epoch != 0 {
		t.Errorf("derived epochs = %d/%d, want 0/0", gotA.Epoch, gotB.Epoch)
	}
	// And the premise really did hold: the two views disagreed.
	if gotA.Holder == gotB.Holder {
		t.Errorf("both views resolved to %q; the scenario needs them to differ (a stale host view "+
			"must be able to pick a different holder) — otherwise this asserts nothing", gotA.Holder)
	}
}

// TestResolveProjectAuthority_RecordedTransferWins: an explicit transfer IS recorded
// and must beat the derived candidate — that is the sticky, CAS-guarded path, and the
// only writer of this table.
func TestResolveProjectAuthority_RecordedTransferWins(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	for _, h := range []string{"node-a", "node-b"} {
		if err := InsertHost(ctx, c, HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443,
			State: "active", Role: "worker", CertSerial: "s-" + h,
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}

	// A first explicit transfer must be accepted against a DERIVED (epoch 0)
	// authority — nothing minted epoch 1, so the CAS baseline is 0.
	newEpoch, applied, err := TakeoverProjectAuthority(ctx, c, "/acme", "node-b", "planned", "", 0)
	if err != nil || !applied {
		t.Fatalf("planned takeover from a derived authority: applied=%v err=%v", applied, err)
	}
	if newEpoch != 1 {
		t.Errorf("new epoch = %d, want 1", newEpoch)
	}

	got, ok, err := ResolveProjectAuthority(ctx, c, "/acme")
	if err != nil || !ok {
		t.Fatalf("ResolveProjectAuthority: ok=%v err=%v", ok, err)
	}
	if got.Holder != "node-b" || got.Epoch != 1 {
		t.Errorf("resolved %q epoch %d, want node-b epoch 1 — a recorded transfer must beat the "+
			"derived candidate", got.Holder, got.Epoch)
	}
}
