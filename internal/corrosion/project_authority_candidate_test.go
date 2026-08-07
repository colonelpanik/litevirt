package corrosion

import "testing"

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
