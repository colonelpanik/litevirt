package corrosion

import "testing"

// The initial-holder rule, pinned because getting it wrong is silent.
//
// Claiming authority for SELF passes every unit test, latches cleanly, and produces a
// cluster where delegation never happens: each node serves its own creates, so each
// becomes the holder of its own replica and every admission stays local. The lab
// showed it directly — node-1 and node-2 each held /qa at epoch 1, and not one
// delegated RPC was made. Only agreement between nodes makes the mechanism real.

// TestDeriveProjectAuthorityHolder_AgreesAcrossNodes is the property that matters:
// two nodes deriving from the same host set must choose the SAME holder, whatever
// order they happen to see it in.
func TestDeriveProjectAuthorityHolder_AgreesAcrossNodes(t *testing.T) {
	a := []string{"node-1", "node-2", "node-3", "node-4"}
	b := []string{"node-3", "node-1", "node-4", "node-2"} // same set, different order

	for _, project := range []string{"/qa", "/acme", "_default", "/a/deep/one"} {
		ha := DeriveProjectAuthorityHolder(project, a)
		hb := DeriveProjectAuthorityHolder(project, b)
		if ha != hb {
			t.Errorf("project %q derives %q from one node and %q from another — "+
				"disagreement means two holders at one epoch, which is the state this prevents",
				project, ha, hb)
		}
		if ha == "" {
			t.Errorf("project %q derived no holder from a non-empty host list", project)
		}
	}
}

// TestDeriveProjectAuthorityHolder_SpreadsProjects: piling every project onto one host
// would make that host the admission bottleneck for the whole cluster, and its loss
// would stall every project at once.
func TestDeriveProjectAuthorityHolder_SpreadsProjects(t *testing.T) {
	hosts := []string{"node-1", "node-2", "node-3", "node-4"}
	seen := map[string]bool{}
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i", "/j"} {
		seen[DeriveProjectAuthorityHolder(p, hosts)] = true
	}
	if len(seen) < 2 {
		t.Errorf("10 projects landed on %d host(s) out of 4 — every project on one holder "+
			"makes it a cluster-wide bottleneck and single point of stall", len(seen))
	}
}

// TestDeriveProjectAuthorityHolder_StableAsMembershipHolds. Authority is sticky, so
// the derivation must not wander between calls — only a genuine membership change may
// change the answer.
func TestDeriveProjectAuthorityHolder_StableAsMembershipHolds(t *testing.T) {
	hosts := []string{"node-1", "node-2", "node-3"}
	first := DeriveProjectAuthorityHolder("/qa", hosts)
	for i := 0; i < 50; i++ {
		if got := DeriveProjectAuthorityHolder("/qa", hosts); got != first {
			t.Fatalf("derivation is unstable: %q then %q for the same inputs", first, got)
		}
	}
}

// TestDeriveProjectAuthorityHolder_EmptyCandidates returns "" rather than panicking on
// a modulo by zero, so a caller with no readable host list can fall back instead of
// taking the daemon down.
func TestDeriveProjectAuthorityHolder_EmptyCandidates(t *testing.T) {
	if got := DeriveProjectAuthorityHolder("/qa", nil); got != "" {
		t.Errorf("derived %q from an empty host list, want \"\"", got)
	}
}

// TestDeriveProjectAuthorityHolder_NormalizesTheProject: "" and the default project
// name are the same tenancy bucket, so they must not land on different holders.
func TestDeriveProjectAuthorityHolder_NormalizesTheProject(t *testing.T) {
	hosts := []string{"node-1", "node-2", "node-3"}
	if a, b := DeriveProjectAuthorityHolder("", hosts), DeriveProjectAuthorityHolder(DefaultProject, hosts); a != b {
		t.Errorf("the unnamed project derives %q but %q derives %q — one bucket, two holders", a, DefaultProject, b)
	}
}
