package firewall

import (
	"strings"
	"testing"
)

// renderSetsOnly renders a plan holding just these sets and one rule that
// references the first, and returns the rendered ruleset.
func renderSetsOnly(t *testing.T, sets []IPSet) string {
	t.Helper()
	out, err := Render(Plan{
		IPSets: sets,
		ClusterRules: []Rule{{
			Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: "@" + sets[0].Name, Action: Accept,
		}},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return out
}

// ip_sets.name carries no UNIQUE constraint — the primary key is a random id,
// CreateIpSet checks nothing, and two stacks may each declare a set of the
// same name — so the plan can hold two live sets called "office" (#218).
//
// nft MERGES repeated `set office { … }` declarations into one set (checked
// with nft 1.1 in a throwaway netns), so the union of every same-name row is
// what the kernel already enforced whenever the ruleset applied. The renderer
// now emits that union as ONE block, in a byte order that does not depend on
// which row the query returned first.
//
// Mutation: render one block per row again — two `set office {` lines.
func TestRender_DuplicateIPSetNamesRenderOneUnionBlock(t *testing.T) {
	a := IPSet{Name: "office", CIDRs: []string{"192.168.1.0/24"}}
	b := IPSet{Name: "office", CIDRs: []string{"10.0.0.0/24", "192.168.1.0/24"}}

	out := renderSetsOnly(t, []IPSet{a, b})
	if n := strings.Count(out, "set office {"); n != 1 {
		t.Fatalf("rendered %d `set office` blocks, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "elements = { 10.0.0.0/24, 192.168.1.0/24 }") {
		t.Errorf("want the deduplicated union of both rows' CIDRs:\n%s", out)
	}
	if other := renderSetsOnly(t, []IPSet{b, a}); other != out {
		t.Errorf("row order changed the rendered bytes:\n%s\n---\n%s", out, other)
	}
}

// An interval set refuses overlapping elements outright — `nft -f` fails with
// "conflicting intervals specified", and because the ruleset is one
// transaction, the WHOLE firewall stops applying on every host. Two IPv4
// prefixes either nest or are disjoint, so dropping each prefix another one
// already covers removes every conflict without changing what the set
// matches. That matters most for duplicate names (two rows that are fine
// alone, nested together), but a single row listing 10.0.0.0/8 and
// 10.1.0.0/16 failed the same way.
//
// Mutation: skip the containment pruning — 10.1.0.0/16 stays in the elements.
func TestRender_NestedIPSetElementsCollapseToTheCoveringPrefix(t *testing.T) {
	for name, sets := range map[string][]IPSet{
		"across same-name rows": {
			{Name: "office", CIDRs: []string{"10.0.0.0/8"}},
			{Name: "office", CIDRs: []string{"10.1.0.0/16", "172.16.0.1"}},
		},
		"within one row": {
			{Name: "office", CIDRs: []string{"10.1.0.0/16", "10.0.0.0/8", "172.16.0.1"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			out := renderSetsOnly(t, sets)
			if !strings.Contains(out, "elements = { 10.0.0.0/8, 172.16.0.1 }") {
				t.Errorf("want the nested prefix dropped and the disjoint one kept:\n%s", out)
			}
		})
	}
}
