package main

import (
	"go/token"
	"strings"
	"testing"
)

// The guard's decision is "an unexported builder nothing references", so these
// cases drive it through fakeUses rather than a real package load.
func TestUnreachableEmitters(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fn      string
		uses    int
		wantGap bool
	}{
		{name: "unexported builder with a caller", fn: "deleteContainerGuarded", uses: 2, wantGap: false},
		{name: "unexported builder with no caller", fn: "deleteContainerGuarded", uses: 1, wantGap: true},
		{name: "exported builder is never flagged", fn: "DeleteContainer", uses: 1, wantGap: false},
		{name: "allowlisted builder with no caller", fn: "checkClockSkew", uses: 1, wantGap: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builders := map[string]token.Position{tc.fn: {Filename: "x.go", Line: 1}}
			if isExportedName(tc.fn) {
				// Exported names never enter the builder set: their callers can
				// be in any package, which this guard deliberately doesn't chase.
				builders = map[string]token.Position{}
			}
			gaps := unreachableFrom(builders, map[string]int{tc.fn: tc.uses})
			// The allowlist-rot check fires whenever checkClockSkew is absent from
			// the builder set; ignore it here so each case asserts its own subject.
			gaps = withoutRotWarnings(gaps, tc.fn)
			if got := len(gaps) > 0; got != tc.wantGap {
				t.Fatalf("gap=%v, want %v (gaps=%v)", got, tc.wantGap, gaps)
			}
		})
	}
}

// An allowlist entry that no longer names a builder must fail, so the list
// cannot outlive the finding it documents.
func TestUnreachableEmitters_AllowlistCannotRot(t *testing.T) {
	gaps := unreachableFrom(map[string]token.Position{}, map[string]int{})
	found := false
	for _, g := range gaps {
		if strings.Contains(g, "checkClockSkew") && strings.Contains(g, "remove the exemption") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a stale allowlist entry must be reported; got %v", gaps)
	}
}

// withoutRotWarnings drops the allowlist-rot messages for every name except the
// case's own subject, so a case about one builder isn't perturbed by another
// allowlist entry being absent from its synthetic builder set.
func withoutRotWarnings(gaps []string, subject string) []string {
	var out []string
	for _, g := range gaps {
		if strings.Contains(g, "remove the exemption") && !strings.Contains(g, subject) {
			continue
		}
		out = append(out, g)
	}
	return out
}
