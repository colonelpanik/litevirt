package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestRBACPathBuilders verifies the per-resource RBAC path builders canonicalize
// the project (no double slash, no "acme" vs "/acme" drift) and map a malformed
// project to a deny-safe sentinel that can't collide with a real tenant grant.
func TestRBACPathBuilders(t *testing.T) {
	cases := []struct {
		project, name, wantVM, wantCT string
	}{
		{"", "web", "/projects/_default/vms/web", "/projects/_default/containers/web"},
		{"_default", "web", "/projects/_default/vms/web", "/projects/_default/containers/web"},
		{"acme", "web", "/projects/acme/vms/web", "/projects/acme/containers/web"},
		{"acme/team", "web", "/projects/acme/team/vms/web", "/projects/acme/team/containers/web"},
		{"/acme/team", "web", "/projects/acme/team/vms/web", "/projects/acme/team/containers/web"},
	}
	for _, c := range cases {
		if got := vmRBACPathFor(c.project, c.name); got != c.wantVM {
			t.Errorf("vmRBACPathFor(%q,%q) = %q, want %q", c.project, c.name, got, c.wantVM)
		}
		if got := ctRBACPathFor(c.project, c.name); got != c.wantCT {
			t.Errorf("ctRBACPathFor(%q,%q) = %q, want %q", c.project, c.name, got, c.wantCT)
		}
		if got := vmRBACPath(&corrosion.VMRecord{Project: c.project, Name: c.name}); got != c.wantVM {
			t.Errorf("vmRBACPath(%q,%q) = %q, want %q", c.project, c.name, got, c.wantVM)
		}
	}

	// A traversal project must NOT map onto another tenant's path — it gets the
	// deny-safe sentinel (matches only a cluster-root "/" grant).
	bad := vmRBACPathFor("../../etc", "web")
	if bad != "/projects/\x00invalid/vms/web" {
		t.Errorf("malformed project = %q, want sentinel path", bad)
	}
}

// TestScheduleRBACTarget_PoolSentinel verifies a malformed pool name yields the
// deny-safe sentinel rather than concatenating into a real pool's grant.
func TestScheduleRBACTarget_PoolSentinel(t *testing.T) {
	s := &Server{}
	if got := s.scheduleRBACTarget(nil, "pool", "", "main", ""); got != "/storage/pools/main" {
		t.Errorf("good pool = %q", got)
	}
	if got := s.scheduleRBACTarget(nil, "pool", "", "../etc", ""); got != "/storage/pools/\x00invalid" {
		t.Errorf("bad pool = %q, want sentinel", got)
	}
}
