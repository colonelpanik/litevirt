package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestProvisionPlannedNetworks_PeerFailureSurfaces is the B3 regression: when a
// peer target's network can't be provisioned, provisionPlannedNetworks must
// return an error (naming the host) instead of silently reporting a clean
// deploy. We target a host that isn't in cluster state, so peerClient fails.
func TestProvisionPlannedNetworks_PeerFailureSurfaces(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	s := &Server{db: db, hostName: "host-a"}

	f := &compose.File{
		Name:     "s1",
		Networks: map[string]compose.NetworkDef{"net1": {Type: "bridge"}},
	}
	// Target a peer that does NOT exist in cluster state. host-a (self) is not a
	// target, so the local-provision path is skipped and only the peer loop runs.
	plan := &planner.ResolvedPlan{
		StackName: "s1",
		Networks: []planner.NetworkAction{{
			Name:        "net1",
			Type:        "bridge",
			TargetHosts: []string{"ghost-host"},
		}},
	}

	err = s.provisionPlannedNetworks(context.Background(), f, plan, nil)
	if err == nil {
		t.Fatal("expected an error when a peer target's network provisioning fails, got nil (silent success)")
	}
	if !strings.Contains(err.Error(), "ghost-host") {
		t.Errorf("error should name the failed host, got %v", err)
	}
}

// TestProvisionPlannedNetworks_NoPeersNoError confirms the happy path: when the
// only target is the local host (no peers), the peer loop has nothing to do and
// no spurious error is returned.
func TestProvisionPlannedNetworks_NoPeersNoError(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	s := &Server{db: db, hostName: "host-a"}

	f := &compose.File{
		Name:     "s1",
		Networks: map[string]compose.NetworkDef{"net1": {Type: "bridge"}},
	}
	// No TargetHosts at all → no peer provisioning, no local provisioning.
	plan := &planner.ResolvedPlan{
		StackName: "s1",
		Networks:  []planner.NetworkAction{{Name: "net1", Type: "bridge"}},
	}

	if err := s.provisionPlannedNetworks(context.Background(), f, plan, nil); err != nil {
		t.Fatalf("unexpected error with no peer targets: %v", err)
	}
}
