package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// TestCreateLoadBalancer_PersistsDurableHolder: an explicit LB created with no
// hosts must persist a concrete holder ([self]), not [] — otherwise a later
// update/reapply entering through another node can't tell who serves the VIP.
func TestCreateLoadBalancer_PersistsDurableHolder(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.vipGateFlipped = func() bool { return true }
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil } // no real haproxy
	s.vipHoldersOverride = func(context.Context, string) ([]string, bool) {
		return nil, true // VIP unassigned everywhere
	}

	if _, err := s.CreateLoadBalancer(ctx, &pb.CreateLBRequest{
		Name: "lbNoHosts", Vip: "10.0.100.92/24", Algorithm: "roundrobin",
		Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []*pb.LBBackendAddress{{Name: "b1", Address: "10.0.0.9"}},
		// Hosts intentionally empty.
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	rows, _ := s.db.Query(ctx, `SELECT hosts FROM lb_configs WHERE name = 'lbNoHosts' AND deleted_at IS NULL`)
	if len(rows) == 0 {
		t.Fatal("LB row not persisted")
	}
	if got := rows[0].String("hosts"); got != `["test-host"]` {
		t.Errorf("explicit LB with no hosts must persist a durable holder [test-host]; hosts = %q", got)
	}
}

// TestLBRunsOnHost_ExplicitNeedsRecordedHolder: an explicit LB (no stack) with no
// recorded holder must NOT be claimed by an arbitrary host — only VM-derived
// membership for a STACK LB may run without an explicit host list.
func TestLBRunsOnHost_ExplicitNeedsRecordedHolder(t *testing.T) {
	s := testServerR2(t)
	ctx := context.Background()

	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: "[]"}) {
		t.Error("explicit LB with empty hosts must not run on an arbitrary host")
	}
	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: ""}) {
		t.Error("explicit LB with unset hosts must not run here")
	}
	if !s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: `["test-host"]`}) {
		t.Error("explicit LB whose recorded holder is this host must run here")
	}
	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: `["other"]`}) {
		t.Error("explicit LB held by another host must not run here")
	}
	// Stack LB, empty hosts, no local VMs → derived membership yields false (not a
	// blanket claim). The StackName != "" branch is what permits VM-derived running.
	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", StackName: "s", Hosts: "[]"}) {
		t.Error("stack LB with no local VMs must not run here")
	}
}

// TestRepairLegacyLBHolder_Guards: the migration repair only claims a legacy
// explicit LB this host is actually serving. A stack LB, an already-owned LB, or
// an LB whose keepalived isn't running here (the default in tests) is left as-is —
// so a non-holder never claims a VIP.
func TestRepairLegacyLBHolder_Guards(t *testing.T) {
	s := testServerR2(t)
	ctx := context.Background()

	if got := s.repairLegacyLBHolder(ctx, corrosion.LBConfigRecord{Name: "x", StackName: "s", Hosts: "[]"}); got.Hosts != "[]" {
		t.Errorf("stack LB must not be repaired; hosts = %q", got.Hosts)
	}
	if got := s.repairLegacyLBHolder(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: `["h"]`}); got.Hosts != `["h"]` {
		t.Errorf("already-owned LB must not be re-claimed; hosts = %q", got.Hosts)
	}
	// Explicit unowned LB, but keepalived for it isn't running on this host (no
	// pidfile in the test env) → not claimed, left for the real holder.
	if got := s.repairLegacyLBHolder(ctx, corrosion.LBConfigRecord{Name: "not-running-lb", Hosts: "[]"}); got.Hosts != "[]" {
		t.Errorf("must not claim an LB this host isn't serving; hosts = %q", got.Hosts)
	}
}
