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

// TestRepairLegacyLBHolder_ProbesParticipants: the migration repair backfills a
// holder ONLY when the cluster-wide participant probe proves exactly one, and
// never touches a stack LB or an already-owned row. Zero or multiple participants
// are left unowned (not guessed).
func TestRepairLegacyLBHolder_ProbesParticipants(t *testing.T) {
	s := testServerR2(t)
	ctx := context.Background()

	// Guards: stack LB and already-owned rows are returned untouched.
	if got := s.repairLegacyLBHolder(ctx, corrosion.LBConfigRecord{Name: "x", StackName: "s", Hosts: "[]"}); got.Hosts != "[]" {
		t.Errorf("stack LB must not be repaired; hosts = %q", got.Hosts)
	}
	if got := s.repairLegacyLBHolder(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: `["h"]`}); got.Hosts != `["h"]` {
		t.Errorf("already-owned LB must not be re-claimed; hosts = %q", got.Hosts)
	}

	// Zero participants → left unowned.
	s.lbParticipantsOverride = func(context.Context, string) ([]string, bool) { return nil, true }
	if got := s.repairLegacyLBHolder(ctx, corrosion.LBConfigRecord{Name: "none", Hosts: "[]"}); got.Hosts != "[]" {
		t.Errorf("no participants → must stay unowned; hosts = %q", got.Hosts)
	}
	// Multiple participants → ambiguous, left unowned (not guessed).
	s.lbParticipantsOverride = func(context.Context, string) ([]string, bool) { return []string{"a", "b"}, true }
	if got := s.repairLegacyLBHolder(ctx, corrosion.LBConfigRecord{Name: "multi", Hosts: "[]"}); got.Hosts != "[]" {
		t.Errorf("multiple participants → must stay unowned; hosts = %q", got.Hosts)
	}

	// Exactly one proven participant → backfilled as the durable holder.
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "one", VIP: "10.0.0.7/24", Hosts: "[]", Enabled: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s.lbParticipantsOverride = func(context.Context, string) ([]string, bool) { return []string{"holder-h"}, true }
	if got := s.repairLegacyLBHolder(ctx, corrosion.LBConfigRecord{Name: "one", Hosts: "[]"}); got.Hosts != `["holder-h"]` {
		t.Errorf("exactly one participant → must backfill it as holder; hosts = %q", got.Hosts)
	}
}
