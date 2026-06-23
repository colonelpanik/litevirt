package grpcapi

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
)

// lbRunsOnHost: an explicit host in cfg.Hosts, or (empty hosts) a host with VMs
// in the LB's stack.
func TestLBRunsOnHost(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := adminCtx()

	if !s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "a-lb", Hosts: `["test-host","x"]`}) {
		t.Error("explicit host match should run here")
	}
	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "b-lb", Hosts: `["other-host"]`}) {
		t.Error("explicit non-match should NOT run here")
	}
	// Empty hosts: runs where the stack has VMs.
	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "c-lb", StackName: "app"}) {
		t.Error("empty hosts + no local stack VMs → should not run here")
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "app-1", StackName: "app", HostName: "test-host", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "c-lb", StackName: "app"}) {
		t.Error("empty hosts + a local stack VM → should run here")
	}
}

// refreshLBMetrics publishes the keepalived gauge for LBs this host runs (live
// value via the seam) and clears it for LBs it doesn't — so the gauge tracks
// live state continuously, not just at apply time.
func TestRefreshLBMetrics(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := adminCtx()

	reg := prometheus.NewRegistry()
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "litevirt_lb_keepalived_up_test2", Help: "t"}, []string{"lb"})
	reg.MustRegister(g)
	s.lbMetrics = &metrics.LBMetrics{KeepalivedUp: g}

	// Owned LB (runs here) + a foreign LB (runs elsewhere).
	mustUpsertLB(t, ctx, s, "mine-lb", `["test-host"]`)
	mustUpsertLB(t, ctx, s, "theirs-lb", `["other-host"]`)

	s.lbKeepalivedOverride = func(string) bool { return true } // VIP up
	s.refreshLBMetrics(ctx)
	if v, ok := lbGauge(t, reg, "mine-lb"); !ok || v != 1 {
		t.Errorf("mine-lb gauge = %v (present=%v), want 1", v, ok)
	}
	if _, ok := lbGauge(t, reg, "theirs-lb"); ok {
		t.Error("a foreign LB should not be reported here")
	}

	// keepalived goes down → gauge flips to 0 on the next refresh (continuous).
	s.lbKeepalivedOverride = func(string) bool { return false }
	s.refreshLBMetrics(ctx)
	if v, _ := lbGauge(t, reg, "mine-lb"); v != 0 {
		t.Errorf("mine-lb gauge = %v, want 0 after keepalived down", v)
	}
}

// The LBKeepalivedRunning RPC returns THIS host's keepalived state for an LB.
func TestLBKeepalivedRunningRPC(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.lbKeepalivedOverride = func(string) bool { return true }
	if resp, err := s.LBKeepalivedRunning(ctx, &pb.LBKeepalivedRequest{Name: "x-lb"}); err != nil || !resp.Running {
		t.Fatalf("running=true expected, got %v err=%v", resp, err)
	}
	s.lbKeepalivedOverride = func(string) bool { return false }
	if resp, _ := s.LBKeepalivedRunning(ctx, &pb.LBKeepalivedRequest{Name: "x-lb"}); resp.Running {
		t.Error("running=false expected")
	}
}

// lbVIPDegraded: degraded only when a host answered AND none report keepalived
// up. A remote that's unreachable / on an old version (RPC Unimplemented) is
// not a definitive answer, so it must never produce a false degraded.
func TestLBVIPDegraded(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := adminCtx()

	s.lbKeepalivedOverride = func(string) bool { return true }
	if s.lbVIPDegraded(ctx, "lb", []string{"test-host"}) {
		t.Error("local keepalived up → not degraded")
	}
	s.lbKeepalivedOverride = func(string) bool { return false }
	if !s.lbVIPDegraded(ctx, "lb", []string{"test-host"}) {
		t.Error("local keepalived down → degraded")
	}
	// any-up across hosts → healthy (a backup keepalived can hold the VIP).
	s.lbKeepalivedOverride = func(string) bool { return true }
	if s.lbVIPDegraded(ctx, "lb", []string{"test-host", "other-host"}) {
		t.Error("at least one keepalived up → not degraded")
	}
	// Only an unreachable/old-version remote → no definitive answer → NOT
	// degraded (mixed-version safety).
	if s.lbVIPDegraded(ctx, "lb", []string{"other-host"}) {
		t.Error("unreachable/old remote → no answer → must not be degraded")
	}
}

func mustUpsertLB(t *testing.T, ctx context.Context, s *Server, name, hosts string) {
	t.Helper()
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: name, VIP: "10.0.0.9/24", Algorithm: "roundrobin", Hosts: hosts, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func lbGauge(t *testing.T, reg *prometheus.Registry, lb string) (float64, bool) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "lb" && l.GetValue() == lb {
					return m.GetGauge().GetValue(), true
				}
			}
		}
	}
	return 0, false
}
