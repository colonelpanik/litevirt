package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// corruptHosts is a non-empty value that is NOT valid JSON and is NOT one of the
// legacy unowned shapes ("" / "[]" / "null") — so parseHostsJSON must read it as
// UNKNOWN (ok=false), the case the fail-closed contract exists to catch.
const corruptHosts = `{"not":"an array"`

// TestParseHostsJSON_Contract pins the fail-closed contract the LB host-ownership
// logic depends on: legacy unowned shapes parse as an empty (owned-by-nobody) set,
// a real host list parses, and only a corrupt non-empty value reads as UNKNOWN.
func TestParseHostsJSON_Contract(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantHost []string
		wantOK   bool
	}{
		{"", nil, true},     // legacy: no --host given
		{"[]", nil, true},   // explicit empty
		{"null", nil, true}, // nil slice marshaled by an older CLI
		{`["a","b"]`, []string{"a", "b"}, true},
		{corruptHosts, nil, false}, // corrupt ⇒ UNKNOWN, fail closed
		{`["a"`, nil, false},       // truncated array ⇒ UNKNOWN
	} {
		got, ok := parseHostsJSON(tc.in)
		if ok != tc.wantOK {
			t.Errorf("parseHostsJSON(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
		}
		if len(got) != len(tc.wantHost) {
			t.Errorf("parseHostsJSON(%q) = %v, want %v", tc.in, got, tc.wantHost)
		}
	}
}

// TestUpdateLB_CorruptHostsRefused: a corrupt stored hosts column makes the host
// set UNKNOWN, so an update must FAIL CLOSED (FailedPrecondition) BEFORE mutating
// anything — never silently act on an unresolvable ownership set.
func TestUpdateLB_CorruptHostsRefused(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	createLBTable(t, ctx, s.db)

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "corrupt-lb", VIP: "10.0.0.1/24", Algorithm: "roundrobin",
		Hosts: corruptHosts, Enabled: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// A pure backend/algorithm edit (no host or VIP change) still reads the stored
	// host set (local apply + stale-holder cleanup) — so a corrupt row must refuse.
	_, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "corrupt-lb", Algorithm: "leastconn"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Update on corrupt hosts: code = %v, want FailedPrecondition", status.Code(err))
	}

	// The refusal is pre-mutation: the stored algorithm must be untouched.
	rows, _ := s.db.Query(ctx, `SELECT algorithm FROM lb_configs WHERE name = 'corrupt-lb'`)
	if len(rows) != 1 || rows[0].String("algorithm") != "roundrobin" {
		t.Errorf("refused update must not mutate the row; algorithm = %q, want roundrobin", rows[0].String("algorithm"))
	}
}

// TestDeleteLB_CorruptHostsTearsDownEverywhere: deletion is the remediation for a
// corrupt row, so Delete must NEVER refuse. A corrupt host set falls back to
// tearing down on ALL known hosts, and a per-host teardown failure against an
// unreachable peer must not abort the delete — the row still tombstones.
func TestDeleteLB_CorruptHostsTearsDownEverywhere(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	createLBTable(t, ctx, s.db)

	// Peers present so the all-known-hosts fan-out is exercised; peerClient can't
	// dial them (no PKI in unit tests) — those failures must not abort the delete.
	for _, h := range []string{"peer-a", "peer-b"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.9", State: "active"}); err != nil {
			t.Fatalf("InsertHost(%s): %v", h, err)
		}
	}

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "corrupt-del", VIP: "10.0.0.2/24", Algorithm: "roundrobin",
		Hosts: corruptHosts, Enabled: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := corrosion.UpsertLBBackend(ctx, s.db, corrosion.LBBackendRecord{
		LBName: "corrupt-del", Name: "b1", Address: "10.0.1.1", Enabled: true,
	}); err != nil {
		t.Fatalf("seed backend: %v", err)
	}

	if _, err := s.DeleteLoadBalancer(ctx, &pb.DeleteLBRequest{Name: "corrupt-del"}); err != nil {
		t.Fatalf("Delete on corrupt hosts must succeed (deletion is the remediation), got: %v", err)
	}

	rows, _ := s.db.Query(ctx, `SELECT deleted_at FROM lb_configs WHERE name = 'corrupt-del'`)
	if len(rows) != 1 || rows[0].String("deleted_at") == "" {
		t.Errorf("corrupt LB must be tombstoned after delete, got %+v", rows)
	}
	if backends, _ := corrosion.ListLBBackends(ctx, s.db, "corrupt-del"); len(backends) != 0 {
		t.Errorf("backends must be removed on delete, got %d", len(backends))
	}
}

// TestLbRunsOnHost_CorruptFailsClosed: a reconcile-path membership check on a
// corrupt hosts column must fail closed — this host does NOT claim the LB (a
// guessed claim could double-serve the VIP).
func TestLbRunsOnHost_CorruptFailsClosed(t *testing.T) {
	s := testServerCov(t)
	ctx := context.Background()
	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: corruptHosts}) {
		t.Error("corrupt hosts column must NOT be claimed by this host (fail closed)")
	}
}

// TestReapplyExplicitLB_CorruptSkips: the reconciler must NOT re-apply an LB whose
// stored host set is corrupt (unresolvable ownership); a valid host set still
// applies (control).
func TestReapplyExplicitLB_CorruptSkips(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	createLBTable(t, ctx, s.db)

	applied := false
	s.lbApplyOverride = func(context.Context, lb.Config) error { applied = true; return nil }

	// Corrupt hosts, valid VIP (so ParseVIP doesn't short-circuit first): must skip.
	s.reapplyExplicitLB(ctx, corrosion.LBConfigRecord{Name: "c", VIP: "10.0.0.5/24", Hosts: corruptHosts})
	if applied {
		t.Error("reapplyExplicitLB must NOT apply an LB with a corrupt hosts column")
	}

	// Control: a valid host set naming this host applies.
	s.reapplyExplicitLB(ctx, corrosion.LBConfigRecord{Name: "c", VIP: "10.0.0.5/24", Hosts: `["test-host"]`})
	if !applied {
		t.Error("reapplyExplicitLB must apply an LB with a valid host set (control)")
	}
}

// TestListInspectLB_CorruptSurfacesUnknown: display paths must not crash or invent
// members on a corrupt hosts column — they surface an empty (UNKNOWN) host set.
func TestListInspectLB_CorruptSurfacesUnknown(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	createLBTable(t, ctx, s.db)

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "corrupt-show", VIP: "10.0.0.3/24", Algorithm: "roundrobin",
		Hosts: corruptHosts, Enabled: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp, err := s.ListLoadBalancers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListLoadBalancers: %v", err)
	}
	var found bool
	for _, l := range resp.Lbs {
		if l.Name == "corrupt-show" {
			found = true
			if len(l.LbHosts) != 0 {
				t.Errorf("List must surface UNKNOWN (empty) hosts on corrupt row, got %v", l.LbHosts)
			}
		}
	}
	if !found {
		t.Fatal("corrupt LB must still be listed")
	}

	insp, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "corrupt-show"})
	if err != nil {
		t.Fatalf("InspectLoadBalancer on corrupt row must not error, got: %v", err)
	}
	if len(insp.LbHosts) != 0 {
		t.Errorf("Inspect must surface UNKNOWN (empty) hosts on corrupt row, got %v", insp.LbHosts)
	}
}

// TestInspectLB_CorruptStackStaysUnknown: a STACK LB with a corrupt hosts column
// must NOT be repopulated from its stack's VM hosts — that would mask the
// corruption behind a fabricated (guessed) membership. A legacy-empty stack LB
// (hosts parses cleanly as unowned) still expands to VM-derived membership.
func TestInspectLB_CorruptStackStaysUnknown(t *testing.T) {
	s := testServerCov(t)
	ctx := adminCtx()
	createLBTable(t, ctx, s.db)

	// A VM in stack "app" on host "vh1" — VM-derived membership WOULD resolve to it.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "appvm", StackName: "app", HostName: "vh1", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Corrupt STACK LB → membership must stay UNKNOWN (empty), NOT expand to vh1.
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "cstack", StackName: "app", VIP: "10.0.0.5/24", Algorithm: "roundrobin",
		Hosts: corruptHosts, Enabled: true,
	}); err != nil {
		t.Fatalf("seed corrupt stack LB: %v", err)
	}
	if insp, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "cstack"}); err != nil {
		t.Fatalf("Inspect corrupt stack LB: %v", err)
	} else if len(insp.LbHosts) != 0 {
		t.Errorf("corrupt stack LB must stay UNKNOWN (not expand to VM hosts), got %v", insp.LbHosts)
	}

	// Control: a legacy-empty stack LB (hosts="null", parses cleanly) DOES expand.
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "lstack", StackName: "app", VIP: "10.0.0.6/24", Algorithm: "roundrobin",
		Hosts: "null", Enabled: true,
	}); err != nil {
		t.Fatalf("seed legacy stack LB: %v", err)
	}
	if insp, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "lstack"}); err != nil {
		t.Fatalf("Inspect legacy stack LB: %v", err)
	} else if len(insp.LbHosts) != 1 || insp.LbHosts[0] != "vh1" {
		t.Errorf("legacy-empty stack LB must expand to VM hosts [vh1], got %v", insp.LbHosts)
	}
}
