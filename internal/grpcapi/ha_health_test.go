package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// capabilityDegradedReason: vip_demote_v1 is a SOFTWARE capability (no watchdog gate), so
// a member that can't confirm any supported token — including vip_demote_v1 — is simply an
// unsupported member mid-roll. (The "demoted but can't self-fence" state is a per-node
// runtime condition surfaced via haDemotionUnfenced, not here.)
func TestCapabilityDegradedReason(t *testing.T) {
	if r := capabilityDegradedReason(capabilities.SplitBrainGateV1, true, ""); r != "" {
		t.Fatalf("active token → no degrade; got %q", r)
	}
	if r := capabilityDegradedReason(capabilities.VIPDemoteV1, false, health.ReasonUnsupportedCapability); r != haUnsupportedMember {
		t.Fatalf("unsupported vip_demote token → unsupported_member; got %q", r)
	}
	if r := capabilityDegradedReason(capabilities.VIPDemoteV1, false, health.ReasonActivationUnconfirm); r != haUnsupportedMember {
		t.Fatalf("unreachable member → unsupported_member; got %q", r)
	}
	if r := capabilityDegradedReason(capabilities.SplitBrainGateV1, false, health.ReasonUnsupportedCapability); r != haUnsupportedMember {
		t.Fatalf("non-vip token unsupported → unsupported_member; got %q", r)
	}
}

// vipUnheld alarms ONLY on a definitive no-holder state: every participant reachable and
// none claiming. An unreachable participant or any claimant suppresses the alarm.
func TestVIPUnheld(t *testing.T) {
	cfg := corrosion.LBConfigRecord{Name: "lb", VIP: "10.0.0.9/24", Hosts: `["p1","p2"]`, Enabled: true}
	newS := func(st map[string]holderStatus) *Server {
		return &Server{hostName: "self", probeHolder: func(_ context.Context, host, _ string) holderStatus {
			return st[host]
		}}
	}
	ctx := context.Background()

	// All reachable, neither claims → unheld (alarm).
	s := newS(map[string]holderStatus{
		"p1": {reachable: true, assigned: false},
		"p2": {reachable: true, assigned: false},
	})
	if !s.vipUnheld(ctx, cfg) {
		t.Fatal("all reachable + none claiming → unheld")
	}
	// One claims → held.
	s = newS(map[string]holderStatus{
		"p1": {reachable: true, assigned: true},
		"p2": {reachable: true, assigned: false},
	})
	if s.vipUnheld(ctx, cfg) {
		t.Fatal("a claimant means it's held")
	}
	// One unreachable → indeterminate, no alarm.
	s = newS(map[string]holderStatus{
		"p1": {reachable: false},
		"p2": {reachable: true, assigned: false},
	})
	if s.vipUnheld(ctx, cfg) {
		t.Fatal("an unreachable participant must suppress the alarm (indeterminate)")
	}
}

// anyStrandedPending detects a markerless (no pending_action_id) state=pending VM assigned
// here — the enforcement-flip legacy-pending stranding surfaced as HA-degraded.
func TestAnyStrandedPending(t *testing.T) {
	s := testServerR2(t) // hostName "test-host"
	ctx := adminCtx()
	if s.anyStrandedPending(ctx) {
		t.Fatal("no VMs → not stranded")
	}
	// A running VM (not pending) is never a stranded transfer — exercises the state filter.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vmrun", HostName: "test-host", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if s.anyStrandedPending(ctx) {
		t.Fatal("a running VM is not a stranded pending transfer")
	}
	// A markerless state=pending VM assigned here → stranded.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vmbad", HostName: "test-host", State: "pending",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if !s.anyStrandedPending(ctx) {
		t.Fatal("a markerless pending VM must be detected as stranded")
	}
}

// evaluateHADegraded flags vip_no_holder when the gate is enforced and a configured VIP is
// held by nobody.
func TestEvaluateHADegraded_VIPNoHolder(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.enfVIPProofReclaim = true // vip_no_holder keys off vipHAHealthEnabled (either VIP flag)
	s.vipGateFlipped = func() bool { return true }
	s.probeHolder = func(context.Context, string, string) holderStatus {
		return holderStatus{reachable: true, assigned: false} // reachable, holds nothing
	}
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "lbz", VIP: "10.0.77.1/24", Algorithm: "roundrobin",
		Hosts: `["p1"]`, Ports: "[]", Enabled: true, Generation: "g1",
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if got := s.evaluateHADegraded(ctx); !got[haVIPNoHolder] {
		t.Fatalf("expected vip_no_holder degraded; got %v", got)
	}
	// With a claimant, no alarm.
	s.probeHolder = func(context.Context, string, string) holderStatus {
		return holderStatus{reachable: true, assigned: true}
	}
	if got := s.evaluateHADegraded(ctx); got[haVIPNoHolder] {
		t.Fatalf("held VIP must not be vip_no_holder; got %v", got)
	}
}
