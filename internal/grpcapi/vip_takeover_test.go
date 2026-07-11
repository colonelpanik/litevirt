package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// vipMoveRefused is INERT until vip_proof_reclaim is enabled — even a removed holder
// that still holds the VIP does not refuse while the enforcement.vip_proof_reclaim
// config flag is off (its default). The token is advertised by this build, so
// inertness here comes from the kill-switch flag being off, not de-advertisement.
func TestVIPMove_InertUntilFlipped(t *testing.T) {
	// enfVIPProofReclaim defaults false (kill-switch off) and gate is nil.
	s := &Server{hostName: "self", probeHolder: func(context.Context, string, string) holderStatus {
		return holderStatus{reachable: true, assigned: true} // still holds it
	}}
	if _, refused := s.vipMoveRefused(context.Background(), "lb", "10.0.0.1", "10.0.0.1", []string{"old"}, []string{"new"}, true, true); refused {
		t.Fatal("must be inert (not refuse) while enforcement.vip_proof_reclaim is off")
	}
}

// TestVIPProofReclaim_KillSwitch: the config flag disables proof-required reclaim
// even when the VIPReleaseProbeV1 capability is enforced cluster-wide (redeploy-free
// stand-down). Mirrors the safe_fence kill-switch test.
func TestVIPProofReclaim_KillSwitch(t *testing.T) {
	s := &Server{
		hostName:           "self",
		enfVIPProofReclaim: false,                          // kill-switch OFF
		gate:               fakeServerGate{enforced: true}, // capability latched cluster-wide
		removeLBFromHost:   func(context.Context, string, string) error { return nil },
		probeHolder: func(context.Context, string, string) holderStatus {
			return holderStatus{reachable: true, assigned: true} // still holds
		},
	}
	if s.vipGateActive(context.Background()) {
		t.Fatal("config flag off must keep the gate inert even with the capability enforced")
	}
	if _, refused := s.vipMoveRefused(context.Background(), "lb", "10.0.0.1", "10.0.0.1", []string{"old"}, []string{"new"}, true, true); refused {
		t.Fatal("kill-switch off must not refuse (legacy behavior) despite a still-holding removed holder")
	}
}

// vipMoveRefused is a TRANSITION predicate: it acts ONLY on the removed holders
// (old∖new), never unchanged/added ones, and requires a STRONG release proof —
// synchronous stand-down (RemoveLB) AND the VIP absent afterwards.
func TestVIPMove_TransitionPredicate(t *testing.T) {
	statuses := map[string]holderStatus{
		"still-holds": {reachable: true, assigned: true},
		"released":    {reachable: true, assigned: false},
	}
	newS := func() *Server {
		return &Server{
			hostName:           "self",
			vipGateFlipped:     func() bool { return true }, // activate the gate for the test
			enfVIPProofReclaim: true,
			removeLBFromHost:   func(context.Context, string, string) error { return nil }, // stand-down "succeeds"
			probeHolder: func(_ context.Context, host, _ string) holderStatus {
				return statuses[host]
			},
		}
	}
	ctx := context.Background()

	// A REMOVED holder that still holds the VIP (after stand-down) → refuse.
	if _, refused := newS().vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", []string{"still-holds"}, []string{"new"}, true, true); !refused {
		t.Fatal("a removed holder still assigned the VIP must refuse the move")
	}
	// The SAME still-assigned holder, but UNCHANGED (in both old and new) → allow.
	// High-2 regression: a snapshot "any other holder assigned?" predicate would break
	// normal multi-host VRRP here.
	if _, refused := newS().vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", []string{"still-holds"}, []string{"still-holds", "new"}, true, true); refused {
		t.Fatal("an UNCHANGED holder that still has the VIP must NOT refuse (normal VRRP)")
	}
	// A pure ADD (added a host, removed none) → allow even though a current holder holds it.
	if _, refused := newS().vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", []string{"still-holds"}, []string{"still-holds"}, true, true); refused {
		t.Fatal("no removed holders (add/refresh) must allow")
	}
	// A removed holder that has RELEASED (post stand-down) → allow.
	if _, refused := newS().vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", []string{"released"}, []string{"new"}, true, true); refused {
		t.Fatal("a removed holder that released the VIP must allow the move")
	}
	// UNKNOWN old membership → refuse (fail closed).
	if _, refused := newS().vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", nil, []string{"new"}, false, true); !refused {
		t.Fatal("unknown old membership must refuse (fail closed)")
	}
}

// vipGateActive routes through the CLUSTER-WIDE latch (gate.Enforced), NOT a local
// "does this build advertise it" check — so the flip can't activate Phase 2 on one node
// before every member participates. With Enforced=false the gate is inert even with a
// still-holding removed holder; flipping Enforced=true activates it.
func TestVIPMove_UsesClusterLatch(t *testing.T) {
	newS := func(enforced bool) *Server {
		return &Server{
			hostName:           "self",
			enfVIPProofReclaim: true,                               // config kill-switch on
			gate:               fakeServerGate{enforced: enforced}, // no vipGateFlipped seam → real path
			removeLBFromHost:   func(context.Context, string, string) error { return nil },
			probeHolder: func(context.Context, string, string) holderStatus {
				return holderStatus{reachable: true, assigned: true} // still holds
			},
		}
	}
	ctx := context.Background()

	// Not enforced cluster-wide → inert (not refused) even though the removed holder holds it.
	if _, refused := newS(false).vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", []string{"old"}, []string{"new"}, true, true); refused {
		t.Fatal("must be inert until vip_demote_v1 is ENFORCED cluster-wide (latch), not just built")
	}
	// Latched enforced → active → the still-holding removed holder refuses.
	if _, refused := newS(true).vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", []string{"old"}, []string{"new"}, true, true); !refused {
		t.Fatal("once enforced cluster-wide, a still-holding removed holder must refuse")
	}
}

// High-2: ADDING a participant while a RETAINED existing participant is UNREACHABLE must
// refuse — bringing up a new VRRP claimant beside an unreachable-but-maybe-live holder
// risks dual-master (adverts unseen). No holder is removed here (pure add).
func TestVIPMove_AddWhileExistingUnreachableRefuses(t *testing.T) {
	s := &Server{
		hostName:           "self",
		vipGateFlipped:     func() bool { return true },
		enfVIPProofReclaim: true,
		probeHolder: func(_ context.Context, host, _ string) holderStatus {
			if host == "a" {
				return holderStatus{reachable: false} // existing holder unreachable
			}
			return holderStatus{reachable: true, assigned: false}
		},
	}
	// old=[a], new=[a,b] — adding b as a backup while a (still first/master) is unreachable.
	if _, refused := s.vipMoveRefused(context.Background(), "lb", "10.0.0.1", "10.0.0.1", []string{"a"}, []string{"a", "b"}, true, true); !refused {
		t.Fatal("adding a participant while an existing one is unreachable must refuse")
	}
	// Sanity: with a reachable, the same add is allowed.
	s.probeHolder = func(context.Context, string, string) holderStatus {
		return holderStatus{reachable: true, assigned: false}
	}
	if _, refused := s.vipMoveRefused(context.Background(), "lb", "10.0.0.1", "10.0.0.1", []string{"a"}, []string{"a", "b"}, true, true); refused {
		t.Fatal("adding a participant with all existing ones reachable must be allowed")
	}
}

// High-2: a first-host (VRRP master) change is takeover-like — the OLD master must be
// stood down (break-before-make) and provably released before the new master claims,
// even though it REMAINS in the set as a backup.
func TestVIPMove_MasterChangeStandsDownOldMaster(t *testing.T) {
	var stoodDown []string
	newS := func(oldMasterReleased bool) *Server {
		return &Server{
			hostName:           "self",
			vipGateFlipped:     func() bool { return true },
			enfVIPProofReclaim: true,
			removeLBFromHost: func(_ context.Context, _, host string) error {
				stoodDown = append(stoodDown, host)
				return nil
			},
			probeHolder: func(_ context.Context, host, _ string) holderStatus {
				if host == "a" {
					return holderStatus{reachable: true, assigned: !oldMasterReleased}
				}
				return holderStatus{reachable: true, assigned: false}
			},
		}
	}
	ctx := context.Background()

	// old=[a] (a master), new=[b,a] (b becomes master, a demotes to backup). a still holds → refuse.
	stoodDown = nil
	if _, refused := newS(false).vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", []string{"a"}, []string{"b", "a"}, true, true); !refused {
		t.Fatal("a master change must refuse while the old master still holds the VIP")
	}
	if len(stoodDown) == 0 || stoodDown[0] != "a" {
		t.Fatalf("the old master must be stood down (break-before-make); stoodDown=%v", stoodDown)
	}
	// Old master released after stand-down → the master change is allowed.
	stoodDown = nil
	if _, refused := newS(true).vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", []string{"a"}, []string{"b", "a"}, true, true); refused {
		t.Fatal("a master change must be allowed once the old master has released")
	}
}

// A removed holder whose stand-down (RemoveLB) FAILS must refuse: we can't confirm its
// keepalived is inert, so it could still become VRRP master and re-claim the VIP —
// even though its kernel currently reports the VIP absent.
func TestVIPMove_StandDownFailureRefuses(t *testing.T) {
	s := &Server{
		hostName:           "self",
		vipGateFlipped:     func() bool { return true },
		enfVIPProofReclaim: true,
		removeLBFromHost:   func(context.Context, string, string) error { return errors.New("unreachable") },
		probeHolder: func(context.Context, string, string) holderStatus {
			return holderStatus{reachable: true, assigned: false} // VIP absent right now
		},
	}
	if _, refused := s.vipMoveRefused(context.Background(), "lb", "10.0.0.1", "10.0.0.1", []string{"old"}, []string{"new"}, true, true); !refused {
		t.Fatal("a removed holder that can't be stood down must refuse (keepalived not confirmed inert)")
	}
}

// High-2: when stored old membership is EMPTY, the gate resolves ACTUAL PARTICIPANTS by
// lbName (ground truth — incl. VRRP backups) so an implicit/legacy hosts=[] LB can't
// hide a removed participant. A resolved participant not in the new set (still holding
// the VIP after stand-down) must refuse.
func TestVIPMove_EmptyOldResolvesActualParticipants(t *testing.T) {
	// vipFree controls the by-address kernel-absence proof used on the FRESH-claim path
	// (no participants); it's only consulted when participants resolve to empty.
	newS := func(participants []string, ok bool, vipFree bool) *Server {
		var holders []string
		if !vipFree {
			holders = []string{"someone"}
		}
		return &Server{
			hostName:               "self",
			vipGateFlipped:         func() bool { return true },
			enfVIPProofReclaim:     true,
			removeLBFromHost:       func(context.Context, string, string) error { return nil },
			lbParticipantsOverride: func(context.Context, string) ([]string, bool) { return participants, ok },
			vipHoldersOverride:     func(context.Context, string) ([]string, bool) { return holders, true },
			probeHolder: func(context.Context, string, string) holderStatus {
				return holderStatus{reachable: true, assigned: true} // resolved participant still holds it
			},
		}
	}
	ctx := context.Background()

	// Empty stored old, but "ghost" is a participant NOT in the new set and still holds → refuse.
	if _, refused := newS([]string{"ghost"}, true, true).vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", nil, []string{"new"}, true, true); !refused {
		t.Fatal("an actual participant not in the new set must refuse even when stored hosts is empty")
	}
	// No participants AND the VIP provably free → fresh claim allowed.
	if _, refused := newS(nil, true, true).vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", nil, []string{"new"}, true, true); refused {
		t.Fatal("no participants + VIP free → allow the fresh claim")
	}
	// No participants BUT the VIP still assigned somewhere (config-less orphan / stale
	// address) → the fresh-claim kernel-absence proof must refuse (High 1: stack LBs).
	if _, refused := newS(nil, true, false).vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", nil, []string{"new"}, true, true); !refused {
		t.Fatal("no participants but VIP still held → fresh-claim absence proof must refuse")
	}
	// Enumeration failed → can't resolve membership → fail closed.
	if _, refused := newS(nil, false, true).vipMoveRefused(ctx, "lb", "10.0.0.1", "10.0.0.1", nil, []string{"new"}, true, true); !refused {
		t.Fatal("failure to resolve actual participants must fail closed (refuse)")
	}
}

// High: the fresh-claim absence probe must include OFFLINE/FENCED hosts, because those
// states are set even on a PARTIAL fence and don't prove the host is down. An offline +
// unreachable host must be probed and fail closed (claimable), not skipped.
func TestVIPClaimableAnywhere_ProbesOfflineHosts(t *testing.T) {
	s := testServerR2(t) // hostName "test-host", no host rows seeded
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "offline-peer", Address: "127.0.0.1", State: "offline",
	}); err != nil {
		t.Fatal(err)
	}
	// Not self, unreachable → peerVIPClaims fail-closes to claims=true → claimable.
	claimable, ok := s.vipClaimableAnywhere(ctx, "10.0.123.1")
	if !ok || !claimable {
		t.Fatalf("an offline+unreachable host must be probed and fail closed: claimable=%v ok=%v (want true,true)", claimable, ok)
	}
}

// Medium: a combined VIP+host change must verify the REMOVED holder against the OLD VIP
// it was actually serving — not the new VIP (which it never had, so a stale assignment of
// the old one would be missed). The new VIP's freedom is proven separately.
func TestUpdateLoadBalancer_VIPAndHostChange_ReleasesOldVIP(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.vipGateFlipped = func() bool { return true }
	s.enfVIPProofReclaim = true
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
	s.removeLBFromHost = func(context.Context, string, string) error { return nil }
	s.vipHoldersOverride = func(context.Context, string) ([]string, bool) { return nil, true } // new VIP free
	var releaseVIPs []string
	s.probeHolder = func(_ context.Context, host, vip string) holderStatus {
		releaseVIPs = append(releaseVIPs, vip) // record which VIP the release proof checks
		return holderStatus{reachable: true, assigned: false}
	}

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "lbM", VIP: "10.0.200.1/24", Algorithm: "roundrobin",
		Hosts: `["h1"]`, Ports: "[]", Enabled: true, Generation: "g1",
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	// Change the VIP (A→B) AND move the host (h1→h2).
	if _, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{
		Name: "lbM", Vip: "10.0.200.2/24", Hosts: []string{"h2"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	sawOld, sawNew := false, false
	for _, v := range releaseVIPs {
		if strings.Contains(v, "10.0.200.1") {
			sawOld = true
		}
		if strings.Contains(v, "10.0.200.2") {
			sawNew = true
		}
	}
	if !sawOld {
		t.Fatalf("removed holder must be verified released against the OLD vip 10.0.200.1; probed=%v", releaseVIPs)
	}
	if sawNew {
		t.Fatalf("removed holder must NOT be checked against the NEW vip; probed=%v", releaseVIPs)
	}
}

// A VIP-only change on an IMPLICIT (hosts=[]) LB must prove the new VIP free but must NOT
// tear the live participant down — the empty new host set means "unchanged implicit
// membership", not "remove everyone" (the hostsChanged=false path).
func TestUpdateLoadBalancer_VIPOnlyChangeImplicitLBNotTornDown(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.vipGateFlipped = func() bool { return true }
	s.enfVIPProofReclaim = true
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
	s.vipHoldersOverride = func(context.Context, string) ([]string, bool) { return nil, true } // new VIP free
	// An existing implicit participant resolves here.
	s.lbParticipantsOverride = func(context.Context, string) ([]string, bool) { return []string{"h1"}, true }
	// If the gate wrongly reads empty-new as "remove everyone", it stands h1 down — fail loudly.
	s.removeLBFromHost = func(_ context.Context, _, host string) error {
		t.Fatalf("a VIP-only change must NOT stand any holder down; got RemoveLB(%s)", host)
		return nil
	}

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "lbImp", VIP: "10.0.50.1/24", Algorithm: "roundrobin",
		Hosts: `[]`, Ports: "[]", Enabled: true, Generation: "g1",
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	if _, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lbImp", Vip: "10.0.50.2/24"}); err != nil {
		t.Fatalf("VIP-only change on an implicit LB (new VIP free) must be allowed, got: %v", err)
	}
	rows, _ := s.db.Query(ctx, `SELECT vip FROM lb_configs WHERE name = 'lbImp' AND deleted_at IS NULL`)
	if len(rows) == 0 || !strings.Contains(rows[0].String("vip"), "10.0.50.2") {
		t.Fatalf("VIP not updated after an allowed change: %v", rows)
	}
}

// Medium: CreateLoadBalancer needs a cluster KERNEL-ABSENCE proof — creating a VIP that
// a leftover keepalived still answers (row gone after a prior delete/partition) would
// overlap. With the token flipped, a create is REFUSED when the VIP is held somewhere,
// and the row is NOT persisted.
func TestCreateLoadBalancer_RefusedWhenVIPHeldElsewhere(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.vipGateFlipped = func() bool { return true }
	s.enfVIPProofReclaim = true
	s.vipHoldersOverride = func(context.Context, string) ([]string, bool) {
		return []string{"leftover-host"}, true // VIP still assigned somewhere
	}

	_, err := s.CreateLoadBalancer(ctx, &pb.CreateLBRequest{
		Name: "lbX", Vip: "10.0.100.90/24", Algorithm: "roundrobin",
		Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []*pb.LBBackendAddress{{Name: "b1", Address: "10.0.0.9"}},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (VIP not provably free)", status.Code(err))
	}
	rows, _ := s.db.Query(ctx, `SELECT name FROM lb_configs WHERE name = 'lbX' AND deleted_at IS NULL`)
	if len(rows) != 0 {
		t.Fatalf("LB row persisted despite a refused create: %v", rows)
	}
}

// High-2: changing an LB's VIP (with hosts UNCHANGED) is a fresh claim of the new
// address and must run the kernel-absence proof — refused (row unchanged) when the new
// VIP is held elsewhere, even though req.Hosts is empty (so the host-move gate is off).
func TestUpdateLoadBalancer_VIPChangeRequiresClaimProof(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.vipGateFlipped = func() bool { return true }
	s.enfVIPProofReclaim = true
	s.vipHoldersOverride = func(context.Context, string) ([]string, bool) {
		return []string{"holds-new-vip"}, true // the NEW VIP is assigned somewhere
	}

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "lbV", VIP: "10.0.100.10/24", Algorithm: "roundrobin",
		Hosts: `["h1"]`, Ports: "[]", Enabled: true, Generation: "g1",
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	// Change ONLY the VIP (no req.Hosts) → the host gate is off, but the VIP-claim proof must fire.
	_, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lbV", Vip: "10.0.100.11/24"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (new VIP not provably free)", status.Code(err))
	}
	rows, _ := s.db.Query(ctx, `SELECT vip FROM lb_configs WHERE name = 'lbV' AND deleted_at IS NULL`)
	if len(rows) == 0 || !strings.Contains(rows[0].String("vip"), "10.0.100.10") {
		t.Fatalf("VIP overwritten despite a refused change: %v", rows)
	}
}

// With the VIP provably free cluster-wide, the create proceeds past the gate.
func TestCreateLoadBalancer_AllowedWhenVIPFree(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.vipGateFlipped = func() bool { return true }
	s.enfVIPProofReclaim = true
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil } // no real haproxy
	s.vipHoldersOverride = func(context.Context, string) ([]string, bool) {
		return nil, true // VIP unassigned everywhere
	}

	if _, err := s.CreateLoadBalancer(ctx, &pb.CreateLBRequest{
		Name: "lbY", Vip: "10.0.100.91/24", Algorithm: "roundrobin",
		Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []*pb.LBBackendAddress{{Name: "b1", Address: "10.0.0.9"}},
	}); err != nil {
		t.Fatalf("create with a free VIP must be allowed, got: %v", err)
	}
	rows, _ := s.db.Query(ctx, `SELECT name FROM lb_configs WHERE name = 'lbY' AND deleted_at IS NULL`)
	if len(rows) == 0 {
		t.Fatal("LB row not persisted after an allowed create")
	}
}

// CheckLBPresent is peer-only, validates its argument, and reports present=false for an
// LB this host isn't configured for.
func TestCheckLBPresent_PeerOnly(t *testing.T) {
	s := newPeerAuthServer(t)
	if _, err := s.CheckLBPresent(adminCtx(), &pb.CheckLBPresentRequest{LbName: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-peer: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := s.CheckLBPresent(mtlsCtx("peer-1"), &pb.CheckLBPresentRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty lb_name: code = %v, want InvalidArgument", status.Code(err))
	}
	resp, err := s.CheckLBPresent(mtlsCtx("peer-1"), &pb.CheckLBPresentRequest{LbName: "ghost-lb-xyz"})
	if err != nil {
		t.Fatalf("CheckLBPresent: %v", err)
	}
	if resp.GetPresent() {
		t.Fatal("a host with no config/process for the LB must report present=false")
	}
}

// High: when the lb_configs row is GONE (oldVip unknown, ""), a recreate must still prove
// the new VIP free — even if stale by-name participants for the LB still exist (which
// would otherwise fill oldHosts and skip the fresh-claim branch). A stale participant is
// not evidence the new VIP is free.
func TestVIPMove_RowGoneUnknownOldVipProvesNewVip(t *testing.T) {
	newS := func(newVipClaimed bool) *Server {
		var holders []string
		if newVipClaimed {
			holders = []string{"elsewhere"}
		}
		return &Server{
			hostName:               "self",
			vipGateFlipped:         func() bool { return true },
			enfVIPProofReclaim:     true,
			removeLBFromHost:       func(context.Context, string, string) error { return nil },
			lbParticipantsOverride: func(context.Context, string) ([]string, bool) { return []string{"stale-h"}, true },
			vipHoldersOverride:     func(context.Context, string) ([]string, bool) { return holders, true },
			probeHolder: func(context.Context, string, string) holderStatus {
				return holderStatus{reachable: true, assigned: false}
			},
		}
	}
	ctx := context.Background()

	// oldVip="" (row gone), a stale by-name participant exists, and the NEW vip is claimed
	// elsewhere → must refuse (the fresh-claim proof runs despite the by-name participant).
	if _, refused := newS(true).vipMoveRefused(ctx, "stack-lb", "", "10.0.9.9", nil, []string{"stale-h"}, true, true); !refused {
		t.Fatal("row gone + new VIP claimed elsewhere must refuse even when a by-name participant exists")
	}
	// Sanity: with the new VIP free, the same recreate is allowed.
	if _, refused := newS(false).vipMoveRefused(ctx, "stack-lb", "", "10.0.9.9", nil, []string{"stale-h"}, true, true); refused {
		t.Fatal("row gone + new VIP free → the recreate must be allowed")
	}
}

// End-to-end through the production UpdateLoadBalancer RPC with the token FLIPPED:
// moving an LB off "old-holder" is REFUSED — and the row is NOT overwritten — while
// that REMOVED old holder still holds the (CIDR-form) VIP after stand-down.
func TestUpdateLoadBalancer_TakeoverRefusesRemovedHolder(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "lb1", VIP: "10.0.100.50/24", Algorithm: "roundrobin",
		Hosts: `["old-holder"]`, Ports: "[]", Enabled: true, Generation: "g1",
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	s.vipGateFlipped = func() bool { return true } // pretend the token is advertised

	s.enfVIPProofReclaim = true
	s.removeLBFromHost = func(context.Context, string, string) error { return nil }
	s.probeHolder = func(_ context.Context, host, _ string) holderStatus {
		if host == "old-holder" {
			return holderStatus{reachable: true, assigned: true} // still holds it
		}
		return holderStatus{reachable: true, assigned: false}
	}

	// Move the LB to a new host, removing old-holder from the target set.
	_, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lb1", Hosts: []string{"new-host"}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (takeover refused)", status.Code(err))
	}
	rows, _ := s.db.Query(ctx, `SELECT hosts FROM lb_configs WHERE name = 'lb1' AND deleted_at IS NULL`)
	if len(rows) == 0 || !strings.Contains(rows[0].String("hosts"), "old-holder") {
		t.Fatalf("hosts overwritten despite refusal: %v", rows)
	}
}

// With the removed old holder RELEASED (assigned=false after stand-down), the same move
// is allowed past the gate (it then proceeds to persist/apply).
func TestUpdateLoadBalancer_TakeoverAllowedWhenReleased(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil } // no real haproxy
	s.removeLBFromHost = func(context.Context, string, string) error { return nil }

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "lb2", VIP: "10.0.100.60/24", Algorithm: "roundrobin",
		Hosts: `["old-holder"]`, Ports: "[]", Enabled: true, Generation: "g1",
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	s.vipGateFlipped = func() bool { return true }
	s.enfVIPProofReclaim = true
	s.probeHolder = func(context.Context, string, string) holderStatus {
		return holderStatus{reachable: true, assigned: false} // released
	}

	if _, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lb2", Hosts: []string{"new-host"}}); err != nil {
		t.Fatalf("released holder should allow the update, got: %v", err)
	}
	rows, _ := s.db.Query(ctx, `SELECT hosts FROM lb_configs WHERE name = 'lb2' AND deleted_at IS NULL`)
	if len(rows) == 0 || !strings.Contains(rows[0].String("hosts"), "new-host") {
		t.Fatalf("hosts not updated after an allowed takeover: %v", rows)
	}
}

// Medium regression: a backend/algorithm-only edit (req.Hosts empty = "no change") of a
// stored hosts=[] LB must NOT be gated — otherwise the gate would resolve the current
// participant(s) and, comparing against an empty new set, stand the live holder down.
// If the gate ran it would blow up (participants seam + probe forced "still holds"); the
// update must sail past it because req.Hosts is empty.
func TestUpdateLoadBalancer_BackendOnlyEditNotGated(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
	s.vipGateFlipped = func() bool { return true }
	s.enfVIPProofReclaim = true
	// If these run, the gate is (wrongly) active for a no-host-change edit → fail loudly.
	s.lbParticipantsOverride = func(context.Context, string) ([]string, bool) {
		t.Fatal("gate must NOT resolve participants for a backend-only edit (req.Hosts empty)")
		return nil, false
	}

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "lb4", VIP: "10.0.100.80/24", Algorithm: "roundrobin",
		Hosts: `["lb-host-1"]`, Ports: "[]", Enabled: true, Generation: "g1",
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	// Algorithm-only edit, no req.Hosts → must not be gated/refused (the gate must
	// not resolve participants). The LB has a recorded holder, so the legacy-holder
	// repair doesn't engage either.
	if _, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "lb4", Algorithm: "leastconn"}); err != nil {
		t.Fatalf("backend/algorithm-only edit must not be refused, got: %v", err)
	}
}

// TestUpdateLoadBalancer_LegacyNoHolderRepairOrRefuse: updating a legacy explicit
// LB with no recorded holder (hosts=[]) either backfills the single proven
// participant and proceeds, or fails closed — never silently persists a
// reload-required change that would apply nowhere.
func TestUpdateLoadBalancer_LegacyNoHolderRepairOrRefuse(t *testing.T) {
	ctx := adminCtx()

	// No resolvable participant → FailedPrecondition, and the edit is NOT persisted.
	s := testServerR2(t)
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
	s.lbParticipantsOverride = func(context.Context, string) ([]string, bool) { return nil, true }
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "orphan-lb", VIP: "10.0.100.81/24", Algorithm: "roundrobin", Hosts: `[]`, Ports: "[]", Enabled: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "orphan-lb", Algorithm: "leastconn"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("unowned legacy LB update = %v; want FailedPrecondition", err)
	}
	rows, _ := s.db.Query(ctx, `SELECT algorithm FROM lb_configs WHERE name = 'orphan-lb' AND deleted_at IS NULL`)
	if len(rows) > 0 && rows[0].String("algorithm") != "roundrobin" {
		t.Errorf("refused update must not persist; algorithm = %q", rows[0].String("algorithm"))
	}

	// Exactly one proven participant → backfilled as holder and the update proceeds.
	s2 := testServerR2(t)
	s2.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
	s2.lbParticipantsOverride = func(context.Context, string) ([]string, bool) { return []string{"lb-host-1"}, true }
	if err := corrosion.UpsertLBConfig(ctx, s2.db, corrosion.LBConfigRecord{
		Name: "adopt-lb", VIP: "10.0.100.82/24", Algorithm: "roundrobin", Hosts: `[]`, Ports: "[]", Enabled: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s2.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "adopt-lb", Algorithm: "leastconn"}); err != nil {
		t.Fatalf("update with a resolvable holder must proceed, got: %v", err)
	}
	rows, _ = s2.db.Query(ctx, `SELECT hosts, algorithm FROM lb_configs WHERE name = 'adopt-lb' AND deleted_at IS NULL`)
	if len(rows) == 0 || rows[0].String("hosts") != `["lb-host-1"]` || rows[0].String("algorithm") != "leastconn" {
		t.Errorf("expected backfilled holder + applied edit; got %v", rows)
	}
}

// TestUpdateLoadBalancer_LegacyMoveStandsOldHolderDown (pre-flip): moving a legacy
// hosts=[] LB to a new host must stand the OLD holder down even with the VIP gate
// de-advertised. The original holder is resolved from live participants up front,
// so the pre-flip stale-holder cleanup knows whom to remove — without it the old
// keepalived would keep running alongside the new holder.
func TestUpdateLoadBalancer_LegacyMoveStandsOldHolderDown(t *testing.T) {
	s := testServerR2(t) // hostName "test-host"
	ctx := adminCtx()
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
	s.vipGateFlipped = func() bool { return false } // pre-flip: gate inert
	// The legacy LB's live holder resolves to THIS host, so its stand-down runs
	// locally (removeLBLocal) — observable, unlike the remote fire-and-forget path.
	s.lbParticipantsOverride = func(context.Context, string) ([]string, bool) { return []string{"test-host"}, true }

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "move-lb", VIP: "10.0.100.90/24", Algorithm: "roundrobin", Hosts: `[]`, Ports: "[]", Enabled: true,
	}); err != nil {
		t.Fatalf("seed lb: %v", err)
	}
	// Seed the LB's firewall intent on the old holder; standing it down deletes it.
	if err := corrosion.UpsertHostFWIntent(ctx, s.db, "test-host", corrosion.HostFWIntent{
		ScopeKey: "lb:move-lb", Bridge: "br-iso-x",
		Exceptions: []corrosion.HostFWException{{VIP: "10.0.100.90", Ports: []int{80}}},
	}); err != nil {
		t.Fatalf("seed intent: %v", err)
	}

	if _, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "move-lb", Hosts: []string{"new-host"}}); err != nil {
		t.Fatalf("move of a legacy LB with a resolvable holder must be allowed pre-flip, got: %v", err)
	}
	// The old holder (this host) was stood down → its LB firewall intent is gone.
	intents, _ := corrosion.ListHostFWIntent(ctx, s.db, "test-host")
	for _, in := range intents {
		if in.ScopeKey == "lb:move-lb" {
			t.Error("old legacy holder not stood down on move: lb:move-lb firewall intent still present")
		}
	}
}

// High-2 regression through the production RPC: an update that ADDS a host (removes
// none) must NOT be refused even though the existing holders still answer the VIP.
func TestUpdateLoadBalancer_AddHolderNotRefused(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
	s.removeLBFromHost = func(context.Context, string, string) error { return nil }

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "lb3", VIP: "10.0.100.70/24", Algorithm: "roundrobin",
		Hosts: `["holder-a","holder-b"]`, Ports: "[]", Enabled: true, Generation: "g1",
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	s.vipGateFlipped = func() bool { return true }
	s.enfVIPProofReclaim = true
	// Every configured holder currently holds the VIP (would trip a snapshot gate).
	s.probeHolder = func(context.Context, string, string) holderStatus {
		return holderStatus{reachable: true, assigned: true}
	}

	if _, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{
		Name: "lb3", Hosts: []string{"holder-a", "holder-b", "holder-c"},
	}); err != nil {
		t.Fatalf("adding a holder (no removals) must not be refused, got: %v", err)
	}
	rows, _ := s.db.Query(ctx, `SELECT hosts FROM lb_configs WHERE name = 'lb3' AND deleted_at IS NULL`)
	if len(rows) == 0 || !strings.Contains(rows[0].String("hosts"), "holder-c") {
		t.Fatalf("hosts not updated after an allowed add: %v", rows)
	}
}
