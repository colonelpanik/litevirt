package grpcapi

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fenceTestServer is a single-host server whose own posture is the whole
// cluster's, so the readiness rules can be exercised without a peer.
func fenceTestServer(t *testing.T, enforcing, latched bool) *Server {
	t.Helper()
	s := testServer(t)
	s.SetEnforcementConfig(false, false, false, false, false, enforcing)
	s.SetGate(fakeServerGate{
		execOK:      true,
		enforcedTok: map[string]bool{capabilities.SharedStorageFenceV1: latched},
	})
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	return s
}

func addSharedDiskVM(t *testing.T, s *Server, vm string) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`INSERT INTO vm_disks (vm_name, disk_name, host_name, path, storage_type, updated_at)
		 VALUES (?, 'd0', 'test-host', '/pool/d0', 'ceph', ?)`, vm, s.db.NowTS()); err != nil {
		t.Fatalf("insert shared disk: %v", err)
	}
}

// TestNotEnforcingTokens_ReportsTheKillSwitch is the field the whole diagnostic
// rests on. A node advertises a token regardless of its own config flag, so
// without this list a cluster can show shared_storage_fence_v1 latched while
// members silently skip the fence — visible to nobody.
func TestNotEnforcingTokens_ReportsTheKillSwitch(t *testing.T) {
	off := fenceTestServer(t, false, true)
	if !slices.Contains(off.notEnforcingTokens(), capabilities.SharedStorageFenceV1) {
		t.Errorf("kill-switch off, but %s is absent from not_enforcing: %v",
			capabilities.SharedStorageFenceV1, off.notEnforcingTokens())
	}

	on := fenceTestServer(t, true, true)
	if slices.Contains(on.notEnforcingTokens(), capabilities.SharedStorageFenceV1) {
		t.Errorf("kill-switch on, but %s is still reported as not enforced: %v",
			capabilities.SharedStorageFenceV1, on.notEnforcingTokens())
	}
}

// TestPing_AlwaysReportsPosture pins that posture_reported is UNCONDITIONAL.
//
// An empty not_enforcing list has two opposite meanings — "this node enforces
// everything it advertises" and "this node is too old to say" — and only this
// flag separates them. Deriving it from anything (whether the list is empty, a
// config value, a capability) would reintroduce exactly the ambiguity it exists
// to remove, and the failure mode is a diagnostic reporting all-clear for a host
// whose posture it never learned.
func TestPing_AlwaysReportsPosture(t *testing.T) {
	for _, tc := range []struct {
		name       string
		enforceAll bool
	}{
		// The second case is the one that matters: with every kill-switch on,
		// not_enforcing is EMPTY, which is exactly the reading an old peer also
		// produces. Deriving posture_reported from the list would look correct
		// in the first case and silently break here.
		{"some tokens unenforced", false},
		{"nothing unenforced (empty list, the ambiguous case)", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fenceTestServer(t, true, true)
			if tc.enforceAll {
				enforceEveryToken(s)
				if got := s.notEnforcingTokens(); len(got) != 0 {
					t.Fatalf("fixture did not reach the ambiguous case: not_enforcing = %v", got)
				}
			}
			resp, err := s.Ping(context.Background(), nil)
			if err != nil {
				t.Fatalf("Ping: %v", err)
			}
			if !resp.GetPostureReported() {
				t.Error("posture_reported is false on a binary that does report posture, " +
					"so its not_enforcing list cannot be told apart from an old peer's silence")
			}
		})
	}
}

// enforceEveryToken switches on every kill-switch tokenEnabled consults, so
// notEnforcingTokens returns empty. Set directly rather than through the
// setters: the point is to reach the empty-list state, not to model a config.
func enforceEveryToken(s *Server) {
	s.enfAuditSignature = true
	s.enfCanonicalIdentity = true
	s.enfCanonicalRegistry = true
	s.enfHLCLww = true
	s.enfIsolationEpoch = true
	s.enfLiveResize = true
	s.enfLWWSkew = true
	s.enfOperationProtocol = true
	s.enfOwnerEpoch = true
	s.enfProjectAuthority = true
	s.enfSafeFence = true
	s.enfSharedStorageFence = true
	s.enfVIPProofReclaim = true
	s.enfVIPSelfDemote = true
	s.forwardedIdentity = true
	s.rbacRealm = true
	s.strictMTLSIdentity = true
}

// TestPostureFromPing_OldPeerSilenceIsUnknown pins how a peer that predates the
// posture field is read. Its not_enforcing list is empty for the same reason a
// fully-enforcing node's is, so reading emptiness as "enforcing" would report a
// host covered on the strength of a question it never answered — the exact
// false all-clear this diagnostic exists to prevent.
func TestPostureFromPing_OldPeerSilenceIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		resp                     *pb.PingResponse
		wantKnown, wantEnforcing bool
	}{
		{"old binary: empty list, no flag",
			&pb.PingResponse{}, false, false},
		{"current binary, nothing unenforced",
			&pb.PingResponse{PostureReported: true}, true, true},
		{"current binary, fence off",
			&pb.PingResponse{PostureReported: true,
				NotEnforcing: []string{capabilities.SharedStorageFenceV1}}, true, false},
		{"current binary, a DIFFERENT token off",
			&pb.PingResponse{PostureReported: true,
				NotEnforcing: []string{capabilities.SafeFenceDefaultV1}}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := postureFromPing("peer", tc.resp)
			if p.GetPostureKnown() != tc.wantKnown {
				t.Errorf("posture_known = %v, want %v", p.GetPostureKnown(), tc.wantKnown)
			}
			if p.GetEnforcing() != tc.wantEnforcing {
				t.Errorf("enforcing = %v, want %v", p.GetEnforcing(), tc.wantEnforcing)
			}
		})
	}
}

// TestGetFenceReadiness_ExposureRequiresBothSwitches pins the core rule: the
// fence runs only when the capability is latched AND the host's kill-switch is
// on. Either one off leaves a shared-disk VM unprotected.
func TestGetFenceReadiness_ExposureRequiresBothSwitches(t *testing.T) {
	for _, tc := range []struct {
		name             string
		enforcing, latch bool
		wantEverywhere   bool
		wantLatched      bool
	}{
		{"both on", true, true, true, true},
		{"kill-switch off", false, true, false, true},
		{"not latched", true, false, true, false},
		{"both off", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fenceTestServer(t, tc.enforcing, tc.latch)
			addSharedDiskVM(t, s, "vm1")

			r, err := s.GetFenceReadiness(adminCtx(), &emptypb.Empty{})
			if err != nil {
				t.Fatalf("GetFenceReadiness: %v", err)
			}
			if r.GetEnforcedEverywhere() != tc.wantEverywhere {
				t.Errorf("enforced_everywhere = %v, want %v", r.GetEnforcedEverywhere(), tc.wantEverywhere)
			}
			if r.GetCapabilityLatched() != tc.wantLatched {
				t.Errorf("capability_latched = %v, want %v", r.GetCapabilityLatched(), tc.wantLatched)
			}
			if r.GetVmsWithSharedDisk() != 1 {
				t.Errorf("vms_with_shared_disk = %d, want 1", r.GetVmsWithSharedDisk())
			}
		})
	}
}

// TestGetFenceReadiness_CountsOnlySharedDiskVMs pins that the exposure count is
// about shared storage, not VM count. A local-disk cluster with the switches off
// is a posture note, not a hazard: a relocation target holds a different image,
// so there are no shared bytes to corrupt.
func TestGetFenceReadiness_CountsOnlySharedDiskVMs(t *testing.T) {
	s := fenceTestServer(t, false, true)
	if err := s.db.Execute(context.Background(),
		`INSERT INTO vm_disks (vm_name, disk_name, host_name, path, storage_type, updated_at)
		 VALUES ('local-vm', 'd0', 'test-host', '/var/lib/d0', 'dir', ?)`, s.db.NowTS()); err != nil {
		t.Fatalf("insert local disk: %v", err)
	}

	r, err := s.GetFenceReadiness(adminCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetFenceReadiness: %v", err)
	}
	if r.GetVmsWithSharedDisk() != 0 {
		t.Errorf("vms_with_shared_disk = %d, want 0 — a dir-backed VM is not exposed",
			r.GetVmsWithSharedDisk())
	}
	if len(r.GetSampleVms()) != 0 {
		t.Errorf("sample_vms = %v, want empty", r.GetSampleVms())
	}
}

// TestGetFenceReadiness_UnreachableHostIsNotAllClear is the fail-safe direction.
// A host that cannot be asked has UNKNOWN posture, and unknown must clear
// enforced_everywhere exactly as "not enforcing" does — reporting the cluster
// covered on behalf of a host that never answered is the one wrong answer here.
func TestGetFenceReadiness_UnreachableHostIsNotAllClear(t *testing.T) {
	s := fenceTestServer(t, true, true)
	addSharedDiskVM(t, s, "vm1")
	// A second host that exists in the DB and cannot be dialled.
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "ghost", Address: "192.0.2.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	r, err := s.GetFenceReadiness(adminCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetFenceReadiness: %v", err)
	}
	if r.GetEnforcedEverywhere() {
		t.Error("enforced_everywhere = true with an unreachable host; unknown posture " +
			"must never be reported as covered")
	}
	var ghost bool
	for _, h := range r.GetHosts() {
		if h.GetHost() == "ghost" {
			ghost = true
			if h.GetReachable() {
				t.Error("an undiallable host is reported reachable")
			}
			if h.GetEnforcing() {
				t.Error("an unreachable host is reported as enforcing")
			}
		}
	}
	if !ghost {
		t.Error("the unreachable host is missing from the per-host report, so an operator " +
			"cannot see which host is unaccounted for")
	}
}
