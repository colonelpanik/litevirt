package grpcapi

import (
	"context"
	"slices"
	"strings"
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
// advertisesFence is the minimum a peer must advertise for its posture to be
// readable at all.
var advertisesFence = []string{capabilities.SharedStorageFenceV1}

func TestPostureFromPing_OldPeerSilenceIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		resp                     *pb.PingResponse
		wantKnown, wantEnforcing bool
	}{
		{"old binary: empty list, no flag",
			&pb.PingResponse{}, false, false},
		{"current binary, nothing unenforced",
			&pb.PingResponse{PostureReported: true, Capabilities: advertisesFence}, true, true},
		{"current binary, fence off",
			&pb.PingResponse{PostureReported: true, Capabilities: advertisesFence,
				NotEnforcing: []string{capabilities.SharedStorageFenceV1}}, true, false},
		// A self-fenced or WAL-quarantined node advertises NOTHING, so its
		// not_enforcing list is empty for a reason that has nothing to do with
		// its kill-switches. Reading that as "enforcing" would give the most
		// degraded node the cleanest posture.
		{"quarantined peer: advertises nothing, empty list",
			&pb.PingResponse{PostureReported: true, WalQuarantined: true}, false, false},
		{"peer advertises other tokens but not the fence",
			&pb.PingResponse{PostureReported: true,
				Capabilities: []string{capabilities.SafeFenceDefaultV1}}, false, false},
		{"current binary, a DIFFERENT token off",
			&pb.PingResponse{PostureReported: true, Capabilities: advertisesFence,
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

// TestProbeFencePostures_ExpiredBudgetYieldsUnknown pins the fan-out's failure
// shape. Probes run concurrently under one overall budget so a large fleet of
// unreachable hosts cannot multiply the per-peer timeout into a report the
// caller's own deadline kills before it returns. When that budget is already
// gone, every host must come back UNKNOWN — a host nothing asked is not a host
// that answered — and readiness must not be reported as covered.
func TestProbeFencePostures_ExpiredBudgetYieldsUnknown(t *testing.T) {
	s := fenceTestServer(t, true, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hosts := []corrosion.HostRecord{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	got := s.probeFencePostures(ctx, hosts)

	if len(got) != len(hosts) {
		t.Fatalf("got %d postures for %d hosts", len(got), len(hosts))
	}
	for i, p := range got {
		if p == nil {
			t.Fatalf("host %q has no posture entry: a missing entry reads as covered downstream", hosts[i].Name)
		}
		if p.GetHost() != hosts[i].Name {
			t.Errorf("posture %d is for %q, want %q — results must stay aligned with the hosts asked",
				i, p.GetHost(), hosts[i].Name)
		}
		if p.GetEnforcing() || p.GetPostureKnown() || p.GetReachable() {
			t.Errorf("%s: unprobed host reported enforcing=%v posture_known=%v reachable=%v, want all false",
				p.GetHost(), p.GetEnforcing(), p.GetPostureKnown(), p.GetReachable())
		}
		// Without this the assertions above are satisfied by ANY failure — a
		// dial error looks identical — so budgetExpiredPosture could be deleted
		// and the test would stay green while the operator was told a host "did
		// not answer" about one nothing ever dialled.
		if !strings.Contains(p.GetDetail(), "budget expired") {
			t.Errorf("%s: detail = %q, want it to say the budget expired rather than "+
				"blaming the host for not answering", p.GetHost(), p.GetDetail())
		}
	}
}

// fenceLatchGate distinguishes the two gate reads that fakeServerGate collapses:
// it answers Latched from the map and RECORDS any call to Enforced.
type fenceLatchGate struct {
	fakeServerGate
	enforcedCalls *int
}

func (g fenceLatchGate) Enforced(ctx context.Context, token string) bool {
	*g.enforcedCalls++
	return g.fakeServerGate.Enforced(ctx, token)
}

// TestGetFenceReadiness_NeverLatchesTheCapability is the guard for the worst
// thing this command could do.
//
// Checker.Enforced is a MUTATOR: on a token that has not latched it runs
// CapabilityActive and then sets activated[token] and writes a durable marker
// that survives restart. A viewer running a read-only diagnostic would thereby
// latch shared_storage_fence_v1 permanently — and then report the `true` it had
// just caused, an answer manufactured by the act of asking. Latched is the pure
// in-memory read, and nothing on this path may call anything else.
//
// The shared fakeServerGate answers Latched and Enforced identically, so no
// assertion on the RESULT can catch a regression here; only counting the calls
// can.
func TestGetFenceReadiness_NeverLatchesTheCapability(t *testing.T) {
	s := fenceTestServer(t, true, true)
	calls := 0
	s.SetGate(fenceLatchGate{
		fakeServerGate: fakeServerGate{
			execOK:      true,
			enforcedTok: map[string]bool{capabilities.SharedStorageFenceV1: true},
		},
		enforcedCalls: &calls,
	})

	r, err := s.GetFenceReadiness(adminCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetFenceReadiness: %v", err)
	}
	if calls != 0 {
		t.Errorf("gate.Enforced called %d time(s) by a read-only diagnostic; it latches the "+
			"capability durably, so the report would be manufacturing its own answer", calls)
	}
	if !r.GetCapabilityLatched() {
		t.Error("capability_latched is false though the gate reports it latched")
	}
}

// TestFenceHostPosture_SelfFencedLocalHostIsUnknown holds the LOCAL node to the
// same standard as a peer.
//
// postureFromPing refuses to call a non-advertising peer enforcing, but the self
// branch short-circuits before that check. Without this the node an operator is
// logged into — the one that just self-fenced, and so is advertising nothing —
// would be the only host in the fleet handed a confident posture, while every
// peer in exactly that state correctly reads unknown.
func TestFenceHostPosture_SelfFencedLocalHostIsUnknown(t *testing.T) {
	s := fenceTestServer(t, true, true)

	if p := s.fenceHostPosture(context.Background(), s.hostName); !p.GetPostureKnown() {
		t.Fatalf("fixture: a healthy local host should report a posture, got detail %q", p.GetDetail())
	}

	fenced := func() bool { return true }
	s.watchdogFenced.Store(&fenced)

	p := s.fenceHostPosture(context.Background(), s.hostName)
	if p.GetPostureKnown() || p.GetEnforcing() {
		t.Errorf("a self-fenced local host reports posture_known=%v enforcing=%v detail=%q; "+
			"it advertises nothing, so its posture is no more readable than a peer's",
			p.GetPostureKnown(), p.GetEnforcing(), p.GetDetail())
	}
}

// TestNotEnforcingTokens_OmitsTokensWithNoKillSwitch keeps the field
// actionable. hardware_v2 has no enforcement.* flag, so tokenEnabled returns its
// fail-closed default for it — right for the decisions it gates, wrong as a
// posture claim. Reporting it would put a permanent, unfixable entry in every
// node's list, and a field that always names something is one operators learn to
// skim past.
func TestNotEnforcingTokens_OmitsTokensWithNoKillSwitch(t *testing.T) {
	s := fenceTestServer(t, true, true)
	enforceEveryToken(s)
	// hardware_v2 is advertised only once the backfill audit has completed AND
	// operation_protocol_v1 has latched (see hardwareV2Ready). Both are needed
	// or the token never appears and this test would pass without observing
	// anything.
	s.hwV2Ready.Store(true)
	s.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{
		capabilities.SharedStorageFenceV1: true,
		capabilities.OperationProtocolV1:  true,
	}})

	if !slices.Contains(s.advertisedCapabilities(), capabilities.HardwareV2) {
		t.Fatal("fixture does not advertise hardware_v2, so the exclusion is not being observed")
	}
	if got := s.notEnforcingTokens(); slices.Contains(got, capabilities.HardwareV2) {
		t.Errorf("not_enforcing = %v; hardware_v2 has no kill switch, so it can never be "+
			"switched on and would sit there on every node forever", got)
	}
}

// TestGetFenceReadiness_WitnessIsNotCounted keeps the check usable on any
// cluster that runs a quorum arbiter.
//
// A witness never hosts a workload, so it can never perform the fence and its
// flag will never be turned on. Counting it would pin enforced_everywhere false
// forever, and the remedy would tell an operator to reconfigure and restart
// their arbiter to fix a fence it cannot perform — a permanent false positive,
// which is how a diagnostic gets ignored.
func TestGetFenceReadiness_WitnessIsNotCounted(t *testing.T) {
	s := fenceTestServer(t, true, true)
	addSharedDiskVM(t, s, "vm1")
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "arbiter", Address: "10.0.0.9", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", Role: "witness",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	r, err := s.GetFenceReadiness(adminCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetFenceReadiness: %v", err)
	}
	for _, p := range r.GetHosts() {
		if p.GetHost() == "arbiter" {
			t.Errorf("witness %q appears in the report (detail %q); it cannot fence, so it can "+
				"only ever be reported as a problem the operator cannot fix", p.GetHost(), p.GetDetail())
		}
	}
	if !r.GetEnforcedEverywhere() {
		t.Error("enforced_everywhere = false because of a witness; every workload host enforces")
	}
}
