package grpcapi

import (
	"context"
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// relayHandlerServer builds a "relay" Server with a db in which the peer caller ("caller")
// is a known host, so requirePeerCert passes for mtlsCtx("caller").
func relayHandlerServer(t *testing.T, gate serverGate) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "caller", Address: "127.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	return &Server{hostName: "relay", db: db, gate: gate}
}

// fakeRelayPeer is a pb.LiteVirtClient stub for the VIP relay tests. It answers the two
// legs the relay path uses: CheckVIPParticipant (relay→target) and RelayCheckVIPParticipant
// (caller→relay). Everything else is Unimplemented (embedded interface).
type fakeRelayPeer struct {
	pb.LiteVirtClient
	checkClaims bool  // CheckVIPParticipant.claims (relay→target leg)
	checkErr    error // CheckVIPParticipant error
	relayResult pb.RelayVIPResult
	relayErr    error
}

func (c *fakeRelayPeer) CheckVIPParticipant(_ context.Context, _ *pb.CheckVIPParticipantRequest, _ ...grpc.CallOption) (*pb.CheckVIPParticipantResponse, error) {
	if c.checkErr != nil {
		return nil, c.checkErr
	}
	return &pb.CheckVIPParticipantResponse{Claims: c.checkClaims}, nil
}

func (c *fakeRelayPeer) RelayCheckVIPParticipant(_ context.Context, _ *pb.RelayCheckVIPParticipantRequest, _ ...grpc.CallOption) (*pb.RelayCheckVIPParticipantResponse, error) {
	if c.relayErr != nil {
		return nil, c.relayErr
	}
	return &pb.RelayCheckVIPParticipantResponse{Result: c.relayResult}, nil
}

// RemoveLB models a peer reached over a LAZILY-dialed gRPC conn that is actually
// unreachable: the dial "succeeds" but the call errors. Used by the stand-down test.
func (c *fakeRelayPeer) RemoveLB(_ context.Context, _ *pb.RemoveLBRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	return nil, errors.New("rpc error: connection refused")
}

// The relay HANDLER: peer-only; validates args; requires the target to advertise
// vip_release_probe_v1 (fresh Ping — it answers absence probes authoritatively); then does a
// fresh CheckVIPParticipant. Every reach/verify failure → UNKNOWN so the caller fails closed.
// It DECIDES nothing.
func TestRelayCheckVIPParticipant_Handler(t *testing.T) {
	req := &pb.RelayCheckVIPParticipantRequest{TargetHost: "target", Vip: "10.0.0.9/24"}

	// Peer-only: a non-peer (no mTLS cert) context is denied.
	s := relayHandlerServer(t, fakeServerGate{supports: map[string]bool{"target": true}})
	if _, err := s.RelayCheckVIPParticipant(context.Background(), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-peer must be PermissionDenied; got %v", err)
	}

	ctx := mtlsCtx("caller")

	// Missing args → InvalidArgument.
	if _, err := s.RelayCheckVIPParticipant(ctx, &pb.RelayCheckVIPParticipantRequest{Vip: "x"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("missing target_host → InvalidArgument; got %v", err)
	}

	// Target does not advertise vip_release_probe_v1 → UNKNOWN (fail closed), no dial. It is
	// NOT enough to advertise vip_demote_v1 (minority self-demote) — the trust anchor for a
	// relayed absence answer is specifically the release-probe token.
	unsup := relayHandlerServer(t, fakeServerGate{
		supportsTok: map[string]map[string]bool{"target": {capabilities.VIPDemoteV1: true}},
	})
	unsup.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		t.Fatal("must not dial a target lacking vip_release_probe_v1")
		return nil, nil, nil
	}
	if r, _ := unsup.RelayCheckVIPParticipant(ctx, req); r.GetResult() != pb.RelayVIPResult_RELAY_VIP_UNKNOWN {
		t.Fatalf("target with vip_demote_v1 but not vip_release_probe_v1 → UNKNOWN; got %v", r.GetResult())
	}

	// Supported target but the relay can't dial it → UNKNOWN.
	dialFail := relayHandlerServer(t, fakeServerGate{supports: map[string]bool{"target": true}})
	dialFail.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, errors.New("unreachable")
	}
	if r, _ := dialFail.RelayCheckVIPParticipant(ctx, req); r.GetResult() != pb.RelayVIPResult_RELAY_VIP_UNKNOWN {
		t.Fatalf("target dial failure → UNKNOWN; got %v", r.GetResult())
	}

	// Supported + reachable: claims→CLAIMS, not→NO_CLAIMS, RPC error→UNKNOWN.
	cases := []struct {
		name string
		peer *fakeRelayPeer
		want pb.RelayVIPResult
	}{
		{"claims", &fakeRelayPeer{checkClaims: true}, pb.RelayVIPResult_RELAY_VIP_CLAIMS},
		{"absent", &fakeRelayPeer{checkClaims: false}, pb.RelayVIPResult_RELAY_VIP_NO_CLAIMS},
		{"target-error", &fakeRelayPeer{checkErr: errors.New("ip failed")}, pb.RelayVIPResult_RELAY_VIP_UNKNOWN},
	}
	for _, tc := range cases {
		srv := relayHandlerServer(t, fakeServerGate{supports: map[string]bool{"target": true}})
		peer := tc.peer
		srv.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
			return peer, func() {}, nil
		}
		if r, _ := srv.RelayCheckVIPParticipant(ctx, req); r.GetResult() != tc.want {
			t.Fatalf("%s: got %v; want %v", tc.name, r.GetResult(), tc.want)
		}
	}
}

// The CALLER side: when the target is unreachable directly, peerVIPClaims consults a
// quorum-visible reachable relay and accepts a NO_CLAIMS absence ONLY — every other
// relay outcome (CLAIMS/UNKNOWN/error/no eligible relay/relay==target) fails closed
// (assume the target STILL claims).
func TestPeerVIPClaims_RelayFallback(t *testing.T) {
	const vip = "10.0.0.9/24"
	// Server whose direct dial to "target" always fails (permanent segmentation) but can
	// reach "relay"; HealthyPeers (quorum-visible set) is configurable.
	mkServer := func(healthy []string, relay *fakeRelayPeer) *Server {
		s := &Server{hostName: "self", gate: fakeServerGate{healthy: healthy}}
		s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
			switch host {
			case "target":
				return nil, nil, errors.New("segmented: unreachable")
			case "relay":
				return relay, func() {}, nil
			}
			return nil, nil, errors.New("no route")
		}
		return s
	}
	ctx := context.Background()

	tests := []struct {
		name       string
		healthy    []string
		relay      *fakeRelayPeer
		wantClaims bool
	}{
		{"relayed absence → not claiming", []string{"relay"}, &fakeRelayPeer{relayResult: pb.RelayVIPResult_RELAY_VIP_NO_CLAIMS}, false},
		{"relayed claims → still claims", []string{"relay"}, &fakeRelayPeer{relayResult: pb.RelayVIPResult_RELAY_VIP_CLAIMS}, true},
		{"relayed unknown → fail closed", []string{"relay"}, &fakeRelayPeer{relayResult: pb.RelayVIPResult_RELAY_VIP_UNKNOWN}, true},
		{"relay RPC error → fail closed", []string{"relay"}, &fakeRelayPeer{relayErr: errors.New("boom")}, true},
		{"no quorum-visible relay → fail closed", nil, &fakeRelayPeer{relayResult: pb.RelayVIPResult_RELAY_VIP_NO_CLAIMS}, true},
		{"only healthy peer IS the target → skipped, fail closed", []string{"target"}, &fakeRelayPeer{relayResult: pb.RelayVIPResult_RELAY_VIP_NO_CLAIMS}, true},
	}
	for _, tc := range tests {
		s := mkServer(tc.healthy, tc.relay)
		if got := s.peerVIPClaims(ctx, "target", vip); got != tc.wantClaims {
			t.Fatalf("%s: peerVIPClaims=%v; want %v", tc.name, got, tc.wantClaims)
		}
	}

	// A self=="relay" candidate must never be dialed as its own relay.
	selfHealthy := &Server{hostName: "self", gate: fakeServerGate{healthy: []string{"self"}}}
	selfHealthy.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host == "self" {
			t.Fatal("must not relay through self")
		}
		return nil, nil, errors.New("segmented")
	}
	if !selfHealthy.peerVIPClaims(ctx, "target", vip) {
		t.Fatal("self-only healthy set must fail closed (no external relay)")
	}
}

// PR 2 token split: the MAJORITY-side probe/relay trust keys off vip_release_probe_v1 ("I
// answer by-VIP absence probes authoritatively"), NOT vip_demote_v1 (minority self-demote).
// A node may advertise one without the other, so these must be distinct.

// Direct-probe trust: a REACHABLE peer's "not claiming" answer is a release-proof input only
// if it advertises vip_release_probe_v1 — consistent with the relay path's anchor. A peer
// advertising only vip_demote_v1 → fail closed (treated as still claiming).
func TestPeerVIPClaims_DirectRequiresReleaseProbe(t *testing.T) {
	const vip = "10.0.0.9/24"
	peer := &fakeRelayPeer{checkClaims: false} // reachable, reports NOT claiming
	mk := func(tok string) *Server {
		s := &Server{hostName: "self", gate: fakeServerGate{
			supportsTok: map[string]map[string]bool{"target": {tok: true}},
		}}
		s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
			return peer, func() {}, nil
		}
		return s
	}
	if !mk(capabilities.VIPDemoteV1).peerVIPClaims(context.Background(), "target", vip) {
		t.Fatal("reachable peer without vip_release_probe_v1 must fail closed (claims=true)")
	}
	if mk(capabilities.VIPReleaseProbeV1).peerVIPClaims(context.Background(), "target", vip) {
		t.Fatal("reachable peer with vip_release_probe_v1 answering not-claiming must be trusted (claims=false)")
	}
}

// An existing participant is trusted (reachable + release-probe-capable) only when it
// advertises vip_release_probe_v1 — not merely vip_demote_v1.
func TestParticipantReachable_RequiresReleaseProbe(t *testing.T) {
	ctx := context.Background()
	mk := func(tok string) *Server {
		return &Server{hostName: "self", gate: fakeServerGate{
			supportsTok: map[string]map[string]bool{"peer": {tok: true}},
		}}
	}
	if mk(capabilities.VIPDemoteV1).participantReachable(ctx, "peer") {
		t.Fatal("participant advertising only vip_demote_v1 must NOT be trusted")
	}
	if !mk(capabilities.VIPReleaseProbeV1).participantReachable(ctx, "peer") {
		t.Fatal("participant advertising vip_release_probe_v1 must be trusted")
	}
}

// The majority-side takeover gate activates off vip_release_probe_v1 (the cluster can prove
// release cluster-wide), NOT vip_demote_v1.
func TestVIPGateActive_KeysOffReleaseProbe(t *testing.T) {
	ctx := context.Background()
	demoteOnly := &Server{hostName: "self", gate: fakeServerGate{
		enforcedTok: map[string]bool{capabilities.VIPDemoteV1: true},
	}}
	if demoteOnly.vipGateActive(ctx) {
		t.Fatal("vip_demote_v1 enforced alone must NOT activate the majority takeover gate")
	}
	probeEnforced := &Server{hostName: "self", gate: fakeServerGate{
		enforcedTok: map[string]bool{capabilities.VIPReleaseProbeV1: true},
	}}
	if !probeEnforced.vipGateActive(ctx) {
		t.Fatal("vip_release_probe_v1 enforced must activate the majority takeover gate")
	}
}

// PR 5: an UNREACHABLE holder that an operator has manual-fence-confirmed (attested down via
// `lv host fence-confirm <host>`) is treated as having RELEASED its VIP — the supported
// availability-first recovery. No row, an expired row, or an automatic 'fenced' attempt →
// fail closed (assume it still claims).
func TestPeerVIPClaims_ManualFenceConfirmRelease(t *testing.T) {
	ctx := context.Background()
	const vip = "10.0.0.9/24"
	newS := func() *Server {
		db, err := corrosion.NewTestClient()
		if err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		s := &Server{hostName: "self", db: db, gate: fakeServerGate{}} // no healthy peers → no relay
		s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
			return nil, nil, errors.New("unreachable")
		}
		return s
	}

	// Unreachable + no fence row → assume it STILL claims (fail closed).
	if s := newS(); !s.peerVIPClaims(ctx, "deadholder", vip) {
		t.Fatal("unreachable holder with no proof must fail closed (claims=true)")
	}

	// Unreachable + a recent operator manual-confirm → released (claims=false).
	s2 := newS()
	if err := corrosion.InsertFenceLog(ctx, s2.db, corrosion.FenceLogRecord{ID: "mc1", HostName: "deadholder", Method: "manual", Result: "manual-confirmed"}); err != nil {
		t.Fatal(err)
	}
	if s2.peerVIPClaims(ctx, "deadholder", vip) {
		t.Fatal("unreachable holder with a fresh manual-fence-confirm must be treated as released (claims=false)")
	}

	// Unreachable + only an automatic 'fenced' attempt (maybe partial) → still fail closed.
	s3 := newS()
	if err := corrosion.InsertFenceLog(ctx, s3.db, corrosion.FenceLogRecord{ID: "f1", HostName: "deadholder", Method: "ipmi", Result: "fenced"}); err != nil {
		t.Fatal(err)
	}
	if !s3.peerVIPClaims(ctx, "deadholder", vip) {
		t.Fatal("automatic 'fenced' (not manual-confirmed) must not release → claims=true")
	}
}

// standDownHolder treats an UNREACHABLE but manual-fence-confirmed holder as already stood
// down (its keepalived is gone) — so the move gate's stand-down step doesn't refuse before
// the release proof is consulted. Regression for the gap found in live validation: PR 5
// wired manual-confirm into the release proof but NOT into stand-down, which runs first.
// manualFenceConfirmedVIP is honored ONLY for a host that is NOT a currently-healthy quorum
// member. A live/rejoined member (in HealthyPeers) must NOT have a stale attestation free its
// VIP — its live state governs. (High finding from the ephemeral-partition validation review.)
func TestManualFenceConfirmedVIP_GatedOnHealthyMember(t *testing.T) {
	ctx := context.Background()
	mk := func(healthy []string) *Server {
		db, err := corrosion.NewTestClient()
		if err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{ID: "mc", HostName: "h", Method: "manual", Result: "manual-confirmed"}); err != nil {
			t.Fatal(err)
		}
		return &Server{hostName: "self", db: db, gate: fakeServerGate{healthy: healthy}}
	}
	// Down host (not a healthy member) + fresh confirm → honored.
	if !mk(nil).manualFenceConfirmedVIP(ctx, "h") {
		t.Fatal("a down host with a fresh manual-confirm must be honored")
	}
	// Currently-healthy member (reachable / rejoined) → NOT honored despite the fresh row.
	if mk([]string{"h"}).manualFenceConfirmedVIP(ctx, "h") {
		t.Fatal("a currently-healthy member must NOT honor a (stale) manual-confirm")
	}
}

func TestStandDownHolder_ManualFenceConfirmedUnreachable(t *testing.T) {
	ctx := context.Background()
	// Two unreachability models — both must behave the same:
	//   dialErr: dialPeer itself fails (eager).
	//   rpcErr:  dialPeer "succeeds" (gRPC dials LAZILY) but the RemoveLB CALL fails — the
	//            REAL production path for a dead peer, which the first fix missed.
	newS := func(rpcErr bool) *Server {
		db, err := corrosion.NewTestClient()
		if err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		s := &Server{hostName: "self", db: db, gate: fakeServerGate{}}
		s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
			if rpcErr {
				return &fakeRelayPeer{}, func() {}, nil // dial OK; RemoveLB is Unimplemented → RPC error
			}
			return nil, nil, errors.New("unreachable") // eager dial failure
		}
		return s
	}
	for _, rpcErr := range []bool{false, true} {
		// No manual-confirm → stand-down FAILS (fail closed → move refused).
		if err := newS(rpcErr).standDownHolder(ctx, "lbtest", "deadholder"); err == nil {
			t.Fatalf("rpcErr=%v: unreachable holder with no fence-confirm must fail stand-down", rpcErr)
		}
		// A fresh manual-fence-confirm → treated as already stood down (nil).
		s2 := newS(rpcErr)
		if err := corrosion.InsertFenceLog(ctx, s2.db, corrosion.FenceLogRecord{ID: "mc", HostName: "deadholder", Method: "manual", Result: "manual-confirmed"}); err != nil {
			t.Fatal(err)
		}
		if err := s2.standDownHolder(ctx, "lbtest", "deadholder"); err != nil {
			t.Fatalf("rpcErr=%v: manual-fence-confirmed unreachable holder must be stood down; got %v", rpcErr, err)
		}
	}
}
