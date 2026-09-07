package grpcapi

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fenceReadinessSampleVMs bounds the example list in the response. The count is
// the number that matters; the names are only so an operator recognises which
// workloads are meant.
const fenceReadinessSampleVMs = 10

// fenceReadinessPingTimeout bounds one peer's posture Ping. A host that cannot
// answer promptly is reported as unreachable — unknown posture, never assumed
// good — rather than stalling a diagnostic an operator is running during an
// incident.
const fenceReadinessPingTimeout = 5 * time.Second

// GetFenceReadiness answers whether the shared-storage fence would actually run
// if a shared-disk VM had to change hosts right now.
//
// It exists because neither half of that answer was observable. The capability
// latch is visible cluster-wide, but the per-node `enforcement.shared_storage_fence`
// kill-switch is local config that appears nowhere on the wire — so a cluster
// could show shared_storage_fence_v1 fully latched while some members silently
// skipped the fence, and a cross-host transfer of a shared-disk VM would proceed
// on a best-effort fence that never confirmed power-off.
//
// This is a DIAGNOSTIC. Nothing here may be consulted by a fencing decision: the
// answer is assembled from self-reports (PingResponse.not_enforcing), which are
// trustworthy as claims of degradation and worthless as claims of safety.
func (s *Server) GetFenceReadiness(ctx context.Context, _ *emptypb.Empty) (*pb.FenceReadiness, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}

	sharedVMs, err := corrosion.VMNamesWithWritableSharedDisk(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list shared-disk VMs: %v", err)
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list hosts: %v", err)
	}

	resp := &pb.FenceReadiness{
		CapabilityLatched: s.gate != nil && s.gate.Enforced(ctx, capabilities.SharedStorageFenceV1),
		VmsWithSharedDisk: int32(len(sharedVMs)),
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	if len(sharedVMs) > fenceReadinessSampleVMs {
		resp.SampleVms = append(resp.SampleVms, sharedVMs[:fenceReadinessSampleVMs]...)
	} else {
		resp.SampleVms = append(resp.SampleVms, sharedVMs...)
	}

	// enforced_everywhere starts true and is cleared by any host that is not
	// demonstrably enforcing. Unknown clears it exactly like "not enforcing"
	// does: a diagnostic that cannot see a host's posture must not report the
	// cluster clear on its behalf.
	everywhere := len(hosts) > 0
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	for _, h := range hosts {
		p := s.fenceHostPosture(ctx, h.Name)
		if !p.GetReachable() || !p.GetPostureKnown() || !p.GetEnforcing() {
			everywhere = false
		}
		resp.Hosts = append(resp.Hosts, p)
	}
	resp.EnforcedEverywhere = everywhere
	return resp, nil
}

// fenceHostPosture fresh-Pings one host for its own shared-storage-fence
// posture. Self is answered locally: this node's config is not something it
// needs to ask itself over the network, and a loopback dial would fail on a
// single-node cluster whose listener is mid-restart.
func (s *Server) fenceHostPosture(ctx context.Context, host string) *pb.FenceHostPosture {
	if host == s.hostName {
		return &pb.FenceHostPosture{
			Host: host, Reachable: true, PostureKnown: true,
			Enforcing: s.tokenEnabled(capabilities.SharedStorageFenceV1),
			Detail:    "local config",
		}
	}

	pctx, cancel := context.WithTimeout(ctx, fenceReadinessPingTimeout)
	defer cancel()

	c, closeConn, err := s.dialPeer(pctx, host)
	if err != nil {
		return &pb.FenceHostPosture{Host: host, Detail: fmt.Sprintf("dial: %v", err)}
	}
	defer closeConn()

	resp, err := c.Ping(pctx, &pb.PingRequest{})
	if err != nil {
		return &pb.FenceHostPosture{Host: host, Detail: fmt.Sprintf("ping: %v", err)}
	}
	return postureFromPing(host, resp)
}

// postureFromPing maps one peer's Ping answer to its fence posture. Split out as
// a pure function because it holds the judgement that matters — how an old
// binary's silence is read — and standing up a real peer to reach it would leave
// that judgement untested.
func postureFromPing(host string, resp *pb.PingResponse) *pb.FenceHostPosture {
	// An empty not_enforcing list is ambiguous without this flag: it means both
	// "enforces everything" and "too old to say". posture_reported separates
	// them, and false is UNKNOWN — never all-clear.
	if !resp.GetPostureReported() {
		return &pb.FenceHostPosture{
			Host: host, Reachable: true, PostureKnown: false,
			Detail: "host runs a binary that does not report enforcement posture",
		}
	}

	enforcing := !slices.Contains(resp.GetNotEnforcing(), capabilities.SharedStorageFenceV1)
	detail := "enforcing"
	if !enforcing {
		detail = "enforcement.shared_storage_fence is false on this host"
	}
	return &pb.FenceHostPosture{
		Host: host, Reachable: true, PostureKnown: true,
		Enforcing: enforcing, Detail: detail,
	}
}
