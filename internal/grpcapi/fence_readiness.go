package grpcapi

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
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

const (
	// fenceReadinessPingTimeout bounds ONE peer's posture Ping. A host that
	// cannot answer promptly is reported as unreachable — unknown posture, never
	// assumed good.
	fenceReadinessPingTimeout = 5 * time.Second
	// fenceReadinessTotalBudget bounds the WHOLE fan-out. A per-peer timeout
	// alone does not: probed one after another, thirty unreachable hosts would
	// take thirty times the per-peer timeout, and the caller's own deadline
	// would kill the RPC before it returned anything — losing the per-host
	// detail exactly when an operator is running this during an incident.
	fenceReadinessTotalBudget = 20 * time.Second
	// fenceReadinessProbeWorkers bounds concurrent peer dials, so a large fleet
	// does not open one connection per host at once.
	fenceReadinessProbeWorkers = 8
)

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
		// Latched, NEVER Enforced. Enforced is a mutator: on an unlatched token it
		// runs CapabilityActive and then sets activated[token] plus a durable
		// marker that survives restart — so this read-only diagnostic, run by a
		// viewer, would permanently latch the capability and then report the
		// `true` it had just caused. Latched is a pure in-memory marker read.
		CapabilityLatched: s.gate != nil && s.gate.Latched(capabilities.SharedStorageFenceV1),
		VmsWithSharedDisk: int32(len(sharedVMs)),
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	if len(sharedVMs) > fenceReadinessSampleVMs {
		resp.SampleVms = append(resp.SampleVms, sharedVMs[:fenceReadinessSampleVMs]...)
	} else {
		resp.SampleVms = append(resp.SampleVms, sharedVMs...)
	}

	// Witnesses are excluded, following dualRunProbeTargets: a witness never
	// hosts a workload, so it can never perform the fence and its operator will
	// never turn the flag on. Including it would pin enforced_everywhere false on
	// every cluster that runs one, and the remedy would tell an operator to
	// reconfigure and restart their quorum arbiter to fix a fence it cannot
	// perform. Every other state stays IN — a draining, upgrading, offline or
	// fenced host still has disks, and is exactly where an unfenced second copy
	// would hide.
	workloadHosts := make([]corrosion.HostRecord, 0, len(hosts))
	for _, h := range hosts {
		if h.IsWitness() {
			continue
		}
		workloadHosts = append(workloadHosts, h)
	}
	hosts = workloadHosts

	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	resp.Hosts = s.probeFencePostures(ctx, hosts)

	// enforced_everywhere starts true and is cleared by any host that is not
	// demonstrably enforcing. Unknown clears it exactly like "not enforcing"
	// does: a diagnostic that cannot see a host's posture must not report the
	// cluster clear on its behalf.
	everywhere := len(hosts) > 0
	for _, p := range resp.Hosts {
		if !p.GetReachable() || !p.GetPostureKnown() || !p.GetEnforcing() {
			everywhere = false
		}
	}
	resp.EnforcedEverywhere = everywhere
	return resp, nil
}

// probeFencePostures asks every host for its posture, concurrently and under one
// overall budget, returning results in the order given.
//
// The budget is the point: probes are independent, so running them serially
// multiplies one slow host's timeout by the fleet size, and a caller deadline
// tripping mid-sweep would fail the whole RPC instead of returning the per-host
// detail that makes the report useful. A probe cut short by the budget lands as
// unreachable — unknown, which clears readiness — never as covered.
func (s *Server) probeFencePostures(ctx context.Context, hosts []corrosion.HostRecord) []*pb.FenceHostPosture {
	probeCtx, cancel := context.WithTimeout(ctx, fenceReadinessTotalBudget)
	defer cancel()

	out := make([]*pb.FenceHostPosture, len(hosts))
	sem := make(chan struct{}, fenceReadinessProbeWorkers)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-probeCtx.Done():
				out[i] = budgetExpiredPosture(name)
				return
			}
			// select chooses uniformly among ready cases, so once the budget is
			// spent the sem branch still wins about half the time. Without this
			// re-check those hosts get dialled on a dead context and come back as
			// `ping: context deadline exceeded` — rendered to the operator as "did
			// not answer" about a host nothing ever dialled.
			if probeCtx.Err() != nil {
				out[i] = budgetExpiredPosture(name)
				return
			}
			out[i] = s.fenceHostPosture(probeCtx, name)
		}(i, h.Name)
	}
	wg.Wait()
	return out
}

// budgetExpiredPosture is the answer for a host never probed because the report
// budget ran out first. It is deliberately shaped like every other unknown: a
// host nothing asked is not a host that answered.
func budgetExpiredPosture(host string) *pb.FenceHostPosture {
	return &pb.FenceHostPosture{
		Host: host,
		Detail: fmt.Sprintf("not probed: the %s report budget expired before this host's turn",
			fenceReadinessTotalBudget),
	}
}

// fenceHostPosture fresh-Pings one host for its own shared-storage-fence
// posture. Self is answered locally: this node's config is not something it
// needs to ask itself over the network, and a loopback dial would fail on a
// single-node cluster whose listener is mid-restart.
func (s *Server) fenceHostPosture(ctx context.Context, host string) *pb.FenceHostPosture {
	if host == s.hostName {
		// Self is held to the same standard as a peer. postureFromPing refuses to
		// call a non-advertising peer enforcing; without this the node an operator
		// is logged into — the one that just self-fenced — would be the ONLY host
		// in the fleet given a confident posture while every peer in that state
		// reads unknown.
		//
		// The two predicates are read directly rather than through
		// advertisedCapabilities, which returns an empty list for exactly these
		// two states and nothing else. Equivalent, and better on both counts: it
		// is two atomic loads instead of a list build that walks the runtime
		// inventory under its own 10s context when enforcement.owner_epoch is on
		// — inside a probe already holding one of the sweep's semaphore slots and
		// bounded by a budget that context cannot see. A residual race remains
		// (the watchdog can trip between this check and the config read below),
		// which is inherent to a node reporting on itself; the peers' answers are
		// the authority in that window.
		if s.selfFenced() || s.walQuarantinedNow() {
			return &pb.FenceHostPosture{
				Host: host, Reachable: true, PostureKnown: false,
				Detail: "this host advertises nothing (self-fenced or WAL-quarantined), so its posture cannot be read",
			}
		}
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
	// "enforces everything" and "nothing was said". posture_reported separates
	// them, and false is UNKNOWN — never all-clear.
	//
	// The detail names no cause, because two reach here and they call for
	// opposite actions: the peer predates the field, or it declined to answer a
	// caller without a host certificate. Asserting the first would have an
	// operator upgrade every binary in the fleet over a credential property of
	// the one node they ran the command from.
	if !resp.GetPostureReported() {
		return &pb.FenceHostPosture{
			Host: host, Reachable: true, PostureKnown: false,
			Detail: "host reported no enforcement posture (its binary predates the field, " +
				"or it withheld posture from this caller)",
		}
	}

	// not_enforcing is scoped to what the peer advertises, so a peer advertising
	// NOTHING sends an empty list that says nothing about its kill-switches.
	// That is not a hypothetical: advertisedCapabilities returns nothing at all
	// for a self-fenced or WAL-quarantined node. Reading the absence of the token
	// as "enforcing" would hand the most degraded node in the cluster the
	// cleanest posture — the precise false all-clear this whole field exists to
	// prevent. Require the peer to advertise the token before believing it acts
	// on it.
	//
	// Absence is UNKNOWN and never "not enforcing", because this token is
	// advertised unconditionally (see advertisedCapabilities): a healthy node
	// with the flag off still carries it and reports the switch through
	// not_enforcing below, so absence means something else went wrong — a
	// regressed binary, a self-fence — and naming a cause would send the operator
	// to fix a config value that is not the problem.
	if !slices.Contains(resp.GetCapabilities(), capabilities.SharedStorageFenceV1) {
		// Keyed on what the peer actually said. Reporting a self-fenced node as
		// "does not advertise the token" reads as version skew and points an
		// operator at a binary upgrade for a node that is deliberately going down.
		detail := "host advertises nothing (self-fenced, or too old to carry the token), so its posture cannot be read"
		if resp.GetWalQuarantined() {
			detail = "host is WAL-quarantined and advertising nothing"
		} else if len(resp.GetCapabilities()) > 0 {
			detail = "host advertises other tokens but not shared_storage_fence_v1, so it cannot be enforcing it"
		}
		return &pb.FenceHostPosture{
			Host: host, Reachable: true, PostureKnown: false, Detail: detail,
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
