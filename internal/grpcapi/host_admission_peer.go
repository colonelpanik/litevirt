package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Destination-owned migration host admission.
//
// A migration's host admission used to run on the SOURCE daemon, reserving
// target capacity against the source's replicated view. The source cannot probe
// the target's runtime inventory, and a missing, stale, incomplete, or
// unreadable replicated capacity observation degrades to DB-only arithmetic —
// silently, which is the worst way: the final target-local safety gate the code
// described did not actually exist for a remote target.
//
// These two peer-only RPCs move the decision to the node that owns the facts.
// The destination re-runs the full local admission — fresh runtime inventory,
// active ownership conditions, bounded runtime-only load, reserve-then-verify
// against its own database — and its database therefore serializes ALL host
// admission claims for it, remote and local alike. The source holds the
// returned lease across the entire transfer and releases it in a
// cancellation-independent bounded context on every return path
// (reservationLease.release).
//
// An old destination that does not implement ReserveHostCapacity is refused
// with FailedPrecondition rather than falling back to the source-side
// arithmetic: migration stays unavailable across the brief mixed-version edge
// instead of making the correctness guarantee conditional on fleet version.

// ReserveHostCapacity runs host-only admission for a workload migrating IN,
// on behalf of the source daemon. Peer-only.
func (s *Server) ReserveHostCapacity(ctx context.Context, req *pb.ReserveHostCapacityRequest) (*pb.ReserveHostCapacityResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	// The destination decides for ITSELF. A request naming another host is a
	// routing error, and answering it would recreate the remote-view admission
	// this RPC exists to remove.
	if req.Host != s.hostName {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host capacity reservation addressed to %q, but this daemon is %q — the destination decides for itself", req.Host, s.hostName)
	}
	intent := admissionIntent{newResidency: req.NewResidency, vmOverhead: req.VmOverhead}
	lease, err := s.admitReserved(ctx, reservedPrincipal(req.Principal), "", req.Method, s.hostName, req.Project, req.ResourceId,
		subjectForCreate(req.ResourceId, s.hostName, int(req.CpuDelta), int(req.MemMibDelta)),
		int(req.CpuDelta), int(req.MemMibDelta), false, intent)
	if err != nil {
		return nil, err
	}
	// The lease's operation row IS the durable reservation; the caller releases
	// it by id. Empty for a zero-delta admission that passed safety.
	return &pb.ReserveHostCapacityResponse{LeaseId: lease.id}, nil
}

// reservedPrincipal guards the journal against an empty carried principal: the
// operation record should always say who asked, and a peer that failed to fill
// it should not produce a blank actor.
func reservedPrincipal(p string) string {
	if p == "" {
		return "peer@cluster"
	}
	return p
}

// ReleaseHostCapacity frees a lease granted by ReserveHostCapacity. Peer-only
// and idempotent (a repeated release re-appends an identical terminal step).
//
// Unlike ReleaseProjectCapacity, this validates WHAT it is asked to terminate:
// only a capacity operation whose reservation targets THIS host may be
// completed here. A malformed, unknown, or foreign operation id is refused
// rather than blindly marked terminal — a release path that can complete
// arbitrary operations is a lever for erasing someone else's live reservation.
func (s *Server) ReleaseHostCapacity(ctx context.Context, req *pb.ReleaseHostCapacityRequest) (*emptypb.Empty, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.LeaseId == "" {
		return &emptypb.Empty{}, nil
	}
	op, err := corrosion.GetOperation(ctx, s.db, req.LeaseId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read lease operation: %v", err)
	}
	if op == nil {
		return nil, status.Errorf(codes.NotFound, "no operation %q on this host", req.LeaseId)
	}
	if op.ResourceKind != corrosion.CapacityResourceKind {
		return nil, status.Errorf(codes.FailedPrecondition,
			"operation %q is a %s operation, not a capacity lease", req.LeaseId, op.ResourceKind)
	}
	rv, err := corrosion.DecodeReservation(op.ReservationJSON)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decode lease reservation: %v", err)
	}
	if rv.TargetHost != s.hostName {
		return nil, status.Errorf(codes.FailedPrecondition,
			"lease %q reserves capacity on host %q, not on this host (%s)", req.LeaseId, rv.TargetHost, s.hostName)
	}
	if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
		OperationID: req.LeaseId, StepName: corrosion.OpStepCompleted,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "release host lease: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// acquireDestinationHostLease obtains the destination-held host lease for a
// workload migrating to host. For the local host it is the ordinary local
// admission — same implementation, no dialing. For a remote host it asks the
// destination daemon, which admits against its own fresh inventory; the
// returned lease releases over the same peer channel.
//
// There is deliberately NO source-side fallback: a destination that cannot
// answer (unreachable, or too old to implement the RPC) refuses the migration.
func (s *Server) acquireDestinationHostLease(
	ctx context.Context, method, host, project, resourceID string, cpuDelta, memDelta int, intent admissionIntent,
) (*reservationLease, error) {
	if host == s.hostName {
		return s.admitHostWithReservation(ctx, method, host, project, resourceID, cpuDelta, memDelta, intent)
	}
	client, closer, err := s.dialPeer(ctx, host)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable,
			"migration target %s is unreachable for host admission: %v", host, err)
	}
	defer closer()
	resp, rerr := client.ReserveHostCapacity(ctx, &pb.ReserveHostCapacityRequest{
		Host:        host,
		Project:     project,
		Method:      method,
		Principal:   callerUsername(ctx) + "@" + callerRealm(ctx),
		ResourceId:  resourceID,
		CpuDelta:    int32(cpuDelta),
		MemMibDelta: int32(memDelta),
		NewResidency: intent.newResidency,
		VmOverhead:   intent.vmOverhead,
	})
	if rerr != nil {
		if status.Code(rerr) == codes.Unimplemented {
			return nil, status.Errorf(codes.FailedPrecondition,
				"migration target %s does not implement destination-owned host admission; "+
					"upgrade it before migrating — there is no safe source-side fallback", host)
		}
		return nil, rerr
	}
	return &reservationLease{s: s, id: resp.LeaseId, hostHolder: host}, nil
}

// releaseRemoteHostLease frees a destination-held host lease over the peer
// channel. Failure strands the lease on the destination until the stale-lease
// sweep collects it; surfaced the same way as a failed local release, because
// it shows up later as capacity pressure with no workload behind it.
func (s *Server) releaseRemoteHostLease(ctx context.Context, holder, leaseID string) error {
	client, closer, err := s.dialPeer(ctx, holder)
	if err != nil {
		return err
	}
	defer closer()
	_, err = client.ReleaseHostCapacity(ctx, &pb.ReleaseHostCapacityRequest{LeaseId: leaseID})
	return err
}
