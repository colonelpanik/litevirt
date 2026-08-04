package grpcapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Delegated project-quota admission — the second half of F2.
//
// Reserve-then-verify (reservation_admission.go) makes two concurrent admissions
// agree on a winner, but only once both reservations are VISIBLE to both deciders.
// Corrosion is eventually consistent, so two nodes that have not yet exchanged
// operation rows each see only their own claim and both admit. No amount of local
// ordering fixes that: the inputs differ.
//
// So the PROJECT-QUOTA decision moves to one node — the project's D1 authority
// holder — which necessarily sees every grant it has made. HOST capacity is not
// delegated: only the target host's owner reserves against it, so it is already
// serialized by a single node for exactly the same reason.
//
// Why a peer RPC and not a conditional write. A compare-and-swap against the
// replicated store would succeed independently on each node's own copy — it
// serializes writes to one row, not decisions across a partition. Delegation is the
// only shape that makes two racing admissions consult the same view.
//
// An unreachable holder REFUSES the admission. That is the repo-wide partition rule
// (a partition fails closed) applied here: the alternative — deciding locally when
// the holder cannot be reached — is precisely the behavior this exists to remove,
// and it would reappear exactly when the network is least trustworthy.

// projectAdmissionSettleGrace bounds how long a RELEASED project lease may keep
// holding quota while the winner's committed row makes its way to the holder.
//
// The lease is normally freed by VISIBILITY, not by this timer: the moment the
// admitted resource appears in the holder's replica, committed usage counts it and the
// lease stops (see corrosion.ProjectReservedSettling). Without that, the single
// decider still over-admits — the winner writes its VM on its OWN node and then
// releases, leaving the holder's usage short by one admission until replication
// catches up.
//
// This constant only backstops the case where the resource NEVER appears, because the
// admission was granted and the create then failed downstream. Long enough to cover
// ordinary replication lag, short enough that a failed create does not sit on quota
// that nothing is using.
const projectAdmissionSettleGrace = 5 * time.Second

// ReserveProjectCapacity is the authority holder's side of a delegated admission:
// it runs reserve-then-verify for the PROJECT-QUOTA dimension against its own view
// and returns a lease the caller must release.
//
// Peer-only. The epoch in the request is the caller's belief about who holds
// authority; a mismatch is refused rather than decided, so a request aimed at an
// authority this node no longer holds cannot be answered under the old one.
func (s *Server) ReserveProjectCapacity(ctx context.Context, req *pb.ReserveProjectCapacityRequest) (*pb.ReserveProjectCapacityResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, req.Project)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read project authority: %v", err)
	}
	// Bootstrap. The caller minted the initial authority on ITS replica, so the row
	// naming us has not reached us yet — waiting for replication would fail the very
	// first admission of every project. We do not have to take the caller's word for
	// it either: the initial holder is DERIVED, so we re-derive and confirm
	// independently. A peer cannot talk us into holding an authority our own view of
	// membership does not assign us.
	if !ok && req.AuthorityEpoch == 1 && s.derivedProjectHolder(ctx, req.Project) == s.hostName {
		if _, cerr := corrosion.ClaimInitialProjectAuthority(ctx, s.db, req.Project, s.hostName); cerr != nil {
			return nil, status.Errorf(codes.Internal, "establish project authority: %v", cerr)
		}
		cur, ok, err = corrosion.CurrentProjectAuthority(ctx, s.db, req.Project)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read project authority: %v", err)
		}
	}
	// Refuse unless we are CURRENTLY the holder at the epoch the caller addressed.
	// Answering under a newer epoch would be just as wrong as answering under an
	// older one: the caller's peer may have already been told a different holder is
	// deciding, and two deciders is the state this whole mechanism removes.
	if !ok || cur.Holder != s.hostName || cur.Epoch != req.AuthorityEpoch {
		holder, epoch := "", int64(0)
		if ok {
			holder, epoch = cur.Holder, cur.Epoch
		}
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %s does not hold project %q admission authority at epoch %d (current: holder %q epoch %d)",
			s.hostName, req.Project, req.AuthorityEpoch, holder, epoch)
	}

	// Rebuild the subject from the wire: identity (kind:name from resource_id,
	// host) plus the absolute want. The HOLDER's op row is the one the settle rule
	// reads, so the retire-by-observation hint must survive the delegation hop.
	subject := subjectForCreate(req.ResourceId, req.WorkloadHost, int(req.WantCpu), int(req.WantMemMib))
	lease, err := s.admitProjectLocal(ctx, req.Method, req.Project, req.Principal, req.ResourceId, subject, int(req.CpuDelta), int(req.MemMibDelta))
	if err != nil {
		return nil, err
	}
	return &pb.ReserveProjectCapacityResponse{LeaseId: lease, AuthorityEpoch: cur.Epoch}, nil
}

// ReleaseProjectCapacity frees a lease granted by ReserveProjectCapacity. Peer-only
// and idempotent (a repeated release re-appends an identical terminal step).
//
// Deliberately NOT epoch-checked. A lease outliving a takeover must still be
// releasable — refusing here would strand held quota until the expiry reaper, which
// is a worse outcome than honouring a release from a node that has since lost
// authority. Releasing only ever frees capacity, so a stale caller cannot use this
// to admit anything.
func (s *Server) ReleaseProjectCapacity(ctx context.Context, req *pb.ReleaseProjectCapacityRequest) (*emptypb.Empty, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.LeaseId == "" {
		return &emptypb.Empty{}, nil
	}
	if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
		OperationID: req.LeaseId, StepName: corrosion.OpStepCompleted,
	}); err != nil {
		return nil, status.Errorf(codes.Internal, "release project lease: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// admitProjectLocal runs reserve-then-verify for the project-quota dimension against
// THIS node's view, returning the lease's operation id. It is the holder's decision
// procedure, used both when serving a delegated request and when this node is itself
// the holder (in which case there is no reason to make a network call to ourselves).
//
// principal is the ORIGINATING end user, carried across the delegation so the
// journal records who asked rather than which daemon relayed it.
func (s *Server) admitProjectLocal(ctx context.Context, method, project, principal, resourceID string, subject quotaSubject, cpuDelta, memDelta int) (string, error) {
	if cpuDelta <= 0 && memDelta <= 0 {
		return "", nil
	}
	rv := corrosion.ReservationVector{
		Project: project, ProjectCPU: cpuDelta, ProjectMemMiB: memDelta,
		Workload: subject.Name, WorkloadKind: subject.Kind, WorkloadHost: subject.Host,
		WantCPU: subject.WantCPU, WantMemMiB: subject.WantMemMiB,
	}
	resJSON, err := rv.Encode()
	if err != nil {
		return "", status.Errorf(codes.Internal, "encode reservation: %v", err)
	}
	op := corrosion.OperationRecord{
		ID:              newID(),
		Method:          method,
		Principal:       principal,
		Project:         project,
		ResourceID:      resourceID,
		ResourceKind:    corrosion.CapacityResourceKind,
		OperationKind:   string(corrosion.OpResourceUpdateRunning),
		ReservationJSON: resJSON,
	}
	if err := corrosion.InsertOperation(ctx, s.db, op); err != nil {
		return "", status.Errorf(codes.Internal, "reserve project capacity: %v", err)
	}
	if err := s.stampReservationAuthority(ctx, op.ID, project); err != nil {
		s.releaseLocalLease(ctx, op.ID)
		return "", err
	}
	if err := s.checkProjectQuotaSettling(ctx, project, cpuDelta, memDelta, op.ID); err != nil {
		s.releaseLocalLease(ctx, op.ID)
		return "", err
	}
	return op.ID, nil
}

// checkProjectQuotaSettling is the quota check the AUTHORITY HOLDER makes: committed
// usage, plus earlier in-flight claimants, plus winners whose committed row has not
// reached this node yet (see projectAdmissionSettleGrace).
func (s *Server) checkProjectQuotaSettling(ctx context.Context, project string, cpuDelta, memDelta int, opID string) error {
	q, err := corrosion.GetProjectQuota(ctx, s.db, project)
	if err != nil {
		return status.Errorf(codes.Internal, "get project quota: %v", err)
	}
	if q == nil {
		return nil // unbounded
	}
	u, err := corrosion.SumProjectUsage(ctx, s.db, project)
	if err != nil {
		return status.Errorf(codes.Internal, "sum project usage: %v", err)
	}
	rCPU, rMem, err := corrosion.ProjectReservedSettling(ctx, s.db, project, opID, projectAdmissionSettleGrace, time.Now())
	if err != nil {
		return status.Errorf(codes.Internal, "sum project reservations: %v", err)
	}
	if q.VCPULimit > 0 && u.VCPUUsed+rCPU+cpuDelta > q.VCPULimit {
		return status.Errorf(codes.ResourceExhausted,
			"project %q vCPU quota exceeded (used %d + reserved %d + new %d > limit %d)",
			project, u.VCPUUsed, rCPU, cpuDelta, q.VCPULimit)
	}
	if q.MemMiBLimit > 0 && u.MemMiBUsed+rMem+memDelta > q.MemMiBLimit {
		return status.Errorf(codes.ResourceExhausted,
			"project %q memory quota exceeded (used %d + reserved %d + new %d > limit %d)",
			project, u.MemMiBUsed, rMem, memDelta, q.MemMiBLimit)
	}
	return nil
}

// releaseLocalLease marks a local capacity lease terminal, freeing it.
func (s *Server) releaseLocalLease(ctx context.Context, id string) {
	if id == "" {
		return
	}
	if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
		OperationID: id, StepName: corrosion.OpStepCompleted,
	}); err != nil {
		s.noteStateWriteFail(string(corrosion.OpResourceUpdateRunning), err)
	}
}

// admitProjectQuota decides the project-quota half of an admission, delegating to
// the authority holder when delegation is active and this node is not the holder.
// It returns the holder it decided on and the lease held there ("" for a local or
// no-op decision).
func (s *Server) admitProjectQuota(ctx context.Context, method, project, resourceID string, subject quotaSubject, cpuDelta, memDelta int) (holder, leaseID string, epoch int64, err error) {
	if cpuDelta <= 0 && memDelta <= 0 {
		return "", "", 0, nil
	}
	principal := callerUsername(ctx) + "@" + callerRealm(ctx)

	auth, aerr := s.ensureProjectAuthority(ctx, project)
	if aerr != nil || auth.Holder == "" {
		// No authority could be established — fall back to the local check rather
		// than refusing outright. This is the pre-delegation behavior, and an
		// authority record that cannot be read is a state problem, not evidence that
		// a competing admission is in flight. epoch 0: no authority backed this
		// grant, so there is nothing for the commit fence to re-validate.
		return "", "", 0, s.checkProjectQuotaSettling(ctx, project, cpuDelta, memDelta, "")
	}
	if auth.Holder == s.hostName {
		id, derr := s.admitProjectLocal(ctx, method, project, principal, resourceID, subject, cpuDelta, memDelta)
		return s.hostName, id, auth.Epoch, derr
	}

	client, conn, cerr := s.peerClient(ctx, auth.Holder)
	if cerr != nil {
		return "", "", 0, status.Errorf(codes.Unavailable,
			"project %q admission authority %s is unreachable, refusing to admit from a stale local view: %v",
			project, auth.Holder, cerr)
	}
	defer conn.Close()

	resp, rerr := client.ReserveProjectCapacity(ctx, &pb.ReserveProjectCapacityRequest{
		Project:        project,
		Method:         method,
		CpuDelta:       int32(cpuDelta),
		MemMibDelta:    int32(memDelta),
		AuthorityEpoch: auth.Epoch,
		Principal:      principal,
		ResourceId:     resourceID,
		WorkloadHost:   subject.Host,
		WantCpu:        int32(subject.WantCPU),
		WantMemMib:     int32(subject.WantMemMiB),
	})
	if rerr != nil {
		// A FailedPrecondition means authority moved between our read and the call.
		// Retry ONCE against the freshly-read holder: a handoff should not surface as
		// a spurious refusal to the user, but retrying indefinitely would turn a
		// flapping authority into a hang.
		if status.Code(rerr) == codes.FailedPrecondition {
			return s.retryProjectQuotaOnce(ctx, method, project, principal, resourceID, subject, cpuDelta, memDelta, auth.Epoch)
		}
		return "", "", 0, rerr
	}
	// The epoch the grant was ACTUALLY made under, from the holder — not our own
	// read. The commit fence re-validates this epoch before the durable write.
	return auth.Holder, resp.LeaseId, resp.AuthorityEpoch, nil
}

// retryProjectQuotaOnce re-reads the authority and makes exactly one more attempt,
// used when the first attempt raced a handoff. prevEpoch guards against retrying
// into the same stale answer.
func (s *Server) retryProjectQuotaOnce(ctx context.Context, method, project, principal, resourceID string, subject quotaSubject, cpuDelta, memDelta int, prevEpoch int64) (holder, leaseID string, epoch int64, err error) {
	cur, ok, cerr := corrosion.CurrentProjectAuthority(ctx, s.db, project)
	if cerr != nil || !ok || cur.Epoch == prevEpoch {
		return "", "", 0, status.Errorf(codes.Unavailable,
			"project %q admission authority moved while admitting; retry", project)
	}
	if cur.Holder == s.hostName {
		id, derr := s.admitProjectLocal(ctx, method, project, principal, resourceID, subject, cpuDelta, memDelta)
		return s.hostName, id, cur.Epoch, derr
	}
	client, conn, derr := s.peerClient(ctx, cur.Holder)
	if derr != nil {
		return "", "", 0, status.Errorf(codes.Unavailable,
			"project %q admission authority %s is unreachable: %v", project, cur.Holder, derr)
	}
	defer conn.Close()
	resp, rerr := client.ReserveProjectCapacity(ctx, &pb.ReserveProjectCapacityRequest{
		Project:        project,
		Method:         method,
		CpuDelta:       int32(cpuDelta),
		MemMibDelta:    int32(memDelta),
		AuthorityEpoch: cur.Epoch,
		Principal:      principal,
		ResourceId:     resourceID,
		WorkloadHost:   subject.Host,
		WantCpu:        int32(subject.WantCPU),
		WantMemMib:     int32(subject.WantMemMiB),
	})
	if rerr != nil {
		return "", "", 0, rerr
	}
	return cur.Holder, resp.LeaseId, resp.AuthorityEpoch, nil
}

// releaseProjectQuota frees a lease taken by admitProjectQuota, wherever it lives.
func (s *Server) releaseProjectQuota(ctx context.Context, holder, project, leaseID string) {
	if leaseID == "" {
		return
	}
	if holder == "" || holder == s.hostName {
		s.releaseLocalLease(ctx, leaseID)
		return
	}
	client, conn, err := s.peerClient(ctx, holder)
	if err != nil {
		// The lease is stranded on the holder until the expiry reaper collects it.
		// Surfaced rather than swallowed: it shows up later as quota pressure with no
		// workload behind it, which is miserable to diagnose from scratch.
		s.noteStateWriteFail(string(corrosion.OpResourceUpdateRunning), err)
		return
	}
	defer conn.Close()
	if _, err := client.ReleaseProjectCapacity(ctx, &pb.ReleaseProjectCapacityRequest{
		Project: project, LeaseId: leaseID,
	}); err != nil {
		s.noteStateWriteFail(string(corrosion.OpResourceUpdateRunning), err)
	}
}
