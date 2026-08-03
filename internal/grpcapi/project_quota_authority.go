package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// quotaReservationTTL bounds how long a routed reservation survives without an
// explicit release. A caller always releases via defer, so the TTL only matters
// when the CALLER dies mid-request — without it that project would leak quota until
// this daemon restarted.
const quotaReservationTTL = 15 * time.Minute

// quotaLease is a reservation held on behalf of a remote caller.
type quotaLease struct {
	project string
	cpu     int
	mem     int
	expires time.Time
}

// admitProjectQuota admits a vCPU/memory GROW against the project's quota and
// reserves it for the rest of the caller's request. The returned release func is
// never nil and must be deferred.
//
// Three paths:
//
//  1. Feature inactive (config flag off, or the capability has not latched
//     cluster-wide) → the historical local, UNSERIALIZED check. Byte-for-behaviour
//     what shipped before, which is what makes this safe to roll out.
//  2. This node holds the project's authority → serialize locally: the same
//     mutex + in-flight ledger the host-capacity path uses. With every admission
//     for the project arriving here, process-local serialization IS cluster-wide
//     serialization.
//  3. Another node holds it → route there over peer mTLS.
//
// Only vCPU and memory are serialized. The other quota dimensions (disk, NIC,
// public IPs, backup GiB) are still admitted by tenancy.Engine.Admit with no
// reservation and remain racy; that is a known gap, not something this closes.
func (s *Server) admitProjectQuota(ctx context.Context, project string, cpuDelta, memMiBDelta int) (func(), error) {
	if cpuDelta <= 0 && memMiBDelta <= 0 {
		return noopRelease, nil
	}
	project = tenancy.NormalizeProject(project)
	if !s.projectQuotaAuthorityActive(ctx) {
		return noopRelease, s.checkProjectQuota(ctx, project, cpuDelta, memMiBDelta)
	}

	holder, epoch, err := s.projectQuotaHolder(ctx, project)
	if err != nil || holder == "" {
		// No authority resolvable (no eligible hosts, or a state read failed).
		// Degrade to the local check rather than refusing a create.
		return noopRelease, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta, "authority unresolved", err)
	}
	if holder == s.hostName {
		return s.admitProjectQuotaLocal(ctx, project, cpuDelta, memMiBDelta)
	}
	return s.admitProjectQuotaRemote(ctx, holder, epoch, project, cpuDelta, memMiBDelta)
}

// projectQuotaHolder resolves who serializes this project's quota. A recorded
// authority always wins — it is STICKY by design and only moves via an explicit,
// proof-carrying transfer — so an unreachable holder is NOT reassigned here (see
// quotaFailOpen). With no record yet, the deterministic candidate is the answer, and
// ensureProjectAuthority mints it when the request reaches that node.
func (s *Server) projectQuotaHolder(ctx context.Context, project string) (string, int64, error) {
	cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, project)
	if err != nil {
		return "", 0, err
	}
	if ok {
		return cur.Holder, cur.Epoch, nil
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return "", 0, err
	}
	candidate, hasCandidate := corrosion.DeterministicAuthorityCandidate(hosts, project)
	if !hasCandidate {
		return "", 0, nil
	}
	if candidate == s.hostName {
		// Mint it now so peers routing here find a recorded holder. Best-effort:
		// a failure just means we serialize locally this time and mint later.
		if _, err := s.ensureProjectAuthority(ctx, project); err != nil {
			slog.Warn("project quota: minting authority failed; serializing locally anyway",
				"project", project, "error", err)
		}
	}
	return candidate, 0, nil
}

func (s *Server) projectAdmitStateFor(project string) *hostAdmitState {
	s.projectAdmitMu.Lock()
	defer s.projectAdmitMu.Unlock()
	if s.projectAdmit == nil {
		s.projectAdmit = map[string]*hostAdmitState{}
	}
	st, ok := s.projectAdmit[project]
	if !ok {
		st = &hostAdmitState{}
		s.projectAdmit[project] = st
	}
	return st
}

// admitProjectQuotaLocal is the holder-side admit: check quota against committed
// usage + replicated reservations + this node's in-flight ledger, then reserve.
func (s *Server) admitProjectQuotaLocal(ctx context.Context, project string, cpuDelta, memMiBDelta int) (func(), error) {
	st := s.projectAdmitStateFor(project)
	st.mu.Lock()
	if err := s.checkProjectQuotaWithPending(ctx, project, cpuDelta, memMiBDelta, st.pendingCPU, st.pendingMem); err != nil {
		st.mu.Unlock()
		return noopRelease, err
	}
	cpu, mem := maxInt(cpuDelta, 0), maxInt(memMiBDelta, 0)
	st.pendingCPU += cpu
	st.pendingMem += mem
	st.mu.Unlock()
	return st.releaseFor(cpu, mem), nil
}

// admitProjectQuotaRemote routes to the holder. On an epoch mismatch it retries
// ONCE against the holder the remote reports, so a stale local view self-corrects
// without looping.
func (s *Server) admitProjectQuotaRemote(ctx context.Context, holder string, epoch int64, project string, cpuDelta, memMiBDelta int) (func(), error) {
	// Never send a request a peer would answer Unimplemented: a mixed-version or
	// flag-off holder must degrade, not error.
	if s.gate == nil || !s.gate.PeerSupportsFresh(ctx, holder, capabilities.ProjectQuotaAuthorityV1) {
		return noopRelease, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
			"holder does not advertise "+capabilities.ProjectQuotaAuthorityV1, nil)
	}

	for attempt := 0; attempt < 2; attempt++ {
		client, conn, err := s.peerClient(ctx, holder)
		if err != nil {
			return noopRelease, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
				"holder "+holder+" unreachable", err)
		}
		resp, err := client.AdmitProjectQuota(ctx, &pb.AdmitProjectQuotaRequest{
			Sender:         s.hostName,
			Project:        project,
			CpuDelta:       int32(cpuDelta),
			MemMibDelta:    int32(memMiBDelta),
			AuthorityEpoch: epoch,
		})
		conn.Close()
		if err != nil {
			if status.Code(err) == codes.FailedPrecondition && attempt == 0 {
				// Epoch/holder moved under us. Re-resolve and try the new one.
				if h2, e2, rerr := s.projectQuotaHolder(ctx, project); rerr == nil && h2 != "" && h2 != holder {
					holder, epoch = h2, e2
					continue
				}
			}
			return noopRelease, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
				"holder "+holder+" refused to answer", err)
		}
		if !resp.Admitted {
			return noopRelease, status.Errorf(codes.ResourceExhausted,
				"project %q quota exceeded: %s", project, resp.Detail)
		}
		id := resp.ReservationId
		return func() { s.releaseRemoteQuota(holder, id) }, nil
	}
	return noopRelease, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
		"authority epoch kept moving", nil)
}

func (s *Server) releaseRemoteQuota(holder, id string) {
	if id == "" {
		return
	}
	// Detached context: the request context is usually already cancelled by the
	// time a deferred release runs, and dropping the release would leak the
	// holder's reservation until its TTL.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, conn, err := s.peerClient(ctx, holder)
	if err != nil {
		slog.Warn("project quota: releasing routed reservation failed; it will expire on TTL",
			"holder", holder, "reservation", id, "error", err)
		return
	}
	defer conn.Close()
	if _, err := client.ReleaseProjectQuotaReservation(ctx, &pb.ReleaseProjectQuotaReservationRequest{
		Sender: s.hostName, ReservationId: id,
	}); err != nil {
		slog.Warn("project quota: releasing routed reservation failed; it will expire on TTL",
			"holder", holder, "reservation", id, "error", err)
	}
}

// quotaFailOpen degrades to the local unserialized check when the authority cannot
// be consulted, and says so loudly.
//
// Fail OPEN, deliberately. Quota is a tenancy/business limit, not a safety
// invariant — the fail-CLOSED treatment in this codebase is reserved for
// double-run and fencing hazards. Failing closed here would mean one dead node
// blocks every VM create in every project it happens to hold, which is a worse
// outage than the over-admission it would prevent. The window is bounded, alerted,
// and audited so it is never silent.
//
// Reassigning the authority is NOT an option: TakeoverProjectAuthority requires a
// fence_proof_ref for an unplanned takeover, and "I could not reach it" is not
// proof that it stopped admitting.
func (s *Server) quotaFailOpen(ctx context.Context, project string, cpuDelta, memMiBDelta int, reason string, cause error) error {
	detail := reason
	if cause != nil {
		detail = fmt.Sprintf("%s: %v", reason, cause)
	}
	slog.Warn("project quota admission is not serialized; falling back to the local check",
		"project", project, "reason", detail)
	s.notify(ctx, notify.Notification{
		Kind: "quota.unserialized", Severity: notify.SevWarn, Subject: project,
		Detail: "project-quota admission fell back to an unserialized local check: " + detail,
	})
	s.audit(ctx, "project.quota", project,
		"unserialized admission fallback: "+detail, "degraded")
	return s.checkProjectQuota(ctx, project, cpuDelta, memMiBDelta)
}

// ---- holder side ----

// AdmitProjectQuota admits and reserves a grow on behalf of a peer. Peer-only.
func (s *Server) AdmitProjectQuota(ctx context.Context, req *pb.AdmitProjectQuotaRequest) (*pb.AdmitProjectQuotaResponse, error) {
	if err := requireReplicationPeer(ctx, req.Sender); err != nil {
		return nil, err
	}
	project := tenancy.NormalizeProject(req.Project)

	// Refuse if we are not the current authority: accepting would defeat the whole
	// point (two nodes reserving for one project). Report what we see so the caller
	// re-resolves instead of retrying blindly.
	cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, project)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read project authority: %v", err)
	}
	if !ok || cur.Holder != s.hostName {
		holder := ""
		var epoch int64
		if ok {
			holder, epoch = cur.Holder, cur.Epoch
		}
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %s is not the admission authority for project %q (current holder %q epoch %d)",
			s.hostName, project, holder, epoch)
	}
	if req.AuthorityEpoch != 0 && req.AuthorityEpoch != cur.Epoch {
		return &pb.AdmitProjectQuotaResponse{
			Admitted: false, Detail: "stale authority epoch",
			CurrentHolder: cur.Holder, CurrentEpoch: cur.Epoch,
		}, status.Errorf(codes.FailedPrecondition,
			"stale authority epoch %d for project %q (current %d)", req.AuthorityEpoch, project, cur.Epoch)
	}

	release, err := s.admitProjectQuotaLocal(ctx, project, int(req.CpuDelta), int(req.MemMibDelta))
	if err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			return &pb.AdmitProjectQuotaResponse{Admitted: false, Detail: status.Convert(err).Message()}, nil
		}
		return nil, err
	}

	id, err := newReservationID()
	if err != nil {
		release()
		return nil, status.Errorf(codes.Internal, "mint reservation id: %v", err)
	}
	s.putQuotaLease(id, release, project, int(req.CpuDelta), int(req.MemMibDelta))
	return &pb.AdmitProjectQuotaResponse{
		Admitted: true, ReservationId: id, CurrentHolder: cur.Holder, CurrentEpoch: cur.Epoch,
	}, nil
}

// ReleaseProjectQuotaReservation drops a routed reservation. Peer-only. Idempotent:
// an unknown id (already released, or expired) is a success, so a caller retrying a
// release never gets an error it cannot act on.
func (s *Server) ReleaseProjectQuotaReservation(ctx context.Context, req *pb.ReleaseProjectQuotaReservationRequest) (*emptypb.Empty, error) {
	if err := requireReplicationPeer(ctx, req.Sender); err != nil {
		return nil, err
	}
	s.dropQuotaLease(req.ReservationId)
	return &emptypb.Empty{}, nil
}

// quotaLeaseEntry is one routed reservation held for a remote caller.
//
// The table lives on the Server, NOT in a package global: the fleet harness runs
// several daemons in one process, and a shared table would let one node release
// another's reservations.
//
// In-memory on purpose. A durable table would need an operations row per admission
// plus crash recovery, and a crashed create would wedge the project's quota until an
// operator noticed. The cost is that a holder restart forgets in-flight
// reservations — a bounded over-admission window, the same trade the host ledger
// makes.
type quotaLeaseEntry struct {
	lease   quotaLease
	release func()
}

func (s *Server) putQuotaLease(id string, release func(), project string, cpu, mem int) {
	s.quotaLeaseMu.Lock()
	defer s.quotaLeaseMu.Unlock()
	if s.quotaLeases == nil {
		s.quotaLeases = map[string]*quotaLeaseEntry{}
	}
	s.reapQuotaLeasesLocked()
	s.quotaLeases[id] = &quotaLeaseEntry{
		lease:   quotaLease{project: project, cpu: cpu, mem: mem, expires: time.Now().Add(quotaReservationTTL)},
		release: release,
	}
}

func (s *Server) dropQuotaLease(id string) {
	s.quotaLeaseMu.Lock()
	e, ok := s.quotaLeases[id]
	if ok {
		delete(s.quotaLeases, id)
	}
	s.reapQuotaLeasesLocked()
	s.quotaLeaseMu.Unlock()
	if ok {
		e.release()
	}
}

// reapQuotaLeasesLocked releases leases whose caller never came back. Caller holds
// quotaLeaseMu. Without this a caller that died mid-request would hold the
// project's quota until this daemon restarted.
func (s *Server) reapQuotaLeasesLocked() {
	now := time.Now()
	for id, e := range s.quotaLeases {
		if now.After(e.lease.expires) {
			slog.Warn("project quota: reservation expired without a release",
				"project", e.lease.project, "reservation", id,
				"cpu", e.lease.cpu, "mem_mib", e.lease.mem)
			delete(s.quotaLeases, id)
			e.release()
		}
	}
}

func newReservationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
