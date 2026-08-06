package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
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

// errQuotaBarrierFailed says the reservation could not be made durable across the
// cluster. It is distinct from a generic error on purpose: the caller's RPC-error path
// degrades to an unserialized local check, and degrading here would admit against a
// charge no peer can see. It must propagate FAIL CLOSED.
type errQuotaBarrierFailed struct{ detail string }

func (e errQuotaBarrierFailed) Error() string {
	return "project-quota reservation could not be replicated: " + e.detail
}

// errQuotaReconcileIncomplete says this node holds authority but has not drained its
// voters' reservations for the current term, so it cannot know what it would be
// over-admitting. Distinct from a generic error because the caller's error path degrades
// to an unserialized local check — which permits exactly the unreserved admission the
// drain exists to prevent. Must propagate FAIL CLOSED.
type errQuotaReconcileIncomplete struct{ project, detail string }

func (e errQuotaReconcileIncomplete) Error() string {
	return "project-quota authority for " + e.project + " has not reconciled: " + e.detail
}

// errQuotaAuthorityMoved says this node is no longer the project's authority, and
// names the successor when one is recorded.
type errQuotaAuthorityMoved struct{ holder string }

func (e errQuotaAuthorityMoved) Error() string {
	return "project quota authority moved to " + e.holder
}

// RunQuotaLeaseRenewer keeps the admission lease alive for every project this node
// still holds CHARGES for, and drops a project's ledger the moment the lease is lost.
//
// This is what makes a short lease TTL safe. A charge can outlive the TTL (a create
// waiting on an image pull, a routed reservation), and an unrenewed lease would lapse
// underneath it — the next node would acquire with an empty ledger and re-hand quota
// that is still owed. Renewing only while charges exist also means an idle node lets
// its leases expire, so authority naturally follows load instead of being pinned to
// whoever happened to go first.
//
// Losing the lease is not recoverable by holding on: the successor is now the
// authority, and our ledger describes reservations it knows nothing about. Keeping
// them would only refuse our own future requests. Drop them and say so loudly — any
// in-flight commits are covered by the successor's own observation of the workloads
// once they replicate.
func (s *Server) RunQuotaLeaseRenewer(ctx context.Context) {
	t := time.NewTicker(corrosion.QuotaLeaseRenewInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.renewHeldQuotaLeases(ctx)
		}
	}
}

func (s *Server) renewHeldQuotaLeases(ctx context.Context) {
	// Sweep first: retire reservations whose workloads are now visible, and expire
	// stragglers. Any node may sweep — it only tombstones rows that are no longer
	// charged — so this does not depend on being the authority.
	if err := corrosion.SweepQuotaReservations(ctx, s.db); err != nil {
		slog.Warn("project quota: sweeping reservations failed; will retry", "error", err)
	}

	// Renew for every project we still hold a live reservation for. The charges are
	// ROWS now, so this is a query rather than a walk of in-memory state — which also
	// means a restarted holder keeps renewing for charges it granted before the restart.
	projects, err := corrosion.ProjectsWithLiveQuotaReservations(ctx, s.db, s.hostName)
	if err != nil {
		slog.Warn("project quota: listing live reservations failed; will retry", "error", err)
		return
	}
	for _, project := range projects {
		held, currentHolder, err := s.holdsQuotaLease(ctx, project)
		if err != nil {
			slog.Warn("project quota: lease renewal failed; will retry",
				"project", project, "error", err)
			continue
		}
		if held {
			continue
		}
		// We are no longer the authority. The charges are NOT dropped: they are
		// durable rows, the successor already counts them, and our in-flight requests
		// can still commit safely against them. That is the point of durability —
		// there is nothing to discard and nothing to fence.
		slog.Warn("project quota: lost the admission lease; the successor accounts for our "+
			"outstanding reservations from the replicated rows",
			"project", project, "new_holder", currentHolder)
		s.notify(ctx, notify.Notification{
			Kind: "quota.authority_lost", Severity: notify.SevWarn, Subject: project,
			Detail: "lost the project-quota admission lease to " + currentHolder +
				"; outstanding reservations remain charged and are visible to the new authority",
		})
	}
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
func (s *Server) admitProjectQuota(ctx context.Context, project string, cpuDelta, memMiBDelta int) (Admission, error) {
	if cpuDelta <= 0 && memMiBDelta <= 0 {
		return Admission{}, nil
	}
	project = tenancy.NormalizeProject(project)
	if !s.projectQuotaAuthorityActive(ctx) {
		return Admission{}, s.checkProjectQuota(ctx, project, cpuDelta, memMiBDelta)
	}

	holder, epoch, err := s.projectQuotaHolder(ctx, project)
	if err != nil || holder == "" {
		// No authority resolvable (no eligible hosts, or a state read failed).
		// Degrade to the local check rather than refusing a create.
		return Admission{}, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta, "authority unresolved", err)
	}
	if holder == s.hostName {
		// Admitting for ourselves: the row is already local, so only the quorum half of
		// the barrier applies.
		release, err := s.admitProjectQuotaLocal(ctx, project, cpuDelta, memMiBDelta, s.hostName)
		var recon errQuotaReconcileIncomplete
		if errors.As(err, &recon) {
			// FAIL CLOSED. quotaFailOpen would degrade to an unserialized local check —
			// permitting exactly the unreserved admission the drain exists to prevent.
			return Admission{}, status.Errorf(codes.Unavailable,
				"project %q: this node holds admission authority but has not read a quorum of "+
					"voters' reservations, so the request is refused rather than admitted against "+
					"charges it cannot see: %s", project, recon.detail)
		}
		var barrier errQuotaBarrierFailed
		if errors.As(err, &barrier) {
			return Admission{}, status.Errorf(codes.Unavailable,
				"project %q: could not replicate the quota reservation, so the request is refused "+
					"rather than admitted against a charge peers cannot see: %s", project, barrier.detail)
		}
		var moved errQuotaAuthorityMoved
		if errors.As(err, &moved) {
			if moved.holder != "" && moved.holder != s.hostName {
				return s.admitProjectQuotaRemote(ctx, moved.holder, 0, project, cpuDelta, memMiBDelta)
			}
			return Admission{}, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
				"lost the admission lease and no successor is recorded", nil)
		}
		return release, err
	}
	return s.admitProjectQuotaRemote(ctx, holder, epoch, project, cpuDelta, memMiBDelta)
}

// projectQuotaHolder resolves who serializes this project's quota.
//
// A DERIVED holder is not sufficient and was the previous bug: the rendezvous
// candidate is computed from the asynchronously replicated host set, so two nodes
// with different views pick different winners and both serve as authority, with
// nothing converging them. The holder is therefore a LEASE — one replicated fact —
// and peers route to the RECORDED holder rather than to their own derivation.
//
// Order of preference:
//
//  1. An explicitly TRANSFERRED authority (project_authority_epochs) wins outright.
//     That is a deliberate, CAS-guarded, proof-carrying act.
//  2. A live lease wins: whoever holds it is the authority, and every node reads the
//     same row.
//  3. No live lease → the deterministic candidate ATTEMPTS to acquire one, gated on
//     quorum. It becomes the authority only if the read-back confirms it. Restricting
//     the attempt to the candidate stops every node racing for the lease on the first
//     admission; the read-back is what makes the outcome single-valued.
//
// A node that is not the holder never serializes locally — it routes.
func (s *Server) projectQuotaHolder(ctx context.Context, project string) (string, int64, error) {
	// (1) explicit transfer.
	if cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, project); err != nil {
		return "", 0, err
	} else if ok {
		return cur.Holder, cur.Epoch, nil
	}

	// (2) live lease.
	if h, ok, err := corrosion.ProjectQuotaLeaseHolder(ctx, s.db, project); err != nil {
		return "", 0, err
	} else if ok {
		return h, 0, nil
	}

	// (3) nobody holds it. Only the deterministic candidate tries, and only with
	// quorum: acquiring on a minority side would create a second authority for the
	// majority side to contend with.
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return "", 0, err
	}
	candidate, hasCandidate := corrosion.DeterministicAuthorityCandidate(hosts, project)
	if !hasCandidate {
		return "", 0, nil
	}
	if candidate != s.hostName {
		// Someone else should take it. Report them so we route there; if they have
		// not acquired yet the RPC redirects us to whoever actually did.
		return candidate, 0, nil
	}
	if reason, refused := s.decideGateRefused(ctx); refused {
		slog.Warn("project quota: not acquiring the admission lease without quorum",
			"project", project, "reason", reason)
		return "", 0, nil
	}
	held, currentHolder, prevHolder, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, project, s.hostName)
	if err != nil {
		return "", 0, err
	}
	if held {
		s.noteAuthorityTerm(project, prevHolder != s.hostName)
		// Reconciliation is NOT done here. Acquisition is only one of several ways to
		// start serving, so the drain is enforced per authority TERM on the admission
		// path itself — see ensureReconciledForTerm.
		return s.hostName, 0, nil
	}
	// Lost the race (or a concurrent writer won). currentHolder may be empty, in
	// which case the caller degrades.
	return currentHolder, 0, nil
}

// holdsQuotaLease reports whether this node may serve as the project's authority
// RIGHT NOW: an explicit transfer naming it, or a lease it can still renew. Called
// on the serving path so a holder that lost its lease stops admitting.
func (s *Server) holdsQuotaLease(ctx context.Context, project string) (bool, string, error) {
	if cur, ok, err := corrosion.CurrentProjectAuthority(ctx, s.db, project); err != nil {
		return false, "", err
	} else if ok {
		if cur.Holder == s.hostName {
			// An explicit TRANSFER is a new authority term too, and it previously bypassed
			// reconciliation entirely. A different epoch means a different tenure.
			s.noteEpochTerm(project, cur.Epoch)
		} else {
			s.clearAuthorityTerm(project)
		}
		return cur.Holder == s.hostName, cur.Holder, nil
	}
	// QUORUM ON EVERY RENEWAL, not just on first acquisition. Gating only acquisition
	// let a partitioned-away holder keep extending its LOCAL lease row forever: the
	// majority never sees those renewals, observes the lease expire, elects a
	// successor — and now two nodes are both admitting. A minority-side holder must
	// stop being the authority, which means it must stop renewing.
	//
	// NOTE, because it bounds the guarantee: decideGateRefused only consults the
	// DECIDE gate once split_brain_gate_v1 is enforced cluster-wide. Until that token
	// latches there is no quorum gate here OR on acquisition, and the lease degrades
	// to "first writer wins, LWW resolves" — better than a derived holder, but not
	// partition-safe. Same dependency as every other quorum-gated decision in this
	// codebase.
	if reason, refused := s.decideGateRefused(ctx); refused {
		slog.Warn("project quota: refusing to renew the admission lease without quorum; "+
			"standing down as authority", "project", project, "reason", reason)
		return false, "", nil
	}
	// Renew-or-confirm. The conditional upsert only wins on an expired lease or a
	// renewal by us, so this cannot steal a live peer's lease.
	held, currentHolder, prevHolder, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, project, s.hostName)
	if err != nil {
		return false, "", err
	}
	if held {
		// prevHolder, not a name prefix, decides whether this is a TAKEOVER. If we
		// reconciled, lost authority to another node, and later reacquired, our name is
		// unchanged — so a name-based check read that as a renewal and skipped the drain,
		// missing every reservation the other node granted.
		s.noteAuthorityTerm(project, prevHolder != s.hostName)
	} else {
		// Not the authority: drop the term so a later reacquisition cannot inherit a
		// reconciliation that predates someone else's tenure.
		s.clearAuthorityTerm(project)
	}
	return held, currentHolder, nil
}

// noteAuthorityTerm records the current authority tenure. takeover=true mints a NEW term,
// which invalidates any previous reconciliation; a renewal keeps the existing one.
func (s *Server) noteAuthorityTerm(project string, takeover bool) {
	st := s.projectAdmitStateFor(project)
	st.mu.Lock()
	defer st.mu.Unlock()
	if !takeover && st.term != "" {
		return // our own unbroken renewal
	}
	id, err := newReservationID()
	if err != nil {
		id = time.Now().UTC().Format(time.RFC3339Nano)
	}
	st.term = "lease:" + id
	st.reconciledTerm = "" // a new tenure has reconciled nothing
}

// noteEpochTerm records a tenure established by an explicit authority transfer. The epoch
// identifies it, so re-reading the same epoch is a continuation.
func (s *Server) noteEpochTerm(project string, epoch int64) {
	st := s.projectAdmitStateFor(project)
	st.mu.Lock()
	defer st.mu.Unlock()
	term := fmt.Sprintf("epoch:%d", epoch)
	if st.term == term {
		return
	}
	st.term = term
	st.reconciledTerm = ""
}

// clearAuthorityTerm forgets the tenure when this node is not the authority, so a later
// reacquisition cannot inherit a reconciliation that predates another node's tenure.
func (s *Server) clearAuthorityTerm(project string) {
	st := s.projectAdmitStateFor(project)
	st.mu.Lock()
	st.term, st.reconciledTerm = "", ""
	st.mu.Unlock()
}

// ensureReconciledForTerm drains the voters' reservation state once per authority term,
// and reports whether this node may admit.
//
// Gated on the term rather than run at acquisition, because acquisition is not the only way
// to start serving: the lease is visible to concurrent requests immediately, a free lease
// can be taken inside an admission, and an explicit transfer never touched the acquisition
// path at all. Checking here covers every one of them.
//
// Caller must NOT hold st.mu.
func (s *Server) ensureReconciledForTerm(ctx context.Context, project string) error {
	st := s.projectAdmitStateFor(project)
	st.mu.Lock()
	term, done := st.term, st.reconciledTerm
	st.mu.Unlock()
	if term == "" {
		return errQuotaReconcileIncomplete{project: project, detail: "no authority term recorded"}
	}
	if done == term {
		return nil
	}
	complete, err := corrosion.ReconcileProjectQuotaReservations(ctx, s.db, s.reservationSource(), s.hostName, project)
	if err != nil {
		return errQuotaReconcileIncomplete{project: project, detail: err.Error()}
	}
	if !complete {
		return errQuotaReconcileIncomplete{project: project,
			detail: "could not read a quorum of voters' reservations"}
	}
	st.mu.Lock()
	moved := st.term != term
	if !moved {
		st.reconciledTerm = term
	}
	st.mu.Unlock()
	if moved {
		// Authority changed while we were draining over the network. Declining to mark the
		// old term was right but returning nil was not: the caller would go on to take the
		// mutex and write a reservation under a term nothing has reconciled. Refuse and let
		// it retry, which re-drains for the new term.
		return errQuotaReconcileIncomplete{project: project,
			detail: "authority term changed during reconciliation; retry"}
	}
	return nil
}

// projectAdmitState is now only a per-project MUTEX.
//
// The charges themselves are rows in the replicated quota_reservations table, because a
// charge must survive this node ceasing to be the project's authority. An in-memory
// ledger did not: a lease handoff left the successor with nothing, so it re-admitted the
// same quota while the previous holder's in-flight request still committed on top.
//
// The mutex still earns its place: it keeps two same-project admissions on this node from
// interleaving between the reservation guard's read and its write.
type projectAdmitState struct {
	mu sync.Mutex
	// term identifies the current AUTHORITY TERM: it changes whenever this node newly
	// acquires authority (a fresh lease, or a different transfer epoch) and stays put
	// across renewals. reconciledTerm records the term whose voter drain COMPLETED.
	//
	// Both are required because reconciliation is not something a single code path can
	// own. The lease row becomes visible the moment it is acquired, so a concurrent
	// request took the "live lease" branch and skipped the drain entirely; a free lease
	// could be acquired and admitted against in the same call; and an explicit authority
	// transfer never went near it. Gating on the term instead means EVERY admission path
	// — local, peer RPC, self-admit — refuses until the drain for its own term is done.
	term           string
	reconciledTerm string
}

func (s *Server) projectAdmitStateFor(project string) *projectAdmitState {
	s.projectAdmitMu.Lock()
	defer s.projectAdmitMu.Unlock()
	if s.projectAdmit == nil {
		s.projectAdmit = map[string]*projectAdmitState{}
	}
	st, ok := s.projectAdmit[project]
	if !ok {
		st = &projectAdmitState{}
		s.projectAdmit[project] = st
	}
	return st
}

func (s *Server) admitProjectQuotaLocal(ctx context.Context, project string, cpuDelta, memMiBDelta int, requester string) (Admission, error) {
	// Still renew here: the lease is what keeps admissions for this project arriving at
	// ONE node, which is what makes the local guard meaningful.
	held, currentHolder, err := s.holdsQuotaLease(ctx, project)
	if err != nil {
		return Admission{}, status.Errorf(codes.Internal, "renew project authority lease: %v", err)
	}
	if !held {
		return Admission{}, errQuotaAuthorityMoved{holder: currentHolder}
	}

	// Drain the voters' reservations for THIS authority term before admitting anything.
	// Fails closed: an authority that cannot see the outstanding charges cannot bound
	// what it would over-admit.
	if rerr := s.ensureReconciledForTerm(ctx, project); rerr != nil {
		return Admission{}, rerr
	}

	// Serialize same-project admissions within this process so two of them cannot
	// interleave between the guard's read and its write.
	st := s.projectAdmitStateFor(project)
	st.mu.Lock()
	defer st.mu.Unlock()

	// Re-validate UNDER THE MUTEX, immediately before writing. ensureReconciledForTerm ran
	// outside it and did network I/O, so the tenure can have turned over in between — and a
	// reservation written under an unreconciled term is one the authority cannot account
	// for.
	if st.term == "" || st.reconciledTerm != st.term {
		return Admission{}, errQuotaReconcileIncomplete{project: project,
			detail: "authority term is not reconciled at reservation time; retry"}
	}

	id, err := newReservationID()
	if err != nil {
		return Admission{}, status.Errorf(codes.Internal, "mint reservation id: %v", err)
	}
	cpu, mem := maxInt(cpuDelta, 0), maxInt(memMiBDelta, 0)
	applied, detail, err := corrosion.ReserveProjectQuota(ctx, s.db, id, project, s.hostName, cpu, mem)
	if err != nil {
		return Admission{}, status.Errorf(codes.Internal, "reserve project quota: %v", err)
	}
	if detail == "" && !applied {
		return Admission{}, nil // unbounded project: nothing to enforce or reserve
	}
	if !applied {
		return Admission{}, status.Errorf(codes.ResourceExhausted, "project %q %s", project, detail)
	}

	// The row exists locally, which is not the same as existing. Until it has been
	// REPLICATED it is invisible to a successor authority (which would admit the same
	// quota after our lease expires) and to the requesting node's own commit fence
	// (which would abort a perfectly valid request). Neither is acceptable, so the
	// admission is not complete until the barrier clears.
	if berr := corrosion.ReplicateReservationBarrier(ctx, s.db, s.reservationBarrier(), s.hostName, requester); berr != nil {
		// FAIL CLOSED, and undo: an un-replicated charge is indistinguishable from no
		// charge, so leaving it behind would refuse future requests for a reservation
		// nobody can see.
		if rerr := corrosion.ReleaseProjectQuotaReservationRow(ctx, s.db, id); rerr != nil {
			slog.Error("project quota: could not roll back an unreplicated reservation; it "+
				"expires on TTL", "project", project, "reservation", id, "error", rerr)
		}
		return Admission{}, errQuotaBarrierFailed{detail: berr.Error()}
	}
	return s.durableAdmission(project, id), nil
}

// durableAdmission wraps a durable reservation row.
//
// Release tombstones an UNCOMMITTED reservation and converts a committed one in place —
// the row keeps the charge until the workload is observed, so a successor holds it too.
//
// AllowCommit is a LOCAL read of the reservation row, and it fails CLOSED. That is the
// whole benefit of durability: the previous fence had to ask the authority over the
// network and fell open when it could not, which is precisely the case it existed for.
// Here there is no RPC, so a partition cannot defeat it, and nothing to fall open to.
func (s *Server) durableAdmission(project, id string) Admission {
	return Admission{
		reservationID: id,
		release: func(f CommitFact) {
			rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if !f.Committed {
				if err := corrosion.ReleaseProjectQuotaReservationRow(rctx, s.db, id); err != nil {
					slog.Warn("project quota: releasing a reservation failed; it expires on TTL",
						"project", project, "reservation", id, "error", err)
				}
				return
			}
			kind := f.Kind
			if kind == "" {
				kind = corrosion.WorkloadVM
			}
			if err := corrosion.CommitProjectQuotaReservation(rctx, s.db, id,
				f.Workload, kind, f.Host, f.CPU, f.MemMiB); err != nil {
				// The charge stays 'pending' and expires on TTL — conservative, and it
				// never releases quota the project actually owes.
				slog.Error("project quota: marking a reservation committed failed; it stays "+
					"charged until its TTL", "project", project, "reservation", id,
					"workload", f.Workload, "error", err)
			}
		},
		fence: func(fctx context.Context) error {
			live, err := corrosion.QuotaReservationLive(fctx, s.db, id)
			if err != nil {
				// FAIL CLOSED. A local read failing is not a licence to commit against
				// a charge we cannot confirm.
				return status.Errorf(codes.Unavailable,
					"cannot confirm the project-quota reservation for %q before committing: %v",
					project, err)
			}
			if !live {
				return status.Errorf(codes.Aborted,
					"the project-quota reservation for %q is gone (expired or swept) before this "+
						"request could commit; nothing was committed — retry", project)
			}
			return nil
		},
	}
}

// admitProjectQuotaRemote routes to the holder. On an epoch mismatch it retries
// ONCE against the holder the remote reports, so a stale local view self-corrects
// without looping.
func (s *Server) admitProjectQuotaRemote(ctx context.Context, holder string, epoch int64, project string, cpuDelta, memMiBDelta int) (Admission, error) {
	// Never send a request a peer would answer Unimplemented: a mixed-version or
	// flag-off holder must degrade, not error.
	if s.gate == nil || !s.gate.PeerSupportsFresh(ctx, holder, capabilities.ProjectQuotaAuthorityV1) {
		return Admission{}, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
			"holder does not advertise "+capabilities.ProjectQuotaAuthorityV1, nil)
	}

	for attempt := 0; attempt < 2; attempt++ {
		client, conn, err := s.peerClient(ctx, holder)
		if err != nil {
			return Admission{}, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
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
			return Admission{}, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
				"holder "+holder+" refused to answer", err)
		}
		// Redirect: the peer is not the authority and has told us who is. Follow THAT,
		// not our own view — re-resolving locally returns the same answer that sent us
		// to the wrong node, so the retry would just repeat itself and then fall open.
		if resp.Redirect {
			if attempt == 0 && resp.CurrentHolder != "" && resp.CurrentHolder != holder {
				holder, epoch = resp.CurrentHolder, resp.CurrentEpoch
				continue
			}
			return Admission{}, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
				"authority moved to "+resp.CurrentHolder+" and could not be followed", nil)
		}
		if resp.BarrierFailed {
			// FAIL CLOSED. The authority could not make the charge visible to the
			// cluster, so proceeding would consume quota nothing is accounting for.
			// Deliberately NOT routed through quotaFailOpen.
			return Admission{}, status.Errorf(codes.Unavailable,
				"project %q: the admission authority could not replicate the quota reservation, so "+
					"the request is refused rather than admitted against a charge peers cannot "+
					"see: %s", project, resp.Detail)
		}
		if !resp.Admitted {
			return Admission{}, status.Errorf(codes.ResourceExhausted,
				"project %q quota exceeded: %s", project, resp.Detail)
		}
		id := resp.ReservationId
		return Admission{
			// Tell the holder whether the workload was written, so its DURABLE row is
			// either tombstoned or converted to a committed charge it keeps until the
			// workload is observed.
			release: func(f CommitFact) { s.releaseRemoteQuota(holder, id, f) },
			// A LOCAL read of the holder's replicated reservation row, failing CLOSED.
			//
			// No RPC. The previous fence asked the authority over the network and fell
			// open when it could not answer — which is exactly when authority is being
			// lost, so it was defeated in the only case it mattered. And even a good
			// answer left a gap: the holder could lose its lease and discard the
			// reservation between responding and this write. A durable row has neither
			// problem: it is visible here through replication, a successor counts it,
			// and losing the lease does not erase it.
			fence: func(fctx context.Context) error {
				live, ferr := corrosion.QuotaReservationLive(fctx, s.db, id)
				if ferr != nil {
					return status.Errorf(codes.Unavailable,
						"cannot confirm the project-quota reservation for %q before committing: %v",
						project, ferr)
				}
				if !live {
					return status.Errorf(codes.Aborted,
						"the project-quota reservation for %q is gone before this request could "+
							"commit; nothing was committed — retry", project)
				}
				return nil
			},
		}, nil
	}
	return Admission{}, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
		"authority kept moving", nil)
}

func (s *Server) releaseRemoteQuota(holder, id string, f CommitFact) {
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
		Sender: s.hostName, ReservationId: id, Committed: f.Committed,
		Workload: f.Workload, Kind: f.Kind, WorkloadHost: f.Host,
		CommittedCpu: int32(f.CPU), CommittedMemMib: int32(f.MemMiB),
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

	// Re-validate the LEASE before serving. A holder that stopped renewing has
	// stopped being the authority, and admitting on a stale lease is exactly the
	// two-serializer bug. Deriving a candidate here is not good enough — that is what
	// let two differently-informed nodes both answer as authority.
	held, currentHolder, err := s.holdsQuotaLease(ctx, project)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read project authority: %v", err)
	}
	if !held {
		// A REDIRECT, deliberately on a SUCCESSFUL response. Returning it alongside an
		// error would make gRPC drop the message, so the caller could not learn the
		// real holder — it would re-resolve from the same view that misrouted it, be
		// sent back here, and fall open.
		return &pb.AdmitProjectQuotaResponse{
			Admitted: false, Redirect: true,
			Detail:        "not the admission authority for this project",
			CurrentHolder: currentHolder,
		}, nil
	}

	// req.Sender is the requesting node: the barrier must deliver the row to it, or its
	// local commit fence would race replication and abort a valid request.
	grant, err := s.admitProjectQuotaLocal(ctx, project, int(req.CpuDelta), int(req.MemMibDelta), req.Sender)
	if err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			return &pb.AdmitProjectQuotaResponse{Admitted: false, Detail: status.Convert(err).Message()}, nil
		}
		var recon errQuotaReconcileIncomplete
		if errors.As(err, &recon) {
			// Reuse barrier_failed: from the caller's side both mean "the authority could
			// not establish the state it needs", and both must fail closed rather than
			// land in the generic error path that degrades.
			return &pb.AdmitProjectQuotaResponse{
				Admitted: false, BarrierFailed: true,
				Detail: "authority has not reconciled voter reservations: " + recon.detail,
			}, nil
		}
		var barrier errQuotaBarrierFailed
		if errors.As(err, &barrier) {
			// A SUCCESSFUL response carrying barrier_failed. Returned as an error it
			// would land in the caller's generic RPC-error path, which degrades to an
			// unserialized local check — admitting against a charge no peer can see,
			// which is the opposite of what the barrier is for.
			return &pb.AdmitProjectQuotaResponse{
				Admitted: false, BarrierFailed: true, Detail: barrier.detail,
			}, nil
		}
		return nil, err
	}
	// The id names a REPLICATED row, so the caller's fence is a local read and a
	// successor authority already accounts for the charge.
	return &pb.AdmitProjectQuotaResponse{
		Admitted: true, ReservationId: grant.reservationID, CurrentHolder: s.hostName,
	}, nil
}

// ReleaseProjectQuotaReservation finalizes a routed reservation. Peer-only.
//
// committed=false tombstones the row. committed=true CONVERTS it: the row keeps the
// charge, now carrying the workload identity it is retired against, until some node
// observes that workload. A successor authority counts it either way, which is the
// whole point of the row being durable.
//
// Idempotent: an unknown id is a success, so a caller retrying a release never wedges.
func (s *Server) ReleaseProjectQuotaReservation(ctx context.Context, req *pb.ReleaseProjectQuotaReservationRequest) (*emptypb.Empty, error) {
	if err := requireReplicationPeer(ctx, req.Sender); err != nil {
		return nil, err
	}
	if req.ReservationId == "" {
		return &emptypb.Empty{}, nil
	}
	if !req.Committed {
		if err := corrosion.ReleaseProjectQuotaReservationRow(ctx, s.db, req.ReservationId); err != nil {
			return nil, status.Errorf(codes.Internal, "release reservation: %v", err)
		}
		return &emptypb.Empty{}, nil
	}
	kind := req.Kind
	if kind == "" {
		kind = corrosion.WorkloadVM
	}
	if err := corrosion.CommitProjectQuotaReservation(ctx, s.db, req.ReservationId,
		req.Workload, kind, req.WorkloadHost, int(req.CommittedCpu), int(req.CommittedMemMib)); err != nil {
		return nil, status.Errorf(codes.Internal, "commit reservation: %v", err)
	}
	return &emptypb.Empty{}, nil
}

func newReservationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// reservationBarrier returns the replication barrier, or a nil INTERFACE when no
// replicator is wired.
//
// Returning s.replicator directly would box a nil *Replicator into a non-nil interface,
// so the callee's `b == nil` check would miss and the first method call would panic. This
// is the standard Go trap and it cost a test panic to notice.
func (s *Server) reservationBarrier() corrosion.ReservationBarrier {
	if s.replicator == nil {
		return nil
	}
	return s.replicator
}

// reservationSource lets a taking-over authority pull peers' reservations. Returns nil
// when there is no replicator wired (single node / shared-store harness), which
// ReconcileProjectQuotaReservations reads as "no peers to reconcile against".
func (s *Server) reservationSource() corrosion.ReservationSource {
	if s.reservationSourceOverride != nil {
		return s.reservationSourceOverride // test seam
	}
	if s.replicator == nil {
		return nil
	}
	return peerReservationSource{s: s}
}

type peerReservationSource struct{ s *Server }

func (p peerReservationSource) FetchProjectQuotaReservations(ctx context.Context, peer, project string) ([]corrosion.QuotaReservation, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, conn, err := p.s.peerClient(cctx, peer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	resp, err := client.ListProjectQuotaReservations(cctx, &pb.ListProjectQuotaReservationsRequest{
		Sender: p.s.hostName, Project: project,
	})
	if err != nil {
		return nil, err
	}
	out := make([]corrosion.QuotaReservation, 0, len(resp.Reservations))
	for _, r := range resp.Reservations {
		out = append(out, corrosion.QuotaReservation{
			ID: r.Id, Project: r.Project, Holder: r.Holder,
			CPU: int(r.Cpu), MemMiB: int(r.MemMib), State: r.State,
			Workload: r.Workload, Kind: r.Kind, Host: r.Host,
			WantCPU: int(r.WantCpu), WantMem: int(r.WantMem),
		})
	}
	return out, nil
}

// ListProjectQuotaReservations serves this node's live reservations for a project to a
// peer taking over its admission authority. Peer-only.
func (s *Server) ListProjectQuotaReservations(ctx context.Context, req *pb.ListProjectQuotaReservationsRequest) (*pb.ListProjectQuotaReservationsResponse, error) {
	if err := requireReplicationPeer(ctx, req.Sender); err != nil {
		return nil, err
	}
	rows, err := corrosion.ListLiveProjectQuotaReservations(ctx, s.db, tenancy.NormalizeProject(req.Project))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list reservations: %v", err)
	}
	out := &pb.ListProjectQuotaReservationsResponse{}
	for _, r := range rows {
		out.Reservations = append(out.Reservations, &pb.ProjectQuotaReservation{
			Id: r.ID, Project: r.Project, Holder: r.Holder,
			Cpu: int32(r.CPU), MemMib: int32(r.MemMiB), State: r.State,
			Workload: r.Workload, Kind: r.Kind, Host: r.Host,
			WantCpu: int32(r.WantCPU), WantMem: int32(r.WantMem),
		})
	}
	return out, nil
}

// admitProjectQuotaRemoteForTest exposes the response-handling half of the routed path so
// a test can pin that a barrier refusal is NOT degraded into a fail-open admission.
func (s *Server) admitProjectQuotaRemoteForTest(ctx context.Context, resp *pb.AdmitProjectQuotaResponse, project string) (Admission, error) {
	if resp.BarrierFailed {
		return Admission{}, status.Errorf(codes.Unavailable,
			"project %q: the admission authority could not replicate the quota reservation, so the "+
				"request is refused rather than admitted against a charge peers cannot see: %s",
			project, resp.Detail)
	}
	if !resp.Admitted {
		return Admission{}, status.Errorf(codes.ResourceExhausted,
			"project %q quota exceeded: %s", project, resp.Detail)
	}
	return s.durableAdmission(project, resp.ReservationId), nil
}
