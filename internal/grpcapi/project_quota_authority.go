package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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
	s.projectAdmitMu.Lock()
	projects := make([]string, 0, len(s.projectAdmit))
	for p, st := range s.projectAdmit {
		st.mu.Lock()
		charged := st.pendingCPU > 0 || st.pendingMem > 0 || len(st.unobserved) > 0
		st.mu.Unlock()
		if charged {
			projects = append(projects, p)
		}
	}
	s.projectAdmitMu.Unlock()

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
		slog.Error("project quota: LOST the admission lease while charges were outstanding; "+
			"dropping them — the new authority accounts for these workloads once they replicate",
			"project", project, "new_holder", currentHolder)
		s.notify(ctx, notify.Notification{
			Kind: "quota.authority_lost", Severity: notify.SevWarn, Subject: project,
			Detail: "lost the project-quota admission lease to " + currentHolder +
				" while admissions were in flight",
		})
		st := s.projectAdmitStateFor(project)
		st.mu.Lock()
		st.pendingCPU, st.pendingMem = 0, 0
		st.unobserved = nil
		st.mu.Unlock()
	}
}

// workloadKey is the ledger key: identity is (kind, host, name), never name alone.
func workloadKey(f CommitFact) string {
	kind := f.Kind
	if kind == "" {
		kind = corrosion.WorkloadVM
	}
	return kind + "\x00" + f.Host + "\x00" + f.Workload
}

func workloadNameFromKey(key string) string {
	parts := strings.Split(key, "\x00")
	return parts[len(parts)-1]
}

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
func (s *Server) admitProjectQuota(ctx context.Context, project string, cpuDelta, memMiBDelta int) (func(CommitFact), error) {
	if cpuDelta <= 0 && memMiBDelta <= 0 {
		return noopReleaseCommitted, nil
	}
	project = tenancy.NormalizeProject(project)
	if !s.projectQuotaAuthorityActive(ctx) {
		return noopReleaseCommitted, s.checkProjectQuota(ctx, project, cpuDelta, memMiBDelta)
	}

	holder, epoch, err := s.projectQuotaHolder(ctx, project)
	if err != nil || holder == "" {
		// No authority resolvable (no eligible hosts, or a state read failed).
		// Degrade to the local check rather than refusing a create.
		return noopReleaseCommitted, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta, "authority unresolved", err)
	}
	if holder == s.hostName {
		release, err := s.admitProjectQuotaLocal(ctx, project, cpuDelta, memMiBDelta)
		var moved errQuotaAuthorityMoved
		if errors.As(err, &moved) {
			if moved.holder != "" && moved.holder != s.hostName {
				return s.admitProjectQuotaRemote(ctx, moved.holder, 0, project, cpuDelta, memMiBDelta)
			}
			return noopReleaseCommitted, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
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
	held, currentHolder, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, project, s.hostName)
	if err != nil {
		return "", 0, err
	}
	if held {
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
		return cur.Holder == s.hostName, cur.Holder, nil
	}
	// Renew-or-confirm. The conditional upsert only wins on an expired lease or a
	// renewal by us, so this cannot steal a live peer's lease.
	held, currentHolder, err := corrosion.AcquireProjectQuotaLease(ctx, s.db, project, s.hostName)
	if err != nil {
		return false, "", err
	}
	return held, currentHolder, nil
}

// projectAdmitState is the authority holder's per-project ledger. Two distinct
// charges live here, and they cover two different windows:
//
//   - pending*: admitted, caller still working. Dropped when the caller releases.
//   - unobserved*: the caller COMMITTED, but this node has not yet SEEN the
//     workload. Dropped only once the commit shows up in local usage.
//
// The second one is the subtle half. A routed admission is committed by the target
// HOST, not by the authority — so between that commit and CRDT replication
// delivering the row here, the holder sees neither the reservation (the caller
// released it) nor the committed usage. Another concurrent request would then be
// handed the very same quota. Converting the reservation into an unobserved charge,
// instead of just dropping it, keeps the quota spoken for across exactly that gap.
//
// The charge is keyed by WORKLOAD IDENTITY. An aggregate "usage grew since a
// baseline" heuristic looked simpler but is unsound: any unrelated increase — a
// workload created before the charge that replicates late, or one admitted through
// the fail-open path — would satisfy it and retire someone else's charge early, and
// the next request would over-admit. A charge may only be retired by observing the
// workload it was taken for.
//
// A commit that never becomes visible (the create failed after the durable write, or
// the workload was deleted immediately) would otherwise hold quota forever, so a
// short grace TTL is the backstop. It errs toward over-charging, which refuses a
// request that might have fit — never the reverse.
type projectAdmitState struct {
	mu         sync.Mutex
	pendingCPU int
	pendingMem int

	// unobserved is keyed by WORKLOAD name: charges the caller says it committed but
	// this node cannot see yet. Keyed by identity, not aggregated, so one workload's
	// arrival can only ever retire ITS OWN charge.
	unobserved map[string]*unobservedCommit
}

// unobservedCommit is one committed-but-unseen workload.
//
// wantCPU/wantMem are what the workload should contribute to project usage once its
// row lands here. The charge retires when this node's own replica says the workload
// contributes at least that — which is a direct observation of THIS commit, not an
// inference from aggregate movement.
//
// chargeCPU/chargeMem are what to hold meanwhile: the delta that was admitted, not
// the absolute size, so a resize holds only its growth.
type unobservedCommit struct {
	kind, host           string
	wantCPU, wantMem     int
	chargeCPU, chargeMem int
	at                   time.Time
}

// unobservedGraceTTL bounds how long a committed-but-unseen charge is held. It only
// needs to exceed normal replication delivery; the self-healing baseline comparison
// does the real work.
const unobservedGraceTTL = 2 * time.Minute

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

// releaseFor returns the idempotent release for one admission. committed=true
// converts the reservation into an unobserved-commit charge (see the type doc);
// committed=false just gives the quota back.
//
// usedCPU/usedMem are the usage this node observed at admit time, and become the
// baseline the unobserved charge is measured against.
func (st *projectAdmitState) releaseFor(cpu, mem int) func(CommitFact) {
	var once sync.Once
	return func(f CommitFact) {
		once.Do(func() {
			st.mu.Lock()
			defer st.mu.Unlock()
			st.pendingCPU = maxInt(st.pendingCPU-cpu, 0)
			st.pendingMem = maxInt(st.pendingMem-mem, 0)
			if !f.Committed || f.Workload == "" {
				return
			}
			if st.unobserved == nil {
				st.unobserved = map[string]*unobservedCommit{}
			}
			key := workloadKey(f)
			e, ok := st.unobserved[key]
			if !ok {
				e = &unobservedCommit{kind: f.Kind, host: f.Host}
				st.unobserved[key] = e
			}
			// SUM the charges; do not take the larger. Two consecutive +2 vCPU
			// resizes that both commit before either is visible here owe FOUR unseen
			// vCPU, not two — max() silently released half of it.
			e.chargeCPU += cpu
			e.chargeMem += mem
			// want is the LATEST absolute target, which is monotone across resizes.
			// Observing the workload at or above it means every summed delta has
			// landed, so the whole entry retires at once.
			e.wantCPU = maxInt(e.wantCPU, f.CPU)
			e.wantMem = maxInt(e.wantMem, f.MemMiB)
			e.at = time.Now()
		})
	}
}

// unobservedChargeLocked sums the charges whose workloads this node still cannot
// see, retiring each one that HAS arrived. Caller holds st.mu.
//
// observe reports what the local replica says a named workload contributes to the
// project; found=false means the row has not arrived (or was deleted).
func (st *projectAdmitState) unobservedChargeLocked(
	project string,
	observe func(kind, host, workload string) (cpu, mem int, found bool, err error),
) (int, int, error) {
	if len(st.unobserved) == 0 {
		return 0, 0, nil
	}
	var totalCPU, totalMem int
	for key, e := range st.unobserved {
		name := workloadNameFromKey(key)
		cpu, mem, found, err := observe(e.kind, e.host, name)
		if err != nil {
			return 0, 0, err
		}
		// Retire on DIRECT observation of this workload, at or above the size it
		// was admitted for. A resize is covered by the >= comparison.
		if found && cpu >= e.wantCPU && mem >= e.wantMem {
			delete(st.unobserved, key)
			continue
		}
		if time.Since(e.at) > unobservedGraceTTL {
			// Backstop: the commit never became visible (it failed after the
			// durable write, or the workload was deleted straight away).
			slog.Warn("project quota: a committed workload never became visible locally; dropping its charge",
				"project", project, "workload", name, "kind", e.kind, "host", e.host,
				"cpu", e.chargeCPU, "mem_mib", e.chargeMem, "held_for", time.Since(e.at))
			delete(st.unobserved, key)
			continue
		}
		totalCPU += e.chargeCPU
		totalMem += e.chargeMem
	}
	return totalCPU, totalMem, nil
}

// admitProjectQuotaLocal is the holder-side admit. It charges, in one pass under the
// project lock: committed usage, replicated operation reservations, this node's
// in-flight admissions, AND the committed-but-not-yet-visible total (see
// projectAdmitState) — then reserves.
//
// The observed usage is carried into the release func so a commit can anchor its
// unobserved charge to the usage that was visible when it was admitted.
func (s *Server) admitProjectQuotaLocal(ctx context.Context, project string, cpuDelta, memMiBDelta int) (func(CommitFact), error) {
	// RENEW the lease, do not merely read it. Admitting extends the life of a charge,
	// so it must also extend the authority that owns that charge — otherwise the lease
	// lapses mid-create and another node acquires it with an empty ledger.
	held, currentHolder, err := s.holdsQuotaLease(ctx, project)
	if err != nil {
		return noopReleaseCommitted, status.Errorf(codes.Internal, "renew project authority lease: %v", err)
	}
	if !held {
		// Lost it between resolving and serving. Do not admit locally against a ledger
		// we no longer own; let the caller route or degrade.
		return noopReleaseCommitted, errQuotaAuthorityMoved{holder: currentHolder}
	}

	st := s.projectAdmitStateFor(project)
	st.mu.Lock()
	defer st.mu.Unlock()

	bounded, err := s.projectIsBounded(ctx, project)
	if err != nil {
		return noopReleaseCommitted, err
	}
	if !bounded {
		return noopReleaseCommitted, nil // unbounded project: nothing to serialize
	}
	unobsCPU, unobsMem, err := st.unobservedChargeLocked(project, func(kind, host, w string) (int, int, bool, error) {
		return corrosion.WorkloadQuotaContribution(ctx, s.db, project, kind, host, w)
	})
	if err != nil {
		return noopReleaseCommitted, status.Errorf(codes.Internal, "observe committed workloads: %v", err)
	}
	if err := s.checkProjectQuotaWithPending(ctx, project, cpuDelta, memMiBDelta,
		st.pendingCPU+unobsCPU, st.pendingMem+unobsMem); err != nil {
		return noopReleaseCommitted, err
	}
	cpu, mem := maxInt(cpuDelta, 0), maxInt(memMiBDelta, 0)
	st.pendingCPU += cpu
	st.pendingMem += mem
	return st.releaseFor(cpu, mem), nil
}

// admitProjectQuotaRemote routes to the holder. On an epoch mismatch it retries
// ONCE against the holder the remote reports, so a stale local view self-corrects
// without looping.
func (s *Server) admitProjectQuotaRemote(ctx context.Context, holder string, epoch int64, project string, cpuDelta, memMiBDelta int) (func(CommitFact), error) {
	// Never send a request a peer would answer Unimplemented: a mixed-version or
	// flag-off holder must degrade, not error.
	if s.gate == nil || !s.gate.PeerSupportsFresh(ctx, holder, capabilities.ProjectQuotaAuthorityV1) {
		return noopReleaseCommitted, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
			"holder does not advertise "+capabilities.ProjectQuotaAuthorityV1, nil)
	}

	for attempt := 0; attempt < 2; attempt++ {
		client, conn, err := s.peerClient(ctx, holder)
		if err != nil {
			return noopReleaseCommitted, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
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
			return noopReleaseCommitted, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
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
			return noopReleaseCommitted, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
				"authority moved to "+resp.CurrentHolder+" and could not be followed", nil)
		}
		if !resp.Admitted {
			return noopReleaseCommitted, status.Errorf(codes.ResourceExhausted,
				"project %q quota exceeded: %s", project, resp.Detail)
		}
		id := resp.ReservationId
		// The committed flag has to reach the holder: on a commit it must KEEP the
		// charge until it can see the workload, since the target host wrote the row
		// and replication has not delivered it here yet.
		return func(f CommitFact) { s.releaseRemoteQuota(holder, id, f) }, nil
	}
	return noopReleaseCommitted, s.quotaFailOpen(ctx, project, cpuDelta, memMiBDelta,
		"authority epoch kept moving", nil)
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

	release, err := s.admitProjectQuotaLocal(ctx, project, int(req.CpuDelta), int(req.MemMibDelta))
	if err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			return &pb.AdmitProjectQuotaResponse{Admitted: false, Detail: status.Convert(err).Message()}, nil
		}
		return nil, err
	}

	id, err := newReservationID()
	if err != nil {
		release(CommitFact{}) // never handed out, so nothing committed against it
		return nil, status.Errorf(codes.Internal, "mint reservation id: %v", err)
	}
	s.putQuotaLease(id, release, project, int(req.CpuDelta), int(req.MemMibDelta))
	return &pb.AdmitProjectQuotaResponse{
		Admitted: true, ReservationId: id, CurrentHolder: s.hostName,
	}, nil
}

// ReleaseProjectQuotaReservation drops a routed reservation. Peer-only. Idempotent:
// an unknown id (already released, or expired) is a success, so a caller retrying a
// release never gets an error it cannot act on.
func (s *Server) ReleaseProjectQuotaReservation(ctx context.Context, req *pb.ReleaseProjectQuotaReservationRequest) (*emptypb.Empty, error) {
	if err := requireReplicationPeer(ctx, req.Sender); err != nil {
		return nil, err
	}
	s.dropQuotaLease(req.ReservationId, CommitFact{
		Committed: req.Committed, Workload: req.Workload,
		Kind: req.Kind, Host: req.WorkloadHost,
		CPU: int(req.CommittedCpu), MemMiB: int(req.CommittedMemMib),
	})
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
	release func(CommitFact)
}

func (s *Server) putQuotaLease(id string, release func(CommitFact), project string, cpu, mem int) {
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

func (s *Server) dropQuotaLease(id string, f CommitFact) {
	s.quotaLeaseMu.Lock()
	e, ok := s.quotaLeases[id]
	if ok {
		delete(s.quotaLeases, id)
	}
	s.reapQuotaLeasesLocked()
	s.quotaLeaseMu.Unlock()
	if ok {
		e.release(f)
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
			// Unconfirmed: the caller never told us it committed, so give the
			// quota back rather than holding it as an unobserved commit.
			e.release(CommitFact{})
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
