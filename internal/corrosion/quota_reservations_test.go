package corrosion

import (
	"context"
	"errors"
	"testing"
)

// TestReserveProjectQuota_KindScopedRetirement is the regression test for a same-named
// workload of ANOTHER KIND retiring a reservation.
//
// The guard's retirement rule had an unqualified `OR EXISTS (containers …)`, so a VM
// named "web" satisfied a still-owed CONTAINER reservation for "web" — releasing its
// quota before the container row replicated, and letting the next request over-admit.
func TestReserveProjectQuota_KindScopedRetirement(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)

	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/acme", VCPULimit: 8}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}

	// A CONTAINER reservation for "web" on host h1, committed but not yet visible.
	if applied, _, err := ReserveProjectQuota(ctx, c, "res-ct", "/acme", "node-a", 4, 0); err != nil || !applied {
		t.Fatalf("reserve: applied=%v err=%v", applied, err)
	}
	if err := CommitProjectQuotaReservation(ctx, c, "res-ct", "web", WorkloadContainer, "h1", 4, 0); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// A VM that merely SHARES the name appears. It must not satisfy the container's
	// charge — different kind, different workload.
	if err := InsertVM(ctx, c, VMRecord{
		Name: "web", HostName: "h1", State: "running", Project: "/acme",
		CPUActual: 4, Spec: `{"name":"web","cpu":4,"memory_mib":0}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// 8 vCPU quota: the VM now uses 4 and the container still owes 4. A further 1 must
	// be refused. If the VM retired the container's charge, this would be admitted.
	applied, detail, err := ReserveProjectQuota(ctx, c, "res-next", "/acme", "node-a", 1, 0)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if applied {
		t.Errorf("admitted 1 more vCPU with 4 used by a VM and 4 still owed by a same-named "+
			"CONTAINER reservation (8 vCPU quota) — a VM must not retire a container's charge "+
			"(detail=%q)", detail)
	}

	// And the read path must agree with the guard.
	cpu, _, err := SumLiveQuotaReservations(ctx, c, "/acme")
	if err != nil {
		t.Fatalf("SumLiveQuotaReservations: %v", err)
	}
	if cpu != 4 {
		t.Errorf("live reservation charge = %d vCPU, want 4 — the container's charge is still owed", cpu)
	}
}

// TestReplicateReservationBarrier_RequiresQuorumAndRequester pins both obligations.
//
// A reservation that exists only where it was written is invisible to a successor
// authority (which would admit the same quota once the lease expires) and to the
// requesting node's own commit fence (which would race replication and abort a valid
// request). Admission must not succeed until both are satisfied.
func TestReplicateReservationBarrier_RequiresQuorumAndRequester(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	for _, h := range []string{"node-a", "node-b", "node-c"} {
		if err := InsertHost(ctx, c, HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443,
			State: "active", Role: "worker", CertSerial: "s-" + h,
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}

	// Everything reachable: quorum met, requester served.
	if err := ReplicateReservationBarrier(ctx, c, okBarrier{}, "node-a", "node-b"); err != nil {
		t.Errorf("barrier with all peers reachable: %v", err)
	}

	// The REQUESTER is unreachable. Quorum is still met (self + node-c of three), but the
	// requester's fence would abort a valid request, so this must fail.
	if err := ReplicateReservationBarrier(ctx, c, failFor{"node-b"}, "node-a", "node-b"); err == nil {
		t.Error("barrier passed with the REQUESTING node unreachable — its commit fence would " +
			"race replication and abort a valid request")
	}

	// Quorum unmet (only self of three), requester is self.
	if err := ReplicateReservationBarrier(ctx, c, failFor{"node-b", "node-c"}, "node-a", "node-a"); err == nil {
		t.Error("barrier passed without QUORUM — a successor could win the lease without ever " +
			"having seen this reservation and admit the same quota")
	}

	// No replicator wired (single node / shared-store harness): nothing to be invisible to.
	if err := ReplicateReservationBarrier(ctx, c, nil, "node-a", "node-a"); err != nil {
		t.Errorf("barrier with no replicator: %v", err)
	}
}

type okBarrier struct{}

func (okBarrier) ReplicateNowTo(context.Context, string, int64) error { return nil }
func (okBarrier) LatestMutationSeq(context.Context) (int64, error)    { return 7, nil }

// failFor rejects delivery to the named peers, standing in for an unreachable node.
type failFor []string

func (f failFor) ReplicateNowTo(_ context.Context, peer string, _ int64) error {
	for _, p := range f {
		if p == peer {
			return errors.New("unreachable")
		}
	}
	return nil
}
func (failFor) LatestMutationSeq(context.Context) (int64, error) { return 7, nil }

// TestReplicateReservationBarrier_PassesARealSequence: the barrier must obtain the local
// mutation sequence and pass it to every delivery, because that sequence is the ONLY thing
// that distinguishes "the peer accepted a batch" from "the peer has my reservation".
// replicateOnce ships a bounded batch, so a peer with a backlog can ack while the entry
// sits in a later one.
func TestReplicateReservationBarrier_PassesARealSequence(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	for _, h := range []string{"node-a", "node-b"} {
		if err := InsertHost(ctx, c, HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443,
			State: "active", Role: "worker", CertSerial: "s-" + h,
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	rec := &recordingBarrier{seq: 42}
	if err := ReplicateReservationBarrier(ctx, c, rec, "node-a", "node-a"); err != nil {
		t.Fatalf("barrier: %v", err)
	}
	if !rec.askedSeq {
		t.Error("barrier never asked for the local mutation sequence, so it cannot know what " +
			"delivery it is waiting for")
	}
	for peer, got := range rec.sawSeq {
		if got != 42 {
			t.Errorf("delivery to %s carried throughSeq=%d, want 42 — a bounded batch ack is not "+
				"proof the reservation arrived", peer, got)
		}
	}
	if len(rec.sawSeq) == 0 {
		t.Error("barrier delivered to no peers")
	}
}

// TestHostVotes_MatchesTheQuorumDenominator: the barrier's population and the quorum that
// elects an authority must be the SAME set. When the barrier counted only "active" hosts,
// "a quorum holds the row" implied nothing about who could become the authority.
func TestHostVotes_MatchesTheQuorumDenominator(t *testing.T) {
	for _, c := range []struct {
		state string
		votes bool
	}{
		{"active", true},
		{"draining", true},  // votes but hosts nothing — still in the denominator
		{"upgrading", true}, // ditto
		{"offline", false},
		{"maintenance", false},
		{"fenced", false},
	} {
		if got := HostVotes(HostRecord{State: c.state}); got != c.votes {
			t.Errorf("HostVotes(state=%q) = %v, want %v — this must mirror "+
				"health.votingEligible exactly or the barrier and the quorum disagree",
				c.state, got, c.votes)
		}
	}
	// A witness votes: it can be part of the quorum that elects an authority.
	if !HostVotes(HostRecord{State: "active", Role: "witness"}) {
		t.Error("a witness must count as a voter")
	}
}

type recordingBarrier struct {
	seq      int64
	askedSeq bool
	sawSeq   map[string]int64
}

func (r *recordingBarrier) LatestMutationSeq(context.Context) (int64, error) {
	r.askedSeq = true
	return r.seq, nil
}

func (r *recordingBarrier) ReplicateNowTo(_ context.Context, peer string, throughSeq int64) error {
	if r.sawSeq == nil {
		r.sawSeq = map[string]int64{}
	}
	r.sawSeq[peer] = throughSeq
	return nil
}

// TestReconcileProjectQuotaReservations_ReadQuorumNotUnanimity is the regression test for
// takeover demanding every voter.
//
// Every reservation was written to a majority, so reading a majority — counting the
// successor's own replica — necessarily intersects the write set of every reservation that
// exists. Requiring ALL voters made takeover impossible in exactly the configuration meant
// to tolerate a failure: three nodes with one down still hold quorum and can win the lease,
// but could never finish the drain.
func TestReconcileProjectQuotaReservations_ReadQuorumNotUnanimity(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	for _, h := range []string{"node-a", "node-b", "node-c"} {
		if err := InsertHost(ctx, c, HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443,
			State: "active", Role: "worker", CertSerial: "s-" + h,
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}

	// node-c is down. self (node-a) + node-b = 2 of 3 = a read quorum.
	complete, err := ReconcileProjectQuotaReservations(ctx, c,
		srcFailing{peers: []string{"node-c"}}, "node-a", "/acme")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !complete {
		t.Error("takeover refused with a READ QUORUM available (self + 1 of 3) — every " +
			"reservation was written to a majority, so a majority read intersects it; demanding " +
			"unanimity makes takeover impossible with one node down")
	}

	// Both peers down: self alone is a minority of three, so the view cannot be trusted.
	complete, err = ReconcileProjectQuotaReservations(ctx, c,
		srcFailing{peers: []string{"node-b", "node-c"}}, "node-a", "/acme")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if complete {
		t.Error("takeover accepted a MINORITY read — a reservation may exist that this node " +
			"cannot see, so it cannot bound what it would over-admit")
	}
}

// TestReconcileProjectQuotaReservations_AdoptsPeerRows: the drain must actually copy the
// rows in, or the successor still admits blind.
func TestReconcileProjectQuotaReservations_AdoptsPeerRows(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	for _, h := range []string{"node-a", "node-b"} {
		if err := InsertHost(ctx, c, HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", GRPCPort: 7443,
			State: "active", Role: "worker", CertSerial: "s-" + h,
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := InsertProject(ctx, c, ProjectRecord{Name: "/acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := UpsertProjectQuota(ctx, c, ProjectQuotaRecord{ProjectName: "/acme", VCPULimit: 8}); err != nil {
		t.Fatalf("quota: %v", err)
	}

	src := srcRows{rows: []QuotaReservation{{
		ID: "peer-res", Project: "/acme", Holder: "node-b", CPU: 6,
		State: QuotaReservationPending,
	}}}
	if complete, err := ReconcileProjectQuotaReservations(ctx, c, src, "node-a", "/acme"); err != nil || !complete {
		t.Fatalf("reconcile: complete=%v err=%v", complete, err)
	}

	cpu, _, err := SumLiveQuotaReservations(ctx, c, "/acme")
	if err != nil {
		t.Fatalf("sum: %v", err)
	}
	if cpu != 6 {
		t.Errorf("adopted charge = %d vCPU, want 6 — a successor that does not copy the rows in "+
			"still admits blind", cpu)
	}
}

type srcFailing struct{ peers []string }

func (s srcFailing) FetchProjectQuotaReservations(_ context.Context, peer, _ string) ([]QuotaReservation, error) {
	for _, p := range s.peers {
		if p == peer {
			return nil, errors.New("unreachable")
		}
	}
	return nil, nil
}

type srcRows struct{ rows []QuotaReservation }

func (s srcRows) FetchProjectQuotaReservations(context.Context, string, string) ([]QuotaReservation, error) {
	return s.rows, nil
}
