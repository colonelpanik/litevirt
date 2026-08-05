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

func (okBarrier) ReplicateNowTo(context.Context, string) error { return nil }

type failFor []string

func (f failFor) ReplicateNowTo(_ context.Context, peer string) error {
	for _, p := range f {
		if p == peer {
			return errors.New("unreachable")
		}
	}
	return nil
}
