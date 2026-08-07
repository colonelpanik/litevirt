package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A reservation must actually HOLD capacity.
//
// Capacity aggregation refuses to count a reservation it cannot attribute to the
// project's current authority epoch, so a mint that does not record which authority
// admitted it consumes nothing: the lease sits in the journal looking live while the
// headroom it should be protecting is handed to the next admission. That is invisible
// — no error, no log, just two workloads sharing one allocation.
//
// It is also easy to reintroduce, because the mint and the aggregation live in
// different packages and neither fails loudly when they disagree. Every live
// reservation writer is pinned here.

// authorityHost seeds a host plus an established project authority, the state in which
// the attribution rule is active.
func authorityHost(t *testing.T, s *Server, project string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: s.hostName, Address: "10.0.0.9", State: "active", CPUTotal: 64, MemTotal: 65536,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if applied, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, project, s.hostName); err != nil || !applied {
		t.Fatalf("ClaimInitialProjectAuthority: applied=%v err=%v", applied, err)
	}
}

// TestAdmitWithReservation_HoldsCapacityUnderAnEstablishedAuthority is the direct
// assertion: after admission, the reservation is visible to the aggregate that
// admission itself consults.
func TestAdmitWithReservation_HoldsCapacityUnderAnEstablishedAuthority(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	authorityHost(t, s, "_default")

	lease, err := s.admitWithReservation(ctx, "CreateVM", s.hostName, "_default", "vm:probe", 2, 2048, corrosion.QuotaAmount{VCPU: 2, MemMiB: 2048}, intentResourceGrow)
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	defer lease.release(ctx)

	cpu, mem, err := corrosion.HostReserved(ctx, s.db, s.hostName)
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if cpu != 2 || mem != 2048 {
		t.Fatalf("open lease holds %d vCPU/%d MiB, want 2/2048 — a reservation that cannot be "+
			"attributed to the current authority is not counted at all, so this lease is "+
			"protecting nothing and the next admission gets the same headroom", cpu, mem)
	}
}

// TestAdmitHostWithReservation_HoldsHostCapacityWithoutChargingQuota pins both halves
// of the host-only lease: it must be attributable to its project (or it counts for
// nothing) while charging that project's quota nothing (or a plain stop/start of a
// workload over half its quota is refused).
func TestAdmitHostWithReservation_HoldsHostCapacityWithoutChargingQuota(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	authorityHost(t, s, "_default")

	lease, err := s.admitHostWithReservation(ctx, "StartVM", s.hostName, "_default", "vm:facts-test", 2, 2048, intentResourceGrow)
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	defer lease.release(ctx)

	cpu, mem, err := corrosion.HostReserved(ctx, s.db, s.hostName)
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if cpu != 2 || mem != 2048 {
		t.Errorf("host-only lease holds %d vCPU/%d MiB of HOST capacity, want 2/2048", cpu, mem)
	}

	qCPU, qMem, err := corrosion.ProjectReserved(ctx, s.db, "_default")
	if err != nil {
		t.Fatalf("ProjectReserved: %v", err)
	}
	if qCPU != 0 || qMem != 0 {
		t.Errorf("host-only lease charged %d vCPU/%d MiB against project quota, want 0/0 — "+
			"a start grows no project allocation", qCPU, qMem)
	}
}

// TestReserveProjectCapacity_HoldsQuotaUnderAnEstablishedAuthority is the delegated
// mint, which runs on the holder and must hold quota there.
func TestReserveProjectCapacity_HoldsQuotaUnderAnEstablishedAuthority(t *testing.T) {
	s := authorityServer(t, "tenant")
	ctx := mtlsCtx("peer-host")
	if applied, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, "tenant", s.hostName); err != nil || !applied {
		t.Fatalf("ClaimInitialProjectAuthority: applied=%v err=%v", applied, err)
	}

	resp, err := s.ReserveProjectCapacity(ctx, reserveReq("tenant", 1))
	if err != nil {
		t.Fatalf("ReserveProjectCapacity: %v", err)
	}
	defer s.releaseLocalLease(ctx, resp.LeaseId)

	cpu, mem, err := corrosion.ProjectReserved(ctx, s.db, "tenant")
	if err != nil {
		t.Fatalf("ProjectReserved: %v", err)
	}
	if cpu != 1 || mem != 1024 {
		t.Fatalf("delegated lease holds %d vCPU/%d MiB of quota, want 1/1024 — an unattributable "+
			"reservation is skipped entirely, which is the single decider granting the same quota twice",
			cpu, mem)
	}
}
