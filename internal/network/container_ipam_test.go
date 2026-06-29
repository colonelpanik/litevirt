package network

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ReserveContainerIP must transfer an IP for the SAME container re-homing across
// hosts, but never steal one held by a DIFFERENT workload.
func TestReserveContainerIP_TransfersButNeverSteals(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Container "a" on h1 claims a free IP.
	if ok, err := ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "mac-a", "h1", "a"); err != nil || !ok {
		t.Fatalf("free IP should reserve: ok=%v err=%v", ok, err)
	}
	// Same container re-homing to h2 → transfer (owner_host moves to h2).
	if ok, err := ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "mac-a", "h2", "a"); err != nil || !ok {
		t.Fatalf("same container should transfer its IP: ok=%v err=%v", ok, err)
	}
	if al, _ := GetAllocationFor(ctx, db, "net1", "ct", "h2", "a"); al == nil || al.IP != "10.0.0.5" {
		t.Fatalf("transfer should move the lease to h2, got %+v", al)
	}
	// A DIFFERENT container must NOT steal it.
	if ok, err := ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "mac-b", "h3", "b"); err != nil || ok {
		t.Fatalf("must not steal an IP held by another container: ok=%v err=%v", ok, err)
	}
	if al, _ := GetAllocationFor(ctx, db, "net1", "ct", "h2", "a"); al == nil {
		t.Fatal("original owner (a) must remain intact after a steal attempt")
	}
	if al, _ := GetAllocationFor(ctx, db, "net1", "ct", "h3", "b"); al != nil {
		t.Fatal("the other container (b) must not have acquired the IP")
	}
}
