package network

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ReserveContainerIP reserves a free IP and is idempotent for the SAME owner,
// but never steals a live lease — including a same-named CT on ANOTHER host
// (v36: CT names are per-host, so that may be a different workload), and a
// released (tombstoned) IP is reusable.
func TestReserveContainerIP_NeverStealsAcrossHosts(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// "a" on h1 claims a free IP; re-reserving on h1 is idempotent.
	if ok, err := ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "mac-a", "h1", "a"); err != nil || !ok {
		t.Fatalf("free IP should reserve: ok=%v err=%v", ok, err)
	}
	if ok, err := ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "mac-a", "h1", "a"); err != nil || !ok {
		t.Fatalf("same owner re-reserve should be idempotent: ok=%v err=%v", ok, err)
	}
	// A same-NAMED container on ANOTHER host must NOT steal it (can't prove it's ours).
	if ok, err := ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "mac-a", "h2", "a"); err != nil || ok {
		t.Fatalf("must not steal a same-named CT's IP across hosts: ok=%v err=%v", ok, err)
	}
	// A different container must NOT steal it either.
	if ok, err := ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "mac-b", "h3", "b"); err != nil || ok {
		t.Fatalf("must not steal an IP held by another container: ok=%v err=%v", ok, err)
	}
	if al, _ := GetAllocationFor(ctx, db, "net1", "ct", "h1", "a"); al == nil {
		t.Fatal("original owner (a@h1) must remain intact after steal attempts")
	}
	// A RELEASED IP becomes reusable (tombstone resurrected).
	if err := ReleaseIPFor(ctx, db, "net1", "ct", "h1", "a"); err != nil {
		t.Fatalf("ReleaseIPFor: %v", err)
	}
	if ok, err := ReserveContainerIP(ctx, db, "net1", "10.0.0.5", "mac-c", "h2", "c"); err != nil || !ok {
		t.Fatalf("a released IP must be reusable: ok=%v err=%v", ok, err)
	}
}
