package corrosion

import (
	"context"
	"testing"
)

// TestClaimLBHolderIfUnowned covers the migration CAS: the first live holder
// claims an unowned (hosts=[]) explicit LB and later claims are no-ops, so
// exactly one durable holder is recorded.
func TestClaimLBHolderIfUnowned(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := UpsertLBConfig(ctx, c, LBConfigRecord{
		Name: "lb1", VIP: "10.0.0.1/24", Hosts: "[]", Enabled: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// First claim on an unowned LB wins.
	if ok, err := ClaimLBHolderIfUnowned(ctx, c, "lb1", `["hostA"]`); err != nil || !ok {
		t.Fatalf("first claim = %v,%v; want true", ok, err)
	}
	// Second claim (now owned) must NOT overwrite.
	if ok, err := ClaimLBHolderIfUnowned(ctx, c, "lb1", `["hostB"]`); err != nil || ok {
		t.Fatalf("second claim = %v,%v; want false (already owned)", ok, err)
	}

	cfgs, _ := ListLBConfigs(ctx, c)
	var got string
	for _, cf := range cfgs {
		if cf.Name == "lb1" {
			got = cf.Hosts
		}
	}
	if got != `["hostA"]` {
		t.Errorf("recorded holder = %q, want [\"hostA\"]", got)
	}
}

// TestClaimLBHolderIfUnowned_NullShape: a legacy CLI-created LB stores hosts as the
// string "null" (marshaled nil slice). The claim CAS must treat that as unowned.
func TestClaimLBHolderIfUnowned_NullShape(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := UpsertLBConfig(ctx, c, LBConfigRecord{
		Name: "lbnull", VIP: "10.0.0.2/24", Hosts: "null", Enabled: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if ok, err := ClaimLBHolderIfUnowned(ctx, c, "lbnull", `["hostA"]`); err != nil || !ok {
		t.Fatalf("claim on a 'null'-hosts LB = %v,%v; want true", ok, err)
	}
	cfgs, _ := ListLBConfigs(ctx, c)
	var got string
	for _, cf := range cfgs {
		if cf.Name == "lbnull" {
			got = cf.Hosts
		}
	}
	if got != `["hostA"]` {
		t.Errorf("recorded holder = %q, want [\"hostA\"]", got)
	}
}
