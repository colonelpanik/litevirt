package network

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestNextFreeIP_Basic(t *testing.T) {
	ip, err := nextFreeIP("10.0.0.0/24", nil)
	if err != nil {
		t.Fatalf("nextFreeIP error: %v", err)
	}
	if ip != "10.0.0.2" {
		t.Errorf("expected 10.0.0.2, got %s", ip)
	}
}

func TestNextFreeIP_SkipsUsed(t *testing.T) {
	ip, err := nextFreeIP("10.0.0.0/24", []string{"10.0.0.2", "10.0.0.3"})
	if err != nil {
		t.Fatalf("nextFreeIP error: %v", err)
	}
	if ip != "10.0.0.4" {
		t.Errorf("expected 10.0.0.4, got %s", ip)
	}
}

func TestNextFreeIP_Full(t *testing.T) {
	// /29:.0=network,.1=anycast-gw (skipped),.2-.6 allocatable,.7=broadcast
	used := []string{"10.0.0.2"}
	ip, err := nextFreeIP("10.0.0.0/29", used)
	if err != nil {
		t.Fatalf("nextFreeIP error: %v", err)
	}
	if ip != "10.0.0.3" {
		t.Errorf("expected 10.0.0.3, got %s", ip)
	}

	// Exhaust a /30:.0=network,.1=anycast-gw,.2=only host,.3=broadcast
	used = []string{"10.0.0.2"}
	_, err = nextFreeIP("10.0.0.0/30", used)
	if err == nil {
		t.Fatal("expected error for exhausted /30 subnet")
	}
}

// TestNextFreeIPv6_Basic verifies v6 allocation starts at network + 2
// (skipping subnet-router anycast at::0 and gateway at::1).
func TestNextFreeIPv6_Basic(t *testing.T) {
	ip, err := nextFreeIP("2001:db8::/64", nil)
	if err != nil {
		t.Fatalf("nextFreeIP v6: %v", err)
	}
	if ip != "2001:db8::2" {
		t.Errorf("expected 2001:db8::2, got %s", ip)
	}
}

func TestNextFreeIPv6_SkipsUsed(t *testing.T) {
	used := []string{"2001:db8::2", "2001:db8::3"}
	ip, err := nextFreeIP("2001:db8::/64", used)
	if err != nil {
		t.Fatalf("nextFreeIP v6: %v", err)
	}
	if ip != "2001:db8::4" {
		t.Errorf("expected 2001:db8::4, got %s", ip)
	}
}

// TestNextFreeIPv6_Canonicalization verifies non-canonical input forms
// for "used" addresses are matched correctly (2001:db8::2 == 2001:0db8::2).
func TestNextFreeIPv6_Canonicalization(t *testing.T) {
	used := []string{"2001:0db8:0000:0000:0000:0000:0000:0002"}
	ip, err := nextFreeIP("2001:db8::/64", used)
	if err != nil {
		t.Fatalf("nextFreeIP v6: %v", err)
	}
	if ip != "2001:db8::3" {
		t.Errorf("expected 2001:db8::3, got %s", ip)
	}
}

// TestAllocateIPv6 wires v6 through the full DB-backed allocation path.
func TestAllocateIPv6(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	ip, err := AllocateIP(ctx, db, "v6net", "2001:db8::/64", "aa:bb:cc:dd:ee:01", "vm1")
	if err != nil {
		t.Fatalf("AllocateIP v6: %v", err)
	}
	if ip != "2001:db8::2" {
		t.Errorf("expected 2001:db8::2, got %s", ip)
	}
	ip2, err := AllocateIP(ctx, db, "v6net", "2001:db8::/64", "aa:bb:cc:dd:ee:02", "vm2")
	if err != nil {
		t.Fatalf("AllocateIP v6 #2: %v", err)
	}
	if ip2 != "2001:db8::3" {
		t.Errorf("expected 2001:db8::3, got %s", ip2)
	}
}

func TestAllocateAndRelease(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	ip, err := AllocateIP(ctx, db, "net1", "10.50.0.0/24", "aa:bb:cc:dd:ee:01", "vm1")
	if err != nil {
		t.Fatalf("AllocateIP: %v", err)
	}
	if ip != "10.50.0.2" {
		t.Errorf("expected 10.50.0.2, got %s", ip)
	}

	alloc, err := GetAllocation(ctx, db, "net1", "vm1")
	if err != nil {
		t.Fatalf("GetAllocation: %v", err)
	}
	if alloc == nil {
		t.Fatal("expected allocation, got nil")
	}
	if alloc.IP != "10.50.0.2" {
		t.Errorf("expected 10.50.0.2, got %s", alloc.IP)
	}

	if err := ReleaseIP(ctx, db, "net1", "vm1"); err != nil {
		t.Fatalf("ReleaseIP: %v", err)
	}

	// After release, tombstoned — GetAllocation returns nil
	alloc, err = GetAllocation(ctx, db, "net1", "vm1")
	if err != nil {
		t.Fatalf("GetAllocation after release: %v", err)
	}
	if alloc != nil {
		t.Errorf("expected nil after release, got %+v", alloc)
	}
}

func TestAllocateIP_TwoVMs(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	ip1, err := AllocateIP(ctx, db, "net2", "10.60.0.0/24", "aa:bb:cc:dd:ee:01", "vm-a")
	if err != nil {
		t.Fatalf("AllocateIP vm-a: %v", err)
	}

	ip2, err := AllocateIP(ctx, db, "net2", "10.60.0.0/24", "aa:bb:cc:dd:ee:02", "vm-b")
	if err != nil {
		t.Fatalf("AllocateIP vm-b: %v", err)
	}

	if ip1 == ip2 {
		t.Errorf("two VMs got same IP: %s", ip1)
	}
	if ip1 != "10.60.0.2" {
		t.Errorf("vm-a expected 10.60.0.2, got %s", ip1)
	}
	if ip2 != "10.60.0.3" {
		t.Errorf("vm-b expected 10.60.0.3, got %s", ip2)
	}
}

func TestGetAllocation_NotFound(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	alloc, err := GetAllocation(ctx, db, "net99", "nonexistent-vm")
	if err != nil {
		t.Fatalf("GetAllocation: %v", err)
	}
	if alloc != nil {
		t.Errorf("expected nil for nonexistent allocation, got %+v", alloc)
	}
}
