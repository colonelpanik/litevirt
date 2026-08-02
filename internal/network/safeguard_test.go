package network

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestSafeProvision_DirectSkipsSafeguard(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		// Direct provisioning does not need safeguard commands.
		if name == "ip" && len(args) > 0 && args[0] == "link" {
			return []byte("1: loopback: <LOOPBACK,UP,LOWER_UP>"), nil
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	loopback := testLoopbackInterface(t)
	def := compose.NetworkDef{
		Type:      "direct",
		Interface: loopback,
	}

	result, err := SafeProvision(ctx, db, "test-direct", def, "127.0.0.1", "test-host")
	if err != nil {
		t.Fatalf("SafeProvision direct: %v", err)
	}
	if want := "direct:" + loopback; result != want {
		t.Fatalf("expected %s, got %s", want, result)
	}
}

func TestSafeProvision_RollbackOnConnectivityLoss(t *testing.T) {
	// Track commands executed during rollback.
	pingCount := 0
	var allCmds []string

	execCommand = func(name string, args ...string) ([]byte, error) {
		cmd := name + " " + fmt.Sprintf("%v", args)
		allCmds = append(allCmds, cmd)

		if name == "ping" {
			pingCount++
			if pingCount <= 1 {
				// Baseline check succeeds.
				return []byte("1 packets transmitted, 1 received"), nil
			}
			// After provisioning, pings fail.
			return []byte("1 packets transmitted, 0 received"), fmt.Errorf("ping failed")
		}
		if name == "ip" {
			// Default route.
			if len(args) >= 3 && args[1] == "route" && args[2] == "show" {
				return []byte("default via 10.0.0.1 dev eth0"), nil
			}
			// Address query.
			if len(args) >= 4 && args[1] == "-o" && args[2] == "addr" {
				return []byte("2: eth0    inet 10.0.0.50/24 brd 10.0.0.255 scope global eth0"), nil
			}
			// Route query for interface.
			if len(args) >= 3 && args[1] == "route" {
				return []byte("10.0.0.0/24 proto kernel scope link src 10.0.0.50"), nil
			}
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	// Use a short timeout for the test.
	origTimeout := SafeProvisionTimeout
	SafeProvisionTimeout = 12 * time.Second
	defer func() { SafeProvisionTimeout = origTimeout }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:      "bridge",
		Interface: "lv-test-br",
	}

	_, err = SafeProvision(ctx, db, "test-net", def, "127.0.0.1", "test-host")
	if err == nil {
		t.Fatal("expected error from SafeProvision after connectivity loss, got nil")
	}
	if pingCount < 4 {
		t.Errorf("expected at least 4 ping checks (1 baseline + 3 failures), got %d", pingCount)
	}
	// Verify restore ran: should see "ip addr add" with our snapshotted address.
	foundRestore := false
	for _, c := range allCmds {
		if fmt.Sprintf("%v", c) == "ip [addr add 10.0.0.50/24 dev eth0]" {
			foundRestore = true
			break
		}
	}
	if !foundRestore {
		t.Error("expected restore to re-add address 10.0.0.50/24 to eth0")
	}
}

func TestTakeSnapshot(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) {
		if name == "ip" {
			if len(args) >= 3 && args[1] == "route" && args[2] == "show" {
				return []byte("default via 192.168.1.1 dev ens18 proto static"), nil
			}
			if len(args) >= 4 && args[1] == "-o" && args[2] == "addr" {
				return []byte("2: ens18    inet 192.168.1.100/24 brd 192.168.1.255 scope global ens18"), nil
			}
			if len(args) >= 3 && args[1] == "route" {
				return []byte("192.168.1.0/24 proto kernel scope link src 192.168.1.100\ndefault via 192.168.1.1"), nil
			}
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	snap, err := takeSnapshot()
	if err != nil {
		t.Fatalf("takeSnapshot: %v", err)
	}
	if snap.Gateway != "192.168.1.1" {
		t.Errorf("gateway = %q, want 192.168.1.1", snap.Gateway)
	}
	if snap.GwIface != "ens18" {
		t.Errorf("iface = %q, want ens18", snap.GwIface)
	}
	if len(snap.Addrs) != 1 || snap.Addrs[0] != "192.168.1.100/24" {
		t.Errorf("addrs = %v, want [192.168.1.100/24]", snap.Addrs)
	}
}
