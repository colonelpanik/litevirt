package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// PreFlightCheck verifies network prerequisites before a VM starts on a host.
// Checks: bridge exists, VLAN filtering if needed, SR-IOV VFs available, IP conflicts.
type PreFlightCheck struct {
	Bridge      string // bridge name to verify
	VLAN        int    // non-zero if VLAN required
	SRIOV       bool   // true if SR-IOV VF needed
	SRIOVPF     string // physical function name
	IP          string // static IP to check for conflicts
	NetworkName string // network name for IP conflict check
}

// PreFlightResult contains the result of a single check.
type PreFlightResult struct {
	Check   string
	Passed  bool
	Message string
}

// RunPreFlight runs all applicable pre-flight checks and returns results.
// Returns an error describing the first failure, or nil if all pass.
func RunPreFlight(ctx context.Context, db *corrosion.Client, checks []PreFlightCheck) error {
	for _, c := range checks {
		if err := checkBridge(c.Bridge); err != nil {
			return err
		}
		if c.VLAN > 0 {
			if err := checkVLANFiltering(c.Bridge); err != nil {
				return err
			}
		}
		if c.SRIOV {
			if err := checkSRIOVVFs(c.SRIOVPF); err != nil {
				return err
			}
		}
		if c.IP != "" && c.NetworkName != "" && db != nil {
			if err := checkIPConflict(ctx, db, c.NetworkName, c.IP); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkBridge verifies the bridge interface exists on this host.
func checkBridge(bridge string) error {
	if bridge == "" {
		return nil
	}
	if _, err := net.InterfaceByName(bridge); err != nil {
		return fmt.Errorf("preflight: bridge %q not found on host: %w", bridge, err)
	}
	return nil
}

// checkVLANFiltering verifies the bridge has VLAN filtering enabled.
func checkVLANFiltering(bridge string) error {
	path := fmt.Sprintf("/sys/class/net/%s/bridge/vlan_filtering", bridge)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("preflight: cannot read VLAN filtering for %q: %w", bridge, err)
	}
	if strings.TrimSpace(string(data)) != "1" {
		return fmt.Errorf("preflight: bridge %q does not have VLAN filtering enabled (echo 1 > %s)", bridge, path)
	}
	return nil
}

// checkSRIOVVFs verifies the physical function has free VFs available.
func checkSRIOVVFs(pf string) error {
	if pf == "" {
		return fmt.Errorf("preflight: SR-IOV requested but no physical function specified")
	}
	totalPath := fmt.Sprintf("/sys/class/net/%s/device/sriov_totalvfs", pf)
	data, err := os.ReadFile(totalPath)
	if err != nil {
		return fmt.Errorf("preflight: cannot read SR-IOV total VFs for %q: %w", pf, err)
	}
	if strings.TrimSpace(string(data)) == "0" {
		return fmt.Errorf("preflight: PF %q has no SR-IOV VFs configured", pf)
	}
	numPath := fmt.Sprintf("/sys/class/net/%s/device/sriov_numvfs", pf)
	data, err = os.ReadFile(numPath)
	if err != nil {
		return fmt.Errorf("preflight: cannot read SR-IOV active VFs for %q: %w", pf, err)
	}
	if strings.TrimSpace(string(data)) == "0" {
		return fmt.Errorf("preflight: PF %q has no active VFs — create them first (echo N > %s)", pf, numPath)
	}
	return nil
}

// checkIPConflict verifies the IP is not already allocated to another VM on the network.
func checkIPConflict(ctx context.Context, db *corrosion.Client, networkName, ip string) error {
	rows, err := db.Query(ctx,
		`SELECT vm_name FROM ip_allocations
		 WHERE network = ? AND ip = ? AND deleted_at IS NULL`,
		networkName, ip)
	if err != nil {
		return fmt.Errorf("preflight: IP conflict check query failed: %w", err)
	}
	if len(rows) > 0 {
		return fmt.Errorf("preflight: IP %s is already allocated to VM %q on network %q",
			ip, rows[0].String("vm_name"), networkName)
	}
	return nil
}
