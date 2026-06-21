package network

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// netSnapshot captures the network state of the host's management interface
// before a provisioning operation, so it can be restored if connectivity breaks.
type netSnapshot struct {
	Gateway string   // default gateway IP
	GwIface string   // interface the default route uses
	Addrs   []string // all IPv4 CIDR addresses on the gateway interface
	Routes  []string // all routes via the gateway interface
}

// takeSnapshot records the current management network state.
func takeSnapshot() (*netSnapshot, error) {
	gw, gwIface := defaultGateway()
	if gw == "" || gwIface == "" {
		return nil, fmt.Errorf("cannot determine default gateway")
	}

	snap := &netSnapshot{
		Gateway: gw,
		GwIface: gwIface,
		Addrs:   ifaceAddrs(gwIface),
		Routes:  ifaceRoutes(gwIface),
	}

	if len(snap.Addrs) == 0 {
		return nil, fmt.Errorf("management interface %s has no addresses", gwIface)
	}

	slog.Info("network safeguard: snapshot taken",
		"gateway", gw, "iface", gwIface, "addrs", snap.Addrs)
	return snap, nil
}

// defaultGateway returns the default gateway IP and the interface it uses.
func defaultGateway() (string, string) {
	out, err := execCommand("ip", "-4", "route", "show", "default")
	if err != nil {
		return "", ""
	}
	// "default via 192.0.2.1 dev bond0.206..."
	fields := strings.Fields(string(out))
	var gw, dev string
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			gw = fields[i+1]
		}
		if f == "dev" && i+1 < len(fields) {
			dev = fields[i+1]
		}
	}
	return gw, dev
}

// ifaceAddrs returns all IPv4 CIDR addresses on an interface.
func ifaceAddrs(iface string) []string {
	out, err := execCommand("ip", "-4", "-o", "addr", "show", "dev", iface)
	if err != nil {
		return nil
	}
	var addrs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				addrs = append(addrs, fields[i+1])
				break
			}
		}
	}
	return addrs
}

// ifaceRoutes returns all routes that use the given interface.
func ifaceRoutes(iface string) []string {
	out, err := execCommand("ip", "-4", "route", "show", "dev", iface)
	if err != nil {
		return nil
	}
	var routes []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		routes = append(routes, line)
	}
	return routes
}

// restore re-applies the snapshotted addresses and routes to the original interface.
func (s *netSnapshot) restore() {
	slog.Warn("network safeguard: RESTORING network state",
		"iface", s.GwIface, "addrs", s.Addrs, "gateway", s.Gateway)

	// Re-add addresses.
	for _, addr := range s.Addrs {
		out, err := execCommand("ip", "addr", "add", addr, "dev", s.GwIface)
		if err != nil && !isFileExists(out) {
			slog.Error("safeguard restore: failed to add address", "addr", addr, "iface", s.GwIface, "error", err)
		}
	}

	// Bring interface up.
	execCommand("ip", "link", "set", s.GwIface, "up") //nolint:errcheck

	// Re-add routes.
	for _, route := range s.Routes {
		args := append([]string{"route", "replace"}, strings.Fields(route)...)
		execCommand("ip", args...) //nolint:errcheck
	}

	// Ensure default route exists.
	execCommand("ip", "route", "replace", "default", "via", s.Gateway, "dev", s.GwIface) //nolint:errcheck

	slog.Warn("network safeguard: restore complete", "iface", s.GwIface)
}

// checkConnectivity pings the default gateway to verify the host can still reach the network.
func (s *netSnapshot) checkConnectivity() bool {
	out, err := execCommand("ping", "-c", "1", "-W", "3", s.Gateway)
	if err != nil {
		slog.Warn("network safeguard: connectivity check failed",
			"gateway", s.Gateway, "error", err, "output", string(out))
		return false
	}
	return true
}

// SafeProvisionTimeout is how long the safeguard waits for connectivity
// after provisioning before rolling back. Default 30 seconds.
var SafeProvisionTimeout = 30 * time.Second

// SafeProvision wraps Provision with a connectivity safeguard.
// It snapshots the host's management network state, runs the provision,
// then verifies the host can still reach its default gateway.
// If connectivity is lost, it deprovisions the network and restores the
// original state — similar to "netplan try".
//
// For network types that don't touch host interfaces (direct, sriov, external),
// the safeguard is skipped since they can't break host connectivity.
func SafeProvision(ctx context.Context, db *corrosion.Client, networkName string, def compose.NetworkDef, localIP, hostName string) (string, error) {
	// Types that cannot break host connectivity — skip safeguard.
	switch def.Type {
	case "direct", "sriov", "isolated":
		return Provision(ctx, db, networkName, def, localIP, hostName)
	}

	// Take a snapshot of the current network state.
	snap, err := takeSnapshot()
	if err != nil {
		slog.Warn("network safeguard: cannot snapshot, proceeding without safeguard", "error", err)
		return Provision(ctx, db, networkName, def, localIP, hostName)
	}

	// Verify we have connectivity before provisioning (baseline).
	if !snap.checkConnectivity() {
		slog.Warn("network safeguard: no baseline connectivity, proceeding without safeguard")
		return Provision(ctx, db, networkName, def, localIP, hostName)
	}

	// Run provisioning.
	result, provErr := Provision(ctx, db, networkName, def, localIP, hostName)
	if provErr != nil {
		return "", provErr
	}

	// Check connectivity repeatedly over the timeout period.
	// We check multiple times because bridge/VLAN changes can take a moment to settle.
	deadline := time.Now().Add(SafeProvisionTimeout)
	checkInterval := 3 * time.Second
	consecutiveFailures := 0
	requiredFailures := 3 // require 3 consecutive failures before rollback

	for time.Now().Before(deadline) {
		time.Sleep(checkInterval)
		if snap.checkConnectivity() {
			slog.Info("network safeguard: connectivity verified after provisioning",
				"network", networkName)
			return result, nil
		}
		consecutiveFailures++
		if consecutiveFailures >= requiredFailures {
			break
		}
	}

	// Connectivity lost — rollback.
	slog.Error("network safeguard: connectivity lost after provisioning, rolling back",
		"network", networkName, "failures", consecutiveFailures)

	// Deprovision what we just created.
	if depErr := Deprovision(networkName, def); depErr != nil {
		slog.Error("network safeguard: deprovision failed during rollback",
			"network", networkName, "error", depErr)
	}

	// Restore the original network state.
	snap.restore()

	return "", fmt.Errorf("network %q provisioning rolled back: host lost connectivity to gateway %s after %d failed checks",
		networkName, snap.Gateway, consecutiveFailures)
}
