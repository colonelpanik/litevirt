package network

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// BridgeExists returns true if a network interface with the given name exists.
func BridgeExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// EnsureBridge idempotently creates a Linux bridge and brings it up.
// If the bridge already exists, this is a no-op.
func EnsureBridge(name string) error {
	if len(name) > 15 {
		return fmt.Errorf("create bridge %s: interface name exceeds 15-character Linux limit (%d chars)", name, len(name))
	}
	// Fast path: if the interface already exists, nothing to do.
	if _, err := net.InterfaceByName(name); err == nil {
		return nil
	}

	out, err := execCommand("ip", "link", "add", name, "type", "bridge")
	if err != nil && !isFileExists(out) {
		return fmt.Errorf("create bridge %s: %w: %s", name, err, out)
	}

	out, err = execCommand("ip", "link", "set", name, "up")
	if err != nil {
		return fmt.Errorf("bring up bridge %s: %w: %s", name, err, out)
	}

	return nil
}

// VLANInterfaceName returns the name of the VLAN sub-interface for a given
// parent and VLAN ID (e.g. "bond0" + 219 → "bond0.219").
func VLANInterfaceName(parent string, vlanID int) string {
	return fmt.Sprintf("%s.%d", parent, vlanID)
}

// sysfsParent returns the parent interface name by reading
// /sys/class/net/<iface>/lower_* entries. Returns "" if no parent.
func sysfsParent(iface string) string {
	entries, _ := filepath.Glob(fmt.Sprintf("/sys/class/net/%s/lower_*", iface))
	if len(entries) == 1 {
		return strings.TrimPrefix(filepath.Base(entries[0]), "lower_")
	}
	return ""
}

// isBond returns true if the interface is a bond (has /sys/class/net/<iface>/bonding/).
func isBond(iface string) bool {
	_, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/bonding", iface))
	return err == nil
}

// isPhysicalNIC returns true if the interface is a physical NIC (has /sys/class/net/<iface>/device/).
func isPhysicalNIC(iface string) bool {
	_, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/device", iface))
	return err == nil
}

// isBridgeIface returns true if the interface is a bridge (has /sys/class/net/<iface>/bridge/).
func isBridgeIface(iface string) bool {
	_, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/bridge", iface))
	return err == nil
}

// bridgeMembers returns the interfaces attached to a bridge via /sys/class/net/<bridge>/brif/.
func bridgeMembers(bridge string) []string {
	entries, _ := filepath.Glob(fmt.Sprintf("/sys/class/net/%s/brif/*", bridge))
	members := make([]string, 0, len(entries))
	for _, e := range entries {
		members = append(members, filepath.Base(e))
	}
	return members
}

// resolveVLANParent walks the sysfs interface topology from the default route
// interface to find the physical NIC or bond suitable for creating VLAN
// sub-interfaces on.
//
// Examples:
//
//	bond0.206 → lower_bond0 → bond0 has /bonding/ → "bond0"
//	eth0      → no lower_*, has /device/           → "eth0"
//	bond0     → no lower_*, has /bonding/          → "bond0"
//	br-mgmt   → has /bridge/, brif=[bond0.206]     → walk bond0.206 → "bond0"
func resolveVLANParent() (string, error) {
	iface := defaultRouteInterface()
	if iface == "" {
		return "", fmt.Errorf("no default route interface found")
	}

	// Walk up to 5 levels to avoid infinite loops.
	for i := 0; i < 5; i++ {
		if isBond(iface) || isPhysicalNIC(iface) {
			return iface, nil
		}

		// Check for a sysfs parent link (e.g. VLAN sub-interface).
		parent := sysfsParent(iface)
		if parent != "" {
			iface = parent
			continue
		}

		// No sysfs parent — check if it's a bridge and follow its first member.
		if isBridgeIface(iface) {
			members := bridgeMembers(iface)
			if len(members) > 0 {
				iface = members[0]
				continue
			}
		}

		// Can't walk further — use current interface as best effort.
		slog.Warn("resolveVLANParent: could not classify interface, using as-is", "interface", iface)
		return iface, nil
	}

	return iface, nil
}

// EnsureBridgeVLAN creates a VLAN sub-interface on the physical interface
// (or explicit underlay) and attaches it to the bridge, giving VMs direct L2
// access to the tagged VLAN. Idempotent — skips if already configured.
//
// The parent is determined by: explicit underlay > sysfs topology walk from
// default route interface to find physical NIC or bond.
func EnsureBridgeVLAN(bridge string, vlanID int, underlay string) error {
	parent := underlay
	if parent == "" {
		var err error
		parent, err = resolveVLANParent()
		if err != nil {
			return fmt.Errorf("cannot find parent for VLAN %d: %w (set 'underlay' explicitly)", vlanID, err)
		}
	}

	vlanIface := VLANInterfaceName(parent, vlanID)

	// Create the VLAN interface if it doesn't exist.
	if _, err := net.InterfaceByName(vlanIface); err != nil {
		out, err := execCommand("ip", "link", "add", "link", parent, "name", vlanIface, "type", "vlan", "id", fmt.Sprintf("%d", vlanID))
		if err != nil && !isFileExists(out) {
			return fmt.Errorf("create VLAN interface %s: %w: %s", vlanIface, err, out)
		}
	}

	// Bring up the VLAN interface.
	if out, err := execCommand("ip", "link", "set", vlanIface, "up"); err != nil {
		return fmt.Errorf("bring up %s: %w: %s", vlanIface, err, out)
	}

	// Attach to the bridge (if not already a member).
	out, _ := execCommand("ip", "link", "show", "master", bridge, "dev", vlanIface)
	if !strings.Contains(string(out), vlanIface) {
		if out, err := execCommand("ip", "link", "set", vlanIface, "master", bridge); err != nil {
			return fmt.Errorf("attach %s to bridge %s: %w: %s", vlanIface, bridge, err, out)
		}
	}

	slog.Info("bridge VLAN configured", "bridge", bridge, "vlan", vlanID, "interface", vlanIface)
	return nil
}

// RemoveBridgeVLAN detaches and deletes the VLAN sub-interface from a bridge.
func RemoveBridgeVLAN(bridge string, vlanID int, underlay string) {
	parent := underlay
	if parent == "" {
		var err error
		parent, err = resolveVLANParent()
		if err != nil {
			slog.Warn("RemoveBridgeVLAN: cannot resolve parent, skipping", "vlan", vlanID, "error", err)
			return
		}
	}
	vlanIface := VLANInterfaceName(parent, vlanID)

	// Detach from bridge and delete.
	execCommand("ip", "link", "set", vlanIface, "nomaster")    //nolint:errcheck
	execCommand("ip", "link", "del", vlanIface)                 //nolint:errcheck
	slog.Info("bridge VLAN removed", "bridge", bridge, "vlan", vlanID, "interface", vlanIface)
}

// EnsureProxyARP enables proxy_arp and ip_forward on the host's default-route
// interface so the hypervisor answers ARP requests for VM IPs on the physical
// network. This allows external hosts (outside the cluster) to reach VMs on
// bridge subnets that differ from the hypervisor's own subnet.
func EnsureProxyARP(bridge string) error {
	// Enable IP forwarding (may already be set by EnsureNAT).
	if out, err := execCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable ip_forward: %w: %s", err, out)
	}

	// Enable proxy ARP on the physical (default-route) interface.
	phys := defaultRouteInterface()
	if phys == "" {
		return fmt.Errorf("cannot determine default route interface for proxy ARP")
	}
	if out, err := execCommand("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.proxy_arp=1", phys)); err != nil {
		return fmt.Errorf("enable proxy_arp on %s: %w: %s", phys, err, out)
	}

	// Enable proxy ARP on the bridge too so the host proxies in both directions.
	if out, err := execCommand("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.proxy_arp=1", bridge)); err != nil {
		return fmt.Errorf("enable proxy_arp on %s: %w: %s", bridge, err, out)
	}

	slog.Info("proxy ARP enabled", "bridge", bridge, "physical", phys)
	return nil
}

// RemoveProxyARP disables proxy_arp on the bridge. The physical interface is
// left alone since other bridges may still need it.
func RemoveProxyARP(bridge string) {
	execCommand("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.proxy_arp=0", bridge)) //nolint:errcheck
}

// EnsureSubnetRoute adds a static route for a VM subnet via a remote
// hypervisor IP. This allows the local host to reach VMs on a peer host's
// bridge without needing a VLAN interface on the VM subnet.
// Idempotent — skips if route already exists.
func EnsureSubnetRoute(subnet, viaIP string) error {
	// Check if route already exists.
	out, err := execCommand("ip", "route", "show", subnet)
	if err == nil && strings.Contains(string(out), viaIP) {
		return nil // already present
	}

	out, err = execCommand("ip", "route", "replace", subnet, "via", viaIP)
	if err != nil {
		return fmt.Errorf("add route %s via %s: %w: %s", subnet, viaIP, err, out)
	}
	slog.Info("subnet route added", "subnet", subnet, "via", viaIP)
	return nil
}

// RemoveSubnetRoute removes a static route for a VM subnet via a specific
// hypervisor IP. No-op if the route doesn't exist.
func RemoveSubnetRoute(subnet, viaIP string) {
	// Only remove if the route points to the expected gateway.
	out, _ := execCommand("ip", "route", "show", subnet)
	if strings.Contains(string(out), viaIP) {
		execCommand("ip", "route", "del", subnet, "via", viaIP) //nolint:errcheck
		slog.Info("subnet route removed", "subnet", subnet, "via", viaIP)
	}
}

// macvlanName returns the companion macvlan interface name for a parent.
// e.g. "bond0.206" → "mv-bond0.206"
func macvlanName(parent string) string {
	return "mv-" + parent
}

// ensureMacvlan idempotently creates a macvlan interface in bridge mode on the
// given parent. This allows the hypervisor to communicate with macvtap (direct)
// guests on the same parent interface — a kernel limitation where the host stack
// cannot reach macvtap devices without a macvlan companion.
func ensureMacvlan(parent string) {
	name := macvlanName(parent)
	if _, err := net.InterfaceByName(name); err == nil {
		return // already exists
	}
	if out, err := execCommand("ip", "link", "add", name, "link", parent, "type", "macvlan", "mode", "bridge"); err != nil {
		slog.Warn("ensureMacvlan: create failed", "name", name, "parent", parent, "error", err, "output", string(out))
		return
	}
	if out, err := execCommand("ip", "link", "set", name, "up"); err != nil {
		slog.Warn("ensureMacvlan: bring up failed", "name", name, "error", err, "output", string(out))
	}
	slog.Info("macvlan companion created for direct network", "name", name, "parent", parent)
}
