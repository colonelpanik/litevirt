package network

import (
	"fmt"
	"net"
	"strings"
)

// gatewayForSubnet returns "<firstHostIP>/<prefix>" from a CIDR.
// e.g. "10.100.0.0/24" → "10.100.0.1/24"
func gatewayForSubnet(cidr string) (string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if ip == nil || ipNet == nil {
		return "", fmt.Errorf("invalid CIDR %q", cidr)
	}

	// Get network address as 4-byte slice
	network := ipNet.IP.To4()
	if network == nil {
		return "", fmt.Errorf("only IPv4 CIDRs are supported: %q", cidr)
	}

	// Increment to get first host IP (network + 1)
	gw := make(net.IP, 4)
	copy(gw, network)
	ipInc(gw)

	// Verify it's still within the subnet
	if !ipNet.Contains(gw) {
		return "", fmt.Errorf("subnet %q has no host addresses", cidr)
	}

	prefix, _ := ipNet.Mask.Size()
	return fmt.Sprintf("%s/%d", gw.String(), prefix), nil
}

// EnsureIRB sets up anycast gateway on the VNI bridge.
// Derives.1 gateway from subnet, runs:
//
//	ip addr add <gw>/<prefix> dev br-vni<VNI>    (EEXIST = ok)
//	bridge link set dev vxlan<VNI> neigh_suppress on
//
// Returns gateway IP (without prefix).
func EnsureIRB(vni int, subnet string) (string, error) {
	gwCIDR, err := gatewayForSubnet(subnet)
	if err != nil {
		return "", err
	}

	bridge := vxlanBridgeName(vni)
	vxlan := vtepName(vni)

	// Add gateway IP to bridge
	out, err := execCommand("ip", "addr", "add", gwCIDR, "dev", bridge)
	if err != nil && !isAlreadyExists(out) {
		return "", fmt.Errorf("ip addr add %s dev %s: %w: %s", gwCIDR, bridge, err, out)
	}

	// Enable neighbor suppression on VXLAN interface
	out, err = execCommand("bridge", "link", "set", "dev", vxlan, "neigh_suppress", "on")
	if err != nil && !isAlreadyExists(out) {
		return "", fmt.Errorf("bridge link set neigh_suppress: %w: %s", err, out)
	}

	// Return just the IP (without prefix)
	gwIP := strings.SplitN(gwCIDR, "/", 2)[0]
	return gwIP, nil
}

// RemoveIRB removes the gateway IP from the VNI bridge.
func RemoveIRB(vni int, subnet string) error {
	gwCIDR, err := gatewayForSubnet(subnet)
	if err != nil {
		return err
	}

	bridge := vxlanBridgeName(vni)
	out, err := execCommand("ip", "addr", "del", gwCIDR, "dev", bridge)
	if err != nil && !isNoSuchDevice(out) {
		return fmt.Errorf("ip addr del %s dev %s: %w: %s", gwCIDR, bridge, err, out)
	}
	return nil
}
