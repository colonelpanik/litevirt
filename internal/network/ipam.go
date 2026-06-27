package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// IPAllocation holds an IP allocation record.
type IPAllocation struct {
	Network string
	IP      string
	MAC     string
	VMName  string
}

// maxV6ScanHosts caps how many addresses nextFreeIP will scan in a v6
// subnet. Real-world IPAM-managed v6 deployments (DHCPv6) rarely need more
// than a few thousand allocations; SLAAC-using deployments don't use the
// IPAM layer at all. Scanning a /64 linearly is impossible (2⁶⁴ addresses);
// this cap makes the loop bounded for practical sizes.
const maxV6ScanHosts = 1 << 16

// nextFreeIP finds the lowest host IP in subnet not in used set.
// Pure function — no DB. Supports both IPv4 and IPv6 subnets.
//
// IPv4: skips.0 (network) and.1 (anycast gateway). "10.0.0.0/24" → ".2".
// IPv6: skips::0 (subnet-router anycast) and::1 (gateway).
//
//	"2001:db8::/64" → "2001:db8::2".
func nextFreeIP(subnet string, used []string) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}

	usedSet := make(map[string]bool, len(used))
	for _, ip := range used {
		// Canonicalize so 2001:db8::1 and 2001:0db8::1 collide.
		if parsed := net.ParseIP(ip); parsed != nil {
			usedSet[parsed.String()] = true
		} else {
			usedSet[ip] = true
		}
	}

	if v4 := ipNet.IP.To4(); v4 != nil {
		return nextFreeIPv4(v4, ipNet.Mask, usedSet)
	}
	return nextFreeIPv6(ipNet.IP.To16(), ipNet.Mask, usedSet)
}

func nextFreeIPv4(network net.IP, mask net.IPMask, used map[string]bool) (string, error) {
	base := binary.BigEndian.Uint32(network)
	maskU := binary.BigEndian.Uint32([]byte(mask))
	broadcast := base | ^maskU
	for i := base + 2; i < broadcast; i++ {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, i)
		c := net.IP(b).String()
		if !used[c] {
			return c, nil
		}
	}
	return "", fmt.Errorf("ipv4 subnet exhausted")
}

func nextFreeIPv6(network net.IP, mask net.IPMask, used map[string]bool) (string, error) {
	// Start at network + 2 (skip subnet-router anycast and::1 gateway).
	candidate := make(net.IP, 16)
	copy(candidate, network)
	addOne(candidate)
	addOne(candidate)
	for scanned := 0; scanned < maxV6ScanHosts; scanned++ {
		if !ipNetContains(network, mask, candidate) {
			break
		}
		c := candidate.String()
		if !used[c] {
			return c, nil
		}
		addOne(candidate)
	}
	return "", fmt.Errorf("ipv6 subnet exhausted (scanned %d host addresses)", maxV6ScanHosts)
}

// addOne increments ip in-place (big-endian arithmetic). Wraps silently —
// callers must check containment with ipNetContains afterwards.
func addOne(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

// ipNetContains is a faster Contains for v6 paths that bypasses net's
// allocations on the hot loop.
func ipNetContains(network net.IP, mask net.IPMask, ip net.IP) bool {
	if len(network) != len(ip) || len(mask) != len(ip) {
		return false
	}
	for i := range ip {
		if ip[i]&mask[i] != network[i]&mask[i] {
			return false
		}
	}
	return true
}

// AllocateIP claims next free host IP in subnet. Retries 3x on conflict.
// Skips.0 (network addr) and.1 (anycast gateway). Returns IP string only (no CIDR).
func AllocateIP(ctx context.Context, db *corrosion.Client, network, subnet, mac, vmName string) (string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		// Get currently used IPs
		rows, err := db.Query(ctx,
			`SELECT ip FROM ip_allocations WHERE network = ? AND deleted_at IS NULL`,
			network)
		if err != nil {
			return "", fmt.Errorf("query allocations: %w", err)
		}

		var used []string
		for _, r := range rows {
			used = append(used, r.String("ip"))
		}

		ip, err := nextFreeIP(subnet, used)
		if err != nil {
			return "", err
		}

		err = db.Execute(ctx,
			`INSERT INTO ip_allocations (network, ip, mac, vm_name, allocated_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			network, ip, mac, vmName, time.Now().UTC().Format(time.RFC3339), db.NowTS())
		if err == nil {
			return ip, nil
		}
		// If conflict, retry
	}
	return "", fmt.Errorf("failed to allocate IP after 3 attempts")
}

// ReleaseIP tombstones the row for vmName on network.
func ReleaseIP(ctx context.Context, db *corrosion.Client, network, vmName string) error {
	now := db.NowTS()
	return db.Execute(ctx,
		`UPDATE ip_allocations SET deleted_at = ?, updated_at = ? WHERE network = ? AND vm_name = ?`,
		now, now, network, vmName)
}

// GetAllocation returns allocation for vmName on network, or nil.
func GetAllocation(ctx context.Context, db *corrosion.Client, network, vmName string) (*IPAllocation, error) {
	rows, err := db.Query(ctx,
		`SELECT network, ip, mac, vm_name FROM ip_allocations
		 WHERE network = ? AND vm_name = ? AND deleted_at IS NULL`,
		network, vmName)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &IPAllocation{
		Network: r.String("network"),
		IP:      r.String("ip"),
		MAC:     r.String("mac"),
		VMName:  r.String("vm_name"),
	}, nil
}
