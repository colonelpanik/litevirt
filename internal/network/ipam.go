package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// IPAllocation holds an IP allocation record. VMName is the legacy owner-NAME
// column; OwnerKind/OwnerHost (v36) disambiguate VM vs CT and same-named CTs
// across hosts.
type IPAllocation struct {
	Network   string
	IP        string
	MAC       string
	VMName    string
	OwnerKind string
	OwnerHost string
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

// ComputeCandidateIP returns the next free host IP in subnet given the addresses
// currently allocated on network, WITHOUT writing a lease. Used by the container
// create path to pick an address under a single atomic batch (the lease row is
// written alongside the container + interface rows), so a failed create leaks no
// lease. The used-set spans all owners on the network (an IP is taken regardless
// of who holds it).
func ComputeCandidateIP(ctx context.Context, db *corrosion.Client, network, subnet string) (string, error) {
	rows, err := db.Query(ctx,
		`SELECT ip FROM ip_allocations WHERE network = ? AND deleted_at IS NULL`, network)
	if err != nil {
		return "", fmt.Errorf("query allocations: %w", err)
	}
	var used []string
	for _, r := range rows {
		used = append(used, r.String("ip"))
	}
	return nextFreeIP(subnet, used)
}

// AllocateIPFor claims the next free host IP in subnet for an owner of the given
// kind ('vm'|'ct'). ownerHost is "" for VMs (names are cluster-global) and the
// container's host for CTs (CT names are per-host). It resurrects a tombstoned
// lease for the chosen address (so a RELEASED IP is reusable — the (network,ip)
// PK otherwise blocks a plain re-INSERT) but never clobbers a LIVE lease: a
// guarded ON CONFLICT update + a read-back confirm ownership, and a lost race
// retries a fresh candidate.
func AllocateIPFor(ctx context.Context, db *corrosion.Client, network, subnet, mac, ownerKind, ownerHost, name string) (string, error) {
	for attempt := 0; attempt < 5; attempt++ {
		ip, err := ComputeCandidateIP(ctx, db, network, subnet) // free or tombstoned (excludes LIVE)
		if err != nil {
			return "", err
		}
		if err := db.Execute(ctx,
			`INSERT INTO ip_allocations (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(network, ip) DO UPDATE SET
			   mac = excluded.mac, vm_name = excluded.vm_name, owner_kind = excluded.owner_kind,
			   owner_host = excluded.owner_host, allocated_at = excluded.allocated_at,
			   updated_at = excluded.updated_at, deleted_at = NULL
			 WHERE ip_allocations.deleted_at IS NOT NULL`, // only resurrect a tombstone; LIVE → no-op
			network, ip, mac, name, ownerKind, ownerHost, time.Now().UTC().Format(time.RFC3339), db.NowTS()); err != nil {
			return "", err
		}
		// Confirm WE hold (network, ip): the guarded UPDATE no-ops if a LIVE lease
		// won the race, so a no-op means try a fresh candidate.
		held, err := ipLeaseHeldBy(ctx, db, network, ip, ownerKind, ownerHost, name)
		if err != nil {
			return "", err
		}
		if held {
			return ip, nil
		}
	}
	return "", fmt.Errorf("failed to allocate IP after retries (contention or subnet exhausted)")
}

// ipLeaseHeldBy reports whether (network, ip) is held by a LIVE lease owned by
// exactly (kind, host, name) — the read-back the conditional reserve/allocate
// paths use to detect a no-op guarded update.
func ipLeaseHeldBy(ctx context.Context, db *corrosion.Client, network, ip, ownerKind, ownerHost, name string) (bool, error) {
	rows, err := db.Query(ctx,
		`SELECT 1 AS ok FROM ip_allocations
		 WHERE network = ? AND ip = ? AND vm_name = ? AND owner_kind = ? AND owner_host = ? AND deleted_at IS NULL`,
		network, ip, name, ownerKind, ownerHost)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// AllocateIP is the VM-owner wrapper (owner_kind='vm', owner_host='').
func AllocateIP(ctx context.Context, db *corrosion.Client, network, subnet, mac, vmName string) (string, error) {
	return AllocateIPFor(ctx, db, network, subnet, mac, "vm", "", vmName)
}

// ReleaseIPFor tombstones the live lease for the given owner on network.
func ReleaseIPFor(ctx context.Context, db *corrosion.Client, network, ownerKind, ownerHost, name string) error {
	now := db.NowTS()
	return db.Execute(ctx,
		`UPDATE ip_allocations SET deleted_at = ?, updated_at = ?
		 WHERE network = ? AND vm_name = ? AND owner_kind = ? AND owner_host = ? AND deleted_at IS NULL`,
		now, now, network, name, ownerKind, ownerHost)
}

// ReleaseIP is the VM-owner wrapper.
func ReleaseIP(ctx context.Context, db *corrosion.Client, network, vmName string) error {
	return ReleaseIPFor(ctx, db, network, "vm", "", vmName)
}

// GetAllocationFor returns the live lease for the given owner on network, or nil.
func GetAllocationFor(ctx context.Context, db *corrosion.Client, network, ownerKind, ownerHost, name string) (*IPAllocation, error) {
	rows, err := db.Query(ctx,
		`SELECT network, ip, mac, vm_name,
		        COALESCE(owner_kind, 'vm') AS owner_kind, COALESCE(owner_host, '') AS owner_host
		 FROM ip_allocations
		 WHERE network = ? AND vm_name = ? AND owner_kind = ? AND owner_host = ? AND deleted_at IS NULL`,
		network, name, ownerKind, ownerHost)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &IPAllocation{
		Network:   r.String("network"),
		IP:        r.String("ip"),
		MAC:       r.String("mac"),
		VMName:    r.String("vm_name"),
		OwnerKind: r.String("owner_kind"),
		OwnerHost: r.String("owner_host"),
	}, nil
}

// GetAllocation is the VM-owner wrapper.
func GetAllocation(ctx context.Context, db *corrosion.Client, network, vmName string) (*IPAllocation, error) {
	return GetAllocationFor(ctx, db, network, "vm", "", vmName)
}
