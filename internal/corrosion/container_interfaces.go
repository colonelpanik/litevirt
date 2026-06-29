package corrosion

import (
	"context"
	"fmt"
	"hash/fnv"
	"time"
)

// ContainerVethName derives the deterministic, IFNAMSIZ-safe (≤15 bytes) host
// veth name for a container NIC from (ct name, ordinal). Stable across recreate
// — the create, restore, relocate-recreate, and firewall paths all recompute it
// rather than persisting it. "lvc" + 8 hex (fnv32a of the name) + ordinal ⇒
// ≤13 bytes for ordinal<100. Lives here (the lowest layer) so grpcapi and health
// share it without a cross-package edge.
func ContainerVethName(ctName string, ordinal int) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ctName))
	return fmt.Sprintf("lvc%08x%d", h.Sum32(), ordinal)
}

// BuildContainerInterfacesFromSpec reconstructs the MANAGED interface rows for a
// container from its create spec — used by the restore / relocate-recreate paths
// to re-home the network identity on a (possibly new) host. Only NICs that name
// a managed network (NetworkName != "") get a row; legacy raw-bridge NICs don't.
// The veth is recomputed deterministically; IP carries the create-time STATIC
// intent only (an auto-allocated address was stored empty, so it's re-discovered
// / re-allocated rather than reusing a stale value).
// The IP carries the create-time EFFECTIVE address (static or the originally
// auto-allocated one), so the rebuild can re-reserve it. The caller (see
// network.ReserveContainerNICs) conditionally re-reserves each non-empty IP —
// never stealing one held by another workload — and blanks the row's IP if it
// can't, so we never assert an address we don't own.
func BuildContainerInterfacesFromSpec(hostName, ctName string, spec ContainerCreateSpec) []ContainerInterfaceRecord {
	var ifs []ContainerInterfaceRecord
	for i, n := range spec.Networks {
		if n.NetworkName == "" {
			continue // legacy/unmanaged NIC — no row
		}
		ifs = append(ifs, ContainerInterfaceRecord{
			HostName: hostName, CtName: ctName, NetworkName: n.NetworkName, Ordinal: i,
			MAC: n.MAC, IP: n.IP, VethDevice: ContainerVethName(ctName, i), SecurityGroups: n.SecurityGroups,
		})
	}
	return ifs
}

// ContainerInterfaceRecord is one litevirt-MANAGED container NIC — the container
// analogue of InterfaceRecord. Persisted in container_interfaces (schema v35).
// VethDevice is the deterministic host-side veth the firewall reconciler binds
// security groups to (the CT equivalent of vm_interfaces.tap_device). Raw,
// unmanaged bridge NICs get NO record (this table is the managed-NIC source of
// truth).
type ContainerInterfaceRecord struct {
	HostName       string
	CtName         string
	NetworkName    string
	Ordinal        int
	MAC            string
	IP             string
	VethDevice     string
	SecurityGroups []string
}

// IPLease is a single ip_allocations row to write atomically with the container
// + interface rows. vm_name is the legacy owner-name column; OwnerKind/OwnerHost
// (v36) disambiguate a VM from a CT and same-named CTs across hosts.
type IPLease struct {
	Network   string
	IP        string
	MAC       string
	OwnerKind string // "vm" | "ct"
	OwnerHost string // "" for VMs; the host for CTs
	OwnerName string
}

// UpsertContainerInterface writes one container NIC row (resurrecting a
// soft-deleted row), keyed by (host_name, ct_name, ordinal). Used by the
// migrate/restore/relocate-recreate paths to rebuild a NIC.
func UpsertContainerInterface(ctx context.Context, c *Client, r ContainerInterfaceRecord) error {
	stmt, err := containerInterfaceStmt(c, r)
	if err != nil {
		return err
	}
	return c.ExecuteBatch(ctx, []Statement{stmt})
}

func containerInterfaceStmt(c *Client, r ContainerInterfaceRecord) (Statement, error) {
	sgs, err := encodeSGs(r.SecurityGroups)
	if err != nil {
		return Statement{}, err
	}
	return Statement{
		SQL: `INSERT OR REPLACE INTO container_interfaces
		 (host_name, ct_name, network_name, ordinal, mac, ip, veth_device, security_groups, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		Params: []interface{}{r.HostName, r.CtName, r.NetworkName, r.Ordinal, r.MAC, r.IP, r.VethDevice, sgs, c.NowTS()},
	}, nil
}

// containerLeaseStmts builds plain ip_allocations INSERTs for the create batch
// (CreateContainerAtomic). A PK conflict on (network, ip) from a racing
// allocation fails the whole batch rather than clobbering an existing lease.
func containerLeaseStmts(c *Client, leases []IPLease) []Statement {
	now := c.NowTS()
	allocAt := time.Now().UTC().Format(time.RFC3339)
	out := make([]Statement, 0, len(leases))
	for _, l := range leases {
		out = append(out, Statement{
			SQL: `INSERT INTO ip_allocations
			 (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{l.Network, l.IP, l.MAC, l.OwnerName, l.OwnerKind, l.OwnerHost, allocAt, now},
		})
	}
	return out
}

// ContainerMAC derives a deterministic, locally-administered MAC for a container
// NIC from (ct name, ordinal). Deterministic so the clone path writes the SAME
// MAC into the on-disk LXC config and the interface row (no drift), and a
// relocate/restore rebuild reproduces it.
func ContainerMAC(ctName string, ordinal int) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(fmt.Sprintf("%s/%d", ctName, ordinal)))
	s := h.Sum32()
	return fmt.Sprintf("52:54:00:%02x:%02x:%02x", byte(s>>16), byte(s>>8), byte(s))
}

// GetContainerInterfaces returns the live NICs of a container on a host, ordered.
func GetContainerInterfaces(ctx context.Context, c *Client, hostName, ctName string) ([]ContainerInterfaceRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, ct_name, network_name, ordinal, mac, ip, veth_device,
		        COALESCE(security_groups, '') AS security_groups
		 FROM container_interfaces
		 WHERE host_name = ? AND ct_name = ? AND deleted_at IS NULL
		 ORDER BY ordinal`, hostName, ctName)
	if err != nil {
		return nil, err
	}
	return scanContainerInterfaces(rows), nil
}

// ListContainerInterfacesByHost returns every live container NIC on this host —
// the firewall reconciler (PR 2b) binds security groups to their veths.
func ListContainerInterfacesByHost(ctx context.Context, c *Client, hostName string) ([]ContainerInterfaceRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT i.host_name, i.ct_name, i.network_name, i.ordinal, i.mac, i.ip, i.veth_device,
		        COALESCE(i.security_groups, '') AS security_groups
		 FROM container_interfaces i
		 JOIN containers ct ON ct.host_name = i.host_name AND ct.name = i.ct_name
		 WHERE i.host_name = ? AND ct.deleted_at IS NULL AND i.deleted_at IS NULL
		 ORDER BY i.ct_name, i.ordinal`, hostName)
	if err != nil {
		return nil, err
	}
	return scanContainerInterfaces(rows), nil
}

func scanContainerInterfaces(rows []Row) []ContainerInterfaceRecord {
	out := make([]ContainerInterfaceRecord, len(rows))
	for i, r := range rows {
		out[i] = ContainerInterfaceRecord{
			HostName:       r.String("host_name"),
			CtName:         r.String("ct_name"),
			NetworkName:    r.String("network_name"),
			Ordinal:        r.Int("ordinal"),
			MAC:            r.String("mac"),
			IP:             r.String("ip"),
			VethDevice:     r.String("veth_device"),
			SecurityGroups: decodeSGs(r.String("security_groups")),
		}
	}
	return out
}

// DeleteContainerInterfaces tombstones all NICs of a container (the delete
// cascade — pairs with releasing the container's IPAM leases).
func DeleteContainerInterfaces(ctx context.Context, c *Client, hostName, ctName string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE container_interfaces SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND ct_name = ? AND deleted_at IS NULL`,
		now, now, hostName, ctName)
}

// UpdateContainerInterfaceIP records a discovered (e.g. DHCP) address on a NIC.
// Used by PR 2b's CT IP refresh path.
func UpdateContainerInterfaceIP(ctx context.Context, c *Client, hostName, ctName string, ordinal int, ip string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE container_interfaces SET ip = ?, updated_at = ?
		 WHERE host_name = ? AND ct_name = ? AND ordinal = ? AND deleted_at IS NULL`,
		ip, now, hostName, ctName, ordinal)
}
