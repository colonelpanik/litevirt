package corrosion

import (
	"context"
	"fmt"
	"hash/fnv"
)

// ContainerVethName derives the deterministic, IFNAMSIZ-safe host veth name for a
// container NIC from (ct name, ordinal). Stable across recreate — the create,
// restore, relocate-recreate, and firewall paths all recompute it rather than
// persisting it. "lvc" + 12 hex = 15 bytes, exactly the IFNAMSIZ max (16 incl. the
// NUL). The 48 bits are fnv64a over (ct, ordinal): folding the ordinal INTO the
// hash (instead of appending it as decimal) keeps every NIC fixed-width and
// distinct, and 48 bits makes a per-host name collision negligible (the old scheme
// kept only 32 bits and appended the ordinal). The veth is host-LOCAL, so the host
// is deliberately NOT in the hash (it's constant per host — no added entropy).
// Lives here (the lowest layer) so grpcapi and health share it without a
// cross-package edge.
func ContainerVethName(ctName string, ordinal int) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(fmt.Sprintf("%s/%d", ctName, ordinal)))
	return fmt.Sprintf("lvc%012x", h.Sum64()&0xffffffffffff)
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

// ContainerMAC derives a deterministic, locally-administered MAC for a container
// NIC from (host, ct name, ordinal). Deterministic so the clone path writes the
// SAME MAC into the on-disk LXC config and the interface row (no drift), and a
// fresh create reproduces it; migrate/restore/relocate read the PERSISTED MAC
// (create_spec) rather than regenerating, so a host change never re-derives it.
//
// First octet 0x52 is locally-administered (0x02 set) + unicast (0x01 clear) — the
// familiar litevirt look, still a valid LAA. The other 5 octets (40 bits) are
// fnv64a over (host, ct, ordinal): the HOST keeps two same-named containers on
// different hosts (e.g. sharing a vxlan L2) from deriving the SAME MAC, and 40 bits
// makes a birthday collision negligible at fleet scale (the old scheme fixed
// 52:54:00 and kept only 24 bits).
func ContainerMAC(hostName, ctName string, ordinal int) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(fmt.Sprintf("%s/%s/%d", hostName, ctName, ordinal)))
	s := h.Sum64()
	return fmt.Sprintf("52:%02x:%02x:%02x:%02x:%02x",
		byte(s>>32), byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
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
