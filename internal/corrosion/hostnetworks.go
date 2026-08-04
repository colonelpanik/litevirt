package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
)

// HostNetworkRecord is one host's declarative intent for one named interface
// (§O host network configuration). Only the owning host renders and applies its
// rows; every node reads them (UI/CLI list cluster-wide, and a host that lost
// its DB re-learns its wiring intent from peers).
type HostNetworkRecord struct {
	HostName string
	Name     string
	// Kind is bridge | bond | vlan | ethernet.
	Kind string
	// Members are member interface names (bridge/bond kinds).
	Members []string
	// VLANID and VLANLink apply to kind=vlan only.
	VLANID   int
	VLANLink string
	// Addressing is the JSON-encoded HostNetworkAddressing blob; '' = none
	// (an L2-only bridge, or a bond member NIC).
	Addressing string
	MTU        int
	// BondMode, LACPRate and HashPolicy apply to kind=bond only.
	BondMode   string
	LACPRate   string
	HashPolicy string
	// State is the apply lifecycle: desired → applying → applied|rolled_back.
	// Generation counts CONFIRMED applies (bumped by MarkHostNetworkApplied),
	// so a reader can tell "edited since last apply" (state=desired) from
	// "never applied" (generation=0).
	State      string
	Generation int64
	LastError  string
	CreatedAt  string
	UpdatedAt  string
}

// HostNetworkAddressing is the parsed form of HostNetworkRecord.Addressing.
// It maps 1:1 onto the netplan keys the renderer emits.
type HostNetworkAddressing struct {
	DHCP4       bool     `json:"dhcp4,omitempty"`
	DHCP6       bool     `json:"dhcp6,omitempty"`
	Addresses   []string `json:"addresses,omitempty"` // CIDR literals, v4 or v6
	Gateway     string   `json:"gateway,omitempty"`   // default-route via (v4)
	Gateway6    string   `json:"gateway6,omitempty"`  // default-route via (v6)
	Nameservers []string `json:"nameservers,omitempty"`
}

// Host network states. The apply protocol owns the transitions; see the design
// (docs/superpowers/specs/2026-08-02… §O) — desired is "edited, not yet
// applied", applying is journal-held, applied/rolled_back are outcomes.
const (
	HostNetworkDesired    = "desired"
	HostNetworkApplying   = "applying"
	HostNetworkApplied    = "applied"
	HostNetworkRolledBack = "rolled_back"
)

var hostNetworkKinds = map[string]bool{
	"bridge": true, "bond": true, "vlan": true, "ethernet": true,
}

// UpsertHostNetwork records (or edits) one interface intent, resetting its
// lifecycle to desired: an edit invalidates whatever the last apply confirmed,
// and only a new confirmed apply moves it back. created_at and generation
// survive an edit — the intent's identity and its apply count are not the
// edit's to reset.
func UpsertHostNetwork(ctx context.Context, c *Client, rec HostNetworkRecord) error {
	if rec.HostName == "" || rec.Name == "" {
		return invalidf("host network intent requires host_name and name")
	}
	if !hostNetworkKinds[rec.Kind] {
		return invalidf("host network kind %q: want bridge|bond|vlan|ethernet", rec.Kind)
	}
	if rec.Kind == "vlan" && (rec.VLANID < 1 || rec.VLANID > 4094 || rec.VLANLink == "") {
		return invalidf("vlan intent %q requires vlan_link and vlan_id in 1..4094", rec.Name)
	}
	if rec.Addressing != "" {
		var a HostNetworkAddressing
		if err := json.Unmarshal([]byte(rec.Addressing), &a); err != nil {
			return invalidf("addressing for %q is not valid JSON: %v", rec.Name, err)
		}
	}
	members := ""
	if len(rec.Members) > 0 {
		b, err := json.Marshal(rec.Members)
		if err != nil {
			return fmt.Errorf("encode members: %w", err)
		}
		members = string(b)
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO host_networks (host_name, name, kind, members, vlan_id, vlan_link,
		   addressing, mtu, bond_mode, lacp_rate, hash_policy, state, generation,
		   last_error, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'desired', 0, '', ?, ?)
		 ON CONFLICT(host_name, name) DO UPDATE SET
		   kind = excluded.kind,
		   members = excluded.members,
		   vlan_id = excluded.vlan_id,
		   vlan_link = excluded.vlan_link,
		   addressing = excluded.addressing,
		   mtu = excluded.mtu,
		   bond_mode = excluded.bond_mode,
		   lacp_rate = excluded.lacp_rate,
		   hash_policy = excluded.hash_policy,
		   state = 'desired',
		   last_error = '',
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		rec.HostName, rec.Name, rec.Kind, members, rec.VLANID, rec.VLANLink,
		rec.Addressing, rec.MTU, rec.BondMode, rec.LACPRate, rec.HashPolicy,
		nowRFC3339Nano(), now)
}

// SetHostNetworkState records an apply-lifecycle transition (applying /
// rolled_back with its error). The confirmed-apply transition has its own
// writer below because it also mints the generation.
func SetHostNetworkState(ctx context.Context, c *Client, hostName, name, state, lastError string) error {
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE host_networks SET state = ?, last_error = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		state, lastError, now, hostName, name)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// MarkHostNetworkApplied records a CONFIRMED apply: state=applied, the error
// cleared, and the generation minted. Only the apply protocol's confirm step —
// after the gateway/cluster-LAN/own-listener checks passed — may call this.
func MarkHostNetworkApplied(ctx context.Context, c *Client, hostName, name string) error {
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE host_networks SET state = 'applied', last_error = '',
		   generation = generation + 1, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		now, hostName, name)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// DeleteHostNetwork soft-deletes one intent row. The next apply on the owning
// host renders WITHOUT it, which is what actually removes the interface — a
// tombstoned row with state=applied means "removal pending apply".
func DeleteHostNetwork(ctx context.Context, c *Client, hostName, name string) error {
	now := c.NowTS()
	n, err := c.ExecuteRows(ctx,
		`UPDATE host_networks SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		nowRFC3339(), now, hostName, name)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoRowsAffected
	}
	return nil
}

// GetHostNetwork returns one live intent row, nil when absent/tombstoned.
func GetHostNetwork(ctx context.Context, c *Client, hostName, name string) (*HostNetworkRecord, error) {
	rows, err := c.Query(ctx, hostNetworkSelect+` WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		hostName, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	rec := scanHostNetwork(rows[0])
	return &rec, nil
}

// ListHostNetworks returns the live intent rows, optionally scoped to one host
// ('' = cluster-wide, ordered per host for the UI).
func ListHostNetworks(ctx context.Context, c *Client, hostName string) ([]HostNetworkRecord, error) {
	sql := hostNetworkSelect + ` WHERE deleted_at IS NULL`
	var params []interface{}
	if hostName != "" {
		sql += ` AND host_name = ?`
		params = append(params, hostName)
	}
	sql += ` ORDER BY host_name, name`
	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}
	out := make([]HostNetworkRecord, len(rows))
	for i, r := range rows {
		out[i] = scanHostNetwork(r)
	}
	return out, nil
}

const hostNetworkSelect = `SELECT host_name, name, kind,
	COALESCE(members, '') AS members, vlan_id, COALESCE(vlan_link, '') AS vlan_link,
	COALESCE(addressing, '') AS addressing, mtu,
	COALESCE(bond_mode, '') AS bond_mode, COALESCE(lacp_rate, '') AS lacp_rate,
	COALESCE(hash_policy, '') AS hash_policy, state, generation,
	COALESCE(last_error, '') AS last_error, created_at, updated_at
	FROM host_networks`

func scanHostNetwork(r Row) HostNetworkRecord {
	rec := HostNetworkRecord{
		HostName:   r.String("host_name"),
		Name:       r.String("name"),
		Kind:       r.String("kind"),
		VLANID:     int(r.Int64("vlan_id")),
		VLANLink:   r.String("vlan_link"),
		Addressing: r.String("addressing"),
		MTU:        int(r.Int64("mtu")),
		BondMode:   r.String("bond_mode"),
		LACPRate:   r.String("lacp_rate"),
		HashPolicy: r.String("hash_policy"),
		State:      r.String("state"),
		Generation: r.Int64("generation"),
		LastError:  r.String("last_error"),
		CreatedAt:  r.String("created_at"),
		UpdatedAt:  r.String("updated_at"),
	}
	if m := r.String("members"); m != "" {
		_ = json.Unmarshal([]byte(m), &rec.Members)
	}
	return rec
}
