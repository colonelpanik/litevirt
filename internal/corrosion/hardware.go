package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// NICRecord represents a single VM network interface as read from either the
// v42 vm_nics table (the multi-NIC successor) or the legacy vm_interfaces
// table — the overlay's uniform row shape (see MergedVMNICs). UpdatedAt and
// DeletedAt are carried through from whichever table sourced the row so the
// overlay can apply the greatest-updated_at / tombstone-hides-the-winner rule
// without a second round-trip.
type NICRecord struct {
	VMName      string
	ID          string
	NetworkName string
	Model       string
	MAC         string
	Ordinal     int
	IP          string
	TapDevice   string
	// SecurityGroups is carried through verbatim as stored (JSON-encoded list
	// or empty) — this layer does not decode it; callers that need the list
	// form use decodeSGs like the legacy vm_interfaces accessors do.
	SecurityGroups string
	UpdatedAt      string
	DeletedAt      string
}

// DeterministicNICID derives a stable NIC id from (vmName, mac) — the first
// 32 hex chars (128 bits) of sha256(vmName + "\x00" + mac). It is a pure
// function of its inputs so every peer synthesizes the byte-identical id for
// a legacy vm_interfaces row, which is required for the vm_nics backfill to
// converge under replication (two nodes backfilling the same legacy NIC must
// produce the same vm_nics primary key, or the backfill creates duplicate rows
// instead of merging into one).
func DeterministicNICID(vmName, mac string) string {
	sum := sha256.Sum256([]byte(vmName + "\x00" + mac))
	return hex.EncodeToString(sum[:])[:32]
}

// UpsertNIC writes a vm_nics row keyed by (vm_name, id), replacing any
// existing row with the same key (INSERT OR REPLACE, mirroring InsertDisk /
// InsertInterface). Model defaults to "virtio" when unset, matching the
// synthesized default GetVMNICsRaw applies to legacy vm_interfaces rows.
// Clears deleted_at — an upsert of a previously-tombstoned id resurrects it,
// same as InsertInterface's re-attach semantics.
func UpsertNIC(ctx context.Context, c *Client, r NICRecord) error {
	now := c.NowTS()
	model := r.Model
	if model == "" {
		model = "virtio"
	}
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO vm_nics
		 (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		r.VMName, r.ID, r.NetworkName, model, r.MAC, r.Ordinal,
		nullIfEmpty(r.IP), nullIfEmpty(r.TapDevice), nullIfEmpty(r.SecurityGroups), now)
}

// TombstoneNIC soft-deletes a vm_nics row by (vm_name, id). Mirrors
// SoftDeleteInterfaceByMAC/DeleteVM: deleted_at is the wall-clock display
// marker, updated_at is the monotonic LWW conflict key.
func TombstoneNIC(ctx context.Context, c *Client, vmName, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_nics SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND id = ?`,
		nowRFC3339(), now, vmName, id)
}

// GetVMNICsRaw reads every row (live AND tombstoned — deleted_at is carried
// through, not filtered) for vmName from table, which must be "vm_nics" or
// "vm_interfaces". vm_interfaces has no id/model columns, so those rows
// synthesize ID via DeterministicNICID and default Model to "virtio".
//
// Tombstoned rows are intentionally included: this is the shared source both
// direct callers (which typically want live rows only — filter on
// DeletedAt == "") and MergedVMNICs (which needs the full live+tombstoned set
// from both tables to apply the greatest-updated_at overlay rule) read from.
func GetVMNICsRaw(ctx context.Context, c *Client, table, vmName string) ([]NICRecord, error) {
	switch table {
	case "vm_nics":
		rows, err := c.Query(ctx,
			`SELECT vm_name, id, network_name, model, mac, ordinal,
			        COALESCE(ip, '') AS ip, COALESCE(tap_device, '') AS tap_device,
			        COALESCE(security_groups, '') AS security_groups,
			        updated_at, COALESCE(deleted_at, '') AS deleted_at
			 FROM vm_nics WHERE vm_name = ?`, vmName)
		if err != nil {
			return nil, err
		}
		out := make([]NICRecord, len(rows))
		for i, r := range rows {
			out[i] = NICRecord{
				VMName:         r.String("vm_name"),
				ID:             r.String("id"),
				NetworkName:    r.String("network_name"),
				Model:          r.String("model"),
				MAC:            r.String("mac"),
				Ordinal:        r.Int("ordinal"),
				IP:             r.String("ip"),
				TapDevice:      r.String("tap_device"),
				SecurityGroups: r.String("security_groups"),
				UpdatedAt:      r.String("updated_at"),
				DeletedAt:      r.String("deleted_at"),
			}
		}
		return out, nil
	case "vm_interfaces":
		rows, err := c.Query(ctx,
			`SELECT vm_name, network_name, mac, ordinal,
			        COALESCE(ip, '') AS ip, COALESCE(tap_device, '') AS tap_device,
			        COALESCE(security_groups, '') AS security_groups,
			        updated_at, COALESCE(deleted_at, '') AS deleted_at
			 FROM vm_interfaces WHERE vm_name = ?`, vmName)
		if err != nil {
			return nil, err
		}
		out := make([]NICRecord, len(rows))
		for i, r := range rows {
			vmn := r.String("vm_name")
			mac := r.String("mac")
			out[i] = NICRecord{
				VMName:         vmn,
				ID:             DeterministicNICID(vmn, mac),
				NetworkName:    r.String("network_name"),
				Model:          "virtio",
				MAC:            mac,
				Ordinal:        r.Int("ordinal"),
				IP:             r.String("ip"),
				TapDevice:      r.String("tap_device"),
				SecurityGroups: r.String("security_groups"),
				UpdatedAt:      r.String("updated_at"),
				DeletedAt:      r.String("deleted_at"),
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("corrosion: GetVMNICsRaw: unknown NIC table %q", table)
	}
}

// nicKey groups vm_nics/vm_interfaces rows for the MergedVMNICs overlay. Two
// rows describe the same physical NIC iff they share (vm_name, mac) — mac is
// the only identifier the legacy table carries, so it is the only safe join
// key across both tables. mac is lower-cased before building the key (see
// nicJoinKey) so the two tables disagreeing on MAC letter-case still join as
// one NIC instead of emitting a duplicate; the stored/returned NICRecord.MAC
// value itself is never mutated.
type nicKey struct {
	vmName, mac string
}

// nicJoinKey builds the overlay's join key for r, normalizing MAC case so
// vm_nics/vm_interfaces rows for the same physical NIC always land in the
// same group even if the two tables disagree on letter-case.
func nicJoinKey(r NICRecord) nicKey {
	return nicKey{r.VMName, strings.ToLower(r.MAC)}
}

// MergedVMNICs is the transition-time overlay reconciling the v42 vm_nics
// table against the legacy vm_interfaces table into one NIC list, for callers
// that must see a consistent view while the fleet backfills vm_nics.
//
// Overlay rule: gather every live-or-tombstoned row for vmName from both
// tables, group by (vm_name, mac) (case-insensitively, via nicJoinKey), and
// within each group pick the row with the greatest updated_at, ordered via
// lwwOrder (see sync.go) rather than a raw string compare — updated_at
// becomes an HLC key once hlc_lww is enabled, and an HLC string sorts
// LEXICALLY BEFORE any legacy RFC3339 string, so a plain `>` would let a
// stale vm_interfaces row beat a chronologically newer vm_nics row. On an
// EXACT updated_at tie (lwwOrder == 0), the vm_nics row wins (it is the
// forward-looking source of truth once a writer has touched it). The winner
// is emitted only if its deleted_at is empty — a tombstoned winner hides the
// NIC entirely, even if the other table has an older LIVE row for the same
// mac (the newer tombstone is authoritative).
func MergedVMNICs(ctx context.Context, c *Client, vmName string) ([]NICRecord, error) {
	nics, err := GetVMNICsRaw(ctx, c, "vm_nics", vmName)
	if err != nil {
		return nil, err
	}
	ifaces, err := GetVMNICsRaw(ctx, c, "vm_interfaces", vmName)
	if err != nil {
		return nil, err
	}

	type candidate struct {
		rec      NICRecord
		fromNics bool
	}
	best := make(map[nicKey]candidate)

	consider := func(r NICRecord, fromNics bool) {
		k := nicJoinKey(r)
		cur, ok := best[k]
		if !ok {
			best[k] = candidate{r, fromNics}
			return
		}
		switch {
		case lwwOrder(r.UpdatedAt, cur.rec.UpdatedAt) > 0:
			best[k] = candidate{r, fromNics}
		case lwwOrder(r.UpdatedAt, cur.rec.UpdatedAt) == 0 && fromNics && !cur.fromNics:
			// Exact tie: vm_nics wins over vm_interfaces.
			best[k] = candidate{r, fromNics}
		}
	}

	for _, r := range ifaces {
		consider(r, false)
	}
	for _, r := range nics {
		consider(r, true)
	}

	out := make([]NICRecord, 0, len(best))
	for _, cand := range best {
		if cand.rec.DeletedAt == "" {
			out = append(out, cand.rec)
		}
	}
	return out, nil
}
