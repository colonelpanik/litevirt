package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pci"
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

// BridgeVMNICs materializes vmName's legacy vm_interfaces rows (and their
// tombstones) into the v42 vm_nics table, keyed by the deterministic (vm_name,
// mac) id. It is the per-VM step of the continuous transition-window bridge (see
// grpcapi.RunHardwareBridge): during a rolling upgrade an OLD peer still writes
// ONLY vm_interfaces, and this mirrors those writes into vm_nics so the overlay
// (MergedVMNICs) converges toward vm_nics completeness.
//
// It is strictly ONE-DIRECTIONAL (legacy → vm_nics; it NEVER writes vm_interfaces),
// so it can never affect an old peer, which ignores vm_nics entirely.
//
// It is IDEMPOTENT, CHURN-FREE, and NEVER REGRESSES vm_nics: a legacy row is
// mirrored only when the matching vm_nics row is ABSENT or STRICTLY OLDER
// (lwwOrder < 0). Once mirrored, the newer vm_nics conflict key suppresses further
// writes on subsequent passes, and a genuinely-newer vm_nics row (produced by a
// hardware_v2 writer, or a later bridge pass) is left untouched. A tombstoned
// legacy row tombstones a LIVE vm_nics counterpart; a tombstoned legacy row with no
// live vm_nics counterpart is a no-op (nothing to converge).
func BridgeVMNICs(ctx context.Context, c *Client, vmName string) error {
	ifaces, err := GetVMNICsRaw(ctx, c, "vm_interfaces", vmName)
	if err != nil {
		return err
	}
	if len(ifaces) == 0 {
		return nil
	}
	nics, err := GetVMNICsRaw(ctx, c, "vm_nics", vmName)
	if err != nil {
		return err
	}
	byID := make(map[string]NICRecord, len(nics))
	for _, n := range nics {
		byID[n.ID] = n
	}
	for _, iface := range ifaces {
		existing, have := byID[iface.ID]
		// Never regress: a vm_nics row already at least as new as the legacy row is
		// authoritative (a hardware_v2 writer, or a prior bridge pass) — skip.
		if have && lwwOrder(existing.UpdatedAt, iface.UpdatedAt) >= 0 {
			continue
		}
		if iface.DeletedAt == "" {
			// Live legacy NIC → materialize into vm_nics. Fields come through
			// GetVMNICsRaw's vm_interfaces projection (Model synthesized "virtio").
			if err := UpsertNIC(ctx, c, NICRecord{
				VMName:         iface.VMName,
				ID:             iface.ID,
				NetworkName:    iface.NetworkName,
				Model:          iface.Model,
				MAC:            iface.MAC,
				Ordinal:        iface.Ordinal,
				IP:             iface.IP,
				TapDevice:      iface.TapDevice,
				SecurityGroups: iface.SecurityGroups,
			}); err != nil {
				return err
			}
			continue
		}
		// Legacy row is a tombstone and newer than the vm_nics row: converge by
		// tombstoning a LIVE counterpart. If none exists (or it is already
		// tombstoned), there is nothing to converge.
		if have && existing.DeletedAt == "" {
			if err := TombstoneNIC(ctx, c, vmName, iface.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// ═══════════ PCI PASSTHROUGH: INTENT + REALIZATION ═══════════
//
// vm_pci_intent declares what a VM WANTS attached, expressed as a selector
// (not yet a resolved device); vm_pci_realizations records what actually got
// attached once the resolver matched the selector against
// host_pci_devices. Neither table has a legacy sibling, so — unlike
// vm_nics/vm_interfaces above — these accessors are plain live-only reads
// (deleted_at IS NULL), not an overlay.

// ClassifyPCISelector derives a vm_pci_intent row's selector_kind from a
// DeviceSpec by SEMANTIC PRECEDENCE — mapping → sriov → type/vendor →
// address — never by mere field presence. exclusiveKey (the host-pinning
// field persisted as vm_pci_intent.exclusive_key) is populated ONLY for kind
// "address": a mapping- or type/vendor-classified spec that also carries a
// resolved Address (e.g. copied back onto the spec by a prior realization)
// must NOT host-pin on that address — the address there is a resolution
// artifact, not a request, and pinning on it would wrongly force every
// future re-resolve onto the same host/device even though the selector
// itself is portable.
//
// For kind "address" the exclusiveKey is the NORMALIZED BDF
// (canonicalPCIAddress), NOT the raw lowercased string — it must equal the
// address branch of CanonicalPCISelector so the same physical device yields
// both the same device_id AND the same exclusive reservation regardless of the
// input form (short "41:00.0" vs full "0000:41:00.0", case, whitespace).
func ClassifyPCISelector(d *pb.DeviceSpec) (kind string, exclusiveKey *string) {
	switch {
	case d.Mapping != "":
		return "mapping", nil
	case d.Sriov:
		return "sriov", nil
	case d.Type != "" || d.Vendor != "":
		return "type", nil
	default:
		key := canonicalPCIAddress(d.Address)
		return "address", &key
	}
}

// canonicalPCIAddress normalizes a concrete PCI address to the single form
// shared by both the address-kind exclusive_key (ClassifyPCISelector) and the
// address branch of CanonicalPCISelector, so a physical BDF's device_id and its
// exclusive reservation agree regardless of input form. A malformed address
// (pci.CanonicalBDF !ok) falls back to a lowercased/trimmed form so it still
// yields a deterministic — if unnormalized — value rather than panicking.
func canonicalPCIAddress(addr string) string {
	if canon, ok := pci.CanonicalBDF(addr); ok {
		return canon
	}
	return strings.ToLower(strings.TrimSpace(addr))
}

// CanonicalPCISelector builds the string every peer must derive identically
// from a DeviceSpec, for use as the canonicalSelector argument to
// DeterministicPCIIntentID. It is SELECTOR-PRECEDENCE-AWARE, sharing
// ClassifyPCISelector's precedence (mapping → sriov → type/vendor →
// concrete-address): it captures ONLY the SEMANTIC request for the classified
// kind and is prefixed by that kind so two kinds can never collide.
//
// This is the COMMITTED foundation scheme, being DEFINED PRE-DEPLOYMENT (no
// live cluster yet holds vm_pci_intent rows, so there is no online migration):
//
//   - The id is name-INDEPENDENT — the vm_name is NOT part of the derivation
//     (DeterministicPCIIntentID takes no vmName), so a VM rename preserves the
//     device_id and the adoption audit's re-derive converges instead of forking.
//   - The id is resolution-artifact-INDEPENDENT for a PORTABLE selector
//     (mapping/sriov/type/vendor): the resolved Address (a per-host artifact
//     copied back onto the spec by a prior realization) is DELIBERATELY EXCLUDED,
//     so re-resolving the same selector on a different host does not change the id.
//   - A CONCRETE-ADDRESS selector hashes the NORMALIZED BDF (canonicalPCIAddress,
//     equal to the exclusive_key ClassifyPCISelector emits), so short/uppercase/
//     whitespace forms all fold to one id.
//
// proto.Marshal is deliberately NOT used here: wire encoding is not guaranteed
// byte-identical across peers or proto-library versions, whereas a plain string
// join is. The per-kind field set + ordering is part of the committed scheme;
// changing it post-deployment would require an online migration.
func CanonicalPCISelector(d *pb.DeviceSpec) string {
	switch {
	case d.Mapping != "":
		// Mapping semantics: the pool name plus the request-shaping fields. The
		// resolved Address is a per-host artifact and is EXCLUDED.
		return strings.Join([]string{
			"mapping",
			d.Mapping,
			d.MigProfile,
			strconv.Itoa(int(d.Namespace)),
			strconv.Itoa(int(d.Count)),
		}, "|")
	case d.Sriov:
		// SR-IOV request semantics: the parent PF / vendor / type it selects from,
		// plus request-shaping fields. Address EXCLUDED.
		return strings.Join([]string{
			"sriov",
			d.Type,
			d.Vendor,
			d.Parent,
			d.Model,
			d.MigProfile,
			strconv.Itoa(int(d.Namespace)),
			strconv.Itoa(int(d.Count)),
		}, "|")
	case d.Type != "" || d.Vendor != "":
		// Type/vendor request semantics. Address EXCLUDED.
		return strings.Join([]string{
			"type",
			d.Type,
			d.Vendor,
			d.Model,
			d.MigProfile,
			strconv.Itoa(int(d.Namespace)),
			strconv.Itoa(int(d.Count)),
		}, "|")
	default:
		// Concrete address: the normalized BDF IS the request identity.
		return strings.Join([]string{"address", canonicalPCIAddress(d.Address)}, "|")
	}
}

// DeterministicPCIIntentID derives a stable vm_pci_intent device_id from
// (canonicalSelector, occurrence) — the first 32 hex chars (128 bits) of
// sha256(canonicalSelector + "\x00" + strconv.Itoa(occurrence)). occurrence
// disambiguates a VM requesting the IDENTICAL selector more than once (e.g. two
// GPUs via the same type-selector): without mixing it in, both attaches would
// hash to the same device_id and collide on vm_pci_intent's (vm_name,
// device_id) primary key.
//
// The vm_name is NOT part of the derivation: the (vm_name, device_id) PK
// already scopes the row per-VM and the hostdev xml_alias is per-domain, so
// cross-VM device_id equality is harmless — and excluding the name is what lets
// a rename preserve the id and lets the adoption audit's unconditional
// re-derive+upsert converge onto the same row instead of forking a duplicate.
// It is a pure function of its inputs so every peer synthesizes the
// byte-identical id for the same selector + occurrence, which is required for
// the intent to converge under replication rather than fork into duplicate
// rows on different nodes.
func DeterministicPCIIntentID(canonicalSelector string, occurrence int) string {
	sum := sha256.Sum256([]byte(canonicalSelector + "\x00" + strconv.Itoa(occurrence)))
	return hex.EncodeToString(sum[:])[:32]
}

// PCIIntentRecord represents a single vm_pci_intent row: declared PCI
// passthrough intent for a VM, pending realization against
// host_pci_devices. SelectorKind/ExclusiveKey are the classification
// ClassifyPCISelector produces; ExclusiveKey is non-nil only when
// SelectorKind is "address" (see ClassifyPCISelector).
type PCIIntentRecord struct {
	VMName          string
	DeviceID        string
	HostName        string
	SelectorKind    string
	SelectorPayload string
	ExclusiveKey    *string
}

// UpsertPCIIntent writes a vm_pci_intent row keyed by (vm_name, device_id),
// replacing any existing row with the same key (INSERT OR REPLACE, mirroring
// UpsertNIC). Clears deleted_at — an upsert of a previously-tombstoned
// device_id resurrects it.
func UpsertPCIIntent(ctx context.Context, c *Client, r PCIIntentRecord) error {
	now := c.NowTS()
	var exclusiveKey interface{}
	if r.ExclusiveKey != nil {
		exclusiveKey = *r.ExclusiveKey
	}
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO vm_pci_intent
		 (vm_name, device_id, host_name, selector_kind, selector_payload, exclusive_key, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		r.VMName, r.DeviceID, r.HostName, r.SelectorKind, r.SelectorPayload, exclusiveKey, now)
}

// TombstonePCIIntent soft-deletes a vm_pci_intent row by (vm_name,
// device_id). Mirrors TombstoneNIC: deleted_at is the wall-clock display
// marker, updated_at is the monotonic LWW conflict key.
func TombstonePCIIntent(ctx context.Context, c *Client, vmName, deviceID string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_pci_intent SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND device_id = ?`,
		nowRFC3339(), now, vmName, deviceID)
}

// ListVMPCIIntents returns every LIVE (deleted_at IS NULL) vm_pci_intent row
// for vmName. vm_pci_intent has no legacy sibling — this is a plain
// live-only accessor, not an overlay.
func ListVMPCIIntents(ctx context.Context, c *Client, vmName string) ([]PCIIntentRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, device_id, host_name, selector_kind, selector_payload,
		        COALESCE(exclusive_key, '') AS exclusive_key
		 FROM vm_pci_intent WHERE vm_name = ? AND deleted_at IS NULL`, vmName)
	if err != nil {
		return nil, err
	}
	out := make([]PCIIntentRecord, len(rows))
	for i, r := range rows {
		out[i] = PCIIntentRecord{
			VMName:          r.String("vm_name"),
			DeviceID:        r.String("device_id"),
			HostName:        r.String("host_name"),
			SelectorKind:    r.String("selector_kind"),
			SelectorPayload: r.String("selector_payload"),
			ExclusiveKey:    strPtrOrNil(r.String("exclusive_key")),
		}
	}
	return out, nil
}

// PCIIntentExclusiveOwner returns the vm_name of the LIVE (deleted_at IS NULL)
// vm_pci_intent row that already holds (hostName, exclusiveKey), or "" when none
// does. It enforces the concrete-address passthrough exclusivity invariant: a
// given host BDF may back at most one VM's live intent, so a second VM claiming
// the same address is rejected before any bind. It is a plain read (no
// replicated write), so it introduces no new statement shape. exclusiveKey is the
// normalized BDF stored in vm_pci_intent.exclusive_key.
func PCIIntentExclusiveOwner(ctx context.Context, c *Client, hostName, exclusiveKey string) (string, error) {
	if exclusiveKey == "" {
		return "", nil
	}
	rows, err := c.Query(ctx,
		`SELECT vm_name FROM vm_pci_intent
		 WHERE host_name = ? AND exclusive_key = ? AND deleted_at IS NULL
		 LIMIT 1`, hostName, exclusiveKey)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("vm_name"), nil
}

// PCIRealizationRecord represents a single vm_pci_realizations row: the
// resolved outcome of a vm_pci_intent row — the concrete host device(s)
// actually attached. Ordinal orders multiple members realizing the same
// intent (e.g. an SR-IOV VF-pool selector realizing as several VFs).
type PCIRealizationRecord struct {
	VMName          string
	DeviceID        string
	MemberID        string
	HostName        string
	ResolvedAddress string
	XMLAlias        string
	Ordinal         int
}

// UpsertPCIRealization writes a vm_pci_realizations row keyed by (vm_name,
// device_id, member_id), replacing any existing row with the same key
// (INSERT OR REPLACE). Clears deleted_at — an upsert of a previously-
// tombstoned member resurrects it.
func UpsertPCIRealization(ctx context.Context, c *Client, r PCIRealizationRecord) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT OR REPLACE INTO vm_pci_realizations
		 (vm_name, device_id, member_id, host_name, resolved_address, xml_alias, ordinal, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		r.VMName, r.DeviceID, r.MemberID, r.HostName,
		nullIfEmpty(r.ResolvedAddress), nullIfEmpty(r.XMLAlias), r.Ordinal, now)
}

// TombstonePCIRealizations soft-deletes EVERY vm_pci_realizations row for
// (vm_name, device_id) — every member realizing that intent, not a single
// member_id. A re-resolve of an intent (e.g. the SR-IOV pool reassigning
// different VFs to the same request) must retract the whole prior
// realization set, not leave stale members mixed in alongside the new ones.
func TombstonePCIRealizations(ctx context.Context, c *Client, vmName, deviceID string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE vm_pci_realizations SET deleted_at = ?, updated_at = ? WHERE vm_name = ? AND device_id = ?`,
		nowRFC3339(), now, vmName, deviceID)
}

// ListVMPCIRealizations returns every LIVE (deleted_at IS NULL)
// vm_pci_realizations row for vmName. Like vm_pci_intent, this table has no
// legacy sibling — a plain live-only accessor, not an overlay.
func ListVMPCIRealizations(ctx context.Context, c *Client, vmName string) ([]PCIRealizationRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT vm_name, device_id, member_id, host_name,
		        COALESCE(resolved_address, '') AS resolved_address,
		        COALESCE(xml_alias, '') AS xml_alias, ordinal
		 FROM vm_pci_realizations WHERE vm_name = ? AND deleted_at IS NULL`, vmName)
	if err != nil {
		return nil, err
	}
	out := make([]PCIRealizationRecord, len(rows))
	for i, r := range rows {
		out[i] = PCIRealizationRecord{
			VMName:          r.String("vm_name"),
			DeviceID:        r.String("device_id"),
			MemberID:        r.String("member_id"),
			HostName:        r.String("host_name"),
			ResolvedAddress: r.String("resolved_address"),
			XMLAlias:        r.String("xml_alias"),
			Ordinal:         r.Int("ordinal"),
		}
	}
	return out, nil
}

// strPtrOrNil returns nil for an empty string, else a pointer to s. Used to
// turn a COALESCE(...,”)-read nullable column back into the *string shape
// PCIIntentRecord.ExclusiveKey exposes to callers.
func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
