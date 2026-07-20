package corrosion

import "strings"

// Historical shape families: parameterized generators for the statement shapes a SUPPORTED
// PRIOR release emits that the CURRENT tree no longer emits (because the builders were made
// static), so their fingerprints aren't produced by scanning current source. They are
// enumerated here as versioned, parameterized FAMILIES (not a hand-written fingerprint list)
// and expanded into checked-in historical ledger entries by
// `stmtshapecheck -emit-historical` → stmtledger_historical.go. The checked-in entries are the
// authorization decision; this generator is only a generation aid.
//
// Each family is gated to the release that emits it (FirstEmitter) and a RemovalHorizon after
// which, once no supported peer emits it, the entries may be removed (a CI rule forbids
// removing an entry whose emitter is still supported).

const emitterV130 = "v1.3.0"

// HistoricalShape is one expanded historical statement plus its provenance.
type HistoricalShape struct {
	SQL          string
	Family       string // policy/family id, for grouping + the no-delete rule
	FirstEmitter string // earliest supported release that emits it
	LastEmitter  string // latest release that emits it ("" ⇒ still emitted by a supported release)
	Removal      string // release after which the entry may be removed once unused
}

// configureHostFieldsV130 is v1.3.0 ConfigureHost's SET field append order. Its dynamic SET
// list is any NON-EMPTY subset of these (in this order), always followed by updated_at.
var configureHostFieldsV130 = []string{
	"fence_strategy", "ipmi_address", "ipmi_user", "ipmi_pass", "watchdog_dev", "role", "region",
}

// HistoricalShapes returns every prior-release shape family the current tree stopped emitting,
// fully expanded. Deterministic + duplicate-free is the emitter's concern (the generator dedups
// by fingerprint).
func HistoricalShapes() []HistoricalShape {
	var out []HistoricalShape
	add := func(sql, family string) {
		out = append(out, HistoricalShape{SQL: sql, Family: family, FirstEmitter: emitterV130, Removal: "after " + emitterV130 + " unsupported"})
	}

	// ConfigureHost (v1.3.0): UPDATE hosts SET <non-empty subset of fields>, updated_at = ?
	// WHERE name = ?. 2^7-1 = 127 variants — a parameterized policy expansion, not a list.
	n := len(configureHostFieldsV130)
	for mask := 1; mask < (1 << n); mask++ {
		sets := make([]string, 0, n+1)
		for i := 0; i < n; i++ {
			if mask&(1<<i) != 0 {
				sets = append(sets, configureHostFieldsV130[i]+" = ?")
			}
		}
		sets = append(sets, "updated_at = ?")
		add("UPDATE hosts SET "+strings.Join(sets, ", ")+" WHERE name = ?", "configure_host_v130")
	}

	// DeleteStackFirewall (v1.3.0): one bulk tombstone per firewall table by stack_name.
	for _, tbl := range []string{"ip_sets", "cluster_firewall_rules", "host_firewall_rules", "firewall_defaults"} {
		add("UPDATE "+tbl+" SET deleted_at = ?, updated_at = ? WHERE stack_name = ? AND deleted_at IS NULL", "stack_firewall_teardown_v130")
	}

	// RenameVM (v1.3.0): bulk rekey cascades by the old vm_name (row-scoped in the current tree).
	for _, tbl := range []string{"vm_interfaces", "vm_disks", "ip_allocations"} {
		add("UPDATE "+tbl+" SET vm_name = ?, updated_at = ? WHERE vm_name = ?", "vm_rename_v130")
	}

	// migrateLegacyNetworkNames (v1.3.0): bulk rekey cascades by the old network name.
	add("UPDATE network_vteps SET network_name = ?, updated_at = ? WHERE network_name = ? AND deleted_at IS NULL", "network_rename_v130")
	add("UPDATE ip_allocations SET network = ?, updated_at = ? WHERE network = ? AND deleted_at IS NULL", "network_rename_v130")
	add("UPDATE vm_interfaces SET network_name = ?, updated_at = ? WHERE network_name = ? AND deleted_at IS NULL", "network_rename_v130")

	// InsertDisk (v1.3.0..): the vm_disks hot-plug/create upsert BEFORE its column list widened
	// to carry the per-disk hardware fields (bus, device_kind, delete_with_vm, controller_model).
	// Supported peers still emit this narrower shape while the current tree emits the wider one, so
	// the narrow shape is historical-only and must stay registered for the rolling-upgrade horizon.
	add(`INSERT OR REPLACE INTO vm_disks
		 (vm_name, disk_name, host_name, path, size_bytes, backing_image,
		  storage_type, storage_volume, target_dev, backing_disk, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`, "vm_disks_insert_v130")

	return out
}
