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

	// InsertHost (v1.3.0): the column list before per-host capacity policy (v43)
	// added cpu_overcommit/mem_overcommit/cpu_reserve/mem_reserve_mib. A v1.3.0
	// peer still emits the shorter INSERT, and an upgraded receiver that no longer
	// recognises it would back-pressure a perfectly valid statement and stall that
	// peer's stream.
	add("INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial,\n\t\t\tcpu_total, mem_total, disk_total, fence_strategy, version, role, created_at, updated_at)\n\t\t VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", "insert_host_v130")

	// InsertHost (schema v43): the intermediate shape after per-host capacity
	// overrides were added and before v44 appended capacity_policy_hash. Peers
	// running that schema still emit this statement during a rolling upgrade.
	add(`INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial,
			cpu_total, mem_total, disk_total, fence_strategy, version, role,
			cpu_overcommit, mem_overcommit, cpu_reserve, mem_reserve_mib,
			created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, "insert_host_v43")

	// ConfigureHost fixed shape (pre-v43): the single COALESCE UPDATE before the
	// per-host capacity policy added cpu_overcommit/mem_overcommit/cpu_reserve/
	// mem_reserve_mib. Same hazard as insert_host_v130: a prior-release peer
	// still emits the 7-column shape, and an upgraded receiver that no longer
	// recognises it would back-pressure a valid ConfigureHost and stall that
	// peer's stream.
	add(`UPDATE hosts SET `+
		`fence_strategy = COALESCE(?, fence_strategy), `+
		`ipmi_address = COALESCE(?, ipmi_address), `+
		`ipmi_user = COALESCE(?, ipmi_user), `+
		`ipmi_pass = COALESCE(?, ipmi_pass), `+
		`watchdog_dev = COALESCE(?, watchdog_dev), `+
		`role = COALESCE(?, role), `+
		`region = COALESCE(?, region), `+
		`updated_at = ? `+
		`WHERE name = ?`, "configure_host_fixed_v130")

	// Schema v44 widened these three builders with receiver-visible lifecycle
	// and routing columns. Keep the v1.3.0 shapes accepted for the supported
	// rolling-upgrade/WAL-retention horizon; receiver-only v44 columns retain
	// their defaults or existing values through the column-preserving apply.
	add(`INSERT INTO vms (name, stack_name, host_name, spec, state, state_detail,
				cpu_actual, mem_actual, project, is_template, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, "insert_vm_pre_authority")
	// Workload deletes became owner/generation guarded. Older retained WAL
	// entries remain valid ordinary LWW tombstones during the support horizon.
	add(legacyVMDeleteSQL, "delete_vm_pre_authority")
	add(legacyContainerDeleteSQL, "delete_container_pre_authority")
	add(legacyContainerStrictDeleteSQL, "delete_container_strict_pre_authority")
	add(`INSERT INTO containers (host_name, name, state, image, cpu_limit, memory_mib, labels, restart_policy, state_detail, project, is_template, on_host_failure, create_spec, relocate_token, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(host_name, name) DO UPDATE SET
		   state = excluded.state,
		   image = excluded.image,
		   cpu_limit = excluded.cpu_limit,
		   memory_mib = excluded.memory_mib,
		   labels = excluded.labels,
		   restart_policy = excluded.restart_policy,
		   state_detail = excluded.state_detail,
		   project = excluded.project,
		   is_template = excluded.is_template,
		   on_host_failure = excluded.on_host_failure,
		   -- Keep an existing create_spec when the caller didn't supply one, so a
		   -- generic upsert can't wipe the create-time intent (it's "current
		   -- intent", forward-only).
		   create_spec = CASE WHEN excluded.create_spec <> '' THEN excluded.create_spec ELSE create_spec END,
		   relocate_token = excluded.relocate_token,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`, "containers_upsert_v130")
	add(`INSERT OR REPLACE INTO containers
		 (host_name, name, state, image, cpu_limit, memory_mib, labels, restart_policy, state_detail, project, is_template, on_host_failure, create_spec, relocate_token, created_at, updated_at, deleted_at)
		 VALUES (?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`, "containers_rekey_v130")
	add(`INSERT OR REPLACE INTO notification_routes (id, event_pattern, target_id, min_severity, enabled, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`, "notification_routes_insert_v130")

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

	// ReleasePCIDevicesByVM (pre-branch): cluster-wide clear of a VM's PCI ownership by
	// vm_name. The current tree releases per-device host+owner-scoped (ReleasePCIDevice) so a
	// whole-VM teardown never clears a remote host's ownership without unbinding there.
	// Supported peers still emit the cluster-wide shape, so it stays historical-only for the
	// rolling-upgrade horizon.
	add("UPDATE host_pci_devices SET vm_name = NULL, updated_at = ? WHERE vm_name = ?", "pci_release_by_vm_v130")

	return out
}
