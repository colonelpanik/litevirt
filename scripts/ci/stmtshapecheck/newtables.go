package main

import (
	"fmt"
	"go/token"
	"sort"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// THE FIRST REPLICATED SHAPE ON A TABLE IS THE ONE THAT BREAKS A ROLLING UPGRADE.
//
// Neither existing guard can see it. check-schema-bump.sh inspects DDL, so it
// says nothing about statements. check-ledger-drift.sh compares the ledgers
// against the merge-base and fails on a fingerprint that DISAPPEARED — a shape a
// prior-release peer still emits and this build would no longer recognise. A
// newly-ADDED fingerprint is invisible to both, and it is the dangerous
// direction: the receiver on the OLD binary is the one whose ledger misses, and
// its apply fails closed, rolls the whole batch back and stops advancing its
// watermark. That head-of-line blocks every later statement on that stream.
//
// A new shape on a table that ALREADY had replicated shapes is usually benign:
// the table's writers are already gated the way that table's feature is gated,
// and a widened builder is what the historical ledger and the legacy
// transformers exist for. The first-ever shape on a table is different. It comes
// with a new subsystem, so nothing about it is established yet — least of all
// whether the write is reachable before that subsystem's capability has latched
// cluster-wide.
//
// The finding that produced this guard: a startup heal wrote the very first
// `cluster` statement shape through the REPLICATED path, unconditionally, on
// every daemon start, with no capability gate — and it fired on every
// installation, because nothing had ever written that row. It bit the
// RECOMMENDED rollout specifically: pre-staging equalises the schema first, so
// the schema-skew refusal saw no gap and accepted the stream, leaving the
// binary-resident ledger as the only cross-version gate. A whole-branch review
// missed it and both CI guards were structurally blind to it.
//
// So: a table that had NO accepted replicated shape at the previous release, and
// has one now, must be acknowledged BY A HUMAN in firstShapeAcks below, naming
// what keeps the write off a previous-release peer's stream. The guard does not
// decide whether the gating is sound — it cannot — it decides that somebody
// looked.
//
// WHY A FROZEN BASELINE AND NOT A GIT DIFF. The question is "did the PREVIOUS
// RELEASE accept a shape on this table", and a release is exactly what the
// baseline below records. It also makes the guard deterministic and offline: no
// base revision to resolve, no shallow clone to fetch, the same answer in a
// dirty worktree as in CI, and no third copy of check-schema-bump.sh's
// base-resolution rules.

// replicatedTableBaseline is every table carrying at least one ACCEPTED
// replicated statement shape at the previous release — the union of that
// release's generated and historical ledgers, which is precisely the set of
// tables a peer on that binary can resolve a fingerprint for.
//
// FROZEN. It moves when a release is cut (regenerate it from that release's
// stmtledger_generated.go + stmtledger_historical.go), never to make a failing
// build pass: shifting the baseline forward is how the guard would be silenced
// on the exact change it exists to flag. Entries do not need removing when a
// table's shapes go away — a table the previous release accepted is not a new
// table, whatever this build does.
var replicatedTableBaseline = map[string]bool{
	"audit_chain_heads": true, "audit_key_lifecycle": true, "audit_log": true,
	"audit_signing_keys": true, "backup_repos": true, "backup_schedules": true,
	"clock_skew": true, "cluster_crl": true, "cluster_firewall_rules": true,
	"container_backups": true, "container_interfaces": true, "container_restarts": true,
	"container_snapshots": true, "containers": true, "crl_versions": true,
	"dns_records": true, "fencing_log": true, "firewall_defaults": true,
	"health_conditions": true, "health_evaluator_status": true,
	"host_capacity_observations": true, "host_firewall_rules": true, "host_health": true,
	"host_networks": true, "host_pci_devices": true, "host_runtime_usage": true,
	"hosts": true, "image_hosts": true, "images": true, "ip_allocations": true,
	"ip_sets": true, "lb_backends": true, "lb_configs": true, "leader_election": true,
	"network_vteps": true, "networks": true, "notification_routes": true,
	"notification_targets": true, "operation_steps": true, "operations": true,
	"project_authority_epochs": true, "project_quotas": true, "projects": true,
	"quota_reservations": true, "rebalance_proposals": true, "recovery_code_sets": true,
	"recovery_codes": true, "registry_credentials": true, "replication_checkpoints": true,
	"resource_mappings": true, "role_bindings": true, "roles": true,
	"runtime_action_proofs": true, "security_groups": true, "service_endpoints": true,
	"sessions": true, "sg_rules": true, "snapshots": true, "stacks": true,
	"storage_pools": true, "tokens": true, "user_2fa": true, "user_2fa_sets": true,
	"users": true, "vm_backups": true, "vm_disks": true, "vm_events": true,
	"vm_interfaces": true, "vm_locks": true, "vm_nics": true, "vm_pci_intent": true,
	"vm_pci_realizations": true, "vm_restarts": true, "vms": true,
}

// firstShapeAcks are the tables that gained their FIRST replicated statement
// shape since replicatedTableBaseline, each with the reviewed reason a
// previous-release peer never sees one of its statements.
//
// An acknowledgement is a permanent record of a decision, not a temporary
// suppression: it stays after the shape ages into a later baseline, because what
// it documents — how this table's writes are kept off an old peer's stream — is
// what a future reader needs before adding another writer. It is removed only
// when the table stops carrying replicated shapes altogether, which the guard
// checks so the list cannot quietly rot.
//
// A reason must name the MECHANISM. "It is new" is not one; neither is "it is
// only used by feature X" unless something stops feature X running mid-roll.
var firstShapeAcks = map[string]string{
	"netbox_bindings": "the row can only be created by validateAndBindPrefix, which requires " +
		"DurablyLatched(netbox_ipam_v1) — a latch that needs `netbox.enabled` on every " +
		"advertising node, so it cannot form while a peer is still on the old build. Every later " +
		"write (suspend/resume/re-key) needs an existing row, and the latch is monotone, so those " +
		"are post-latch too",
	"netbox_objects": "inventory-mirror writes, behind netboxMirrorAuthorized: the local " +
		"`netbox.mirror_inventory` flag AND DurablyLatched of BOTH netbox_mirror_v1 and " +
		"netbox_ipam_v1. The second latch is what proves every peer carries these v51 tables — " +
		"netbox_mirror_v1 alone cannot, since a cluster may opt into mirroring mid-roll",
	"netbox_sync_queue": "same mirror path and the same two durable latches as netbox_objects; " +
		"the orphan-check enqueues need a bound network, which itself required netbox_ipam_v1",
	"netbox_host_config": "published only through netboxClusterComparable, which returns " +
		"errNetBoxClusterNotYetComparable until DurablyLatched(netbox_ipam_v1) — the publication " +
		"is deliberately withheld until the latch makes it safe to replicate",
}

// tableShape is one builder statement reduced to what this guard decides on.
type tableShape struct {
	table string
	pos   token.Position
	fn    string
}

// firstShapeTables reduces the scan's findings to the (table, first site) pairs
// this guard decides on. The table comes from the SAME authoritative parse that
// generates the ledger (corrosion.LedgerEntryFor → parseResolved), not from a
// string scan and not from the ledger's own best-effort Table field.
//
// Statements that do not resolve are skipped: computeGaps already fails those,
// and a second failure naming the same line would only obscure the first.
func firstShapeTables(findings []finding) []tableShape {
	seen := map[string]bool{}
	var out []tableShape
	for _, f := range findings {
		if f.unresolvedBatch || f.dynamic || f.parseErr != "" {
			continue
		}
		le, err := corrosion.LedgerEntryFor(f.sql)
		if err != nil || le.Table == "" || seen[le.Table] {
			continue
		}
		seen[le.Table] = true
		out = append(out, tableShape{table: le.Table, pos: f.pos, fn: f.fn})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].table < out[j].table })
	return out
}

// newTableShapeGaps is the guard's decision, split from the scan so it is
// unit-testable (mirroring computeGaps and unreachableFrom).
func newTableShapeGaps(shapes []tableShape, baseline map[string]bool, acks map[string]string) []string {
	var gaps []string

	present := map[string]bool{}
	for _, s := range shapes {
		present[s.table] = true
	}

	// Anti-rot: an acknowledgement for a table that no longer carries any
	// replicated shape describes nothing, so it must go rather than sit there
	// vouching for a table whose writers have all been deleted or renamed.
	names := make([]string, 0, len(acks))
	for table := range acks {
		names = append(names, table)
	}
	sort.Strings(names)
	for _, table := range names {
		if !present[table] {
			gaps = append(gaps, fmt.Sprintf(
				"firstShapeAcks acknowledges %q but no builder emits a replicated statement on "+
					"that table any more — remove the acknowledgement", table))
			continue
		}
		if acks[table] == "" {
			gaps = append(gaps, fmt.Sprintf(
				"firstShapeAcks[%q] has an empty reason — it must name what keeps this table's "+
					"writes off a previous-release peer's replication stream", table))
		}
	}

	for _, s := range shapes {
		if baseline[s.table] || acks[s.table] != "" {
			continue
		}
		where := loc(s.pos)
		if s.fn != "" {
			where += " (" + s.fn + ")"
		}
		gaps = append(gaps, fmt.Sprintf(
			"%s: %q had NO accepted replicated statement shape at the previous release and has one "+
				"now. A peer still on that release cannot resolve the fingerprint: its apply fails "+
				"closed, the whole batch rolls back and its replication watermark stalls, which "+
				"head-of-line blocks the stream into every not-yet-rolled node. Decide what keeps "+
				"this write off that stream — a capability latch that cannot form mid-roll, or a "+
				"local-only write for a table anti-entropy already carries — then record it in "+
				"firstShapeAcks. If nothing does, the write must not replicate",
			where, s.table))
	}
	return gaps
}
