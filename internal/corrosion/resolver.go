package corrosion

import (
	"strconv"
	"strings"
	"time"
)

// Equal-timestamp tie resolution.
//
// Strict last-writer-wins order (lwwOrder) decides every conflict where the two
// updated_at values differ. Only an EXACT tie (lwwOrder == 0) with differing
// content reaches resolveTie — the single entrypoint that converges, or
// deliberately refuses to converge, an equal-timestamp split.
//
// The root hazard (see PLAN.md / [[lww-equal-ts-repair-plan]]): the old code
// broke an exact tie by keeping local, which is node-local, not a cluster total
// order, so two different values for the same PK at the same updated_at never
// re-converged. A naive global fix (content-max everything) is WORSE: it can
// converge runtime ownership onto a non-running host, flip a tenancy/policy row
// to the more-permissive value, or resurrect a consumed recovery code.
//
// So resolution is table-aware. Every replicated table is assigned EXACTLY ONE
// ordered chain of rules in capabilityMap (enforced by TestCapabilityMap_*). On
// a tie the chain is walked in order; the first rule that yields a strict
// decision wins. A chain is a total order (so both nodes pick the same winner
// and converge) OR it ends by marking the row UNRESOLVED — keep local, count
// lww_tie_unresolved, alert, and let a human / runtime repair settle it. There
// is no implicit content-max fallback: a table reaches content-default only by
// explicit assignment.

// tieDecision is the outcome of one rule (or the whole chain).
type tieDecision struct {
	decided    bool   // terminal? if false, try the next rule
	keepLocal  bool   // when decided && !unresolved: keep local row vs take incoming
	unresolved bool   // when decided: no safe winner — keep local, track, alert
	resolver   string // metric label for the deciding rule (tombstone, content_max, …)
	category   string // metric label when unresolved (runtime_owned, tenancy, policy, …)
}

var (
	pass               = tieDecision{}
	decideKeepLocal    = func(r string) tieDecision { return tieDecision{decided: true, keepLocal: true, resolver: r} }
	decideTakeIncoming = func(r string) tieDecision { return tieDecision{decided: true, keepLocal: false, resolver: r} }
	decideUnresolved   = func(cat string) tieDecision { return tieDecision{decided: true, unresolved: true, category: cat} }
)

// rowView exposes a local/incoming row pair by column name, aligned to the
// incoming dump's declared columns (which may be a vN/v(N-1) subset).
type rowView struct {
	colIdx   map[string]int
	local    []interface{}
	incoming []interface{}
}

func newRowView(cols []string, local, incoming []interface{}) rowView {
	idx := make(map[string]int, len(cols))
	for i, c := range cols {
		idx[c] = i
	}
	return rowView{colIdx: idx, local: local, incoming: incoming}
}

func (rv rowView) has(col string) bool { _, ok := rv.colIdx[col]; return ok }

func (rv rowView) localStr(col string) string    { return cellStr(rv.local, rv.colIdx, col) }
func (rv rowView) incomingStr(col string) string { return cellStr(rv.incoming, rv.colIdx, col) }

func cellStr(row []interface{}, idx map[string]int, col string) string {
	i, ok := idx[col]
	if !ok || i >= len(row) || row[i] == nil {
		return ""
	}
	return coerceString(row[i])
}

// tieRule decides (or passes on) one aspect of a tie.
type tieRule func(rv rowView) tieDecision

// tableResolver is a table's single declared chain plus a short category name
// (used by the coverage test + docs to describe the table's headline behavior).
type tableResolver struct {
	category string
	chain    []tieRule
}

// ───────────────────────── rules ─────────────────────────

// ruleTombstone: a one-sided soft-delete wins (a delete must not be silently
// resurrected by a tied merge). Both-deleted or neither-deleted → pass (a
// both-deleted content difference falls through to content-max). No-ops when the
// table has no deleted_at column.
func ruleTombstone() tieRule {
	return func(rv rowView) tieDecision {
		if !rv.has("deleted_at") {
			return pass
		}
		lDel := rv.localStr("deleted_at") != ""
		iDel := rv.incomingStr("deleted_at") != ""
		switch {
		case lDel && !iDel:
			return decideKeepLocal("tombstone")
		case !lDel && iDel:
			return decideTakeIncoming("tombstone")
		default:
			return pass
		}
	}
}

// ruleColUnresolved: if the named column differs, the tie has no safe winner
// (runtime ownership, tenancy, auth-set pointer) → unresolved. Equal → pass.
func ruleColUnresolved(col, category string) tieRule {
	return func(rv rowView) tieDecision {
		if !rv.has(col) {
			return pass
		}
		if rv.localStr(col) != rv.incomingStr(col) {
			return decideUnresolved(category)
		}
		return pass
	}
}

// ruleAnyColUnresolved: if ANY of the named columns differ, the tie has no safe
// winner → unresolved. For tables (like hosts) that are content-default for
// benign telemetry but carry a few control-plane/safety columns where a
// content-max coin-flip would be unsafe. Columns absent from the dump's declared
// subset are skipped (mixed-schema safe).
func ruleAnyColUnresolved(cols []string, category string) tieRule {
	return func(rv rowView) tieDecision {
		for _, col := range cols {
			if rv.has(col) && rv.localStr(col) != rv.incomingStr(col) {
				return decideUnresolved(category)
			}
		}
		return pass
	}
}

// ruleNumericMax: integer-max on a monotonic ratchet column (e.g. user_2fa
// last_step — a TOTP replay guard that must never decrease). Equal → pass.
func ruleNumericMax(col string) tieRule {
	return func(rv rowView) tieDecision {
		if !rv.has(col) {
			return pass
		}
		l, lerr := strconv.ParseInt(strings.TrimSpace(rv.localStr(col)), 10, 64)
		i, ierr := strconv.ParseInt(strings.TrimSpace(rv.incomingStr(col)), 10, 64)
		if lerr != nil || ierr != nil || l == i {
			return pass
		}
		if l > i {
			return decideKeepLocal("numeric_max")
		}
		return decideTakeIncoming("numeric_max")
	}
}

// ruleTimestampMax: later parsed-instant wins (NOT lexical — a fixed-width
// fractional value sorts before a bare-second one). A set value beats an unset
// one. Equal instants → pass.
func ruleTimestampMax(col string) tieRule {
	return func(rv rowView) tieDecision {
		if !rv.has(col) {
			return pass
		}
		ls, is := rv.localStr(col), rv.incomingStr(col)
		if ls == is {
			return pass
		}
		lt, lok := parseInstant(ls)
		it, iok := parseInstant(is)
		switch {
		case lok && !iok:
			return decideKeepLocal("timestamp_max")
		case !lok && iok:
			return decideTakeIncoming("timestamp_max")
		case !lok && !iok:
			return pass
		case lt.Equal(it):
			return pass
		case lt.After(it):
			return decideKeepLocal("timestamp_max")
		default:
			return decideTakeIncoming("timestamp_max")
		}
	}
}

// ruleNonNullWins: a non-empty value beats an empty one (e.g. recovery_codes
// used_at — consuming a single-use code is irreversible). Both set / both empty
// → pass.
func ruleNonNullWins(col string) tieRule {
	return func(rv rowView) tieDecision {
		if !rv.has(col) {
			return pass
		}
		l := rv.localStr(col) != ""
		i := rv.incomingStr(col) != ""
		switch {
		case l && !i:
			return decideKeepLocal("non_null_wins")
		case !l && i:
			return decideTakeIncoming("non_null_wins")
		default:
			return pass
		}
	}
}

// ruleLBGeneration preserves the LB incarnation semantics (a per-incarnation
// opaque token, never value-ordered): equal → pass; a non-empty token beats an
// empty one (the COALESCE-on-upsert rule); two DIFFERENT non-empty tokens at the
// same updated_at have no valid ordering → unresolved (the render-time
// generation match already fails safe; the row divergence is surfaced).
func ruleLBGeneration(col string) tieRule {
	return func(rv rowView) tieDecision {
		if !rv.has(col) {
			return pass
		}
		lg, ig := rv.localStr(col), rv.incomingStr(col)
		switch {
		case lg == ig:
			return pass
		case lg != "" && ig == "":
			return decideKeepLocal("lb_generation")
		case lg == "" && ig != "":
			return decideTakeIncoming("lb_generation")
		default:
			return decideUnresolved("lb_token")
		}
	}
}

// ruleContentMax is the symmetric total-order terminal: the row whose canonical
// encoding is lexically greater wins. Deterministic and identical on both nodes,
// so it converges. Only tables with no authorization/isolation/runtime/auth
// meaning may end here (explicit assignment, enforced by coverage tests).
func ruleContentMax() tieRule {
	return func(rv rowView) tieDecision {
		if encodeRowCells(rv.local) >= encodeRowCells(rv.incoming) {
			return decideKeepLocal("content_max")
		}
		return decideTakeIncoming("content_max")
	}
}

// ruleUnresolved is a terminal that always refuses to converge (whole-table
// policy/auth tables, where any tied content difference is a fail-to-human).
func ruleUnresolved(category string) tieRule {
	return func(rv rowView) tieDecision { return decideUnresolved(category) }
}

func parseInstant(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// ───────────────────────── chains ─────────────────────────

// chain helpers for the common shapes.
//
// "Opaque" columns are large structured-blob workload/resource DEFINITIONS
// (vms.spec, containers.create_spec, networks.config, …). They must NEVER be
// content-max'd: the canonical encoder length-prefixes each cell, so content-max
// orders two specs by their length digits — an arbitrary, non-semantic tiebreak
// that (as seen in prod) can converge a whole cluster DOWN to one bystander's
// stale serialization, silently overwriting the live definition. A differing
// opaque column has no safe deterministic winner → unresolved (keep local +
// alert), and a human / runtime repair makes one side authoritative.
func contentDefaultChain() []tieRule { return []tieRule{ruleTombstone(), ruleContentMax()} }
func contentOpaqueChain(opaqueCols ...string) []tieRule {
	chain := []tieRule{ruleTombstone()}
	if len(opaqueCols) > 0 {
		chain = append(chain, ruleAnyColUnresolved(opaqueCols, "opaque"))
	}
	return append(chain, ruleContentMax())
}
func tenancyOpaqueChain(projectCol string, opaqueCols ...string) []tieRule {
	chain := []tieRule{ruleColUnresolved(projectCol, "tenancy"), ruleTombstone()}
	if len(opaqueCols) > 0 {
		chain = append(chain, ruleAnyColUnresolved(opaqueCols, "opaque"))
	}
	return append(chain, ruleContentMax())
}
func policyChain() []tieRule { return []tieRule{ruleTombstone(), ruleUnresolved("policy")} }
func authPointerChain(pointerCol string) []tieRule {
	return []tieRule{ruleTombstone(), ruleColUnresolved(pointerCol, "auth_pointer"), ruleContentMax()}
}
func lbChain() []tieRule {
	return []tieRule{ruleTombstone(), ruleLBGeneration("generation"), ruleContentMax()}
}

// capabilityMap assigns every AE-repaired table (the union of tableNames and
// sensitiveTableNames) exactly one resolver chain. AE-excluded tables
// (antiEntropyExcluded) deliberately have NO entry — they keep their existing
// lease/self-correcting behavior and never reach the resolver. The coverage
// tests enforce: capabilityMap keys == tableNames ∪ sensitiveTableNames, and a
// schema table is in exactly one of {capabilityMap, antiEntropyExcluded}.
var capabilityMap = map[string]tableResolver{
	// Runtime-owned: an ownership column on the PK row. host_name diff or a
	// tenancy diff has no safe row-level winner → defer to runtime repair / human.
	"vms": {category: "runtime-owned", chain: []tieRule{
		ruleColUnresolved("host_name", "runtime_owned"),
		ruleColUnresolved("project", "tenancy"),
		ruleTombstone(),
		ruleAnyColUnresolved([]string{"spec"}, "opaque"), // never content-max the VM definition
		ruleContentMax(),
	}},
	// containers: host_name is part of the PK (an ownership split is two distinct
	// rows the per-PK resolver can't see — Phase 4 runtime re-key handles it), so
	// only the tenancy column needs a carve-out here. create_spec is the
	// relocation-critical definition blob → opaque.
	"containers": {category: "tenancy-content", chain: tenancyOpaqueChain("project", "create_spec")},

	// Tenancy-bearing, otherwise content-default. config is the resource
	// definition blob → opaque (storage_pools has only scalar columns).
	"networks":         {category: "tenancy-content", chain: tenancyOpaqueChain("project", "config")},
	"storage_pools":    {category: "tenancy-content", chain: tenancyOpaqueChain("project")},
	"volumes":          {category: "tenancy-content", chain: tenancyOpaqueChain("project", "config")},
	"backup_schedules": {category: "tenancy-content", chain: tenancyOpaqueChain("project_name")},

	// Whole-table policy / authorization / accounting — content-max could
	// converge to the more-permissive value (privilege/isolation regression) or
	// resurrect a deleted grant. Tombstone-delete wins; any other tied difference
	// is unresolved (fail-to-human). Secret-bearing config tables join here too.
	"roles":                  {category: "policy", chain: policyChain()},
	"role_bindings":          {category: "policy", chain: policyChain()},
	"users":                  {category: "policy", chain: policyChain()},
	"tokens":                 {category: "policy", chain: policyChain()},
	"projects":               {category: "policy", chain: policyChain()},
	"project_quotas":         {category: "policy", chain: policyChain()},
	"security_groups":        {category: "policy", chain: policyChain()},
	"sg_rules":               {category: "policy", chain: policyChain()},
	"ip_sets":                {category: "policy", chain: policyChain()},
	"cluster_firewall_rules": {category: "policy", chain: policyChain()},
	"host_firewall_rules":    {category: "policy", chain: policyChain()},
	"firewall_defaults":      {category: "policy", chain: policyChain()},
	"registry_credentials":   {category: "policy", chain: policyChain()},
	"notification_targets":   {category: "policy", chain: policyChain()},
	"notification_routes":    {category: "policy", chain: policyChain()},

	// Auth factor/code tables — per-table converging rules, then fail-to-human.
	"user_2fa": {category: "auth", chain: []tieRule{
		ruleTombstone(),
		ruleNumericMax("last_step"),      // TOTP replay ratchet — never decrease
		ruleTimestampMax("last_used_at"), // informational, parsed-instant max
		ruleUnresolved("auth_factor"),    // a differing secret/epoch is fail-to-human
	}},
	"recovery_codes": {category: "auth", chain: []tieRule{
		ruleTombstone(),
		ruleNonNullWins("used_at"), // consume is irreversible
		ruleUnresolved("auth_factor"),
	}},
	// Active-set pointers: a tie naming two different live sets could re-expose a
	// superseded factor/code set → unresolved (never coin-flip).
	"user_2fa_sets":      {category: "auth-pointer", chain: authPointerChain("active_epoch")},
	"recovery_code_sets": {category: "auth-pointer", chain: authPointerChain("active_set_id")},

	// LB incarnation tokens.
	"lb_configs":  {category: "lb", chain: lbChain()},
	"lb_backends": {category: "lb", chain: lbChain()},

	// Content-default (explicitly assigned — no authorization/isolation/runtime/
	// auth meaning). Tombstone-delete wins, then symmetric content-max converges.
	"cluster": {category: "content", chain: contentDefaultChain()},
	// hosts is mostly content-default telemetry (cpu/mem/disk totals, labels,
	// version) BUT carries control-plane/safety columns where a content-max
	// coin-flip could pick a wrong fencing strategy, IPMI target, cert serial,
	// address/port, role, or schema version. Those differing → unresolved; a tie
	// in only the benign columns still converges by content-max.
	"hosts": {category: "host-control-plane", chain: []tieRule{
		ruleTombstone(),
		ruleAnyColUnresolved([]string{
			"state", "address", "ssh_user", "ssh_port", "grpc_port", "cert_serial",
			"ipmi_address", "ipmi_user", "ipmi_pass", "watchdog_dev", "fence_strategy",
			"role", "schema_version",
		}, "control_plane"),
		ruleContentMax(),
	}},
	"host_labels":             {category: "content", chain: contentDefaultChain()},
	"host_health":             {category: "content", chain: contentDefaultChain()},
	"images":                  {category: "content", chain: contentDefaultChain()},
	"image_hosts":             {category: "content", chain: contentDefaultChain()},
	"stacks":                  {category: "content", chain: contentOpaqueChain("spec", "compose_yaml")},
	"vm_interfaces":           {category: "content", chain: contentDefaultChain()},
	"vm_disks":                {category: "content", chain: contentDefaultChain()},
	"snapshots":               {category: "content", chain: contentDefaultChain()},
	"dns_records":             {category: "content", chain: contentDefaultChain()},
	"fencing_log":             {category: "content", chain: contentDefaultChain()},
	"audit_log":               {category: "content", chain: contentDefaultChain()},
	"network_vteps":           {category: "content", chain: contentDefaultChain()},
	"bgp_peers":               {category: "content", chain: contentDefaultChain()},
	"ip_allocations":          {category: "content", chain: contentDefaultChain()},
	"container_interfaces":    {category: "content", chain: contentDefaultChain()},
	"host_pci_devices":        {category: "content", chain: contentDefaultChain()},
	"resource_mappings":       {category: "content", chain: contentDefaultChain()},
	"service_endpoints":       {category: "content", chain: contentDefaultChain()},
	"backup_repos":            {category: "content", chain: contentDefaultChain()},
	"replication_checkpoints": {category: "content", chain: contentDefaultChain()},
	"vm_backups":              {category: "content", chain: contentDefaultChain()},
	"container_backups":       {category: "content", chain: contentDefaultChain()},
	"container_snapshots":     {category: "content", chain: contentDefaultChain()},
}

// resolveTiePath labels which replication path observed a tie (for metrics).
type resolveTiePath string

const (
	pathAE  resolveTiePath = "ae"
	pathWAL resolveTiePath = "wal"
)

// resolveTie decides an exact-timestamp tie for one row of `table`, over the
// incoming dump's declared `cols`. keepLocal=true means keep the local row (skip
// the incoming); false means take the incoming row. unresolved=true means the
// tie has no safe winner: it keeps local, is tracked (bounded — see
// trackUnresolved), and emits lww_tie_unresolved exactly once per distinct
// (table,PK,content-pair). A converging decision (unresolved=false) lets the
// caller clear any stale tracked entry for the PK.
func (c *Client) resolveTie(table string, cols []string, local, incoming []interface{}, pkIdx []int, path resolveTiePath) (keepLocal, unresolved bool) {
	tr, ok := capabilityMap[table]
	if !ok {
		// Unreachable if the coverage test passes; fail safe (keep local + alert).
		c.trackUnresolved(table, pkKeyAt(incoming, pkIdx), local, incoming, path, "uncategorized")
		return true, true
	}
	rv := newRowView(cols, local, incoming)
	for _, rule := range tr.chain {
		d := rule(rv)
		if !d.decided {
			continue
		}
		if d.unresolved {
			c.trackUnresolved(table, pkKeyAt(incoming, pkIdx), local, incoming, path, d.category)
			return true, true
		}
		c.observeTieBreak(table, d.resolver, winnerLabel(d.keepLocal))
		return d.keepLocal, false
	}
	// A well-formed chain always ends in a terminal rule, so this is unreachable;
	// keep local defensively.
	return true, true
}

func winnerLabel(keepLocal bool) string {
	if keepLocal {
		return "local"
	}
	return "incoming"
}
