package corrosion

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// Divergence scanner engine (Phase 0 — read-only). This file is the PURE
// comparison/classification core: it takes per-node row metadata already
// collected by the gRPC gatherer and reports row-level divergence classes plus
// cluster-wide semantic-invariant violations. No DB, no RPC, no I/O — so it is
// exhaustively unit-testable, and the same logic runs identically on every node.
//
// Two framing points from the plan:
//   - A cluster can CONVERGE (all nodes hold identical rows, digests match) to a
//     state that is jointly illegal — e.g. two live container rows (host-a,ct) and
//     (host-b,ct). Row-divergence detection can't see that; the semantic-invariant
//     checks below do.
//   - Sensitive tables never expose raw PKs or plaintext: their row labels/hashes
//     are domain-separated keyed HMACs (ScanHMAC), computed per-node with one
//     shared per-scan key so identical rows match across nodes without leaking
//     content.

// DivergenceClass categorizes a single row's disagreement across nodes.
type DivergenceClass string

const (
	// ClassEqualUpdatedAtDifferentContent is THE pathological tie: same PK, same
	// updated_at on every node, different content — the LWW keep-local split that
	// never re-converges.
	ClassEqualUpdatedAtDifferentContent DivergenceClass = "equal_updated_at_different_content"
	// ClassDifferentUpdatedAt is usually lag / in-flight replication; promoted to
	// stuck_different by the orchestrator only if it persists across resamples.
	ClassDifferentUpdatedAt DivergenceClass = "different_updated_at"
	// ClassStuckDifferent is a different_updated_at that survived resampling after
	// watermark catch-up — a converged-wrong or lost-write split.
	ClassStuckDifferent DivergenceClass = "stuck_different"
	// ClassMissingRow: the PK exists on some nodes, absent on others.
	ClassMissingRow DivergenceClass = "missing_row"
	// ClassTombstoneVsLive: some nodes have the row tombstoned (deleted_at set),
	// others live.
	ClassTombstoneVsLive DivergenceClass = "tombstone_vs_live"
	// ClassTerminalVsLive: a workload is in a terminal state on some nodes, live on
	// others.
	ClassTerminalVsLive DivergenceClass = "terminal_vs_live"
	// ClassSchemaShapeMismatch: the table's column set differs across nodes.
	ClassSchemaShapeMismatch DivergenceClass = "schema_shape_mismatch"
)

// RowMeta is one node's view of one row. RowHash is over the canonical row
// encoding (encodeRowCells) for operator-safe tables, or a keyed HMAC for
// sensitive tables — the engine only compares it for equality, never interprets
// it, so both lanes share this type.
type RowMeta struct {
	UpdatedAt string // raw updated_at (RFC3339 or HLC) as stored
	RowHash   string // hash/HMAC of the canonical row encoding
	Deleted   bool   // deleted_at non-null (tombstone)
	State     string // optional state column (for terminal_vs_live); "" if N/A
}

// TableSnapshot is one node's view of one table: its column shape plus row
// metadata keyed by the composed PK label (plaintext PK for operator-safe tables,
// HMAC for sensitive).
type TableSnapshot struct {
	Columns []string           // ordered column names, for schema-shape comparison
	Rows    map[string]RowMeta // pkLabel → meta
}

// NodeSnapshot is one node's full contribution to a scan.
type NodeSnapshot struct {
	Host   string
	Tables map[string]TableSnapshot // table → snapshot
}

// RowDivergence is one diverging row reported to the operator.
type RowDivergence struct {
	Table   string                `json:"table"`
	PKLabel string                `json:"pk"`     // plaintext PK, or HMAC for sensitive tables
	Class   DivergenceClass       `json:"class"`
	PerNode map[string]RowMeta    `json:"per_node"` // host → meta (only nodes where it matters)
}

// SemanticViolation is a cluster-wide invariant breach that survives convergence
// (matching digests, yet jointly illegal).
type SemanticViolation struct {
	Kind   string   `json:"kind"`   // e.g. "duplicate_live_container", "duplicate_ip_owner"
	Key    string   `json:"key"`    // the offending identity (name / ip)
	Detail string   `json:"detail"` // human description
	Hosts  []string `json:"hosts"`  // hosts involved
}

// terminalStates lists the per-table state-column values treated as "terminal"
// (a workload not actively running). A terminal-on-one / live-on-another split is
// ClassTerminalVsLive. Tables not listed have no terminal notion.
var terminalStates = map[string]map[string]bool{
	"vms":        {"stopped": true, "error": true, "crashed": true},
	"containers": {"stopped": true, "error": true},
}

func isTerminalState(table, state string) bool {
	if state == "" {
		return false
	}
	if m, ok := terminalStates[table]; ok {
		return m[state]
	}
	return false
}

// ClassifyTable compares one table across all node snapshots and returns the set
// of diverging rows. A row present and byte-identical on every node is omitted.
// nodes is the full set of hosts in the scan (so a row missing on some is
// detected as ClassMissingRow).
func ClassifyTable(table string, nodes []string, snaps map[string]NodeSnapshot) []RowDivergence {
	// schema-shape: if the column set differs across nodes that have the table,
	// report one table-level divergence and stop (row comparison is unreliable).
	if shapes := distinctColumnShapes(table, nodes, snaps); len(shapes) > 1 {
		per := map[string]RowMeta{}
		for _, h := range nodes {
			if ts, ok := snaps[h].Tables[table]; ok {
				per[h] = RowMeta{RowHash: joinCols(ts.Columns)}
			}
		}
		return []RowDivergence{{Table: table, PKLabel: "(table)", Class: ClassSchemaShapeMismatch, PerNode: per}}
	}

	// Union of all PK labels seen for this table.
	pkSet := map[string]struct{}{}
	for _, h := range nodes {
		for pk := range snaps[h].Tables[table].Rows {
			pkSet[pk] = struct{}{}
		}
	}

	var out []RowDivergence
	for pk := range pkSet {
		perNode := map[string]RowMeta{}
		for _, h := range nodes {
			if m, ok := snaps[h].Tables[table].Rows[pk]; ok {
				perNode[h] = m
			}
		}
		if class := classifyRow(table, perNode, len(nodes)); class != "" {
			out = append(out, RowDivergence{Table: table, PKLabel: pk, Class: class, PerNode: perNode})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PKLabel < out[j].PKLabel })
	return out
}

// classifyRow categorizes one PK's per-node metadata. Returns "" when converged
// (present and identical on every node). Precedence: missing > tombstone >
// terminal > equal-TS-content > different-TS.
func classifyRow(table string, perNode map[string]RowMeta, nodeCount int) DivergenceClass {
	if len(perNode) < nodeCount {
		return ClassMissingRow
	}
	if sameHash(perNode) {
		return "" // converged
	}
	if mixedBool(perNode, func(m RowMeta) bool { return m.Deleted }) {
		return ClassTombstoneVsLive
	}
	if mixedTerminal(table, perNode) {
		return ClassTerminalVsLive
	}
	if sameUpdatedAt(perNode) {
		return ClassEqualUpdatedAtDifferentContent
	}
	return ClassDifferentUpdatedAt
}

func sameHash(perNode map[string]RowMeta) bool {
	var first string
	set := false
	for _, m := range perNode {
		if !set {
			first, set = m.RowHash, true
			continue
		}
		if m.RowHash != first {
			return false
		}
	}
	return true
}

func sameUpdatedAt(perNode map[string]RowMeta) bool {
	var first string
	set := false
	for _, m := range perNode {
		if !set {
			first, set = m.UpdatedAt, true
			continue
		}
		if m.UpdatedAt != first {
			return false
		}
	}
	return true
}

// mixedBool reports whether pred is true for some nodes and false for others.
func mixedBool(perNode map[string]RowMeta, pred func(RowMeta) bool) bool {
	var sawT, sawF bool
	for _, m := range perNode {
		if pred(m) {
			sawT = true
		} else {
			sawF = true
		}
	}
	return sawT && sawF
}

// mixedTerminal reports a terminal-on-some / live-on-others split for table
// (non-terminal, non-empty state counts as live).
func mixedTerminal(table string, perNode map[string]RowMeta) bool {
	var sawTerminal, sawLive bool
	for _, m := range perNode {
		if m.State == "" {
			continue
		}
		if isTerminalState(table, m.State) {
			sawTerminal = true
		} else {
			sawLive = true
		}
	}
	return sawTerminal && sawLive
}

func distinctColumnShapes(table string, nodes []string, snaps map[string]NodeSnapshot) map[string]struct{} {
	shapes := map[string]struct{}{}
	for _, h := range nodes {
		if ts, ok := snaps[h].Tables[table]; ok && len(ts.Columns) > 0 {
			shapes[joinCols(ts.Columns)] = struct{}{}
		}
	}
	return shapes
}

func joinCols(cols []string) string {
	out := make([]byte, 0, 64)
	for i, c := range cols {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, c...)
	}
	return string(out)
}

// ── Domain-separated keyed HMACs for the sensitive lane ──────────────────────
//
// Sensitive PKs and row content are themselves secret (recovery_codes' PK
// includes a bcrypt hash), so the sensitive lane never returns raw values — only
// these keyed HMACs. The key is one random per-scan secret distributed to peers
// ONLY over peer-mTLS and never logged. Domain separation ("pk\0"/"row\0"/
// "digest\0" prefixes) ensures a label can't alias a row hash or a digest.

func scanHMAC(key []byte, domain, table, input string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write([]byte(table))
	mac.Write([]byte{0})
	mac.Write([]byte(input))
	return hex.EncodeToString(mac.Sum(nil))
}

// ScanPKLabel is the sensitive-row label: HMAC(key, "pk\0"+table+"\0"+pk).
func ScanPKLabel(key []byte, table, pk string) string { return scanHMAC(key, "pk", table, pk) }

// ScanRowHash is the sensitive-row content hash: HMAC(key, "row\0"+table+"\0"+enc).
func ScanRowHash(key []byte, table, rowEncoding string) string {
	return scanHMAC(key, "row", table, rowEncoding)
}

// EncodeRowCells exposes the frozen canonical row encoder to callers outside the
// package's digest path (the gRPC gatherer hashes operator-safe rows with it and
// feeds sensitive rows' encodings to ScanRowHash).
func EncodeRowCells(vals []interface{}) string { return encodeRowCells(vals) }

// ── Cluster-wide semantic invariants ─────────────────────────────────────────
//
// These catch states that survive convergence: every node holds the SAME rows
// (digests match, a dump-diff is clean), yet the rows are JOINTLY illegal. The
// canonical case is two live container rows (host-a,ct) and (host-b,ct) — a
// cross-PK ownership split the per-PK row resolver structurally cannot see.

// OwnedRow is a flattened ownership fact gathered (deduped by identity) from the
// operator-safe dumps for the semantic checks.
type OwnedRow struct {
	Host string // owning host (containers.host_name)
	Name string // workload name (containers.name) or owner identity
	IP   string // for IP-ownership checks; "" otherwise
}

// CheckLiveContainerNames flags any container NAME that is live on more than one
// host — the cross-host ownership split. rows is the union of all nodes' live
// (non-tombstoned) container rows; duplicate (host,name) pairs are deduped.
func CheckLiveContainerNames(rows []OwnedRow) []SemanticViolation {
	byName := map[string]map[string]struct{}{} // name → set of hosts
	for _, r := range rows {
		if byName[r.Name] == nil {
			byName[r.Name] = map[string]struct{}{}
		}
		byName[r.Name][r.Host] = struct{}{}
	}
	var out []SemanticViolation
	for name, hosts := range byName {
		if len(hosts) < 2 {
			continue
		}
		hs := sortedKeys(hosts)
		out = append(out, SemanticViolation{
			Kind:   "duplicate_live_container",
			Key:    name,
			Detail: "container name is live on multiple hosts (cross-host ownership split)",
			Hosts:  hs,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// CheckDuplicateIPOwners flags any IP claimed by more than one distinct owner
// across ip_allocations / interface rows. rows is the union of live allocations;
// Name carries the owner identity, IP the address.
func CheckDuplicateIPOwners(rows []OwnedRow) []SemanticViolation {
	byIP := map[string]map[string]struct{}{} // ip → set of owners
	for _, r := range rows {
		if r.IP == "" {
			continue
		}
		if byIP[r.IP] == nil {
			byIP[r.IP] = map[string]struct{}{}
		}
		byIP[r.IP][r.Name] = struct{}{}
	}
	var out []SemanticViolation
	for ip, owners := range byIP {
		if len(owners) < 2 {
			continue
		}
		out = append(out, SemanticViolation{
			Kind:   "duplicate_ip_owner",
			Key:    ip,
			Detail: "IP is owned by multiple workloads",
			Hosts:  sortedKeys(owners),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
