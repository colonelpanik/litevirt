package corrosion

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/hlc"
)

// These tests pin the reported data-loss bug: a peer that is BEHIND on schema emits a
// row/statement that omits columns the receiver already populated. A whole-row
// INSERT OR REPLACE deletes the existing row and re-inserts only the supplied columns, so
// every receiver-only column resets to its default/NULL — silent data loss that only
// surfaces after the rolling upgrade completes. The fix is a PK-aware upsert that touches
// only the columns the sender supplied. role (NOT NULL DEFAULT 'worker') and ipmi_address
// (nullable) stand in for the newer control columns; ssh_port carries a numeric default.

// TestBuildMergeUpsertSQL pins the anti-entropy upsert builder's exact output.
func TestBuildMergeUpsertSQL(t *testing.T) {
	cases := []struct {
		name         string
		table        string
		cols, pkCols []string
		want         string
	}{
		{
			name: "single pk", table: "hosts",
			cols: []string{"name", "address", "updated_at"}, pkCols: []string{"name"},
			want: "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
		},
		{
			name: "composite pk", table: "host_labels",
			cols: []string{"host_name", "key", "value", "updated_at"}, pkCols: []string{"host_name", "key"},
			want: "INSERT INTO host_labels (host_name, key, value, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(host_name, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
		},
		{
			name: "all columns are pk", table: "t",
			cols: []string{"a", "b"}, pkCols: []string{"a", "b"},
			want: "INSERT INTO t (a, b) VALUES (?, ?) ON CONFLICT(a, b) DO NOTHING",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildMergeUpsertSQL(c.table, c.cols, c.pkCols); got != c.want {
				t.Errorf("buildMergeUpsertSQL:\n got %q\nwant %q", got, c.want)
			}
		})
	}
}

// TestInsertUpsertRewrite pins the WAL INSERT→upsert rewrite and its fail-closed invariants.
func TestInsertUpsertRewrite(t *testing.T) {
	cases := []struct {
		name         string
		sql          string
		nParams      int
		pkCols       []string
		hasUpdatedAt bool
		wantErr      bool
		want         string
	}{
		{
			name:    "plain insert (LWW)",
			sql:     "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?)",
			nParams: 3, pkCols: []string{"name"}, hasUpdatedAt: true,
			want: "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
		},
		{
			name:    "OR REPLACE normalized to plain",
			sql:     "INSERT OR REPLACE INTO hosts (name, address, updated_at) VALUES (?, ?, ?)",
			nParams: 3, pkCols: []string{"name"}, hasUpdatedAt: true,
			want: "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
		},
		{
			name:    "explicit ON CONFLICT with updated_at applied verbatim",
			sql:     "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
			nParams: 3, pkCols: []string{"name"}, hasUpdatedAt: true,
			want: "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
		},
		{
			name:    "trailing semicolon stripped",
			sql:     "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?);",
			nParams: 3, pkCols: []string{"name"}, hasUpdatedAt: true,
			want: "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
		},
		{
			// A trailing line comment must NOT swallow the appended ON CONFLICT clause: the
			// tail is spliced at the end of the VALUES tuple, dropping the comment.
			name:    "trailing line comment does not swallow tail",
			sql:     "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) -- note",
			nParams: 3, pkCols: []string{"name"}, hasUpdatedAt: true,
			want: "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
		},
		{
			// An ObservePCIDevice-shaped explicit partial upsert (literal '' / NULL cells,
			// updated_at advanced in SET, vm_name deliberately omitted) is applied verbatim.
			name:    "explicit partial upsert (ObservePCIDevice shape) verbatim",
			sql:     "INSERT INTO host_pci_devices (host_name, address, vm_name, updated_at, deleted_at) VALUES (?, ?, '', ?, NULL) ON CONFLICT(host_name, address) DO UPDATE SET updated_at = excluded.updated_at, deleted_at = NULL",
			nParams: 3, pkCols: []string{"host_name", "address"}, hasUpdatedAt: true,
			want: "INSERT INTO host_pci_devices (host_name, address, vm_name, updated_at, deleted_at) VALUES (?, ?, '', ?, NULL) ON CONFLICT(host_name, address) DO UPDATE SET updated_at = excluded.updated_at, deleted_at = NULL",
		},
		{
			name:    "non-LWW table needs no updated_at",
			sql:     "INSERT INTO t (id, val) VALUES (?, ?)",
			nParams: 2, pkCols: []string{"id"}, hasUpdatedAt: false,
			want: "INSERT INTO t (id, val) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET val = excluded.val",
		},
		{
			name:    "LWW insert omitting updated_at fails closed",
			sql:     "INSERT INTO hosts (name, address) VALUES (?, ?)",
			nParams: 2, pkCols: []string{"name"}, hasUpdatedAt: true, wantErr: true,
		},
		{
			name:    "explicit upsert not mentioning updated_at fails closed",
			sql:     "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address",
			nParams: 3, pkCols: []string{"name"}, hasUpdatedAt: true, wantErr: true,
		},
		{
			// Mentioning updated_at is not enough — a non-advancing self/literal assignment
			// must fail closed (finding 3).
			name:    "explicit upsert with updated_at = updated_at fails closed",
			sql:     "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = updated_at",
			nParams: 3, pkCols: []string{"name"}, hasUpdatedAt: true, wantErr: true,
		},
		{
			name:    "explicit upsert with updated_at = '' fails closed",
			sql:     "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = ''",
			nParams: 3, pkCols: []string{"name"}, hasUpdatedAt: true, wantErr: true,
		},
		{
			name:    "no full PK identity fails closed",
			sql:     "INSERT INTO hosts (address, updated_at) VALUES (?, ?)",
			nParams: 2, pkCols: []string{"name"}, hasUpdatedAt: true, wantErr: true,
		},
		{
			name:    "param arity mismatch fails closed",
			sql:     "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?)",
			nParams: 2, pkCols: []string{"name"}, hasUpdatedAt: true, wantErr: true,
		},
		{
			name:    "non-INSERT fails closed",
			sql:     "UPDATE hosts SET address = ? WHERE name = ?",
			nParams: 2, pkCols: []string{"name"}, hasUpdatedAt: true, wantErr: true,
		},
		{
			name:    "empty pkCols fails closed",
			sql:     "INSERT INTO t (a) VALUES (?)",
			nParams: 1, pkCols: nil, hasUpdatedAt: false, wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := Statement{SQL: c.sql, Params: make([]interface{}, c.nParams)}
			got, err := insertUpsertRewrite(s, c.pkCols, c.hasUpdatedAt)
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("rewrite:\n got %q\nwant %q", got, c.want)
			}
		})
	}
}

// TestMergeLWW_PreservesReceiverOnlyColumns covers the anti-entropy full-dump path.
func TestMergeLWW_PreservesReceiverOnlyColumns(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, ssh_port, cert_serial, role, ipmi_address, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"h1", "10.0.0.1", "operator", 2222, "serialX", "witness", "10.0.0.99",
		"2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// A behind sender's dump carries only the columns it knows, with a newer updated_at
	// that wins LWW on address.
	const newHLC = "2000000000000-0000-n2"
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "hosts",
		Columns: []string{"name", "address", "ssh_user", "cert_serial", "created_at", "updated_at"},
		Rows:    [][]interface{}{{"h1", "10.9.9.9", "operator", "serialX", "2020-01-01T00:00:00Z", newHLC}},
	}}})

	rows, err := c.Query(ctx, "SELECT address, role, ipmi_address, ssh_port FROM hosts WHERE name = ?", "h1")
	if err != nil || len(rows) == 0 {
		t.Fatalf("query: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].String("address"); got != "10.9.9.9" {
		t.Errorf("address = %q, want 10.9.9.9 (newer incoming must win)", got)
	}
	if got := rows[0].String("role"); got != "witness" {
		t.Errorf("role = %q, want witness (receiver-only column erased by whole-row replace)", got)
	}
	if got := rows[0].String("ipmi_address"); got != "10.0.0.99" {
		t.Errorf("ipmi_address = %q, want 10.0.0.99 (receiver-only column erased)", got)
	}
	if got := rows[0].Int("ssh_port"); got != 2222 {
		t.Errorf("ssh_port = %d, want 2222 (receiver-only column erased)", got)
	}
}

// TestMergeLWW_PreservesVMControlColumns is the concrete v41 case from the bug report: a
// v40 sender's dump omits the vms control columns (active_operation_id, spec_generation,
// vm_owner_epoch), which must survive the merge rather than reset to their defaults.
func TestMergeLWW_PreservesVMControlColumns(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := c.Execute(ctx,
		`INSERT INTO vms (name, host_name, spec, state, active_operation_id, spec_generation, vm_owner_epoch, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"vm1", "host-a", "{}", "running", "op-123", 5, 3,
		"2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const newHLC = "2000000000000-0000-n2"
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "vms",
		Columns: []string{"name", "host_name", "spec", "state", "created_at", "updated_at"},
		Rows:    [][]interface{}{{"vm1", "host-b", "{}", "stopped", "2020-01-01T00:00:00Z", newHLC}},
	}}})

	rows, err := c.Query(ctx, "SELECT state, active_operation_id, spec_generation, vm_owner_epoch FROM vms WHERE name = ?", "vm1")
	if err != nil || len(rows) == 0 {
		t.Fatalf("query: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].String("state"); got != "stopped" {
		t.Errorf("state = %q, want stopped (newer incoming wins)", got)
	}
	if got := rows[0].String("active_operation_id"); got != "op-123" {
		t.Errorf("active_operation_id = %q, want op-123 (v41 control column erased)", got)
	}
	if got := rows[0].Int("spec_generation"); got != 5 {
		t.Errorf("spec_generation = %d, want 5 (v41 control column erased)", got)
	}
	if got := rows[0].Int("vm_owner_epoch"); got != 3 {
		t.Errorf("vm_owner_epoch = %d, want 3 (v41 control column erased)", got)
	}
}

// TestMergeLWW_TombstonePreservesReceiverOnlyColumns confirms a winning tombstone (deleted_at
// set) from a behind sender still preserves columns the sender doesn't know about.
func TestMergeLWW_TombstonePreservesReceiverOnlyColumns(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, cert_serial, ipmi_address, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"h1", "10.0.0.1", "operator", "serialX", "10.0.0.99",
		"2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const newHLC = "2000000000000-0000-n2"
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "hosts",
		Columns: []string{"name", "address", "ssh_user", "cert_serial", "created_at", "updated_at", "deleted_at"},
		Rows:    [][]interface{}{{"h1", "10.0.0.1", "operator", "serialX", "2020-01-01T00:00:00Z", newHLC, newHLC}},
	}}})

	rows, err := c.Query(ctx, "SELECT deleted_at, ipmi_address FROM hosts WHERE name = ?", "h1")
	if err != nil || len(rows) == 0 {
		t.Fatalf("query: err=%v rows=%d", err, len(rows))
	}
	if rows[0].String("deleted_at") == "" {
		t.Error("deleted_at not set (tombstone must apply)")
	}
	if got := rows[0].String("ipmi_address"); got != "10.0.0.99" {
		t.Errorf("ipmi_address = %q, want 10.0.0.99 (receiver-only column erased by tombstone)", got)
	}
}

// TestApplyRemoteMutations_ParamArityBackPressure confirms a statement whose bound-parameter
// count doesn't match its params back-pressures instead of indexing out of range or binding
// wrong values.
func TestApplyRemoteMutations_ParamArityBackPressure(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	r := NewReplicator(c, "", RelayConfig{})
	ts := hlc.NewClock("origin-node").Now().String()

	// Three '?' placeholders, only two params.
	stmts := `[{"SQL":"INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?)","Params":["h1","10.0.0.1"]}]`
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: ts, Origin: "origin-node", Stmts: stmts}}

	if _, err := r.ApplyRemoteMutations(ctx, entries); err == nil {
		t.Fatal("expected back-pressure error for param arity mismatch")
	}
	assertNotSeen(t, c, "origin-node")
}

// TestMergeLWW_SecondaryUniqueKeepsLocal: an incoming snapshots row with a NEW primary key
// but a colliding UNIQUE(vm_name, name) must NOT delete-and-replace the local row (the old
// INSERT OR REPLACE behavior). The PK-aware upsert conflicts only on id, so the insert hits
// the secondary UNIQUE and the local row is kept.
func TestMergeLWW_SecondaryUniqueKeepsLocal(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := c.Execute(ctx,
		`INSERT INTO snapshots (id, vm_name, host_name, name, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"s1", "vm1", "host-a", "snapA", "ready", "2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const newHLC = "2000000000000-0000-n2"
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "snapshots",
		Columns: []string{"id", "vm_name", "host_name", "name", "state", "created_at", "updated_at"},
		Rows:    [][]interface{}{{"s2", "vm1", "host-b", "snapA", "ready", "2020-01-01T00:00:00Z", newHLC}},
	}}})

	rows, err := c.Query(ctx, "SELECT id, host_name FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snapA")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 snapshot row, got %d (whole-row replace across the UNIQUE?)", len(rows))
	}
	if got := rows[0].String("id"); got != "s1" {
		t.Errorf("id = %q, want s1 (local row must be kept, not replaced by the colliding incoming)", got)
	}
}

// TestMergeLWW_SecondaryUniqueRecordsRejectedMetric: an AE constraint rejection (keep-local)
// increments litevirt_merge_apply_rejected_total{table,path=ae,reason=constraint}.
func TestMergeLWW_SecondaryUniqueRecordsRejectedMetric(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	sm := &fakeSyncMetrics{}
	c.SetSyncMetrics(sm)

	if err := c.Execute(ctx,
		`INSERT INTO snapshots (id, vm_name, host_name, name, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"s1", "vm1", "host-a", "snapA", "ready", "2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	const newHLC = "2000000000000-0000-n2"
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "snapshots",
		Columns: []string{"id", "vm_name", "host_name", "name", "state", "created_at", "updated_at"},
		Rows:    [][]interface{}{{"s2", "vm1", "host-b", "snapA", "ready", "2020-01-01T00:00:00Z", newHLC}},
	}}})

	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.mergeRejected) != 1 || sm.mergeRejected[0] != "snapshots/ae/constraint" {
		t.Errorf("mergeRejected = %v, want [snapshots/ae/constraint]", sm.mergeRejected)
	}
}

// TestApplyRemoteMutations_SecondaryUniqueBackPressure: the same collision on the WAL path
// surfaces as a constraint error and MUST back-pressure (roll back, don't record seen), not
// silently drop the mutation.
func TestApplyRemoteMutations_SecondaryUniqueBackPressure(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := c.Execute(ctx,
		`INSERT INTO snapshots (id, vm_name, host_name, name, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"s1", "vm1", "host-a", "snapA", "ready", "2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := NewReplicator(c, "", RelayConfig{})
	ts := hlc.NewClock("origin-node").Now().String()
	stmts := fmt.Sprintf(
		`[{"SQL":"INSERT INTO snapshots (id, vm_name, host_name, name, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["s2","vm1","host-b","snapA","ready","2020-01-01T00:00:00Z","%s"]}]`, ts)
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: ts, Origin: "origin-node", Stmts: stmts}}

	if _, err := r.ApplyRemoteMutations(ctx, entries); err == nil {
		t.Fatal("expected back-pressure error for secondary-UNIQUE collision")
	}
	assertNotSeen(t, c, "origin-node")

	// Local row unchanged; nothing inserted.
	rows, err := c.Query(ctx, "SELECT id FROM snapshots WHERE vm_name = ? AND name = ?", "vm1", "snapA")
	if err != nil || len(rows) != 1 || rows[0].String("id") != "s1" {
		t.Fatalf("local snapshot must be intact (s1), got err=%v rows=%d", err, len(rows))
	}
}

// TestApplyRemoteMutations_EmptyStatements confirms a valid-but-empty statement list — both
// the [] and null JSON representations — back-pressures rather than being acknowledged.
func TestApplyRemoteMutations_EmptyStatements(t *testing.T) {
	for _, stmts := range []string{`[]`, `null`} {
		t.Run(stmts, func(t *testing.T) {
			c := mustTestClient(t)
			ctx := context.Background()
			r := NewReplicator(c, "", RelayConfig{})
			ts := hlc.NewClock("origin-node").Now().String()
			entries := []*pb.MutationEntry{{Seq: 1, Hlc: ts, Origin: "origin-node", Stmts: stmts}}
			if _, err := r.ApplyRemoteMutations(ctx, entries); err == nil {
				t.Fatalf("expected back-pressure error for empty statement list %q", stmts)
			}
			assertNotSeen(t, c, "origin-node")
		})
	}
}

// TestTableHasUpdatedAt covers the schema-introspection helper for known/unknown tables.
func TestTableHasUpdatedAt(t *testing.T) {
	c := mustTestClient(t)
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	ctx := context.Background()
	if has, err := tableHasUpdatedAt(ctx, tx, "hosts"); err != nil || !has {
		t.Errorf("hosts: has=%v err=%v, want true/nil", has, err)
	}
	if has, err := tableHasUpdatedAt(ctx, tx, "mutation_log"); err != nil || has {
		t.Errorf("mutation_log: has=%v err=%v, want false/nil (append-only, no updated_at)", has, err)
	}
	if has, err := tableHasUpdatedAt(ctx, tx, "not_a_table"); err != nil || has {
		t.Errorf("unknown table: has=%v err=%v, want false/nil", has, err)
	}
}

// assertNotSeen fails if any mutation_seen row exists for origin — proving a back-pressured
// batch did not advance the dedup watermark (the sender must retry).
func assertNotSeen(t *testing.T, c *Client, origin string) {
	t.Helper()
	seen, err := c.Query(context.Background(), "SELECT COUNT(*) AS n FROM mutation_seen WHERE origin = ?", origin)
	if err != nil {
		t.Fatalf("query mutation_seen: %v", err)
	}
	if len(seen) > 0 && seen[0].Int("n") != 0 {
		t.Errorf("mutation_seen has %d rows after back-pressure (should be 0 — sender must retry)", seen[0].Int("n"))
	}
}

// TestApplyRemoteMutations_INSERTPreservesReceiverOnlyColumns covers the WAL per-statement
// replay path.
func TestApplyRemoteMutations_INSERTPreservesReceiverOnlyColumns(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, ssh_port, cert_serial, role, ipmi_address, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"h1", "10.0.0.1", "operator", 2222, "serialX", "witness", "10.0.0.99",
		"2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := NewReplicator(c, "", RelayConfig{})
	ts := hlc.NewClock("origin-node").Now().String() // current time ≫ seeded HLC

	// An older sender emits a plain INSERT listing only the columns it knows — omitting
	// role, ipmi_address, ssh_port. Newer updated_at wins LWW on address.
	stmts := fmt.Sprintf(
		`[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)","Params":["h1","10.9.9.9","operator","serialX","2020-01-01T00:00:00Z","%s"]}]`, ts)
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: ts, Origin: "origin-node", Stmts: stmts}}

	if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("apply: %v", err)
	}

	rows, err := c.Query(ctx, "SELECT address, role, ipmi_address, ssh_port FROM hosts WHERE name = ?", "h1")
	if err != nil || len(rows) == 0 {
		t.Fatalf("query: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].String("address"); got != "10.9.9.9" {
		t.Errorf("address = %q, want 10.9.9.9 (newer incoming must win)", got)
	}
	if got := rows[0].String("role"); got != "witness" {
		t.Errorf("role = %q, want witness (receiver-only column erased by whole-row replace)", got)
	}
	if got := rows[0].String("ipmi_address"); got != "10.0.0.99" {
		t.Errorf("ipmi_address = %q, want 10.0.0.99 (receiver-only column erased)", got)
	}
	if got := rows[0].Int("ssh_port"); got != 2222 {
		t.Errorf("ssh_port = %d, want 2222 (receiver-only column erased)", got)
	}
}
