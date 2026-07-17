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

// TestInsertUpsertRewrite pins the WAL INSERT→upsert rewrite across its branches.
func TestInsertUpsertRewrite(t *testing.T) {
	cases := []struct {
		name   string
		sql    string
		pkCols []string
		wantOK bool
		want   string
	}{
		{
			name:   "plain insert",
			sql:    "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?)",
			pkCols: []string{"name"}, wantOK: true,
			want: "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
		},
		{
			name:   "OR REPLACE normalized to plain",
			sql:    "INSERT OR REPLACE INTO hosts (name, address, updated_at) VALUES (?, ?, ?)",
			pkCols: []string{"name"}, wantOK: true,
			want: "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
		},
		{
			name:   "explicit ON CONFLICT applied verbatim",
			sql:    "INSERT INTO hosts (name, address) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address",
			pkCols: []string{"name"}, wantOK: true,
			want: "INSERT INTO hosts (name, address) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address",
		},
		{
			name:   "trailing semicolon stripped",
			sql:    "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?);",
			pkCols: []string{"name"}, wantOK: true,
			want: "INSERT INTO hosts (name, address, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET address = excluded.address, updated_at = excluded.updated_at",
		},
		{
			name:   "no full PK identity fails closed",
			sql:    "INSERT INTO hosts (address, updated_at) VALUES (?, ?)",
			pkCols: []string{"name"}, wantOK: false,
		},
		{
			name:   "non-INSERT fails closed",
			sql:    "UPDATE hosts SET address = ? WHERE name = ?",
			pkCols: []string{"name"}, wantOK: false,
		},
		{
			name:   "empty pkCols fails closed",
			sql:    "INSERT INTO t (a) VALUES (?)",
			pkCols: nil, wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := insertUpsertRewrite(c.sql, c.pkCols)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (sql=%q)", ok, c.wantOK, got)
			}
			if ok && got != c.want {
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
