package corrosion

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The cluster row is the ROOT of every NetBox identity this cluster mints: the
// fingerprint is the first component of `lv:<fingerprint>:<uuid>:<mac>`. Until
// this heal existed nothing in production ever wrote that row, so every test
// below is written against the heal rather than against a seeded row.

const testCAPEM = "-----BEGIN CERTIFICATE-----\ntest-ca\n-----END CERTIFICATE-----\n"

func pkiDirWithCA(t *testing.T, pem string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte(pem), 0o644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	return dir
}

func schemaClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func clusterRows(t *testing.T, c *Client) []Row {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT id, name, domain, ca_cert, updated_at FROM cluster`)
	if err != nil {
		t.Fatalf("read cluster rows: %v", err)
	}
	return rows
}

// The blocker itself: a cluster that nobody seeded cannot derive a fingerprint,
// and after the startup heal it can.
func TestEnsureClusterRecordHealsAMissingRow(t *testing.T) {
	ctx := context.Background()
	c := schemaClient(t)

	if _, err := ClusterFingerprint(ctx, c); err == nil {
		t.Fatal("a cluster with no row must not yield a fingerprint")
	}

	if err := EnsureClusterRecord(ctx, c, pkiDirWithCA(t, testCAPEM)); err != nil {
		t.Fatalf("EnsureClusterRecord: %v", err)
	}

	got, err := ClusterFingerprint(ctx, c)
	if err != nil {
		t.Fatalf("ClusterFingerprint after heal: %v", err)
	}
	want, err := fingerprintFromCert(testCAPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("fingerprint = %q, want %q (the digest of the CA on disk)", got, want)
	}
	if n := len(clusterRows(t, c)); n != 1 {
		t.Fatalf("cluster rows = %d, want exactly 1", n)
	}
}

// Every node in a cluster runs this heal on every start. It must not rewrite a
// row it agrees with, or the row's updated_at would churn cluster-wide on every
// restart and every LWW compare against it would move for nothing.
func TestEnsureClusterRecordIsIdempotent(t *testing.T) {
	ctx := context.Background()
	c := schemaClient(t)
	dir := pkiDirWithCA(t, testCAPEM)

	if err := EnsureClusterRecord(ctx, c, dir); err != nil {
		t.Fatalf("first heal: %v", err)
	}
	first := clusterRows(t, c)
	if len(first) != 1 {
		t.Fatalf("cluster rows after first heal = %d, want 1", len(first))
	}
	before := first[0].String("updated_at")

	for i := 0; i < 3; i++ {
		if err := EnsureClusterRecord(ctx, c, dir); err != nil {
			t.Fatalf("repeat heal %d: %v", i, err)
		}
	}

	after := clusterRows(t, c)
	if len(after) != 1 {
		t.Fatalf("cluster rows after repeat heals = %d, want 1", len(after))
	}
	if got := after[0].String("updated_at"); got != before {
		t.Fatalf("updated_at moved on a no-op heal: %q -> %q (write-on-change)", before, got)
	}
}

// The row is REPLICATED and an operator (or a peer that healed first) may hold a
// CA this node does not. Overwriting it would make the cluster fingerprint
// depend on which node restarted last.
func TestEnsureClusterRecordNeverOverwritesAnExistingRow(t *testing.T) {
	ctx := context.Background()
	c := schemaClient(t)

	const seeded = "-----BEGIN CERTIFICATE-----\nseeded-by-a-peer\n-----END CERTIFICATE-----\n"
	if err := c.Execute(ctx,
		`INSERT INTO cluster (id, name, domain, ca_cert, created_at, updated_at)
		 VALUES ('default', 'seeded', 'seeded.invalid', ?, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')`,
		seeded); err != nil {
		t.Fatalf("seed cluster row: %v", err)
	}

	if err := EnsureClusterRecord(ctx, c, pkiDirWithCA(t, testCAPEM)); err != nil {
		t.Fatalf("EnsureClusterRecord: %v", err)
	}

	rows := clusterRows(t, c)
	if len(rows) != 1 {
		t.Fatalf("cluster rows = %d, want 1", len(rows))
	}
	if got := rows[0].String("ca_cert"); got != seeded {
		t.Fatalf("ca_cert was rewritten: got %q, want the seeded value", got)
	}
	if got := rows[0].String("name"); got != "seeded" {
		t.Fatalf("name was rewritten: got %q, want %q", got, "seeded")
	}
	if got := rows[0].String("updated_at"); got != "2024-01-01T00:00:00Z" {
		t.Fatalf("updated_at was rewritten: got %q", got)
	}
}

// A node with no CA on disk has nothing to derive from. It must still start —
// the daemon comes up long before anyone binds a network — and the feature must
// stay fail-closed rather than get a row it cannot stand behind.
func TestEnsureClusterRecordWithNoCAOnDiskStaysFailClosed(t *testing.T) {
	ctx := context.Background()
	c := schemaClient(t)

	if err := EnsureClusterRecord(ctx, c, t.TempDir()); err != nil {
		t.Fatalf("a missing ca.crt must not fail daemon startup: %v", err)
	}
	if n := len(clusterRows(t, c)); n != 0 {
		t.Fatalf("cluster rows = %d, want 0 — nothing to derive from", n)
	}
	if _, err := ClusterFingerprint(ctx, c); err == nil {
		t.Fatal("with no CA on disk the fingerprint must stay underivable")
	}
}

// An EMPTY ca.crt is the same "nothing to derive from" state as a missing one,
// and the row it would write is worse than none: ca_cert is NOT NULL, so a blank
// row looks present to every presence check while fingerprintFromCert still
// refuses it — a wedged cluster no later heal could repair.
func TestEnsureClusterRecordRefusesAnEmptyCA(t *testing.T) {
	ctx := context.Background()
	c := schemaClient(t)

	if err := EnsureClusterRecord(ctx, c, pkiDirWithCA(t, "   \n")); err != nil {
		t.Fatalf("a blank ca.crt must not fail daemon startup: %v", err)
	}
	if n := len(clusterRows(t, c)); n != 0 {
		t.Fatalf("cluster rows = %d, want 0 — a blank ca.crt is not a cluster identity", n)
	}
}

// The heal must write NOTHING to mutation_log, and that is the whole of whether
// it survives a mixed-version rolling upgrade.
//
// It fires unconditionally on every daemon start — no capability gate, nothing
// to turn it off — and `cluster` had NO replicated statement shape at the
// previous release, because nothing ever wrote that row. A replicated write
// here therefore reaches a peer still running the previous binary as a
// fingerprint its ledger cannot resolve; that peer fails the shape closed,
// rolls back the WHOLE batch and stops advancing its watermark, which
// head-of-line blocks every later statement on that stream (see
// replicator.go's "unregistered replicated statement shape"). Pre-staging —
// the RECOMMENDED rolling upgrade — equalises the schema first, so the
// schema-skew refusal sees no gap and accepts the stream: the binary-resident
// ledger is then the only cross-version gate, and this shape is not in the old
// one.
//
// Local-only is not a weaker write. Every node derives the row from the SAME
// shared CA on disk, so all N nodes converge on identical content by
// construction, and `cluster` is in the anti-entropy table set — which carries
// no ledger check at all — so a node that cannot derive it yet (no CA on disk)
// still receives it from a peer.
func TestEnsureClusterRecordEmitsNoReplicatedStatement(t *testing.T) {
	ctx := context.Background()
	c := schemaClient(t)

	before := mutationLogCount(t, c)
	if err := EnsureClusterRecord(ctx, c, pkiDirWithCA(t, testCAPEM)); err != nil {
		t.Fatalf("EnsureClusterRecord: %v", err)
	}
	if n := len(clusterRows(t, c)); n != 1 {
		t.Fatalf("cluster rows = %d, want 1 — precondition: the heal must write the row", n)
	}
	if after := mutationLogCount(t, c); after != before {
		t.Fatalf("the startup heal logged %d replicated statement(s): the `cluster` shape would "+
			"reach a previous-release peer whose ledger cannot resolve it, and that peer rolls "+
			"the batch back and stalls its watermark. The row must be written LOCALLY — "+
			"anti-entropy already replicates `cluster`, and every node derives the same value "+
			"from the shared CA", after-before)
	}
	if sql := mutationLogSQL(t, c); strings.Contains(sql, "cluster") {
		t.Fatalf("a replicated statement names the cluster table: %q", sql)
	}
}

// mutationLogSQL is every replicated statement this client has logged,
// concatenated, so an assertion can name the TABLE rather than only a count.
func mutationLogSQL(t *testing.T, c *Client) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	var all []string
	for _, r := range rows {
		all = append(all, r.String("stmts"))
	}
	return strings.Join(all, "\n")
}

// The heal leans on the fixed row id to converge: every node writes id='default',
// so N nodes healing concurrently produce ONE row under LWW instead of N. That
// only holds if `id` really is the primary key, so pin it here rather than
// trusting the DDL to stay as it reads today.
func TestClusterTablePrimaryKeyIsID(t *testing.T) {
	ctx := context.Background()
	c := schemaClient(t)

	rows, err := c.Query(ctx, `SELECT name FROM pragma_table_info('cluster') WHERE pk > 0 ORDER BY pk`)
	if err != nil {
		t.Fatalf("read cluster pragma_table_info: %v", err)
	}
	if len(rows) != 1 || rows[0].String("name") != "id" {
		var got []string
		for _, r := range rows {
			got = append(got, r.String("name"))
		}
		t.Fatalf("cluster primary key = %v, want [id] — the heal's fixed row id no longer converges", got)
	}
}
