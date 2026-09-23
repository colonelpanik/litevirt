package corrosion

import (
	"context"
	"testing"
)

// --- the rule itself ----------------------------------------------------

func TestAdminRemintRefused(t *testing.T) {
	const genesis = "2026-09-15T06:35:33Z"
	const remint = "2026-09-18T11:02:10Z"

	for _, tc := range []struct {
		name                                                   string
		localRole, localDeletedAt, localCreatedAt, incomingCAt string
		want                                                   bool
		why                                                    string
	}{
		{"a fresh mint under a live admin's name", "admin", "", genesis, remint, true,
			"this is #186: a joining node minted its own admin and it replicated"},
		{"the same admin's password change", "admin", "", genesis, genesis, false,
			"`lv user reset-admin` preserves created_at and must keep replicating"},
		{"a non-admin account", "viewer", "", genesis, remint, false,
			"the guard protects a cluster credential, not every row"},
		{"a tombstoned admin", "admin", "2026-09-16T00:00:00Z", genesis, remint, false,
			"a tombstoned admin cannot log in, so there is no live credential to protect"},
		{"local created_at unknown", "admin", "", "", remint, false,
			"nothing to compare against is not evidence of a re-mint"},
		{"incoming created_at unknown", "admin", "", genesis, "", false,
			"a dump that does not project created_at must not become a refusal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := adminRemintRefused(tc.localRole, tc.localDeletedAt, tc.localCreatedAt, tc.incomingCAt)
			if got != tc.want {
				t.Errorf("adminRemintRefused = %v, want %v\n%s", got, tc.want, tc.why)
			}
		})
	}
}

// --- the anti-entropy lane ----------------------------------------------

func usersSyncTable() syncTable {
	return syncTable{Name: "users", Columns: []string{
		"username", "role", "password_hash", "created_at", "updated_at", "deleted_at",
	}}
}

func usersRowCells(username, role, hash, createdAt, updatedAt string) []interface{} {
	return []interface{}{username, role, hash, createdAt, updatedAt, nil}
}

func mergeUsersRow(t *testing.T, c *Client, row []interface{}) {
	t.Helper()
	table := usersSyncTable()
	if _, _, err := c.mergeChunk(
		table, [][]interface{}{row},
		buildMergeUpsertSQL(table.Name, table.Columns, []string{"username"}),
		[]string{"username"}, []int{0}, indexOf(table.Columns, "updated_at"),
	); err != nil {
		t.Fatalf("mergeChunk: %v", err)
	}
}

func adminHash(t *testing.T, c *Client) string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT password_hash FROM users WHERE username = 'admin'`)
	if err != nil {
		t.Fatalf("read admin hash: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("the admin row is gone entirely")
	}
	return rows[0].String("password_hash")
}

// This is the #186 event on the anti-entropy lane: a node that minted its own
// admin offers it to a converged cluster. Its updated_at is newer, so plain LWW
// takes it — which replaces the cluster's admin credential with one only the
// sender knows.
func TestUsersMerge_APeersFreshAdminDoesNotReplaceTheClustersAdmin(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := InsertUser(ctx, c, "admin", "admin", "cluster-hash"); err != nil {
		t.Fatalf("seed founder admin: %v", err)
	}
	localCreatedAt := func() string {
		rows, _ := c.Query(ctx, `SELECT created_at FROM users WHERE username = 'admin'`)
		return rows[0].String("created_at")
	}()

	mergeUsersRow(t, c, usersRowCells("admin", "admin", "joiner-hash",
		"2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"))

	if got := adminHash(t, c); got != "cluster-hash" {
		t.Fatalf("password_hash = %q, want cluster-hash\n"+
			"a node that minted its own admin replaced the cluster's credential, and "+
			"nothing recorded that it happened", got)
	}
	if got := func() string {
		rows, _ := c.Query(ctx, `SELECT created_at FROM users WHERE username = 'admin'`)
		return rows[0].String("created_at")
	}(); got != localCreatedAt {
		t.Errorf("created_at = %q, want %q — the account's identity moved", got, localCreatedAt)
	}
}

// The other side of the rule: a genuine password change carries the SAME
// created_at, and it has to keep converging or `lv user reset-admin` stops
// working cluster-wide.
func TestUsersMerge_ARealPasswordChangeStillReplicates(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := InsertUser(ctx, c, "admin", "admin", "old-hash"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	rows, _ := c.Query(ctx, `SELECT created_at FROM users WHERE username = 'admin'`)
	createdAt := rows[0].String("created_at")

	mergeUsersRow(t, c, usersRowCells("admin", "admin", "new-hash",
		createdAt, "2099-01-01T00:00:00Z"))

	if got := adminHash(t, c); got != "new-hash" {
		t.Fatalf("password_hash = %q, want new-hash — a legitimate reset-admin was "+
			"refused, so the cluster can no longer rotate its admin password", got)
	}
}

// A second admin ACCOUNT is legitimate — it is exactly what the last-admin
// delete guard tells operators to create — so the guard must not touch it.
func TestUsersMerge_ASecondAdminAccountStillReplicates(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := InsertUser(ctx, c, "admin", "admin", "cluster-hash"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	mergeUsersRow(t, c, usersRowCells("root", "admin", "root-hash",
		"2026-09-18T12:00:00Z", "2026-09-18T12:00:00Z"))

	rows, err := c.Query(ctx, `SELECT username FROM users WHERE username = 'root'`)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	if len(rows) == 0 {
		t.Error("a legitimately created second admin was refused by the re-mint guard")
	}
}

func TestUsersMerge_ANonAdminRowIsUnaffected(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := InsertUser(ctx, c, "bob", "viewer", "old"); err != nil {
		t.Fatalf("seed viewer: %v", err)
	}

	mergeUsersRow(t, c, usersRowCells("bob", "viewer", "new",
		"2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"))

	rows, _ := c.Query(ctx, `SELECT password_hash FROM users WHERE username = 'bob'`)
	if got := rows[0].String("password_hash"); got != "new" {
		t.Errorf("password_hash = %q, want new — an ordinary user row stopped converging", got)
	}
}

// --- the WAL lane -------------------------------------------------------

// applyWALUserInsert drives the WAL apply path for one users INSERT — the exact
// statement InsertUser emits when a node mints an admin into an empty table.
func applyWALUserInsert(t *testing.T, c *Client, username, role, hash, createdAt, updatedAt string) error {
	t.Helper()
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()
	s := Statement{
		SQL:    `INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		Params: []interface{}{username, role, hash, createdAt, updatedAt},
	}
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if aerr := r.applyStatementLWW(ctx, tx, s, updatedAt); aerr != nil {
		tx.Rollback()
		c.dropDeferredEffects(tx)
		return aerr
	}
	if cerr := tx.Commit(); cerr != nil {
		t.Fatalf("commit: %v", cerr)
	}
	c.runDeferredEffects(tx)
	return nil
}

// The WAL lane is the one that actually carried #186 in the lab: the joining
// node's INSERT arrives as a replicated statement, and applyLWWGated compared
// nothing but updated_at.
func TestUsersWAL_APeersFreshAdminDoesNotReplaceTheClustersAdmin(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := InsertUser(ctx, c, "admin", "admin", "cluster-hash"); err != nil {
		t.Fatalf("seed founder admin: %v", err)
	}

	if err := applyWALUserInsert(t, c, "admin", "admin", "joiner-hash",
		"2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if got := adminHash(t, c); got != "cluster-hash" {
		t.Fatalf("password_hash = %q, want cluster-hash\n"+
			"a joining node's minted admin overwrote the cluster credential on the "+
			"WAL lane — the lane that carried this in the lab", got)
	}
}

func TestUsersWAL_ARealPasswordChangeStillReplicates(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := InsertUser(ctx, c, "admin", "admin", "old-hash"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	rows, _ := c.Query(ctx, `SELECT created_at FROM users WHERE username = 'admin'`)
	createdAt := rows[0].String("created_at")

	if err := applyWALUserInsert(t, c, "admin", "admin", "new-hash",
		createdAt, "2099-01-01T00:00:00Z"); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if got := adminHash(t, c); got != "new-hash" {
		t.Fatalf("password_hash = %q, want new-hash — the WAL lane refused a "+
			"legitimate credential rotation", got)
	}
}

func TestUsersWAL_ASecondAdminAccountStillReplicates(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := InsertUser(ctx, c, "admin", "admin", "cluster-hash"); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	if err := applyWALUserInsert(t, c, "root", "admin", "root-hash",
		"2026-09-18T12:00:00Z", "2026-09-18T12:00:00Z"); err != nil {
		t.Fatalf("apply: %v", err)
	}

	rows, err := c.Query(ctx, `SELECT username FROM users WHERE username = 'root'`)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	if len(rows) == 0 {
		t.Error("a legitimately created second admin was refused on the WAL lane")
	}
}
