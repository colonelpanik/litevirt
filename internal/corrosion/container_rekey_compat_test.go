package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
)

func TestRekeyContainerOwnerRollingCompatibility(t *testing.T) {
	ctx := context.Background()

	t.Run("ordinary sender emits exact v1.3 envelope", func(t *testing.T) {
		c := testClient(t)
		if err := UpsertContainer(ctx, c, ContainerRecord{
			HostName: "h1", Name: "ct1", State: "running", Image: "alpine",
			Project: "p1",
		}); err != nil {
			t.Fatal(err)
		}
		src, err := GetContainer(ctx, c, "h1", "ct1")
		if err != nil || src == nil {
			t.Fatalf("source: got=%+v err=%v", src, err)
		}
		if applied, err := RekeyContainerOwner(ctx, c, *src, "h2"); err != nil || !applied {
			t.Fatalf("legacy rekey: applied=%v err=%v", applied, err)
		}

		entry := latestMutationEntry(t, c, "compat-sender", 1)
		var stmts []Statement
		if err := json.Unmarshal([]byte(entry.Stmts), &stmts); err != nil {
			t.Fatal(err)
		}
		if len(stmts) != 4 {
			t.Fatalf("v1.3 envelope statement count=%d, want 4", len(stmts))
		}
		wantSQL := []string{
			legacyContainerStrictDeleteSQL,
			legacyContainerRekeySQL,
			containerRekeyInterfaceCleanupSQL,
			containerRekeyLeaseSQL,
		}
		for i := range stmts {
			if stmts[i].Guard != nil {
				t.Fatalf("v1.3 statement %d unexpectedly carries a guard", i)
			}
			if stmts[i].SQL != wantSQL[i] {
				t.Fatalf("v1.3 statement %d SQL mismatch:\ngot:  %s\nwant: %s",
					i, stmts[i].SQL, wantSQL[i])
			}
		}

		old, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer old.Close()
		schema := []string{
			`CREATE TABLE containers (
				host_name TEXT NOT NULL, name TEXT NOT NULL,
				state TEXT NOT NULL DEFAULT 'stopped', image TEXT,
				cpu_limit INTEGER NOT NULL DEFAULT 0,
				memory_mib INTEGER NOT NULL DEFAULT 0, labels TEXT,
				restart_policy TEXT, state_detail TEXT,
				project TEXT NOT NULL DEFAULT '_default',
				is_template INTEGER NOT NULL DEFAULT 0,
				on_host_failure TEXT, create_spec TEXT, relocate_token TEXT,
				created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT,
				PRIMARY KEY (host_name, name))`,
			`CREATE TABLE container_interfaces (
				host_name TEXT NOT NULL, ct_name TEXT NOT NULL,
				network_name TEXT NOT NULL, ordinal INTEGER NOT NULL,
				mac TEXT NOT NULL, ip TEXT, veth_device TEXT,
				security_groups TEXT, updated_at TEXT NOT NULL, deleted_at TEXT,
				PRIMARY KEY (host_name, ct_name, ordinal))`,
			`CREATE TABLE ip_allocations (
				network TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT NOT NULL,
				vm_name TEXT NOT NULL, owner_kind TEXT NOT NULL DEFAULT 'vm',
				owner_host TEXT NOT NULL DEFAULT '', allocated_at TEXT NOT NULL,
				updated_at TEXT NOT NULL, deleted_at TEXT,
				PRIMARY KEY (network, ip))`,
		}
		for _, ddl := range schema {
			if _, err := old.Exec(ddl); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := old.Exec(
			`INSERT INTO containers
			 (host_name, name, state, image, project, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			src.HostName, src.Name, src.State, src.Image, src.Project,
			src.CreatedAt, src.UpdatedAt,
		); err != nil {
			t.Fatal(err)
		}
		tx, err := old.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i, stmt := range stmts {
			if _, err := tx.ExecContext(ctx, stmt.SQL, stmt.Params...); err != nil {
				_ = tx.Rollback()
				t.Fatalf("v1.3-like receiver rejected statement %d: %v", i, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		var image string
		if err := old.QueryRow(
			`SELECT image FROM containers
			 WHERE host_name = 'h2' AND name = 'ct1' AND deleted_at IS NULL`,
		).Scan(&image); err != nil || image != "alpine" {
			t.Fatalf("v1.3 target image=%q err=%v", image, err)
		}
	})

	t.Run("modern authority requires guarded API", func(t *testing.T) {
		c := testClient(t)
		op := createOp("op-rekey-modern-api", "container", "ct1", "hash", "", 3)
		rec := ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "alpine", Project: "p1",
			OwnerEpoch: 3, SpecGeneration: 5,
		}
		if applied, err := c.BeginContainerCreateOperation(ctx, op, rec); err != nil || !applied {
			t.Fatalf("begin: applied=%v err=%v", applied, err)
		}
		if applied, err := c.CommitContainerCreateOperation(
			ctx, op.ID, rec.OwnerEpoch, rec, nil,
		); err != nil || !applied {
			t.Fatalf("commit: applied=%v err=%v", applied, err)
		}
		src, err := GetContainer(ctx, c, "h1", "ct1")
		if err != nil || src == nil {
			t.Fatalf("source: got=%+v err=%v", src, err)
		}
		if applied, err := RekeyContainerOwner(ctx, c, *src, "h2"); applied ||
			!errors.Is(err, ErrGuardedContainerRekeyRequired) {
			t.Fatalf("ordinary modern rekey: applied=%v err=%v", applied, err)
		}
		if got, _ := GetContainer(ctx, c, "h1", "ct1"); got == nil {
			t.Fatal("ordinary modern rekey changed source")
		}
		if applied, err := RekeyContainerOwnerGuarded(ctx, c, *src, "h2"); err != nil || !applied {
			t.Fatalf("guarded modern rekey: applied=%v err=%v", applied, err)
		}
	})
}
