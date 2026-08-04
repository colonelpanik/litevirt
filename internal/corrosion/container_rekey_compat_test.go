package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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

func TestGuardedRekeyRefusesProvisionalContainerCreate(t *testing.T) {
	ctx := context.Background()
	const delayed = "9900000000000-0000-provisional-rekey"

	begin := func(t *testing.T, suffix string) (*Client, OperationRecord, ContainerRecord) {
		t.Helper()
		c := testClient(t)
		op := createOp("op-provisional-rekey-"+suffix, "container", "ct1", "hash", "", 4)
		rec := ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "alpine", Project: "p1",
			OwnerEpoch: 4, SpecGeneration: 2,
		}
		if applied, err := c.BeginContainerCreateOperation(ctx, op, rec); err != nil || !applied {
			t.Fatalf("begin provisional create: applied=%v err=%v", applied, err)
		}
		got, err := GetContainer(ctx, c, rec.HostName, rec.Name)
		if err != nil || got == nil || got.State != "creating" ||
			got.ActiveOperationID != op.ID {
			t.Fatalf("provisional row: got=%+v err=%v", got, err)
		}
		return c, op, rec
	}
	seedFootprint := func(t *testing.T, c *Client) {
		t.Helper()
		if _, err := c.db.Exec(
			`INSERT INTO container_interfaces
			 (host_name, ct_name, network_name, ordinal, mac, updated_at)
			 VALUES ('h1', 'ct1', 'sentinel', 0, '52:54:00:00:00:01', 'sentinel')`,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := c.db.Exec(
			`INSERT INTO ip_allocations
			 (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
			 VALUES ('sentinel', '10.0.0.10', '52:54:00:00:00:01',
			         'ct1', 'ct', 'h1', 'sentinel', 'sentinel')`,
		); err != nil {
			t.Fatal(err)
		}
	}
	finish := func(t *testing.T, c *Client, op OperationRecord, rec ContainerRecord, action string) {
		t.Helper()
		switch action {
		case "commit":
			if applied, err := c.CommitContainerCreateOperation(
				ctx, op.ID, rec.OwnerEpoch, rec, nil,
			); err != nil || !applied {
				t.Fatalf("commit after refused rekey: applied=%v err=%v", applied, err)
			}
			got, err := GetContainer(ctx, c, rec.HostName, rec.Name)
			if err != nil || got == nil || got.State != "running" ||
				got.ActiveOperationID != "" {
				t.Fatalf("committed row: got=%+v err=%v", got, err)
			}
		case "rollback":
			if applied, err := c.RollbackContainerCreateOperation(
				ctx, rec.HostName, rec.Name, op.ID, rec.OwnerEpoch, "cancelled",
			); err != nil || !applied {
				t.Fatalf("rollback after refused rekey: applied=%v err=%v", applied, err)
			}
			if got, _ := GetContainer(ctx, c, rec.HostName, rec.Name); got != nil {
				t.Fatalf("rollback left provisional row live: %+v", got)
			}
		default:
			t.Fatalf("unknown terminal action %q", action)
		}
	}

	t.Run("local preflight", func(t *testing.T) {
		for _, action := range []string{"commit", "rollback"} {
			t.Run(action, func(t *testing.T) {
				c, op, rec := begin(t, "local-"+action)
				seedFootprint(t, c)
				src, err := GetContainer(ctx, c, rec.HostName, rec.Name)
				if err != nil || src == nil {
					t.Fatalf("source: got=%+v err=%v", src, err)
				}
				rowsBefore := containerRowsSnapshot(t, c, rec.Name)
				footprintBefore := containerOwnershipFootprintSnapshot(t, c, rec.Name)
				if applied, err := RekeyContainerOwnerGuarded(ctx, c, *src, "h2"); err != nil || applied {
					t.Fatalf("provisional local rekey: applied=%v err=%v", applied, err)
				}
				if rowsAfter := containerRowsSnapshot(t, c, rec.Name); rowsAfter != rowsBefore {
					t.Fatalf("refused local rekey changed container rows:\nbefore=%s\nafter=%s",
						rowsBefore, rowsAfter)
				}
				if footprintAfter := containerOwnershipFootprintSnapshot(
					t, c, rec.Name,
				); footprintAfter != footprintBefore {
					t.Fatalf("refused local rekey changed footprint:\nbefore=%s\nafter=%s",
						footprintBefore, footprintAfter)
				}
				finish(t, c, op, rec, action)
			})
		}
	})

	t.Run("delayed guarded replay", func(t *testing.T) {
		for _, action := range []string{"commit", "rollback"} {
			t.Run(action, func(t *testing.T) {
				c, op, rec := begin(t, "remote-"+action)
				seedFootprint(t, c)
				src, err := GetContainer(ctx, c, rec.HostName, rec.Name)
				if err != nil || src == nil {
					t.Fatalf("source: got=%+v err=%v", src, err)
				}
				guard, err := containerRekeyMutationGuard(*src, "h2")
				if err != nil {
					t.Fatal(err)
				}
				target, err := rekeyContainerStmt(c, *src, "h2", delayed)
				if err != nil {
					t.Fatal(err)
				}
				stmts := []Statement{
					{SQL: target.SQL, Params: target.Params, Guard: guard},
					{
						SQL: containerRekeyInterfaceCleanupSQL,
						Params: []interface{}{
							"2026-07-29T12:00:00Z", delayed, src.HostName, src.Name,
						},
						Guard: guard,
					},
					{
						SQL: containerRekeyLeaseSQL,
						Params: []interface{}{
							"h2", "2026-07-29T12:00:00Z", delayed, src.HostName, src.Name,
						},
						Guard: guard,
					},
					{
						SQL: containerDeleteSQL,
						Params: []interface{}{
							"2026-07-29T12:00:00Z", delayed, src.HostName, src.Name,
							src.OwnerEpoch, src.SpecGeneration,
						},
						Guard: guard,
					},
				}
				raw, err := json.Marshal(stmts)
				if err != nil {
					t.Fatal(err)
				}
				rowsBefore := containerRowsSnapshot(t, c, rec.Name)
				footprintBefore := containerOwnershipFootprintSnapshot(t, c, rec.Name)
				applyMutationEntry(t, c, &pb.MutationEntry{
					Seq: 1, Hlc: delayed, Origin: "provisional-rekey-" + action,
					Stmts: string(raw),
				})
				if rowsAfter := containerRowsSnapshot(t, c, rec.Name); rowsAfter != rowsBefore {
					t.Fatalf("declined replay changed container rows:\nbefore=%s\nafter=%s",
						rowsBefore, rowsAfter)
				}
				if footprintAfter := containerOwnershipFootprintSnapshot(
					t, c, rec.Name,
				); footprintAfter != footprintBefore {
					t.Fatalf("declined replay changed footprint:\nbefore=%s\nafter=%s",
						footprintBefore, footprintAfter)
				}
				finish(t, c, op, rec, action)
			})
		}
	})
}

func TestContainerRekeySourceSafetyAxes(t *testing.T) {
	cases := []struct {
		name              string
		state             string
		activeOperationID string
		want              bool
	}{
		{name: "safe running source", state: "running", want: true},
		{name: "creating without barrier", state: "creating"},
		{name: "provisional without barrier", state: "provisional"},
		{name: "running with active barrier", state: "running", activeOperationID: "op-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containerRekeySourceSafe(
				tc.state, "", "", tc.activeOperationID,
			); got != tc.want {
				t.Fatalf("containerRekeySourceSafe(%q, active=%q)=%v, want %v",
					tc.state, tc.activeOperationID, got, tc.want)
			}
		})
	}
}

func TestOrdinaryRekeyLocalTargetAuthority(t *testing.T) {
	ctx := context.Background()
	seedLegacySource := func(t *testing.T, c *Client) ContainerRecord {
		t.Helper()
		if err := UpsertContainer(ctx, c, ContainerRecord{
			HostName: "h1", Name: "ct1", State: "running", Image: "source",
			Project: "p1",
		}); err != nil {
			t.Fatal(err)
		}
		got, err := GetContainer(ctx, c, "h1", "ct1")
		if err != nil || got == nil {
			t.Fatalf("legacy source: got=%+v err=%v", got, err)
		}
		return *got
	}
	seedSourceFootprint := func(t *testing.T, c *Client) {
		t.Helper()
		if _, err := c.db.Exec(
			`INSERT INTO container_interfaces
			 (host_name, ct_name, network_name, ordinal, mac, updated_at)
			 VALUES ('h1', 'ct1', 'sentinel', 0, '52:54:00:00:00:01', 'sentinel')`,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := c.db.Exec(
			`INSERT INTO ip_allocations
			 (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
			 VALUES ('sentinel', '10.0.0.10', '52:54:00:00:00:01',
			         'ct1', 'ct', 'h1', 'sentinel', 'sentinel')`,
		); err != nil {
			t.Fatal(err)
		}
	}
	mutationCount := func(t *testing.T, c *Client) int64 {
		t.Helper()
		var count int64
		if err := c.db.QueryRow(`SELECT COUNT(*) FROM mutation_log`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	t.Run("modern tombstone declines without WAL", func(t *testing.T) {
		c := testClient(t)
		source := seedLegacySource(t, c)
		seedSourceFootprint(t, c)
		targetOp := createOp("op-modern-tombstone-target", "container", "ct1", "hash", "", 3)
		target := ContainerRecord{
			HostName: "h2", Name: "ct1", Image: "modern", Project: "p1",
			OwnerEpoch: 3, SpecGeneration: 4,
		}
		if applied, err := c.BeginContainerCreateOperation(
			ctx, targetOp, target,
		); err != nil || !applied {
			t.Fatalf("target begin: applied=%v err=%v", applied, err)
		}
		if applied, err := c.CommitContainerCreateOperation(
			ctx, targetOp.ID, target.OwnerEpoch, target, nil,
		); err != nil || !applied {
			t.Fatalf("target commit: applied=%v err=%v", applied, err)
		}
		if err := DeleteContainer(ctx, c, target.HostName, target.Name); err != nil {
			t.Fatal(err)
		}

		rowsBefore := containerRowsSnapshot(t, c, source.Name)
		footprintBefore := containerOwnershipFootprintSnapshot(t, c, source.Name)
		mutationsBefore := mutationCount(t, c)
		if applied, err := RekeyContainerOwner(ctx, c, source, target.HostName); err != nil || applied {
			t.Fatalf("ordinary rekey over modern tombstone: applied=%v err=%v", applied, err)
		}
		if rowsAfter := containerRowsSnapshot(t, c, source.Name); rowsAfter != rowsBefore {
			t.Fatalf("declined ordinary rekey changed container rows:\nbefore=%s\nafter=%s",
				rowsBefore, rowsAfter)
		}
		if footprintAfter := containerOwnershipFootprintSnapshot(
			t, c, source.Name,
		); footprintAfter != footprintBefore {
			t.Fatalf("declined ordinary rekey changed footprint:\nbefore=%s\nafter=%s",
				footprintBefore, footprintAfter)
		}
		if mutationsAfter := mutationCount(t, c); mutationsAfter != mutationsBefore {
			t.Fatalf("declined ordinary rekey appended WAL: before=%d after=%d",
				mutationsBefore, mutationsAfter)
		}
	})

	t.Run("preauthority tombstone remains replaceable", func(t *testing.T) {
		c := testClient(t)
		source := seedLegacySource(t, c)
		if err := UpsertContainer(ctx, c, ContainerRecord{
			HostName: "h2", Name: "ct1", State: "stopped", Image: "stale",
			Project: "p1",
		}); err != nil {
			t.Fatal(err)
		}
		if err := DeleteContainer(ctx, c, "h2", "ct1"); err != nil {
			t.Fatal(err)
		}
		if applied, err := RekeyContainerOwner(ctx, c, source, "h2"); err != nil || !applied {
			t.Fatalf("ordinary rekey over preauthority tombstone: applied=%v err=%v", applied, err)
		}
		if got, _ := GetContainer(ctx, c, "h1", "ct1"); got != nil {
			t.Fatalf("successful ordinary rekey left source live: %+v", got)
		}
		if got, err := GetContainer(ctx, c, "h2", "ct1"); err != nil || got == nil ||
			got.Image != "source" || got.OwnerEpoch != 0 || got.SpecGeneration != 0 {
			t.Fatalf("replacement target: got=%+v err=%v", got, err)
		}
	})

	t.Run("live target still declines", func(t *testing.T) {
		c := testClient(t)
		source := seedLegacySource(t, c)
		if err := UpsertContainer(ctx, c, ContainerRecord{
			HostName: "h2", Name: "ct1", State: "running", Image: "target",
			Project: "p1",
		}); err != nil {
			t.Fatal(err)
		}
		rowsBefore := containerRowsSnapshot(t, c, source.Name)
		mutationsBefore := mutationCount(t, c)
		if applied, err := RekeyContainerOwner(ctx, c, source, "h2"); err != nil || applied {
			t.Fatalf("ordinary rekey over live target: applied=%v err=%v", applied, err)
		}
		if rowsAfter := containerRowsSnapshot(t, c, source.Name); rowsAfter != rowsBefore {
			t.Fatalf("declined live-target rekey changed rows:\nbefore=%s\nafter=%s",
				rowsBefore, rowsAfter)
		}
		if mutationsAfter := mutationCount(t, c); mutationsAfter != mutationsBefore {
			t.Fatalf("declined live-target rekey appended WAL: before=%d after=%d",
				mutationsBefore, mutationsAfter)
		}
	})
}

func TestOrdinaryRekeyCannotForgePreauthoritySource(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	op := createOp("op-modern-source-forged-legacy", "container", "ct1", "hash", "", 3)
	rec := ContainerRecord{
		HostName: "h1", Name: "ct1", Image: "modern", Project: "p1",
		OwnerEpoch: 3, SpecGeneration: 5,
	}
	if applied, err := c.BeginContainerCreateOperation(ctx, op, rec); err != nil || !applied {
		t.Fatalf("begin modern source: applied=%v err=%v", applied, err)
	}
	if applied, err := c.CommitContainerCreateOperation(
		ctx, op.ID, rec.OwnerEpoch, rec, nil,
	); err != nil || !applied {
		t.Fatalf("commit modern source: applied=%v err=%v", applied, err)
	}
	fresh, err := GetContainer(ctx, c, rec.HostName, rec.Name)
	if err != nil || fresh == nil {
		t.Fatalf("fresh modern source: got=%+v err=%v", fresh, err)
	}
	if _, err := c.db.Exec(
		`INSERT INTO container_interfaces
		 (host_name, ct_name, network_name, ordinal, mac, updated_at)
		 VALUES ('h1', 'ct1', 'sentinel', 0, '52:54:00:00:00:01', 'sentinel')`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(
		`INSERT INTO ip_allocations
		 (network, ip, mac, vm_name, owner_kind, owner_host, allocated_at, updated_at)
		 VALUES ('sentinel', '10.0.0.10', '52:54:00:00:00:01',
		         'ct1', 'ct', 'h1', 'sentinel', 'sentinel')`,
	); err != nil {
		t.Fatal(err)
	}

	forged := *fresh
	forged.OwnerEpoch = 0
	forged.SpecGeneration = 0
	forged.ActiveOperationID = ""
	rowsBefore := containerRowsSnapshot(t, c, rec.Name)
	footprintBefore := containerOwnershipFootprintSnapshot(t, c, rec.Name)
	var mutationsBefore int64
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM mutation_log`).Scan(&mutationsBefore); err != nil {
		t.Fatal(err)
	}
	if applied, err := RekeyContainerOwner(ctx, c, forged, "h2"); err != nil || applied {
		t.Fatalf("forged legacy rekey: applied=%v err=%v", applied, err)
	}
	if rowsAfter := containerRowsSnapshot(t, c, rec.Name); rowsAfter != rowsBefore {
		t.Fatalf("forged legacy rekey changed container rows:\nbefore=%s\nafter=%s",
			rowsBefore, rowsAfter)
	}
	if footprintAfter := containerOwnershipFootprintSnapshot(
		t, c, rec.Name,
	); footprintAfter != footprintBefore {
		t.Fatalf("forged legacy rekey changed footprint:\nbefore=%s\nafter=%s",
			footprintBefore, footprintAfter)
	}
	var mutationsAfter int64
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM mutation_log`).Scan(&mutationsAfter); err != nil {
		t.Fatal(err)
	}
	if mutationsAfter != mutationsBefore {
		t.Fatalf("forged legacy rekey appended WAL: before=%d after=%d",
			mutationsBefore, mutationsAfter)
	}

	if applied, err := RekeyContainerOwnerGuarded(ctx, c, *fresh, "h2"); err != nil || !applied {
		t.Fatalf("fresh guarded rekey: applied=%v err=%v", applied, err)
	}
	got, err := GetContainer(ctx, c, "h2", rec.Name)
	if err != nil || got == nil || got.OwnerEpoch != rec.OwnerEpoch ||
		got.SpecGeneration != rec.SpecGeneration {
		t.Fatalf("guarded target authority: got=%+v err=%v", got, err)
	}
}

func containerRowsSnapshot(t *testing.T, c *Client, name string) string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT * FROM containers WHERE name = ? ORDER BY host_name`, name)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
