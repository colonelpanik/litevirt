package corrosion

import (
	"context"
	"reflect"
	"testing"
)

func TestSchemaV44FreshColumnsAndDefaults(t *testing.T) {
	// v44's columns must survive every later version, so this pins a floor
	// rather than an exact match — a bump is not supposed to break v44.
	if CurrentSchemaVersion < 44 {
		t.Fatalf("CurrentSchemaVersion = %d, want >= 44", CurrentSchemaVersion)
	}
	c := newTestDB(t)
	ctx := context.Background()

	for _, tc := range []struct {
		table  string
		column string
	}{
		{"containers", "owner_epoch"},
		{"containers", "spec_generation"},
		{"containers", "active_operation_id"},
		{"hosts", "capacity_policy_hash"},
		{"notification_routes", "subject_pattern"},
		{"notification_routes", "project"},
	} {
		if ok, err := columnExists(ctx, c.db, tc.table, tc.column); err != nil || !ok {
			t.Errorf("%s.%s present = %v, err = %v", tc.table, tc.column, ok, err)
		}
	}

	if err := c.Execute(ctx,
		`INSERT INTO containers
		 (host_name, name, state, image, cpu_limit, memory_mib, created_at, updated_at)
		 VALUES ('h1', 'ct1', 'stopped', '', 0, 0, 'now', 'now')`); err != nil {
		t.Fatalf("insert legacy-shaped container: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO hosts
		 (name, address, ssh_user, cert_serial, created_at, updated_at)
		 VALUES ('h1', '127.0.0.1', 'root', '', 'now', 'now')`); err != nil {
		t.Fatalf("insert legacy-shaped host: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO notification_routes
		 (id, event_pattern, target_id, created_at, updated_at)
		 VALUES ('r1', '*', 't1', 'now', 'now')`); err != nil {
		t.Fatalf("insert legacy-shaped notification route: %v", err)
	}

	rows, err := c.Query(ctx,
		`SELECT owner_epoch, spec_generation, active_operation_id
		 FROM containers WHERE host_name = 'h1' AND name = 'ct1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read container defaults: rows=%d err=%v", len(rows), err)
	}
	if rows[0].Int64("owner_epoch") != 0 ||
		rows[0].Int64("spec_generation") != 0 ||
		rows[0].String("active_operation_id") != "" {
		t.Fatalf("container defaults = owner:%d generation:%d op:%q, want 0/0/empty",
			rows[0].Int64("owner_epoch"), rows[0].Int64("spec_generation"),
			rows[0].String("active_operation_id"))
	}
	rows, err = c.Query(ctx, `SELECT capacity_policy_hash FROM hosts WHERE name = 'h1'`)
	if err != nil || len(rows) != 1 || rows[0].String("capacity_policy_hash") != "" {
		t.Fatalf("host capacity policy default: rows=%v err=%v", rows, err)
	}
	rows, err = c.Query(ctx, `SELECT subject_pattern, project FROM notification_routes WHERE id = 'r1'`)
	if err != nil || len(rows) != 1 ||
		rows[0].String("subject_pattern") != "*" || rows[0].String("project") != "" {
		t.Fatalf("route defaults: rows=%v err=%v", rows, err)
	}
}

func TestSchemaV44MigratesV43AndPreservesRows(t *testing.T) {
	c := newTestDB(t)
	ctx := context.Background()

	if err := c.Execute(ctx,
		`INSERT INTO containers
		 (host_name, name, state, image, cpu_limit, memory_mib, created_at, updated_at)
		 VALUES ('h1', 'ct1', 'running', 'debian', 2, 2048, 'created', 'updated')`); err != nil {
		t.Fatalf("seed container: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO hosts
		 (name, address, ssh_user, cert_serial, created_at, updated_at)
		 VALUES ('h1', '10.0.0.1', 'root', 'serial', 'created', 'updated')`); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO notification_routes
		 (id, event_pattern, target_id, created_at, updated_at)
		 VALUES ('r1', 'vm.*', 't1', 'created', 'updated')`); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	for _, column := range []string{"owner_epoch", "spec_generation", "active_operation_id"} {
		if err := c.execLocal(ctx, `ALTER TABLE containers DROP COLUMN `+column); err != nil {
			t.Fatalf("simulate v43 drop containers.%s: %v", column, err)
		}
	}
	if err := c.execLocal(ctx, `ALTER TABLE hosts DROP COLUMN capacity_policy_hash`); err != nil {
		t.Fatalf("simulate v43 drop hosts.capacity_policy_hash: %v", err)
	}
	for _, column := range []string{"subject_pattern", "project"} {
		if err := c.execLocal(ctx, `ALTER TABLE notification_routes DROP COLUMN `+column); err != nil {
			t.Fatalf("simulate v43 drop notification_routes.%s: %v", column, err)
		}
	}
	for _, m := range schemaMigrationLedger {
		if m.Version == 44 {
			if err := c.execLocal(ctx, `DELETE FROM applied_migrations WHERE id = ?`, m.ID); err != nil {
				t.Fatalf("remove v44 ledger %s: %v", m.ID, err)
			}
		}
	}
	if err := c.execLocal(ctx,
		`UPDATE schema_state SET version = 43 WHERE id = 1`); err != nil {
		t.Fatalf("stamp v43: %v", err)
	}

	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("migrate v43 to v44: %v", err)
	}
	if got := storedVersion(t, c); got != CurrentSchemaVersion {
		t.Fatalf("schema version after migration = %d, want %d", got, CurrentSchemaVersion)
	}
	rows, err := c.Query(ctx,
		`SELECT state, image, cpu_limit, memory_mib, owner_epoch, spec_generation, active_operation_id
		 FROM containers WHERE host_name = 'h1' AND name = 'ct1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read migrated container: rows=%d err=%v", len(rows), err)
	}
	if rows[0].String("state") != "running" || rows[0].String("image") != "debian" ||
		rows[0].Int("cpu_limit") != 2 || rows[0].Int("memory_mib") != 2048 ||
		rows[0].Int64("owner_epoch") != 0 || rows[0].Int64("spec_generation") != 0 ||
		rows[0].String("active_operation_id") != "" {
		t.Fatalf("migrated container row not preserved: %#v", rows[0])
	}
	rows, err = c.Query(ctx, `SELECT address, cert_serial, capacity_policy_hash FROM hosts WHERE name = 'h1'`)
	if err != nil || len(rows) != 1 || rows[0].String("address") != "10.0.0.1" ||
		rows[0].String("cert_serial") != "serial" || rows[0].String("capacity_policy_hash") != "" {
		t.Fatalf("migrated host row not preserved: rows=%v err=%v", rows, err)
	}
	rows, err = c.Query(ctx,
		`SELECT event_pattern, target_id, subject_pattern, project
		 FROM notification_routes WHERE id = 'r1'`)
	if err != nil || len(rows) != 1 || rows[0].String("event_pattern") != "vm.*" ||
		rows[0].String("target_id") != "t1" || rows[0].String("subject_pattern") != "*" ||
		rows[0].String("project") != "" {
		t.Fatalf("migrated route row not preserved: rows=%v err=%v", rows, err)
	}
}

func TestSchemaV44FreshAndUpgradedColumnOrderMatch(t *testing.T) {
	ctx := context.Background()
	fresh := newTestDB(t)
	upgraded := newTestDB(t)

	for _, column := range []string{"owner_epoch", "spec_generation", "active_operation_id"} {
		if err := upgraded.execLocal(ctx, `ALTER TABLE containers DROP COLUMN `+column); err != nil {
			t.Fatalf("simulate v43 drop containers.%s: %v", column, err)
		}
	}
	if err := upgraded.execLocal(ctx, `ALTER TABLE hosts DROP COLUMN capacity_policy_hash`); err != nil {
		t.Fatalf("simulate v43 drop hosts.capacity_policy_hash: %v", err)
	}
	for _, column := range []string{"subject_pattern", "project"} {
		if err := upgraded.execLocal(ctx, `ALTER TABLE notification_routes DROP COLUMN `+column); err != nil {
			t.Fatalf("simulate v43 drop notification_routes.%s: %v", column, err)
		}
	}
	for _, m := range schemaMigrationLedger {
		if m.Version == 44 {
			if err := upgraded.execLocal(ctx, `DELETE FROM applied_migrations WHERE id = ?`, m.ID); err != nil {
				t.Fatalf("remove v44 ledger %s: %v", m.ID, err)
			}
		}
	}
	if err := upgraded.execLocal(ctx, `UPDATE schema_state SET version = 43 WHERE id = 1`); err != nil {
		t.Fatalf("stamp v43: %v", err)
	}
	if err := InitSchema(ctx, upgraded); err != nil {
		t.Fatalf("migrate v43 to v44: %v", err)
	}

	for _, table := range []string{"containers", "hosts", "notification_routes"} {
		freshColumns := tableColumnOrder(t, fresh, table)
		upgradedColumns := tableColumnOrder(t, upgraded, table)
		if !reflect.DeepEqual(freshColumns, upgradedColumns) {
			t.Errorf("%s column order differs:\nfresh:    %v\nupgraded: %v",
				table, freshColumns, upgradedColumns)
		}
	}
}

func tableColumnOrder(t *testing.T, c *Client, table string) []string {
	t.Helper()
	rows, err := c.Query(context.Background(), `PRAGMA table_info(`+table+`)`)
	if err != nil {
		t.Fatalf("read %s column order: %v", table, err)
	}
	columns := make([]string, 0, len(rows))
	for _, row := range rows {
		columns = append(columns, row.String("name"))
	}
	return columns
}

func TestSchemaV44RecordRoundTripsPreserveFields(t *testing.T) {
	c := newTestDB(t)
	ctx := context.Background()

	ct := ContainerRecord{
		HostName:          "h1",
		Name:              "ct1",
		State:             "pending",
		OwnerEpoch:        7,
		SpecGeneration:    9,
		ActiveOperationID: "op-1",
	}
	if err := UpsertContainer(ctx, c, ct); err != nil {
		t.Fatalf("upsert container: %v", err)
	}
	if _, err := c.db.Exec(
		`UPDATE containers
		 SET owner_epoch = ?, spec_generation = ?, active_operation_id = ?
		 WHERE host_name = ? AND name = ?`,
		ct.OwnerEpoch, ct.SpecGeneration, ct.ActiveOperationID, ct.HostName, ct.Name,
	); err != nil {
		t.Fatalf("seed receiver-only lifecycle fields: %v", err)
	}
	gotCT, err := GetContainer(ctx, c, "h1", "ct1")
	if err != nil || gotCT == nil {
		t.Fatalf("get container: got=%v err=%v", gotCT, err)
	}
	if gotCT.OwnerEpoch != 7 || gotCT.SpecGeneration != 9 || gotCT.ActiveOperationID != "op-1" {
		t.Fatalf("container lifecycle fields = (%d,%d,%q), want (7,9,op-1)",
			gotCT.OwnerEpoch, gotCT.SpecGeneration, gotCT.ActiveOperationID)
	}
	gotCT.State = "running"
	if err := UpsertContainer(ctx, c, *gotCT); err != nil {
		t.Fatalf("update container: %v", err)
	}
	gotCT, err = GetContainer(ctx, c, "h1", "ct1")
	if err != nil || gotCT == nil ||
		gotCT.OwnerEpoch != 7 || gotCT.SpecGeneration != 9 || gotCT.ActiveOperationID != "op-1" {
		t.Fatalf("container update lost lifecycle fields: got=%v err=%v", gotCT, err)
	}
	applied, err := RekeyContainerOwnerGuarded(ctx, c, *gotCT, "h2")
	if err != nil || applied {
		t.Fatalf("re-key container with active operation: applied=%v err=%v", applied, err)
	}
	if _, err := c.db.Exec(
		`UPDATE containers SET active_operation_id = ''
		 WHERE host_name = ? AND name = ?`,
		gotCT.HostName, gotCT.Name,
	); err != nil {
		t.Fatalf("clear completed operation barrier: %v", err)
	}
	gotCT, err = GetContainer(ctx, c, "h1", "ct1")
	if err != nil || gotCT == nil {
		t.Fatalf("get re-keyable container: got=%v err=%v", gotCT, err)
	}
	applied, err = RekeyContainerOwnerGuarded(ctx, c, *gotCT, "h2")
	if err != nil || !applied {
		t.Fatalf("re-key container after clearing operation: applied=%v err=%v", applied, err)
	}
	gotCT, err = GetContainer(ctx, c, "h2", "ct1")
	if err != nil || gotCT == nil ||
		gotCT.OwnerEpoch != 7 || gotCT.SpecGeneration != 9 || gotCT.ActiveOperationID != "" {
		t.Fatalf("container re-key lost lifecycle fields: got=%v err=%v", gotCT, err)
	}

	host := HostRecord{Name: "h2", State: "active", CapacityPolicyHash: "sha256:policy"}
	if err := InsertHost(ctx, c, host); err != nil {
		t.Fatalf("insert host: %v", err)
	}
	gotHost, err := GetHost(ctx, c, "h2")
	if err != nil || gotHost == nil || gotHost.CapacityPolicyHash != "sha256:policy" {
		t.Fatalf("host capacity policy hash: got=%v err=%v", gotHost, err)
	}

	route := NotificationRoute{
		ID:             "r2",
		EventPattern:   "workload.*",
		SubjectPattern: "vm:*",
		Project:        "acme",
		TargetID:       "t1",
		Enabled:        true,
	}
	if err := InsertNotificationRoute(ctx, c, route); err != nil {
		t.Fatalf("insert route: %v", err)
	}
	routes, err := ListNotificationRoutes(ctx, c)
	if err != nil || len(routes) != 1 ||
		routes[0].SubjectPattern != "vm:*" || routes[0].Project != "acme" {
		t.Fatalf("route scope fields: routes=%v err=%v", routes, err)
	}
}

func TestUpsertContainerPreservesLifecycleFieldsOnConflict(t *testing.T) {
	c := newTestDB(t)
	ctx := context.Background()

	if err := UpsertContainer(ctx, c, ContainerRecord{
		HostName:          "h1",
		Name:              "ct1",
		State:             "pending",
		Image:             "debian:12",
		OwnerEpoch:        7,
		SpecGeneration:    9,
		ActiveOperationID: "op-current",
	}); err != nil {
		t.Fatalf("seed container: %v", err)
	}
	if _, err := c.db.Exec(
		`UPDATE containers
		 SET owner_epoch = 7, spec_generation = 9, active_operation_id = 'op-current'
		 WHERE host_name = ? AND name = ?`,
		"h1", "ct1",
	); err != nil {
		t.Fatalf("seed receiver-only lifecycle fields: %v", err)
	}

	if err := UpsertContainer(ctx, c, ContainerRecord{
		HostName:          "h1",
		Name:              "ct1",
		State:             "running",
		Image:             "debian:13",
		OwnerEpoch:        1,
		SpecGeneration:    2,
		ActiveOperationID: "op-stale",
	}); err != nil {
		t.Fatalf("ordinary update with stale lifecycle fields: %v", err)
	}
	got, err := GetContainer(ctx, c, "h1", "ct1")
	if err != nil || got == nil {
		t.Fatalf("get container after stale update: got=%v err=%v", got, err)
	}
	if got.State != "running" || got.Image != "debian:13" {
		t.Fatalf("ordinary fields not updated: state=%q image=%q", got.State, got.Image)
	}
	if got.OwnerEpoch != 7 || got.SpecGeneration != 9 || got.ActiveOperationID != "op-current" {
		t.Fatalf("stale update changed lifecycle fields: got=(%d,%d,%q), want=(7,9,op-current)",
			got.OwnerEpoch, got.SpecGeneration, got.ActiveOperationID)
	}

	if err := UpsertContainer(ctx, c, ContainerRecord{
		HostName: "h1",
		Name:     "ct1",
		State:    "stopped",
		Image:    "debian:14",
	}); err != nil {
		t.Fatalf("ordinary update with omitted lifecycle fields: %v", err)
	}
	got, err = GetContainer(ctx, c, "h1", "ct1")
	if err != nil || got == nil {
		t.Fatalf("get container after omitted update: got=%v err=%v", got, err)
	}
	if got.State != "stopped" || got.Image != "debian:14" {
		t.Fatalf("ordinary fields not updated after omitted lifecycle fields: state=%q image=%q", got.State, got.Image)
	}
	if got.OwnerEpoch != 7 || got.SpecGeneration != 9 || got.ActiveOperationID != "op-current" {
		t.Fatalf("omitted update changed lifecycle fields: got=(%d,%d,%q), want=(7,9,op-current)",
			got.OwnerEpoch, got.SpecGeneration, got.ActiveOperationID)
	}
}

func TestSchemaV44BehindSenderPreservesReceiverOnlyFields(t *testing.T) {
	c := newTestDB(t)
	ctx := context.Background()

	if err := c.Execute(ctx,
		`INSERT INTO containers
		 (host_name, name, state, image, cpu_limit, memory_mib,
		  owner_epoch, spec_generation, active_operation_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"h1", "ct1", "pending", "debian", 2, 2048, 7, 9, "op-1",
		"2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed container: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO hosts
		 (name, address, ssh_user, cert_serial, capacity_policy_hash, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"h1", "10.0.0.1", "root", "serial", "sha256:policy",
		"2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed host: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO notification_routes
		 (id, event_pattern, subject_pattern, project, target_id, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"r1", "vm.*", "vm:*", "acme", "t1",
		"2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	const newer = "2000000000000-0000-n2"
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{
		{
			Name: "containers",
			Columns: []string{
				"host_name", "name", "state", "image", "cpu_limit", "memory_mib",
				"created_at", "updated_at",
			},
			Rows: [][]interface{}{{
				"h1", "ct1", "running", "debian", 2, 2048,
				"2020-01-01T00:00:00Z", newer,
			}},
		},
		{
			Name:    "hosts",
			Columns: []string{"name", "address", "ssh_user", "cert_serial", "created_at", "updated_at"},
			Rows: [][]interface{}{{
				"h1", "10.0.0.2", "root", "serial", "2020-01-01T00:00:00Z", newer,
			}},
		},
	}})
	c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name: "notification_routes",
		Columns: []string{
			"id", "event_pattern", "target_id", "created_at", "updated_at",
		},
		Rows: [][]interface{}{{
			"r1", "workload.*", "t1", "2020-01-01T00:00:00Z", newer,
		}},
	}}}))

	rows, err := c.Query(ctx,
		`SELECT state, owner_epoch, spec_generation, active_operation_id
		 FROM containers WHERE host_name = 'h1' AND name = 'ct1'`)
	if err != nil || len(rows) != 1 || rows[0].String("state") != "running" ||
		rows[0].Int64("owner_epoch") != 7 || rows[0].Int64("spec_generation") != 9 ||
		rows[0].String("active_operation_id") != "op-1" {
		t.Fatalf("behind container merge lost receiver-only fields: rows=%v err=%v", rows, err)
	}
	rows, err = c.Query(ctx, `SELECT address, capacity_policy_hash FROM hosts WHERE name = 'h1'`)
	if err != nil || len(rows) != 1 || rows[0].String("address") != "10.0.0.2" ||
		rows[0].String("capacity_policy_hash") != "sha256:policy" {
		t.Fatalf("behind host merge lost receiver-only field: rows=%v err=%v", rows, err)
	}
	rows, err = c.Query(ctx,
		`SELECT event_pattern, subject_pattern, project FROM notification_routes WHERE id = 'r1'`)
	if err != nil || len(rows) != 1 || rows[0].String("event_pattern") != "workload.*" ||
		rows[0].String("subject_pattern") != "vm:*" || rows[0].String("project") != "acme" {
		t.Fatalf("behind route merge lost receiver-only fields: rows=%v err=%v", rows, err)
	}
}
