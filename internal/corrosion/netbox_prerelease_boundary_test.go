package corrosion

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// THE UNSUPPORTED UPGRADE, IN EXECUTABLE FORM.
//
// The removed permanent-loss mechanism could authorize a binding to go live: an
// inventory grant excused a destroyed peer from producing its digest, the proof
// completed, and the binding served claims. Nothing about that decision was
// written onto the binding row — it records `suspended`, a reason and a
// validation timestamp, never which evidence its proof rested on.
//
// So a database that ran those prerelease commits cannot be migrated by a build
// that has no way to attribute the authority. The answer is to REFUSE, preserve
// every artifact, and say so. These scenarios pin the three outcomes that have to
// be different from each other: the prerelease tables present (refuse), the
// removed evaluator's condition rows present with the tables already gone
// (refuse), and neither (start exactly as before).
//
// THE NEGATIVE CASE IS THE IMPORTANT ONE. A boundary that refuses everything is
// indistinguishable from a broken daemon, so every refusal here is paired with a
// clean database that must still start, and with an assertion that the refusal
// changed nothing.

// seedPrereleaseTrustTables re-creates the three removed tables exactly as the
// prerelease DDL did, so a scenario starts from the database an operator who ran
// those commits actually has.
//
// It also writes the MIGRATION LEDGER rows that build wrote, because they are
// part of the same database state: the tables were created by schemaDDL and then
// recorded as create-table units by the ledger loop, in one startup. A seed that
// created the tables without the ledger rows would model a database no build has
// ever produced — and would leave the ledger signal untested against the shape it
// exists for.
func seedPrereleaseTrustTables(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	seedPrereleaseTrustLedger(t, c)
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS netbox_recovery_manifests (
			id TEXT PRIMARY KEY, cluster_fingerprint TEXT NOT NULL, host_name TEXT NOT NULL,
			host_incarnation TEXT NOT NULL, premise TEXT NOT NULL, accounting TEXT NOT NULL,
			attested_by TEXT NOT NULL, attested_at TEXT NOT NULL, created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL, deleted_at TEXT)`,
		`CREATE TABLE IF NOT EXISTS netbox_host_retirements (
			cluster_fingerprint TEXT NOT NULL, host_incarnation TEXT NOT NULL,
			premise TEXT NOT NULL, host_name TEXT NOT NULL, manifest_id TEXT NOT NULL,
			attested_by TEXT NOT NULL, attested_at TEXT NOT NULL, created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL, deleted_at TEXT,
			PRIMARY KEY (cluster_fingerprint, host_incarnation, premise))`,
		`CREATE TABLE IF NOT EXISTS netbox_retirement_withdrawals (
			cluster_fingerprint TEXT NOT NULL, host_incarnation TEXT NOT NULL,
			premise TEXT NOT NULL, manifest_id TEXT NOT NULL, host_name TEXT NOT NULL,
			withdrawn_by TEXT NOT NULL, withdrawn_at TEXT NOT NULL, reason TEXT NOT NULL,
			created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted_at TEXT,
			PRIMARY KEY (cluster_fingerprint, host_incarnation, premise, manifest_id))`,
	} {
		if err := c.execLocal(ctx, ddl); err != nil {
			t.Fatalf("seed a prerelease trust table: %v", err)
		}
	}
}

// seedPrereleaseTrustLedger records the create-table units the prerelease build
// wrote into applied_migrations when it created the three removed tables.
//
// This is the artifact the removal path CANNOT erase: it drops the tables and
// never touches the ledger, and the migration loop only reads and inserts, so
// these ids outlive every later upgrade.
func seedPrereleaseTrustLedger(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	for _, id := range prereleaseTrustLedgerIDs {
		if err := c.execLocal(ctx,
			`INSERT OR IGNORE INTO applied_migrations (id, applied_at, checksum)
			 VALUES (?, '2026-09-08T00:00:00Z', '')`, id); err != nil {
			t.Fatalf("seed the prerelease ledger entry %s: %v", id, err)
		}
	}
}

// seedPrereleaseSuspension writes the suspension the rejected automatic
// migration left on every live binding.
func seedPrereleaseSuspension(t *testing.T, c *Client) {
	t.Helper()
	if err := c.execLocal(context.Background(),
		`UPDATE netbox_bindings SET suspended = 1, suspend_reason = ?, updated_at = ?`,
		prereleaseTrustSuspendPrefix+", which have been removed", "2026-09-08T20:00:00Z"); err != nil {
		t.Fatalf("seed the removed migration's suspension: %v", err)
	}
}

// recordPrereleaseGrant writes one grant plus the manifest it rested on, which is
// the pair the removed RPC always wrote together.
func recordPrereleaseGrant(t *testing.T, c *Client, host, premise string) {
	t.Helper()
	ctx := context.Background()
	now := "2026-09-08T00:00:00Z"
	if err := c.execLocal(ctx,
		`INSERT INTO netbox_recovery_manifests
		 (id, cluster_fingerprint, host_name, host_incarnation, premise, accounting,
		  attested_by, attested_at, created_at, updated_at)
		 VALUES ('manifest-1', 'fp-1', ?, 'incarnation-1', ?, '', 'an-operator', ?, ?, ?)`,
		host, premise, now, now, now); err != nil {
		t.Fatalf("record a prerelease manifest: %v", err)
	}
	if err := c.execLocal(ctx,
		`INSERT INTO netbox_host_retirements
		 (cluster_fingerprint, host_incarnation, premise, host_name, manifest_id,
		  attested_by, attested_at, created_at, updated_at)
		 VALUES ('fp-1', 'incarnation-1', ?, ?, 'manifest-1', 'an-operator', ?, ?, ?)`,
		premise, host, now, now, now); err != nil {
		t.Fatalf("record a prerelease grant: %v", err)
	}
}

// seedRemovedEvaluatorConditions writes the health conditions the removed
// attestation evaluator used to keep up. Nothing writes or resolves them now.
func seedRemovedEvaluatorConditions(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	for _, cond := range []HealthCondition{
		{
			Evaluator: "netbox", Code: "netbox_premise_attested",
			SubjectKind: "host_incarnation", SubjectID: "incarnation-1",
			Lifecycle: ConditionConfirmed, Severity: SeverityInfo,
			FirstSeen: "2026-09-08T00:00:00Z", LastSeen: "2026-09-08T00:00:00Z",
		},
		{
			Evaluator: "netbox", Code: "netbox_attestation_unvalidatable",
			SubjectKind: "cluster", SubjectID: "netbox",
			Lifecycle: ConditionConfirmed, Severity: SeverityWarning,
			FirstSeen: "2026-09-08T00:00:00Z", LastSeen: "2026-09-08T00:00:00Z",
		},
	} {
		if err := UpsertHealthCondition(ctx, c, cond); err != nil {
			t.Fatalf("seed a removed-evaluator condition: %v", err)
		}
	}
}

// seedLiveBindingAndClaim gives the database one live binding and one claim
// against it — the two things a refusal must leave exactly as they are.
func seedLiveBindingAndClaim(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	ours, err := ClaimBinding(ctx, c, BindingRecord{
		Network: "a-network", PrefixID: 7, ObservedCIDR: "192.0.2.0/24",
		VRFID: 1, ClusterFingerprint: "fp-1", NetBoxCluster: "a-cluster",
	})
	if err != nil || !ours {
		t.Fatalf("seed a live binding: ours=%v err=%v", ours, err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO ip_allocations
		   (network, ip, mac, vm_name, owner_kind, netbox_ip_id, netbox_prefix_id,
		    allocated_at, updated_at)
		 VALUES ('a-network', '192.0.2.10', '52:54:00:00:00:01', 'a-guest', 'vm', 4242, 7, ?, ?)`,
		c.NowTS(), c.NowTS()); err != nil {
		t.Fatalf("seed a claim: %v", err)
	}
}

// bindingRows is every column of every binding row, in a fixed order, so "the
// refusal wrote nothing" is compared as a whole rather than one field at a time.
// `suspended` and `updated_at` are the two the removed migration wrote, and they
// are in here for that reason, but the point is that NOTHING moved.
func bindingRows(t *testing.T, c *Client) string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT prefix_id, network, observed_cidr, vrf_id, cluster_fingerprint,
		        netbox_cluster, suspended, suspend_reason, validated_at,
		        created_at, updated_at, COALESCE(deleted_at, '') AS deleted_at
		   FROM netbox_bindings ORDER BY prefix_id`)
	if err != nil {
		t.Fatalf("read the bindings: %v", err)
	}
	var b strings.Builder
	for _, r := range rows {
		fmt.Fprintf(&b, "prefix=%d network=%q cidr=%q vrf=%d fp=%q cluster=%q suspended=%d "+
			"reason=%q validated=%q created=%q updated=%q deleted=%q\n",
			r.Int("prefix_id"), r.String("network"), r.String("observed_cidr"),
			r.Int("vrf_id"), r.String("cluster_fingerprint"), r.String("netbox_cluster"),
			r.Int("suspended"), r.String("suspend_reason"), r.String("validated_at"),
			r.String("created_at"), r.String("updated_at"), r.String("deleted_at"))
	}
	if len(rows) == 0 {
		t.Fatal("the binding row went away; a refusal must never delete one")
	}
	return b.String()
}

func claimSurvives(t *testing.T, c *Client) bool {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT COUNT(*) AS n FROM ip_allocations WHERE ip = '192.0.2.10' AND deleted_at IS NULL`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("count claims: err=%v rows=%d", err, len(rows))
	}
	return rows[0].Int("n") == 1
}

// tablesPresent reports which prerelease trust tables the database still has.
func tablesPresent(t *testing.T, c *Client) []string {
	t.Helper()
	var present []string
	for _, table := range prereleaseTrustTables {
		ok, err := tableExists(context.Background(), c, table)
		if err != nil {
			t.Fatalf("look for %s: %v", table, err)
		}
		if ok {
			present = append(present, table)
		}
	}
	return present
}

// TestAPrereleaseTrustDatabaseRefusesToStartAndIsNotModified is the boundary.
//
// The grant is for the INVENTORY premise, the one that could authorize a binding
// to go live. It could equally have been membership: the point is that the
// binding row does not say, so no migration can be selective and this build does
// not pretend to be.
func TestAPrereleaseTrustDatabaseRefusesToStartAndIsNotModified(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedPrereleaseTrustTables(t, c)
	recordPrereleaseGrant(t, c, "a-lost-host", "inventory")
	seedLiveBindingAndClaim(t, c)

	before := bindingRows(t, c)
	if strings.Contains(before, "suspended=1") {
		t.Fatal("precondition: the binding must start live")
	}

	err := InitSchema(ctx, c)
	if err == nil {
		t.Fatal("a database carrying the prerelease permanent-loss trust schema STARTED. " +
			"A binding that went live on a removed grant cannot be told apart from one " +
			"proved against every participant, and this build cannot work out which is " +
			"which — so it must refuse rather than migrate on a guess")
	}

	// NOTHING WAS MODIFIED, which is the half that makes a deliberate offline
	// recovery possible at all.
	if after := bindingRows(t, c); after != before {
		t.Errorf("the refusal modified a binding row.\nbefore: %s after:  %s", before, after)
	}
	if !claimSurvives(t, c) {
		t.Error("the refusal disturbed an existing claim; it must write nothing at all")
	}
	if got := tablesPresent(t, c); len(got) != len(prereleaseTrustTables) {
		t.Errorf("the refusal dropped a prerelease table (%v remain); the evidence is the "+
			"only surviving account of what was granted and must survive intact", got)
	}
	// The grant rows themselves, not merely the tables.
	rows, qerr := c.Query(ctx, `SELECT COUNT(*) AS n FROM netbox_host_retirements`)
	if qerr != nil || len(rows) == 0 || rows[0].Int("n") != 1 {
		t.Errorf("the recorded grant did not survive: err=%v rows=%v", qerr, rows)
	}
}

// TestEmptyPrereleaseTrustTablesStillRefuse.
//
// The migration this replaced treated empty local grant tables as proof that no
// binding had been authorized by one, and dropped them silently. That is not
// sound on a REPLICA: rows arrive per table, so a node can hold the live binding
// before the grant rows that authorized it. Append-only is a positive signal, not
// a completeness proof — the SCHEMA being here is what says this database ran
// those commits, and that is what is detected.
func TestEmptyPrereleaseTrustTablesStillRefuse(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedPrereleaseTrustTables(t, c)
	seedLiveBindingAndClaim(t, c)

	before := bindingRows(t, c)
	if err := InitSchema(ctx, c); err == nil {
		t.Fatal("empty prerelease trust tables let the daemon start. A replica can hold the " +
			"live binding before the grant rows that authorized it, so an empty local table " +
			"proves nothing about how a binding came to be live")
	}
	if after := bindingRows(t, c); after != before {
		t.Errorf("the refusal modified a binding row.\nbefore: %s after:  %s", before, after)
	}
	if got := tablesPresent(t, c); len(got) != len(prereleaseTrustTables) {
		t.Errorf("the refusal dropped a prerelease table: %v remain", got)
	}
}

// TestATombstonedGrantStillRefuses, because deleting a row was never a way to
// establish that it had not been recorded. Detection reads neither `deleted_at`
// nor lifecycle for exactly this reason.
func TestATombstonedGrantStillRefuses(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedPrereleaseTrustTables(t, c)
	recordPrereleaseGrant(t, c, "a-lost-host", "inventory")
	for _, table := range []string{"netbox_host_retirements", "netbox_recovery_manifests"} {
		if err := c.execLocal(ctx,
			`UPDATE `+table+` SET deleted_at = '2026-09-08T01:00:00Z'`); err != nil {
			t.Fatalf("tombstone %s: %v", table, err)
		}
	}
	seedLiveBindingAndClaim(t, c)

	if err := InitSchema(ctx, c); err == nil {
		t.Fatal("a tombstoned grant let the daemon start; deleting the row must not be a way " +
			"to inherit the authority it granted")
	}
}

// TestOrphanedRemovedEvaluatorConditionsRefuseWithTheTablesGone is the SECOND
// shape, and the one a tables-only check would miss.
//
// This is the database of an operator who already ran the automatic migration
// that used to live here: it dropped the three tables and never touched
// health_conditions, so the removed evaluator's rows are still standing with no
// lifecycle owner — nothing writes them and nothing will ever resolve them. It is
// also the database that has already been rewritten once, which is precisely the
// one that must not be started on and rewritten again.
func TestOrphanedRemovedEvaluatorConditionsRefuseWithTheTablesGone(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedRemovedEvaluatorConditions(t, c)
	seedLiveBindingAndClaim(t, c)

	if got := tablesPresent(t, c); len(got) != 0 {
		t.Fatalf("precondition: the tables must be absent for this shape, found %v", got)
	}
	before := bindingRows(t, c)

	err := InitSchema(ctx, c)
	if err == nil {
		t.Fatal("a database whose prerelease trust tables were already dropped, but whose " +
			"removed-evaluator condition rows survive, STARTED. A tables-only check lets " +
			"exactly this database through")
	}
	for _, code := range prereleaseTrustConditionCodes {
		if !strings.Contains(err.Error(), code) {
			t.Errorf("the refusal must name the orphaned condition code %q it found: %v", code, err)
		}
	}
	if after := bindingRows(t, c); after != before {
		t.Errorf("the refusal modified a binding row.\nbefore: %s after:  %s", before, after)
	}
	// And the conditions themselves survive; they are part of the evidence.
	conds, cerr := ListHealthConditions(ctx, c, true)
	if cerr != nil {
		t.Fatalf("list conditions: %v", cerr)
	}
	seen := 0
	for _, h := range conds {
		for _, code := range prereleaseTrustConditionCodes {
			if h.Code == code {
				seen++
			}
		}
	}
	if seen != len(prereleaseTrustConditionCodes) {
		t.Errorf("the refusal removed a removed-evaluator condition row (%d of %d survive); "+
			"it is evidence and must be preserved", seen, len(prereleaseTrustConditionCodes))
	}
}

// TestAResolvedOrphanedConditionStillRefuses. A resolved advisory is still an
// advisory that stood, which is the same reasoning as the tombstoned grant: the
// row records that the mechanism was used here, and its lifecycle does not
// unrecord it.
func TestAResolvedOrphanedConditionStillRefuses(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if err := UpsertHealthCondition(ctx, c, HealthCondition{
		Evaluator: "netbox", Code: "netbox_premise_attested",
		SubjectKind: "host_incarnation", SubjectID: "incarnation-1",
		Lifecycle: ConditionResolved, Severity: SeverityInfo,
		ResolvedAt: "2026-09-08T01:00:00Z",
		FirstSeen:  "2026-09-08T00:00:00Z", LastSeen: "2026-09-08T00:00:00Z",
	}); err != nil {
		t.Fatalf("seed a resolved condition: %v", err)
	}
	if err := InitSchema(ctx, c); err == nil {
		t.Fatal("a resolved removed-evaluator condition let the daemon start; resolving a row " +
			"is not a way to unrecord that the mechanism was used in this database")
	}
}

// TestTheMigrationLedgerAloneRefuses is the shape the first two signals both
// miss, and the reason the third one is built from schema history rather than
// from another observable side effect.
//
// The rejected migration could run BEFORE the advisory had ever been evaluated:
// an advisory needs a running leader to write a condition row, and schema init
// runs first. Such a database ends up with no trust tables (dropped) and no
// condition rows (never written) — and it was accepted here. What it still has is
// the ledger entries recording that those tables were created in it, because
// dropping a table does not unrecord its creation and nothing has ever deleted a
// row from applied_migrations.
//
// The suspension marker is deliberately NOT seeded: this database's bindings were
// suspended, but the same gap can leave a database with no live binding to
// suspend at all, and the ledger has to stand on its own.
func TestTheMigrationLedgerAloneRefuses(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedPrereleaseTrustLedger(t, c)
	seedLiveBindingAndClaim(t, c)

	if got := tablesPresent(t, c); len(got) != 0 {
		t.Fatalf("precondition: the tables must be absent for this shape, found %v", got)
	}
	before := bindingRows(t, c)

	err := InitSchema(ctx, c)
	if err == nil {
		t.Fatal("a database whose prerelease trust tables and condition rows are BOTH gone " +
			"started, although its migration ledger still records that those tables were " +
			"created in it. That is the database of an operator whose migration ran before " +
			"the advisory ever wrote a row — neither of the other two signals can see it")
	}
	for _, id := range prereleaseTrustLedgerIDs {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("the refusal must name the ledger entry %q it found: %v", id, err)
		}
	}
	if after := bindingRows(t, c); after != before {
		t.Errorf("the refusal modified a binding row.\nbefore: %s after:  %s", before, after)
	}
	// The ledger rows are evidence too, and evidence is never consumed by the
	// check that reads it.
	rows, qerr := c.Query(ctx,
		`SELECT COUNT(*) AS n FROM applied_migrations WHERE id LIKE 't_netbox_%'`)
	if qerr != nil || len(rows) == 0 || rows[0].Int("n") < len(prereleaseTrustLedgerIDs) {
		t.Errorf("a prerelease ledger entry went away: err=%v rows=%v", qerr, rows)
	}
}

// TestADatabaseHealedWithoutAnAdvisoryStillRefuses is the state the rejected
// automatic migration actually left behind, reproduced from its own two data
// changes: suspend every live binding, then drop the three tables.
//
// It is the shape that escaped: the migration could run before the advisory had
// ever been evaluated, so this database has NEITHER trust tables NOR condition
// rows. Both signals that existed came up empty and it started. What it does
// have is the ledger entries recording that those tables were created in it, and
// the migration's own suspension reason on the binding — two artifacts written
// when the mechanism was installed and when it was removed, neither of which the
// removal path can erase.
func TestADatabaseHealedWithoutAnAdvisoryStillRefuses(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedPrereleaseTrustTables(t, c)
	recordPrereleaseGrant(t, c, "a-lost-host", "inventory")
	seedLiveBindingAndClaim(t, c)
	seedPrereleaseSuspension(t, c)
	for _, name := range prereleaseTrustTables {
		if err := c.execLocal(ctx, "DROP TABLE "+name); err != nil {
			t.Fatalf("drop %s the way the rejected migration did: %v", name, err)
		}
	}
	if got := tablesPresent(t, c); len(got) != 0 {
		t.Fatalf("precondition: the tables must be gone for this shape, found %v", got)
	}
	before := bindingRows(t, c)

	if err := InitSchema(ctx, c); err == nil {
		t.Fatal("an already-healed trust database started because no advisory had ever " +
			"written a condition row. Advisory history is not migration history: the tables " +
			"were created in this database and the removal has already run against it, and " +
			"both of those are recorded in artifacts the removal cannot erase")
	}
	if after := bindingRows(t, c); after != before {
		t.Errorf("the refusal modified a binding row.\nbefore: %s after:  %s", before, after)
	}
	if !claimSurvives(t, c) {
		t.Error("the refusal disturbed an existing claim; it must write nothing at all")
	}
}

// TestTheRemovedMigrationsOwnSuspensionRefuses is the fourth signal on its own.
//
// A binding suspended under that reason was suspended by the rejected migration
// and by nothing else, so it is a durable record that the removal has already
// been run against this database — the one state that must never be started on
// and rewritten a second time.
func TestTheRemovedMigrationsOwnSuspensionRefuses(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedLiveBindingAndClaim(t, c)
	seedPrereleaseSuspension(t, c)

	if got := tablesPresent(t, c); len(got) != 0 {
		t.Fatalf("precondition: the tables must be absent for this shape, found %v", got)
	}
	before := bindingRows(t, c)

	err := InitSchema(ctx, c)
	if err == nil {
		t.Fatal("a database carrying the removed migration's own suspension reason started; " +
			"that reason is written by that migration and by nothing else, so it records that " +
			"this database has already been rewritten once")
	}
	if !strings.Contains(err.Error(), "already run") {
		t.Errorf("the refusal must say the removed migration has already run here: %v", err)
	}
	if after := bindingRows(t, c); after != before {
		t.Errorf("the refusal modified a binding row.\nbefore: %s after:  %s", before, after)
	}
}

// TestACleanDatabaseStartsExactlyAsBefore is the negative case, and the most
// important test here.
//
// A boundary that refuses a database with none of these artifacts is a bricked
// cluster, which is a far worse outcome than the one it was built to prevent. An
// ordinary binding keeps allocating, its claims stay intact, and it survives as
// many restarts as it likes.
func TestACleanDatabaseStartsExactlyAsBefore(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedLiveBindingAndClaim(t, c)

	before := bindingRows(t, c)
	for i := 0; i < 3; i++ {
		if err := InitSchema(ctx, c); err != nil {
			t.Fatalf("a clean database refused to start on pass %d: %v", i, err)
		}
	}
	if after := bindingRows(t, c); after != before {
		t.Errorf("a clean database's binding changed across restarts.\nbefore: %s after:  %s",
			before, after)
	}
	if !claimSurvives(t, c) {
		t.Error("an existing claim was disturbed")
	}
	// A LIVE netbox condition under the still-current evaluator must not be
	// mistaken for the removed one — the codes are what is matched, not the
	// evaluator.
	if err := UpsertHealthCondition(ctx, c, HealthCondition{
		Evaluator: "netbox", Code: "netbox_binding_suspended",
		SubjectKind: "network", SubjectID: "a-network",
		Lifecycle: ConditionConfirmed, Severity: SeverityWarning,
		FirstSeen: "2026-09-08T00:00:00Z", LastSeen: "2026-09-08T00:00:00Z",
	}); err != nil {
		t.Fatalf("seed a live netbox condition: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("a live NetBox health condition was mistaken for the removed evaluator's: %v", err)
	}
}

// TestTheRefusalSaysWhatWasFoundAndWhatToDo pins the message, which is the
// deliverable: an operator staring at a daemon that will not start has to be able
// to tell a deliberate boundary from a fault, and to know the next step.
func TestTheRefusalSaysWhatWasFoundAndWhatToDo(t *testing.T) {
	msg := prereleaseTrustFinding{
		Tables:     prereleaseTrustTables,
		Conditions: []string{"netbox_premise_attested (2 row(s))"},
	}.refusal()

	// WHAT WAS FOUND, named specifically enough to act on.
	for _, want := range append(append([]string{}, prereleaseTrustTables...),
		"netbox_premise_attested (2 row(s))") {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must name what it found (%q):\n%s", want, msg)
		}
	}
	// THAT THIS BUILD CANNOT UPGRADE IT, and THAT NOTHING WAS MODIFIED.
	for _, want := range []string{
		"prerelease", "cannot upgrade it", "NOTHING HAS BEEN MODIFIED",
		"deliberate boundary, not a fault",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must say %q:\n%s", want, msg)
		}
	}
	// THE RECOVERY PATH: a backup first, then a deliberate offline procedure.
	for _, want := range []string{
		"backup", "OFFLINE",
		"docs/reviews/2026-09-08-trust-lifecycle-followup-scope.md",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal must point at the recovery path (%q):\n%s", want, msg)
		}
	}
	// AND IT MUST NOT ADVERTISE RESUME AS SUFFICIENT. Saying so is what made the
	// approach this replaced unsafe: resume re-proves against the participants
	// answering NOW, which on a database whose accounting was dropped is a
	// smaller universe that can succeed while freeing a live guest's address.
	if strings.Contains(msg, "lv netbox resume") &&
		!strings.Contains(msg, "`lv netbox resume` is NOT sufficient") {
		t.Errorf("the refusal names `lv netbox resume` without saying it is not sufficient; "+
			"advertising it as the remedy is the unsafe claim this boundary exists to "+
			"withdraw:\n%s", msg)
	}
}

// TestAnUnreadableCatalogueIsNotAbsence. Concluding "not present" from a lookup
// that failed would start a daemon on exactly the database this boundary stops,
// so the error propagates.
func TestAnUnreadableCatalogueIsNotAbsence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := testClient(t)
	cancel()
	if _, err := findPrereleaseTrustSchema(ctx, c); err == nil {
		t.Fatal("a catalogue lookup that could not run reported absence; an unreadable " +
			"catalogue is a failure, never an all-clear")
	}
}
