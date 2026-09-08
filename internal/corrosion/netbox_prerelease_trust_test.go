package corrosion

import (
	"context"
	"strings"
	"testing"
)

// THE GRANDFATHERING HAZARD, IN EXECUTABLE FORM.
//
// The removed permanent-loss mechanism could authorize a binding to go live: an
// inventory grant excused a destroyed peer from producing its digest, the proof
// completed, and the binding served claims. Nothing about that decision was
// written onto the binding row — it records `suspended`, a reason and a
// validation timestamp, never which evidence its proof rested on.
//
// So once the grant tables are gone, a binding that went live on a grant is
// INDISTINGUISHABLE from one proved against every participant, and it would keep
// allocating on authority it never earned with nothing left to review. Detection
// is still possible at the level that matters — the grant rows are append-only,
// so their presence says the mechanism was used in THIS database — and the
// fail-closed answer is to suspend and require re-proving.
//
// These scenarios pin the three outcomes that have to be different from each
// other: grants recorded (suspend), tables present but empty (leave alone), no
// tables at all (leave alone). A heal that suspended in all three would be an
// outage; one that suspended in none would be the silent grandfather.

// seedPrereleaseTrustTables re-creates the three removed tables exactly as the
// prerelease DDL did, so a scenario starts from the database an operator who ran
// those commits actually has.
func seedPrereleaseTrustTables(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
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

// seedLiveBindingAndClaim gives the database one live binding and one claim
// against it — the two things a heal must treat differently.
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

func bindingSuspension(t *testing.T, c *Client) (bool, string) {
	t.Helper()
	b, err := GetBindingByPrefix(context.Background(), c, 7)
	if err != nil {
		t.Fatalf("read the binding: %v", err)
	}
	if b == nil {
		t.Fatal("the binding row went away; a trust heal must never delete one")
	}
	return b.Suspended, b.SuspendReason
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

// TestARecordedPrereleaseGrantSuspendsEveryLiveBinding is the fail-closed case.
//
// The grant is for the INVENTORY premise, the one that could authorize a binding
// to go live. It could equally have been membership: the point is that the
// binding row does not say, so the heal cannot be selective and must not pretend
// to be.
func TestARecordedPrereleaseGrantSuspendsEveryLiveBinding(t *testing.T) {
	c := testClient(t)
	seedPrereleaseTrustTables(t, c)
	recordPrereleaseGrant(t, c, "a-lost-host", "inventory")
	seedLiveBindingAndClaim(t, c)

	if suspended, _ := bindingSuspension(t, c); suspended {
		t.Fatal("precondition: the binding must start live")
	}
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema over a database that recorded a prerelease grant: %v", err)
	}

	suspended, reason := bindingSuspension(t, c)
	if !suspended {
		t.Fatal("a binding that may have gone live on a removed permanent-loss grant was left " +
			"LIVE. It cannot be told apart from one proved against every participant, so it " +
			"would keep allocating on authority nothing can any longer review — the silent " +
			"grandfather this heal exists to prevent")
	}
	// The reason has to send the operator somewhere. A suspension with no remedy
	// in it reads as a fault.
	for _, want := range []string{"prerelease", "lv netbox resume"} {
		if !strings.Contains(reason, want) {
			t.Errorf("the suspension reason must name %q so an operator can tell a known "+
				"boundary from a fault: %q", want, reason)
		}
	}
	// THE CLAIM IS UNTOUCHED. A suspension refuses NEW allocation; revoking a
	// live guest's address would turn a bookkeeping correction into an outage.
	if !claimSurvives(t, c) {
		t.Error("the existing claim was disturbed; a trust heal must leave claims and NetBox " +
			"objects exactly as they are")
	}
	// And the tables are gone, so nothing is left with no reader — and the heal
	// is idempotent by construction.
	for _, table := range prereleaseTrustTables {
		if ok, _ := tableExists(context.Background(), c, table); ok {
			t.Errorf("%s survived the heal; a table with no reader is a trap for the "+
				"follow-up", table)
		}
	}
}

// TestTheHealIsIdempotentAndDoesNotReSuspendAReProvedBinding is the other half of
// dropping the tables.
//
// An operator who re-proves a binding with `lv netbox resume` must not find it
// suspended again on the next daemon start. Dropping the tables is what makes
// that true without any "already healed" bookkeeping.
func TestTheHealIsIdempotentAndDoesNotReSuspendAReProvedBinding(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedPrereleaseTrustTables(t, c)
	recordPrereleaseGrant(t, c, "a-lost-host", "membership")
	seedLiveBindingAndClaim(t, c)

	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("first InitSchema: %v", err)
	}
	if suspended, _ := bindingSuspension(t, c); !suspended {
		t.Fatal("precondition: the first heal must suspend")
	}

	// The operator re-proves and resumes.
	b, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil {
		t.Fatal(err)
	}
	b.Suspended, b.SuspendReason = false, ""
	if err := UpsertBinding(ctx, c, *b); err != nil {
		t.Fatalf("resume the binding: %v", err)
	}

	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("second InitSchema: %v", err)
	}
	if suspended, reason := bindingSuspension(t, c); suspended {
		t.Fatalf("a re-proved binding was suspended again by a later start: %q", reason)
	}
}

// TestEmptyPrereleaseTablesLeaveBindingsAlone is the case that keeps the heal from
// being an outage.
//
// A database that ran the prerelease build but never retired anything has the
// tables and no grants, so no binding can have been authorized by one. Suspending
// here would be caution with no subject.
func TestEmptyPrereleaseTablesLeaveBindingsAlone(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedPrereleaseTrustTables(t, c)
	seedLiveBindingAndClaim(t, c)

	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if suspended, reason := bindingSuspension(t, c); suspended {
		t.Fatalf("the tables held no grant, so nothing was authorized by one and the binding "+
			"must stay live: %q", reason)
	}
	for _, table := range prereleaseTrustTables {
		if ok, _ := tableExists(ctx, c, table); ok {
			t.Errorf("%s survived the heal", table)
		}
	}
}

// TestAnOrdinaryDatabaseIsUntouched is acceptance case 5 at the storage layer: a
// binding authorized independently of the removed mechanism keeps allocating, and
// its claims stay intact, across as many restarts as it likes.
func TestAnOrdinaryDatabaseIsUntouched(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedLiveBindingAndClaim(t, c)

	for i := 0; i < 3; i++ {
		if err := InitSchema(ctx, c); err != nil {
			t.Fatalf("InitSchema pass %d: %v", i, err)
		}
	}
	if suspended, reason := bindingSuspension(t, c); suspended {
		t.Fatalf("an independently authorized binding was suspended: %q", reason)
	}
	if !claimSurvives(t, c) {
		t.Error("an existing claim was disturbed")
	}
}

// TestATombstonedGrantStillSuspends, because deleting a row was never a way to
// establish that it had not been recorded.
//
// The removed withdrawal path already had this rule in the other direction: a
// tombstone on a withdrawal did not restore trust. The same reasoning applies
// here — a grant with a deleted_at is still a grant that may have authorized a
// binding, so the heal reads the rows without filtering deleted_at.
func TestATombstonedGrantStillSuspends(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedPrereleaseTrustTables(t, c)
	recordPrereleaseGrant(t, c, "a-lost-host", "inventory")
	if err := c.execLocal(ctx,
		`UPDATE netbox_host_retirements SET deleted_at = '2026-09-08T01:00:00Z'`); err != nil {
		t.Fatalf("tombstone the grant: %v", err)
	}
	if err := c.execLocal(ctx,
		`UPDATE netbox_recovery_manifests SET deleted_at = '2026-09-08T01:00:00Z'`); err != nil {
		t.Fatalf("tombstone the manifest: %v", err)
	}
	seedLiveBindingAndClaim(t, c)

	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if suspended, _ := bindingSuspension(t, c); !suspended {
		t.Fatal("a tombstoned grant left a binding live; deleting the row must not be a way " +
			"to inherit the authority it granted")
	}
}
