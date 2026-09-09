// THE PRERELEASE UPGRADE BOUNDARY, AT FLEET TIER.
//
// A database that carries the removed permanent-loss trust schema cannot be
// migrated by this build: a binding never recorded which evidence its inventory
// proof rested on, so one that went live on a grant cannot be told apart from one
// proved against every participant. The daemon refuses to start on such a
// database and changes nothing, leaving the evidence for a deliberate offline
// recovery (docs/reviews/2026-09-08-trust-lifecycle-followup-scope.md).
//
// WHY THIS BELONGS HERE AND NOT ONLY IN THE STORAGE PACKAGE. The refusal happens
// during one node's startup, and the question a rolling upgrade asks is what it
// does to the CLUSTER. A refusal that half-migrated — suspending a binding and
// then failing — would replicate that suspension to every peer and take the
// network's allocation down fleet-wide, from one node that never came up. So the
// assertion is the whole cluster's: the refusing node's rows are untouched, the
// accounting the removed mechanism recorded survives, and a peer that never
// carried the schema keeps binding and allocating.

package fleet

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedPrereleaseAccounting gives one node's database the prerelease accounting
// table and one row in it — the shape of a node that ran those commits and
// recorded an operator's account of a permanently lost machine.
//
// The accounting row matters beyond being a detection signal: while it existed it
// was a discovery reference to a host, and erasing it is how the migration this
// boundary replaced came to free a stopped-but-defined guest's address. It has to
// be here after the refusal.
func seedPrereleaseAccounting(t *testing.T, n *Node) {
	t.Helper()
	ctx := context.Background()
	if err := n.DB.Execute(ctx, `CREATE TABLE netbox_recovery_manifests (
		id TEXT PRIMARY KEY, cluster_fingerprint TEXT NOT NULL, host_name TEXT NOT NULL,
		host_incarnation TEXT NOT NULL, premise TEXT NOT NULL, accounting TEXT NOT NULL,
		attested_by TEXT NOT NULL, attested_at TEXT NOT NULL, created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL, deleted_at TEXT)`); err != nil {
		t.Fatalf("seed the prerelease accounting table on %s: %v", n.Name, err)
	}
	fp, err := corrosion.ClusterFingerprint(ctx, n.DB)
	if err != nil {
		t.Fatalf("ClusterFingerprint on %s: %v", n.Name, err)
	}
	if err := n.DB.Execute(ctx, `INSERT INTO netbox_recovery_manifests
		(id, cluster_fingerprint, host_name, host_incarnation, premise, accounting,
		 attested_by, attested_at, created_at, updated_at)
		VALUES ('an-account', ?, 'a-lost-host', 'an-incarnation', 'membership', '',
		        'an-operator', '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z',
		        '2026-09-01T00:00:00Z')`, fp); err != nil {
		t.Fatalf("seed a prerelease accounting row on %s: %v", n.Name, err)
	}
}

// accountingRows counts what survived on n.
func accountingRows(t *testing.T, n *Node) int {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT COUNT(*) AS n FROM netbox_recovery_manifests`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("count the accounting rows on %s: err=%v rows=%d", n.Name, err, len(rows))
	}
	return rows[0].Int("n")
}

// TestFleetAPrereleaseDatabaseRefusesToStartAndTheClusterIsUnaffected.
//
// One node of a live, bound, allocating cluster is given the prerelease schema
// and re-initialized, which is what a daemon restart onto this build does. It
// must refuse — and the cluster must be exactly where it was.
func TestFleetAPrereleaseDatabaseRefusesToStartAndTheClusterIsUnaffected(t *testing.T) {
	ctx := context.Background()
	nb, c := boundCluster(t, 2)
	carrier, peer := c.Nodes[0], c.Nodes[1]

	first := mustCreateVMOnNetwork(t, c, carrier, "first-guest", orphanNetwork)
	firstIP := vmNICIP(t, carrier, first.GetName())
	if firstIP == "" {
		t.Fatal("control: a guest on a live NetBox binding must be given an address")
	}
	claimed := len(nb.Identities())

	seedPrereleaseAccounting(t, carrier)

	if err := corrosion.InitSchema(ctx, carrier.DB); err == nil {
		t.Fatal("a node whose database carries the prerelease permanent-loss trust schema " +
			"started. It cannot tell which of its bindings the removed grants authorized, so " +
			"it must refuse rather than migrate on a guess")
	} else {
		t.Logf("refused, as it must: %v", err)
	}

	// THE REFUSING NODE WROTE NOTHING. A suspension written here would replicate
	// and take allocation down on every peer.
	b, err := corrosion.GetBindingByPrefix(ctx, carrier.DB, orphanPrefixID)
	if err != nil || b == nil {
		t.Fatalf("the binding row must survive the refusal: %+v (err %v)", b, err)
	}
	if b.Suspended {
		t.Fatalf("the refusal suspended a binding: %q. It must change nothing — the whole "+
			"point of refusing is that this build cannot tell which bindings were affected",
			b.SuspendReason)
	}
	if got := accountingRows(t, carrier); got != 1 {
		t.Errorf("the refusal erased the prerelease accounting (%d rows left). Removing "+
			"authority must not erase knowledge: that row was a discovery reference to a "+
			"host, and dropping it is how the migration this replaced freed a live guest's "+
			"address", got)
	}
	if got := len(nb.Identities()); got != claimed {
		t.Errorf("the refusal disturbed NetBox objects behind existing claims, %d -> %d",
			claimed, got)
	}

	// AND THE PEER IS UNAFFECTED, which is what makes this a boundary rather than
	// an outage. It never carried the schema, so it starts — and the schema does
	// not travel: the removed tables left the replicated set with the mechanism,
	// so one node's unsupported database cannot spread the refusal to a fleet.
	if err := corrosion.InitSchema(ctx, peer.DB); err != nil {
		t.Fatalf("a peer that never carried the prerelease schema refused to start: %v", err)
	}
	if rows, qerr := peer.DB.Query(ctx,
		`SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table'
		   AND name = 'netbox_recovery_manifests'`); qerr != nil || len(rows) == 0 {
		t.Fatalf("look for the prerelease table on the peer: err=%v rows=%d", qerr, len(rows))
	} else if rows[0].Int("n") != 0 {
		t.Error("the prerelease schema replicated to a peer that never ran those commits; " +
			"one node's unsupported database must not spread")
	}

	// STILL ALLOCATING. The refusal wrote nothing, so the data it refused to
	// migrate is exactly as functional as it was.
	second := mustCreateVMOnNetwork(t, c, carrier, "second-guest", orphanNetwork)
	if ip := vmNICIP(t, carrier, second.GetName()); ip == "" || ip == firstIP {
		t.Fatalf("the binding must keep allocating distinct addresses after the refusal, "+
			"got %q (first %q)", ip, firstIP)
	}
}
