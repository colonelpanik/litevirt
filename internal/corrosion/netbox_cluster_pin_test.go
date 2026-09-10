package corrosion

import (
	"context"
	"testing"
)

// The binding row carries the NetBox cluster name the first bind resolved.
//
// `netbox.cluster_name` names the `virtualization.cluster` this installation
// mirrors into, and it has to be uniform cluster-wide: the mirror sweep runs on
// whichever node holds the `netbox` leader lease, so set non-uniformly, whichever
// node leads decides that sweep and the inventory moves between two cluster
// objects as leadership moves. Unlike every `enforcement.*` flag it has no latch
// to make it uniform, because a capability token cannot express a string.
//
// So it is PINNED on the binding row, next to the other facts a binding
// validates against (observed_cidr, vrf_id, cluster_fingerprint). The row already
// replicates, which is what a node needs in order to discover that its own
// configuration disagrees with the cluster's.

func newBindingTestClient(t *testing.T) *Client {
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

// TestClaimBindingRecordsTheNetBoxCluster pins the write and the read-back.
//
// A pin that did not round-trip would read back empty on every node, which the
// mismatch check treats as "nothing was pinned" — so it would not refuse, it
// would silently agree with everything.
func TestClaimBindingRecordsTheNetBoxCluster(t *testing.T) {
	c := newBindingTestClient(t)
	ctx := context.Background()

	rec := BindingRecord{
		PrefixID: 7, Network: "net-a", ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "fp", NetBoxCluster: "site-a",
	}
	ok, err := ClaimBinding(ctx, c, rec)
	if err != nil || !ok {
		t.Fatalf("ClaimBinding: ok=%v err=%v", ok, err)
	}

	got, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil || got == nil {
		t.Fatalf("GetBindingByPrefix: %+v err=%v", got, err)
	}
	if got.NetBoxCluster != "site-a" {
		t.Fatalf("NetBoxCluster = %q, want %q", got.NetBoxCluster, "site-a")
	}
	byNet, err := GetBindingByNetwork(ctx, c, "net-a")
	if err != nil || byNet == nil {
		t.Fatalf("GetBindingByNetwork: %+v err=%v", byNet, err)
	}
	if byNet.NetBoxCluster != "site-a" {
		t.Fatalf("GetBindingByNetwork NetBoxCluster = %q, want %q", byNet.NetBoxCluster, "site-a")
	}
	list, err := ListBindings(ctx, c)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListBindings: %d row(s) err=%v", len(list), err)
	}
	if list[0].NetBoxCluster != "site-a" {
		t.Fatalf("ListBindings NetBoxCluster = %q, want %q", list[0].NetBoxCluster, "site-a")
	}
}

// TestUpsertBindingPreservesTheNetBoxCluster pins the pin against the paths
// that REWRITE a binding.
//
// Revalidation, `lv netbox resume` and the CA re-key all write the whole row
// back. Every one of them runs on whichever node an operator happened to use, so
// a rewrite that dropped or re-observed the pin would let the disagreeing node
// overwrite the value that is supposed to catch it — the pin would follow the
// last writer, which is precisely the flapping this closes.
func TestUpsertBindingPreservesTheNetBoxCluster(t *testing.T) {
	c := newBindingTestClient(t)
	ctx := context.Background()

	rec := BindingRecord{
		PrefixID: 7, Network: "net-a", ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "fp", NetBoxCluster: "site-a",
	}
	if ok, err := ClaimBinding(ctx, c, rec); err != nil || !ok {
		t.Fatalf("ClaimBinding: ok=%v err=%v", ok, err)
	}

	// The shape every rewrite uses: read the row, change one flag, write it back.
	b, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil || b == nil {
		t.Fatalf("GetBindingByPrefix: %+v err=%v", b, err)
	}
	next := *b
	next.Suspended = true
	next.SuspendReason = "drifted"
	if err := UpsertBinding(ctx, c, next); err != nil {
		t.Fatalf("UpsertBinding: %v", err)
	}

	after, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil || after == nil {
		t.Fatalf("GetBindingByPrefix after upsert: %+v err=%v", after, err)
	}
	if after.NetBoxCluster != "site-a" {
		t.Fatalf("a rewrite lost the pin: NetBoxCluster = %q, want %q",
			after.NetBoxCluster, "site-a")
	}
}

// TestNetBoxClusterColumnHealsAnEarlierV51Database is the ALTER unit's reason to
// exist, and the answer to "does this column need a v52 migration?".
//
// It does not. netbox_bindings is NEW in v51 and v51 is unreleased, so no
// deployed database has ever held the table WITHOUT this column — the column
// belongs in the v51 CREATE TABLE, and CurrentSchemaVersion (the mixed-version
// replication skew signal) must not claim a v52 that nothing shipped.
//
// What DOES exist is a database created by an earlier commit of this branch: a
// dev box, an ephemeral cluster. There, CREATE TABLE IF NOT EXISTS is a no-op
// and the column would never appear, so every read of it would fail. The
// ledger's presence predicate is what covers that, which is why the column is
// declared in BOTH places — the same belt-and-braces shape every other column
// here has. On a fresh database the unit is recorded mark-only and its ALTER
// never runs.
func TestNetBoxClusterColumnHealsAnEarlierV51Database(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	ctx := context.Background()

	// The table exactly as an earlier v51 build created it: no netbox_cluster.
	// InitSchema's CREATE TABLE IF NOT EXISTS finds this and does nothing.
	if err := c.execLocal(ctx, `CREATE TABLE netbox_bindings (
		prefix_id           INTEGER PRIMARY KEY,
		network             TEXT NOT NULL,
		observed_cidr       TEXT NOT NULL,
		vrf_id              INTEGER NOT NULL,
		cluster_fingerprint TEXT NOT NULL,
		suspended           INTEGER NOT NULL DEFAULT 0,
		suspend_reason      TEXT NOT NULL DEFAULT '',
		validated_at        TEXT NOT NULL,
		created_at          TEXT NOT NULL,
		updated_at          TEXT NOT NULL,
		deleted_at          TEXT
	)`); err != nil {
		t.Fatalf("seed the pre-column table: %v", err)
	}

	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema over a pre-column netbox_bindings: %v", err)
	}

	// The end-to-end proof, not a PRAGMA: the pin round-trips, which it cannot
	// do unless the ALTER healed the column.
	ok, err := ClaimBinding(ctx, c, BindingRecord{
		PrefixID: 7, Network: "net-a", ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: "fp", NetBoxCluster: "site-a",
	})
	if err != nil || !ok {
		t.Fatalf("ClaimBinding after the heal: ok=%v err=%v", ok, err)
	}
	got, err := GetBindingByPrefix(ctx, c, 7)
	if err != nil || got == nil {
		t.Fatalf("GetBindingByPrefix after the heal: %+v err=%v", got, err)
	}
	if got.NetBoxCluster != "site-a" {
		t.Fatalf("NetBoxCluster = %q after the heal, want %q", got.NetBoxCluster, "site-a")
	}
}
