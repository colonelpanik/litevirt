// Fleet scenario: every renewal of the `netbox` leader lease reaches the peers.
//
// Three writers share the `netbox` lease under one holder — the orphan sweeper
// and the inventory mirror (an expiry two sweep intervals out) and the CA
// re-key (two minutes out). A re-key followed by the node's next mirror pass
// renews the lease twice in quick succession with DIFFERENT expiries.
//
// A receiver orders the renewals by updated_at and, on an exact tie, keeps its
// local row: leader_election is outside anti-entropy, so nothing repairs it.
// While acquireNetBoxLease stamped updated_at as a whole-second wall time, the
// second renewal tied the first on every peer and was dropped there. The holder
// then believed it led for thirty minutes while every peer saw its lease lapse
// after two, at which point any of them could take the lease while the holder
// went on sweeping and mirroring under its own: two NetBox writers.

package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// pumpStatementsOn carries from's mutation_log entries that write table to one
// peer, in order, over the real PushMutations RPC. The harness's own fixture
// writes (the cluster row's name) are not replicable shapes, so a scenario that
// pumps the whole log cannot get past them.
func pumpStatementsOn(t *testing.T, c *Cluster, from, to *Node, table string) {
	t.Helper()
	ctx := context.Background()
	rows, err := from.DB.Query(ctx,
		`SELECT seq, hlc, origin, stmts FROM mutation_log WHERE stmts LIKE ? ORDER BY seq`,
		"%"+table+"%")
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", from.Name, err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s logged no %s write; the pump would be vacuous", from.Name, table)
	}
	entries := make([]*pb.MutationEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, &pb.MutationEntry{
			Seq: r.Int64("seq"), Hlc: r.String("hlc"),
			Origin: r.String("origin"), Stmts: r.String("stmts"),
		})
	}
	if _, err := c.PeerClient(from, to).PushMutations(ctx, &pb.ReplicateRequest{
		Sender:              from.Name,
		SenderVersion:       "fleet-test",
		SenderSchemaVersion: int32(corrosion.CurrentSchemaVersion),
		Entries:             entries,
	}); err != nil {
		t.Fatalf("push %s→%s: %v", from.Name, to.Name, err)
	}
}

// inAFreshSecond runs fn at the start of a wall-clock second no earlier write
// shares, until one run also ends inside it. The fresh start matters as much
// as the end: a renewal tying an EARLIER write of the same second would leave
// the peer on that write's expiry, so the case under test would not be the
// only one in play.
func inAFreshSecond(t *testing.T, fn func()) {
	t.Helper()
	for attempt := 0; attempt < 5; attempt++ {
		now := time.Now()
		time.Sleep(now.Truncate(time.Second).Add(time.Second).Sub(now))
		before := time.Now().Unix()
		fn()
		if time.Now().Unix() == before {
			return
		}
	}
	t.Fatal("could not run the renewals within one second")
}

// netBoxLeaseExpiry reads the raw holder and expires_at of the `netbox` lease.
func netBoxLeaseExpiry(t *testing.T, n *Node) (holder, expires string) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT holder, expires_at FROM leader_election WHERE key = 'netbox'`)
	if err != nil {
		t.Fatalf("read the netbox lease on %s: %v", n.Name, err)
	}
	if len(rows) == 0 {
		return "", ""
	}
	return rows[0].String("holder"), rows[0].String("expires_at")
}

func TestFleet_NetBoxLeaseRenewalInTheSameSecondReplicates(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	c := NewClusterWithNetBox(t, 3, nb)
	latchNetBoxBoth(t, c, gateAll(t, c))
	leader := c.Nodes[0]

	// The re-key refuses with nothing mirrored, so give it one VM to re-stamp.
	mustCreateUnboundNetwork(t, c, leader, mirrorOnlyNetwork, "")
	mustCreateVM(t, leader, "lease-vm", mirrorOnlyNetwork)
	// The leader mirrors nothing until it has read every peer's published
	// NetBox cluster name.
	publishClusterNamesEverywhere(t, c)
	for _, n := range c.Nodes[1:] {
		pumpStatementsOn(t, c, n, leader, "netbox_host_config")
	}
	if err := leader.SyncNetBoxMirror(); err != nil {
		t.Fatalf("mirror pass on %s: %v", leader.Name, err)
	}

	var want string
	inAFreshSecond(t, func() {
		// The re-key takes the lease two minutes out, and the mirror pass
		// straight after renews it two sweep intervals out. A re-key with
		// nothing to re-stamp takes no lease, so move the fingerprint first.
		c.MoveClusterFingerprint()
		mustRekeyInventoryOnly(t, c, leader)
		_, rekeyExpiry := netBoxLeaseExpiry(t, leader)
		if err := leader.SyncNetBoxMirror(); err != nil {
			t.Fatalf("mirror pass on %s: %v", leader.Name, err)
		}
		var holder string
		holder, want = netBoxLeaseExpiry(t, leader)
		if holder != leader.Name {
			t.Fatalf("the netbox lease is held by %q, want %s", holder, leader.Name)
		}
		if want == rekeyExpiry {
			t.Fatalf("the mirror pass left the re-key's expiry %s in place; "+
				"the two renewals must differ for the scenario to prove anything", want)
		}
	})

	// Every renewal, in the order the holder wrote it.
	for _, n := range c.Nodes[1:] {
		pumpStatementsOn(t, c, leader, n, "leader_election")
	}
	for _, n := range c.Nodes {
		if h, e := netBoxLeaseExpiry(t, n); h != leader.Name || e != want {
			t.Errorf("%s: netbox lease is %q until %q; the holder %s has it until %q",
				n.Name, h, e, leader.Name, want)
		}
	}
}
