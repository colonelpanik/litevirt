package fleet

import (
	"context"
	"io"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// pullDump reassembles node n's full state over the real streaming RPC — the
// same path anti-entropy uses to repair a lagging peer.
func pullDump(t *testing.T, c *Cluster, n *Node) []byte {
	t.Helper()
	stream, err := c.SelfClient(n).StreamStateDump(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("StreamStateDump: %v", err)
	}
	var blob []byte
	for {
		chunk, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("Recv: %v", rerr)
		}
		blob = append(blob, chunk.Data...)
	}
	return blob
}

func nodeHostAddr(t *testing.T, n *Node, name string) string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), "SELECT address FROM hosts WHERE name = ?", name)
	if err != nil || len(rows) == 0 {
		t.Fatalf("host %q on %s: err=%v rows=%d", name, n.Name, err, len(rows))
	}
	return rows[0].String("address")
}

func rowCount(t *testing.T, n *Node, query string, args ...interface{}) int {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), query, args...)
	if err != nil {
		t.Fatalf("count query on %s: %v", n.Name, err)
	}
	return rows[0].Int("n")
}

// TestFleet_AntiEntropyRepairsDivergence seeds varied replicated tables on one
// node, pulls its full state over the real gRPC/mTLS stack, and merges it into a
// lagging peer — which must then hold all of it (cross-table convergence).
func TestFleet_AntiEntropyRepairsDivergence(t *testing.T) {
	c := New(t, Options{Nodes: 3})
	a, b := c.Node("node-0"), c.Node("node-1")
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, a.DB, corrosion.HostRecord{
		Name: "wl", Address: "10.0.0.9", SSHUser: "root", CertSerial: "s", State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertVM(ctx, a.DB,
		corrosion.VMRecord{Name: "vm1", HostName: "wl", Spec: "{}", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "vm1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:cc"}},
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "wl", Path: "/d/vm1.qcow2", SizeBytes: 1 << 30, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertSecurityGroup(ctx, a.DB, corrosion.SecurityGroup{ID: "sg1", Name: "web", StackName: "s"}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}
	if err := corrosion.InsertSGRule(ctx, a.DB, corrosion.SGRule{ID: "r1", SGID: "sg1", Direction: "ingress", Proto: "tcp", PortRange: "443", Action: "allow"}); err != nil {
		t.Fatalf("InsertSGRule: %v", err)
	}
	if err := corrosion.InsertAuditLog(ctx, a.DB, corrosion.AuditRecord{ID: "a1", Username: "admin", Action: "create_vm", Target: "vm1", Result: "success"}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}

	b.DB.MergeStateBytesLWW(pullDump(t, c, a))

	for _, ch := range []struct {
		what  string
		query string
		args  []interface{}
	}{
		{"vm", "SELECT count(*) AS n FROM vms WHERE name = ?", []interface{}{"vm1"}},
		{"vm_disk", "SELECT count(*) AS n FROM vm_disks WHERE vm_name = ?", []interface{}{"vm1"}},
		{"vm_interface", "SELECT count(*) AS n FROM vm_interfaces WHERE vm_name = ?", []interface{}{"vm1"}},
		{"security_group", "SELECT count(*) AS n FROM security_groups WHERE id = ?", []interface{}{"sg1"}},
		{"sg_rule", "SELECT count(*) AS n FROM sg_rules WHERE id = ?", []interface{}{"r1"}},
		{"audit", "SELECT count(*) AS n FROM audit_log WHERE id = ?", []interface{}{"a1"}},
	} {
		if n := rowCount(t, b, ch.query, ch.args...); n != 1 {
			t.Errorf("after anti-entropy, %s row count on %s = %d, want 1 (divergence not repaired)", ch.what, b.Name, n)
		}
	}
}

// TestFleet_AntiEntropyLWWConflict creates conflicting writes to the same PK on
// two nodes and confirms bidirectional merge converges everywhere on the
// HLC-newest value — including a mixed RFC3339-vs-HLC case where HLC must win
// regardless of lexical order.
func TestFleet_AntiEntropyLWWConflict(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Node("node-0"), c.Node("node-1")
	ctx := context.Background()

	const hlcOld = "1000000000000-0000-na"
	const hlcNew = "2000000000000-0000-nb"

	seed := func(n *Node, name, addr, updatedAt string) {
		if err := n.DB.Execute(ctx,
			`INSERT OR REPLACE INTO hosts (name, address, ssh_user, cert_serial, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			name, addr, "root", "s", "2020-01-01T00:00:00Z", updatedAt); err != nil {
			t.Fatalf("seed %s on %s: %v", name, n.Name, err)
		}
	}

	// Conflict 1: pure HLC — B's write is newer.
	seed(a, "wl", "10.0.0.1", hlcOld)
	seed(b, "wl", "10.0.0.2", hlcNew)
	// Conflict 2: mixed format — A has a (lexically huge) RFC3339, B has HLC.
	seed(a, "wl2", "10.0.0.1", "2099-01-01T00:00:00Z")
	seed(b, "wl2", "10.0.0.2", hlcNew)

	// Bidirectional anti-entropy: merge each node's dump into the other.
	dumpA, dumpB := pullDump(t, c, a), pullDump(t, c, b)
	a.DB.MergeStateBytesLWW(dumpB)
	b.DB.MergeStateBytesLWW(dumpA)

	for _, n := range []*Node{a, b} {
		if got := nodeHostAddr(t, n, "wl"); got != "10.0.0.2" {
			t.Errorf("%s wl = %q, want 10.0.0.2 (HLC-newest must win everywhere)", n.Name, got)
		}
		if got := nodeHostAddr(t, n, "wl2"); got != "10.0.0.2" {
			t.Errorf("%s wl2 = %q, want 10.0.0.2 (incoming HLC must beat legacy RFC3339)", n.Name, got)
		}
	}
}
