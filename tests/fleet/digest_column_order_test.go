package fleet

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A replica founded at an older schema and upgraded holds the columns later
// ALTERs added after deleted_at; a replica founded on this build holds them
// where CREATE TABLE puts them. For `vms`, a database founded at schema 0
// holds project, is_template, pending_action_id, the epochs and the hardware
// adoption pair after deleted_at, in ALTER order. Identical rows, different
// SELECT * order — and the positional v1 digest disagreed about the table on
// every pass, so anti-entropy re-pulled it from every differently-founded
// peer each cycle and `lv cluster converge` called it DIVERGENT for good.
//
// These scenarios hold the rows identical and change only node-1's physical
// column order, then ask what an operator asks: does node-1's anti-entropy
// comparison against node-0 find a difference, and what does each host's
// verification digest say.

const skewTable = "vms"

// olderFoundedPair is a two-node fleet holding one identical VM row, with
// node-1's table then rebuilt as a database founded at schema 0 and upgraded
// would hold it. node-1 emits v2 only if bEmitsV2. differs reports whether
// node-1's anti-entropy comparison — its own digest against node-0's, by
// corrosion.TableDigestsAgree, the predicate a pass pulls on — finds the
// table different.
//
// Before the rebuild both tables share one column order, and the comparison
// must agree whether or not node-1 emits v2: with one side v1-only, both v1
// hashes agree, and anything else would be a v1 hash judged against a v2 one.
func olderFoundedPair(t *testing.T, bEmitsV2 bool) (c *Cluster, a, b *Node, differs func() bool) {
	t.Helper()
	c = New(t, Options{Nodes: 2})
	a, b = c.Nodes[0], c.Nodes[1]
	b.DB.SetDigestV2Enabled(func() bool { return bEmitsV2 })
	ctx := context.Background()

	for _, n := range []*Node{a, b} {
		if err := n.DB.Execute(ctx, `INSERT INTO vms
			(name, host_name, spec, state, created_at, updated_at, project, is_template, vm_owner_epoch, spec_generation)
			VALUES ('colorder-vm', ?, '{"cpu":1}', 'stopped', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
			        'colorder', 0, 3, 5)`, a.Name); err != nil {
			t.Fatal(err)
		}
	}
	differs = func() bool {
		t.Helper()
		local := tableDigest(t, b, skewTable)
		remote, err := c.SelfClient(a).GetStateDigest(ctx, &emptypb.Empty{})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range remote.GetTables() {
			if r.GetName() == skewTable {
				return !corrosion.TableDigestsAgree(local, r)
			}
		}
		t.Fatalf("%s reported no %s digest", a.Name, skewTable)
		return false
	}
	if differs() {
		t.Fatalf("identical rows in one column order read as different (node-1 emits v2: %v)", bEmitsV2)
	}

	before := tableColumns(t, a, skewTable)
	after, err := b.DB.RefoundTableForTest(ctx, skewTable, 0)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Equal(before, after) {
		t.Fatalf("precondition: refounding should move the columns; both %v", after)
	}
	return c, a, b, differs
}

func tableDigest(t *testing.T, n *Node, table string) corrosion.TableDigest {
	t.Helper()
	ds, err := n.DB.StateDigest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		if d.Name == table {
			return d
		}
	}
	t.Fatalf("%s has no %s digest", n.Name, table)
	return corrosion.TableDigest{}
}

func tableColumns(t *testing.T, n *Node, table string) []string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `PRAGMA table_info(`+table+`)`)
	if err != nil {
		t.Fatal(err)
	}
	var cols []string
	for _, r := range rows {
		cols = append(cols, r.String("name"))
	}
	return cols
}

// tableHashes returns each host's digest of table from the cluster report
// `lv cluster converge` prints.
func tableHashes(t *testing.T, c *Cluster, via *Node, table string) map[string]*pb.TableDigest {
	t.Helper()
	dig, err := c.SelfClient(via).GetClusterStateDigest(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*pb.TableDigest{}
	for _, h := range dig.GetHosts() {
		for _, d := range h.GetTables() {
			if d.GetName() == table {
				out[h.GetHostName()] = d
			}
		}
	}
	return out
}

// Both on this build, digest_v2 at its default: the column order is not a
// difference. The comparison a pass pulls on agrees, and every host's
// verification digest agrees under v2.
//
// Mutation: default digestV2On to false for an unset predicate — the
// comparison differs and the v2 hashes are empty.
func TestFleet_OlderFoundedReplicaIsNotADifference(t *testing.T) {
	c, a, b, differs := olderFoundedPair(t, true)
	if differs() {
		t.Fatal("identical rows in another column order read as a difference")
	}
	hashes := tableHashes(t, c, b, skewTable)
	da, db := hashes[a.Name], hashes[b.Name]
	if da == nil || db == nil {
		t.Fatalf("the cluster report is missing a host's digest: %v", hashes)
	}
	if da.GetHash() == db.GetHash() {
		t.Fatalf("precondition: the positional hashes should differ, both %s", da.GetHash())
	}
	if da.GetHashV2() == "" || da.GetHashV2() != db.GetHashV2() {
		t.Fatalf("the order-invariant hashes should be present and equal: %s=%q %s=%q",
			a.Name, da.GetHashV2(), b.Name, db.GetHashV2())
	}
}

// Mixed: node-1 does not emit v2 — an older build, or its operator turned
// digest_v2 off — while node-0 does. Every comparison with node-1 is v1, as
// before this build; the point of pinning it is what does NOT happen. In one
// column order nothing differs (no v1 hash is judged against a v2 one —
// olderFoundedPair checks that). In two, the v1 mismatch makes the pass pull
// node-0's dump, as it always did, but merging it changes no row and
// registers no tie, so nothing reads as a SAFETY-FAULT. Once node-1 emits v2,
// the difference is gone.
//
// Mutation: make localAndRemoteHash pick v2 when either side sent it — the
// one-order precondition reads as a difference; make fetchLocalRowCells read
// the local row in its physical order (SELECT *) instead of aligning it to
// the incoming columns — an unresolved tie is registered.
func TestFleet_OlderFoundedReplica_MixedV1PeerFallsBackSafely(t *testing.T) {
	c, a, b, differs := olderFoundedPair(t, false)

	if !differs() {
		t.Fatal("against a v1-only node the comparison is positional, and these orders differ; " +
			"agreeing here means a v1 hash was compared with a v2 one")
	}
	rowsBefore := vmRows(t, b)
	b.DB.MergeStateBytesLWW(pullDump(t, c, a)) // what the pass does on that mismatch
	if got := vmRows(t, b); !slices.Equal(got, rowsBefore) {
		t.Fatalf("the pull changed rows:\nbefore %v\nafter  %v", rowsBefore, got)
	}
	for host, d := range tableHashes(t, c, b, skewTable) {
		if d.GetUnresolvedTies() != 0 {
			t.Fatalf("%s registered %d unresolved tie(s) from a column-order-only difference — "+
				"`lv cluster converge` would call that a SAFETY-FAULT", host, d.GetUnresolvedTies())
		}
		if host == b.Name && d.GetHashV2() != "" {
			t.Fatalf("%s has digest_v2 off but sent a v2 hash", host)
		}
		if host == a.Name && d.GetHashV2() == "" {
			t.Fatalf("%s is at the default but sent no v2 hash", host)
		}
	}

	b.DB.SetDigestV2Enabled(func() bool { return true })
	if differs() {
		t.Fatal("with both sides on v2 the column order still reads as a difference")
	}
}

func vmRows(t *testing.T, n *Node) []string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT name, host_name, spec, state, project, vm_owner_epoch, spec_generation, updated_at FROM vms ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("name")+"|"+r.String("host_name")+"|"+r.String("spec")+"|"+r.String("state")+"|"+
			r.String("project")+"|"+r.String("vm_owner_epoch")+"|"+r.String("spec_generation")+"|"+r.String("updated_at"))
	}
	return out
}
