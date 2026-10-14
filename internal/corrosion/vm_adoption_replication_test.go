package corrosion

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func vmAdoptionState(t *testing.T, c *Client, name string) (state, updatedAt string) {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT hardware_adoption_state, updated_at FROM vms WHERE name = ?`, name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("vm %s: %d rows (%v)", name, len(rows), err)
	}
	return rows[0].String("hardware_adoption_state"), rows[0].String("updated_at")
}

func vmRowImage(t *testing.T, c *Client, name string) string {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT * FROM vms WHERE name = ?`, name)
	if err != nil || len(rows) != 1 {
		t.Fatalf("vm %s: %d rows (%v)", name, len(rows), err)
	}
	return fmt.Sprint(rows[0])
}

func replayMutationLog(t *testing.T, from, to *Client, origin string) {
	t.Helper()
	entries, err := from.Query(context.Background(), `SELECT seq, hlc, stmts FROM mutation_log ORDER BY seq`)
	if err != nil || len(entries) == 0 {
		t.Fatalf("mutation_log: %d entries (%v)", len(entries), err)
	}
	for _, e := range entries {
		applyMutationEntry(t, to, &pb.MutationEntry{
			Seq: e.Int64("seq"), Hlc: e.String("hlc"), Origin: origin, Stmts: e.String("stmts"),
		})
	}
}

// A create's adoption UPDATE reaches a receiver through replication. At the
// INSERT's updated_at the receiver dropped it as a tied partial update, and
// only the creating host recorded the VM adopted.
func TestInsertVMWithHardware_AdoptionReplicates(t *testing.T) {
	ctx := context.Background()
	source, receiver := testClient(t), testClient(t)
	if err := InsertVMWithHardware(ctx, source,
		VMRecord{Name: "web", HostName: "h1", Project: "p1", Spec: `{"cpu":1}`},
		nil, nil, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if st, _ := vmAdoptionState(t, source, "web"); st != "adopted" {
		t.Fatalf("source: hardware_adoption_state = %q, want adopted", st)
	}
	replayMutationLog(t, source, receiver, "source-adopt")
	if st, _ := vmAdoptionState(t, receiver, "web"); st != "adopted" {
		t.Fatalf("receiver: hardware_adoption_state = %q, want adopted", st)
	}
	if s, r := vmRowImage(t, source, "web"), vmRowImage(t, receiver, "web"); s != r {
		t.Fatalf("rows differ after replication:\nsource   %s\nreceiver %s", s, r)
	}
}

// Two replicas hold tombstones of one VM incarnation at one updated_at and one
// authority that differ in a column the authority does not cover. Each pulls
// the other at once; both must end on one row, and stay there. Applied
// unconditionally, the two were exchanged on every pull and never settled.
func TestAntiEntropy_TiedTombstonesOfOneVMSettle(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	if err := InsertVMWithHardware(ctx, a,
		VMRecord{Name: "web", HostName: "h1", Project: "p1", Spec: `{"cpu":1}`},
		nil, nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	if outcome, err := deleteVMGuarded(ctx, a, "web"); err != nil || outcome != deleteApplied {
		t.Fatalf("delete: outcome=%v err=%v", outcome, err)
	}
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}

	// The tombstones as a build that dropped the adoption UPDATE left them:
	// adopted on the creating host only. updated_at is unchanged, and nothing
	// replicates the change.
	for c, st := range map[*Client]string{a: "adopted", b: "pending"} {
		c.Mu().Lock()
		_, err := c.DB().Exec(`UPDATE vms SET hardware_adoption_state = ? WHERE name = ?`, st, "web")
		c.Mu().Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	sa, ua := vmAdoptionState(t, a, "web")
	sb, ub := vmAdoptionState(t, b, "web")
	if sa != "adopted" || sb != "pending" || ua != ub {
		t.Fatalf("setup: a %q at %s, b %q at %s; want adopted/pending at one updated_at", sa, ua, sb, ub)
	}

	for pass := 0; pass < 3; pass++ {
		da, db := a.DumpStateBytes(), b.DumpStateBytes()
		if err := a.MergeStateBytesLWW(db); err != nil {
			t.Fatal(err)
		}
		if err := b.MergeStateBytesLWW(da); err != nil {
			t.Fatal(err)
		}
		if ra, rb := vmRowImage(t, a, "web"), vmRowImage(t, b, "web"); ra != rb {
			t.Fatalf("pass %d: the tombstones were exchanged, not settled:\na %s\nb %s", pass, ra, rb)
		}
	}
	if rows, err := a.Query(ctx, `SELECT 1 FROM vms WHERE name = ? AND deleted_at IS NOT NULL`, "web"); err != nil || len(rows) != 1 {
		t.Fatalf("the settled row is no longer a tombstone: %v (%v)", rows, err)
	}
}
