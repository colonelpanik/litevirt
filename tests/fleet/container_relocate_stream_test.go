package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// pushLogAfter carries every mutation_log entry `from` logged after seq
// `after` to `to` over the real PushMutations RPC (real gRPC, real mTLS, the
// receiver's own entry validation and LWW apply), in one push, exactly as the
// replicator's push loop ships a batch. It returns the receiver's applied_up_to
// and the RPC error unchanged, so a scenario can assert on a refusal.
func pushLogAfter(t *testing.T, c *Cluster, from, to *Node, after int64) (last, appliedUpTo int64, err error) {
	t.Helper()
	ctx := context.Background()
	rows, qerr := from.DB.Query(ctx,
		`SELECT seq, hlc, origin, stmts FROM mutation_log WHERE seq > ? ORDER BY seq`, after)
	if qerr != nil {
		t.Fatalf("read %s mutation_log: %v", from.Name, qerr)
	}
	entries := make([]*pb.MutationEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, &pb.MutationEntry{
			Seq: r.Int64("seq"), Hlc: r.String("hlc"),
			Origin: r.String("origin"), Stmts: r.String("stmts"),
		})
		last = r.Int64("seq")
	}
	resp, err := c.PeerClient(from, to).PushMutations(ctx, &pb.ReplicateRequest{
		Sender:              from.Name,
		SenderVersion:       "fleet-test",
		SenderSchemaVersion: int32(corrosion.CurrentSchemaVersion),
		AfterSeq:            after,
		Entries:             entries,
	})
	if err != nil {
		return last, 0, err
	}
	return last, resp.AppliedUpTo, nil
}

func lastLoggedSeq(t *testing.T, n *Node) int64 {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT COALESCE(MAX(seq), 0) AS s FROM mutation_log`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s mutation_log tail: %v", n.Name, err)
	}
	return rows[0].Int64("s")
}

// An image-recreate relocation is one replicated write from the coordinator,
// and every receiver validates the entry it arrives in before applying it. The
// relocation used to put the source's guarded tombstone in the MIDDLE of its
// entry, with the unguarded target row after it, which the receiver's
// apply-safety check refuses outright ("guarded workload transition/delete must
// be the unique final statement"). The refusal back-pressures, so it was not one
// lost row: the push fails, the sender's cursor for that peer does not move, and
// every later write it made — however unrelated — never reached a peer.
//
// This drives the coordinator's log over the real PushMutations RPC to each
// peer, as the push loop would: the relocation and a later unrelated write in
// one batch. A stalled stream shows as a refused push and a peer that never
// sees the later write.
func TestFleet_ContainerRelocationDoesNotStallTheStream(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	before := lastLoggedSeq(t, a)

	// The container lives on victim; a is the coordinator that relocates it.
	if err := corrosion.UpsertContainer(ctx, a.DB, corrosion.ContainerRecord{
		HostName: victim.Name, Name: "ct-moved", Image: "docker.io/library/alpine:3.19",
		State: "running", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("seed container: %v", err)
	}
	if err := corrosion.RelocateContainerWithToken(ctx, a.DB, victim.Name, "ct-moved", b.Name, "tok-stream"); err != nil {
		t.Fatalf("relocate: %v", err)
	}
	// An unrelated write from the same sender, strictly after the relocation.
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "vm-after-relocate", HostName: a.Name, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	for _, peer := range []*Node{b, victim} {
		last, applied, err := pushLogAfter(t, c, a, peer, before)
		if err != nil {
			t.Fatalf("%s refused %s's push: its replication stream is stalled behind "+
				"the relocation entry: %v", peer.Name, a.Name, err)
		}
		if applied != last {
			t.Errorf("%s applied up to seq %d of %d: the stream stopped short", peer.Name, applied, last)
		}
		if vm, err := corrosion.GetVM(ctx, peer.DB, "vm-after-relocate"); err != nil || vm == nil {
			t.Errorf("%s never received a write %s made after the relocation: vm=%+v err=%v",
				peer.Name, a.Name, vm, err)
		}
	}

	// And the relocation itself arrived intact everywhere: source tombstoned,
	// target pending recreate with its token.
	for _, n := range c.Nodes {
		if src, err := corrosion.GetContainer(ctx, n.DB, victim.Name, "ct-moved"); err != nil || src != nil {
			t.Errorf("%s: source row still live after relocation: %+v err=%v", n.Name, src, err)
		}
		dst, err := corrosion.GetContainer(ctx, n.DB, b.Name, "ct-moved")
		if err != nil || dst == nil {
			t.Errorf("%s: target row missing: err=%v", n.Name, err)
			continue
		}
		if dst.StateDetail != corrosion.ContainerRelocateRecreateDetail || dst.RelocateToken != "tok-stream" {
			t.Errorf("%s: target = detail %q token %q, want %q / tok-stream",
				n.Name, dst.StateDetail, dst.RelocateToken, corrosion.ContainerRelocateRecreateDetail)
		}
	}
}
