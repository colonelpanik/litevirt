package corrosion

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// peerLacksProofSupport is the WAL send-side filter that keeps proof-table mutations off a
// peer that can't apply them. It is TOKEN-based and FAILS CLOSED on a nil gate — a proof
// must never leak to a peer we can't confirm advertises split_brain_gate_v1 (a schema-38
// peer that doesn't advertise the token would otherwise wrongly receive proofs post-flip).
func TestPeerLacksProofSupport_FailsClosed(t *testing.T) {
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()

	// nil gate → fail closed (peer treated as lacking support → proofs deferred).
	if !r.peerLacksProofSupport(ctx, "peer-1") {
		t.Fatal("a nil proofReplicaGate must FAIL CLOSED (peer lacks support)")
	}

	// Gate says the peer advertises the token → support present.
	r.SetProofReplicaGate(func(context.Context, string) bool { return true })
	if r.peerLacksProofSupport(ctx, "peer-1") {
		t.Fatal("a peer the gate reports as supporting must NOT be treated as lacking")
	}

	// Gate says the peer does NOT advertise the token → lacks support.
	r.SetProofReplicaGate(func(context.Context, string) bool { return false })
	if !r.peerLacksProofSupport(ctx, "peer-1") {
		t.Fatal("a peer the gate reports as NOT supporting must be treated as lacking")
	}
}

// dropUnsupportedProofEntries removes proof-bearing entries from the batch (never splitting
// an entry) while keeping every OTHER entry in order, so the WAL stream keeps flowing instead
// of stalling behind a proof destined for a peer that can't honor it — the dropped proofs
// reconverge via the peer-only sensitive AE net.
func TestDropUnsupportedProofEntries(t *testing.T) {
	mustJSON := func(ss []Statement) string { b, _ := json.Marshal(ss); return string(b) }
	proofEntry := func(seq int64) mutationEntry {
		return mutationEntry{Seq: seq, Stmts: mustJSON([]Statement{
			{SQL: `INSERT INTO runtime_action_proofs (id) VALUES (?)`, Params: []interface{}{"p1"}},
			{SQL: `UPDATE vms SET pending_action_id=? WHERE name=?`, Params: []interface{}{"p1", "vm1"}},
		})}
	}
	plainEntry := func(seq int64) mutationEntry {
		return mutationEntry{Seq: seq, Stmts: mustJSON([]Statement{
			{SQL: `UPDATE vms SET state='running' WHERE name=?`, Params: []interface{}{"vm1"}},
		})}
	}
	seqs := func(es []mutationEntry) []int64 {
		out := make([]int64, len(es))
		for i, e := range es {
			out[i] = e.Seq
		}
		return out
	}

	// No proof-bearing entry → whole batch kept.
	if got := seqs(dropUnsupportedProofEntries([]mutationEntry{plainEntry(1), plainEntry(2)})); !reflect.DeepEqual(got, []int64{1, 2}) {
		t.Fatalf("proof-free batch: kept=%v; want [1 2]", got)
	}

	// Leading proof entry → dropped, the plain entry after it still flows (no stall).
	if got := seqs(dropUnsupportedProofEntries([]mutationEntry{proofEntry(1), plainEntry(2)})); !reflect.DeepEqual(got, []int64{2}) {
		t.Fatalf("leading proof entry: kept=%v; want [2] (drop the proof, keep the rest flowing)", got)
	}

	// Plain entries on BOTH sides of a proof → proof dropped, both plains kept in order:
	// leader_election / vm_locks after a proof no longer stall.
	if got := seqs(dropUnsupportedProofEntries([]mutationEntry{plainEntry(5), plainEntry(6), proofEntry(7), plainEntry(8)})); !reflect.DeepEqual(got, []int64{5, 6, 8}) {
		t.Fatalf("prefix+proof+suffix: kept=%v; want [5 6 8]", got)
	}

	// All proof entries → all dropped (the caller advances the watermark past them).
	if got := dropUnsupportedProofEntries([]mutationEntry{proofEntry(1), proofEntry(2)}); len(got) != 0 {
		t.Fatalf("all-proof batch: kept=%d; want 0", len(got))
	}
}
