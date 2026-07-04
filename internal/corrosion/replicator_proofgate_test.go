package corrosion

import (
	"context"
	"encoding/json"
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

// deferUnsupportedProofEntries truncates a batch at the first proof-bearing entry so proof +
// co-batched marker replicate atomically (or defer whole) to an unsupported peer — never
// split, never advance the watermark past the deferred entry.
func TestDeferUnsupportedProofEntries(t *testing.T) {
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

	// No proof-bearing entry → whole batch sendable, no truncation.
	kept, _, truncated := deferUnsupportedProofEntries([]mutationEntry{plainEntry(1), plainEntry(2)})
	if len(kept) != 2 || truncated {
		t.Fatalf("proof-free batch: kept=%d truncated=%v; want 2/false", len(kept), truncated)
	}

	// First entry proof-bearing → send NOTHING, hold the watermark (kept empty, not truncated).
	kept, _, truncated = deferUnsupportedProofEntries([]mutationEntry{proofEntry(1), plainEntry(2)})
	if len(kept) != 0 || truncated {
		t.Fatalf("leading proof entry: kept=%d truncated=%v; want 0/false (hold watermark)", len(kept), truncated)
	}

	// Proof-free prefix then a proof entry → send the prefix, ceiling = last kept seq, so the
	// watermark can't advance past the deferred proof entry.
	kept, ceiling, truncated := func() ([]mutationEntry, int64, bool) {
		return deferUnsupportedProofEntries([]mutationEntry{plainEntry(5), plainEntry(6), proofEntry(7), plainEntry(8)})
	}()
	if len(kept) != 2 || !truncated || ceiling != 6 {
		t.Fatalf("prefix+proof: kept=%d truncated=%v ceiling=%d; want 2/true/6", len(kept), truncated, ceiling)
	}
}
