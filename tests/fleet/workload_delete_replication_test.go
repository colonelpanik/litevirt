package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_WorkloadDeleteMustReplicate is the multi-node property behind the
// duplicate_live_container the lab produced on 2026-08-02 (sb-ct1 live on both
// node-2 and node-3). It is deliberately table-driven on the ownership
// generation, because THAT is the axis the bug turns on.
//
// Every production delete call site uses the LEGACY writers (DeleteContainer /
// DeleteContainerStrict / DeleteVM). The receiver applies a legacy workload
// delete only via legacyWorkloadDeleteMatchesPreAuthority, which requires the
// peer's row to have owner_epoch == 0 AND spec_generation == 0 — otherwise it
// returns "not safe" and the tombstone is SILENTLY DROPPED (a no-op, not an
// error, so nothing back-pressures and no metric fires). The guarded writers
// that would apply (deleteContainerGuarded / deleteVMGuarded, emitting the
// DispWorkloadDelete shapes) exist and are unit-tested but have no production
// caller.
//
// So the deleting node hides the row and every peer keeps it live forever. Any
// VM whose spec was ever mutated already had a nonzero spec_generation and hit
// this before Phase 4; the owner-epoch backfill made it universal.
//
// The epoch-zero case is the positive control: it proves the harness really
// does deliver and apply a tombstone, so the nonzero failure is the guard
// dropping it and not the test failing to replicate anything.
func TestFleet_WorkloadDeleteMustReplicate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		epochs bool
	}{
		{name: "pre-authority row (control: delivery works)", epochs: false},
		{name: "row carrying an ownership generation", epochs: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2})
			a, b := c.Nodes[0], c.Nodes[1]
			ctx := context.Background()

			if err := corrosion.UpsertContainer(ctx, a.DB, corrosion.ContainerRecord{
				HostName: a.Name, Name: "ct1", State: "running", Image: "alpine:3.19",
			}); err != nil {
				t.Fatalf("UpsertContainer: %v", err)
			}
			if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
				Name: "vm1", HostName: a.Name, State: "running",
			}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			if tc.epochs {
				if err := corrosion.BackfillOwnerEpochs(ctx, a.DB, a.Name); err != nil {
					t.Fatalf("BackfillOwnerEpochs: %v", err)
				}
			}
			pumpMutations(t, c, a, b)

			// Delete through the SAME writers production uses.
			if err := corrosion.DeleteContainer(ctx, a.DB, a.Name, "ct1"); err != nil {
				t.Fatalf("DeleteContainer: %v", err)
			}
			if err := corrosion.DeleteVM(ctx, a.DB, "vm1"); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			pumpMutations(t, c, a, b)

			for _, q := range []struct{ label, sql string }{
				{"container", `SELECT COALESCE(deleted_at,'') d, owner_epoch e FROM containers WHERE name='ct1'`},
				{"vm", `SELECT COALESCE(deleted_at,'') d, vm_owner_epoch e FROM vms WHERE name='vm1'`},
			} {
				local, err := a.DB.Query(ctx, q.sql)
				if err != nil || len(local) == 0 {
					t.Fatalf("%s: read deleter row: %v", q.label, err)
				}
				peer, err := b.DB.Query(ctx, q.sql)
				if err != nil || len(peer) == 0 {
					t.Fatalf("%s: read peer row: %v", q.label, err)
				}
				if local[0].String("d") == "" {
					t.Fatalf("%s: precondition — the deleting node must have tombstoned its own row", q.label)
				}
				if peer[0].String("d") == "" {
					t.Errorf("%s delete did not reach the peer: the row is still LIVE there "+
						"(peer generation=%d). The deleter hides it, every peer keeps serving it.",
						q.label, peer[0].Int64("e"))
				}
			}
		})
	}
}

// TestFleet_AntiEntropyMustCarryATombstone pins anti-entropy's half of the
// invariant. AE is the backstop for anything the WAL path drops, so what it does
// with a tombstone decides whether a lost delete is a blip or permanent.
//
// AE's full-row merge is TIMESTAMP-FIRST (sync.go, lwwOrder): local strictly
// newer wins and the row is skipped outright, and resolveTie — hence
// ruleTombstone, which encodes "a one-sided soft-delete wins" — runs ONLY on an
// exact-instant tie. So AE repairs a lost tombstone right up until the diverged
// node writes to that row once, which bumps it past the tombstone and pins the
// divergence forever. A health checker on a rejoining node does exactly that,
// every sweep. That is why the lab's sb-ct1 never self-healed.
//
// Deletion is terminal: it must not be decided by a timestamp race.
func TestFleet_AntiEntropyMustCarryATombstone(t *testing.T) {
	for _, tc := range []struct {
		name       string
		peerWrites bool
	}{
		{name: "quiet peer (control: AE delivers the tombstone)", peerWrites: false},
		{name: "peer wrote after the delete", peerWrites: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2})
			a, b := c.Nodes[0], c.Nodes[1]
			ctx := context.Background()

			if err := corrosion.UpsertContainer(ctx, a.DB, corrosion.ContainerRecord{
				HostName: a.Name, Name: "ct1", State: "running", Image: "alpine:3.19",
			}); err != nil {
				t.Fatalf("UpsertContainer: %v", err)
			}
			pumpMutations(t, c, a, b)

			if err := corrosion.DeleteContainer(ctx, a.DB, a.Name, "ct1"); err != nil {
				t.Fatalf("DeleteContainer: %v", err)
			}

			// The diverged peer, which never received the tombstone, touches the
			// row — the drift heal a rejoining node emits.
			if tc.peerWrites {
				if err := corrosion.SetContainerState(ctx, b.DB, a.Name, "ct1", "stopped"); err != nil {
					t.Fatalf("peer state write: %v", err)
				}
			}

			// Anti-entropy: b pulls a's full state and merges it.
			b.DB.MergeStateBytesLWW(pullDump(t, c, a))

			rows, err := b.DB.Query(ctx,
				`SELECT COALESCE(deleted_at,'') d FROM containers WHERE host_name=? AND name=?`,
				a.Name, "ct1")
			if err != nil || len(rows) == 0 {
				t.Fatalf("read peer row: %v", err)
			}
			if rows[0].String("d") == "" {
				t.Errorf("anti-entropy did not carry the tombstone: the row is still LIVE on %s. "+
					"A delete must not lose to a later write on the diverged node.", b.Name)
			}
		})
	}
}

// TestFleet_AntiEntropyMustNotResurrectAtEqualAuthority is the other direction of
// the same invariant, and the step that actually erased the lab's tombstone.
//
// anti_entropy_authority.go handles an incoming TOMBSTONE well: at equal or
// higher authority it applies regardless of timestamps. But the mirror case —
// local tombstoned, incoming LIVE at EQUAL authority — returns
// mergeAuthorityNormal and falls through to plain timestamp LWW. A diverged node
// that keeps writing (a health checker heals drift every sweep) therefore
// produces a newer live row that overwrites the tombstone.
//
// On the lab this ran to completion: the delete reached only the coordinator (a
// legacy delete is dropped at peers whose row carries authority), node-3 kept
// writing its still-live copy, and AE then carried that newer live row back over
// the coordinator's tombstone. All four nodes agreed on a resurrected row —
// which is why it never looked like divergence.
//
// A delete is terminal AT ITS AUTHORITY. Resurrection is legitimate only at a
// HIGHER generation (a genuine recreate), which the control below pins.
func TestFleet_AntiEntropyMustNotResurrectAtEqualAuthority(t *testing.T) {
	for _, tc := range []struct {
		name          string
		bumpAuthority bool
		wantLive      bool
	}{
		{name: "equal authority: the tombstone is terminal", bumpAuthority: false, wantLive: false},
		{name: "higher authority: a real recreate wins (control)", bumpAuthority: true, wantLive: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2})
			deleter, diverged := c.Nodes[0], c.Nodes[1]
			ctx := context.Background()

			if err := corrosion.UpsertContainer(ctx, deleter.DB, corrosion.ContainerRecord{
				HostName: "wl", Name: "ct1", State: "running", Image: "alpine:3.19",
			}); err != nil {
				t.Fatalf("UpsertContainer: %v", err)
			}
			if err := corrosion.BackfillOwnerEpochs(ctx, deleter.DB, "wl"); err != nil {
				t.Fatalf("BackfillOwnerEpochs: %v", err)
			}
			pumpMutations(t, c, deleter, diverged)

			// The coordinator retires the row. (Whether peers receive this is the
			// subject of the other test; here the point is what AE does next.)
			if err := corrosion.DeleteContainer(ctx, deleter.DB, "wl", "ct1"); err != nil {
				t.Fatalf("DeleteContainer: %v", err)
			}

			// The diverged node, which still holds a live copy, writes to it —
			// strictly newer than the tombstone.
			if tc.bumpAuthority {
				// A genuine recreate mints a NEW generation, and that must win.
				// Drive it through the real minting writer (relocation completion),
				// not an ad-hoc UPDATE the receiver's apply guard would refuse.
				if err := diverged.DB.Execute(ctx,
					`UPDATE containers SET state = 'pending', relocate_token = ?, updated_at = ?
					 WHERE host_name = ? AND name = ?`,
					"tok1", diverged.DB.NowTS(), "wl", "ct1"); err != nil {
					t.Fatalf("stage relocation: %v", err)
				}
				if err := corrosion.CompleteContainerRelocation(ctx, diverged.DB, "wl", "ct1", "tok1"); err != nil {
					t.Fatalf("mint a higher generation: %v", err)
				}
			}
			if err := corrosion.SetContainerState(ctx, diverged.DB, "wl", "ct1", "stopped"); err != nil {
				t.Fatalf("diverged state write: %v", err)
			}

			// Anti-entropy: the coordinator pulls the diverged node's state.
			if err := deleter.DB.MergeStateBytesLWW(pullDump(t, c, diverged)); err != nil {
				t.Fatalf("merge: %v", err)
			}

			rows, err := deleter.DB.Query(ctx,
				`SELECT COALESCE(deleted_at,'') d, owner_epoch e FROM containers WHERE host_name='wl' AND name='ct1'`)
			if err != nil || len(rows) == 0 {
				t.Fatalf("read coordinator row: %v", err)
			}
			live := rows[0].String("d") == ""
			if live != tc.wantLive {
				t.Errorf("after anti-entropy the coordinator's row live=%v, want %v (incoming generation=%d). "+
					"A delete is terminal at its own authority; only a higher generation may resurrect.",
					live, tc.wantLive, rows[0].Int64("e"))
			}
		})
	}
}

// TestFleet_PingReportsAWallClock covers the server half of clock-skew
// detection over real gRPC. Without it the field can silently go unset — the
// health checker then sees the zero time from every peer, reads it as "unknown"
// (correctly), and skew detection is dark again, which is exactly the state this
// whole area was in until 2026-08-02.
func TestFleet_PingReportsAWallClock(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]

	caps, peerWall, err := a.Server.PeerCapabilities(context.Background(), b.Name)
	if err != nil {
		t.Fatalf("PeerCapabilities: %v", err)
	}
	_ = caps
	if peerWall.IsZero() {
		t.Fatal("a peer must report its wall clock, else skew detection is silently dark")
	}
	if skew := time.Since(peerWall).Abs(); skew > time.Minute {
		t.Fatalf("peer wall clock is %v away from ours — it is not a real wall clock", skew)
	}
}
