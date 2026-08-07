package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ctRow reads a container row INCLUDING soft-deleted ones — the CLI and
// GetContainer both hide tombstoned rows, which is part of why a non-terminal
// delete stayed invisible.
func ctRow(t *testing.T, n *Node, host, name string) (state string, deleted bool, exists bool) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT state, COALESCE(deleted_at, '') AS del FROM containers WHERE host_name = ? AND name = ?`,
		host, name)
	if err != nil {
		t.Fatalf("read %s containers: %v", n.Name, err)
	}
	if len(rows) == 0 {
		return "", false, false
	}
	return rows[0].String("state"), rows[0].String("del") != "", true
}

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
// A delete is terminal FOR ITS INCARNATION (created_at names the incarnation).
// Neither a newer timestamp nor an ownership-epoch mint may resurrect it — an
// epoch is WHO OWNS the incarnation, not WHICH incarnation it is, and
// TransferVMOwner/relocation completion mint epoch+1 with created_at untouched.
// Resurrection is legitimate only for a genuinely NEW incarnation: a recreate,
// which purges the local tombstone and inserts a fresh row with a fresh
// created_at. The recreate control below pins that revival path so the
// terminality cases can't pass by AE simply refusing everything.
func TestFleet_AntiEntropyMustNotResurrectAtEqualAuthority(t *testing.T) {
	for _, tc := range []struct {
		name     string
		diverged func(t *testing.T, ctx context.Context, db *corrosion.Client)
		wantLive bool
	}{
		{
			name:     "equal authority: the tombstone is terminal",
			diverged: func(*testing.T, context.Context, *corrosion.Client) {},
			wantLive: false,
		},
		{
			// This was previously the "higher authority resurrects" control —
			// which is exactly the delete-vs-transfer race that resurrects a
			// deleted workload with no disks behind it. An epoch mint of the
			// SAME incarnation must now lose to its tombstone.
			name: "ownership-epoch mint of the same incarnation: still terminal",
			diverged: func(t *testing.T, ctx context.Context, db *corrosion.Client) {
				if err := db.Execute(ctx,
					`UPDATE containers SET state = 'pending', relocate_token = ?, updated_at = ?
					 WHERE host_name = ? AND name = ?`,
					"tok1", db.NowTS(), "wl", "ct1"); err != nil {
					t.Fatalf("stage relocation: %v", err)
				}
				if err := corrosion.CompleteContainerRelocation(ctx, db, "wl", "ct1", "tok1"); err != nil {
					t.Fatalf("mint an ownership epoch: %v", err)
				}
			},
			wantLive: false,
		},
		{
			// The revival control: a genuine recreate — a FRESH incarnation with
			// its own created_at, landing at authority 0/0 like every
			// default-config create — must win over the old tombstone even
			// though its authority axes restart BELOW the tombstone's backfilled
			// epoch. Before the incarnation rules this wedged forever: the
			// equal/crossed-authority arms kept the tombstone and an AE-only
			// peer could never see a delete-then-recreate again.
			name: "a recreate is a new incarnation and wins (control)",
			diverged: func(t *testing.T, ctx context.Context, db *corrosion.Client) {
				if err := corrosion.DeleteContainer(ctx, db, "wl", "ct1"); err != nil {
					t.Fatalf("diverged delete before recreate: %v", err)
				}
				if err := corrosion.CreateContainerAtomic(ctx, db, corrosion.ContainerRecord{
					HostName: "wl", Name: "ct1", State: "running", Image: "alpine:3.20",
				}, nil); err != nil {
					t.Fatalf("recreate: %v", err)
				}
			},
			wantLive: true,
		},
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

			// The diverged node, which never saw the tombstone, keeps going.
			tc.diverged(t, ctx, diverged.DB)
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
				t.Errorf("after anti-entropy the coordinator's row live=%v, want %v (incoming epoch=%d). "+
					"A delete is terminal for its incarnation; only a NEW incarnation may resurrect.",
					live, tc.wantLive, rows[0].Int64("e"))
			}
		})
	}
}

// TestFleet_DeleteVsTransferConvergesToTheTombstone pins BOTH directions of the
// delete-vs-ownership-transfer race for VMs and containers. A coordinator
// deletes the workload (disks/rootfs already destroyed by its handler) while a
// peer that never received the tombstone completes a migration/failover
// transfer, minting epoch+1 on the SAME incarnation. Whichever side anti-
// entropy runs from, the cluster must converge on the tombstone: converging on
// the live row resurrects a workload with no storage behind it, and refusing
// both directions pins a permanent divergence.
func TestFleet_DeleteVsTransferConvergesToTheTombstone(t *testing.T) {
	t.Run("vm", func(t *testing.T) {
		c := New(t, Options{Nodes: 2})
		deleter, transferer := c.Nodes[0], c.Nodes[1]
		ctx := context.Background()

		if err := corrosion.InsertVM(ctx, deleter.DB, corrosion.VMRecord{
			Name: "vm1", HostName: deleter.Name, State: "running",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
		if err := corrosion.BackfillOwnerEpochs(ctx, deleter.DB, deleter.Name); err != nil {
			t.Fatalf("BackfillOwnerEpochs: %v", err)
		}
		pumpMutations(t, c, deleter, transferer)

		if err := corrosion.DeleteVM(ctx, deleter.DB, "vm1"); err != nil {
			t.Fatalf("DeleteVM: %v", err)
		}
		// The peer, unaware of the delete, completes a failover transfer.
		if err := corrosion.TransferVMOwner(ctx, transferer.DB, "vm1", transferer.Name, "running", 1); err != nil {
			t.Fatalf("TransferVMOwner: %v", err)
		}

		// Deleter pulls the transferer: the epoch+1 live row must NOT revive.
		if err := deleter.DB.MergeStateBytesLWW(pullDump(t, c, transferer)); err != nil {
			t.Fatalf("merge into deleter: %v", err)
		}
		// Transferer pulls the deleter: the tombstone must land despite its
		// LOWER epoch — same incarnation, and the delete is terminal for it.
		if err := transferer.DB.MergeStateBytesLWW(pullDump(t, c, deleter)); err != nil {
			t.Fatalf("merge into transferer: %v", err)
		}

		for _, n := range []*Node{deleter, transferer} {
			rows, err := n.DB.Query(ctx,
				`SELECT COALESCE(deleted_at,'') d, vm_owner_epoch e FROM vms WHERE name='vm1'`)
			if err != nil || len(rows) == 0 {
				t.Fatalf("read %s row: %v", n.Name, err)
			}
			if rows[0].String("d") == "" {
				t.Errorf("%s: the deleted VM is LIVE (epoch=%d) — the transfer resurrected a "+
					"workload whose disks the delete already destroyed", n.Name, rows[0].Int64("e"))
			}
		}
	})

	t.Run("container", func(t *testing.T) {
		c := New(t, Options{Nodes: 2})
		deleter, transferer := c.Nodes[0], c.Nodes[1]
		ctx := context.Background()

		if err := corrosion.UpsertContainer(ctx, deleter.DB, corrosion.ContainerRecord{
			HostName: "wl", Name: "ct1", State: "running", Image: "alpine:3.19",
		}); err != nil {
			t.Fatalf("UpsertContainer: %v", err)
		}
		if err := corrosion.BackfillOwnerEpochs(ctx, deleter.DB, "wl"); err != nil {
			t.Fatalf("BackfillOwnerEpochs: %v", err)
		}
		pumpMutations(t, c, deleter, transferer)

		if err := corrosion.DeleteContainer(ctx, deleter.DB, "wl", "ct1"); err != nil {
			t.Fatalf("DeleteContainer: %v", err)
		}
		if err := transferer.DB.Execute(ctx,
			`UPDATE containers SET state = 'pending', relocate_token = ?, updated_at = ?
			 WHERE host_name = ? AND name = ?`,
			"tok1", transferer.DB.NowTS(), "wl", "ct1"); err != nil {
			t.Fatalf("stage relocation: %v", err)
		}
		if err := corrosion.CompleteContainerRelocation(ctx, transferer.DB, "wl", "ct1", "tok1"); err != nil {
			t.Fatalf("CompleteContainerRelocation: %v", err)
		}

		if err := deleter.DB.MergeStateBytesLWW(pullDump(t, c, transferer)); err != nil {
			t.Fatalf("merge into deleter: %v", err)
		}
		if err := transferer.DB.MergeStateBytesLWW(pullDump(t, c, deleter)); err != nil {
			t.Fatalf("merge into transferer: %v", err)
		}

		for _, n := range []*Node{deleter, transferer} {
			_, deleted, exists := ctRow(t, n, "wl", "ct1")
			if !exists || !deleted {
				t.Errorf("%s: the deleted container is LIVE — the relocation mint resurrected it "+
					"(deleted=%v exists=%v)", n.Name, deleted, exists)
			}
		}
	})
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

// recordingSyncMetrics captures the merge-rejection calls a receiver makes, so a
// test can assert that a refusal was REPORTED and not merely correct-and-silent.
type recordingSyncMetrics struct {
	mu       sync.Mutex
	rejected []string // "table/path/reason"
}

func (m *recordingSyncMetrics) ObserveMergeRejected(table, path, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejected = append(m.rejected, table+"/"+path+"/"+reason)
}
func (m *recordingSyncMetrics) reasons() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.rejected...)
}

func (m *recordingSyncMetrics) ObserveDump(time.Duration, int)              {}
func (m *recordingSyncMetrics) ObserveDigest(time.Duration)                 {}
func (m *recordingSyncMetrics) ObserveMerge(time.Duration, int, int)        {}
func (m *recordingSyncMetrics) ObserveLegacyTransformed(string)             {}
func (m *recordingSyncMetrics) ObserveTieBreak(string, string, string)      {}
func (m *recordingSyncMetrics) ObserveTieUnresolved(string, string, string) {}
func (m *recordingSyncMetrics) ObserveTombstoneTie(string)                  {}
func (m *recordingSyncMetrics) ObserveUnresolvedTieCurrent(int)             {}
func (m *recordingSyncMetrics) ObserveIdentityCollapseOrphan(string)        {}
func (m *recordingSyncMetrics) ObserveSkewQuarantined()                     {}

// TestFleet_RefusedPreAuthorityDeleteIsReported covers the MIXED-VERSION path: a
// peer still running a pre-fix build emits the pre-authority delete shape, and an
// upgraded receiver whose row carries authority must refuse it — loudly.
//
// The refusal itself is correct and load-bearing (that shape cannot prove the
// local row is the same workload the sender deleted). What is NOT acceptable is
// doing it silently: the entry is ACKNOWLEDGED, so nothing back-pressures and the
// sender believes it replicated, which is exactly how a dropped tombstone stayed
// invisible for a week.
//
// This pins the ENTRY-level skip, which is the site that actually fires for a
// complete legacy batch — the per-statement branch is bypassed by its `continue`.
// The lab found that the hard way on 2026-08-02: the first instrumentation went
// on the per-statement path and never fired in a real mixed cluster.
func TestFleet_RefusedPreAuthorityDeleteIsReported(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	sender, receiver := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()

	metrics := &recordingSyncMetrics{}
	receiver.DB.SetSyncMetrics(metrics)

	if err := corrosion.UpsertContainer(ctx, sender.DB, corrosion.ContainerRecord{
		HostName: "wl", Name: "ct1", State: "running", Image: "alpine:3.19",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, sender.DB, "wl"); err != nil {
		t.Fatalf("BackfillOwnerEpochs: %v", err)
	}
	pumpMutations(t, c, sender, receiver)

	// Emit the PRE-AUTHORITY shape by hand: nothing in this tree produces it any
	// more, but a supported peer still does, and that is the case under test.
	if err := sender.DB.Execute(ctx,
		`UPDATE containers SET deleted_at = ?, updated_at = ?
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		"2026-08-02T00:00:00Z", sender.DB.NowTS(), "wl", "ct1"); err != nil {
		t.Fatalf("emit pre-authority delete: %v", err)
	}
	pumpMutations(t, c, sender, receiver)

	// Refused: the receiver's row carries authority the shape cannot speak to.
	state, deleted, exists := ctRow(t, receiver, "wl", "ct1")
	if !exists || deleted {
		t.Fatalf("precondition: the receiver must refuse the pre-authority delete "+
			"(state=%q deleted=%v exists=%v)", state, deleted, exists)
	}

	// And REPORTED — with the REAL table label. An operator's natural query
	// after this incident filters on table="containers"; the entry-level skip
	// initially reported table="unknown", which that filter silently misses.
	var found bool
	for _, r := range metrics.reasons() {
		if strings.Contains(r, "pre_authority_delete") {
			found = true
			if !strings.HasPrefix(r, "containers/") {
				t.Fatalf("the refusal must carry its table label, got %q — table=\"unknown\" is "+
					"invisible to a dashboard filtered on the workload table", r)
			}
		}
	}
	if !found {
		t.Fatalf("the refusal must be reported, got %v — a silently dropped tombstone is "+
			"invisible to the operator and the sender believes it replicated", metrics.reasons())
	}
}
