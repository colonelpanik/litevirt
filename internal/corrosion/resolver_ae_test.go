package corrosion

import (
	"context"
	"testing"
)

// forceUpdatedAt rewrites a row's updated_at so two nodes can be put into an
// exact-timestamp tie (the condition the resolver exists for).
func forceUpdatedAt(t *testing.T, c *Client, table, pkCol, pk, ts string) {
	t.Helper()
	if _, err := c.db.Exec("UPDATE "+table+" SET updated_at = ? WHERE "+pkCol+" = ?", ts, pk); err != nil {
		t.Fatalf("force updated_at on %s: %v", table, err)
	}
}

// TestAntiEntropy_ContentTieConverges: two nodes hold the same image row at the
// SAME updated_at but different content. After a full-state merge, content-max
// converges deterministically (the lexically-greater row wins on both nodes).
// This is the end-to-end path through mergeChunk → resolveTie → fetchLocalRowCells.
func TestAntiEntropy_ContentTieConverges(t *testing.T) {
	ctx := context.Background()
	src, dst := testClient(t), testClient(t)
	const ts = "2026-06-03T18:40:00Z"

	if err := InsertImage(ctx, src, ImageRecord{Name: "img", Format: "zzz", SizeBytes: 1}); err != nil {
		t.Fatalf("InsertImage src: %v", err)
	}
	if err := InsertImage(ctx, dst, ImageRecord{Name: "img", Format: "aaa", SizeBytes: 1}); err != nil {
		t.Fatalf("InsertImage dst: %v", err)
	}
	forceUpdatedAt(t, src, "images", "name", "img", ts)
	forceUpdatedAt(t, dst, "images", "name", "img", ts)

	dst.MergeStateBytesLWW(src.DumpStateBytes())

	got, _ := GetImage(ctx, dst, "img")
	if got == nil || got.Format != "zzz" {
		t.Fatalf("content-max should converge to the lexically-greater row (zzz), got %+v", got)
	}
	// Symmetry: merging dst's (now zzz) into src is a no-op — both agree.
	src.MergeStateBytesLWW(dst.DumpStateBytes())
	if g, _ := GetImage(ctx, src, "img"); g == nil || g.Format != "zzz" {
		t.Fatalf("nodes must converge to the same row, src has %+v", g)
	}
}

// TestAntiEntropy_RuntimeOwnedTieKeepsLocal: a vms host_name split at an exact
// tie must NOT converge by content — each node keeps its own row (defer to
// runtime repair) and the tie is tracked for alerting. This is the §2.1
// data-loss guard: content-max here could adopt a non-running host.
func TestAntiEntropy_RuntimeOwnedTieKeepsLocal(t *testing.T) {
	ctx := context.Background()
	src, dst := testClient(t), testClient(t)
	sm := &fakeSyncMetrics{}
	dst.SetSyncMetrics(sm)
	const ts = "2026-06-03T18:40:00Z"

	if err := InsertVM(ctx, src, VMRecord{Name: "vm1", HostName: "host-b", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM src: %v", err)
	}
	if err := InsertVM(ctx, dst, VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM dst: %v", err)
	}
	forceUpdatedAt(t, src, "vms", "name", "vm1", ts)
	forceUpdatedAt(t, dst, "vms", "name", "vm1", ts)

	dst.MergeStateBytesLWW(src.DumpStateBytes())

	got, _ := GetVM(ctx, dst, "vm1")
	if got == nil || got.HostName != "host-a" {
		t.Fatalf("runtime-owned tie must keep local (host-a), got %+v", got)
	}
	if dst.UnresolvedTieCount() != 1 {
		t.Fatalf("the ownership split must be tracked as unresolved, count=%d", dst.UnresolvedTieCount())
	}
	found := false
	for _, u := range sm.tieUnresolved {
		if u == "vms/ae/runtime_owned" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a vms/ae/runtime_owned unresolved metric, got %v", sm.tieUnresolved)
	}
}

// TestAntiEntropy_RepairClearsUnresolved: the remediation path is a fresh/newer
// write (e.g. repair-owner re-stamping ownership). A strictly-newer incoming row
// applies AND clears the tracked unresolved tie, so UnresolvedTieCount returns to
// zero after repair (the finding-1 regression).
func TestAntiEntropy_RepairClearsUnresolved(t *testing.T) {
	ctx := context.Background()
	src, dst := testClient(t), testClient(t)
	const ts = "2026-06-03T18:40:00Z"

	_ = InsertVM(ctx, src, VMRecord{Name: "vm1", HostName: "host-b", State: "running", Spec: "{}"}, nil, nil)
	_ = InsertVM(ctx, dst, VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: "{}"}, nil, nil)
	forceUpdatedAt(t, src, "vms", "name", "vm1", ts)
	forceUpdatedAt(t, dst, "vms", "name", "vm1", ts)

	dst.MergeStateBytesLWW(src.DumpStateBytes()) // unresolved host_name tie
	if dst.UnresolvedTieCount() != 1 {
		t.Fatalf("expected one tracked unresolved tie, got %d", dst.UnresolvedTieCount())
	}

	// Repair: the owning side re-stamps with a strictly-newer timestamp.
	forceUpdatedAt(t, src, "vms", "name", "vm1", "2026-06-30T00:00:00Z")
	dst.MergeStateBytesLWW(src.DumpStateBytes())

	if got, _ := GetVM(ctx, dst, "vm1"); got == nil || got.HostName != "host-b" {
		t.Fatalf("strictly-newer repair must apply, got %+v", got)
	}
	if dst.UnresolvedTieCount() != 0 {
		t.Fatalf("repair (newer write) must clear the unresolved tracking, count=%d", dst.UnresolvedTieCount())
	}
}

// TestAntiEntropy_TieConvergesThenStable: after content-max converges a tie, a
// re-merge applies nothing (the digests now match) — no infinite resync.
func TestAntiEntropy_TieConvergesThenStable(t *testing.T) {
	ctx := context.Background()
	src, dst := testClient(t), testClient(t)
	const ts = "2026-06-03T18:40:00Z"
	_ = InsertImage(ctx, src, ImageRecord{Name: "img", Format: "zzz", SizeBytes: 1})
	_ = InsertImage(ctx, dst, ImageRecord{Name: "img", Format: "aaa", SizeBytes: 1})
	forceUpdatedAt(t, src, "images", "name", "img", ts)
	forceUpdatedAt(t, dst, "images", "name", "img", ts)

	dst.MergeStateBytesLWW(src.DumpStateBytes())

	sm := &fakeSyncMetrics{}
	dst.SetSyncMetrics(sm)
	dst.MergeStateBytesLWW(src.DumpStateBytes()) // second merge after convergence
	if sm.lastMerged != 0 {
		t.Fatalf("a converged tie must not re-merge rows, merged=%d", sm.lastMerged)
	}
}
