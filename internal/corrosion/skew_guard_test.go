package corrosion

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
)

func TestTsInstant(t *testing.T) {
	rfc := "2026-07-05T10:00:00.000000000Z"
	if inst, ok := tsInstant(rfc); !ok || inst.UTC().Format(time.RFC3339) != "2026-07-05T10:00:00Z" {
		t.Errorf("tsInstant(RFC3339) = %v, %v", inst, ok)
	}
	h := hlc.Timestamp{PhysicalMS: time.Date(2026, 7, 5, 10, 0, 0, 0, time.UTC).UnixMilli(), Logical: 3, NodeID: "n1"}.String()
	if inst, ok := tsInstant(h); !ok || inst.UTC().Format(time.RFC3339) != "2026-07-05T10:00:00Z" {
		t.Errorf("tsInstant(HLC) = %v, %v", inst, ok)
	}
	if _, ok := tsInstant("not-a-timestamp"); ok {
		t.Error("tsInstant(garbage) should be !ok")
	}
}

func TestTsFutureSkewed(t *testing.T) {
	now := time.Date(2026, 7, 5, 10, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour).Format(nowTSLayout)          // > 5min cutoff
	slightly := now.Add(time.Minute).Format(nowTSLayout)      // within cutoff
	past := now.Add(-time.Hour).Format(nowTSLayout)
	if !tsFutureSkewed(future, now) {
		t.Error("now+1h must be skewed")
	}
	if tsFutureSkewed(slightly, now) {
		t.Error("now+1m must NOT be skewed (within MaxSkew)")
	}
	if tsFutureSkewed(past, now) {
		t.Error("past must NOT be skewed")
	}
	// HLC far-future.
	hFuture := hlc.Timestamp{PhysicalMS: now.Add(time.Hour).UnixMilli(), NodeID: "n1"}.String()
	if !tsFutureSkewed(hFuture, now) {
		t.Error("HLC now+1h must be skewed")
	}
	// Unparseable → never skewed (falls through to comparator).
	if tsFutureSkewed("garbage", now) {
		t.Error("unparseable must not be treated as skewed")
	}
}

// TestSkewGuard_AEQuarantinesFutureRow proves the vulnerability and the fix: a
// clock-corrupted peer whose row is far-future wins LWW WITHOUT the guard, but is
// quarantined (local kept) WITH the guard enabled.
func TestSkewGuard_AEQuarantinesFutureRow(t *testing.T) {
	ctx := context.Background()
	future := time.Now().Add(time.Hour).UTC().Format(nowTSLayout)

	// --- Guard OFF: the skewed peer wins (demonstrates the vulnerability). ---
	dst := testClient(t)
	src := testClient(t)
	if err := InsertHost(ctx, dst, HostRecord{Name: "h1", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertHost(ctx, src, HostRecord{Name: "h1", Address: "10.0.0.2", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := src.Execute(ctx, `UPDATE hosts SET updated_at=? WHERE name=?`, future, "h1"); err != nil {
		t.Fatal(err)
	}
	dst.MergeStateBytesLWW(src.DumpStateBytes())
	if h, _ := GetHost(ctx, dst, "h1"); h == nil || h.Address != "10.0.0.2" {
		t.Fatalf("guard OFF: expected skewed peer to win (10.0.0.2), got %+v", h)
	}

	// --- Guard ON: the skewed peer is quarantined, local is kept. ---
	dst2 := testClient(t)
	dst2.SetHLCSkewGuard(func() bool { return true })
	if err := InsertHost(ctx, dst2, HostRecord{Name: "h1", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	dst2.MergeStateBytesLWW(src.DumpStateBytes())
	if h, _ := GetHost(ctx, dst2, "h1"); h == nil || h.Address != "10.0.0.1" {
		t.Fatalf("guard ON: expected local kept (10.0.0.1), got %+v", h)
	}
	if dst2.SkewQuarantinedCount() == 0 {
		t.Error("guard ON: expected the quarantine counter to increment")
	}
}

// TestSkewGuard_QuarantinesFirstSeenFutureRow proves the first-seen fix: a
// future-skewed row for a PK this node has NEVER seen must be quarantined (not
// inserted), or its inflated updated_at would become the baseline and beat
// legitimate later writes.
func TestSkewGuard_QuarantinesFirstSeenFutureRow(t *testing.T) {
	ctx := context.Background()
	future := time.Now().Add(time.Hour).UTC().Format(nowTSLayout)

	src := testClient(t)
	if err := InsertHost(ctx, src, HostRecord{Name: "newh", Address: "10.0.0.5", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := src.Execute(ctx, `UPDATE hosts SET updated_at=? WHERE name=?`, future, "newh"); err != nil {
		t.Fatal(err)
	}

	// Guard OFF: the first-seen skewed row is applied (vulnerability).
	dstOff := testClient(t)
	dstOff.MergeStateBytesLWW(src.DumpStateBytes())
	if h, _ := GetHost(ctx, dstOff, "newh"); h == nil {
		t.Fatal("guard OFF: expected first-seen row to be applied")
	}

	// Guard ON: the first-seen skewed row is quarantined — not inserted at all.
	dstOn := testClient(t)
	dstOn.SetHLCSkewGuard(func() bool { return true })
	dstOn.MergeStateBytesLWW(src.DumpStateBytes())
	if h, _ := GetHost(ctx, dstOn, "newh"); h != nil {
		t.Fatalf("guard ON: first-seen future-skewed row must NOT be inserted, got %+v", h)
	}
	if dstOn.SkewQuarantinedCount() == 0 {
		t.Error("guard ON: expected the quarantine counter to increment for a first-seen row")
	}
}
