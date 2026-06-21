package corrosion

import (
	"context"
	"testing"
	"time"
)

func TestVMEvents_InsertListOrderingLimitSince(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	for i, ev := range []struct {
		id, typ, result string
		off             time.Duration
	}{
		{"e1", "backup.started", "ok", 0},
		{"e2", "backup.failed", "error", 1 * time.Minute},
		{"e3", "vm.started", "ok", 2 * time.Minute},
	} {
		if err := InsertVMEvent(ctx, c, VMEventRecord{
			ID: ev.id, VMName: "vm-a", HostName: "host-a", Type: ev.typ, Result: ev.result,
			TS: base.Add(ev.off).Format(time.RFC3339Nano),
		}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	// Event for a different VM must not leak into vm-a's list.
	if err := InsertVMEvent(ctx, c, VMEventRecord{ID: "x1", VMName: "vm-b", HostName: "host-a", Type: "vm.started", TS: base.Format(time.RFC3339Nano)}); err != nil {
		t.Fatalf("insert other vm: %v", err)
	}

	got, err := ListVMEvents(ctx, c, "vm-a", 0, "")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 events for vm-a, got %d", len(got))
	}
	// Newest first.
	if got[0].ID != "e3" || got[1].ID != "e2" || got[2].ID != "e1" {
		t.Errorf("ordering wrong: %s,%s,%s", got[0].ID, got[1].ID, got[2].ID)
	}
	if got[1].Result != "error" || got[1].Severity == "" {
		t.Errorf("e2 should be error with severity, got result=%q severity=%q", got[1].Result, got[1].Severity)
	}

	// limit
	lim, _ := ListVMEvents(ctx, c, "vm-a", 1, "")
	if len(lim) != 1 || lim[0].ID != "e3" {
		t.Errorf("limit=1 should return newest only, got %v", lim)
	}
	// since (>= cutoff at e2)
	since, _ := ListVMEvents(ctx, c, "vm-a", 0, base.Add(1*time.Minute).Format(time.RFC3339Nano))
	if len(since) != 2 {
		t.Errorf("since e2 should return 2 (e2,e3), got %d", len(since))
	}
}

func TestVMEvents_InsertIdempotentOnID(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	rec := VMEventRecord{ID: "dup", VMName: "vm-a", HostName: "host-a", Type: "vm.started", TS: "2026-06-01T00:00:00Z"}
	if err := InsertVMEvent(ctx, c, rec); err != nil {
		t.Fatalf("insert 1: %v", err)
	}
	if err := InsertVMEvent(ctx, c, rec); err != nil { // simulate replicated re-delivery
		t.Fatalf("insert 2: %v", err)
	}
	got, _ := ListVMEvents(ctx, c, "vm-a", 0, "")
	if len(got) != 1 {
		t.Fatalf("re-insert on same id must be a no-op, got %d rows", len(got))
	}
}

func TestVMEvents_Prune(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	now := time.Now().UTC()
	mk := func(id, result string, age time.Duration) {
		if err := InsertVMEvent(ctx, c, VMEventRecord{
			ID: id, VMName: "vm-a", HostName: "host-a", Type: "backup", Result: result,
			TS: now.Add(-age).Format(time.RFC3339Nano),
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	mk("old-info", "ok", 40*24*time.Hour)    // >30d → pruned
	mk("recent-info", "ok", 5*24*time.Hour)  // kept
	mk("mid-err", "error", 40*24*time.Hour)  // <90d → kept
	mk("old-err", "error", 100*24*time.Hour) // >90d → pruned
	// foreign host row must survive a host-a prune.
	if err := InsertVMEvent(ctx, c, VMEventRecord{ID: "foreign", VMName: "vm-a", HostName: "host-b", Type: "backup", Result: "ok", TS: now.Add(-200 * 24 * time.Hour).Format(time.RFC3339Nano)}); err != nil {
		t.Fatalf("insert foreign: %v", err)
	}

	if err := PruneVMEvents(ctx, c, "host-a", 30, 90, 0); err != nil {
		t.Fatalf("prune: %v", err)
	}
	got, _ := ListVMEvents(ctx, c, "vm-a", 0, "")
	keep := map[string]bool{}
	for _, e := range got {
		keep[e.ID] = true
	}
	if keep["old-info"] || keep["old-err"] {
		t.Errorf("old-info/old-err should be pruned; got %v", keep)
	}
	if !keep["recent-info"] || !keep["mid-err"] || !keep["foreign"] {
		t.Errorf("recent-info/mid-err/foreign should survive; got %v", keep)
	}
}

func TestVMEvents_PrunePerVMCap(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	base := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		mkID := string(rune('a' + i))
		if err := InsertVMEvent(ctx, c, VMEventRecord{
			ID: mkID, VMName: "vm-a", HostName: "host-a", Type: "tick", Result: "ok",
			TS: base.Add(time.Duration(i) * time.Minute).Format(time.RFC3339Nano),
		}); err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
	}
	if err := PruneVMEvents(ctx, c, "host-a", 0, 0, 3); err != nil { // cap=3, age sweeps disabled
		t.Fatalf("prune: %v", err)
	}
	got, _ := ListVMEvents(ctx, c, "vm-a", 0, "")
	if len(got) != 3 {
		t.Fatalf("per-VM cap=3 should leave 3 newest, got %d", len(got))
	}
	// Newest three are f,e,d.
	if got[0].ID != "f" || got[2].ID != "d" {
		t.Errorf("expected newest 3 (f,e,d), got %s..%s", got[0].ID, got[2].ID)
	}
}
