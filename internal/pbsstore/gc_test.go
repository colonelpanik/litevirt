package pbsstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestGC_RemovesUnreferencedChunks pushes one snapshot, deletes its
// manifest, and verifies GC reclaims the chunks.
func TestGC_RemovesUnreferencedChunks(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize*2)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	// Drop the manifest by hand.
	manifestPath := filepath.Join(r.root, "snapshots", m.VMName,
		filenameSafeTS(m.Timestamp)+"-"+m.DiskName+".manifest.json")
	if err := os.Remove(manifestPath); err != nil {
		t.Fatalf("remove manifest: %v", err)
	}

	stats, err := GC(context.Background(), r)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.ChunksDeleted != len(m.Chunks) {
		t.Errorf("deleted = %d, want %d", stats.ChunksDeleted, len(m.Chunks))
	}
	for _, c := range m.Chunks {
		if r.HasChunk(c.ID) {
			t.Errorf("chunk %s should have been swept", c.ID)
		}
	}
}

// TestGC_KeepsFirmwareChunks ensures GC treats a manifest's FirmwareChunks as
// reachable — a vTPM backup's NVRAM/swtpm bundle must not be swept as garbage.
func TestGC_KeepsFirmwareChunks(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "fwvm", DiskName: "root", Timestamp: "2026-06-26T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	// Store a firmware bundle as separate content-addressed chunks and attach
	// the refs to the manifest, then re-write it.
	fwRefs, err := r.PutBytes(randomBytes(t, 4096))
	if err != nil {
		t.Fatalf("PutBytes firmware: %v", err)
	}
	m.FirmwareChunks = fwRefs
	if err := r.PutManifest(m); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	if _, err := GC(context.Background(), r); err != nil {
		t.Fatalf("GC: %v", err)
	}
	for _, c := range fwRefs {
		if !r.HasChunk(c.ID) {
			t.Errorf("firmware chunk %s swept by GC; should be reachable", c.ID)
		}
	}
}

// TestGC_KeepsLiveChunks ensures GC never deletes chunks that any
// surviving manifest still points at.
func TestGC_KeepsLiveChunks(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize*2)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	stats, err := GC(context.Background(), r)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.ChunksDeleted != 0 {
		t.Errorf("deleted = %d on healthy repo, want 0", stats.ChunksDeleted)
	}
	for _, c := range m.Chunks {
		if !r.HasChunk(c.ID) {
			t.Errorf("chunk %s missing after GC", c.ID)
		}
	}
}

// TestVerify_FlagsBitRot pushes a snapshot, corrupts a chunk, runs
// Verify, and asserts the chunk id appears in Mismatches.
func TestVerify_FlagsBitRot(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize+5)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if err := os.WriteFile(r.chunkPath(m.Chunks[0].ID), []byte{0x00, 0x01}, 0640); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	stats, err := Verify(context.Background(), r)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(stats.Mismatches) != 1 || stats.Mismatches[0] != m.Chunks[0].ID {
		t.Errorf("Mismatches = %v, want [%s]", stats.Mismatches, m.Chunks[0].ID)
	}
}

// TestVerify_FlagsMissing reports manifest references whose chunks are
// gone.
func TestVerify_FlagsMissing(t *testing.T) {
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if err := r.DeleteChunk(m.Chunks[0].ID); err != nil {
		t.Fatalf("DeleteChunk: %v", err)
	}
	stats, err := Verify(context.Background(), r)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(stats.Missing) != 1 {
		t.Errorf("Missing = %v, want 1 entry", stats.Missing)
	}
}

// TestPlanPrune_KeepLast retains the N most-recent regardless of
// per-bucket settings.
func TestPlanPrune_KeepLast(t *testing.T) {
	r := newTestRepo(t)
	for _, ts := range []string{
		"2026-05-09T01:00:00Z",
		"2026-05-09T02:00:00Z",
		"2026-05-09T03:00:00Z",
		"2026-05-09T04:00:00Z",
	} {
		if err := r.PutManifest(&Manifest{VMName: "vm", DiskName: "root", Timestamp: ts}); err != nil {
			t.Fatalf("PutManifest: %v", err)
		}
	}
	plan, err := PlanPrune(r, RetentionPolicy{KeepLast: 2})
	if err != nil {
		t.Fatalf("PlanPrune: %v", err)
	}
	if len(plan.Keep) != 2 || len(plan.Delete) != 2 {
		t.Errorf("Keep=%d Delete=%d, want 2/2", len(plan.Keep), len(plan.Delete))
	}
	// The retained pair must be the two newest.
	for _, m := range plan.Keep {
		if m.Timestamp < "2026-05-09T03:00:00Z" {
			t.Errorf("retained too-old timestamp %q", m.Timestamp)
		}
	}
}

// TestPlanPrune_DailyWeeklyMonthly verifies the cascading bucket logic
// keeps the *first* (newest) snapshot in each daily/weekly/monthly slot.
func TestPlanPrune_DailyWeeklyMonthly(t *testing.T) {
	r := newTestRepo(t)
	timestamps := []string{
		// Same day → only the newest of the day kept under KeepDaily=2.
		"2026-05-09T22:00:00Z",
		"2026-05-09T01:00:00Z",
		// Distinct day, same week.
		"2026-05-08T01:00:00Z",
		// Earlier week.
		"2026-04-25T01:00:00Z",
		// Earlier month.
		"2026-03-25T01:00:00Z",
		// Earlier year.
		"2025-05-09T01:00:00Z",
	}
	for _, ts := range timestamps {
		if err := r.PutManifest(&Manifest{VMName: "vm", DiskName: "root", Timestamp: ts}); err != nil {
			t.Fatalf("PutManifest: %v", err)
		}
	}
	// KeepYearly=2 ⇒ keep one snapshot from each of the most recent 2
	// distinct years. Per-bucket retention is "first occurrence wins"
	// when input is sorted newest-first, so 2026's newest and 2025's
	// newest both qualify.
	plan, err := PlanPrune(r, RetentionPolicy{KeepDaily: 2, KeepWeekly: 1, KeepMonthly: 1, KeepYearly: 2})
	if err != nil {
		t.Fatalf("PlanPrune: %v", err)
	}
	keepTS := map[string]bool{}
	for _, m := range plan.Keep {
		keepTS[m.Timestamp] = true
	}
	if keepTS["2026-05-09T01:00:00Z"] {
		t.Errorf("expected older same-day snapshot to be pruned")
	}
	if !keepTS["2026-05-09T22:00:00Z"] {
		t.Errorf("expected newest of the day to be retained")
	}
	if !keepTS["2025-05-09T01:00:00Z"] {
		t.Errorf("expected the lone 2025 snapshot to be retained for KeepYearly=2")
	}
}

// TestApplyPrune_DeletesManifestFiles confirms ApplyPrune removes the
// .manifest.json files and the GC reclaims now-orphaned chunks.
func TestApplyPrune_DeletesManifestFiles(t *testing.T) {
	r := newTestRepo(t)
	// Two pushes with DIFFERENT bytes — randomBytes is seeded by n, so
	// both must use distinct sizes (or distinct content) to avoid full
	// dedup which would leave nothing for GC to reclaim.
	srcA := randomBytes(t, ChunkSize)
	srcB := randomBytes(t, ChunkSize+1024) // distinct seed → distinct chunks
	if _, err := PushDisk(context.Background(), r, bytes.NewReader(srcA), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-04-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("push: %v", err)
	}
	if _, err := PushDisk(context.Background(), r, bytes.NewReader(srcB), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T00:00:00Z",
	}); err != nil {
		t.Fatalf("push 2: %v", err)
	}
	plan, err := PlanPrune(r, RetentionPolicy{KeepLast: 1})
	if err != nil {
		t.Fatalf("PlanPrune: %v", err)
	}
	if err := ApplyPrune(r, plan); err != nil {
		t.Fatalf("ApplyPrune: %v", err)
	}
	mans, err := r.ListManifests()
	if err != nil {
		t.Fatalf("ListManifests: %v", err)
	}
	if len(mans) != 1 || mans[0].Timestamp != "2026-05-09T00:00:00Z" {
		t.Errorf("manifests after prune: %+v", mans)
	}
	stats, err := GC(context.Background(), r)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.ChunksDeleted == 0 {
		t.Errorf("expected GC to reclaim orphaned chunks")
	}
}
