package opjournal

import (
	"os"
	"path/filepath"
	"testing"
)

func sampleEntry() Entry {
	return Entry{
		OperationID: "op-abc123", OwnerEpoch: 2, SpecGeneration: 5,
		ResourceID: "vm1", Kind: "restart", Stage: "journaled",
		Artifacts: map[string]string{"old_domain_xml": "<domain>...</domain>"},
		CreatedAt: "2026-07-14T00:00:00Z",
	}
}

func TestJournal_WriteReadRoundTrip(t *testing.T) {
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	e := sampleEntry()
	if err := j.Write(e); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, found, err := j.Read("op-abc123")
	if err != nil || !found {
		t.Fatalf("Read: found=%v err=%v", found, err)
	}
	if got.ResourceID != "vm1" || got.OwnerEpoch != 2 || got.SpecGeneration != 5 ||
		got.Artifacts["old_domain_xml"] != "<domain>...</domain>" || got.Version != entryVersion {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if !got.Matches("op-abc123", 2, 5) {
		t.Fatal("Matches should be true for the same identity")
	}
	if got.Matches("op-abc123", 3, 5) {
		t.Fatal("Matches must be false for a different owner epoch")
	}
}

func TestJournal_ReadMissing(t *testing.T) {
	j, _ := Open(t.TempDir())
	if _, found, err := j.Read("nope"); found || err != nil {
		t.Fatalf("missing entry: found=%v err=%v", found, err)
	}
}

func TestJournal_CorruptionDetected(t *testing.T) {
	dir := t.TempDir()
	j, _ := Open(dir)
	if err := j.Write(sampleEntry()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Rewrite valid JSON with an altered field but a stale checksum: the entry
	// parses but must fail verification (not be silently accepted).
	p := filepath.Join(dir, "op-abc123.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"operation_id":"op-abc123","owner_epoch":2,"spec_generation":5,"resource_id":"HACKED","kind":"restart","stage":"journaled","artifacts":{},"created_at":"x","checksum":"deadbeef"}`), filePerm); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, _, err := j.Read("op-abc123"); err == nil {
		t.Fatal("tampered entry must be reported corrupt, not silently accepted")
	}
}

func TestJournal_RemoveAndList(t *testing.T) {
	j, _ := Open(t.TempDir())
	e1 := sampleEntry()
	e2 := sampleEntry()
	e2.OperationID = "op-def456"
	if err := j.Write(e1); err != nil {
		t.Fatalf("Write e1: %v", err)
	}
	if err := j.Write(e2); err != nil {
		t.Fatalf("Write e2: %v", err)
	}
	entries, corrupt, err := j.List()
	if err != nil || len(entries) != 2 || len(corrupt) != 0 {
		t.Fatalf("List: entries=%d corrupt=%d err=%v", len(entries), len(corrupt), err)
	}
	if err := j.Remove("op-abc123"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, found, _ := j.Read("op-abc123"); found {
		t.Fatal("removed entry should be gone")
	}
	if _, found, _ := j.Read("op-def456"); !found {
		t.Fatal("Remove must not affect other entries")
	}
	// Removing a missing entry is not an error.
	if err := j.Remove("op-abc123"); err != nil {
		t.Fatalf("Remove(missing): %v", err)
	}
}

func TestJournal_RejectsOversizedEntry(t *testing.T) {
	j, _ := Open(t.TempDir())
	e := sampleEntry()
	big := make([]byte, maxEntryBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	e.Artifacts["blob"] = string(big)
	if err := j.Write(e); err == nil {
		t.Fatal("an oversized entry must be rejected (fail-closed)")
	}
}
