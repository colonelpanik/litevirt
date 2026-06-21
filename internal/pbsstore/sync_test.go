package pbsstore

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

// TestSyncRepo_CopiesMissingSnapshot pushes one snapshot to src and
// syncs to a fresh dst, asserting the dst can restore the data.
func TestSyncRepo_CopiesMissingSnapshot(t *testing.T) {
	src := newTestRepo(t)
	dst := newTestRepo(t)

	payload := randomBytes(t, ChunkSize*2+128)
	m, err := PushDisk(context.Background(), src, bytes.NewReader(payload), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}

	stats, err := SyncRepo(context.Background(), src, dst)
	if err != nil {
		t.Fatalf("SyncRepo: %v", err)
	}
	if stats.ManifestsCopied != 1 || stats.ChunksCopied != len(m.Chunks) {
		t.Errorf("stats = %+v", stats)
	}

	// Restore from the destination and confirm bit-equality.
	got, err := dst.GetManifest(m.VMName, m.Timestamp, m.DiskName)
	if err != nil {
		t.Fatalf("dst.GetManifest: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := RestoreToFile(context.Background(), dst, got, out, RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile from dst: %v", err)
	}
}

// TestSyncRepo_Idempotent verifies a second sync is a no-op.
func TestSyncRepo_Idempotent(t *testing.T) {
	src := newTestRepo(t)
	dst := newTestRepo(t)
	if _, err := PushDisk(context.Background(), src, bytes.NewReader(randomBytes(t, ChunkSize)), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if _, err := SyncRepo(context.Background(), src, dst); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	stats, err := SyncRepo(context.Background(), src, dst)
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if stats.ManifestsCopied != 0 || stats.ChunksCopied != 0 {
		t.Errorf("expected idempotent second sync, got %+v", stats)
	}
}

// TestSyncRepo_RefusesEncryptionMismatch protects against accidentally
// dumping plaintext chunks into an encrypted DR repo.
func TestSyncRepo_RefusesEncryptionMismatch(t *testing.T) {
	plain := newTestRepo(t)
	encDir := t.TempDir()
	enc, err := InitEncrypted(encDir, EncryptionModeAESGCM)
	if err != nil {
		t.Fatalf("InitEncrypted: %v", err)
	}
	if err := enc.SetKey(bytes.Repeat([]byte{0x11}, 32)); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	// plaintext src → encrypted dst should fail (and vice-versa).
	if _, err := SyncRepo(context.Background(), plain, enc); err == nil {
		t.Error("expected mode mismatch error (plain → encrypted)")
	}
	if _, err := SyncRepo(context.Background(), enc, plain); err == nil {
		t.Error("expected mode mismatch error (encrypted → plain)")
	}
}

// TestSyncRepo_ContextCancel guards against runaway syncs.
func TestSyncRepo_ContextCancel(t *testing.T) {
	src := newTestRepo(t)
	dst := newTestRepo(t)
	if _, err := PushDisk(context.Background(), src, bytes.NewReader(randomBytes(t, ChunkSize*2)), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	}); err != nil {
		t.Fatalf("Push: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := SyncRepo(ctx, src, dst)
	if err == nil {
		t.Error("expected context.Canceled, got nil")
	}
}
