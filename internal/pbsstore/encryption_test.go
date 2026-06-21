package pbsstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptedRepo_RoundTrip pushes a snapshot through an encrypted
// repo, restores it, and asserts byte-for-byte equality.
func TestEncryptedRepo_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	r, err := InitEncrypted(dir, EncryptionModeAESGCM)
	if err != nil {
		t.Fatalf("InitEncrypted: %v", err)
	}
	if !r.IsEncrypted() {
		t.Fatal("repo should report IsEncrypted() == true")
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	if err := r.SetKey(key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	src := randomBytes(t, ChunkSize*2+999)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-05-09T01:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}

	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := RestoreToFile(context.Background(), r, m, dst, RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(src, got) {
		t.Errorf("encrypted round-trip mismatch")
	}
}

// TestEncryptedRepo_OnDiskBytesAreCipher confirms chunk files do NOT
// equal the plaintext — i.e. the encryption is actually happening.
func TestEncryptedRepo_OnDiskBytesAreCipher(t *testing.T) {
	r, err := InitEncrypted(t.TempDir(), EncryptionModeAESGCM)
	if err != nil {
		t.Fatalf("InitEncrypted: %v", err)
	}
	key := bytes.Repeat([]byte{0x33}, 32)
	if err := r.SetKey(key); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	plaintext := []byte("THIS_MUST_NOT_APPEAR_ON_DISK_AS_CLEARTEXT")
	id, _, err := r.PutChunk(plaintext)
	if err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	onDisk, err := os.ReadFile(r.chunkPath(id))
	if err != nil {
		t.Fatalf("read chunk file: %v", err)
	}
	if bytes.Contains(onDisk, plaintext) {
		t.Error("plaintext bytes appear on disk — encryption is not active")
	}
	// Must be at least 12 (nonce) + 16 (auth tag) larger than plaintext.
	if len(onDisk) < len(plaintext)+12+16 {
		t.Errorf("on-disk size %d looks too small for nonce+ciphertext+tag (plaintext=%d)",
			len(onDisk), len(plaintext))
	}
}

// TestEncryptedRepo_WrongKeyFails opens the repo with a different key
// and confirms reads surface ErrKeyMismatch.
func TestEncryptedRepo_WrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	r, err := InitEncrypted(dir, EncryptionModeAESGCM)
	if err != nil {
		t.Fatalf("InitEncrypted: %v", err)
	}
	if err := r.SetKey(bytes.Repeat([]byte{0x77}, 32)); err != nil {
		t.Fatalf("SetKey: %v", err)
	}
	id, _, err := r.PutChunk([]byte("payload"))
	if err != nil {
		t.Fatalf("PutChunk: %v", err)
	}

	// Re-open with a different key.
	r2, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !r2.IsEncrypted() {
		t.Fatal("Open should remember encryption mode")
	}
	if err := r2.SetKey(bytes.Repeat([]byte{0x00}, 32)); err != nil {
		t.Fatalf("SetKey wrong: %v", err)
	}
	_, err = r2.GetChunk(id)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("expected ErrKeyMismatch, got %v", err)
	}
}

// TestSetKey_RejectsWrongLength locks the public contract.
func TestSetKey_RejectsWrongLength(t *testing.T) {
	r := newTestRepo(t)
	for _, n := range []int{0, 16, 24, 31, 33} {
		if err := r.SetKey(make([]byte, n)); err == nil {
			t.Errorf("SetKey(len=%d) should fail", n)
		}
	}
}

// TestUnencryptedRepo_StoresPlaintext sanity-checks that plain repos
// (no SetKey) still write raw chunk bytes verbatim.
func TestUnencryptedRepo_StoresPlaintext(t *testing.T) {
	r := newTestRepo(t)
	plaintext := []byte("clear bytes")
	id, _, err := r.PutChunk(plaintext)
	if err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	onDisk, err := os.ReadFile(r.chunkPath(id))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(onDisk, plaintext) {
		t.Errorf("on-disk = %q, want plaintext", onDisk)
	}
}
