package pbsstore

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPutBytesReadBytesRoundTrip(t *testing.T) {
	repo, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Spans multiple chunks plus a short tail, to exercise ref ordering.
	orig := make([]byte, ChunkSize*2+1234)
	if _, err := rand.Read(orig); err != nil {
		t.Fatalf("rand: %v", err)
	}

	refs, err := repo.PutBytes(orig)
	if err != nil {
		t.Fatalf("PutBytes: %v", err)
	}
	if len(refs) != 3 {
		t.Fatalf("expected 3 chunk refs for %d bytes, got %d", len(orig), len(refs))
	}

	var got bytes.Buffer
	if err := repo.ReadBytesTo(refs, &got); err != nil {
		t.Fatalf("ReadBytesTo: %v", err)
	}
	if !bytes.Equal(got.Bytes(), orig) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", got.Len(), len(orig))
	}
}

func TestPutBytesEmpty(t *testing.T) {
	repo, err := Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	refs, err := repo.PutBytes(nil)
	if err != nil {
		t.Fatalf("PutBytes(nil): %v", err)
	}
	if refs != nil {
		t.Fatalf("expected no refs for an empty blob, got %d", len(refs))
	}
}
