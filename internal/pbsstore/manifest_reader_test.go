package pbsstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"
)

// TestManifestReader_RoundTrip pushes a deterministic byte stream into
// a repo, opens it via ManifestReader, and asserts ReadAt returns the
// exact bytes at the same offsets — proves the read path can rebuild
// any disk slice without first materialising the full image.
func TestManifestReader_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	repo, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// 12 MiB of pseudo-random bytes split into 3 chunks at 4 MiB.
	src := make([]byte, 12*1024*1024)
	if _, err := rand.Read(src); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	m, err := PushDisk(context.Background(), repo, bytes.NewReader(src), PushOptions{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-11T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}

	r, nerr := NewManifestReader(repo, m)
	if nerr != nil {
		t.Fatalf("NewManifestReader: %v", nerr)
	}
	defer r.Close()

	if r.Size() != int64(len(src)) {
		t.Fatalf("Size = %d, want %d", r.Size(), len(src))
	}

	// Spot-check ten random windows.
	for _, off := range []int64{0, 1024, 4*1024*1024 - 5, 4 * 1024 * 1024, 8*1024*1024 - 1, 11 * 1024 * 1024} {
		for _, length := range []int{1, 4096, 1024 * 1024} {
			if off+int64(length) > int64(len(src)) {
				continue
			}
			got := make([]byte, length)
			n, err := r.ReadAt(got, off)
			if err != nil && err != io.EOF {
				t.Fatalf("ReadAt(off=%d, len=%d): %v", off, length, err)
			}
			if n != length {
				t.Fatalf("ReadAt(off=%d) n=%d, want %d", off, n, length)
			}
			want := src[off : off+int64(length)]
			if !bytes.Equal(got, want) {
				t.Fatalf("ReadAt(off=%d, len=%d) byte mismatch", off, length)
			}
		}
	}
}

// TestManifestReader_CrossChunkRead asserts a single read spanning two
// chunk boundaries returns contiguous bytes — the NBD server hits
// this whenever a guest reads a multi-MiB transfer.
func TestManifestReader_CrossChunkRead(t *testing.T) {
	dir := t.TempDir()
	repo, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	src := make([]byte, 9*1024*1024) // 3 chunks: 4 MiB / 4 MiB / 1 MiB
	for i := range src {
		src[i] = byte(i)
	}
	m, err := PushDisk(context.Background(), repo, bytes.NewReader(src), PushOptions{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-11T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}

	r, nerr := NewManifestReader(repo, m)
	if nerr != nil {
		t.Fatalf("NewManifestReader: %v", nerr)
	}
	defer r.Close()

	// Straddle chunks 0/1 by 1 MiB on each side.
	off := int64(3 * 1024 * 1024)
	length := 2 * 1024 * 1024
	got := make([]byte, length)
	if _, err := r.ReadAt(got, off); err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	want := src[off : off+int64(length)]
	if !bytes.Equal(got, want) {
		t.Fatalf("cross-chunk bytes mismatch")
	}
}

// TestManifestReader_PastEnd asserts reads past TotalSize report EOF
// — the NBD server uses this to bound the disk size advertised to
// the guest.
func TestManifestReader_PastEnd(t *testing.T) {
	dir := t.TempDir()
	repo, err := Init(dir)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	src := make([]byte, 4096)
	m, err := PushDisk(context.Background(), repo, bytes.NewReader(src), PushOptions{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-11T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	r, nerr := NewManifestReader(repo, m)
	if nerr != nil {
		t.Fatalf("NewManifestReader: %v", nerr)
	}
	got := make([]byte, 1024)
	_, err = r.ReadAt(got, 4096)
	if err != io.EOF {
		t.Fatalf("ReadAt past end err = %v, want io.EOF", err)
	}
}
