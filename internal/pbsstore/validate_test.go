package pbsstore

import (
	"strings"
	"testing"
)

func hexID(c byte) string { return strings.Repeat(string(c), 64) }

func TestValidateManifest_Good(t *testing.T) {
	// A sparse full backup: TotalSize spans 3 windows, only 2 are allocated
	// (a hole between them), so chunk sizes deliberately sum to less than
	// TotalSize. Empty BasedOn = full backup, which must be accepted.
	m := &Manifest{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-06-26T00:00:00Z",
		TotalSize: 3 * ChunkSize,
		Chunks: []ChunkRef{
			{ID: hexID('a'), Size: ChunkSize, Offset: 0},
			{ID: hexID('b'), Size: ChunkSize, Offset: 2 * ChunkSize},
		},
		FirmwareChunks: []ChunkRef{
			{ID: hexID('c'), Size: 1024, Offset: 0},
		},
	}
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("ValidateManifest(good sparse + firmware) = %v", err)
	}
	// An incremental (BasedOn set, RFC3339) is also fine.
	m.BasedOn = "2026-06-25T00:00:00Z"
	if err := ValidateManifest(m); err != nil {
		t.Fatalf("ValidateManifest(incremental) = %v", err)
	}
}

func TestValidateManifest_Reject(t *testing.T) {
	base := func() *Manifest {
		return &Manifest{
			VMName: "vm1", DiskName: "root", Timestamp: "2026-06-26T00:00:00Z",
			TotalSize: 2 * ChunkSize,
			Chunks: []ChunkRef{
				{ID: hexID('a'), Size: ChunkSize, Offset: 0},
				{ID: hexID('b'), Size: ChunkSize, Offset: ChunkSize},
			},
		}
	}
	tests := map[string]func(*Manifest){
		"bad-vm-name":     func(m *Manifest) { m.VMName = "../etc" },
		"bad-disk-name":   func(m *Manifest) { m.DiskName = "a/b" },
		"bad-timestamp":   func(m *Manifest) { m.Timestamp = "2026/06/26" },
		"bad-based-on":    func(m *Manifest) { m.BasedOn = "../x" },
		"non-hex-chunk":   func(m *Manifest) { m.Chunks[0].ID = "aaaa" },
		"negative-offset": func(m *Manifest) { m.Chunks[0].Offset = -1 },
		"oversize-chunk":  func(m *Manifest) { m.Chunks[0].Size = ChunkSize + 1 },
		"overlap":         func(m *Manifest) { m.Chunks[1].Offset = 0 },
		"extent-exceeds":  func(m *Manifest) { m.Chunks[1].Offset = 2 * ChunkSize }, // end = 3*ChunkSize > TotalSize
		"bad-fw-chunk":    func(m *Manifest) { m.FirmwareChunks = []ChunkRef{{ID: "zz", Size: 1, Offset: 0}} },
		"negative-total":  func(m *Manifest) { m.TotalSize = -1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			m := base()
			mutate(m)
			if err := ValidateManifest(m); err == nil {
				t.Errorf("ValidateManifest(%s) = nil, want error", name)
			}
		})
	}
}
