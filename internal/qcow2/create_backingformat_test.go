package qcow2

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// readBackingFormatExt walks the qcow2 header-extension area (starting at
// offset 104 in cluster 0) and returns the payload of the backing-format
// extension, or "" if none is present.
func readBackingFormatExt(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	off := 104
	for off+8 <= len(data) {
		extType := binary.BigEndian.Uint32(data[off : off+4])
		extLen := int(binary.BigEndian.Uint32(data[off+4 : off+8]))
		if extType == ExtEndOfArea {
			return ""
		}
		payloadStart := off + 8
		if payloadStart+extLen > len(data) {
			t.Fatalf("extension length %d overruns file", extLen)
		}
		if extType == ExtBackingFormat {
			return string(data[payloadStart : payloadStart+extLen])
		}
		off = payloadStart + ((extLen + 7) &^ 7) // skip padded payload
	}
	return ""
}

// TestCreateWithBackingURI_DeclaresRaw guards the live-restore fix: an overlay
// over an NBD URI must declare its backing format as "raw" (the export serves
// guest-visible raw content), otherwise qemu rejects it with "Image is not in
// qcow2 format" at start.
func TestCreateWithBackingURI_DeclaresRaw(t *testing.T) {
	path := filepath.Join(t.TempDir(), "overlay.qcow2")
	if err := CreateWithBackingURI(path, "nbd://localhost:10809/vda", 10<<30, nil); err != nil {
		t.Fatalf("CreateWithBackingURI: %v", err)
	}
	if got := readBackingFormatExt(t, path); got != "raw" {
		t.Fatalf("backing format = %q, want %q", got, "raw")
	}
}

// TestCreateWithBacking_DeclaresQcow2 confirms a plain local-file overlay still
// declares qcow2 backing (unchanged behaviour).
func TestCreateWithBacking_DeclaresQcow2(t *testing.T) {
	dir := t.TempDir()
	backing := filepath.Join(dir, "base.qcow2")
	if err := Create(backing, 1<<30, nil); err != nil {
		t.Fatalf("Create backing: %v", err)
	}
	overlay := filepath.Join(dir, "overlay.qcow2")
	if err := CreateWithBacking(overlay, backing, 0, nil); err != nil {
		t.Fatalf("CreateWithBacking: %v", err)
	}
	if got := readBackingFormatExt(t, overlay); got != "qcow2" {
		t.Fatalf("backing format = %q, want %q", got, "qcow2")
	}
}
