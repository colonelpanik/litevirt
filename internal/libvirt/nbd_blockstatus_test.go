package libvirt

import (
	"encoding/binary"
	"testing"
)

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func TestParseBlockStatusPayload(t *testing.T) {
	// ctxID=7, then three extents:
	//   8 MiB clean, 4 MiB dirty, 4 MiB clean.
	var p []byte
	p = append(p, be32(7)...)
	p = append(p, be32(8<<20)...)
	p = append(p, be32(0)...) // clean
	p = append(p, be32(4<<20)...)
	p = append(p, be32(nbdStateDirty)...) // dirty
	p = append(p, be32(4<<20)...)
	p = append(p, be32(0)...) // clean

	ctxID, extents, err := parseBlockStatusPayload(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ctxID != 7 {
		t.Errorf("ctxID = %d, want 7", ctxID)
	}
	if len(extents) != 3 {
		t.Fatalf("got %d extents, want 3", len(extents))
	}
	if extents[0].length != 8<<20 || extents[0].flags != 0 {
		t.Errorf("extent0 = %+v", extents[0])
	}
	if extents[1].length != 4<<20 || extents[1].flags&nbdStateDirty == 0 {
		t.Errorf("extent1 not dirty: %+v", extents[1])
	}
	if extents[2].flags != 0 {
		t.Errorf("extent2 should be clean: %+v", extents[2])
	}
}

func TestParseBlockStatusPayload_Errors(t *testing.T) {
	if _, _, err := parseBlockStatusPayload([]byte{0, 1}); err == nil {
		t.Error("expected error for short payload")
	}
	// ctxID + 9 trailing bytes (not a multiple of 8)
	bad := append(be32(1), make([]byte, 9)...)
	if _, _, err := parseBlockStatusPayload(bad); err == nil {
		t.Error("expected error for non-multiple-of-8 extent array")
	}
}

func TestParseMetaContextReply(t *testing.T) {
	data := append(be32(42), []byte("qemu:dirty-bitmap:lvdirty")...)
	id, name, err := parseMetaContextReply(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id != 42 {
		t.Errorf("id = %d, want 42", id)
	}
	if name != "qemu:dirty-bitmap:lvdirty" {
		t.Errorf("name = %q", name)
	}
	if _, _, err := parseMetaContextReply([]byte{1, 2}); err == nil {
		t.Error("expected error for short reply")
	}
}

func TestEncodeSetMetaContext(t *testing.T) {
	got := encodeSetMetaContext("vda", "qemu:dirty-bitmap:lvdirty")
	// 4 (exportlen) + 3 (export) + 4 (count) + 4 (querylen) + 25 (query)
	if len(got) != 4+3+4+4+25 {
		t.Fatalf("encoded length = %d", len(got))
	}
	if binary.BigEndian.Uint32(got[0:4]) != 3 {
		t.Errorf("export length field wrong")
	}
	if string(got[4:7]) != "vda" {
		t.Errorf("export name wrong: %q", got[4:7])
	}
	if binary.BigEndian.Uint32(got[7:11]) != 1 {
		t.Errorf("query count != 1")
	}
	if binary.BigEndian.Uint32(got[11:15]) != 25 {
		t.Errorf("query length field wrong")
	}
	if string(got[15:]) != "qemu:dirty-bitmap:lvdirty" {
		t.Errorf("query wrong: %q", got[15:])
	}
}

func TestEncodeOptGo(t *testing.T) {
	got := encodeOptGo("vda")
	// 4 (exportlen) + 3 (export) + 2 (info count = 0)
	if len(got) != 4+3+2 {
		t.Fatalf("encoded length = %d", len(got))
	}
	if binary.BigEndian.Uint32(got[0:4]) != 3 {
		t.Errorf("export length wrong")
	}
	if string(got[4:7]) != "vda" {
		t.Errorf("export wrong")
	}
	if got[7] != 0 || got[8] != 0 {
		t.Errorf("info-request count should be 0")
	}
}

func TestBuildCheckpointXML(t *testing.T) {
	got, err := buildCheckpointXML("lv-2026", []string{"vda", "vdb"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := `<domaincheckpoint><name>lv-2026</name><disks>` +
		`<disk name="vda" checkpoint="bitmap"></disk>` +
		`<disk name="vdb" checkpoint="bitmap"></disk>` +
		`</disks></domaincheckpoint>`
	if got != want {
		t.Errorf("checkpoint XML mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestBuildBackupXML(t *testing.T) {
	got, err := buildBackupXML("vda", "lv-parent", "/run/x.sock", "/run/x.scratch")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Spot-check the pull-mode incremental wiring rather than exact bytes.
	for _, sub := range []string{
		`mode="pull"`,
		`<incremental>lv-parent</incremental>`,
		`transport="unix"`,
		`socket="/run/x.sock"`,
		`name="vda"`,
		`exportname="vda"`,
		`exportbitmap="lvdirty"`,
		`file="/run/x.scratch"`,
	} {
		if !contains(got, sub) {
			t.Errorf("backup XML missing %q in:\n%s", sub, got)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
