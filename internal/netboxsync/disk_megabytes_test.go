// NetBox's `virtual_machine.disk` is DECIMAL MEGABYTES. The mirror used to put
// project quota's GiB-rounded figure in it, so a 20 GiB disk was recorded as 20
// and a 64 MiB one as 1.
//
// The unit is pinned by ASSERTING THE NUMBER, here and in
// internal/netbox/disk_megabytes_test.go and tests/fleet/netbox_mirror_test.go.
// A round-trip assertion cannot do it on its own: written and read in the same
// wrong unit, the value compares equal to itself forever.

package netboxsync

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestDesiredDiskIsDecimalMegabytes pins the unit of NetBox's
// `virtual_machine.disk`: DECIMAL megabytes, 1 MB = 1,000,000 bytes.
func TestDesiredDiskIsDecimalMegabytes(t *testing.T) {
	cases := []struct {
		name  string
		disks []corrosion.DiskRecord
		want  int
	}{
		{"no disks", nil, 0},
		{"20 GiB", []corrosion.DiskRecord{{SizeBytes: 20 << 30}}, 21475},
		{"64 MiB", []corrosion.DiskRecord{{SizeBytes: 64 << 20}}, 68},
		{"exactly one MB", []corrosion.DiskRecord{{SizeBytes: 1_000_000}}, 1},
		{"one byte rounds up", []corrosion.DiskRecord{{SizeBytes: 1}}, 1},
		{"two disks sum", []corrosion.DiskRecord{{SizeBytes: 20 << 30}, {SizeBytes: 64 << 20}}, 21542},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := totalDiskMB(tc.disks); got != tc.want {
				t.Errorf("disk = %d MB, want %d MB", got, tc.want)
			}
		})
	}
}

// TestDiskEmitsNoPatchWhenAlreadyCorrect is the round trip the mirror's
// write-on-change rule depends on: the value this package computes, decoded
// back out of a NetBox payload by the production decoder, must compare EQUAL.
//
// Desired is built through totalDiskMB from a real disk row rather than written
// out as a literal, so a conversion that changed on one side only fails here.
func TestDiskEmitsNoPatchWhenAlreadyCorrect(t *testing.T) {
	disks := []corrosion.DiskRecord{{SizeBytes: 20 << 30}}
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"vm-1","vcpus":2,`+
		`"memory":2048,"disk":21475,"status":{"value":"active"},"cluster":{"id":5},`+
		`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048,
		DiskMB: totalDiskMB(disks), Status: "active",
	}}, actual, fp)

	if len(got) != 0 {
		t.Fatalf("a disk already recorded correctly emitted %+v — every sweep would "+
			"PATCH it and bury NetBox's changelog", got)
	}
}

// TestDiskConvergesFromTheGibibyteValue is the other direction: a cluster
// mirrored by a build that wrote gibibytes has wrong numbers in NetBox, and the
// first sweep after the fix must correct them rather than agree with them.
func TestDiskConvergesFromTheGibibyteValue(t *testing.T) {
	disks := []corrosion.DiskRecord{{SizeBytes: 20 << 30}}
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"vm-1","vcpus":2,`+
		`"memory":2048,"disk":20,"status":{"value":"active"},"cluster":{"id":5},`+
		`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048,
		DiskMB: totalDiskMB(disks), Status: "active",
	}}, actual, fp)

	if len(got) != 1 || got[0].Op != "update" || got[0].NetBoxID != 11 {
		t.Fatalf("got %+v, want one vm/update converging the stale gibibyte value", got)
	}
}
