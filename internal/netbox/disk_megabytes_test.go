// NetBox's `virtual_machine.disk` is MEGABYTES — decimal ones, 1 MB =
// 1,000,000 bytes — and `virtual_disk.size` is the same unit. The mirror wrote
// gibibytes into that column and decoded them back into a field called DiskGB,
// so a 20 GiB disk was recorded as 20 MB and read back as 20 GiB.
//
// Nothing caught it, and the round trip is why: the value was written and read
// in the SAME wrong unit, so it compared equal to itself on every sweep. The
// fleet's fake is faithful here — it echoes `disk` exactly as written and
// normalises nothing — and that is precisely what makes a round-trip assertion
// unit-blind. Only an assertion on the NUMBER can tell the units apart, which is
// what the first test below is.

package netbox

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"testing"
)

func TestDiskMBFromBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes int64
		want  int
	}{
		// The value that made the bug legible: 21,474,836,480 bytes is 21475
		// decimal megabytes, and was being recorded as 20.
		{"20 GiB", 20 << 30, 21475},
		{"64 MiB", 64 << 20, 68},
		// Round UP, always: a recorded size must never understate the disk.
		{"one byte", 1, 1},
		{"one MB exactly", bytesPerMB, 1},
		{"one MB and one byte", bytesPerMB + 1, 2},
		// A megabyte, not a mebibyte: the two differ by ~4.9% and diverge
		// further with size, so a mebibyte conversion would put 1000 here.
		{"1000 MB exactly", 1000 * bytesPerMB, 1000},
		{"zero", 0, 0},
		// Absent and impossible both mean "nothing to record", never a
		// negative megabyte count NetBox would reject.
		{"negative", -1, 0},
		// The remainder is carried rather than added up front, so a size near
		// the maximum does not overflow into a negative.
		{"max int64", math.MaxInt64, 9223372036855},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DiskMBFromBytes(tc.bytes); got != tc.want {
				t.Errorf("DiskMBFromBytes(%d) = %d MB, want %d MB", tc.bytes, got, tc.want)
			}
		})
	}
}

// TestVMDiskRoundTripsInMegabytes writes a VM and reads the server's echo back
// through the real decoder.
//
// It pins the two halves that must agree: the value on the WIRE is the megabyte
// figure (asserted against the raw request body, so a conversion applied on read
// instead of on write cannot satisfy it), and what comes back decodes into the
// same field with the same number — which is what stops a sweep over unchanged
// state emitting a PATCH.
func TestVMDiskRoundTripsInMegabytes(t *testing.T) {
	const twentyGiB = int64(20) << 30
	var sent map[string]any

	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&sent); err != nil {
			t.Errorf("decode write body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// Echoed VERBATIM, in NetBox's response shape (a choice object for
		// status, a decimal for vcpus). A server that re-derived or rounded the
		// value would hide a write-side unit error.
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":11,"name":"vm-1","vcpus":2.0,"memory":2048,"disk":` +
			jsonNumber(t, sent["disk"]) + `,"status":{"value":"active"},"cluster":{"id":5},` +
			`"custom_fields":{"litevirt_identity":"lv:fp:u1"}}`))
	})

	want := DiskMBFromBytes(twentyGiB)
	if want != 21475 {
		t.Fatalf("precondition: 20 GiB is %d MB, want 21475", want)
	}
	got, err := c.CreateVM(context.Background(), VirtualMachine{
		Name: "vm-1", ClusterID: 5, VCPUs: 2, MemoryMB: 2048,
		DiskMB: want, Status: "active", Identity: "lv:fp:u1",
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if n, ok := sent["disk"].(float64); !ok || int(n) != want {
		t.Fatalf("the wire carried disk=%v, want the megabyte figure %d", sent["disk"], want)
	}
	if got.DiskMB != want {
		t.Fatalf("disk read back as %d MB, want %d MB — a value written and read in "+
			"different units makes every sweep PATCH", got.DiskMB, want)
	}
}

func jsonNumber(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %v: %v", v, err)
	}
	return string(b)
}
