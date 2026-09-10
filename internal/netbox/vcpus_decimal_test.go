// NetBox's `vcpus` is a DECIMAL, and the mirror has to decode one.
//
// `virtual_machine.vcpus` is a DecimalField on the model and NetBox does not
// coerce decimals to strings, so every real response carries `"vcpus": 2.0`.
// While the field was declared `int` that number failed to unmarshal, and the
// failure was not partial: it took down the WHOLE response — the create-response
// decode and every page of the inventory enumeration — so the mirror could not
// read a live server at all. Nothing here caught it because the fleet's fake
// echoed the bare integer it had been given (that fake now renders a decimal
// too; see tests/fleet/netboxfake_inventory.go).

package netbox

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// TestListVMsDecodesADecimalVCPUsResponse is the live-server shape: the exact
// body NetBox returns for a two-vCPU guest.
func TestListVMsDecodesADecimalVCPUsResponse(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"id":11,"name":"vm-1","vcpus":2.0,"memory":2048,` +
			`"disk":20000,"status":{"value":"active"},"cluster":{"id":5}}],"next":null}`))
	})
	vms, err := c.ListVMsByCluster(context.Background(), 5)
	if err != nil {
		t.Fatalf("decode NetBox's decimal vcpus response: %v", err)
	}
	if len(vms) != 1 {
		t.Fatalf("decoded %d VMs, want 1", len(vms))
	}
	// The value has to SURVIVE, not merely decode: the diff compares it, so a
	// decode that dropped it would trade a hard failure for a PATCH every sweep.
	if vms[0].VCPUs != 2 {
		t.Fatalf("VCPUs = %v, want 2", vms[0].VCPUs)
	}
}

// TestVCPUsDecodesEveryShapeAServerCanSend covers the rest of what the field can
// carry: a null (the column is nullable, and unset means the zero value to the
// diff), a bare integer (what the old fake sent, and what NetBox accepts on a
// write), a quoted decimal (DRF's framework default rendering, which NetBox
// overrides but an install fronting it need not), and a genuinely fractional
// value, which must survive rather than round.
func TestVCPUsDecodesEveryShapeAServerCanSend(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want VCPUs
	}{
		{`null`, 0},
		{`2`, 2},
		{`2.0`, 2},
		{`"2.00"`, 2},
		{`2.5`, 2.5},
	} {
		var got VCPUs
		if err := json.Unmarshal([]byte(tc.raw), &got); err != nil {
			t.Errorf("unmarshal %s: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("unmarshal %s = %v, want %v", tc.raw, got, tc.want)
		}
	}
	// …and a value that is not a number at all is still an error, so a server
	// answering with something else is reported rather than read as zero vCPUs.
	var got VCPUs
	if err := json.Unmarshal([]byte(`"many"`), &got); err == nil {
		t.Fatalf("a non-numeric vcpus must not decode, got %v", got)
	}
}

// TestVMBodySendsVCPUsAsANumber pins the write side. NetBox's DecimalField
// accepts a JSON number, and a whole count must go out as one — not as a string,
// and not with a spurious fractional part that would show up in the changelog.
func TestVMBodySendsVCPUsAsANumber(t *testing.T) {
	var got map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	if err := c.UpdateVM(context.Background(), 11, VirtualMachine{Name: "vm-1", VCPUs: 2}); err != nil {
		t.Fatal(err)
	}
	if v, ok := got["vcpus"].(float64); !ok || v != 2 {
		t.Fatalf("vcpus was sent as %#v, want the number 2", got["vcpus"])
	}
}
