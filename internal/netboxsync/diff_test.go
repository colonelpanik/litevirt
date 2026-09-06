package netboxsync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/netbox"
)

const fp = "abc123"

func vmIdent(uuid string) string  { return netbox.Identity(fp, uuid, "") }
func nicIdent(u, m string) string { return netbox.Identity(fp, u, m) }

func TestDiffCreatesMissingVM(t *testing.T) {
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u1", VCPUs: 2}}, Actual{}, fp)
	if len(got) != 1 || got[0].Op != "create" || got[0].Key != vmIdent("u1") {
		t.Fatalf("got %+v", got)
	}
}

// TestDiffEmitsNothingWhenIdenticalUsingDecodedActual builds the actual state by
// DECODING a NetBox payload rather than constructing the struct by hand.
//
// Constructing it by hand hides the bug that matters: if vmJSON.toVM fails to
// populate a field vmDiffers compares, every VM looks changed on every sweep and
// write-on-change never fires. A hand-built fixture would pass regardless.
func TestDiffEmitsNothingWhenIdenticalUsingDecodedActual(t *testing.T) {
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"vm-1","vcpus":2,`+
		`"memory":2048,"disk":20,"status":{"value":"active"},"cluster":{"id":5},`+
		`"device":{"id":9},"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048,
		DiskGB: 20, Status: "active", DeviceID: 9,
	}}, actual, fp)

	if len(got) != 0 {
		t.Fatalf("identical state must emit no actions, got %+v", got)
	}
}

func TestDiffUpdatesOnDeviceChange(t *testing.T) {
	// A migration moves the host link but not the address. Without DeviceID in
	// vmDiffers, migration never converges in NetBox.
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u1", DeviceID: 10, Status: "active"}},
		Actual{VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", DeviceID: 9, Status: "active"},
		}}, fp)
	if len(got) != 1 || got[0].Op != "update" {
		t.Fatalf("got %+v", got)
	}
}

func TestDiffCreatesAndDeletesNICs(t *testing.T) {
	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01"}},
	}}, Actual{
		VMs:  map[string]netbox.VirtualMachine{vmIdent("u1"): {ID: 11, Status: "active"}},
		NICs: map[string]netbox.VMInterface{nicIdent("u1", "52:54:00:aa:bb:02"): {ID: 21}},
	}, fp)

	var creates, deletes int
	for _, a := range got {
		if a.Kind != "nic" {
			continue
		}
		switch a.Op {
		case "create":
			creates++
		case "delete":
			deletes++
		}
	}
	// Hotplug attach and detach cannot converge without both.
	if creates != 1 || deletes != 1 {
		t.Fatalf("want one NIC create and one delete, got %+v", got)
	}
}

func TestDiffUpdatesOnRenameUsingDecodedActual(t *testing.T) {
	// Identity-keying keeps the object across a rename, so nothing creates a new
	// one — but without Name in vmDiffers, NetBox keeps the OLD name forever.
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"old-name","vcpus":2,`+
		`"memory":2048,"disk":20,"status":{"value":"active"},"cluster":{"id":5},`+
		`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "new-name", UUID: "u1", VCPUs: 2, MemoryMB: 2048, DiskGB: 20, Status: "active",
	}}, actual, fp)

	if len(got) != 1 || got[0].Op != "update" || got[0].NetBoxID != 11 {
		t.Fatalf("a rename must emit one update carrying the object id, got %+v", got)
	}
}

func TestDiffClearsAStaleDeviceLinkUsingDecodedActual(t *testing.T) {
	actual := decodeActualFixture(t, `{"results":[{"id":11,"name":"vm-1","vcpus":2,`+
		`"memory":2048,"disk":20,"status":{"value":"active"},"cluster":{"id":5},`+
		`"device":{"id":9},"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`)

	// The host is no longer modelled as a DCIM device.
	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048,
		DiskGB: 20, Status: "active", DeviceID: 0,
	}}, actual, fp)

	if len(got) != 1 || got[0].Op != "update" {
		t.Fatalf("want one update to clear the device link, got %+v", got)
	}
	// The applier must send an explicit null; a body that omits the key leaves
	// device 9 in place and this same update repeats every sweep forever.
	body := vmBodyForTest(t, DesiredVM{Name: "vm-1", DeviceID: 0})
	if v, ok := body["device"]; !ok || v != nil {
		t.Fatalf("device must be sent as an explicit null, got %v (present=%v)", v, ok)
	}
}

func TestPhasesOrderParentsBeforeChildren(t *testing.T) {
	actions := []Action{
		{Kind: "vm", Op: "delete", Key: "vm-gone"},
		{Kind: "nic", Op: "delete", Key: "nic-gone"},
		{Kind: "nic", Op: "create", Key: "nic-new"},
		{Kind: "nic", Op: "clear", Key: "nic-stale", IPID: 41},
		{Kind: "vm", Op: "create", Key: "vm-new"},
	}
	got := Phases(actions)

	for _, tc := range []struct {
		phase int
		key   string
		what  string
	}{
		{PhaseVMUpsert, "vm-new", "VM creates/updates"},
		{PhaseIPClear, "nic-stale", "IP clears"},
		{PhaseNICUpsert, "nic-new", "NIC create/update/assign"},
		{PhaseNICDelete, "nic-gone", "NIC deletes"},
		{PhaseVMDelete, "vm-gone", "VM deletes"},
	} {
		if len(got[tc.phase]) != 1 || got[tc.phase][0].Key != tc.key {
			t.Errorf("phase %d must be %s, got %+v", tc.phase, tc.what, got[tc.phase])
		}
	}
}

func TestClearIsStrictlyBeforeEveryAssignment(t *testing.T) {
	// Ordering stated as an INEQUALITY on phase numbers, not as an observation
	// about a particular list. An assertion that merely checked which bucket
	// each action landed in would still pass if someone renumbered the phases
	// while collapsing two of them together.
	clear := Action{Kind: "nic", Op: "clear", IPID: 41}
	assign := Action{Kind: "nic", Op: "assign", IPID: 41}
	create := Action{Kind: "nic", Op: "create"}

	if !(Phase(clear) < Phase(assign)) {
		t.Errorf("clear must precede assign: %d vs %d", Phase(clear), Phase(assign))
	}
	// nic/create assigns its own address, so it counts as an assignment too.
	if !(Phase(clear) < Phase(create)) {
		t.Errorf("clear must precede nic/create: %d vs %d", Phase(clear), Phase(create))
	}
}

func TestDiffDetectsAssignmentDriftUsingDecodedActual(t *testing.T) {
	// The address was detached in NetBox after creation. Assignment happens only
	// on the create path, so without an assign action the sweep never repairs it.
	//
	// Actual state is DECODED from the real IP-address payload that BuildActual
	// consumes. Hand-setting an assignment field would prove nothing about
	// whether production collection can see the drift at all — the same gap that
	// made the earlier write-on-change test vacuous.
	actual := decodeActualWithIPs(t,
		`{"results":[{"id":11,"name":"vm-1","vcpus":2,"memory":2048,"disk":20,`+
			`"status":{"value":"active"},"cluster":{"id":5},`+
			`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`,
		`{"results":[{"id":21,"name":"eth0","mac_address":"52:54:00:aa:bb:01",`+
			`"virtual_machine":{"id":11},`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", "52:54:00:aa:bb:01")+`"}}],"next":""}`,
		// The address exists but is assigned to NOTHING — the drift.
		`{"results":[{"id":41,"address":"10.0.5.100/24","assigned_object_id":null,`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", "52:54:00:aa:bb:01")+`"}}],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048, DiskGB: 20, Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01", NetBoxIPID: 41}},
	}}, actual, fp)

	var assign *Action
	for i := range got {
		if got[i].Op == "assign" {
			assign = &got[i]
		}
	}
	if assign == nil {
		t.Fatalf("want an assign action to repair the drift, got %+v", got)
	}
	if assign.NetBoxID != 21 || assign.IPID != 41 {
		t.Fatalf("assign must target iface 21 with address 41, got %+v", *assign)
	}
	// Nothing was assigned before, so there is nothing to clear.
	for _, a := range got {
		if a.Op == "clear" {
			t.Fatalf("no clear expected when the interface held nothing: %+v", a)
		}
	}
}

func TestDiffNeverClearsAnOperatorOwnedAddress(t *testing.T) {
	// DECODED, not hand-built. An empty OwnedIPsByIface would only prove that an
	// empty map yields no clear — it would say nothing about whether BuildActual
	// actually excludes an operator-owned address it decoded.
	actual := decodeActualWithIPs(t,
		`{"results":[{"id":11,"name":"vm-1","status":{"value":"active"},"cluster":{"id":5},`+
			`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`,
		`{"results":[{"id":21,"name":"eth0","mac_address":"52:54:00:aa:bb:01",`+
			`"virtual_machine":{"id":11},`+
			`"custom_fields":{"litevirt_identity":"`+nicIdent("u1", "52:54:00:aa:bb:01")+`"}}],"next":""}`,
		// Assigned to OUR interface, but with no litevirt identity: an operator's.
		`{"results":[{"id":77,"address":"10.0.5.77/24","assigned_object_id":21,`+
			`"custom_fields":{}}],"next":""}`)

	if len(actual.OwnedIPsByIface[21]) != 0 {
		t.Fatalf("BuildActual must not admit an operator-owned address, got %+v", actual.OwnedIPsByIface[21])
	}
	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01", NetBoxIPID: 41}},
	}}, actual, fp)

	for _, a := range got {
		if a.Op == "clear" {
			t.Fatalf("an operator-owned address must never be cleared: %+v", a)
		}
	}
}

func TestDiffAssignmentIsOrderIndependent(t *testing.T) {
	// A NetBox interface can hold several addresses. Picking ips[0] made the
	// action set depend on API ordering: [desired, stale] looked correct and
	// left the stale one forever, [stale, desired] emitted a needless clear.
	desired := []DesiredVM{{
		Name: "vm-1", UUID: "u1", Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01", NetBoxIPID: 41}},
	}}
	base := func(ips []netbox.IPAddress) Actual {
		return Actual{
			VMs:             map[string]netbox.VirtualMachine{vmIdent("u1"): {ID: 11, Name: "vm-1", Status: "active"}},
			NICs:            map[string]netbox.VMInterface{nicIdent("u1", "52:54:00:aa:bb:01"): {ID: 21, Name: "eth0", MAC: "52:54:00:aa:bb:01"}},
			OwnedIPsByIface: map[int][]netbox.IPAddress{21: ips},
		}
	}
	forward := Diff(desired, base([]netbox.IPAddress{{ID: 41}, {ID: 42}}), fp)
	reverse := Diff(desired, base([]netbox.IPAddress{{ID: 42}, {ID: 41}}), fp)

	summarise := func(as []Action) []string {
		var out []string
		for _, a := range as {
			if a.Op == "assign" || a.Op == "clear" {
				out = append(out, fmt.Sprintf("%s:%d", a.Op, a.IPID))
			}
		}
		return out
	}
	f, rv := summarise(forward), summarise(reverse)
	if !reflect.DeepEqual(f, rv) {
		t.Fatalf("action set depends on API ordering: %v vs %v", f, rv)
	}
	// The desired address is already present, so only the stale one is cleared.
	if len(f) != 1 || f[0] != "clear:42" {
		t.Fatalf("want exactly clear:42, got %v", f)
	}
}

func TestDiffNeverDeletesAnotherClustersVM(t *testing.T) {
	// Same VM NAME, different cluster fingerprint. A name-keyed diff would emit
	// a delete here and destroy the other cluster's inventory.
	other := netbox.Identity("otherfp", "u9", "")
	got := Diff([]DesiredVM{{Name: "vm-1", UUID: "u1", Status: "active"}},
		Actual{VMs: map[string]netbox.VirtualMachine{
			vmIdent("u1"): {ID: 11, Name: "vm-1", Status: "active"},
			other:         {ID: 99, Name: "vm-1"},
		}}, fp)

	for _, a := range got {
		if a.Op == "delete" && a.Key == other {
			t.Fatal("diff deleted another cluster's VM")
		}
		// Identity-keying is also what makes OUR lookup hit at all. Keyed by
		// name, the desired VM would miss its own actual object — both entries
		// are named vm-1 — and the sweep would re-create it and then delete it
		// as unseen on the very same pass.
		if a.Key == vmIdent("u1") {
			t.Fatalf("our VM already matches its actual object, so no action is due: %+v", a)
		}
	}
}

func TestActualStateDiscardsForeignIdentities(t *testing.T) {
	// The first of two independent guards: BuildActual must not even ADMIT
	// another cluster's objects. Diff's fingerprint filter is the second.
	actual := decodeActualFixture(t, `{"results":[`+
		`{"id":11,"name":"vm-1","status":{"value":"active"},"cluster":{"id":5},`+
		`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}},`+
		`{"id":99,"name":"vm-1","status":{"value":"active"},"cluster":{"id":5},`+
		`"custom_fields":{"litevirt_identity":"`+netbox.Identity("otherfp", "u9", "")+`"}}`+
		`],"next":""}`)

	if len(actual.VMs) != 1 {
		t.Fatalf("BuildActual must discard foreign identities, got %d: %+v", len(actual.VMs), actual.VMs)
	}
	if _, ok := actual.VMs[vmIdent("u1")]; !ok {
		t.Fatalf("BuildActual kept the wrong VM: %+v", actual.VMs)
	}
}

func TestDiffDerivesParentFromActualWhenMappingIsLost(t *testing.T) {
	// The VM already exists in NetBox and matches, so Diff emits NO vm action —
	// nothing this sweep records its NetBox id. If the local netbox_objects row
	// was also lost, phase ordering gives the applier nothing to look up and a
	// nic/create has no parent to be created under. Reading the parent from
	// ACTUAL state is the only thing that closes that hole.
	actual := decodeActualWithIPs(t,
		`{"results":[{"id":11,"name":"vm-1","vcpus":2,"memory":2048,"disk":20,`+
			`"status":{"value":"active"},"cluster":{"id":5},`+
			`"custom_fields":{"litevirt_identity":"`+vmIdent("u1")+`"}}],"next":""}`,
		// No interfaces at all: the NIC must be created.
		`{"results":[],"next":""}`,
		`{"results":[],"next":""}`)

	got := Diff([]DesiredVM{{
		Name: "vm-1", UUID: "u1", VCPUs: 2, MemoryMB: 2048, DiskGB: 20, Status: "active",
		NICs: []DesiredNIC{{Name: "eth0", MAC: "52:54:00:aa:bb:01"}},
	}}, actual, fp)

	if len(got) != 1 || got[0].Kind != "nic" || got[0].Op != "create" {
		t.Fatalf("want exactly one nic/create, got %+v", got)
	}
	if got[0].ParentNetBoxID != 11 {
		t.Fatalf("nic/create must carry the owning VM's NetBox id from actual state, got %+v", got[0])
	}
}

// --- helpers ---------------------------------------------------------------

// decodeActualFixture builds Actual from a VM-list payload alone.
func decodeActualFixture(t *testing.T, vmsJSON string) Actual {
	t.Helper()
	return decodeActualWithIPs(t, vmsJSON, `{"results":[],"next":""}`, `{"results":[],"next":""}`)
}

// decodeActualWithIPs builds Actual from the three payloads BuildActual reads,
// using the production decoders rather than hand-built structs.
func decodeActualWithIPs(t *testing.T, vmsJSON, ifacesJSON, ipsJSON string) Actual {
	t.Helper()
	c := netboxClientServing(t, map[string]string{
		"/api/virtualization/virtual-machines/": vmsJSON,
		"/api/virtualization/interfaces/":       ifacesJSON,
		"/api/ipam/ip-addresses/":               ipsJSON,
	})
	actual, err := BuildActual(context.Background(), c, 5, fp)
	if err != nil {
		t.Fatal(err)
	}
	return actual
}

// allowedQuery lists, per endpoint, the query parameters a real NetBox
// implements.
//
// A fake that ignored an unrecognised parameter would let a query like
// virtual_machine_cluster_id — which NetBox does not implement — pass here while
// silently losing its scope against a real server, handing the sweep every
// litevirt object in the install. The same rule applies to the fleet fake.
var allowedQuery = map[string]map[string]bool{
	"/api/virtualization/virtual-machines/": {"cluster_id": true, "limit": true, "offset": true},
	"/api/virtualization/interfaces/":       {"cluster_id": true, "limit": true, "offset": true},
	"/api/ipam/ip-addresses/": {
		"vminterface_id": true, "limit": true, "offset": true,
		"cf_" + netbox.IdentityField + "__n": true,
	},
}

// netboxClientServing starts an httptest server routing by path and returns a
// REAL *netbox.Client, so every fixture is decoded by the production decoders.
// It rejects an unrecognised query parameter with a 400 naming the ones it knows.
func netboxClientServing(t *testing.T, byPath map[string]string) *netbox.Client {
	t.Helper()
	return netboxClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		body, ok := byPath[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		allowed := allowedQuery[r.URL.Path]
		for k := range r.URL.Query() {
			if !allowed[k] {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"detail":"unknown query parameter %q; recognised: %v"}`,
					k, sortedKeys(allowed))
				return
			}
		}
		_, _ = w.Write([]byte(body))
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// netboxClientFor wires a real client to an arbitrary handler.
func netboxClientFor(t *testing.T, h http.HandlerFunc) *netbox.Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := netbox.New(netbox.Config{BaseURL: srv.URL, TokenPath: tok, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// vmBodyForTest returns the write body the PRODUCTION client sends for a VM,
// captured off the wire from a real UpdateVM rather than reconstructed here.
// Reconstructing it would assert on a copy of the rule instead of on the rule.
func vmBodyForTest(t *testing.T, d DesiredVM) map[string]any {
	t.Helper()
	var got map[string]any
	c := netboxClientFor(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode PATCH body: %v", err)
		}
		_, _ = w.Write([]byte(`{}`))
	})
	if err := c.UpdateVM(context.Background(), 11, netbox.VirtualMachine{
		Name: d.Name, VCPUs: d.VCPUs, MemoryMB: d.MemoryMB,
		DiskGB: d.DiskGB, Status: d.Status, DeviceID: d.DeviceID,
	}); err != nil {
		t.Fatal(err)
	}
	return got
}
