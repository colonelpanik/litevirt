package netbox

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// NetBox 4.2 moved the MAC off the interface: `vminterface.mac_address` became
// READ-ONLY, and a MAC is now a `dcim.MACAddress` object assigned to the
// interface and pointed at by `primary_mac_address`. A server on that shape
// accepts an interface POST carrying `mac_address` with a 201 and SILENTLY
// IGNORES the field, so the write looks like it worked and the object has no
// MAC.
//
// That silence is what makes it worth a test. The mirror's nicDiffers compares
// the desired MAC against the one NetBox reports, so an ignored write does not
// merely lose a field: every sweep sees the MAC missing, emits an update, and
// the update is ignored in turn — one PATCH per NIC per sweep, forever, against
// a mirror that can never converge.
//
// These handlers reproduce a 4.2+ server: `mac_address` is dropped on write and
// reported from the assigned MACAddress object on read.
func netbox42Handler(t *testing.T) (http.HandlerFunc, func() []string) {
	t.Helper()
	var (
		writes    []string // every path written, in order, for the assertions below
		macByID   = map[int]string{}
		primaryOf = map[int]int{}
		nextMAC   = 700
	)
	h := func(w http.ResponseWriter, r *http.Request) {
		switch {
		// Interface create: accept, and DROP mac_address the way 4.2+ does.
		case r.Method == http.MethodPost && r.URL.Path == "/api/virtualization/interfaces/":
			writes = append(writes, "POST "+r.URL.Path)
			var body struct {
				Name string `json:"name"`
			}
			decodeBody(t, r, &body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":42,"name":"` + body.Name +
				`","mac_address":null,"virtual_machine":{"id":11}}`))

		// The idempotent read. NetBox permits duplicate MACAddress objects, so
		// the client is expected to look before it creates; this returns nothing
		// the first time and the created object afterwards.
		case r.Method == http.MethodGet && r.URL.Path == "/api/dcim/mac-addresses/":
			q := r.URL.Query()
			if q.Get("assigned_object_type") != "virtualization.vminterface" {
				t.Errorf("MAC lookup assigned_object_type = %q", q.Get("assigned_object_type"))
			}
			var hits []string
			for id, m := range macByID {
				if strings.EqualFold(m, q.Get("mac_address")) && q.Get("assigned_object_id") == "42" {
					hits = append(hits, `{"id":`+itoa(id)+`}`)
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"results":[` + strings.Join(hits, ",") + `],"next":null}`))

		// A MACAddress object, assigned to the interface that asked for it.
		case r.Method == http.MethodPost && r.URL.Path == "/api/dcim/mac-addresses/":
			writes = append(writes, "POST "+r.URL.Path)
			var body struct {
				MAC              string `json:"mac_address"`
				AssignedType     string `json:"assigned_object_type"`
				AssignedObjectID int    `json:"assigned_object_id"`
			}
			decodeBody(t, r, &body)
			if body.AssignedType != "virtualization.vminterface" {
				t.Errorf("assigned_object_type = %q, want virtualization.vminterface", body.AssignedType)
			}
			if body.AssignedObjectID == 0 {
				t.Error("MACAddress was created unassigned; it would belong to no interface")
			}
			nextMAC++
			macByID[nextMAC] = strings.ToUpper(body.MAC)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":` + itoa(nextMAC) + `,"mac_address":"` +
				strings.ToUpper(body.MAC) + `"}`))

		// primary_mac_address is the writable field. mac_address may be sent —
		// that is how a pre-4.2 server is addressed — and is simply dropped, so
		// the response reports whatever the assigned MACAddress object says.
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/virtualization/interfaces/"):
			writes = append(writes, "PATCH "+r.URL.Path)
			var body struct {
				PrimaryMAC *int `json:"primary_mac_address"`
			}
			decodeBody(t, r, &body)
			if body.PrimaryMAC != nil {
				primaryOf[42] = *body.PrimaryMAC
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":42,"name":"eth0","mac_address":` +
				quoteOrNull(macOfPrimary(primaryOf[42], macByID)) +
				`,"virtual_machine":{"id":11}}`))

		// Read-back: the MAC comes from the interface's primary MACAddress.
		case r.Method == http.MethodGet && r.URL.Path == "/api/virtualization/interfaces/":
			mac := macOfPrimary(primaryOf[42], macByID)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"results":[{"id":42,"name":"eth0","mac_address":` +
				quoteOrNull(mac) + `,"virtual_machine":{"id":11},` +
				`"custom_fields":{"litevirt_identity":"lv:fp:uuid:52:54:00:aa:bb:01"}}],"next":null}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
	return h, func() []string { return writes }
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return string(b)
}

// macOfPrimary is what NetBox reports in the read-only mac_address field: the
// address of the MACAddress object the interface names as primary.
func macOfPrimary(primaryID int, macByID map[int]string) string {
	if primaryID == 0 {
		return ""
	}
	return macByID[primaryID]
}

func quoteOrNull(s string) string {
	if s == "" {
		return "null"
	}
	return `"` + s + `"`
}

// A created interface must end up CARRYING the MAC on a server where
// mac_address is read-only — not merely have been sent one.
func TestCreateInterfaceMakesTheMACStickWhenMACAddressIsReadOnly(t *testing.T) {
	h, _ := netbox42Handler(t)
	c := testClient(t, h)

	if _, err := c.CreateInterface(context.Background(), VMInterface{
		VMID: 11, Name: "eth0", MAC: "52:54:00:aa:bb:01",
		Identity: "lv:fp:uuid:52:54:00:aa:bb:01",
	}); err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}

	// Read it back the way the mirror's diff does. This is the assertion that
	// fails when the MAC write is silently dropped.
	ifs, err := c.ListInterfacesByCluster(context.Background(), 5)
	if err != nil {
		t.Fatalf("ListInterfacesByCluster: %v", err)
	}
	if len(ifs) != 1 {
		t.Fatalf("interfaces = %d, want 1", len(ifs))
	}
	if ifs[0].MAC != "52:54:00:aa:bb:01" {
		t.Fatalf("MAC read back = %q, want %q — NetBox never recorded the MAC, so "+
			"every mirror sweep will emit an update that changes nothing",
			ifs[0].MAC, "52:54:00:aa:bb:01")
	}
}

// The same for the repair path: UpdateInterface is what the mirror calls once it
// has noticed a MAC missing, so if it too cannot make the MAC stick the sweep
// never converges.
func TestUpdateInterfaceMakesTheMACStickWhenMACAddressIsReadOnly(t *testing.T) {
	h, _ := netbox42Handler(t)
	c := testClient(t, h)

	if err := c.UpdateInterface(context.Background(), 42, VMInterface{
		VMID: 11, Name: "eth0", MAC: "52:54:00:aa:bb:01",
	}); err != nil {
		t.Fatalf("UpdateInterface: %v", err)
	}

	ifs, err := c.ListInterfacesByCluster(context.Background(), 5)
	if err != nil {
		t.Fatalf("ListInterfacesByCluster: %v", err)
	}
	if len(ifs) != 1 || ifs[0].MAC != "52:54:00:aa:bb:01" {
		t.Fatalf("MAC after update = %q, want %q", ifs[0].MAC, "52:54:00:aa:bb:01")
	}
}

// NetBox permits SEVERAL MACAddress objects carrying the same address, so a
// repair that only ever created would add one more every time it ran again.
//
// It does run again: the repair is two writes, and if the second — pointing the
// interface at the object — is lost, the MACAddress is already there when the
// next sweep retries. A retry that creates rather than adopts leaves a duplicate
// behind on every pass, and they accumulate for as long as the second write
// keeps failing.
func TestRepairedMACIsAdoptedOnRetryRatherThanDuplicated(t *testing.T) {
	var (
		macPosts  int
		failPatch = true
		primary   int
		macByID   = map[int]string{}
		nextMAC   = 700
	)
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/api/virtualization/interfaces/"):
			var body struct {
				PrimaryMAC *int `json:"primary_mac_address"`
			}
			decodeBody(t, r, &body)
			if body.PrimaryMAC != nil {
				// The write that gets lost the first time round.
				if failPatch {
					failPatch = false
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"detail":"boom"}`))
					return
				}
				primary = *body.PrimaryMAC
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":42,"name":"eth0","mac_address":` +
				quoteOrNull(macOfPrimary(primary, macByID)) + `,"virtual_machine":{"id":11}}`))

		case r.Method == http.MethodGet && r.URL.Path == "/api/dcim/mac-addresses/":
			q := r.URL.Query()
			var hits []string
			for id, m := range macByID {
				if strings.EqualFold(m, q.Get("mac_address")) && q.Get("assigned_object_id") == "42" {
					hits = append(hits, `{"id":`+itoa(id)+`}`)
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"results":[` + strings.Join(hits, ",") + `],"next":null}`))

		case r.Method == http.MethodPost && r.URL.Path == "/api/dcim/mac-addresses/":
			macPosts++
			var body struct {
				MAC string `json:"mac_address"`
			}
			decodeBody(t, r, &body)
			nextMAC++
			macByID[nextMAC] = strings.ToUpper(body.MAC)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":` + itoa(nextMAC) + `,"mac_address":"` +
				strings.ToUpper(body.MAC) + `"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	upd := VMInterface{VMID: 11, Name: "eth0", MAC: "52:54:00:aa:bb:01"}
	// First pass: the MACAddress is created, then the pointer write is lost.
	if err := c.UpdateInterface(context.Background(), 42, upd); err == nil {
		t.Fatal("UpdateInterface reported success though the primary MAC write failed")
	}
	// Second pass: the object is already there and must be reused.
	if err := c.UpdateInterface(context.Background(), 42, upd); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if macPosts != 1 {
		t.Fatalf("created %d MACAddress objects across the retry, want 1 — "+
			"NetBox allows duplicates, so each retry would leave another behind", macPosts)
	}
	if primary == 0 {
		t.Fatal("the retry never pointed the interface at the MAC it adopted")
	}
}

// On a pre-4.2 server `mac_address` IS writable, and the MACAddress collection
// does not exist — a request to it 404s. The client must not need it there.
func TestCreateInterfaceUsesTheWritableMACFieldOnOlderNetBox(t *testing.T) {
	var hitMACCollection bool
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/virtualization/interfaces/":
			var body struct {
				MAC string `json:"mac_address"`
			}
			decodeBody(t, r, &body)
			// Pre-4.2 honours the field, and echoes it upper-cased.
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":42,"name":"eth0","mac_address":"` +
				strings.ToUpper(body.MAC) + `","virtual_machine":{"id":11}}`))
		case strings.HasPrefix(r.URL.Path, "/api/dcim/mac-addresses/"):
			hitMACCollection = true
			w.WriteHeader(http.StatusNotFound) // the collection does not exist here
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	got, err := c.CreateInterface(context.Background(), VMInterface{
		VMID: 11, Name: "eth0", MAC: "52:54:00:aa:bb:01",
	})
	if err != nil {
		t.Fatalf("CreateInterface: %v", err)
	}
	if got.MAC != "52:54:00:aa:bb:01" {
		t.Fatalf("MAC = %q, want the lower-cased 52:54:00:aa:bb:01", got.MAC)
	}
	if hitMACCollection {
		t.Error("touched /dcim/mac-addresses/ on a server that honoured mac_address; " +
			"the extra round trip is not needed and 404s on pre-4.2")
	}
}
