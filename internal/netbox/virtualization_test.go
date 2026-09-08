package netbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// decodeBody JSON-decodes a request body inside a test handler.
func decodeBody(t *testing.T, r *http.Request, out any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
}

func TestCreateVMSendsIdentityCustomField(t *testing.T) {
	var gotIdentity string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/virtualization/virtual-machines/" {
			var body struct {
				CustomFields map[string]string `json:"custom_fields"`
			}
			decodeBody(t, r, &body)
			gotIdentity = body.CustomFields[IdentityField]
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":11,"name":"vm-1","vcpus":2,"memory":2048}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	got, err := c.CreateVM(context.Background(), VirtualMachine{
		Name: "vm-1", ClusterID: 5, VCPUs: 2, MemoryMB: 2048,
		Identity: "lv:fp:uuid",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 11 {
		t.Fatalf("VM id = %d, want 11", got.ID)
	}
	// Without the identity field the orphan sweep cannot reclaim an object whose
	// local mapping was lost.
	if gotIdentity != "lv:fp:uuid" {
		t.Fatalf("identity custom field = %q, want lv:fp:uuid", gotIdentity)
	}
}

func TestFindInterfaceByIdentity(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query().Get("cf_" + IdentityField); q != "lv:fp:uuid:52:54:00:aa:bb:cc" {
			t.Errorf("query = %q", q)
		}
		_, _ = w.Write([]byte(`{"results":[{"id":21,"name":"eth0","mac_address":"52:54:00:AA:BB:CC","virtual_machine":{"id":11}}]}`))
	})
	got, err := c.FindInterfaceByIdentity(context.Background(), "lv:fp:uuid:52:54:00:aa:bb:cc")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != 21 || got[0].VMID != 11 {
		t.Fatalf("got %+v", got)
	}
}

func TestToVMPopulatesEveryComparedField(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Every number in the fixture differs from every other one, so no
		// assertion can pass by reading a neighbouring field's value.
		_, _ = w.Write([]byte(`{"results":[{"id":11,"name":"vm-1","vcpus":3,"memory":2049,"disk":41,` +
			`"status":{"value":"active"},"cluster":{"id":5},"device":{"id":9},` +
			`"custom_fields":{"litevirt_identity":"lv:fp:uuid"}}],"next":""}`))
	})
	got, err := c.ListVMsByCluster(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d VMs, want 1", len(got))
	}
	v := got[0]
	// EVERY field the diff compares must survive decoding, not just the nullable
	// objects: a decoder that drops VCPUs, MemoryMB, DiskMB or Name makes every
	// VM look changed on every sweep, defeating write-on-change exactly as
	// completely as dropping Status does. So all of them are pinned here.
	if v.ID != 11 {
		t.Errorf("ID = %d, want 11", v.ID)
	}
	if v.Name != "vm-1" {
		t.Errorf("Name = %q, want vm-1", v.Name)
	}
	if v.VCPUs != 3 {
		t.Errorf("VCPUs = %v, want 3", v.VCPUs)
	}
	if v.MemoryMB != 2049 {
		t.Errorf("MemoryMB = %d, want 2049", v.MemoryMB)
	}
	if v.DiskMB != 41 {
		t.Errorf("DiskMB = %d, want 41", v.DiskMB)
	}
	if v.Status != "active" {
		t.Errorf("Status = %q, want active", v.Status)
	}
	if v.ClusterID != 5 {
		t.Errorf("ClusterID = %d, want 5", v.ClusterID)
	}
	if v.DeviceID != 9 {
		t.Errorf("DeviceID = %d, want 9", v.DeviceID)
	}
	if v.Identity != "lv:fp:uuid" {
		t.Errorf("Identity = %q, want lv:fp:uuid", v.Identity)
	}
}

func TestListOwnedIPsForInterfacesBatchesAndPaginates(t *testing.T) {
	var reqs []url.Values
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		reqs = append(reqs, q)

		// NetBox has no cluster filter on addresses. Rejecting unknown
		// parameters here is what stops a query like virtual_machine_cluster_id
		// from passing locally while silently losing its scope against a real
		// server.
		allowed := map[string]bool{
			"vminterface_id": true, "limit": true, "offset": true,
			"cf_" + IdentityField + "__n": true,
		}
		for k := range q {
			if !allowed[k] {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"detail":"unknown query parameter ` + k + `"}`))
				return
			}
		}
		// One extra page inside the first batch.
		if q.Get("offset") == "" || q.Get("offset") == "0" {
			if len(q["vminterface_id"]) == 50 {
				_, _ = w.Write([]byte(`{"results":[{"id":41,"address":"10.0.5.100/24","assigned_object_id":1}],"next":"more"}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{"results":[],"next":""}`))
	})

	ids := make([]int, 51)
	for i := range ids {
		ids[i] = i + 1
	}
	got, err := c.ListOwnedIPsForInterfaces(context.Background(), ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].AssignedObjectID != 1 {
		t.Fatalf("got %+v", got)
	}

	// 51 ids at 50 per batch = two batches, and the first batch pages twice.
	var batches, pages int
	for _, q := range reqs {
		pages++
		if q.Get("offset") == "" || q.Get("offset") == "0" {
			batches++
		}
		if len(q["vminterface_id"]) == 0 {
			t.Error("every request must scope by vminterface_id")
		}
		// The identity filter is the sole structural barrier keeping an
		// operator-owned address out of the mirror's clear path, so it must ride
		// on EVERY request, not just the first batch's first page.
		k := "cf_" + IdentityField + "__n"
		if !q.Has(k) || q.Get(k) != "" {
			t.Errorf("request must carry %s= (non-empty identity), got %q", k, q[k])
		}
	}
	if batches != 2 {
		t.Errorf("51 ids must produce 2 batches, got %d", batches)
	}
	if pages < 3 {
		t.Errorf("the first batch must paginate, got %d requests total", pages)
	}
}

// TestListOwnedIPsForInterfacesFiltersToLitevirtIdentities pins the identity
// filter by BEHAVIOUR rather than by query-string shape. The fake serves an
// operator-owned address alongside a litevirt one whenever the filter is absent,
// which is what a real NetBox does: the filter is the only thing that hides it.
// Losing it hands the reconciler an address it would take for ours and could
// detach from the operator's interface.
func TestListOwnedIPsForInterfacesFiltersToLitevirtIdentities(t *testing.T) {
	const ours = `{"id":41,"address":"10.0.5.100/24","assigned_object_id":1,` +
		`"custom_fields":{"litevirt_identity":"lv:fp:uuid"}}`
	const operators = `{"id":42,"address":"10.0.5.101/24","assigned_object_id":1,` +
		`"custom_fields":{"litevirt_identity":null}}`
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// NetBox reads cf_<field>__n= as "custom field not equal to empty", so
		// with the filter present only identity-carrying addresses come back.
		k := "cf_" + IdentityField + "__n"
		if q.Has(k) && q.Get(k) == "" {
			_, _ = w.Write([]byte(`{"results":[` + ours + `],"next":""}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[` + ours + `,` + operators + `],"next":""}`))
	})
	got, err := c.ListOwnedIPsForInterfaces(context.Background(), []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range got {
		if ip.Identity == "" {
			t.Fatalf("operator-owned address %d (%s) reached the caller: the mirror "+
				"would treat it as litevirt-owned and could detach it", ip.ID, ip.Address)
		}
	}
	if len(got) != 1 || got[0].ID != 41 {
		t.Fatalf("got %+v, want only the litevirt-owned address 41", got)
	}
}

func TestUnknownQueryParameterIsRejected(t *testing.T) {
	// Guards the guard: if the fake silently ignored an unknown parameter, the
	// batching test above could not detect a filter NetBox does not implement.
	//
	// The test is in package netbox, so it calls the unexported do() directly.
	// Adding an exported wrapper purely so a test can reach it would put
	// test-only surface into the production client.
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("virtual_machine_cluster_id") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"results":[],"next":""}`))
	})
	var out struct {
		Results []ipJSON `json:"results"`
	}
	err := c.do(context.Background(), http.MethodGet,
		"/api/ipam/ip-addresses/?virtual_machine_cluster_id=5", nil, &out)
	if err == nil {
		t.Fatal("an unknown filter must be rejected, not silently ignored")
	}
	if Classify(err) != ClassClient {
		t.Fatalf("a rejected filter is a 4xx, got class %v", Classify(err))
	}
}

func TestFindDeviceByNameReturnsZeroWhenAbsent(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[]}`))
	})
	// A host that is not modelled as a DCIM device must NOT be an error — the
	// host link is best-effort, and requiring it would break the whole mirror
	// for operators who do not model hosts in NetBox.
	id, err := c.FindDeviceByName(context.Background(), "some-host")
	if err != nil {
		t.Fatalf("an absent device must not error, got %v", err)
	}
	if id != 0 {
		t.Fatalf("id = %d, want 0", id)
	}
}

// TestUpdateVMSendsDeviceExplicitlyWhenAbsent pins the one thing an omitted key
// would break silently: a PATCH that leaves out "device" cannot CLEAR a stale
// host link, so the diff keeps seeing a device the VM no longer sits on and
// re-emits the same update on every sweep.
func TestUpdateVMSendsDeviceExplicitlyWhenAbsent(t *testing.T) {
	var body map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/virtualization/virtual-machines/11/" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		decodeBody(t, r, &body)
		_, _ = w.Write([]byte(`{"id":11}`))
	})
	err := c.UpdateVM(context.Background(), 11, VirtualMachine{
		Name: "vm-1", ClusterID: 5, VCPUs: 2, MemoryMB: 2048, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	v, ok := body["device"]
	if !ok {
		t.Fatal("device must be sent explicitly, even when absent — omitting the key leaves a stale link")
	}
	if v != nil {
		t.Fatalf("device = %v, want null", v)
	}
}

// TestListInterfacesByClusterPaginatesAndLowercasesMAC covers both halves of the
// interface list: a truncated walk would make live interfaces look deleted, and
// a MAC left in NetBox's uppercase form would never match the lower-cased MAC
// the identity is built from.
func TestListInterfacesByClusterPaginatesAndLowercasesMAC(t *testing.T) {
	var reqs []url.Values
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r.URL.Query())
		if len(reqs) == 1 {
			_, _ = w.Write([]byte(`{"results":[{"id":21,"name":"eth0","mac_address":"52:54:00:AA:BB:CC",` +
				`"virtual_machine":{"id":11},"custom_fields":{"litevirt_identity":"lv:fp:uuid:52:54:00:aa:bb:cc"}}],` +
				`"next":"http://x/api/virtualization/interfaces/?limit=200&offset=1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"id":22,"name":"eth1","mac_address":"52:54:00:dd:ee:ff",` +
			`"virtual_machine":{"id":11}}],"next":""}`))
	})
	got, err := c.ListInterfacesByCluster(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("want 2 requests (the walk must follow next), got %d", len(reqs))
	}
	if q := reqs[0].Get("cluster_id"); q != "5" {
		t.Errorf("cluster_id = %q, want 5", q)
	}
	if len(got) != 2 || got[0].ID != 21 || got[1].ID != 22 {
		t.Fatalf("got %+v, want ids [21 22]", got)
	}
	if got[0].MAC != "52:54:00:aa:bb:cc" {
		t.Errorf("MAC = %q, want it lower-cased to match the identity", got[0].MAC)
	}
	if got[0].VMID != 11 {
		t.Errorf("VMID = %d, want 11", got[0].VMID)
	}
	if got[0].Identity != "lv:fp:uuid:52:54:00:aa:bb:cc" {
		t.Errorf("Identity = %q", got[0].Identity)
	}
}

func TestEnsureClusterReusesExisting(t *testing.T) {
	posts := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":99}`))
			return
		}
		if r.URL.Path != "/api/virtualization/clusters/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("name"); got != "lab" {
			t.Errorf("name filter = %q, want lab", got)
		}
		_, _ = w.Write([]byte(`{"results":[{"id":5,"name":"lab"}]}`))
	})
	id, err := c.EnsureCluster(context.Background(), "lab", 2)
	if err != nil {
		t.Fatal(err)
	}
	if id != 5 {
		t.Fatalf("id = %d, want the existing 5", id)
	}
	// A second cluster with the same name would split the mirror in two.
	if posts != 0 {
		t.Fatalf("an existing cluster must be reused, got %d create(s)", posts)
	}
}

func TestEnsureClusterTypeCreatesWhenAbsent(t *testing.T) {
	var body map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/virtualization/cluster-types/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Method == http.MethodPost {
			decodeBody(t, r, &body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":7}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[]}`))
	})
	id, err := c.EnsureClusterType(context.Background(), "litevirt")
	if err != nil {
		t.Fatal(err)
	}
	if id != 7 {
		t.Fatalf("id = %d, want 7", id)
	}
	if body["name"] != "litevirt" {
		t.Errorf("name = %v", body["name"])
	}
	// NetBox requires a slug on create and will not derive one for the API.
	if body["slug"] != "litevirt" {
		t.Errorf("slug = %v, want litevirt", body["slug"])
	}
}

func TestAssignAndClearIPAssignment(t *testing.T) {
	var bodies []map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/api/ipam/ip-addresses/41/" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		var b map[string]any
		decodeBody(t, r, &b)
		bodies = append(bodies, b)
		_, _ = w.Write([]byte(`{"id":41}`))
	})
	if err := c.AssignIPToInterface(context.Background(), 41, 21); err != nil {
		t.Fatal(err)
	}
	if err := c.ClearIPAssignment(context.Background(), 41); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 2 {
		t.Fatalf("want 2 PATCHes, got %d", len(bodies))
	}
	if bodies[0]["assigned_object_type"] != "virtualization.vminterface" {
		t.Errorf("assigned_object_type = %v", bodies[0]["assigned_object_type"])
	}
	if bodies[0]["assigned_object_id"] != float64(21) {
		t.Errorf("assigned_object_id = %v, want 21", bodies[0]["assigned_object_id"])
	}
	// Clearing needs EXPLICIT nulls on both halves: an omitted key is a no-op
	// PATCH, so the address would stay attached to a VM that no longer exists.
	for _, k := range []string{"assigned_object_type", "assigned_object_id"} {
		v, ok := bodies[1][k]
		if !ok {
			t.Errorf("clear must send %s explicitly", k)
			continue
		}
		if v != nil {
			t.Errorf("clear sent %s = %v, want null", k, v)
		}
	}
}

// TestSetVMIdentityAndSetInterfaceIdentity pins the CA re-key's INVENTORY wire
// shape, the counterpart of TestSetIPIdentity.
//
// Every part is load-bearing in the same way. PATCH, not PUT: NetBox's PUT is a
// full replace, so an omitted `name` or `cluster` would be blanked and a re-key
// would destroy the objects it exists to preserve. The id-scoped path is what
// makes this an update rather than a create. And a body carrying anything
// besides the custom field would let a re-key silently rename a VM or move it
// between clusters.
func TestSetVMIdentityAndSetInterfaceIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		call func(*Client) error
	}{
		{
			name: "vm",
			path: "/api/virtualization/virtual-machines/11/",
			call: func(c *Client) error {
				return c.SetVMIdentity(context.Background(), 11, "lv:new:uuid:")
			},
		},
		{
			name: "interface",
			path: "/api/virtualization/interfaces/21/",
			call: func(c *Client) error {
				return c.SetInterfaceIdentity(context.Background(), 21, "lv:new:uuid:aa:bb")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod, gotPath string
			var gotBody map[string]any
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				gotMethod, gotPath = r.Method, r.URL.Path
				decodeBody(t, r, &gotBody)
				_, _ = w.Write([]byte(`{"id":11}`))
			})
			if err := tc.call(c); err != nil {
				t.Fatal(err)
			}
			if gotMethod != http.MethodPatch {
				t.Errorf("method = %q, want PATCH — a PUT would blank every omitted field", gotMethod)
			}
			if gotPath != tc.path {
				t.Errorf("path = %q, want the id-scoped %s path", gotPath, tc.name)
			}
			if len(gotBody) != 1 {
				t.Fatalf("body = %v, want ONLY custom_fields — anything else can rename or "+
					"re-parent a live object", gotBody)
			}
			cf, ok := gotBody["custom_fields"].(map[string]any)
			if !ok {
				t.Fatalf("body = %v, want a custom_fields object", gotBody)
			}
			if cf[IdentityField] == "" || cf[IdentityField] == nil {
				t.Fatalf("custom_fields = %v, want %s set to the new identity", cf, IdentityField)
			}
		})
	}
}

// TestSetInventoryIdentityPropagatesFailure pins that a refused PATCH is an
// ERROR the caller sees. A re-key that swallowed one failed rewrite would resume
// the binding with objects still carrying the old fingerprint — unfindable by
// identity, and duplicated by the next sweep.
func TestSetInventoryIdentityPropagatesFailure(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"no write permission"}`))
	})
	if err := c.SetVMIdentity(context.Background(), 11, "lv:new:uuid:"); err == nil {
		t.Error("a refused VM PATCH must be an error")
	} else if Classify(err) != ClassClient {
		t.Errorf("Classify = %v, want ClassClient", Classify(err))
	}
	if err := c.SetInterfaceIdentity(context.Background(), 21, "lv:new:uuid:aa:bb"); err == nil {
		t.Error("a refused interface PATCH must be an error")
	}
}

// TestFindCluster resolves a cluster id by name WITHOUT creating one.
//
// EnsureCluster would do, and is wrong here: the CA re-key must not bring a
// NetBox object into existence as a side effect of asking what inventory this
// cluster owns. An absent cluster resolves to 0 — there is then no inventory to
// re-key — rather than to an error.
func TestFindCluster(t *testing.T) {
	var gotQuery url.Values
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET — a lookup must never create", r.Method)
		}
		if r.URL.Path != "/api/virtualization/clusters/" {
			t.Errorf("path = %q, want the clusters collection", r.URL.Path)
		}
		gotQuery = r.URL.Query()
		if gotQuery.Get("name") == "absent" {
			_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"count":1,"results":[{"id":9}]}`))
	})
	got, err := c.FindCluster(context.Background(), "a-cluster")
	if err != nil {
		t.Fatal(err)
	}
	if got != 9 {
		t.Fatalf("FindCluster = %d, want 9", got)
	}
	if gotQuery.Get("name") != "a-cluster" {
		t.Errorf("name filter = %q, want the exact cluster name", gotQuery.Get("name"))
	}
	absent, err := c.FindCluster(context.Background(), "absent")
	if err != nil {
		t.Fatalf("an absent cluster must not be an error: %v", err)
	}
	if absent != 0 {
		t.Fatalf("FindCluster on an absent cluster = %d, want 0", absent)
	}
}
