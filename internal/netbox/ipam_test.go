package netbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestListDecodesAllFields proves toIP() actually populates VRFID, Identity,
// and AssignedObjectID from the raw JSON — not just ID/Address, which every
// other fixture in this file happens to leave at their zero values too, so a
// deleted assignment in toIP() would still let those tests pass.
func TestListDecodesAllFields(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"id":41,"address":"10.0.5.100/24","vrf":{"id":3},"assigned_object_id":99,"custom_fields":{"litevirt_identity":"lv:abc:uuid:aa:bb"}}],"next":""}`))
	})
	got, err := c.LookupByAddress(context.Background(), "10.0.5.100/24", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	ip := got[0]
	if ip.VRFID != 3 {
		t.Errorf("VRFID = %d, want 3", ip.VRFID)
	}
	if ip.Identity != "lv:abc:uuid:aa:bb" {
		t.Errorf("Identity = %q, want lv:abc:uuid:aa:bb", ip.Identity)
	}
	if ip.AssignedObjectID != 99 {
		t.Errorf("AssignedObjectID = %d, want 99", ip.AssignedObjectID)
	}
}

// TestListDecodesNullAssignedObjectAndMissingVRF covers the nullable/absent
// side of the same fields: a null assigned_object_id and a missing vrf key
// must decode to zero values, not panic or leak a stale pointer's value.
func TestListDecodesNullAssignedObjectAndMissingVRF(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"id":41,"address":"10.0.5.100/24","assigned_object_id":null}],"next":""}`))
	})
	got, err := c.LookupByAddress(context.Background(), "10.0.5.100/24", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	ip := got[0]
	if ip.AssignedObjectID != 0 {
		t.Errorf("AssignedObjectID = %d, want 0 for a null assigned_object_id", ip.AssignedObjectID)
	}
	if ip.VRFID != 0 {
		t.Errorf("VRFID = %d, want 0 for a missing vrf", ip.VRFID)
	}
}

// TestListFollowsPagination proves list() actually walks a second page rather
// than stopping at the first: every other fixture in this file returns
// "next":"" on the first page, so a list() that ignored Next entirely would
// still pass them all.
func TestListFollowsPagination(t *testing.T) {
	var reqs []*http.Request
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r)
		if len(reqs) == 1 {
			_, _ = w.Write([]byte(`{"results":[{"id":1,"address":"10.0.5.1/24"}],"next":"http://x/api/ipam/ip-addresses/?limit=200&offset=1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"id":2,"address":"10.0.5.2/24"}],"next":""}`))
	})
	got, err := c.LookupByAddress(context.Background(), "10.0.5.0/24", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("want exactly 2 requests, got %d", len(reqs))
	}
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 2 {
		t.Fatalf("got %+v, want [1 2] in order", got)
	}
	secondOffset := reqs[1].URL.Query().Get("offset")
	if secondOffset != "1" {
		t.Fatalf("second request offset = %q, want %q (first page returned 1 result)", secondOffset, "1")
	}
}

// TestListStopsOnEmptyPageDespiteNext proves the defensive guard in list():
// a page that reports a non-empty Next but zero results must terminate the
// walk rather than loop forever re-requesting the same offset.
func TestListStopsOnEmptyPageDespiteNext(t *testing.T) {
	calls := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 3 {
			t.Fatal("list() did not stop on an empty page — infinite loop guard failed")
		}
		_, _ = w.Write([]byte(`{"results":[],"next":"http://x/api/ipam/ip-addresses/?limit=200&offset=0"}`))
	})
	got, err := c.LookupByAddress(context.Background(), "10.0.5.0/24", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
	if calls != 1 {
		t.Fatalf("want exactly 1 request, got %d", calls)
	}
}

func TestClaimAvailableIP(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/ipam/prefixes/7/available-ips/" {
			t.Errorf("got %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		// A single-object POST gets a single OBJECT back from NetBox, not an
		// array. A fake that returns an array while the client expects one makes
		// both agree with each other and disagree with the real server.
		_, _ = w.Write([]byte(`{"id":41,"address":"10.0.5.100/24","custom_fields":{"litevirt_identity":"lv:abc:uuid:aa:bb"}}`))
	})
	got, err := c.ClaimAvailableIP(context.Background(), 7, "lv:abc:uuid:aa:bb")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 41 || got.Address != "10.0.5.100/24" {
		t.Fatalf("got %+v", got)
	}
}

func TestClaimAvailableIPToleratesArrayShape(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`[{"id":41,"address":"10.0.5.100/24"}]`))
	})
	got, err := c.ClaimAvailableIP(context.Background(), 7, "id")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 41 {
		t.Fatalf("got %+v", got)
	}
}

func TestLookupByIdentityIsScopedToVRFAndPrefix(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("cf_litevirt_identity") != "lv:abc:uuid:aa:bb" {
			t.Errorf("identity query = %q", q.Get("cf_litevirt_identity"))
		}
		// Unscoped, this would adopt an object moved to another VRF or prefix.
		// parent is a CIDR: NetBox parses it as a network, and an id would
		// filter on nonsense.
		if q.Get("vrf_id") != "3" || q.Get("parent") != "10.0.5.0/24" {
			t.Errorf("lookup must be scoped to the bound VRF and prefix CIDR, got %v", q)
		}
		_, _ = w.Write([]byte(`{"results":[{"id":41,"address":"10.0.5.100/24","vrf":{"id":3},"custom_fields":{"litevirt_identity":"lv:abc:uuid:aa:bb"}}]}`))
	})
	got, err := c.LookupByIdentity(context.Background(), "lv:abc:uuid:aa:bb", 3, "10.0.5.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != 41 {
		t.Fatalf("got %+v", got)
	}
}

func TestLookupByAddressScopesToVRF(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("address") != "10.0.5.100/24" || q.Get("vrf_id") != "3" {
			t.Errorf("query = %v", q)
		}
		_, _ = w.Write([]byte(`{"results":[]}`))
	})
	got, err := c.LookupByAddress(context.Background(), "10.0.5.100/24", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestClaimSpecificIPConflictIsClientClass(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"address":["Duplicate IP address"]}`))
	})
	_, err := c.ClaimSpecificIP(context.Background(), "10.0.5.100/24", 3, "lv:abc:uuid:aa:bb")
	if err == nil {
		t.Fatal("want error")
	}
	// ClassClient is the DEFINITE "did not happen" answer — the one class a
	// caller may treat as certain. Every other class leaves the server-side
	// outcome unknown and sends the claim path into identity recovery.
	if Classify(err) != ClassClient {
		t.Fatalf("Classify = %v, want ClassClient", Classify(err))
	}
}

func TestIdentityFormat(t *testing.T) {
	got := Identity("abc123", "550e8400-e29b-41d4-a716-446655440000", "52:54:00:aa:bb:cc")
	want := "lv:abc123:550e8400-e29b-41d4-a716-446655440000:52:54:00:aa:bb:cc"
	if got != want {
		t.Fatalf("Identity = %q, want %q", got, want)
	}
}

// TestSetIPIdentity pins the re-key wire shape: a PATCH at the id-scoped
// ip-address path carrying ONLY the identity custom field.
//
// Every part is load-bearing. A PUT would blank every field the body omits
// (NetBox's PUT is a full replace), so the method is not cosmetic; the id-scoped
// path is what makes this an update rather than a create; and a body that
// carried `address` or `vrf` would let a re-key silently move an address a guest
// is using.
func TestSetIPIdentity(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"id":41,"address":"10.0.5.100/24","custom_fields":{"litevirt_identity":"lv:new:uuid:aa:bb"}}`))
	})
	if err := c.SetIPIdentity(context.Background(), 41, "lv:new:uuid:aa:bb"); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q, want PATCH — a PUT would blank every omitted field", gotMethod)
	}
	if gotPath != "/api/ipam/ip-addresses/41/" {
		t.Errorf("path = %q, want the id-scoped ip-address path", gotPath)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("body %q is not JSON: %v", gotBody, err)
	}
	if len(body) != 1 {
		t.Fatalf("body = %v, want ONLY custom_fields — anything else can move a live address", body)
	}
	cf, ok := body["custom_fields"].(map[string]any)
	if !ok {
		t.Fatalf("body = %v, want a custom_fields object", body)
	}
	if cf[IdentityField] != "lv:new:uuid:aa:bb" {
		t.Fatalf("custom_fields = %v, want %s set to the new identity", cf, IdentityField)
	}
}

// TestSetIPIdentityPropagatesFailure pins that a refused PATCH is an ERROR the
// caller sees. A re-key that swallowed one failed rewrite would resume the
// binding with objects still carrying the old fingerprint.
func TestSetIPIdentityPropagatesFailure(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"no write permission"}`))
	})
	err := c.SetIPIdentity(context.Background(), 41, "lv:new:uuid:aa:bb")
	if err == nil {
		t.Fatal("a refused PATCH must be an error")
	}
	if Classify(err) != ClassClient {
		t.Fatalf("Classify = %v, want ClassClient", Classify(err))
	}
}
