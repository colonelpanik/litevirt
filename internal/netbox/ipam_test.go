package netbox

import (
	"context"
	"net/http"
	"testing"
)

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
	if Classify(err) != ClassClient {
		t.Fatalf("Classify = %v, want ClassClient", Classify(err))
	}
	if Ambiguous(err) {
		t.Fatal("a 400 is a definite answer, not ambiguous")
	}
}

func TestIdentityFormat(t *testing.T) {
	got := Identity("abc123", "550e8400-e29b-41d4-a716-446655440000", "52:54:00:aa:bb:cc")
	want := "lv:abc123:550e8400-e29b-41d4-a716-446655440000:52:54:00:aa:bb:cc"
	if got != want {
		t.Fatalf("Identity = %q, want %q", got, want)
	}
}
