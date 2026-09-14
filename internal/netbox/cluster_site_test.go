package netbox

import (
	"context"
	"net/http"
	"testing"
)

// The NetBox cluster carries the SITE, and every VM in it inherits that site.
// Without one a mirrored VM has no site at all, which is invisible to anything
// that scopes by site — NetBox's own filters, and the DNS and inventory
// integrations built on them.
//
// litevirt cannot derive it: which site the hardware sits in is operator
// knowledge, exactly like netbox.cluster_name. So it is supplied, and these pin
// what supplying it (and NOT supplying it) must do.

// TestEnsureClusterSetsTheSiteOnCreate: a cluster created with a site carries it
// from the first sweep, so the very first VM mirrored into it inherits one.
func TestEnsureClusterSetsTheSiteOnCreate(t *testing.T) {
	var posted map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"results":[]}`)) // absent
			return
		}
		decodeBody(t, r, &posted)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":8}`))
	})

	id, err := c.EnsureCluster(context.Background(), "litevirt", 3, 5)
	if err != nil {
		t.Fatalf("EnsureCluster: %v", err)
	}
	if id != 8 {
		t.Fatalf("id = %d, want 8", id)
	}
	if posted["scope_type"] != "dcim.site" {
		t.Errorf("scope_type = %v, want dcim.site", posted["scope_type"])
	}
	if got, _ := posted["scope_id"].(float64); int(got) != 5 {
		t.Errorf("scope_id = %v, want 5", posted["scope_id"])
	}
}

// TestEnsureClusterConvergesTheSiteOnAnExistingCluster is the half a
// create-only body would miss: an operator who adds the site to config later
// must see it reach the cluster that already exists, or the setting silently
// does nothing on every cluster that has ever mirrored.
func TestEnsureClusterConvergesTheSiteOnAnExistingCluster(t *testing.T) {
	var patched map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Exists, with NO scope.
			_, _ = w.Write([]byte(`{"results":[{"id":8,"scope_type":null,"scope_id":null}]}`))
		case http.MethodPatch:
			decodeBody(t, r, &patched)
			_, _ = w.Write([]byte(`{"id":8}`))
		default:
			t.Errorf("unexpected %s", r.Method)
		}
	})

	if _, err := c.EnsureCluster(context.Background(), "litevirt", 3, 5); err != nil {
		t.Fatalf("EnsureCluster: %v", err)
	}
	if patched == nil {
		t.Fatal("an existing cluster with no site was never patched — the setting " +
			"would do nothing on any cluster that already mirrored")
	}
	if got, _ := patched["scope_id"].(float64); int(got) != 5 {
		t.Errorf("scope_id = %v, want 5", patched["scope_id"])
	}
}

// TestEnsureClusterLeavesAMatchingSiteAlone: write-on-change. The cluster is
// resolved on EVERY sweep, so a PATCH per sweep would be a write storm on a
// 15-minute timer.
func TestEnsureClusterLeavesAMatchingSiteAlone(t *testing.T) {
	patches := 0
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"results":[{"id":8,"scope_type":"dcim.site","scope_id":5}]}`))
		case http.MethodPatch:
			patches++
			_, _ = w.Write([]byte(`{"id":8}`))
		}
	})

	if _, err := c.EnsureCluster(context.Background(), "litevirt", 3, 5); err != nil {
		t.Fatalf("EnsureCluster: %v", err)
	}
	if patches != 0 {
		t.Fatalf("issued %d PATCH(es) for a site that already matches", patches)
	}
}

// TestEnsureClusterWithNoSiteNeverClearsOne is the trap, and the reason an unset
// site means UNMANAGED rather than "none".
//
// Operators set this scope by hand long before litevirt could supply it. If an
// empty config were written through as null, deploying this change would strip
// the site off a working cluster and take every VM's inherited site with it —
// silently undoing exactly what it exists to provide.
func TestEnsureClusterWithNoSiteNeverClearsOne(t *testing.T) {
	patches := 0
	var body map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"results":[{"id":8,"scope_type":"dcim.site","scope_id":5}]}`))
		case http.MethodPatch:
			patches++
			decodeBody(t, r, &body)
			_, _ = w.Write([]byte(`{"id":8}`))
		}
	})

	if _, err := c.EnsureCluster(context.Background(), "litevirt", 3, 0); err != nil {
		t.Fatalf("EnsureCluster: %v", err)
	}
	if patches != 0 {
		t.Fatalf("an unset site issued %d PATCH(es) (body %v) — it must leave a "+
			"hand-set scope alone, not clear it", patches, body)
	}
}

// TestEnsureClusterWithNoSiteOmitsScopeOnCreate: the same rule on the create
// path. Posting an explicit null scope is harmless today but states an intent
// litevirt does not have.
func TestEnsureClusterWithNoSiteOmitsScopeOnCreate(t *testing.T) {
	var posted map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"results":[]}`))
			return
		}
		decodeBody(t, r, &posted)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":8}`))
	})

	if _, err := c.EnsureCluster(context.Background(), "litevirt", 3, 0); err != nil {
		t.Fatalf("EnsureCluster: %v", err)
	}
	if _, ok := posted["scope_type"]; ok {
		t.Errorf("create body carried a scope with no site configured: %v", posted)
	}
	if _, ok := posted["scope_id"]; ok {
		t.Errorf("create body carried a scope_id with no site configured: %v", posted)
	}
}

// TestFindSiteByName resolves the operator's site name to the id the scope needs,
// and reports an absent site as 0 rather than an error the caller must special-case.
func TestFindSiteByName(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") == "FIN-03" {
			_, _ = w.Write([]byte(`{"results":[{"id":5}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[]}`))
	})
	id, err := c.FindSiteByName(context.Background(), "FIN-03")
	if err != nil || id != 5 {
		t.Fatalf("FindSiteByName = %d, %v; want 5, nil", id, err)
	}
	id, err = c.FindSiteByName(context.Background(), "nope")
	if err != nil || id != 0 {
		t.Fatalf("absent site = %d, %v; want 0, nil", id, err)
	}
}
