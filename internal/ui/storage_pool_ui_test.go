package ui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// assertToast checks the HX-Trigger header (where sendToast writes) contains substr.
func assertToast(t *testing.T, w *httptest.ResponseRecorder, substr string) {
	t.Helper()
	trig := w.Header().Get("HX-Trigger")
	if !strings.Contains(trig, substr) {
		t.Errorf("HX-Trigger = %q, want substring %q", trig, substr)
	}
}

// formPost builds an authenticated form-encoded POST request.
func formPost(t *testing.T, path string, form url.Values) *http.Request {
	t.Helper()
	r, err := http.NewRequest("POST", path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return withAuth(r)
}

// ── parsePoolOptionLines (unit) ──────────────────────────────────────────────

func TestParsePoolOptionLines(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    map[string]string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"whitespace only", "   \n\n  ", nil, false},
		{"single", "rsize=1048576", map[string]string{"rsize": "1048576"}, false},
		{"multi", "a=b\nc=d", map[string]string{"a": "b", "c": "d"}, false},
		{"trim and skip blanks", "  k = v  \n\n x=y \n", map[string]string{"k": "v", "x": "y"}, false},
		{"value contains equals", "conn=a=b=c", map[string]string{"conn": "a=b=c"}, false},
		{"missing value", "k=", nil, true},
		{"missing key", "=v", nil, true},
		{"no equals", "noequals", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePoolOptionLines(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (out=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d (got=%v)", len(got), len(tc.want), got)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("key %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// ── handleCreatePoolModal ─────────────────────────────────────────────────────

func TestCreatePoolModal_RendersDriversAndHosts(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock()) // default mock has host "host1"
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/storage/create-modal")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Create storage pool")
	assertContains(t, w, ">dir<") // a driver option
	assertContains(t, w, "host1") // host option from ListHosts
}

// ── handleCreatePool ──────────────────────────────────────────────────────────

func TestCreatePool_Happy(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{
		"name":    {"nvme-2t"},
		"driver":  {"dir"},
		"source":  {""},
		"target":  {"/docker/litevirt"},
		"host":    {"host1"},
		"options": {"a=b\nc=d"},
	}
	w := serveRequest(s, formPost(t, "/ui/storage", form))
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/storage")
	assertToast(t, w, "created")
	req := mock.lastCreatePoolReq
	if req == nil {
		t.Fatal("CreateStoragePool not called")
	}
	if req.Name != "nvme-2t" || req.Driver != "dir" || req.Target != "/docker/litevirt" || req.Host != "host1" {
		t.Errorf("unexpected req: %+v", req)
	}
	if req.Options["a"] != "b" || req.Options["c"] != "d" {
		t.Errorf("options = %v, want a=b c=d", req.Options)
	}
}

func TestCreatePool_MissingNameRejected(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{"name": {""}, "driver": {"dir"}}
	w := serveRequest(s, formPost(t, "/ui/storage", form))
	assertStatus(t, w, http.StatusBadRequest)
	assertToast(t, w, "required")
	if mock.lastCreatePoolReq != nil {
		t.Error("CreateStoragePool should not be called when name is missing")
	}
}

func TestCreatePool_MissingDriverRejected(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{"name": {"p"}, "driver": {""}}
	w := serveRequest(s, formPost(t, "/ui/storage", form))
	assertStatus(t, w, http.StatusBadRequest)
	if mock.lastCreatePoolReq != nil {
		t.Error("CreateStoragePool should not be called when driver is missing")
	}
}

func TestCreatePool_BadOptionRejected(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{"name": {"p"}, "driver": {"dir"}, "options": {"noequals"}}
	w := serveRequest(s, formPost(t, "/ui/storage", form))
	assertStatus(t, w, http.StatusBadRequest)
	assertToast(t, w, "key=value")
	if mock.lastCreatePoolReq != nil {
		t.Error("CreateStoragePool should not be called on bad option")
	}
}

func TestCreatePool_RPCErrorReported(t *testing.T) {
	mock := newDefaultMock()
	mock.createPoolErr = errSimulated
	s := newTestUIServer(t, mock)
	form := url.Values{"name": {"p"}, "driver": {"dir"}}
	w := serveRequest(s, formPost(t, "/ui/storage", form))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "failed")
}

// ── handleDeletePool ──────────────────────────────────────────────────────────

func TestDeletePool_Happy(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/storage/nvme-2t?host=host1")))
	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/storage")
	if mock.lastDeletePoolReq == nil || mock.lastDeletePoolReq.Name != "nvme-2t" || mock.lastDeletePoolReq.Host != "host1" {
		t.Errorf("DeleteStoragePool req = %+v, want {nvme-2t host1}", mock.lastDeletePoolReq)
	}
}

func TestDeletePool_RPCErrorReported(t *testing.T) {
	mock := newDefaultMock()
	mock.deletePoolErr = errSimulated
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "DELETE", "/ui/storage/p?host=host1")))
	assertStatus(t, w, http.StatusInternalServerError)
	assertToast(t, w, "failed")
}

// ── /storage page renders pool rows + actions ─────────────────────────────────

func TestStoragePage_RendersCreateAndDelete(t *testing.T) {
	mock := newDefaultMock()
	mock.listStoragePoolsResp = &pb.ListStoragePoolsResponse{
		Pools: []*pb.StoragePool{{Name: "nvme-2t", Driver: "dir", Host: "host1", State: "active", TotalBytes: 100, UsedBytes: 50}},
	}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/storage")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "+ Create Pool")
	assertContains(t, w, "nvme-2t")
	assertContains(t, w, "/ui/storage/nvme-2t?host=host1") // delete button target
}
