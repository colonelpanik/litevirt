package netbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("secret-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{BaseURL: srv.URL, TokenPath: tok, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetPrefix(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Token secret-token" {
			t.Errorf("auth header = %q", got)
		}
		if r.URL.Path != "/api/ipam/prefixes/7/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":7,"prefix":"10.0.5.0/24","vrf":{"id":3}}`))
	})
	p, err := c.GetPrefix(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != 7 || p.Prefix != "10.0.5.0/24" || p.VRFID != 3 {
		t.Fatalf("prefix = %+v", p)
	}
}

func TestGetPrefixGlobalTableHasNoVRF(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":7,"prefix":"10.0.5.0/24","vrf":null}`))
	})
	p, err := c.GetPrefix(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if p.VRFID != 0 {
		t.Fatalf("global-table prefix must report VRFID 0, got %d", p.VRFID)
	}
}

func TestVRFEnforcesUnique(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":3,"enforce_unique":true}`))
	})
	ok, err := c.VRFEnforcesUnique(context.Background(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("want enforce_unique true")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ErrClass
	}{
		{"400", &APIError{Status: 400}, ClassClient},
		{"403", &APIError{Status: 403}, ClassClient},
		{"409", &APIError{Status: 409}, ClassClient},
		{"500", &APIError{Status: 500}, ClassServer},
		{"503", &APIError{Status: 503}, ClassServer},
		{"transport", context.DeadlineExceeded, ClassTransport},
	}
	for _, tc := range cases {
		if got := Classify(tc.err); got != tc.want {
			t.Errorf("%s: Classify = %v, want %v", tc.name, got, tc.want)
		}
	}
}
