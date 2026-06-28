package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func testDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNewServer(t *testing.T) {
	db := testDB(t)
	s := NewServer(7444, "", db, nil, nil, "host-a")

	if s.port != 7444 {
		t.Errorf("port = %d, want 7444", s.port)
	}
	if s.hostName != "host-a" {
		t.Errorf("hostName = %s, want host-a", s.hostName)
	}
	if s.db == nil {
		t.Error("db should not be nil")
	}
	if s.httpSrv != nil {
		t.Error("httpSrv should be nil before Start")
	}
}

func TestHandleStatus(t *testing.T) {
	db := testDB(t)
	s := NewServer(7444, "", db, nil, nil, "host-a")

	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()

	s.handleStatus(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %s, want application/json", ct)
	}

	body := w.Body.String()
	if body != `{"status":"ok"}` {
		t.Errorf("body = %s, want {\"status\":\"ok\"}", body)
	}
}

func TestNewCollector(t *testing.T) {
	db := testDB(t)
	c := newCollector(db, nil, nil, "host-a")

	if c.hostName != "host-a" {
		t.Errorf("hostName = %s", c.hostName)
	}
	if c.hostVMCount == nil {
		t.Error("hostVMCount desc should not be nil")
	}
	if c.hostCPUTotal == nil {
		t.Error("hostCPUTotal desc should not be nil")
	}
	if c.hostMemTotal == nil {
		t.Error("hostMemTotal desc should not be nil")
	}
	if c.vmState == nil {
		t.Error("vmState desc should not be nil")
	}
	if c.vmCPU == nil {
		t.Error("vmCPU desc should not be nil")
	}
	if c.vmMemory == nil {
		t.Error("vmMemory desc should not be nil")
	}
	if c.peerHealthy == nil {
		t.Error("peerHealthy desc should not be nil")
	}
}
