package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestHandleResourceMappings_RendersWithDevices(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.CreateResourceMapping(ctx, db, "gpu-a100", "A100 pool"); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, db, "gpu-a100", "kvm-01", "0000:41:00.0", "10de", "A100"); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}
	s.SetCorrosionDB(db)

	r := withAuth(httptest.NewRequest(http.MethodGet, "/resource-mappings", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mustContain(t, w.Body.String(), "gpu-a100", "A100 pool", "kvm-01", "0000:41:00.0")
}

func TestHandleResourceMappings_Modals(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	for _, path := range []string{
		"/ui/resource-mappings/create-modal",
		"/ui/resource-mappings/gpu-a100/device-modal",
	} {
		r := withAuth(httptest.NewRequest(http.MethodGet, path, nil))
		w := serveRequest(s, r)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d", path, w.Code)
		}
	}
}
