package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestMoveVolumeStream_ParsesForm guards the regression where the SSE move
// handler called r.ParseForm() before r.FormValue(), which left disk/target_pool
// empty for a (multipart) body and produced a spurious "disk and target pool are
// required" error. A url-encoded POST must parse cleanly, call MoveVolume with
// the right fields, and stream to completion.
func TestMoveVolumeStream_ParsesForm(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{"disk": {"osd0"}, "target_pool": {"nvme-2t"}}
	w := serveRequest(s, formPost(t, "/ui/vms/vm-01/move-volume-stream", form))
	assertStatus(t, w, http.StatusOK)
	if body := w.Body.String(); strings.Contains(body, "disk and target pool are required") {
		t.Fatalf("form fields were not parsed; body: %s", body)
	}
	assertContains(t, w, "event: done")
	req := mock.lastMoveReq
	if req == nil || req.VmName != "vm-01" || req.DiskName != "osd0" || req.TargetPool != "nvme-2t" {
		t.Errorf("MoveVolume req = %+v, want vm=vm-01 disk=osd0 pool=nvme-2t", req)
	}
}

// TestMoveVolumeStream_MissingFields confirms the validation still rejects an
// incomplete form (and never reaches the RPC).
func TestMoveVolumeStream_MissingFields(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	w := serveRequest(s, formPost(t, "/ui/vms/vm1/move-volume-stream", url.Values{"disk": {"osd0"}}))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "disk and target pool are required")
	if mock.lastMoveReq != nil {
		t.Error("MoveVolume must not be called when target_pool is missing")
	}
}
