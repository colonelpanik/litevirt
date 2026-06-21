package ui

import (
	"net/http"
	"strings"
	"testing"
)

// TestConfirmDialogInShell verifies the themed confirm dialog markup + script
// ship in the page shell and the asset is served.
func TestConfirmDialogInShell(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/")))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{`id="confirm-dialog"`, `id="cd-message"`, `id="cd-confirm"`, "confirm-dialog.js"} {
		if !strings.Contains(body, want) {
			t.Errorf("shell missing %q", want)
		}
	}
	rr := serveRequest(s, withAuth(mustReq(t, "GET", "/static/confirm-dialog.js")))
	assertStatus(t, rr, http.StatusOK)
	if !strings.Contains(rr.Body.String(), "htmx:confirm") {
		t.Error("confirm-dialog.js not served from embed")
	}
}
