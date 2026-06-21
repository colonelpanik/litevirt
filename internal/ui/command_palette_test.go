package ui

import (
	"net/http"
	"strings"
	"testing"
)

// TestCommandPaletteInShell verifies the ⌘K palette markup + script ship in the
// page shell, and the static JS asset is served.
func TestCommandPaletteInShell(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())

	r := withAuth(mustReq(t, "GET", "/"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, want := range []string{`id="command-palette"`, `id="cp-input"`, "command-palette.js", "⌘K"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard shell missing %q", want)
		}
	}

	// The embedded static asset is served.
	rr := serveRequest(s, withAuth(mustReq(t, "GET", "/static/command-palette.js")))
	assertStatus(t, rr, http.StatusOK)
	if !strings.Contains(rr.Body.String(), "cp-input") {
		t.Error("command-palette.js not served from embed")
	}
}
