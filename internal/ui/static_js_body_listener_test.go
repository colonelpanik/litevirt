package ui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestStaticJS_NoHtmxListenerOnDocumentBody guards against a subtle load-order bug: the static
// scripts are included in <head> (base.html), so they execute BEFORE <body> is parsed — at which
// point document.body is null. Registering an event listener on document.body at that point throws
// a TypeError and drops the listener (and everything after it in the same IIFE). htmx events bubble
// to document, which always exists, so htmx: listeners must be attached to document, not
// document.body.
//
// This is exactly the bug behind "selecting a VM shows the controls, then a few seconds later it
// deselects and reselecting does nothing": bulk-select.js's htmx:afterSwap (rewire) and
// htmx:beforeRequest (poll-pause) listeners never registered, so the 5s table refresh cleared the
// selection and the re-rendered rows were never rewired.
func TestStaticJS_NoHtmxListenerOnDocumentBody(t *testing.T) {
	files, err := filepath.Glob("static/*.js")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no static/*.js found — test is looking in the wrong place")
	}
	re := regexp.MustCompile(`document\.body\.addEventListener\(\s*['"]htmx:`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if loc := re.FindIndex(b); loc != nil {
			line := 1 + strings.Count(string(b[:loc[0]]), "\n")
			t.Errorf("%s:%d attaches an htmx: listener to document.body — head-loaded scripts run before "+
				"<body> exists (document.body is null → TypeError → the listener is silently dropped). "+
				"Use document.addEventListener instead (htmx events bubble to document).", f, line)
		}
	}
}
