package ui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoUIHandlerWritesReplicatedStateInProcess is a source-level guard.
//
// The UI's handlers hold a host-local Corrosion handle for reads. A mutation
// made through it passes through nothing that authorizes it: the session's
// bearer only means something to the daemon's gRPC interceptor. Every UI write
// therefore goes through its gRPC twin with s.uiBearerCtx(r), so the daemon
// authorizes it exactly as it does for `lv`. The security-group pages show why
// that is the only safe shape: they wrote in-process behind an in-process
// authorizer that could not see the session, so it authorized every caller as
// the bearerless admin (colonelpanik/litevirt#182).
//
// This test exists so a NEW handler cannot quietly start writing in-process,
// the kind of gap that is invisible in review because the write itself looks
// ordinary. It is an allowlist of read prefixes, not a denylist of write
// verbs: a denylist of Insert/Delete/Update/Upsert/Set never sees
// CreateResourceMapping, AddMappingDevice or RemoveMappingDevice, and those
// sat in the resource-mapping pages with no authorization at all.
//
// Carried from the fork's main.
func TestNoUIHandlerWritesReplicatedStateInProcess(t *testing.T) {
	callRe := regexp.MustCompile(`corrosion\.([A-Z][A-Za-z0-9]*)\(`)
	readRe := regexp.MustCompile(`^(List|Get)`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			for _, m := range callRe.FindAllStringSubmatch(line, -1) {
				if readRe.MatchString(m[1]) {
					continue
				}
				t.Errorf("%s:%d: corrosion.%s is not a read, and the UI must not write replicated "+
					"state in-process; call its gRPC twin with s.uiBearerCtx(r) instead, so the daemon "+
					"authorizes it the way it does for the CLI", name, i+1, m[1])
			}
		}
	}
}
