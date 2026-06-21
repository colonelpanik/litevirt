// Package golden is a tiny helper for golden-file tests.
//
// Usage:
//
//	got:= someRenderer(input)
//	golden.Assert(t, "testdata/case_a.golden", got)
//
// Run `go test -run TestX -update./...` to refresh the golden file
// after an intentional change. Without -update the test fails on diff.
package golden

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "update golden files in place")

// Assert compares got against the bytes in path. If the bytes differ
// the test fails with a unified-style diff. With -update, the file is
// rewritten instead.
func Assert(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir golden: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -update to create it)", path, err)
	}
	if string(want) != got {
		t.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s\n--- end ---\nrun with -update to overwrite", path, string(want), got)
	}
}
