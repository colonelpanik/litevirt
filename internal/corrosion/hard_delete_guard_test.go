package corrosion

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var hardDeleteRe = regexp.MustCompile(`DELETE\s+FROM\s+([a-z_0-9]+)`)

// TestNoHardDeleteOfFullStateTables guards the delete-safety invariant: a full-
// state (anti-entropy) table must be soft-deleted (deleted_at + LWW on
// updated_at), never hard-deleted — a union merge can't propagate a hard delete,
// so a peer that missed it resurrects the row. The only sanctioned exception is a
// purge of an ALREADY-tombstoned row immediately before re-insert, tagged with a
// `full-state-delete-ok` marker on the statement line (see InsertVM).
//
// This is a TRIPWIRE, not complete enforcement: it is regex/line-based, so it only
// catches a single-line `DELETE FROM <table>` written in the canonical casing. It
// will miss lowercase keywords, multi-line statements, and SQL built from string
// fragments. It exists to catch the easy regression; correctness still rests on the
// behavioral merge/resurrection tests, not on this scan being exhaustive.
func TestNoHardDeleteOfFullStateTables(t *testing.T) {
	fullState := make(map[string]bool, len(tableNames))
	for _, n := range tableNames {
		fullState[n] = true
	}

	// CWD during `go test` is internal/corrosion; scan all of internal/.
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(b), "\n") {
			m := hardDeleteRe.FindStringSubmatch(line)
			if m == nil || !fullState[m[1]] {
				continue
			}
			if strings.Contains(line, "full-state-delete-ok") {
				continue
			}
			rel, _ := filepath.Rel(root, path)
			t.Errorf("internal/%s:%d hard-deletes full-state table %q without a `full-state-delete-ok` "+
				"marker — full-state tables must soft-delete (deleted_at) so the delete survives "+
				"anti-entropy:\n  %s", rel, i+1, m[1], strings.TrimSpace(line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
