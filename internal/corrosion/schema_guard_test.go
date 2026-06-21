package corrosion

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestSchemaHistoryDocumentsCurrentVersion is one half of the schema-versioning
// guard. The other half — "growth of schemaDDL/schemaMigrations/schemaIndexes
// requires a CurrentSchemaVersion bump" — is enforced in CI by
// scripts/ci/schemacheck against the diff (it needs the previous revision, so
// it can't be a self-contained unit test).
//
// This test enforces the part that IS self-contained: the History comment block
// in schema.go must stay in lockstep with CurrentSchemaVersion. Every version
// from v1..CurrentSchemaVersion must be documented, and the current version in
// particular must have an entry. That catches the common slip of bumping the
// constant (or adding a migration + bump) without recording what changed and
// why — the History block is the audit trail operators read before a staged
// rollout.
func TestSchemaHistoryDocumentsCurrentVersion(t *testing.T) {
	src, err := os.ReadFile("schema.go")
	if err != nil {
		t.Fatalf("read schema.go: %v", err)
	}

	// History lines look like:  //\tv23: registry credentials — ...
	re := regexp.MustCompile(`(?m)^\s*//\s*v(\d+):`)
	documented := map[int]bool{}
	for _, m := range re.FindAllSubmatch(src, -1) {
		n, err := strconv.Atoi(string(m[1]))
		if err != nil {
			continue
		}
		documented[n] = true
	}

	if len(documented) == 0 {
		t.Fatal("no `vN:` History entries found in schema.go — has the History comment block moved or changed format?")
	}
	if !documented[CurrentSchemaVersion] {
		t.Errorf("CurrentSchemaVersion=%d has no `v%d:` line in the History comment block; "+
			"add one describing the schema change.", CurrentSchemaVersion, CurrentSchemaVersion)
	}
	for v := 1; v <= CurrentSchemaVersion; v++ {
		if !documented[v] {
			t.Errorf("schema History is missing an entry for v%d "+
				"(versions must be documented contiguously from v1..v%d)", v, CurrentSchemaVersion)
		}
	}
}
