package corrosion

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// updated_at is the LWW conflict key and becomes an HLC string ("<physms>-…") once
// hlc_lww is enabled. Reading it as WALL time via a lexical `substr(updated_at,…)` cutoff
// or a raw `time.Parse(time.RFC3339, …updated_at)` then breaks silently (an HLC "175…"
// sorts below every RFC3339 value → rows read as permanently stale). These guards fail
// if such a raw consumer is (re)introduced; use corrosion.ParseUpdatedAt (Go) or the
// tsMsSQL helper (SQL) instead, both of which interpret HLC and RFC3339.
var (
	// bare `substr(updated_at` / `substr(COALESCE(NULLIF(updated_at` — the lexical form.
	// tsMsSQL emits `substr((updated_at)…` (double paren), which this does NOT match.
	reSubstrUpdatedAt = regexp.MustCompile(`substr\((?:COALESCE\(NULLIF\()?updated_at`)
	// raw RFC3339 parse of an updated_at value on one line.
	reParseUpdatedAt = regexp.MustCompile(`time\.Parse\(time\.RFC3339,[^)]*[Uu]pdated`)
)

func TestUpdatedAtConsumersUseBothFormatHelper(t *testing.T) {
	root, err := filepath.Abs("..") // internal/
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(src), "\n") {
			if reSubstrUpdatedAt.MatchString(line) {
				t.Errorf("internal/%s:%d: lexical substr(updated_at) — updated_at is the LWW key (RFC3339 or HLC); use the tsMsSQL helper for age/GC cutoffs", rel, i+1)
			}
			if reParseUpdatedAt.MatchString(line) {
				t.Errorf("internal/%s:%d: time.Parse(RFC3339, updated_at) — use corrosion.ParseUpdatedAt (handles HLC + RFC3339)", rel, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
