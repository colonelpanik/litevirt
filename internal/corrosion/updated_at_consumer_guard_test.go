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
	// parameterized SQL comparison `updated_at < ?` / `> ?` / `<= ?` — reads updated_at
	// as a wall instant against a bind cutoff, which breaks the same way under HLC. The
	// tsMsSQL helper wraps updated_at inside a CASE/julianday expression, so its output
	// is `…END < ?` (never a bare `updated_at <`), which this does NOT match.
	reCmpUpdatedAt = regexp.MustCompile(`updated_at\s*[<>]=?\s*\?`)
)

// allowedLocalUpdatedAt names tables whose updated_at is intentionally read as WALL
// RFC3339 and is never emitted as an HLC LWW key, so a raw `updated_at < ?` compare is
// safe:
//   - replication_watermarks / clock_skew: LOCAL-only (never replicated) wall bookkeeping.
//   - rebalance_proposals: replicated but LEADER-GATED single-writer; its updated_at is
//     stamped wall RFC3339 via the rebalancer's injected clock (NOT NowLWW). If those
//     writers ever move to NowLWW/HLC, the reaper MUST switch to tsMsSQL first (see
//     recordProposal / reapStale).
var allowedLocalUpdatedAt = []string{"replication_watermarks", "clock_skew", "rebalance_proposals"}

// nearAllowedTable reports whether the SQL statement around line index i (a short
// backward window bounding it to the current query literal) references an allowlisted
// local-updated_at table.
func nearAllowedTable(lines []string, i int) bool {
	start := i - 8
	if start < 0 {
		start = 0
	}
	window := strings.Join(lines[start:i+1], "\n")
	for _, tbl := range allowedLocalUpdatedAt {
		if strings.Contains(window, tbl) {
			return true
		}
	}
	return false
}

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
		lines := strings.Split(string(src), "\n")
		for i, line := range lines {
			// Skip comment-only lines: explanatory comments legitimately mention these
			// shapes (e.g. documenting why a site is allowlisted) and must not trip.
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if reSubstrUpdatedAt.MatchString(line) {
				t.Errorf("internal/%s:%d: lexical substr(updated_at) — updated_at is the LWW key (RFC3339 or HLC); use the tsMsSQL helper for age/GC cutoffs", rel, i+1)
			}
			if reParseUpdatedAt.MatchString(line) {
				t.Errorf("internal/%s:%d: time.Parse(RFC3339, updated_at) — use corrosion.ParseUpdatedAt (handles HLC + RFC3339)", rel, i+1)
			}
			if reCmpUpdatedAt.MatchString(line) && !nearAllowedTable(lines, i) {
				t.Errorf("internal/%s:%d: raw `updated_at < ?` compare — updated_at is the LWW key (may be HLC); use the tsMsSQL helper, or allowlist the table in allowedLocalUpdatedAt if its updated_at is wall-only", rel, i+1)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
