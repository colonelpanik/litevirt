package corrosion

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/hlc"
)

// TestNowTS_MonotonicFixedWidth: NowTS must return strictly-increasing,
// fixed-width RFC3339Nano timestamps even under a same-instant burst, so two
// writes to the same row in the same wall-clock second can't tie on updated_at.
func TestNowTS_MonotonicFixedWidth(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// UTC output is fixed-width: "2006-01-02T15:04:05.000000000Z" = 30 chars
	// (the layout's "Z07:00" collapses to "Z"). Fixed width keeps lexical order
	// == chronological order across all NowTS values.
	const wantWidth = 30
	const n = 1000
	prev := ""
	for i := 0; i < n; i++ {
		ts := c.NowTS()
		if len(ts) != wantWidth {
			t.Fatalf("NowTS %q not fixed-width (%d != %d)", ts, len(ts), wantWidth)
		}
		if _, perr := time.Parse(time.RFC3339, ts); perr != nil {
			t.Fatalf("NowTS %q does not parse as RFC3339: %v", ts, perr)
		}
		if i > 0 && ts <= prev {
			t.Fatalf("NowTS not strictly increasing: %q then %q", prev, ts)
		}
		prev = ts
	}

	// Independent Clients keep independent clocks (no shared global state).
	c2, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if c2.NowTS() == "" {
		t.Fatal("second client NowTS empty")
	}
}

// TestHostVersion_PropagatesAfterSameSecondBootWrites is the kvm001 regression:
// a node re-execs and writes its hosts row's state then version in the same
// wall-clock second. A peer that already holds an older copy of the row applies
// the state-write (bumping updated_at), then the version-write arrives with an
// updated_at that — at 1-second resolution — TIES the just-applied state-write,
// so shouldSkipLWW keeps local and the new version is stranded forever.
//
// With sub-second monotonic updated_at the version-write is strictly newer than
// the state-write, so it propagates. RED before NowTS lands on the host writers.
func TestHostVersion_PropagatesAfterSameSecondBootWrites(t *testing.T) {
	ctx := context.Background()

	a, err := NewSharedTestClient("lww-subsec-a", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewSharedTestClient("lww-subsec-b", "node-b")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := InitSchema(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(ctx, b); err != nil {
		t.Fatal(err)
	}

	// Both sides know host "node-a" at the OLD version. Force the peer's copy to
	// an older second so the incoming same-second boot writes are strictly newer
	// than the peer's existing row (the real post-upgrade situation).
	for _, c := range []*Client{a, b} {
		if err := InsertHost(ctx, c, HostRecord{Name: "node-a", Address: "127.0.0.1", State: "active", Version: "v-old"}); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
	}
	if _, err := b.DB().ExecContext(ctx,
		`UPDATE hosts SET updated_at = ? WHERE name = ?`, "2020-01-01T00:00:00Z", "node-a"); err != nil {
		t.Fatalf("age peer row: %v", err)
	}

	// Capture the boot sequence's mutations only (after the InsertHost above).
	var afterSeq int64
	if rows, err := a.Query(ctx, `SELECT COALESCE(MAX(seq),0) AS s FROM mutation_log`); err == nil && len(rows) > 0 {
		afterSeq = int64(rows[0].Int("s"))
	}

	// Boot sequence on node-a: state then version, same wall-clock second.
	if err := UpdateHostState(ctx, a, "node-a", "active"); err != nil {
		t.Fatalf("UpdateHostState: %v", err)
	}
	if err := UpdateHostVersion(ctx, a, "node-a", "v-new"); err != nil {
		t.Fatalf("UpdateHostVersion: %v", err)
	}

	// Ship node-a's boot mutations to the peer via the real apply path.
	rows, err := a.Query(ctx,
		`SELECT seq, hlc, origin, stmts FROM mutation_log WHERE seq > ? ORDER BY seq`, afterSeq)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	var entries []*pb.MutationEntry
	for _, r := range rows {
		entries = append(entries, &pb.MutationEntry{
			Seq: int64(r.Int("seq")), Hlc: r.String("hlc"),
			Origin: r.String("origin"), Stmts: r.String("stmts"),
		})
	}
	if len(entries) < 2 {
		t.Fatalf("expected ≥2 boot mutations, got %d", len(entries))
	}

	brepl := NewReplicator(b, "", RelayConfig{})
	if _, err := brepl.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("ApplyRemoteMutations: %v", err)
	}

	hb, err := GetHost(ctx, b, "node-a")
	if err != nil || hb == nil {
		t.Fatalf("GetHost(node-a) on peer: err=%v host=%v", err, hb)
	}
	if hb.Version != "v-new" {
		t.Errorf("peer's node-a version = %q, want %q (version stranded by a same-second LWW tie)", hb.Version, "v-new")
	}
}

// TestLocalWinsLWW_FormatHandling pins the comparator: HLC beats legacy RFC3339
// both directions; two RFC3339 values compare by parsed instant (so a fixed-width
// fractional value isn't lexically mis-ordered against a bare-second one); equal
// instants keep local.
func TestLocalWinsLWW_FormatHandling(t *testing.T) {
	hlcStr := hlc.NewClock("n").Now().String()
	const bare = "2026-06-27T10:03:01Z"
	const nanoLater = "2026-06-27T10:03:01.000000001Z" // 1ns AFTER bare, same second
	const nanoZero = "2026-06-27T10:03:01.000000000Z"  // == bare instant
	const laterSec = "2026-06-27T10:03:02Z"

	cases := []struct {
		name            string
		local, incoming string
		wantLocalWins   bool
	}{
		{"local HLC beats RFC3339", hlcStr, bare, true},
		{"incoming HLC beats RFC3339", bare, hlcStr, false},
		{"bare loses to later fractional same second", bare, nanoLater, false},
		{"later fractional beats bare same second", nanoLater, bare, true},
		{"equal instant keeps local (bare vs nano-zero)", bare, nanoZero, true},
		{"equal bare keeps local", bare, bare, true},
		{"earlier second loses", bare, laterSec, false},
		{"later second wins", laterSec, bare, true},
	}
	for _, tc := range cases {
		if got := localWinsLWW(tc.local, tc.incoming); got != tc.wantLocalWins {
			t.Errorf("%s: localWinsLWW(%q, %q) = %v, want %v", tc.name, tc.local, tc.incoming, got, tc.wantLocalWins)
		}
	}
}

// TestMergeLWW_MixedFormat: an anti-entropy dump carrying a fixed-nano updated_at
// that is later than a local bare-second value must win (the row updates); an
// exact-equal instant must keep local. Guards the RFC3339→nano rollout window.
func TestMergeLWW_MixedFormat(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}

	// Seed a local row with a BARE-second updated_at (legacy shape).
	if _, err := c.DB().ExecContext(ctx,
		`INSERT INTO hosts (name, address, ssh_user, cert_serial, version, state, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?)`,
		"h1", "127.0.0.1", "root", "serial", "bare", "active", "2026-06-27T10:03:01Z", "2026-06-27T10:03:01Z"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Full NOT-NULL column set so INSERT OR REPLACE (whole-row) doesn't violate
	// constraints — mirrors a real full-state dump row.
	merge := func(version, updatedAt string) {
		c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
			Name:    "hosts",
			Columns: []string{"name", "address", "ssh_user", "cert_serial", "version", "created_at", "updated_at"},
			Rows:    [][]interface{}{{"h1", "127.0.0.1", "root", "serial", version, "2026-06-27T10:03:01Z", updatedAt}},
		}}})
	}

	// Later fixed-nano in the same second → incoming wins.
	merge("nano-newer", "2026-06-27T10:03:01.000000001Z")
	if h, _ := GetHost(ctx, c, "h1"); h == nil || h.Version != "nano-newer" {
		t.Fatalf("later-nano should win, got %+v", h)
	}
	// Exact-equal instant with IDENTICAL content → no-op (no churn). A
	// differing-content equal-instant tie is no longer a blind keep-local: it is
	// resolved deterministically by the table-aware resolver (content-max for the
	// content-default `hosts` table) — see TestAntiEntropy_ContentTieConverges and
	// the resolver unit tests.
	merge("nano-newer", "2026-06-27T10:03:01.000000001Z")
	if h, _ := GetHost(ctx, c, "h1"); h == nil || h.Version != "nano-newer" {
		t.Errorf("equal instant + equal content should be a stable no-op, got %+v", h)
	}
}
