package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/hlc"
)

// ─── Relay Election Tests ───────────────────────────────────────────────────

func TestComputeRelays_Deterministic(t *testing.T) {
	members := makePeers("node-a", "node-b", "node-c", "node-d", "node-e")
	cfg := RelayConfig{BaseRelays: 3, NodesPerRelay: 50}

	// Every node should compute the same relay set.
	for _, self := range []string{"node-a", "node-b", "node-c", "node-d", "node-e"} {
		rs := ComputeRelays(members, self, cfg)
		if got := len(rs.Relays()); got != 4 {
			t.Errorf("self=%s: expected 4 relays (3 + ceil(5/50)), got %d", self, got)
		}
		// First 4 alphabetically: node-a, node-b, node-c, node-d
		want := []string{"node-a", "node-b", "node-c", "node-d"}
		for i, r := range rs.Relays() {
			if r != want[i] {
				t.Errorf("self=%s: relay[%d] = %s, want %s", self, i, r, want[i])
			}
		}
	}
}

func TestComputeRelays_SmallCluster(t *testing.T) {
	cfg := RelayConfig{BaseRelays: 3, NodesPerRelay: 50}

	// 2-node cluster: both should be relays (R = min(2, 3+1) = 2).
	members := makePeers("node-b")
	rs := ComputeRelays(members, "node-a", cfg)
	if got := len(rs.Relays()); got != 2 {
		t.Errorf("2-node cluster: expected 2 relays, got %d", got)
	}
	if !rs.IsRelay("node-a") || !rs.IsRelay("node-b") {
		t.Error("2-node cluster: both nodes should be relays")
	}

	// 3-node cluster: all relays (R = min(3, 3+1) = 3).
	members = makePeers("node-b", "node-c")
	rs = ComputeRelays(members, "node-a", cfg)
	if got := len(rs.Relays()); got != 3 {
		t.Errorf("3-node cluster: expected 3 relays, got %d", got)
	}

	// 1-node cluster: self is relay.
	rs = ComputeRelays(nil, "node-a", cfg)
	if got := len(rs.Relays()); got != 1 {
		t.Errorf("1-node cluster: expected 1 relay, got %d", got)
	}
	if !rs.IsRelay("node-a") {
		t.Error("1-node cluster: self should be relay")
	}
}

func TestComputeRelays_Scaling(t *testing.T) {
	cfg := RelayConfig{BaseRelays: 3, NodesPerRelay: 50}

	tests := []struct {
		nodes     int
		wantRelay int
	}{
		{10, 4},  // 3 + ceil(10/50) = 4
		{50, 4},  // 3 + ceil(50/50) = 4
		{51, 5},  // 3 + ceil(51/50) = 5
		{100, 5}, // 3 + ceil(100/50) = 5
		{200, 7}, // 3 + ceil(200/50) = 7
	}

	for _, tt := range tests {
		members := makePeersN(tt.nodes - 1) // -1 because self is added
		rs := ComputeRelays(members, "node-0000", cfg)
		if got := len(rs.Relays()); got != tt.wantRelay {
			t.Errorf("n=%d: expected %d relays, got %d", tt.nodes, tt.wantRelay, got)
		}
	}
}

func TestComputeRelays_MembershipChange(t *testing.T) {
	cfg := RelayConfig{BaseRelays: 3, NodesPerRelay: 50}

	// Start with 5 nodes: relays are node-a, node-b, node-c, node-d
	members := makePeers("node-a", "node-b", "node-c", "node-d", "node-e")
	rs1 := ComputeRelays(members, "node-e", cfg)

	// node-a departs: relays should be re-elected from remaining 4
	members = makePeers("node-b", "node-c", "node-d", "node-e")
	rs2 := ComputeRelays(members, "node-e", cfg)

	if rs2.IsRelay("node-a") {
		t.Error("departed node-a should not be relay")
	}
	// node-e should now be a relay (first 4 of 4 sorted names)
	if !rs2.IsRelay("node-e") {
		t.Error("node-e should become relay after node-a departs")
	}
	_ = rs1 // suppress unused
}

func TestLeafAssignment_Deterministic(t *testing.T) {
	cfg := RelayConfig{BaseRelays: 3, NodesPerRelay: 50}

	// 6 nodes, 4 relays, 2 leaves
	members := makePeers("node-a", "node-b", "node-c", "node-d", "node-e", "node-f")
	rs := ComputeRelays(members, "node-a", cfg)

	// Leaves are node-e, node-f (alphabetically after the 4 relays)
	if rs.IsRelay("node-e") || rs.IsRelay("node-f") {
		t.Error("node-e and node-f should be leaves")
	}

	pair := rs.AssignedRelays("node-e")
	if pair[0] == "" || pair[1] == "" {
		t.Errorf("node-e should have 2 assigned relays, got %v", pair)
	}
	if pair[0] == pair[1] {
		t.Errorf("primary and backup should differ for >1 relay, got %v", pair)
	}
}

func TestLeafAssignment_Overlap(t *testing.T) {
	cfg := RelayConfig{BaseRelays: 3, NodesPerRelay: 50}

	// 10 nodes
	members := makePeersN(10)
	rs := ComputeRelays(members, "node-0000", cfg)

	// Every leaf should have exactly 2 assigned relays.
	for _, m := range members {
		if rs.IsRelay(m.Name) {
			continue
		}
		pair := rs.AssignedRelays(m.Name)
		if pair[0] == "" || pair[1] == "" {
			t.Errorf("leaf %s missing relay assignment: %v", m.Name, pair)
		}
		if !rs.IsRelay(pair[0]) || !rs.IsRelay(pair[1]) {
			t.Errorf("leaf %s assigned to non-relay: %v", m.Name, pair)
		}
	}
}

func TestTargetsFor_Relay(t *testing.T) {
	cfg := RelayConfig{BaseRelays: 3, NodesPerRelay: 50}

	members := makePeers("node-a", "node-b", "node-c", "node-d", "node-e", "node-f")
	rs := ComputeRelays(members, "node-a", cfg)

	targets := rs.TargetsFor("node-a", false, nil)
	// Relay should target: assigned leaves + other relays
	targetSet := toSet(targets)
	// Must include other relays
	for _, r := range rs.Relays() {
		if r == "node-a" {
			continue
		}
		if !targetSet[r] {
			t.Errorf("relay node-a should target relay %s", r)
		}
	}
}

func TestTargetsFor_Leaf(t *testing.T) {
	cfg := RelayConfig{BaseRelays: 3, NodesPerRelay: 50}

	members := makePeers("node-a", "node-b", "node-c", "node-d", "node-e", "node-f")
	rs := ComputeRelays(members, "node-e", cfg)

	targets := rs.TargetsFor("node-e", false, nil)
	// Leaf should only target its 2 assigned relays.
	if len(targets) != 2 {
		t.Errorf("leaf should have 2 targets, got %d: %v", len(targets), targets)
	}
	for _, target := range targets {
		if !rs.IsRelay(target) {
			t.Errorf("leaf target %s is not a relay", target)
		}
	}
}

// ─── Dedup Tests ────────────────────────────────────────────────────────────

func TestDedup_MutationSeen(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	ctx := context.Background()
	clock := hlc.NewClock("origin-node")
	ts := clock.Now()

	entries := []*pb.MutationEntry{{
		Seq:    1,
		Hlc:    ts.String(),
		Origin: "origin-node",
		Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["h1","10.0.0.1","root","serial1","active","2025-01-01T00:00:00Z","` + ts.String() + `"]}]`,
	}}

	// First apply should succeed.
	seq1, err := r.ApplyRemoteMutations(ctx, entries)
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if seq1 != 1 {
		t.Errorf("first apply seq = %d, want 1", seq1)
	}

	// Verify host was inserted.
	rows, err := c.Query(ctx, "SELECT name FROM hosts WHERE name = 'h1'")
	if err != nil || len(rows) == 0 {
		t.Fatal("host h1 should exist after first apply")
	}

	// Second apply of same entries should be deduped.
	seq2, err := r.ApplyRemoteMutations(ctx, entries)
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if seq2 != 1 {
		t.Errorf("second apply seq = %d, want 1", seq2)
	}

	// Verify mutation_seen has exactly one entry.
	var count int
	c.mu.RLock()
	c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mutation_seen").Scan(&count)
	c.mu.RUnlock()
	if count != 1 {
		t.Errorf("mutation_seen count = %d, want 1", count)
	}
}

func TestApplyRemoteMutations_AdvancesPastTrailingDuplicates(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()
	clock := hlc.NewClock("origin-node")
	tsNew := clock.Now().String()
	tsSeen := clock.Now().String()

	entries := []*pb.MutationEntry{
		{
			Seq:    1,
			Hlc:    tsNew,
			Origin: "origin-node",
			Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["dedup-new","10.0.0.1","root","serial1","active","2025-01-01T00:00:00Z","` + tsNew + `"]}]`,
		},
		{
			Seq:    2,
			Hlc:    tsSeen,
			Origin: "origin-node",
			Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["dedup-seen","10.0.0.2","root","serial2","active","2025-01-01T00:00:00Z","` + tsSeen + `"]}]`,
		},
	}

	c.mu.Lock()
	if _, err := c.db.ExecContext(ctx,
		`INSERT INTO mutation_seen (origin, hlc) VALUES (?, ?)`,
		"origin-node", tsSeen); err != nil {
		c.mu.Unlock()
		t.Fatalf("seed mutation_seen: %v", err)
	}
	c.mu.Unlock()

	got, err := r.ApplyRemoteMutations(ctx, entries)
	if err != nil {
		t.Fatalf("ApplyRemoteMutations: %v", err)
	}
	if got != 2 {
		t.Fatalf("acked seq = %d, want 2 (must advance past trailing duplicates)", got)
	}
}

// ─── Relay Recording Tests ──────────────────────────────────────────────────

func TestRelay_ForwardsMutations(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	// Force relay mode.
	r.mu.Lock()
	r.isRelay = true
	r.mu.Unlock()

	ctx := context.Background()
	clock := hlc.NewClock("remote-node")
	ts := clock.Now()

	entries := []*pb.MutationEntry{{
		Seq:    1,
		Hlc:    ts.String(),
		Origin: "remote-node",
		Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["h2","10.0.0.2","root","serial2","active","2025-01-01T00:00:00Z","` + ts.String() + `"]}]`,
	}}

	_, err := r.ApplyRemoteMutations(ctx, entries)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Relay should have recorded in mutation_log with original origin.
	c.mu.RLock()
	var origin string
	err = c.db.QueryRowContext(ctx,
		"SELECT origin FROM mutation_log ORDER BY seq DESC LIMIT 1").Scan(&origin)
	c.mu.RUnlock()
	if err != nil {
		t.Fatalf("query mutation_log: %v", err)
	}
	if origin != "remote-node" {
		t.Errorf("mutation_log origin = %q, want %q", origin, "remote-node")
	}
}

func TestLeaf_DoesNotRecordInLog(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	// Ensure leaf mode (default).
	r.mu.Lock()
	r.isRelay = false
	r.mu.Unlock()

	ctx := context.Background()
	clock := hlc.NewClock("remote-node")
	ts := clock.Now()

	entries := []*pb.MutationEntry{{
		Seq:    1,
		Hlc:    ts.String(),
		Origin: "remote-node",
		Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["h3","10.0.0.3","root","serial3","active","2025-01-01T00:00:00Z","` + ts.String() + `"]}]`,
	}}

	_, err := r.ApplyRemoteMutations(ctx, entries)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Leaf should NOT have recorded in mutation_log.
	var count int
	c.mu.RLock()
	c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mutation_log").Scan(&count)
	c.mu.RUnlock()
	if count != 0 {
		t.Errorf("leaf mutation_log count = %d, want 0", count)
	}

	// But mutation_seen should have the entry.
	c.mu.RLock()
	c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mutation_seen").Scan(&count)
	c.mu.RUnlock()
	if count != 1 {
		t.Errorf("leaf mutation_seen count = %d, want 1", count)
	}
}

func TestNoEchoBack(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	// Simulate relay that received a mutation from "peer-x".
	r.mu.Lock()
	r.isRelay = true
	r.mu.Unlock()

	ctx := context.Background()
	clock := hlc.NewClock("peer-x")
	ts := clock.Now()

	entries := []*pb.MutationEntry{{
		Seq:    1,
		Hlc:    ts.String(),
		Origin: "peer-x",
		Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["h4","10.0.0.4","root","serial4","active","2025-01-01T00:00:00Z","` + ts.String() + `"]}]`,
	}}

	_, err := r.ApplyRemoteMutations(ctx, entries)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	// readMutationLog for peer-x should return nothing (origin filter).
	filtered, _, err := r.readMutationLog(ctx, 0, 100, "peer-x")
	if err != nil {
		t.Fatalf("readMutationLog: %v", err)
	}
	if len(filtered) != 0 {
		t.Errorf("readMutationLog for peer-x returned %d entries, want 0", len(filtered))
	}

	// readMutationLog for a different peer should return the entry.
	unfiltered, _, err := r.readMutationLog(ctx, 0, 100, "peer-y")
	if err != nil {
		t.Fatalf("readMutationLog: %v", err)
	}
	if len(unfiltered) != 1 {
		t.Errorf("readMutationLog for peer-y returned %d entries, want 1", len(unfiltered))
	}
}

// ─── LWW Tests ──────────────────────────────────────────────────────────────

func TestLWW_ConcurrentWrites(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()

	// Two clocks with different node IDs to simulate concurrent writes.
	clockA := hlc.NewClock("node-a")
	clockB := hlc.NewClock("node-b")

	tsA := clockA.Now()
	// Advance B past A to ensure B wins.
	clockB.Update(tsA)
	tsB := clockB.Now()

	// Apply A's write first.
	entriesA := []*pb.MutationEntry{{
		Seq:    1,
		Hlc:    tsA.String(),
		Origin: "node-a",
		Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["conflict-host","10.0.0.1","root","serialA","active","2025-01-01T00:00:00Z","` + tsA.String() + `"]}]`,
	}}
	if _, err := r.ApplyRemoteMutations(ctx, entriesA); err != nil {
		t.Fatalf("apply A: %v", err)
	}

	// Apply B's write (newer HLC) for the same host.
	entriesB := []*pb.MutationEntry{{
		Seq:    2,
		Hlc:    tsB.String(),
		Origin: "node-b",
		Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["conflict-host","10.0.0.2","root","serialB","active","2025-01-01T00:00:00Z","` + tsB.String() + `"]}]`,
	}}
	if _, err := r.ApplyRemoteMutations(ctx, entriesB); err != nil {
		t.Fatalf("apply B: %v", err)
	}

	// B should win (newer HLC).
	rows, err := c.Query(ctx, "SELECT address FROM hosts WHERE name = 'conflict-host'")
	if err != nil || len(rows) == 0 {
		t.Fatal("conflict-host should exist")
	}
	if addr := rows[0].String("address"); addr != "10.0.0.2" {
		t.Errorf("address = %s, want 10.0.0.2 (node-b should win)", addr)
	}

	// Now apply an older write — should be rejected by LWW. We construct an
	// HLC string that is deterministically earlier than tsB rather than
	// relying on wall-clock ordering of two NewClock().Now() calls (which
	// can reorder under sub-millisecond clock resolution).
	tsOld := hlc.Timestamp{
		PhysicalMS: tsB.PhysicalMS - 1000,
		Logical:    0,
		NodeID:     "node-c",
	}
	entriesOld := []*pb.MutationEntry{{
		Seq:    3,
		Hlc:    tsOld.String(),
		Origin: "node-c",
		Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["conflict-host","10.0.0.3","root","serialC","active","2025-01-01T00:00:00Z","` + tsOld.String() + `"]}]`,
	}}
	if _, err := r.ApplyRemoteMutations(ctx, entriesOld); err != nil {
		t.Fatalf("apply old: %v", err)
	}

	// B should still win.
	rows, err = c.Query(ctx, "SELECT address FROM hosts WHERE name = 'conflict-host'")
	if err != nil || len(rows) == 0 {
		t.Fatal("conflict-host should exist")
	}
	if addr := rows[0].String("address"); addr != "10.0.0.2" {
		t.Errorf("after old write: address = %s, want 10.0.0.2", addr)
	}
}

func TestLWW_PrimaryReplicationUsesStatementUpdatedAt(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()

	localTS := "2026-01-02T00:00:00Z"
	incomingRowTS := "2026-01-01T00:00:00Z"
	incomingMutationHLC := "9999999999999-0000-remote"

	if err := c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"rfc-conflict", "10.0.0.1", "root", "serial-local", "active", localTS, localTS); err != nil {
		t.Fatalf("seed local host: %v", err)
	}

	entries := []*pb.MutationEntry{{
		Seq:    1,
		Hlc:    incomingMutationHLC,
		Origin: "remote-node",
		Stmts:  `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["rfc-conflict","10.0.0.2","root","serial-remote","active","` + incomingRowTS + `","` + incomingRowTS + `"]}]`,
	}}
	if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("apply older row with newer mutation HLC: %v", err)
	}

	rows, err := c.Query(ctx, "SELECT address FROM hosts WHERE name = 'rfc-conflict'")
	if err != nil || len(rows) == 0 {
		t.Fatalf("lookup rfc-conflict: err=%v rows=%d", err, len(rows))
	}
	if addr := rows[0].String("address"); addr != "10.0.0.1" {
		t.Errorf("address = %s, want 10.0.0.1 (row updated_at, not mutation HLC, should decide)", addr)
	}
}

// ─── Prune Tests ────────────────────────────────────────────────────────────

func TestPruneMutationSeen(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()

	// Insert an old entry (20 minutes ago) and a recent entry.
	oldMS := time.Now().Add(-20 * time.Minute).UnixMilli()
	oldHLC := fmt.Sprintf("%013d-0000-old-node", oldMS)
	recentHLC := hlc.NewClock("recent-node").Now().String()

	c.mu.Lock()
	c.db.ExecContext(ctx, "INSERT INTO mutation_seen (origin, hlc) VALUES (?, ?)", "old-node", oldHLC)
	c.db.ExecContext(ctx, "INSERT INTO mutation_seen (origin, hlc) VALUES (?, ?)", "recent-node", recentHLC)
	c.mu.Unlock()

	r.pruneMutationSeen(ctx)

	var count int
	c.mu.RLock()
	c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mutation_seen").Scan(&count)
	c.mu.RUnlock()

	if count != 1 {
		t.Errorf("after prune: mutation_seen count = %d, want 1 (only recent)", count)
	}
}

func seenCount(t *testing.T, c *Client) int {
	t.Helper()
	var n int
	c.mu.RLock()
	defer c.mu.RUnlock()
	c.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM mutation_seen").Scan(&n)
	return n
}

// TestPruneMutationSeen_DataRelative proves the cutoff is derived from the
// newest stored HLC, not the wall clock. All rows sit in the year 2000 — far
// behind "now" — so the old wall-clock cutoff would have deleted every row;
// the data-relative cutoff deletes only the one >15m behind the table's max.
func TestPruneMutationSeen_DataRelative(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()

	baseMS := int64(946684800000) // 2000-01-01, far behind any plausible now
	mk := func(ms int64, node string) string { return fmt.Sprintf("%013d-%04d-%s", ms, 0, node) }

	c.mu.Lock()
	c.db.ExecContext(ctx, "INSERT INTO mutation_seen (origin, hlc) VALUES (?, ?)", "max", mk(baseMS, "max"))
	c.db.ExecContext(ctx, "INSERT INTO mutation_seen (origin, hlc) VALUES (?, ?)", "keep", mk(baseMS-5*60*1000, "keep"))
	c.db.ExecContext(ctx, "INSERT INTO mutation_seen (origin, hlc) VALUES (?, ?)", "drop", mk(baseMS-20*60*1000, "drop"))
	c.mu.Unlock()

	r.pruneMutationSeen(ctx)

	if got := seenCount(t, c); got != 2 {
		t.Errorf("data-relative prune: count = %d, want 2 (max + keep; only the 20m-old row dropped)", got)
	}
}

// TestPruneMutationSeen_MalformedSurvives ensures a row that is not a canonical
// HLC neither defines the max nor is deleted. "12abc12345678-0000-x" is the
// case a loose '[0-9][0-9]*-*' GLOB would have wrongly matched.
func TestPruneMutationSeen_MalformedSurvives(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()

	nowMS := time.Now().UnixMilli()
	mk := func(ms int64, node string) string { return fmt.Sprintf("%013d-%04d-%s", ms, 0, node) }

	c.mu.Lock()
	c.db.ExecContext(ctx, "INSERT INTO mutation_seen (origin, hlc) VALUES (?, ?)", "max", mk(nowMS, "max"))
	c.db.ExecContext(ctx, "INSERT INTO mutation_seen (origin, hlc) VALUES (?, ?)", "old", mk(nowMS-20*60*1000, "old"))
	c.db.ExecContext(ctx, "INSERT INTO mutation_seen (origin, hlc) VALUES (?, ?)", "bad", "12abc12345678-0000-x")
	c.mu.Unlock()

	r.pruneMutationSeen(ctx)

	// max + malformed survive; the valid 20m-old row is pruned.
	if got := seenCount(t, c); got != 2 {
		t.Errorf("malformed prune: count = %d, want 2 (max + malformed kept; valid old row dropped)", got)
	}
	var badCount int
	c.mu.RLock()
	c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mutation_seen WHERE origin = 'bad'").Scan(&badCount)
	c.mu.RUnlock()
	if badCount != 1 {
		t.Errorf("malformed row was pruned (count=%d), want kept", badCount)
	}
}

// ─── Fallback Tests ─────────────────────────────────────────────────────────

func TestFallbackActivation(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{FallbackTimeout: 100 * time.Millisecond})

	// Initially not in fallback.
	if r.fallbackActive.Load() {
		t.Error("should not be in fallback initially")
	}

	// Simulate leaf mode with stale relay push.
	r.mu.Lock()
	r.isRelay = false
	r.relaySet = ComputeRelays(makePeers("relay-1", "relay-2", "relay-3"), "leaf-1", r.relayCfg)
	r.mu.Unlock()
	r.lastRelayPush.Store(time.Now().Add(-1 * time.Second).UnixMilli())

	r.checkFallback()

	if !r.fallbackActive.Load() {
		t.Error("fallback should be active after timeout")
	}

	// Simulate successful relay push.
	r.lastRelayPush.Store(time.Now().UnixMilli())
	r.checkFallback()

	if r.fallbackActive.Load() {
		t.Error("fallback should deactivate after successful relay push")
	}
}

func TestFallback_RelayNeverActivates(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{FallbackTimeout: 100 * time.Millisecond})

	// Relays should never activate fallback.
	r.mu.Lock()
	r.isRelay = true
	r.mu.Unlock()
	r.lastRelayPush.Store(time.Now().Add(-1 * time.Hour).UnixMilli())

	r.checkFallback()

	if r.fallbackActive.Load() {
		t.Error("relays should never activate fallback")
	}
}

// ─── Role Transition Tests ──────────────────────────────────────────────────

func TestRoleTransition(t *testing.T) {
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})
	ctx := context.Background()
	clock := hlc.NewClock("remote")

	// Start as relay.
	r.mu.Lock()
	r.isRelay = true
	r.mu.Unlock()

	ts1 := clock.Now()
	entries1 := []*pb.MutationEntry{{
		Seq: 1, Hlc: ts1.String(), Origin: "remote",
		Stmts: `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["rt-1","10.0.0.1","root","s1","active","2025-01-01T00:00:00Z","` + ts1.String() + `"]}]`,
	}}
	if _, err := r.ApplyRemoteMutations(ctx, entries1); err != nil {
		t.Fatalf("apply as relay: %v", err)
	}

	// Should be in mutation_log (relay mode).
	var count int
	c.mu.RLock()
	c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mutation_log").Scan(&count)
	c.mu.RUnlock()
	if count == 0 {
		t.Error("relay should have recorded in mutation_log")
	}

	// Transition to leaf.
	r.mu.Lock()
	r.isRelay = false
	r.mu.Unlock()

	prevCount := count
	ts2 := clock.Now()
	entries2 := []*pb.MutationEntry{{
		Seq: 2, Hlc: ts2.String(), Origin: "remote",
		Stmts: `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["rt-2","10.0.0.2","root","s2","active","2025-01-01T00:00:00Z","` + ts2.String() + `"]}]`,
	}}
	if _, err := r.ApplyRemoteMutations(ctx, entries2); err != nil {
		t.Fatalf("apply as leaf: %v", err)
	}

	// mutation_log count should NOT have increased (leaf mode).
	c.mu.RLock()
	c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mutation_log").Scan(&count)
	c.mu.RUnlock()
	if count != prevCount {
		t.Errorf("leaf should not record in mutation_log: count went from %d to %d", prevCount, count)
	}
}

// ─── No Mutation Loops Test ─────────────────────────────────────────────────

func TestNoMutationLoops(t *testing.T) {
	// Simulate: leaf writes → relay receives → relay records in log →
	// relay's readMutationLog for the original leaf returns nothing.
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	r.mu.Lock()
	r.isRelay = true
	r.mu.Unlock()

	ctx := context.Background()
	clock := hlc.NewClock("leaf-1")

	// Simulate 5 mutations from leaf-1.
	for i := 1; i <= 5; i++ {
		ts := clock.Now()
		entries := []*pb.MutationEntry{{
			Seq: int64(i), Hlc: ts.String(), Origin: "leaf-1",
			Stmts: fmt.Sprintf(`[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["loop-%d","10.0.0.%d","root","s%d","active","2025-01-01T00:00:00Z","%s"]}]`, i, i, i, ts.String()),
		}}
		if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
			t.Fatalf("apply %d: %v", i, err)
		}
	}

	// Reading for leaf-1 should return 0 (all origin=leaf-1, filtered).
	filtered, _, err := r.readMutationLog(ctx, 0, 100, "leaf-1")
	if err != nil {
		t.Fatalf("readMutationLog: %v", err)
	}
	if len(filtered) != 0 {
		t.Errorf("should not echo back to leaf-1, got %d entries", len(filtered))
	}

	// Reading for leaf-2 should return all 5.
	unfiltered, _, err := r.readMutationLog(ctx, 0, 100, "leaf-2")
	if err != nil {
		t.Fatalf("readMutationLog: %v", err)
	}
	if len(unfiltered) != 5 {
		t.Errorf("leaf-2 should see 5 entries, got %d", len(unfiltered))
	}

	// mutation_seen should have exactly 5 entries.
	var count int
	c.mu.RLock()
	c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mutation_seen").Scan(&count)
	c.mu.RUnlock()
	if count != 5 {
		t.Errorf("mutation_seen count = %d, want 5", count)
	}
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func mustTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func makePeers(names ...string) []PeerInfo {
	peers := make([]PeerInfo, len(names))
	for i, n := range names {
		peers[i] = PeerInfo{Name: n, Addr: fmt.Sprintf("10.0.0.%d:7946", i+1)}
	}
	return peers
}

func makePeersN(n int) []PeerInfo {
	peers := make([]PeerInfo, n)
	for i := 0; i < n; i++ {
		peers[i] = PeerInfo{Name: fmt.Sprintf("node-%04d", i+1), Addr: fmt.Sprintf("10.0.0.%d:7946", i+1)}
	}
	return peers
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// Ensure sql is imported (used in test helpers).
var _ = sql.ErrNoRows
