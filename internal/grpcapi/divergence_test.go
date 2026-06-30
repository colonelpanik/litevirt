package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func rd(table, pk string, class corrosion.DivergenceClass, per map[string]corrosion.RowMeta) corrosion.RowDivergence {
	return corrosion.RowDivergence{Table: table, PKLabel: pk, Class: class, PerNode: per}
}

// Only divergences present in BOTH samples with unchanged hashes are reported; a
// stable different_updated_at becomes stuck_different.
func TestReconcileSamples(t *testing.T) {
	per := map[string]corrosion.RowMeta{
		"a": {UpdatedAt: "t1", RowHash: "h1"},
		"b": {UpdatedAt: "t2", RowHash: "h2"},
	}
	d1 := map[string]corrosion.RowDivergence{
		"vms\x00vm1": rd("vms", "vm1", corrosion.ClassDifferentUpdatedAt, per),
		"vms\x00vm2": rd("vms", "vm2", corrosion.ClassEqualUpdatedAtDifferentContent, per),
	}
	// s2: vm1 stable (same hashes) → stuck_different; vm2 changed (in-flight) → dropped;
	// vm3 only-in-s2 → dropped.
	perChanged := map[string]corrosion.RowMeta{"a": {RowHash: "h1"}, "b": {RowHash: "hX"}}
	d2 := map[string]corrosion.RowDivergence{
		"vms\x00vm1": rd("vms", "vm1", corrosion.ClassDifferentUpdatedAt, per),
		"vms\x00vm2": rd("vms", "vm2", corrosion.ClassEqualUpdatedAtDifferentContent, perChanged),
		"vms\x00vm3": rd("vms", "vm3", corrosion.ClassEqualUpdatedAtDifferentContent, per),
	}
	rows := reconcileSamples(d1, d2)
	if len(rows) != 1 {
		t.Fatalf("want 1 stable divergence, got %d: %+v", len(rows), rows)
	}
	if rows[0].GetPk() != "vm1" || rows[0].GetClass() != string(corrosion.ClassStuckDifferent) {
		t.Fatalf("want vm1 stuck_different, got %s/%s", rows[0].GetPk(), rows[0].GetClass())
	}
}

// ScanSensitiveDivergence is peer-mTLS only and returns HMAC'd rows for the
// sensitive allowlist.
func TestScanSensitiveDivergence_PeerOnlyAndHMAC(t *testing.T) {
	s := newPeerAuthServer(t)
	ctx := context.Background()
	now := s.db.NowTS()
	if err := s.db.Execute(ctx,
		`INSERT INTO recovery_codes (username, code_hash, set_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"alice", "$2a$10$abcdefghijklmnopqrstuv", "set1", now, now); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")

	// Non-peer (operator) caller → rejected.
	if _, err := s.ScanSensitiveDivergence(adminCtx(), &pb.ScanSensitiveRequest{Sender: "peer-1", ScanKey: key}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator ctx: want PermissionDenied, got %v", err)
	}
	// Peer whose CN != sender → rejected.
	if _, err := s.ScanSensitiveDivergence(mtlsCtx("other"), &pb.ScanSensitiveRequest{Sender: "peer-1", ScanKey: key}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("CN mismatch: want PermissionDenied, got %v", err)
	}
	// Valid peer → HMAC rows, no plaintext.
	resp, err := s.ScanSensitiveDivergence(mtlsCtx("peer-1"), &pb.ScanSensitiveRequest{
		Sender: "peer-1", ScanKey: key, Tables: []string{"recovery_codes"},
	})
	if err != nil {
		t.Fatalf("ScanSensitiveDivergence: %v", err)
	}
	if len(resp.GetRows()) != 1 {
		t.Fatalf("want 1 row, got %d", len(resp.GetRows()))
	}
	r := resp.GetRows()[0]
	if r.GetTable() != "recovery_codes" || r.GetPkLabel() == "" || r.GetRowHash() == "" {
		t.Fatalf("bad row: %+v", r)
	}
	if containsStr(r.GetPkLabel(), "alice") || containsStr(r.GetPkLabel(), "$2a$") {
		t.Fatalf("HMAC leaked plaintext: %q", r.GetPkLabel())
	}
}

// DiagnoseDivergence is admin-gated and, even with a single reachable node, runs
// the cluster-wide semantic invariants (catching a converged-but-illegal state).
func TestDiagnoseDivergence_AdminGateAndSemantic(t *testing.T) {
	old := divergenceResampleDelay
	divergenceResampleDelay = 0
	defer func() { divergenceResampleDelay = old }()

	s := newPeerAuthServer(t) // hostName "self", knows host "peer-1" (active, unreachable in test)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "self", Address: "127.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost self: %v", err)
	}
	// The converged-but-illegal state: the same container name live on two hosts.
	for _, h := range []string{"host-a", "host-b"} {
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{HostName: h, Name: "web", State: "running"}); err != nil {
			t.Fatalf("UpsertContainer %s: %v", h, err)
		}
	}

	// Non-admin → denied.
	if _, err := s.DiagnoseDivergence(viewerCtx(), &pb.DiagnoseDivergenceRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer: want PermissionDenied, got %v", err)
	}
	// Admin → report with the duplicate-container semantic violation.
	rep, err := s.DiagnoseDivergence(adminCtx(), &pb.DiagnoseDivergenceRequest{})
	if err != nil {
		t.Fatalf("DiagnoseDivergence: %v", err)
	}
	var sawDup bool
	for _, v := range rep.GetViolations() {
		if v.GetKind() == "duplicate_live_container" && v.GetKey() == "web" {
			sawDup = true
		}
	}
	if !sawDup {
		t.Fatalf("expected duplicate_live_container violation, got %+v", rep.GetViolations())
	}
}

// An unknown --table value is rejected, not silently scanned-as-nothing (which
// would read as a clean scan — false reassurance for a diagnostic).
func TestDiagnoseDivergence_RejectsUnknownTable(t *testing.T) {
	s := newPeerAuthServer(t)
	_, err := s.DiagnoseDivergence(adminCtx(), &pb.DiagnoseDivergenceRequest{Tables: []string{"recovery_code"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for an unknown table, got %v", err)
	}
}

// A sensitive table named WITHOUT --include-sensitive is rejected (it would
// otherwise resolve to no scanned table and read as clean).
func TestDiagnoseDivergence_RejectsSensitiveTableWithoutFlag(t *testing.T) {
	old := divergenceResampleDelay
	divergenceResampleDelay = 0
	defer func() { divergenceResampleDelay = old }()
	s := newPeerAuthServer(t)
	_, err := s.DiagnoseDivergence(adminCtx(), &pb.DiagnoseDivergenceRequest{Tables: []string{"recovery_codes"}})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for a sensitive table without --include-sensitive, got %v", err)
	}
	// With the flag, it's accepted.
	if _, err := s.DiagnoseDivergence(adminCtx(), &pb.DiagnoseDivergenceRequest{
		Tables: []string{"recovery_codes"}, IncludeSensitive: true,
	}); err != nil {
		t.Fatalf("recovery_codes + --include-sensitive should be accepted, got %v", err)
	}
}

// --include-sensitive with only an operator-safe table in scope must NOT mark
// every host sensitive-unreachable (no sensitive table was actually scanned).
func TestDiagnoseDivergence_NoSensitiveTableNoPartial(t *testing.T) {
	old := divergenceResampleDelay
	divergenceResampleDelay = 0
	defer func() { divergenceResampleDelay = old }()

	s := newPeerAuthServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "self", Address: "127.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	rep, err := s.DiagnoseDivergence(adminCtx(), &pb.DiagnoseDivergenceRequest{
		IncludeSensitive: true, Tables: []string{"vms"}, // no sensitive table in scope
	})
	if err != nil {
		t.Fatalf("DiagnoseDivergence: %v", err)
	}
	if len(rep.GetSensitiveUnreachable()) != 0 {
		t.Fatalf("no sensitive table scanned → sensitive_unreachable must be empty, got %v", rep.GetSensitiveUnreachable())
	}
}

// A semantic violation present in only ONE sample (a migration in flight) is NOT
// reported; one present in BOTH is.
func TestReconcileViolations(t *testing.T) {
	dupA := []corrosion.SemanticViolation{{Kind: "duplicate_live_container", Key: "web", Hosts: []string{"host-a", "host-b"}}}
	// s1 has the duplicate, s2 doesn't (fixed / migration settled) → not reported.
	if got := reconcileViolations(dupA, nil); len(got) != 0 {
		t.Fatalf("transient violation (only s1) must not be reported, got %+v", got)
	}
	if got := reconcileViolations(nil, dupA); len(got) != 0 {
		t.Fatalf("transient violation (only s2) must not be reported, got %+v", got)
	}
	// Present in both with the same identity → reported.
	if got := reconcileViolations(dupA, dupA); len(got) != 1 || got[0].GetKey() != "web" {
		t.Fatalf("stable violation must be reported, got %+v", got)
	}
	// Same kind/key but DIFFERENT hosts across samples → not stable.
	dupB := []corrosion.SemanticViolation{{Kind: "duplicate_live_container", Key: "web", Hosts: []string{"host-a", "host-c"}}}
	if got := reconcileViolations(dupA, dupB); len(got) != 0 {
		t.Fatalf("host-set changed between samples → not stable, got %+v", got)
	}
}

// With --include-sensitive, a host whose sensitive lane fails is surfaced as
// sensitive_unreachable (partial), never silently treated as clean.
func TestDiagnoseDivergence_SensitivePartialSurfaced(t *testing.T) {
	old := divergenceResampleDelay
	divergenceResampleDelay = 0
	defer func() { divergenceResampleDelay = old }()

	s := newPeerAuthServer(t) // self + active host "peer-1" (unreachable in test)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "self", Address: "127.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost self: %v", err)
	}
	rep, err := s.DiagnoseDivergence(adminCtx(), &pb.DiagnoseDivergenceRequest{IncludeSensitive: true})
	if err != nil {
		t.Fatalf("DiagnoseDivergence: %v", err)
	}
	// peer-1 is unreachable for BOTH lanes → in nodes_unreachable AND sensitive_unreachable.
	if !hostListHas(rep.GetNodesUnreachable(), "peer-1") {
		t.Fatalf("peer-1 should be nodes_unreachable, got %v", rep.GetNodesUnreachable())
	}
	if !hostListHas(rep.GetSensitiveUnreachable(), "peer-1") {
		t.Fatalf("peer-1 should be sensitive_unreachable, got %v", rep.GetSensitiveUnreachable())
	}
}

func hostListHas(hs []string, want string) bool {
	for _, h := range hs {
		if h == want {
			return true
		}
	}
	return false
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
