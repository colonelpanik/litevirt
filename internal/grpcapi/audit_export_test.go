package grpcapi

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// TestExportAuditChain_ReplaysInAuthoredOrder pins the export against the
// verifier it exists to stand in for.
//
// docs/audit-log.md tells operators to export to WORM storage so an external
// system can re-verify the chain without contacting the daemon. That only works
// if the file carries the same order the daemon walks and the fields the walk
// uses. The daemon orders a host's sub-chain by seq; an export ordered by stamp
// replays a chain the daemon verifies as intact and reports a hash break on it,
// and an export with no seq column gives the external checker no way to recover
// the right order for itself.
func TestExportAuditChain_ReplaysInAuthoredOrder(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	for _, r := range []struct{ id, ts string }{
		{"row-a", "2026-01-01T00:00:02.000000000Z"},
		{"row-b", "2026-01-01T00:00:01.000000000Z"}, // stamp regressed
	} {
		if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
			ID: r.id, Username: "u", HostName: "node-0",
			Action: "vm.start", Target: "x", Result: "ok", Timestamp: r.ts,
		}); err != nil {
			t.Fatalf("InsertAuditLog %s: %v", r.id, err)
		}
	}

	resp, err := s.ExportAuditChain(ctx, &pb.ExportAuditChainRequest{})
	if err != nil {
		t.Fatalf("ExportAuditChain: %v", err)
	}
	var got struct {
		Rows []map[string]string `json:"rows"`
	}
	if err := json.Unmarshal([]byte(resp.Json), &got); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("exported %d rows, want 2", len(got.Rows))
	}

	if got.Rows[0]["id"] != "row-a" || got.Rows[1]["id"] != "row-b" {
		t.Errorf("exported order is %s,%s — want row-a,row-b (the order the daemon walks)",
			got.Rows[0]["id"], got.Rows[1]["id"])
	}
	for _, field := range []string{"seq", "key_id", "signature"} {
		if _, ok := got.Rows[0][field]; !ok {
			t.Errorf("export omits %q; an external verifier cannot reproduce the daemon's check without it", field)
		}
	}
}

// TestExportAuditChain_CarriesWhatVerifyReads pins the export to the job the
// docs give it: re-verification by an external system, without the daemon.
//
// The hash chain alone does not carry that. VerifyAuditChain reasons over three
// further replicated tables — the signing certificates a key_id resolves
// through, the adoption and retirement events that bound each host's signing
// contract, and the signed chain heads. Without the heads a truncated tail
// replays clean, because a backward-linked chain has nothing pointing forward;
// without the contracts an unsigned row cannot be told from one written before
// the host committed to signing.
//
// An export missing them is not a weaker check, it is a different one that
// happens to say "intact" more often — the failure mode an offline attestation
// must not have.
func TestExportAuditChain_CarriesWhatVerifyReads(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
		ID: "r1", Username: "u", HostName: "node-0",
		Action: "vm.start", Target: "x", Result: "ok",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}

	resp, err := s.ExportAuditChain(ctx, &pb.ExportAuditChainRequest{})
	if err != nil {
		t.Fatalf("ExportAuditChain: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal([]byte(resp.Json), &got); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	for _, key := range []string{"rows", "chain_heads", "signing_keys", "key_lifecycle"} {
		if _, ok := got[key]; !ok {
			t.Errorf("export has no %q; an offline verifier cannot reproduce the daemon's answer without it", key)
		}
	}
}

// TestExportAuditChain_TombstonedEvidenceIsStillExported is the one that keeps
// the export honest.
//
// A chain head is the only construct that detects a truncated tail: the chain
// links backward, so cutting the last N rows leaves every surviving link
// verifying. Deleting the heads is therefore the efficient attack, and the
// daemon's answer is that a tombstone is INERT — VerifyAuditChain does not
// filter deleted_at on any evidence table, which is pinned by
// TestAuditEvidence_ATombstoneIsInert.
//
// An export that honours the tombstone hands that attack back: the daemon
// reports tampering and the offline replay of the same cluster reports clean.
// The export must see exactly what the verifier sees.
func TestExportAuditChain_TombstonedEvidenceIsStillExported(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	if err := s.db.Execute(ctx,
		`INSERT INTO audit_chain_heads
		   (host_name, epoch, seq, head_hash, key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-0', 1, 7, 'deadbeef', 'k1', 'sig', '2026-01-01T00:00:00.000000000Z',
		         '2026-01-01T00:00:00.000000000Z', '2026-01-02T00:00:00.000000000Z')`); err != nil {
		t.Fatalf("insert tombstoned head: %v", err)
	}

	resp, err := s.ExportAuditChain(ctx, &pb.ExportAuditChainRequest{})
	if err != nil {
		t.Fatalf("ExportAuditChain: %v", err)
	}
	var got struct {
		ChainHeads []map[string]string `json:"chain_heads"`
	}
	if err := json.Unmarshal([]byte(resp.Json), &got); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if len(got.ChainHeads) != 1 {
		t.Fatalf("exported %d chain heads, want 1: a tombstone is inert to the verifier "+
			"and must be inert to the export, or deleting a head hides a truncated tail",
			len(got.ChainHeads))
	}
}

// TestExportAuditChain_CarriesTheCA pins the last thing an offline verifier
// needs. VerifyRow requires each signing certificate to chain to the cluster CA,
// which the daemon reads from local disk — so without it a replay can see a
// cert_pem but cannot tell whether it was issued by this cluster, and the
// UnknownKeyID class of finding is unreproducible. The CA certificate is public
// by construction: every node and CLI already holds it.
func TestExportAuditChain_CarriesTheCA(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	s.pkiDir = t.TempDir()
	if err := pki.GenerateCA(filepath.Join(s.pkiDir, "ca.crt"), filepath.Join(s.pkiDir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	resp, err := s.ExportAuditChain(ctx, &pb.ExportAuditChainRequest{})
	if err != nil {
		t.Fatalf("ExportAuditChain: %v", err)
	}
	var got struct {
		CAPem string `json:"ca_pem"`
	}
	if err := json.Unmarshal([]byte(resp.Json), &got); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	// Present is not enough — an empty string would satisfy that and verify
	// nothing. It has to be the certificate.
	block, _ := pem.Decode([]byte(got.CAPem))
	if block == nil {
		t.Fatalf("ca_pem is not PEM: %q", got.CAPem)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Errorf("ca_pem does not parse as a certificate: %v", err)
	}
}

// TestExportAuditChain_PagesWithoutLosingOrDuplicatingRows pins the paging.
//
// The export is one unary message against the daemon's 64 MiB send cap, so a
// chain big enough to be worth attesting to does not fit. The only workaround
// without paging is a since/until window, which produces a fragment whose first
// row links outside it — converting a complete attestation into a useless one
// precisely when it matters.
func TestExportAuditChain_PagesWithoutLosingOrDuplicatingRows(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	const total = 25
	for i := 0; i < total; i++ {
		if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
			ID: fmt.Sprintf("p-%03d", i), Username: "u", HostName: "node-0",
			Action: "vm.start", Target: fmt.Sprintf("vm-%03d", i), Result: "ok",
		}); err != nil {
			t.Fatalf("InsertAuditLog p-%03d: %v", i, err)
		}
	}

	seen := map[string]int{}
	order := []string{}
	cursor := ""
	pages := 0
	for page := 0; ; page++ {
		if page > total+2 {
			t.Fatal("paging did not terminate")
		}
		resp, err := s.ExportAuditChain(ctx, &pb.ExportAuditChainRequest{Cursor: cursor, Limit: 7})
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		var got struct {
			Rows  []map[string]string `json:"rows"`
			CAPem json.RawMessage     `json:"ca_pem"`
			Chain json.RawMessage     `json:"chain_heads"`
		}
		if err := json.Unmarshal([]byte(resp.Json), &got); err != nil {
			t.Fatalf("page %d unmarshal: %v", page, err)
		}
		// Evidence rides on the first page only; later pages are rows.
		if page == 0 && got.Chain == nil {
			t.Error("first page carries no chain_heads")
		}
		if page > 0 && got.Chain != nil {
			t.Errorf("page %d repeats the evidence tables", page)
		}
		for _, r := range got.Rows {
			seen[r["id"]]++
			order = append(order, r["id"])
		}
		pages++
		if resp.NextCursor == "" {
			break
		}
		cursor = resp.NextCursor
	}

	if pages < 2 {
		t.Fatalf("limit=7 over %d rows produced %d page(s): the limit is being ignored, "+
			"so this test would pass without any paging at all", total, pages)
	}
	if len(seen) != total {
		t.Errorf("saw %d distinct rows across pages, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("row %s appeared %d times across pages", id, n)
		}
	}
	for i := 1; i < len(order); i++ {
		if order[i-1] >= order[i] {
			t.Errorf("paged order breaks at %d: %s then %s", i, order[i-1], order[i])
			break
		}
	}
}
