package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auditexport"
)

// bigChain serves pages of fat rows, `pages` of them, so the whole chain is
// several times auditexport.MaxAssembledBytes once that is shrunk.
func bigChain(pages int) auditexport.FetchPage {
	fat := strings.Repeat("x", 2<<10)
	return func(_ context.Context, cursor string) (*pb.ExportAuditChainResponse, error) {
		n := 0
		if cursor != "" {
			fmt.Sscanf(cursor, "%d", &n)
		}
		resp := &pb.ExportAuditChainResponse{
			Json:     fmt.Sprintf(`{"rows":[{"id":"r%d","detail":"%s"}]}`, n, fat),
			RowCount: 1,
		}
		if n+1 < pages {
			resp.NextCursor = fmt.Sprint(n + 1)
		}
		return resp, nil
	}
}

// TestAuditExport_TheCLIHasNoInMemoryCap: the in-memory cap protects the
// DAEMON's heap, where the web UI and REST gateway assemble the chain, and its
// refusal tells the operator to use `lv audit export --out` instead. That
// remedy has to work: the CLI is a separate process with a file to write, so it
// spools to disk rather than holding the chain, and a chain over the cap
// exports in full.
//
// Mutation: assemble in memory in writeAuditExport (the old code) — the export
// is refused as too large and this goes red.
func TestAuditExport_TheCLIHasNoInMemoryCap(t *testing.T) {
	prev := auditexport.MaxAssembledBytes
	auditexport.MaxAssembledBytes = 8 << 10
	t.Cleanup(func() { auditexport.MaxAssembledBytes = prev })

	out := filepath.Join(t.TempDir(), "audit.json")
	if err := writeAuditExport(context.Background(), bigChain(20), out, false, io.Discard, io.Discard); err != nil {
		t.Fatalf("lv audit export --out refused a chain over the daemon's in-memory cap: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rows []map[string]string `json:"rows"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("the export is not one JSON document: %v", err)
	}
	if len(doc.Rows) != 20 || doc.Rows[19]["id"] != "r19" {
		t.Fatalf("exported %d rows, want all 20 in order", len(doc.Rows))
	}
	if fi, err := os.Stat(out); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("export file mode = %v (%v), want 0600", fi.Mode().Perm(), err)
	}

	var stdout bytes.Buffer
	if err := writeAuditExport(context.Background(), bigChain(20), "-", false, &stdout, io.Discard); err != nil {
		t.Fatalf("lv audit export to stdout refused a chain over the daemon's in-memory cap: %v", err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil || len(doc.Rows) != 20 {
		t.Fatalf("stdout export: %d rows, %v", len(doc.Rows), err)
	}
}

// --allow-gaps reaches the walk: a chain with a reported seq gap is refused by
// default and exported, with the gap listed, under the flag.
//
// Mutation: drop allowGaps on the way to auditexport.Write — the flagged
// export is refused and this goes red.
func TestAuditExport_AllowGapsExportsAGappedChain(t *testing.T) {
	gapped := func(_ context.Context, _ string) (*pb.ExportAuditChainResponse, error) {
		return &pb.ExportAuditChainResponse{
			Json: `{"rows":[{"id":"a","host_name":"kvm001","seq":"1"},{"id":"c","host_name":"kvm001","seq":"3"}],
			        "seq_gaps":[{"host_name":"kvm001","missing_from":"2","missing_to":"2"}]}`,
			RowCount: 2,
		}, nil
	}
	out := filepath.Join(t.TempDir(), "audit.json")
	if err := writeAuditExport(context.Background(), gapped, out, false, io.Discard, io.Discard); err == nil {
		t.Fatal("a gapped chain was exported without --allow-gaps")
	}
	if err := writeAuditExport(context.Background(), gapped, out, true, io.Discard, io.Discard); err != nil {
		t.Fatalf("--allow-gaps export: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"seq_gaps":[{"host_name":"kvm001"`) {
		t.Fatalf("the gapped export does not list its gap: %s", b)
	}
	if newAuditExportCmd().Flags().Lookup("allow-gaps") == nil {
		t.Fatal("lv audit export has no --allow-gaps flag")
	}
}

// A refused export leaves nothing behind: spooling to disk must not turn a
// refusal into a truncated file at --out, or a partial document on stdout.
//
// Mutation: write the spool to --out directly — the refused export leaves a
// file and this goes red.
func TestAuditExport_ARefusalWritesNothing(t *testing.T) {
	refused := func(_ context.Context, cursor string) (*pb.ExportAuditChainResponse, error) {
		if cursor == "" {
			return &pb.ExportAuditChainResponse{Json: `{"rows":[{"id":"a"}]}`, RowCount: 1, NextCursor: "x"}, nil
		}
		return &pb.ExportAuditChainResponse{Json: `{"rows":[{"id":"b"}]}`, RowCount: 1, NextCursor: "x"}, nil
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "audit.json")
	if err := writeAuditExport(context.Background(), refused, out, false, io.Discard, io.Discard); err == nil {
		t.Fatal("a server repeating its cursor was exported")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("a refused export left %d file(s) in the output directory, first %q", len(ents), ents[0].Name())
	}
	var stdout bytes.Buffer
	if err := writeAuditExport(context.Background(), refused, "", false, &stdout, io.Discard); err == nil {
		t.Fatal("a server repeating its cursor was exported")
	}
	if stdout.Len() != 0 {
		t.Fatalf("a refused export wrote %d bytes to stdout", stdout.Len())
	}
}
