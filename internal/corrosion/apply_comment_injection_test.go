package corrosion

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestApplyRemoteMutations_CommentInjectedTableCannotMisdirectLWW (review 1): a fingerprint is
// comment-insensitive, so an OLDER incoming write can carry a comment that names a DIFFERENT table
// than the one the structural parser (and the fingerprint) actually target. The apply path must key
// LWW off the STRUCTURAL table, not a string scan — otherwise it would read the wrong table's PK
// (here hosts, which shares the 'name' PK), see no row, and blind-overwrite the newer image.
func TestApplyRemoteMutations_CommentInjectedTableCannotMisdirectLWW(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	// Receiver already holds a NEWER images row.
	if err := c.Execute(ctx,
		`INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"img1", "new-format", "", "", 1, "2020-01-01T00:00:00Z", "3000000000000-0000-n2"); err != nil {
		t.Fatalf("seed newer image: %v", err)
	}

	// An OLDER incoming write disguised with a comment naming hosts. The lexer strips the comment; the
	// structural parser + fingerprint see images (a registered builder shape).
	inj := `INSERT /* INTO hosts */ OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	stmts := fmt.Sprintf(`[{"SQL":%q,"Params":["img1","old-format","","",1,"2020-01-01T00:00:00Z","1000000000000-0000-n1"]}]`, inj)
	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: "1000000000000-0000-n1", Origin: "peer", Stmts: stmts}}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// The NEWER receiver image must survive (LWW keyed on images.name, not hosts.name).
	rows, _ := c.Query(ctx, "SELECT format FROM images WHERE name = ?", "img1")
	if len(rows) != 1 || rows[0].String("format") != "new-format" {
		t.Fatalf("newer image was overwritten by an older comment-injected write: %v", rows)
	}
	// And nothing leaked into hosts.
	if h, _ := c.Query(ctx, "SELECT name FROM hosts WHERE name = ?", "img1"); len(h) != 0 {
		t.Fatal("comment-injected statement must not touch hosts")
	}
}

// TestEntryTouchesCustomMerge_CommentCannotHideProofTable (review 1, proof-filter): a comment cannot
// disguise a custom-merge (proof) statement so the drop filter misses it — the structural parser
// must still resolve runtime_action_proofs.
func TestEntryTouchesCustomMerge_CommentCannotHideProofTable(t *testing.T) {
	inj := `INSERT /* INTO operations */ INTO runtime_action_proofs (id, status) VALUES (?, ?)`
	stmts := fmt.Sprintf(`[{"SQL":%q,"Params":["p1","prepared"]}]`, inj)
	if !entryTouchesCustomMerge(stmts) {
		t.Fatal("a comment-injected custom-merge (proof) statement must still be detected and dropped")
	}
	// A genuine non-custom-merge statement is not falsely flagged.
	ok := `[{"SQL":"INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["i","f","","",1,"t","t"]}]`
	if entryTouchesCustomMerge(ok) {
		t.Fatal("a non-custom-merge statement must not be flagged")
	}
}
