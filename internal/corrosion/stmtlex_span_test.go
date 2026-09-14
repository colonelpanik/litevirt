package corrosion

import "testing"

// The parser hands the apply path byte offsets, not tokens: applyBulkPerRowLWW
// rebuilds a per-row UPDATE from sql[SetClauseStart:SetClauseEnd]. A token whose
// recorded span is shorter than the text it consumed therefore truncates that
// slice, and the rebuilt statement is invalid SQL — which fails the whole batch
// and stalls the replication watermark for every table, not just this one.
//
// Asserted on the extracted SET clause rather than on the offset, because the
// offset is only wrong in so far as it cuts the clause short.
func TestStmtShape_SetClauseSurvivesATrailingLiteral(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
		want string
	}{
		{
			// The statement that wedges replication in production:
			// SoftDeleteLBBackends, registered DispBulkUpdate/CatPerRowLWW.
			name: "trailing integer literal",
			sql:  `UPDATE lb_backends SET deleted_at = ?, updated_at = ?, enabled = 0 WHERE lb_name = ?`,
			want: `deleted_at = ?, updated_at = ?, enabled = 0`,
		},
		{
			name: "trailing string literal",
			sql:  `UPDATE t SET a = ?, b = 'x' WHERE k = ?`,
			want: `a = ?, b = 'x'`,
		},
		{
			name: "trailing string literal with an escaped quote",
			sql:  `UPDATE t SET a = 'it''s' WHERE k = ?`,
			want: `a = 'it''s'`,
		},
		{
			name: "trailing param is unaffected",
			sql:  `UPDATE t SET a = ?, b = ? WHERE k = ?`,
			want: `a = ?, b = ?`,
		},
		{
			// Comment-bearing replicated SQL is a first-class case here — see
			// apply_comment_injection_test.go, which replays one through
			// ApplyRemoteMutations. The comment is inside the span, so it is
			// re-executed verbatim in the rebuilt per-row UPDATE.
			name: "block comment inside the SET clause",
			sql:  `UPDATE t SET a = ?, /* keep */ b = 0 WHERE k = ?`,
			want: `a = ?, /* keep */ b = 0`,
		},
		{
			name: "line comment inside the SET clause",
			sql:  "UPDATE t SET a = ?, -- keep\n b = 0 WHERE k = ?",
			want: "a = ?, -- keep\n b = 0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sh, err := parseStmtShape(tc.sql, nil)
			if err != nil {
				t.Fatalf("parseStmtShape: %v", err)
			}
			got := tc.sql[sh.SetClauseStart:sh.SetClauseEnd]
			if got != tc.want {
				t.Errorf("SET clause = %q, want %q\n  rebuilt statement would be: %s",
					got, tc.want, "UPDATE t SET "+got+" WHERE pk = ?")
			}
		})
	}
}

// Token spans must TILE the input: between one token's end and the next one's
// start there can be nothing that carries meaning. That is the property the
// offsets in StmtShape rest on, and it is strictly stronger than "the span is
// non-empty" — it catches a span that is merely one byte short, which is exactly
// how a quoted identifier or a string literal loses its closing delimiter.
//
// "Nothing that carries meaning" is asserted by re-lexing the gap rather than by
// trimming whitespace. An earlier version of this test required gaps to be pure
// whitespace, which is FALSE: the lexer skips -- and /* */ comments without
// emitting a token, so a comment is a legitimate gap. That version passed only
// because its input happened to be comment-free — a vacuous test of exactly the
// kind this file exists to prevent.
//
// Stated once, over every token kind the lexer emits, so a new kind cannot
// reintroduce the bug by deriving its span from .text.
func TestLex_TokenSpansTileTheInput(t *testing.T) {
	const sql = `UPDATE "q" SET a = 0, /* c1 */ b = 'x', c = ?, d = e.f, g = 'it''s' ` +
		"-- c2\n" +
		`WHERE h <= 1 AND i >= 2 AND j <> 3 AND k != 4 AND l || m = -5;`

	toks, err := lex(sql)
	if err != nil {
		t.Fatalf("lex: %v", err)
	}

	// gapIsInert reports whether the text between two tokens carries no token of
	// its own. Re-lexing is used instead of a whitespace/comment matcher so this
	// test cannot drift from the lexer's own idea of what it skips.
	gapIsInert := func(gap string) bool {
		g, err := lex(gap)
		if err != nil {
			return false
		}
		for _, tk := range g {
			if tk.kind != tokEOF {
				return false
			}
		}
		return true
	}

	prevEnd := 0
	for _, tk := range toks {
		if tk.kind == tokEOF {
			break
		}
		if tk.pos < prevEnd || tk.end > len(sql) || tk.end <= tk.pos {
			t.Fatalf("token kind=%d span [%d,%d) is not a forward range inside a %d-byte input (previous ended at %d)",
				tk.kind, tk.pos, tk.end, len(sql), prevEnd)
		}
		if gap := sql[prevEnd:tk.pos]; !gapIsInert(gap) {
			t.Errorf("token kind=%d at %d left %q unconsumed before it; the previous token's span stopped short of the text it read",
				tk.kind, tk.pos, gap)
		}
		prevEnd = tk.end
	}
	if tail := sql[prevEnd:]; !gapIsInert(tail) {
		t.Errorf("%q left unconsumed after the last token", tail)
	}
}
