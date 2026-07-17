package corrosion

// StmtShape is the single, fully-validated structural model of a replicated SQL
// statement. It is the ONLY parse of a peer-supplied statement the apply path trusts:
// every consumer (PK extraction, updated_at extraction, tie eligibility, the upsert
// rewrite, the fingerprint, and receive-time authorization) reads this shape, never a
// second ad-hoc string scan. parseStmtShape fully BOUNDS the statement — it locates the
// exact end of the column list, the single VALUES tuple, and any ON CONFLICT clause, and
// rejects anything it cannot bound (a second tuple/statement, RETURNING, SELECT-insert,
// quoted identifiers, receiver-evaluated expressions in INSERT VALUES, an unterminated
// string/paren/comment). It is treated as a security boundary and is fuzzed; it must
// never panic and must be deterministic.
//
// Anything parseStmtShape rejects is an "invalid" statement — the caller fails closed
// (WAL back-pressure / AE keep-local), never a best-effort apply.

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidStmt marks a statement that could not be fully, unambiguously bounded and
// validated. The apply path treats it as fail-closed.
var ErrInvalidStmt = errors.New("corrosion: statement not structurally valid for replication apply")

func invalidf(format string, a ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidStmt, fmt.Sprintf(format, a...))
}

// StmtKind is the top-level statement kind.
type StmtKind int

const (
	KindOther StmtKind = iota // zero value only; a successful parse never yields this (unmodelled kinds fail closed)
	KindInsert
	KindUpdate
	KindDelete
)

func (k StmtKind) String() string {
	switch k {
	case KindInsert:
		return "insert"
	case KindUpdate:
		return "update"
	case KindDelete:
		return "delete"
	default:
		return "other"
	}
}

// LiteralKind classifies a canonical, receiver-reproducible literal. Only these three
// literal forms are permitted in an INSERT VALUES tuple; a receiver-evaluated expression
// (e.g. datetime('now')) or any other sqlTok there makes the statement invalid.
type LiteralKind int

const (
	LitNone   LiteralKind = iota // not a literal (the cell is a bound parameter)
	LitNull                      // NULL
	LitInt                       // integer constant
	LitString                    // fixed string constant
)

// LiteralValue carries the EXACT literal value (not just its kind) so distinct constants
// never collide in the fingerprint or in full-image reasoning: 0 != 1, ” != 'deleted'.
type LiteralValue struct {
	Kind LiteralKind
	Int  int64
	Str  string
}

func (lv LiteralValue) canon() string {
	switch lv.Kind {
	case LitNull:
		return "NULL"
	case LitInt:
		return fmt.Sprintf("i%d", lv.Int)
	case LitString:
		return "s" + fmt.Sprintf("%d:", len(lv.Str)) + lv.Str // length-prefixed, no aliasing
	default:
		return "?" // a bound parameter
	}
}

// ValueShape describes one cell of an INSERT VALUES tuple: either a bound parameter (by
// positional index) or a canonical literal. Exactly one applies.
type ValueShape struct {
	ParamIndex int          // >=0 ⇒ the s.Params index bound here; -1 ⇒ a literal
	Literal    LiteralValue // valid only when ParamIndex < 0
}

func (v ValueShape) isParam() bool { return v.ParamIndex >= 0 }

// NormalizedExpr is the canonical form of an UPDATE SET / DO UPDATE right-hand side
// (a bound param, a literal, a column reference, an increment, COALESCE/NULLIF, or another
// deterministic function). Text is a typed, length-prefixed canonical encoding of the token
// sequence (see canonToken); ParamIdx lists the bound-parameter indices it consumes, left to
// right; ExcludedRef is the lower-cased column name when the RHS is exactly `excluded.<col>`
// (else "").
//
// SCOPE (stmtshape/v1): this is an OPAQUE canonical token encoding for EXACT fingerprint
// matching — it is deliberately NOT a typed expression AST. That is sufficient for the
// compatibility ledger (exact match) and for full-image detection (via ExcludedRef), but
// later phases that need real structure (dynamic parameterized policies, reference
// validation, per-row-LWW expansion) must use finite, structurally-generated policy
// expansions rather than interpreting this text. Constructs the flat model would mis-handle
// (e.g. BETWEEN, whose AND is not a boolean separator) are rejected at parse time.
type NormalizedExpr struct {
	Text        string
	ParamIdx    []int
	ExcludedRef string // lower-cased column when RHS is exactly `excluded.<col>`; else ""
	SoleParam   int    // the param index when RHS is exactly a single `?`; else -1
}

// AssignmentShape is one UPDATE `SET col = <expr>` item. When the RHS is a single bound
// parameter, Expr.Text is "?" and Expr.ParamIdx has one entry.
type AssignmentShape struct {
	Column string
	Expr   NormalizedExpr
}

// ConflictClause is a fully-bounded `ON CONFLICT (targets) DO {NOTHING|UPDATE SET ...}`.
type ConflictClause struct {
	Targets     []string          // conflict-target columns (may be empty for a bare ON CONFLICT)
	DoNothing   bool              // true ⇒ DO NOTHING
	Assignments []AssignmentShape // DO UPDATE SET assignments (empty when DoNothing)
	Where       PredicateTree     // optional guard on DO UPDATE (a conditional upsert); zero if none
	IsFullImage bool              // every supplied non-PK insert column is assigned c = excluded.c
}

// PredicateTree is the parsed WHERE clause as a canonical tree.
type PredicateTree struct {
	Node *predNode // nil ⇒ no WHERE clause
}

// predNode is a boolean tree: an AND/OR of children, or a leaf comparison/test.
type predNode struct {
	op       string      // "AND", "OR", or "" for a leaf
	children []*predNode // for AND/OR
	negated  bool        // NOT applied to this node
	// leaf fields (op == ""):
	col      string // bare left-hand column when the leaf is exactly `ident = ?`; else ""
	cmp      string // "=" for the recognized pk-identity leaf; else ""
	rhsParam int    // >=0 ⇒ the bound param index the leaf's single `?` binds; else -1
	text     string // canonical rendering of the leaf's tokens (for the fingerprint)
	params   []int  // bound-param indices the leaf consumes, in order
}

// StmtShape is the validated structural model. Fields not relevant to Kind are zero.
type StmtShape struct {
	Kind  StmtKind
	Table string

	// INSERT
	InsertCols  []string
	InsertVals  []ValueShape
	LeadingAlgo string // "", "OR REPLACE", "OR IGNORE"
	// LeadingAlgoStart/End are the byte span of the "OR REPLACE"/"OR IGNORE" keywords in
	// the ORIGINAL sql, so the apply path can splice them out to normalize to a plain
	// INSERT (stripLeadingAlgo) without a substring search. Both 0 when no algo is present.
	LeadingAlgoStart int
	LeadingAlgoEnd   int
	OnConflict       *ConflictClause

	// UPDATE
	SetAssigns []AssignmentShape

	// UPDATE / DELETE
	Where PredicateTree

	// ParamCount is the total number of bound '?' parameters in the statement. The apply
	// path MUST verify ParamCount == len(Statement.Params) before reading any parameter by
	// index — a valid template with truncated params would otherwise index out of range.
	ParamCount int

	// Row-identity (LWW) mapping, resolved against the table's declared PK columns.
	// HasFullPKIdentity: for INSERT, every PK column is present in InsertCols and bound
	// to a parameter; for UPDATE, every PK column appears as a top-level `pk = ?` conjunct
	// in WHERE. PKParamIdx/UpdatedAtParamIdx are the corresponding s.Params indices, or
	// nil/-1 when not resolvable as direct bound parameters.
	HasFullPKIdentity bool
	PKParamIdx        []int
	UpdatedAtParamIdx int
}

// ValidateParamArity checks that the number of bound parameters supplied with the statement
// matches the count the parsed shape requires. The apply path MUST call this (or otherwise
// verify equality) before reading any parameter by index — a valid template paired with a
// truncated Statement.Params would otherwise index out of range or bind the wrong value.
func (sh StmtShape) ValidateParamArity(nParams int) error {
	if nParams != sh.ParamCount {
		return invalidf("parameter arity mismatch: statement needs %d, got %d", sh.ParamCount, nParams)
	}
	return nil
}

// parseStmtShape is the single entry point. pkCols is the table's declared primary key
// (from tablePrimaryKeys); it is used only to resolve the row-identity mapping, never to
// authorize. On any structural ambiguity it returns an error wrapping ErrInvalidStmt.
func parseStmtShape(sql string, pkCols []string) (StmtShape, error) {
	toks, err := lex(sql)
	if err != nil {
		return StmtShape{}, err
	}
	p := &sqlParser{toks: toks}
	sh, err := p.parseStatement(pkCols)
	if err != nil {
		return StmtShape{}, err
	}
	// Exactly one statement: an optional single trailing ';' then EOF.
	if p.peek().kind == tokSemi {
		p.next()
	}
	if p.peek().kind != tokEOF {
		return StmtShape{}, invalidf("trailing content after statement (%q)", p.peek().text)
	}
	sh.ParamCount = p.paramCount
	return sh, nil
}

// ---- parser ----

type sqlParser struct {
	toks       []sqlTok
	pos        int
	paramCount int // running count of '?' consumed → global positional param index
}

// takeParam consumes the current '?' sqlTok and returns its global positional index
// (the index into s.Params it binds), matching database/sql left-to-right binding.
func (p *sqlParser) takeParam() int {
	idx := p.paramCount
	p.paramCount++
	p.next()
	return idx
}

func (p *sqlParser) peek() sqlTok {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return sqlTok{kind: tokEOF}
}

func (p *sqlParser) next() sqlTok {
	t := p.peek()
	if p.pos < len(p.toks) {
		p.pos++
	}
	return t
}

func (p *sqlParser) acceptKeyword(kw string) bool {
	t := p.peek()
	if t.kind == tokIdent && strings.EqualFold(t.text, kw) {
		p.next()
		return true
	}
	return false
}

func (p *sqlParser) expectKeyword(kw string) error {
	if !p.acceptKeyword(kw) {
		return invalidf("expected %q, got %q", kw, p.peek().text)
	}
	return nil
}

func (p *sqlParser) parseStatement(pkCols []string) (StmtShape, error) {
	t := p.peek()
	if t.kind != tokIdent {
		return StmtShape{}, invalidf("statement does not begin with a keyword (%q)", t.text)
	}
	switch {
	case strings.EqualFold(t.text, "INSERT"):
		return p.parseInsert(pkCols)
	case strings.EqualFold(t.text, "UPDATE"):
		return p.parseUpdate(pkCols)
	case strings.EqualFold(t.text, "DELETE"):
		return p.parseDelete(pkCols)
	default:
		// A statement kind we do not model (SELECT/CTE/DDL/…). We never authorize it, so
		// fail closed directly rather than returning an observable KindOther.
		return StmtShape{}, invalidf("unsupported statement kind %q", t.text)
	}
}

// plainIdent returns the identifier text of the current token, or an error if it is not a
// bare (unquoted, undotted) identifier. Quoted identifiers and schema-qualified names are
// rejected — no replicated builder uses them, and permitting them widens the parser's
// trusted surface.
func (p *sqlParser) plainIdent(what string) (string, error) {
	t := p.peek()
	if t.kind == tokQuotedIdent {
		return "", invalidf("%s must be a bare identifier, got quoted %q", what, t.text)
	}
	if t.kind != tokIdent {
		return "", invalidf("%s expected an identifier, got %q", what, t.text)
	}
	if !isPlainIdent(t.text) {
		return "", invalidf("%s is not a plain identifier: %q", what, t.text)
	}
	p.next()
	// Reject a schema-qualified follow-on (ident '.' ident).
	if p.peek().kind == tokDot {
		return "", invalidf("%s must not be schema-qualified", what)
	}
	return t.text, nil
}

// isPlainIdent reports whether s is a bare SQL identifier: ^[A-Za-z_][A-Za-z0-9_]*$.
// Keyword-vs-identifier is resolved positionally by the parser, so a plain identifier that
// happens to spell a keyword is still a valid identifier in an identifier position.
func isPlainIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
