package corrosion

// Per-kind parsers producing a fully-bounded StmtShape. All parameter indices are global
// (lex order across the whole statement), matching database/sql positional binding.

import (
	"strconv"
	"strings"
)

// ---- shared helpers ----

// parseIdentList parses `( ident, ident, ... )` of bare identifiers: non-empty, unique.
func (p *sqlParser) parseIdentList(what string) ([]string, error) {
	if p.peek().kind != tokLParen {
		return nil, invalidf("expected '(' for %s list", what)
	}
	p.next()
	var out []string
	seen := map[string]bool{}
	for {
		id, err := p.plainIdent(what)
		if err != nil {
			return nil, err
		}
		lc := strings.ToLower(id)
		if seen[lc] {
			return nil, invalidf("duplicate %s %q", what, id)
		}
		seen[lc] = true
		out = append(out, id)
		if p.peek().kind == tokComma {
			p.next()
			continue
		}
		break
	}
	if p.peek().kind != tokRParen {
		return nil, invalidf("unterminated %s list", what)
	}
	p.next()
	if len(out) == 0 {
		return nil, invalidf("empty %s list", what)
	}
	return out, nil
}

// ---- INSERT ----

func (p *sqlParser) parseInsert(pkCols []string) (StmtShape, error) {
	sh := StmtShape{Kind: KindInsert, UpdatedAtParamIdx: -1}
	insTok := p.next() // INSERT
	sh.InsertKeywordEnd = insTok.pos + len(insTok.text)
	if p.peek().kind == tokIdent && strings.EqualFold(p.peek().text, "OR") {
		orTok := p.next() // OR
		algoTok := p.peek()
		switch {
		case p.acceptKeyword("REPLACE"):
			sh.LeadingAlgo = "OR REPLACE"
		case p.acceptKeyword("IGNORE"):
			sh.LeadingAlgo = "OR IGNORE"
		default:
			return sh, invalidf("unsupported INSERT OR <algo> (%q)", p.peek().text)
		}
		// Record the exact byte span of the algorithm keywords so the apply path can
		// splice them out (stripLeadingAlgo) rather than string-searching.
		sh.LeadingAlgoStart = orTok.pos
		sh.LeadingAlgoEnd = algoTok.pos + len(algoTok.text)
	}
	if err := p.expectKeyword("INTO"); err != nil {
		return sh, err
	}
	tbl, err := p.plainIdent("table name")
	if err != nil {
		return sh, err
	}
	sh.Table = tbl

	cols, err := p.parseIdentList("column")
	if err != nil {
		return sh, err
	}
	sh.InsertCols = cols

	if err := p.expectKeyword("VALUES"); err != nil {
		return sh, err
	}
	if p.peek().kind != tokLParen {
		return sh, invalidf("expected VALUES tuple")
	}
	p.next() // (
	var vals []ValueShape
	for {
		v, err := p.parseValue()
		if err != nil {
			return sh, err
		}
		vals = append(vals, v)
		if p.peek().kind == tokComma {
			p.next()
			continue
		}
		break
	}
	if p.peek().kind != tokRParen {
		return sh, invalidf("unterminated VALUES tuple")
	}
	rparen := p.next() // )
	sh.InsertValuesEnd = rparen.pos + len(rparen.text)
	sh.InsertVals = vals
	if len(cols) != len(vals) {
		return sh, invalidf("column/value count mismatch (%d cols, %d vals)", len(cols), len(vals))
	}
	if p.peek().kind == tokComma {
		return sh, invalidf("multi-row INSERT is not supported")
	}

	if p.acceptKeyword("ON") {
		cc, err := p.parseOnConflict(cols, pkCols)
		if err != nil {
			return sh, err
		}
		sh.OnConflict = cc
	}
	if t := p.peek(); t.kind == tokIdent &&
		(strings.EqualFold(t.text, "RETURNING") || strings.EqualFold(t.text, "SELECT")) {
		return sh, invalidf("unsupported INSERT clause %q", t.text)
	}

	resolveInsertIdentity(&sh, pkCols)
	return sh, nil
}

// parseValue parses one INSERT VALUES cell: a bound '?' or a canonical fixed literal
// (NULL / integer / string). A receiver-evaluated expression (bare identifier, function
// call, etc.) is rejected — it could evaluate differently on each receiver.
func (p *sqlParser) parseValue() (ValueShape, error) {
	t := p.peek()
	switch t.kind {
	case tokParam:
		return ValueShape{ParamIndex: p.takeParam()}, nil
	case tokInt:
		p.next()
		return ValueShape{ParamIndex: -1, Literal: LiteralValue{Kind: LitInt, Int: t.intVal}}, nil
	case tokString:
		p.next()
		return ValueShape{ParamIndex: -1, Literal: LiteralValue{Kind: LitString, Str: t.strVal}}, nil
	case tokPlusMinus:
		p.next()
		if p.peek().kind == tokInt {
			it := p.next()
			v := it.intVal
			if t.text == "-" {
				v = -v
			}
			return ValueShape{ParamIndex: -1, Literal: LiteralValue{Kind: LitInt, Int: v}}, nil
		}
		return ValueShape{}, invalidf("unsupported signed value in INSERT VALUES")
	case tokIdent:
		if strings.EqualFold(t.text, "NULL") {
			p.next()
			return ValueShape{ParamIndex: -1, Literal: LiteralValue{Kind: LitNull}}, nil
		}
		return ValueShape{}, invalidf("non-literal expression in INSERT VALUES: %q", t.text)
	default:
		return ValueShape{}, invalidf("unsupported value sqlTok in INSERT VALUES: %q", t.text)
	}
}

// parseOnConflict parses a single, fully-bounded ON CONFLICT clause. It accepts an
// optional conflict-target column list, then DO NOTHING or DO UPDATE SET assignments with
// an optional trailing WHERE guard (a conditional upsert). It rejects a partial-index
// target WHERE, a second ON CONFLICT clause, and any trailing content it can't bound.
func (p *sqlParser) parseOnConflict(insertCols, pkCols []string) (*ConflictClause, error) {
	if err := p.expectKeyword("CONFLICT"); err != nil {
		return nil, err
	}
	cc := &ConflictClause{}
	if p.peek().kind == tokLParen {
		targets, err := p.parseIdentList("conflict-target")
		if err != nil {
			return nil, err
		}
		cc.Targets = targets
	}
	if p.peek().kind == tokIdent && strings.EqualFold(p.peek().text, "WHERE") {
		return nil, invalidf("ON CONFLICT partial-index target WHERE not supported")
	}
	if err := p.expectKeyword("DO"); err != nil {
		return nil, err
	}
	if p.acceptKeyword("NOTHING") {
		cc.DoNothing = true
		return cc, nil
	}
	if err := p.expectKeyword("UPDATE"); err != nil {
		return nil, err
	}
	if err := p.expectKeyword("SET"); err != nil {
		return nil, err
	}
	assigns, err := p.parseAssignments()
	if err != nil {
		return nil, err
	}
	cc.Assignments = assigns
	if p.peek().kind == tokIdent && strings.EqualFold(p.peek().text, "WHERE") {
		p.next()
		where, err := p.parsePredicate()
		if err != nil {
			return nil, err
		}
		cc.Where = where
	}
	if p.peek().kind == tokIdent && strings.EqualFold(p.peek().text, "ON") {
		return nil, invalidf("multiple ON CONFLICT clauses not supported")
	}
	cc.IsFullImage = computeFullImage(insertCols, pkCols, cc)
	return cc, nil
}

// ---- UPDATE ----

func (p *sqlParser) parseUpdate(pkCols []string) (StmtShape, error) {
	sh := StmtShape{Kind: KindUpdate, UpdatedAtParamIdx: -1}
	p.next() // UPDATE
	tbl, err := p.plainIdent("table name")
	if err != nil {
		return sh, err
	}
	sh.Table = tbl
	if err := p.expectKeyword("SET"); err != nil {
		return sh, err
	}
	sh.SetClauseStart = p.peek().pos
	assigns, err := p.parseAssignments()
	if err != nil {
		return sh, err
	}
	sh.SetClauseEnd = p.lastEnd
	sh.SetAssigns = assigns
	if p.acceptKeyword("WHERE") {
		sh.WhereStart = p.peek().pos
		where, err := p.parsePredicate()
		if err != nil {
			return sh, err
		}
		sh.WhereEnd = p.lastEnd
		sh.Where = where
	}
	if t := p.peek(); t.kind == tokIdent && strings.EqualFold(t.text, "RETURNING") {
		return sh, invalidf("unsupported UPDATE clause %q", t.text)
	}
	resolveUpdateIdentity(&sh, pkCols)
	return sh, nil
}

// ---- DELETE ----

func (p *sqlParser) parseDelete(pkCols []string) (StmtShape, error) {
	sh := StmtShape{Kind: KindDelete, UpdatedAtParamIdx: -1}
	p.next() // DELETE
	if err := p.expectKeyword("FROM"); err != nil {
		return sh, err
	}
	tbl, err := p.plainIdent("table name")
	if err != nil {
		return sh, err
	}
	sh.Table = tbl
	if p.acceptKeyword("WHERE") {
		where, err := p.parsePredicate()
		if err != nil {
			return sh, err
		}
		sh.Where = where
	}
	if t := p.peek(); t.kind == tokIdent && strings.EqualFold(t.text, "RETURNING") {
		return sh, invalidf("unsupported DELETE clause %q", t.text)
	}
	resolveUpdateIdentity(&sh, pkCols) // same full-PK-identity computation over WHERE
	return sh, nil
}

// ---- assignments ----

// parseAssignments parses `col = <expr> [, col = <expr>]*`. The RHS is a bound '?', a
// literal, or a deterministic expression captured as a NormalizedExpr.
func (p *sqlParser) parseAssignments() ([]AssignmentShape, error) {
	var out []AssignmentShape
	seen := map[string]bool{}
	for {
		col, err := p.plainIdent("SET column")
		if err != nil {
			return nil, err
		}
		lc := strings.ToLower(col)
		if seen[lc] {
			// A duplicate SET target makes identity/timestamp classification ambiguous
			// (which assignment wins?) — reject it.
			return nil, invalidf("duplicate SET target %q", col)
		}
		seen[lc] = true
		if p.peek().kind != tokEq {
			return nil, invalidf("expected '=' after SET column %q", col)
		}
		p.next() // =
		expr, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		out = append(out, AssignmentShape{Column: col, Expr: expr})
		if p.peek().kind == tokComma {
			p.next()
			continue
		}
		break
	}
	if len(out) == 0 {
		return nil, invalidf("empty SET clause")
	}
	return out, nil
}

// parseExpr consumes a single expression, stopping (at paren depth 0) at a ',',
// a WHERE/ON keyword, ';', ')', or EOF. It builds a canonical typed encoding (Text) and
// records the bound-parameter indices it consumes in order. It also detects the exact
// `excluded.<ident>` shape (ExcludedRef) so full-image classification does not depend on
// the Text format.
func (p *sqlParser) parseExpr() (NormalizedExpr, error) {
	var sb strings.Builder
	var params []int
	var toks []sqlTok
	depth := 0
	for {
		t := p.peek()
		if depth == 0 {
			if t.kind == tokComma || t.kind == tokSemi || t.kind == tokEOF || t.kind == tokRParen {
				break
			}
			if t.kind == tokIdent && (strings.EqualFold(t.text, "WHERE") || strings.EqualFold(t.text, "ON")) {
				break
			}
		}
		switch t.kind {
		case tokLParen:
			depth++
		case tokRParen:
			depth--
			if depth < 0 {
				return NormalizedExpr{}, invalidf("unbalanced ')' in expression")
			}
		case tokParam:
			params = append(params, p.paramCount)
			p.paramCount++
		case tokQuotedIdent:
			return NormalizedExpr{}, invalidf("quoted identifier in expression")
		}
		sb.WriteString(canonToken(t))
		toks = append(toks, t)
		p.next()
		if len(toks) > 4096 {
			return NormalizedExpr{}, invalidf("expression too long")
		}
	}
	if depth != 0 {
		return NormalizedExpr{}, invalidf("unbalanced '(' in expression")
	}
	if len(toks) == 0 {
		return NormalizedExpr{}, invalidf("empty expression")
	}
	ne := NormalizedExpr{Text: sb.String(), ParamIdx: params, SoleParam: -1}
	// Detect exactly a single bound parameter → used to recognize `updated_at = ?`.
	if len(toks) == 1 && toks[0].kind == tokParam {
		ne.SoleParam = params[0]
	}
	// Detect exactly `excluded.<ident>` (3 tokens, no params) → the plain copy used for
	// full-image reasoning.
	if len(toks) == 3 && len(params) == 0 &&
		toks[0].kind == tokIdent && strings.EqualFold(toks[0].text, "excluded") &&
		toks[1].kind == tokDot && toks[2].kind == tokIdent {
		ne.ExcludedRef = strings.ToLower(toks[2].text)
	}
	return ne, nil
}

// canonToken renders one token to a TYPED, length-prefixed canonical encoding for a
// NormalizedExpr / predicate leaf. A type tag byte plus a length-prefixed payload makes the
// encoding self-delimiting and collision-free ACROSS token types: an integer literal 1 and
// an identifier named "i1" produce distinct encodings (`n1:1` vs `d2:i1`), so two statements
// that differ only in a literal-vs-identifier token never share an authorization fingerprint.
// Encodings are concatenated with no separator (each is self-delimiting). Identifiers are
// lower-cased (SQLite identifiers are case-insensitive); this is a canonical form for
// hashing, not executable SQL.
func canonToken(t sqlTok) string {
	switch t.kind {
	case tokIdent:
		s := strings.ToLower(t.text)
		return "d" + strconv.Itoa(len(s)) + ":" + s
	case tokParam:
		return "p;"
	case tokInt:
		s := strconv.FormatInt(t.intVal, 10)
		return "n" + strconv.Itoa(len(s)) + ":" + s
	case tokString:
		return "s" + strconv.Itoa(len(t.strVal)) + ":" + t.strVal
	case tokLParen:
		return "("
	case tokRParen:
		return ")"
	case tokComma:
		return ","
	case tokDot:
		return "."
	case tokStar:
		return "*"
	case tokEq:
		return "="
	case tokOp, tokPlusMinus, tokOther:
		return "o" + strconv.Itoa(len(t.text)) + ":" + t.text
	default:
		return "p;" // unreachable in a bounded expression
	}
}

// stripLeadingAlgo returns sql with any leading "OR REPLACE"/"OR IGNORE" removed, yielding
// a plain INSERT while leaving the rest of the statement — including a verbatim ON CONFLICT
// tail, literals, and comments — byte-for-byte unchanged. sh must be the parse of sql. This
// is the structural, offset-based replacement for the old substring replaceInsertStrategy:
// it never rewrites anything but the exact algorithm-keyword span the parser located.
func stripLeadingAlgo(sql string, sh StmtShape) string {
	s, e := sh.LeadingAlgoStart, sh.LeadingAlgoEnd
	if e <= s || e > len(sql) {
		return sql
	}
	// Consume one following space so "INSERT OR REPLACE INTO" collapses to "INSERT INTO"
	// rather than leaving a double space. Only a single ASCII space (the token separator
	// the lexer emitted) is dropped, never content inside the statement.
	if e < len(sql) && sql[e] == ' ' {
		e++
	}
	return sql[:s] + sql[e:]
}

// setInsertOrIgnore returns sql rewritten to "INSERT OR IGNORE INTO …" — a create-only INSERT that
// never clobbers an existing row — by splicing at the parser-located keyword offsets. It is the
// structural, offset-based replacement for the substring replaceInsertStrategy: it first removes any
// existing OR REPLACE/OR IGNORE (stripLeadingAlgo, which only touches content after the INSERT
// keyword) and then inserts " OR IGNORE" right after the INSERT keyword, leaving everything else —
// ON CONFLICT tail, literals, comments — byte-for-byte unchanged. sh must be the parse of sql with
// sh.Kind == KindInsert.
func setInsertOrIgnore(sql string, sh StmtShape) string {
	plain := stripLeadingAlgo(sql, sh)
	kwEnd := sh.InsertKeywordEnd
	if kwEnd <= 0 || kwEnd > len(plain) {
		return plain
	}
	return plain[:kwEnd] + " OR IGNORE" + plain[kwEnd:]
}
