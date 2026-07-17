package corrosion

// WHERE-clause parser (recursive descent over the token stream) + row-identity
// resolution. The tree is used both for the fingerprint and to decide HasFullPKIdentity —
// whether every declared PK column appears as a top-level `pk = ?` conjunct, which makes
// an UPDATE/DELETE a single-row, LWW-gateable statement.

import "strings"

// parsePredicate parses a WHERE clause into a canonical boolean tree.
func (p *sqlParser) parsePredicate() (PredicateTree, error) {
	n, err := p.parseOr()
	if err != nil {
		return PredicateTree{}, err
	}
	return PredicateTree{Node: n}, nil
}

func (p *sqlParser) parseOr() (*predNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokIdent || !strings.EqualFold(p.peek().text, "OR") {
		return left, nil
	}
	children := []*predNode{left}
	for p.acceptKeyword("OR") {
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		children = append(children, r)
	}
	return &predNode{op: "OR", children: children}, nil
}

func (p *sqlParser) parseAnd() (*predNode, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokIdent || !strings.EqualFold(p.peek().text, "AND") {
		return left, nil
	}
	children := []*predNode{left}
	for p.acceptKeyword("AND") {
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		children = append(children, r)
	}
	return &predNode{op: "AND", children: children}, nil
}

func (p *sqlParser) parseNot() (*predNode, error) {
	negated := false
	for p.acceptKeyword("NOT") {
		negated = !negated
	}
	n, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	if negated {
		n.negated = !n.negated
	}
	return n, nil
}

func (p *sqlParser) parseTerm() (*predNode, error) {
	if p.peek().kind == tokLParen {
		p.next()
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, invalidf("unterminated '(' in WHERE")
		}
		p.next()
		return n, nil
	}
	return p.parseLeaf()
}

// parseLeaf consumes a maximal run of tokens forming one comparison/test, stopping at a
// depth-0 AND/OR, ')', ';', or EOF. It bounds and param-counts any predicate our builders
// emit (`col = ?`, `col IS NULL`, `col < ?`, `owner_kind = 'ct'`, `x = excluded.x`, …) and
// specifically recognizes the bare `ident = ?` form used for PK identity.
func (p *sqlParser) parseLeaf() (*predNode, error) {
	var toks []sqlTok
	var params []int
	var sb strings.Builder
	depth := 0
	for {
		t := p.peek()
		if depth == 0 {
			if t.kind == tokRParen || t.kind == tokSemi || t.kind == tokEOF {
				break
			}
			if t.kind == tokIdent && (strings.EqualFold(t.text, "AND") || strings.EqualFold(t.text, "OR")) {
				break
			}
		}
		switch t.kind {
		case tokLParen:
			depth++
		case tokRParen:
			depth--
			if depth < 0 {
				return nil, invalidf("unbalanced ')' in WHERE")
			}
		case tokParam:
			params = append(params, p.paramCount)
			p.paramCount++
		case tokQuotedIdent:
			return nil, invalidf("quoted identifier in WHERE")
		}
		if len(toks) > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(canonToken(t))
		toks = append(toks, t)
		p.next()
		if len(toks) > 4096 {
			return nil, invalidf("WHERE predicate too long")
		}
	}
	if depth != 0 {
		return nil, invalidf("unbalanced '(' in WHERE")
	}
	if len(toks) == 0 {
		return nil, invalidf("empty WHERE predicate")
	}
	leaf := &predNode{text: sb.String(), params: params, rhsParam: -1}
	// Recognize exactly `ident = ?` (bare, unqualified) for PK identity.
	if len(toks) == 3 &&
		toks[0].kind == tokIdent && isPlainIdent(toks[0].text) &&
		toks[1].kind == tokEq && toks[2].kind == tokParam && len(params) == 1 {
		leaf.col = toks[0].text
		leaf.cmp = "="
		leaf.rhsParam = params[0]
	}
	return leaf, nil
}

// collectConjuncts returns the leaves that are guaranteed top-level AND conjuncts of the
// tree (reachable through only non-negated AND nodes). An OR anywhere on the path, or a
// negation, means the leaves under it are not guaranteed to hold, so they are excluded.
func collectConjuncts(n *predNode) []*predNode {
	if n == nil || n.negated {
		return nil
	}
	switch n.op {
	case "":
		return []*predNode{n}
	case "AND":
		var out []*predNode
		for _, c := range n.children {
			out = append(out, collectConjuncts(c)...)
		}
		return out
	default: // "OR"
		return nil
	}
}

// resolveInsertIdentity fills HasFullPKIdentity / PKParamIdx / UpdatedAtParamIdx for an
// INSERT: every PK column must be present in the column list and bound to a parameter
// (not a literal), and updated_at, if present, must also be a bound parameter.
func resolveInsertIdentity(sh *StmtShape, pkCols []string) {
	sh.UpdatedAtParamIdx = -1
	idx := map[string]int{}
	for i, c := range sh.InsertCols {
		idx[strings.ToLower(c)] = i
	}
	if j, ok := idx["updated_at"]; ok && sh.InsertVals[j].isParam() {
		sh.UpdatedAtParamIdx = sh.InsertVals[j].ParamIndex
	}
	if len(pkCols) == 0 {
		return
	}
	pkParam := make([]int, len(pkCols))
	for i, pk := range pkCols {
		j, ok := idx[strings.ToLower(pk)]
		if !ok || !sh.InsertVals[j].isParam() {
			return // missing PK column, or PK bound to a literal ⇒ not a bound-param identity
		}
		pkParam[i] = sh.InsertVals[j].ParamIndex
	}
	sh.HasFullPKIdentity = true
	sh.PKParamIdx = pkParam
}

// resolveUpdateIdentity fills HasFullPKIdentity / PKParamIdx (from top-level `pk = ?`
// conjuncts in WHERE) and, for UPDATE, UpdatedAtParamIdx (from a `SET updated_at = ?`
// assignment bound to a single parameter). Shared by UPDATE and DELETE.
func resolveUpdateIdentity(sh *StmtShape, pkCols []string) {
	sh.UpdatedAtParamIdx = -1
	for _, a := range sh.SetAssigns {
		if strings.EqualFold(a.Column, "updated_at") && a.Expr.Text == "?" && len(a.Expr.ParamIdx) == 1 {
			sh.UpdatedAtParamIdx = a.Expr.ParamIdx[0]
		}
	}
	if len(pkCols) == 0 {
		return
	}
	conjuncts := collectConjuncts(sh.Where.Node)
	byCol := map[string]int{} // lower(col) -> param index of a bare `col = ?` conjunct
	for _, leaf := range conjuncts {
		if leaf.col != "" && leaf.cmp == "=" && leaf.rhsParam >= 0 {
			byCol[strings.ToLower(leaf.col)] = leaf.rhsParam
		}
	}
	pkParam := make([]int, len(pkCols))
	for i, pk := range pkCols {
		pi, ok := byCol[strings.ToLower(pk)]
		if !ok {
			return // some PK column is not a top-level `pk = ?` conjunct ⇒ not single-row identity
		}
		pkParam[i] = pi
	}
	sh.HasFullPKIdentity = true
	sh.PKParamIdx = pkParam
}

// computeFullImage reports whether an INSERT's ON CONFLICT DO UPDATE copies EXACTLY the
// supplied non-PK row image and nothing else — the condition under which an exact-timestamp
// tie may be resolved over the full row. It requires: no WHERE guard; no DO NOTHING; every
// assignment is `c = excluded.c`; the assigned set equals exactly the supplied non-PK
// columns (no PK assignments, no columns outside the insert list / receiver-only columns);
// and no duplicate targets (already rejected at parse time). Anything else keeps local on a
// tie and defers to anti-entropy. (Not part of the fingerprint — it depends on pkCols.)
func computeFullImage(insertCols, pkCols []string, cc *ConflictClause) bool {
	if cc.DoNothing || cc.Where.Node != nil {
		return false
	}
	pkset := map[string]bool{}
	for _, pk := range pkCols {
		pkset[strings.ToLower(pk)] = true
	}
	insertSet := map[string]bool{}
	for _, c := range insertCols {
		insertSet[strings.ToLower(c)] = true
	}
	assigned := map[string]bool{}
	for _, a := range cc.Assignments {
		lc := strings.ToLower(a.Column)
		if a.Expr.Text != "excluded . "+lc {
			return false // transformed / non-copy assignment
		}
		if pkset[lc] {
			return false // assigning a PK/conflict-key column ⇒ not a clean row image
		}
		if !insertSet[lc] {
			return false // assigns a column outside the supplied row (e.g. a receiver-only column)
		}
		assigned[lc] = true // duplicates already rejected in parseAssignments
	}
	// Exact set: every supplied non-PK column is copied, and nothing else was assigned.
	for c := range insertSet {
		if pkset[c] {
			continue
		}
		if !assigned[c] {
			return false // a supplied non-PK column is not copied
		}
	}
	return true
}
