package corrosion

// Canonical, versioned fingerprint of a StmtShape. The fingerprint is what the runtime
// receiver and the CI guard both key on to authorize a statement, so it must be identical
// across builds and stable byte-for-byte: it is pinned by golden vectors
// (TestStmtCanon_GoldenVectors). A change to canonicalization that alters any existing
// hash MUST bump the tag to stmtshape/v2 rather than silently changing v1 — old binaries'
// in-flight statements are matched against v1 fingerprints in the compatibility ledger.

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

const stmtFingerprintVersion = "stmtshape/v1"

// stmtFingerprint returns "stmtshape/v1:<sha256(canonical)>".
func stmtFingerprint(sh StmtShape) string {
	sum := sha256.Sum256([]byte(stmtCanonical(sh)))
	return stmtFingerprintVersion + ":" + hex.EncodeToString(sum[:])
}

// stmtCanonical builds the canonical, length-prefixed pre-hash encoding. Every field is
// tagged and length-prefixed so no field's content can alias a delimiter or another field.
// Identifiers are lower-cased (SQLite identifiers are case-insensitive). Placeholder
// positions are captured by position in the ordered value/assignment lists.
func stmtCanonical(sh StmtShape) string {
	var b strings.Builder
	enc := func(tag, s string) {
		b.WriteString(tag)
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
		b.WriteByte(';')
	}
	enc("k", sh.Kind.String())
	enc("t", strings.ToLower(sh.Table))
	switch sh.Kind {
	case KindInsert:
		enc("algo", normLeadingAlgo(sh.LeadingAlgo))
		enc("cols", lowerJoin(sh.InsertCols))
		enc("vals", encodeVals(sh.InsertVals))
		enc("conflict", encodeConflict(sh.OnConflict))
	case KindUpdate:
		enc("set", encodeAssigns(sh.SetAssigns))
		enc("where", encodePred(sh.Where.Node))
	case KindDelete:
		enc("where", encodePred(sh.Where.Node))
	}
	return b.String()
}

// normLeadingAlgo canonicalizes the INSERT leading conflict algorithm. It is retained in
// the fingerprint (an OR IGNORE insert to an append-only table is a distinct shape from a
// plain insert), even though the apply path normalizes it away before execution.
func normLeadingAlgo(a string) string {
	switch strings.ToUpper(strings.TrimSpace(a)) {
	case "OR REPLACE":
		return "OR REPLACE"
	case "OR IGNORE":
		return "OR IGNORE"
	default:
		return ""
	}
}

func lowerJoin(cols []string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = strings.ToLower(c)
	}
	return strings.Join(parts, ",")
}

func encodeVals(vals []ValueShape) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = v.Literal.canon() // "?" for a bound param, canonical exact literal otherwise
	}
	return strings.Join(parts, ",")
}

func encodeAssigns(assigns []AssignmentShape) string {
	var sb strings.Builder
	for _, a := range assigns {
		col := strings.ToLower(a.Column)
		// length-prefix both column and expr text so neither can alias the other
		sb.WriteString(strconv.Itoa(len(col)) + ":" + col)
		sb.WriteString("=")
		sb.WriteString(strconv.Itoa(len(a.Expr.Text)) + ":" + a.Expr.Text)
		sb.WriteString(";")
	}
	return sb.String()
}

func encodeConflict(cc *ConflictClause) string {
	if cc == nil {
		return "none"
	}
	var sb strings.Builder
	sb.WriteString("targets=" + lowerJoin(cc.Targets) + ";")
	if cc.DoNothing {
		sb.WriteString("do=nothing;")
	} else {
		sb.WriteString("do=update;")
		set := encodeAssigns(cc.Assignments)
		sb.WriteString("set=" + strconv.Itoa(len(set)) + ":" + set + ";")
	}
	where := encodePred(cc.Where.Node)
	sb.WriteString("where=" + strconv.Itoa(len(where)) + ":" + where + ";")
	if cc.IsFullImage {
		sb.WriteString("full=1")
	} else {
		sb.WriteString("full=0")
	}
	return sb.String()
}

// encodePred renders the WHERE tree unambiguously via length-prefixing at every node.
func encodePred(n *predNode) string {
	if n == nil {
		return ""
	}
	neg := ""
	if n.negated {
		neg = "!"
	}
	if n.op == "" {
		return neg + "L" + strconv.Itoa(len(n.text)) + ":" + n.text
	}
	var sb strings.Builder
	sb.WriteString(neg + n.op + "[")
	for _, c := range n.children {
		e := encodePred(c)
		sb.WriteString(strconv.Itoa(len(e)) + ":" + e)
	}
	sb.WriteByte(']')
	return sb.String()
}
