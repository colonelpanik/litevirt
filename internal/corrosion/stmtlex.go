package corrosion

// Lexer for the constrained SQLite dialect that replicated statements are drawn from.
// It is deliberately strict: it recognises exactly the token classes our builders emit
// and returns an error (→ ErrInvalidStmt) for anything else, so an unexpected construct
// fails closed rather than being silently mis-parsed. It handles the fuzz-critical
// boundary cases — '' string escapes, -- and /* */ comments, nested parentheses, and
// semicolons inside strings — so those can never break statement boundaries.

import (
	"strconv"
	"strings"
)

type tokKind int

const (
	tokEOF         tokKind = iota
	tokIdent               // bare identifier or keyword (original case preserved in .text)
	tokQuotedIdent         // "x" / [x] / `x` — rejected by the parser (advisory token)
	tokString              // 'string literal' — .strVal holds the unescaped value
	tokInt                 // integer literal — .intVal holds the value
	tokParam               // ?
	tokLParen              // (
	tokRParen              // )
	tokComma               // ,
	tokSemi                // ;
	tokDot                 // .
	tokStar                // *
	tokEq                  // =
	tokOp                  // < > <= >= <> != (comparison operators)
	tokPlusMinus           // + or - (unary/binary; for expression rendering only)
	tokOther               // any other single char we tokenise verbatim (e.g. || ) — parser decides
)

type sqlTok struct {
	kind   tokKind
	text   string // original slice text (for keywords/idents/operators)
	strVal string // tokString
	intVal int64  // tokInt
	pos    int    // byte offset of the token's start in the original SQL
	end    int    // byte offset just past the token's last byte in the original SQL

	// pos/end are the token's SOURCE SPAN, and they are what the offsets in
	// StmtShape are built from — applyBulkPerRowLWW slices the original SQL
	// with them to rebuild a per-row UPDATE. They must never be derived from
	// .text: .text carries the token's MEANING, and for a string literal it is
	// the unescaped value, for a quoted identifier the content without its
	// delimiters, and for a number nothing at all. A span short of the text it
	// consumed silently truncates a rebuilt statement into invalid SQL, which
	// fails the whole remote batch and stalls the replication watermark.
}

// lex tokenises sql. On an unterminated string/comment or an unsupported placeholder form
// it returns an error wrapping ErrInvalidStmt.
func lex(sql string) ([]sqlTok, error) {
	var toks []sqlTok
	i := 0
	n := len(sql)
	start := 0
	emit := func(tk sqlTok, end int) {
		tk.pos = start
		tk.end = end
		toks = append(toks, tk)
	}
	for i < n {
		start = i
		c := sql[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '-' && i+1 < n && sql[i+1] == '-':
			// line comment to end of line
			i += 2
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			// block comment
			i += 2
			closed := false
			for i+1 < n {
				if sql[i] == '*' && sql[i+1] == '/' {
					i += 2
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, invalidf("unterminated block comment")
			}
		case c == '\'':
			// string literal with '' escape
			j := i + 1
			var sb strings.Builder
			closed := false
			for j < n {
				if sql[j] == '\'' {
					if j+1 < n && sql[j+1] == '\'' {
						sb.WriteByte('\'')
						j += 2
						continue
					}
					j++
					closed = true
					break
				}
				sb.WriteByte(sql[j])
				j++
			}
			if !closed {
				return nil, invalidf("unterminated string literal")
			}
			emit(sqlTok{kind: tokString, strVal: sb.String()}, j)
			i = j
		case c == '"' || c == '[' || c == '`':
			// quoted identifier — tokenise so the parser can reject it explicitly.
			close := byte('"')
			if c == '[' {
				close = ']'
			} else if c == '`' {
				close = '`'
			}
			j := i + 1
			for j < n && sql[j] != close {
				j++
			}
			if j >= n {
				return nil, invalidf("unterminated quoted identifier")
			}
			emit(sqlTok{kind: tokQuotedIdent, text: sql[i+1 : j]}, j+1)
			i = j + 1
		case c == '?':
			// Only the bare positional '?' is supported. Reject ?NNN / :name / @x / $x.
			if i+1 < n && (isDigit(sql[i+1]) || isIdentStart(sql[i+1])) {
				return nil, invalidf("unsupported parameter form at %q", sql[i:minInt(i+4, n)])
			}
			emit(sqlTok{kind: tokParam, text: "?"}, i+1)
			i++
		case c == ':' || c == '@' || c == '$':
			return nil, invalidf("unsupported named-parameter form %q", string(c))
		case isDigit(c):
			j := i
			for j < n && isDigit(sql[j]) {
				j++
			}
			// reject a number that runs into an identifier char (e.g. 1abc) or a decimal
			if j < n && (sql[j] == '.' || isIdentStart(sql[j])) {
				return nil, invalidf("unsupported numeric/identifier token near %q", sql[i:minInt(j+2, n)])
			}
			v, err := strconv.ParseInt(sql[i:j], 10, 64)
			if err != nil {
				return nil, invalidf("bad integer literal %q", sql[i:j])
			}
			emit(sqlTok{kind: tokInt, intVal: v}, j)
			i = j
		case isIdentStart(c):
			j := i
			for j < n && isIdentPart(sql[j]) {
				j++
			}
			emit(sqlTok{kind: tokIdent, text: sql[i:j]}, j)
			i = j
		case c == '(':
			emit(sqlTok{kind: tokLParen, text: "("}, i+1)
			i++
		case c == ')':
			emit(sqlTok{kind: tokRParen, text: ")"}, i+1)
			i++
		case c == ',':
			emit(sqlTok{kind: tokComma, text: ","}, i+1)
			i++
		case c == ';':
			emit(sqlTok{kind: tokSemi, text: ";"}, i+1)
			i++
		case c == '.':
			emit(sqlTok{kind: tokDot, text: "."}, i+1)
			i++
		case c == '*':
			emit(sqlTok{kind: tokStar, text: "*"}, i+1)
			i++
		case c == '=':
			// SQLite accepts '==' too; normalise both to '='.
			if i+1 < n && sql[i+1] == '=' {
				i++
			}
			emit(sqlTok{kind: tokEq, text: "="}, i+1)
			i++
		case c == '<':
			if i+1 < n && (sql[i+1] == '=' || sql[i+1] == '>') {
				emit(sqlTok{kind: tokOp, text: sql[i : i+2]}, i+2)
				i += 2
			} else {
				emit(sqlTok{kind: tokOp, text: "<"}, i+1)
				i++
			}
		case c == '>':
			if i+1 < n && sql[i+1] == '=' {
				emit(sqlTok{kind: tokOp, text: ">="}, i+2)
				i += 2
			} else {
				emit(sqlTok{kind: tokOp, text: ">"}, i+1)
				i++
			}
		case c == '!':
			if i+1 < n && sql[i+1] == '=' {
				emit(sqlTok{kind: tokOp, text: "!="}, i+2)
				i += 2
			} else {
				return nil, invalidf("unexpected %q", string(c))
			}
		case c == '+' || c == '-':
			emit(sqlTok{kind: tokPlusMinus, text: string(c)}, i+1)
			i++
		case c == '|':
			if i+1 < n && sql[i+1] == '|' {
				emit(sqlTok{kind: tokOther, text: "||"}, i+2)
				i += 2
			} else {
				return nil, invalidf("unexpected %q", string(c))
			}
		default:
			return nil, invalidf("unexpected character %q", string(c))
		}
	}
	emit(sqlTok{kind: tokEOF}, n)
	return toks, nil
}

func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isIdentStart(c byte) bool { return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }
func isIdentPart(c byte) bool  { return isIdentStart(c) || isDigit(c) }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
