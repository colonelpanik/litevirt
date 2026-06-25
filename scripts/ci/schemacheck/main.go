// Command schemacheck enforces litevirt's schema-versioning rule: any growth of
// schemaDDL / schemaMigrations / schemaIndexes in internal/corrosion/schema.go
// must be accompanied by a bump to the CurrentSchemaVersion constant (and, by
// the companion test TestSchemaHistoryDocumentsCurrentVersion, a History line).
//
// Mixed-version rolling upgrades depend on this: the cross-version replication
// skew check in internal/grpcapi/sync.go can only tell that a peer is missing
// newly-added tables/columns if the version number actually moved. Adding DDL
// without bumping the version silently breaks that guard.
//
// It parses both revisions of schema.go with go/ast — no regexes, no
// line-number fragility — so reordering or reformatting an array never trips
// it; only a real change in the NUMBER of DDL/migration/index statements counts
// as "growth".
//
// Usage:
//
//	schemacheck -head <schema.go>              # print counts + version
//	schemacheck -base <old> -head <new>        # enforce: growth => version bump
//
// With -base it exits non-zero iff an array grew but the version did not
// increase. Without -base it just reports the facts (useful for debugging).
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
)

type schemaFacts struct {
	version    int
	ddl        int
	migrations int
	indexes    int
	ddlStmts   []string // raw CREATE TABLE statements (for the non-additive diff)
	migStmts   []string // raw ALTER statements
}

// localOnlyTables are NOT replicated (written via execLocal, excluded from the
// full-state sync list), so non-additive changes to them can't break a peer.
// Defined deliberately here rather than reusing sync.go's (stale) tableNames.
var localOnlyTables = map[string]bool{
	"schema_state":           true,
	"mutation_log":           true,
	"mutation_seen":          true,
	"replication_watermarks": true,
	"applied_migrations":     true,
}

// tableModel is the column-type + primary-key shape of one CREATE TABLE.
type tableModel struct {
	cols map[string]string // column name → first type token (upper-cased)
	pk   []string          // primary-key columns (sorted)
}

func main() {
	base := flag.String("base", "", "path to the base (pre-change) schema.go; enables the growth=>bump check")
	head := flag.String("head", "", "path to the head (post-change) schema.go (required)")
	flag.Parse()

	if *head == "" {
		fmt.Fprintln(os.Stderr, "schemacheck: -head is required")
		os.Exit(2)
	}

	headFacts, err := parseSchema(*head)
	if err != nil {
		fmt.Fprintf(os.Stderr, "schemacheck: head: %v\n", err)
		os.Exit(2)
	}

	if *base == "" {
		fmt.Printf("CurrentSchemaVersion=%d schemaDDL=%d schemaMigrations=%d schemaIndexes=%d\n",
			headFacts.version, headFacts.ddl, headFacts.migrations, headFacts.indexes)
		return
	}

	baseFacts, err := parseSchema(*base)
	if err != nil {
		fmt.Fprintf(os.Stderr, "schemacheck: base: %v\n", err)
		os.Exit(2)
	}

	var grew []string
	if headFacts.ddl > baseFacts.ddl {
		grew = append(grew, fmt.Sprintf("schemaDDL %d->%d", baseFacts.ddl, headFacts.ddl))
	}
	if headFacts.migrations > baseFacts.migrations {
		grew = append(grew, fmt.Sprintf("schemaMigrations %d->%d", baseFacts.migrations, headFacts.migrations))
	}
	if headFacts.indexes > baseFacts.indexes {
		grew = append(grew, fmt.Sprintf("schemaIndexes %d->%d", baseFacts.indexes, headFacts.indexes))
	}

	// Non-additive guard: replicated tables may only GROW (new defaulted columns,
	// new tables). A dropped/renamed/retyped column or a changed PK is invisible
	// to the growth check (counts can stay equal) but breaks a mixed-version
	// cluster — and it's what makes the relaxed startup guard (an old binary on a
	// newer DB) sound. Enforce it structurally, base vs head.
	if v := nonAdditiveViolations(baseFacts, headFacts); len(v) > 0 {
		fmt.Fprintf(os.Stderr,
			"schemacheck: FAIL — non-additive schema change on replicated table(s):\n  - %s\n\n"+
				"Replicated tables are additive-only: never drop/rename a column, change its\n"+
				"type, change a PRIMARY KEY, or ADD COLUMN ... NOT NULL without a DEFAULT.\n"+
				"In a mixed-version cluster the other peers address columns by name, so a\n"+
				"removed/renamed/retyped column silently drops or mis-applies their writes,\n"+
				"and an old binary on the newer DB would mis-handle it. Add a new column\n"+
				"instead (with a DEFAULT) and dual-write/migrate. See docs/upgrades.md.\n",
			strings.Join(v, "\n  - "))
		os.Exit(1)
	}

	if len(grew) == 0 {
		fmt.Printf("schemacheck: no schema growth (version %d); OK\n", headFacts.version)
		return
	}
	if headFacts.version > baseFacts.version {
		fmt.Printf("schemacheck: schema grew (%s) and CurrentSchemaVersion bumped %d->%d; OK\n",
			strings.Join(grew, ", "), baseFacts.version, headFacts.version)
		return
	}

	fmt.Fprintf(os.Stderr,
		"schemacheck: FAIL — schema grew (%s) but CurrentSchemaVersion did not increase (still %d).\n\n"+
			"litevirt's mixed-version replication safety depends on this. When you add a\n"+
			"CREATE TABLE / ALTER / index to internal/corrosion/schema.go you MUST:\n"+
			"  1. bump the CurrentSchemaVersion constant, and\n"+
			"  2. append a matching `vN:` line to the History comment block.\n"+
			"See docs/upgrades.md (Schema versioning).\n",
		strings.Join(grew, ", "), headFacts.version)
	os.Exit(1)
}

// nonAdditiveViolations returns human-readable descriptions of any non-additive
// schema change between base and head (empty = clean).
func nonAdditiveViolations(base, head schemaFacts) []string {
	var out []string

	// 1) CREATE TABLE structural diff for tables present in BOTH revisions.
	baseTables := parseTables(base.ddlStmts)
	headTables := parseTables(head.ddlStmts)
	for name, bt := range baseTables {
		if localOnlyTables[name] {
			continue
		}
		ht, ok := headTables[name]
		if !ok {
			out = append(out, fmt.Sprintf("table %q was removed", name))
			continue
		}
		for col, btype := range bt.cols {
			htype, ok := ht.cols[col]
			if !ok {
				out = append(out, fmt.Sprintf("%s.%s was dropped or renamed", name, col))
				continue
			}
			if htype != btype {
				out = append(out, fmt.Sprintf("%s.%s type changed (%s -> %s)", name, col, btype, htype))
			}
		}
		if strings.Join(bt.pk, ",") != strings.Join(ht.pk, ",") {
			out = append(out, fmt.Sprintf("%s PRIMARY KEY changed ([%s] -> [%s])",
				name, strings.Join(bt.pk, ","), strings.Join(ht.pk, ",")))
		}
	}

	// 2) Every head ALTER must be additive: ADD COLUMN, and if NOT NULL then with
	//    a DEFAULT. Reject DROP/RENAME/ALTER COLUMN and RENAME TABLE outright.
	for _, m := range head.migStmts {
		if reason := nonAdditiveAlter(m); reason != "" {
			out = append(out, fmt.Sprintf("migration %q: %s", strings.TrimSpace(m), reason))
		}
	}
	return out
}

// nonAdditiveAlter returns a reason string if an ALTER is non-additive, else "".
func nonAdditiveAlter(alter string) string {
	u := strings.ToUpper(strings.Join(strings.Fields(alter), " "))
	switch {
	case strings.Contains(u, " DROP COLUMN"):
		return "DROP COLUMN is non-additive"
	case strings.Contains(u, " RENAME COLUMN"), strings.Contains(u, " RENAME TO"):
		return "RENAME is non-additive"
	case strings.Contains(u, " ALTER COLUMN"):
		return "ALTER COLUMN (type/constraint change) is non-additive"
	}
	if strings.Contains(u, " ADD COLUMN ") {
		if strings.Contains(u, " NOT NULL") && !strings.Contains(u, " DEFAULT ") {
			return "ADD COLUMN NOT NULL without DEFAULT breaks rows written by older peers"
		}
		return ""
	}
	// Unknown ALTER verb — be conservative.
	return "unrecognized ALTER form (only additive ADD COLUMN is allowed)"
}

// parseTables turns CREATE TABLE statements into a name → tableModel map.
func parseTables(stmts []string) map[string]tableModel {
	out := map[string]tableModel{}
	for _, ddl := range stmts {
		name := tableNameFromCreate(ddl)
		if name == "" {
			continue
		}
		ddl = stripLineComments(ddl) // a `--` comment runs only to end-of-line
		open := strings.Index(ddl, "(")
		end := strings.LastIndex(ddl, ")")
		if open < 0 || end <= open {
			continue
		}
		tm := tableModel{cols: map[string]string{}}
		for _, item := range splitTopLevel(ddl[open+1 : end]) {
			line := stripSQLComment(strings.TrimSpace(item))
			if line == "" {
				continue
			}
			u := strings.ToUpper(line)
			if strings.HasPrefix(u, "PRIMARY KEY") {
				tm.pk = keyColumns(line)
				continue
			}
			if strings.HasPrefix(u, "UNIQUE") || strings.HasPrefix(u, "FOREIGN KEY") ||
				strings.HasPrefix(u, "CHECK") || strings.HasPrefix(u, "CONSTRAINT") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			col := strings.Trim(fields[0], `"`)
			tm.cols[col] = strings.ToUpper(fields[1])
			if strings.Contains(u, "PRIMARY KEY") {
				tm.pk = append(tm.pk, col)
			}
		}
		sort.Strings(tm.pk)
		out[name] = tm
	}
	return out
}

// tableNameFromCreate extracts the table name from a CREATE TABLE IF NOT EXISTS.
func tableNameFromCreate(ddl string) string {
	t := strings.TrimSpace(ddl)
	const p = "CREATE TABLE IF NOT EXISTS "
	if !strings.HasPrefix(t, p) {
		return ""
	}
	rest := t[len(p):]
	end := strings.IndexAny(rest, " \t\n(")
	if end < 0 {
		return ""
	}
	return strings.Trim(rest[:end], `"`)
}

// splitTopLevel splits a CREATE-TABLE body on commas at paren depth 0.
func splitTopLevel(body string) []string {
	var parts []string
	depth, start := 0, 0
	for i, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, body[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, body[start:])
	return parts
}

// stripSQLComment removes a trailing `-- ...` line comment.
func stripSQLComment(s string) string {
	if i := strings.Index(s, "--"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// stripLineComments removes `-- ...` comments to end-of-line on every line,
// preserving the newlines (so a comment never swallows the next line).
func stripLineComments(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if j := strings.Index(ln, "--"); j >= 0 {
			lines[i] = ln[:j]
		}
	}
	return strings.Join(lines, "\n")
}

// keyColumns extracts the columns from `PRIMARY KEY (a, b)` (sorted).
func keyColumns(line string) []string {
	open := strings.Index(line, "(")
	end := strings.LastIndex(line, ")")
	if open < 0 || end <= open {
		return nil
	}
	var cols []string
	for _, c := range strings.Split(line[open+1:end], ",") {
		if c = strings.Trim(strings.TrimSpace(c), `"`); c != "" {
			cols = append(cols, c)
		}
	}
	sort.Strings(cols)
	return cols
}

// parseSchema parses schema.go and extracts the version constant and the
// element counts of the three schema arrays.
func parseSchema(path string) (schemaFacts, error) {
	var f schemaFacts
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return f, err
	}

	found := map[string]bool{}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				switch name.Name {
				case "CurrentSchemaVersion":
					n, err := intLit(vs.Values[i])
					if err != nil {
						return f, fmt.Errorf("CurrentSchemaVersion: %w", err)
					}
					f.version, found["version"] = n, true
				case "schemaDDL":
					n, err := countElts(vs.Values[i])
					if err != nil {
						return f, fmt.Errorf("schemaDDL: %w", err)
					}
					f.ddl, found["ddl"] = n, true
					f.ddlStmts = stringElts(vs.Values[i])
				case "schemaMigrations":
					n, err := countElts(vs.Values[i])
					if err != nil {
						return f, fmt.Errorf("schemaMigrations: %w", err)
					}
					f.migrations, found["migrations"] = n, true
					f.migStmts = stringElts(vs.Values[i])
				case "schemaIndexes":
					n, err := countElts(vs.Values[i])
					if err != nil {
						return f, fmt.Errorf("schemaIndexes: %w", err)
					}
					f.indexes, found["indexes"] = n, true
				}
			}
		}
	}

	for _, k := range []string{"version", "ddl", "migrations", "indexes"} {
		if !found[k] {
			return f, fmt.Errorf("could not find %s declaration in %s", k, path)
		}
	}
	return f, nil
}

// countElts returns the number of elements in a []string{...} composite literal.
func countElts(expr ast.Expr) (int, error) {
	cl, ok := expr.(*ast.CompositeLit)
	if !ok {
		return 0, fmt.Errorf("expected a composite literal, got %T", expr)
	}
	return len(cl.Elts), nil
}

// stringElts unquotes the string-literal elements of a []string{...} composite
// literal (skips any non-literal element).
func stringElts(expr ast.Expr) []string {
	cl, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range cl.Elts {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			continue
		}
		if s, err := strconv.Unquote(bl.Value); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// intLit parses an integer basic literal (e.g. the value of CurrentSchemaVersion).
func intLit(expr ast.Expr) (int, error) {
	bl, ok := expr.(*ast.BasicLit)
	if !ok || bl.Kind != token.INT {
		return 0, fmt.Errorf("expected an integer literal, got %T", expr)
	}
	return strconv.Atoi(bl.Value)
}
