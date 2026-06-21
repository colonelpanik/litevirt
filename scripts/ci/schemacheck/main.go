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
	"strconv"
	"strings"
)

type schemaFacts struct {
	version    int
	ddl        int
	migrations int
	indexes    int
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
				case "schemaMigrations":
					n, err := countElts(vs.Values[i])
					if err != nil {
						return f, fmt.Errorf("schemaMigrations: %w", err)
					}
					f.migrations, found["migrations"] = n, true
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

// intLit parses an integer basic literal (e.g. the value of CurrentSchemaVersion).
func intLit(expr ast.Expr) (int, error) {
	bl, ok := expr.(*ast.BasicLit)
	if !ok || bl.Kind != token.INT {
		return 0, fmt.Errorf("expected an integer literal, got %T", expr)
	}
	return strconv.Atoi(bl.Value)
}
