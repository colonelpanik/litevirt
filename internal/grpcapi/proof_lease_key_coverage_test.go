package grpcapi

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestProofLeaseKeyProducible_AcceptsEveryKeyTheTreeStamps derives the accepted
// set from the code instead of trusting a hand-written predicate to stay true.
//
// proofLeaseKeyProducible is a hand-maintained answer to "which lease keys does
// a proof PRODUCER hold", and it is in a FAIL-CLOSED position: a key missing
// from it is refused on every executor, so a new lease-holding producer that
// stamps its own key has every proof it mints rejected cluster-wide the moment
// the token latches — with no compile error and no test failure to warn anyone.
// That is the same silent-drift shape as ownershipTieTables, which was a
// hand-kept map in this package naming tables whose schema lived in
// internal/corrosion, was already wrong on three of them, and was replaced by a
// completeness test derived from the DDL. This is that test, for this map.
//
// The derivation: parse every non-test .go file under internal/ and cmd/, find
// composite literals of ActionProof or RuntimeActionProof, and collect what each
// assigns to LeaseKey. That is exactly "what the tree stamps onto a proof" —
// narrower than "what lease keys exist", which is the distinction the predicate
// is about. Tests are excluded deliberately: they construct unproducible keys on
// purpose, to prove the refusals work.
//
// A non-constant expression (a variable, a function call) cannot be resolved by
// a source scan, so it FAILS the test rather than being skipped. A stamp site
// this test cannot read is a stamp site it cannot vouch for.
func TestProofLeaseKeyProducible_AcceptsEveryKeyTheTreeStamps(t *testing.T) {
	root := repoRoot(t)

	// The exported lease-key constants, by the selector a caller would write.
	known := map[string]string{
		"corrosion.LeaseKeyFailover":   corrosion.LeaseKeyFailover,
		"corrosion.LeaseKeyRebalancer": corrosion.LeaseKeyRebalancer,
		"corrosion.LeaseKeyDualRun":    corrosion.LeaseKeyDualRun,
	}

	type site struct{ where, expr, key string }
	var sites []site

	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok || !isProofType(lit.Type) {
					return true
				}
				for _, elt := range lit.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if id, ok := kv.Key.(*ast.Ident); !ok || id.Name != "LeaseKey" {
						continue
					}
					// A FORWARDING site copies whatever key it was handed —
					// proofFromPB and proofToPB exist to move the field between the
					// struct and the proto — so it originates nothing and there is
					// no constant to check. The stamp it forwards was already
					// checked wherever it was written.
					if forwardsLeaseKey(kv.Value) {
						continue
					}
					expr := exprText(kv.Value)
					rel, _ := filepath.Rel(root, path)
					sites = append(sites, site{
						where: fmt.Sprintf("%s:%d", rel, fset.Position(kv.Pos()).Line),
						expr:  expr,
						key:   known[expr],
					})
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	if len(sites) == 0 {
		t.Fatal("no proof stamp site was found at all, so this test proves nothing — the " +
			"literal types or field name it scans for must have been renamed")
	}

	for _, s := range sites {
		if s.key == "" {
			t.Errorf("%s stamps LeaseKey = %s, which this scan cannot resolve to a known "+
				"lease-key constant; a stamp site that cannot be read cannot be vouched "+
				"for, so either spell it as one of the corrosion.LeaseKey* constants or "+
				"teach this test to resolve it", s.where, s.expr)
			continue
		}
		if !proofLeaseKeyProducible(s.key) {
			t.Errorf("%s stamps LeaseKey = %s (%q), but proofLeaseKeyProducible refuses it: "+
				"every proof this site mints is refused on every executor once "+
				"lease_term_v1 latches. Widen the predicate to include this producer's "+
				"key (and see its doc comment on what the equal-term holder check then "+
				"has to distinguish)", s.where, s.expr, s.key)
		}
	}
}

// forwardsLeaseKey reports whether the value assigned to a proof's LeaseKey
// merely MOVES a key that already exists rather than originating one.
//
// Three shapes qualify, and none of them is a stamp:
//   - p.LeaseKey — proofFromPB/proofToPB moving the field between the struct and
//     the proto.
//   - p.GetLeaseKey() — the same, through a proto getter.
//   - r.String("lease_key") — hydrating a ProofRecord from its own stored row.
//
// The key such a site carries was checked wherever it was written; requiring a
// resolvable constant here would only force the scan to be taught about every
// conversion in the tree, which is not what it is for.
func forwardsLeaseKey(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		return t.Sel.Name == "LeaseKey"
	case *ast.CallExpr:
		sel, ok := t.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if sel.Sel.Name == "GetLeaseKey" {
			return true
		}
		// A single-argument read of the lease_key column.
		if len(t.Args) == 1 {
			if lit, ok := t.Args[0].(*ast.BasicLit); ok && lit.Value == `"lease_key"` {
				return true
			}
		}
	}
	return false
}

// isProofType reports whether a composite-literal type is an action-proof struct,
// under either the corrosion struct or the protobuf message.
func isProofType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name == "ActionProof" || t.Name == "RuntimeActionProof"
	case *ast.SelectorExpr:
		return isProofType(t.Sel)
	case *ast.StarExpr:
		return isProofType(t.X)
	}
	return false
}

// exprText renders a selector or identifier as written, and "" for anything a
// source scan cannot resolve to a constant.
func exprText(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok {
			return x.Name + "." + t.Sel.Name
		}
	}
	return ""
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found above the test's working directory")
		}
		dir = parent
	}
}
