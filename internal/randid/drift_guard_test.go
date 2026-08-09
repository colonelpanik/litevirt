package randid

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoLocalEightByteHexIDGenerators fails if any package outside internal/randid
// hand-rolls the 8-byte-hex ID scheme again. This package exists because eight
// byte-identical copies of it had already accumulated across internal/failover,
// internal/grpcapi (three), internal/scheduler, internal/health, internal/ui, and
// cmd/litevirt — and had drifted into two different crypto/rand error policies.
// A dedup that isn't guarded drifts back.
//
// The predicate is deliberately narrow: a single function body containing all
// three of `make([]byte, 8)`, a `rand.Read` call, and `hex.EncodeToString`. That
// needs no allowlist. The repo's other short-random helpers use different sizes
// (daemon.generatePassword 16, grpcapi.newSessionID 32, pbsstore.randomChunkSuffix
// 4), and the only other `make([]byte, 8)` in the tree — internal/qcow2's
// writeEndOfExtensions — is in a package that imports neither crypto/rand nor
// encoding/hex. Innocent code cannot trip this.
func TestNoLocalEightByteHexIDGenerators(t *testing.T) {
	root := repoRoot(t)

	var offenders []string
	scanned := 0
	for _, sub := range []string{"internal", "cmd", "tests"} {
		dir := filepath.Join(root, sub)
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("scan dir %s missing: %v — scan path wrong?", dir, err)
		}
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				// This package is the one place the scheme is allowed to live.
				if path == filepath.Join(root, "internal", "randid") {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			scanned++
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if !isEightByteHexIDBody(fn.Body) {
					continue
				}
				rel, _ := filepath.Rel(root, path)
				offenders = append(offenders, fmt.Sprintf("%s:%d func %s",
					rel, fset.Position(fn.Pos()).Line, fn.Name.Name))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}

	// A source-walking guard that finds no files passes, and a vacuous pass
	// reads exactly like a real one. Assert it actually scanned something.
	if scanned == 0 {
		t.Fatal("scanned no production .go files — scan path wrong?")
	}
	if len(offenders) > 0 {
		t.Errorf("local 8-byte-hex ID generator(s) found outside internal/randid:\n  %s\n\n"+
			"Use randid.New() instead. These ids are primary keys in replicated Corrosion "+
			"tables; a per-package copy is how the crypto/rand error policy drifted last time.",
			strings.Join(offenders, "\n  "))
	}
}

// isEightByteHexIDBody reports whether one function body contains all three
// markers of the scheme: make([]byte, 8), a rand.Read call, and hex.EncodeToString.
func isEightByteHexIDBody(body *ast.BlockStmt) bool {
	var eightByteBuf, randRead, hexEncode bool
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "make" && len(call.Args) == 2 {
			if arr, ok := call.Args[0].(*ast.ArrayType); ok && arr.Len == nil {
				if elt, ok := arr.Elt.(*ast.Ident); ok && elt.Name == "byte" {
					if lit, ok := call.Args[1].(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "8" {
						eightByteBuf = true
					}
				}
			}
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			pkg, _ := sel.X.(*ast.Ident)
			switch {
			case sel.Sel.Name == "Read" && pkg != nil && pkg.Name == "rand":
				randRead = true
			case sel.Sel.Name == "EncodeToString" && pkg != nil && pkg.Name == "hex":
				hexEncode = true
			}
		}
		return true
	})
	return eightByteBuf && randRead && hexEncode
}

// repoRoot walks up from the test's working directory to the module root.
// Mirrors the idiom in cmd/litevirt/docs_triangulation_test.go.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (go.mod not found above test dir)")
		}
		dir = parent
	}
}
