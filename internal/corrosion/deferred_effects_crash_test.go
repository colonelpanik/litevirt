package corrosion

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Gap 5 — crash between tx.Commit() and runDeferredEffects().
//
// The apply paths schedule their post-commit consequences (unresolved-tie tracking/clearing,
// identity-fault tracking, tie-break / orphan metrics) via deferAfterCommit, and run them with
// runDeferredEffects AFTER the batch transaction commits. If the process dies in the window
// between the commit and running the effects, those effects are lost. This is only safe if
// (a) no deferred effect performs a DB write — otherwise a crash would split it from the tx it
// was meant to accompany — and (b) the effects are non-durable observations the next
// anti-entropy / apply cycle reconstructs. These tests pin both properties.

// TestDeferredEffects_CrashBeforeRunKeepsDataDropsEffect proves the crash-window contract at the
// machinery level: the committed row is durable, but an effect scheduled on that tx does NOT run
// unless runDeferredEffects is explicitly called after the commit. A crash before that call
// therefore loses the effect harmlessly (a dead process discards the in-memory map entirely).
func TestDeferredEffects_CrashBeforeRunKeepsDataDropsEffect(t *testing.T) {
	c, err := NewLocalClient(t.TempDir(), "node-1")
	if err != nil {
		t.Fatalf("NewLocalClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// --- commit succeeds, then the process "crashes" before runDeferredEffects ---
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO images (name, format, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		"crashimg", "raw", "T", "T"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	ran := 0
	c.deferAfterCommit(tx, func() { ran++ })
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// CRASH POINT: runDeferredEffects is never called. The effect must not have fired.
	if ran != 0 {
		t.Fatalf("deferred effect ran without runDeferredEffects (ran=%d) — it is not gated on the post-commit call", ran)
	}
	// The committed row is durable — the data survives the crash.
	rows, err := c.Query(ctx, `SELECT name FROM images WHERE name = ?`, "crashimg")
	if err != nil || len(rows) != 1 {
		t.Fatalf("committed row not durable after the crash window: err=%v rows=%d", err, len(rows))
	}
	// Cleaning up a dead tx's effects (the production defer) must not run them either.
	c.dropDeferredEffects(tx)
	if ran != 0 {
		t.Fatalf("dropDeferredEffects ran the effect (ran=%d) — drop must discard, not run", ran)
	}

	// --- normal path: the effect runs EXACTLY once, only after commit+run ---
	tx2, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin2: %v", err)
	}
	ran2 := 0
	c.deferAfterCommit(tx2, func() { ran2++ })
	if ran2 != 0 {
		t.Fatalf("effect ran at registration (ran2=%d) — must wait for commit+run", ran2)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("commit2: %v", err)
	}
	c.runDeferredEffects(tx2)
	if ran2 != 1 {
		t.Fatalf("effect ran %d times, want exactly 1 after commit+run", ran2)
	}
	c.runDeferredEffects(tx2) // idempotent: the tx's effects were removed by the first run
	if ran2 != 1 {
		t.Fatalf("effect double-ran (ran2=%d) — runDeferredEffects must clear after running", ran2)
	}
}

// TestDeferredEffects_RollbackDropsEffect proves the rollback path never runs effects: a
// statement that fails and rolls back must not leak its scheduled tracker mutation.
func TestDeferredEffects_RollbackDropsEffect(t *testing.T) {
	c, err := NewLocalClient(t.TempDir(), "node-1")
	if err != nil {
		t.Fatalf("NewLocalClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	ran := 0
	c.deferAfterCommit(tx, func() { ran++ })
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	c.dropDeferredEffects(tx) // the production defer on the rollback path
	if ran != 0 {
		t.Fatalf("effect ran on a rolled-back tx (ran=%d)", ran)
	}
}

// TestDeferredEffects_TrackerSelfHealsAfterRestart shows the lost effect is recoverable: the
// unresolved-tie tracker is in-memory, so a restart (a fresh Client) starts empty, and
// re-observing the still-divergent state re-populates it. A crash that dropped the deferred
// trackUnresolved therefore self-heals on the next observation — no durable state is lost.
func TestDeferredEffects_TrackerSelfHealsAfterRestart(t *testing.T) {
	dir := t.TempDir()
	c1, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatalf("NewLocalClient c1: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c1); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// Model "the deferred trackUnresolved fired" on the original process.
	c1.trackUnresolved("vm_interfaces", "vm1\x00neta", []interface{}{"X"}, []interface{}{"Y"}, pathAE, "uncategorized")
	if !c1.anyUnresolved() {
		t.Fatal("precondition: c1 should be tracking the tie")
	}
	c1.Close()

	// Restart: a fresh Client on the same DB starts with an EMPTY tracker (the crash lost the
	// in-memory observation).
	c2, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatalf("NewLocalClient c2: %v", err)
	}
	t.Cleanup(func() { c2.Close() })
	if c2.anyUnresolved() {
		t.Fatal("a fresh Client must start with an empty in-memory tie tracker")
	}
	// Re-observing the same persistent divergence (what the next AE cycle does) re-tracks it.
	c2.trackUnresolved("vm_interfaces", "vm1\x00neta", []interface{}{"X"}, []interface{}{"Y"}, pathAE, "uncategorized")
	if !c2.anyUnresolved() {
		t.Fatal("re-observation after restart must re-populate the tie tracker (self-heal)")
	}
}

// TestDeferredEffects_NoClosureWritesDB is a source guard for the load-bearing invariant: a
// closure scheduled via deferAfterCommit must never perform a DB write. If one did, a crash in
// the commit→run window would split that write from the transaction it was meant to accompany.
// It parses the package and asserts no inline deferAfterCommit closure body contains a
// tx/db/Exec/Query/Execute call.
func TestDeferredEffects_NoClosureWritesDB(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	dbWriteMethods := map[string]bool{
		"Exec": true, "ExecContext": true, "Query": true, "QueryContext": true,
		"QueryRow": true, "QueryRowContext": true, "Execute": true, "ExecuteRows": true,
		"ExecuteBatch": true, "ExecuteDeferred": true, "ExecuteBatchGuarded": true,
		"Prepare": true, "PrepareContext": true, "Begin": true, "BeginTx": true,
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "deferAfterCommit" || len(call.Args) < 2 {
				return true
			}
			lit, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
			if !ok {
				return true // an ident-passed effect (resolveTie's closures) — vetted separately
			}
			checked++
			ast.Inspect(lit.Body, func(bn ast.Node) bool {
				bc, ok := bn.(*ast.CallExpr)
				if !ok {
					return true
				}
				bs, ok := bc.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if dbWriteMethods[bs.Sel.Name] {
					t.Errorf("%s:%d: a deferAfterCommit closure calls .%s(...) — a deferred effect must not touch the DB "+
						"(a crash between commit and runDeferredEffects would split it from its transaction)",
						f, fset.Position(bc.Pos()).Line, bs.Sel.Name)
				}
				return true
			})
			return true
		})
	}
	if checked == 0 {
		t.Fatal("source guard found no inline deferAfterCommit closures — the scan is broken")
	}
}
