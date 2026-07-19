// Package fixtures exercises every call/dataflow pattern the stmtshapecheck guard must
// classify. It is loaded (with type info) by the guard's own tests; it is under testdata so
// it never participates in normal builds. Line-tagged comments (want: …) let the test
// assert the classification at each call.
package fixtures

import (
	"context"
	"database/sql"
	"text/template"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func Direct(c *corrosion.Client, ctx context.Context) {
	_ = c.Execute(ctx, "INSERT INTO t (a, updated_at) VALUES (?, ?)", 1, 2) // want: resolved
}

const constSQL = "UPDATE t SET a = ? WHERE id = ?"

func ConstBuilder(c *corrosion.Client, ctx context.Context) {
	_ = c.Execute(ctx, constSQL, 1, 2) // want: resolved (compile-time const)
}

func InlineBatch(c *corrosion.Client, ctx context.Context) {
	_ = c.ExecuteBatch(ctx, []corrosion.Statement{ // want: 2 resolved
		{SQL: "DELETE FROM t WHERE id = ?"},
		{SQL: "UPDATE t SET a = ? WHERE id = ?"},
	})
}

func AppendedBatch(c *corrosion.Client, ctx context.Context, n int) {
	stmts := make([]corrosion.Statement, 0, n) // make init: benign
	stmts = append(stmts, corrosion.Statement{SQL: "INSERT INTO t (a) VALUES (?)"})
	for i := 0; i < n; i++ {
		stmts = append(stmts, corrosion.Statement{SQL: "UPDATE t SET a = ? WHERE id = ?"})
	}
	_ = c.ExecuteBatch(ctx, stmts) // want: resolved (make + appends)
}

func helperStmt() corrosion.Statement {
	return corrosion.Statement{SQL: "INSERT INTO t (a) VALUES (?)"}
}

func HelperReturnBatch(c *corrosion.Client, ctx context.Context) {
	_ = c.ExecuteBatch(ctx, []corrosion.Statement{helperStmt()}) // want: resolved via helper
}

func Guarded(c *corrosion.Client, ctx context.Context, g func(*sql.Tx) (bool, error)) {
	_, _ = c.ExecuteBatchGuarded(ctx, g, []corrosion.Statement{ // want: resolved (arg[2])
		{SQL: "INSERT INTO t (a) VALUES (?)"},
	})
}

// Shadowed: the call uses the PARAMETER stmts; a shadowing inner `stmts :=` is a different
// object and must NOT make it appear resolved.
func Shadowed(c *corrosion.Client, ctx context.Context, stmts []corrosion.Statement) {
	if true {
		stmts := []corrosion.Statement{{SQL: "INSERT INTO t (a) VALUES (?)"}}
		_ = stmts
	}
	_ = c.ExecuteBatch(ctx, stmts) // want: unresolved (shadowing must not resolve)
}

func DynamicBuilder(c *corrosion.Client, ctx context.Context, col string) {
	_ = c.Execute(ctx, "UPDATE t SET "+col+" = ? WHERE id = ?", 1, 2) // want: dynamic
}

// UnregisteredStatic emits a static, parseable statement whose shape is NOT in the compatibility
// ledger (a real table with a column no builder uses), so scanPkg classifies it as a RESOLVED
// finding, yet the complete guard decision (computeGaps) must still FAIL it.
func UnregisteredStatic(c *corrosion.Client, ctx context.Context) {
	_ = c.Execute(ctx, "INSERT INTO images (name, bogus_extra, updated_at) VALUES (?, ?, ?)", 1, 2, 3) // want: resolved
}

// SnapshotParentIDWriter binds snapshots.parent_id — a self-reference the H1 identity collapse fails
// closed on rather than rewriting. It parses (resolved finding), but the complete guard must FAIL it
// because LedgerEntryFor rejects the non-overridable invariant.
func SnapshotParentIDWriter(c *corrosion.Client, ctx context.Context) {
	_ = c.Execute(ctx, "INSERT INTO snapshots (id, vm_name, host_name, name, parent_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)", 1, 2, 3, 4, 5, 6, 7) // want: resolved
}

// UnkeyedComposite: a non-empty Statement without a keyed SQL field must fail closed.
func UnkeyedComposite(c *corrosion.Client, ctx context.Context, p []interface{}) {
	_ = c.ExecuteBatch(ctx, []corrosion.Statement{{Params: p}}) // want: unresolved
}

// recSelf is directly recursive; the guard's visited set must stop, not hang.
func recSelf() []corrosion.Statement { return recSelf() }

func RecursiveBatch(c *corrosion.Client, ctx context.Context) {
	_ = c.ExecuteBatch(ctx, recSelf()) // want: unresolved (recursion guarded)
}

// AssignAfterCall: the only assignment to the param is AFTER the call, so it must not count
// (flow-sensitivity, review finding 1).
func AssignAfterCall(c *corrosion.Client, ctx context.Context, stmts []corrosion.Statement) {
	_ = c.ExecuteBatch(ctx, stmts) // want: unresolved (assignment is after the call)
	stmts = []corrosion.Statement{{SQL: "INSERT INTO t (a) VALUES (?)"}}
	_ = stmts
}

// CondParam: a conditional (non-dominating) reassignment of a PARAMETER must not make it
// resolved — the param's input value can still reach the call.
func CondParam(c *corrosion.Client, ctx context.Context, cond bool, stmts []corrosion.Statement) {
	if cond {
		stmts = []corrosion.Statement{{SQL: "INSERT INTO t (a) VALUES (?)"}}
	}
	_ = c.ExecuteBatch(ctx, stmts) // want: unresolved (parameter, non-dominating def)
}

// SameHelperTwice: the same non-recursive helper appears twice in one batch; the visited set
// must be popped so the second call is not mistaken for recursion (review finding 4).
func SameHelperTwice(c *corrosion.Client, ctx context.Context) {
	_ = c.ExecuteBatch(ctx, []corrosion.Statement{helperStmt(), helperStmt()}) // want: 2 resolved
}

// mutateStmts is an opaque helper (to the guard) that can rewrite the slice's elements in
// place, since a slice shares its backing array.
func mutateStmts(stmts []corrosion.Statement) {
	if len(stmts) > 0 {
		stmts[0].SQL = "DROP TABLE t"
	}
}

// FieldMutation: the Statement is fingerprinted from its literal, then its SQL field is
// overwritten before the call — the executed SQL differs from the fingerprint (finding: field
// mutation). Must fail closed.
func FieldMutation(c *corrosion.Client, ctx context.Context, dyn string) {
	stmt := corrosion.Statement{SQL: "INSERT INTO t (a) VALUES (?)"}
	stmt.SQL = dyn
	_ = c.ExecuteBatch(ctx, []corrosion.Statement{stmt}) // want: unresolved (field mutated in place)
}

// IndexedReplacement: an element of the tracked slice is replaced by index before the call
// (finding: indexed replacement). Must fail closed.
func IndexedReplacement(c *corrosion.Client, ctx context.Context, dyn string) {
	stmts := []corrosion.Statement{{SQL: "INSERT INTO t (a) VALUES (?)"}}
	stmts[0] = corrosion.Statement{SQL: dyn}
	_ = c.ExecuteBatch(ctx, stmts) // want: unresolved (element replaced by index)
}

// HelperMutation: the tracked slice is passed to an opaque helper that can mutate its backing
// array before the call (finding: escape to unknown code). Must fail closed.
func HelperMutation(c *corrosion.Client, ctx context.Context) {
	stmts := []corrosion.Statement{{SQL: "INSERT INTO t (a) VALUES (?)"}}
	mutateStmts(stmts)
	_ = c.ExecuteBatch(ctx, stmts) // want: unresolved (slice escapes to unknown helper)
}

// UnrelatedExecute uses text/template.Execute — a different Execute; must NOT be flagged.
func UnrelatedExecute(tmpl *template.Template) {
	_ = tmpl.Execute(nil, "UPDATE t SET a = ? WHERE id = ?")
}
