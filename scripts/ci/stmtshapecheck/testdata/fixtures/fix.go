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

// UnkeyedComposite: a non-empty Statement without a keyed SQL field must fail closed.
func UnkeyedComposite(c *corrosion.Client, ctx context.Context, p []interface{}) {
	_ = c.ExecuteBatch(ctx, []corrosion.Statement{{Params: p}}) // want: unresolved
}

// recSelf is directly recursive; the guard's visited set must stop, not hang.
func recSelf() []corrosion.Statement { return recSelf() }

func RecursiveBatch(c *corrosion.Client, ctx context.Context) {
	_ = c.ExecuteBatch(ctx, recSelf()) // want: unresolved (recursion guarded)
}

// UnrelatedExecute uses text/template.Execute — a different Execute; must NOT be flagged.
func UnrelatedExecute(tmpl *template.Template) {
	_ = tmpl.Execute(nil, "UPDATE t SET a = ? WHERE id = ?")
}
