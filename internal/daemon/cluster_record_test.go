package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The `cluster` row is the root of every NetBox identity litevirt mints — the
// cluster fingerprint is the first component of `lv:<fingerprint>:<uuid>:<mac>`,
// and corrosion.ClusterFingerprint reads it from that one replicated row.
//
// Nothing in production ever wrote it. Every INSERT INTO cluster in the tree was
// in a test, so the whole NetBox integration derived no fingerprint, minted no
// identity and refused every bind on a real cluster — while the suite stayed
// green because the harnesses seeded by hand what the daemon never created.
//
// So this file pins BOTH halves: that the startup step heals the row, and that
// Run actually performs it. A heal nothing calls is the bug all over again.

func TestDaemonHealsTheClusterRecordAtStartup(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	pkiDir := t.TempDir()
	const caPEM = "-----BEGIN CERTIFICATE-----\ndaemon-startup-ca\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(filepath.Join(pkiDir, "ca.crt"), []byte(caPEM), 0o644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}

	if _, err := corrosion.ClusterFingerprint(ctx, db); err == nil {
		t.Fatal("a freshly initialised cluster must not yield a fingerprint before the heal")
	}

	d := &Daemon{cfg: &Config{PKIDir: pkiDir}, db: db}
	d.ensureClusterRecord(ctx)

	if _, err := corrosion.ClusterFingerprint(ctx, db); err != nil {
		t.Fatalf("ClusterFingerprint after daemon startup: %v", err)
	}
}

// A node that has not been `host init`ed has no CA on disk. It must still boot:
// the heal is one startup step among many and the NetBox feature simply stays
// fail-closed until a CA exists.
func TestDaemonStartupHealSurvivesAMissingCA(t *testing.T) {
	ctx := context.Background()
	db := newHostTestClient(t)

	d := &Daemon{cfg: &Config{PKIDir: t.TempDir()}, db: db}
	d.ensureClusterRecord(ctx)

	if _, err := corrosion.ClusterFingerprint(ctx, db); err == nil {
		t.Fatal("with no CA on disk the fingerprint must stay underivable")
	}
}

// Run must actually perform the heal, and it must do so AFTER InitSchema — the
// `cluster` table does not exist before it.
//
// A behavioural test cannot reach this: Run opens libvirt, binds sockets and
// joins gossip, so nothing in this package can drive it. The call site is the
// entire finding, so it is asserted against the source.
func TestRunHealsTheClusterRecordAfterInitSchema(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatalf("parse daemon.go: %v", err)
	}

	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "Run" && fn.Recv != nil {
			run = fn
			break
		}
	}
	if run == nil {
		t.Fatal("no (*Daemon).Run in daemon.go")
	}

	initSchemaAt, healAt := -1, -1
	ast.Inspect(run, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			if fn.Sel.Name == "InitSchema" && initSchemaAt < 0 {
				initSchemaAt = int(call.Pos())
			}
			if fn.Sel.Name == "ensureClusterRecord" && healAt < 0 {
				healAt = int(call.Pos())
			}
		}
		return true
	})

	if healAt < 0 {
		t.Fatal("(*Daemon).Run never calls ensureClusterRecord — nothing in production writes the " +
			"`cluster` row, so no NetBox identity can be minted on a real cluster")
	}
	if initSchemaAt < 0 {
		t.Fatal("(*Daemon).Run never calls InitSchema")
	}
	if healAt < initSchemaAt {
		t.Fatal("Run heals the cluster record before InitSchema — the `cluster` table does not exist yet")
	}
}
