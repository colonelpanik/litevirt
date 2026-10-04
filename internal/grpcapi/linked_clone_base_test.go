package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv vm delete base --keep-disks` exists so linked clones stay valid: it
// tombstones the base's rows and leaves base-root.qcow2 on disk, still named by
// every overlay's backing_disk. Creating a NEW VM that reuses the name then runs
// the debris glob for "base-*.qcow2" — and the keep set it is given is derived
// from the named VM's LIVE rows, of which a freshly-created name has none by
// construction (createVM refuses a duplicate live name before reaching here).
//
// So the guard cannot protect anything on that path, the base file is removed,
// and every clone's backing chain is destroyed with no recovery.
func TestProtectedDiskPaths_ProtectsABaseStillBackingALiveClone(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	basePath := s.images.DiskPath("base", "root")
	if err := os.MkdirAll(filepath.Dir(basePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(basePath, []byte("base image"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A live linked clone whose overlay still names the base as its backing file.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "clone1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "clone1", DiskName: "root", HostName: "test-host",
			Path: s.images.DiskPath("clone1", "root"), StorageType: "local",
			BackingDisk: basePath,
		}},
	); err != nil {
		t.Fatalf("InsertVM clone1: %v", err)
	}

	// The base itself has NO live rows — it was deleted with --keep-disks, and a
	// new VM is about to be created under the same name.
	s.sweepVMDiskDebris(ctx, "base")

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		t.Fatal("the debris glob deleted a base image that a live linked clone still names as " +
			"its backing file — every overlay's chain is destroyed, unrecoverably, and " +
			"--keep-disks exists precisely to prevent this")
	}
}

// protectedDiskPaths' own comment claims it "Fails CLOSED in both directions".
// Returning nil on a read error protects nothing, so the glob then deletes every
// <vm>-*.qcow2 including a live clone base — a transient SQLITE_BUSY is enough.
func TestProtectedDiskPaths_FailsClosedWhenItCannotRead(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	basePath := s.images.DiskPath("base", "root")
	if err := os.MkdirAll(filepath.Dir(basePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(basePath, []byte("base image"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Make every disk read fail.
	s.db.Close()

	s.sweepVMDiskDebris(ctx, "base")

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		t.Fatal("a failed disk read let the glob delete everything — the read that decides " +
			"whether a file is still referenced cannot fail OPEN, which is what the function's " +
			"own comment already claims it does not do")
	}
}

// No production caller may reach the RE-LISTING delete at all.
//
// The rule used to be "do not pass protectedDiskPaths into DeleteVMDisks
// inline", which matched one syntactic shape and nothing else. Splitting the
// call across a variable —
//
//	keep := s.protectedDiskPaths(ctx, n)
//	s.images.DeleteVMDisks(n, keep)
//
// — reintroduced the exact fail-open while the guard stayed green, so the guard
// could be walked around by a line break.
//
// The rule is now about the FUNCTION, not the argument shape. DeleteVMDisks
// lists again, so whatever it deletes is not what the caller computed
// protection against: a file appearing after the keep set was built is in no
// keep set, and a listing that succeeded for the caller but fails there turns
// "protect nothing" into "delete everything". Production sweeps go through
// sweepVMDiskDebris, which lists once and hands that one list to both halves
// via DeleteVMDisksIn. There is no argument shape left to get wrong.
func TestNoProductionCallerUsesTheRelistingDelete(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	seen := 0
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, n, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", n, perr)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "DeleteVMDisksIn":
				seen++ // the sanctioned form; counted so this scan cannot pass by matching nothing
			case "DeleteVMDisks":
				bad = append(bad, n+":"+strconv.Itoa(fset.Position(call.Pos()).Line))
			case "protectedDiskPaths":
				// The listing keep-set builder, deleted rather than guarded. It
				// returned an EMPTY keep set on a listing failure, so banning
				// only the delete half left the pair writeable: DeleteVMDisksIn
				// with protectedDiskPaths still protects nothing. Naming it here
				// keeps it from coming back under its inviting old name.
				bad = append(bad, n+":"+strconv.Itoa(fset.Position(call.Pos()).Line)+" (protectedDiskPaths)")
			}
			return true
		})
	}
	if seen == 0 {
		t.Error("no call to DeleteVMDisksIn was found anywhere in the package; either the sweep " +
			"stopped deleting disks or this matcher no longer matches the call it polices")
	}
	for _, b := range bad {
		t.Errorf("%s: DeleteVMDisks re-lists, so it deletes a set the caller never computed "+
			"protection against. Use sweepVMDiskDebris, which lists once and passes that list "+
			"to both protectedDiskPathsFrom and DeleteVMDisksIn.", b)
	}
}

// ONE listing must drive both the protection and the deletion.
//
// There were three independent VMDiskCandidates calls: the sweep's own guard,
// another inside the keep-set builder, and a third inside the delete. Protection
// was computed against one list and the deletion walked another, so the safety
// still rested on all three agreeing — the "survivable only because the
// downstream call fails identically" the change exists to remove.
//
// The observable consequence is a file that appears after the keep set was
// built: it is in no keep set, because it did not exist when protection was
// computed, and a re-listing deletion sweeps it anyway. A disk written
// concurrently with a delete is destroyed with no reference check ever run
// against it. Driving sweepVMDiskDebrisIn with an explicit list is that
// interleaving, without a test-only global in the production delete path.
func TestSweepVMDiskDebris_DeletesOnlyWhatItListedAndProtected(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	seed := func(name string) string {
		p := s.images.DiskPath(name, "root")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("disk"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	debris := seed("vm1")

	candidates, err := s.images.VMDiskCandidates("vm1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// Appears AFTER the candidate list was taken, so nothing ever asked whether
	// it is referenced.
	latecomer := seed("vm1-extra")

	s.sweepVMDiskDebrisIn(ctx, "vm1", candidates)

	if _, err := os.Stat(debris); !os.IsNotExist(err) {
		t.Errorf("the debris this sweep listed and did not protect was left behind (%v); the "+
			"sweep did nothing, so this test proves nothing about what it spares", err)
	}
	if _, err := os.Stat(latecomer); os.IsNotExist(err) {
		t.Error("a disk that did not exist when the candidate list was taken was deleted anyway " +
			"— the deletion re-listed instead of walking the list protection was derived from, " +
			"so a file no reference check ever saw was destroyed")
	}
}
