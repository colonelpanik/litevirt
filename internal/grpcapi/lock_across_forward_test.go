package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestNoHandlerHoldsAVMLockAcrossAPeerForward is a source-level guard.
//
// A handler that takes the per-VM (or per-container) process lock and then
// forwards to the owning host still holds that lock for the whole round trip.
// Two nodes with a contradictory view of who owns a VM -- an in-flight
// migration, a stale host_name -- each lock it and forward to the other, and
// both block until the gRPC deadlines fire, with every other operation on that
// VM queued behind them on both hosts.
//
// The three snapshot handlers already spell this rule out ("never hold a
// process lock across a peer RPC"); DeleteVM, CutoverVM and RebuildVM did not
// follow it. A behavioural test cannot reach the arrangement without two real
// daemons and a contradictory database, so the rule is checked where it is
// actually expressible: in the shape of the code.
func TestNoHandlerHoldsAVMLockAcrossAPeerForward(t *testing.T) {
	funcRe := regexp.MustCompile(`\nfunc \(s \*Server\) (\w+)\(`)
	// releaseOnce(...) wraps the lock in the handlers that release before a
	// forward; without the optional group this scan never saw them lock at all,
	// and passed them whatever they did afterwards.
	lockRe := regexp.MustCompile(`unlock\s*:=\s*(releaseOnce\()?s\.lock(VM|Container)\(`)
	// One or two tabs: a STATEMENT-level release. The closure that defines
	// releaseLock contains `unlock()` three tabs deep, and matching that would
	// let a handler pass by merely declaring the helper it never calls.
	// A trailing comment is allowed, because every call site carries one.
	releaseRe := regexp.MustCompile("^\t{1,2}(releaseLock|releaseLocks|unlock)\\(\\)(\\s*//.*)?$")

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(src)
		locs := funcRe.FindAllStringSubmatchIndex(text, -1)
		for i, loc := range locs {
			end := len(text)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			body := text[loc[0]:end]
			fname := text[loc[2]:loc[3]]

			lines := strings.Split(body, "\n")
			lock, forward, release := -1, -1, -1
			for n, l := range lines {
				if lock < 0 && lockRe.MatchString(l) {
					lock = n
				}
				// lockVM used in a loop (CutoverVM) appends instead.
				if lock < 0 && strings.Contains(l, "s.lockVM(") && strings.Contains(l, "append(") {
					lock = n
				}
				if lock >= 0 && release < 0 && releaseRe.MatchString(l) {
					release = n
				}
				if lock >= 0 && forward < 0 && strings.Contains(l, "s.peerClient(") {
					forward = n
				}
			}
			if lock >= 0 && forward > lock && (release < 0 || release > forward) {
				t.Errorf("%s: %s takes a per-VM lock and forwards to a peer while still "+
					"holding it; release before the forward, as the snapshot handlers do",
					name, fname)
			}
		}
	}
}

// A per-VM lock must never be held across a peer RPC.
//
// lockVM hands back a plain sync.Mutex with no context, so waiting on it cannot
// be interrupted or timed out. Holding it across a forward pins the lock for the
// whole remote call — minutes for a memory snapshot, indefinitely if the peer
// hangs — and blocks every other lifecycle RPC for that VM on this node.
//
// Worse, it deadlocks on divergent vms.host_name replicas: A believes B owns the
// VM and B believes A does, so A locks, calls B, B locks, calls A, and A's inner
// handler blocks forever on the mutex it already holds. Neither call returns and
// the VM is permanently wedged on A.
//
// StartVM shows the correct shape — read the row, authorize, forward if remote,
// and only then lock and re-read — and says so in a comment. AttachDevice and
// DetachDevice place the lock after the forward for the same reason.
func TestNoPerVMLockIsHeldAcrossAPeerForward(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var violations []string
	forwards := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, name, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			lockPos := firstCallPos(fn, func(sel *ast.SelectorExpr) bool { return sel.Sel.Name == "lockVM" })
			if !lockPos.IsValid() {
				continue
			}
			// The forward's receiver is whatever peerClient/dialPeer was assigned
			// to, NOT a fixed name. Matching the literal identifier "client" made
			// the scan blind to every handler that spells it otherwise —
			// snapshot_container.go uses `c`, reseed.go uses `peer` — so an
			// entire class of forwards was invisible and a new handler naming its
			// client anything else got no coverage at all.
			peerVars := peerClientVars(fn)
			if len(peerVars) == 0 {
				continue
			}
			// DEFERRED unlocks do not count: `defer unlock()` runs at RETURN, not
			// where it is written, so a deferred release sitting above a forward
			// releases nothing while that forward is in flight. Counting it was
			// the bug in the first version of this scan, and it made the whole
			// test pass against code that was plainly holding the lock.
			//
			// Nor do calls inside a function LITERAL: the closure that defines an
			// idempotent releaseLock contains `unlock()`, and counting that call
			// at the closure's position let a handler pass by declaring a
			// release it never makes. The named release helpers count where they
			// are CALLED instead.
			var unlockPositions []token.Pos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n.(type) {
				case *ast.DeferStmt, *ast.FuncLit:
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok {
					switch id.Name {
					case "unlock", "releaseLock", "releaseLocks":
						unlockPositions = append(unlockPositions, call.Pos())
					}
				}
				return true
			})
			// Every peer forward in this function.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || !peerVars[recv.Name] {
					return true
				}
				forwards++
				if call.Pos() < lockPos {
					return true // forwarded before taking the lock: the correct shape
				}
				for _, u := range unlockPositions {
					if u < call.Pos() {
						return true // released before forwarding
					}
				}
				// A BOUNDED context is tolerated. Holding the lock across a
				// remote call is only unbounded-bad when the remote call itself
				// is unbounded: DeleteVM deliberately proxies under a 2-minute
				// proxyCtx and probes under a 15-second probeCtx, so its lock is
				// held for a known maximum and the cycle breaks on its own. A
				// forward handed the raw handler ctx has no such bound and waits
				// forever on a hung peer.
				if len(call.Args) > 0 {
					if id, ok := call.Args[0].(*ast.Ident); ok && id.Name != "ctx" {
						return true
					}
				}
				violations = append(violations,
					name+":"+strconv.Itoa(fset.Position(call.Pos()).Line)+" in "+fn.Name.Name+
						" → "+recv.Name+"."+sel.Sel.Name)
				return true
			})
		}
	}

	if forwards == 0 {
		t.Fatal("found no peer forwards at all; the matcher is broken, not the code")
	}
	for _, v := range violations {
		t.Errorf("%s: a per-VM lock is still held while forwarding to a peer. lockVM is an "+
			"uninterruptible sync.Mutex, so this pins the VM's lock for the whole remote "+
			"call and deadlocks outright when two nodes each believe the other owns the VM. "+
			"Release before forwarding, as StartVM does.", v)
	}
}

func firstCallPos(fn *ast.FuncDecl, match func(*ast.SelectorExpr) bool) token.Pos {
	var out token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if out.IsValid() {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && match(sel) {
			out = call.Pos()
			return false
		}
		return true
	})
	return out
}

// peerClientVars returns the identifiers in fn that hold a peer client — the
// left-hand side of an assignment from peerClient or dialPeer.
func peerClientVars(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		// The two helpers that hand back a peer client, plus the raw
		// constructor.
		//
		// NewLiteVirtClient recovers no coverage in the tree as it stands: the
		// one function that builds a client that way, notifyTargetHostOfVM,
		// takes no per-VM lock, so the scan skips it before it ever looks for a
		// client. An earlier version of this comment claimed the old scan "saw
		// that one" — it did not, and neither does this one. The arm is here so
		// that a future handler which locks AND builds its client directly is
		// covered, which is the case the helper-only match would miss.
		case "peerClient", "dialPeer", "NewLiteVirtClient":
		default:
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
			out[id.Name] = true
		}
		return true
	})
	// Deliberately NOT seeded with the literal name "client". Adding it
	// unconditionally restored the old coverage at the cost of matching every
	// unrelated `client` in the package — an HTTP, IPAM or metrics client held
	// across a lock would be reported as a peer RPC, failing CI on something
	// that has nothing to do with peer forwarding. It also made the set never
	// empty, so the fast-path skip below became dead code. The shape that
	// mattered, `client := pb.NewLiteVirtClient(conn)`, is matched by name of
	// the CONSTRUCTOR above, whatever the variable is called.
	return out
}
