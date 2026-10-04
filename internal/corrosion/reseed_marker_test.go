package corrosion

import (
	"context"
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/hlc"
)

// openFileClient opens a file-backed client on the same path twice over, which
// is the only way to test what this marker exists for: an in-memory DB cannot
// be reopened after the process that held it died.
func openFileClient(t *testing.T, dir string) *Client {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(dir, "state.db")))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping sqlite: %v", err)
	}
	return &Client{
		db:               db,
		hostName:         "test-node",
		clock:            hlc.NewClock("test-node"),
		replicatorNotify: make(chan struct{}, 1),
		membershipNotify: make(chan struct{}, 1),
		leaseTermLedger:  testLeaseTermLedgerOpen,
	}
}

// The marker's entire job is to outlive the process that set it. A reseed that
// dies between the operator merge and the sensitive merge leaves users and their
// password hashes restored while user_2fa is still empty, and nothing in the
// running process survives to say so.
func TestReseedMarker_SurvivesTheProcessThatSetIt(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	first := openFileClient(t, dir)
	if err := InitSchema(ctx, first); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := first.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}
	// The daemon dies here, mid-reseed.
	first.db.Close()

	second := openFileClient(t, dir)
	defer second.db.Close()
	if err := InitSchema(ctx, second); err != nil {
		t.Fatalf("InitSchema on reopen: %v", err)
	}

	incomplete, source, err := second.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if !incomplete {
		t.Fatal("ReseedIncomplete = false after a restart mid-reseed; " +
			"the marker did not survive, so nothing stops this node serving logins " +
			"with an empty user_2fa")
	}
	if source != "kvm001" {
		t.Errorf("source = %q, want %q — an operator needs to know which peer to repeat the reseed from", source, "kvm001")
	}
}

// Only a completed reseed clears it. This is the pair to the test above: the
// marker has to be releasable, or the first reseed would wedge the node
// permanently.
func TestReseedMarker_FinishClears(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := openFileClient(t, dir)
	defer c.db.Close()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	if _, err := c.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}
	if err := c.FinishReseed(ctx, 1); err != nil {
		t.Fatalf("FinishReseed: %v", err)
	}

	incomplete, _, err := c.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if incomplete {
		t.Error("ReseedIncomplete = true after FinishReseed; a completed reseed must release the node")
	}
}

// A fresh node has never reseeded and must serve normally.
func TestReseedMarker_AbsentOnAFreshNode(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	incomplete, _, err := c.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if incomplete {
		t.Error("ReseedIncomplete = true on a node that has never reseeded")
	}
}

// A second BeginReseed must not collide with the first. A repeat reseed is the
// documented recovery path, so it has to be callable while the marker is set.
func TestReseedMarker_ARepeatReseedReplacesTheMarker(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := openFileClient(t, dir)
	defer c.db.Close()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	if _, err := c.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("first BeginReseed: %v", err)
	}
	if _, err := c.BeginReseed(ctx, "kvm002"); err != nil {
		t.Fatalf("second BeginReseed (the repeat-reseed recovery path): %v", err)
	}

	incomplete, source, err := c.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if !incomplete {
		t.Fatal("ReseedIncomplete = false while a repeat reseed is in flight")
	}
	if source != "kvm002" {
		t.Errorf("source = %q, want %q — the marker must name the reseed actually running", source, "kvm002")
	}
}

// The marker must not replicate. It describes one node's interrupted operation;
// a peer that adopted it would refuse logins for a reseed it never ran.
func TestReseedMarker_IsNotReplicated(t *testing.T) {
	for _, name := range tableNames {
		if name == "reseed_in_progress" {
			t.Fatal("reseed_in_progress is in sync.go tableNames; it would replicate to peers " +
				"and lock them out over a reseed they never ran")
		}
	}
	for _, name := range sensitiveTableNames {
		if name == "reseed_in_progress" {
			t.Fatal("reseed_in_progress is in sensitiveTableNames; it would replicate to peers")
		}
	}
}

// The discard loop walks the replicated table names, so a marker absent from
// them is structurally safe from it. This pins that reasoning: the marker set
// before the discard must still be there after it.
func TestReseedMarker_SurvivesTheDiscardItGuards(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := c.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}

	if _, err := c.DiscardReplicatedStateForReseed(ctx); err != nil {
		t.Fatalf("DiscardReplicatedStateForReseed: %v", err)
	}

	incomplete, _, err := c.ReseedIncomplete(ctx)
	if err != nil {
		t.Fatalf("ReseedIncomplete: %v", err)
	}
	if !incomplete {
		t.Fatal("the discard deleted the marker that guards it — the window is now unguarded " +
			"for exactly the operation the marker exists for")
	}
}

// The fence must be ONE read, not two reads behind one function call.
//
// This is the second time this hole has been closed. The first fix collapsed
// the two ADMISSION-side calls — refuseLoginWhileReseedIncomplete read the
// marker, stampReseedFence read the fence again — into a single ReseedFence
// call, and asserted the result by counting call sites in
// reseed_login_gate.go. But ReseedFence itself then read twice, untransacted:
// ReseedIncomplete for the marker, then a separate SELECT for the generation.
// The scan could not see inside the call it was counting, so it certified an
// invariant the code did not have, and the race survived one layer deeper:
//
//	marker read  -> clear
//	BeginReseed lands: marker set, generation N -> N+1
//	generation read -> N+1, stamped on the request
//	bcrypt; user_2fa is still empty, so Requires2FA is false
//	reseed finishes, marker cleared
//	mint: incomplete false, generation N+1 == entry -> a password-only session
//	      for an enrolled account
//
// Ordering the two reads generation-first would also close it, but only by an
// argument that has to be re-derived every time either side is touched. One
// statement is atomic in SQLite and needs no such argument, so that is the
// invariant pinned here — at the layer that actually reads, which is where the
// previous guard should have been.
func TestReseedFence_IsASingleRead(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "reseed_marker.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "ReseedFence" && d.Body != nil {
			fn = d
			break
		}
	}
	if fn == nil {
		t.Fatal("ReseedFence not found in reseed_marker.go; the matcher is broken or the " +
			"function was renamed — either way this guard is no longer guarding anything")
	}
	reads := map[string]int{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// A direct query, or a call to the marker reader that runs one of its
		// own. Counting only Query would let the two-read shape back in, which
		// is precisely how the previous guard was defeated.
		switch sel.Sel.Name {
		case "Query", "QueryContext", "ReseedIncomplete":
			reads[sel.Sel.Name]++
		}
		return true
	})
	total := 0
	for _, n := range reads {
		total += n
	}
	if total != 1 {
		t.Errorf("ReseedFence performs %d reads %v; it must perform exactly one. "+
			"Two untransacted reads let a reseed land between them, so the generation "+
			"stamped on an admitted request is the POST-reseed value and the comparison "+
			"at mintSession finds nothing changed.", total, reads)
	}
}

// The single statement must still report every state correctly. Collapsing two
// reads into one SELECT is only a fix if the SELECT answers what the two did:
// the shape guard above cannot tell a correct statement from a wrong one.
func TestReseedFence_ReportsEveryState(t *testing.T) {
	ctx := context.Background()
	c := openFileClient(t, t.TempDir())
	defer c.db.Close()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	fence := func(t *testing.T) (bool, string, int64) {
		t.Helper()
		incomplete, source, gen, err := c.ReseedFence(ctx)
		if err != nil {
			t.Fatalf("ReseedFence: %v", err)
		}
		return incomplete, source, gen
	}

	// A node that has never reseeded: nothing pending, and a generation of 0
	// that a later comparison can still be made against.
	if inc, src, gen := fence(t); inc || src != "" || gen != 0 {
		t.Errorf("fresh node: incomplete=%v source=%q generation=%d, want false/\"\"/0", inc, src, gen)
	}

	if _, err := c.BeginReseed(ctx, "kvm001"); err != nil {
		t.Fatalf("BeginReseed: %v", err)
	}
	// In flight: the marker names its source, and the generation has moved.
	if inc, src, gen := fence(t); !inc || src != "kvm001" || gen != 1 {
		t.Errorf("mid-reseed: incomplete=%v source=%q generation=%d, want true/\"kvm001\"/1", inc, src, gen)
	}

	if err := c.FinishReseed(ctx, 1); err != nil {
		t.Fatalf("FinishReseed: %v", err)
	}
	// Finished: the marker is clear, but the generation does NOT reset. This is
	// the half that carries the guarantee — a request admitted before the
	// reseed sees a different number here than the one it stamped, which is the
	// only evidence left that anything happened.
	if inc, src, gen := fence(t); inc || src != "" || gen != 1 {
		t.Errorf("after finish: incomplete=%v source=%q generation=%d, want false/\"\"/1", inc, src, gen)
	}

	if _, err := c.BeginReseed(ctx, "kvm002"); err != nil {
		t.Fatalf("second BeginReseed: %v", err)
	}
	if inc, src, gen := fence(t); !inc || src != "kvm002" || gen != 2 {
		t.Errorf("second reseed: incomplete=%v source=%q generation=%d, want true/\"kvm002\"/2", inc, src, gen)
	}
}

// An earlier reseed finishing must not clear a LATER one's marker.
//
// FinishReseed was an unconditional DELETE. Once two reseeds can overlap — a
// retry started while the first is still merging, or two operators racing — the
// first to finish lifted the login gate while the second still had the
// credential tables mid-discard. That is precisely the condition the marker
// exists to signal, cleared by the one party that had no right to say it was
// over: user_2fa is empty, Requires2FA comes back false, and an enrolled
// account is served a password-only session.
func TestReseedMarker_AnEarlierReseedDoesNotClearALaterOnesMarker(t *testing.T) {
	ctx := context.Background()
	c := openFileClient(t, t.TempDir())
	defer c.db.Close()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	first, err := c.BeginReseed(ctx, "kvm001")
	if err != nil {
		t.Fatalf("first BeginReseed: %v", err)
	}
	second, err := c.BeginReseed(ctx, "kvm002")
	if err != nil {
		t.Fatalf("second BeginReseed: %v", err)
	}
	if second <= first {
		t.Fatalf("generations did not advance: first=%d second=%d", first, second)
	}

	// The FIRST reseed finishes. The second is still mid-merge.
	if err := c.FinishReseed(ctx, first); err != nil {
		t.Fatalf("FinishReseed(first): %v", err)
	}
	incomplete, source, _, err := c.ReseedFence(ctx)
	if err != nil {
		t.Fatalf("ReseedFence: %v", err)
	}
	if !incomplete {
		t.Error("the marker was cleared by a reseed that did not set it — the node is still " +
			"mid-discard with user_2fa empty, and the login gate has just lifted over it")
	}
	if source != "kvm002" {
		t.Errorf("source = %q, want kvm002 — the marker must still name the reseed in flight", source)
	}

	// The reseed that actually owns it may clear it.
	if err := c.FinishReseed(ctx, second); err != nil {
		t.Fatalf("FinishReseed(second): %v", err)
	}
	if incomplete, _, _, err := c.ReseedFence(ctx); err != nil || incomplete {
		t.Errorf("the owning reseed could not clear its own marker (incomplete=%v err=%v)", incomplete, err)
	}
}

// BeginReseed's two writes must be ONE transaction.
//
// The single-statement fence read makes the two values consistent with each
// other, but it cannot make them consistent with a WRITER that lands halfway.
// With the marker set and the generation bumped as separate statements, the
// safety depended on that order and nothing else: a fence read landing after a
// bump but before the marker write sees a clear marker and the POST-reseed
// generation, is admitted, stamps that value, and the mint later compares equal
// against a marker that has since been cleared — a password-only session for an
// enrolled account, which is the whole condition being guarded.
//
// Swapping those two statements would have reopened it silently. The
// transaction removes the dependency rather than documenting it, and this
// pins the transaction.
func TestBeginReseed_WritesBothMarkersInOneTransaction(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "reseed_marker.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var fn *ast.FuncDecl
	for _, decl := range f.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "BeginReseed" && d.Body != nil {
			fn = d
			break
		}
	}
	if fn == nil {
		t.Fatal("BeginReseed not found; the matcher is broken or the function was renamed")
	}
	seen := map[string]int{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "BeginTx", "Commit", "execLocal", "ExecContext":
					seen[sel.Sel.Name]++
				}
			}
		}
		return true
	})
	if seen["BeginTx"] != 1 || seen["Commit"] != 1 {
		t.Errorf("BeginReseed has BeginTx=%d Commit=%d, want 1 each — its marker write and "+
			"generation bump must land together or not at all",
			seen["BeginTx"], seen["Commit"])
	}
	if seen["execLocal"] != 0 {
		t.Errorf("BeginReseed makes %d execLocal call(s); those run outside the transaction, "+
			"which is the split this guard exists to prevent", seen["execLocal"])
	}
}
