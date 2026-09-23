// Command runningcheck enforces litevirt's marker chokepoint: a VM row must
// never say "running" without a marker naming the ownership generation that
// runtime belongs to.
//
// A row that says running while no marker names its generation is a workload
// nobody can prove. That window is what the dual-run detector's newborn grace
// exists to tolerate, so closing it everywhere is what eventually makes that
// grace deletable — and a new unrouted call site would silently reopen it.
//
// There are two publish orderings — mark-then-commit for a writer that leaves
// the ownership generation alone, commit-then-mark for one that advances it in
// the same statement. internal/health/publish.go states why; this tool only has
// to enforce that each writer takes the right one, because using the WRONG
// ordering is as much a defect as using neither.
//
// The rules, all AST-checked:
//
//  1. A non-minting primitive whose state argument is a string literal other
//     than "running" is exempt — it cannot publish a running VM. Any other
//     state argument (literal "running", or a value only known at runtime) must
//     be inside a closure handed to a publish helper.
//  2. A minting primitive must always be inside such a closure, and it must be a
//     MINTED helper. There is no state argument to exempt it by.
//  3. A closure assigned to a variable and handed to a publish helper may ALSO
//     be invoked directly, but only inside a branch that has proven the state is
//     not "running" — otherwise the routing is decorative and the direct call
//     publishes unmarked.
//  4. A corrosion.VMRecord literal born at "running" — or at a state only known
//     at runtime — must be graduated by an assignOwnerEpochAtCreate call in the
//     same function. An insert lands at the vm_owner_epoch column default of 0,
//     convergence early-returns on zero, and the backfill that would graduate it
//     is gated behind enforcement.owner_epoch, which is off by default.
//  5. Every SQL statement in production code that writes the vms.state column
//     must be registered in the stateWritingStatements inventory below. Rules 1-4
//     police call sites against hand-maintained maps of writer NAMES, and a map
//     nobody is forced to update is a guard that decays — UpdateVMHost sat in one
//     as permanently exempt for exactly that reason. This rule closes the loop
//     from the other end: a new statement fails the build until someone says
//     which ordering it takes. `runningcheck -inventory` prints what to add.
//  6. Every FUNCTION that executes such a statement must be classified — in
//     nonMinting, minting or clientMethods, or in one of the two exemption maps
//     in writers.go. Rule 5 catches a new STATEMENT; on its own it passed a new
//     FUNCTION that ran an existing one, while rules 1-4 never looked at that
//     function because its name was in none of their maps. Rule 6 is the only
//     type-aware pass: half these statements are package-level consts referenced
//     across files, so resolving what SQL a function executes needs go/types
//     constant folding. See writers.go.
//
// A site that genuinely cannot be routed opts out with a trailing
// `//runningcheck:allow <reason>` comment on any line the statement spans. The
// four ownership HANDOFFS use this: they commit a row that names a DIFFERENT
// host while running on the host giving the VM away, whose domain libvirt has
// already undefined. Marking there would stamp a runtime that is going away, and
// for the post-cutover commit it would refuse the commit outright on every
// successful migration.
//
// Usage:
//
//	runningcheck -root .        # walk <root> for production .go files; exit 1 on any violation
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The two meanings a state-argument index can have besides a real position.
// They were both spelled -1 once, and that overload is exactly how UpdateVMHost
// ended up permanently exempt under a comment describing the other case.
const (
	// stateInVMRecord: the state travels inside a corrosion.VMRecord argument,
	// so rule 4 (born-running inserts) is what polices it.
	stateInVMRecord = -1
	// alwaysRunning: the statement hardcodes state='running' and takes no state
	// argument, so no literal can ever exempt it.
	alwaysRunning = -2
)

// nonMinting are corrosion writers that can set state='running' while leaving
// vm_owner_epoch alone. stateArg is the zero-based index of the state parameter,
// or -1 where the state travels inside a VMRecord (rule 4 covers those).
var nonMinting = map[string]int{
	"UpdateVMState":        3,
	"UpdateVMStateStrict":  3,
	"UpdateVMStateAtEpoch": 3,
	// UpdateVMHost(ctx, c, name, hostName, state) — a plain state argument that
	// goes straight into `UPDATE vms SET host_name = ?, state = ?`. It was
	// registered -1 here under a comment claiming the state travelled inside a
	// VMRecord; it does not, and -1 made it unconditionally exempt.
	"UpdateVMHost":             4,
	"CommitMigrationOwnership": 5,
	"InsertVM":                 stateInVMRecord,
	"InsertVMWithHardware":     stateInVMRecord,
}

// clientMethods are writers invoked as methods on the corrosion client
// (s.db.X(...)) rather than as package functions. corrosionCall cannot see
// them, and CommitVMCreateOperation's statement is a literal
// `UPDATE vms SET state = 'running'`.
var clientMethods = map[string]int{
	// Takes a VMRecord (index 3) whose State the guarded statement writes, so
	// rule 4 polices it exactly as it does the package-level inserts.
	"CommitVMCreateOperation": stateInVMRecord,
}

// minting are writers whose statement sets state='running' AND advances
// vm_owner_epoch together. The value is the zero-based index of the state
// parameter, or -1 for a writer that always publishes running and so can never
// be exempted by a literal.
var minting = map[string]int{
	"TransferVMOwner":      4,
	"TransferVMOwnerFresh": 4,
	"CompleteVMStartProof": alwaysRunning,
	// ReplaceVM installs a cutover's replacement with the state copied from its
	// row, not taken as an argument, so no literal can ever exempt a call.
	"ReplaceVM": alwaysRunning,
}

// The publish helpers, mapped to the zero-based index of their state argument —
// the value rule 3 must see a branch disprove before it accepts a direct
// invocation of a routed closure.
//
// mintedHelpers take the commit-then-mark ordering; plainHelpers the
// mark-then-commit one (see internal/health/publish.go for why the two exist).
// A minting primitive routed through a plain helper is a family mismatch, not a
// pass. A minted helper has NO state argument — it always publishes running —
// which is alwaysRunning here exactly as it is for the primitives.
var mintedHelpers = map[string]int{
	"publishRunningMinted":   alwaysRunning,
	"PublishVMRunningMinted": alwaysRunning,
}

var plainHelpers = map[string]int{
	// publishRunning(ctx, name, state, commit)
	"publishRunning": 2,
	// PublishVMRunning(ctx, virt, dataDir, name, state, epoch, commit)
	"PublishVMRunning": 4,
	// PublishRunningVia(ctx, virt, db, dataDir, hostName, name, state, commit)
	"PublishRunningVia": 6,
}

type violation struct {
	file string
	line int
	msg  string
}

func main() {
	root := flag.String("root", ".", "repository root to scan for production .go files")
	dump := flag.Bool("inventory", false,
		"print the normalized fingerprint of every UNREGISTERED vms.state statement and exit 0")
	flag.Parse()

	violations, err := scanTree(*root, *dump)
	if err == nil && !*dump {
		// Rule 6 is a separate, type-aware pass: it loads the module so a
		// statement held in a package-level const resolves to the functions that
		// execute it. Skipped under -inventory, which is about statements.
		var wv []violation
		wv, err = checkWriters(*root)
		violations = append(violations, wv...)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "runningcheck: %v\n", err)
		os.Exit(2)
	}

	if *dump {
		return
	}
	if len(violations) == 0 {
		fmt.Println("runningcheck: every running publish is routed through the marker chokepoint; OK")
		return
	}
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].file != violations[j].file {
			return violations[i].file < violations[j].file
		}
		return violations[i].line < violations[j].line
	})
	fmt.Fprintf(os.Stderr, "runningcheck: FAIL — %d unrouted or misrouted running publish(es):\n", len(violations))
	for _, v := range violations {
		fmt.Fprintf(os.Stderr, "  %s:%d: %s\n", v.file, v.line, v.msg)
	}
	fmt.Fprintf(os.Stderr,
		"\nA row that says \"running\" with no marker naming its generation is a workload\n"+
			"nobody can prove. Route the write through the chokepoint:\n"+
			"    s.publishRunning(ctx, name, state, func(ctx context.Context) error { ... })\n"+
			"or, when the statement ALSO advances vm_owner_epoch:\n"+
			"    s.publishRunningMinted(ctx, name, func(ctx context.Context) error { ... })\n"+
			"If the site genuinely cannot be routed — an ownership handoff marks the host\n"+
			"that is giving the VM away — add a trailing `//runningcheck:allow <reason>`.\n")
	os.Exit(1)
}

// scanTree walks root for production .go files and returns every violation.
//
// Extracted from main so a test can exercise THIS walk. The skip list used to
// live inline, and the test that covered it carried its own copy — which would
// have passed while main() regressed, since the two lists were never compared.
func scanTree(root string, dump bool) ([]violation, error) {
	var violations []violation
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			// .worktrees holds full checkouts of OTHER branches. They are
			// gitignored and not part of this tree, but the walk read their .go
			// files anyway: on a machine with six worktrees `make ci-guards`
			// reported 161 violations, every one a call site on another branch.
			// CI never saw it, because Actions checks out a clean tree — so the
			// guard was broken for exactly the local command developers are
			// told to run.
			case "vendor", ".git", "gen", ".worktrees":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		vs, perr := scanFileOpts(path, dump)
		if perr != nil {
			return perr
		}
		violations = append(violations, vs...)
		return nil
	})
	return violations, err
}

// fileScan carries the per-file state the rules share.
// directive is one //runningcheck:allow, tracked as a unit rather than as a set
// of lines: a reason block marks several lines, and per-line bookkeeping made
// every line but one look orphaned.
type directive struct {
	// line is where the token sits, and where a stale directive is reported.
	line int
	// covers are the lines this directive may suppress a statement on: its own
	// (the trailing form) and the one after its comment block (the block form).
	covers []int
	// used records whether it actually suppressed something. An orphaned
	// directive — its statement deleted or moved — would otherwise sit there
	// silently exempting whatever code next occupies those lines, which is the
	// self-defeating allowlist this guard exists to rule out.
	used bool
}

type fileScan struct {
	path       string
	fset       *token.FileSet
	directives []*directive
	out        []violation
	// dump is -inventory: print unregistered fingerprints instead of failing on
	// them. Per-scan state, not a package global — scanFile is called directly by
	// 20+ tests in one binary, and a global one of them set and did not restore
	// would make every later rule-5 assertion pass vacuously.
	dump bool
}

func scanFile(path string) ([]violation, error) { return scanFileOpts(path, false) }

func scanFileOpts(path string, dump bool) ([]violation, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s := &fileScan{path: path, fset: fset, dump: dump}
	// A directive is honored on any line the statement spans (the trailing form
	// writecheck uses) AND on the line immediately after a comment block that
	// carries it — these reasons run to several lines, and a block sitting
	// directly above the call reads far better than a trailing fragment.
	//
	// The token must START its comment, so this tool's own documentation of the
	// directive (which quotes it inside backticks) is not mistaken for one.
	for _, cg := range file.Comments {
		d := (*directive)(nil)
		for _, c := range cg.List {
			body := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
			if !strings.HasPrefix(body, "runningcheck:allow") {
				continue
			}
			ln := fset.Position(c.Slash).Line
			if d == nil {
				d = &directive{line: ln}
			}
			d.covers = append(d.covers, ln)
		}
		if d != nil {
			d.covers = append(d.covers, fset.Position(cg.End()).Line+1)
			s.directives = append(s.directives, d)
		}
	}

	// Rules are per-function: routing evidence (which closures reach a helper,
	// whether the function graduates its insert) is function-scoped.
	ast.Inspect(file, func(n ast.Node) bool {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body != nil {
				s.checkFunc(fn.Body)
			}
		}
		return true
	})
	// Rule 5 runs on EVERY production file. It was gated on internal/corrosion
	// under a comment asserting that no other package holds a vms.state
	// statement — exactly the sort of unenforced assumption rule 5 was written
	// to replace. The tool already walks every file, so the gate bought nothing
	// and let a statement added anywhere else escape the inventory entirely.
	s.checkStateStatements(file)

	// A directive that suppressed nothing is itself a violation.
	for _, d := range s.directives {
		if d.used {
			continue
		}
		s.out = append(s.out, violation{file: s.path, line: d.line,
			msg: "this //runningcheck:allow directive suppressed nothing — its statement was " +
				"deleted or moved. Remove it: left in place it silently exempts whatever code " +
				"next occupies these lines"})
	}
	return s.out, nil
}

// report anchors at the statement's first line but honors an allow directive on
// ANY line it spans — a routed call is usually multi-line, and the natural place
// for the directive is the closing line.
func (s *fileScan) report(n ast.Node, msg string) {
	start := s.fset.Position(n.Pos()).Line
	end := s.fset.Position(n.End()).Line
	for _, d := range s.directives {
		for _, ln := range d.covers {
			if ln >= start && ln <= end {
				d.used = true
				return
			}
		}
	}
	s.out = append(s.out, violation{file: s.path, line: start, msg: msg})
}

func (s *fileScan) checkFunc(body *ast.BlockStmt) {
	routed := collectRouting(body, s.fset)

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := corrosionCall(call)
		if name == "" {
			name = clientMethodCall(call)
		}
		switch {
		case hasKey(minting, name):
			if idx := minting[name]; idx >= 0 && idx < len(call.Args) { //nolint:nestif // one literal check
				if lit, ok := stringLit(call.Args[idx]); ok && lit != "running" {
					return true // a transfer that hands over a STOPPED VM publishes no runtime
				}
			}
			switch routed.family(call, s.fset) {
			case familyMinted:
				// Correct.
			case familyPlain:
				s.report(call, fmt.Sprintf("corrosion.%s(...) is a MINTING write routed through the "+
					"mark-then-commit helper; it would stamp the generation the row is about to leave "+
					"— use publishRunningMinted", name))
			default:
				s.report(call, fmt.Sprintf("corrosion.%s(...) publishes a running VM at a NEW generation "+
					"but is not routed through publishRunningMinted", name))
			}
		case hasKey(nonMinting, name) || hasKey(clientMethods, name):
			idx, ok := nonMinting[name]
			if !ok {
				idx = clientMethods[name]
			}
			if idx >= 0 && idx < len(call.Args) {
				if lit, ok := stringLit(call.Args[idx]); ok && lit != "running" {
					return true // cannot publish a running VM
				}
			}
			if idx == stateInVMRecord {
				return true // rule 4 polices the VMRecord it carries
			}
			if routed.family(call, s.fset) == familyNone {
				s.report(call, fmt.Sprintf("corrosion.%s(...) can publish a running VM but is not routed "+
					"through publishRunning", name))
			}
		}
		return true
	})

	// Rule 3: a routed closure variable may be invoked directly only under a
	// proven non-running branch.
	for _, use := range routed.directCalls(body, s.fset) {
		s.report(use.call, fmt.Sprintf("the routed closure %q is also invoked directly outside a branch "+
			"that proves the state is not \"running\"; that invocation publishes unmarked", use.name))
	}

	// Rule 4: born-running inserts must graduate, and the graduation must be in
	// the insert's OWN block. A function-wide check let a second born-running
	// insert on another branch ride on the first branch's call — and the routed
	// code already depends on branch placement: promote.go graduates inside
	// `if renamed`, templates.go inside `if state == "running"`.
	ast.Inspect(body, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || !isVMRecord(cl) {
			return true
		}
		st, found := stateField(cl)
		if !found {
			return true
		}
		if lit, ok := stringLit(st); ok && lit != "running" {
			return true
		}
		if graduatedInScope(body, cl, s.fset) {
			return true
		}
		s.report(cl, "a corrosion.VMRecord is inserted at a running (or runtime-determined) state "+
			"with no assignOwnerEpochAtCreate call in the same block; it would be born at "+
			"epoch 0, which convergence never repairs and the default-off backfill never graduates")
		return true
	})
}

// graduatedInScope reports whether the INNERMOST scope enclosing the insert
// graduates it — searching that scope and anything nested inside it, but not
// its parents.
//
// Innermost, not function-wide: promote.go's insert sits inside `if renamed`
// alongside its graduation, so a sibling `else` that inserts without one must
// not ride on it. Nested still counts, because templates.go inserts in the
// function body and graduates from an `if state == "running"` block inside it.
//
// A scope is a *ast.BlockStmt OR a switch/select case. A case clause holds its
// statements directly and is NOT a BlockStmt, so searching only blocks fell
// through every case to the enclosing function body — and one case's graduation
// then covered every sibling case, which is the function-wide hole this function
// was written to close, surviving in the one construct branchy code uses most.
func graduatedInScope(root ast.Node, insert ast.Node, fset *token.FileSet) bool {
	line := fset.Position(insert.Pos()).Line
	var best ast.Node
	bestSpan := 1 << 30
	ast.Inspect(root, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.BlockStmt, *ast.CaseClause, *ast.CommClause:
		default:
			return true
		}
		start, end := fset.Position(n.Pos()).Line, fset.Position(n.End()).Line
		if line < start || line > end {
			return true
		}
		if span := end - start; span < bestSpan {
			best, bestSpan = n, span
		}
		return true
	})
	if best == nil {
		return false
	}
	return callsGraduation(best)
}

// Rule 5: every SQL statement in production code that writes the vms.state
// column must be registered here.
//
// Rules 1-4 police CALL SITES against hand-maintained maps of writer names, and
// a map nobody is forced to update is a guard that decays: UpdateVMHost sat in
// nonMinting as permanently exempt for exactly that reason. This rule closes the
// loop from the other end — a new `UPDATE vms SET ... state = ?` fails the build
// until someone says which writer owns it and which ordering it takes.
//
// Matched on the statement's normalized text (whitespace collapsed, lowercased)
// rather than on its enclosing function: half of these are package-level consts
// that an AST-only pass cannot attribute to the function that executes them.
// Written here in their SOURCE form and normalized at startup, so reflowing a
// statement in corrosion does not read as a new one and the inventory stays
// legible as SQL.
//
// Each entry names the Go writer and how it is policed. Adding one is the point
// at which to ask whether that writer belongs in nonMinting, minting or
// clientMethods above. `runningcheck -inventory` prints the entries a new
// statement needs.
//
// Statements that normalize to the same text share an entry — UpdateVMState and
// UpdateVMStateStrict differ only in their Go-side row-count check, and
// UpdateVMHost and CommitMigrationOwnership execute character-identical SQL.
type stateStatement struct {
	sql string
	// writers names the Go functions that execute this statement. CHECKED, not
	// prose: a test asserts every name here appears in nonMinting, minting or
	// clientMethods, so the inventory cannot claim an ordering for a writer the
	// call-site rules do not police. An unchecked owner string left the inventory
	// describing a connection to those maps that did not exist.
	//
	// Empty only for a statement whose state is a hardcoded non-running literal,
	// or for a frozen receive-only shape — note says which.
	writers []string
	note    string
}

var stateWritingStatements = []stateStatement{
	{
		sql:     `UPDATE vms SET state = ?, state_detail = ?, updated_at = ? WHERE name = ?`,
		writers: []string{"UpdateVMState", "UpdateVMStateStrict"},
		note:    "nonMinting, state at arg 3; they differ only in their Go-side row-count check",
	},
	{
		sql:     `UPDATE vms SET state = ?, state_detail = ?, updated_at = ? WHERE name = ? AND vm_owner_epoch = ?`,
		writers: []string{"UpdateVMStateAtEpoch"},
		note:    "nonMinting, state at arg 3",
	},
	{
		sql:     `UPDATE vms SET host_name = ?, state = ?, state_detail = '', updated_at = ? WHERE name = ?`,
		writers: []string{"UpdateVMHost", "CommitMigrationOwnership"},
		note:    "both nonMinting (state at arg 4 and arg 5) - identical SQL, different guards in Go",
	},
	{
		sql: `UPDATE vms
	  SET host_name = ?, state = ?, state_detail = '',
	      vm_owner_epoch = vm_owner_epoch + 1, updated_at = ?
	  WHERE name = ? AND deleted_at IS NULL AND vm_owner_epoch = ?`,
		writers: []string{"TransferVMOwner", "TransferVMOwnerFresh"},
		note:    "MINTING: the statement advances the generation, so the correct marker value does not exist until it commits",
	},
	{
		sql: `INSERT INTO vms (name, stack_name, host_name, spec, state, state_detail,
				cpu_actual, mem_actual, project, is_template, vm_owner_epoch,
				spec_generation, active_operation_id, created_at, updated_at,
				deleted_at, pending_action_id, hardware_adoption_state,
				hardware_adoption_error)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, NULL, '', ?, NULL)
			 ON CONFLICT(name) DO UPDATE SET
			   stack_name = excluded.stack_name,
			   host_name = excluded.host_name,
			   spec = excluded.spec,
			   state = excluded.state,
			   state_detail = excluded.state_detail,
			   cpu_actual = excluded.cpu_actual,
			   mem_actual = excluded.mem_actual,
			   project = excluded.project,
			   is_template = excluded.is_template,
			   vm_owner_epoch = excluded.vm_owner_epoch,
			   spec_generation = excluded.spec_generation,
			   active_operation_id = excluded.active_operation_id,
			   created_at = excluded.created_at,
			   updated_at = excluded.updated_at,
			   deleted_at = excluded.deleted_at,
			   pending_action_id = excluded.pending_action_id,
			   hardware_adoption_state = excluded.hardware_adoption_state,
			   hardware_adoption_error = excluded.hardware_adoption_error
			 WHERE excluded.vm_owner_epoch > vms.vm_owner_epoch
			   AND excluded.spec_generation > vms.spec_generation
			   AND (vms.deleted_at IS NOT NULL OR vms.created_at = excluded.created_at)`,
		writers: []string{"ReplaceVM"},
		note:    "MINTING: a cutover installs the replacement above both VMs' generations, with its state copied from the replacement's row",
	},
	{
		sql: `UPDATE vms SET state = 'running', pending_action_id = '',
	        vm_owner_epoch = vm_owner_epoch + 1, updated_at = ?
	        WHERE name = ? AND deleted_at IS NULL AND pending_action_id = ?`,
		writers: []string{"CompleteVMStartProof"},
		note:    "MINTING, and alwaysRunning - no state argument can exempt it",
	},
	{
		sql: `INSERT INTO vms (name, stack_name, host_name, spec, state, state_detail,
			cpu_actual, mem_actual, project, is_template, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		writers: []string{"InsertVM", "InsertVMWithHardware"},
		note:    "stateInVMRecord, so rule 4 polices the record's State field. HistoricalShapes' insert_vm_pre_authority is the same text: receive-only, writes nothing",
	},
	{
		sql: `UPDATE vms SET state = 'running', state_detail = ?,
			cpu_actual = ?, mem_actual = ?,
			hardware_adoption_state = 'adopted', hardware_adoption_error = NULL,
			active_operation_id = '', updated_at = ?
		 WHERE name = ? AND state = 'creating' AND active_operation_id = ?
		   AND vm_owner_epoch = ? AND spec_generation = ? AND deleted_at IS NULL`,
		writers: []string{"CommitVMCreateOperation"},
		note:    "clientMethods, stateInVMRecord; the create path graduates via assignOwnerEpochAtCreate",
	},
	{
		sql: `UPDATE vms SET host_name = ?, state = 'pending', pending_action_id = ?, updated_at = ?
	        WHERE name = ? AND deleted_at IS NULL`,
		writers: nil,
		note:    "WriteVMRescheduleProof - literal state='pending', never a runtime",
	},
	{
		sql: `UPDATE vms SET state = 'error', state_detail = ?, pending_action_id = '', updated_at = ?
	       WHERE name = ? AND deleted_at IS NULL AND pending_action_id = ?`,
		writers: nil,
		note:    "FailActionProof - literal state='error', never a runtime",
	},
	{
		sql: `INSERT INTO vms (name, stack_name, host_name, spec, state, state_detail,
				cpu_actual, mem_actual, project, is_template, vm_owner_epoch,
				spec_generation, active_operation_id, created_at, updated_at,
				deleted_at, pending_action_id, hardware_adoption_state,
				hardware_adoption_error)
			 VALUES (?, ?, ?, ?, 'creating', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
				NULL, '', 'pending', NULL)
			 ON CONFLICT(name) DO UPDATE SET
				stack_name = excluded.stack_name, host_name = excluded.host_name,
				spec = excluded.spec, state = excluded.state,
				state_detail = excluded.state_detail,
				cpu_actual = excluded.cpu_actual, mem_actual = excluded.mem_actual,
				project = excluded.project, is_template = excluded.is_template,
				vm_owner_epoch = excluded.vm_owner_epoch,
				spec_generation = excluded.spec_generation,
				active_operation_id = excluded.active_operation_id,
				created_at = excluded.created_at, updated_at = excluded.updated_at,
				deleted_at = excluded.deleted_at,
				pending_action_id = excluded.pending_action_id,
				hardware_adoption_state = excluded.hardware_adoption_state,
				hardware_adoption_error = excluded.hardware_adoption_error
			 WHERE vms.deleted_at IS NOT NULL
			   AND excluded.vm_owner_epoch > vms.vm_owner_epoch
			   AND excluded.spec_generation > vms.spec_generation`,
		writers: nil,
		note:    "vmCreateBeginSQL - literal state='creating'; the conflict arm resurrects a tombstone at that same state",
	},
	{
		sql: `UPDATE vms SET state = 'running', pending_action_id = '', updated_at = ?
	        WHERE name = ? AND deleted_at IS NULL AND pending_action_id = ?`,
		writers: nil,
		note:    "HistoricalShapes' complete_vm_start_pre_epoch_v47 - a frozen RECEIVE-ONLY shape for the support horizon; no Go writer emits it",
	},
}

// stateInventory is stateWritingStatements keyed by normalized text.
var stateInventory = func() map[string]string {
	m := make(map[string]string, len(stateWritingStatements))
	for _, st := range stateWritingStatements {
		m[normalizeSQL(st.sql)] = st.note
	}
	return m
}()

var insertVMsRe = regexp.MustCompile(`^insert into vms *\(([^)]*)\)`)

// writesVMState reports whether a normalized statement assigns vms.state.
//
// The SET clause is split on commas and each assignment's LEFT side compared for
// equality, rather than pattern-matched. A regex looking for "state =" anywhere
// matches state_detail, hardware_adoption_state and a WHERE clause's `state = ?`
// as readily as the column itself; equality on the split target cannot.
func writesVMState(sql string) bool {
	if rest, ok := strings.CutPrefix(sql, "update vms set "); ok {
		if where := strings.Index(rest, " where "); where >= 0 {
			rest = rest[:where]
		}
		return assignsState(rest)
	}
	if m := insertVMsRe.FindStringSubmatch(sql); m != nil {
		for _, col := range strings.Split(m[1], ",") {
			if strings.TrimSpace(col) == "state" {
				return true
			}
		}
	}
	return false
}

// assignsState reports whether a comma-separated SET clause assigns `state`.
func assignsState(setClause string) bool {
	for _, assign := range strings.Split(setClause, ",") {
		target, _, found := strings.Cut(assign, "=")
		if found && strings.TrimSpace(target) == "state" {
			return true
		}
	}
	return false
}

// constStringExpr returns the text of a string literal, INCLUDING one assembled
// from `"a" + "b"` concatenation.
//
// Scanning one *ast.BasicLit at a time missed any statement split across source
// lines with `+`, which is the ordinary way to keep a long SQL string readable —
// neither fragment carries the `update vms set` prefix writesVMState needs, so a
// new state writer escaped the inventory by being formatted nicely. Only a
// `+`-tree of string literals is folded; a literal concatenated with a variable
// is not constant SQL and the shape guards refuse it elsewhere.
func constStringExpr(n ast.Node) (string, bool) {
	switch e := n.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		return strings.Trim(e.Value, "`\""), true
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, lok := constStringExpr(e.X)
		r, rok := constStringExpr(e.Y)
		if !lok || !rok {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// normalizeSQL collapses whitespace and lowercases, so reflowing a statement
// across lines does not read as a new one.
func normalizeSQL(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// checkStateStatements walks a corrosion file for unregistered state writers.
func (s *fileScan) checkStateStatements(file *ast.File) {
	ast.Inspect(file, func(n ast.Node) bool {
		text, ok := constStringExpr(n)
		if !ok {
			return true
		}
		// Do NOT descend into a folded concatenation. Its fragments are not
		// statements, and a leading `UPDATE vms SET state = ?,` fragment matches
		// the SET-clause test on its own — so a correctly registered statement
		// split across two lines was reported unregistered by its own first half.
		descend := false
		sql := normalizeSQL(text)
		if !writesVMState(sql) {
			return descend
		}
		if _, known := stateInventory[sql]; known {
			return descend
		}
		if s.dump {
			// A pasteable stateWritingStatements entry, carrying the statement in
			// its SOURCE form — the inventory's own rule, and the only form that
			// stays legible as SQL. It printed map-literal syntax with a stray
			// backslash for a SLICE inventory, so the output the failure message
			// tells a maintainer to paste did not compile.
			fmt.Printf("\t{\n\t\tsql:     `%s`,\n\t\twriters: []string{\"<the Go writers>\"},\n"+
				"\t\tnote:    \"<which ordering, and why>\",\n\t},\n", text)
			return descend
		}
		s.report(n, "this statement writes the vms.state column but is not registered in "+
			"runningcheck's stateWritingStatements inventory. A writer nobody registered is a "+
			"writer rules 1-4 do not police: add the statement, and add its Go writer to "+
			"nonMinting, minting or clientMethods (or record there why it can never publish "+
			"a running VM)")
		return descend
	})
}

func hasKey(m map[string]int, k string) bool { _, ok := m[k]; return ok }

// corrosionCall returns the function name for a corrosion.<Fn>(...) call, else "".
func corrosionCall(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "corrosion" {
		return ""
	}
	return sel.Sel.Name
}

// clientMethodCall returns the writer name for a corrosion-client METHOD call —
// s.db.X(...), c.X(...) — that writes vms.state. Matched on the selector name
// alone, because the receiver is a client value whose type this AST-only pass
// cannot resolve. The set is deliberately tiny for that reason.
func clientMethodCall(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if _, known := clientMethods[sel.Sel.Name]; known {
		return sel.Sel.Name
	}
	return ""
}

// helperName returns the publish-helper name a call targets, else "".
func helperName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

type family int

const (
	familyNone family = iota
	familyPlain
	familyMinted
)

// routing records, per function, the source spans of closures handed to a
// publish helper — plus, for closures reached through a variable, that
// variable's name.
type routing struct {
	spans []span
	vars  map[string]routedVar
}

// routedVar is a closure variable handed to a publish helper, together with the
// state expression that helper was given alongside it. Rule 3 needs the
// expression, not just the fact of routing: a branch proving some OTHER string
// is not "running" proves nothing about the state this closure will write.
type routedVar struct {
	fam family
	// stateText is the state argument's source text, or "" when the helper takes
	// no state argument (a minted publish is always running, so no branch can
	// disprove it).
	stateText string
}

type span struct {
	start, end int
	fam        family
}

func (r routing) family(n ast.Node, fset *token.FileSet) family {
	line := fset.Position(n.Pos()).Line
	best := familyNone
	for _, sp := range r.spans {
		if line >= sp.start && line <= sp.end {
			// A minted span wins: it is the stricter classification, and a
			// primitive inside one is being published with that ordering.
			if sp.fam == familyMinted {
				return familyMinted
			}
			best = sp.fam
		}
	}
	return best
}

// collectRouting finds every closure handed to a publish helper — inline, or
// reached through a variable — and records the source span it covers, so a
// primitive can be tested for "is lexically inside a routed closure".
func collectRouting(body *ast.BlockStmt, fset *token.FileSet) routing {
	r := routing{vars: map[string]routedVar{}}

	// Pass 1: which arguments reach a helper, and with which ordering.
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fam, stateIdx := helperFamily(helperName(call))
		if fam == familyNone {
			return true
		}
		stateText := ""
		if stateIdx >= 0 && stateIdx < len(call.Args) {
			stateText = exprText(call.Args[stateIdx])
		}
		// Only the LAST argument can be the commit callback. Registering every
		// identifier argument put ctx, name and state into vars, so a local
		// helper or shadowing variable of one of those names was reported as
		// "the routed closure invoked directly", and pass 2 attached a closure
		// span to an unrelated assignment of that name — silently marking
		// whatever writes lived in it as routed.
		if len(call.Args) > 0 {
			switch a := call.Args[len(call.Args)-1].(type) {
			case *ast.FuncLit:
				// Written inline at the call.
				r.spans = append(r.spans, span{
					start: fset.Position(a.Body.Pos()).Line,
					end:   fset.Position(a.Body.End()).Line,
					fam:   fam,
				})
			case *ast.Ident:
				// Reached through a variable; its closure body is found below.
				r.vars[a.Name] = routedVar{fam: fam, stateText: stateText}
			}
		}
		return true
	})

	// Pass 2: the bodies of the closures those variables hold.
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		rv, routed := r.vars[id.Name]
		if !routed {
			return true
		}
		if fl, ok := assign.Rhs[0].(*ast.FuncLit); ok {
			r.spans = append(r.spans, span{
				start: fset.Position(fl.Body.Pos()).Line,
				end:   fset.Position(fl.Body.End()).Line,
				fam:   rv.fam,
			})
		}
		return true
	})
	return r
}

// helperFamily returns a helper's ordering family and the index of its state
// argument (alwaysRunning when it has none).
func helperFamily(name string) (family, int) {
	if idx, ok := mintedHelpers[name]; ok {
		return familyMinted, idx
	}
	if idx, ok := plainHelpers[name]; ok {
		return familyPlain, idx
	}
	return familyNone, alwaysRunning
}

// directUse names a direct invocation of a routed closure variable.
type directUse struct {
	name string
	call *ast.CallExpr
}

func (r routing) directCalls(body *ast.BlockStmt, fset *token.FileSet) []directUse {
	// Per routed closure variable, the source ranges of `if` statements whose
	// condition proves THAT closure's state expression is not "running". A direct
	// invocation inside one is legitimate.
	//
	// Per-variable, not one shared set: the proof has to be about the value the
	// closure will actually write. `detail != "running"` was accepted as proof
	// for a closure writing `state`, which proves nothing — it only has to
	// mention the string.
	proven := map[string][]span{}
	for name, rv := range r.vars {
		if rv.stateText == "" {
			continue // no state argument: always running, nothing can disprove it
		}
		ast.Inspect(body, func(n ast.Node) bool {
			ifs, ok := n.(*ast.IfStmt)
			if !ok || ifs.Cond == nil || !provesNotRunning(ifs.Cond, rv.stateText) {
				return true
			}
			proven[name] = append(proven[name], span{
				start: fset.Position(ifs.Body.Pos()).Line,
				end:   fset.Position(ifs.Body.End()).Line,
			})
			return true
		})
	}

	var out []directUse
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if _, routed := r.vars[id.Name]; !routed {
			return true
		}
		line := fset.Position(call.Pos()).Line
		for _, sp := range proven[id.Name] {
			if line >= sp.start && line <= sp.end {
				return true
			}
		}
		out = append(out, directUse{name: id.Name, call: call})
		return true
	})
	return out
}

// provesNotRunning reports whether a condition establishes that the expression
// whose source text is stateText holds something other than "running".
//
// Both comparison directions count, because both appear in real code:
//
//   - `state != "running"` — the negative form.
//   - `state == "stopped"` — the positive form, against any literal that is not
//     "running". classifyStop's callers read this way, and rejecting it would
//     have pushed a future site toward a directive instead of a proof.
//
// The non-literal operand must BE stateText. Accepting any expression compared
// against "running" made `detail != "running"` — or any unrelated string — read
// as proof about the state, which is a bypass, not a proof.
func provesNotRunning(e ast.Expr, stateText string) bool {
	switch b := e.(type) {
	case *ast.ParenExpr:
		return provesNotRunning(b.X, stateText)
	case *ast.BinaryExpr:
		switch b.Op {
		case token.NEQ, token.EQL:
			lit, other, ok := litAndOther(b)
			if !ok || exprText(other) != stateText {
				return false
			}
			if b.Op == token.NEQ {
				return lit == "running"
			}
			return lit != "running"
		case token.LAND:
			// Either conjunct proving it is enough: both must hold to enter.
			return provesNotRunning(b.X, stateText) || provesNotRunning(b.Y, stateText)
		case token.LOR:
			// BOTH alternatives must prove it. `state != "running" || retry`
			// is entered with state == "running" whenever retry is true, and
			// treating OR like AND accepted exactly that bypass.
			return provesNotRunning(b.X, stateText) && provesNotRunning(b.Y, stateText)
		}
	}
	return false
}

// litAndOther splits a comparison into its string literal and its other side.
func litAndOther(b *ast.BinaryExpr) (lit string, other ast.Expr, ok bool) {
	if l, isLit := stringLit(b.Y); isLit {
		return l, b.X, true
	}
	if l, isLit := stringLit(b.X); isLit {
		return l, b.Y, true
	}
	return "", nil, false
}

// exprText renders an expression back to source so two occurrences of the same
// state expression can be compared. Printed rather than compared structurally:
// the state is `state`, `vm.State` or `fresh.State` at real call sites, and
// go/printer normalizes all of those to a single canonical form.
func exprText(e ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, token.NewFileSet(), e); err != nil {
		return ""
	}
	return buf.String()
}

func callsGraduation(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if helperName(call) == "assignOwnerEpochAtCreate" {
			found = true
		}
		return true
	})
	return found
}

func isVMRecord(cl *ast.CompositeLit) bool {
	sel, ok := cl.Type.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "corrosion" && sel.Sel.Name == "VMRecord"
}

func stateField(cl *ast.CompositeLit) (ast.Expr, bool) {
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "State" {
			return kv.Value, true
		}
	}
	return nil, false
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	return strings.Trim(bl.Value, "`\""), true
}
