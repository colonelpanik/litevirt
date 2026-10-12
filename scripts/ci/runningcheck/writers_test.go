package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// loadCorrosion loads the packages the writer rules inspect.
func loadCorrosion(t *testing.T) ([]*packages.Package, error) {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps,
		Dir:   repoRoot,
		Tests: false,
	}
	return packages.Load(cfg, "./internal/...")
}

// repoRoot is the module root relative to this package.
const repoRoot = "../../.."

// TestNoUnclassifiedStateWriters is rule 6 against the real tree.
//
// It is the rule's whole point: a new FUNCTION executing an already-registered
// statement was caught by nothing. Rule 5 saw SQL it knew and passed it; rules
// 1-4 never looked at the function, because its name was in none of their maps.
func TestNoUnclassifiedStateWriters(t *testing.T) {
	vs, err := checkWriters(repoRoot)
	if err != nil {
		t.Fatalf("checkWriters: %v", err)
	}
	for _, v := range vs {
		t.Errorf("%s:%d: %s", v.file, v.line, v.msg)
	}
}

// TestNoStaleWriterExemptions: an exemption that matches no state-writing
// function silently excuses whatever function later takes that name.
func TestNoStaleWriterExemptions(t *testing.T) {
	seen, err := stateWritingFuncs(repoRoot)
	if err != nil {
		t.Fatalf("stateWritingFuncs: %v", err)
	}
	for _, name := range staleExemptions(seen) {
		t.Errorf("%q is exempted as a vms.state writer but executes no state-writing statement — "+
			"remove it, or it exempts whatever next takes the name", name)
	}
}

// TestLiteralNonRunningWritersReallyAreLiteral is what makes that exemption
// class a check rather than a claim.
//
// Each of these is excused because its statement HARDCODES a state that is not
// "running", so no call site can publish a runtime through it. Change the
// literal to a bound `?` and the function becomes a publisher while its
// exemption still reads as valid — so the literal is verified here.
func TestLiteralNonRunningWritersReallyAreLiteral(t *testing.T) {
	pkgs, err := loadCorrosion(t)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	checked := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			for _, d := range file.Decls {
				fd := asFuncDecl(d)
				if fd == nil {
					continue
				}
				if _, exempt := literalNonRunningWriters[fd.Name.Name]; !exempt {
					continue
				}
				sql, _, found := stateWriteIn(pkg, fd)
				if !found {
					continue // the staleness test reports this
				}
				checked[fd.Name.Name] = true
				vals := stateAssignments(normalizeSQL(sql))
				if len(vals) == 0 {
					t.Errorf("%s: could not read the state assignment out of %q", fd.Name.Name, shorten(sql))
					continue
				}
				for _, v := range vals {
					if !strings.HasPrefix(v, "'") {
						t.Errorf("%s is exempted as writing a literal non-running state, but its "+
							"statement assigns state %s — it can now publish a runtime and its call "+
							"sites are policed by nothing", fd.Name.Name, v)
						continue
					}
					if v == "'running'" {
						t.Errorf("%s is exempted as non-running but assigns state 'running'", fd.Name.Name)
					}
				}
			}
		}
	}
	for name := range literalNonRunningWriters {
		if !checked[name] {
			t.Errorf("%q was never verified — it executes no state write this pass can read", name)
		}
	}
}

// TestStateAssignments covers the reader the check above depends on, including
// the near-misses that would make it vacuous.
func TestStateAssignments(t *testing.T) {
	for _, tc := range []struct {
		sql  string
		want []string
	}{
		{"update vms set state = ?, state_detail = ? where name = ?", []string{"?"}},
		{"update vms set host_name = ?, state = 'pending', updated_at = ? where name = ?", []string{"'pending'"}},
		{"update vms set state = 'error', state_detail = ? where name = ?", []string{"'error'"}},
		// state_detail alone is not a state assignment.
		{"update vms set state_detail = ? where name = ?", nil},
		// A WHERE clause mentioning state must not be read as an assignment.
		{"update vms set updated_at = ? where name = ? and state = 'running'", nil},
		// INSERT: the value at the state column's position.
		{"insert into vms (name, host_name, state, spec) values (?, ?, 'creating', ?)", []string{"'creating'"}},
		{"insert into vms (name, state) values (?, ?)", []string{"?"}},
		{"insert into vms (name, spec) values (?, ?)", nil},
	} {
		got := stateAssignments(tc.sql)
		if len(got) != len(tc.want) {
			t.Errorf("stateAssignments(%q) = %v, want %v", tc.sql, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("stateAssignments(%q) = %v, want %v", tc.sql, got, tc.want)
				break
			}
		}
	}
}

// fixtureModule writes a throwaway module containing src and returns its root.
//
// Rule 7 has to be tested against a tree that VIOLATES it, which the real one
// by construction does not. Pointing it at the repo would assert only that the
// repo is clean today — a test that stays green with the rule deleted.
func fixtureModule(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module rule7fixture\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write a.go: %v", err)
	}
	return dir
}

// TestOnlyCallerClaimWithTwoCallers is the break rule 7 exists to catch.
//
// Adding a second caller is the natural thing to do when a new path wants the
// helper without the chokepoint. The directive still reads as valid, so
// nothing else in this checker objects, and the new path publishes a running
// row with no marker naming its generation.
func TestOnlyCallerClaimWithTwoCallers(t *testing.T) {
	root := fixtureModule(t, `package fixture

func publish() {
	//runningcheck:allow the only caller routes this
	_ = 1
}

func routed()   { publish() }
func unrouted() { publish() }
`)
	vs, err := checkOnlyCallerClaims(root)
	if err != nil {
		t.Fatalf("checkOnlyCallerClaims: %v", err)
	}
	if len(vs) != 1 {
		t.Fatalf("a function claiming one caller has two, want 1 violation, got %d: %+v", len(vs), vs)
	}
	if !strings.Contains(vs[0].msg, "2 call site(s)") {
		t.Errorf("violation should name the real call-site count, got %q", vs[0].msg)
	}
}

// TestOnlyCallerClaimWithOneCaller is the positive control: the rule must not
// fire on the arrangement the directive actually describes, or it would be
// satisfied by refusing everything.
func TestOnlyCallerClaimWithOneCaller(t *testing.T) {
	root := fixtureModule(t, `package fixture

func publish() {
	//runningcheck:allow the only caller routes this
	_ = 1
}

func routed() { publish() }
`)
	vs, err := checkOnlyCallerClaims(root)
	if err != nil {
		t.Fatalf("checkOnlyCallerClaims: %v", err)
	}
	if len(vs) != 0 {
		t.Fatalf("a genuinely singly-called function must not be flagged, got %+v", vs)
	}
}

// TestNoStaleOnlyCallerClaims is rule 7 against the real tree.
func TestNoStaleOnlyCallerClaims(t *testing.T) {
	vs, err := checkOnlyCallerClaims(repoRoot)
	if err != nil {
		t.Fatalf("checkOnlyCallerClaims: %v", err)
	}
	for _, v := range vs {
		t.Errorf("%s:%d: %s", v.file, v.line, v.msg)
	}
}
