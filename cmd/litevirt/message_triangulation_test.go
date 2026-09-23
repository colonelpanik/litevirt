package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// backtickedInvocationRE matches a backtick-quoted `lv …` inside Go source — the
// house form for naming a command in an error message, a log line or a comment.
var backtickedInvocationRE = regexp.MustCompile("`lv ([^`\n]+)`")

// plainInvocationRE matches an UNBACKTICKED `lv …` — a command named in prose,
// in a help example, or in parentheses.
//
// The house form is backticks, and for a long time only that form was checked.
// A message written without them is exactly as wrong and was invisible: the
// template refusal in StartVM told operators to run "(lv vm clone <name>
// <new-name>)" from the initial commit onward, and the SPICE help text offered
// "lv host ssh <host> -- -L …". Neither command has ever existed.
//
// The leading class rejects a `lv` that is part of something else: the package
// alias in `lv.CloudInitISOPath`, a path like `vg/lv`, an identifier like
// `mylv`. The token run stops at anything that is not a bare lowercase word, so
// flags, placeholders and punctuation end it — and validateInvocation stops
// again at the first non-command token, treating what follows a runnable leaf
// as arguments rather than subcommands. That is what keeps ordinary prose
// ("lv host drain moves every VM") from registering.
var plainInvocationRE = regexp.MustCompile(`(?:^|[^\w/.-])lv ((?:[a-z][a-z0-9-]*)(?:[ \t]+[a-z][a-z0-9-]*)*)`)

// invocationsIn returns every `lv …` candidate on a line, in both spellings.
//
// A function rather than two calls inline in the guard, so that dropping one of
// the two patterns is a test failure rather than a silent narrowing — which is
// precisely how the unbackticked form went unchecked for as long as it did.
// Each element is a submatch slice whose [1] is the token run.
func invocationsIn(line string) [][]string {
	out := backtickedInvocationRE.FindAllStringSubmatch(line, -1)
	return append(out, plainInvocationRE.FindAllStringSubmatch(line, -1)...)
}

// TestOperatorMessagesReferenceRealCLICommands is TestDocsReferenceRealCLICommands
// for the Go source.
//
// The docs are guarded in both directions, and a command that does not exist is
// caught the moment a doc mentions it. Nothing guarded the same reference inside
// an ERROR MESSAGE — which is where an operator is most likely to read it, and
// least likely to have a doc open. A bound-network refusal told operators to
// "create the VM with `lv vm create` instead" for as long as the refusal existed:
// there is no `lv vm` command, the docs never repeated the mistake, and so
// nothing failed.
//
// Comments count too. A comment naming a command that does not exist is the same
// stale reference, one edit away from being copied into a message.
func TestOperatorMessagesReferenceRealCLICommands(t *testing.T) {
	root := newRootCmd()
	rootDir := repoRoot(t)

	var problems []string
	for _, f := range goSourceFiles(t, rootDir) {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		rel, _ := filepath.Rel(rootDir, f)
		for _, line := range strings.Split(string(content), "\n") {
			if strings.Contains(line, "ci:skip-cmd") {
				continue
			}
			for _, m := range invocationsIn(line) {
				args := strings.Fields(m[1])
				if len(args) == 0 {
					continue
				}
				if _, known := staleMessageCommands[strings.Join(args, " ")]; known {
					continue
				}
				if bad := validateInvocation(root, args); bad != "" {
					problems = append(problems, fmt.Sprintf("%s: `lv %s` — %q is not a known command",
						rel, strings.Join(args, " "), bad))
				}
			}
		}
	}

	if len(problems) > 0 {
		t.Errorf("Go source names %d CLI command(s) not present in the cobra tree:\n  %s\n\n"+
			"Fix the message, register the command, or add `ci:skip-cmd` to the line.",
			len(problems), strings.Join(problems, "\n  "))
	}
}

// staleMessageCommands records operator-facing messages and comments that name
// a command which does not exist, where the right replacement is not obvious
// enough to apply without guessing.
//
// It is EMPTY. The eight entries it was created with — every one of them
// predating this guard — have since been corrected against the cobra tree
// rather than recorded, so each message now names a command an operator can
// actually run. The map stays as the mechanism: add an entry when a message is
// wrong and the intended command is genuinely ambiguous, and delete it when the
// message is fixed.
var staleMessageCommands = map[string]string{}

// goSourceFiles lists the production Go files to scan. Tests are excluded: a
// test asserting on a message is not itself operator-facing, and it names the
// same string the production file already had checked.
func goSourceFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if info.Name() == "testdata" || info.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no Go source files found — the guard would be vacuous")
	}
	return out
}

// TestPlainInvocationRE_MatchesCommandsNotProse pins what widening the guard to
// unbackticked references may and may not claim.
//
// The risk of dropping the backtick requirement is false positives: `lv` is a
// package alias in this repo, half of `vg/lv`, and a substring of identifiers.
// Each exclusion below is a real shape from the tree, not a hypothetical.
func TestPlainInvocationRE_MatchesCommandsNotProse(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string // "" = must not match at all
	}{
		{"parenthesised message", `"clone it first (lv clone %s <new-name>)"`, "clone"},
		{"single-quoted hint", `"consolidate with 'lv snapshot rm "+name+"'"`, "snapshot rm"},
		// Over-capture is deliberate and safe: the regex finds a CANDIDATE and
		// validateInvocation decides. Here `root` is swallowed because `@` only
		// ends the token run after it — and the walk stops at `init`, a runnable
		// leaf, so `root` is read as the argument it is. See the prose test.
		{"indented help example", "    lv host init root@10.0.0.1", "host init root"},
		{"start of line", "lv host ls", "host ls"},

		{"package alias", `path := lv.CloudInitISOPath(dir, name)`, ""},
		{"path component", `return fmt.Errorf("cannot derive vg/lv from %q", path)`, ""},
		{"identifier suffix", `mylv foo`, ""},
		{"hyphen prefix", `some-lv host ls`, ""},
		{"uppercase after", `lv Client`, ""},
		{"assignment", `lv := newClient()`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := plainInvocationRE.FindStringSubmatch(tc.line)
			got := ""
			if m != nil {
				got = strings.TrimSpace(m[1])
			}
			if got != tc.want {
				t.Errorf("plainInvocationRE on %q = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

// Prose that follows a real command must not be read as a bogus subcommand.
// This is validateInvocation's job, not the regex's: once the walk reaches a
// RUNNABLE command, an unknown token is a positional argument. Without that,
// widening the pattern would flag every sentence that names a command.
func TestPlainInvocation_ProseAfterACommandIsNotASubcommand(t *testing.T) {
	root := newRootCmd()
	for _, line := range []string{
		"lv host drain moves every VM off the host",
		"lv snapshot rm removes it and flattens the chain",
		"lv ssh myvm connects to the guest",
		"lv host init root@10.0.0.1",
	} {
		m := plainInvocationRE.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("fixture failed: %q did not match at all", line)
		}
		if bad := validateInvocation(root, strings.Fields(m[1])); bad != "" {
			t.Errorf("prose %q was reported as naming a bogus command %q", line, bad)
		}
	}
}

// And the shapes the loophole hid must now be caught.
func TestPlainInvocation_CatchesWhatTheBacktickRuleMissed(t *testing.T) {
	root := newRootCmd()
	for _, tc := range []struct{ line, bad string }{
		{`"%q is a template; clone it first (lv vm clone %s <new-name>)"`, "vm"},
		{"    lv host ssh <host> -- -L 5901:127.0.0.1:<port>", "ssh"},
		{`"consolidate with 'lv snapshot flatten "+name+"'"`, "flatten"},
	} {
		m := plainInvocationRE.FindStringSubmatch(tc.line)
		if m == nil {
			t.Fatalf("%q did not match", tc.line)
		}
		if bad := validateInvocation(root, strings.Fields(m[1])); bad != tc.bad {
			t.Errorf("validateInvocation(%q) = %q, want %q", m[1], bad, tc.bad)
		}
	}
}

// TestInvocationsIn_CoversBothSpellings is the wiring guard.
//
// Without it, deleting either pattern from invocationsIn passes every other
// test in this file: the regex tests exercise the patterns directly, and the
// tree-wide scan only fails when the tree actually contains a bad reference.
// A narrowing would therefore go unnoticed until the next wrong message shipped
// — which is the exact history this widening is correcting.
func TestInvocationsIn_CoversBothSpellings(t *testing.T) {
	got := map[string]bool{}
	for _, m := range invocationsIn("see `lv host ls` or run lv snapshot rm <vm> <name>") {
		got[strings.TrimSpace(m[1])] = true
	}
	if !got["host ls"] {
		t.Error("the BACKTICKED spelling is no longer extracted")
	}
	if !got["snapshot rm"] {
		t.Error("the UNBACKTICKED spelling is no longer extracted")
	}
}
