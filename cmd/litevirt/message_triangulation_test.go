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
			for _, m := range backtickedInvocationRE.FindAllStringSubmatch(line, -1) {
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
