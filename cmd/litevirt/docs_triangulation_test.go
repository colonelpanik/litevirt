package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/litevirt/litevirt/internal/daemon"
)

// This file is the claim-vs-code triangulation guard: it makes CI fail when the
// published docs (README.md + docs/*.md) reference a CLI command or a litevirt_*
// identifier (Prometheus metric, Ansible inventory var) that doesn't actually
// exist in the code. It is the public-mirror analogue of the internal "claim ↔
// code" audit — the private Plan.md/TODO/MEMORY aren't in this repo, so the
// docs ARE the claim surface here.
//
// Escape hatches for intentional references (placeholders, roadmap items):
//   - add `ci:skip-cmd` to a line to skip CLI validation on it
//   - add `ci:skip-metric` to a line to skip identifier validation on it
//   - add a roadmap identifier to knownAbsentIdentifiers below

// commandLikeRE matches a token that looks like a subcommand name (lowercase,
// no flags/placeholders/args). Used to decide whether an unknown token after a
// pure group command is a bogus subcommand or just a positional argument.
var commandLikeRE = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// assignRE matches a leading shell env assignment, e.g. `LV_HOST=root@host`,
// so `LV_HOST=… lv ls` is recognized as an `lv` invocation.
var assignRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// knownAbsentIdentifiers lists litevirt_* identifiers that docs reference on
// purpose even though they don't exist in code yet. Each must say why; remove
// the entry when the identifier ships.
// Empty is the goal state: an allowlisted identifier is a doc promising
// something the code does not do. litevirt_audit_chain_last_verified_ok was the
// last entry and shipped with v45 audit signing.
var knownAbsentIdentifiers = map[string]string{}

// TestDocsReferenceRealCLICommands fails if README/docs show an `lv` or
// `litevirt` command whose path doesn't resolve in the real cobra tree.
func TestDocsReferenceRealCLICommands(t *testing.T) {
	root := newRootCmd()
	rootDir := repoRoot(t)

	var problems []string
	for _, f := range docFiles(t, rootDir) {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		rel, _ := filepath.Rel(rootDir, f)
		for _, args := range extractInvocations(string(content)) {
			if bad := validateInvocation(root, args); bad != "" {
				problems = append(problems, fmt.Sprintf("%s: `lv %s` — %q is not a known command",
					rel, strings.Join(args, " "), bad))
			}
		}
	}

	if len(problems) > 0 {
		t.Errorf("docs reference %d CLI command(s) not present in the cobra tree:\n  %s\n\n"+
			"Fix the doc, register the command, or add `ci:skip-cmd` to the line if the reference is an intentional placeholder.",
			len(problems), strings.Join(problems, "\n  "))
	}
}

// TestDocsReferenceRealMetrics fails if an inline-code `litevirt_*` identifier
// in the docs has no matching string literal in the Go source (and isn't an
// allowlisted roadmap item). Catches a metric / Ansible var that was renamed or
// removed but left dangling in the docs.
func TestDocsReferenceRealMetrics(t *testing.T) {
	rootDir := repoRoot(t)
	code := collectCodeIdentifiers(t, rootDir)
	if len(code) == 0 {
		t.Fatal("found no litevirt_* identifiers in the code — scan path wrong?")
	}

	inlineRE := regexp.MustCompile("`([^`]+)`")
	fenceRE := regexp.MustCompile("^\\s*(```|~~~)")
	// Trailing * (glob in prose) or _ (a prefix like litevirt_label_) marks a
	// prefix reference rather than an exact identifier.
	tokRE := regexp.MustCompile(`litevirt_[a-z0-9_]+\*?`)

	var problems []string
	for _, f := range docFiles(t, rootDir) {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		rel, _ := filepath.Rel(rootDir, f)

		inFence := false
		for _, line := range strings.Split(string(content), "\n") {
			if fenceRE.MatchString(line) {
				inFence = !inFence
				continue
			}
			// Only inline code spans count: fenced blocks carry shell and
			// package names (e.g. the litevirt_0.2.0 .deb dir) that aren't
			// identifiers.
			if inFence || strings.Contains(line, "ci:skip-metric") {
				continue
			}
			for _, span := range inlineRE.FindAllStringSubmatch(line, -1) {
				for _, tok := range tokRE.FindAllString(span[1], -1) {
					if msg := checkIdentifier(tok, code); msg != "" {
						problems = append(problems, fmt.Sprintf("%s: %s", rel, msg))
					}
				}
			}
		}
	}

	if len(problems) > 0 {
		t.Errorf("docs reference %d litevirt_* identifier(s) not defined in code:\n  %s\n\n"+
			"Fix the doc, add the identifier in code, allowlist it in knownAbsentIdentifiers (with a reason), or add `ci:skip-metric` to the line.",
			len(problems), strings.Join(problems, "\n  "))
	}
}

// TestDocsDocumentEveryCLICommand is the REVERSE direction of
// TestDocsReferenceRealCLICommands: that one catches a doc referencing a command
// that no longer exists; this one catches a command that ships with no doc at
// all. Both directions are needed — a brand-new command group is invisible to
// the forward check, which is exactly how `lv operation` shipped undocumented.
//
// Only user-facing runnable commands count. Hidden and deprecated commands are
// exempt (they are deliberately not advertised), as are cobra's built-ins.
// Intentional omissions go in undocumentedCommands with a reason.
func TestDocsDocumentEveryCLICommand(t *testing.T) {
	root := newRootCmd()
	rootDir := repoRoot(t)

	documented := map[string]bool{}
	for _, f := range docFiles(t, rootDir) {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, args := range extractInvocations(string(content)) {
			if cmd := resolveInvocation(root, args); cmd != nil {
				// A reference to `lv operation show` documents the leaf AND
				// establishes that the `operation` group exists.
				for c := cmd; c != nil && c != root; c = c.Parent() {
					documented[commandPath(c)] = true
				}
			}
		}
	}

	var missing []string
	walkCommands(root, func(c *cobra.Command) {
		path := commandPath(c)
		if path == "" || !c.Runnable() || c.Hidden || c.Deprecated != "" {
			return
		}
		if _, ok := undocumentedCommands[path]; ok {
			return
		}
		if !documented[path] {
			missing = append(missing, path)
		}
	})

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d CLI command(s) are not referenced anywhere in README.md or docs/*.md:\n  lv %s\n\n"+
			"Document the command, mark it Hidden if it is not user-facing, or add it to undocumentedCommands (with a reason).",
			len(missing), strings.Join(missing, "\n  lv "))
	}
}

// undocumentedCommands lists command paths intentionally absent from the docs.
// Each must say why; remove the entry when the command is documented.
var undocumentedCommands = map[string]string{}

// TestDocsDocumentEveryConfigKey is the config-file analogue of the CLI checks:
// every yaml key an operator can set must appear somewhere in README.md or
// docs/*.md. The CLI guards walk the cobra tree and so cannot see config keys —
// which is exactly how advertise_address shipped undocumented, a key whose
// absence silently prevents a multi-homed cluster from ever converging.
//
// Membership, not prose quality: a key that appears anywhere in the docs passes.
// That is enough to catch the real failure — adding a knob and never mentioning it.
func TestDocsDocumentEveryConfigKey(t *testing.T) {
	rootDir := repoRoot(t)
	var docs strings.Builder
	for _, f := range docFiles(t, rootDir) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		docs.Write(b)
	}
	text := docs.String()

	keys := configYAMLKeys(reflect.TypeOf(daemon.Config{}), map[reflect.Type]bool{})
	if len(keys) == 0 {
		t.Fatal("found no yaml keys on daemon.Config — reflection path wrong?")
	}

	var missing []string
	for _, k := range keys {
		if _, ok := undocumentedConfigKeys[k]; ok {
			continue
		}
		if !strings.Contains(text, k) {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d config key(s) are not mentioned anywhere in README.md or docs/*.md:\n  %s\n\n"+
			"Document the key (docs/configuration.md is the reference), or add it to "+
			"undocumentedConfigKeys (with a reason).",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// undocumentedConfigKeys lists yaml keys intentionally absent from the docs.
// Each must say why; remove the entry when the key is documented.
var undocumentedConfigKeys = map[string]string{}

// configYAMLKeys collects every yaml tag reachable from a config struct,
// descending through nested structs, pointers, slices, and maps so keys inside
// blocks like `auth:` and `enforcement:` are covered too. seen guards against a
// recursive type looping forever.
func configYAMLKeys(rt reflect.Type, seen map[reflect.Type]bool) []string {
	for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Map {
		rt = rt.Elem()
	}
	if rt.Kind() != reflect.Struct || seen[rt] {
		return nil
	}
	seen[rt] = true

	var keys []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if tag := strings.Split(f.Tag.Get("yaml"), ",")[0]; tag != "" && tag != "-" {
			keys = append(keys, tag)
		}
		keys = append(keys, configYAMLKeys(f.Type, seen)...)
	}
	return keys
}

// commandPath is a command's full path with the binary name stripped —
// "host upgrade" for `lv host upgrade`, "" for the root itself.
func commandPath(c *cobra.Command) string {
	parts := strings.Fields(c.CommandPath())
	if len(parts) <= 1 {
		return ""
	}
	return strings.Join(parts[1:], " ")
}

// walkCommands invokes fn for every command in the tree, root included.
func walkCommands(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, child := range c.Commands() {
		walkCommands(child, fn)
	}
}

// resolveInvocation walks doc-extracted args down the cobra tree and returns the
// DEEPEST command they resolve to, or nil if the first token isn't a command.
// It is the read-side counterpart to validateInvocation, which reports the first
// token that fails to resolve.
func resolveInvocation(root *cobra.Command, args []string) *cobra.Command {
	cur := root
	for _, tok := range args {
		if tok == "" || tok == "help" || tok == "completion" ||
			strings.HasPrefix(tok, "-") ||
			strings.ContainsAny(tok, "<>[]{}|&;$`\"'=()") || assignRE.MatchString(tok) {
			break
		}
		child := findChild(cur, tok)
		if child == nil {
			break
		}
		cur = child
	}
	if cur == root {
		return nil
	}
	return cur
}

// checkIdentifier returns an error message if tok isn't backed by code, or "".
func checkIdentifier(tok string, code map[string]bool) string {
	if _, ok := knownAbsentIdentifiers[tok]; ok {
		return ""
	}
	id := strings.TrimSuffix(tok, "*")
	prefix := id != tok || strings.HasSuffix(id, "_")
	if prefix {
		for k := range code {
			if strings.HasPrefix(k, id) {
				return ""
			}
		}
		return fmt.Sprintf("`%s` matches no litevirt_* identifier defined in the code", tok)
	}
	if code[id] {
		return ""
	}
	return fmt.Sprintf("`%s` is not a litevirt_* identifier defined in the code", tok)
}

// validateInvocation walks the args that follow `lv`/`litevirt` down the cobra
// tree. It returns the offending token if a token that should be a subcommand
// isn't one, or "" if the invocation resolves (flags/placeholders/args are
// fine). Resolution mirrors cobra: descend while tokens match child commands;
// the first flag, placeholder, or arg ends the command path.
func validateInvocation(root *cobra.Command, args []string) string {
	cur := root
	for _, tok := range args {
		// help/completion are cobra built-ins valid under any command.
		if tok == "help" || tok == "completion" {
			return ""
		}
		// Flags, placeholders, env assignments, and shell metachars end the
		// command path — everything after is arguments.
		if tok == "" || strings.HasPrefix(tok, "-") ||
			strings.ContainsAny(tok, "<>[]{}|&;$`\"'=()") || assignRE.MatchString(tok) {
			return ""
		}
		if child := findChild(cur, tok); child != nil {
			cur = child
			continue
		}
		// Unknown token. If cur is a pure group (no Run of its own, has
		// subcommands), a command-like token here is a bogus subcommand.
		// Otherwise it's a positional argument to a leaf command — fine.
		if !cur.Runnable() && len(cur.Commands()) > 0 && commandLikeRE.MatchString(tok) {
			return tok
		}
		return ""
	}
	return ""
}

func findChild(parent *cobra.Command, name string) *cobra.Command {
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
		for _, a := range c.Aliases {
			if a == name {
				return c
			}
		}
	}
	return nil
}

// extractInvocations pulls `lv`/`litevirt` command invocations out of markdown,
// returning the argument tokens after the binary name for each. It reads both
// fenced code blocks (shell examples) and inline code spans.
func extractInvocations(content string) [][]string {
	var invs [][]string
	inlineRE := regexp.MustCompile("`([^`]+)`")
	fenceRE := regexp.MustCompile("^\\s*(```|~~~)")

	inFence := false
	for _, line := range strings.Split(content, "\n") {
		if fenceRE.MatchString(line) {
			inFence = !inFence
			continue
		}
		if strings.Contains(line, "ci:skip-cmd") {
			continue
		}
		if inFence {
			invs = append(invs, invocationsFromShell(line)...)
		} else {
			for _, span := range inlineRE.FindAllStringSubmatch(line, -1) {
				invs = append(invs, invocationsFromShell(span[1])...)
			}
		}
	}
	return invs
}

// invocationsFromShell finds `lv`/`litevirt` invocations in one shell-ish line,
// splitting on pipes/separators so `lv ls | grep` and `a && lv b` both work.
func invocationsFromShell(s string) [][]string {
	var out [][]string
	segRE := regexp.MustCompile(`\|\||&&|[|;&]`)
	for _, seg := range segRE.Split(s, -1) {
		fields := strings.Fields(seg)
		// Skip a `$ ` prompt, `sudo`, and leading env assignments.
		i := 0
		for i < len(fields) {
			f := strings.Trim(fields[i], "`")
			if f == "$" || f == "sudo" || assignRE.MatchString(f) {
				i++
				continue
			}
			break
		}
		if i >= len(fields) {
			continue
		}
		bin := strings.Trim(fields[i], "`")
		if bin != "lv" && bin != "litevirt" {
			continue
		}
		var args []string
		for _, t := range fields[i+1:] {
			t = strings.Trim(t, "`")
			if t == "#" || strings.HasPrefix(t, "#") { // inline comment ends the command
				break
			}
			args = append(args, t)
		}
		out = append(out, args)
	}
	return out
}

// collectCodeIdentifiers gathers every "litevirt_*" string literal defined in
// the Go source under internal/ and cmd/ (metrics names, Ansible inventory
// vars, etc.).
func collectCodeIdentifiers(t *testing.T, root string) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	idRE := regexp.MustCompile(`"(litevirt_[a-z0-9_]+)"`)
	for _, sub := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, sub), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for _, m := range idRE.FindAllStringSubmatch(string(b), -1) {
				set[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}
	return set
}

// docFiles returns the published claim surface: README.md plus docs/*.md.
// It deliberately does NOT glob other top-level *.md — files like the private,
// gitignored TODO.md are roadmap notes that reference not-yet-built commands
// and metrics on purpose, and aren't part of the public docs anyway.
func docFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	if readme := filepath.Join(root, "README.md"); fileExists(readme) {
		files = append(files, readme)
	}
	m, err := filepath.Glob(filepath.Join(root, "docs", "*.md"))
	if err != nil {
		t.Fatalf("glob docs/*.md: %v", err)
	}
	files = append(files, m...)
	if len(files) == 0 {
		t.Fatal("no doc files found — repo layout changed?")
	}
	return files
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// --- guard-logic unit tests (prove the triangulation actually catches drift) ---

func TestValidateInvocation(t *testing.T) {
	root := newRootCmd()
	cases := []struct {
		args []string
		bad  string // expected offending token, "" if the invocation is valid
	}{
		{[]string{"ls"}, ""},
		{[]string{"run", "--name", "web", "--image", "ubuntu"}, ""},
		{[]string{"start", "<vm>"}, ""},   // placeholder arg to a leaf
		{[]string{"host", "upgrade"}, ""}, // real nested subcommand
		{[]string{"compose", "up", "-f", "x.yml"}, ""},
		{[]string{"help"}, ""},                         // cobra built-in
		{[]string{"host", "help"}, ""},                 // cobra built-in under a group
		{[]string{"frobnicate"}, "frobnicate"},         // bogus top-level command
		{[]string{"host", "frobnicate"}, "frobnicate"}, // bogus subcommand of a group
	}
	for _, tc := range cases {
		if got := validateInvocation(root, tc.args); got != tc.bad {
			t.Errorf("validateInvocation(%v) = %q, want %q", tc.args, got, tc.bad)
		}
	}
}

// TestResolveInvocation pins the read-side resolver the reverse guard depends
// on: it must return the DEEPEST command a doc reference reaches, so a mention
// of `lv host upgrade` credits the leaf and not just the group, and must return
// nil for anything that isn't a command at all.
func TestResolveInvocation(t *testing.T) {
	root := newRootCmd()
	cases := []struct {
		args []string
		want string // expected resolved command path, "" for nil
	}{
		{[]string{"ls"}, "ls"},
		{[]string{"host", "upgrade"}, "host upgrade"},          // deepest, not "host"
		{[]string{"host", "upgrade", "node1"}, "host upgrade"}, // positional arg ends the path
		{[]string{"start", "<vm>"}, "start"},                   // placeholder ends the path
		{[]string{"compose", "up", "-f", "x.yml"}, "compose up"},
		{[]string{"frobnicate"}, ""}, // not a command
		{[]string{"--help"}, ""},     // flag first
		{[]string{"help"}, ""},       // cobra built-in
	}
	for _, tc := range cases {
		var got string
		if cmd := resolveInvocation(root, tc.args); cmd != nil {
			got = commandPath(cmd)
		}
		if got != tc.want {
			t.Errorf("resolveInvocation(%v) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestCheckIdentifier(t *testing.T) {
	code := map[string]bool{"litevirt_foo_total": true, "litevirt_label_": true}
	cases := []struct {
		tok    string
		wantOK bool
	}{
		{"litevirt_foo_total", true},
		{"litevirt_bar", false},
		{"litevirt_foo_*", true},                        // glob prefix in prose
		{"litevirt_label_", true},                       // trailing-underscore prefix
		// The allowlist is empty by design, so a name that is neither in the code
		// nor a prefix form must be rejected — that is the whole point of the guard.
		{"litevirt_audit_chain_last_verified_ok", false},
	}
	for _, tc := range cases {
		got := checkIdentifier(tc.tok, code)
		if (got == "") != tc.wantOK {
			t.Errorf("checkIdentifier(%q) = %q, wantOK=%v", tc.tok, got, tc.wantOK)
		}
	}
}

func TestExtractInvocations(t *testing.T) {
	md := "Run `lv ls` first.\n" +
		"```bash\n" +
		"$ lv host upgrade node1\n" +
		"LV_HOST=x lv run --name web\n" +
		"sudo lv ct create foo\n" +
		"# lv not-a-command-its-a-comment\n" +
		"```\n" +
		"Then `lv compose up`.\n"
	got := extractInvocations(md)
	want := [][]string{
		{"ls"},
		{"host", "upgrade", "node1"},
		{"run", "--name", "web"},
		{"ct", "create", "foo"},
		{"compose", "up"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("extractInvocations:\n got=%v\nwant=%v", got, want)
	}
}

// repoRoot walks up from the test's working directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (go.mod not found above test dir)")
		}
		dir = parent
	}
}
