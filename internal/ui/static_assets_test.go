package ui

import (
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// consoleTemplates are the pages that load the bundled noVNC client.
var consoleTemplates = []string{
	"templates/vnc.html",
	"templates/vnc_modal.html",
	"templates/console_modal.html",
}

// buildFetchedPrefixes are the static directories `make vendor-js` downloads at
// build time instead of committing (see the Makefile and .gitignore). A plain
// `go test` tree does not have them, so the all-references check skips a
// prefix only while its directory is absent on disk; once vendor-js has run
// (as in CI), every reference into it must resolve. The console module graph
// must never depend on one.
var buildFetchedPrefixes = []string{
	"static/vendor/htmx/",
	"static/vendor/uplot/",
	"static/fonts/",
}

var (
	// <script src="..."> and <link href="..."> under /static/.
	htmlStaticRef = regexp.MustCompile(`(?:src|href)\s*=\s*["'](/static/[^"']+)["']`)
	// CSS url("...") under /static/ (the fonts, from style.css).
	cssStaticRef = regexp.MustCompile(`url\(\s*["']?(/static/[^"')\s]+)["']?\s*\)`)
	// Static and dynamic ES module specifiers:
	//   import X from "s";  import {a} from 's';  import "s";
	//   export {a} from "s";  import("s")
	moduleSpecifier = regexp.MustCompile(`(?m)(?:^|[;\s])(?:import|export)\s*(?:[\w*{}\s,$]+?\s*from\s*)?\(?\s*["']([^"'\n]+)["']`)
)

// staticPath maps a URL path or module specifier, resolved against the file
// that references it, to its path inside staticFS. The UI serves staticFS at
// /static/ unchanged (http.FileServerFS in Handler), so "/static/a.js" is the
// embedded file "static/a.js".
func staticPath(fromFile, spec string) (string, bool) {
	switch {
	case strings.HasPrefix(spec, "/static/"):
		return strings.TrimPrefix(spec, "/"), true
	case strings.HasPrefix(spec, "./"), strings.HasPrefix(spec, "../"):
		return path.Join(path.Dir(fromFile), spec), true
	}
	return "", false
}

// walkModuleGraph follows every import reachable from the entry specifiers and
// returns the embedded paths it visited and the ones that are not embedded,
// each missing path listed with the file that imports it.
func walkModuleGraph(t *testing.T, entries map[string]string) (visited []string, missing []string) {
	t.Helper()
	seen := map[string]bool{}
	type edge struct{ from, to string }
	queue := []edge{}
	for to, from := range entries {
		queue = append(queue, edge{from, to})
	}
	for len(queue) > 0 {
		e := queue[0]
		queue = queue[1:]
		if seen[e.to] {
			continue
		}
		seen[e.to] = true
		data, err := fs.ReadFile(staticFS, e.to)
		if err != nil {
			missing = append(missing, "/"+e.to+" (imported by "+e.from+")")
			continue
		}
		visited = append(visited, e.to)
		if !strings.HasSuffix(e.to, ".js") {
			continue
		}
		for _, m := range moduleSpecifier.FindAllStringSubmatch(string(data), -1) {
			p, ok := staticPath(e.to, m[1])
			if !ok {
				t.Errorf("%s imports %q, which is not a /static/ or relative path: the UI serves no bare module specifiers", e.to, m[1])
				continue
			}
			queue = append(queue, edge{e.to, p})
		}
	}
	sort.Strings(visited)
	sort.Strings(missing)
	return visited, missing
}

// TestConsoleModuleGraphIsEmbedded walks every <script src> and ES module
// import reachable from the console pages and requires each target to be in
// staticFS. An ES module whose import 404s aborts the whole graph, so one
// missing file (pako, kept out of the repo by an unanchored `vendor/` ignore
// rule) leaves the console blank with no error on the page.
func TestConsoleModuleGraphIsEmbedded(t *testing.T) {
	entries := map[string]string{}
	for _, tmpl := range consoleTemplates {
		data, err := fs.ReadFile(templateFS, tmpl)
		if err != nil {
			t.Fatalf("read %s: %v", tmpl, err)
		}
		src := string(data)
		for _, m := range htmlStaticRef.FindAllStringSubmatch(src, -1) {
			p, _ := staticPath(tmpl, m[1])
			entries[p] = tmpl
		}
		for _, m := range moduleSpecifier.FindAllStringSubmatch(src, -1) {
			p, ok := staticPath(tmpl, m[1])
			if !ok {
				t.Errorf("%s imports %q, which is not a /static/ path", tmpl, m[1])
				continue
			}
			entries[p] = tmpl
		}
	}
	if _, ok := entries["static/novnc/rfb.js"]; !ok {
		t.Fatalf("no console template imports /static/novnc/rfb.js; the walk would prove nothing (entries: %v)", entries)
	}

	visited, missing := walkModuleGraph(t, entries)
	for _, p := range visited {
		for _, pre := range buildFetchedPrefixes {
			if strings.HasPrefix(p, pre) {
				t.Errorf("console module graph reaches build-fetched %s; it must only use committed files", p)
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("console module graph imports %d file(s) that are not embedded, so the browser gets 404 and noVNC never loads:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	// A walk that stopped following imports would pass vacuously, so require
	// the files the console cannot work without: noVNC's entry point and the
	// pako modules its inflator and deflator import.
	reached := map[string]bool{}
	for _, p := range visited {
		reached[p] = true
	}
	for _, anchor := range []string{
		"static/novnc/rfb.js",
		"static/vendor/pako/lib/zlib/inflate.js",
		"static/vendor/pako/lib/zlib/deflate.js",
		"static/vendor/pako/lib/zlib/zstream.js",
	} {
		if !reached[anchor] {
			t.Errorf("walk did not reach embedded %s", anchor)
		}
	}
	if len(visited) < 40 {
		t.Errorf("walk visited only %d files; the import pattern has probably stopped matching noVNC's imports", len(visited))
	}
}

// TestTemplateStaticRefsAreEmbedded checks every /static/ reference in every
// template and every embedded stylesheet. References into a build-fetched
// directory are checked whenever that directory exists on disk, and skipped
// (with a log line) only while `make vendor-js` has not run.
func TestTemplateStaticRefsAreEmbedded(t *testing.T) {
	type source struct {
		fsys     fs.FS
		name     string
		patterns []*regexp.Regexp
	}
	var sources []source
	tmpls, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil || len(tmpls) == 0 {
		t.Fatalf("glob templates: %v (%d)", err, len(tmpls))
	}
	for _, tmpl := range tmpls {
		sources = append(sources, source{templateFS, tmpl, []*regexp.Regexp{htmlStaticRef, moduleSpecifier}})
	}
	css, err := fs.Glob(staticFS, "static/*.css")
	if err != nil || len(css) == 0 {
		t.Fatalf("glob stylesheets: %v (%d)", err, len(css))
	}
	for _, c := range css {
		sources = append(sources, source{staticFS, c, []*regexp.Regexp{cssStaticRef}})
	}

	// Build-fetched directories present on disk. The test runs in the package
	// directory, which is where go:embed reads static/ from, so a directory
	// present now was present when the test binary embedded static/*.
	fetched := map[string]bool{}
	for _, pre := range buildFetchedPrefixes {
		if st, err := os.Stat(strings.TrimSuffix(pre, "/")); err == nil && st.IsDir() {
			fetched[pre] = true
		}
	}

	var missing []string
	skipped := map[string]int{}
	checked := 0
	for _, src := range sources {
		data, err := fs.ReadFile(src.fsys, src.name)
		if err != nil {
			t.Fatalf("read %s: %v", src.name, err)
		}
		var refs [][]string
		for _, re := range src.patterns {
			refs = append(refs, re.FindAllStringSubmatch(string(data), -1)...)
		}
	ref:
		for _, m := range refs {
			if strings.Contains(m[1], "{{") {
				continue // templated (e.g. grafana/{{.Filename}})
			}
			p, ok := staticPath(src.name, m[1])
			if !ok {
				continue
			}
			for _, pre := range buildFetchedPrefixes {
				if strings.HasPrefix(p, pre) && !fetched[pre] {
					skipped[pre]++
					continue ref
				}
			}
			checked++
			if _, err := fs.Stat(staticFS, p); err != nil {
				missing = append(missing, "/"+p+" (referenced by "+src.name+")")
			}
		}
	}
	for pre, n := range skipped {
		t.Logf("skipped %d reference(s) into %s: not fetched (run `make vendor-js` to check them)", n, pre)
	}
	if checked == 0 {
		t.Fatalf("no /static/ reference was checked; the patterns have stopped matching")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d static reference(s) are not embedded:\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}
