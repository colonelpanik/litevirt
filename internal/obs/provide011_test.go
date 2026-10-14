package obs

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// provide-telemetry reserves service, env, version, trace_id and span_id: a
// caller attribute with one of those keys is dropped once the matching stamped
// field exists. No litevirt log call may use them as an attribute key. The scan
// is AST based and follows slog's own key/value pairing, so a value that
// happens to read "version" is not a key. It covers package-level slog
// functions, *slog.Logger methods, slog.Log/LogAttrs, With arguments, the
// slog.String/Int/Any... attr constructors (and slog.Group's name) and
// slog.Attr{Key: ...} literals, multi-line calls included. The constructor
// names only count on the slog package, so a DB row accessor such as
// rows[0].Int("version") is not a log call. The one exception is named
// exactly, by file, message and key: the daemon's startup line logs before
// obs.Setup runs, so the default logger keeps the key.
func TestNoReservedSlogKeys(t *testing.T) {
	reserved := map[string]bool{"service": true, "env": true, "version": true, "trace_id": true, "span_id": true}
	// Method or function name → index of the message argument; the key/value
	// arguments follow it. With has no message, so its pairs start at 0.
	msgIndex := map[string]int{
		"Debug": 0, "Info": 0, "Warn": 0, "Error": 0,
		"DebugContext": 1, "InfoContext": 1, "WarnContext": 1, "ErrorContext": 1,
		"Log": 2, "LogAttrs": 2, "With": -1,
	}
	// Attr constructors and Group: the first argument is the key (the name).
	attrFuncs := map[string]bool{
		"String": true, "Int": true, "Int64": true, "Uint64": true, "Float64": true,
		"Bool": true, "Duration": true, "Time": true, "Any": true, "Group": true,
	}
	// file | message | key of the exempt call.
	allowed := map[string]bool{
		"cmd/litevirt/daemon.go|starting litevirt daemon|version": true,
	}
	isSlog := func(e ast.Expr) bool { id, ok := e.(*ast.Ident); return ok && id.Name == "slog" }
	strLit := func(e ast.Expr) (string, bool) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		v, err := strconv.Unquote(lit.Value)
		return v, err == nil
	}
	isAttrType := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && isSlog(sel.X) && sel.Sel.Name == "Attr"
	}
	// attrLitKey is the key of an slog.Attr composite literal, keyed or positional.
	attrLitKey := func(x *ast.CompositeLit) string {
		for i, el := range x.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Key" {
					k, _ := strLit(kv.Value)
					return k
				}
			} else if i == 0 {
				k, _ := strLit(el)
				return k
			}
		}
		return ""
	}
	// attrKey returns the literal key of an slog.Attr expression: a
	// slog.String(...)-style call or a slog.Attr{...} literal.
	attrKey := func(e ast.Expr) (key string, isAttr bool) {
		switch x := e.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && isSlog(sel.X) && attrFuncs[sel.Sel.Name] && len(x.Args) > 0 {
				k, _ := strLit(x.Args[0])
				return k, true
			}
		case *ast.CompositeLit:
			if isAttrType(x.Type) {
				return attrLitKey(x), true
			}
		}
		return "", false
	}
	// handled holds the attr expressions already judged. A slog.Group's inner
	// attributes are keys inside the group, not top-level ones, so they are
	// marked handled without being judged.
	handled := map[ast.Node]bool{}
	var skipNested func(e ast.Expr)
	skipNested = func(e ast.Expr) {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !isSlog(sel.X) || sel.Sel.Name != "Group" {
			return
		}
		for _, a := range call.Args[min(1, len(call.Args)):] {
			handled[a] = true
			if lit, ok := a.(*ast.CompositeLit); ok {
				for _, el := range lit.Elts {
					handled[el] = true
				}
			}
			skipNested(a)
		}
	}
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "gen" || n == ".claude" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		scanned++
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		report := func(pos token.Pos, what, msg, key string) {
			if reserved[key] && !allowed[rel+"|"+msg+"|"+key] {
				t.Errorf("%s: %s uses reserved key %q; provide-telemetry drops it when the stamped field exists. Use a specific key (crl_version, build_version, ...)",
					fset.Position(pos), what, key)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if mi, isLog := msgIndex[sel.Sel.Name]; isLog {
					msg := ""
					if mi >= 0 && mi < len(x.Args) {
						msg, _ = strLit(x.Args[mi])
					}
					for i := mi + 1; i < len(x.Args); {
						arg := x.Args[i]
						if k, isAttr := attrKey(arg); isAttr {
							handled[arg] = true
							skipNested(arg)
							report(arg.Pos(), sel.Sel.Name+"(...) attribute", msg, k)
							i++
							continue
						}
						k, isKey := strLit(arg)
						if !isKey {
							// A key held in a variable or constant is not
							// resolved; assume it pairs with the next argument
							// and keep reading the rest.
							i += 2
							continue
						}
						report(arg.Pos(), sel.Sel.Name+"(...)", msg, k)
						i += 2
					}
					return true
				}
				if isSlog(sel.X) && attrFuncs[sel.Sel.Name] && !handled[x] {
					skipNested(x)
					k, _ := attrKey(x)
					report(x.Pos(), "slog."+sel.Sel.Name+"(...)", "", k)
				}
			case *ast.CompositeLit:
				if at, ok := x.Type.(*ast.ArrayType); ok && isAttrType(at.Elt) {
					// []slog.Attr{{Key: ...}}: the elements carry no type of their own.
					for _, el := range x.Elts {
						if lit, ok := el.(*ast.CompositeLit); ok && lit.Type == nil {
							handled[lit] = true
							report(lit.Pos(), "slog.Attr{Key: ...}", "", attrLitKey(lit))
						}
					}
				} else if !handled[x] {
					if k, isAttr := attrKey(x); isAttr {
						report(x.Pos(), "slog.Attr{Key: ...}", "", k)
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files; the walk root is wrong", scanned)
	}
}

// log_level CRITICAL was accepted before provide-telemetry 0.8 and meant ERROR.
// Since 0.8 it is a level above ERROR that litevirt never emits, so it would
// silence every line. obs maps it to ERROR (from config and from env) and says so.
func TestSetup_CriticalLogLevelMappedToError(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		env  map[string]string
	}{
		{"config", Config{ServiceName: "litevirt", LogLevel: "CRITICAL"}, nil},
		{"litevirt env", Config{ServiceName: "litevirt"}, map[string]string{"LITEVIRT_LOG_LEVEL": "critical"}},
		{"vendor env", Config{ServiceName: "litevirt"}, map[string]string{"PROVIDE_LOG_LEVEL": "CRITICAL"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			// The WARN goes through the pre-Setup default logger.
			var pre bytes.Buffer
			prev := slog.Default()
			t.Cleanup(func() { slog.SetDefault(prev) })
			slog.SetDefault(slog.New(slog.NewTextHandler(&pre, nil)))
			lines := captureDaemonStderrEnv(t, tc.cfg, func() {
				slog.Info("info below error")
				slog.Error("an error line", "k", "v")
			})
			if n := countWith(lines, "an error line"); n != 1 {
				t.Fatalf("ERROR record emitted %d times under CRITICAL, want 1 (silenced?): %q", n, lines)
			}
			if n := countWith(lines, "info below error"); n != 0 {
				t.Errorf("INFO record emitted under a CRITICAL->ERROR level: %q", lines)
			}
			if got := os.Getenv("PROVIDE_LOG_LEVEL"); got != "ERROR" {
				t.Errorf("PROVIDE_LOG_LEVEL=%q, want ERROR", got)
			}
			if n := strings.Count(pre.String(), "treated as ERROR"); n != 1 {
				t.Errorf("startup WARN count=%d, want 1: %q", n, pre.String())
			}
		})
	}
}

// PROVIDE_LOG_INCLUDE_CALLER defaults true in provide-telemetry 0.9+, which
// adds filename/lineno to every record. Through the stdlib log bridge that
// reports adapter frames and lengthens every journald line, so obs defaults
// it off; an operator can still opt in.
//
// On the default local path (no endpoint, no explicit level or format) the
// record reaches stderr re-logged as a message, with no caller fields
// whatever the setting, so the line checks below hold either way. The
// environment check is what pins the default: removing the default turns this
// red through it.
func TestSetup_IncludeCallerDefaultsOff(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "litevirt", HostName: "node-3"}, func() {
		slog.Info("caller probe")
	})
	line := lineWith(lines, "caller probe")
	if line == "" {
		t.Fatalf("no journal line: %q", lines)
	}
	f := logfmtFields(line)
	if _, ok := f["filename"]; ok {
		t.Errorf("filename on a default record: %q", line)
	}
	if _, ok := f["lineno"]; ok {
		t.Errorf("lineno on a default record: %q", line)
	}
	if v, ok := os.LookupEnv("PROVIDE_LOG_INCLUDE_CALLER"); !ok || v != "false" {
		t.Errorf("PROVIDE_LOG_INCLUDE_CALLER=%q (set=%v), want the obs default false", v, ok)
	}
}

// captureDaemonStderr runs Setup the way the daemon does, with os.Stderr (the
// daemon's journal stream) swapped for a pipe, then runs emit and returns
// every line the installed handler chain wrote. The slog default and the
// stdlib log output are restored afterwards.
func captureDaemonStderr(t *testing.T, cfg Config, emit func()) []string {
	t.Helper()
	cleanEnv(t)
	return captureDaemonStderrEnv(t, cfg, emit)
}

// captureDaemonStderrEnv is captureDaemonStderr without the env reset, for a
// test that has called cleanEnv and then exported operator variables.
func captureDaemonStderrEnv(t *testing.T, cfg Config, emit func()) []string {
	t.Helper()
	prevDefault, prevWriter, prevFlags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(prevDefault)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prevStderr := os.Stderr
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()

	shutdown, serr := Setup(context.Background(), cfg)
	if serr != nil {
		t.Logf("Setup (fail-open): %v", serr)
	}
	emit()
	if shutdown != nil {
		_ = shutdown(context.Background())
	}
	os.Stderr = prevStderr
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return strings.Split(strings.TrimSpace(string(bytes.TrimSpace(out))), "\n")
}

// countWith counts the lines containing needle.
func countWith(lines []string, needle string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l, needle) {
			n++
		}
	}
	return n
}

func lineWith(lines []string, needle string) string {
	for _, l := range lines {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

// logfmtFields splits one text-handler line into key -> value, unquoting
// quoted values. Enough for the shapes slog's TextHandler writes.
func logfmtFields(line string) map[string]string {
	f := map[string]string{}
	for len(line) > 0 {
		line = strings.TrimLeft(line, " ")
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			break
		}
		key := line[:eq]
		line = line[eq+1:]
		var val string
		if strings.HasPrefix(line, `"`) {
			end := 1
			for end < len(line) && (line[end] != '"' || line[end-1] == '\\') {
				end++
			}
			val = strings.ReplaceAll(line[1:end], `\"`, `"`)
			line = line[min(end+1, len(line)):]
		} else {
			sp := strings.IndexByte(line, ' ')
			if sp < 0 {
				sp = len(line)
			}
			val = line[:sp]
			line = line[sp:]
		}
		f[key] = val
	}
	return f
}
