package lxc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExportImportContainer_RoundTrip tars a container dir out of one lxcpath
// and back into a *different* one, proving the archive is self-contained and the
// imported config's rootfs path is rewritten to the new host's layout.
func TestExportImportContainer_RoundTrip(t *testing.T) {
	srcPath := t.TempDir()
	src := &LxcRunner{Lxcpath: srcPath}

	// Lay down a container dir: config (with the source rootfs path) + a rootfs
	// holding a sentinel file.
	ctDir := filepath.Join(srcPath, "web")
	if err := os.MkdirAll(filepath.Join(ctDir, "rootfs", "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(ctDir, "rootfs", "etc", "hostname")
	if err := os.WriteFile(sentinel, []byte("web-ct\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "lxc.uts.name = web\nlxc.rootfs.path = dir:" + filepath.Join(ctDir, "rootfs") + "\nlxc.net.0.type = veth\n"
	if err := os.WriteFile(filepath.Join(ctDir, "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := src.ExportContainer(context.Background(), "web", &buf); err != nil {
		t.Fatalf("ExportContainer: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("export produced no bytes")
	}

	// Import into a fresh lxcpath (simulating restore on another host).
	dstPath := t.TempDir()
	dst := &LxcRunner{Lxcpath: dstPath}
	if err := dst.ImportContainer(context.Background(), "web", &buf); err != nil {
		t.Fatalf("ImportContainer: %v", err)
	}

	// Rootfs sentinel survived.
	got, err := os.ReadFile(filepath.Join(dstPath, "web", "rootfs", "etc", "hostname"))
	if err != nil || string(got) != "web-ct\n" {
		t.Errorf("restored sentinel = %q err=%v", got, err)
	}
	// Config's rootfs path was rewritten to the new lxcpath, net config preserved.
	rewritten, err := os.ReadFile(filepath.Join(dstPath, "web", "config"))
	if err != nil {
		t.Fatal(err)
	}
	wantPath := "lxc.rootfs.path = dir:" + filepath.Join(dstPath, "web", "rootfs")
	if !strings.Contains(string(rewritten), wantPath) {
		t.Errorf("config not rewritten to new path:\n%s\nwant line: %s", rewritten, wantPath)
	}
	if !strings.Contains(string(rewritten), "lxc.net.0.type = veth") {
		t.Errorf("network config lost on import:\n%s", rewritten)
	}
	// RootFSPath now resolves to the rewritten location.
	if p, _ := dst.RootFSPath("web"); p != filepath.Join(dstPath, "web", "rootfs") {
		t.Errorf("RootFSPath after import = %q", p)
	}
}

// TestRevertContainer_RoundTripAndCrashSafety: a snapshot tar from
// ExportContainer reverts a modified container back to the captured state
// in place; and a corrupt snapshot stream never loses the live container.
func TestRevertContainer_RoundTripAndCrashSafety(t *testing.T) {
	path := t.TempDir()
	r := &LxcRunner{Lxcpath: path}
	hn := filepath.Join(path, "web", "rootfs", "etc", "hostname")
	if err := os.MkdirAll(filepath.Dir(hn), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hn, []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "web", "config"),
		[]byte("lxc.uts.name = web\nlxc.rootfs.path = dir:"+filepath.Join(path, "web", "rootfs")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Snapshot the current ("v1") state.
	var snap bytes.Buffer
	if err := r.ExportContainer(context.Background(), "web", &snap); err != nil {
		t.Fatalf("ExportContainer: %v", err)
	}
	snapBytes := snap.Bytes()

	// Mutate the rootfs to "v2".
	if err := os.WriteFile(hn, []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Revert from the snapshot → back to "v1".
	if err := r.RevertContainer(context.Background(), "web", bytes.NewReader(snapBytes)); err != nil {
		t.Fatalf("RevertContainer: %v", err)
	}
	if got, _ := os.ReadFile(hn); string(got) != "v1\n" {
		t.Errorf("after revert hostname = %q, want v1", got)
	}

	// Crash safety: a corrupt snapshot stream must leave the live container intact.
	if err := os.WriteFile(hn, []byte("v3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.RevertContainer(context.Background(), "web", strings.NewReader("not-a-valid-tar")); err == nil {
		t.Error("expected error reverting from a corrupt snapshot")
	}
	if got, _ := os.ReadFile(hn); string(got) != "v3\n" {
		t.Errorf("corrupt revert lost data: hostname = %q, want v3 (rolled back)", got)
	}
}

// TestCloneContainer_FreshIdentity clones a container dir and verifies the clone
// is an independent copy with a fresh identity: new uts.name, regenerated NIC
// MAC, rootfs.path repointed, hostname file updated — and mutating the clone
// doesn't touch the source.
func TestCloneContainer_FreshIdentity(t *testing.T) {
	path := t.TempDir()
	r := &LxcRunner{Lxcpath: path}
	srcRoot := filepath.Join(path, "base", "rootfs")
	if err := os.MkdirAll(filepath.Join(srcRoot, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "etc", "hostname"), []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "data.txt"), []byte("payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srcCfg := "lxc.uts.name = base\n" +
		"lxc.rootfs.path = dir:" + srcRoot + "\n" +
		"lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\nlxc.net.0.hwaddr = 52:54:00:aa:bb:cc\n"
	if err := os.WriteFile(filepath.Join(path, "base", "config"), []byte(srcCfg), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := r.CloneContainer(context.Background(), "base", "clone1"); err != nil {
		t.Fatalf("CloneContainer: %v", err)
	}

	// Clone has the data (independent copy).
	if got, _ := os.ReadFile(filepath.Join(path, "clone1", "rootfs", "data.txt")); string(got) != "payload\n" {
		t.Errorf("clone data = %q, want payload", got)
	}
	cfg, _ := os.ReadFile(filepath.Join(path, "clone1", "config"))
	cfgStr := string(cfg)
	if !strings.Contains(cfgStr, "lxc.uts.name = clone1") {
		t.Errorf("clone uts.name not rewritten:\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "lxc.rootfs.path = dir:"+filepath.Join(path, "clone1", "rootfs")) {
		t.Errorf("clone rootfs.path not repointed:\n%s", cfgStr)
	}
	if strings.Contains(cfgStr, "52:54:00:aa:bb:cc") {
		t.Errorf("clone kept the source MAC — should be regenerated:\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "lxc.net.0.hwaddr = 52:54:00:") {
		t.Errorf("clone has no regenerated MAC:\n%s", cfgStr)
	}
	if got, _ := os.ReadFile(filepath.Join(path, "clone1", "rootfs", "etc", "hostname")); string(got) != "clone1\n" {
		t.Errorf("clone /etc/hostname = %q, want clone1", got)
	}

	// Independence: mutating the clone leaves the source untouched.
	if err := os.WriteFile(filepath.Join(path, "clone1", "rootfs", "data.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(srcRoot, "data.txt")); string(got) != "payload\n" {
		t.Errorf("source data mutated by clone change: %q", got)
	}

	// Refuses to clobber an existing target.
	if err := r.CloneContainer(context.Background(), "base", "clone1"); err == nil {
		t.Error("expected clone to refuse an existing target dir")
	}
}

// TestImportContainer_RefusesClobber guards against overwriting a live container.
func TestImportContainer_RefusesClobber(t *testing.T) {
	dstPath := t.TempDir()
	dst := &LxcRunner{Lxcpath: dstPath}
	if err := os.MkdirAll(filepath.Join(dstPath, "web"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := dst.ImportContainer(context.Background(), "web", strings.NewReader("ignored"))
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected already-exists refusal, got %v", err)
	}
}

// RootFSPath parses lxc.rootfs.path from the container config (stripping "dir:"),
// falls back to the standard <lxcpath>/<name>/rootfs layout, and errors on a
// missing config.
func TestRootFSPath(t *testing.T) {
	dir := t.TempDir()
	r := &LxcRunner{Lxcpath: dir}

	mkcfg := func(name, body string) {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name, "config"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	mkcfg("web", "lxc.uts.name = web\nlxc.rootfs.path = dir:/custom/web/rootfs\n")
	if p, err := r.RootFSPath("web"); err != nil || p != "/custom/web/rootfs" {
		t.Errorf("explicit rootfs.path = %q, err=%v; want /custom/web/rootfs", p, err)
	}

	mkcfg("bare", "lxc.uts.name = bare\n") // no rootfs.path → standard layout
	if p, _ := r.RootFSPath("bare"); p != filepath.Join(dir, "bare", "rootfs") {
		t.Errorf("fallback rootfs = %q, want %s", p, filepath.Join(dir, "bare", "rootfs"))
	}

	if _, err := r.RootFSPath("nope"); err == nil {
		t.Error("missing config should error")
	}
}

// fakeRuntime records calls and returns scripted responses. Used for
// gRPC-handler tests that need a Runtime but mustn't shell out.
type fakeRuntime struct {
	containers map[string]*Container
	createErr  error
	stateMap   map[string]State
	listOut    []string
	statsMap   map[string]ContainerStats // scripted Stats responses; absent → ErrStatsUnavailable
}

func (f *fakeRuntime) Stats(_ context.Context, name string) (ContainerStats, error) {
	if st, ok := f.statsMap[name]; ok {
		return st, nil
	}
	return ContainerStats{}, ErrStatsUnavailable
}

func newFakeRuntime() *fakeRuntime {
	return &fakeRuntime{
		containers: map[string]*Container{},
		stateMap:   map[string]State{},
	}
}

func (f *fakeRuntime) Create(_ context.Context, opts CreateOpts) (*Container, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	c := &Container{
		Name: opts.Name, State: StateStopped,
		CPULimit: opts.CPULimit, MemoryMiB: opts.MemoryMiB,
		Network: opts.Network, Labels: opts.Labels,
	}
	f.containers[opts.Name] = c
	f.stateMap[opts.Name] = StateStopped
	return c, nil
}

func (f *fakeRuntime) Start(_ context.Context, name string) error {
	if _, ok := f.containers[name]; !ok {
		return errors.New("not found")
	}
	f.containers[name].State = StateRunning
	f.stateMap[name] = StateRunning
	return nil
}

func (f *fakeRuntime) Stop(_ context.Context, name string, _ int) error {
	if c, ok := f.containers[name]; ok {
		c.State = StateStopped
		f.stateMap[name] = StateStopped
	}
	return nil
}

func (f *fakeRuntime) Delete(_ context.Context, name string) error {
	delete(f.containers, name)
	delete(f.stateMap, name)
	return nil
}

func (f *fakeRuntime) Exec(_ context.Context, _ string, _ []string) (ExecResult, error) {
	return ExecResult{Stdout: []byte("ok"), ExitCode: 0}, nil
}

func (f *fakeRuntime) State(_ context.Context, name string) (State, error) {
	if s, ok := f.stateMap[name]; ok {
		return s, nil
	}
	return StateUnknown, nil
}

func (f *fakeRuntime) List(_ context.Context) ([]string, error)   { return f.listOut, nil }
func (f *fakeRuntime) Freeze(_ context.Context, _ string) error   { return nil }
func (f *fakeRuntime) Unfreeze(_ context.Context, _ string) error { return nil }
func (f *fakeRuntime) RootFSPath(name string) (string, error) {
	return "/var/lib/lxc/" + name + "/rootfs", nil
}
func (f *fakeRuntime) ExportContainer(_ context.Context, _ string, w io.Writer) error {
	_, err := w.Write([]byte("fake-tar"))
	return err
}
func (f *fakeRuntime) ImportContainer(_ context.Context, _ string, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}
func (f *fakeRuntime) RevertContainer(_ context.Context, _ string, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}
func (f *fakeRuntime) CloneContainer(_ context.Context, _, _ string) error { return nil }

// TestCreateOpts_Validate covers every documented invariant.
func TestCreateOpts_Validate(t *testing.T) {
	cases := []struct {
		name string
		o    CreateOpts
		err  string
	}{
		{"empty name", CreateOpts{Template: "download", Distro: "alpine"}, "container name required"},
		{"slash in name", CreateOpts{Name: "a/b", Template: "download", Distro: "alpine"}, "must not contain"},
		{"missing template", CreateOpts{Name: "ok"}, "template required"},
		{"download missing distro", CreateOpts{Name: "ok", Template: "download"}, "requires distro"},
		{"network missing bridge", CreateOpts{
			Name: "ok", Template: "download", Distro: "alpine",
			Network: []NetworkAttach{{Name: "eth0"}},
		}, "bridge required"},
		{"happy path", CreateOpts{Name: "ok", Template: "download", Distro: "alpine"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.o.Validate()
			if tc.err == "" {
				if err != nil {
					t.Errorf("expected nil, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("expected error containing %q, got %v", tc.err, err)
			}
		})
	}
}

// TestParseLxcInfoState covers every documented mapping.
func TestParseLxcInfoState(t *testing.T) {
	cases := map[string]State{
		"RUNNING\n":  StateRunning,
		"STOPPED\n":  StateStopped,
		"STARTING\n": StateStarting,
		"STOPPING\n": StateStopping,
		"FROZEN\n":   StateRunning, // frozen counts as running upstream
		"WEIRD":      StateUnknown,
	}
	for in, want := range cases {
		if got := parseLxcInfoState(in); got != want {
			t.Errorf("parseLxcInfoState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseLxcInfoIP(t *testing.T) {
	cases := map[string]string{
		"10.0.0.20\n":            "10.0.0.20", // single IPv4
		"127.0.0.1\n10.0.0.20\n": "10.0.0.20", // skip loopback, take the real one
		"fe80::1\n10.0.0.21\n":   "10.0.0.21", // skip IPv6, take IPv4
		"  10.0.0.22 \n":         "10.0.0.22", // trims whitespace
		"":                       "",          // none assigned yet
		"not-an-ip\n":            "",          // garbage
	}
	for in, want := range cases {
		if got := parseLxcInfoIP(in); got != want {
			t.Errorf("parseLxcInfoIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestFakeRuntime_LifecycleRoundTrip exercises the test double itself
// to lock its semantics — gRPC handler tests rely on it.
func TestFakeRuntime_LifecycleRoundTrip(t *testing.T) {
	f := newFakeRuntime()
	ctx := context.Background()
	c, err := f.Create(ctx, CreateOpts{
		Name: "ct1", Template: "download", Distro: "alpine", Release: "3.19", Arch: "amd64",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.State != StateStopped {
		t.Errorf("State after Create = %q, want stopped", c.State)
	}
	if err := f.Start(ctx, "ct1"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s, _ := f.State(ctx, "ct1"); s != StateRunning {
		t.Errorf("State after Start = %q", s)
	}
	if err := f.Stop(ctx, "ct1", 5); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := f.Delete(ctx, "ct1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := f.containers["ct1"]; ok {
		t.Error("container map still has ct1 after Delete")
	}
}

// TestLxcRunner_WithLxcpath verifies the -P flag is prepended only
// when a path override is set.
func TestLxcRunner_WithLxcpath(t *testing.T) {
	r := &LxcRunner{}
	got := r.withLxcpath([]string{"-n", "x"})
	want := []string{"-n", "x"}
	if !slicesEq(got, want) {
		t.Errorf("default = %v, want %v", got, want)
	}
	r.Lxcpath = "/tmp/lxc-test"
	got = r.withLxcpath([]string{"-n", "x"})
	want = []string{"-P", "/tmp/lxc-test", "-n", "x"}
	if !slicesEq(got, want) {
		t.Errorf("with path = %v, want %v", got, want)
	}
}

func slicesEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
