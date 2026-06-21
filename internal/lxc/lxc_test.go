package lxc

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRuntime records calls and returns scripted responses. Used for
// gRPC-handler tests that need a Runtime but mustn't shell out.
type fakeRuntime struct {
	containers map[string]*Container
	createErr  error
	stateMap   map[string]State
	listOut    []string
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

func (f *fakeRuntime) List(_ context.Context) ([]string, error) { return f.listOut, nil }

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
