package health

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// fakeCtRuntime is a deterministic lxc.Runtime for the container reconciler
// tests. State is whatever the test sets; Start records the call and (unless
// startErr is set) flips the container to running, mimicking a successful boot.
type fakeCtRuntime struct {
	states   map[string]lxc.State
	startErr map[string]error
	started  []string
}

func newFakeCtRuntime() *fakeCtRuntime {
	return &fakeCtRuntime{states: map[string]lxc.State{}, startErr: map[string]error{}}
}

func (f *fakeCtRuntime) Create(ctx context.Context, opts lxc.CreateOpts) (*lxc.Container, error) {
	return &lxc.Container{Name: opts.Name, State: lxc.StateStopped}, nil
}
func (f *fakeCtRuntime) Start(ctx context.Context, name string) error {
	if e := f.startErr[name]; e != nil {
		return e
	}
	f.started = append(f.started, name)
	f.states[name] = lxc.StateRunning
	return nil
}
func (f *fakeCtRuntime) Stop(ctx context.Context, name string, timeoutSec int) error {
	f.states[name] = lxc.StateStopped
	return nil
}
func (f *fakeCtRuntime) Delete(ctx context.Context, name string) error { return nil }
func (f *fakeCtRuntime) Exec(ctx context.Context, name string, argv []string) (lxc.ExecResult, error) {
	return lxc.ExecResult{}, nil
}
func (f *fakeCtRuntime) State(ctx context.Context, name string) (lxc.State, error) {
	if s, ok := f.states[name]; ok {
		return s, nil
	}
	return lxc.StateUnknown, nil
}
func (f *fakeCtRuntime) Stats(ctx context.Context, name string) (lxc.ContainerStats, error) {
	return lxc.ContainerStats{}, lxc.ErrStatsUnavailable
}
func (f *fakeCtRuntime) IP(ctx context.Context, name string) (string, error) { return "", nil }
func (f *fakeCtRuntime) Freeze(ctx context.Context, name string) error       { return nil }
func (f *fakeCtRuntime) Unfreeze(ctx context.Context, name string) error     { return nil }
func (f *fakeCtRuntime) RootFSPath(name string) (string, error) {
	return "/var/lib/lxc/" + name + "/rootfs", nil
}
func (f *fakeCtRuntime) ExportContainer(ctx context.Context, name string, w io.Writer) error {
	_, err := w.Write([]byte("fake-tar"))
	return err
}
func (f *fakeCtRuntime) ImportContainer(ctx context.Context, name string, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}
func (f *fakeCtRuntime) RevertContainer(ctx context.Context, name string, r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}
func (f *fakeCtRuntime) CloneContainer(ctx context.Context, src, dst string) error { return nil }
func (f *fakeCtRuntime) List(ctx context.Context) ([]string, error) {
	out := make([]string, 0, len(f.states))
	for n := range f.states {
		out = append(out, n)
	}
	return out, nil
}

func ctPolicyJSON(t *testing.T, condition string, maxAttempts int32, delay, window string) string {
	t.Helper()
	if condition == "" || condition == "none" {
		return ""
	}
	b, err := json.Marshal(&pb.RestartPolicy{Condition: condition, MaxAttempts: maxAttempts, Delay: delay, Window: window})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	return string(b)
}

// startCount returns how many times Start was called for a given name.
func (f *fakeCtRuntime) startCount(name string) int {
	n := 0
	for _, s := range f.started {
		if s == name {
			n++
		}
	}
	return n
}

func insertCt(t *testing.T, db *corrosion.Client, rec corrosion.ContainerRecord) {
	t.Helper()
	if err := corrosion.UpsertContainer(context.Background(), db, rec); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
}

func TestContainerCheck_OnFailure_RestartsUnexpectedStop(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateStopped // crashed / killed out of band

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "running",
		RestartPolicy: ctPolicyJSON(t, "on-failure", 0, "0s", ""),
	})

	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())

	if rt.startCount("ct1") != 1 {
		t.Errorf("expected 1 start, got %d", rt.startCount("ct1"))
	}
	fresh := mustGetCt(t, db, "ct1")
	if fresh.State != "running" {
		t.Errorf("state = %q, want running after restart", fresh.State)
	}
	rs, _ := corrosion.GetContainerRestartState(ctx, db, "node1", "ct1")
	if rs == nil || rs.AttemptCount != 1 {
		t.Errorf("restart attempts = %v, want 1", rs)
	}
}

func TestContainerCheck_OperatorStop_Sticks(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateStopped

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "stopped", StateDetail: "operator-stop",
		RestartPolicy: ctPolicyJSON(t, "always", 0, "0s", ""),
	})

	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())

	if rt.startCount("ct1") != 0 {
		t.Errorf("operator-stopped container was restarted (%d starts)", rt.startCount("ct1"))
	}
	fresh := mustGetCt(t, db, "ct1")
	if fresh.State != "stopped" || fresh.StateDetail != "operator-stop" {
		t.Errorf("state=%q detail=%q, want stopped/operator-stop", fresh.State, fresh.StateDetail)
	}
}

func TestContainerCheck_NoPolicy_NeverRestarts_ButSyncsState(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateStopped

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "running", // cluster drift
		// no restart policy
	})

	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())

	if rt.startCount("ct1") != 0 {
		t.Errorf("no-policy container restarted (%d starts)", rt.startCount("ct1"))
	}
	fresh := mustGetCt(t, db, "ct1")
	if fresh.State != "stopped" {
		t.Errorf("state = %q, want stopped (write-back to reality)", fresh.State)
	}
}

func TestContainerCheck_Running_HealsClusterDrift(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateRunning // reality: up (frozen also maps here)

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "stopped", // stale
		RestartPolicy: ctPolicyJSON(t, "always", 0, "0s", ""),
	})

	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())

	if rt.startCount("ct1") != 0 {
		t.Errorf("running container was (re)started (%d starts)", rt.startCount("ct1"))
	}
	fresh := mustGetCt(t, db, "ct1")
	if fresh.State != "running" {
		t.Errorf("state = %q, want running (healed from runtime reality)", fresh.State)
	}
}

func TestContainerCheck_NoneCondition_NeverRestarts(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateStopped

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "running",
		RestartPolicy: ctPolicyJSON(t, "none", 0, "0s", ""), // == ""
	})

	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())

	if rt.startCount("ct1") != 0 {
		t.Errorf("none-policy container restarted (%d starts)", rt.startCount("ct1"))
	}
}

func TestContainerCheck_MaxAttempts(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateStopped
	rt.startErr["ct1"] = errFakeStart // never comes up → keeps trying

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "running",
		RestartPolicy: ctPolicyJSON(t, "always", 2, "0s", "1h"),
	})

	c := NewContainerChecker("node1", db, rt)
	for i := 0; i < 3; i++ {
		c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())
	}

	rs, _ := corrosion.GetContainerRestartState(ctx, db, "node1", "ct1")
	if rs == nil || rs.AttemptCount != 2 {
		t.Errorf("attempts = %v, want 2 (max_attempts blocks the third)", rs)
	}
}

func TestContainerCheck_DelayEnforced(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateStopped
	rt.startErr["ct1"] = errFakeStart // stays down so we can re-evaluate

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "running",
		RestartPolicy: ctPolicyJSON(t, "always", 0, "1h", ""), // long delay
	})

	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())

	rs, _ := corrosion.GetContainerRestartState(ctx, db, "node1", "ct1")
	if rs == nil || rs.AttemptCount != 1 {
		t.Errorf("attempts = %v, want 1 (delay blocks the second)", rs)
	}
}

func TestContainerCheck_WindowReset(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime()
	rt.states["ct1"] = lxc.StateStopped
	rt.startErr["ct1"] = errFakeStart

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "running",
		RestartPolicy: ctPolicyJSON(t, "always", 1, "0s", "1ms"),
	})

	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())
	time.Sleep(5 * time.Millisecond) // let the window expire
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())

	rs, _ := corrosion.GetContainerRestartState(ctx, db, "node1", "ct1")
	if rs == nil || rs.AttemptCount != 1 {
		t.Errorf("attempts = %v, want 1 after window reset", rs)
	}
}

// TestContainerCheck_RelocateRecreate: a container re-homed here by failover
// (pending + relocate-recreate) is recreated from its image and started.
func TestContainerCheck_RelocateRecreate(t *testing.T) {
	db := testLogicDB(t)
	ctx := context.Background()
	rt := newFakeCtRuntime() // State() returns Unknown for an uncreated container

	insertCt(t, db, corrosion.ContainerRecord{
		HostName: "node1", Name: "ct1", State: "pending",
		StateDetail: corrosion.ContainerRelocateRecreateDetail,
		Image:       "alpine:3.19", CPULimit: 1, MemMiB: 128,
	})

	c := NewContainerChecker("node1", db, rt)
	c.checkContainer(ctx, mustGetCt(t, db, "ct1"), time.Now())

	// Recreated + started from its image.
	if rt.startCount("ct1") != 1 {
		t.Errorf("relocated container should be started once, got %d", rt.startCount("ct1"))
	}
	fresh := mustGetCt(t, db, "ct1")
	if fresh.State != "running" || fresh.StateDetail != "" {
		t.Errorf("after recreate state=%q detail=%q, want running/'' (marker cleared)", fresh.State, fresh.StateDetail)
	}
}

var errFakeStart = &fakeStartError{}

type fakeStartError struct{}

func (e *fakeStartError) Error() string { return "fake: start failed" }

func mustGetCt(t *testing.T, db *corrosion.Client, name string) corrosion.ContainerRecord {
	t.Helper()
	rec, err := corrosion.GetContainer(context.Background(), db, "node1", name)
	if err != nil || rec == nil {
		t.Fatalf("GetContainer(%s): %v (nil=%v)", name, err, rec == nil)
	}
	return *rec
}
