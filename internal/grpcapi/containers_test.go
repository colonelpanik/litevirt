package grpcapi

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeCTRuntime captures every call so handler tests can assert
// behaviour without standing up real LXC.
type fakeCTRuntime struct {
	mu          sync.Mutex
	createCalls []CreateContainerOpts
	startCalls  []string
	stopCalls   []struct {
		Name    string
		Timeout int
	}
	deleteCalls []string
	execCalls   []struct {
		Name string
		Argv []string
	}
	pullCalls []struct{ Image, Dest, Tag, Username, Password string }

	createErr error
	createOut *ContainerInfo
	deleteErr error

	// ipByName lets a test simulate a locally-discovered (e.g. DHCP) container
	// IP — what IPContainer (lxc-info -iH) would return on the LB host.
	ipByName map[string]string

	// B0 day-2 primitives: rootfs path a test wants returned, plus freeze/unfreeze
	// call tracking so backup/snapshot tests can assert quiesce + unfreeze.
	rootfs        string
	freezeCalls   []string
	unfreezeCalls []string

	// B1 backup/restore: exportPayload is what ExportContainer writes (the fake
	// "rootfs tar"); imported captures bytes handed to ImportContainer keyed by
	// name; exportErr/importErr inject failures.
	exportPayload []byte
	exported      []string
	imported      map[string][]byte
	exportErr     error
	importErr     error

	// B2 snapshot revert: captures bytes handed to RevertContainer keyed by name;
	// revertErr injects a failure.
	reverted  map[string][]byte
	revertErr error

	// B4 clone: records (src,dst) clone calls; cloneErr injects a failure.
	cloneCalls []struct{ Src, Dst string }
	cloneErr   error

	// createHook / importHook / stopHook run INSIDE the respective runtime call
	// (after the gRPC handler's pre-runtime preflight, before a subsequent
	// cluster-row write). A test uses these to mutate cluster state mid-call —
	// e.g. break the row write after the runtime object exists, or delete the row
	// between a migrate's preflight read and its stop-intent write.
	createHook func()
	importHook func()
	stopHook   func()
}

func (f *fakeCTRuntime) CreateContainer(_ context.Context, opts CreateContainerOpts) (*ContainerInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls = append(f.createCalls, opts)
	if f.createHook != nil {
		f.createHook()
	}
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.createOut != nil {
		return f.createOut, nil
	}
	return &ContainerInfo{Name: opts.Name, State: "stopped"}, nil
}
func (f *fakeCTRuntime) StartContainer(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls = append(f.startCalls, name)
	return nil
}
func (f *fakeCTRuntime) StopContainer(_ context.Context, name string, timeoutSec int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls = append(f.stopCalls, struct {
		Name    string
		Timeout int
	}{name, timeoutSec})
	if f.stopHook != nil {
		f.stopHook()
	}
	return nil
}
func (f *fakeCTRuntime) DeleteContainer(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls = append(f.deleteCalls, name)
	return f.deleteErr
}
func (f *fakeCTRuntime) ExecContainer(_ context.Context, name string, argv []string) (ContainerExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execCalls = append(f.execCalls, struct {
		Name string
		Argv []string
	}{name, argv})
	return ContainerExecResult{Stdout: []byte("ok"), ExitCode: 0}, nil
}
func (f *fakeCTRuntime) StateContainer(_ context.Context, _ string) (string, error) {
	return "running", nil
}
func (f *fakeCTRuntime) IPContainer(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ipByName[name], nil
}
func (f *fakeCTRuntime) FreezeContainer(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.freezeCalls = append(f.freezeCalls, name)
	return nil
}
func (f *fakeCTRuntime) UnfreezeContainer(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unfreezeCalls = append(f.unfreezeCalls, name)
	return nil
}
func (f *fakeCTRuntime) ContainerRootFSPath(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rootfs != "" {
		return f.rootfs, nil
	}
	return "/var/lib/lxc/" + name + "/rootfs", nil
}
func (f *fakeCTRuntime) ExportContainer(_ context.Context, name string, w io.Writer) error {
	f.mu.Lock()
	f.exported = append(f.exported, name)
	payload := f.exportPayload
	err := f.exportErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if payload == nil {
		payload = []byte("fake-rootfs-tar:" + name)
	}
	_, werr := w.Write(payload)
	return werr
}
func (f *fakeCTRuntime) ImportContainer(_ context.Context, name string, r io.Reader) error {
	data, _ := io.ReadAll(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.importHook != nil {
		f.importHook()
	}
	if f.importErr != nil {
		return f.importErr
	}
	if f.imported == nil {
		f.imported = map[string][]byte{}
	}
	f.imported[name] = data
	return nil
}
func (f *fakeCTRuntime) RevertContainer(_ context.Context, name string, r io.Reader) error {
	data, _ := io.ReadAll(r)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revertErr != nil {
		return f.revertErr
	}
	if f.reverted == nil {
		f.reverted = map[string][]byte{}
	}
	f.reverted[name] = data
	return nil
}
func (f *fakeCTRuntime) CloneContainer(_ context.Context, src, dst string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cloneErr != nil {
		return f.cloneErr
	}
	f.cloneCalls = append(f.cloneCalls, struct{ Src, Dst string }{src, dst})
	return nil
}
func (f *fakeCTRuntime) ListContainers(_ context.Context) ([]string, error) { return nil, nil }
func (f *fakeCTRuntime) PullOCIImage(_ context.Context, image, dest, tag, username, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pullCalls = append(f.pullCalls, struct{ Image, Dest, Tag, Username, Password string }{image, dest, tag, username, password})
	return nil
}

// TestCreateContainer_LocalHost_PersistsRow verifies the happy path:
// runtime.Create is invoked, and a containers row exists for the new
// name on this host.
func TestCreateContainer_LocalHost_PersistsRow(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)

	ct, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{
		Name: "alpine-1", Template: "download", Distro: "alpine", Release: "3.19", Arch: "amd64",
		Cpu: 2, MemoryMib: 256,
	})
	if err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if ct.HostName != "host-a" || ct.Name != "alpine-1" {
		t.Errorf("response = %+v", ct)
	}
	if len(rt.createCalls) != 1 {
		t.Errorf("runtime.Create called %d times, want 1", len(rt.createCalls))
	}
	row, err := corrosion.GetContainer(context.Background(), s.db, "host-a", "alpine-1")
	if err != nil || row == nil {
		t.Fatalf("expected containers row, got %v / %v", row, err)
	}
}

// TestCreateContainer_PersistsOnHostFailure guards the v1.0.18 gap: the B5
// on_host_failure relocation policy must be settable at create time and persist
// to the cluster row (else no container can ever be relocated on host loss).
func TestCreateContainer_PersistsOnHostFailure(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.SetContainerRuntime(&fakeCTRuntime{})
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{
		Name: "ct1", Template: "download", Distro: "alpine", OnHostFailure: "image-recreate",
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	row, err := corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1")
	if err != nil || row == nil {
		t.Fatalf("GetContainer: %v / nil=%v", err, row == nil)
	}
	if row.OnHostFailure != "image-recreate" {
		t.Errorf("on_host_failure = %q, want image-recreate", row.OnHostFailure)
	}
}

// TestCreateContainer_NoRuntime_Unavailable handles the "lxc-* not on
// this host" case with a clear error.
func TestCreateContainer_NoRuntime_Unavailable(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	// no runtime set
	_, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "x"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", err)
	}
}

// TestCreateContainer_RuntimeError_Internal surfaces a runtime failure
// as Internal so operators see the lxc-create stderr.
func TestCreateContainer_RuntimeError_Internal(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.SetContainerRuntime(&fakeCTRuntime{createErr: errors.New("disk full")})

	_, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "x"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
}

// TestStartStopDeleteContainer_LocalHost_StateTransitions verifies
// each lifecycle RPC drives both the runtime and the cluster row.
func TestStartStopDeleteContainer_LocalHost_StateTransitions(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "ct1", Template: "download", Distro: "alpine"}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "ct1"}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1")
	if row.State != "running" {
		t.Errorf("after Start state = %q, want running", row.State)
	}

	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "ct1", TimeoutSec: 5}); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	row, _ = corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1")
	if row.State != "stopped" {
		t.Errorf("after Stop state = %q, want stopped", row.State)
	}
	if rt.stopCalls[0].Timeout != 5 {
		t.Errorf("Stop timeout = %d, want 5", rt.stopCalls[0].Timeout)
	}

	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "ct1"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	row, _ = corrosion.GetContainer(context.Background(), s.db, "host-a", "ct1")
	if row != nil {
		t.Errorf("expected soft-deleted row to disappear from GetContainer, got %+v", row)
	}
}

// TestExecContainer_PassesThroughResult — the unstructured stdout/
// exit_code passes back to the caller verbatim.
func TestExecContainer_PassesThroughResult(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.SetContainerRuntime(&fakeCTRuntime{})

	res, err := s.ExecContainer(adminCtx(), &pb.ExecContainerRequest{
		Name: "ct1", Argv: []string{"echo", "hi"},
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(res.Stdout) != "ok" {
		t.Errorf("stdout = %q", res.Stdout)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit = %d", res.ExitCode)
	}
}

// TestListContainers_AggregatesAcrossHosts verifies the cluster-wide
// query returns rows owned by other hosts even though this server
// only has the local runtime.
func TestListContainers_AggregatesAcrossHosts(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()
	_ = corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "running",
	})
	_ = corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "ct2", State: "stopped",
	})
	resp, err := s.ListContainers(adminCtx(), &pb.ListContainersRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resp.Containers) != 2 {
		t.Errorf("got %d containers cluster-wide, want 2: %+v", len(resp.Containers), resp.Containers)
	}
	// And filter-by-host returns only the host's rows.
	resp, _ = s.ListContainers(adminCtx(), &pb.ListContainersRequest{HostName: "host-b"})
	if len(resp.Containers) != 1 || resp.Containers[0].HostName != "host-b" {
		t.Errorf("filtered by host-b, got %+v", resp.Containers)
	}
}

// TestPullOCIImage_ForwardsToRuntime calls through and asserts the
// runtime sees the image arguments.
func TestPullOCIImage_ForwardsToRuntime(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{
		Image: "alpine:3.19", Dest: "/tmp/r",
	}); err != nil {
		t.Fatalf("Pull: %v", err)
	}
	if len(rt.pullCalls) != 1 {
		t.Fatalf("pull calls = %d, want 1", len(rt.pullCalls))
	}
	if rt.pullCalls[0].Image != "alpine:3.19" || rt.pullCalls[0].Dest != "/tmp/r" {
		t.Errorf("pull args wrong: %+v", rt.pullCalls[0])
	}
}
