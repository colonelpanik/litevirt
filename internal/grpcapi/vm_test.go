package grpcapi

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// testServerWithLocks returns a Server that has vmLocks and a dataDir, needed
// for operations that call lockVM (StopVM, DeleteVM, etc.).
func testServerWithLocks(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{
		hostName: "test-host",
		dataDir:  t.TempDir(),
		db:       db,
		events:   events.NewBus(),
		vmLocks:  make(map[string]*sync.Mutex),
	}
}

func insertTestVM(t *testing.T, ctx context.Context, db *corrosion.Client, name, host, state string) {
	t.Helper()
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      name,
		HostName:  host,
		State:     state,
		CPUActual: 2,
		MemActual: 4096,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

func TestCreateVM_NilSpec(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{})
	if err == nil {
		t.Fatal("expected error for nil spec")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestCreateVM_EmptyName(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{}})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

// TestCreateVM_HooksRequireAdmin is the F3 regression: an operator (the floor
// for ordinary VM creation) may NOT define a lifecycle hook, since hooks run as
// root on the target host. An admin may.
func TestCreateVM_HooksRequireAdmin(t *testing.T) {
	s := testServer(t)
	opCtx := context.WithValue(context.Background(), ctxKeyUsername, "op")
	opCtx = context.WithValue(opCtx, ctxKeyRole, "operator")

	specWithHook := &pb.VMSpec{
		Name: "hooked-vm", Cpu: 1, MemoryMib: 512,
		Hooks: &pb.HooksSpec{PreStart: "/bin/touch /tmp/pwned"},
	}
	_, err := s.CreateVM(opCtx, &pb.CreateVMRequest{Spec: specWithHook})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator defining a hook: expected PermissionDenied, got %v", err)
	}

	// An operator WITHOUT hooks gets past the hook gate (fails later for other
	// reasons in this minimal harness, but NOT with PermissionDenied).
	_, err = s.CreateVM(opCtx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "plain-vm", Cpu: 1, MemoryMib: 512}})
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("operator creating a hookless VM should not be permission-denied, got %v", err)
	}
}

func TestHooksDefined(t *testing.T) {
	if hooksDefined(nil) {
		t.Error("nil HooksSpec should be undefined")
	}
	if hooksDefined(&pb.HooksSpec{}) {
		t.Error("empty HooksSpec should be undefined")
	}
	if !hooksDefined(&pb.HooksSpec{PostMigrate: "x"}) {
		t.Error("a set hook should be defined")
	}
}

func TestCreateVM_AlreadyExists(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "dup-vm", "test-host", "running")

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{Name: "dup-vm", Cpu: 1, MemoryMib: 512},
	})
	if err == nil {
		t.Fatal("expected error for duplicate VM")
	}
	if c := status.Code(err); c != codes.AlreadyExists {
		t.Errorf("code = %v, want AlreadyExists", c)
	}
}

func TestCreateVM_QuotaThenPlacementLabelsAndAntiAffinity(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()

	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "/acme", Display: "Acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", VCPULimit: 4, MemMiBLimit: 4096,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	for _, h := range []corrosion.HostRecord{
		{Name: "test-host", Address: "10.0.0.1", State: "active", CPUTotal: 8, MemTotal: 16384},
		{Name: "anti-host", Address: "10.0.0.2", State: "active", CPUTotal: 8, MemTotal: 16384},
		{Name: "wrong-label", Address: "10.0.0.3", State: "active", CPUTotal: 8, MemTotal: 16384},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	for host, tier := range map[string]string{"test-host": "gold", "anti-host": "gold", "wrong-label": "silver"} {
		if err := corrosion.SetHostLabel(ctx, s.db, host, "tier", tier); err != nil {
			t.Fatalf("SetHostLabel %s: %v", host, err)
		}
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "db", HostName: "anti-host", State: "running", CPUActual: 1, MemActual: 1024,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM db: %v", err)
	}

	resp, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name:      "api",
		Project:   "/acme",
		Cpu:       2,
		MemoryMib: 1024,
		Placement: &pb.PlacementSpec{
			Require:      map[string]string{"tier": "gold"},
			AntiAffinity: []string{"db"},
		},
	}})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if resp.HostName != "test-host" {
		t.Errorf("CreateVM host = %q, want test-host", resp.HostName)
	}
	rec, err := corrosion.GetVM(ctx, s.db, "api")
	if err != nil || rec == nil {
		t.Fatalf("GetVM api: %v %v", err, rec)
	}
	if rec.Project != "/acme" || rec.HostName != "test-host" {
		t.Errorf("persisted api = %+v, want project /acme on test-host", rec)
	}

	_, err = s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name:      "api-over-quota",
		Project:   "/acme",
		Cpu:       3,
		MemoryMib: 1024,
		Placement: &pb.PlacementSpec{
			Require:      map[string]string{"tier": "gold"},
			AntiAffinity: []string{"db"},
		},
	}})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over-quota CreateVM: got %v, want ResourceExhausted", err)
	}
	if rec, _ := corrosion.GetVM(ctx, s.db, "api-over-quota"); rec != nil {
		t.Errorf("over-quota VM should not be persisted: %+v", rec)
	}
}

func TestListVMs_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(resp.Vms) != 0 {
		t.Errorf("expected 0 VMs, got %d", len(resp.Vms))
	}
}

func TestListVMs_FilterByHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "vm-a", "host-1", "running")
	insertTestVM(t, ctx, s.db, "vm-b", "host-2", "stopped")

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{HostName: "host-1"})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(resp.Vms) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(resp.Vms))
	}
	if resp.Vms[0].Name != "vm-a" {
		t.Errorf("Name = %q, want vm-a", resp.Vms[0].Name)
	}
}

func TestListVMs_FilterByStack(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "stack-vm",
		StackName: "mystack",
		HostName:  "h1",
		State:     "running",
	}, nil, nil)
	insertTestVM(t, ctx, s.db, "other-vm", "h1", "running")

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{StackName: "mystack"})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(resp.Vms) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(resp.Vms))
	}
	if resp.Vms[0].Name != "stack-vm" {
		t.Errorf("Name = %q, want stack-vm", resp.Vms[0].Name)
	}
}

func TestInspectVM_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestInspectVM_Found(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "inspect-me", "other-host", "running")

	vm, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "inspect-me"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if vm.Name != "inspect-me" {
		t.Errorf("Name = %q, want inspect-me", vm.Name)
	}
	if vm.State != pb.VMState_VM_RUNNING {
		t.Errorf("State = %v, want RUNNING", vm.State)
	}
}

func TestStartVM_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestStartVM_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "stopped")

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "remote-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestStopVM_NotFound(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestStopVM_WrongHost(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "remote-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestDeleteVM_NotFound(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestDeleteVM_WrongHost(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "stopped")

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "remote-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestDeleteVM_BackingUp(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "busy-vm", "test-host", "backing-up")

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "busy-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestRestartVM_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.RestartVM(ctx, &pb.RestartVMRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestRestartVM_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.RestartVM(ctx, &pb.RestartVMRequest{Name: "remote-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestExecVM_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "nope", Command: []string{"ls"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestExecVM_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "remote-vm", Command: []string{"ls"}})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestExecVM_NotRunning(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "stopped-vm", "test-host", "stopped")

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "stopped-vm", Command: []string{"ls"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestExecVM_NoCommand(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "exec-vm", "test-host", "running")

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "exec-vm", Command: nil})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestSetVMIP_Validation(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Empty name.
	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty name: code = %v, want InvalidArgument", c)
	}

	// Empty IP.
	_, err = s.SetVMIP(ctx, &pb.SetVMIPRequest{Name: "vm1"})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty ip: code = %v, want InvalidArgument", c)
	}

	// VM not found.
	_, err = s.SetVMIP(ctx, &pb.SetVMIPRequest{Name: "nope", Ip: "10.0.0.1"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("not found: code = %v, want NotFound", c)
	}
}

func TestSetBootOrder_Validation(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.SetBootOrder(ctx, &pb.SetBootOrderRequest{})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty name: code = %v, want InvalidArgument", c)
	}

	_, err = s.SetBootOrder(ctx, &pb.SetBootOrderRequest{Name: "vm1"})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty boot_order: code = %v, want InvalidArgument", c)
	}

	_, err = s.SetBootOrder(ctx, &pb.SetBootOrderRequest{Name: "nope", BootOrder: "disk"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("not found: code = %v, want NotFound", c)
	}
}

func TestRebuildVM_Validation(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty name: code = %v, want InvalidArgument", c)
	}

	_, err = s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "nope"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("not found: code = %v, want NotFound", c)
	}
}

func TestCutoverVM_Validation(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty name: code = %v, want InvalidArgument", c)
	}

	_, err = s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "vm1"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("not found -next: code = %v, want NotFound", c)
	}
}

func TestVmHooks_EmptySpec(t *testing.T) {
	vm := &corrosion.VMRecord{Name: "test-vm", Spec: ""}
	if hooks := vmHooks(vm); hooks != nil {
		t.Errorf("expected nil hooks for empty spec, got %v", hooks)
	}
}

func TestVmHooks_InvalidJSON(t *testing.T) {
	vm := &corrosion.VMRecord{Name: "test-vm", Spec: "not json"}
	if hooks := vmHooks(vm); hooks != nil {
		t.Errorf("expected nil hooks for invalid JSON, got %v", hooks)
	}
}

func TestReplaceDomainName(t *testing.T) {
	xml := `<domain><name>old-vm</name><uuid>123</uuid></domain>`
	got := replaceDomainName(xml, "old-vm", "new-vm")
	want := `<domain><name>new-vm</name><uuid>123</uuid></domain>`
	if got != want {
		t.Errorf("replaceDomainName:\n  got  %s\n  want %s", got, want)
	}
}

func TestReplaceDomainName_NotFound(t *testing.T) {
	xml := `<domain><name>different</name></domain>`
	got := replaceDomainName(xml, "old-vm", "new-vm")
	if got != xml {
		t.Errorf("expected unchanged XML when name not found, got %s", got)
	}
}

func TestReplaceFirst(t *testing.T) {
	tests := []struct {
		s, old, new, want string
	}{
		{"hello world hello", "hello", "hi", "hi world hello"},
		{"no match here", "xyz", "abc", "no match here"},
		{"", "a", "b", ""},
	}
	for _, tt := range tests {
		got := replaceFirst(tt.s, tt.old, tt.new)
		if got != tt.want {
			t.Errorf("replaceFirst(%q, %q, %q) = %q, want %q", tt.s, tt.old, tt.new, got, tt.want)
		}
	}
}

func TestParseDiskSizeBytes(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"20G", 20 * 1024 * 1024 * 1024},
		{"20g", 20 * 1024 * 1024 * 1024},
		{"512M", 512 * 1024 * 1024},
		{"1T", 1024 * 1024 * 1024 * 1024},
		{"", 0},
		{"100", 100},
	}
	for _, tt := range tests {
		got := parseDiskSizeBytes(tt.input)
		if got != tt.want {
			t.Errorf("parseDiskSizeBytes(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestVmBaseName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"web-3", "web"},
		{"web-10", "web"},
		{"db", "db"},
		{"worker-1", "worker"},
		{"my-service-2", "my-service"},
		// No trailing digits → name unchanged.
		{"web-", "web-"},
		// All digits → name unchanged (no dash prefix).
		{"123", "123"},
	}
	for _, tt := range tests {
		got := vmBaseName(tt.input)
		if got != tt.want {
			t.Errorf("vmBaseName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestResolveStopTimeout_ReqTimeout(t *testing.T) {
	// Request timeout takes highest priority.
	got := resolveStopTimeout(60, `{"stop_timeout_sec":10}`)
	if got != 60 {
		t.Errorf("got %d, want 60 (req timeout wins)", got)
	}
}

func TestResolveStopTimeout_SpecTimeout(t *testing.T) {
	// No request timeout → fall back to spec JSON field.
	got := resolveStopTimeout(0, `{"stop_timeout_sec":90}`)
	if got != 90 {
		t.Errorf("got %d, want 90 (spec timeout)", got)
	}
}

func TestResolveStopTimeout_Default(t *testing.T) {
	// Neither request nor spec → default 30s.
	got := resolveStopTimeout(0, "")
	if got != 30 {
		t.Errorf("got %d, want 30 (default)", got)
	}
}

func TestResolveStopTimeout_Default_EmptySpec(t *testing.T) {
	// Spec JSON present but stop_timeout_sec is 0 → still use default.
	got := resolveStopTimeout(0, `{"stop_timeout_sec":0}`)
	if got != 30 {
		t.Errorf("got %d, want 30 (default when spec value is 0)", got)
	}
}

func TestResolveStopTimeout_Default_InvalidJSON(t *testing.T) {
	// Unparseable spec JSON → fall back to default.
	got := resolveStopTimeout(0, "not json")
	if got != 30 {
		t.Errorf("got %d, want 30 (default on invalid JSON)", got)
	}
}

func TestResolveStopTimeout_ReqOverridesSpec(t *testing.T) {
	// Explicit request timeout beats a spec value.
	got := resolveStopTimeout(15, `{"stop_timeout_sec":120}`)
	if got != 15 {
		t.Errorf("got %d, want 15 (req timeout beats spec)", got)
	}
}

func TestLockVM_Concurrent(t *testing.T) {
	s := testServerWithLocks(t)

	// Verify lockVM returns a working unlock function.
	unlock := s.lockVM("test-vm")
	unlock()

	// Verify the same VM can be locked again after unlock.
	unlock2 := s.lockVM("test-vm")
	unlock2()
}
