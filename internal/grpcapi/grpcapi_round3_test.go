package grpcapi

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
)

// ── NewServer constructor ───────────────────────────────────────────────────

func TestR3_NewServer(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	corrosion.InitSchema(ctx, db)

	s := NewServer("node-1", "/tmp/data", "/etc/litevirt/pki", db, nil, nil)
	if s.hostName != "node-1" {
		t.Errorf("hostName = %q, want node-1", s.hostName)
	}
	if s.dataDir != "/tmp/data" {
		t.Errorf("dataDir = %q, want /tmp/data", s.dataDir)
	}
	if s.vmLocks == nil {
		t.Error("vmLocks should be initialized")
	}
	if s.events == nil {
		t.Error("events bus should be initialized")
	}
}

// ── SetWebhookURL / SetMigrationMetrics ─────────────────────────────────────

func TestR3_SetWebhookURL(t *testing.T) {
	s := testServerR2(t)
	s.SetWebhookURL("https://hooks.example.com/events")
	if s.webhookURL != "https://hooks.example.com/events" {
		t.Errorf("webhookURL = %q", s.webhookURL)
	}
}

func TestR3_SetMigrationMetrics(t *testing.T) {
	s := testServerR2(t)
	m := newTestMigrationMetrics()
	s.SetMigrationMetrics(m)
	if s.migrationMetrics == nil {
		t.Error("migrationMetrics should be set")
	}
}

// newTestMigrationMetrics creates MigrationMetrics without registering to global registry.
func newTestMigrationMetrics() *metrics.MigrationMetrics {
	return &metrics.MigrationMetrics{
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "test_mig_duration",
			Help: "test",
		}, []string{"strategy", "result"}),
		Downtime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "test_mig_downtime",
			Help: "test",
		}, []string{"strategy"}),
		Transfer: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "test_mig_transfer",
			Help: "test",
		}, []string{"strategy"}),
	}
}

// ── lockVM: concurrent access ───────────────────────────────────────────────

func TestR3_LockVM_SameVM(t *testing.T) {
	s := testServerR2(t)

	unlock := s.lockVM("vm-1")
	// Verify a second lock on a different VM doesn't block.
	done := make(chan bool, 1)
	go func() {
		u2 := s.lockVM("vm-2")
		done <- true
		u2()
	}()

	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("lockVM on different VM should not block")
	}
	unlock()
}

func TestR3_LockVM_ReuseMutex(t *testing.T) {
	s := testServerR2(t)
	u1 := s.lockVM("vm-x")
	u1()
	// Lock again — should reuse the same mutex entry.
	u2 := s.lockVM("vm-x")
	u2()
}

// ── ListVMs: with interfaces populated ──────────────────────────────────────

func TestR3_ListVMs_WithInterfaces(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "iface-vm",
		HostName:  "test-host",
		State:     "running",
		CPUActual: 2,
		MemActual: 4096,
	}, []corrosion.InterfaceRecord{
		{VMName: "iface-vm", NetworkName: "prod", Ordinal: 0, MAC: "52:54:00:aa:bb:cc", IP: "10.0.0.5"},
	}, nil)

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(resp.Vms) != 1 {
		t.Fatalf("got %d VMs, want 1", len(resp.Vms))
	}
	vm := resp.Vms[0]
	if len(vm.Interfaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(vm.Interfaces))
	}
	iface := vm.Interfaces[0]
	if iface.NetworkName != "prod" {
		t.Errorf("NetworkName = %q, want prod", iface.NetworkName)
	}
	if iface.Mac != "52:54:00:aa:bb:cc" {
		t.Errorf("Mac = %q", iface.Mac)
	}
	if iface.Ip != "10.0.0.5" {
		t.Errorf("Ip = %q", iface.Ip)
	}
}

// ── ListVMs: filter by stack ────────────────────────────────────────────────

func TestR3_ListVMs_StackFilter(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2WithStack(t, ctx, s.db, "app-web-1", "test-host", "running", "app")
	insertTestVMR2WithStack(t, ctx, s.db, "app-web-2", "test-host", "running", "app")
	insertTestVMR2(t, ctx, s.db, "other-vm", "test-host", "running")

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{StackName: "app"})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(resp.Vms) != 2 {
		t.Errorf("got %d VMs, want 2", len(resp.Vms))
	}
}

// ── vmToProto: remote host (no live state lookup) ───────────────────────────

func TestR3_InspectVM_RemoteHost_NoLiveState(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "remote-vm", "other-host", "running")

	vm, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "remote-vm"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if vm.State != pb.VMState_VM_RUNNING {
		t.Errorf("State = %v, want VM_RUNNING", vm.State)
	}
	if vm.HostName != "other-host" {
		t.Errorf("HostName = %q, want other-host", vm.HostName)
	}
}

// ── vmToProto: with spec JSON and disks ─────────────────────────────────────

func TestR3_InspectVM_WithSpecAndDisks(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{Name: "spec-vm", Cpu: 4, MemoryMib: 8192, Image: "ubuntu-22.04"}
	specJSON, _ := json.Marshal(spec)

	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "spec-vm",
		HostName:  "other-host",
		State:     "stopped",
		CPUActual: 4,
		MemActual: 8192,
		Spec:      string(specJSON),
	}, nil, []corrosion.DiskRecord{
		{VMName: "spec-vm", DiskName: "root", HostName: "other-host", Path: "/data/disks/spec-vm/root.qcow2", BackingImage: "ubuntu-22.04", StorageType: "local"},
	})

	vm, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "spec-vm"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if vm.Spec == nil {
		t.Fatal("expected Spec to be populated")
	}
	if vm.Spec.Image != "ubuntu-22.04" {
		t.Errorf("Spec.Image = %q, want ubuntu-22.04", vm.Spec.Image)
	}
	if len(vm.Disks) != 1 {
		t.Fatalf("got %d disks, want 1", len(vm.Disks))
	}
	if vm.Disks[0].BackingImage != "ubuntu-22.04" {
		t.Errorf("Disk BackingImage = %q", vm.Disks[0].BackingImage)
	}
}

// ── vmToProto: local host with nil virt (no live state) ─────────────────────

func TestR3_InspectVM_LocalHost_NilVirt(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "local-vm", "test-host", "running")

	vm, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "local-vm"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	// With nil virt client, should fall back to DB state.
	if vm.State != pb.VMState_VM_RUNNING {
		t.Errorf("State = %v, want VM_RUNNING", vm.State)
	}
}

// ── ExecVM: empty command ───────────────────────────────────────────────────

func TestR3_ExecVM_EmptyCommand(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "exec-vm", "test-host", "running")

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "exec-vm", Command: []string{}})
	if err == nil {
		t.Fatal("expected error for empty command")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

// ── StartVM: not found ──────────────────────────────────────────────────────

func TestR3_StartVM_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "ghost-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── StartVM: wrong host ─────────────────────────────────────────────────────

func TestR3_StartVM_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "remote-start-vm", "other-host", "stopped")

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "remote-start-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── RestartVM: not found and wrong host ─────────────────────────────────────

func TestR3_RestartVM_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.RestartVM(ctx, &pb.RestartVMRequest{Name: "nonexistent"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_RestartVM_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "remote-restart-vm", "other-host", "running")

	_, err := s.RestartVM(ctx, &pb.RestartVMRequest{Name: "remote-restart-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── StopVM: not found ───────────────────────────────────────────────────────

func TestR3_StopVM_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "ghost-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── DeleteVM: wrong host ────────────────────────────────────────────────────

func TestR3_DeleteVM_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "remote-del-vm", "other-host", "running")

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "remote-del-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── CreateVM: nil spec and empty name ───────────────────────────────────────

func TestR3_CreateVM_NilSpecR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_CreateVM_EmptyNameR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{}})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

// ── SetVMIP: missing name, missing IP ───────────────────────────────────────

func TestR3_SetVMIP_MissingName(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{Ip: "10.0.0.1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_SetVMIP_MissingIP(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{Name: "some-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_SetVMIP_VMNotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{Name: "ghost", Ip: "10.0.0.1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── SetBootOrder: missing fields ────────────────────────────────────────────

func TestR3_SetBootOrder_MissingNameR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.SetBootOrder(ctx, &pb.SetBootOrderRequest{BootOrder: "disk"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_SetBootOrder_MissingBootOrderR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.SetBootOrder(ctx, &pb.SetBootOrderRequest{Name: "vm-1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_SetBootOrder_VMNotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.SetBootOrder(ctx, &pb.SetBootOrderRequest{Name: "ghost", BootOrder: "network"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_SetBootOrder_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "remote-boot-vm", "other-host", "running")

	_, err := s.SetBootOrder(ctx, &pb.SetBootOrderRequest{Name: "remote-boot-vm", BootOrder: "network"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── RebuildVM: validation paths ─────────────────────────────────────────────

func TestR3_RebuildVM_MissingNameR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_RebuildVM_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_RebuildVM_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "rebuild-remote", "other-host", "running")

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "rebuild-remote"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestR3_RebuildVM_InvalidSpecJSON(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2WithSpec(t, ctx, s.db, "rebuild-badspec", "test-host", "running", "not-json{{{")

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "rebuild-badspec"})
	if err == nil {
		t.Fatal("expected error for invalid spec JSON")
	}
	if c := status.Code(err); c != codes.Internal {
		t.Errorf("code = %v, want Internal", c)
	}
}

// ── CutoverVM: validation paths ─────────────────────────────────────────────

func TestR3_CutoverVM_MissingNameR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_CutoverVM_NextNotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "old-vm", "test-host", "running")

	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "old-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_CutoverVM_NextInBadState(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "cut-vm", "test-host", "running")
	insertTestVMR2(t, ctx, s.db, "cut-vm-next", "test-host", "creating")

	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "cut-vm"})
	if err == nil {
		t.Fatal("expected error for bad next-VM state")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

// ── GetClusterStatus: with hosts and VMs ────────────────────────────────────

func TestR3_GetClusterStatus_Mixed(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "host-a", "active")
	insertTestHostR2(t, ctx, s.db, "host-b", "draining")

	insertTestVMR2(t, ctx, s.db, "vm-run-1", "host-a", "running")
	insertTestVMR2(t, ctx, s.db, "vm-run-2", "host-a", "running")
	insertTestVMR2(t, ctx, s.db, "vm-err-1", "host-b", "error")
	insertTestVMR2(t, ctx, s.db, "vm-stop-1", "host-b", "stopped")

	cs, err := s.GetClusterStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	if cs.HostsTotal != 2 {
		t.Errorf("HostsTotal = %d, want 2", cs.HostsTotal)
	}
	if cs.HostsActive != 1 {
		t.Errorf("HostsActive = %d, want 1", cs.HostsActive)
	}
	if cs.VmsTotal != 4 {
		t.Errorf("VmsTotal = %d, want 4", cs.VmsTotal)
	}
	if cs.VmsRunning != 2 {
		t.Errorf("VmsRunning = %d, want 2", cs.VmsRunning)
	}
	if cs.VmsError != 1 {
		t.Errorf("VmsError = %d, want 1", cs.VmsError)
	}
	if len(cs.Hosts) != 2 {
		t.Errorf("got %d hosts in response, want 2", len(cs.Hosts))
	}
}

func TestR3_GetClusterStatus_WithClusterName(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Insert a cluster record with all required fields.
	if err := s.db.Execute(ctx, `INSERT INTO cluster (id, name, domain, ca_cert, created_at, updated_at) VALUES ('default', 'my-cluster', 'test.local', 'cert', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	cs, err := s.GetClusterStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	if cs.ClusterName != "my-cluster" {
		t.Errorf("ClusterName = %q, want my-cluster", cs.ClusterName)
	}
}

// ── GetHostHealth: with entries ──────────────────────────────────────────────

func TestR3_GetHostHealth_WithEntries(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	if err := s.db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('host-a', 'host-b', 'healthy', 0, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert health 1: %v", err)
	}
	if err := s.db.Execute(ctx,
		`INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('host-b', 'host-a', 'suspect', 3, '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert health 2: %v", err)
	}

	resp, err := s.GetHostHealth(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetHostHealth: %v", err)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(resp.Entries))
	}
	found := false
	for _, e := range resp.Entries {
		if e.Observer == "host-b" && e.Target == "host-a" {
			found = true
			if e.Status != "suspect" {
				t.Errorf("Status = %q, want suspect", e.Status)
			}
			if e.ConsecutiveFailures != 3 {
				t.Errorf("ConsecutiveFailures = %d, want 3", e.ConsecutiveFailures)
			}
		}
	}
	if !found {
		t.Error("expected host-b -> host-a entry")
	}
}

// ── Ping ────────────────────────────────────────────────────────────────────

func TestR3_Ping(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	resp, err := s.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if resp.HostName != "test-host" {
		t.Errorf("HostName = %q, want test-host", resp.HostName)
	}
}

// ── ListHosts: with VMs ─────────────────────────────────────────────────────

func TestR3_ListHosts_WithVMs(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "node-1", "active")
	insertTestVMR2(t, ctx, s.db, "n1-vm-1", "node-1", "running")
	insertTestVMR2(t, ctx, s.db, "n1-vm-2", "node-1", "stopped")

	resp, err := s.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(resp.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(resp.Hosts))
	}
	h := resp.Hosts[0]
	if h.VmCount != 2 {
		t.Errorf("VmCount = %d, want 2", h.VmCount)
	}
	if h.CpuTotal != 8 {
		t.Errorf("CpuTotal = %d, want 8", h.CpuTotal)
	}
}

// ── InspectHost: not found ──────────────────────────────────────────────────

func TestR3_InspectHost_NotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── InspectHost: found, remote host (no live stats) ─────────────────────────

func TestR3_InspectHost_RemoteHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "remote-node", "active")
	insertTestVMR2(t, ctx, s.db, "rn-vm-1", "remote-node", "running")

	h, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "remote-node"})
	if err != nil {
		t.Fatalf("InspectHost: %v", err)
	}
	if h.Name != "remote-node" {
		t.Errorf("Name = %q", h.Name)
	}
	if h.VmCount != 1 {
		t.Errorf("VmCount = %d, want 1", h.VmCount)
	}
	// hostAllocatedResources queries DB — works for remote hosts too.
	if h.CpuUsed != 2 {
		t.Errorf("CpuUsed = %d, want 2", h.CpuUsed)
	}
	if h.MemUsedMib != 4096 {
		t.Errorf("MemUsedMib = %d, want 4096", h.MemUsedMib)
	}
}

// ── InspectHost: local host with nil virt ───────────────────────────────────

func TestR3_InspectHost_LocalHost_NilVirt(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "test-host", "active")
	insertTestVMR2(t, ctx, s.db, "local-h-vm", "test-host", "running")

	h, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "test-host"})
	if err != nil {
		t.Fatalf("InspectHost: %v", err)
	}
	// hostAllocatedResources queries DB directly — one running VM with CPUActual=2, MemActual=4096.
	if h.CpuUsed != 2 {
		t.Errorf("CpuUsed = %d, want 2", h.CpuUsed)
	}
	if h.MemUsedMib != 4096 {
		t.Errorf("MemUsedMib = %d, want 4096", h.MemUsedMib)
	}
}

// ── SetHostLabels: not found ────────────────────────────────────────────────

func TestR3_SetHostLabels_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
		Name:   "ghost",
		Labels: map[string]string{"env": "prod"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── SetHostLabels: add and remove ───────────────────────────────────────────

func TestR3_SetHostLabels_AddRemove(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "label-host", "active")

	// Add labels.
	_, err := s.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
		Name:   "label-host",
		Labels: map[string]string{"env": "prod", "zone": "us-east"},
	})
	if err != nil {
		t.Fatalf("SetHostLabels add: %v", err)
	}

	// Remove one label and add another.
	_, err = s.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
		Name:   "label-host",
		Labels: map[string]string{"tier": "gold"},
		Remove: []string{"zone"},
	})
	if err != nil {
		t.Fatalf("SetHostLabels remove: %v", err)
	}
}

// ── UndrainHost: not found ──────────────────────────────────────────────────

func TestR3_UndrainHost_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.UndrainHost(ctx, &pb.UndrainHostRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── UndrainHost: success ────────────────────────────────────────────────────

func TestR3_UndrainHost_SuccessR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "drain-host", "draining")

	h, err := s.UndrainHost(ctx, &pb.UndrainHostRequest{Name: "drain-host"})
	if err != nil {
		t.Fatalf("UndrainHost: %v", err)
	}
	if h.State != pb.HostState_HOST_ACTIVE {
		t.Errorf("State = %v, want HOST_ACTIVE", h.State)
	}
}

// ── RemoveHost: validation ──────────────────────────────────────────────────

func TestR3_RemoveHost_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.RemoveHost(ctx, &pb.RemoveHostRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_RemoveHost_HasVMs_NoForce(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "busy-host", "active")
	insertTestVMR2(t, ctx, s.db, "busy-vm", "busy-host", "running")

	_, err := s.RemoveHost(ctx, &pb.RemoveHostRequest{Name: "busy-host"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestR3_RemoveHost_HasVMs_Force(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "force-host", "active")
	insertTestVMR2(t, ctx, s.db, "force-vm", "force-host", "running")

	_, err := s.RemoveHost(ctx, &pb.RemoveHostRequest{Name: "force-host", Force: true})
	if err != nil {
		t.Fatalf("RemoveHost with force: %v", err)
	}
}

func TestR3_RemoveHost_NoVMs(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "empty-host", "active")

	_, err := s.RemoveHost(ctx, &pb.RemoveHostRequest{Name: "empty-host"})
	if err != nil {
		t.Fatalf("RemoveHost: %v", err)
	}
}

// ── FenceHost: validation ───────────────────────────────────────────────────

func TestR3_FenceHost_NotConfirmedR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.FenceHost(ctx, &pb.FenceHostRequest{Name: "some-host", Confirmed: false})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_FenceHost_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.FenceHost(ctx, &pb.FenceHostRequest{Name: "ghost", Confirmed: true})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── Snapshot: validation paths ──────────────────────────────────────────────

func TestR3_CreateSnapshot_VMNotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "ghost", Name: "snap1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_CreateSnapshot_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "snap-remote-vm", "other-host", "running")

	_, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "snap-remote-vm", Name: "snap1"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestR3_ListSnapshots_EmptyR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	resp, err := s.ListSnapshots(ctx, &pb.ListSnapshotsRequest{VmName: "nonexistent"})
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(resp.Snapshots) != 0 {
		t.Errorf("got %d snapshots, want 0", len(resp.Snapshots))
	}
}

func TestR3_ListSnapshots_WithRecords(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "snap-list-vm", "test-host", "running")
	corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		VMName:   "snap-list-vm",
		HostName: "test-host",
		Name:     "before-upgrade",
		State:    "ok",
	})
	corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		VMName:   "snap-list-vm",
		HostName: "test-host",
		Name:     "after-upgrade",
		State:    "ok",
	})

	resp, err := s.ListSnapshots(ctx, &pb.ListSnapshotsRequest{VmName: "snap-list-vm"})
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(resp.Snapshots) != 2 {
		t.Errorf("got %d snapshots, want 2", len(resp.Snapshots))
	}
}

func TestR3_RestoreSnapshot_VMNotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{VmName: "ghost", SnapshotName: "snap1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_RestoreSnapshot_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "restore-remote", "other-host", "running")

	_, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{VmName: "restore-remote", SnapshotName: "snap1"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestR3_RestoreSnapshot_TransientStates(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	for _, state := range []string{"migrating", "creating", "starting"} {
		insertTestVMR2(t, ctx, s.db, "restore-"+state, "test-host", state)

		_, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{
			VmName:       "restore-" + state,
			SnapshotName: "snap1",
		})
		if err == nil {
			t.Errorf("expected error for state %q", state)
			continue
		}
		if c := status.Code(err); c != codes.FailedPrecondition {
			t.Errorf("state %q: code = %v, want FailedPrecondition", state, c)
		}
	}
}

func TestR3_DeleteSnapshot_VMNotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "ghost", SnapshotName: "snap1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_DeleteSnapshot_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "del-snap-remote", "other-host", "running")

	_, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "del-snap-remote", SnapshotName: "snap1"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── ListLoadBalancers ───────────────────────────────────────────────────────

func TestR3_ListLoadBalancers_EmptyR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	resp, err := s.ListLoadBalancers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListLoadBalancers: %v", err)
	}
	if len(resp.Lbs) != 0 {
		t.Errorf("got %d LBs, want 0", len(resp.Lbs))
	}
}

func TestR3_ListLoadBalancers_WithRecords(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name:      "web-lb",
		VIP:       "10.0.0.100/24",
		Algorithm: "roundrobin",
		Enabled:   true,
	})

	resp, err := s.ListLoadBalancers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListLoadBalancers: %v", err)
	}
	if len(resp.Lbs) != 1 {
		t.Fatalf("got %d LBs, want 1", len(resp.Lbs))
	}
	if resp.Lbs[0].Name != "web-lb" {
		t.Errorf("Name = %q, want web-lb", resp.Lbs[0].Name)
	}
	if resp.Lbs[0].Algorithm != "roundrobin" {
		t.Errorf("Algorithm = %q", resp.Lbs[0].Algorithm)
	}
}

func TestR3_InspectLoadBalancer_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_InspectLoadBalancer_Found(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name:      "api-lb",
		VIP:       "10.0.0.200/24",
		Algorithm: "leastconn",
		Enabled:   true,
	})

	lb, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "api-lb"})
	if err != nil {
		t.Fatalf("InspectLoadBalancer: %v", err)
	}
	if lb.Name != "api-lb" {
		t.Errorf("Name = %q", lb.Name)
	}
	if lb.Vip != "10.0.0.200/24" {
		t.Errorf("Vip = %q", lb.Vip)
	}
}

// ── ListHostDevices ─────────────────────────────────────────────────────────

func TestR3_ListHostDevices_EmptyR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	resp, err := s.ListHostDevices(ctx, &pb.ListHostDevicesRequest{})
	if err != nil {
		t.Fatalf("ListHostDevices: %v", err)
	}
	if len(resp.Devices) != 0 {
		t.Errorf("got %d devices, want 0", len(resp.Devices))
	}
}

func TestR3_ListHostDevices_WithTypeFilter(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host",
		Address:  "0000:03:00.0",
		Type:     "gpu",
		VendorID: "10de",
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host",
		Address:  "0000:04:00.0",
		Type:     "nic",
		VendorID: "8086",
	})

	resp, err := s.ListHostDevices(ctx, &pb.ListHostDevicesRequest{TypeFilter: "gpu"})
	if err != nil {
		t.Fatalf("ListHostDevices: %v", err)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("got %d devices, want 1", len(resp.Devices))
	}
	if resp.Devices[0].Type != "gpu" {
		t.Errorf("Type = %q, want gpu", resp.Devices[0].Type)
	}
}

func TestR3_ListHostDevices_SpecificHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "other-host",
		Address:  "0000:05:00.0",
		Type:     "gpu",
	})

	resp, err := s.ListHostDevices(ctx, &pb.ListHostDevicesRequest{Name: "other-host"})
	if err != nil {
		t.Fatalf("ListHostDevices: %v", err)
	}
	if len(resp.Devices) != 1 {
		t.Errorf("got %d devices, want 1", len(resp.Devices))
	}
}

// ── MigrateVM: additional validation paths ──────────────────────────────────

// mockMigrateStreamR3 implements grpc.ServerStreamingServer[pb.MigrateProgress].
type mockMigrateStreamR3 struct {
	ctx  context.Context
	sent []*pb.MigrateProgress
}

func (m *mockMigrateStreamR3) Send(p *pb.MigrateProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockMigrateStreamR3) Context() context.Context       { return m.ctx }
func (m *mockMigrateStreamR3) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockMigrateStreamR3) SendHeader(_ metadata.MD) error { return nil }
func (m *mockMigrateStreamR3) SetTrailer(_ metadata.MD)       {}
func (m *mockMigrateStreamR3) SendMsg(_ any) error            { return nil }
func (m *mockMigrateStreamR3) RecvMsg(_ any) error            { return nil }

func TestR3_MigrateVM_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	stream := &mockMigrateStreamR3{ctx: adminCtx()}

	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "ghost", TargetHost: "h2"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_MigrateVM_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	stream := &mockMigrateStreamR3{ctx: ctx}

	insertTestVMR2(t, ctx, s.db, "mig-remote", "other-host", "running")

	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "mig-remote", TargetHost: "h2"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestR3_MigrateVM_VMNotRunning(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	stream := &mockMigrateStreamR3{ctx: ctx}

	insertTestVMR2(t, ctx, s.db, "mig-stopped", "test-host", "stopped")

	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "mig-stopped", TargetHost: "h2"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestR3_MigrateVM_TargetNotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	stream := &mockMigrateStreamR3{ctx: ctx}

	insertTestVMR2(t, ctx, s.db, "mig-local", "test-host", "running")

	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "mig-local", TargetHost: "nonexistent"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_MigrateVM_TargetNotActive(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	stream := &mockMigrateStreamR3{ctx: ctx}

	insertTestVMR2(t, ctx, s.db, "mig-local2", "test-host", "running")
	insertTestHostR2(t, ctx, s.db, "drain-target", "draining")

	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "mig-local2", TargetHost: "drain-target"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestR3_MigrateVM_LocalDisk_BlocksLive(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	stream := &mockMigrateStreamR3{ctx: ctx}

	insertTestVMR2(t, ctx, s.db, "mig-localdisk", "test-host", "running")
	insertTestHostR2(t, ctx, s.db, "active-target", "active")

	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName:      "mig-localdisk",
		DiskName:    "root",
		HostName:    "test-host",
		Path:        "/data/disks/root.qcow2",
		StorageType: "local",
	})

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "mig-localdisk",
		TargetHost: "active-target",
		Strategy:   pb.MigrateStrategy_MIGRATE_LIVE,
	}, stream)
	if err == nil {
		t.Fatal("expected error for local disk live migration")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestR3_MigrateVM_CPUPinning_NUMAWarning(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	stream := &mockMigrateStreamR3{ctx: ctx}

	// VM with CPU pinning in spec — triggers NUMA warning but still fails at target not found.
	spec := `{"resources":{"cpu_pinning":[0,1,2,3]}}`
	insertTestVMR2WithSpec(t, ctx, s.db, "mig-pinned", "test-host", "running", spec)

	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "mig-pinned", TargetHost: "nonexistent"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	// Should fail at target not found (after NUMA warning path is exercised).
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── BuildImage: validation paths ────────────────────────────────────────────

func TestR3_BuildImage_EmptyFieldsR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.BuildImage(ctx, &pb.BuildImageRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_BuildImage_VMNotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.BuildImage(ctx, &pb.BuildImageRequest{VmName: "ghost", ImageName: "my-image"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_BuildImage_WrongHostR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "build-remote", "other-host", "running")

	_, err := s.BuildImage(ctx, &pb.BuildImageRequest{VmName: "build-remote", ImageName: "img"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── DiffStack: validation paths ─────────────────────────────────────────────

func TestR3_DiffStack_EmptyYAML(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.DiffStack(ctx, &pb.DiffStackRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_DiffStack_InvalidYAML(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.DiffStack(ctx, &pb.DiffStackRequest{ComposeYaml: "{{invalid yaml"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestR3_DiffStack_WithExistingVMs(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "test-host", "active")

	// Pre-existing VMs in the stack.
	insertTestVMR2WithStack(t, ctx, s.db, "diffstack-web-1", "test-host", "running", "diffstack")

	yaml := `name: diffstack
vms:
  web:
    image: ubuntu-22.04
    cpu: 2
    memory: 4096
    replicas: 2
`
	resp, err := s.DiffStack(ctx, &pb.DiffStackRequest{ComposeYaml: yaml})
	if err != nil {
		t.Fatalf("DiffStack: %v", err)
	}
	if len(resp.Entries) == 0 {
		t.Fatal("expected non-empty diff entries")
	}
}

// ── ListStacks: with VM state counts ────────────────────────────────────────

func TestR3_ListStacks_WithCounts(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name:  "myapp",
		State: "active",
	})

	insertTestVMR2WithStack(t, ctx, s.db, "myapp-web-1", "h1", "running", "myapp")
	insertTestVMR2WithStack(t, ctx, s.db, "myapp-web-2", "h1", "stopped", "myapp")
	insertTestVMR2WithStack(t, ctx, s.db, "myapp-web-3", "h1", "error", "myapp")

	resp, err := s.ListStacks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListStacks: %v", err)
	}
	if len(resp.Stacks) != 1 {
		t.Fatalf("got %d stacks, want 1", len(resp.Stacks))
	}
	st := resp.Stacks[0]
	if st.VmCount != 3 {
		t.Errorf("VmCount = %d, want 3", st.VmCount)
	}
	if st.Running != 1 {
		t.Errorf("Running = %d, want 1", st.Running)
	}
	if st.Stopped != 1 {
		t.Errorf("Stopped = %d, want 1", st.Stopped)
	}
	if st.Error != 1 {
		t.Errorf("Error = %d, want 1", st.Error)
	}
}

// ── Users/Tokens: validation paths ──────────────────────────────────────────

func TestR3_CreateUser_Success(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	user, err := s.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "alice",
		Password: "secret123",
		Role:     "operator",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("Username = %q", user.Username)
	}
	if user.Role != "operator" {
		t.Errorf("Role = %q", user.Role)
	}
}

func TestR3_CreateUser_DefaultRole(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	user, err := s.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "bob",
		Password: "pass",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Role != "viewer" {
		t.Errorf("Role = %q, want viewer", user.Role)
	}
}

func TestR3_CreateUser_Duplicate(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	s.CreateUser(ctx, &pb.CreateUserRequest{Username: "dupe", Password: "pass"})
	_, err := s.CreateUser(ctx, &pb.CreateUserRequest{Username: "dupe", Password: "pass"})
	if err == nil {
		t.Fatal("expected error for duplicate")
	}
	if c := status.Code(err); c != codes.AlreadyExists {
		t.Errorf("code = %v, want AlreadyExists", c)
	}
}

func TestR3_ListUsers_R3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	s.CreateUser(ctx, &pb.CreateUserRequest{Username: "u1", Password: "p1"})
	s.CreateUser(ctx, &pb.CreateUserRequest{Username: "u2", Password: "p2", Role: "admin"})

	resp, err := s.ListUsers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(resp.Users) != 2 {
		t.Errorf("got %d users, want 2", len(resp.Users))
	}
}

func TestR3_DeleteUser_R3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	s.CreateUser(ctx, &pb.CreateUserRequest{Username: "del-user", Password: "p"})

	_, err := s.DeleteUser(ctx, &pb.DeleteUserRequest{Username: "del-user"})
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
}

func TestR3_CreateToken_Success(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	s.CreateUser(ctx, &pb.CreateUserRequest{Username: "tok-user", Password: "p"})

	tok, err := s.CreateToken(ctx, &pb.CreateTokenRequest{
		Username: "tok-user",
		Name:     "ci-token",
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tok.Token == "" {
		t.Error("expected non-empty token")
	}
	if tok.Name != "ci-token" {
		t.Errorf("Name = %q", tok.Name)
	}
}

func TestR3_CreateToken_UserNotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.CreateToken(ctx, &pb.CreateTokenRequest{
		Username: "nobody",
		Name:     "tok",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_RevokeToken_R3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.RevokeToken(ctx, &pb.RevokeTokenRequest{Id: "some-id"})
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
}

// ── AttachDevice / DetachDevice: validation ─────────────────────────────────

func TestR3_AttachDevice_EmptyNameR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_AttachDevice_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_AttachDevice_NotRunningR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "attach-stopped", "test-host", "stopped")

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "attach-stopped"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestR3_AttachDevice_NoDeviceSpecified(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "attach-no-dev", "test-host", "running")

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "attach-no-dev"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_DetachDevice_EmptyNameR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_DetachDevice_NotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_DetachDevice_NotRunningR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "detach-stopped", "test-host", "stopped")

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "detach-stopped"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestR3_DetachDevice_NoDeviceSpecified(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "detach-no-dev", "test-host", "running")

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "detach-no-dev"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

// ── recordMigrationMetrics: with metrics ────────────────────────────────────

func TestR3_RecordMigrationMetrics_WithMetrics(t *testing.T) {
	s := testServerR2(t)
	m := newTestMigrationMetrics()
	s.SetMigrationMetrics(m)

	// Should not panic.
	s.recordMigrationMetrics("live", "success", 5*time.Second, 100.0, 1048576.0)
	s.recordMigrationMetrics("cold", "failure", 10*time.Second, 0, 0)
	s.recordMigrationMetrics("live", "success", 3*time.Second, 50.0, 0)
}

func TestR3_RecordMigrationMetrics_NilMetrics(t *testing.T) {
	s := testServerR2(t)
	// Should not panic with nil migrationMetrics.
	s.recordMigrationMetrics("live", "success", 5*time.Second, 100.0, 1024.0)
}

// ── liveHostStats ───────────────────────────────────────────────────────────

func TestR3_LiveHostStats(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "stat-vm-1", "test-host", "running")
	insertTestVMR2(t, ctx, s.db, "stat-vm-2", "test-host", "running")
	insertTestVMR2(t, ctx, s.db, "stat-vm-3", "test-host", "stopped")

	cpu, mem, _ := s.hostAllocatedResources(ctx, s.hostName)
	// Two running VMs with 2 CPU and 4096 MiB each.
	if cpu != 4 {
		t.Errorf("cpuUsed = %d, want 4", cpu)
	}
	if mem != 8192 {
		t.Errorf("memUsed = %d, want 8192", mem)
	}
}

// ── resolveVolume ───────────────────────────────────────────────────────────

func TestR3_ResolveVolume_EmptyStackR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	cfg := s.resolveVolume(ctx, "", "vol1")
	if cfg.Driver != "local" {
		t.Errorf("Driver = %q, want local", cfg.Driver)
	}
}

func TestR3_ResolveVolume_StackNotFoundR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	cfg := s.resolveVolume(ctx, "nonexistent", "vol1")
	if cfg.Driver != "local" {
		t.Errorf("Driver = %q, want local", cfg.Driver)
	}
}

// ── publish / audit ─────────────────────────────────────────────────────────

func TestR3_Publish_NoPanic(t *testing.T) {
	s := testServerR2(t)
	// Should not panic even with no webhook or subscribers.
	s.publish("test.event", "target-1", "detail info")
}

func TestR3_Publish_WithWebhook(t *testing.T) {
	s := testServerR2(t)
	s.SetWebhookURL("https://example.com/hook")
	// Should not panic — webhook will fail to connect, but that's handled gracefully.
	s.publish("test.event", "target-1", "detail info")
}

func TestR3_Audit_NoPanic(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	// Should not panic.
	s.audit(ctx, "vm.create", "test-vm", "created by test", "ok")
}

func TestR3_Audit_WithUsername(t *testing.T) {
	s := testServerR2(t)
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	s.audit(ctx, "vm.delete", "my-vm", "deleted", "ok")
}

// ── DeleteVM: backing-up state rejection ────────────────────────────────────

func TestR3_DeleteVM_BackingUpState(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "backing-up-vm", "test-host", "backing-up")

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "backing-up-vm"})
	if err == nil {
		t.Fatal("expected error for backing-up VM")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

// ── vmStateToPB comprehensive ───────────────────────────────────────────────

func TestR3_VmStateToPB_AllStates(t *testing.T) {
	tests := []struct {
		input string
		want  pb.VMState
	}{
		{"creating", pb.VMState_VM_CREATING},
		{"starting", pb.VMState_VM_STARTING},
		{"running", pb.VMState_VM_RUNNING},
		{"stopping", pb.VMState_VM_STOPPING},
		{"stopped", pb.VMState_VM_STOPPED},
		{"migrating", pb.VMState_VM_MIGRATING},
		{"error", pb.VMState_VM_ERROR},
		{"unknown-state", pb.VMState_VM_UNKNOWN},
		{"", pb.VMState_VM_UNKNOWN},
	}
	for _, tt := range tests {
		got := vmStateToPB(tt.input)
		if got != tt.want {
			t.Errorf("vmStateToPB(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ── hostStateToPB comprehensive ─────────────────────────────────────────────

func TestR3_HostStateToPB_AllStates(t *testing.T) {
	tests := []struct {
		input string
		want  pb.HostState
	}{
		{"active", pb.HostState_HOST_ACTIVE},
		{"draining", pb.HostState_HOST_DRAINING},
		{"maintenance", pb.HostState_HOST_MAINTENANCE},
		{"suspect", pb.HostState_HOST_SUSPECT},
		{"offline", pb.HostState_HOST_OFFLINE},
		{"unknown", pb.HostState_HOST_ACTIVE}, // default
	}
	for _, tt := range tests {
		got := hostStateToPB(tt.input)
		if got != tt.want {
			t.Errorf("hostStateToPB(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ── parseTimestamp ───────────────────────────────────────────────────────────

func TestR3_ParseTimestamp(t *testing.T) {
	// Valid timestamp.
	ts := parseTimestamp("2026-01-15T10:30:00Z")
	if ts == nil {
		t.Fatal("expected non-nil timestamp")
	}

	// Empty string.
	if parseTimestamp("") != nil {
		t.Error("expected nil for empty string")
	}

	// Invalid format.
	if parseTimestamp("not-a-timestamp") != nil {
		t.Error("expected nil for invalid timestamp")
	}
}

// ── pciDeviceToProto ────────────────────────────────────────────────────────

func TestR3_PCIDeviceToProto_WithLinkPeers(t *testing.T) {
	d := corrosion.PCIDeviceRecord{
		HostName:   "host-1",
		Address:    "0000:03:00.0",
		VendorID:   "10de",
		DeviceID:   "2206",
		VendorName: "NVIDIA",
		DeviceName: "GA102",
		Type:       "gpu",
		IOMMUGroup: 42,
		LinkPeers:  "0000:03:00.1, 0000:03:00.2",
	}

	p := pciDeviceToProto(d)
	if len(p.LinkPeers) != 2 {
		t.Fatalf("got %d LinkPeers, want 2", len(p.LinkPeers))
	}
	if p.LinkPeers[0] != "0000:03:00.1" {
		t.Errorf("LinkPeers[0] = %q", p.LinkPeers[0])
	}
	if p.IommuGroup != 42 {
		t.Errorf("IommuGroup = %d, want 42", p.IommuGroup)
	}
}

func TestR3_PCIDeviceToProto_EmptyLinkPeers(t *testing.T) {
	d := corrosion.PCIDeviceRecord{
		HostName: "host-1",
		Address:  "0000:04:00.0",
		Type:     "nic",
	}

	p := pciDeviceToProto(d)
	if len(p.LinkPeers) != 0 {
		t.Errorf("got %d LinkPeers, want 0", len(p.LinkPeers))
	}
}

// ── parseDiskSizeBytes ──────────────────────────────────────────────────────

func TestR3_ParseDiskSizeBytes_Additional(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"", 0},
		{"1T", 1024 * 1024 * 1024 * 1024},
		{"2t", 2 * 1024 * 1024 * 1024 * 1024},
		{"100m", 100 * 1024 * 1024},
		{"50g", 50 * 1024 * 1024 * 1024},
	}
	for _, tt := range tests {
		got := parseDiskSizeBytes(tt.input)
		if got != tt.want {
			t.Errorf("parseDiskSizeBytes(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// ── GenerateMAC ─────────────────────────────────────────────────────────────

func TestR3_GenerateMAC_UniqueR3(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		mac := GenerateMAC()
		if seen[mac] {
			t.Errorf("duplicate MAC: %s", mac)
		}
		seen[mac] = true
		// Should start with 52:54:00:
		if mac[:9] != "52:54:00:" {
			t.Errorf("MAC %q doesn't have KVM prefix", mac)
		}
	}
}

// ── specImage / specCloudInitHash ───────────────────────────────────────────

func TestR3_SpecImage_Various(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`{"image":"ubuntu-22.04","cpu":2}`, "ubuntu-22.04"},
		{`{"cpu":2}`, ""},
		{"", ""},
		{`{"image":""}`, ""},
	}
	for _, tt := range tests {
		got := specImage(tt.input)
		if got != tt.want {
			t.Errorf("specImage(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestR3_SpecCloudInitHash_WithData(t *testing.T) {
	spec := `{"cloud_init":{"userdata":"#cloud-config\npackages:\n  - nginx\n","networkconfig":"version: 2"}}`
	h := specCloudInitHash(spec)
	if h == "" {
		t.Error("expected non-empty hash for spec with cloud-init")
	}
}

func TestR3_SpecCloudInitHash_EmptySpec(t *testing.T) {
	if specCloudInitHash("") != "" {
		t.Error("expected empty hash for empty spec")
	}
}

func TestR3_SpecCloudInitHash_NoCloudInit(t *testing.T) {
	if specCloudInitHash(`{"cpu":2}`) != "" {
		t.Error("expected empty hash for spec without cloud-init")
	}
}

// ── vmHooks ─────────────────────────────────────────────────────────────────

func TestR3_VmHooks_EmptySpec(t *testing.T) {
	vm := &corrosion.VMRecord{Spec: ""}
	if vmHooks(vm) != nil {
		t.Error("expected nil hooks for empty spec")
	}
}

func TestR3_VmHooks_InvalidJSON(t *testing.T) {
	vm := &corrosion.VMRecord{Spec: "{invalid"}
	if vmHooks(vm) != nil {
		t.Error("expected nil hooks for invalid JSON")
	}
}

func TestR3_VmHooks_NoHooks(t *testing.T) {
	vm := &corrosion.VMRecord{Spec: `{"cpu":2}`}
	if vmHooks(vm) != nil {
		t.Error("expected nil hooks when hooks not in spec")
	}
}

// ── replaceDomainName / replaceFirst ────────────────────────────────────────

func TestR3_ReplaceDomainName(t *testing.T) {
	xml := `<domain><name>old-vm</name><memory>4096</memory></domain>`
	got := replaceDomainName(xml, "old-vm", "new-vm")
	want := `<domain><name>new-vm</name><memory>4096</memory></domain>`
	if got != want {
		t.Errorf("replaceDomainName:\n  got  %s\n  want %s", got, want)
	}
}

func TestR3_ReplaceDomainName_NotFound(t *testing.T) {
	xml := `<domain><name>other-vm</name></domain>`
	got := replaceDomainName(xml, "old-vm", "new-vm")
	// Should be unchanged.
	if got != xml {
		t.Errorf("expected unchanged XML, got %s", got)
	}
}

func TestR3_ReplaceFirst_NoMatch(t *testing.T) {
	result := replaceFirst("hello world", "xyz", "abc")
	if result != "hello world" {
		t.Errorf("replaceFirst = %q, want unchanged", result)
	}
}

func TestR3_ReplaceFirst_Match(t *testing.T) {
	result := replaceFirst("aabbcc", "bb", "XX")
	if result != "aaXXcc" {
		t.Errorf("replaceFirst = %q, want aaXXcc", result)
	}
}

// ── sortDeployOps / statePriority / opKindToDiffOp ──────────────────────────

func TestR3_StatePriority(t *testing.T) {
	if statePriority("error") >= statePriority("stopped") {
		t.Error("error should have lower priority than stopped")
	}
	if statePriority("stopped") >= statePriority("running") {
		t.Error("stopped should have lower priority than running")
	}
	if statePriority("anything") != 2 {
		t.Errorf("unknown state priority = %d, want 2", statePriority("anything"))
	}
}

// ── ConsoleVM: validation paths ─────────────────────────────────────────────

// mockConsoleStreamR3 implements grpc.BidiStreamingServer[pb.ConsoleInput, pb.ConsoleOutput].
type mockConsoleStreamR3 struct {
	ctx context.Context
}

func (m *mockConsoleStreamR3) Send(_ *pb.ConsoleOutput) error { return nil }
func (m *mockConsoleStreamR3) Recv() (*pb.ConsoleInput, error) {
	<-m.ctx.Done()
	return nil, m.ctx.Err()
}
func (m *mockConsoleStreamR3) Context() context.Context       { return m.ctx }
func (m *mockConsoleStreamR3) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockConsoleStreamR3) SendHeader(_ metadata.MD) error { return nil }
func (m *mockConsoleStreamR3) SetTrailer(_ metadata.MD)       {}
func (m *mockConsoleStreamR3) SendMsg(_ any) error            { return nil }
func (m *mockConsoleStreamR3) RecvMsg(_ any) error            { return nil }

func TestR3_ConsoleVM_NoMetadata(t *testing.T) {
	s := testServerR2(t)
	stream := &mockConsoleStreamR3{ctx: adminCtx()}

	err := s.ConsoleVM(stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_ConsoleVM_VMNotFound(t *testing.T) {
	s := testServerR2(t)
	md := metadata.New(map[string]string{"x-vm-name": "ghost"})
	ctx := metadata.NewIncomingContext(adminCtx(), md)
	stream := &mockConsoleStreamR3{ctx: ctx}

	err := s.ConsoleVM(stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_ConsoleVM_WrongHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "console-remote", "other-host", "running")

	md := metadata.New(map[string]string{"x-vm-name": "console-remote"})
	streamCtx := metadata.NewIncomingContext(ctx, md)
	stream := &mockConsoleStreamR3{ctx: streamCtx}

	err := s.ConsoleVM(stream)
	if err == nil {
		t.Fatal("expected error")
	}
	// Remote VMs are now forwarded via peerClient, which fails with Unavailable
	// when the remote host can't be reached (no host record in test DB).
	if c := status.Code(err); c != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", c)
	}
}

func TestR3_ConsoleVM_NotRunning(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "console-stopped", "test-host", "stopped")

	md := metadata.New(map[string]string{"x-vm-name": "console-stopped"})
	streamCtx := metadata.NewIncomingContext(ctx, md)
	stream := &mockConsoleStreamR3{ctx: streamCtx}

	err := s.ConsoleVM(stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

// ── PushImage: validation paths ─────────────────────────────────────────────

type mockPushImageStreamR3 struct {
	ctx  context.Context
	sent []*pb.PushImageProgress
}

func (m *mockPushImageStreamR3) Send(p *pb.PushImageProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockPushImageStreamR3) Context() context.Context       { return m.ctx }
func (m *mockPushImageStreamR3) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockPushImageStreamR3) SendHeader(_ metadata.MD) error { return nil }
func (m *mockPushImageStreamR3) SetTrailer(_ metadata.MD)       {}
func (m *mockPushImageStreamR3) SendMsg(_ any) error            { return nil }
func (m *mockPushImageStreamR3) RecvMsg(_ any) error            { return nil }

func TestR3_PushImage_MissingFields(t *testing.T) {
	s := testServerR2(t)
	stream := &mockPushImageStreamR3{ctx: adminCtx()}

	err := s.PushImage(&pb.PushImageRequest{}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestR3_PushImage_ImageNotFound(t *testing.T) {
	s := testServerR2(t)
	stream := &mockPushImageStreamR3{ctx: adminCtx()}

	err := s.PushImage(&pb.PushImageRequest{Name: "nonexistent", TargetHost: "h2"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestR3_PushImage_TargetHostNotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	stream := &mockPushImageStreamR3{ctx: ctx}

	createFakeImage(t, s, "push-test-img")

	err := s.PushImage(&pb.PushImageRequest{Name: "push-test-img", TargetHost: "ghost-host"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.Unavailable && c != codes.NotFound {
		t.Errorf("code = %v, want Unavailable or NotFound", c)
	}
}

// ── ListImages ──────────────────────────────────────────────────────────────

func TestR3_ListImages_EmptyR3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	resp, err := s.ListImages(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(resp.Images) != 0 {
		t.Errorf("got %d images, want 0", len(resp.Images))
	}
}

func TestR3_ListImages_WithRecords(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name:      "ubuntu-22.04",
		Format:    "qcow2",
		SourceURL: "https://cloud-images.ubuntu.com/...",
		SizeBytes: 1024 * 1024 * 500,
	})
	corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
		ImageName: "ubuntu-22.04",
		HostName:  "host-a",
		Path:      "/data/images/ubuntu-22.04",
		Status:    "ready",
	})

	resp, err := s.ListImages(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(resp.Images) != 1 {
		t.Fatalf("got %d images, want 1", len(resp.Images))
	}
	img := resp.Images[0]
	if img.Name != "ubuntu-22.04" {
		t.Errorf("Name = %q", img.Name)
	}
	if len(img.Hosts) != 1 {
		t.Errorf("got %d hosts, want 1", len(img.Hosts))
	}
}

// ── DeleteImage ─────────────────────────────────────────────────────────────

func TestR3_DeleteImage_R3(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name:   "del-img",
		Format: "qcow2",
	})

	_, err := s.DeleteImage(ctx, &pb.DeleteImageRequest{Name: "del-img"})
	if err != nil {
		t.Fatalf("DeleteImage: %v", err)
	}
}

// ── parseDiskSize (hotplug) ─────────────────────────────────────────────────

func TestR3_ParseDiskSize_Additional(t *testing.T) {
	tests := []struct {
		input  string
		wantGB int
		err    bool
	}{
		{"10G", 10, false},
		{"1T", 1024, false},
		{"500M", 1, false},
		{"2048M", 2, false},
		{"100GB", 100, false},
		{"2TB", 2048, false},
		{"50", 50, false},
		{"", 0, true},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		got, err := parseDiskSize(tt.input)
		if tt.err {
			if err == nil {
				t.Errorf("parseDiskSize(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDiskSize(%q): %v", tt.input, err)
			continue
		}
		if got != tt.wantGB {
			t.Errorf("parseDiskSize(%q) = %d, want %d", tt.input, got, tt.wantGB)
		}
	}
}

// ── countVMDisks ────────────────────────────────────────────────────────────

func TestR3_CountVMDisks(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	if n := countVMDisks(ctx, s.db, "nonexistent"); n != 0 {
		t.Errorf("countVMDisks = %d, want 0", n)
	}

	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName:   "disk-vm",
		DiskName: "root",
		HostName: "test-host",
		Path:     "/data/root.qcow2",
	})
	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName:   "disk-vm",
		DiskName: "data",
		HostName: "test-host",
		Path:     "/data/data.qcow2",
	})

	if n := countVMDisks(ctx, s.db, "disk-vm"); n != 2 {
		t.Errorf("countVMDisks = %d, want 2", n)
	}
}

// ── refreshLBForStack ───────────────────────────────────────────────────────

func TestR3_RefreshLBForStack_EmptyStack(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	// Should not panic.
	s.refreshLBForStack(ctx, "")
}

func TestR3_RefreshLBForStack_NoVMs(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	// Should not panic — no VMs in this stack.
	s.refreshLBForStack(ctx, "nonexistent-stack")
}

func TestR3_RefreshLBForStack_VMsWithoutLBSpec(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2WithStack(t, ctx, s.db, "nolb-vm", "test-host", "running", "nolb-stack")

	// Should not panic — VM has no LB spec.
	s.refreshLBForStack(ctx, "nolb-stack")
}

// ── applyLBFromSpec ─────────────────────────────────────────────────────────

func TestR3_ApplyLBFromSpec_NilLB(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	// nil LB spec: should return immediately.
	s.applyLBFromSpec(ctx, &pb.VMSpec{})
}

func TestR3_ApplyLBFromSpec_Disabled(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	s.applyLBFromSpec(ctx, &pb.VMSpec{
		Loadbalancer: &pb.LBSpec{Enabled: false},
	})
}

// ── RequireRole / roleLevel / callerUsername ─────────────────────────────────

func TestR3_RequireRole_Admin(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyRole, "admin")
	if err := RequireRole(ctx, "operator"); err != nil {
		t.Errorf("admin should satisfy operator: %v", err)
	}
}

func TestR3_RequireRole_Viewer(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyRole, "viewer")
	if err := RequireRole(ctx, "operator"); err == nil {
		t.Error("viewer should not satisfy operator")
	}
}

func TestR3_RequireRole_NoRole(t *testing.T) {
	ctx := context.Background()
	if err := RequireRole(ctx, "viewer"); err == nil {
		t.Error("no role should not satisfy viewer")
	}
}

func TestR3_CallerUsername(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	if u := callerUsername(ctx); u != "alice" {
		t.Errorf("callerUsername = %q, want alice", u)
	}

	if u := callerUsername(context.Background()); u != "" {
		t.Errorf("callerUsername = %q, want empty", u)
	}
}

func TestR3_CallerRole(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyRole, "operator")
	if r := callerRole(ctx); r != "operator" {
		t.Errorf("callerRole = %q, want operator", r)
	}

	if r := callerRole(context.Background()); r != "" {
		t.Errorf("callerRole = %q, want empty", r)
	}
}
