package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func insertFirmwareVM(t *testing.T, ctx context.Context, s *Server, name, state string) {
	t.Helper()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: name, HostName: s.hostName, Spec: `{"name":"` + name + `","tpm":true,"uuid":"u1"}`,
		State: state, CPUActual: 2, MemActual: 2048,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
}

// Live migration of an SB/vTPM VM is refused (carry unvalidated; source must not
// be wiped on an unverified carry) — cold only.
func TestMigrateVM_FirmwareLiveRefused(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	insertFirmwareVM(t, ctx, s, "fw", "running")
	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "fw", TargetHost: "t1"}, &mockMigrateStream{ctx: ctx}) // default strategy = live
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition refusing live firmware migration, got %v", err)
	}
	if !strings.Contains(err.Error(), "cold") {
		t.Errorf("error should steer to cold migration, got: %v", err)
	}
}

// Cold migration of a RUNNING SB/vTPM VM is refused — firmware can't be captured
// consistently while the guest mutates TPM state. Must be stopped first.
func TestMigrateVM_FirmwareRunningColdRefused(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	insertFirmwareVM(t, ctx, s, "fw", "running")
	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "fw", TargetHost: "t1", Strategy: pb.MigrateStrategy_MIGRATE_COLD}, &mockMigrateStream{ctx: ctx})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for cold-migrating a running firmware VM, got %v", err)
	}
	if !strings.Contains(err.Error(), "stop") {
		t.Errorf("error should tell the operator to stop the VM, got: %v", err)
	}
}

// A stopped SB/vTPM VM cold-migrated to a non-capable host is refused at the gate.
func TestMigrateVM_FirmwareTargetNotCapable(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	insertFirmwareVM(t, ctx, s, "fw", "stopped")
	insertTestHost(t, ctx, s.db, "t1", "active") // no capability labels

	err := s.MigrateVM(&pb.MigrateVMRequest{VmName: "fw", TargetHost: "t1", Strategy: pb.MigrateStrategy_MIGRATE_COLD}, &mockMigrateStream{ctx: ctx})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition migrating a vTPM VM to a non-capable host, got %v", err)
	}
	if !strings.Contains(err.Error(), "vTPM-capable") {
		t.Errorf("error should name the missing capability, got: %v", err)
	}
}

// EnsureFirmwareState materializes a pushed firmware bundle on the target.
func TestEnsureFirmwareState_MaterializesNvram(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	ctx := adminCtx()

	// Build an NVRAM-only bundle (uuid "" → no swtpm member, so no root-owned path).
	src := lv.NvramPath(s.dataDir, "src")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(src, []byte("vars"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var buf bytes.Buffer
	has, err := lv.WriteFirmwareBundle(s.dataDir, "src", "", &buf)
	if err != nil || !has {
		t.Fatalf("WriteFirmwareBundle: has=%v err=%v", has, err)
	}

	if _, err := s.EnsureFirmwareState(ctx, &pb.EnsureFirmwareStateRequest{
		VmName: "win", Bundle: buf.Bytes(),
	}); err != nil {
		t.Fatalf("EnsureFirmwareState: %v", err)
	}
	if !lv.HasNvram(s.dataDir, "win") {
		t.Error("EnsureFirmwareState should have materialized NVRAM for the target VM")
	}
}

// nvramBundle builds a valid NVRAM-only firmware bundle (uuid "" → no swtpm).
func nvramBundle(t *testing.T, dataDir string) []byte {
	t.Helper()
	src := lv.NvramPath(dataDir, "bundle-src")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(src, []byte("vars"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var buf bytes.Buffer
	if has, err := lv.WriteFirmwareBundle(dataDir, "bundle-src", "", &buf); err != nil || !has {
		t.Fatalf("WriteFirmwareBundle: has=%v err=%v", has, err)
	}
	return buf.Bytes()
}

// With a domain_xml, EnsureFirmwareState also defines the domain (shut off) so
// the migrated stopped VM is startable on the target.
func TestEnsureFirmwareState_DefinesDomain(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	if _, err := s.EnsureFirmwareState(adminCtx(), &pb.EnsureFirmwareStateRequest{
		VmName: "win", Bundle: nvramBundle(t, s.dataDir),
		DomainXml: `<domain type='kvm'><name>win</name></domain>`,
	}); err != nil {
		t.Fatalf("EnsureFirmwareState: %v", err)
	}
	if !fake.DomainExists("win") {
		t.Error("EnsureFirmwareState with domain_xml should define the domain on the target")
	}
}

// If the define fails, the just-materialized firmware is wiped (clean retry).
func TestEnsureFirmwareState_DefineFailureWipesFirmware(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	fake.FailDefineDomain = func(string) error { return errors.New("define boom") }
	s.virt = fake
	s.dataDir = t.TempDir()
	_, err := s.EnsureFirmwareState(adminCtx(), &pb.EnsureFirmwareStateRequest{
		VmName: "win", Bundle: nvramBundle(t, s.dataDir),
		DomainXml: `<domain type='kvm'><name>win</name></domain>`,
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal on define failure, got %v", err)
	}
	if lv.HasNvram(s.dataDir, "win") {
		t.Error("firmware must be wiped after a failed define-on-target")
	}
}

// A domain XML is only portable to a host with an identical firmware-path
// layout — a fingerprint mismatch must refuse the define (and wipe firmware).
func TestEnsureFirmwareState_FingerprintMismatchRefused(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	_, err := s.EnsureFirmwareState(adminCtx(), &pb.EnsureFirmwareStateRequest{
		VmName: "win", Bundle: nvramBundle(t, s.dataDir),
		DomainXml:                 `<domain type='kvm'><name>win</name></domain>`,
		SourceFirmwareFingerprint: "not-our-layout",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition on firmware-layout mismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "layout differs") {
		t.Errorf("error should explain the layout mismatch, got: %v", err)
	}
	if lv.HasNvram(s.dataDir, "win") {
		t.Error("firmware must be wiped on a refused define")
	}
}

// The pushed domain XML must match the request identity — never define an
// unrelated/mismatched domain via this RPC.
func TestEnsureFirmwareState_XMLIdentityMismatchRejected(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	_, err := s.EnsureFirmwareState(adminCtx(), &pb.EnsureFirmwareStateRequest{
		VmName: "win", Bundle: nvramBundle(t, s.dataDir),
		DomainXml: `<domain type='kvm'><name>evil</name></domain>`, // name != win
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument on domain-XML identity mismatch, got %v", err)
	}
}

// A firmware VM with a PCI passthrough device can't be cold-migrated (source PCI
// addresses would be carried into the target XML) — refuse for now.
func TestColdMigrateFirmwareVM_RefusesHostdev(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "fw", HostName: s.hostName, Spec: `{"name":"fw","tpm":true,"uuid":"u1"}`, State: "stopped",
	}, nil, []corrosion.DiskRecord{
		{VMName: "fw", DiskName: "root", HostName: s.hostName, Path: "/srv/root.qcow2", StorageType: "nfs"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: "0000:01:00.0", Type: "gpu", VMName: "fw",
	}); err != nil {
		t.Fatalf("UpsertPCIDevice: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "fw")
	err := s.coldMigrateFirmwareVM(ctx, vm, &corrosion.HostRecord{Name: "t1"},
		firmwareSpec{Tpm: true, UUID: "u1"}, func(pb.MigratePhase, float32, float32) error { return nil })
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for a firmware VM with a hostdev, got %v", err)
	}
	if !strings.Contains(err.Error(), "PCI passthrough") {
		t.Errorf("error should name the hostdev limitation, got: %v", err)
	}
}

func TestEnsureFirmwareState_EmptyBundleRejected(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	_, err := s.EnsureFirmwareState(adminCtx(), &pb.EnsureFirmwareStateRequest{VmName: "win"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for an empty bundle, got %v", err)
	}
}

// EnsureFirmwareState must refuse to materialize over an already-defined domain
// (it's a migration-target RPC; clobbering a live VM's firmware is destructive).
func TestEnsureFirmwareState_RefusesExistingDomain(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	if err := fake.DefineDomain(`<domain type='kvm'><name>win</name></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}
	_, err := s.EnsureFirmwareState(adminCtx(), &pb.EnsureFirmwareStateRequest{VmName: "win", Bundle: []byte("x")})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition materializing over an existing domain, got %v", err)
	}
}

// firmwarePresent rejects a partial set (vTPM VM with NVRAM but no swtpm).
func TestFirmwarePresent_PartialRejected(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	nv := lv.NvramPath(s.dataDir, "fw")
	if err := os.MkdirAll(filepath.Dir(nv), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(nv, []byte("vars"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// NVRAM present, swtpm (uuid) absent → reject for a vTPM VM.
	if err := s.firmwarePresent("fw", firmwareSpec{Tpm: true, Firmware: "uefi", UUID: "no-such"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for a missing swtpm component, got %v", err)
	}
}

// CleanupMigrationArtifacts must never remove a path outside the data dir.
func TestCleanupMigrationArtifacts_RefusesPathOutsideDataDir(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	outside := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(outside, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := s.CleanupMigrationArtifacts(adminCtx(), &pb.CleanupMigrationArtifactsRequest{
		VmName: "fw", DiskPaths: []string{outside},
	}); err != nil {
		t.Fatalf("CleanupMigrationArtifacts: %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Error("a path outside dataDir must NOT be removed by cleanup")
	}
}

// The stopped-firmware cold move requires shared storage — a host-local disk
// can't be block-copied while stopped, so it's refused (would leave disks behind).
func TestColdMigrateFirmwareVM_RefusesLocalDisk(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "fw", HostName: s.hostName, Spec: `{"name":"fw","tpm":true,"uuid":"u1"}`, State: "stopped",
	}, nil, []corrosion.DiskRecord{
		{VMName: "fw", DiskName: "root", HostName: s.hostName, Path: "/x/root.qcow2", StorageType: "dir"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "fw")
	err := s.coldMigrateFirmwareVM(ctx, vm, &corrosion.HostRecord{Name: "t1"},
		firmwareSpec{Tpm: true, UUID: "u1"}, func(pb.MigratePhase, float32, float32) error { return nil })
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for a host-local (dir) firmware migration, got %v", err)
	}
	if !strings.Contains(err.Error(), "shared storage") {
		t.Errorf("error should steer to shared storage, got: %v", err)
	}
}

// Drain must refuse an SB/vTPM VM regardless of storage type (firmware isn't
// transferred by reassignment / raw live-migrate).
func TestDrainOneVM_RefusesFirmwareVM(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	insertFirmwareVM(t, ctx, s, "fw", "running")
	vm, _ := corrosion.GetVM(ctx, s.db, "fw")
	prog := s.drainOneVM(ctx, *vm, corrosion.HostRecord{Name: "t1"})
	if prog.Status != "skipped" {
		t.Fatalf("expected firmware VM drain to be skipped, got %q (err=%q)", prog.Status, prog.Error)
	}
	if !strings.Contains(prog.Error, "migrate it explicitly") {
		t.Errorf("skip reason should point to explicit migration, got: %q", prog.Error)
	}
}

// A disk replica carries no firmware, so promoting an SB/vTPM VM must refuse.
func TestPromoteReplica_RefusesFirmwareVM(t *testing.T) {
	s := testServer(t)
	vm := &corrosion.VMRecord{Name: "fw", HostName: s.hostName, Spec: `{"name":"fw","secure_boot":true,"tpm":true,"uuid":"u1"}`}
	err := s.promoteResolved(context.Background(), &pb.PromoteReplicaRequest{VmName: "fw"}, vm, func(*pb.PromoteReplicaProgress) error { return nil })
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition promoting an SB/vTPM VM, got %v", err)
	}
}
