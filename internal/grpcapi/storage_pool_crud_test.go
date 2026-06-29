package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func newPoolTestServer(t *testing.T) *Server {
	t.Helper()
	dataDir := t.TempDir()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{
		hostName: "host-a",
		dataDir:  dataDir,
		db:       db,
		virt:     libvirtfake.New(),
		images:   image.NewStore(dataDir),
		events:   events.NewBus(),
	}
}

func TestCreateStoragePool_LocalDriverHappyPath(t *testing.T) {
	s := newPoolTestServer(t)
	resp, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name:   "p1",
		Driver: "local",
		Target: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("CreateStoragePool: %v", err)
	}
	if resp.Pool.Name != "p1" || resp.Pool.Driver != "local" {
		t.Fatalf("got %+v", resp.Pool)
	}

	get, err := s.GetStoragePool(adminCtx(), &pb.GetStoragePoolRequest{Name: "p1"})
	if err != nil {
		t.Fatalf("GetStoragePool: %v", err)
	}
	if get.Pool.Name != "p1" {
		t.Fatalf("get got %+v", get.Pool)
	}
}

// A file-based pool must have its capacity populated at create time (statfs),
// not left at 0 until the daemon's next refresh tick — the dir-pool "0B/0B"
// regression.
func TestCreateStoragePool_PopulatesCapacity(t *testing.T) {
	s := newPoolTestServer(t)
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "cap", Driver: "dir", Target: t.TempDir(),
	}); err != nil {
		t.Fatalf("CreateStoragePool: %v", err)
	}
	rec, ok, err := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, "cap")
	if err != nil || !ok {
		t.Fatalf("GetStoragePool: ok=%v err=%v", ok, err)
	}
	if rec.TotalBytes <= 0 {
		t.Fatalf("pool TotalBytes = %d, want > 0 (capacity not populated at create)", rec.TotalBytes)
	}
	if rec.UsedBytes <= 0 {
		t.Errorf("pool UsedBytes = %d, want > 0", rec.UsedBytes)
	}
}

func TestCreateStoragePool_RejectsUnknownDriver(t *testing.T) {
	s := newPoolTestServer(t)
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name:   "p1",
		Driver: "made-up",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
	if !strings.Contains(err.Error(), "supported") {
		t.Fatalf("want hint about supported drivers; got %v", err)
	}
}

// TestCreateStoragePool_OptionsRoundTrip uses the dir driver (whose
// Prepare just stats the target dir) to confirm Options is serialised
// via JSON and read back intact — the ceph/iscsi shell-outs would
// fail Prepare in the test sandbox, masking the actual round-trip.
func TestCreateStoragePool_OptionsRoundTrip(t *testing.T) {
	s := newPoolTestServer(t)
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name:   "p1",
		Driver: "dir",
		Target: t.TempDir(),
		Options: map[string]string{
			"label":  "fast-tier",
			"region": "eu-west",
		},
	})
	if err != nil {
		t.Fatalf("CreateStoragePool: %v", err)
	}
	rec, ok, err := corrosion.GetStoragePool(adminCtx(), s.db, "host-a", "p1")
	if err != nil || !ok {
		t.Fatalf("GetStoragePool: %v ok=%v", err, ok)
	}
	if rec.Options["label"] != "fast-tier" || rec.Options["region"] != "eu-west" {
		t.Fatalf("options round-trip lost data: %+v", rec.Options)
	}
}

func TestDeleteStoragePool_MarksDeleted(t *testing.T) {
	s := newPoolTestServer(t)
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: "p1", Driver: "local", Target: t.TempDir(),
	}); err != nil {
		t.Fatalf("CreateStoragePool: %v", err)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "p1"}); err != nil {
		t.Fatalf("DeleteStoragePool: %v", err)
	}
	_, err := s.GetStoragePool(adminCtx(), &pb.GetStoragePoolRequest{Name: "p1"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound after delete, got %v", err)
	}
}

func TestDeleteStoragePool_NotFound(t *testing.T) {
	s := newPoolTestServer(t)
	_, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "ghost"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}

// auditRows returns the audit_log rows matching (action, result) on the test DB.
func auditRows(t *testing.T, s *Server, action, result string) int {
	t.Helper()
	rows, err := s.db.Query(adminCtx(),
		`SELECT COUNT(*) AS n FROM audit_log WHERE action = ? AND result = ?`, action, result)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if len(rows) == 0 {
		return 0
	}
	return rows[0].Int("n")
}

// poolDestroyed reports whether the libvirtfake recorded a pool-destroy for name.
func poolDestroyed(s *Server, name string) bool {
	f, ok := s.virt.(*libvirtfake.Fake)
	if !ok {
		return false
	}
	for _, e := range f.EventLog() {
		if e.Op == "pool-destroy" && e.Domain == name {
			return true
		}
	}
	return false
}

func makePool(t *testing.T, s *Server, name, driver string) {
	t.Helper()
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{
		Name: name, Driver: driver, Target: t.TempDir(),
	}); err != nil {
		t.Fatalf("CreateStoragePool %q: %v", name, err)
	}
}

// A pool with a live VM disk on its own host must NOT delete without --force, and
// the refusal is audited as "blocked".
func TestDeleteStoragePool_RefusedWhenDiskReferences(t *testing.T) {
	s := newPoolTestServer(t)
	makePool(t, s, "p1", "local")
	if err := corrosion.InsertDisk(adminCtx(), s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "root", HostName: s.hostName,
		StorageType: "local", StorageVolume: "p1", Path: "/x/root.qcow2",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	_, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "p1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
	// Pool row must still be present (not deleted).
	if _, err := s.GetStoragePool(adminCtx(), &pb.GetStoragePoolRequest{Name: "p1"}); err != nil {
		t.Fatalf("pool should survive a blocked delete: %v", err)
	}
	if n := auditRows(t, s, "storage.pool.delete", "blocked"); n != 1 {
		t.Fatalf("want 1 blocked audit row, got %d", n)
	}
	if poolDestroyed(s, "p1") {
		t.Fatalf("libvirt pool must NOT be undefined on a blocked delete")
	}
}

// A disk on a DIFFERENT host with the same pool name must not block (host-scoped).
func TestDeleteStoragePool_DiskOnOtherHostDoesNotBlock(t *testing.T) {
	s := newPoolTestServer(t)
	makePool(t, s, "p1", "local")
	if err := corrosion.InsertDisk(adminCtx(), s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "root", HostName: "host-b", // other host
		StorageType: "local", StorageVolume: "p1", Path: "/x/root.qcow2",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "p1"}); err != nil {
		t.Fatalf("delete should succeed (disk is on another host): %v", err)
	}
}

// --force deletes a referenced pool, undefines the libvirt object, and audits "ok".
func TestDeleteStoragePool_ForceOverridesReference(t *testing.T) {
	s := newPoolTestServer(t)
	makePool(t, s, "p1", "local")
	if err := corrosion.InsertDisk(adminCtx(), s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "root", HostName: s.hostName,
		StorageType: "local", StorageVolume: "p1", Path: "/x/root.qcow2",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "p1", Force: true}); err != nil {
		t.Fatalf("force delete: %v", err)
	}
	if _, err := s.GetStoragePool(adminCtx(), &pb.GetStoragePoolRequest{Name: "p1"}); status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound after force delete, got %v", err)
	}
	if !poolDestroyed(s, "p1") {
		t.Fatalf("libvirt pool should be undefined on delete")
	}
	if n := auditRows(t, s, "storage.pool.delete", "ok"); n != 1 {
		t.Fatalf("want 1 ok audit row, got %d", n)
	}
}

// An ENABLED pool-scoped backup schedule blocks delete without --force.
func TestDeleteStoragePool_RefusedWhenScheduleReferences(t *testing.T) {
	s := newPoolTestServer(t)
	makePool(t, s, "p1", "local")
	if err := corrosion.UpsertBackupSchedule(adminCtx(), s.db, corrosion.BackupScheduleRecord{
		Scope: "pool", PoolName: "p1", Repo: "r1", Cron: "@daily", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "p1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
}

// A DISABLED schedule must not block delete.
func TestDeleteStoragePool_DisabledScheduleDoesNotBlock(t *testing.T) {
	s := newPoolTestServer(t)
	makePool(t, s, "p1", "local")
	if err := corrosion.UpsertBackupSchedule(adminCtx(), s.db, corrosion.BackupScheduleRecord{
		Scope: "pool", PoolName: "p1", Repo: "r1", Cron: "@daily", Enabled: false,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "p1"}); err != nil {
		t.Fatalf("disabled schedule should not block delete: %v", err)
	}
}

// A delete forwarded to a remote host must be reference-guarded on THIS (entry)
// node BEFORE it forwards — otherwise a new node forwarding to an old (unguarded)
// node could hide a referenced pool. The guard blocks before any peer dial.
func TestDeleteStoragePool_EntryNodeGuardsBeforeForward(t *testing.T) {
	s := newPoolTestServer(t) // hostName = host-a
	if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
		HostName: "host-b", Name: "p1", Driver: "local", State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool: %v", err)
	}
	if err := corrosion.InsertDisk(adminCtx(), s.db, corrosion.DiskRecord{
		VMName: "vm1", DiskName: "root", HostName: "host-b",
		StorageType: "local", StorageVolume: "p1", Path: "/x/root.qcow2",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}
	// Host-b is unreachable in the test; the guard must fire first (FailedPrecondition),
	// not a dial error.
	_, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "p1", Host: "host-b"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("entry node must guard before forwarding; got %v", err)
	}
	if n := auditRows(t, s, "storage.pool.delete", "blocked"); n != 1 {
		t.Fatalf("want 1 blocked audit row on entry node, got %d", n)
	}
}

// The clean path: an unreferenced pool deletes, undefines the libvirt object, and audits "ok".
func TestDeleteStoragePool_UnreferencedSucceeds(t *testing.T) {
	s := newPoolTestServer(t)
	makePool(t, s, "p1", "local")
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "p1"}); err != nil {
		t.Fatalf("DeleteStoragePool: %v", err)
	}
	if !poolDestroyed(s, "p1") {
		t.Fatalf("libvirt pool should be undefined on delete")
	}
	if n := auditRows(t, s, "storage.pool.delete", "ok"); n != 1 {
		t.Fatalf("want 1 ok audit row, got %d", n)
	}
}
