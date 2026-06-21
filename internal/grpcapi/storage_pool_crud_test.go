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
