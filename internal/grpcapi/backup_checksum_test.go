package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// failChecksumStream accepts data frames but fails on the final checksum frame,
// simulating a client that dropped right before the integrity confirmation.
type failChecksumStream struct {
	ctx  context.Context
	sent int
}

func (m *failChecksumStream) Send(c *pb.BackupChunk) error {
	m.sent++
	if c.Checksum != "" {
		return status.Error(codes.Unavailable, "client gone")
	}
	return nil
}
func (m *failChecksumStream) Context() context.Context     { return m.ctx }
func (m *failChecksumStream) SetHeader(metadata.MD) error  { return nil }
func (m *failChecksumStream) SendHeader(metadata.MD) error { return nil }
func (m *failChecksumStream) SetTrailer(metadata.MD)       {}
func (m *failChecksumStream) SendMsg(interface{}) error    { return nil }
func (m *failChecksumStream) RecvMsg(interface{}) error    { return nil }

// TestBackupVM_ChecksumSendErrorSurfaces is the C1 regression: a failed Send of
// the final checksum frame must be returned, not silently dropped.
func TestBackupVM_ChecksumSendErrorSurfaces(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	diskPath := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(diskPath, []byte("some-disk-bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "test-host", State: "running", CPUActual: 2, MemActual: 4096,
	}, nil, []corrosion.DiskRecord{{
		VMName: "vm1", DiskName: "root", HostName: "test-host", Path: diskPath, SizeBytes: 15,
	}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	err := s.BackupVM(&pb.BackupVMRequest{VmName: "vm1"}, &failChecksumStream{ctx: ctx})
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal on checksum send failure, got %v (code=%v)", err, status.Code(err))
	}
}
