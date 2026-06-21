package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// mockBackupStream implements grpc.ServerStreamingServer[pb.BackupChunk].
type mockBackupStream struct {
	ctx  context.Context
	sent []*pb.BackupChunk
}

func (m *mockBackupStream) Send(chunk *pb.BackupChunk) error {
	m.sent = append(m.sent, chunk)
	return nil
}
func (m *mockBackupStream) Context() context.Context          { return m.ctx }
func (m *mockBackupStream) SetHeader(_ metadata.MD) error     { return nil }
func (m *mockBackupStream) SendHeader(_ metadata.MD) error    { return nil }
func (m *mockBackupStream) SetTrailer(_ metadata.MD)          {}
func (m *mockBackupStream) SendMsg(_ interface{}) error       { return nil }
func (m *mockBackupStream) RecvMsg(_ interface{}) error       { return nil }

func TestBackupVM_EmptyName(t *testing.T) {
	s := testServerWithLocks(t)
	stream := &mockBackupStream{ctx: adminCtx()}

	err := s.BackupVM(&pb.BackupVMRequest{}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestBackupVM_NotFound(t *testing.T) {
	s := testServerWithLocks(t)
	stream := &mockBackupStream{ctx: adminCtx()}

	err := s.BackupVM(&pb.BackupVMRequest{VmName: "nope"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestBackupVM_WrongHost(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	stream := &mockBackupStream{ctx: ctx}

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	err := s.BackupVM(&pb.BackupVMRequest{VmName: "remote-vm"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}
