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

// TestBackupVM_Deprecated verifies the raw full-disk backup RPC is retired —
// it returns Unimplemented regardless of arguments, directing callers to the
// snapshot-based backup path.
func TestBackupVM_Deprecated(t *testing.T) {
	s := testServerWithLocks(t)
	stream := &mockBackupStream{ctx: adminCtx()}
	err := s.BackupVM(&pb.BackupVMRequest{VmName: "anything"}, stream)
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("code = %v, want Unimplemented", status.Code(err))
	}
}
