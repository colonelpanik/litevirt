package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// mockPushImageStream implements grpc.ServerStreamingServer[pb.PushImageProgress].
type mockPushImageStream struct {
	ctx  context.Context
	sent []*pb.PushImageProgress
}

func (m *mockPushImageStream) Send(p *pb.PushImageProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockPushImageStream) Context() context.Context       { return m.ctx }
func (m *mockPushImageStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockPushImageStream) SendHeader(_ metadata.MD) error { return nil }
func (m *mockPushImageStream) SetTrailer(_ metadata.MD)       {}
func (m *mockPushImageStream) SendMsg(_ interface{}) error    { return nil }
func (m *mockPushImageStream) RecvMsg(_ interface{}) error    { return nil }

func TestPushImage_MissingFields(t *testing.T) {
	s := testServer(t)
	stream := &mockPushImageStream{ctx: adminCtx()}

	err := s.PushImage(&pb.PushImageRequest{}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestPushImage_MissingName(t *testing.T) {
	s := testServer(t)
	stream := &mockPushImageStream{ctx: adminCtx()}

	err := s.PushImage(&pb.PushImageRequest{TargetHost: "h1"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestPushImage_MissingTarget(t *testing.T) {
	s := testServer(t)
	stream := &mockPushImageStream{ctx: adminCtx()}

	err := s.PushImage(&pb.PushImageRequest{Name: "ubuntu"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}
