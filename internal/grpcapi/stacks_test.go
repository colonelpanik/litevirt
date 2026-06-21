package grpcapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
)

// mockDeployStream implements grpc.ServerStreamingServer[pb.DeployProgress].
type mockDeployStream struct {
	ctx  context.Context
	sent []*pb.DeployProgress
}

func (m *mockDeployStream) Send(p *pb.DeployProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockDeployStream) Context() context.Context       { return m.ctx }
func (m *mockDeployStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockDeployStream) SendHeader(_ metadata.MD) error { return nil }
func (m *mockDeployStream) SetTrailer(_ metadata.MD)       {}
func (m *mockDeployStream) SendMsg(_ interface{}) error    { return nil }
func (m *mockDeployStream) RecvMsg(_ interface{}) error    { return nil }

func TestDeployStack_EmptyYAML(t *testing.T) {
	s := testServer(t)
	// DeployStack checks RequireRole first. Provide operator context.
	ctx := context.WithValue(context.Background(), ctxKeyRole, "operator")
	stream := &mockDeployStream{ctx: ctx}

	err := s.DeployStack(&pb.DeployStackRequest{}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestDeployStack_InvalidYAML(t *testing.T) {
	s := testServer(t)
	ctx := context.WithValue(context.Background(), ctxKeyRole, "operator")
	stream := &mockDeployStream{ctx: ctx}

	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "{{{"}, stream)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestDeployStack_Unauthorized(t *testing.T) {
	s := testServer(t)
	ctx := context.WithValue(context.Background(), ctxKeyRole, "viewer")
	stream := &mockDeployStream{ctx: ctx}

	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: "name: test\nvms:\n  web:\n    image: ubuntu"}, stream)
	if err == nil {
		t.Fatal("expected error for viewer role")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestDiffStack_EmptyYAML(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.DiffStack(ctx, &pb.DiffStackRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestDiffStack_InvalidYAML(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.DiffStack(ctx, &pb.DiffStackRequest{ComposeYaml: "{{{"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestListStacks_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.ListStacks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListStacks: %v", err)
	}
	if len(resp.Stacks) != 0 {
		t.Errorf("expected 0 stacks, got %d", len(resp.Stacks))
	}
}

func TestListStacks_WithStacks(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name:  "myapp",
		State: "active",
	})

	resp, err := s.ListStacks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListStacks: %v", err)
	}
	if len(resp.Stacks) != 1 {
		t.Fatalf("expected 1 stack, got %d", len(resp.Stacks))
	}
	if resp.Stacks[0].Name != "myapp" {
		t.Errorf("Name = %q, want myapp", resp.Stacks[0].Name)
	}
}

func TestSortDeployOps(t *testing.T) {
	ops := []compose.Op{
		{Kind: compose.OpUpdate, VMName: "vm-running"},
		{Kind: compose.OpUpdate, VMName: "vm-error"},
		{Kind: compose.OpUpdate, VMName: "vm-stopped"},
		{Kind: compose.OpCreate, VMName: "vm-new"},
	}
	current := []compose.CurrentVM{
		{Name: "vm-running", State: "running"},
		{Name: "vm-error", State: "error"},
		{Name: "vm-stopped", State: "stopped"},
	}

	sortDeployOps(ops, current)

	// OpCreate should stay at its position (no reordering for non-updates).
	// Among OpUpdate, error < stopped < running.
	if ops[0].VMName != "vm-error" {
		t.Errorf("ops[0] = %s, want vm-error", ops[0].VMName)
	}
	if ops[1].VMName != "vm-stopped" {
		t.Errorf("ops[1] = %s, want vm-stopped", ops[1].VMName)
	}
	if ops[2].VMName != "vm-running" {
		t.Errorf("ops[2] = %s, want vm-running", ops[2].VMName)
	}
	// OpCreate should be last.
	if ops[3].Kind != compose.OpCreate {
		t.Errorf("ops[3].Kind = %v, want OpCreate", ops[3].Kind)
	}
}

func TestStatePriority(t *testing.T) {
	if statePriority("error") >= statePriority("stopped") {
		t.Error("error should have lower priority than stopped")
	}
	if statePriority("stopped") >= statePriority("running") {
		t.Error("stopped should have lower priority than running")
	}
}

func TestOpKindToDiffOp(t *testing.T) {
	tests := []struct {
		input compose.OpKind
		want  pb.DiffOp
	}{
		{compose.OpCreate, pb.DiffOp_DIFF_CREATE},
		{compose.OpUpdate, pb.DiffOp_DIFF_UPDATE},
		{compose.OpDelete, pb.DiffOp_DIFF_DELETE},
	}
	for _, tt := range tests {
		got := opKindToDiffOp(tt.input)
		if got != tt.want {
			t.Errorf("opKindToDiffOp(%v) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestSpecImage(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`{"image":"ubuntu-22.04","cpu":2}`, "ubuntu-22.04"},
		{`{"cpu":2}`, ""},
		{``, ""},
		{`{"image":""}`, ""},
	}
	for _, tt := range tests {
		got := specImage(tt.input)
		if got != tt.want {
			t.Errorf("specImage(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSpecCloudInitHash_Empty(t *testing.T) {
	if got := specCloudInitHash(""); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestSpecCloudInitHash_NoCloudInit(t *testing.T) {
	if got := specCloudInitHash(`{"cpu":2}`); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestAutoPullImages_PullsFromCompose(t *testing.T) {
	// Serve a fake image file over HTTP.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake-qcow2-data"))
	}))
	defer ts.Close()

	s := testServer(t)
	tmpDir := t.TempDir()
	s.images = image.NewStore(tmpDir)
	if err := s.images.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	f := &compose.File{
		Images: map[string]compose.ImageDef{
			"myimg": {Source: ts.URL + "/myimg.qcow2", Format: "qcow2"},
		},
		VMs: map[string]compose.VMDef{
			"web": {Image: "myimg"},
		},
	}

	ctx := context.Background()
	stream := &mockDeployStream{ctx: ctx}

	if err := s.autoPullImages(ctx, f, stream); err != nil {
		t.Fatalf("autoPullImages: %v", err)
	}

	// Image should now exist on disk.
	if !s.images.ImageExists("myimg") {
		t.Error("expected image to exist after auto-pull")
	}

	// Stream should have received progress updates.
	if len(stream.sent) == 0 {
		t.Error("expected deploy progress messages for pull")
	}
	foundPull := false
	for _, p := range stream.sent {
		if p.Phase == "pull-image" {
			foundPull = true
		}
	}
	if !foundPull {
		t.Error("expected pull-image phase in progress")
	}
}

func TestAutoPullImages_SkipsExisting(t *testing.T) {
	s := testServer(t)
	tmpDir := t.TempDir()
	s.images = image.NewStore(tmpDir)
	if err := s.images.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Pre-create the image file so it already exists.
	if err := os.WriteFile(s.images.ImagePath("existing"), []byte("data"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f := &compose.File{
		Images: map[string]compose.ImageDef{
			"existing": {Source: "http://should-not-be-called/img.qcow2"},
		},
		VMs: map[string]compose.VMDef{
			"web": {Image: "existing"},
		},
	}

	ctx := context.Background()
	stream := &mockDeployStream{ctx: ctx}

	if err := s.autoPullImages(ctx, f, stream); err != nil {
		t.Fatalf("autoPullImages: %v", err)
	}

	// No progress should be sent — image already existed.
	if len(stream.sent) != 0 {
		t.Errorf("expected no progress for existing image, got %d messages", len(stream.sent))
	}
}

func TestAutoPullImages_NoSourceFallsThrough(t *testing.T) {
	s := testServer(t)
	tmpDir := t.TempDir()
	s.images = image.NewStore(tmpDir)
	if err := s.images.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Image referenced by VM but not in compose images: section.
	f := &compose.File{
		VMs: map[string]compose.VMDef{
			"web": {Image: "missing"},
		},
	}

	ctx := context.Background()
	stream := &mockDeployStream{ctx: ctx}

	// Should not error — validateDeployDependencies handles the missing image.
	if err := s.autoPullImages(ctx, f, stream); err != nil {
		t.Fatalf("autoPullImages: %v", err)
	}

	if len(stream.sent) != 0 {
		t.Errorf("expected no progress, got %d messages", len(stream.sent))
	}
}
