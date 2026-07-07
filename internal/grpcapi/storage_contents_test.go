package grpcapi

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeUploadStream scripts a client-streaming Upload: msgs are returned in order by
// Recv, then io.EOF. idx records how many frames were consumed (so a denied upload
// can be shown to stop after the header frame).
type fakeUploadStream struct {
	grpc.ServerStream
	ctx  context.Context
	msgs []*pb.UploadStoragePoolContentRequest
	idx  int
	resp *pb.UploadStoragePoolContentResponse
}

func (f *fakeUploadStream) Context() context.Context { return f.ctx }
func (f *fakeUploadStream) Recv() (*pb.UploadStoragePoolContentRequest, error) {
	if f.idx >= len(f.msgs) {
		return nil, io.EOF
	}
	m := f.msgs[f.idx]
	f.idx++
	return m, nil
}
func (f *fakeUploadStream) SendAndClose(r *pb.UploadStoragePoolContentResponse) error {
	f.resp = r
	return nil
}

var _ pb.LiteVirt_UploadStoragePoolContentServer = (*fakeUploadStream)(nil)

// contentServer wires three pools on the local host: poolA (project A), poolB
// (project B), poolG (global), each a file-based local pool with its own dir.
func contentServer(t *testing.T) (s *Server, dirA, dirB, dirG string) {
	t.Helper()
	s = testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	dirA, dirB, dirG = t.TempDir(), t.TempDir(), t.TempDir()
	ctx := context.Background()
	for _, p := range []corrosion.StoragePoolRecord{
		{HostName: "test-host", Name: "poolA", Driver: "local", Target: dirA, Project: "A", State: "active"},
		{HostName: "test-host", Name: "poolB", Driver: "local", Target: dirB, Project: "B", State: "active"},
		{HostName: "test-host", Name: "poolG", Driver: "local", Target: dirG, Project: "", State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, s.db, p); err != nil {
			t.Fatalf("UpsertStoragePool %s: %v", p.Name, err)
		}
	}
	return s, dirA, dirB, dirG
}

// contentEngineAliceCtx seeds the auth engine with an Admin binding for alice scoped
// to poolA's path only (so she does NOT cover poolB), and returns alice's user ctx.
func contentEngineAliceCtx(t *testing.T, s *Server) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, "alice", "admin", "x"); err != nil {
		t.Fatalf("InsertUser: %v", err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "alice-poolA", Path: poolRBACPathFor("A", "poolA"), Role: "Admin",
		Principal: "user:alice@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	s.SetAuthEngine(engine)
	out := context.WithValue(context.Background(), ctxKeyUsername, "alice")
	return context.WithValue(out, ctxKeyRole, "admin")
}

// contentPeerCtx returns a context that requirePeerCert accepts: mTLS auth with a CN
// that is a known cluster host.
func contentPeerCtx(t *testing.T, s *Server) context.Context {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "peer1"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	ctx := context.WithValue(context.Background(), ctxKeyAuthMethod, authMethodMTLS)
	ctx = context.WithValue(ctx, ctxKeyMTLSCommonName, "peer1")
	return context.WithValue(ctx, ctxKeyPrincipalKind, principalKindPeer)
}

// TestStoragePoolContents_ProjectIsolation: a user scoped to project A may browse/
// modify A's pool but not B's.
func TestStoragePoolContents_ProjectIsolation(t *testing.T) {
	s, _, _, _ := contentServer(t)
	alice := contentEngineAliceCtx(t, s)

	if _, err := s.ListStoragePoolContents(alice, &pb.ListStoragePoolContentsRequest{PoolName: "poolA"}); err != nil {
		t.Fatalf("listing own project's pool should be allowed: %v", err)
	}
	if _, err := s.ListStoragePoolContents(alice, &pb.ListStoragePoolContentsRequest{PoolName: "poolB"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("listing another project's pool: want PermissionDenied, got %v", err)
	}
	if _, err := s.DeleteStoragePoolContent(alice, &pb.DeleteStoragePoolContentRequest{PoolName: "poolB", Filename: "x.iso"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("deleting in another project's pool: want PermissionDenied, got %v", err)
	}
}

// TestStoragePoolContents_GlobalPoolNoRegression: a plain viewer can still read a
// global (project-less) pool even with the engine active.
func TestStoragePoolContents_GlobalPoolNoRegression(t *testing.T) {
	s, _, _, _ := contentServer(t)
	_ = contentEngineAliceCtx(t, s) // engine active
	viewer := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "vv"), ctxKeyRole, "viewer")
	if _, err := s.ListStoragePoolContents(viewer, &pb.ListStoragePoolContentsRequest{PoolName: "poolG"}); err != nil {
		t.Fatalf("a viewer listing a GLOBAL pool should be allowed: %v", err)
	}
}

// TestStoragePoolContents_PeerBypassesProjectRBAC: the peer boundary — not admin role —
// is what keeps replication/auto-promote working. With an admin USER binding that does
// not cover poolB, the user is denied but a peer (host cert) is allowed.
func TestStoragePoolContents_PeerBypassesProjectRBAC(t *testing.T) {
	s, _, _, _ := contentServer(t)
	alice := contentEngineAliceCtx(t, s)
	peer := contentPeerCtx(t, s)

	if _, err := s.ListStoragePoolContents(alice, &pb.ListStoragePoolContentsRequest{PoolName: "poolB"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("user-admin not covering poolB should be denied, got %v", err)
	}
	if _, err := s.ListStoragePoolContents(peer, &pb.ListStoragePoolContentsRequest{PoolName: "poolB"}); err != nil {
		t.Fatalf("peer should be allowed on poolB, got %v", err)
	}
	if _, err := s.DeleteStoragePoolContent(peer, &pb.DeleteStoragePoolContentRequest{PoolName: "poolB", Filename: "absent.iso"}); err != nil {
		t.Fatalf("peer delete (absent file) should be allowed, got %v", err)
	}
}

// TestStoragePoolContents_UploadFirstChunkRejected: the header frame must carry no
// payload, so authorization always precedes any byte.
func TestStoragePoolContents_UploadFirstChunkRejected(t *testing.T) {
	s, _, _, _ := contentServer(t)
	peer := contentPeerCtx(t, s)
	st := &fakeUploadStream{ctx: peer, msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "poolB", Filename: "x.iso", Chunk: []byte("data")},
	}}
	if err := s.UploadStoragePoolContent(st); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a first frame carrying chunk data must be InvalidArgument, got %v", err)
	}
}

// TestStoragePoolContents_DeniedUploadWritesNothing: a denied upload creates no temp
// file and does not drain past the header frame.
func TestStoragePoolContents_DeniedUploadWritesNothing(t *testing.T) {
	s, _, dirB, _ := contentServer(t)
	alice := contentEngineAliceCtx(t, s)
	st := &fakeUploadStream{ctx: alice, msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "poolB", Filename: "x.iso"},
		{Chunk: []byte("payload")},
	}}
	if err := s.UploadStoragePoolContent(st); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	ents, _ := os.ReadDir(dirB)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".upload-") {
			t.Fatalf("denied upload left a temp file: %s", e.Name())
		}
	}
	if st.idx != 1 {
		t.Errorf("denied upload consumed %d frames; should stop after the header frame", st.idx)
	}
}

// TestStoragePoolContents_PeerUploadSucceeds: a peer upload to a project-owned pool
// streams to disk.
func TestStoragePoolContents_PeerUploadSucceeds(t *testing.T) {
	s, _, dirB, _ := contentServer(t)
	peer := contentPeerCtx(t, s)
	st := &fakeUploadStream{ctx: peer, msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "poolB", Filename: "image.iso"},
		{Chunk: []byte("hello ")},
		{Chunk: []byte("world")},
	}}
	if err := s.UploadStoragePoolContent(st); err != nil {
		t.Fatalf("peer upload should succeed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dirB, "image.iso"))
	if err != nil || string(got) != "hello world" {
		t.Fatalf("uploaded file = %q err=%v", got, err)
	}
}

// TestStoragePoolContents_PeerStillValidates: the peer bypass skips ONLY tenant RBAC —
// pool-name/filename validation still applies.
func TestStoragePoolContents_PeerStillValidates(t *testing.T) {
	s, _, _, _ := contentServer(t)
	peer := contentPeerCtx(t, s)

	if _, err := s.DeleteStoragePoolContent(peer, &pb.DeleteStoragePoolContentRequest{PoolName: "poolB", Filename: "../escape"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("peer must still reject a path-traversal filename, got %v", err)
	}
	st := &fakeUploadStream{ctx: peer, msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "bad/name", Filename: "x.iso"},
	}}
	if err := s.UploadStoragePoolContent(st); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("peer must still reject an invalid pool name, got %v", err)
	}
}
