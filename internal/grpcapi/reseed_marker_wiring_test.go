package grpcapi

import (
	"context"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// chunkStream serves a fixed list of dump chunks and then EOF.
type chunkStream struct {
	chunks [][]byte
	i      int
}

func (c *chunkStream) Recv() (*pb.StateDumpChunk, error) {
	if c.i >= len(c.chunks) {
		return nil, io.EOF
	}
	c.i++
	return &pb.StateDumpChunk{Data: c.chunks[c.i-1]}, nil
}
func (c *chunkStream) Header() (metadata.MD, error) { return nil, nil }
func (c *chunkStream) Trailer() metadata.MD         { return nil }
func (c *chunkStream) CloseSend() error             { return nil }
func (c *chunkStream) Context() context.Context     { return context.Background() }
func (c *chunkStream) SendMsg(any) error            { return nil }
func (c *chunkStream) RecvMsg(any) error            { return nil }

// dumpServingSource serves a valid (empty) operator dump and a sensitive dump
// the caller chooses, so a test can fail the reseed at the exact step the marker
// exists to cover.
type dumpServingSource struct {
	*fakeReseedSource
	sensitiveChunks [][]byte
}

func (d *dumpServingSource) StreamStateDump(context.Context, *emptypb.Empty, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.StateDumpChunk], error) {
	return &chunkStream{}, nil
}

func (d *dumpServingSource) StreamSensitiveStateDump(context.Context, *pb.SensitiveStateRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.StateDumpChunk], error) {
	return &chunkStream{chunks: d.sensitiveChunks}, nil
}

// This is the defect. The reseed discards this node's state, restores users and
// their password hashes, and then fails restoring user_2fa. Before the marker,
// the node came back serving logins with an empty user_2fa and every enrolled
// account reachable by password alone.
//
// It drives the real ReseedHost rather than the marker calls directly: the three
// previous wiring bugs in this branch all passed a test that called the helper
// and never went through the entry point.
func TestReseedHost_AFailedSensitiveMergeLeavesTheNodeMarked(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	for _, h := range []corrosion.HostRecord{
		{Name: "test-host", Address: "10.0.0.1", State: "active"},
		{Name: "peer1", Address: "10.0.0.2", State: "active"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	if err := corrosion.IsolateHost(ctx, s.db, "peer1", "test-host", "schema_forward"); err != nil {
		t.Fatalf("IsolateHost: %v", err)
	}

	// Fit source, serves an empty operator dump, then garbage for the sensitive
	// lane so MergeSensitiveStateBytesLWW fails on decompress — the step after
	// the password hashes are already back.
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &dumpServingSource{
			fakeReseedSource: &fakeReseedSource{
				ping: &pb.PingResponse{SchemaVersion: int32(corrosion.CurrentSchemaVersion)},
			},
			sensitiveChunks: [][]byte{[]byte("not a gzip payload")},
		}, func() {}, nil
	}

	_, err := s.ReseedHost(ctx, &pb.ReseedHostRequest{
		Name: "test-host", Source: "peer1", DrivenByPeer: "peer1",
	})
	if err == nil {
		t.Fatal("a reseed whose sensitive merge failed reported success")
	}

	incomplete, source, rerr := s.db.ReseedIncomplete(ctx)
	if rerr != nil {
		t.Fatalf("ReseedIncomplete: %v", rerr)
	}
	if !incomplete {
		t.Fatal("the reseed deleted this node's sensitive state, failed to restore it, and left " +
			"NO marker — the node will serve logins with an empty user_2fa and every enrolled " +
			"account is reachable with a password alone")
	}
	if source != "peer1" {
		t.Errorf("marker source = %q, want peer1", source)
	}

	// And the gate actually bites, through the real interceptor.
	if _, gerr := s.UnaryAuthInterceptor(ctx, nil,
		&grpc.UnaryServerInfo{FullMethod: "/litevirt.v1.LiteVirt/Login"},
		func(context.Context, interface{}) (interface{}, error) { return nil, nil }); gerr == nil {
		t.Error("Login is still served after a reseed that failed to restore the sensitive tables")
	} else if !strings.Contains(gerr.Error(), "peer1") {
		t.Errorf("refusal = %q; it must name the source to repeat the reseed from", gerr)
	}
}

// A reseed refused at the preflight discarded nothing, so it must leave no
// marker: the node is healthy and must keep serving logins.
func TestReseedHost_ARefusedPreflightLeavesNoMarker(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	for _, h := range []corrosion.HostRecord{
		{Name: "test-host", Address: "10.0.0.1", State: "active"},
		{Name: "peer1", Address: "10.0.0.2", State: "active"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	if err := corrosion.IsolateHost(ctx, s.db, "peer1", "test-host", "schema_forward"); err != nil {
		t.Fatalf("IsolateHost: %v", err)
	}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &fakeReseedSource{
			ping: &pb.PingResponse{SchemaVersion: int32(corrosion.CurrentSchemaVersion) - 1},
		}, func() {}, nil
	}

	if _, err := s.ReseedHost(ctx, &pb.ReseedHostRequest{
		Name: "test-host", Source: "peer1", DrivenByPeer: "peer1",
	}); err == nil {
		t.Fatal("a reseed from an older-schema source must be refused")
	}

	incomplete, _, rerr := s.db.ReseedIncomplete(ctx)
	if rerr != nil {
		t.Fatalf("ReseedIncomplete: %v", rerr)
	}
	if incomplete {
		t.Error("a reseed that discarded nothing left the node marked incomplete, " +
			"which needlessly refuses every login on a healthy node")
	}
}

// The positive half of the same property: a reseed that discards the
// secret-bearing tables must put the SOURCE's rows back. The tests above pin
// what happens when the restore fails; this one pins that it happens at all.
// Without it, dropping the sensitive fetch-and-merge from ReseedHost leaves a
// node with user_2fa empty and only a failed-merge test to notice, and that
// test reads a missing merge as a merge that did not fail.
func TestReseedHost_RestoresTheSourcesSecrets(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	for _, h := range []corrosion.HostRecord{
		{Name: "test-host", Address: "10.0.0.1", State: "active"},
		{Name: "peer1", Address: "10.0.0.2", State: "active"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	if err := corrosion.IsolateHost(ctx, s.db, "peer1", "test-host", "schema_forward"); err != nil {
		t.Fatalf("IsolateHost: %v", err)
	}
	// What the quarantine holds: a factor only this node has.
	if err := corrosion.InsertUser2FA(ctx, s.db, corrosion.User2FARecord{
		Username: "mallory", Method: "totp", Secret: "quarantined", Label: "q",
	}); err != nil {
		t.Fatalf("InsertUser2FA mallory: %v", err)
	}

	// The source's secret-bearing state: carol is enrolled there.
	src, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })
	if err := corrosion.InitSchema(ctx, src); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertUser2FA(ctx, src, corrosion.User2FARecord{
		Username: "carol", Method: "totp", Secret: "enrolled", Label: "phone",
	}); err != nil {
		t.Fatalf("InsertUser2FA carol: %v", err)
	}

	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &dumpServingSource{
			fakeReseedSource: &fakeReseedSource{
				ping: &pb.PingResponse{SchemaVersion: int32(corrosion.CurrentSchemaVersion)},
			},
			sensitiveChunks: [][]byte{src.DumpSensitiveStateBytes()},
		}, func() {}, nil
	}

	// The double reports no digests, so convergence is not certified and the
	// call returns an error. The restore happens before that point, which is
	// what is asserted here.
	_, _ = s.ReseedHost(ctx, &pb.ReseedHostRequest{
		Name: "test-host", Source: "peer1", DrivenByPeer: "peer1",
	})

	carol, err := corrosion.ListUser2FA(ctx, s.db, "carol")
	if err != nil {
		t.Fatalf("ListUser2FA carol: %v", err)
	}
	if len(carol) == 0 {
		t.Fatal("the reseed discarded user_2fa and did not restore the source's rows: carol is " +
			"enrolled on the source and reads as having no second factor here")
	}
	mallory, err := corrosion.ListUser2FA(ctx, s.db, "mallory")
	if err != nil {
		t.Fatalf("ListUser2FA mallory: %v", err)
	}
	if len(mallory) != 0 {
		t.Error("a factor that existed only in the quarantine survived the reseed")
	}
	if incomplete, _, _ := s.db.ReseedIncomplete(ctx); incomplete {
		t.Error("the sensitive merge landed but the login gate is still closed")
	}
}
