package grpcapi

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ListStoragePoolContents lists the files in a file-based storage pool (used by
// the UI content browser to pick ISOs). Block-backed pools (ceph/iscsi/zfs/
// lvm-thin) return empty — they have no plain-file directory. Forwards to the
// pool's owning host, since the files live on that host's filesystem.
func (s *Server) ListStoragePoolContents(ctx context.Context, req *pb.ListStoragePoolContentsRequest) (*pb.ListStoragePoolContentsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.PoolName == "" {
		return nil, status.Error(codes.InvalidArgument, "pool_name required")
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.PoolName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup pool: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.PoolName, host)
	}

	// Files live on the owning host — forward there if it isn't us.
	if host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		return client.ListStoragePoolContents(ctx, req)
	}

	if !isFileBasedDriver(rec.Driver) {
		// Block-backed pool: no browsable file directory.
		return &pb.ListStoragePoolContentsResponse{}, nil
	}
	dir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target})
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "resolve pool dir: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return &pb.ListStoragePoolContentsResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "read pool dir: %v", err)
	}

	resp := &pb.ListStoragePoolContentsResponse{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		name := e.Name()
		resp.Contents = append(resp.Contents, &pb.StoragePoolContent{
			Name:       name,
			Path:       filepath.Join(dir, name),
			SizeBytes:  info.Size(),
			ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
			IsIso:      strings.HasSuffix(strings.ToLower(name), ".iso"),
		})
	}
	sort.Slice(resp.Contents, func(i, j int) bool { return resp.Contents[i].Name < resp.Contents[j].Name })
	return resp, nil
}

// DeleteStoragePoolContent removes one file from a file-based pool (forwarded
// to the pool's owning host). Used by cross-host replication pruning.
func (s *Server) DeleteStoragePoolContent(ctx context.Context, req *pb.DeleteStoragePoolContentRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.PoolName == "" || req.Filename == "" {
		return nil, status.Error(codes.InvalidArgument, "pool_name and filename required")
	}
	if req.Filename != filepath.Base(req.Filename) || strings.Contains(req.Filename, "/") || req.Filename == ".." {
		return nil, status.Error(codes.InvalidArgument, "filename must be a base name")
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, req.PoolName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup pool: %v", err)
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "pool %q not on host %q", req.PoolName, host)
	}
	if host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		return client.DeleteStoragePoolContent(ctx, req)
	}
	if !isFileBasedDriver(rec.Driver) {
		return nil, status.Errorf(codes.FailedPrecondition, "pool %q is not file-based", req.PoolName)
	}
	dir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target})
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "resolve pool dir: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, req.Filename)); err != nil && !os.IsNotExist(err) {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// UploadStoragePoolContent streams a file into a file-based pool. The first
// message carries pool_name/host/filename; the rest carry chunks. Forwards the
// whole stream to the pool's owning host when it isn't local.
func (s *Server) UploadStoragePoolContent(stream pb.LiteVirt_UploadStoragePoolContentServer) error {
	ctx := stream.Context()
	if err := RequireRole(ctx, "operator"); err != nil {
		return err
	}

	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "no data: %v", err)
	}
	if first.PoolName == "" || first.Filename == "" {
		return status.Error(codes.InvalidArgument, "pool_name and filename required")
	}
	// Reject path traversal — filename must be a bare base name.
	if first.Filename != filepath.Base(first.Filename) || strings.Contains(first.Filename, "/") || first.Filename == ".." {
		return status.Error(codes.InvalidArgument, "filename must be a base name")
	}
	host := first.Host
	if host == "" {
		host = s.hostName
	}
	rec, ok, err := corrosion.GetStoragePool(ctx, s.db, host, first.PoolName)
	if err != nil {
		return status.Errorf(codes.Internal, "lookup pool: %v", err)
	}
	if !ok {
		return status.Errorf(codes.NotFound, "pool %q not on host %q", first.PoolName, host)
	}

	// Remote pool: proxy the stream to the owning host.
	if host != s.hostName {
		client, conn, err := s.peerClient(ctx, host)
		if err != nil {
			return status.Errorf(codes.Unavailable, "reach host %q: %v", host, err)
		}
		defer conn.Close()
		up, err := client.UploadStoragePoolContent(ctx)
		if err != nil {
			return status.Errorf(codes.Unavailable, "open upload to %q: %v", host, err)
		}
		if err := up.Send(first); err != nil {
			return err
		}
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if err := up.Send(msg); err != nil {
				return err
			}
		}
		resp, err := up.CloseAndRecv()
		if err != nil {
			return err
		}
		return stream.SendAndClose(resp)
	}

	if !isFileBasedDriver(rec.Driver) {
		return status.Errorf(codes.FailedPrecondition, "pool %q is not file-based", first.PoolName)
	}
	dir, err := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: rec.Driver, Source: rec.Source, Target: rec.Target})
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "resolve pool dir: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return status.Errorf(codes.Internal, "mkdir: %v", err)
	}
	tmp, err := os.CreateTemp(dir, ".upload-*.tmp")
	if err != nil {
		return status.Errorf(codes.Internal, "create temp: %v", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	defer tmp.Close()

	var total int64
	writeChunk := func(b []byte) error {
		if len(b) == 0 {
			return nil
		}
		n, err := tmp.Write(b)
		total += int64(n)
		return err
	}
	if err := writeChunk(first.Chunk); err != nil {
		return status.Errorf(codes.Internal, "write: %v", err)
	}
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if err := writeChunk(msg.Chunk); err != nil {
			return status.Errorf(codes.Internal, "write: %v", err)
		}
	}
	if err := tmp.Close(); err != nil {
		return status.Errorf(codes.Internal, "close: %v", err)
	}
	dest := filepath.Join(dir, first.Filename)
	if err := os.Rename(tmpName, dest); err != nil {
		return status.Errorf(codes.Internal, "finalize: %v", err)
	}
	return stream.SendAndClose(&pb.UploadStoragePoolContentResponse{Path: dest, SizeBytes: total})
}
