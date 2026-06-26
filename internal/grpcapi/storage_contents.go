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
	"github.com/litevirt/litevirt/internal/safename"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// maxPoolUploadBytes caps a single pool-content upload stream so a client can't
// fill the host disk. Generous (matches the restore ceiling) since legitimate
// ISOs/images are large.
const maxPoolUploadBytes int64 = 2 << 40 // 2 TiB

// poolContentRBACPath validates a pool name and returns its RBAC path. Building
// the path only through here keeps a malformed pool name out of the auth path.
func poolContentRBACPath(pool string) (string, error) {
	if err := safename.ValidatePoolName(pool); err != nil {
		return "", err
	}
	return "/storage/pools/" + pool, nil
}

// ListStoragePoolContents lists the files in a file-based storage pool (used by
// the UI content browser to pick ISOs). Block-backed pools (ceph/iscsi/zfs/
// lvm-thin) return empty — they have no plain-file directory. Forwards to the
// pool's owning host, since the files live on that host's filesystem.
func (s *Server) ListStoragePoolContents(ctx context.Context, req *pb.ListStoragePoolContentsRequest) (*pb.ListStoragePoolContentsResponse, error) {
	if req.PoolName == "" {
		return nil, status.Error(codes.InvalidArgument, "pool_name required")
	}
	rbacPath, err := poolContentRBACPath(req.PoolName)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := s.RequirePerm(ctx, rbacPath, "storage.content.read", "viewer"); err != nil {
		return nil, err
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
	if req.PoolName == "" || req.Filename == "" {
		return nil, status.Error(codes.InvalidArgument, "pool_name and filename required")
	}
	rbacPath, err := poolContentRBACPath(req.PoolName)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := s.RequirePerm(ctx, rbacPath, "storage.content.write", "operator"); err != nil {
		return nil, err
	}
	if err := safename.ValidateName(req.Filename); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "filename: %v", err)
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
	target, err := safename.SafeJoin(dir, req.Filename)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// os.Remove deletes a symlink itself (not its target), so this can't be
	// redirected to delete an arbitrary file outside the pool.
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return nil, status.Errorf(codes.Internal, "delete: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// UploadStoragePoolContent streams a file into a file-based pool. The first
// message carries pool_name/host/filename; the rest carry chunks. Forwards the
// whole stream to the pool's owning host when it isn't local.
func (s *Server) UploadStoragePoolContent(stream pb.LiteVirt_UploadStoragePoolContentServer) error {
	ctx := stream.Context()

	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "no data: %v", err)
	}
	if first.PoolName == "" || first.Filename == "" {
		return status.Error(codes.InvalidArgument, "pool_name and filename required")
	}
	rbacPath, err := poolContentRBACPath(first.PoolName)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := s.RequirePerm(ctx, rbacPath, "storage.content.write", "operator"); err != nil {
		return err
	}
	if err := safename.ValidateName(first.Filename); err != nil {
		return status.Errorf(codes.InvalidArgument, "filename: %v", err)
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
		if total+int64(len(b)) > maxPoolUploadBytes {
			return status.Errorf(codes.InvalidArgument, "upload exceeds %d-byte ceiling", maxPoolUploadBytes)
		}
		n, err := tmp.Write(b)
		total += int64(n)
		return err
	}
	if err := writeChunk(first.Chunk); err != nil {
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
		if err := writeChunk(msg.Chunk); err != nil {
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return status.Errorf(codes.Internal, "close: %v", err)
	}
	dest, err := safename.SafeJoin(dir, first.Filename)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// Don't clobber/write through a symlink an admin may have placed at dest.
	if fi, lerr := os.Lstat(dest); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		return status.Errorf(codes.FailedPrecondition, "destination %q is a symlink", first.Filename)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return status.Errorf(codes.Internal, "finalize: %v", err)
	}
	return stream.SendAndClose(&pb.UploadStoragePoolContentResponse{Path: dest, SizeBytes: total})
}
