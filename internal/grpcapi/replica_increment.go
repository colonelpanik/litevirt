package grpcapi

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PushReplicaIncrement receives an incremental (or full) replica into a
// file-based pool. The first message is the header (pool/host/filename/base/
// total_size); the rest carry (offset,data) dirty extents. The new replica is a
// sparse RAW file: when base is set it is forked from that previous replica
// (server-side, no network) and only the streamed extents are patched in, so a
// plain WriteAt suffices — no qcow2 writer needed. base="" makes it a full push.
func (s *Server) PushReplicaIncrement(stream pb.LiteVirt_PushReplicaIncrementServer) error {
	ctx := stream.Context()
	// Peer-only: dirty-extent replica pushes come from a peer over host mTLS
	// (no direct operator caller). Tighter than the old RequireRole("operator").
	if err := s.requirePeerCert(ctx); err != nil {
		return err
	}
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "no header: %v", err)
	}
	if first.PoolName == "" || first.Filename == "" {
		return status.Error(codes.InvalidArgument, "pool_name and filename required")
	}
	if !isBaseName(first.Filename) || (first.Base != "" && !isBaseName(first.Base)) {
		return status.Error(codes.InvalidArgument, "filename and base must be base names")
	}
	if first.TotalSize <= 0 {
		return status.Error(codes.InvalidArgument, "total_size must be > 0")
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

	// Remote pool: proxy the whole stream to the owning host.
	if host != s.hostName {
		client, conn, perr := s.peerClient(ctx, host)
		if perr != nil {
			return status.Errorf(codes.Unavailable, "reach host %q: %v", host, perr)
		}
		defer conn.Close()
		up, perr := client.PushReplicaIncrement(ctx)
		if perr != nil {
			return status.Errorf(codes.Unavailable, "open push to %q: %v", host, perr)
		}
		if err := up.Send(first); err != nil {
			return err
		}
		for {
			msg, rerr := stream.Recv()
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				return rerr
			}
			if err := up.Send(msg); err != nil {
				return err
			}
		}
		resp, rerr := up.CloseAndRecv()
		if rerr != nil {
			return rerr
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
	if first.Base != "" {
		if _, serr := os.Stat(filepath.Join(dir, first.Base)); serr != nil {
			return status.Errorf(codes.FailedPrecondition, "base replica %q not present: %v", first.Base, serr)
		}
	}

	var written int64
	apply := func(f *os.File) error {
		// The header may itself carry a first extent (offset/data).
		if len(first.Data) > 0 {
			if _, err := f.WriteAt(first.Data, first.Offset); err != nil {
				return err
			}
			written += int64(len(first.Data))
		}
		for {
			msg, rerr := stream.Recv()
			if rerr == io.EOF {
				return nil
			}
			if rerr != nil {
				return rerr
			}
			if len(msg.Data) == 0 {
				continue
			}
			if msg.Offset < 0 || msg.Offset+int64(len(msg.Data)) > first.TotalSize {
				return status.Errorf(codes.InvalidArgument, "extent [%d,%d) out of bounds (size %d)", msg.Offset, msg.Offset+int64(len(msg.Data)), first.TotalSize)
			}
			if _, err := f.WriteAt(msg.Data, msg.Offset); err != nil {
				return err
			}
			written += int64(len(msg.Data))
		}
	}
	dest, ferr := forkRawAndApply(dir, first.Filename, first.Base, first.TotalSize, apply)
	if ferr != nil {
		return status.Errorf(codes.Internal, "apply replica: %v", ferr)
	}
	return stream.SendAndClose(&pb.PushReplicaIncrementResponse{Path: dest, BytesWritten: written})
}

// isBaseName rejects path separators / traversal so a streamed filename can't
// escape the pool directory.
func isBaseName(name string) bool {
	return name != "" && name == filepath.Base(name) && !strings.Contains(name, "/") && name != ".."
}

// forkRawAndApply materializes a new sparse RAW replica at dir/name of
// total_size bytes: when base is set it copies that previous replica forward
// (sparse, skipping zero runs) then runs apply to patch the dirty extents;
// base="" starts from an all-zero sparse file. Written atomically via a temp +
// rename so a partial transfer never leaves a half-written replica in place.
func forkRawAndApply(dir, name, base string, totalSize int64, apply func(*os.File) error) (string, error) {
	if totalSize <= 0 {
		return "", fmt.Errorf("total_size must be > 0")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".repl-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		tmp.Close() // idempotent enough: a second Close just errors, which we ignore
		if !committed {
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Truncate(totalSize); err != nil {
		return "", err
	}
	if base != "" {
		if err := sparseCopyInto(tmp, filepath.Join(dir, base)); err != nil {
			return "", err
		}
	}
	if err := apply(tmp); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, name)
	if err := os.Rename(tmpName, dest); err != nil {
		return "", err
	}
	committed = true
	return dest, nil
}

// sparseCopyInto copies srcPath into dst at matching offsets, skipping all-zero
// 1 MiB chunks so holes in the source stay holes in the destination (dst is
// pre-truncated to size). Pure file I/O — no network.
func sparseCopyInto(dst *os.File, srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	buf := make([]byte, 1<<20)
	var off int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if !allZero(buf[:n]) {
				if _, err := dst.WriteAt(buf[:n], off); err != nil {
					return err
				}
			}
			off += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
