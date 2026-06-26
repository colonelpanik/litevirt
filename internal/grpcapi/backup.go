package grpcapi

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/safename"
)

// maxRestoreBytes is a sanity ceiling on a single streamed write (image import)
// so a client can't write until the disk fills. Generous for real disks.
const maxRestoreBytes int64 = 2 << 40 // 2 TiB

// validRestoreName rejects names that would let filepath.Join escape dataDir.
// It delegates to internal/safename, the single source of truth for the safe
// name charset (letters, digits, '_', '.', '-'; no '/', no '.'/'..').
func validRestoreName(name string) bool {
	return safename.ValidateName(name) == nil
}

// validResourceName enforces the same safe charset on user-supplied resource
// names rendered into shell/config templates run as root (e.g. load-balancer
// and backend names in the HAProxy/keepalived configs). Same rule as
// validRestoreName; named generically because it guards more than restores.
func validResourceName(name string) bool {
	return validRestoreName(name)
}

// BackupVM is DEPRECATED. The raw full-disk stream wrote/read a whole disk over
// the gRPC stream with only a broad role check. It is superseded by the
// snapshot-based backup path (deduplicated, incremental, repo-backed), which is
// project-RBAC-scoped and quota-aware. The RPC now returns Unimplemented.
func (s *Server) BackupVM(req *pb.BackupVMRequest, stream pb.LiteVirt_BackupVMServer) error {
	return status.Error(codes.Unimplemented,
		"raw full-disk backup is deprecated; use snapshot backup (`lv backup snapshot` — incremental, deduplicated, to a backup repo) instead")
}

// RestoreVM is DEPRECATED alongside BackupVM. Use the repo-backed restore paths:
// `lv restore-from` (materialize a disk from a manifest) or `lv restore-live`
// (boot against an NBD-backed overlay). The RPC now returns Unimplemented.
func (s *Server) RestoreVM(stream pb.LiteVirt_RestoreVMServer) error {
	return status.Error(codes.Unimplemented,
		"raw full-disk restore is deprecated; use `lv restore-from` or `lv restore-live` (from a backup repo) instead")
}
