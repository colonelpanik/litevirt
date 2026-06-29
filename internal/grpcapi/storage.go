package grpcapi

import (
	"context"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ListStoragePools returns the pools the caller may view: global pools (any
// viewer) + those owned by a project the caller can read. A legacy cluster viewer
// (no project binding) still sees all via the role fallback.
func (s *Server) ListStoragePools(ctx context.Context, _ *pb.ListStoragePoolsRequest) (*pb.ListStoragePoolsResponse, error) {
	pools, err := corrosion.ListAllStoragePools(ctx, s.db)
	if err != nil {
		return nil, err
	}

	resp := &pb.ListStoragePoolsResponse{}
	for _, p := range pools {
		if s.authorizeResourceRead(ctx, p.Project, poolRBACPathFor(p.Project, p.Name), "storage.pool.read") != nil {
			continue
		}
		resp.Pools = append(resp.Pools, storagePoolRecordToPB(p))
	}
	return resp, nil
}

func storagePoolRecordToPB(p corrosion.StoragePoolRecord) *pb.StoragePool {
	return &pb.StoragePool{
		Name:       p.Name,
		Driver:     p.Driver,
		Source:     p.Source,
		Target:     p.Target,
		Host:       p.HostName,
		TotalGib:   p.TotalBytes / (1024 * 1024 * 1024),
		UsedGib:    p.UsedBytes / (1024 * 1024 * 1024),
		TotalBytes: p.TotalBytes,
		UsedBytes:  p.UsedBytes,
		State:      p.State,
		Project:    p.Project,
	}
}

// storagePoolsForHost returns pb.StoragePool list for a given host from the DB.
func (s *Server) storagePoolsForHost(ctx context.Context, hostName string) []*pb.StoragePool {
	pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, hostName)
	if err != nil {
		return nil
	}
	result := make([]*pb.StoragePool, len(pools))
	for i, p := range pools {
		result[i] = storagePoolRecordToPB(p)
	}
	return result
}
