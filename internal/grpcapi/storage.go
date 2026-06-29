package grpcapi

import (
	"context"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func (s *Server) ListStoragePools(ctx context.Context, _ *pb.ListStoragePoolsRequest) (*pb.ListStoragePoolsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	pools, err := corrosion.ListAllStoragePools(ctx, s.db)
	if err != nil {
		return nil, err
	}

	resp := &pb.ListStoragePoolsResponse{}
	for _, p := range pools {
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
