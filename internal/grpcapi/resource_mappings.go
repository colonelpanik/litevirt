package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Resource mappings (#14) are cluster-wide aliases for equivalent passthrough
// devices on one or more hosts. A VM requesting a device by mapping name can be
// placed on / migrated to any host registered under that mapping. The rows are
// CRDT-replicated, so any daemon serves a consistent view.

func toPbResourceMapping(m corrosion.ResourceMappingRecord) *pb.ResourceMapping {
	out := &pb.ResourceMapping{Name: m.Name, Description: m.Description}
	for _, d := range m.Devices {
		out.Devices = append(out.Devices, &pb.ResourceMappingDevice{
			HostName: d.HostName, Address: d.Address, Vendor: d.Vendor, Device: d.Device,
		})
	}
	return out
}

func (s *Server) CreateResourceMapping(ctx context.Context, req *pb.CreateResourceMappingRequest) (*pb.ResourceMapping, error) {
	if err := s.RequirePerm(ctx, "/", "resourcemap.write", "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "mapping name required")
	}
	if err := corrosion.CreateResourceMapping(ctx, s.db, req.Name, req.Description); err != nil {
		return nil, status.Errorf(codes.Internal, "create resource mapping: %v", err)
	}
	slog.Info("resource mapping created", "name", req.Name)
	m, err := corrosion.GetResourceMapping(ctx, s.db, req.Name)
	if err != nil || m == nil {
		return &pb.ResourceMapping{Name: req.Name, Description: req.Description}, nil
	}
	return toPbResourceMapping(*m), nil
}

func (s *Server) ListResourceMappings(ctx context.Context, _ *pb.ListResourceMappingsRequest) (*pb.ListResourceMappingsResponse, error) {
	if err := s.RequirePerm(ctx, "/", "resourcemap.read", "viewer"); err != nil {
		return nil, err
	}
	mappings, err := corrosion.ListResourceMappings(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list resource mappings: %v", err)
	}
	resp := &pb.ListResourceMappingsResponse{}
	for _, m := range mappings {
		resp.Mappings = append(resp.Mappings, toPbResourceMapping(m))
	}
	return resp, nil
}

func (s *Server) DeleteResourceMapping(ctx context.Context, req *pb.DeleteResourceMappingRequest) (*emptypb.Empty, error) {
	if err := s.RequirePerm(ctx, "/", "resourcemap.write", "operator"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteResourceMapping(ctx, s.db, req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete resource mapping: %v", err)
	}
	slog.Info("resource mapping deleted", "name", req.Name)
	return &emptypb.Empty{}, nil
}

func (s *Server) AddMappingDevice(ctx context.Context, req *pb.AddMappingDeviceRequest) (*pb.ResourceMapping, error) {
	if err := s.RequirePerm(ctx, "/", "resourcemap.write", "operator"); err != nil {
		return nil, err
	}
	if req.Mapping == "" || req.Address == "" {
		return nil, status.Error(codes.InvalidArgument, "mapping and address required")
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	if err := corrosion.AddMappingDevice(ctx, s.db, req.Mapping, host, req.Address, req.Vendor, req.Device); err != nil {
		return nil, status.Errorf(codes.Internal, "add mapping device: %v", err)
	}
	slog.Info("resource mapping device added", "mapping", req.Mapping, "host", host, "address", req.Address)
	m, err := corrosion.GetResourceMapping(ctx, s.db, req.Mapping)
	if err != nil || m == nil {
		return nil, status.Errorf(codes.Internal, "reload mapping: %v", err)
	}
	return toPbResourceMapping(*m), nil
}

func (s *Server) RemoveMappingDevice(ctx context.Context, req *pb.RemoveMappingDeviceRequest) (*pb.ResourceMapping, error) {
	if err := s.RequirePerm(ctx, "/", "resourcemap.write", "operator"); err != nil {
		return nil, err
	}
	host := req.Host
	if host == "" {
		host = s.hostName
	}
	if err := corrosion.RemoveMappingDevice(ctx, s.db, req.Mapping, host, req.Address); err != nil {
		return nil, status.Errorf(codes.Internal, "remove mapping device: %v", err)
	}
	slog.Info("resource mapping device removed", "mapping", req.Mapping, "host", host, "address", req.Address)
	m, err := corrosion.GetResourceMapping(ctx, s.db, req.Mapping)
	if err != nil || m == nil {
		return &pb.ResourceMapping{Name: req.Mapping}, nil
	}
	return toPbResourceMapping(*m), nil
}
