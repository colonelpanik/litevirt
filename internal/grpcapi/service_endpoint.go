// anycast service-endpoint RPC handlers.
//
// service_endpoints map a logical name to N (ip, region) pairs. The
// embedded DNS server reads this table on every query and rotates the
// answers so a multi-region frontend surfaces under one record without
// requiring an external anycast routing layer.

package grpcapi

import (
	"context"
	"net"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func (s *Server) UpsertServiceEndpoint(ctx context.Context, req *pb.UpsertServiceEndpointRequest) (*pb.ServiceEndpoint, error) {
	if err := s.RequirePerm(ctx, "/projects/_default/dns", "dns.write", "operator"); err != nil {
		return nil, err
	}
	if req.ServiceName == "" || req.Ip == "" {
		return nil, status.Error(codes.InvalidArgument, "service_name and ip required")
	}
	if net.ParseIP(req.Ip) == nil {
		return nil, status.Errorf(codes.InvalidArgument, "ip %q is not a valid address", req.Ip)
	}
	rec := corrosion.ServiceEndpoint{
		ServiceName: req.ServiceName,
		IP:          req.Ip,
		Region:      req.Region,
		Weight:      int(req.Weight),
	}
	if err := corrosion.UpsertServiceEndpoint(ctx, s.db, rec); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert endpoint: %v", err)
	}
	return endpointToPB(rec), nil
}

func (s *Server) ListServiceEndpoints(ctx context.Context, req *pb.ListServiceEndpointsRequest) (*pb.ListServiceEndpointsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rows, err := corrosion.ListServiceEndpoints(ctx, s.db, req.ServiceName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list endpoints: %v", err)
	}
	resp := &pb.ListServiceEndpointsResponse{}
	for _, r := range rows {
		resp.Endpoints = append(resp.Endpoints, endpointToPB(r))
	}
	return resp, nil
}

func (s *Server) DeleteServiceEndpoint(ctx context.Context, req *pb.DeleteServiceEndpointRequest) (*emptypb.Empty, error) {
	if err := s.RequirePerm(ctx, "/projects/_default/dns", "dns.write", "operator"); err != nil {
		return nil, err
	}
	if req.ServiceName == "" || req.Ip == "" {
		return nil, status.Error(codes.InvalidArgument, "service_name and ip required")
	}
	if err := corrosion.DeleteServiceEndpoint(ctx, s.db, req.ServiceName, req.Ip); err != nil {
		return nil, status.Errorf(codes.Internal, "delete endpoint: %v", err)
	}
	return &emptypb.Empty{}, nil
}

func endpointToPB(e corrosion.ServiceEndpoint) *pb.ServiceEndpoint {
	w := e.Weight
	if w <= 0 {
		w = 1
	}
	return &pb.ServiceEndpoint{
		ServiceName: e.ServiceName,
		Ip:          e.IP,
		Region:      e.Region,
		Weight:      int32(w),
	}
}
