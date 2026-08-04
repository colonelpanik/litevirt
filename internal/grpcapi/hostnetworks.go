package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostnet"
)

// Host network configuration (schema v48, §O Tier 1).
//
// Routing model: every RPC that names a host FORWARDS to it — not only Plan
// and Apply (which read/mutate that host's local netplan state) but the intent
// writes too, so all writes to one host's rows funnel through its daemon and
// serialize against its applies under one lock. List with host_name=="" reads
// the replicated rows locally, from any node.
//
// Everything is admin-gated and audited: rewiring a host is exactly the class
// of action the audit chain exists for.

// SetHostNetworkEnv wires the apply protocol's host-side dependencies. The
// daemon passes the real system (netplan/proc); fleet tests inject a fake so
// multi-node behavior is testable without root.
func (s *Server) SetHostNetworkEnv(sys hostnet.System, advertiseIP string) {
	s.hostNetSys = sys
	s.hostNetAdvertiseIP = advertiseIP
}

func (s *Server) hostNetApplier() (*hostnet.Applier, error) {
	if s.opJournal == nil {
		return nil, status.Error(codes.Unavailable, "operation journal not wired on this host")
	}
	if s.hostNetSys == nil {
		return nil, status.Error(codes.Unavailable, "host network management not wired on this host")
	}
	return &hostnet.Applier{
		DB:          s.db,
		HostName:    s.hostName,
		AdvertiseIP: s.hostNetAdvertiseIP,
		Journal:     s.opJournal,
		Sys:         s.hostNetSys,
	}, nil
}

// RecoverHostNetworks consumes a crashed apply's journal entry on daemon
// start: previous file restored + re-applied, rows recorded rolled_back.
// Called by the daemon inside the F1 recovery barrier, before any RPC runs.
func (s *Server) RecoverHostNetworks(ctx context.Context) {
	ap, err := s.hostNetApplier()
	if err != nil {
		return // not wired on this build/host — nothing journaled either
	}
	if err := ap.Recover(ctx); err != nil {
		slog.Error("host network apply recovery failed — this host may need manual netplan attention",
			"error", err)
	}
}

func (s *Server) ListHostNetworks(ctx context.Context, req *pb.ListHostNetworksRequest) (*pb.ListHostNetworksResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	recs, err := corrosion.ListHostNetworks(ctx, s.db, req.HostName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list host networks: %v", err)
	}
	resp := &pb.ListHostNetworksResponse{}
	for _, r := range recs {
		resp.Networks = append(resp.Networks, hostNetworkToProto(r))
	}
	return resp, nil
}

func (s *Server) UpsertHostNetwork(ctx context.Context, req *pb.UpsertHostNetworkRequest) (*pb.HostNetwork, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	n := req.Network
	if n == nil || n.HostName == "" || n.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "network with host_name and name required")
	}
	if n.HostName != s.hostName {
		c, conn, err := s.peerClient(ctx, n.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward to %s: %v", n.HostName, err)
		}
		defer conn.Close()
		return c.UpsertHostNetwork(ctx, req)
	}
	unlock := s.lockVM("hostnet/" + s.hostName)
	defer unlock()
	rec := corrosion.HostNetworkRecord{
		HostName: n.HostName, Name: n.Name, Kind: n.Kind,
		Members: n.Members, VLANID: int(n.VlanId), VLANLink: n.VlanLink,
		Addressing: n.Addressing, MTU: int(n.Mtu),
		BondMode: n.BondMode, LACPRate: n.LacpRate, HashPolicy: n.HashPolicy,
	}
	// The renderer is the deep validator (names, injection, kind invariants);
	// running it here means a row that cannot render is never recorded.
	if _, err := hostnet.Render([]corrosion.HostNetworkRecord{rec}); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if err := corrosion.UpsertHostNetwork(ctx, s.db, rec); err != nil {
		s.audit(ctx, "host.network", n.HostName+"/"+n.Name, "upsert "+n.Kind, "error")
		return nil, status.Errorf(codes.Internal, "record host network intent: %v", err)
	}
	s.audit(ctx, "host.network", n.HostName+"/"+n.Name, "upsert "+n.Kind, "ok")
	out, err := corrosion.GetHostNetwork(ctx, s.db, n.HostName, n.Name)
	if err != nil || out == nil {
		return nil, status.Errorf(codes.Internal, "read back host network intent: %v", err)
	}
	return hostNetworkToProto(*out), nil
}

func (s *Server) PlanHostNetwork(ctx context.Context, req *pb.PlanHostNetworkRequest) (*pb.PlanHostNetworkResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.HostName == "" {
		return nil, status.Error(codes.InvalidArgument, "host_name required")
	}
	if req.HostName != s.hostName {
		c, conn, err := s.peerClient(ctx, req.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward to %s: %v", req.HostName, err)
		}
		defer conn.Close()
		return c.PlanHostNetwork(ctx, req)
	}
	ap, err := s.hostNetApplier()
	if err != nil {
		return nil, err
	}
	plan, err := ap.Plan(ctx)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &pb.PlanHostNetworkResponse{
		Rendered:         plan.Rendered,
		Current:          plan.Current,
		NoOp:             plan.NoOp,
		CutoffReason:     plan.CutoffReason,
		ClusterInterface: plan.ClusterIface,
		Conflicts:        plan.Conflicts,
	}, nil
}

func (s *Server) ApplyHostNetwork(ctx context.Context, req *pb.ApplyHostNetworkRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.HostName == "" {
		return nil, status.Error(codes.InvalidArgument, "host_name required")
	}
	if req.HostName != s.hostName {
		c, conn, err := s.peerClient(ctx, req.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward to %s: %v", req.HostName, err)
		}
		defer conn.Close()
		return c.ApplyHostNetwork(ctx, req)
	}
	ap, err := s.hostNetApplier()
	if err != nil {
		return nil, err
	}
	unlock := s.lockVM("hostnet/" + s.hostName)
	defer unlock()
	if err := ap.Apply(ctx, req.ForceInterface); err != nil {
		s.audit(ctx, "host.network", s.hostName, "apply", "error")
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	detail := "apply"
	if req.ForceInterface != "" {
		detail = "apply forced=" + req.ForceInterface
	}
	s.audit(ctx, "host.network", s.hostName, detail, "ok")
	slog.Info("host network configuration applied", "host", s.hostName, "forced", req.ForceInterface != "")
	return &emptypb.Empty{}, nil
}

func (s *Server) DeleteHostNetwork(ctx context.Context, req *pb.DeleteHostNetworkRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.HostName == "" || req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "host_name and name required")
	}
	if req.HostName != s.hostName {
		c, conn, err := s.peerClient(ctx, req.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "forward to %s: %v", req.HostName, err)
		}
		defer conn.Close()
		return c.DeleteHostNetwork(ctx, req)
	}
	unlock := s.lockVM("hostnet/" + s.hostName)
	defer unlock()
	if err := corrosion.DeleteHostNetwork(ctx, s.db, req.HostName, req.Name); err != nil {
		s.audit(ctx, "host.network", req.HostName+"/"+req.Name, "delete", "error")
		return nil, status.Errorf(codes.NotFound, "delete host network intent: %v", err)
	}
	// The row is tombstoned; the interface itself goes away on the NEXT apply,
	// which renders without it. Deliberate two-step — removal changes host
	// wiring and must ride the same plan/confirm path as any other change.
	s.audit(ctx, "host.network", req.HostName+"/"+req.Name, "delete (pending apply)", "ok")
	return &emptypb.Empty{}, nil
}

func hostNetworkToProto(r corrosion.HostNetworkRecord) *pb.HostNetwork {
	return &pb.HostNetwork{
		HostName: r.HostName, Name: r.Name, Kind: r.Kind,
		Members: r.Members, VlanId: int32(r.VLANID), VlanLink: r.VLANLink,
		Addressing: r.Addressing, Mtu: int32(r.MTU),
		BondMode: r.BondMode, LacpRate: r.LACPRate, HashPolicy: r.HashPolicy,
		State: r.State, Generation: r.Generation, LastError: r.LastError,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
}
