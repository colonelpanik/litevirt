package grpcapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
)

// notify dispatches a notification (#5) to every enabled target whose route
// matches the event kind + min-severity. Fire-and-log in goroutines — it must
// never block or fail the operation that triggered it. Safe to call with a nil
// DB (no-op). Use this from event sites (backup fail, fence, replication fail,
// quota breach).
func (s *Server) notify(ctx context.Context, n notify.Notification) {
	if s.db == nil {
		return
	}
	if n.Timestamp.IsZero() {
		n.Timestamp = time.Now().UTC()
	}
	if n.Cluster == "" {
		n.Cluster = s.hostName
	}
	routes, err := corrosion.ListNotificationRoutes(ctx, s.db)
	if err != nil || len(routes) == 0 {
		return
	}
	targets, err := corrosion.ListNotificationTargets(ctx, s.db)
	if err != nil {
		return
	}
	byID := make(map[string]corrosion.NotificationTarget, len(targets))
	for _, t := range targets {
		if t.Enabled {
			byID[t.ID] = t
		}
	}
	dispatched := map[string]bool{}
	for _, r := range routes {
		if !r.Enabled || !notify.MatchPattern(r.EventPattern, n.Kind) {
			continue
		}
		if !n.Severity.AtLeast(notify.Severity(r.MinSeverity)) {
			continue
		}
		t, ok := byID[r.TargetID]
		if !ok || dispatched[t.ID] {
			continue
		}
		dispatched[t.ID] = true
		target, terr := notify.NewTarget(t.Name, t.Type, t.Config)
		if terr != nil {
			slog.Warn("notify: bad target config", "target", t.Name, "error", terr)
			continue
		}
		go func(tg notify.Target) {
			sctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := tg.Send(sctx, n); err != nil {
				slog.Warn("notify: delivery failed", "target", tg.Name(), "kind", n.Kind, "error", err)
			}
		}(target)
	}
}

// NotifyHostFenced is the failover coordinator's OnFence callback (#5): it emits
// a host.fenced notification. A clean fence is error-severity (a host was
// forcibly taken down); a partial/manual result is a warning.
func (s *Server) NotifyHostFenced(host, method, result, detail string) {
	sev := notify.SevError
	if result != "fenced" {
		sev = notify.SevWarn
	}
	s.notify(context.Background(), notify.Notification{
		Kind: "host.fenced", Severity: sev, Subject: host,
		Detail: fmt.Sprintf("method=%s result=%s %s", method, result, detail),
	})
}

func newNotifyID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func toPbTarget(t corrosion.NotificationTarget) *pb.NotificationTarget {
	return &pb.NotificationTarget{Id: t.ID, Name: t.Name, Type: t.Type, Config: t.Config, Enabled: t.Enabled}
}

func toPbRoute(r corrosion.NotificationRoute) *pb.NotificationRoute {
	return &pb.NotificationRoute{Id: r.ID, EventPattern: r.EventPattern, TargetId: r.TargetID, MinSeverity: r.MinSeverity, Enabled: r.Enabled}
}

func (s *Server) CreateNotificationTarget(ctx context.Context, req *pb.CreateNotificationTargetRequest) (*pb.NotificationTarget, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" || req.Type == "" {
		return nil, status.Error(codes.InvalidArgument, "name and type required")
	}
	// Validate the config parses into a real target before storing.
	if _, err := notify.NewTarget(req.Name, req.Type, req.Config); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	t := corrosion.NotificationTarget{ID: newNotifyID(), Name: req.Name, Type: req.Type, Config: req.Config, Enabled: req.Enabled}
	if err := corrosion.InsertNotificationTarget(ctx, s.db, t); err != nil {
		return nil, status.Errorf(codes.Internal, "create target: %v", err)
	}
	slog.Info("notification target created", "name", t.Name, "type", t.Type)
	return toPbTarget(t), nil
}

func (s *Server) ListNotificationTargets(ctx context.Context, _ *pb.ListNotificationTargetsRequest) (*pb.ListNotificationTargetsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	targets, err := corrosion.ListNotificationTargets(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list targets: %v", err)
	}
	resp := &pb.ListNotificationTargetsResponse{}
	for _, t := range targets {
		resp.Targets = append(resp.Targets, toPbTarget(t))
	}
	return resp, nil
}

func (s *Server) DeleteNotificationTarget(ctx context.Context, req *pb.DeleteNotificationTargetRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteNotificationTarget(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete target: %v", err)
	}
	return &emptypb.Empty{}, nil
}

func (s *Server) TestNotificationTarget(ctx context.Context, req *pb.TestNotificationTargetRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	targets, err := corrosion.ListNotificationTargets(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup target: %v", err)
	}
	for _, t := range targets {
		if t.ID != req.Id {
			continue
		}
		target, terr := notify.NewTarget(t.Name, t.Type, t.Config)
		if terr != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", terr)
		}
		n := notify.Notification{
			Kind: "test.notification", Severity: notify.SevInfo, Subject: t.Name,
			Detail: "litevirt test notification", Cluster: s.hostName, Timestamp: time.Now().UTC(),
		}
		sctx, cancel := context.WithTimeout(ctx, 12*time.Second)
		defer cancel()
		if err := target.Send(sctx, n); err != nil {
			return nil, status.Errorf(codes.Unavailable, "send test: %v", err)
		}
		return &emptypb.Empty{}, nil
	}
	return nil, status.Errorf(codes.NotFound, "target %q not found", req.Id)
}

func (s *Server) CreateNotificationRoute(ctx context.Context, req *pb.CreateNotificationRouteRequest) (*pb.NotificationRoute, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.EventPattern == "" || req.TargetId == "" {
		return nil, status.Error(codes.InvalidArgument, "event_pattern and target_id required")
	}
	r := corrosion.NotificationRoute{ID: newNotifyID(), EventPattern: req.EventPattern, TargetID: req.TargetId, MinSeverity: req.MinSeverity, Enabled: req.Enabled}
	if err := corrosion.InsertNotificationRoute(ctx, s.db, r); err != nil {
		return nil, status.Errorf(codes.Internal, "create route: %v", err)
	}
	return toPbRoute(r), nil
}

func (s *Server) ListNotificationRoutes(ctx context.Context, _ *pb.ListNotificationRoutesRequest) (*pb.ListNotificationRoutesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	routes, err := corrosion.ListNotificationRoutes(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list routes: %v", err)
	}
	resp := &pb.ListNotificationRoutesResponse{}
	for _, r := range routes {
		resp.Routes = append(resp.Routes, toPbRoute(r))
	}
	return resp, nil
}

func (s *Server) DeleteNotificationRoute(ctx context.Context, req *pb.DeleteNotificationRouteRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteNotificationRoute(ctx, s.db, req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete route: %v", err)
	}
	return &emptypb.Empty{}, nil
}
