package grpcapi

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/webhook"
)

// StreamEvents streams ClusterEvents to the caller until the connection drops.
// Events come from two sources:
//  1. Local event bus (real-time events from this host)
//  2. Audit log table (cluster-wide events replicated via Corrosion CRDT)
//
// This provides cluster-wide visibility without requiring cross-host event forwarding.
func (s *Server) StreamEvents(req *pb.StreamEventsRequest, stream grpc.ServerStreamingServer[pb.ClusterEvent]) error {
	if err := RequireRole(stream.Context(), "viewer"); err != nil {
		return err
	}
	ch, unsub := s.events.Subscribe()
	defer unsub()

	// Build an optional allow-set for filtering.
	filter := map[string]bool{}
	for _, t := range req.EventTypes {
		filter[t] = true
	}

	// Track the last audit / vm_event timestamp we've seen to avoid duplicates.
	lastAuditTS := time.Now().UTC().Format(time.RFC3339)
	lastVMEventTS := time.Now().UTC().Format(time.RFC3339Nano)

	// Poll audit log periodically for cluster-wide events from other hosts.
	auditTicker := time.NewTicker(5 * time.Second)
	defer auditTicker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return nil

		case e, ok := <-ch:
			if !ok {
				return nil
			}
			if len(filter) > 0 && !filter[e.Action] {
				continue
			}
			if err := stream.Send(&pb.ClusterEvent{
				Action:    e.Action,
				Target:    e.Target,
				Detail:    e.Detail,
				Username:  e.Username,
				Timestamp: timestamppb.New(e.Timestamp),
			}); err != nil {
				return err
			}

		case <-auditTicker.C:
			// Fetch recent audit entries from other hosts since last poll.
			rows, err := s.db.Query(stream.Context(),
				`SELECT timestamp, username, host_name, action, target, detail
				 FROM audit_log
				 WHERE timestamp > ? AND host_name != ?
				 ORDER BY timestamp ASC LIMIT 50`,
				lastAuditTS, s.hostName)
			if err != nil {
				continue
			}
			for _, r := range rows {
				action := r.String("action")
				if len(filter) > 0 && !filter[action] {
					continue
				}
				ts := r.String("timestamp")
				parsed, _ := time.Parse(time.RFC3339, ts)
				detail := r.String("detail")
				if host := r.String("host_name"); host != "" {
					detail = "[" + host + "] " + detail
				}
				if err := stream.Send(&pb.ClusterEvent{
					Action:    action,
					Target:    r.String("target"),
					Detail:    detail,
					Username:  r.String("username"),
					Timestamp: timestamppb.New(parsed),
				}); err != nil {
					return err
				}
				lastAuditTS = ts
			}

			// Also surface other hosts' per-VM events (vm_events is
			// replicated, like audit_log). Same host_name != self dedup —
			// our own emits already came through the in-memory bus above.
			vrows, verr := s.db.Query(stream.Context(),
				`SELECT ts, vm_name, host_name, type, detail FROM vm_events
				 WHERE ts > ? AND host_name != ?
				 ORDER BY ts ASC LIMIT 50`,
				lastVMEventTS, s.hostName)
			if verr != nil {
				continue
			}
			for _, r := range vrows {
				action := r.String("type")
				if len(filter) > 0 && !filter[action] {
					continue
				}
				ts := r.String("ts")
				parsed, _ := time.Parse(time.RFC3339Nano, ts)
				detail := r.String("detail")
				if host := r.String("host_name"); host != "" {
					detail = "[" + host + "] " + detail
				}
				if err := stream.Send(&pb.ClusterEvent{
					Action:    action,
					Target:    r.String("vm_name"),
					Detail:    detail,
					Timestamp: timestamppb.New(parsed),
				}); err != nil {
					return err
				}
				lastVMEventTS = ts
			}
		}
	}
}

// publish emits a cluster event and records it in the audit log.
func (s *Server) publish(action, target, detail string) {
	webhook.Send(context.Background(), s.webhookURL, webhook.Payload{
		Event:  action,
		Detail: detail,
	})
	s.events.Publish(events.Event{
		Action: action,
		Target: target,
		Detail: detail,
	})
}

// ListAuditLog returns recent audit log entries.
func (s *Server) ListAuditLog(ctx context.Context, req *pb.ListAuditLogRequest) (*pb.ListAuditLogResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	limit := int(req.Limit)
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	// Optional filters. action supports a trailing-* prefix glob (e.g. "sg.*")
	// translated to SQL LIKE; everything else is an exact match.
	var conds []string
	var args []interface{}
	if req.Target != "" {
		conds, args = append(conds, "target = ?"), append(args, req.Target)
	}
	if req.Action != "" {
		if strings.HasSuffix(req.Action, "*") {
			conds, args = append(conds, "action LIKE ?"), append(args, strings.TrimSuffix(req.Action, "*")+"%")
		} else {
			conds, args = append(conds, "action = ?"), append(args, req.Action)
		}
	}
	if req.User != "" {
		conds, args = append(conds, "username = ?"), append(args, req.User)
	}
	if req.Since != "" {
		conds, args = append(conds, "timestamp >= ?"), append(args, req.Since)
	}
	if req.Until != "" {
		conds, args = append(conds, "timestamp <= ?"), append(args, req.Until)
	}
	q := `SELECT timestamp, username, host_name, action, target, detail, result FROM audit_log`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY timestamp DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	resp := &pb.ListAuditLogResponse{}
	for _, r := range rows {
		resp.Entries = append(resp.Entries, &pb.AuditEntry{
			Timestamp: r.String("timestamp"),
			Username:  r.String("username"),
			HostName:  r.String("host_name"),
			Action:    r.String("action"),
			Target:    r.String("target"),
			Detail:    r.String("detail"),
			Result:    r.String("result"),
		})
	}
	return resp, nil
}

// audit records an action in the audit_log table, attributed to the caller.
// Errors are logged but not propagated.
func (s *Server) audit(ctx context.Context, action, target, detail, result string) {
	s.auditAs(ctx, callerUsername(ctx), action, target, detail, result)
}

// auditAs records an action attributed to an explicit actor rather than the
// transport caller. It exists for cross-node operations forwarded over peer
// mTLS: the peer authenticates as the bearerless "admin" identity, so a plain
// audit on the target would mis-attribute the write to "admin" instead of the
// operator who initiated it. The initiating principal is carried to the target
// in trusted peer-mTLS metadata and passed here.
func (s *Server) auditAs(ctx context.Context, actor, action, target, detail, result string) {
	rec := corrosion.AuditRecord{
		ID:       newID(),
		Username: actor,
		HostName: s.hostName,
		Action:   action,
		Target:   target,
		Detail:   detail,
		Result:   result,
	}
	if err := corrosion.InsertAuditLog(ctx, s.db, rec); err != nil {
		slog.Warn("audit log insert failed", "action", action, "error", err)
	}
}
