package grpcapi

import (
	"context"
	"log/slog"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
)

// recordVMEvent is the single sink for per-VM operational activity. It (1)
// persists a durable, cluster-replicated row in vm_events, and (2) publishes to
// the in-memory bus for same-host real-time SSE. Cluster-wide visibility comes
// from the replicated table (StreamEvents polls it), not from the bus.
//
// Best-effort: persistence/publish failures are logged, never propagated —
// emitting an event must never fail the VM operation that triggered it.
// result is "ok" (default) or "error"; severity is derived from result.
// Internal only — no external webhook in this pass.
func (s *Server) recordVMEvent(ctx context.Context, vmName, evType, result, detail string) {
	if vmName == "" || evType == "" {
		return
	}
	if result == "" {
		result = "ok"
	}
	severity := "info"
	if result == "error" {
		severity = "error"
	}
	if s.db != nil {
		rec := corrosion.VMEventRecord{
			ID:       newID(),
			VMName:   vmName,
			HostName: s.hostName,
			Type:     evType,
			Result:   result,
			Severity: severity,
			Detail:   detail,
			Username: callerUsername(ctx),
		}
		if err := corrosion.InsertVMEvent(ctx, s.db, rec); err != nil {
			slog.Warn("vm_event insert failed", "vm", vmName, "type", evType, "error", err)
		}
	}
	if s.events != nil {
		s.events.Publish(events.Event{Action: evType, Target: vmName, Detail: detail})
	}
}

// ListVMEvents returns a VM's recent operational events, newest-first.
func (s *Server) ListVMEvents(ctx context.Context, req *pb.ListVMEventsRequest) (*pb.ListVMEventsResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	rows, err := corrosion.ListVMEvents(ctx, s.db, req.VmName, int(req.Limit), req.Since)
	if err != nil {
		return nil, err
	}
	resp := &pb.ListVMEventsResponse{}
	for _, r := range rows {
		resp.Events = append(resp.Events, &pb.VMEvent{
			Id: r.ID, VmName: r.VMName, HostName: r.HostName,
			Type: r.Type, Result: r.Result, Severity: r.Severity,
			Detail: r.Detail, Username: r.Username, Ts: r.TS,
		})
	}
	return resp, nil
}
