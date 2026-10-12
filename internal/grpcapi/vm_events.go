package grpcapi

import (
	"context"
	"log/slog"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/randid"
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
			ID:       randid.New(),
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

// vmEventsHardLimit mirrors corrosion.ListVMEvents' own cap — the ceiling
// listVMEventsFiltered's over-fetch loop will not ask past.
const vmEventsHardLimit = 1000

// listVMEventsFiltered returns up to limit events a caller may read,
// newest-first, over-fetching from corrosion as needed so the RBAC filter
// (applied here, in Go, since project membership is not a vm_events column)
// does not starve the page. corrosion.ListVMEvents applies `LIMIT
// fetchLimit` in SQL before this function ever sees a row, so a naive
// single fetch of exactly `limit` rows can come back ENTIRELY foreign —
// newest-first means the top of the table can easily be some other
// project's recent activity — and the caller's own, merely older, events
// never get read at all. This is the same problem ListVMs solved by reading
// one more page at a time until pageSize+1 READABLE rows were found; here,
// with no keyset cursor over vm_events (ordering is by ts, not a column this
// RPC can resume from), the equivalent is to re-ask for a geometrically
// larger slice of the SAME newest-first window until either the page fills
// or corrosion returns fewer rows than asked (the table is exhausted).
func (s *Server) listVMEventsFiltered(ctx context.Context, vmName string, limit int, since string, canRead func(corrosion.VMEventRecord) bool) ([]corrosion.VMEventRecord, error) {
	fetchLimit := limit
	var filtered []corrosion.VMEventRecord
	for {
		rows, err := corrosion.ListVMEvents(ctx, s.db, vmName, fetchLimit, since)
		if err != nil {
			return nil, err
		}
		filtered = filtered[:0]
		for _, r := range rows {
			if canRead(r) {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) >= limit || len(rows) < fetchLimit || fetchLimit >= vmEventsHardLimit {
			break
		}
		fetchLimit *= 4
		if fetchLimit > vmEventsHardLimit {
			fetchLimit = vmEventsHardLimit
		}
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	return filtered, nil
}

// ListVMEvents returns a VM's recent operational events, newest-first. An
// empty VmName means the cluster-wide activity log instead of one VM (see
// corrosion.ListVMEvents) — that mode used to hand every VM's events to any
// cluster-wide viewer, so each row is additionally filtered by canReadVM,
// over-fetching (listVMEventsFiltered) so a scoped caller still gets a full
// page of its OWN in-scope events rather than an empty or short one whenever
// other projects' events happen to be newer. A non-empty VmName is a
// single-VM read: authorized up front via requireVMReadByName, the same
// vm.read-on-its-own-path check GetVMStats and ListSnapshots use, so a
// caller scoped to one project can no longer read another project's VM's
// events by name either — and every row corrosion returns for it is already
// known-readable, so no further per-row filter or over-fetch applies.
func (s *Server) ListVMEvents(ctx context.Context, req *pb.ListVMEventsRequest) (*pb.ListVMEventsResponse, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	if req.VmName != "" {
		if _, err := s.requireVMReadByName(ctx, req.VmName); err != nil {
			return nil, err
		}
	}
	limit := int(req.Limit)
	if limit <= 0 {
		limit = 100
	}
	if limit > vmEventsHardLimit {
		limit = vmEventsHardLimit
	}
	canRead := func(r corrosion.VMEventRecord) bool {
		return req.VmName != "" || s.canReadVM(ctx, r.VMName)
	}
	rows, err := s.listVMEventsFiltered(ctx, req.VmName, limit, req.Since, canRead)
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
