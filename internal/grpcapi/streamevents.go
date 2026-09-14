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
	"github.com/litevirt/litevirt/internal/randid"
	"github.com/litevirt/litevirt/internal/webhook"
)

// streamAuditPollInterval is how often StreamEvents polls audit_log and
// vm_events for rows other hosts wrote. Overridable in tests.
var streamAuditPollInterval = 5 * time.Second

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

	// Cursors over local ARRIVAL order, not authoring time. See pollCursor.
	//
	// Taken HERE, at stream open, not lazily on the first poll. A cursor read a
	// tick later would take its high-water from rows that arrived in between and
	// then skip them as already-delivered — silently losing exactly the window
	// the caller opened the stream to watch. A read that fails leaves the cursor
	// unknown and is retried by each poll; no rows flow until one succeeds, which
	// is a logged degradation rather than a silent gap or an hour of replay.
	var auditCur, vmEventCur pollCursor
	auditCur.start(stream.Context(), s, "audit_log")
	vmEventCur.start(stream.Context(), s, "vm_events")

	// Poll audit log periodically for cluster-wide events from other hosts.
	auditTicker := time.NewTicker(streamAuditPollInterval)
	defer auditTicker.Stop()

	// drain keeps polling while each batch comes back full, so a backlog is not
	// metered out one batch per tick. A rejoining peer delivers thousands of rows
	// at once; at 50 rows per 5s tick that is 10 rows/s, so the "live" feed would
	// trail minutes behind and fall further behind under any sustained
	// cross-host write rate. The cap keeps one busy table from starving the
	// local-bus case in the same select; whatever is left waits for the next tick.
	// sendLocal forwards one event from the in-memory bus.
	sendLocal := func(e events.Event) error {
		if len(filter) > 0 && !filter[e.Action] {
			return nil
		}
		return stream.Send(&pb.ClusterEvent{
			Action:    e.Action,
			Target:    e.Target,
			Detail:    e.Detail,
			Username:  e.Username,
			Timestamp: timestamppb.New(e.Timestamp),
		})
	}

	// pump empties whatever the local bus has waiting, without blocking.
	//
	// events.Bus DROPS on a full subscriber channel (`default: // subscriber too
	// slow — skip`), so every send the poll spends inside one tick is time this
	// subscriber is not reading. Draining a large backlog without this would
	// trade a missing remote event for a missing LOCAL one — silently, and local
	// events are the ones an operator is watching in real time.
	pump := func() error {
		for {
			select {
			case e, ok := <-ch:
				if !ok {
					return nil
				}
				if err := sendLocal(e); err != nil {
					return err
				}
			default:
				return nil
			}
		}
	}

	drain := func(poll func() (int, error)) error {
		for i := 0; i < streamMaxBatchesPerTick; i++ {
			if err := pump(); err != nil {
				return err
			}
			n, err := poll()
			if err != nil {
				return err
			}
			if n < streamPollBatch {
				return nil
			}
		}
		return nil
	}

	for {
		select {
		case <-stream.Context().Done():
			return nil

		case e, ok := <-ch:
			if !ok {
				return nil
			}
			if err := sendLocal(e); err != nil {
				return err
			}

		case <-auditTicker.C:
			if err := drain(func() (int, error) { return s.pollAudit(stream, filter, &auditCur) }); err != nil {
				return err
			}
			if err := drain(func() (int, error) { return s.pollVMEvents(stream, filter, &vmEventCur) }); err != nil {
				return err
			}
		}
	}
}

// streamPollBatch is how many rows one poll takes, and streamMaxBatchesPerTick
// how many such polls a single tick may chain before yielding.
const (
	streamPollBatch         = 50
	streamMaxBatchesPerTick = 20
)

// pollCursor is one table's position in this node's local arrival order.
//
// Both tables reach this node only by CRDT replication, which is asynchronous
// and per-peer, so the order rows are written in across the cluster is not the
// order they land here in. A high-water over the authoring stamp drops every row
// arriving after a newer-stamped one has advanced it: a host partitioned for two
// minutes rejoins, its whole backlog is older than the cursor, and none of it is
// ever sent — on a stream that stays open, returns no error, and looks healthy.
//
// rowid is assigned when a row is inserted into THIS node's database, so it
// advances once per row we have actually seen and a late arrival sits above the
// cursor however old its stamp is. It is local and never travels between nodes.
//
// It is not, however, allocated forever-upward: SQLite hands out max(rowid)+1, so
// deleting the highest row frees that number for the next insert. vm_events is
// pruned in three places, so this is reachable there. Hence id: the cursor names
// the row that occupied the position as well as the position, the poll re-reads
// that boundary row each time, and skips it only when it is still the same row.
// A reused number carries a different id and is delivered.
type pollCursor struct {
	row   int64  // arrival position of the last row read
	id    string // which row occupied it, so a reused rowid is not mistaken for it
	known bool   // false until the table's high-water has been read
	fails int    // consecutive query failures, for log rate-limiting
}

// start reads the table's current high-water so a fresh stream begins at
// "everything from here on" rather than replaying history.
//
// A failure leaves the cursor UNKNOWN and is retried on the next tick. Starting
// at zero instead would look like the safe direction — replay rather than drop —
// but it is not: one transient error at stream open replays the table's entire
// retained history before reaching anything current, and the operator watching
// a live feed has no idea the events scrolling past are hours old.
func (c *pollCursor) start(ctx context.Context, s *Server, table string) bool {
	if c.known {
		return true
	}
	rows, err := s.db.Query(ctx, `SELECT rowid AS row_id, id FROM `+table+` ORDER BY rowid DESC LIMIT 1`)
	if err != nil {
		c.warn(ctx, "could not read table high-water; retrying next tick", table, err)
		return false
	}
	if len(rows) == 1 {
		c.row, c.id = rows[0].Int64("row_id"), rows[0].String("id")
	}
	c.known, c.fails = true, 0
	return true
}

// followTableDown lowers the cursor when the table's high-water has fallen below
// it.
//
// SQLite allocates max(rowid)+1, so a number is only ever reused after being
// freed at the TOP — and a prune frees a RUN of them, not one. The boundary row
// alone survives exactly one reused number; everything below it would be handed
// back out under the cursor and never sent. Following the table down restores
// the invariant the cursor depends on: every future insert lands above it.
func (c *pollCursor) followTableDown(ctx context.Context, s *Server, table string) {
	rows, err := s.db.Query(ctx, `SELECT COALESCE(MAX(rowid), 0) AS m FROM `+table)
	if err != nil || len(rows) != 1 {
		return // the poll below will report it
	}
	if high := rows[0].Int64("m"); high < c.row {
		c.row, c.id = high, ""
	}
}

// warn reports a poll failure without becoming the noise it is meant to cut
// through. A cancelled context is the caller hanging up — an ordinary Ctrl-C on
// `lv events`, not a fault — and is silent. A persistent fault logs on the first
// tick and every twelfth after it, so a stuck database says so once a minute at
// the default interval instead of once per tick per open stream.
func (c *pollCursor) warn(ctx context.Context, msg, table string, err error) {
	if ctx.Err() != nil {
		return
	}
	c.fails++
	if c.fails == 1 || c.fails%12 == 0 {
		slog.Warn("stream events: "+msg,
			"table", table, "error", err, "consecutive_failures", c.fails)
	}
}

// pollAudit sends audit rows other hosts wrote that have arrived since the
// cursor, and reports how many rows it read.
//
// A query failure leaves the cursor alone and is logged. It used to be a bare
// `continue`, which cost two things: nothing recorded that cluster-wide events
// had stopped — under SQLITE_BUSY the stream kept delivering local events and so
// looked healthy while every remote event was missing — and that `continue`
// targeted the poll loop, so a failing audit query also skipped the vm_events
// poll below it. Only a send failure is returned, because that ends the stream.
func (s *Server) pollAudit(stream grpc.ServerStreamingServer[pb.ClusterEvent], filter map[string]bool, cur *pollCursor) (int, error) {
	ctx := stream.Context()
	if !cur.start(ctx, s, "audit_log") {
		return 0, nil
	}
	cur.followTableDown(ctx, s, "audit_log")
	rows, err := s.db.Query(ctx,
		`SELECT rowid AS row_id, id, timestamp, username, host_name, action, target, detail
		 FROM audit_log
		 WHERE rowid >= ? AND host_name != ?
		 ORDER BY rowid ASC LIMIT ?`,
		cur.row, s.hostName, streamPollBatch)
	if err != nil {
		cur.warn(ctx, "audit poll failed; cluster-wide events are not reaching this stream", "audit_log", err)
		return 0, nil
	}
	cur.fails = 0
	for _, r := range rows {
		id, row := r.String("id"), r.Int64("row_id")
		if row == cur.row && id == cur.id {
			continue // the boundary row, already delivered
		}
		// The cursor advances for every row READ, not every row sent. Advancing
		// only on delivery meant a filtered-out row was re-read on every tick,
		// and a full batch of them held the cursor still for good.
		cur.row, cur.id = row, id
		action := r.String("action")
		if len(filter) > 0 && !filter[action] {
			continue
		}
		parsed, _ := time.Parse(time.RFC3339Nano, r.String("timestamp"))
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
			return len(rows), err
		}
	}
	return len(rows), nil
}

// pollVMEvents does the same for other hosts' per-VM events. vm_events is
// replicated like audit_log, and our own emits already came through the
// in-memory bus, hence the same host_name != self dedup.
func (s *Server) pollVMEvents(stream grpc.ServerStreamingServer[pb.ClusterEvent], filter map[string]bool, cur *pollCursor) (int, error) {
	ctx := stream.Context()
	if !cur.start(ctx, s, "vm_events") {
		return 0, nil
	}
	cur.followTableDown(ctx, s, "vm_events")
	rows, err := s.db.Query(ctx,
		`SELECT rowid AS row_id, id, ts, vm_name, host_name, type, detail
		 FROM vm_events
		 WHERE rowid >= ? AND host_name != ?
		 ORDER BY rowid ASC LIMIT ?`,
		cur.row, s.hostName, streamPollBatch)
	if err != nil {
		cur.warn(ctx, "vm_events poll failed; per-VM events from other hosts are not reaching this stream", "vm_events", err)
		return 0, nil
	}
	cur.fails = 0
	for _, r := range rows {
		id, row := r.String("id"), r.Int64("row_id")
		if row == cur.row && id == cur.id {
			continue
		}
		cur.row, cur.id = row, id
		action := r.String("type")
		if len(filter) > 0 && !filter[action] {
			continue
		}
		parsed, _ := time.Parse(time.RFC3339Nano, r.String("ts"))
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
			return len(rows), err
		}
	}
	return len(rows), nil
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
		ID:       randid.New(),
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
