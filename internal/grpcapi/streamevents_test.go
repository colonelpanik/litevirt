package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
)

// chanEventStream hands each sent event to the test over a channel, so the test
// can wait on delivery while StreamEvents is still running.
type chanEventStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent chan *pb.ClusterEvent
}

func (m *chanEventStream) Context() context.Context { return m.ctx }
func (m *chanEventStream) Send(e *pb.ClusterEvent) error {
	select {
	case m.sent <- e:
		return nil
	case <-m.ctx.Done():
		return m.ctx.Err()
	}
}

// streamReady opens a StreamEvents call and blocks until the subscription is
// live, so a row inserted afterwards is certain to be inside the poll's window.
// It publishes a local probe until one comes back: the cursor is set before the
// loop starts, so a local event returning proves the loop is running.
//
// There is no wall-clock dance here on purpose. The earlier version of this
// test opened the stream just after a whole second and SKIPPED itself if the
// handshake ran long — so on a loaded runner, or under -race, it went green
// having tested nothing, on exactly the machines most likely to break it.
func streamReady(t *testing.T, s *Server, ctx context.Context) (*chanEventStream, chan error) {
	t.Helper()
	stream := &chanEventStream{ctx: ctx, sent: make(chan *pb.ClusterEvent, 64)}
	done := make(chan error, 1)
	go func() { done <- s.StreamEvents(&pb.StreamEventsRequest{}, stream) }()

	for deadline := time.After(5 * time.Second); ; {
		s.events.Publish(events.Event{Action: "probe.ready"})
		select {
		case e := <-stream.sent:
			if e.Action == "probe.ready" {
				return stream, done
			}
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatal("stream never delivered a local event")
		}
	}
}

// TestStreamEvents_DeliversARowThatArrivesLate pins the cursor to the order rows
// ARRIVE in, not the order they were written in.
//
// audit_log and vm_events reach this node only by CRDT replication, which is
// asynchronous and per-peer. A cursor that is a high-water over the AUTHORING
// timestamp therefore drops, permanently and silently, every row that arrives
// after a newer-stamped row has already advanced it: a host partitioned for two
// minutes rejoins, its whole backlog is older than the cursor, and none of it is
// ever sent. The stream stays open and looks healthy, and the events are in
// `lv audit ls` afterwards, so nobody notices at the time.
//
// The row here is stamped an hour in the past, which is strictly harder than the
// same-second case the previous test covered, and needs no clock alignment.
func TestStreamEvents_DeliversARowThatArrivesLate(t *testing.T) {
	old := streamAuditPollInterval
	streamAuditPollInterval = 20 * time.Millisecond
	defer func() { streamAuditPollInterval = old }()

	s := testServer(t)
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()

	stream, done := streamReady(t, s, ctx)

	// A row from a peer that has just caught up: authored long before anything
	// this stream has seen, delivered to us only now.
	if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
		ID: "late-arrival", Username: "bob", HostName: "other-host",
		Action: "vm.deleted", Target: "vm-late", Result: "ok",
		Timestamp: time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04:05.000000000Z07:00"),
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}

	for deadline := time.After(5 * time.Second); ; {
		select {
		case e := <-stream.sent:
			if e.Action == "vm.deleted" && e.Target == "vm-late" {
				cancel()
				if err := <-done; err != nil && err != context.Canceled {
					t.Errorf("StreamEvents: %v", err)
				}
				return
			}
		case <-deadline:
			t.Fatal("a row that arrived after the stream opened, but was stamped before it, was never sent")
		}
	}
}

func TestPublish_DoesNotPanic(t *testing.T) {
	s := testServer(t)
	// Verify publish works with no webhook URL.
	s.publish("test.event", "target", "detail")
}

func TestAudit_DoesNotPanic(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	// Verify audit works.
	s.audit(ctx, "test.action", "target", "detail", "ok")
}

func TestSetWebhookURL(t *testing.T) {
	s := testServer(t)
	s.SetWebhookURL("https://example.com/webhook")
	if s.webhookURL != "https://example.com/webhook" {
		t.Errorf("webhookURL = %q", s.webhookURL)
	}
}

func TestAudit_InsertsRecord(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.audit(ctx, "vm.created", "my-vm", "cpu=2 mem=1024", "ok")

	rows, err := s.db.Query(ctx,
		`SELECT username, host_name, action, target, detail, result FROM audit_log WHERE target = ?`, "my-vm")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 audit row, got %d", len(rows))
	}
	r := rows[0]
	if r.String("username") != "admin" {
		t.Errorf("username = %q, want admin", r.String("username"))
	}
	if r.String("host_name") != "test-host" {
		t.Errorf("host_name = %q, want test-host", r.String("host_name"))
	}
	if r.String("action") != "vm.created" {
		t.Errorf("action = %q", r.String("action"))
	}
	if r.String("detail") != "cpu=2 mem=1024" {
		t.Errorf("detail = %q", r.String("detail"))
	}
	if r.String("result") != "ok" {
		t.Errorf("result = %q", r.String("result"))
	}
}

func TestListAuditLog(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Insert 3 audit records.
	for _, rec := range []corrosion.AuditRecord{
		{ID: "a1", Username: "admin", HostName: "host-a", Action: "vm.created", Target: "vm-1", Detail: "ok", Result: "success"},
		{ID: "a2", Username: "admin", HostName: "host-a", Action: "vm.started", Target: "vm-1", Detail: "ok", Result: "success"},
		{ID: "a3", Username: "bob", HostName: "host-b", Action: "vm.migrated", Target: "vm-2", Detail: "to=host-a", Result: "success"},
	} {
		if err := corrosion.InsertAuditLog(ctx, s.db, rec); err != nil {
			t.Fatalf("InsertAuditLog %s: %v", rec.ID, err)
		}
	}

	resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 10})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(resp.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(resp.Entries))
	}
	// Entries should be ordered by timestamp DESC, but since we insert them in quick
	// succession they may have the same timestamp. Just verify all are present.
	actions := map[string]bool{}
	for _, e := range resp.Entries {
		actions[e.Action] = true
	}
	for _, want := range []string{"vm.created", "vm.started", "vm.migrated"} {
		if !actions[want] {
			t.Errorf("missing action %q", want)
		}
	}
}

func TestListAuditLog_Filters(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	for _, rec := range []corrosion.AuditRecord{
		{ID: "f1", Username: "alice", HostName: "h", Action: "sg.create", Target: "/projects/acme", Result: "ok"},
		{ID: "f2", Username: "alice", HostName: "h", Action: "sg.delete", Target: "/projects/acme", Result: "ok"},
		{ID: "f3", Username: "bob", HostName: "h", Action: "vm.start", Target: "/projects/other", Result: "ok"},
	} {
		if err := corrosion.InsertAuditLog(ctx, s.db, rec); err != nil {
			t.Fatalf("InsertAuditLog %s: %v", rec.ID, err)
		}
	}

	// action prefix glob: sg.* matches sg.create + sg.delete.
	resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Action: "sg.*"})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("action=sg.* → %d entries, want 2", len(resp.Entries))
	}

	// exact action (no glob).
	resp, _ = s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Action: "sg.create"})
	if len(resp.Entries) != 1 {
		t.Fatalf("action=sg.create → %d, want 1", len(resp.Entries))
	}

	// user filter.
	resp, _ = s.ListAuditLog(ctx, &pb.ListAuditLogRequest{User: "bob"})
	if len(resp.Entries) != 1 || resp.Entries[0].Action != "vm.start" {
		t.Fatalf("user=bob filter wrong: %+v", resp.Entries)
	}

	// target filter.
	resp, _ = s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Target: "/projects/other"})
	if len(resp.Entries) != 1 || resp.Entries[0].Username != "bob" {
		t.Fatalf("target filter wrong: %+v", resp.Entries)
	}
}

func TestListAuditLog_DefaultLimit(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Limit 0 should default to 100 (we just verify it doesn't error).
	resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 0})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestListAuditLog_RequiresViewer(t *testing.T) {
	s := testServer(t)
	ctx := context.Background() // no role

	_, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 10})
	if err == nil {
		t.Fatal("expected permission denied, got nil")
	}
	if !strings.Contains(err.Error(), "PermissionDenied") && !strings.Contains(err.Error(), "role") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestListAuditLog_ClusterWideEntries(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Insert audit entries from different hosts — simulates Corrosion CRDT replication.
	for _, rec := range []corrosion.AuditRecord{
		{ID: "local-1", Username: "admin", HostName: "test-host", Action: "vm.created", Target: "vm-local", Result: "ok"},
		{ID: "remote-1", Username: "admin", HostName: "remote-host", Action: "vm.migrated", Target: "vm-remote", Result: "ok"},
		{ID: "remote-2", Username: "bot", HostName: "other-host", Action: "vm.deleted", Target: "vm-other", Result: "ok"},
	} {
		if err := corrosion.InsertAuditLog(ctx, s.db, rec); err != nil {
			t.Fatalf("InsertAuditLog: %v", err)
		}
	}

	resp, err := s.ListAuditLog(ctx, &pb.ListAuditLogRequest{Limit: 50})
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}

	// All entries from all hosts should be visible (cluster-wide via Corrosion).
	if len(resp.Entries) != 3 {
		t.Fatalf("expected 3 entries from all hosts, got %d", len(resp.Entries))
	}

	hosts := map[string]bool{}
	for _, e := range resp.Entries {
		hosts[e.HostName] = true
	}
	for _, want := range []string{"test-host", "remote-host", "other-host"} {
		if !hosts[want] {
			t.Errorf("missing entries from host %q", want)
		}
	}
}

func TestSetDNSDomain(t *testing.T) {
	s := testServer(t)
	s.SetDNSDomain("litevirt.local")
	if s.dnsDomain != "litevirt.local" {
		t.Errorf("dnsDomain = %q", s.dnsDomain)
	}
}

// TestStreamEvents_FilterDoesNotStarveTheCursor pins the cursor to rows READ
// rather than rows SENT.
//
// The poll takes 50 rows a tick. If the cursor only advanced on delivery, a
// filtered-out row was re-read every tick, and a run of 50 of them held the
// cursor still for good: the poll fetched the same 50 rows for ever and nothing
// past them was reached, on a stream that stays open and returns no error.
//
// 51 non-matching rows is the smallest run that proves it — 50 fills one batch,
// and the 51st is the one an unadvanced cursor can never get to.
func TestStreamEvents_FilterDoesNotStarveTheCursor(t *testing.T) {
	old := streamAuditPollInterval
	streamAuditPollInterval = 20 * time.Millisecond
	defer func() { streamAuditPollInterval = old }()

	s := testServer(t)
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()

	stream := &chanEventStream{ctx: ctx, sent: make(chan *pb.ClusterEvent, 256)}
	done := make(chan error, 1)
	go func() {
		done <- s.StreamEvents(&pb.StreamEventsRequest{EventTypes: []string{"vm.wanted"}}, stream)
	}()

	// Give the poll loop a moment to take its starting high-water, so every row
	// below is genuinely new to it.
	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 51; i++ {
		if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
			ID: fmt.Sprintf("noise-%02d", i), Username: "u", HostName: "other-host",
			Action: "vm.ignored", Target: "x", Result: "ok",
		}); err != nil {
			t.Fatalf("InsertAuditLog noise-%02d: %v", i, err)
		}
	}
	if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
		ID: "wanted", Username: "u", HostName: "other-host",
		Action: "vm.wanted", Target: "vm-1", Result: "ok",
	}); err != nil {
		t.Fatalf("InsertAuditLog wanted: %v", err)
	}

	for deadline := time.After(5 * time.Second); ; {
		select {
		case e := <-stream.sent:
			if e.Action == "vm.wanted" {
				cancel()
				if err := <-done; err != nil && err != context.Canceled {
					t.Errorf("StreamEvents: %v", err)
				}
				return
			}
		case <-deadline:
			t.Fatal("a matching row behind a full batch of filtered-out rows was never reached")
		}
	}
}

// TestStreamEvents_DeliversARowOnAReusedRowID covers the one way a rowid cursor
// can go wrong: rowid is not allocated forever-upward, it is reused.
//
// SQLite hands out max(rowid)+1, so deleting the highest row frees that number
// for the next insert. vm_events is pruned in three places — a retention cutoff,
// an error-row cutoff, and a keep-N-per-VM sweep — so its highest row can be
// deleted, and a later row can then land at or below an open stream's cursor and
// never be sent. That is exactly the silent drop the arrival-order cursor exists
// to remove, so it cannot be reintroduced by the mechanism that removes it.
//
// audit_log has no delete outside tests, so it cannot hit this; the guard is
// cheap and identical in both polls rather than correct in only one.
func TestStreamEvents_DeliversARowOnAReusedRowID(t *testing.T) {
	old := streamAuditPollInterval
	streamAuditPollInterval = 20 * time.Millisecond
	defer func() { streamAuditPollInterval = old }()

	s := testServer(t)
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()

	stream, done := streamReady(t, s, ctx)

	if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{
		ID: "first", VMName: "vm-1", HostName: "other-host", Type: "vm.started",
	}); err != nil {
		t.Fatalf("InsertVMEvent first: %v", err)
	}
	waitFor(t, stream, "vm.started", "vm-1")

	// The prune removes the highest row, freeing its rowid.
	if err := s.db.Execute(ctx, `DELETE FROM vm_events WHERE id = 'first'`); err != nil {
		t.Fatalf("prune: %v", err)
	}
	// The next event lands on the freed number, at or below the cursor.
	if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{
		ID: "reused", VMName: "vm-2", HostName: "other-host", Type: "vm.stopped",
	}); err != nil {
		t.Fatalf("InsertVMEvent reused: %v", err)
	}
	waitFor(t, stream, "vm.stopped", "vm-2")

	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Errorf("StreamEvents: %v", err)
	}
}

// TestStreamEvents_DrainsABurstWithoutWaitingATickPerBatch pins the drain rate.
//
// Each poll takes at most 50 rows. Without an immediate re-poll after a full
// batch, a backlog drains at 50 rows per tick — 10 rows/s at the 5s default — so
// the rejoining-peer case this cursor was built for trickles in over minutes,
// and any sustained cross-host rate above that falls behind for ever with no
// signal. The poll interval here is long on purpose: the burst must arrive
// within ONE tick, not one tick per batch.
func TestStreamEvents_DrainsABurstWithoutWaitingATickPerBatch(t *testing.T) {
	old := streamAuditPollInterval
	streamAuditPollInterval = 2 * time.Second
	defer func() { streamAuditPollInterval = old }()

	s := testServer(t)
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()

	stream, done := streamReady(t, s, ctx)

	const burst = 120 // three batches at the 50-row limit
	for i := 0; i < burst; i++ {
		if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
			ID: fmt.Sprintf("burst-%03d", i), Username: "u", HostName: "other-host",
			Action: "vm.backlog", Target: fmt.Sprintf("vm-%03d", i), Result: "ok",
		}); err != nil {
			t.Fatalf("InsertAuditLog burst-%03d: %v", i, err)
		}
	}

	got := 0
	var firstAt time.Time
	for deadline := time.After(15 * time.Second); got < burst; {
		select {
		case e := <-stream.sent:
			if e.Action != "vm.backlog" {
				continue
			}
			if got == 0 {
				firstAt = time.Now()
			}
			got++
		case <-deadline:
			t.Fatalf("delivered %d of %d backlog rows", got, burst)
		}
	}
	// One tick's worth of slack past the first delivery. A tick-per-batch drain
	// needs two more full intervals to finish.
	if spread := time.Since(firstAt); spread > streamAuditPollInterval {
		t.Errorf("the burst took %s after its first row — a tick per batch, not one drain", spread)
	}

	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Errorf("StreamEvents: %v", err)
	}
}

// waitFor blocks until the stream sends a matching event.
func waitFor(t *testing.T, stream *chanEventStream, action, target string) {
	t.Helper()
	for deadline := time.After(5 * time.Second); ; {
		select {
		case e := <-stream.sent:
			if e.Action == action && e.Target == target {
				return
			}
		case <-deadline:
			t.Fatalf("never received %s/%s", action, target)
		}
	}
}

// TestStreamEvents_DeliversAfterARunOfRowIDsIsFreed extends the reuse case from
// one freed rowid to several.
//
// SQLite allocates max(rowid)+1, so reuse only ever happens for numbers freed at
// the TOP of the table — and a prune frees a run of them, not one. A cursor that
// remembers a single boundary row survives exactly one reused number and drops
// every reused row below it, which is the same silent gap in a narrower window.
func TestStreamEvents_DeliversAfterARunOfRowIDsIsFreed(t *testing.T) {
	old := streamAuditPollInterval
	streamAuditPollInterval = 20 * time.Millisecond
	defer func() { streamAuditPollInterval = old }()

	s := testServer(t)
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()

	stream, done := streamReady(t, s, ctx)

	for i := 0; i < 3; i++ {
		if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{
			ID: fmt.Sprintf("old-%d", i), VMName: fmt.Sprintf("vm-%d", i),
			HostName: "other-host", Type: "vm.started",
		}); err != nil {
			t.Fatalf("InsertVMEvent old-%d: %v", i, err)
		}
	}
	waitFor(t, stream, "vm.started", "vm-2")

	// The prune frees the whole run.
	if err := s.db.Execute(ctx, `DELETE FROM vm_events WHERE host_name = 'other-host'`); err != nil {
		t.Fatalf("prune: %v", err)
	}
	// Which SQLite then hands back out, from the bottom of the freed run up.
	if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{
		ID: "after-prune", VMName: "vm-new", HostName: "other-host", Type: "vm.stopped",
	}); err != nil {
		t.Fatalf("InsertVMEvent after-prune: %v", err)
	}
	waitFor(t, stream, "vm.stopped", "vm-new")

	cancel()
	if err := <-done; err != nil && err != context.Canceled {
		t.Errorf("StreamEvents: %v", err)
	}
}
