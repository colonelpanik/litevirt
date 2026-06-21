package dns

import (
	"context"
	"net"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func testDNSDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func TestNewServer(t *testing.T) {
	db := testDNSDB(t)
	s := NewServer("litevirt.local", 5354, db)
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.domain != "litevirt.local." {
		t.Errorf("domain = %q, want litevirt.local.", s.domain)
	}
	if s.port != 5354 {
		t.Errorf("port = %d, want 5354", s.port)
	}
}

func TestNewServer_TrailingDot(t *testing.T) {
	db := testDNSDB(t)
	s := NewServer("litevirt.local.", 5354, db)
	if s.domain != "litevirt.local." {
		t.Errorf("domain = %q, want litevirt.local. (should not add double dot)", s.domain)
	}
}

// fakeResponseWriter captures the DNS response for testing.
type fakeResponseWriter struct {
	msg     *mdns.Msg
	localIP net.Addr
}

func (f *fakeResponseWriter) LocalAddr() net.Addr         { return f.localIP }
func (f *fakeResponseWriter) RemoteAddr() net.Addr         { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (f *fakeResponseWriter) WriteMsg(m *mdns.Msg) error   { f.msg = m; return nil }
func (f *fakeResponseWriter) Write(b []byte) (int, error)   { return len(b), nil }
func (f *fakeResponseWriter) Close() error                  { return nil }
func (f *fakeResponseWriter) TsigStatus() error             { return nil }
func (f *fakeResponseWriter) TsigTimersOnly(bool)           {}
func (f *fakeResponseWriter) Hijack()                        {}

func TestHandleLocal_Found(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()

	if err := UpsertRecord(ctx, db, "web.mystack.litevirt.local", "10.0.0.5"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}

	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}

	req := new(mdns.Msg)
	req.SetQuestion("web.mystack.litevirt.local.", mdns.TypeA)

	s.handleLocal(w, req)

	if w.msg == nil {
		t.Fatal("no response written")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*mdns.A)
	if !ok {
		t.Fatal("answer is not A record")
	}
	if a.A.String() != "10.0.0.5" {
		t.Errorf("A record = %s, want 10.0.0.5", a.A.String())
	}
	if a.Hdr.Ttl != defaultTTL {
		t.Errorf("TTL = %d, want %d", a.Hdr.Ttl, defaultTTL)
	}
}

func TestHandleLocal_NotFound(t *testing.T) {
	db := testDNSDB(t)
	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}

	req := new(mdns.Msg)
	req.SetQuestion("nonexistent.litevirt.local.", mdns.TypeA)

	s.handleLocal(w, req)

	if w.msg == nil {
		t.Fatal("no response written")
	}
	if w.msg.Rcode != mdns.RcodeNameError {
		t.Errorf("Rcode = %d, want NXDOMAIN (%d)", w.msg.Rcode, mdns.RcodeNameError)
	}
}

func TestHandleLocal_SkipsNonAQueries(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()

	if err := UpsertRecord(ctx, db, "web.litevirt.local", "10.0.0.1"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}

	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}

	// Query for MX record — should be skipped.
	req := new(mdns.Msg)
	req.SetQuestion("web.litevirt.local.", mdns.TypeMX)

	s.handleLocal(w, req)

	if w.msg == nil {
		t.Fatal("no response written")
	}
	if len(w.msg.Answer) != 0 {
		t.Errorf("expected 0 answers for MX query, got %d", len(w.msg.Answer))
	}
}

func TestHandleLocal_DeletedRecord(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()

	if err := UpsertRecord(ctx, db, "gone.litevirt.local", "10.0.0.9"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}
	if err := DeleteRecord(ctx, db, "gone.litevirt.local"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}

	req := new(mdns.Msg)
	req.SetQuestion("gone.litevirt.local.", mdns.TypeA)

	s.handleLocal(w, req)

	if w.msg == nil {
		t.Fatal("no response written")
	}
	if w.msg.Rcode != mdns.RcodeNameError {
		t.Errorf("deleted record should return NXDOMAIN, got Rcode=%d", w.msg.Rcode)
	}
}

func TestHandleLocal_MultipleRecords(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()

	// Insert two records, then query for one.
	if err := UpsertRecord(ctx, db, "web1.litevirt.local", "10.0.0.1"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}
	if err := UpsertRecord(ctx, db, "web2.litevirt.local", "10.0.0.2"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}

	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}

	req := new(mdns.Msg)
	req.SetQuestion("web1.litevirt.local.", mdns.TypeA)

	s.handleLocal(w, req)

	if w.msg == nil {
		t.Fatal("no response written")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answer))
	}
	a := w.msg.Answer[0].(*mdns.A)
	if a.A.String() != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", a.A.String())
	}
}

func TestHandleLocal_Authoritative(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()

	if err := UpsertRecord(ctx, db, "vm.litevirt.local", "10.0.0.1"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}

	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}

	req := new(mdns.Msg)
	req.SetQuestion("vm.litevirt.local.", mdns.TypeA)

	s.handleLocal(w, req)

	if w.msg == nil {
		t.Fatal("no response written")
	}
	if !w.msg.Authoritative {
		t.Error("response should be authoritative")
	}
}

func TestHandleLocal_CaseInsensitive(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()

	// Insert lowercase record.
	if err := UpsertRecord(ctx, db, "web.litevirt.local", "10.0.0.1"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}

	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}

	// Query with mixed case.
	req := new(mdns.Msg)
	req.SetQuestion("WEB.litevirt.local.", mdns.TypeA)

	s.handleLocal(w, req)

	if w.msg == nil {
		t.Fatal("no response written")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected case-insensitive match, got %d answers", len(w.msg.Answer))
	}
}

func TestDeleteRecord_Idempotent(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()

	if err := UpsertRecord(ctx, db, "vm.litevirt.local", "10.0.0.1"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}
	// Delete twice — should not error.
	if err := DeleteRecord(ctx, db, "vm.litevirt.local"); err != nil {
		t.Fatalf("first DeleteRecord: %v", err)
	}
	if err := DeleteRecord(ctx, db, "vm.litevirt.local"); err != nil {
		t.Fatalf("second DeleteRecord: %v", err)
	}
}

func TestUpsertRecord_RevivesDeleted(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()

	if err := UpsertRecord(ctx, db, "vm.litevirt.local", "10.0.0.1"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}
	if err := DeleteRecord(ctx, db, "vm.litevirt.local"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	// Re-upsert should clear deleted_at.
	if err := UpsertRecord(ctx, db, "vm.litevirt.local", "10.0.0.2"); err != nil {
		t.Fatalf("re-UpsertRecord: %v", err)
	}

	s := NewServer("litevirt.local", 5354, db)
	ip := s.lookup("vm.litevirt.local.")
	if ip != "10.0.0.2" {
		t.Errorf("expected revived record with 10.0.0.2, got %q", ip)
	}
}
