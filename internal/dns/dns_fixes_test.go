package dns

import (
	"context"
	"testing"

	mdns "github.com/miekg/dns"
)

// TestHandleLocal_AAAAForV4NameIsNodata: an AAAA query for a name that only has
// an IPv4 record must return NOERROR with NO answers (NODATA) — NOT an A record
// in an AAAA response (the prior code emitted A records for AAAA queries), and
// NOT NXDOMAIN (the name exists).
func TestHandleLocal_AAAAForV4NameIsNodata(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()
	if err := UpsertRecord(ctx, db, "web.litevirt.local", "10.0.0.5"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}
	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}
	req := new(mdns.Msg)
	req.SetQuestion("web.litevirt.local.", mdns.TypeAAAA)

	s.handleLocal(w, req)

	if w.msg == nil {
		t.Fatal("no response written")
	}
	if w.msg.Rcode != mdns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR (name exists, just no AAAA)", w.msg.Rcode)
	}
	if len(w.msg.Answer) != 0 {
		t.Fatalf("expected 0 answers for AAAA of a v4-only name, got %d (%T)", len(w.msg.Answer), w.msg.Answer[0])
	}
}

// TestHandleLocal_AAAAForV6NameReturnsAAAA: an AAAA query for a name with an IPv6
// record returns an AAAA record.
func TestHandleLocal_AAAAForV6NameReturnsAAAA(t *testing.T) {
	db := testDNSDB(t)
	ctx := context.Background()
	if err := UpsertRecord(ctx, db, "v6.litevirt.local", "2001:db8::10"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}
	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}
	req := new(mdns.Msg)
	req.SetQuestion("v6.litevirt.local.", mdns.TypeAAAA)

	s.handleLocal(w, req)

	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 AAAA answer, got %d", len(w.msg.Answer))
	}
	aaaa, ok := w.msg.Answer[0].(*mdns.AAAA)
	if !ok {
		t.Fatalf("answer is %T, want *dns.AAAA", w.msg.Answer[0])
	}
	if aaaa.AAAA.String() != "2001:db8::10" {
		t.Errorf("AAAA = %s, want 2001:db8::10", aaaa.AAAA.String())
	}
	// An A query for the same v6-only name is NODATA (no A record fabricated).
	w2 := &fakeResponseWriter{}
	req2 := new(mdns.Msg)
	req2.SetQuestion("v6.litevirt.local.", mdns.TypeA)
	s.handleLocal(w2, req2)
	if len(w2.msg.Answer) != 0 {
		t.Errorf("A query for a v6-only name should be NODATA, got %d answers", len(w2.msg.Answer))
	}
}

// TestHandleLocal_GenuineMissStillNXDOMAIN: a name with no record at all still
// returns NXDOMAIN (the fix must not swallow real misses).
func TestHandleLocal_GenuineMissStillNXDOMAIN(t *testing.T) {
	db := testDNSDB(t)
	s := NewServer("litevirt.local", 5354, db)
	w := &fakeResponseWriter{}
	req := new(mdns.Msg)
	req.SetQuestion("nope.litevirt.local.", mdns.TypeA)

	s.handleLocal(w, req)

	if w.msg.Rcode != mdns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN for a nonexistent name", w.msg.Rcode)
	}
}

func TestRecordFor(t *testing.T) {
	aq := mdns.Question{Name: "x.", Qtype: mdns.TypeA}
	aaaaq := mdns.Question{Name: "x.", Qtype: mdns.TypeAAAA}
	if rr := recordFor(aq, "10.0.0.1"); rr == nil {
		t.Error("A query + v4 should yield an A record")
	} else if _, ok := rr.(*mdns.A); !ok {
		t.Errorf("A query yielded %T, want *dns.A", rr)
	}
	if rr := recordFor(aaaaq, "10.0.0.1"); rr != nil {
		t.Errorf("AAAA query + v4 must yield nil, got %T", rr)
	}
	if rr := recordFor(aaaaq, "2001:db8::1"); rr == nil {
		t.Error("AAAA query + v6 should yield an AAAA record")
	} else if _, ok := rr.(*mdns.AAAA); !ok {
		t.Errorf("AAAA query yielded %T, want *dns.AAAA", rr)
	}
	if rr := recordFor(aq, "2001:db8::1"); rr != nil {
		t.Errorf("A query + v6 must yield nil, got %T", rr)
	}
	if rr := recordFor(aq, "garbage"); rr != nil {
		t.Errorf("unparseable IP must yield nil, got %T", rr)
	}
}
