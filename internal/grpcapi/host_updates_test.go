package grpcapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostupdates"
	"github.com/litevirt/litevirt/internal/notify"
)

type hookRecorder struct {
	mu  sync.Mutex
	got []notify.Notification
}

func (h *hookRecorder) kinds() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var k []string
	for _, n := range h.got {
		k = append(k, n.Kind+"/"+string(n.Severity))
	}
	return k
}

func hostUpdatesServer(t *testing.T, st hostupdates.Status) (*Server, *hookRecorder) {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	rec := &hookRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n notify.Notification
		_ = json.NewDecoder(r.Body).Decode(&n)
		rec.mu.Lock()
		rec.got = append(rec.got, n)
		rec.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	if err := corrosion.InsertNotificationTarget(ctx, s.db, corrosion.NotificationTarget{ID: "t1", Name: "hook", Type: "webhook", Config: string(cfg), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertNotificationRoute(ctx, s.db, corrosion.NotificationRoute{ID: "r1", EventPattern: "host.*", TargetID: "t1", MinSeverity: "info", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s.SetHostUpdates(HostUpdatesConfig{Enabled: true, Check: func(context.Context) hostupdates.Status { return st }})
	return s, rec
}

func waitKinds(t *testing.T, rec *hookRecorder, want int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if k := rec.kinds(); len(k) >= want {
			return k
		}
		time.Sleep(10 * time.Millisecond)
	}
	return rec.kinds()
}

func TestHostUpdates_PublishesLabelsAndFlagsSecurity(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{
		Supported: true, Manager: "apt", Pending: 3, Security: 1,
		Packages: []hostupdates.Pkg{{Name: "openssl", Security: true}, {Name: "vim"}, {Name: "tzdata"}},
	})
	s.CheckHostUpdatesOnce(context.Background())

	h, _ := corrosion.GetHost(context.Background(), s.db, s.hostName)
	p, sec, ok := hostupdates.FromLabels(h.Labels)
	if !ok || p != 3 || sec != 1 {
		t.Fatalf("labels not published: %v", h.Labels)
	}
	k := waitKinds(t, rec, 1)
	if len(k) != 1 || k[0] != "host.security_updates/warn" {
		t.Fatalf("want one warn security notification, got %v", k)
	}
}

func TestHostUpdates_NonSecurityIsInfo(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Pending: 2, Packages: []hostupdates.Pkg{{Name: "vim"}, {Name: "tzdata"}}})
	s.CheckHostUpdatesOnce(context.Background())
	k := waitKinds(t, rec, 1)
	if len(k) != 1 || k[0] != "host.updates/info" {
		t.Fatalf("got %v", k)
	}
}

func TestHostUpdates_UnchangedDoesNotRenotify(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Pending: 1, Security: 1, Packages: []hostupdates.Pkg{{Name: "openssl", Security: true}}})
	s.CheckHostUpdatesOnce(context.Background())
	waitKinds(t, rec, 1)
	s.CheckHostUpdatesOnce(context.Background())
	time.Sleep(150 * time.Millisecond)
	if k := rec.kinds(); len(k) != 1 {
		t.Fatalf("an unchanged result must not notify again, got %v", k)
	}
}

func TestHostUpdates_RestartDoesNotRenotifyKnownState(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Pending: 1, Security: 1, Packages: []hostupdates.Pkg{{Name: "openssl", Security: true}}})
	if err := corrosion.SetHostLabel(context.Background(), s.db, s.hostName, hostupdates.LabelPending, "1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetHostLabel(context.Background(), s.db, s.hostName, hostupdates.LabelSecurity, "1"); err != nil {
		t.Fatal(err)
	}
	s.CheckHostUpdatesOnce(context.Background()) // a fresh Server: no in-memory state
	time.Sleep(150 * time.Millisecond)
	if k := rec.kinds(); len(k) != 0 {
		t.Fatalf("the published labels already say this; a restart must not notify, got %v", k)
	}
}

func TestHostUpdates_FailedCheckIsUnknownNotZero(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Err: "apt list: boom"})
	s.CheckHostUpdatesOnce(context.Background())
	h, _ := corrosion.GetHost(context.Background(), s.db, s.hostName)
	if h.Labels[hostupdates.LabelPending] != "unknown" {
		t.Fatalf("a failed check must publish unknown, got %v", h.Labels)
	}
	time.Sleep(100 * time.Millisecond)
	if k := rec.kinds(); len(k) != 0 {
		t.Fatalf("a failed check is not an update notification, got %v", k)
	}
}

func TestHostUpdates_FullyPatchedClearsAndIsQuiet(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt"})
	s.CheckHostUpdatesOnce(context.Background())
	h, _ := corrosion.GetHost(context.Background(), s.db, s.hostName)
	if p, sec, ok := hostupdates.FromLabels(h.Labels); !ok || p != 0 || sec != 0 {
		t.Fatalf("labels: %v", h.Labels)
	}
	time.Sleep(100 * time.Millisecond)
	if k := rec.kinds(); len(k) != 0 {
		t.Fatalf("nothing pending, nothing to say: %v", k)
	}
}

func TestHostUpdates_UnsupportedHostPublishesNothing(t *testing.T) {
	s, _ := hostUpdatesServer(t, hostupdates.Status{})
	s.CheckHostUpdatesOnce(context.Background())
	h, _ := corrosion.GetHost(context.Background(), s.db, s.hostName)
	if _, ok := h.Labels[hostupdates.LabelPending]; ok {
		t.Fatalf("a host with no package manager must publish no label: %v", h.Labels)
	}
}

// M5: a failed check between two identical results does not repeat the
// notification: the last known counts are kept apart from the published labels,
// which say "unknown" while a check fails.
func TestHostUpdates_AFailedCheckBetweenTwoEqualResultsDoesNotRenotify(t *testing.T) {
	ok := hostupdates.Status{Supported: true, Manager: "apt", Pending: 2, Security: 1,
		Packages: []hostupdates.Pkg{{Name: "openssl", Security: true}, {Name: "vim"}}}
	s, rec := hostUpdatesServer(t, ok)
	s.dataDir = t.TempDir()
	s.CheckHostUpdatesOnce(context.Background())
	waitKinds(t, rec, 1)
	s.hostUpdates.Check = func(context.Context) hostupdates.Status {
		return hostupdates.Status{Supported: true, Manager: "apt", Err: "apt list: lock held"}
	}
	s.CheckHostUpdatesOnce(context.Background())
	s.hostUpdates.Check = func(context.Context) hostupdates.Status { return ok }
	s.CheckHostUpdatesOnce(context.Background())
	time.Sleep(200 * time.Millisecond)
	if k := rec.kinds(); len(k) != 1 {
		t.Fatalf("the same counts after a failed check notified again: %v", k)
	}
}

// M5: a host that stops reporting (the check is disabled, or there is no
// package manager any more) withdraws its counts instead of showing them forever.
func TestHostUpdates_DisabledOrUnsupportedWithdrawsTheCounts(t *testing.T) {
	s, _ := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Pending: 4, Packages: []hostupdates.Pkg{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}}})
	ctx := context.Background()
	labels := func() map[string]string {
		h, _ := corrosion.GetHost(ctx, s.db, s.hostName)
		return h.Labels
	}
	s.CheckHostUpdatesOnce(ctx)
	if labels()[hostupdates.LabelPending] != "4" {
		t.Fatalf("premise: %v", labels())
	}
	s.hostUpdates.Check = func(context.Context) hostupdates.Status { return hostupdates.Status{} }
	s.CheckHostUpdatesOnce(ctx)
	if _, ok := labels()[hostupdates.LabelPending]; ok {
		t.Fatalf("a host with no package manager kept its old counts: %v", labels())
	}
	s.hostUpdates.Check = nil
	s.SetHostUpdates(HostUpdatesConfig{Enabled: true, Check: func(context.Context) hostupdates.Status {
		return hostupdates.Status{Supported: true, Manager: "apt", Pending: 1, Packages: []hostupdates.Pkg{{Name: "a"}}}
	}})
	s.CheckHostUpdatesOnce(ctx)
	s.SetHostUpdates(HostUpdatesConfig{Enabled: false})
	s.RunHostUpdateLoop(ctx) // disabled: withdraws and returns
	if l := labels(); l[hostupdates.LabelPending] != "" || l[hostupdates.LabelSecurity] != "" {
		t.Fatalf("a disabled check left counts on the host: %v", l)
	}
}

// M3: one check publishes both counts in ONE write of the labels column, and a
// check that changes nothing writes nothing: each write of the whole column is
// a chance to carry back a stale copy of another node's concurrent label edit.
func TestHostUpdates_OneLabelWritePerChange(t *testing.T) {
	s, _ := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Pending: 3, Security: 1,
		Packages: []hostupdates.Pkg{{Name: "openssl", Security: true}, {Name: "vim"}, {Name: "tzdata"}}})
	ctx := context.Background()
	writes := func() int {
		rows, err := s.db.Query(ctx, `SELECT COUNT(*) AS n FROM mutation_log WHERE stmts LIKE '%UPDATE hosts SET labels%'`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("count label writes: %v", err)
		}
		return int(rows[0].Int64("n"))
	}
	before := writes()
	s.CheckHostUpdatesOnce(ctx)
	if n := writes() - before; n != 1 {
		t.Fatalf("one check wrote the labels column %d times, want once", n)
	}
	s.CheckHostUpdatesOnce(ctx)
	if n := writes() - before; n != 1 {
		t.Fatalf("an unchanged check wrote the labels column again (%d writes)", n)
	}
}
