package corrosion

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func parseTS(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(nowTSLayout, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

// TestNowTS_PersistsHighWaterAcrossRestart is the backward-clock lost-update repro:
// a node emits an updated_at, restarts with its wall clock stepped BACK, and must NOT
// emit an older-sorting key than it already replicated. Without the persisted
// high-water this FAILS (a fresh process resets the in-memory monotonic floor to zero).
func TestNowTS_PersistsHighWaterAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

	c1, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	c1.nowFn = func() time.Time { return t0 }
	ts1 := parseTS(t, c1.NowTS())
	c1.Close()

	// Restart with the wall clock a full hour in the PAST.
	c2, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.nowFn = func() time.Time { return t0.Add(-time.Hour) }
	ts2 := parseTS(t, c2.NowTS())

	if ts2.Before(ts1) {
		t.Fatalf("backward-clock restart regressed the LWW key: ts2=%s < ts1=%s", ts2, ts1)
	}
}

// TestHWMStore_CorruptIsFailClosed: a corrupt nowts.hwm is a hard startup error, never a
// silent reset to wall clock (which would re-open the rollback bug).
func TestHWMStore_CorruptIsFailClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nowts.hwm"), []byte("garbage not the format\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalClient(dir, "node-1"); err == nil {
		t.Fatal("a corrupt nowts.hwm must fail closed (startup error), not silently reset")
	}
}

// TestHWMStore_MissingIsFresh: an absent file is a fresh node (found=false, no error) —
// only a present-but-unparseable file is corrupt. A torn write that left a stray .tmp
// but no/old main file must load the previous ceiling (or none), never error on .tmp.
func TestHWMStore_MissingAndTornState(t *testing.T) {
	dir := t.TempDir()
	s := newHWMStore(dir)

	if _, _, found, err := s.load(); err != nil || found {
		t.Fatalf("absent file: want found=false,err=nil; got found=%v err=%v", found, err)
	}

	// Commit a valid ceiling, then simulate a torn write (stray .tmp garbage, main
	// intact). load() must return the intact previous ceiling and ignore the .tmp.
	want := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	if err := s.store(want, 1234); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path+".tmp", []byte("half-written garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	lww, hlcMS, found, err := s.load()
	if err != nil || !found {
		t.Fatalf("torn .tmp must not break load: found=%v err=%v", found, err)
	}
	if !lww.Equal(want) || hlcMS != 1234 {
		t.Fatalf("load after torn write: lww=%s hlc=%d; want %s 1234", lww, hlcMS, want)
	}
}

// TestHWMStore_IncreaseOnlyMerge: store() never regresses the on-disk ceilings even if
// a caller passes a lower value (a concurrent NewLocalClient tool with a stale view).
func TestHWMStore_IncreaseOnlyMerge(t *testing.T) {
	dir := t.TempDir()
	s := newHWMStore(dir)
	hi := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	lo := hi.Add(-time.Hour)
	if err := s.store(hi, 5000); err != nil {
		t.Fatal(err)
	}
	if err := s.store(lo, 100); err != nil { // lower — must be ignored (max-merge)
		t.Fatal(err)
	}
	lww, hlcMS, _, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	if !lww.Equal(hi) || hlcMS != 5000 {
		t.Fatalf("increase-only violated: lww=%s hlc=%d; want %s 5000", lww, hlcMS, hi)
	}
}

// TestNowTS_FailClosedOnPersistFailure: when the durable store fails mid-run, NowTS
// keeps emitting up to (never past) the last durable ceiling — the persist-ahead
// headroom — and calls onPersistFatal once wall time passes it, never a silent
// regression or an emission beyond an un-persisted ceiling.
func TestNowTS_FailClosedOnPersistFailure(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)

	c, err := NewLocalClient(dir, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	wall := t0
	c.nowFn = func() time.Time { return wall }

	// One successful emit commits a ceiling of ~t0 + persist-ahead while lastTS≈t0,
	// so there is real headroom (the running-daemon case).
	last := parseTS(t, c.NowTS())
	ceiling := c.durableTS

	// Persistence now fails; onPersistFatal records instead of exiting.
	c.hwm.storeHook = func(time.Time, int64) error { return errors.New("disk full") }
	var fatal int
	c.onPersistFatal = func(error) { fatal++ }

	for i := 0; i < 100 && fatal == 0; i++ {
		wall = wall.Add(500 * time.Millisecond) // eventually passes the ceiling
		before := fatal
		got := parseTS(t, c.NowTS())
		if fatal > before {
			break // fatal fired this call — production would have exited here
		}
		if got.After(ceiling) {
			t.Fatalf("emitted %s beyond un-persisted durable ceiling %s", got, ceiling)
		}
		if got.Before(last) {
			t.Fatalf("regressed: %s < %s", got, last)
		}
		last = got
	}
	if fatal == 0 {
		t.Fatal("headroom should have been exhausted → onPersistFatal expected")
	}
}
