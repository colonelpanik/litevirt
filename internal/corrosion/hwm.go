package corrosion

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// hwmStore durably persists this node's monotonic clock high-waters — the LWW-key
// wall ceiling (behind NowTS) and the HLC physical-ms ceiling — to a single
// versioned file <dataDir>/nowts.hwm. It exists to close the backward-clock
// lost-update: without it, NowTS's in-memory monotonic high-water resets to zero on
// restart, so a daemon that restarts after a wall-clock step-back emits OLDER
// updated_at keys and its fresh writes silently lose LWW cluster-wide.
//
// Writes are increase-only (enforced by the caller's persist-ahead) and crash-safe:
// a separate stable .lock file serializes writers (the data file is replaced by
// rename, so locking IT would lose the lock), the temp file is fsync'd before rename,
// and the containing directory is fsync'd after — so a committed ceiling survives
// power loss. A corrupt/unparseable file is reported as an error (the caller fails
// closed + loud rather than silently resetting to wall clock, which would re-open the
// bug); a genuinely-absent file is "fresh node", not corrupt.
type hwmStore struct {
	dir  string
	path string
	lock string

	// storeHook, when non-nil, replaces the real durable write. Test seam for
	// injected persistence failures; production leaves it nil.
	storeHook func(lww time.Time, hlcMS int64) error
}

func newHWMStore(dir string) *hwmStore {
	return &hwmStore{
		dir:  dir,
		path: filepath.Join(dir, "nowts.hwm"),
		lock: filepath.Join(dir, "nowts.hwm.lock"),
	}
}

// load reads the persisted ceilings. found=false,err=nil ⇒ no file yet (fresh node).
// err!=nil ⇒ the file exists but is unreadable/corrupt — the caller MUST fail closed
// (refuse to start / refuse to advance), never silently fall back to wall clock.
func (s *hwmStore) load() (lww time.Time, hlcMS int64, found bool, err error) {
	b, e := os.ReadFile(s.path)
	if os.IsNotExist(e) {
		return time.Time{}, 0, false, nil
	}
	if e != nil {
		return time.Time{}, 0, false, fmt.Errorf("read %s: %w", s.path, e)
	}
	lww, hlcMS, e = parseHWM(string(b))
	if e != nil {
		return time.Time{}, 0, false, fmt.Errorf("corrupt %s: %w", s.path, e)
	}
	return lww, hlcMS, true, nil
}

// parseHWM decodes the strict versioned format:
//
//	v1
//	lww=<RFC3339Nano>
//	hlc_ms=<int64>
//
// Any deviation is an error (corrupt) so a torn/garbled file is never read as a
// valid-but-lower ceiling.
func parseHWM(s string) (lww time.Time, hlcMS int64, err error) {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) < 3 || strings.TrimSpace(lines[0]) != "v1" {
		return time.Time{}, 0, fmt.Errorf("bad header/too few lines")
	}
	var haveLWW, haveHLC bool
	for _, ln := range lines[1:] {
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			return time.Time{}, 0, fmt.Errorf("bad line %q", ln)
		}
		switch k {
		case "lww":
			t, e := time.Parse(nowTSLayout, v)
			if e != nil {
				return time.Time{}, 0, fmt.Errorf("bad lww %q: %w", v, e)
			}
			lww, haveLWW = t.UTC(), true
		case "hlc_ms":
			n, e := strconv.ParseInt(v, 10, 64)
			if e != nil || n < 0 {
				return time.Time{}, 0, fmt.Errorf("bad hlc_ms %q", v)
			}
			hlcMS, haveHLC = n, true
		}
	}
	if !haveLWW || !haveHLC {
		return time.Time{}, 0, fmt.Errorf("missing lww/hlc_ms")
	}
	return lww, hlcMS, nil
}

// store atomically persists both ceilings, INCREASE-ONLY. flock alone only serializes
// writers, it doesn't stop two processes (the daemon + a NewLocalClient tool sharing
// one dataDir) from each writing their own lower in-memory value — so under the lock we
// RE-READ the current file and max-merge, guaranteeing the on-disk ceilings never
// regress regardless of who writes. Crash-safety ordering: flock → write temp →
// fsync(temp) → rename → fsync(dir). Any step failing returns an error and the caller
// must NOT treat the new ceiling as durable.
func (s *hwmStore) store(lww time.Time, hlcMS int64) error {
	if s.storeHook != nil {
		return s.storeHook(lww, hlcMS)
	}
	lf, err := os.OpenFile(s.lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock: %w", err)
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)

	// Increase-only max-merge against the current on-disk value (a concurrent writer
	// may have advanced it past our in-memory view). A parseable current file wins
	// where it's higher; an unreadable/absent one is replaced by our valid value.
	if cur, e := os.ReadFile(s.path); e == nil {
		if curLWW, curHLC, pe := parseHWM(string(cur)); pe == nil {
			if curLWW.After(lww) {
				lww = curLWW
			}
			if curHLC > hlcMS {
				hlcMS = curHLC
			}
		}
	}

	tmp := s.path + ".tmp"
	content := fmt.Sprintf("v1\nlww=%s\nhlc_ms=%d\n", lww.UTC().Format(nowTSLayout), hlcMS)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open temp: %w", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	// fsync the directory so the rename itself is durable across power loss.
	d, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}
