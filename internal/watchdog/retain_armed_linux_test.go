//go:build linux

package watchdog

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// Declining to call Close does NOT keep a descriptor open. os.OpenFile returns
// a garbage-collected *os.File, and os.File.Fd documents that the descriptor is
// valid only until the File is collected — the runtime closes it for you.
//
// For a watchdog that is the whole ballgame: the runtime's close IS the
// watchdog_release() that stops the timer on a driver without WDIOF_MAGICCLOSE.
// The host then never reboots while Fenced() reports true, on a nondeterministic
// GC timer inside the fence window.
//
// So the fence path must RETAIN the file, not merely refrain from closing it.
func TestRetainArmed_SurvivesGarbageCollection(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "wd"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fd := int(f.Fd())

	retainArmed(f)
	f = nil // the only local reference, exactly as Heartbeat's `f` goes away

	// Finalizers/cleanups run asynchronously, so give them several real chances.
	for i := 0; i < 5; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		t.Fatalf("descriptor %d was closed by the runtime after GC (%v) — a watchdog "+
			"left 'armed' this way is disarmed by the close the runtime performs", fd, err)
	}
}

// The control: an unretained file IS collected and closed, which is the defect
// this guards against. Best-effort — if the runtime declines to collect, the
// test says so rather than failing, because a missed collection proves nothing.
func TestUnretainedFile_IsClosedByTheRuntime(t *testing.T) {
	fd := func() int {
		f, err := os.Create(filepath.Join(t.TempDir(), "wd"))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		return int(f.Fd())
	}()

	for i := 0; i < 10; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return // collected and closed, as expected
		}
	}
	t.Skip("runtime did not collect the file in time; the hazard is real but not " +
		"demonstrated in this run")
}
