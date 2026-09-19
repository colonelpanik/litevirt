package libvirt

import (
	"sync"
	"testing"
)

// PatchInactiveDevices runs under a PER-VM lock, so two reconciles on two
// different VMs execute replaceAttrIfPresent — and therefore attrRegex —
// concurrently. attrRegex memoises into a package-global map.
//
// An unsynchronised map is not merely racy here: Go's runtime detects
// concurrent map writes and calls fatal error, which is NOT recoverable and
// takes the whole PROCESS with it.
//
// PatchInactiveDevices is a pure transform and finishes before its caller
// touches libvirt, so the crash does not strand the VM being patched. It
// strands the others: every concurrent reconcile dies with the process,
// including one sitting between UndefineDomainPreservingState and DefineDomain
// for a different VM.
//
// Distinct attrs on every goroutine so each one takes the write path.
func TestAttrRegex_IsSafeForConcurrentReconciles(t *testing.T) {
	attrs := []string{"file", "dev", "bus", "slot", "function", "domain", "type", "index"}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		for _, attr := range attrs {
			wg.Add(1)
			go func(a string) {
				defer wg.Done()
				if re := attrRegex(a); re == nil {
					t.Errorf("attrRegex(%q) returned nil", a)
				}
			}(attr)
		}
	}
	wg.Wait()
}

// The cache must still be a cache: the same attr yields the identical compiled
// pointer, or the mutex has been "fixed" by recompiling every call.
func TestAttrRegex_StillMemoises(t *testing.T) {
	a, b := attrRegex("memoise-probe"), attrRegex("memoise-probe")
	if a != b {
		t.Error("attrRegex recompiled instead of returning the cached pointer")
	}
}
