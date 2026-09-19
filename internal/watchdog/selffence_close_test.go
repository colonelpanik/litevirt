package watchdog

import "testing"

// The self-fence path closes the watchdog fd WITHOUT disarming, on the premise
// that the timer keeps running and reboots the host. That premise only holds on
// a driver advertising WDIOF_MAGICCLOSE.
//
// The kernel stops the timer on release when
// `expect_close == 42 || !(options & WDIOF_MAGICCLOSE)`. Self-fence never writes
// 'V', so on a driver without the flag the close itself disarms the watchdog:
// the host does NOT reboot, and Controller.Fenced() still reports true. A
// coordinator then believes a node is being reset while it keeps running its
// workloads — the exact split-brain the watchdog is there to prevent.
func TestSelfFenceMayClose_OnlyWhenTheDriverAdvertisesMagicClose(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options uint32
		known   bool
		want    bool
	}{
		{"magic-close advertised", wdiofMagicClose, true, true},
		{"magic-close among other flags", wdiofMagicClose | 0x8000 | 0x0002, true, true},
		{"no magic-close", 0x8000 | 0x0002, true, false},
		{"no flags at all", 0, true, false},
		{"identity unreadable", wdiofMagicClose, false, false},
	} {
		if got := selfFenceMayClose(tc.options, tc.known); got != tc.want {
			t.Errorf("%s: selfFenceMayClose(%#x, %v) = %v, want %v",
				tc.name, tc.options, tc.known, got, tc.want)
		}
	}
}
