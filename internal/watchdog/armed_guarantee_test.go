package watchdog

import (
	"strings"
	"testing"
)

// TestArmedGuarantee separates what this process did with the descriptor from
// what actually happens to the timer.
//
// retainArmed keeps the *os.File out of the garbage collector — "for the life
// of the process" and no longer. On the self-fence path that is enough: the
// daemon keeps running until the watchdog reboots it. On the
// shutdown-with-workloads path it is not: daemon.Run returns, the process
// exits, and the kernel closes every descriptor it held.
//
// On a driver without WDIOF_MAGICCLOSE, watchdog_release() stops the timer on
// ANY close — including that implicit one, and that is exactly the driver class
// the descriptor is retained FOR. So the shutdown path logged
// descriptor=retained and told the operator "the host reboots", on precisely
// the devices where it might not.
func TestArmedGuarantee(t *testing.T) {
	t.Run("self-fence retains and the process lives: guaranteed", func(t *testing.T) {
		if d := armedGuarantee(false, true); !d.guaranteed || d.caveat != "" {
			t.Fatalf("got %+v; the daemon keeps running, so a retained descriptor stays open", d)
		}
	})

	t.Run("magic-close driver closed explicitly: guaranteed", func(t *testing.T) {
		if d := armedGuarantee(true, false); !d.guaranteed || d.caveat != "" {
			t.Fatalf("got %+v; closing is the documented safe route on this driver", d)
		}
	})

	t.Run("shutdown on a non-MAGICCLOSE driver: NOT guaranteed", func(t *testing.T) {
		d := armedGuarantee(false, false)
		if d.guaranteed {
			t.Fatal("the shutdown path claimed a guaranteed reboot while the process is " +
				"exiting on a driver whose timer stops on close; the operator is told the " +
				"host is fenced when it may simply be down with workloads abandoned")
		}
		if !strings.Contains(d.caveat, "nowayout") {
			t.Errorf("the caveat should name nowayout, the one thing that saves this case: %q", d.caveat)
		}
		if !strings.Contains(strings.ToLower(d.caveat), "drain") {
			t.Errorf("the caveat should tell the operator what to do instead: %q", d.caveat)
		}
	})
}
