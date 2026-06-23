package lb

import (
	"strings"
	"testing"
)

// keepalivedArgs must give each LB instance its OWN vrrp + checkers child
// pidfiles. keepalived's child processes default to shared paths
// (/var/run/keepalived_vrrp.pid, _checkers.pid); without per-LB overrides a
// second stack LB on the same host refuses to start ("daemon is already
// running") and never assigns its VIP.
func TestKeepalivedArgs_PerLBChildPidfiles(t *testing.T) {
	pid := "/run/litevirt/lb/lbmix-lb-keepalived.pid"
	args := keepalivedArgs("/etc/litevirt/lb/lbmix-lb-keepalived.conf", pid)

	val := func(flag string) string {
		for i, a := range args {
			if a == flag && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}

	if got := val("-p"); got != pid {
		t.Errorf("-p = %q, want %q", got, pid)
	}
	// VRRP child pidfile (-r) must be per-LB.
	r := val("-r")
	if r == "" {
		t.Error("missing -r (vrrp_pid): a 2nd LB collides on the shared default /var/run/keepalived_vrrp.pid")
	}
	if !strings.Contains(r, "lbmix-lb") || !strings.Contains(r, "vrrp") {
		t.Errorf("-r = %q, want a per-LB vrrp pidfile", r)
	}
	// Checkers child pidfile (-c) must be per-LB.
	c := val("-c")
	if c == "" {
		t.Error("missing -c (checkers_pid): collides on shared default /var/run/keepalived_checkers.pid")
	}
	if !strings.Contains(c, "lbmix-lb") || !strings.Contains(c, "checkers") {
		t.Errorf("-c = %q, want a per-LB checkers pidfile", c)
	}
	// All three pidfiles must be distinct.
	if r == pid || c == pid || r == c {
		t.Errorf("child pidfiles not distinct: -p=%q -r=%q -c=%q", pid, r, c)
	}

	// Remove must reap exactly the child pidfiles that start creates.
	children := keepalivedChildPidFiles(pid)
	want := map[string]bool{r: true, c: true}
	if len(children) != 2 || !want[children[0]] || !want[children[1]] {
		t.Errorf("keepalivedChildPidFiles(%q) = %v, want the -r/-c paths %v", pid, children, want)
	}
}
