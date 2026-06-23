package lb

import "testing"

func nulArgs(parts ...string) string {
	s := ""
	for i, p := range parts {
		if i > 0 {
			s += "\x00"
		}
		s += p
	}
	return s
}

func TestCmdlineMatchesBinaryConfig_HAProxy(t *testing.T) {
	cfg := "/etc/litevirt/lb/lbmix-lb-haproxy.cfg"
	cases := []struct {
		name    string
		cmdline string
		cfg     string
		want    bool
	}{
		{"reload sibling for this LB", nulArgs("haproxy", "-f", cfg, "-p", "/run/x.pid", "-sf", "123"), cfg, true},
		{"absolute haproxy path", nulArgs("/usr/sbin/haproxy", "-f", cfg), cfg, true},
		{"different LB's config", nulArgs("haproxy", "-f", "/etc/litevirt/lb/other-lb-haproxy.cfg"), cfg, false},
		{"not haproxy", nulArgs("keepalived", "-f", cfg), cfg, false},
		{"substring not exact field", nulArgs("haproxy", "-f", cfg+".bak"), cfg, false},
		{"empty cfg never matches", nulArgs("haproxy", "-f", ""), "", false},
	}
	for _, c := range cases {
		if got := cmdlineMatchesBinaryConfig(c.cmdline, "haproxy", c.cfg); got != c.want {
			t.Errorf("%s: = %v, want %v", c.name, got, c.want)
		}
	}
}

// keepalived reload-race siblings must be sweepable too — the parent process
// keeps the full `keepalived -f <conf>` argv (killing it reaps its children).
func TestCmdlineMatchesBinaryConfig_Keepalived(t *testing.T) {
	conf := "/etc/litevirt/lb/lbmix-lb-keepalived.conf"
	cases := []struct {
		name    string
		cmdline string
		want    bool
	}{
		{"orphaned keepalived parent for this LB", nulArgs("keepalived", "-f", conf, "-p", "/run/x.pid", "-r", "/run/x_vrrp.pid"), true},
		{"different LB's keepalived", nulArgs("keepalived", "-f", "/etc/litevirt/lb/other-lb-keepalived.conf"), false},
		{"haproxy is not keepalived", nulArgs("haproxy", "-f", conf), false},
	}
	for _, c := range cases {
		if got := cmdlineMatchesBinaryConfig(c.cmdline, "keepalived", conf); got != c.want {
			t.Errorf("%s: = %v, want %v", c.name, got, c.want)
		}
	}
}
