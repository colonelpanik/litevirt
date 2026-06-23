package lb

import "testing"

func TestCmdlineIsHAProxyForConfig(t *testing.T) {
	cfg := "/etc/litevirt/lb/lbmix-lb-haproxy.cfg"
	nul := func(parts ...string) string {
		s := ""
		for i, p := range parts {
			if i > 0 {
				s += "\x00"
			}
			s += p
		}
		return s
	}
	cases := []struct {
		name    string
		cmdline string
		want    bool
	}{
		{"reload sibling for this LB", nul("haproxy", "-f", cfg, "-p", "/run/x.pid", "-sf", "123"), true},
		{"absolute haproxy path", nul("/usr/sbin/haproxy", "-f", cfg), true},
		{"different LB's config", nul("haproxy", "-f", "/etc/litevirt/lb/other-lb-haproxy.cfg"), false},
		{"not haproxy", nul("keepalived", "-f", cfg), false},
		{"substring not exact field", nul("haproxy", "-f", cfg+".bak"), false},
		{"empty cfg never matches", nul("haproxy", "-f", ""), false},
	}
	for _, c := range cases {
		got := cmdlineIsHAProxyForConfig(c.cmdline, cfg)
		if c.name == "empty cfg never matches" {
			got = cmdlineIsHAProxyForConfig(c.cmdline, "")
		}
		if got != c.want {
			t.Errorf("%s: = %v, want %v", c.name, got, c.want)
		}
	}
}
