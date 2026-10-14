package cli

import (
	"strings"
	"testing"
)

func TestHostUpdatesSummary(t *testing.T) {
	cases := []struct {
		labels map[string]string
		want   string
	}{
		{nil, "-"},
		{map[string]string{"litevirt.os-updates": "0", "litevirt.os-security-updates": "0"}, "0"},
		{map[string]string{"litevirt.os-updates": "5", "litevirt.os-security-updates": "0"}, "5"},
		{map[string]string{"litevirt.os-updates": "5", "litevirt.os-security-updates": "2"}, "5 (2 security)"},
		{map[string]string{"litevirt.os-updates": "unknown", "litevirt.os-security-updates": "unknown"}, "?"},
	}
	for _, c := range cases {
		if got := HostUpdatesSummary(c.labels); got != c.want {
			t.Errorf("%v: got %q want %q", c.labels, got, c.want)
		}
	}
}

func TestHostUpdatesNote(t *testing.T) {
	if n := hostUpdatesNote("h", map[string]string{"litevirt.os-updates": "0", "litevirt.os-security-updates": "0"}); n != "" {
		t.Errorf("nothing pending, want no note, got %q", n)
	}
	if n := hostUpdatesNote("h", map[string]string{"litevirt.os-updates": "3", "litevirt.os-security-updates": "1"}); !strings.Contains(n, "SECURITY") {
		t.Errorf("security must be flagged: %q", n)
	}
	if n := hostUpdatesNote("h", map[string]string{"litevirt.os-updates": "unknown", "litevirt.os-security-updates": "unknown"}); !strings.Contains(n, "unknown") {
		t.Errorf("a failed check must say unknown: %q", n)
	}
}
