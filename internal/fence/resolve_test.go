package fence

import "testing"

func TestResolveStrategy(t *testing.T) {
	cases := map[string]string{
		"":             "best-effort",
		"best-effort":  "best-effort",
		"BEST-EFFORT":  "best-effort",
		"  best-effort ": "best-effort",
		"garbage":      "best-effort", // unknown → lenient best-effort (matches Execute default)
		"ipmi":         "ipmi",
		"IPMI":         "ipmi",
		"ssh":          "ssh",
		"manual":       "manual",
		"watchdog":     "watchdog",
	}
	for in, want := range cases {
		if got := ResolveStrategy(in); got != want {
			t.Errorf("ResolveStrategy(%q) = %q, want %q", in, got, want)
		}
	}
}
