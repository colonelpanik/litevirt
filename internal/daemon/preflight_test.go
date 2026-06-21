package daemon

import "testing"

func TestParseSystemctlProps(t *testing.T) {
	in := "KillMode=process\nDelegate=no\nNotAPair\n\nFoo=bar=baz\n"
	got := parseSystemctlProps(in)
	want := map[string]string{
		"KillMode": "process",
		"Delegate": "no",
		"Foo":      "bar=baz",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("[%s] = %q, want %q", k, got[k], v)
		}
	}
}

// TestPreflight_NotUnderSystemdSkips verifies the check is a no-op when
// not running under systemd (no INVOCATION_ID env var).
func TestPreflight_NotUnderSystemdSkips(t *testing.T) {
	t.Setenv("INVOCATION_ID", "")
	if err := preflightUnitCheck(); err != nil {
		t.Errorf("non-systemd preflight returned error: %v", err)
	}
}

// TestPreflight_OverrideEnv verifies the unsafe override skips the check.
func TestPreflight_OverrideEnv(t *testing.T) {
	t.Setenv("LITEVIRT_UNSAFE_NO_KILLMODE_CHECK", "1")
	t.Setenv("INVOCATION_ID", "fake")
	if err := preflightUnitCheck(); err != nil {
		t.Errorf("override should skip; got error: %v", err)
	}
}
