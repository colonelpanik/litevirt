package notify

import "testing"

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pat, kind string
		want      bool
	}{
		{"*", "backup.failed", true},
		{"", "backup.failed", true},
		{"backup.*", "backup.failed", true},
		{"backup.*", "backup.succeeded", true},
		{"backup.*", "host.fenced", false},
		{"backup.failed", "backup.failed", true},
		{"backup.failed", "backup.succeeded", false},
		{"host.fenced", "host.fenced", true},
		{"replication.*", "replication.failed", true},
		{"quota.exceeded", "backup.failed", false},
	}
	for _, c := range cases {
		if got := MatchPattern(c.pat, c.kind); got != c.want {
			t.Errorf("MatchPattern(%q,%q)=%v want %v", c.pat, c.kind, got, c.want)
		}
	}
}

func TestSeverityAtLeast(t *testing.T) {
	if !SevError.AtLeast(SevWarn) {
		t.Error("error >= warn")
	}
	if SevInfo.AtLeast(SevWarn) {
		t.Error("info should be < warn")
	}
	if !SevWarn.AtLeast(SevWarn) {
		t.Error("warn >= warn")
	}
}

func TestSlackText(t *testing.T) {
	n := Notification{Kind: "backup.failed", Severity: SevError, Subject: "web-1", Detail: "disk full", Cluster: "f3"}
	got := SlackText(n)
	for _, want := range []string{":rotating_light:", "[f3]", "backup.failed", "web-1", "disk full"} {
		if !contains(got, want) {
			t.Errorf("SlackText missing %q in %q", want, got)
		}
	}
}

func TestNewTarget(t *testing.T) {
	if _, err := NewTarget("w", "webhook", `{"url":"http://x"}`); err != nil {
		t.Errorf("webhook: %v", err)
	}
	if _, err := NewTarget("s", "slack", `{"url":"http://x"}`); err != nil {
		t.Errorf("slack: %v", err)
	}
	if _, err := NewTarget("b", "webhook", `{}`); err == nil {
		t.Error("missing url should error")
	}
	if _, err := NewTarget("u", "carrier-pigeon", `{}`); err == nil {
		t.Error("unknown type should error")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
