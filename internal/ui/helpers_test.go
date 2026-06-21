package ui

import (
	"strings"
	"testing"
	"time"
)

func TestHumanCron(t *testing.T) {
	cases := map[string]string{
		"* * * * *":   "Every minute",
		"*/5 * * * *": "Every 5 minutes",
		"0 * * * *":   "Hourly",
		"30 * * * *":  "Hourly at :30",
		"0 2 * * *":   "Daily at 02:00",
		"15 14 * * *": "Daily at 14:15",
		"0 3 * * 1":   "Weekly on Monday at 03:00",
		"0 4 1 * *":   "Monthly on day 1 at 04:00",
		"weird":       "weird",     // not 5 fields → passthrough
		"a b * * *":   "a b * * *", // unparseable min/hour → passthrough
	}
	for expr, want := range cases {
		if got := humanCronHelper(expr); got != want {
			t.Errorf("humanCron(%q) = %q, want %q", expr, got, want)
		}
	}
}

func TestMeterClass(t *testing.T) {
	cases := []struct {
		pct  float64
		want string
	}{{0, ""}, {74.9, ""}, {75, "warn"}, {89, "warn"}, {90, "crit"}, {150, "crit"}}
	for _, c := range cases {
		if got := meterClassHelper(c.pct); got != c.want {
			t.Errorf("meterClass(%v) = %q, want %q", c.pct, got, c.want)
		}
	}
}

func TestPct(t *testing.T) {
	cases := []struct {
		used, limit int64
		want        float64
	}{{0, 0, 0}, {5, 0, 0}, {5, 10, 50}, {10, 10, 100}, {20, 10, 100}, {-1, 10, 0}}
	for _, c := range cases {
		if got := pctHelper(c.used, c.limit); got != c.want {
			t.Errorf("pct(%d,%d) = %v, want %v", c.used, c.limit, got, c.want)
		}
	}
}

func TestDict(t *testing.T) {
	m, err := dictHelper("Title", "Hosts", "Subtitle", "all hosts")
	if err != nil {
		t.Fatalf("dict: %v", err)
	}
	if m["Title"] != "Hosts" || m["Subtitle"] != "all hosts" {
		t.Errorf("dict produced %v", m)
	}
	if _, err := dictHelper("odd"); err == nil {
		t.Error("dict with odd args should error")
	}
}

func TestIconHelper(t *testing.T) {
	if got := string(iconHelper("play")); !strings.Contains(got, `href="#i-play"`) {
		t.Errorf("icon(play) = %q", got)
	}
	if got := iconHelper("nonexistent"); got != "" {
		t.Errorf("icon(nonexistent) = %q, want empty", got)
	}
}

func TestRelTime(t *testing.T) {
	fixed := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	orig := timeNow
	timeNow = func() time.Time { return fixed }
	defer func() { timeNow = orig }()

	cases := []struct {
		in       any
		contains string
	}{
		{fixed.Add(-2 * time.Hour), "2 hours ago"},
		{fixed.Add(-30 * time.Second), "just now"},
		{fixed.Add(-5 * time.Minute), "5 minutes ago"},
		{fixed.Add(-3 * 24 * time.Hour), "3 days ago"},
		{"2026-06-06T10:00:00Z", "2 hours ago"},
		{"", "—"},
		{"never", "—"},
		{"not-a-time", "not-a-time"},
	}
	for _, c := range cases {
		got := string(relTimeHelper(c.in))
		if !strings.Contains(got, c.contains) {
			t.Errorf("relTime(%v) = %q, want contains %q", c.in, got, c.contains)
		}
	}
}
