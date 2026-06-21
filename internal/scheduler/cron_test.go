package scheduler

import (
	"testing"
	"time"
)

func TestParseCron_Errors(t *testing.T) {
	for _, bad := range []string{
		"",
		"* * * *",     // 4 fields
		"* * * * * *", // 6 fields
		"60 * * * *",  // minute out of range
		"* 24 * * *",  // hour out of range
		"* * 0 * *",   // day-of-month must be ≥1
		"* * * 13 *",  // month out of range
		"* * * * 8",   // dow > 7
		"a * * * *",   // not numeric
		"5-3 * * * *", // inverted range
		"*/0 * * * *", // zero step
	} {
		if _, err := ParseCron(bad); err == nil {
			t.Errorf("ParseCron(%q) should fail", bad)
		}
	}
}

func TestCronMatches(t *testing.T) {
	mustParse := func(expr string) Cron {
		c, err := ParseCron(expr)
		if err != nil {
			t.Fatalf("ParseCron(%q): %v", expr, err)
		}
		return c
	}
	at := func(s string) time.Time {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return ts
	}
	cases := []struct {
		expr  string
		when  string
		match bool
	}{
		// Daily 02:00.
		{"0 2 * * *", "2026-01-01T02:00:00Z", true},
		{"0 2 * * *", "2026-01-01T02:01:00Z", false},
		{"0 2 * * *", "2026-01-01T03:00:00Z", false},
		// Every 15 min.
		{"*/15 * * * *", "2026-01-01T00:00:00Z", true},
		{"*/15 * * * *", "2026-01-01T00:15:00Z", true},
		{"*/15 * * * *", "2026-01-01T00:14:00Z", false},
		// Sunday 03:30 (Sunday = 0).
		{"30 3 * * 0", "2026-05-10T03:30:00Z", true}, // 2026-05-10 is a Sunday
		{"30 3 * * 0", "2026-05-11T03:30:00Z", false},
		// Sunday with dow=7 (alias).
		{"30 3 * * 7", "2026-05-10T03:30:00Z", true},
		// Vixie semantics: both dom + dow → either.
		{"0 0 1 * 0", "2026-01-04T00:00:00Z", true}, // Sunday
		{"0 0 1 * 0", "2026-02-01T00:00:00Z", true}, // 1st of month
		{"0 0 1 * 0", "2026-01-05T00:00:00Z", false},
		// Range 9-17 hours, weekdays.
		{"0 9-17 * * 1-5", "2026-05-11T09:00:00Z", true},  // Mon
		{"0 9-17 * * 1-5", "2026-05-11T17:00:00Z", true},
		{"0 9-17 * * 1-5", "2026-05-11T18:00:00Z", false},
		{"0 9-17 * * 1-5", "2026-05-09T10:00:00Z", false}, // Sat
	}
	for _, tc := range cases {
		c := mustParse(tc.expr)
		got := c.Matches(at(tc.when))
		if got != tc.match {
			t.Errorf("Matches(%q, %q) = %v, want %v", tc.expr, tc.when, got, tc.match)
		}
	}
}
