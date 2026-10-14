package corrosion

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestParseTimeWindow_Forms pins every bound form `lv audit ls`, `lv audit
// export` and `lv events <vm>` accept, and what each one means.
//
// Before the bounds were parsed they were compared to the stored stamps as
// TEXT, so every string was "accepted" and the meaning fell out of byte order.
// The forms that produced a sensible answer that way are kept, now with the
// answer they were meant to give; only input that never meant anything is
// refused.
func TestParseTimeWindow_Forms(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	T := time.Date(2026, 10, 3, 22, 16, 30, 0, time.UTC)
	maxTS := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	day := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		in        string
		since     time.Time // the lower bound it gives
		untilLast time.Time // the last instant an upper bound of it includes
	}{
		{"2026-10-03T22:16:30Z", T, T.Add(time.Second - 1)},
		{"2026-10-04T00:16:30+02:00", T, T.Add(time.Second - 1)},
		{"2026-10-03T22:16:30.5Z", T.Add(500 * time.Millisecond), T.Add(600*time.Millisecond - 1)},
		{"2026-10-03T22:16:30.767241380Z", T.Add(767241380), T.Add(767241380)},
		{"2026-10-03T22:16:30", T, T.Add(time.Second - 1)},
		{"2026-10-03 22:16:30", T, T.Add(time.Second - 1)},
		{"2026-10-03T22:16", T.Add(-30 * time.Second), T.Add(30*time.Second - 1)},
		{"2026-10-03", day, day.Add(24*time.Hour - 1)},
		{"2026-10", time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Add(-1)},
		{"2026", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Add(-1)},
		{"2026-10-03T22", T.Add(-16*time.Minute - 30*time.Second), T.Add(43*time.Minute + 30*time.Second - 1)},
		{"2026-10-03 22", T.Add(-16*time.Minute - 30*time.Second), T.Add(43*time.Minute + 30*time.Second - 1)},
		{"2026-10-03T22:16:30,5Z", T.Add(500 * time.Millisecond), T.Add(600*time.Millisecond - 1)},
		{"0", time.Unix(0, 0).UTC(), time.Unix(1, 0).UTC().Add(-1)},
		{"1791065790", T, T.Add(time.Second - 1)},
		{"9999", time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)},
		// Past the last representable stamp once converted to UTC: clamped to it,
		// so an until there still matches everything and a since nothing.
		{"9999-12-31T23:59:59-01:00", maxTS, maxTS},
		{"9999-12-31T23:00:00-05:00", maxTS, maxTS},
		{"90m", now.Add(-90 * time.Minute), now.Add(-90 * time.Minute)},
		{"0s", now, now},
	} {
		w, err := ParseTimeWindow(tc.in, tc.in, now)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if !w.Since.Equal(tc.since) {
			t.Errorf("since %q = %s, want %s", tc.in, w.Since.Format(time.RFC3339Nano), tc.since.Format(time.RFC3339Nano))
		}
		if !w.Until.Equal(tc.untilLast) {
			t.Errorf("until %q = %s, want %s", tc.in, w.Until.Format(time.RFC3339Nano), tc.untilLast.Format(time.RFC3339Nano))
		}
	}

	if w, err := ParseTimeWindow("", "", now); err != nil || !w.Since.IsZero() || !w.Until.IsZero() {
		t.Errorf("empty bounds must stay open: %+v, %v", w, err)
	}
	for _, bad := range []string{"yesterday", "-1h", "2026-13-01", "2026-10-03T25:00:00Z"} {
		if _, err := ParseTimeWindow(bad, "", now); err == nil {
			t.Errorf("since %q accepted; it names no instant", bad)
		} else if !strings.Contains(err.Error(), "since") {
			t.Errorf("since %q: error %q does not say which bound", bad, err)
		}
		if _, err := ParseTimeWindow("", bad, now); err == nil {
			t.Errorf("until %q accepted; it names no instant", bad)
		} else if !strings.Contains(err.Error(), "until") {
			t.Errorf("until %q: error %q does not say which bound", bad, err)
		}
	}
}

// TestTimeWindow_PredicateIsTimeOrder holds the SQL predicate to the time order
// over every stamp shape the tables hold.
//
// The bug it pins: a stamp was compared to the bound as text, and '.' sorts
// below 'Z', so a row stamped 22:16:30.767Z fell BEFORE a bound of 22:16:30Z
// and `--since 22:16:30Z` dropped it. An offset bound was off by the offset.
// Rows written before stamps were fixed-width are still in every long-lived
// log, trimmed (".5Z", or no fraction at all), so the predicate is checked
// against those too, not only against the current layout.
func TestTimeWindow_PredicateIsTimeOrder(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

	stamps := []string{
		"2026-10-03T22:16:29.999999999Z",
		"2026-10-03T22:16:30Z", // legacy: whole second, trimmed
		"2026-10-03T22:16:30.000000001Z",
		"2026-10-03T22:16:30.5Z", // legacy: trimmed fraction
		"2026-10-03T22:16:30.767241380Z",
		"2026-10-03T22:16:30.77Z", // legacy
		"2026-10-03T22:16:31.000000000Z",
		"2026-10-03T23:00:00.000000000Z",
		"2026-10-04T00:00:00Z",
	}
	values := strings.TrimSuffix(strings.Repeat("(?),", len(stamps)), ",")
	args := make([]any, len(stamps))
	for i, s := range stamps {
		args[i] = s
	}

	bounds := []string{
		"", "2026-10-03T22:16:30Z", "2026-10-04T00:16:30+02:00", "2026-10-03T22:16:30.5Z",
		"2026-10-03T22:16:30.767241380Z", "2026-10-03T22:16:30.77Z", "2026-10-03T22:16:31Z",
		"2026-10-03", "2026-10-03T22:16", "2026-10-03T22", "0",
		"9999", "9999-12-31", "9999-12-31T23:59:59Z",
		"9999-12-31T23:59:59-01:00", "9999-12-31T23:00:00-05:00",
	}
	for _, since := range bounds {
		for _, until := range bounds {
			w, err := ParseTimeWindow(since, until, now)
			if err != nil {
				t.Fatalf("ParseTimeWindow(%q, %q): %v", since, until, err)
			}
			pred, pargs := w.Predicate("ts")
			q := `WITH t(ts) AS (VALUES ` + values + `) SELECT ts FROM t`
			if pred != "" {
				q += " WHERE " + pred
			}
			rows, err := c.Query(ctx, q+" ORDER BY ts", append(slices.Clone(args), pargs...)...)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			var got []string
			for _, r := range rows {
				got = append(got, r.String("ts"))
			}
			var want []string
			for _, s := range stamps {
				at, err := time.Parse(time.RFC3339Nano, s)
				if err != nil {
					t.Fatal(err)
				}
				if (w.Since.IsZero() || !at.Before(w.Since)) && (w.Until.IsZero() || !at.After(w.Until)) {
					want = append(want, s)
				}
			}
			slices.Sort(got)
			slices.Sort(want)
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("since=%q until=%q:\n got %v\nwant %v", since, until, got, want)
			}
		}
	}
}

// TestTimeWindow_BoundsNeverPassTheMax: a bound past 9999-12-31T23:59:59Z once
// converted to UTC (a year-9999 "forever" written with a negative offset) must
// never be rendered as a year-10000 stamp. Five digits sort as text BELOW every
// real stamp, so an until there matched nothing and a since everything — on
// this daemon through the predicate, and on an older daemon through the stamp
// the CLI and `lv mcp` send it.
func TestTimeWindow_BoundsNeverPassTheMax(t *testing.T) {
	w, err := ParseTimeWindow("9999-12-31T23:00:00-05:00", "9999-12-31T23:59:59-01:00", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	since, until := w.Bounds()
	for _, b := range []string{since, until} {
		if b != "9999-12-31T23:59:59.999999999Z" {
			t.Errorf("bound rendered as %q, want the last representable stamp", b)
		}
	}
	pred, args := w.Predicate("ts")
	for _, a := range args {
		if s, ok := a.(string); ok && strings.HasPrefix(s, "10000") {
			t.Errorf("predicate %s carries a year-10000 argument %q", pred, s)
		}
	}
}
