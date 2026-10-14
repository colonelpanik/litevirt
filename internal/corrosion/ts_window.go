package corrosion

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// What kind of break AuditVerifyResult.BrokenAt is. The verifier used to call
// every broken link "row content does not match its recorded hash", which is
// true of an edit and false of the two other ways a link breaks.
const (
	// AuditBrokenContent: the row does not hash to its stored content_hash even
	// against its own stored prev_hash. Its content was changed after it was
	// written.
	AuditBrokenContent = "content"
	// AuditBrokenForked: the row hashes correctly against its own stored
	// prev_hash, that prev_hash is empty, and it is a second seq 1 for its host
	// — the first row of a second chain opened under a host name that already
	// had one. A host rebuilt on an
	// empty database that appended before its history replicated back writes
	// exactly this.
	AuditBrokenForked = "forked"
	// AuditBrokenUnlinked: the row hashes correctly against its own stored
	// prev_hash, but that is not the hash of the row before it in the walk, and
	// it is not a second genesis — a row between them was deleted or
	// rewritten, the chain branched, or this row was itself rewritten together
	// with its prev_hash and hash.
	AuditBrokenUnlinked = "unlinked"
)

// TimeWindow bounds a query on a stored timestamp column. A zero bound is open.
// Until is INCLUSIVE: the last instant the window contains.
type TimeWindow struct {
	Since, Until time.Time
}

// IsOpen reports whether neither bound is set.
func (w TimeWindow) IsOpen() bool { return w.Since.IsZero() && w.Until.IsZero() }

// ParseTimeWindow reads a user-supplied since/until pair, as `lv audit ls`, `lv
// audit export`, `lv events <vm>` and the `lv mcp` tools take them (and resolve
// them with Bounds before sending), and as the daemon receives them. An empty
// string leaves that bound open.
//
// These used to be compared to the stored stamps as TEXT, verbatim. The stamps
// are fixed-width UTC with nine fractional digits, and '.' sorts below 'Z', so
// a whole-second bound sorted AFTER every row inside its own second and --since
// dropped them; a bound with an offset compared local digits to UTC ones and
// was wrong by the offset. Parsing the bound and comparing instants fixes both.
//
// Every form that gave a sensible answer under the text comparison is still
// accepted, with the answer it was meant to give:
//
//   - RFC3339, with or without a fraction ('.' or ','), in UTC or with an
//     offset;
//   - the same without a zone, or with a space for the 'T', read as UTC (the
//     stamps are UTC, which is what the text comparison assumed);
//   - minute, hour, date, month and year precision (2026-06-01T12:30,
//     2026-06-01T12, 2026-06-01, 2026-06, 2026);
//   - a bare integer other than a four-digit year, as Unix seconds; "0" is
//     therefore the beginning, which is what `--since 0` returned as text;
//   - a Go duration (90m, 24h), meaning that long before now. Under the text
//     comparison "1h" sorted below every stamp, so it was accepted and meant
//     nothing (every stamp sorted above it); it now means what an operator
//     typing it means.
//
// A bound covers the whole unit it names. --since starts at the beginning of
// it and --until runs to the end of it, so `--until 2026-06-30` takes in all
// of 30 June and `--until 22:16:30Z` all of that second. The second case is
// what the text comparison happened to do, and the export docs' own example
// (`--until 2026-06-30T23:59:59Z`) depends on it.
//
// No bound lies past the last representable stamp, 9999-12-31T23:59:59.999999999Z
// (maxStamp). One written with a negative offset can, once converted to UTC, and
// year 10000 would be rendered with five digits, which sort as text below every
// real stamp: an until there matched nothing and a since everything. Both are
// clamped to maxStamp, so an until there still matches every row and a since
// matches nothing after that instant.
//
// Anything else names no instant and is an error that says which bound it was.
func ParseTimeWindow(since, until string, now time.Time) (TimeWindow, error) {
	var w TimeWindow
	if since != "" {
		start, _, err := parseTimeBound(since, now)
		if err != nil {
			return w, fmt.Errorf("since: %w", err)
		}
		w.Since = start
	}
	if until != "" {
		_, end, err := parseTimeBound(until, now)
		if err != nil {
			return w, fmt.Errorf("until: %w", err)
		}
		w.Until = end
	}
	return w, nil
}

// timeBoundForms are the accepted layouts, most specific first, each with the
// unit a bound in that form covers. A nil unit means "the precision of the
// fraction as written" (whole seconds when there is none).
var timeBoundForms = []struct {
	layout string
	next   func(time.Time) time.Time // the first instant AFTER the unit
}{
	{time.RFC3339Nano, nil},
	{"2006-01-02T15:04:05", nil},
	{"2006-01-02 15:04:05Z07:00", nil},
	{"2006-01-02 15:04:05", nil},
	{"2006-01-02T15:04", func(t time.Time) time.Time { return t.Add(time.Minute) }},
	{"2006-01-02 15:04", func(t time.Time) time.Time { return t.Add(time.Minute) }},
	{"2006-01-02T15", func(t time.Time) time.Time { return t.Add(time.Hour) }},
	{"2006-01-02 15", func(t time.Time) time.Time { return t.Add(time.Hour) }},
	{"2006-01-02", func(t time.Time) time.Time { return t.AddDate(0, 0, 1) }},
	{"2006-01", func(t time.Time) time.Time { return t.AddDate(0, 1, 0) }},
	{"2006", func(t time.Time) time.Time { return t.AddDate(1, 0, 0) }},
}

// maxStamp is the last instant a fixed-width stamp can carry.
var maxStamp = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)

// parseTimeBound returns the first and the last instant s covers, never past
// maxStamp.
func parseTimeBound(s string, now time.Time) (first, last time.Time, err error) {
	first, last, err = parseTimeBoundUnclamped(s, now)
	if first.After(maxStamp) {
		first = maxStamp
	}
	if last.After(maxStamp) {
		last = maxStamp
	}
	return first, last, err
}

func parseTimeBoundUnclamped(s string, now time.Time) (first, last time.Time, err error) {
	for _, f := range timeBoundForms {
		t, perr := time.Parse(f.layout, s)
		if perr != nil {
			continue
		}
		t = t.UTC()
		if f.next != nil {
			return t, f.next(t).Add(-time.Nanosecond), nil
		}
		return t, t.Add(fractionUnit(s) - time.Nanosecond), nil
	}
	// A bare integer other than a 4-digit year is a Unix time in seconds. "0"
	// is therefore the beginning: under the text comparison `--since 0` sorted
	// below every stamp and returned every row, and it still does.
	if isDigits(s) {
		if n, nerr := strconv.ParseInt(s, 10, 64); nerr == nil && n <= maxUnixBound {
			t := time.Unix(n, 0).UTC()
			return t, t.Add(time.Second - time.Nanosecond), nil
		}
	}
	if d, derr := time.ParseDuration(s); derr == nil {
		if d < 0 {
			return first, last, fmt.Errorf("%q is a negative duration; a relative bound is how long AGO, e.g. 24h", s)
		}
		t := now.UTC().Add(-d)
		return t, t, nil
	}
	return first, last, fmt.Errorf("cannot read %q as a time: want an RFC3339 timestamp "+
		"(2026-06-01T00:00:00Z, or with an offset), a coarser one (2026-06-01T12:30, 2026-06-01T12, "+
		"2026-06-01, 2026-06, 2026), Unix seconds (1780272000), or a duration ago (24h)", s)
}

// maxUnixBound is the last Unix second a stamp can carry (9999-12-31T23:59:59Z).
const maxUnixBound = 253402300799

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// fractionUnit is the smallest step the seconds field of s was written to: one
// second with no fraction, 100ms for ".5", 1ns for nine digits.
func fractionUnit(s string) time.Duration {
	// The seconds field is the 18th-19th byte in every accepted layout with
	// seconds, so a fraction starts at index 19.
	// time.Parse accepts ',' as the fraction separator as well as '.'.
	if len(s) <= 19 || (s[19] != '.' && s[19] != ',') {
		return time.Second
	}
	digits := 0
	for _, r := range s[20:] {
		if r < '0' || r > '9' {
			break
		}
		digits++
	}
	unit := time.Second
	for i := 0; i < digits && unit > time.Nanosecond; i++ {
		unit /= 10
	}
	return unit
}

// Predicate renders w as a SQL condition on the timestamp column col, with its
// arguments. It returns "" when w is open. col must be a column name the caller
// controls, never user input.
//
// Two parts per bound. The first compares col to the bound's whole second as
// TEXT, which the column's index can serve, and is exact everywhere but inside
// that second. The second normalises col to the fixed-width layout and compares
// it to the bound at full precision, which is exact inside it. The second part
// is not redundant: rows written before stamps were fixed-width are still in
// every long-lived table, trimmed (".5Z", or no fraction at all), and those
// sort wrongly as text against a fixed-width bound in the same second.
func (w TimeWindow) Predicate(col string) (string, []any) {
	norm := normalisedTSExpr(col)
	var conds []string
	var args []any
	if !w.Since.IsZero() {
		s := w.Since.UTC()
		conds = append(conds, fmt.Sprintf("(%s >= ? AND %s >= ?)", col, norm))
		args = append(args, s.Format("2006-01-02T15:04:05"), s.Format(nowTSLayout))
	}
	if !w.Until.IsZero() {
		u := w.Until.UTC()
		if next := u.Truncate(time.Second).Add(time.Second); next.Year() <= 9999 {
			conds = append(conds, fmt.Sprintf("(%s < ? AND %s <= ?)", col, norm))
			args = append(args, next.Format("2006-01-02T15:04:05"), u.Format(nowTSLayout))
		} else {
			// The second after a bound in the last second of year 9999 is year
			// 10000, which formats with five digits and sorts as text BELOW
			// every real stamp — `--until 9999-12-31` would match nothing. No
			// stamp can lie past it, so the exact part alone is the bound.
			conds = append(conds, fmt.Sprintf("(%s <= ?)", norm))
			args = append(args, u.Format(nowTSLayout))
		}
	}
	return strings.Join(conds, " AND "), args
}

// Bounds renders w as the fixed-width UTC stamps the tables store ("" for an
// open bound): Since as its first instant, Until as its last. A client sends
// these instead of what the user typed, so that even a daemon that compares
// the bound as text — one older than ParseTimeWindow — draws the window in the
// right place, and a relative bound is resolved once, on the client.
func (w TimeWindow) Bounds() (since, until string) {
	if !w.Since.IsZero() {
		since = w.Since.UTC().Format(nowTSLayout)
	}
	if !w.Until.IsZero() {
		until = w.Until.UTC().Format(nowTSLayout)
	}
	return since, until
}

// normalisedTSExpr is col rewritten to nowTSLayout: a fixed-width stamp as is, a
// trimmed RFC3339Nano UTC stamp with its fraction padded to nine digits. Every
// writer stamps in UTC, so only the fraction varies.
func normalisedTSExpr(col string) string {
	return fmt.Sprintf(`(CASE WHEN length(%[1]s) = 30 THEN %[1]s `+
		`WHEN substr(%[1]s, 20, 1) = '.' THEN substr(%[1]s, 1, 20) || substr(substr(%[1]s, 21, length(%[1]s) - 21) || '000000000', 1, 9) || 'Z' `+
		`ELSE substr(%[1]s, 1, 19) || '.000000000Z' END)`, col)
}
