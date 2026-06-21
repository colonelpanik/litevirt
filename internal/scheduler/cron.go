package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Cron is a parsed 5-field standard cron expression:
//
//	min hour dom month dow
//
// Each field accepts:
//
//	*           — any value
//	N           — literal
//	a,b,c       — list of literals
//	a-b         — inclusive range
//	*/k         — every k starting at the field's lower bound
//	a-b/k       — every k within a range
//
// Day-of-week is 0-6 (Sun = 0); 7 is also accepted for Sun.
// Day-of-month and day-of-week match independently — if either is set
// to a literal/list, a tick fires when *either* matches (Vixie cron
// semantics). A bare * on both means "match always".
type Cron struct {
	expr  string
	min   fieldMask
	hour  fieldMask
	dom   fieldMask
	month fieldMask
	dow   fieldMask
	// rawDOM/rawDOW track whether the operator explicitly restricted
	// either day field. When both are restricted, fire if EITHER
	// matches (Vixie semantics).
	rawDOM bool
	rawDOW bool
}

type fieldMask uint64 // bit per allowed value (0..63 spans every cron field)

// String returns the original expression for logging.
func (c Cron) String() string { return c.expr }

// ParseCron parses a 5-field standard cron expression.
func ParseCron(expr string) (Cron, error) {
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return Cron{}, fmt.Errorf("cron %q: want 5 fields, got %d", expr, len(parts))
	}
	c := Cron{expr: expr}
	var err error
	if c.min, err = parseField(parts[0], 0, 59); err != nil {
		return Cron{}, fmt.Errorf("cron %q minute: %w", expr, err)
	}
	if c.hour, err = parseField(parts[1], 0, 23); err != nil {
		return Cron{}, fmt.Errorf("cron %q hour: %w", expr, err)
	}
	if c.dom, err = parseField(parts[2], 1, 31); err != nil {
		return Cron{}, fmt.Errorf("cron %q day-of-month: %w", expr, err)
	}
	if c.month, err = parseField(parts[3], 1, 12); err != nil {
		return Cron{}, fmt.Errorf("cron %q month: %w", expr, err)
	}
	if c.dow, err = parseField(parts[4], 0, 7); err != nil {
		return Cron{}, fmt.Errorf("cron %q day-of-week: %w", expr, err)
	}
	// Normalize Sun=7 → Sun=0 so day-of-week comparisons see 0 only.
	if c.dow&(1<<7) != 0 {
		c.dow = (c.dow &^ (1 << 7)) | 1
	}
	c.rawDOM = parts[2] != "*"
	c.rawDOW = parts[4] != "*"
	return c, nil
}

// Matches reports whether the given time matches the cron expression
// at minute granularity. Seconds and sub-second resolution are ignored.
func (c Cron) Matches(t time.Time) bool {
	if c.min&(1<<uint(t.Minute())) == 0 {
		return false
	}
	if c.hour&(1<<uint(t.Hour())) == 0 {
		return false
	}
	if c.month&(1<<uint(t.Month())) == 0 {
		return false
	}
	domHit := c.dom&(1<<uint(t.Day())) != 0
	dowHit := c.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case c.rawDOM && c.rawDOW:
		// Vixie semantics: either matches.
		return domHit || dowHit
	case c.rawDOM:
		return domHit
	case c.rawDOW:
		return dowHit
	default:
		return true
	}
}

func parseField(spec string, lo, hi int) (fieldMask, error) {
	if spec == "" {
		return 0, fmt.Errorf("empty field")
	}
	var mask fieldMask
	for _, term := range strings.Split(spec, ",") {
		m, err := parseTerm(term, lo, hi)
		if err != nil {
			return 0, err
		}
		mask |= m
	}
	return mask, nil
}

func parseTerm(term string, lo, hi int) (fieldMask, error) {
	step := 1
	if i := strings.IndexByte(term, '/'); i >= 0 {
		s, err := strconv.Atoi(term[i+1:])
		if err != nil || s <= 0 {
			return 0, fmt.Errorf("bad step %q", term[i+1:])
		}
		step = s
		term = term[:i]
	}
	rLo, rHi := lo, hi
	switch {
	case term == "*":
		// rLo/rHi already set to field bounds.
	case strings.ContainsRune(term, '-'):
		parts := strings.SplitN(term, "-", 2)
		a, err1 := strconv.Atoi(parts[0])
		b, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return 0, fmt.Errorf("bad range %q", term)
		}
		if a < lo || b > hi || a > b {
			return 0, fmt.Errorf("range %d-%d out of [%d,%d]", a, b, lo, hi)
		}
		rLo, rHi = a, b
	default:
		v, err := strconv.Atoi(term)
		if err != nil {
			return 0, fmt.Errorf("bad value %q", term)
		}
		if v < lo || v > hi {
			return 0, fmt.Errorf("value %d out of [%d,%d]", v, lo, hi)
		}
		rLo, rHi = v, v
	}
	var mask fieldMask
	for i := rLo; i <= rHi; i += step {
		mask |= 1 << uint(i)
	}
	return mask, nil
}
