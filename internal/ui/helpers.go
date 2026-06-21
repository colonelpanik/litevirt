package ui

import (
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"time"
)

// timeNow is overridable in tests so relTime output is deterministic.
var timeNow = time.Now

// ── Icons ────────────────────────────────────────────────────────────────────

// knownIcons gates iconHelper: an unknown name renders nothing rather than a
// broken <use> reference. Every entry must have a matching <symbol id="i-NAME">
// in the sprite embedded in base.html.
var knownIcons = map[string]bool{
	"play": true, "stop": true, "restart": true, "console": true, "vnc": true,
	"backup": true, "restore": true, "delete": true, "edit": true, "snapshot": true,
	"migrate": true, "add": true, "search": true, "host": true, "vm": true,
	"network": true, "storage": true, "disk": true, "alert": true, "check": true,
	"chevron": true,
}

// iconHelper renders an inline SVG <use> reference to a sprite symbol.
func iconHelper(name string) template.HTML {
	if !knownIcons[name] {
		return ""
	}
	return template.HTML(fmt.Sprintf(`<svg class="icon icon-%s" aria-hidden="true"><use href="#i-%s"></use></svg>`, name, name))
}

// ── Relative time ──────────────────────────────────────────────────────────────

// relTimeHelper renders a timestamp as a relative "2h ago" string with the
// absolute value in a title attribute. Accepts a string (RFC3339 or a few
// common layouts) or a time.Time. Unparseable / empty input degrades to an
// em-dash, and a non-time string is echoed verbatim (escaped).
func relTimeHelper(v any) template.HTML {
	t, ok := parseTime(v)
	if !ok {
		raw := strings.TrimSpace(fmt.Sprintf("%v", v))
		if raw == "" || raw == "<nil>" || raw == "never" {
			return template.HTML(`<span class="muted">—</span>`)
		}
		return template.HTML(template.HTMLEscapeString(raw))
	}
	abs := t.UTC().Format("2006-01-02 15:04:05 MST")
	return template.HTML(fmt.Sprintf(`<abbr title="%s">%s</abbr>`, abs, humanizeSince(t)))
}

func parseTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case time.Time:
		if x.IsZero() {
			return time.Time{}, false
		}
		return x, true
	case *time.Time:
		if x == nil || x.IsZero() {
			return time.Time{}, false
		}
		return *x, true
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{
			time.RFC3339Nano, time.RFC3339,
			"2006-01-02T15:04:05.999999999Z07:00",
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
		} {
			if t, err := time.Parse(layout, s); err == nil {
				return t, true
			}
		}
		return time.Time{}, false
	default:
		return time.Time{}, false
	}
}

func humanizeSince(t time.Time) string {
	d := timeNow().Sub(t)
	future := d < 0
	if future {
		d = -d
	}
	var out string
	switch {
	case d < 45*time.Second:
		return "just now"
	case d < 90*time.Second:
		out = "1 minute"
	case d < time.Hour:
		out = fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 2*time.Hour:
		out = "1 hour"
	case d < 24*time.Hour:
		out = fmt.Sprintf("%d hours", int(d.Hours()))
	case d < 48*time.Hour:
		out = "1 day"
	case d < 30*24*time.Hour:
		out = fmt.Sprintf("%d days", int(d.Hours()/24))
	default:
		return t.UTC().Format("2006-01-02")
	}
	if future {
		return "in " + out
	}
	return out + " ago"
}

// ── Cron humanization ──────────────────────────────────────────────────────────

var cronDayNames = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}

// humanCronHelper turns a 5-field cron expression into an English summary for
// the common backup cadences, falling back to the raw expression for anything
// it doesn't recognize.
func humanCronHelper(expr string) string {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return expr
	}
	minF, hourF, domF, monF, dowF := fields[0], fields[1], fields[2], fields[3], fields[4]

	// Every minute / every N minutes.
	if minF == "*" && hourF == "*" && domF == "*" && monF == "*" && dowF == "*" {
		return "Every minute"
	}
	if strings.HasPrefix(minF, "*/") && hourF == "*" && domF == "*" && monF == "*" && dowF == "*" {
		if n, err := strconv.Atoi(strings.TrimPrefix(minF, "*/")); err == nil {
			return fmt.Sprintf("Every %d minutes", n)
		}
	}
	// Hourly (at minute M).
	if hourF == "*" && domF == "*" && monF == "*" && dowF == "*" {
		if m, err := strconv.Atoi(minF); err == nil {
			if m == 0 {
				return "Hourly"
			}
			return fmt.Sprintf("Hourly at :%02d", m)
		}
	}

	m, errM := strconv.Atoi(minF)
	h, errH := strconv.Atoi(hourF)
	if errM != nil || errH != nil {
		return expr
	}
	at := fmt.Sprintf("%02d:%02d", h, m)

	switch {
	case domF == "*" && monF == "*" && dowF == "*":
		return "Daily at " + at
	case domF == "*" && monF == "*" && dowF != "*":
		if d, err := strconv.Atoi(dowF); err == nil && d >= 0 && d <= 6 {
			return "Weekly on " + cronDayNames[d] + " at " + at
		}
	case domF != "*" && monF == "*" && dowF == "*":
		if d, err := strconv.Atoi(domF); err == nil {
			return fmt.Sprintf("Monthly on day %d at %s", d, at)
		}
	}
	return expr
}

// ── Meters / percentages ───────────────────────────────────────────────────────

// meterClassHelper returns the CSS modifier for a usage meter fill.
func meterClassHelper(pct float64) string {
	switch {
	case pct >= 90:
		return "crit"
	case pct >= 75:
		return "warn"
	default:
		return ""
	}
}

// pctHelper computes a used/limit percentage clamped to [0,100]. A non-positive
// limit (unbounded quota) yields 0 so the meter renders empty. Args are `any`
// so templates can pass int32/int64/float without conversion errors.
func pctHelper(used, limit any) float64 {
	u, l := toFloat(used), toFloat(limit)
	if l <= 0 {
		return 0
	}
	p := u / l * 100
	if p > 100 {
		return 100
	}
	if p < 0 {
		return 0
	}
	return p
}

func toFloat(v any) float64 {
	switch x := v.(type) {
	case int:
		return float64(x)
	case int32:
		return float64(x)
	case int64:
		return float64(x)
	case uint32:
		return float64(x)
	case uint64:
		return float64(x)
	case float32:
		return float64(x)
	case float64:
		return x
	default:
		return 0
	}
}

// ── Template plumbing ────────────────────────────────────────────────────────

// dictHelper builds a map from alternating key/value args so a single
// {{template "x" (dict ...)}} call can pass multiple named values to a partial.
func dictHelper(values ...any) (map[string]any, error) {
	if len(values)%2 != 0 {
		return nil, fmt.Errorf("dict: odd number of arguments (%d)", len(values))
	}
	m := make(map[string]any, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict: key %d is not a string", i)
		}
		m[key] = values[i+1]
	}
	return m, nil
}
