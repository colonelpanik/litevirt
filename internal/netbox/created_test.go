package netbox

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestListDecodesCreated proves the `created` timestamp survives decoding.
//
// It is the orphan sweeper's only source of an address's age, and the sweeper's
// grace window is what stops it reclaiming an address a create is still in the
// middle of claiming. A field that silently decoded to the zero time would make
// every address look "age unknown" — which fails closed, and therefore fails
// SILENTLY: the sweeper would simply stop reclaiming anything, forever, with no
// error anywhere.
func TestListDecodesCreated(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"id":41,"address":"10.0.5.100/24","created":"2026-01-02T03:04:05Z"}],"next":""}`))
	})
	got, err := c.LookupByAddress(context.Background(), "10.0.5.100/24", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !got[0].Created.Equal(want) {
		t.Errorf("Created = %v, want %v", got[0].Created, want)
	}
}

// TestParseCreatedShapes pins the lenient-but-fail-closed contract on every
// shape NetBox has been observed to serve, plus the shapes it never serves.
//
// The zero-time cases matter most: each one is a value the sweeper must read as
// "I do not know how old this is", which its grace check treats as too young to
// reclaim. A parser that guessed a timestamp for unreadable input would hand the
// sweeper a confident age it has no right to.
func TestParseCreatedShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want time.Time
	}{
		{"rfc3339_utc", "2026-01-02T03:04:05Z", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		{"rfc3339_offset", "2026-01-02T04:04:05+01:00", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		{"rfc3339_nano", "2026-01-02T03:04:05.123456Z", time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)},
		{"naive_datetime", "2026-01-02T03:04:05", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
		// NetBox 3.x's date-only form is REFUSED, not coerced. Midnight UTC is
		// not an approximate answer, it is a systematically EARLY one: against a
		// 30-minute grace window it puts every object created after 00:30 UTC
		// already past the cutoff, so the window that protects an in-flight
		// create would be open for 23½ hours of every day. Zero means "age
		// unknown", which the sweeper reads as too young to reclaim.
		{"date_only_netbox3", "2026-01-02", time.Time{}},
		{"empty", "", time.Time{}},
		{"whitespace", "   ", time.Time{}},
		{"garbage", "yesterday", time.Time{}},
		{"epoch_seconds", "1767322000", time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCreated(tc.raw)
			if !got.Equal(tc.want) {
				t.Fatalf("parseCreated(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
