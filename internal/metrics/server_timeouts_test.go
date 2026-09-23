package metrics

import (
	"testing"
	"time"
)

// The metrics endpoint serves an unauthenticated inventory and drives DB queries
// on every scrape. Without server timeouts a slow or hostile client holds a
// connection open indefinitely, and without a deadline on the collector's
// context a stuck query outlives the scrape that asked for it and blocked
// collections accumulate behind it.
func TestMetricsServer_HasRequestTimeouts(t *testing.T) {
	s := NewServer(0, "127.0.0.1", nil, nil, nil, "host-a")
	srv := s.newHTTPServer()

	for _, tc := range []struct {
		name string
		got  time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout},
		{"ReadTimeout", srv.ReadTimeout},
		{"WriteTimeout", srv.WriteTimeout},
		{"IdleTimeout", srv.IdleTimeout},
	} {
		if tc.got <= 0 {
			t.Errorf("%s is unset; a scrape endpoint with no %s lets one client hold "+
				"a connection open for the life of the process", tc.name, tc.name)
		}
	}
}
