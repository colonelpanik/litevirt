package metrics

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestClassifyMetricsBind pins how far each bind spelling reaches.
//
// The endpoint has no TLS and no authentication and serves the cluster's
// inventory plus litevirt_enforcement_* — a readout of which security
// kill-switches are off. Classification is what decides whether an operator is
// told, so a wrong answer here is silent in both directions: a missed wildcard
// leaves a real exposure unannounced, and a false positive is noise nobody can
// silence, which is how a startup warning becomes one everybody skips.
func TestClassifyMetricsBind(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind string
		want metricsExposure
		why  string
	}{
		{"empty is the default", "", metricsBindWildcard,
			"the default binds every interface and is the case nobody chose"},
		{"IPv4 wildcard", "0.0.0.0", metricsBindWildcard, ""},
		// Both IPv6 wildcard spellings, and they are NOT interchangeable in the
		// original code: "::" produced ":::7444" and failed to listen at all,
		// while "[::]" bound every interface with no warning. String-matching
		// the spellings got this exactly backwards — it warned about the one
		// that could not work and stayed silent on the one that did.
		{"IPv6 wildcard, bare", "::", metricsBindWildcard,
			"this spelling could not even listen before; now it can"},
		{"IPv6 wildcard, bracketed", "[::]", metricsBindWildcard,
			"this one always listened on every interface and never warned"},
		{"loopback", "127.0.0.1", metricsBindRestricted, ""},
		{"IPv6 loopback", "::1", metricsBindRestricted, ""},
		{"RFC1918 management address", "10.13.200.5", metricsBindRestricted,
			"the recommended configuration must not warn"},
		{"RFC1918 /16", "192.168.1.10", metricsBindRestricted, ""},
		{"IPv6 ULA", "fc00::1", metricsBindRestricted, ""},
		{"link-local", "169.254.1.1", metricsBindRestricted, ""},
		// netip classifies a tailnet address exactly like 8.8.8.8 — not private,
		// global unicast — so without the CGNAT carve-out a restricted tailnet
		// bind would warn.
		{"CGNAT / tailnet", "100.101.102.103", metricsBindRestricted,
			"a tailnet bind is a deliberately restricted choice"},
		{"a public address", "203.0.113.5", metricsBindPublic,
			"as world-readable as the wildcard, and almost never deliberate here"},
		{"a public IPv6 address", "2606:4700::1111", metricsBindPublic, ""},
		// Not resolved on purpose: resolution can block at startup and can
		// disagree with what the listener does.
		{"a hostname is not classified", "metrics.internal", metricsBindRestricted,
			"a false warning an operator cannot silence is worse than silence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyMetricsBind(tc.bind); got != tc.want {
				t.Errorf("classifyMetricsBind(%q) = %v, want %v — %s", tc.bind, got, tc.want, tc.why)
			}
		})
	}
}

// TestNormalizeBind_ProducesAListenableAddress is the half a classification test
// cannot reach: whether the address the listener is actually given works.
//
// The original code composed it with Sprintf("%s:%d"), so metrics_bind "::"
// became ":::7444" — "too many colons" — ListenAndServe failed, and Start only
// LOGGED that error, leaving the node with no metrics endpoint at all. A
// classification test alone would have called that bind a warned wildcard and
// never noticed it served nothing.
func TestNormalizeBind_ProducesAListenableAddress(t *testing.T) {
	for _, bind := range []string{"", "0.0.0.0", "::", "[::]", "127.0.0.1", "::1"} {
		t.Run("bind="+bind, func(t *testing.T) {
			addr := net.JoinHostPort(normalizeBind(bind), strconv.Itoa(0))
			l, err := net.Listen("tcp", addr)
			if err != nil {
				t.Fatalf("metrics_bind %q composes to %q, which cannot listen: %v — the daemon "+
					"would log this and serve no metrics at all", bind, addr, err)
			}
			l.Close()
		})
	}
}

// TestWarnIfMetricsWorldReadable pins that the operator is actually told, and
// what they are told. A warning without the remedy leaves them to work out both
// what leaks and what to set, from one line among a great deal of startup output.
func TestWarnIfMetricsWorldReadable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		bind     string
		wantWarn bool
		wantWord string // distinguishes the wildcard message from the public one
	}{
		{"the default warns", "", true, "EVERY interface"},
		{"a public address warns differently", "203.0.113.5", true, "PUBLIC"},
		{"loopback stays quiet", "127.0.0.1", false, ""},
		{"a management address stays quiet", "10.13.200.5", false, ""},
		{"a tailnet address stays quiet", "100.101.102.103", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An INJECTED logger, never slog.SetDefault. SetDefault also rewires
			// the std log package, and its restore path skips that when the
			// previous handler is the default one — so a save/restore pair
			// permanently routes std-log writes into this dead buffer for the
			// rest of the test binary, silently swallowing diagnostics in every
			// file that sorts after this one.
			log, records := recordingLogger()
			warnIfMetricsWorldReadable(log, tc.bind, 7444)

			got := records()
			if warned := strings.Contains(got, "level=WARN"); warned != tc.wantWarn {
				t.Fatalf("warned = %v, want %v for metrics_bind=%q; log was %q",
					warned, tc.wantWarn, tc.bind, got)
			}
			if !tc.wantWarn {
				return
			}
			if !strings.Contains(got, tc.wantWord) {
				t.Errorf("warning does not say %q, so the two exposures read alike; got %q",
					tc.wantWord, got)
			}
			// Asserted per SOURCE, because the two halves can be gutted
			// independently: the attributes alone satisfy a bare "7444" match,
			// so a message reduced to slog.Warn("exposed", "port", port,
			// "metrics_bind", bind) would still pass a combined check.
			msg := messageOf(warnRecord(got))
			for _, want := range []string{"authentication", "litevirt_enforcement", "metrics_bind"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the warning MESSAGE does not mention %q, so it no longer says what "+
						"leaks or what to set; message was %q", want, msg)
				}
			}
			// The attributes carry the two values an operator acts on. Dropping
			// the bindAddr attribute leaves the log without the bad value.
			for _, want := range []string{"port=7444", "metrics_bind="} {
				if !strings.Contains(got, want) {
					t.Errorf("warning is missing attribute %q; got %q", want, got)
				}
			}
			// Exactly one record: the doc comment and configuration.md both say
			// "at startup", and strings.Contains cannot count, so an
			// implementation warning per scrape would otherwise pass.
			if n := strings.Count(got, "level=WARN"); n != 1 {
				t.Errorf("emitted %d warnings, want exactly 1 — this is a startup notice, "+
					"not a per-request one", n)
			}
		})
	}
}

// syncBuffer is an io.Writer whose contents can be read concurrently.
//
// A bare bytes.Buffer cannot be: slog writes it from whatever goroutine logs,
// and TestStart_EmitsTheExposureWarning polls it from the test goroutine while
// Start runs. Guarding only the READ side, as a first version did, guards
// nothing — `go test -race` reported the write/read pair as a data race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// recordingLogger returns a logger writing to a synchronized buffer, and a
// reader for it. Nothing global is touched — see the comment at the call site.
func recordingLogger() (*slog.Logger, func() string) {
	b := &syncBuffer{}
	h := slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelInfo})
	return slog.New(h), b.String
}

// warnRecord returns the one WARN line out of an accumulated log buffer, so an
// assertion targets the exposure warning and not whatever else was logged.
//
// This is the reason messageOf takes a single record rather than the buffer:
// fed the buffer it returns the FIRST msg= it finds, and the one production
// path that emits this warning logs an Info line immediately above it
// (server.go: "metrics server starting"), so every message assertion would
// silently read that instead. The `level=WARN` count check cannot catch it —
// the extra record is Info.
func warnRecord(records string) string {
	for _, line := range strings.Split(records, "\n") {
		if strings.Contains(line, "level=WARN") {
			return line
		}
	}
	return ""
}

// messageOf extracts the msg="..." field from ONE log record, so an assertion
// can target the human-readable text rather than being satisfied by an
// attribute value. Pass it warnRecord(...), never a whole buffer.
func messageOf(record string) string {
	const key = `msg="`
	i := strings.Index(record, key)
	if i < 0 {
		return ""
	}
	rest := record[i+len(key):]
	if j := strings.Index(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return rest
}

// TestStart_EmitsTheExposureWarning is the test whose absence made the
// "mutation-verified" claim in the previous commit false.
//
// Every other test here calls warnIfMetricsWorldReadable directly, so deleting
// its CALL SITE in Start left the whole suite green — the function stayed
// referenced by its own tests, so even an unused-code linter said nothing. The
// entire operator-visible behaviour could be removed without a single failure.
// CLAUDE.md's worked example for the mutation rule is this exact shape: a test
// that passed with the wiring deleted.
//
// The server gets its own Prometheus registry. Start registers a collector, and
// Stop does not unregister, so sharing the default registerer made this panic
// with "duplicate metrics collector registration attempted" on the second run
// of `go test -count=2` — no second caller or parallelism needed.
func TestStart_EmitsTheExposureWarning(t *testing.T) {
	db := testDB(t)
	log, records := recordingLogger()

	// Port 0 so the listener takes an ephemeral port instead of colliding with
	// anything real; the bind is what this test is about.
	s := NewServer(0, "", db, nil, nil, "host-a")
	s.log = log
	s.reg = prometheus.NewRegistry()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Start()
	}()
	t.Cleanup(func() {
		s.Stop(context.Background())
		<-done
	})

	// Start logs before it blocks in ListenAndServe, so the records are there as
	// soon as the listener is up.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(records(), "level=WARN") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	got := records()
	if !strings.Contains(got, "level=WARN") {
		t.Fatalf("Start() bound every interface and emitted no exposure warning; the wiring "+
			"is what makes this feature exist, and every other test here would still pass "+
			"with it deleted. Log was:\n%s", got)
	}
	// Scoped to the WARN record, not the buffer: Start logs an Info line
	// immediately above the warning, so a buffer-wide match here would be
	// satisfiable by the wrong record.
	warn := warnRecord(got)
	if !strings.Contains(warn, "metrics_bind") {
		t.Errorf("the warning Start() emitted does not name the setting; the WARN record was %q, "+
			"full log:\n%s", warn, got)
	}
	if !strings.Contains(messageOf(warn), "authentication") {
		t.Errorf("the warning Start() emitted no longer says what leaks; message was %q",
			messageOf(warn))
	}
}

// TestStop_BeforeStart_PreventsServing pins that a shutdown requested during
// startup is not lost.
//
// Start assigns httpSrv from whatever goroutine the daemon launched it on
// (`go d.metrics.Start()`), and Stop runs on the shutdown path. Unsynchronised,
// Stop could read nil, skip the shutdown, and leave an unauthenticated endpoint
// serving after shutdown had been requested — and the pair was a data race
// besides. A test that waits for a log line before stopping cannot reach this:
// it only exercises the ordering where Start already won.
func TestStop_BeforeStart_PreventsServing(t *testing.T) {
	db := testDB(t)
	log, _ := recordingLogger()

	s := NewServer(0, "127.0.0.1", db, nil, nil, "host-a")
	s.log = log
	s.reg = prometheus.NewRegistry()

	// Stop FIRST, before anything has listened.
	s.Stop(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Start()
	}()

	select {
	case <-done:
		// Start returned without serving, which is the whole point.
	case <-time.After(5 * time.Second):
		t.Fatal("Start kept serving after Stop had already been called; a shutdown requested " +
			"during startup must not be lost, or the endpoint outlives the daemon that closed it")
	}

	if s.httpSrv != nil {
		t.Error("Start published a listener despite Stop having run first")
	}
}
