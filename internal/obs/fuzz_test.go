package obs

import (
	"math"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

// Coverage-guided fuzz targets for the telemetry validation surface.
//
//	make test-fuzz-telemetry FUZZTIME=30s
//	go test ./internal/obs/ -run='^$' -fuzz=FuzzValidEndpoint -fuzztime=30s

// FuzzValidEndpoint: never panics; accepts only http(s) with host and no userinfo.
func FuzzValidEndpoint(f *testing.F) {
	for _, s := range []string{
		"",
		"http://host:4318",
		"https://host:4318/v1/traces",
		"http://user:pass@host:4318",
		"http://user@host:4318",
		"otel-collector:4317",
		"grpc://c:4317",
		"file:///etc/passwd",
		"http://",
		"https://[::1]:4318",
		"http://127.0.0.1:5080/api/default",
		"HTTP://HOST:4318",
		"http://host:4318?x=1#y",
		strings.Repeat("a", 10_000),
		"http://" + strings.Repeat("x", 2000) + ".example:4318",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ok := validEndpoint(raw)
		if !ok {
			return
		}
		// Invariant: every accepted URL is parseable http(s) with host, no userinfo.
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("validEndpoint accepted unparseable %q: %v", raw, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			// url.Parse lowercases scheme; if we accepted, scheme must be http(s)
			// after parse (Parse lowercases).
			if s := strings.ToLower(u.Scheme); s != "http" && s != "https" {
				t.Fatalf("accepted non-http(s) scheme %q in %q", u.Scheme, raw)
			}
		}
		if u.Host == "" {
			t.Fatalf("accepted empty host: %q", raw)
		}
		if u.User != nil {
			t.Fatalf("accepted URL userinfo (credential leak surface): %q", raw)
		}
	})
}

// FuzzValidSampleRate: never panics; ok only for finite values in [0,1].
func FuzzValidSampleRate(f *testing.F) {
	for _, s := range []string{
		"", " ", "0", "1", "0.0", "1.0", "0.1", "0.25", "1e-1", "+0.5",
		"7", "-1", "NaN", "nan", "Inf", "+Inf", "-Inf", "abc", "0.5x", " 0.5", "0.5 ",
		"1.0000001", "-0",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r, ok := validSampleRate(raw)
		if !ok {
			return
		}
		if math.IsNaN(r) || math.IsInf(r, 0) {
			t.Fatalf("validSampleRate(%q) ok with non-finite %v", raw, r)
		}
		if r < 0 || r > 1 {
			t.Fatalf("validSampleRate(%q) ok with out-of-range %v", raw, r)
		}
	})
}

// FuzzSafeEndpointForLog: never panics; never echoes a password that was present.
func FuzzSafeEndpointForLog(f *testing.F) {
	for _, s := range []string{
		"",
		"http://host:4318",
		"http://u:secret@host:4318",
		"https://user:p4ssw0rd@otel.example.com:4318/v1/traces",
		"http://user@host:4318",
		"not a url",
		"http://u:s3cr3tPASS@127.0.0.1:4318",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := SafeEndpointForLog(raw) // must not panic even on invalid UTF-8
		if !utf8.ValidString(raw) {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.User == nil {
			if got != raw {
				t.Fatalf("SafeEndpointForLog changed input without userinfo: in=%q out=%q", raw, got)
			}
			return
		}
		// Userinfo present → output must not retain credentials *in userinfo*.
		// Paths/fragments may still contain the same bytes (not our job to rewrite).
		if got == raw {
			t.Fatalf("userinfo URL left unchanged: %q", raw)
		}
		outU, err := url.Parse(got)
		if err != nil {
			t.Fatalf("SafeEndpointForLog produced unparseable %q from %q: %v", got, raw, err)
		}
		if outU.User == nil {
			return // fully stripped — fine
		}
		if outU.User.Username() != "REDACTED" {
			t.Fatalf("userinfo username not REDACTED: in=%q out=%q user=%q", raw, got, outU.User.Username())
		}
		if pass, ok := outU.User.Password(); ok && pass != "" {
			t.Fatalf("userinfo still has password in output: in=%q out=%q", raw, got)
		}
	})
}
