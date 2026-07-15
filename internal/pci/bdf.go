package pci

import (
	"fmt"
	"strings"
)

// CanonicalBDF normalizes a PCI address (bus:device.function, optionally with a
// domain) to its canonical form: a lowercase, zero-padded "dddd:bb:dd.f". It accepts
// the common short form "bb:dd.f" (domain defaults to 0000). It returns ok=false for
// a malformed or ambiguous value — the caller warns and ignores/degrades rather than
// silently mis-adopting a device.
//
// Examples:
//
//	"0000:41:00.0" → "0000:41:00.0"
//	"41:00.0"      → "0000:41:00.0"
//	"AB:0C.1"      → "0000:ab:0c.1"
//	"garbage"      → ("", false)
func CanonicalBDF(s string) (string, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return "", false
	}

	domain := "0000"
	rest := s
	// Split off an optional domain: a "dddd:" prefix leaving one more ":" in rest.
	if i := strings.IndexByte(s, ':'); i >= 0 {
		if strings.Count(s, ":") == 2 {
			domain = s[:i]
			rest = s[i+1:]
		}
	}

	// rest must be "bb:dd.f".
	colon := strings.IndexByte(rest, ':')
	dot := strings.IndexByte(rest, '.')
	if colon < 0 || dot < 0 || dot < colon {
		return "", false
	}
	bus := rest[:colon]
	dev := rest[colon+1 : dot]
	fn := rest[dot+1:]

	// Validate widths + hex, then re-pad to the canonical widths.
	dv, ok := parseHex(domain, 1, 4)
	if !ok {
		return "", false
	}
	bv, ok := parseHex(bus, 1, 2)
	if !ok {
		return "", false
	}
	dvv, ok := parseHex(dev, 1, 2)
	if !ok || dvv > 0x1f { // device is 5 bits
		return "", false
	}
	fv, ok := parseHex(fn, 1, 1)
	if !ok || fv > 7 { // function is 3 bits
		return "", false
	}
	return fmt.Sprintf("%04x:%02x:%02x.%x", dv, bv, dvv, fv), true
}

// parseHex parses a hex string of 1..maxLen digits into a uint64.
func parseHex(s string, minLen, maxLen int) (uint64, bool) {
	if len(s) < minLen || len(s) > maxLen {
		return 0, false
	}
	var v uint64
	for _, r := range s {
		var d uint64
		switch {
		case r >= '0' && r <= '9':
			d = uint64(r - '0')
		case r >= 'a' && r <= 'f':
			d = uint64(r-'a') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}
