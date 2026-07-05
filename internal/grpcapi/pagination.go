package grpcapi

import (
	"encoding/base64"
	"strings"
)

// encodePageToken builds an opaque keyset-pagination cursor from ordered key
// parts (joined by NUL, base64url-encoded). No parts → empty token, which the
// handlers use to mean "no next page".
func encodePageToken(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, "\x00")))
}

// decodePageToken reverses encodePageToken. An empty or malformed token yields
// nil, i.e. start from the beginning — a bad cursor degrades to the first page
// rather than erroring.
func decodePageToken(tok string) []string {
	if tok == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return nil
	}
	return strings.Split(string(raw), "\x00")
}
