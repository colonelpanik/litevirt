package grpcapi

import (
	"encoding/base64"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maxPageSize caps a caller-requested page. Without a ceiling, page_size is an
// unbounded fetch (memory + latency) in a single RPC; a caller asking for more
// is silently clamped to this value and keeps paging via the returned cursor.
const maxPageSize = 1000

// encodePageToken builds an opaque keyset-pagination cursor from ordered key
// parts (joined by NUL, base64url-encoded). No parts → empty token, which the
// handlers use to mean "no next page".
func encodePageToken(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, "\x00")))
}

// decodePageToken reverses encodePageToken. It distinguishes an empty token
// (nil, ok=true → start from the beginning) from a malformed one
// (nil, ok=false → corrupt cursor; the handler returns InvalidArgument). A bad
// cursor must not silently restart pagination from page 1 — that would make a
// client loop over the first page forever without noticing.
func decodePageToken(tok string) ([]string, bool) {
	if tok == "" {
		return nil, true
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return nil, false
	}
	return strings.Split(string(raw), "\x00"), true
}

// normalizePageSize validates a caller page_size and clamps it to maxPageSize.
// A negative value is rejected (InvalidArgument); 0 preserves the legacy
// unpaginated path for callers that don't opt in.
func normalizePageSize(n int32) (int, error) {
	if n < 0 {
		return 0, status.Error(codes.InvalidArgument, "page_size must be >= 0")
	}
	size := int(n)
	if size > maxPageSize {
		size = maxPageSize
	}
	return size, nil
}

// pageCursor decodes a keyset cursor that must contain exactly want parts when
// present. An empty token yields nil parts (first page); a decode failure or a
// wrong part count is a malformed cursor → InvalidArgument. Callers read the
// parts positionally only after checking the returned error.
func pageCursor(tok string, want int) ([]string, error) {
	parts, ok := decodePageToken(tok)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	if len(parts) != 0 && len(parts) != want {
		return nil, status.Error(codes.InvalidArgument, "invalid page_token")
	}
	return parts, nil
}
