package corrosion

import (
	"context"
	"time"
)

// IdempotencyRecord is a completed mutating-RPC result, keyed by a client-supplied
// idempotency key, kept so a lost-response retry replays the original result
// instead of executing the operation a second time. Records are ephemeral: they
// replicate via the WAL for cross-node dedup but are TTL-reaped (ReapExpiredIdempotencyKeys)
// and excluded from anti-entropy.
type IdempotencyRecord struct {
	Key         string
	Method      string
	RequestHash string
	Response    string // base64 of the recorded proto response
	Status      string // "completed"
	ExpiresAt   string // RFC3339; past this the record is reaped and a retry re-executes
}

// GetIdempotencyRecord returns the record for key, or nil if none exists.
func GetIdempotencyRecord(ctx context.Context, c *Client, key string) (*IdempotencyRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT key, method, request_hash, response, status, expires_at
		 FROM idempotency_keys WHERE key = ? AND deleted_at IS NULL LIMIT 1`, key)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &IdempotencyRecord{
		Key:         r.String("key"),
		Method:      r.String("method"),
		RequestHash: r.String("request_hash"),
		Response:    r.String("response"),
		Status:      r.String("status"),
		ExpiresAt:   r.String("expires_at"),
	}, nil
}

// PutIdempotencyRecord records a completed operation. First writer wins (ON
// CONFLICT DO NOTHING) — the record is write-once, so a redundant record (e.g. an
// entry node recording after the owning host already did) is a no-op, and a
// replayed/retried request never overwrites the original stored response.
func PutIdempotencyRecord(ctx context.Context, c *Client, rec IdempotencyRecord) error {
	now := c.NowTS()
	status := rec.Status
	if status == "" {
		status = "completed"
	}
	return c.Execute(ctx,
		`INSERT INTO idempotency_keys (key, method, request_hash, response, status, created_at, updated_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(key) DO NOTHING`,
		rec.Key, rec.Method, rec.RequestHash, rec.Response, status, now, now, rec.ExpiresAt)
}

// ReapExpiredIdempotencyKeys deletes records past their TTL. Called from the
// periodic GC sweep. A lagging peer can't resurrect a useful record: an expired
// row never matches (GetIdempotencyRecord's caller treats past-expiry as absent),
// so a stale replicated copy is harmless and re-reaped on the next sweep.
func ReapExpiredIdempotencyKeys(ctx context.Context, c *Client) (int64, error) {
	return c.ExecuteRows(ctx,
		`DELETE FROM idempotency_keys WHERE expires_at < ?`,
		time.Now().UTC().Format(time.RFC3339Nano))
}
