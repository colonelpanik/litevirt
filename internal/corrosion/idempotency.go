package corrosion

import (
	"context"
	"time"
)

// Idempotency-key status values.
const (
	IdempotencyInProgress = "in_progress" // claimed; the operation is running
	IdempotencyCompleted  = "completed"   // finished; Response holds the replayable result
)

// IdempotencyRecord is a mutating-RPC operation keyed by a client-supplied
// idempotency key. It is first claimed in_progress (before side effects) and then
// completed with the response, so both a lost-response retry AND a concurrent
// duplicate are handled: the first caller claims, a same-node retry sees the claim.
// Records are ephemeral — they replicate via the WAL for cross-node dedup but are
// TTL-reaped (ReapExpiredIdempotencyKeys) and excluded from anti-entropy.
type IdempotencyRecord struct {
	Key         string
	Method      string
	RequestHash string
	Response    string // base64 of the recorded proto response (empty while in_progress)
	Status      string // IdempotencyInProgress | IdempotencyCompleted
	ExpiresAt   string // RFC3339Nano; past this the record is reclaimable/reaped
}

// idempotencyRecordExpired reports whether rec is past its expiry (a crashed
// in-progress claim, or a completed record past its replay window).
func idempotencyRecordExpired(rec *IdempotencyRecord) bool {
	if rec == nil {
		return true
	}
	t, err := time.Parse(time.RFC3339, rec.ExpiresAt)
	if err != nil {
		return false // unparseable → don't treat as expired (fail safe: keep it)
	}
	return time.Now().After(t)
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

// ClaimIdempotencyKey atomically claims key for an in-progress operation.
//   - claimed=true              → THIS caller acquired the claim; run the op, then
//     Complete or Release it. (Also true when it stole an expired prior record.)
//   - claimed=false, existing   → a live record already exists: completed → replay
//     its Response; in_progress → the operation is running (elsewhere / concurrently).
//
// The claim is a local `INSERT … ON CONFLICT DO NOTHING`, so on a single node it
// fully serializes concurrent same-key requests (the first claims, the rest see the
// claim). Cross-node concurrency is narrowed to the WAL-replication window rather
// than eliminated (a cluster-wide lock would be heavier); creates also have the
// name-uniqueness backstop. expiresAt is the claim lease — a crashed op frees the
// key after it lapses.
func ClaimIdempotencyKey(ctx context.Context, c *Client, key, method, reqHash, expiresAt string) (claimed bool, existing *IdempotencyRecord, err error) {
	now := c.NowTS()
	insert := func() (int64, error) {
		return c.ExecuteRows(ctx,
			`INSERT INTO idempotency_keys (key, method, request_hash, response, status, created_at, updated_at, expires_at)
			 VALUES (?, ?, ?, '', ?, ?, ?, ?) ON CONFLICT(key) DO NOTHING`,
			key, method, reqHash, IdempotencyInProgress, now, now, expiresAt)
	}
	n, err := insert()
	if err != nil {
		return false, nil, err
	}
	if n > 0 {
		return true, nil, nil
	}
	rec, err := GetIdempotencyRecord(ctx, c, key)
	if err != nil {
		return false, nil, err
	}
	if rec == nil {
		// Deleted between the INSERT and the read — try once more.
		if n, err = insert(); err != nil {
			return false, nil, err
		} else if n > 0 {
			return true, nil, nil
		}
		rec, err = GetIdempotencyRecord(ctx, c, key)
		return false, rec, err
	}
	// Steal an expired record (a crashed in-progress claim, or a completed record
	// past its replay window) so a retry isn't blocked until the hourly reaper runs.
	if idempotencyRecordExpired(rec) {
		if _, derr := c.ExecuteRows(ctx,
			`DELETE FROM idempotency_keys WHERE key = ? AND expires_at = ?`, key, rec.ExpiresAt); derr == nil {
			if n, ierr := insert(); ierr == nil && n > 0 {
				return true, nil, nil
			}
		}
		rec, err = GetIdempotencyRecord(ctx, c, key) // someone else re-claimed; report current
		return false, rec, err
	}
	return false, rec, nil
}

// CompleteIdempotencyKey marks a claimed key completed with its response and
// extends the expiry to the replay window. Only transitions a row THIS caller
// holds (status in_progress).
func CompleteIdempotencyKey(ctx context.Context, c *Client, key, responseB64, expiresAt string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE idempotency_keys SET status = ?, response = ?, expires_at = ?, updated_at = ?
		 WHERE key = ? AND status = ?`,
		IdempotencyCompleted, responseB64, expiresAt, now, key, IdempotencyInProgress)
}

// ReleaseIdempotencyKey deletes an unfinished (in_progress) claim so a retry can
// proceed after a failed operation. Never removes a completed record.
func ReleaseIdempotencyKey(ctx context.Context, c *Client, key string) error {
	return c.Execute(ctx,
		`DELETE FROM idempotency_keys WHERE key = ? AND status = ?`, key, IdempotencyInProgress)
}

// ReapExpiredIdempotencyKeys deletes records past their TTL (completed past the
// replay window, or crashed in-progress claims). Called from the periodic GC
// sweep. A lagging peer can't resurrect a useful record: an expired row is
// reclaimable/ignored anyway, so a plain local delete is safe.
func ReapExpiredIdempotencyKeys(ctx context.Context, c *Client) (int64, error) {
	return c.ExecuteRows(ctx,
		`DELETE FROM idempotency_keys WHERE expires_at < ?`,
		time.Now().UTC().Format(time.RFC3339Nano))
}
