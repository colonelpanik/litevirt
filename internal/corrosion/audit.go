package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// AuditRecord is a single entry in the audit log.
type AuditRecord struct {
	ID        string
	Timestamp string // RFC3339 UTC; empty = "now" at insert time
	Username  string
	HostName  string
	Action    string
	Target    string
	Detail    string
	Result    string
	// PrevHash + ContentHash form the SHA-256 chain.
	// Populated by InsertAuditLog; callers can ignore them on the
	// write side and use them only when reading via ListAuditLogChain.
	PrevHash    string
	ContentHash string
}

// chainState tracks the in-flight tail hash per Corrosion client.
// We can't read-then-write the last row atomically across replicators
// (mutation_log is the source of truth) so each daemon hashes against
// its own local view. Cross-host gaps (a row arrives via Crescent
// after a local row was hashed) show up as chain breaks at verify
// time — the operator sees the chain reset and knows which row
// arrived out-of-band.
type chainState struct {
	mu       sync.Mutex
	tailHash string
	known    bool // true once we've read the tail from disk at startup
}

var auditChainState chainState

// InsertAuditLog appends an entry to the audit_log table and stamps
// the prev_hash / content_hash chain fields. Idempotent on ID: if
// a row with the same ID already exists (e.g. arrived via Crescent
// replication), the INSERT is silently skipped — the replicator's
// LWW guard does the right thing for the replicated path.
func InsertAuditLog(ctx context.Context, c *Client, r AuditRecord) error {
	if r.Timestamp == "" {
		// Nanosecond precision so two rows inserted in the same second
		// still sort deterministically. The verifier orders by
		// (timestamp ASC, id ASC) — a tie would break the chain when
		// the secondary id-sort doesn't match insert order.
		r.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	auditChainState.mu.Lock()
	defer auditChainState.mu.Unlock()

	if !auditChainState.known {
		// First insert in this process — bootstrap from the most-
		// recent row already in the DB.
		rows, err := c.Query(ctx,
			`SELECT content_hash FROM audit_log
			 WHERE content_hash IS NOT NULL
			 ORDER BY timestamp DESC, id DESC
			 LIMIT 1`)
		if err == nil && len(rows) > 0 {
			auditChainState.tailHash = rows[0].String("content_hash")
		}
		auditChainState.known = true
	}

	prev := auditChainState.tailHash
	r.PrevHash = prev
	r.ContentHash = HashAuditRow(r)

	if err := c.Execute(ctx,
		`INSERT OR IGNORE INTO audit_log
		   (id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Timestamp, r.Username, r.HostName,
		r.Action, r.Target, r.Detail, r.Result,
		r.PrevHash, r.ContentHash,
	); err != nil {
		return err
	}
	auditChainState.tailHash = r.ContentHash
	return nil
}

// HashAuditRow returns the canonical SHA-256 of one audit row, mixed
// with its prev_hash. Format-stable across versions — operators can
// re-verify chains lifted from any future schema rev.
func HashAuditRow(r AuditRecord) string {
	h := sha256.New()
	h.Write([]byte(r.PrevHash))
	h.Write([]byte{0})
	// Use a NUL separator + field name so a field reorganisation
	// (or an injected NUL byte in any field) can't forge a chain.
	for _, kv := range []struct{ k, v string }{
		{"id", r.ID},
		{"timestamp", r.Timestamp},
		{"username", r.Username},
		{"host_name", r.HostName},
		{"action", r.Action},
		{"target", r.Target},
		{"detail", r.Detail},
		{"result", r.Result},
	} {
		h.Write([]byte(kv.k))
		h.Write([]byte{0})
		h.Write([]byte(kv.v))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyAuditChain replays every row in the audit_log (oldest first)
// and confirms each content_hash matches HashAuditRow(row, prev_hash).
// Rows with a NULL content_hash are treated as chain-reset points
// (rows predating the audit hash-chain, or rows that arrived via
// Crescent before upgrade). The first verification failure
// short-circuits and is
// returned to the caller.
//
// Returns (rowsChecked, brokenAt, err). brokenAt is the ID of the
// first row whose hash does not match; "" when the chain is intact.
func VerifyAuditChain(ctx context.Context, c *Client) (int, string, error) {
	rows, err := c.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash
		 FROM audit_log
		 ORDER BY timestamp ASC, id ASC`)
	if err != nil {
		return 0, "", fmt.Errorf("list audit_log: %w", err)
	}
	prev := ""
	checked := 0
	for _, r := range rows {
		stored := r.String("content_hash")
		if stored == "" {
			// Chain-reset point — accept and continue. Reset prev
			// so we don't poison subsequent rows.
			prev = ""
			checked++
			continue
		}
		rec := AuditRecord{
			ID:        r.String("id"),
			Timestamp: r.String("timestamp"),
			Username:  r.String("username"),
			HostName:  r.String("host_name"),
			Action:    r.String("action"),
			Target:    r.String("target"),
			Detail:    r.String("detail"),
			Result:    r.String("result"),
			PrevHash:  prev,
		}
		expect := HashAuditRow(rec)
		if !strings.EqualFold(expect, stored) {
			return checked, rec.ID, nil
		}
		prev = stored
		checked++
	}
	return checked, "", nil
}

// ResetChainStateForTests forgets the cached tail so a test can
// re-initialise the in-memory chain pointer against a freshly-
// truncated audit_log. Test-only.
func ResetChainStateForTests() {
	auditChainState.mu.Lock()
	defer auditChainState.mu.Unlock()
	auditChainState.tailHash = ""
	auditChainState.known = false
}

// FenceLogRecord is a single fencing event.
type FenceLogRecord struct {
	ID       string
	HostName string
	Method   string
	Result   string
	Detail   string
}

// InsertFenceLog records a fencing attempt.
func InsertFenceLog(ctx context.Context, c *Client, r FenceLogRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.ID, r.HostName, r.Method, r.Result, now, r.Detail,
	)
}
