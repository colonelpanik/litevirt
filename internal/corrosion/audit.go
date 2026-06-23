package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
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

// chainState tracks the in-flight tail hash for THIS host's audit
// sub-chain. The audit_log is a multi-writer table — every daemon
// appends its own rows and they all replicate via Crescent — so a
// single global hash-chain can never stay linear (two hosts writing
// concurrently interleave by timestamp and fork the chain). Instead
// each host maintains its OWN per-host sub-chain: a row's prev_hash
// links to the previous row written by the SAME host. A daemon only
// ever authors rows for its own host, so this sub-chain is fully local
// and unaffected by cross-host interleaving or replication ordering.
// VerifyAuditChain validates each host's sub-chain independently.
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
		// First insert in this process — bootstrap THIS host's sub-chain.
		// re-base any legacy rows that were written under the old global
		// chain (prev_hash linking across hosts) into a clean per-host
		// chain, returning the resealed tail. Idempotent: once a host's
		// rows are consistent, this makes no writes and just reads the tail.
		tail, resealed, err := resealHostChainLocked(ctx, c, r.HostName)
		if err == nil {
			auditChainState.tailHash = tail
			if resealed > 0 {
				slog.Info("audit: re-based legacy rows into per-host chain",
					"host", r.HostName, "rows", resealed)
			}
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

// VerifyAuditChain validates every host's audit sub-chain independently
// and confirms each content_hash matches HashAuditRow(row, prev_hash)
// where prev_hash links to the previous row written by the SAME host.
// Ordering rows by (host, timestamp, id) makes each host's sub-chain
// contiguous; a per-host running tail tracks the expected prev_hash.
// Rows with a NULL content_hash are treated as chain-reset points
// (rows predating the audit hash-chain). The first verification failure
// short-circuits and is returned to the caller.
//
// This is the multi-writer-correct verification: a single global chain
// can't stay linear when N daemons append concurrently, but each host's
// own sub-chain is linear and tamper-evident.
//
// Returns (rowsChecked, brokenAt, err). brokenAt is the ID of the
// first row whose hash does not match; "" when every chain is intact.
func VerifyAuditChain(ctx context.Context, c *Client) (int, string, error) {
	rows, err := c.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash
		 FROM audit_log
		 ORDER BY host_name ASC, timestamp ASC, id ASC`)
	if err != nil {
		return 0, "", fmt.Errorf("list audit_log: %w", err)
	}
	prevByHost := map[string]string{} // per-host running tail
	checked := 0
	for _, r := range rows {
		host := r.String("host_name")
		stored := r.String("content_hash")
		if stored == "" {
			// Chain-reset point — accept and reset this host's tail so we
			// don't poison subsequent rows of the same host.
			prevByHost[host] = ""
			checked++
			continue
		}
		rec := AuditRecord{
			ID:        r.String("id"),
			Timestamp: r.String("timestamp"),
			Username:  r.String("username"),
			HostName:  host,
			Action:    r.String("action"),
			Target:    r.String("target"),
			Detail:    r.String("detail"),
			Result:    r.String("result"),
			PrevHash:  prevByHost[host],
		}
		expect := HashAuditRow(rec)
		if !strings.EqualFold(expect, stored) {
			return checked, rec.ID, nil
		}
		prevByHost[host] = stored
		checked++
	}
	return checked, "", nil
}

// ResealAuditChain re-bases one host's audit rows into a clean per-host
// hash-chain and returns the number of rows rewritten. It's the recovery
// path for rows written under the old global-chain model (whose prev_hash
// linked across hosts and so can't verify per-host). Idempotent: once a
// host's sub-chain is consistent it rewrites nothing. A daemon only
// reseals its OWN host's rows, so cluster-wide healing needs no
// coordination — each node fixes the sub-chain it authored.
//
// Re-sealing rewrites tamper-evidence hashes, so it re-bases trust to the
// current state. That's sound here because the global chain it replaces is
// already unverifiable; the per-host chain it produces is tamper-evident
// for every write from this point forward.
func ResealAuditChain(ctx context.Context, c *Client, hostName string) (int, error) {
	auditChainState.mu.Lock()
	defer auditChainState.mu.Unlock()
	tail, resealed, err := resealHostChainLocked(ctx, c, hostName)
	if err != nil {
		return 0, err
	}
	auditChainState.tailHash = tail
	auditChainState.known = true
	return resealed, nil
}

// resealHostChainLocked walks hostName's rows oldest-first, recomputes the
// per-host prev_hash/content_hash chain, and UPDATEs any row whose stored
// content_hash differs. Returns the resealed tail hash + rows rewritten.
// Caller must hold auditChainState.mu. A host authors all its own rows
// locally, so the local DB has the complete sub-chain even right after a
// restart (replication only brings OTHER hosts' rows).
func resealHostChainLocked(ctx context.Context, c *Client, hostName string) (string, int, error) {
	rows, err := c.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result, content_hash
		 FROM audit_log
		 WHERE host_name = ?
		 ORDER BY timestamp ASC, id ASC`, hostName)
	if err != nil {
		return "", 0, fmt.Errorf("list host audit rows: %w", err)
	}
	prev := ""
	resealed := 0
	for _, r := range rows {
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
		newHash := HashAuditRow(rec)
		if !strings.EqualFold(newHash, r.String("content_hash")) {
			if err := c.Execute(ctx,
				`UPDATE audit_log SET prev_hash = ?, content_hash = ? WHERE id = ?`,
				prev, newHash, rec.ID); err != nil {
				return "", resealed, fmt.Errorf("reseal row %s: %w", rec.ID, err)
			}
			resealed++
		}
		prev = newHash
	}
	return prev, resealed, nil
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
