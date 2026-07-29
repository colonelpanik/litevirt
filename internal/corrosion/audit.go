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
	// KeyID + Signature are the v45 tamper-evidence: an ECDSA signature by the
	// authoring host's cluster key over ContentHash, KeyID and Seq. Empty on
	// rows written before signing was enabled — those are chain-checked but not
	// tamper-evident, and the verifier says so rather than implying otherwise.
	KeyID     string
	Signature string
	// Seq is the authoring host's monotonic row counter. Signed alongside the
	// content hash so rows cannot be renumbered, and the value a chain head
	// attests to so a truncated tail is detectable.
	Seq int64
}

// chainState tracks the in-flight tail hash of each audit sub-chain this
// client is appending to. The audit_log is a multi-writer table — every daemon
// appends its own rows and they all replicate via Crescent — so a single global
// hash-chain can never stay linear (two hosts writing concurrently interleave by
// timestamp and fork the chain). Instead each host maintains its OWN per-host
// sub-chain: a row's prev_hash links to the previous row written by the SAME
// host. A daemon only ever authors rows for its own host, so this sub-chain is
// fully local and unaffected by cross-host interleaving or replication ordering.
// VerifyAuditChain validates each host's sub-chain independently.
//
// The state is keyed by host_name and hangs off the Client rather than being a
// package global. A global is correct only while exactly one Client exists per
// process, which is true of a daemon and false of tests/fleet, where N daemons
// share one `go test` process — there, the first node's insert set the global
// `known` flag and the second node's first row linked its prev_hash to a tail
// from another node's database. Keying by host also removes the need to pretend
// a reset stands in for "a separate process": one client can legitimately hold
// several sub-chains, and each advances independently.
type chainState struct {
	mu    sync.Mutex
	tails map[string]*chainTail
}

// chainTail is one host's in-flight sub-chain position.
type chainTail struct {
	hash  string
	seq   int64 // highest seq this host has written; the next row is seq+1
	known bool  // true once the tail has been read back from the DB
}

// tail returns hostName's tail state, creating it on first use.
// Caller must hold cs.mu.
func (cs *chainState) tail(hostName string) *chainTail {
	if cs.tails == nil {
		cs.tails = map[string]*chainTail{}
	}
	t := cs.tails[hostName]
	if t == nil {
		t = &chainTail{}
		cs.tails[hostName] = t
	}
	return t
}

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
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	tail := c.auditChain.tail(r.HostName)

	if !tail.known {
		// First insert for this host on this client — bootstrap its sub-chain
		// from what this host has already written.
		if err := loadHostTail(ctx, c, r.HostName, tail); err != nil {
			return err
		}
		tail.known = true
	}

	r.PrevHash = tail.hash
	r.Seq = tail.seq + 1
	r.ContentHash = HashAuditRow(r)

	// Sign before writing, and fail the insert if signing fails. An audit row
	// that silently degrades to unsigned whenever the key is unreadable would
	// hand an attacker a way to turn tamper-evidence off: make the key
	// unavailable and every subsequent row loses its protection with only a
	// log line to show for it.
	keyring := c.AuditKeyringOf()
	sig, err := keyring.SignRow(r.ContentHash, r.Seq)
	if err != nil {
		return fmt.Errorf("sign audit row %s: %w", r.ID, err)
	}
	r.Signature, r.KeyID = sig, ""
	if sig != "" {
		r.KeyID = keyring.KeyID()
	} else if c.auditSignatureRequiredNow() {
		return fmt.Errorf("audit signing is enforced cluster-wide but this node has no signing "+
			"key; refusing to append an unsigned row for %s", r.Action)
	}

	if err := c.Execute(ctx,
		`INSERT OR IGNORE INTO audit_log
		   (id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Timestamp, r.Username, r.HostName,
		r.Action, r.Target, r.Detail, r.Result,
		r.PrevHash, r.ContentHash, r.KeyID, r.Signature, r.Seq,
	); err != nil {
		return err
	}
	tail.hash, tail.seq = r.ContentHash, r.Seq
	return nil
}

// loadHostTail reads back hostName's current chain position: the content hash
// of its last row and the highest seq it has issued.
//
// Ordering matches the verifier's (timestamp, id), so the tail this returns is
// the row the verifier will also treat as last. seq is taken as a MAX rather
// than from that row, because a legacy row carries seq 0 and must not drag the
// counter backwards onto a value already in use.
func loadHostTail(ctx context.Context, c *Client, hostName string, tail *chainTail) error {
	rows, err := c.Query(ctx,
		`SELECT content_hash FROM audit_log WHERE host_name = ?
		 ORDER BY timestamp DESC, id DESC LIMIT 1`, hostName)
	if err != nil {
		return fmt.Errorf("read audit chain tail for %s: %w", hostName, err)
	}
	if len(rows) == 1 {
		tail.hash = rows[0].String("content_hash")
	}
	seqRows, err := c.Query(ctx,
		`SELECT COALESCE(MAX(seq), 0) AS max_seq FROM audit_log WHERE host_name = ?`, hostName)
	if err != nil {
		return fmt.Errorf("read audit seq for %s: %w", hostName, err)
	}
	if len(seqRows) == 1 {
		tail.seq = seqRows[0].Int64("max_seq")
	}
	return nil
}

// HostHasSignedAuditRows reports whether hostName has written any signed row.
//
// It is the switch between repairing and verifying. A host whose chain is
// entirely unsigned was never tamper-evident, so re-basing its hashes loses
// nothing and heals rows written under the old global-chain model. The moment
// one signed row exists, the chain carries evidence, and a reseal would erase
// exactly the mismatch that proves an edit occurred.
func HostHasSignedAuditRows(ctx context.Context, c *Client, hostName string) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT id FROM audit_log
		 WHERE host_name = ? AND signature IS NOT NULL AND signature <> '' LIMIT 1`, hostName)
	if err != nil {
		return false, fmt.Errorf("check signed audit rows for %s: %w", hostName, err)
	}
	return len(rows) > 0, nil
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
// The result distinguishes the ways a log can be wrong, because the responses
// differ: a hash break is corruption or a crude edit, a bad signature is an
// edit by someone without the host's key, an unsigned row is simply older than
// enforcement, and a truncated tail leaves nothing behind at all.
type AuditVerifyResult struct {
	// RowsChecked counts every row examined.
	RowsChecked int
	// BrokenAt is the first row whose content hash does not match a
	// recomputation. Empty when every chain links correctly.
	BrokenAt string
	// Unsigned counts rows carrying no signature: written before v45, or while
	// enforcement.audit_signature was off. They are chain-checked only.
	Unsigned int
	// Unverifiable counts signed rows this verifier had no keyring to check.
	Unverifiable int
	// BadSignature lists rows whose signature failed against the published
	// certificate for their key. This is the tamper signal that survives a
	// reseal: rewriting the hash cannot produce a matching signature.
	BadSignature []string
	// UnknownKeyID lists rows whose key has no usable published certificate —
	// either never published, or one that does not chain to the cluster CA.
	UnknownKeyID []string
	// SeqGaps lists breaks in a host's sequence numbering, which is how the
	// deletion of a whole run of rows shows up.
	SeqGaps []string
	// Laundered lists rows that blanked their own hash to pose as a pre-chain
	// reset point, which used to silently re-base everything after them.
	Laundered []string
	// Unattributed counts rows with no host name. They belong to no sub-chain
	// and so cannot be chain-verified at all.
	Unattributed int
	// TruncatedHosts lists hosts whose signed chain head attests to more rows
	// than the log actually holds.
	TruncatedHosts []string
}

// Tampered reports whether anything found is evidence of deliberate
// interference rather than age. Unsigned/Unverifiable rows are deliberately
// NOT tampering: they are what a cluster looks like before enforcement.
func (r AuditVerifyResult) Tampered() bool {
	return r.BrokenAt != "" || len(r.BadSignature) > 0 || len(r.UnknownKeyID) > 0 ||
		len(r.SeqGaps) > 0 || len(r.Laundered) > 0 || len(r.TruncatedHosts) > 0
}

// VerifyAuditChain walks every host's sub-chain and reports what it finds.
//
// Unlike the pre-v45 version it does NOT stop at the first problem. Stopping
// hid the shape of an attack: one broken row said nothing about whether the
// rest of the log had been rewritten too, and an operator staring at a single
// id could not tell a disk error from a targeted edit.
func VerifyAuditChain(ctx context.Context, c *Client) (AuditVerifyResult, error) {
	var res AuditVerifyResult
	rows, err := c.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result,
		        prev_hash, content_hash, key_id, signature, seq
		 FROM audit_log
		 ORDER BY host_name ASC, timestamp ASC, id ASC`)
	if err != nil {
		return res, fmt.Errorf("list audit_log: %w", err)
	}
	keyring := c.AuditKeyringOf()
	prevByHost := map[string]string{}  // per-host running tail
	seqByHost := map[string]int64{}    // per-host last signed seq
	hashedByHost := map[string]bool{}  // has this host produced a hashed row yet?
	for _, r := range rows {
		host := r.String("host_name")
		stored := r.String("content_hash")
		res.RowsChecked++

		if host == "" {
			// A row with no host identity belongs to no authored sub-chain, so
			// there is nothing to link it to. Historically these came from
			// background contexts with no host (the failover coordinator);
			// every live caller now stamps one. Counted, not trusted.
			res.Unattributed++
			continue
		}
		if stored == "" {
			// A blank hash means "written before the chain existed" and resets
			// the running tail. That is only credible BEFORE the host's first
			// hashed row — afterwards it is the cheapest possible attack:
			// blank one row's hash and every row after it is re-based against
			// an empty tail, so an edited history verifies clean. Such a row
			// is reported, and crucially does NOT reset the tail.
			if hashedByHost[host] {
				res.Laundered = append(res.Laundered, r.String("id"))
				continue
			}
			prevByHost[host] = ""
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
		if expect := HashAuditRow(rec); !strings.EqualFold(expect, stored) && res.BrokenAt == "" {
			res.BrokenAt = rec.ID
		}
		hashedByHost[host] = true
		prevByHost[host] = stored

		sig, keyID, seq := r.String("signature"), r.String("key_id"), r.Int64("seq")
		if sig == "" {
			res.Unsigned++
			continue
		}
		// Sequence numbers are only meaningful once signed: an unsigned row
		// carries seq 0 and renumbering it costs nothing.
		if last, seen := seqByHost[host]; seen && seq != last+1 {
			res.SeqGaps = append(res.SeqGaps,
				fmt.Sprintf("%s: row %s has seq %d after %d", host, rec.ID, seq, last))
		}
		seqByHost[host] = seq

		if keyring == nil {
			res.Unverifiable++
			continue
		}
		if err := keyring.VerifyRow(ctx, c, host, keyID, stored, seq, sig); err != nil {
			if isUnknownKeyErr(err) {
				res.UnknownKeyID = append(res.UnknownKeyID, rec.ID+": "+err.Error())
			} else {
				res.BadSignature = append(res.BadSignature, rec.ID+": "+err.Error())
			}
		}
	}

	if err := verifyChainHeads(ctx, c, keyring, seqByHost, &res); err != nil {
		return res, err
	}
	return res, nil
}

// isUnknownKeyErr separates "we could not obtain a trustworthy public key" from
// "we had the key and the signature was wrong". Both are findings, but only the
// second says someone edited a row.
func isUnknownKeyErr(err error) bool {
	s := err.Error()
	return strings.Contains(s, "no published certificate") ||
		strings.Contains(s, "does not chain to the cluster CA") ||
		strings.Contains(s, "actually has id") ||
		strings.Contains(s, "carries no key id") ||
		strings.Contains(s, "not an ECDSA key")
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
// current state. That is sound ONLY for rows that were never tamper-evident —
// the unsigned ones — and resealHostChainLocked refuses to touch anything
// carrying a signature. Without that refusal a reseal is an eraser: edit a row,
// reseal, and the recomputed hash matches the edited content.
//
// A reseal that actually rewrites rows is recorded, not silent. It opens a new
// chain epoch and publishes a signed head for it, so the fact that hashes were
// re-based at a particular moment is itself part of the permanent record. An
// operator reading `lv audit verify` can see that it happened and when; the
// pre-v45 behaviour left no trace at all.
func ResealAuditChain(ctx context.Context, c *Client, hostName string) (int, error) {
	c.auditChain.mu.Lock()
	hash, resealed, err := resealHostChainLocked(ctx, c, hostName)
	if err != nil {
		c.auditChain.mu.Unlock()
		return 0, err
	}
	tail := c.auditChain.tail(hostName)
	// Pick up this host's seq (the reseal itself does not change it) before
	// overwriting the tail hash with the freshly re-based one.
	if !tail.known {
		if lerr := loadHostTail(ctx, c, hostName, tail); lerr != nil {
			c.auditChain.mu.Unlock()
			return resealed, lerr
		}
		tail.known = true
	}
	tail.hash = hash
	seq := tail.seq
	c.auditChain.mu.Unlock()

	if resealed == 0 {
		return 0, nil
	}
	keyring := c.AuditKeyringOf()
	if !keyring.CanSign() || seq == 0 {
		return resealed, nil
	}
	epoch, err := currentAuditEpoch(ctx, c, hostName)
	if err != nil {
		return resealed, err
	}
	if err := insertAuditChainHead(ctx, c, keyring, hostName, epoch+1, seq, hash); err != nil {
		return resealed, fmt.Errorf("record reseal epoch: %w", err)
	}
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
		`SELECT id, timestamp, username, host_name, action, target, detail, result, content_hash, signature
		 FROM audit_log
		 WHERE host_name = ?
		 ORDER BY timestamp ASC, id ASC`, hostName)
	if err != nil {
		return "", 0, fmt.Errorf("list host audit rows: %w", err)
	}
	prev := ""
	resealed := 0
	for _, r := range rows {
		// A SIGNED row is never resealed. Its hash is covered by a signature
		// this process may not even be able to reproduce, so rewriting it
		// cannot repair anything — it can only destroy the evidence that the
		// row was altered. If a signed row's hash looks wrong, that is a
		// finding for the verifier to report, not damage for the reseal to
		// paper over. Reseal exists solely to re-base rows written before
		// signing, which were never tamper-evident to begin with.
		if r.String("signature") != "" {
			prev = r.String("content_hash")
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
		newHash := HashAuditRow(rec)
		if !strings.EqualFold(newHash, r.String("content_hash")) {
			// The guard is repeated in the SQL, not just in the loop above,
			// because this statement replicates: peers apply it verbatim by
			// primary key with no clock comparison. Without the WHERE clause a
			// tampering node could reseal its own rows and have every peer
			// overwrite their good copies with the forged ones.
			if err := c.Execute(ctx,
				`UPDATE audit_log SET prev_hash = ?, content_hash = ?
				 WHERE id = ? AND (signature IS NULL OR signature = '')`,
				prev, newHash, rec.ID); err != nil {
				return "", resealed, fmt.Errorf("reseal row %s: %w", rec.ID, err)
			}
			resealed++
		}
		prev = newHash
	}
	return prev, resealed, nil
}

// ResetAuditChainForTests forgets this client's cached tails so a test can
// re-initialise them against a freshly-truncated audit_log. Test-only.
//
// It is a method, not a package function: the state it clears belongs to one
// client. The package-level version had to be called between two hosts' writes
// to stand in for "a separate daemon process" — keying the tails by host_name
// removes that need, since one client can hold several sub-chains and each
// advances on its own.
func (c *Client) ResetAuditChainForTests() {
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	c.auditChain.tails = nil
}

// FenceLogRecord is a single fencing event.
type FenceLogRecord struct {
	ID       string
	HostName string
	Method   string
	Result   string
	Detail   string
	// Timestamp is the RFC3339 event time. Set only on READ (GetFenceLog);
	// InsertFenceLog stamps its own `now` and ignores this field.
	Timestamp string
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

// HostManualFenceConfirmed reports whether an operator has written a "manual-confirmed"
// fencing_log row for host within (now-window, now] — the operator's attestation, via
// `lv host fence-confirm <host>`, that they have VERIFIED the host is DOWN. It is trusted as a
// proof-grade "the host is down" signal, distinct from an automatic result="fenced" row,
// which is only a fence ATTEMPT that may have partially failed (so "fenced" must NOT be
// trusted this way). Used both by failover (reschedule VMs) and by the Phase-2 VIP reclaim
// path (an unreachable holder attested down has released its VIP).
//
// The recency comparison is done in Go, NOT SQL: fencing_log.timestamp is RFC3339 and
// comparing it against SQLite datetime() text is an unreliable string compare that differs
// between the CLI and the pure-Go engine the daemon links (see the failover coordinator's
// fenceWithinWindow). Fail-closed: a read error returns (false, err) so a caller never
// treats an unreadable log as a confirmation.
func HostManualFenceConfirmed(ctx context.Context, c *Client, host string, now time.Time, window time.Duration) (bool, error) {
	rows, err := c.Query(ctx, `SELECT result, timestamp FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		return false, err
	}
	cutoff := now.Add(-window)
	for _, r := range rows {
		if r.String("result") != "manual-confirmed" {
			continue
		}
		ts, perr := time.Parse(time.RFC3339, r.String("timestamp"))
		if perr != nil {
			continue
		}
		if ts.After(cutoff) {
			return true, nil
		}
	}
	return false, nil
}
