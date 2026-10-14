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

	"github.com/litevirt/litevirt/internal/randid"
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
	seq   int64  // highest seq this host has written; the next row is seq+1
	ts    string // the stamp on that row; the ceiling a generated stamp clamps to
	known bool   // true once the tail has been read back from the DB
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

// maxClampSkew is how far ahead of this node's clock a ceiling may sit and still
// be treated as one. Beyond it the ceiling is assumed to come from a clock that
// is wrong, a caller that supplied its own timestamp, or a row that was not
// written by a daemon at all.
const maxClampSkew = 5 * time.Minute

// stampAfter renders now at the chain's fixed width, never earlier than ceiling.
//
// The width is the first half: the stamp is compared as TEXT wherever rows are
// ordered by it, so its text order has to be its time order, and
// time.RFC3339Nano trims trailing zeros — a trimmed ".12Z" sorts after a later
// ".125Z". nowTSLayout pads instead.
//
// The clamp is the second. A wall clock goes backwards: NTP corrects a drift, a
// hypervisor restores a snapshot, an operator sets the date. Ordering the chain
// by seq means such a stamp no longer reads as tampering, but it still puts rows
// out of order in `lv audit ls` and in any export, and it invites every future
// reader to assume an order the data does not have. client.go's NowTS already
// made this trade for replication keys, clamping to lastTS+1ns against a durable
// ceiling; this is the same trade for audit stamps, with the host's own tail as
// the ceiling.
//
// The cost is explicit: after a backward step, a generated stamp is as much as
// that step too high, and it says a row was written later than it was. A stamp
// that is slightly late is a smaller lie than a log that claims an order it does
// not have.
//
// Only GENERATED stamps are clamped. A caller-supplied timestamp is stored
// verbatim — rewriting it would alter data this node did not author.
func stampAfter(now time.Time, ceiling string) string {
	ts := now.UTC()
	if ceiling == "" {
		return ts.Format(nowTSLayout)
	}
	prev, err := time.Parse(time.RFC3339Nano, ceiling)
	if err != nil {
		return ts.Format(nowTSLayout)
	}
	// A ceiling far in the FUTURE is not a clock reading to respect. The clamp
	// only ever raises, so honouring one would move every later stamp with it
	// until wall time caught up — and a stamp a year ahead is not a smaller
	// problem than one a millisecond behind: it breaks timestamp-window exports
	// and makes `lv audit ls` lie about when things happened, with nothing to
	// correct it. Past maxClampSkew the wall clock wins and the row is stamped
	// honestly. Ordering within the host is carried by seq regardless, which is
	// what makes that the safe way to lose this particular tie.
	if prev.After(ts.Add(maxClampSkew)) {
		return ts.Format(nowTSLayout)
	}
	if !ts.After(prev) {
		ts = prev.Add(time.Nanosecond)
	}
	return ts.Format(nowTSLayout)
}

// InsertAuditLog appends an entry to the audit_log table and stamps
// the prev_hash / content_hash chain fields. Idempotent on ID: if
// a row with the same ID already exists (e.g. arrived via Crescent
// replication), the INSERT is silently skipped — the replicator's
// LWW guard does the right thing for the replicated path.
func InsertAuditLog(ctx context.Context, c *Client, r AuditRecord) error {
	// id is the primary key and the insert is INSERT OR IGNORE, so a caller
	// that left it empty got one row ever: every later id-less row was dropped
	// silently, and the tail below advanced anyway, leaving the next row linked
	// to a row that does not exist -- a sequence gap and a hash mismatch that
	// `lv audit verify` reads as tampering. An id is not the caller's to forget.
	if r.ID == "" {
		r.ID = randid.New()
	}
	generated := r.Timestamp == ""
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

	if generated {
		r.Timestamp = stampAfter(c.now(), tail.ts)
	}
	r.PrevHash = tail.hash
	r.Seq = tail.seq + 1
	// After every hashed input is final, prev_hash included, and before the
	// hash: this is the one place every audit row passes through
	// (TestAuditWriters_EveryCallSiteIsCovered holds it so).
	if err := guardAuditNUL(&r); err != nil {
		slog.Error("audit row refused", "action", r.Action, "host", r.HostName, "error", err)
		return err
	}
	r.ContentHash = HashAuditRow(r)

	// Sign before writing, and fail the insert if signing itself errors.
	keyring := c.AuditKeyringOf()
	sig, err := keyring.SignRow(r.ContentHash, r.Seq)
	if err != nil {
		return fmt.Errorf("sign audit row %s: %w", r.ID, err)
	}
	r.Signature, r.KeyID = sig, ""
	if sig != "" {
		r.KeyID = keyring.KeyID()
	} else if c.auditSignatureRequiredNow() {
		// The row is written UNSIGNED, not refused.
		//
		// Refusing was the original design, and it was wrong in the one way that
		// matters: every caller of InsertAuditLog discards the error (the gRPC
		// audit helper warns, failover and the health assertions assign it to
		// `_`). So a node whose key became unreadable under a latched cluster did
		// not fail the operation — it executed the delete, the migrate, the fence,
		// and wrote NO row at all. A silent, total audit gap is strictly worse
		// than the unsigned row the refusal was meant to avoid, and `lv audit
		// verify` reported the log intact because nothing was missing to see.
		//
		// Degrading is only acceptable because it is loud in three independent
		// places: this line, the SeqGaps-style UnsignedAfterSigned finding the
		// verifier raises for any unsigned row following a host's first signed
		// one, and the metric that finding drives. An attacker who makes the key
		// unreadable no longer switches tamper-evidence off; they leave a trail of
		// findings on every node that reads the log.
		slog.Error("audit signing is enforced cluster-wide but this node has no signing key; "+
			"the row is being written UNSIGNED and will be reported as evidence by "+
			"`lv audit verify` on every node until the key is restored",
			"action", r.Action, "target", r.Target, "host", r.HostName, "id", r.ID)
	}

	n, err := c.ExecuteRows(ctx,
		`INSERT OR IGNORE INTO audit_log
		   (id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Timestamp, r.Username, r.HostName,
		r.Action, r.Target, r.Detail, r.Result,
		r.PrevHash, r.ContentHash, r.KeyID, r.Signature, r.Seq,
	)
	if err != nil {
		return err
	}
	if n == 0 {
		// The id was already present, so nothing was written — the idempotent
		// no-op the doc comment promises (a pending-audit replay after a crash
		// lands here by design). The tail must not move: advancing it chained
		// the next row onto a row that is not in the table, which verify reads
		// as a hash break and a sequence gap. Not an error, because the record
		// for this id exists; but the row that exists is the FIRST one, so a
		// caller reusing an id for a different event has lost that event.
		slog.Debug("audit row not written: id already present", "id", r.ID, "action", r.Action, "host", r.HostName)
		return nil
	}
	tail.hash, tail.seq = r.ContentHash, r.Seq
	// Only a stamp this node generated raises the ceiling. A caller-supplied one
	// is stored verbatim but is not a reading of this node's clock, and letting
	// it set the floor for every later row hands any caller a lever on the whole
	// host's timeline.
	if generated && raisesStampCeiling(r.Timestamp, tail.ts) {
		tail.ts = r.Timestamp
	}
	return nil
}

// auditNULReplacement stands in for a NUL byte in a free-text audit field. It is
// U+2400 SYMBOL FOR NULL: visible in `lv audit ls`, and not a byte the encoding
// treats as a separator.
const auditNULReplacement = "␀"

// guardAuditNUL keeps every row InsertAuditLog writes inside the domain on
// which the content hash is injective (no NUL in any hashed field; see
// auditCanonical). It decides per field whether to escape or refuse.
//
// username, target and detail are ESCAPED. They carry text that callers take
// from requests — a login writes the submitted username into target and
// username verbatim, before anything has authenticated it — so a NUL there is
// attacker-chosen. Refusing would hand that attacker an unaudited action:
// every caller discards InsertAuditLog's error, so a refused row is a silent
// gap, and a failed login that leaves no trace is worse than one recorded with
// a visible stand-in. The escape is lossy (a literal U+2400 in the input reads
// the same), which costs nothing here: the log records what was attempted, and
// the hash only needs the STORED value to be NUL-free.
//
// id, timestamp, host_name, action and result are REFUSED. The daemon sets
// them; none is free text from a request. Each is also load-bearing as an
// exact value — id is the primary key every replica dedups on, host_name keys
// the sub-chain, a timestamp is parsed and ordered, action and result are
// matched by equality — so rewriting one would silently change what the row
// means. A NUL in one is a bug, and the row is refused loudly.
//
// prev_hash is refused for the same reason: it is this host's own previous
// content hash, hex by construction, and a NUL there means the table under
// this node was edited.
func guardAuditNUL(r *AuditRecord) error {
	for _, f := range []*string{&r.Username, &r.Target, &r.Detail} {
		if strings.IndexByte(*f, 0) >= 0 {
			*f = strings.ReplaceAll(*f, "\x00", auditNULReplacement)
		}
	}
	if f := auditRecordNULField(*r); f != "" {
		return fmt.Errorf("audit row %q: field %s contains a NUL byte, which would make its content hash ambiguous", r.ID, f)
	}
	return nil
}

// loadHostTail reads back hostName's current chain position: the content hash
// of its last row and the highest seq it has issued.
//
// Ordering matches the verifier's (seq, then timestamp and id), so the tail this
// returns is the row the verifier will also treat as last. A tail picked by
// stamp alone is the wrong row to chain onto the moment a clock steps back, and
// the broken link that follows is WRITTEN into the table rather than merely read
// out of it.
//
// The stamp on that row comes back with it: it is the ceiling the next generated
// stamp clamps to, so a backward clock step cannot put an older stamp on a newer
// row. seq is taken as a MAX rather than from that row so a row inserted outside
// InsertAuditLog cannot drag the counter onto a value already in use.
func loadHostTail(ctx context.Context, c *Client, hostName string, tail *chainTail) error {
	rows, err := c.Query(ctx,
		`SELECT content_hash, timestamp FROM audit_log WHERE host_name = ?
		 ORDER BY seq DESC, timestamp DESC, id DESC LIMIT 1`, hostName)
	if err != nil {
		return fmt.Errorf("read audit chain tail for %s: %w", hostName, err)
	}
	if len(rows) == 1 {
		tail.hash = rows[0].String("content_hash")
		tail.ts = rows[0].String("timestamp")
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

// HostTailSeq returns the highest sequence number hostName has issued, which is
// the boundary a retirement is recorded at: everything up to here was written
// under the key being retired.
//
// It re-reads the log rather than trusting the cached tail, because the cache is
// a WRITE-path structure: it exists so an append can chain onto the previous row
// without a query, and it advances only when THIS node appends. Nothing
// invalidates it when replication delivers rows for another host. So the cached
// tail for a remote host is a snapshot of whenever it was first asked for, and
// every caller here is asking about a remote host at exactly the moment its
// position matters.
//
// The lab caught this: node-1's cache said node-3's chain ended at 5, corrosion
// then delivered 6, 7 and 8, and the cache still said 5 — so a retirement run
// from node-1 kept computing a boundary three rows below reality, and kept doing
// so after replication had caught up, because only a daemon restart could clear
// it.
//
// max(fresh, cached) rather than the fresh read alone. The two can only disagree
// the other way inside InsertAuditLog, which advances the cache after its
// Execute returns; taking the larger keeps the value monotone either way, and a
// boundary must never move backwards.
func HostTailSeq(ctx context.Context, c *Client, hostName string) (int64, error) {
	fresh, err := freshHostTailSeq(ctx, c, hostName)
	if err != nil {
		return 0, err
	}
	cached, err := cachedHostTailSeq(ctx, c, hostName)
	if err != nil {
		return 0, err
	}
	if cached > fresh {
		return cached, nil
	}
	return fresh, nil
}

// freshHostTailSeq reads hostName's highest issued sequence straight from the log.
func freshHostTailSeq(ctx context.Context, c *Client, hostName string) (int64, error) {
	rows, err := c.Query(ctx,
		`SELECT COALESCE(MAX(seq), 0) AS max_seq FROM audit_log WHERE host_name = ?`, hostName)
	if err != nil {
		return 0, fmt.Errorf("read audit seq for %s: %w", hostName, err)
	}
	if len(rows) != 1 {
		return 0, nil
	}
	return rows[0].Int64("max_seq"), nil
}

func cachedHostTailSeq(ctx context.Context, c *Client, hostName string) (int64, error) {
	c.auditChain.mu.Lock()
	defer c.auditChain.mu.Unlock()
	tail := c.auditChain.tail(hostName)
	if !tail.known {
		if err := loadHostTail(ctx, c, hostName, tail); err != nil {
			return 0, err
		}
		tail.known = true
	}
	return tail.seq, nil
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

// auditFieldNames are the row fields HashAuditRow covers, in hash order.
var auditFieldNames = [...]string{
	"id", "timestamp", "username", "host_name", "action", "target", "detail", "result",
}

// auditFieldValues returns r's hashed fields in auditFieldNames order.
func auditFieldValues(r AuditRecord) [len(auditFieldNames)]string {
	return [...]string{r.ID, r.Timestamp, r.Username, r.HostName, r.Action, r.Target, r.Detail, r.Result}
}

// auditCanonical is the v1 encoding HashAuditRow hashes:
//
//	prev_hash NUL ("id" NUL id NUL) ("timestamp" NUL timestamp NUL) ... ("result" NUL result NUL)
//
// It is injective ONLY over records with no NUL in any value, prev_hash
// included. Under that condition the encoding holds exactly 17 NULs, so it
// parses back one way only: prev_hash runs to the first NUL, and each following
// pair is a field name — a fixed NUL-free constant, which the parse checks
// rather than trusts — then a value running to the next NUL. An empty value is
// two adjacent NULs and parses back as empty. Equal encodings therefore parse
// to equal records.
//
// With a NUL inside a value the argument fails — the separators and field names
// on their own do not stop a value from forging a field boundary. It fails
// usefully, though: equal encodings have equal NUL counts, so any colliding pair
// carries a NUL in a value on BOTH sides. Refusing or escaping NUL at the one
// write path (InsertAuditLog) and flagging any NUL row on read
// (VerifyAuditChain) closes collisions without changing a byte of the encoding
// for any row that has none, so every hash and signature already written stays
// valid and no peer on an older build disagrees about a hash.
func auditCanonical(r AuditRecord) []byte {
	b := make([]byte, 0, 256)
	b = append(b, r.PrevHash...)
	b = append(b, 0)
	vals := auditFieldValues(r)
	for i, k := range auditFieldNames {
		b = append(b, k...)
		b = append(b, 0)
		b = append(b, vals[i]...)
		b = append(b, 0)
	}
	return b
}

// auditRecordNULField names the first hashed input of r — prev_hash included —
// that contains a NUL byte, or "" when none does. A record for which this is
// non-empty lies outside the domain on which auditCanonical is injective.
func auditRecordNULField(r AuditRecord) string {
	if strings.IndexByte(r.PrevHash, 0) >= 0 {
		return "prev_hash"
	}
	vals := auditFieldValues(r)
	for i, k := range auditFieldNames {
		if strings.IndexByte(vals[i], 0) >= 0 {
			return k
		}
	}
	return ""
}

// HashAuditRow returns the canonical SHA-256 of one audit row, mixed
// with its prev_hash. Format-stable across versions — operators can
// re-verify chains lifted from any future schema rev.
//
// It is collision-free only over rows with no NUL in any field; see
// auditCanonical for why, and for where that is enforced.
func HashAuditRow(r AuditRecord) string {
	sum := sha256.Sum256(auditCanonical(r))
	return hex.EncodeToString(sum[:])
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
	// BrokenKind says what kind of break BrokenAt is: AuditBrokenContent,
	// AuditBrokenForked or AuditBrokenUnlinked. Empty when BrokenAt is.
	BrokenKind string
	// Unsigned counts rows carrying no signature: written before v45, or while
	// enforcement.audit_signature was off. They are chain-checked only.
	Unsigned int
	// UnsignedAfterSigned lists unsigned rows written by a host that is under a
	// signing contract — it has a published certificate and no signed
	// retirement. Those are not old, they are anomalous: the contract says the
	// host's rows carry a signature, so an unsigned one is either a fabricated
	// entry inserted straight into the table or a node that lost its key and
	// kept writing.
	UnsignedAfterSigned []string
	// NeverAdopted lists hosts holding a published signing certificate that never
	// recorded an adoption, long enough ago that a starting daemon would have.
	//
	// It is the only thing that reports a host which cannot read its own signing
	// key. That host publishes its CERTIFICATE — deliberately, so its unsigned rows
	// are evidence rather than ordinary history — but it cannot SIGN the adoption
	// record a contract requires, so it fell into the gap between the two rules and
	// its rows were reported clean on every node. "The key is unreadable" is the
	// state an attacker arranges, which is exactly why it cannot be the quiet one.
	//
	// A host, not a row. There is no contract and therefore no start sequence, so
	// there is nothing to say about which individual rows are anomalous — and that
	// is the point: claiming a start would condemn the host's whole pre-enforcement
	// history, which is the false alarm that made the contract need a start at all.
	//
	// NOT tamper evidence, deliberately — see Tampered. Every OTHER finding here is
	// derived from something only a key holder could have produced. This one is
	// derived from the ABSENCE of such a thing, next to a certificate row that any
	// peer can write, so it is exactly as trustworthy as its weakest input and that
	// input is not trustworthy at all.
	NeverAdopted []string
	// Unverifiable counts signed rows this verifier had no keyring to check.
	Unverifiable int
	// BadSignature lists rows whose signature failed against the published
	// certificate for their key. This is the tamper signal that survives a
	// reseal: rewriting the hash cannot produce a matching signature.
	BadSignature []string
	// UnknownKeyID lists rows whose key has no usable published certificate —
	// either never published, or one that does not chain to the cluster CA.
	UnknownKeyID []string
	// SeqGaps lists breaks in a host's sequence numbering: a jump, which is how
	// the deletion of a whole run of rows shows up, or a repeated seq, which is
	// a forked chain and is labelled as a duplicate.
	SeqGaps []string
	// SeqDuplicates counts the SeqGaps entries that are a repeated seq (the
	// forked-chain kind), not a jump.
	SeqDuplicates int
	// Every unlinked row is classified, not only the first (BrokenAt):
	// ContentBreaks counts those whose content does not hash to their stored
	// hash (an edit); ForkedHosts lists the hosts with a second genesis
	// (AuditBrokenForked); UnlinkedOutsideForks counts the other unlinked
	// rows on hosts with no second genesis (a deleted or rewritten row).
	ContentBreaks        int
	ForkedHosts          []string
	UnlinkedOutsideForks int
	// Orphaned counts unlinked rows on a host with a second genesis whose
	// stored prev_hash is the hash of no row of that host one seq before them:
	// their predecessor was deleted (or the row renumbered). A fork does not
	// excuse them. Orphans names each, as "host: row ID (seq N) ...".
	Orphaned int
	Orphans  []string
	// Laundered lists rows that blanked their own hash to pose as a pre-chain
	// reset point, which used to silently re-base everything after them.
	Laundered []string
	// Unattributed counts rows with no host name. They belong to no sub-chain
	// and so cannot be chain-verified at all.
	Unattributed int
	// RetiredKeyUse lists rows signed by a key past the sequence at which it was
	// retired. Rotation is done precisely when a key may be in someone else's
	// hands, so a signature from it after the boundary is either an attacker or
	// a node still running with the superseded key installed.
	RetiredKeyUse []string
	// TruncatedHosts lists hosts whose signed chain head attests to more rows
	// than the log actually holds.
	TruncatedHosts []string
	// HeadMismatch lists hosts whose chain does not hash to what their own
	// signed head says it should. This is what catches a row REWRITTEN and
	// re-signed by someone holding a key that has since been rotated out: the
	// signature verifies, the sequence numbers are untouched, and only the head
	// — signed by the successor key they do not have — disagrees.
	HeadMismatch []string
	// Ambiguous lists rows with a NUL byte in a hashed field. The content hash
	// is injective only over NUL-free rows (see auditCanonical), so such a row's
	// hash — and the signature over it — does not pin down which content it
	// covers: a different row with the same hash verifies just as well. A daemon
	// that guards NUL at write time never produces one; it comes from an older
	// build or from a direct write to the table.
	//
	// Not tamper evidence: the row may have been written verbatim by an older
	// build, and the verifier cannot tell that from a substitution. It fails
	// verification as Unverified instead, because the row's content is exactly
	// what could not be verified.
	Ambiguous []string
}

// Tampered reports whether anything found is evidence of deliberate
// interference rather than age.
//
// A bare Unsigned count is deliberately NOT tampering: it is what a cluster
// looks like before enforcement, and flagging it would put a permanent tamper
// verdict on every cluster with any history — protection that only produces
// noise gets switched off.
//
// UnsignedAfterSigned is different, and it is why the bare count does not need
// to be. It is keyed to the host's published signing CERTIFICATE — a replicated,
// CA-signed declaration that this host's rows are signed from here on, revoked
// only by a signed retirement. That closes the hole the latch was supposed to
// close (a fabricated unsigned row with a recomputed hash verified clean,
// because the hash is unkeyed) without accusing anyone of tampering with their
// own pre-enforcement history.
//
// The rule deliberately does not read the host's own log. An earlier version
// asked "has this host signed before?", which is walked in an order the attacker
// chooses and is blind to a host that never managed to sign at all.
// NeverAdopted is deliberately absent, and it is the one finding that had to be
// taken back OUT of this verdict. Every other entry is derived from something
// only a key holder could have produced — a signature that verifies, a signature
// that does not, a chain head, a contract opened by a signed adoption.
// NeverAdopted is derived from a certificate row with no adoption beside it, and
// a certificate row is unauthenticated replicated data: any peer can insert one
// naming any host, using a certificate it merely OBSERVED (every host presents
// its own in every TLS handshake). That made a permanent, unclearable "TAMPERED"
// verdict available to anyone who could reach the cluster, against a host that
// had done nothing — and an operator who cannot clear a false accusation stops
// reading the ones that are true.
//
// The absence is peer-controlled in both directions, which is why no amount of
// tightening rescues it as EVIDENCE: planting the row forges the finding,
// tombstoning it suppresses a real one. So it moved to Unverified below, where it
// still fails the command and still gets printed — a host that cannot sign is
// never reported as clean — without claiming to know that anyone interfered.
func (r AuditVerifyResult) Tampered() bool {
	return r.BrokenAt != "" || len(r.BadSignature) > 0 || len(r.UnknownKeyID) > 0 ||
		len(r.SeqGaps) > 0 || len(r.Laundered) > 0 || len(r.TruncatedHosts) > 0 ||
		len(r.RetiredKeyUse) > 0 || len(r.HeadMismatch) > 0 ||
		len(r.UnsignedAfterSigned) > 0
}

// Forked reports whether the only tamper finding is a forked chain: some host
// has a second genesis (AuditBrokenForked), no row's content fails its hash,
// every other unlinked row is on a host with a second genesis and links to a
// row of that host (no Orphaned), and every
// sequence break is a repeated seq. It is still Tampered — a fork fails verification — but
// nothing found says a row was edited, deleted or forged, so the periodic
// verifier names it a forked chain, as `lv audit verify` does.
func (r AuditVerifyResult) Forked() bool {
	return len(r.ForkedHosts) > 0 && r.ContentBreaks == 0 && r.UnlinkedOutsideForks == 0 && r.Orphaned == 0 &&
		len(r.SeqGaps) == r.SeqDuplicates &&
		len(r.BadSignature) == 0 && len(r.UnknownKeyID) == 0 && len(r.Laundered) == 0 &&
		len(r.TruncatedHosts) == 0 && len(r.RetiredKeyUse) == 0 && len(r.HeadMismatch) == 0 &&
		len(r.UnsignedAfterSigned) == 0
}

// Unverified reports a host that declares its rows are signed and demonstrably
// cannot sign them.
//
// A third outcome between "intact" and "tampered", and currently NeverAdopted is
// the only thing in it. It still fails `lv audit verify` — a key nobody can read
// is not a clean result, and it is exactly the state an attacker arranges — it
// just does not claim to know that anyone interfered, because the row it reads
// cannot tell it that.
//
// The other two uncheckable things are deliberately NOT here, and both for the
// same reason: they are facts about the ASKING node or about legacy data, not
// about the log. Unverifiable counts signed rows this daemon has no keyring to
// check, which is the ordinary state of every node in the middle of a signing
// rollout. Unattributed counts rows written before host_name existed, which every
// cluster with history has and nothing can fix. Failing on either would page
// somebody on a healthy cluster, and an alert that fires on healthy clusters is
// how this command stops being read. Both stay printed notes.
//
// A NeverAdopted entry is cleared the way it was raised — through the CA. A
// CA-signed retirement of that key closes it out (signingContracts skips a
// retired key before it ever asks about adoption), and only the CA holder can
// produce one. That matters: the remedy for a certificate someone else planted
// must not be an action that someone else can also take, which is why the row is
// not simply made deletable — that would hand the same attacker a way to suppress
// a GENUINE finding.
func (r AuditVerifyResult) Unverified() bool {
	return len(r.NeverAdopted) > 0 || len(r.Ambiguous) > 0
}

// brokenLinkKind classifies a row that does not link to the walk's running tail
// by re-hashing it against the prev_hash it STORED. A row that does not hash
// even against that was edited.
//
// A row that does hash is called a fork only when it has the whole shape of
// one: an empty prev_hash AND seq 1 repeating a seq 1 the host already has
// (repeatsSeq1) — a second genesis, which is what a host rebuilt on an empty
// database writes. Anything else self-consistent is a broken link. That matters
// because a stored prev_hash is as writable as the content: an edit to an
// unsigned row mid-chain that blanks prev_hash and recomputes the hash is
// self-consistent too, and calling IT a fork would tell the operator the one
// thing that is false. Every kind is still a finding.
//
// That holds only while seq is honest. seq is not in the content hash, only
// under the signature, so on an UNSIGNED row it is as writable as prev_hash: a
// rewrite that also renumbers the row to seq 1 has exactly a fork's shape and
// is labelled one. No check can tell the two apart there. A signed row
// rewritten that way also shows a bad signature.
func brokenLinkKind(rec AuditRecord, storedPrev, stored string, repeatsSeq1 bool) string {
	rec.PrevHash = storedPrev
	switch {
	case !strings.EqualFold(HashAuditRow(rec), stored):
		return AuditBrokenContent
	case storedPrev == "" && repeatsSeq1:
		return AuditBrokenForked
	default:
		return AuditBrokenUnlinked
	}
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
		 ORDER BY host_name ASC, seq ASC, timestamp ASC, id ASC`)
	if err != nil {
		return res, fmt.Errorf("list audit_log: %w", err)
	}
	keyring := c.AuditKeyringOf()
	// Which hosts are under a signing contract, computed BEFORE the walk.
	//
	// This used to be a latch set as the walk went — "has this host produced a
	// signed row yet" — and the walk is ordered by (host, timestamp, id) over
	// timestamps the writer chooses. So a fabricated row simply carried a
	// timestamp older than the host's first real row, arrived while the latch
	// was still false, and escaped every check. A fact read up front from
	// replicated state cannot be reordered into being false.
	//
	// The lifecycle map comes back with it: retirements are a projection of the same
	// rows, and reading them separately meant scanning the table and re-verifying
	// every signature on it twice per verify.
	contracted, unadopted, lifecycle, err := signingContracts(ctx, c, keyring)
	if err != nil {
		return res, err
	}
	retired := retirementsFrom(lifecycle)
	for _, u := range unadopted {
		res.NeverAdopted = append(res.NeverAdopted, fmt.Sprintf(
			"%s: published signing certificate %s at %s but never recorded an adoption — "+
				"the host declares its rows are signed and cannot sign, so nothing it writes "+
				"is tamper-evident (a key that cannot be read cannot sign the adoption either)",
			u.host, u.keyID, u.publishedAt))
	}
	prevByHost := map[string]string{}  // per-host running tail
	seqByHost := map[string]int64{}    // per-host last seq seen
	forkedHost := map[string]bool{}    // hosts with a second genesis
	// unlinked rows, neither content nor genesis: excused on a forked host
	// only when they link to a row of that host (see Orphaned)
	type unlinkedRow struct {
		host, id, prev string
		seq            int64
	}
	var unlinked []unlinkedRow
	seqOfHash := map[string]map[string]int64{} // per-host stored content_hash -> seq
	hashedByHost := map[string]bool{}          // has this host produced a hashed row yet?
	// Unsigned seq-0 rows of a contracted host, held until the chain says where
	// they sit. See "seq 0 under a contract" below.
	legacy := map[string]*legacyRun{}
	var legacyOrder []string
	flagLegacy := func(host string) {
		for _, id := range legacy[host].ids {
			res.UnsignedAfterSigned = append(res.UnsignedAfterSigned, fmt.Sprintf(
				"%s: row %s carries no signature and no sequence, and does not link into the "+
					"history before this host's signing contract", host, id))
		}
	}
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
			// the running tail. That is credible only for a host with no signing
			// contract, and only before its first hashed row. Otherwise it is the
			// cheapest possible attack: blank one row's hash and every row after
			// it is re-based against an empty tail, so an edited history verifies
			// clean. The contract test is what closes the PREPEND — a fabricated
			// row backdated ahead of the host's real history would otherwise
			// arrive before any latch could be set. Such a row is reported, and
			// crucially does NOT reset the tail.
			if _, underContract := contracted[host]; hashedByHost[host] || underContract {
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
		linked := strings.EqualFold(HashAuditRow(rec), stored)
		if !linked {
			last, seen := seqByHost[host]
			kind := brokenLinkKind(rec, r.String("prev_hash"), stored,
				r.Int64("seq") == 1 && seen && last == 1)
			if res.BrokenAt == "" {
				res.BrokenAt, res.BrokenKind = rec.ID, kind
			}
			switch kind {
			case AuditBrokenContent:
				res.ContentBreaks++
			case AuditBrokenForked:
				if !forkedHost[host] {
					forkedHost[host] = true
					res.ForkedHosts = append(res.ForkedHosts, host)
				}
			default:
				unlinked = append(unlinked, unlinkedRow{host: host, id: rec.ID, prev: r.String("prev_hash"), seq: r.Int64("seq")})
			}
		}
		if run := legacy[host]; run != nil && !linked {
			run.broken = true
		}
		// A row with a NUL in a hashed field can share its hash — and so its
		// signature — with a different row (auditCanonical). Checked whether or
		// not the hash matched: a matching hash is exactly the case in which
		// the content it covers is in doubt.
		if f := auditRecordNULField(rec); f != "" {
			res.Ambiguous = append(res.Ambiguous, fmt.Sprintf(
				"%s: %s: field %s contains a NUL byte, so its hash and signature do not determine "+
					"its content — a different row would verify the same", rec.ID, host, f))
		}
		hashedByHost[host] = true
		prevByHost[host] = stored
		if seqOfHash[host] == nil {
			seqOfHash[host] = map[string]int64{}
		}
		seqOfHash[host][strings.ToLower(stored)] = r.Int64("seq")

		sig, keyID, seq := r.String("signature"), r.String("key_id"), r.Int64("seq")

		// Sequence numbers are tracked for every row that HAS one, signed or not.
		// InsertAuditLog assigns seq = tail+1 before it signs, and loadHostTail
		// takes MAX(seq) across all rows, so a run of unsigned rows still consumes
		// numbers. Counting only signed ones made the next signed row look like it
		// had jumped — reporting a deletion that never happened against a node
		// whose only fault was a few writes it could not sign.
		//
		// seq 0 is the "no sequence" sentinel: every pre-v45 row carries it,
		// because the column was added with DEFAULT 0. Those are not a numbering
		// at all, so comparing them produces one "seq 0 after 0" per legacy row —
		// hundreds of them on the first verify after an upgrade, under a heading
		// that says rows were deleted. Skipped rather than compared.
		if seq > 0 {
			// The host's first numbered row closes its seq-0 region: its stored
			// hash commits to everything before it.
			if run := legacy[host]; run != nil && !run.resolved {
				run.resolved = true
				if run.broken {
					flagLegacy(host)
				}
			}
			if last, seen := seqByHost[host]; seen && seq == last {
				// Not a deletion: two rows claim one position. That is a forked
				// chain — a second writer, or a host that appended to a replica
				// still missing its own history — and saying "rows deleted" sends
				// the investigation the wrong way.
				res.SeqGaps = append(res.SeqGaps,
					fmt.Sprintf("%s: row %s repeats seq %d (duplicate: two rows claim the same position, a forked chain)",
						host, rec.ID, seq))
				res.SeqDuplicates++
			} else if seen && seq != last+1 {
				res.SeqGaps = append(res.SeqGaps,
					fmt.Sprintf("%s: row %s has seq %d after %d", host, rec.ID, seq, last))
			}
			seqByHost[host] = seq
		}

		if sig == "" {
			res.Unsigned++
			// A host under a signing contract has no legitimate way to produce an
			// unsigned row: it published a certificate saying its rows are signed
			// from that point, and nothing but a signed retirement takes that
			// back. So this is either a fabricated row inserted straight into the
			// table — the cheapest forgery, since HashAuditRow is unkeyed — or a
			// node that lost its key and kept writing, which is the same evidence
			// seen from the other side.
			//
			// Keyed to the contract rather than to the host's own history, which
			// the attacker controls: a host that has never managed to sign at all
			// is exactly the case a history-based rule cannot see.
			// Only rows written AFTER the host committed. Everything at or below
			// the contract start predates the certificate, and flagging it would
			// report a whole cluster's pre-enforcement history as tampering the
			// day signing is switched on.
			//
			// seq 0 under a contract. seq 0 is not a position: it is the column
			// default the v45 migration gave every row written before it, and a
			// legacy host adopts at startSeq 0. Reading it as "after the start"
			// (the old `seq == 0 ||`) reported an upgraded cluster's whole
			// history as tampering the day signing came on, which is the false
			// alarm the contract start exists to prevent.
			//
			// It cannot simply be excused either. Since v45 InsertAuditLog
			// assigns seq = tail+1 >= 1 to every row it writes, so no daemon
			// writes a seq-0 row after the upgrade — but anyone who can write
			// the table can, and an unconditional excuse would make seq 0 the
			// free way to forge an unsigned row under a contract.
			//
			// So a seq-0 row is placed by the chain instead. The walk orders by
			// seq, so a host's seq-0 rows form one region ahead of all its
			// numbered rows, and the host's first numbered row was chained onto
			// the tail of that region when it was written. Its stored hash
			// therefore commits to every seq-0 row before it. The region is
			// excused only if every row in it, and that first numbered row,
			// link: a row spliced in anywhere — appended after the legacy tail,
			// or chained onto a post-upgrade row and sorted back by its seq of 0
			// — breaks a link the real history committed to, and the whole
			// region is reported, since the verifier cannot tell which of its
			// rows is the stranger.
			//
			// A host with no numbered row yet (upgraded and adopted, idle since)
			// has nothing committing to its region, and it is excused if it is
			// internally linked. That is deliberate. With no post-upgrade anchor
			// the region is unsigned, unanchored history that anyone able to
			// write the table could already rewrite and re-hash undetected; an
			// appended row is no more than that. Flagging the region instead
			// says "tampered" for every honest idle host and for an attacked one
			// alike, which distinguishes nothing. Once the host writes, its first
			// row is chained onto the tail it holds, and a row appended after
			// that tail was loaded breaks the link and is reported here.
			contract, underContract := contracted[host]
			if underContract && seq == 0 {
				run := legacy[host]
				if run == nil {
					run = &legacyRun{}
					legacy[host] = run
					legacyOrder = append(legacyOrder, host)
				}
				if run.resolved {
					// Cannot happen in seq order; never excuse what cannot be placed.
					res.UnsignedAfterSigned = append(res.UnsignedAfterSigned, fmt.Sprintf(
						"%s: row %s carries no signature and no sequence", host, rec.ID))
					continue
				}
				run.ids = append(run.ids, rec.ID)
				if !linked {
					run.broken = true
				}
				continue
			}
			if underContract && seq > contract.startSeq {
				res.UnsignedAfterSigned = append(res.UnsignedAfterSigned, fmt.Sprintf(
					"%s: row %s carries no signature, but this host has a published signing "+
						"certificate and no retirement", host, rec.ID))
			}
			continue
		}

		// A retired key signing past its boundary. The signature itself will
		// verify — the attacker has the key, that is the whole problem — so the
		// only thing that can flag it is the retirement record, which they
		// cannot rewrite without also defeating the head signed by the
		// successor key.
		if boundary, isRetired := retired[lifecycleKey{host: host, keyID: keyID}]; isRetired && seq > boundary {
			res.RetiredKeyUse = append(res.RetiredKeyUse, fmt.Sprintf(
				"%s: row %s has seq %d, signed by key %s which was retired at seq %d",
				host, rec.ID, seq, keyID, boundary))
		}

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

	// Regions no numbered row closed: excused when internally linked (see "seq 0
	// under a contract"), reported when not.
	for _, host := range legacyOrder {
		if run := legacy[host]; !run.resolved && run.broken {
			flagLegacy(host)
		}
	}

	// On a host with a second genesis its two chains interleave by seq, so
	// rows there are unlinked against the walk's running tail as a matter of
	// course. Only a row that links to a row of its own host, one seq before
	// it, is part of a chain; one whose stored prev_hash names no such row
	// lost its predecessor — deleted inside the seq range the other chain
	// covers, where no seq jump shows it — or was relinked to a row at another
	// seq, and is an orphan.
	for _, u := range unlinked {
		if !forkedHost[u.host] {
			res.UnlinkedOutsideForks++
			continue
		}
		if u.prev == "" && u.seq == 1 {
			continue // a genesis
		}
		pseq, ok := seqOfHash[u.host][strings.ToLower(u.prev)]
		if ok && (u.seq == 0 || pseq == u.seq-1) {
			continue
		}
		res.Orphaned++
		var why string
		switch {
		case ok:
			why = fmt.Sprintf("which is the hash of row seq %d of %s, not seq %d — renumbered or relinked", pseq, u.host, u.seq-1)
		case u.seq == 0:
			why = fmt.Sprintf("which is the hash of no row of %s — a seq-0 row whose predecessor is gone", u.host)
		default:
			why = fmt.Sprintf("which is the hash of no row of %s at seq %d — the row before it was deleted (or rewritten)", u.host, u.seq-1)
		}
		res.Orphans = append(res.Orphans, fmt.Sprintf("%s: row %s (seq %d) follows prev_hash %s, %s",
			u.host, u.id, u.seq, u.prev, why))
	}

	if err := verifyChainHeads(ctx, c, keyring, seqByHost, retired, &res); err != nil {
		return res, err
	}
	return res, nil
}

// legacyRun is one contracted host's unsigned seq-0 rows, pending until the
// chain places them (VerifyAuditChain, "seq 0 under a contract").
type legacyRun struct {
	ids      []string
	broken   bool // a row in the region, or the row closing it, failed to link
	resolved bool // the host's first numbered row has been reached
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

// auditResealGuardedSQL is the ONLY statement in the tree that may rewrite an
// audit row's chain hashes, and the only one a receiver ever executes for a
// reseal — DispAuditReseal runs it in place of whatever shape arrived.
//
// The guard is in the SQL, not just in the caller, because this statement
// replicates and peers apply it by primary key with no clock comparison.
// Without the WHERE clause a tampering node could reseal its own rows and have
// every peer overwrite their good copies with the forged ones; replication
// would do the attacker's work across the whole cluster, and since reseal
// refuses to touch signed rows, nothing could restore the correct hash
// afterwards.
const auditResealGuardedSQL = `UPDATE audit_log SET prev_hash = ?, content_hash = ?
	 WHERE id = ? AND (signature IS NULL OR signature = '')`

// resealHostChainLocked walks hostName's rows in authored (seq) order, recomputes the
// per-host prev_hash/content_hash chain, and UPDATEs any row whose stored
// content_hash differs.
//
// The order has to be the verifier's. Reseal WRITES the chain it computes, and
// the write replicates, so walking these rows in an order the verifier does not
// share does not repair a chain — it rewrites a correct one into a shape every
// peer then reports as broken. Returns the resealed tail hash + rows rewritten.
// Caller must hold auditChainState.mu. A host authors all its own rows
// locally, so the local DB has the complete sub-chain even right after a
// restart (replication only brings OTHER hosts' rows).
func resealHostChainLocked(ctx context.Context, c *Client, hostName string) (string, int, error) {
	rows, err := c.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result, content_hash, signature, seq
		 FROM audit_log
		 WHERE host_name = ?
		 ORDER BY seq ASC, timestamp ASC, id ASC`, hostName)
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
			if err := c.Execute(ctx, auditResealGuardedSQL, prev, newHash, rec.ID); err != nil {
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

// raisesStampCeiling reports whether a newly generated stamp is later than the
// current ceiling, comparing INSTANTS rather than strings.
//
// The two sides are not the same format. A generated stamp is fixed-width
// nowTSLayout; the ceiling comes back verbatim from audit_log and may be a
// legacy RFC3339Nano value with trailing zeros trimmed. A string compare then
// gets it exactly backwards whenever the new stamp extends the stored one as a
// prefix — '.' is 0x2E and 'Z' is 0x5A, so "…10:00:00.000000001Z" sorts BEFORE
// "…10:00:00Z" though it is a nanosecond later. The ceiling never rose past such
// a row, and stampAfter went on returning prev+1ns from that same unchanged
// ceiling, so every row written while the clock was behind carried an identical
// timestamp — the strict ordering the clamp exists to preserve.
//
// An unparseable side falls back to the string compare rather than to a verdict:
// it is the only ordering information left, and treating garbage as "later"
// would let one bad row pin the ceiling for good.
func raisesStampCeiling(stamp, ceiling string) bool {
	if ceiling == "" {
		return true
	}
	newT, nerr := time.Parse(time.RFC3339Nano, stamp)
	oldT, oerr := time.Parse(time.RFC3339Nano, ceiling)
	if nerr != nil || oerr != nil {
		return stamp > ceiling
	}
	return newT.After(oldT)
}
