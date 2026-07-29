package corrosion

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
)

// Signed audit chain heads.
//
// A hash chain links each row backward to its predecessor. That catches an
// edited row and it catches a deletion from the middle, because the row after
// the hole no longer links to anything. It is completely blind to truncation:
// cut the last N rows off a host's chain and every surviving link still
// verifies, since nothing in the log points forward to what was removed.
//
// A chain head closes that. It is a signed statement — "as of now, host H had
// written seq S, and its chain ended at hash X" — published periodically and
// replicated like any other row. To hide a truncation an attacker would have to
// remove every head that mentions the missing rows from every node in the
// cluster, and heads are append-only, so a replayed older head cannot displace
// a newer one.

// headSettleWindow is how long a head must have existed before a shortfall
// counts as truncation.
//
// The cluster is eventually consistent, so a peer can legitimately hold a
// host's head before it holds all the rows that head attests to. Replication
// settles in seconds; a head still missing its rows ten minutes later is not a
// replication lag, it is missing data.
const headSettleWindow = 10 * time.Minute

// AuditChainHead is one signed assertion about a host's chain position.
type AuditChainHead struct {
	HostName  string
	Epoch     int64
	Seq       int64
	HeadHash  string
	KeyID     string
	Signature string
	CreatedAt string
}

// PublishAuditChainHead signs and records this host's current chain position.
//
// A no-op without a signing keyring: an unsigned head would assert nothing an
// attacker could not simply rewrite, so publishing one would be worse than
// useless — it would look like protection that is not there.
func PublishAuditChainHead(ctx context.Context, c *Client, hostName string) error {
	keyring := c.AuditKeyringOf()
	if !keyring.CanSign() {
		return nil
	}
	c.auditChain.mu.Lock()
	tail := c.auditChain.tail(hostName)
	if !tail.known {
		if err := loadHostTail(ctx, c, hostName, tail); err != nil {
			c.auditChain.mu.Unlock()
			return err
		}
		tail.known = true
	}
	seq, hash := tail.seq, tail.hash
	c.auditChain.mu.Unlock()

	if seq == 0 {
		return nil // nothing written yet; a head over an empty chain says nothing
	}
	epoch, err := currentAuditEpoch(ctx, c, hostName)
	if err != nil {
		return err
	}
	return insertAuditChainHead(ctx, c, keyring, hostName, epoch, seq, hash)
}

func insertAuditChainHead(ctx context.Context, c *Client, keyring *AuditKeyring, hostName string, epoch, seq int64, hash string) error {
	sig, err := keyring.SignHead(hostName, epoch, seq, hash)
	if err != nil {
		return fmt.Errorf("sign audit chain head: %w", err)
	}
	// created_at is a WALL time that verifyChainHeads reads back and compares
	// against headSettleWindow; updated_at is the LWW conflict key. They must
	// not share a source: NowTS starts emitting HLC strings the moment hlc_lww
	// latches, and an HLC value in created_at fails the RFC3339 parse, skipping
	// the settle window and reporting every freshly published head as a
	// truncated log on any peer still catching up.
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO audit_chain_heads
		   (host_name, epoch, seq, head_hash, key_id, signature, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		hostName, epoch, seq, hash, keyring.KeyID(), sig, c.NowWall(), c.NowTS())
}

// currentAuditEpoch is the highest epoch this host has published a head for.
// Epoch 0 is the pre-reseal state.
func currentAuditEpoch(ctx context.Context, c *Client, hostName string) (int64, error) {
	rows, err := c.Query(ctx,
		`SELECT COALESCE(MAX(epoch), 0) AS max_epoch FROM audit_chain_heads WHERE host_name = ?`, hostName)
	if err != nil {
		return 0, fmt.Errorf("read audit epoch for %s: %w", hostName, err)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int64("max_epoch"), nil
}

// latestAuditHeadsByKey returns each host's highest head PER SIGNING KEY.
//
// Per key, not per host, and selected by seq rather than epoch. Both details
// are load-bearing.
//
// epoch is chosen by whoever writes the head, and the table is INSERT OR
// IGNORE, so picking the authority by "highest epoch" hands the choice to an
// attacker: someone holding a rotated-out key could rewrite the last row that
// key signed, re-sign it, and then publish a head at epoch+5 — signed with the
// same retired key, over their own tail hash — which would become the single
// head this function returned and would agree with the forgery. The head that
// contradicts them, signed by the successor key they do not have, was silently
// discarded by being at a lower epoch.
//
// Keying by (host, key_id) means a new key's assertion can never be displaced
// by an old key's, whatever epoch it claims. It also keeps the result bounded
// by the number of signing identities a host has ever had, rather than by the
// number of heads it has published.
func latestAuditHeadsByKey(ctx context.Context, c *Client) (map[string][]AuditChainHead, error) {
	rows, err := c.Query(ctx,
		`SELECT h.host_name, h.epoch, h.seq, h.head_hash, h.key_id, h.signature, h.created_at
		 FROM audit_chain_heads h
		 JOIN (SELECT host_name, key_id, MAX(seq) AS max_seq
		       FROM audit_chain_heads WHERE deleted_at IS NULL
		       GROUP BY host_name, key_id) m
		   ON m.host_name = h.host_name AND m.key_id = h.key_id AND m.max_seq = h.seq
		 WHERE h.deleted_at IS NULL
		 ORDER BY h.host_name ASC, h.key_id ASC, h.epoch ASC`)
	if err != nil {
		return nil, fmt.Errorf("list audit chain heads: %w", err)
	}
	byKey := map[string]map[string]AuditChainHead{}
	for _, r := range rows {
		h := AuditChainHead{
			HostName:  r.String("host_name"),
			Epoch:     r.Int64("epoch"),
			Seq:       r.Int64("seq"),
			HeadHash:  r.String("head_hash"),
			KeyID:     r.String("key_id"),
			Signature: r.String("signature"),
			CreatedAt: r.String("created_at"),
		}
		if byKey[h.HostName] == nil {
			byKey[h.HostName] = map[string]AuditChainHead{}
		}
		// Ordered by epoch ascending, so the last one seen for a key wins a tie
		// on seq: a reseal opens a new epoch at the same position and its head
		// describes the re-based hash.
		byKey[h.HostName][h.KeyID] = h
	}
	out := make(map[string][]AuditChainHead, len(byKey))
	for host, keys := range byKey {
		ids := make([]string, 0, len(keys))
		for id := range keys {
			ids = append(ids, id)
		}
		sort.Strings(ids) // deterministic finding order
		for _, id := range ids {
			out[host] = append(out[host], keys[id])
		}
	}
	return out, nil
}

// chainHashAt returns the content hash of a host's row at a given sequence
// number, or "" if there is none.
func chainHashAt(ctx context.Context, c *Client, hostName string, seq int64) (string, error) {
	rows, err := c.Query(ctx,
		`SELECT content_hash FROM audit_log WHERE host_name = ? AND seq = ? LIMIT 1`, hostName, seq)
	if err != nil {
		return "", fmt.Errorf("read chain hash for %s at seq %d: %w", hostName, seq, err)
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("content_hash"), nil
}

// verifyChainHeads compares each host's signed heads against the rows actually
// present, and reports a host whose log is shorter — or hashes differently —
// than its own heads say it should.
//
// retired maps key id → the last sequence that key was entitled to sign. It is
// consulted here for the same reason it is consulted for rows: a head is a
// signed assertion, and a key that has been rotated out has no standing to make
// one about anything past its boundary. Without that check the head machinery
// is self-defeating — the party a rotation is performed against would be able to
// publish the very assertion that certifies their rewrite.
func verifyChainHeads(ctx context.Context, c *Client, keyring *AuditKeyring, observedSeq map[string]int64, retired map[string]int64, res *AuditVerifyResult) error {
	heads, err := latestAuditHeadsByKey(ctx, c)
	if err != nil {
		return err
	}
	hosts := make([]string, 0, len(heads))
	for host := range heads {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		// attestedSeq is the highest position any head this node is willing to
		// trust claims the log reached, counting only heads old enough that
		// replication lag cannot explain a shortfall.
		var attestedSeq int64
		for _, h := range heads[host] {
			if keyring != nil {
				if err := keyring.VerifyHead(ctx, c, host, h.Epoch, h.Seq, h.HeadHash, h.KeyID, h.Signature); err != nil {
					// A head that does not verify is itself a finding: someone
					// either forged one to cover a truncation or damaged the real
					// one to stop it being checked.
					res.BadSignature = append(res.BadSignature,
						fmt.Sprintf("chain head %s/%d/%d: %v", host, h.Epoch, h.Seq, err))
					continue
				}
			}
			// A retired key's head is credible only up to that key's boundary.
			// Beyond it the signature still verifies — the holder has the key,
			// which is why the rotation happened — so the retirement record is
			// the only thing that can say this head is not the host speaking.
			// Reported, and given no authority over anything below.
			if boundary, isRetired := retired[h.KeyID]; isRetired && h.Seq > boundary {
				res.RetiredKeyUse = append(res.RetiredKeyUse, fmt.Sprintf(
					"%s: chain head at seq %d is signed by key %s, which was retired at seq %d — "+
						"a rotated-out key cannot attest to the chain past its boundary",
					host, h.Seq, h.KeyID, boundary))
				continue
			}

			// The head asserts a HASH as well as a length, and the hash is the
			// half that matters after a rotation. Someone holding a retired key
			// can rewrite a row it signed and re-sign it perfectly: the
			// signature verifies, the sequence numbers are untouched, and the
			// row count is unchanged. Only the recorded chain hash — signed by
			// the successor key they do not have — contradicts them.
			if h.Seq > 0 && h.HeadHash != "" && observedSeq[host] >= h.Seq {
				actual, err := chainHashAt(ctx, c, host, h.Seq)
				if err != nil {
					return err
				}
				if actual != "" && !strings.EqualFold(actual, h.HeadHash) {
					res.HeadMismatch = append(res.HeadMismatch, fmt.Sprintf(
						"%s: signed head says the chain hashed to %s at seq %d, but it hashes to %s — "+
							"a row at or before that point was rewritten", host, h.HeadHash, h.Seq, actual))
				}
			}

			if h.Seq > attestedSeq && headHasSettled(h) {
				attestedSeq = h.Seq
			}
		}

		if attestedSeq > observedSeq[host] {
			res.TruncatedHosts = append(res.TruncatedHosts, fmt.Sprintf(
				"%s: signed head attests seq %d but the log ends at %d (%d rows missing)",
				host, attestedSeq, observedSeq[host], attestedSeq-observedSeq[host]))
		}
	}
	return nil
}

// headHasSettled reports whether a head is old enough that a shortfall behind
// it cannot be explained by replication lag.
//
// created_at is stamped with NowWall, not NowTS. NowTS becomes an HLC string
// the moment hlc_lww latches, and the parse failure that produced used to skip
// the window entirely — turning every freshly published head into a truncation
// report on any peer that had not yet received the rows behind it, which is the
// ordinary eventually-consistent case the window exists for.
//
// Both formats are read, because heads already written with an HLC created_at
// are on disk and their truncation detection must not stay switched off. A
// timestamp in neither format counts as NOT settled: an unreadable clock should
// produce silence, never an accusation of tampering.
func headHasSettled(h AuditChainHead) bool {
	if created, err := time.Parse(time.RFC3339Nano, h.CreatedAt); err == nil {
		return time.Since(created) >= headSettleWindow
	}
	if ts, ok := hlc.Parse(h.CreatedAt); ok {
		return time.Since(time.UnixMilli(ts.PhysicalMS)) >= headSettleWindow
	}
	return false
}
