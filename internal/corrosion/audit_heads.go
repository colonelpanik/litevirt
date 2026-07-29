package corrosion

import (
	"context"
	"fmt"
	"time"
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
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO audit_chain_heads
		   (host_name, epoch, seq, head_hash, key_id, signature, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		hostName, epoch, seq, hash, keyring.KeyID(), sig, now, now)
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

// latestAuditHeads returns each host's highest head, ordered by (epoch, seq).
func latestAuditHeads(ctx context.Context, c *Client) (map[string]AuditChainHead, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, epoch, seq, head_hash, key_id, signature, created_at
		 FROM audit_chain_heads WHERE deleted_at IS NULL
		 ORDER BY host_name ASC, epoch ASC, seq ASC`)
	if err != nil {
		return nil, fmt.Errorf("list audit chain heads: %w", err)
	}
	out := map[string]AuditChainHead{}
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
		// Ordered ascending, so the last one seen for a host is its highest.
		out[h.HostName] = h
	}
	return out, nil
}

// verifyChainHeads compares each host's highest signed head against the rows
// actually present, and reports a host whose log is shorter than its own head
// says it should be.
func verifyChainHeads(ctx context.Context, c *Client, keyring *AuditKeyring, observedSeq map[string]int64, res *AuditVerifyResult) error {
	heads, err := latestAuditHeads(ctx, c)
	if err != nil {
		return err
	}
	for host, h := range heads {
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
		if observedSeq[host] >= h.Seq {
			continue
		}
		// Give replication time to deliver rows this node has not seen yet.
		if created, perr := time.Parse(time.RFC3339Nano, h.CreatedAt); perr == nil {
			if time.Since(created) < headSettleWindow {
				continue
			}
		}
		res.TruncatedHosts = append(res.TruncatedHosts, fmt.Sprintf(
			"%s: signed head attests seq %d but the log ends at %d (%d rows missing)",
			host, h.Seq, observedSeq[host], h.Seq-observedSeq[host]))
	}
	return nil
}
