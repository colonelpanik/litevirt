package corrosion

import (
	"context"
	"fmt"
	"log/slog"
)

// Audit signing key rotation.
//
// Rotation exists because a key can leak — and one did: `lv host init
// root@<host>` shipped /etc/litevirt/pki/host.key mode 0644 on every node it
// provisioned, so anyone with a local shell could take a copy. Tightening the
// mode does not undo a copy already made, which is precisely when an operator
// needs to be able to replace the key.
//
// WHAT ROTATION HAS TO ACHIEVE, and what it cannot.
//
// Someone holding the old private key can produce a valid signature over any
// content they like, including a row timestamped before the rotation. So a
// rule like "reject rows signed by the old key after time T" proves nothing:
// the attacker chooses the timestamp and signs it. Comparing timestamps is
// theatre against exactly the adversary rotation is for.
//
// What genuinely constrains them is the CHAIN, and one new fact anchored to the
// NEW key. Rotation publishes a chain head — signed with the new key, over the
// whole existing log — which states "at sequence S this host's chain hashed to
// X". From that moment, altering ANY row at or before S changes the chain and
// contradicts a head the attacker cannot forge, because forging it needs the
// new key they do not have. The old key's entire history is sealed by a
// signature made with its successor.
//
// That is the honest boundary: rows the old key wrote are frozen at rotation,
// and rows written after it need the new key. What rotation cannot do is
// retroactively protect a log that was already forged before anyone noticed —
// no scheme can, and claiming otherwise would be worse than saying so.
//
// The retirement marker (retired_at + retired_at_seq) catches the naive case on
// top of that: continued use of the old key past its boundary, which is what
// happens when rotation is done but the old key is still installed somewhere.

// ActiveAuditKeyID returns the key id a host is currently signing with — its
// one published, non-retired key. ok is false when the host has never published.
func ActiveAuditKeyID(ctx context.Context, c *Client, hostName string) (string, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT key_id FROM audit_signing_keys
		 WHERE host_name = ? AND deleted_at IS NULL AND retired_at IS NULL
		 ORDER BY created_at DESC, key_id ASC LIMIT 1`, hostName)
	if err != nil {
		return "", false, fmt.Errorf("read active audit key for %s: %w", hostName, err)
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	return rows[0].String("key_id"), true, nil
}

// AdoptAuditKey publishes this host's certificate and, if the host was
// previously signing with a DIFFERENT key, completes the rotation.
//
// It runs on every daemon start, so rotating a key is just: replace the files,
// restart. There is no rotate RPC and no coordination — a host is the only
// party that can know which key it now holds, and the only one that can sign
// the head that seals what the old key wrote.
//
// Returns the key id retired by this call, or "" if nothing was rotated.
func AdoptAuditKey(ctx context.Context, c *Client, hostName string) (string, error) {
	keyring := c.AuditKeyringOf()
	if !keyring.CanSign() {
		return "", nil
	}
	if err := keyring.PublishSigningKey(ctx, c); err != nil {
		return "", err
	}

	superseded, err := supersededAuditKeys(ctx, c, hostName, keyring.KeyID())
	if err != nil || len(superseded) == 0 {
		return "", err
	}

	// Retire at the sequence the log has REACHED, not at some future point:
	// every row up to here was legitimately written by the old key, and
	// anything beyond it must carry the new one.
	c.auditChain.mu.Lock()
	tail := c.auditChain.tail(hostName)
	if !tail.known {
		if lerr := loadHostTail(ctx, c, hostName, tail); lerr != nil {
			c.auditChain.mu.Unlock()
			return "", lerr
		}
		tail.known = true
	}
	seq, hash := tail.seq, tail.hash
	c.auditChain.mu.Unlock()

	for _, old := range superseded {
		if err := retireAuditKey(ctx, c, old, seq); err != nil {
			return "", err
		}
	}

	// Seal everything the old key wrote with a head signed by the NEW one.
	// This is the part that actually matters: without it, rotation would swap
	// which key signs future rows and leave every past row rewritable by
	// whoever holds the old one.
	if seq > 0 {
		epoch, eerr := currentAuditEpoch(ctx, c, hostName)
		if eerr != nil {
			return "", eerr
		}
		if err := insertAuditChainHead(ctx, c, keyring, hostName, epoch+1, seq, hash); err != nil {
			return "", fmt.Errorf("seal the retired key's history: %w", err)
		}
	}

	slog.Warn("audit signing key rotated; the previous key can no longer sign valid rows "+
		"and the history it wrote is sealed under the new key",
		"host", hostName, "retired", superseded, "new_key", keyring.KeyID(), "sealed_through_seq", seq)
	return superseded[0], nil
}

// supersededAuditKeys lists this host's published, non-retired keys other than
// the one it now holds.
func supersededAuditKeys(ctx context.Context, c *Client, hostName, currentKeyID string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT key_id FROM audit_signing_keys
		 WHERE host_name = ? AND deleted_at IS NULL AND retired_at IS NULL AND key_id <> ?
		 ORDER BY key_id ASC`, hostName, currentKeyID)
	if err != nil {
		return nil, fmt.Errorf("list superseded audit keys for %s: %w", hostName, err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("key_id"))
	}
	return out, nil
}

// retireAuditKey marks a key retired at a sequence boundary.
//
// It deliberately does NOT tombstone the row. The certificate must stay
// resolvable for as long as any row it signed still exists — deleting it would
// make every one of those rows unverifiable, so a rotation performed to
// IMPROVE integrity would destroy the history it was protecting.
func retireAuditKey(ctx context.Context, c *Client, keyID string, seq int64) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE audit_signing_keys SET retired_at = ?, retired_at_seq = ?, updated_at = ?
		 WHERE key_id = ? AND retired_at IS NULL`,
		now, seq, now, keyID)
}

// auditKeyRetirements maps key id → the last sequence that key was entitled to
// sign. A key absent from the map is still active.
func auditKeyRetirements(ctx context.Context, c *Client) (map[string]int64, error) {
	rows, err := c.Query(ctx,
		`SELECT key_id, retired_at_seq FROM audit_signing_keys
		 WHERE deleted_at IS NULL AND retired_at IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("list retired audit keys: %w", err)
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.String("key_id")] = r.Int64("retired_at_seq")
	}
	return out, nil
}
