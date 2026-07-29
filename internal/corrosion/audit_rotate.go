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
// The retirement record catches the naive case on top of that: continued use of
// the old key past its boundary, which is what happens when rotation is done but
// the old key is still installed somewhere.
//
// A retirement is itself SIGNED (audit_key_retirements, v47). It has to be. It
// began as two mutable columns on audit_signing_keys, and as plain replicated
// data those were writable by anyone: forging a retirement put every row a host
// had ever signed past a boundary on every node at once, with no way back, and
// clearing a genuine one was equally free. The detector for "somebody else has
// this key" cannot itself be something somebody else can write.

// ActiveAuditKeyID returns the key id a host is currently signing with — its
// one published key with no verified retirement. ok is false when the host has
// no signing contract: it has never published, or every key it published has
// been retired.
//
// This is the predicate the verifier's whole unsigned-row rule rests on, so it
// reads retirement through auditKeyRetirements (signatures checked) rather than
// from a column anyone can write.
func ActiveAuditKeyID(ctx context.Context, c *Client, keyring *AuditKeyring, hostName string) (string, bool, error) {
	retired, err := auditKeyRetirements(ctx, c, keyring)
	if err != nil {
		return "", false, err
	}
	rows, err := c.Query(ctx,
		`SELECT key_id FROM audit_signing_keys
		 WHERE host_name = ? ORDER BY created_at DESC, key_id ASC`, hostName)
	if err != nil {
		return "", false, fmt.Errorf("read active audit key for %s: %w", hostName, err)
	}
	for _, r := range rows {
		if id := r.String("key_id"); !isRetired(retired, id) {
			return id, true, nil
		}
	}
	return "", false, nil
}

// isRetired reports whether a key has a verified retirement.
func isRetired(retired map[string]int64, keyID string) bool {
	_, ok := retired[keyID]
	return ok
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
// The keyring is passed in rather than read off the client, because adoption is
// not the same decision as signing. A host that has been handed a dedicated
// audit signing pair must complete the rotation — publish, retire, seal —
// whether or not enforcement.audit_signature is on, since leaving the key it
// replaced un-retired is the failure the operator ran the rotation to avoid.
// Whether the host then SIGNS with it is the flag's business, and the flag's
// alone.
func AdoptAuditKey(ctx context.Context, c *Client, keyring *AuditKeyring, hostName string) (string, error) {
	if !keyring.CanSign() {
		return "", nil
	}
	if err := keyring.PublishSigningKey(ctx, c); err != nil {
		return "", err
	}

	superseded, err := supersededAuditKeys(ctx, c, keyring, hostName, keyring.KeyID())
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
		if err := RetireAuditKey(ctx, c, keyring, hostName, old, seq); err != nil {
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
//
// A key that is ITSELF retired supersedes nothing. Without that rule, rotation
// was undoable by the party it was performed against: start the daemon once with
// the old key back in place — a restored backup, a second instance, or whoever
// kept the copy that prompted the rotation — and "every other non-retired key"
// selects the key that just REPLACED it. The old key stays retired and, in the
// same breath, retires its successor at the tail seq of the moment. From then on
// every row the legitimate key signs is past a retirement boundary,
// `lv audit verify` reports the whole live chain as tampered on every node, and
// the leaked key is the one doing the signing.
func supersededAuditKeys(ctx context.Context, c *Client, keyring *AuditKeyring, hostName, currentKeyID string) ([]string, error) {
	retired, err := auditKeyRetirements(ctx, c, keyring)
	if err != nil {
		return nil, err
	}
	if isRetired(retired, currentKeyID) {
		slog.Error("this host is holding an audit signing key that has already been RETIRED; "+
			"it will not be treated as a rotation and will retire nothing. Every row signed "+
			"with it is reported as retired-key use on every node. If this node was restored "+
			"from a backup, install the current key; if it was not, the key that was rotated "+
			"away is in use on this machine",
			"host", hostName, "key_id", currentKeyID)
		return nil, nil
	}
	rows, err := c.Query(ctx,
		`SELECT key_id FROM audit_signing_keys
		 WHERE host_name = ? AND key_id <> ? ORDER BY key_id ASC`, hostName, currentKeyID)
	if err != nil {
		return nil, fmt.Errorf("list superseded audit keys for %s: %w", hostName, err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if isRetired(retired, r.String("key_id")) {
			continue
		}
		out = append(out, r.String("key_id"))
	}
	return out, nil
}

// RetireAuditKey records a SIGNED assertion that hostName's key retiredKeyID
// signed nothing valid past seq, attributed to the keyring making the claim.
//
// It deliberately does NOT tombstone the certificate. That must stay resolvable
// for as long as any row it signed still exists — deleting it would make every
// one of those rows unverifiable, so a rotation performed to IMPROVE integrity
// would destroy the history it was protecting.
//
// The signature is the whole point of the v47 shape. v46 wrote retirement into
// two mutable columns on audit_signing_keys, which any peer could set or clear:
// forging one put every row a host had signed past a boundary on every node at
// once, and clearing a genuine one was just as cheap. Neither needed a key.
func RetireAuditKey(ctx context.Context, c *Client, keyring *AuditKeyring, hostName, retiredKeyID string, seq int64) error {
	if !keyring.CanSign() {
		return fmt.Errorf("cannot retire key %s: no signing key to attribute the retirement to", retiredKeyID)
	}
	sig, err := keyring.SignRetirement(hostName, retiredKeyID, seq)
	if err != nil {
		return fmt.Errorf("sign retirement of %s: %w", retiredKeyID, err)
	}
	// INSERT OR IGNORE: a retirement is a fixed assertion about (host, key), so
	// the FIRST one recorded stands. Re-running a rotation cannot move a
	// boundary, and neither can anyone else.
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO audit_key_retirements
		   (host_name, retired_key_id, retired_at_seq, retired_by_key_id, signature,
		    created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		hostName, retiredKeyID, seq, keyring.KeyID(), sig, c.NowWall(), c.NowTS())
}

// auditKeyRetirements maps key id → the last sequence that key was entitled to
// sign. A key absent from the map is still active.
//
// Only VERIFIED retirements are returned. An unsigned or unverifiable row is
// ignored entirely rather than trusted or reported: the table is replicated, so
// anyone can put a row in it, and the signature is the only thing separating a
// real retirement from an attempt to invalidate a host's whole live chain.
//
// deleted_at is deliberately not filtered. Tombstoning a retirement must not
// erase it — and because the table is append-only, a row deleted outright is
// simply re-inserted from a peer by ordinary anti-entropy.
func auditKeyRetirements(ctx context.Context, c *Client, keyring *AuditKeyring) (map[string]int64, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, retired_key_id, retired_at_seq, retired_by_key_id, signature
		 FROM audit_key_retirements`)
	if err != nil {
		return nil, fmt.Errorf("list retired audit keys: %w", err)
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		host, keyID := r.String("host_name"), r.String("retired_key_id")
		seq := r.Int64("retired_at_seq")
		if err := keyring.VerifyRetirement(ctx, c, host, keyID,
			seq, r.String("retired_by_key_id"), r.String("signature")); err != nil {
			slog.Warn("ignoring an audit key retirement that does not verify; it proves nothing "+
				"about the key it names and is not treated as one",
				"host", host, "retired_key", keyID, "error", err)
			continue
		}
		// The earliest verified boundary wins, so a second signed assertion can
		// only ever tighten. Nothing legitimate writes two.
		if prev, seen := out[keyID]; !seen || seq < prev {
			out[keyID] = seq
		}
	}
	return out, nil
}
