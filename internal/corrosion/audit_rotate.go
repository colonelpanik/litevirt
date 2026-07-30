package corrosion

import (
	"context"
	"fmt"
	"log/slog"
	"time"
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
// A retirement is itself SIGNED (audit_key_lifecycle, v47). It has to be. It
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
	live, err := LiveAuditKeyIDs(ctx, c, keyring, hostName)
	if err != nil || len(live) == 0 {
		return "", false, err
	}
	return live[0], true, nil
}

// LiveAuditKeyIDs returns EVERY key of hostName that still has an open signing
// contract, newest first.
//
// The plural matters. signingContracts puts a host under contract if ANY
// of its keys is unretired, while retirement used to close only the first one —
// so `lv host retire-audit-key` reported the incident closed and exited 0 while
// the contract survived and every node kept reporting TAMPERED. A host ends up
// with two live certificates easily enough: a failed rotation, or any spurious
// row filed under its name.
func LiveAuditKeyIDs(ctx context.Context, c *Client, keyring *AuditKeyring, hostName string) ([]string, error) {
	retired, err := auditKeyRetirements(ctx, c, keyring)
	if err != nil {
		return nil, err
	}
	rows, err := c.Query(ctx,
		`SELECT key_id FROM audit_signing_keys
		 WHERE host_name = ? ORDER BY created_at DESC, key_id ASC`, hostName)
	if err != nil {
		return nil, fmt.Errorf("read active audit keys for %s: %w", hostName, err)
	}
	var out []string
	for _, r := range rows {
		id := r.String("key_id")
		// Ownership through the CA, not the row's own host_name column — the same
		// rule the contract pre-pass applies, so the two cannot disagree about
		// which keys a host has.
		if !keyring.KeyBelongsToHost(ctx, c, id, hostName) || isRetired(retired, hostName, id) {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

// isRetired reports whether a host's key has a verified retirement.
func isRetired(retired map[lifecycleKey]int64, host, keyID string) bool {
	_, ok := retired[lifecycleKey{host: host, keyID: keyID}]
	return ok
}

// signingContract is the sequence range a host's rows must be signed over.
type signingContract struct {
	// startSeq is the last sequence written BEFORE the host committed. Rows at
	// or below it predate the contract and are not expected to be signed.
	startSeq int64
}

// unadoptedCert is a published certificate that never recorded an adoption: the
// host declared it signs, and then could not say from when.
type unadoptedCert struct {
	host, keyID, publishedAt string
}

// adoptionSettleWindow is how long a published certificate may go without an
// adoption record before that is treated as a finding rather than a startup.
//
// The daemon defers adoption by auditLifecycleSettle (45s) so it does not pin a
// permanent sequence boundary from a local tail that is behind the cluster, and
// the record then has to replicate. This is far longer than either needs, because
// the state it detects is permanent: a host that cannot read its key will never
// adopt, and there is nothing to gain by calling it five minutes sooner.
const adoptionSettleWindow = 10 * time.Minute

// signingContracts returns the hosts whose rows must be signed and the sequence
// each commitment began at, plus separately the published certificates that never
// recorded an adoption.
//
// Publishing a signing certificate IS the contract: a replicated, CA-signed,
// per-host declaration that this host's rows carry a signature from here on.
// Nothing but a signed retirement takes it back.
//
// The START matters as much as the fact. A certificate says a host commits, not
// WHEN — and without the when, publishing one retroactively claims every row the
// host ever wrote, so the first verify after enabling signing reports a cluster's
// entire history as tampering. That is the fastest possible way to teach an
// operator to ignore this command. The signed 'adopted' record supplies it, and a
// certificate WITHOUT one is not a contract at all — see the !adopted branch below.
//
// This is deliberately a fact about replicated state rather than about a node's
// own config or its own log:
//
//   - A node-local flag would let a compromised node declare itself exempt and
//     report its log clean, and peers disagreeing about the same rows destroys
//     the only mechanism that makes cross-node verification worth anything.
//   - The host's own history — "has it signed before?" — is walked in an order
//     the attacker chooses, and says nothing at all about a host that has never
//     managed to sign, which is precisely the interesting case.
//
// It is per host, so a gradual rollout cannot false-fire: a host that has not
// published yet is simply pre-enforcement.
//
// The second return value is the one that closes a false NEGATIVE, and it is the
// half a rule keyed only on adoption cannot express. setupAuditSigning publishes a
// host's certificate even when its private key cannot be read, on the stated
// grounds that publishing nothing is the worst outcome — the host then "looks like
// one that was never meant to sign, so its entire audit log reads as ordinary
// pre-enforcement history", and "the key is unreadable is precisely the state an
// attacker arranges, so it must not be the state that goes unnoticed".
//
// Requiring an adoption record for a contract made that comment false. A host that
// cannot read its key cannot SIGN an adoption record either — writeAuditLifecycle
// refuses without a signing key — so the cert-only path put nobody under contract
// and the attacker's state became the silent one. Verified: three unsigned rows
// from a host with a published certificate returned Tampered=false.
//
// Reporting the certificate rather than resurrecting a contract is what keeps both
// halves. A contract needs a START, and guessing "from row 0" is what condemned a
// cluster's entire pre-enforcement history — 659 legacy rows per node on the lab.
// This needs no start: it says the host declared it signs and demonstrably cannot,
// which is true regardless of which rows predate what.
func signingContracts(ctx context.Context, c *Client, keyring *AuditKeyring) (map[string]signingContract, []unadoptedCert, map[lifecycleKey]map[string]int64, error) {
	lifecycle, err := auditKeyLifecycle(ctx, c, keyring)
	if err != nil {
		return nil, nil, nil, err
	}
	rows, err := c.Query(ctx, `SELECT host_name, key_id, created_at FROM audit_signing_keys`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("list audit signing certificates: %w", err)
	}
	out := map[string]signingContract{}
	var unadopted []unadoptedCert
	for _, r := range rows {
		host, keyID := r.String("host_name"), r.String("key_id")
		// The row's own host_name column is not evidence of anything — this table
		// is replicated, so a fabricated row naming a victim host would otherwise
		// put that host under a contract it never entered. Ownership is proved
		// through the CA, the same way every other reader proves it.
		if !keyring.KeyBelongsToHost(ctx, c, keyID, host) {
			continue
		}
		events := lifecycle[lifecycleKey{host: host, keyID: keyID}]
		if _, retired := events[auditLifecycleRetired]; retired {
			continue // this key's contract has been closed out
		}
		start, adopted := events[auditLifecycleAdopted]
		// No verified adoption record means we do not know WHEN the host
		// committed, and guessing "from row 0" claims its entire history. That
		// misfires on exactly the ordinary paths: a rolling v46→v47 upgrade, where
		// peers have certificates and no lifecycle rows, had the upgraded node
		// report every peer's pre-enforcement rows as tampering while the
		// un-upgraded nodes called the same rows clean — a false alarm and a
		// node-to-node verdict split at once. A certificate with no adoption is
		// simply not a contract.
		if !adopted {
			// Not a contract — but not nothing either. Once the certificate is old
			// enough that a starting daemon would have adopted, the absence is the
			// finding: this host published a declaration it cannot back.
			//
			// An unparseable created_at is NOT reported. It cannot be aged, and the
			// only thing that produced one was a revision that stamped this column
			// with NowTS; guessing would put a permanent finding on a host for a
			// timestamp bug rather than for anything it did.
			if published, perr := time.Parse(time.RFC3339Nano, r.String("created_at")); perr == nil &&
				time.Since(published) >= adoptionSettleWindow {
				unadopted = append(unadopted, unadoptedCert{
					host: host, keyID: keyID, publishedAt: r.String("created_at"),
				})
			}
			continue
		}
		// A host with several live keys is under the EARLIEST of their contracts:
		// the obligation begins the first time it committed, and a later key
		// cannot excuse rows written after an earlier one took effect.
		if cur, seen := out[host]; !seen || start < cur.startSeq {
			out[host] = signingContract{startSeq: start}
		}
	}
	return out, unadopted, lifecycle, nil
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
	// Record WHEN this key's contract begins, before anything else can write a
	// row under it. INSERT OR IGNORE, so the first adoption stands and a restart
	// cannot walk the start forward over rows the host has since signed.
	//
	// Floored for the same reason the retirement boundary is: this runs before
	// replication, so a rebuilt or restored node reads a local tail far behind its
	// own replicated history, and a start recorded there retroactively claims
	// every real row above it. The key being adopted is excluded from the floor —
	// it has published nothing yet, and counting a head it somehow signed would
	// let the adopter choose its own start.
	startSeq, err := FlooredHostTailSeq(ctx, c, keyring, hostName, keyring.KeyID())
	if err != nil {
		return "", err
	}
	if err := AdoptAuditKeyContract(ctx, c, keyring, hostName, startSeq); err != nil {
		return "", fmt.Errorf("record the signing contract start: %w", err)
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
	// sealSeq/sealHash are ONE row's position and hash and must stay paired: a
	// head is the assertion "at seq S this chain hashed to X", so quoting a seq
	// from one row and a hash from another publishes a statement that is false by
	// construction — and permanently, since heads are append-only.
	sealSeq, sealHash := tail.seq, tail.hash
	c.auditChain.mu.Unlock()

	// The retirement boundary is a different question from the seal, and takes a
	// different answer. The SEAL keeps the local pair, because this node cannot
	// vouch for the hash at a position it has not seen; the BOUNDARY is floored,
	// because pinning it below rows the key legitimately signed is permanent.
	//
	// The keys being retired are excluded from the floor. A head signed by the key
	// under retirement is an assertion by exactly the party the retirement is
	// aimed at, and letting it count would hand a leaked key the power to set its
	// own boundary arbitrarily high.
	boundarySeq, err := FlooredHostTailSeq(ctx, c, keyring, hostName, superseded...)
	if err != nil {
		return "", err
	}

	for _, old := range superseded {
		if err := RetireAuditKey(ctx, c, keyring, hostName, old, boundarySeq); err != nil {
			return "", err
		}
	}

	// Seal everything the old key wrote with a head signed by the NEW one.
	// This is the part that actually matters: without it, rotation would swap
	// which key signs future rows and leave every past row rewritable by
	// whoever holds the old one.
	if sealSeq > 0 {
		epoch, eerr := currentAuditEpoch(ctx, c, hostName)
		if eerr != nil {
			return "", eerr
		}
		if err := insertAuditChainHead(ctx, c, keyring, hostName, epoch+1, sealSeq, sealHash); err != nil {
			return "", fmt.Errorf("seal the retired key's history: %w", err)
		}
	}

	slog.Warn("audit signing key rotated; the previous key can no longer sign valid rows "+
		"and the history it wrote is sealed under the new key",
		"host", hostName, "retired", superseded, "new_key", keyring.KeyID(), "retired_at_seq", boundarySeq, "sealed_through_seq", sealSeq)
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
	if isRetired(retired, hostName, currentKeyID) {
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
		if isRetired(retired, hostName, r.String("key_id")) {
			continue
		}
		out = append(out, r.String("key_id"))
	}
	return out, nil
}

// auditLifecycleAdopted / auditLifecycleRetired are the two events in a key's
// signing contract. Both are signed; the pair tells the verifier which rows a
// key was responsible for.
const (
	auditLifecycleAdopted = "adopted"
	auditLifecycleRetired = "retired"
)

// AdoptAuditKeyContract records a SIGNED assertion that hostName's key takes
// effect at seq — everything at or below it predates the commitment.
//
// This is what gives the contract a START. Without it, publishing a certificate
// retroactively claims every row the host ever wrote, so the first verify after
// enabling signing reports a cluster's entire history as tampering — and an
// operator who sees that turns the feature off, which is the failure this design
// is most vulnerable to.
func AdoptAuditKeyContract(ctx context.Context, c *Client, keyring *AuditKeyring, hostName string, seq int64) error {
	return writeAuditLifecycle(ctx, c, keyring, hostName, keyring.KeyID(), auditLifecycleAdopted, seq)
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
	return writeAuditLifecycle(ctx, c, keyring, hostName, retiredKeyID, auditLifecycleRetired, seq)
}

func writeAuditLifecycle(ctx context.Context, c *Client, keyring *AuditKeyring, hostName, keyID, event string, seq int64) error {
	if !keyring.CanSign() {
		return fmt.Errorf("cannot record %s for key %s: no signing key to attribute it to", event, keyID)
	}
	sig, err := keyring.SignLifecycle(hostName, keyID, event, seq)
	if err != nil {
		return fmt.Errorf("sign %s of %s: %w", event, keyID, err)
	}
	// INSERT OR IGNORE: each event is a fixed assertion about (host, key, event),
	// so the FIRST one recorded stands. Re-running a rotation cannot move a
	// boundary, and neither can anyone else.
	return c.Execute(ctx,
		`INSERT OR IGNORE INTO audit_key_lifecycle
		   (host_name, key_id, event, at_seq, by_key_id, signature, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		hostName, keyID, event, seq, keyring.KeyID(), sig, c.NowWall(), c.NowTS())
}

// lifecycleKey identifies one host's claim on one signing key. Keying by the
// PAIR is load-bearing: reducing by key_id alone discarded host_name, so a record
// signed by host A naming host B's key was applied to B by every reader.
type lifecycleKey struct{ host, keyID string }

// auditKeyLifecycle reads every VERIFIED lifecycle event, as
// (host, key) → event → sequence.
//
// A record counts only if BOTH hold:
//
//   - its signature verifies against the published certificate for by_key_id,
//     which must chain to the cluster CA and name host_name (VerifyLifecycle); and
//   - the key it acts on actually belongs to that host (KeyBelongsToHost).
//
// The second check is the one that was missing. Without it the first is not an
// authorisation at all — it proves the signer speaks for host A, and then lets
// them say anything they like about host B's key.
//
// An unsigned or unverifiable row is ignored entirely rather than trusted or
// reported: the table is replicated, so anyone can put a row in it, and the
// signature is the only thing separating a real assertion from an attempt to
// invalidate a host's whole live chain.
//
// deleted_at is deliberately not filtered. Tombstoning an event must not erase
// it — and because the table is append-only, a row deleted outright is simply
// re-inserted from a peer by ordinary anti-entropy.
func auditKeyLifecycle(ctx context.Context, c *Client, keyring *AuditKeyring) (map[lifecycleKey]map[string]int64, error) {
	rows, err := c.Query(ctx,
		`SELECT host_name, key_id, event, at_seq, by_key_id, signature FROM audit_key_lifecycle`)
	if err != nil {
		return nil, fmt.Errorf("list audit key lifecycle: %w", err)
	}
	out := map[lifecycleKey]map[string]int64{}
	for _, r := range rows {
		host, keyID, event := r.String("host_name"), r.String("key_id"), r.String("event")
		seq := r.Int64("at_seq")
		if err := keyring.VerifyLifecycle(ctx, c, host, keyID, event,
			seq, r.String("by_key_id"), r.String("signature")); err != nil {
			slog.Warn("ignoring an audit key lifecycle record that does not verify; it proves "+
				"nothing about the key it names and is not treated as one",
				"host", host, "key", keyID, "event", event, "error", err)
			continue
		}
		if !keyring.KeyBelongsToHost(ctx, c, keyID, host) {
			slog.Warn("ignoring an audit key lifecycle record naming a key that does not belong "+
				"to the host it claims; a signer speaks only for its OWN host's keys",
				"host", host, "key", keyID, "event", event)
			continue
		}
		lk := lifecycleKey{host: host, keyID: keyID}
		if out[lk] == nil {
			out[lk] = map[string]int64{}
		}
		// The strictest verified value wins: the LATEST adoption (the contract
		// starts as late as anyone can prove) and the EARLIEST retirement.
		//
		// Several verified records for one (host, key, event) are expected now
		// that by_key_id is part of the primary key — a rotation and an operator
		// `lv host retire-audit-key` legitimately retire the same key with
		// different signers.
		prev, seen := out[lk][event]
		switch {
		case !seen,
			event == auditLifecycleAdopted && seq > prev,
			event == auditLifecycleRetired && seq < prev:
			out[lk][event] = seq
		}
	}
	return out, nil
}

// auditKeyRetirements maps (host, key) → the last sequence that key was entitled
// to sign. A pair absent from the map is still active.
func auditKeyRetirements(ctx context.Context, c *Client, keyring *AuditKeyring) (map[lifecycleKey]int64, error) {
	lifecycle, err := auditKeyLifecycle(ctx, c, keyring)
	if err != nil {
		return nil, err
	}
	return retirementsFrom(lifecycle), nil
}

// retirementsFrom projects an already-read lifecycle map, for callers that need
// both views and should not pay for the table twice.
//
// auditKeyLifecycle is not a cheap read: it scans the table unfiltered and does an
// ECDSA verify plus an ownership check per row. VerifyAuditChain wants retirements
// AND contracts, and used to take that cost twice for one verify.
func retirementsFrom(lifecycle map[lifecycleKey]map[string]int64) map[lifecycleKey]int64 {
	out := make(map[lifecycleKey]int64, len(lifecycle))
	for lk, events := range lifecycle {
		if seq, ok := events[auditLifecycleRetired]; ok {
			out[lk] = seq
		}
	}
	return out
}

// RecordSignedRetirement records a retirement the CALLER signed, after checking
// it against the cluster CA.
//
// The split exists because the CA private key lives in the operator's config
// directory, not on any node — so a daemon cannot mint a certificate to sign
// with, and should not have to. The operator mints and signs; this verifies and
// stores. The CA never has to be present on a cluster node at all.
//
// certPEM must chain to the cluster CA and name hostName, the same rule every
// other signer is held to. Both signatures must cover exactly the key and
// sequence passed in, so a stale or substituted answer to the first phase cannot
// be replayed against a different boundary.
//
// selfSig retires the minted certificate itself. Without it, the certificate
// created to END a signing contract would stand as a new one — claiming the host
// signs with a key nobody holds, and putting every unsigned row it writes from
// then on back under a contract.
func RecordSignedRetirement(ctx context.Context, c *Client, pkiDir, hostName, retiredKeyID string, seq int64, certPEM, sig, selfSig string) error {
	verifier, err := LoadAuditVerifier(pkiDir)
	if err != nil {
		return fmt.Errorf("load cluster CA: %w", err)
	}
	cert, err := parseCertPEM([]byte(certPEM))
	if err != nil {
		return fmt.Errorf("retirement certificate: %w", err)
	}
	if cert.Subject.CommonName != hostName {
		return fmt.Errorf("retirement certificate names %q, not %q",
			cert.Subject.CommonName, hostName)
	}
	byKeyID, err := AuditKeyID(cert)
	if err != nil {
		return err
	}
	// VERIFY FIRST, publish second. The previous order published the certificate
	// up front on the reasoning that "an unusable certificate achieves nothing on
	// its own" — which was wrong, and expensively so. A certificate naming the
	// host, with no adoption and no retirement, is an orphan: it survives every
	// failure of phase 2 (a boundary that moved between the phases, a bad
	// signature, a wrong cert) and stays in the table forever. Re-running the
	// command mints a different key and leaves the previous orphan behind.
	//
	// certFor normally resolves the signer from the table, so verifying before
	// publishing means seeding the cache with the submitted PEM — checked against
	// the cluster CA first, exactly as certFor would.
	if err := verifier.trustSubmittedCert(cert, byKeyID); err != nil {
		return fmt.Errorf("retirement certificate: %w", err)
	}
	for _, r := range []struct {
		keyID, sig, what string
	}{
		{retiredKeyID, sig, "retirement"},
		{byKeyID, selfSig, "self-retirement of the retirement certificate"},
	} {
		if err := verifier.VerifyLifecycle(ctx, c, hostName, r.keyID,
			auditLifecycleRetired, seq, byKeyID, r.sig); err != nil {
			return fmt.Errorf("%s does not verify: %w", r.what, err)
		}
	}
	pub := &AuditKeyring{hostName: hostName, keyID: byKeyID, certPEM: certPEM}
	if err := pub.publishCert(ctx, c); err != nil {
		return fmt.Errorf("publish the retirement certificate: %w", err)
	}
	for _, keyID := range []string{retiredKeyID, byKeyID} {
		s := sig
		if keyID == byKeyID {
			s = selfSig
		}
		if err := c.Execute(ctx,
			`INSERT OR IGNORE INTO audit_key_lifecycle
			   (host_name, key_id, event, at_seq, by_key_id, signature, created_at, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			hostName, keyID, auditLifecycleRetired, seq, byKeyID, s,
			c.NowWall(), c.NowTS()); err != nil {
			return fmt.Errorf("record retirement of %s: %w", keyID, err)
		}
	}
	return nil
}

// KeyIsRetired reports whether a host's key has a verified retirement — i.e.
// whether its signing contract has been closed.
func KeyIsRetired(ctx context.Context, c *Client, keyring *AuditKeyring, hostName, keyID string) (bool, error) {
	retired, err := auditKeyRetirements(ctx, c, keyring)
	if err != nil {
		return false, err
	}
	return isRetired(retired, hostName, keyID), nil
}
