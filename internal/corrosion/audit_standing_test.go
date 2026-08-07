package corrosion

import (
	"context"
	"testing"
)

// A leaked key that has ALREADY been rotated out and retired signs a retirement for
// its own successor. Nothing checks the signer's standing, and certFor keeps retired
// certificates resolvable so the signature still verifies.
func TestLifecycle_ARetiredKeyCannotRetireItsSuccessor(t *testing.T) {
	ctx := context.Background()
	c, oldKR, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	// Operator rotates: oldKR is retired, newKR adopted.
	newKR := rotateTo(t, c, dir, "node-0")
	ins(t, c, "r2", "node-0", "2026-07-29T10:00:02Z")

	if retired, _ := KeyIsRetired(ctx, c, newKR, "node-0", newKR.KeyID()); retired {
		t.Fatal("precondition: the new key must not start out retired")
	}

	// The attacker still holds oldKR. They sign a retirement naming the SUCCESSOR.
	seq, _ := HostTailSeq(ctx, c, "node-0")
	sig, err := oldKR.SignLifecycle("node-0", newKR.KeyID(), "retired", seq)
	if err != nil {
		t.Fatalf("sign with the retired key: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_key_lifecycle
		   (host_name, key_id, event, at_seq, by_key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-0', ?, 'retired', ?, ?, ?, ?, ?, NULL)`,
		newKR.KeyID(), seq, oldKR.KeyID(), sig,
		"2026-07-29T10:00:03Z", "2026-07-29T10:00:03Z"); err != nil {
		t.Fatalf("insert forged retirement: %v", err)
	}

	retired, err := KeyIsRetired(ctx, c, newKR, "node-0", newKR.KeyID())
	if err != nil {
		t.Fatalf("KeyIsRetired: %v", err)
	}
	live, _ := LiveAuditKeyIDs(ctx, c, newKR, "node-0")
	res, _ := VerifyAuditChain(ctx, c)
	t.Logf("successor retired by the leaked key = %v; live keys = %v; tampered = %v",
		retired, live, res.Tampered())

	if retired {
		t.Fatalf("a retired key retired its own successor\n"+
			"the host has %d live keys, so it stops signing, leaves every signing contract, "+
			"and verify reports CLEAN while its rows are unsigned and freely rewritable — "+
			"unrecoverable, because rotating again just produces another successor to retire",
			len(live))
	}
	if len(live) != 1 {
		t.Errorf("the successor should still be live, got %v", live)
	}
	if res.Tampered() {
		t.Errorf("the forged record should be ignored, not reported as tampering: %+v", res)
	}
}

// TestLifecycle_TheClusterCACanRetireAKey — the other side of the standing rule.
// Retiring a host that cannot sign for itself is exactly what holding ca.key
// authorises, and `lv host retire-audit-key` depends on it.
func TestLifecycle_TheClusterCACanRetireAKey(t *testing.T) {
	ctx := context.Background()
	c, kr, dir := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	seq, _ := HostTailSeq(ctx, c, "node-0")
	caSig, err := SignLifecycleWithCA(dir, "node-0", kr.KeyID(), "retired", seq)
	if err != nil {
		t.Fatalf("SignLifecycleWithCA: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_key_lifecycle
		   (host_name, key_id, event, at_seq, by_key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-0', ?, 'retired', ?, 'cluster-ca', ?, ?, ?, NULL)`,
		kr.KeyID(), seq, caSig, "2026-07-29T10:00:03Z", "2026-07-29T10:00:03Z"); err != nil {
		t.Fatalf("insert the CA retirement: %v", err)
	}

	retired, err := KeyIsRetired(ctx, c, kr, "node-0", kr.KeyID())
	if err != nil {
		t.Fatalf("KeyIsRetired: %v", err)
	}
	if !retired {
		t.Fatal("a retirement signed by the cluster CA was ignored\n" +
			"the operator is the only party who can retire a host that cannot sign for " +
			"itself, which is the whole point of `lv host retire-audit-key`")
	}
}

// TestLifecycle_AForgedCASignatureIsRejected — the reserved signer id is not a
// bypass: it names the CA, and only the CA private key can produce the signature.
func TestLifecycle_AForgedCASignatureIsRejected(t *testing.T) {
	ctx := context.Background()
	c, kr, _ := signedClient(t, "node-0")
	ins(t, c, "r1", "node-0", "2026-07-29T10:00:01Z")

	// The attacker claims the CA signed it, using their own key's signature.
	seq, _ := HostTailSeq(ctx, c, "node-0")
	sig, err := kr.SignLifecycle("node-0", kr.KeyID(), "retired", seq)
	if err != nil {
		t.Fatalf("SignLifecycle: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO audit_key_lifecycle
		   (host_name, key_id, event, at_seq, by_key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-0', ?, 'retired', ?, 'cluster-ca', ?, ?, ?, NULL)`,
		kr.KeyID(), seq, sig, "2026-07-29T10:00:03Z", "2026-07-29T10:00:03Z"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if retired, _ := KeyIsRetired(ctx, c, kr, "node-0", kr.KeyID()); retired {
		t.Fatal("claiming by_key_id=cluster-ca was enough to retire a key\n" +
			"the reserved id must be checked against the CA certificate, not trusted")
	}
}

// TestLifecycle_APredecessorCannotRetireANeverAdoptedKey.
//
// The standing rule compared the signer's adoption against firstAdopted[subject],
// read straight out of the map — which yields 0 for a key that never adopted. The
// test then reduced to "signerAdopted <= 0", true for nothing, so ANY adopted key
// of the host could retire a never-adopted one.
//
// That is exactly the key `never adopted` exists to report: a certificate
// published by a host that cannot sign. signingContracts skips a retired key
// before it ever asks about adoption, so the holder of a leaked predecessor could
// retire it and the finding would vanish — the host back to reading clean, which
// is the outcome the whole verdict is arranged against. Clearing it is supposed to
// take the CA and nothing else.
func TestLifecycle_APredecessorCannotRetireANeverAdoptedKey(t *testing.T) {
	rows := []lifecycleRow{
		// The host's real key, adopted normally, later leaked.
		{host: "node-1", keyID: "old", event: auditLifecycleAdopted, seq: 100, byKeyID: "old",
			subjectGeneration: 100, signerGeneration: 100},
		// A certificate published with no adoption — the never-adopted case.
		// (No adopted row for "new" at all.)
		// What the holder of the leaked key tries.
		{host: "node-1", keyID: "new", event: auditLifecycleRetired, seq: 200, byKeyID: "old",
			subjectGeneration: 200, signerGeneration: 100},
	}
	got := reduceLifecycle(rows)
	if events := got[lifecycleKey{host: "node-1", keyID: "new"}]; len(events) > 0 {
		t.Fatalf("a key that never adopted was retired by another key of the same host: %+v\n"+
			"succession is a relation between two ADOPTED keys — a key with no adoption has no "+
			"predecessor, and letting one exist erases the `never adopted` finding that this "+
			"state is supposed to raise", events)
	}
}

// A published certificate whose private key was unreadable has no adoption
// record. Rotating it installs a CA-signed, later-generation successor; that
// successor must be able to close the orphan contract or the documented repair
// leaves NeverAdopted permanent.
func TestLifecycle_ASuccessorRetiresAnOlderNeverAdoptedKey(t *testing.T) {
	rows := []lifecycleRow{
		{host: "node-1", keyID: "new", event: auditLifecycleAdopted, seq: 200, byKeyID: "new",
			subjectGeneration: 200, signerGeneration: 200},
		{host: "node-1", keyID: "old-orphan", event: auditLifecycleRetired, seq: 200, byKeyID: "new",
			subjectGeneration: 100, signerGeneration: 200},
	}
	got := reduceLifecycle(rows)
	if _, retired := got[lifecycleKey{host: "node-1", keyID: "old-orphan"}][auditLifecycleRetired]; !retired {
		t.Fatalf("a later CA-generated successor could not retire the older orphan: %+v", got)
	}
}

// The legitimate case must keep working: a successor retiring a predecessor that
// DID adopt is an ordinary rotation.
func TestLifecycle_ASuccessorStillRetiresAnAdoptedPredecessor(t *testing.T) {
	rows := []lifecycleRow{
		{host: "node-1", keyID: "old", event: auditLifecycleAdopted, seq: 100, byKeyID: "old"},
		{host: "node-1", keyID: "new", event: auditLifecycleAdopted, seq: 200, byKeyID: "new"},
		{host: "node-1", keyID: "old", event: auditLifecycleRetired, seq: 150, byKeyID: "new"},
	}
	got := reduceLifecycle(rows)
	events := got[lifecycleKey{host: "node-1", keyID: "old"}]
	if _, retired := events[auditLifecycleRetired]; !retired {
		t.Fatalf("an ordinary rotation was refused: a successor could not retire its "+
			"predecessor: %+v", events)
	}
}
