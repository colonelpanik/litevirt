package corrosion

import (
	"bytes"
	"context"
	"math/rand"
	"strings"
	"testing"
)

// The audit content hash is SHA-256 over
//
//	prev_hash NUL ("id" NUL id NUL) ("timestamp" NUL ts NUL) ... ("result" NUL result NUL)
//
// which is injective only while no value contains a NUL. With one, a field
// boundary can be forged from inside a value: these two rows differ and encode
// to the same bytes, and because a signature covers (content_hash, seq) and
// nothing else, it verifies for both.
var (
	collisionA = AuditRecord{ID: "x", Target: "a\x00detail\x00b", Detail: "c"}
	collisionB = AuditRecord{ID: "x", Target: "a", Detail: "b\x00detail\x00c"}
)

// TestHashAuditRow_FixedVectors pins the v1 encoding byte for byte. The vectors
// were computed independently of this package (Python hashlib over the encoding
// written out above), so a refactor of HashAuditRow that changes a single byte
// — a separator, a field name, the field order — fails here, and every signed
// row already in a cluster would otherwise stop verifying.
func TestHashAuditRow_FixedVectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  AuditRecord
		want string
	}{
		{"every field set", AuditRecord{
			ID: "row-1", Timestamp: "2026-06-23T10:00:01.000000000Z", Username: "alice",
			HostName: "node-0", Action: "vm.create", Target: "vm-1",
			Detail: "cpus=2 memory=2048", Result: "ok",
		}, "74382499e13912019ea69aa56a404c47d901b2b2797f15b2f942ec1c66ac5c14"},
		{"empty fields and a prev hash", AuditRecord{
			PrevHash: "151da814", ID: "row-2", Timestamp: "2026-06-23T10:00:02.000000000Z",
			HostName: "node-0", Action: "auth.login", Result: "denied",
		}, "46419b0e4c437d985d2e9b6d4ff034d807ba84a37f3295f90214a5294fe3bb69"},
		{"zero record", AuditRecord{},
			"c851144887e39cdbc83a93ea943b980bf08716a32cee0df559b491b854c97b3e"},
	} {
		if got := HashAuditRow(tc.rec); got != tc.want {
			t.Errorf("%s: HashAuditRow = %s, want %s (the v1 encoding changed)", tc.name, got, tc.want)
		}
	}
}

// TestHashAuditRow_CollisionPairIsReal guards the premise of the tests below:
// at the raw-hash level the pair really does collide. If it ever stops doing so
// the encoding has changed, and TestHashAuditRow_FixedVectors says how.
func TestHashAuditRow_CollisionPairIsReal(t *testing.T) {
	if HashAuditRow(collisionA) != HashAuditRow(collisionB) {
		t.Fatal("the collision pair no longer collides; the v1 encoding has changed")
	}
}

// decodeAuditCanonical is the inverse of auditCanonical over NUL-free input. It
// splits on NUL and expects exactly the fixed field names in the fixed order. A
// decoder that recovers every record from its encoding is the injectivity proof
// in executable form: if two NUL-free records encoded alike, the decoder would
// have to return both of them.
func decodeAuditCanonical(t *testing.T, b []byte) AuditRecord {
	t.Helper()
	parts := bytes.Split(b, []byte{0})
	// prev, 8 × (key, value), and the empty remainder after the final NUL.
	if len(parts) != 1+2*len(auditFieldNames)+1 || len(parts[len(parts)-1]) != 0 {
		t.Fatalf("encoding has %d NUL-separated parts, want %d", len(parts), 1+2*len(auditFieldNames)+1)
	}
	vals := map[string]string{}
	for i, k := range auditFieldNames {
		if got := string(parts[1+2*i]); got != k {
			t.Fatalf("field %d is named %q, want %q", i, got, k)
		}
		vals[k] = string(parts[2+2*i])
	}
	return AuditRecord{
		PrevHash: string(parts[0]), ID: vals["id"], Timestamp: vals["timestamp"],
		Username: vals["username"], HostName: vals["host_name"], Action: vals["action"],
		Target: vals["target"], Detail: vals["detail"], Result: vals["result"],
	}
}

// TestAuditCanonical_RoundTripsWithoutNUL exercises the decoder over records
// built to stress the argument: empty values, values that spell a field name,
// and values that run into one another. Every one must come back exactly.
func TestAuditCanonical_RoundTripsWithoutNUL(t *testing.T) {
	alphabet := []string{"", "a", "detail", "target", "id", "\x01", "x y", "é", "result"}
	rng := rand.New(rand.NewSource(1))
	pick := func() string {
		var b strings.Builder
		for n := rng.Intn(4); n > 0; n-- {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		return b.String()
	}
	for i := 0; i < 5000; i++ {
		r := AuditRecord{
			PrevHash: pick(), ID: pick(), Timestamp: pick(), Username: pick(), HostName: pick(),
			Action: pick(), Target: pick(), Detail: pick(), Result: pick(),
		}
		if got := decodeAuditCanonical(t, auditCanonical(r)); got != r {
			t.Fatalf("round trip lost information:\n in  %+v\n out %+v", r, got)
		}
	}
}

// FuzzAuditCanonical_Injective: for any two NUL-free records, equal encodings
// imply equal records.
func FuzzAuditCanonical_Injective(f *testing.F) {
	f.Add("a", "detail", "b", "", "c")
	f.Add("", "", "", "", "")
	f.Fuzz(func(t *testing.T, a, b, c, d, e string) {
		r1 := AuditRecord{PrevHash: a, ID: b, Target: c, Detail: d, Result: e}
		r2 := AuditRecord{PrevHash: a + b, Target: c + d, Detail: e}
		if auditRecordNULField(r1) != "" || auditRecordNULField(r2) != "" {
			return
		}
		if bytes.Equal(auditCanonical(r1), auditCanonical(r2)) != (r1 == r2) {
			t.Fatalf("encoding equality disagrees with record equality: %+v vs %+v", r1, r2)
		}
		if got := decodeAuditCanonical(t, auditCanonical(r1)); got != r1 {
			t.Fatalf("round trip lost information: %+v -> %+v", r1, got)
		}
	})
}

// TestInsertAuditLog_CollisionPairCannotBothBeWritten writes each half of the
// collision pair through the one audit write path, on two fresh databases so
// that everything else in the hash (prev hash, seq, id, stamp) is identical. The
// stored hashes must differ — otherwise a row written for one could be swapped
// for the other without disturbing its hash or its signature.
func TestInsertAuditLog_CollisionPairCannotBothBeWritten(t *testing.T) {
	ctx := context.Background()
	write := func(r AuditRecord) (target, detail, hash string) {
		c := newAuditTestClient(t)
		r.HostName, r.Timestamp, r.Action, r.Result = "node-0", "2026-06-23T10:00:01Z", "auth.login", "denied"
		if err := InsertAuditLog(ctx, c, r); err != nil {
			t.Fatalf("InsertAuditLog: %v", err)
		}
		rows, err := c.Query(ctx, `SELECT target, detail, content_hash FROM audit_log WHERE id = ?`, r.ID)
		if err != nil || len(rows) != 1 {
			t.Fatalf("read back: %v (rows=%d)", err, len(rows))
		}
		return rows[0].String("target"), rows[0].String("detail"), rows[0].String("content_hash")
	}
	tA, dA, hA := write(collisionA)
	tB, dB, hB := write(collisionB)
	if hA == hB {
		t.Fatalf("both halves of the collision pair were stored with hash %s", hA)
	}
	for _, v := range []string{tA, dA, tB, dB} {
		if strings.ContainsRune(v, 0) {
			t.Errorf("stored value %q contains a NUL", v)
		}
	}
	// The row is kept, with each NUL made visible — a refused row would be a
	// silent audit gap, because every caller discards InsertAuditLog's error.
	if want := "a␀detail␀b"; tA != want {
		t.Errorf("target stored as %q, want %q", tA, want)
	}
}

// TestInsertAuditLog_RefusesNULInStructuralFields: the fields the daemon itself
// controls are not escaped, because escaping one would silently change an id,
// a host's sub-chain key or a value queried by exact match. A NUL there is a
// bug, and the row is refused.
func TestInsertAuditLog_RefusesNULInStructuralFields(t *testing.T) {
	ctx := context.Background()
	base := AuditRecord{ID: "r1", Timestamp: "2026-06-23T10:00:01Z", Username: "u",
		HostName: "node-0", Action: "vm.start", Target: "x", Result: "ok"}
	for _, tc := range []struct {
		field string
		set   func(*AuditRecord)
	}{
		{"id", func(r *AuditRecord) { r.ID = "r\x001" }},
		{"timestamp", func(r *AuditRecord) { r.Timestamp += "\x00" }},
		{"host_name", func(r *AuditRecord) { r.HostName = "node\x000" }},
		{"action", func(r *AuditRecord) { r.Action = "vm\x00start" }},
		{"result", func(r *AuditRecord) { r.Result = "ok\x00" }},
	} {
		c := newAuditTestClient(t)
		r := base
		tc.set(&r)
		err := InsertAuditLog(ctx, c, r)
		if err == nil || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: InsertAuditLog error = %v, want a refusal naming the field", tc.field, err)
		}
		rows, qerr := c.Query(ctx, `SELECT id FROM audit_log`)
		if qerr != nil {
			t.Fatal(qerr)
		}
		if len(rows) != 0 {
			t.Errorf("%s: a refused row was written anyway", tc.field)
		}
	}
}

// TestVerifyAuditChain_FlagsNULRow: a row carrying a NUL can only come from a
// build without the write-side guard or from a direct write to the table, and
// its content is not bound by its hash — its collision partner verifies just as
// well. The hash itself matches, so without this check the row reads as clean.
func TestVerifyAuditChain_FlagsNULRow(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	ins(t, c, "ok-1", "node-0", "2026-06-23T10:00:01Z")

	rows, err := c.Query(ctx, `SELECT content_hash FROM audit_log WHERE id = 'ok-1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read tail: %v", err)
	}
	rec := collisionA
	rec.ID, rec.Timestamp, rec.HostName, rec.Action, rec.Result, rec.Username =
		"nul-1", "2026-06-23T10:00:02Z", "node-0", "auth.login", "denied", "u"
	rec.PrevHash = rows[0].String("content_hash")
	rec.Seq = 2
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash, seq)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName, rec.Action, rec.Target, rec.Detail,
		rec.Result, rec.PrevHash, HashAuditRow(rec), rec.Seq); err != nil {
		t.Fatalf("seed NUL row: %v", err)
	}

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if res.BrokenAt != "" {
		t.Fatalf("hash reported broken at %s; the seeded row's hash is correct, so the NUL check is what must fire", res.BrokenAt)
	}
	if len(res.Ambiguous) != 1 || !strings.HasPrefix(res.Ambiguous[0], "nul-1:") ||
		!strings.Contains(res.Ambiguous[0], "target") {
		t.Fatalf("Ambiguous = %q, want one entry for nul-1 naming target", res.Ambiguous)
	}
	if !res.Unverified() {
		t.Error("a row whose content its hash does not bind must fail verification (Unverified)")
	}
}
