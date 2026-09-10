package corrosion

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFingerprintFromCert(t *testing.T) {
	const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	sum := sha256.Sum256([]byte(pem))
	want := hex.EncodeToString(sum[:])[:16]

	got, err := fingerprintFromCert(pem)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}
	if len(got) != 16 {
		t.Fatalf("fingerprint length = %d, want 16", len(got))
	}
}

func TestFingerprintRejectsEmptyCert(t *testing.T) {
	if _, err := fingerprintFromCert(""); err == nil {
		t.Fatal("an empty ca_cert must be an error, not a fingerprint of the empty string")
	}
}

func TestFingerprintIsDeterministic(t *testing.T) {
	a, _ := fingerprintFromCert("cert-a")
	b, _ := fingerprintFromCert("cert-a")
	c, _ := fingerprintFromCert("cert-b")
	if a != b {
		t.Fatal("same cert must yield same fingerprint")
	}
	if a == c {
		t.Fatal("different certs must yield different fingerprints")
	}
}
