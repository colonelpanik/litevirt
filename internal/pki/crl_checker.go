package pki

import (
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// crlChecker is the revocation oracle for mTLS handshakes. It loads the cluster
// CRL, verifies its signature against the CA, and caches the parsed revoked-set,
// reloading only when the file's mtime changes — so a freshly-revoked cert takes
// effect WITHOUT a daemon restart, while steady-state handshakes don't re-parse.
//
// Fail-safe policy (deliberate, for cluster availability):
//   - no CRL file              → nothing revoked (allow);
//   - CRL present, bad/forged signature, or unparseable
//                              → IGNORE it (log loudly, allow). We never enforce
//                                revocation from a CRL not signed by our CA, and
//                                a corrupt CRL must never partition the cluster.
//   - CRL present, valid CA signature
//                              → enforce its revoked-serial set.
//
// An attacker who could write a forged CRL into pkiDir already has root there
// (game over); the verification's real job is to make sure a corrupt/garbage
// file degrades to "no revocations" instead of breaking every handshake.
type crlChecker struct {
	crlPath string
	caCert  *x509.Certificate // for signature verification; nil → skip verify (legacy)

	mu      sync.Mutex
	mtime   time.Time
	loaded  bool
	revoked map[string]bool // serial (lowercase hex) → revoked
}

func newCRLChecker(pkiDir string, caCert *x509.Certificate) *crlChecker {
	return &crlChecker{
		crlPath: filepath.Join(pkiDir, "crl.pem"),
		caCert:  caCert,
	}
}

// isRevoked reports whether serial is revoked by the currently-valid CRL.
func (c *crlChecker) isRevoked(serial *big.Int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshLocked()
	if c.revoked == nil {
		return false
	}
	return c.revoked[serial.Text(16)]
}

// refreshLocked reloads the CRL if the file changed since the last load.
func (c *crlChecker) refreshLocked() {
	fi, err := os.Stat(c.crlPath)
	if err != nil {
		// No CRL → nothing revoked. Reset so a deleted CRL stops enforcing.
		c.revoked = nil
		c.loaded = false
		c.mtime = time.Time{}
		return
	}
	if c.loaded && fi.ModTime().Equal(c.mtime) {
		return // unchanged
	}
	c.mtime = fi.ModTime()
	c.loaded = true
	c.revoked = nil // default to "not enforcing" until we have a verified set

	data, err := os.ReadFile(c.crlPath)
	if err != nil {
		slog.Error("CRL unreadable — not enforcing revocation", "path", c.crlPath, "error", err)
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		slog.Error("CRL has no PEM block — not enforcing revocation", "path", c.crlPath)
		return
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		slog.Error("CRL parse failed — not enforcing revocation", "path", c.crlPath, "error", err)
		return
	}
	if c.caCert != nil {
		if err := crl.CheckSignatureFrom(c.caCert); err != nil {
			slog.Error("CRL signature does NOT verify against the cluster CA — IGNORING this CRL (revocations not enforced)",
				"path", c.crlPath, "error", err)
			return
		}
	}
	m := make(map[string]bool, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		m[e.SerialNumber.Text(16)] = true
	}
	c.revoked = m
	slog.Info("CRL loaded and verified", "path", c.crlPath, "revoked_count", len(m))
}

// parseCACert extracts the first certificate from a PEM blob, or nil.
func parseCACert(caPEM []byte) *x509.Certificate {
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}
