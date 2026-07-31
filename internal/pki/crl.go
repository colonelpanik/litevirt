package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"crypto/rand"
)

var (
	crlInstallMu sync.Mutex
	crlVerifyMu  sync.RWMutex
	// Only successful signature checks enter this cache. A peer without the CA
	// key cannot grow it with garbage, while periodic sync avoids repeating an
	// ECDSA verification for every historical CRL every 30 seconds.
	verifiedCRLs      = make(map[[sha256.Size]byte]struct{})
	checkCRLSignature = func(crl *x509.RevocationList, ca *x509.Certificate) error {
		return crl.CheckSignatureFrom(ca)
	}
)

// GenerateCRL creates or updates a CRL file, revoking the given serial numbers.
// The CRL is signed by the CA at caCertPath/caKeyPath.
func GenerateCRL(caCertPath, caKeyPath, crlPath string, revokedSerials []string) error {
	crlInstallMu.Lock()
	defer crlInstallMu.Unlock()
	return generateCRLLocked(caCertPath, caKeyPath, crlPath, revokedSerials)
}

func generateCRLLocked(caCertPath, caKeyPath, crlPath string, revokedSerials []string) error {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("load CA for CRL: %w", err)
	}

	// GenerateCRL is also a public minting path. Treat an existing verified
	// bundle as a floor, exactly as AppendToCRL does, so a caller cannot replace
	// established revocations merely by supplying a shorter slice.
	serialSet := make(map[string]struct{}, len(revokedSerials))
	if existing, readErr := os.ReadFile(crlPath); readErr == nil {
		crls, parseErr := parseCRLs(existing)
		if parseErr != nil {
			return fmt.Errorf("refusing to replace an unreadable existing CRL: %w", parseErr)
		}
		for _, crl := range crls {
			if err := checkCRLSignature(crl, caCert); err != nil {
				return fmt.Errorf("refusing to replace an existing CRL not signed by this CA: %w", err)
			}
			for _, entry := range crl.RevokedCertificateEntries {
				serialSet[entry.SerialNumber.Text(16)] = struct{}{}
			}
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read existing CRL: %w", readErr)
	}
	for _, serial := range revokedSerials {
		n, ok := new(big.Int).SetString(serial, 16)
		if !ok || n.Sign() < 0 {
			return fmt.Errorf("invalid certificate serial %q", serial)
		}
		serialSet[n.Text(16)] = struct{}{}
	}
	merged := make([]string, 0, len(serialSet))
	for serial := range serialSet {
		merged = append(merged, serial)
	}
	sort.Strings(merged)

	var revoked []pkix.RevokedCertificate
	for _, s := range merged {
		serial, _ := new(big.Int).SetString(s, 16)
		revoked = append(revoked, pkix.RevokedCertificate{
			SerialNumber:   serial,
			RevocationTime: time.Now(),
		})
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: toRevocationEntries(revoked),
		Number:                    big.NewInt(nextCRLNumber(crlPath)),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(365 * 24 * time.Hour),
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, template, caCert, caKey)
	if err != nil {
		return fmt.Errorf("create CRL: %w", err)
	}

	return writeCRLAtomically(crlPath, crlDER)
}

// AppendToCRL adds a serial number to an existing CRL, or creates a new one.
func AppendToCRL(caCertPath, caKeyPath, crlPath, serial string) error {
	crlInstallMu.Lock()
	defer crlInstallMu.Unlock()

	var existing []string

	// An ABSENT CRL is the first revocation and starts an empty list. An
	// unreadable or corrupt one is not the same thing and must not be treated as
	// empty: the result would be a CRL numbered now — higher than the cluster's —
	// that revokes only this serial, and once that replicates, every host revoked
	// before it is accepted again on every node. InstallCRL refuses such a CRL on
	// the receiving side; refusing to MINT it is the half that keeps the operator
	// from being told the revocation succeeded.
	entries, err := LoadCRL(crlPath)
	switch {
	case err == nil:
		existing = entries
	case errors.Is(err, os.ErrNotExist):
		// no CRL yet — this is the first revocation
	default:
		return fmt.Errorf("refusing to rebuild the CRL from an unreadable %s (%w): a CRL minted "+
			"without the serials already in it would un-revoke every host revoked so far. Restore "+
			"that file, or delete it deliberately if this cluster has never revoked anything",
			crlPath, err)
	}

	// Check for duplicates.
	for _, s := range existing {
		if s == serial {
			return nil // already revoked
		}
	}

	existing = append(existing, serial)
	return generateCRLLocked(caCertPath, caKeyPath, crlPath, existing)
}

// LoadCRL reads a CRL file and returns the revoked serial numbers as hex strings.
func LoadCRL(crlPath string) ([]string, error) {
	data, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, err
	}

	crls, err := parseCRLs(data)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var serials []string
	for _, crl := range crls {
		for _, entry := range crl.RevokedCertificateEntries {
			serial := entry.SerialNumber.Text(16)
			if _, ok := seen[serial]; ok {
				continue
			}
			seen[serial] = struct{}{}
			serials = append(serials, serial)
		}
	}
	sort.Strings(serials)
	return serials, nil
}

// IsCertRevoked checks if a certificate serial is in the CRL.
func IsCertRevoked(pkiDir string, serial *big.Int) bool {
	crlPath := filepath.Join(pkiDir, "crl.pem")
	serials, err := LoadCRL(crlPath)
	if err != nil {
		return false // no CRL or unreadable — not revoked
	}
	target := serial.Text(16)
	for _, s := range serials {
		if s == target {
			return true
		}
	}
	return false
}

// nextCRLNumber picks a CRL number strictly greater than the one already in the
// file. The number is a wall-clock second, which is fine for a human revoking a
// host and wrong for anything faster: two revocations inside the same second
// produce the same number, and every reader of a replicated CRL decides whether
// to install by comparing numbers. Two removals in quick succession would leave
// half the cluster enforcing the first CRL and calling the second a duplicate.
func nextCRLNumber(crlPath string) int64 {
	n := time.Now().Unix()
	if prev := CRLVersion(crlPath); prev >= n {
		n = prev + 1
	}
	return n
}

// verifyCRL parses a CRL and checks it against the cluster CA in pkiDir.
//
// Nothing downstream may look at a CRL's contents before this returns, and that
// includes its number: the number is the value every reader orders by, so taking
// it from an unverified parse is how an attacker gets to choose the ordering.
func verifyCRLs(pkiDir string, crlPEM []byte) ([]*x509.RevocationList, error) {
	crls, err := parseCRLs(crlPEM)
	if err != nil {
		return nil, err
	}
	caCert, err := loadCert(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("load cluster CA to verify the CRL: %w", err)
	}
	for _, crl := range crls {
		cacheMaterial := make([]byte, 0, len(caCert.Raw)+len(crl.Raw))
		cacheMaterial = append(cacheMaterial, caCert.Raw...)
		cacheMaterial = append(cacheMaterial, crl.Raw...)
		cacheKey := sha256.Sum256(cacheMaterial)
		crlVerifyMu.RLock()
		_, cached := verifiedCRLs[cacheKey]
		crlVerifyMu.RUnlock()
		if !cached {
			if err := checkCRLSignature(crl, caCert); err != nil {
				return nil, fmt.Errorf("CRL does not verify against the cluster CA: %w", err)
			}
			crlVerifyMu.Lock()
			verifiedCRLs[cacheKey] = struct{}{}
			crlVerifyMu.Unlock()
		}
		if crl.Number == nil {
			return nil, fmt.Errorf("CRL carries no number, so it cannot be ordered")
		}
	}
	return crls, nil
}

// VerifiedCRLNumber returns a CRL's number, but only once its signature has been
// checked against the cluster CA. Callers ordering several candidate CRLs use this
// rather than parsing the number themselves, so an unsigned blob can never take
// part in the ordering.
func VerifiedCRLNumber(pkiDir string, crlPEM []byte) (int64, error) {
	crls, err := verifyCRLs(pkiDir, crlPEM)
	if err != nil {
		return 0, err
	}
	var highest int64
	for _, crl := range crls {
		if n := crl.Number.Int64(); n > highest {
			highest = n
		}
	}
	return highest, nil
}

// InstallCRL verifies and atomically adds one CA-signed CRL to the locally
// enforced bundle. See InstallCRLs.
func InstallCRL(pkiDir string, crlPEM []byte) (int64, bool, error) {
	return InstallCRLs(pkiDir, [][]byte{crlPEM})
}

// InstallCRLs verifies CA-signed CRLs and atomically installs their union.
//
// A CRL number orders snapshots; it does not prove that one snapshot contains
// another. Two CA holders can mint different CRLs with the same number, and a
// restored CA holder can mint a higher-numbered list from stale state. Choosing
// one winner in either case un-revokes certificates. The file consumed by the
// mTLS checker is therefore a PEM bundle: each member is independently signed by
// the cluster CA and the checker enforces the union of their serials.
//
// The existing on-disk bundle participates only when it still verifies. Missing
// or corrupt local state is not an authority and cannot veto replicated state.
// The process-wide lock makes the compare and rename one operation for the
// PublishCRL and periodic-sync goroutines.
func InstallCRLs(pkiDir string, candidates [][]byte) (int64, bool, error) {
	crlInstallMu.Lock()
	defer crlInstallMu.Unlock()

	crlPath := filepath.Join(pkiDir, "crl.pem")
	all := append([][]byte(nil), candidates...)
	if local, err := os.ReadFile(crlPath); err == nil {
		if _, verifyErr := verifyCRLs(pkiDir, local); verifyErr == nil {
			all = append(all, local)
		}
	}

	type member struct {
		der     []byte
		number  int64
		hash    [sha256.Size]byte
		serials map[string]struct{}
	}
	byHash := make(map[[sha256.Size]byte]member)
	for _, body := range all {
		crls, err := verifyCRLs(pkiDir, body)
		if err != nil {
			return 0, false, err
		}
		for _, crl := range crls {
			hash := sha256.Sum256(crl.Raw)
			n := crl.Number.Int64()
			serials := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
			for _, entry := range crl.RevokedCertificateEntries {
				serials[entry.SerialNumber.Text(16)] = struct{}{}
			}
			byHash[hash] = member{der: crl.Raw, number: n, hash: hash, serials: serials}
		}
	}
	if len(byHash) == 0 {
		return 0, false, fmt.Errorf("no CRL supplied")
	}
	members := make([]member, 0, len(byHash))
	for _, m := range byHash {
		members = append(members, m)
	}
	// Normal CRLs are cumulative. Keeping every historical snapshot would make
	// crl.pem grow quadratically in the number of revocations. Drop a member when
	// another signed member covers all of its serials; incomparable branches stay,
	// because together they are what prevents equal-number or stale-mint forks
	// from un-revoking either side.
	covered := make([]bool, len(members))
	for i := range members {
		for j := range members {
			if i == j || len(members[j].serials) < len(members[i].serials) {
				continue
			}
			all := true
			for serial := range members[i].serials {
				if _, ok := members[j].serials[serial]; !ok {
					all = false
					break
				}
			}
			if !all {
				continue
			}
			// Equal sets keep the deterministically newer member.
			if len(members[j].serials) > len(members[i].serials) ||
				members[j].number > members[i].number ||
				(members[j].number == members[i].number &&
					bytes.Compare(members[j].hash[:], members[i].hash[:]) > 0) {
				covered[i] = true
				break
			}
		}
	}
	pruned := members[:0]
	for i := range members {
		if !covered[i] {
			pruned = append(pruned, members[i])
		}
	}
	members = pruned
	var highest int64
	for _, m := range members {
		if m.number > highest {
			highest = m.number
		}
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].number != members[j].number {
			return members[i].number < members[j].number
		}
		return bytes.Compare(members[i].hash[:], members[j].hash[:]) < 0
	})
	var bundle bytes.Buffer
	for _, m := range members {
		if err := pem.Encode(&bundle, &pem.Block{Type: "X509 CRL", Bytes: m.der}); err != nil {
			return 0, false, fmt.Errorf("encode CRL bundle: %w", err)
		}
	}
	bundleBytes := bundle.Bytes()
	if local, err := os.ReadFile(crlPath); err == nil && bytes.Equal(local, bundleBytes) {
		return highest, false, nil
	}

	// Write through a temporary file: the mTLS checker reloads on mtime change and
	// must never observe a half-written CRL, which it would read as "unparseable →
	// enforce nothing" and cache until the next write.
	tmp, err := os.CreateTemp(pkiDir, "crl-*.pem.tmp")
	if err != nil {
		return 0, false, fmt.Errorf("create a temporary file for the CRL: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(bundleBytes); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return 0, false, fmt.Errorf("write CRL: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return 0, false, fmt.Errorf("write CRL: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return 0, false, fmt.Errorf("set CRL permissions: %w", err)
	}
	if err := os.Rename(tmpName, crlPath); err != nil {
		os.Remove(tmpName)
		return 0, false, fmt.Errorf("install CRL: %w", err)
	}
	return highest, true, nil
}

func writeCRLAtomically(path string, der []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "crl-mint-*.pem.tmp")
	if err != nil {
		return fmt.Errorf("create temporary CRL: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := pem.Encode(tmp, &pem.Block{Type: "X509 CRL", Bytes: der}); err != nil {
		cleanup()
		return fmt.Errorf("encode CRL: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("write CRL: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("set CRL permissions: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("install CRL: %w", err)
	}
	return nil
}

// CRLVersion returns the CRL number (version) from a CRL file, or 0 if not found.
// Used to detect CRL version mismatches between hosts for gossip-based distribution (#49).
func CRLVersion(crlPath string) int64 {
	data, err := os.ReadFile(crlPath)
	if err != nil {
		return 0
	}
	crls, err := parseCRLs(data)
	if err != nil {
		return 0
	}
	var highest int64
	for _, crl := range crls {
		if crl.Number != nil && crl.Number.Int64() > highest {
			highest = crl.Number.Int64()
		}
	}
	return highest
}

func parseCRLs(data []byte) ([]*x509.RevocationList, error) {
	rest := data
	var out []*x509.RevocationList
	for {
		block, tail := pem.Decode(rest)
		if block == nil {
			if len(out) == 0 {
				return nil, fmt.Errorf("no PEM block in CRL")
			}
			if strings.TrimSpace(string(rest)) != "" {
				return nil, fmt.Errorf("non-PEM data in CRL bundle")
			}
			return out, nil
		}
		if block.Type != "X509 CRL" {
			return nil, fmt.Errorf("unexpected PEM block %q in CRL bundle", block.Type)
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CRL: %w", err)
		}
		out = append(out, crl)
		rest = tail
	}
}

func toRevocationEntries(revoked []pkix.RevokedCertificate) []x509.RevocationListEntry {
	entries := make([]x509.RevocationListEntry, len(revoked))
	for i, r := range revoked {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   r.SerialNumber,
			RevocationTime: r.RevocationTime,
		}
	}
	return entries
}
