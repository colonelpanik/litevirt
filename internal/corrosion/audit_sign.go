package corrosion

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/litevirt/litevirt/internal/pki"
)

// Audit tamper-evidence.
//
// The pre-v45 chain is an UNKEYED SHA-256 over each row plus its predecessor's
// hash. That detects accidental corruption and nothing else: HashAuditRow is
// deterministic and takes no secret, so anyone able to write the table can edit
// a row and recompute every hash after it. The daemon then resealed the whole
// sub-chain at every start, so an attacker did not even have to do the
// recomputation — edit, restart, and `lv audit verify` came back clean.
//
// A signature fixes the part a hash cannot: the chain now depends on a secret
// the attacker has to steal rather than an algorithm they can just run.
//
// WHY ASYMMETRIC, NOT HMAC. An HMAC key has to be either host-local or
// cluster-shared, and both defeat the purpose. Host-local means only the host
// that wrote a row can check it, so a compromised host verifies its own edited
// history and its neighbours cannot contradict it — but neighbours noticing is
// the entire mechanism. Cluster-shared means any single compromised node can
// forge any other host's chain. A per-host private key with a published
// certificate gives cross-node verification AND per-host forgery resistance:
// node B can prove node A's log is intact without ever being able to write it.
//
// BOOTSTRAP uses the host's EXISTING cluster identity (pkiDir/host.key). Every
// node already has it, it is already signed by the cluster CA with the host
// name as its CN, and it is already the credential that says "I am this host".
// Minting anything new needs the CA private key, which lives only on whichever
// node ran `lv host init`, so a fresh node could not otherwise sign its own log
// at all. Reuse is made safe by domain separation: the payload below is
// prefixed with a string no TLS handshake ever signs.
//
// ROTATION moves the host onto a DEDICATED audit signing pair (see
// auditSigningPaths). It has to be a separate identity, because replacing
// host.crt/host.key on a running node changes the certificate the gRPC listener
// serves and the one the health checker dials peers with — both built once at
// boot and never reloaded — plus the target of the libvirt symlinks that
// qemu+tls:// migration follows. Rotating the audit key must not put quorum or
// a live migration at risk.

// auditSigDomain separates audit-row signatures from every other use of the
// host key. Without it, a signature produced for one protocol could in
// principle be replayed as a valid signature in another.
const auditSigDomain = "litevirt-audit-row-v1"

// auditHeadDomain is the same idea for chain-head signatures — a head must not
// be interchangeable with a row.
//
// v2 adds created_at to the signed payload. It was outside the signature and the
// verifier reads it back to decide whether a head is old enough for a shortfall
// to count as truncation — so it was an attacker-writable off switch for
// truncation detection. v1 heads are still accepted, or upgrading would report
// every existing head as a bad signature.
const auditHeadDomain = "litevirt-audit-head-v1"
const auditHeadDomainV2 = "litevirt-audit-head-v2"

// auditRetireDomain separates a retirement assertion from a row and a head.
const auditRetireDomain = "litevirt-audit-retire-v1"

// AuditKeyring signs this host's audit rows and verifies any host's.
//
// A nil *AuditKeyring is usable and means "unsigned": Sign returns empty and
// the verifier reports rows as unsigned rather than broken. That is the state
// of every cluster before enforcement.audit_signature is turned on.
type AuditKeyring struct {
	hostName string
	keyID    string
	certPEM  string
	key      *ecdsa.PrivateKey // nil ⇒ verify-only keyring
	roots    *x509.CertPool

	mu     sync.RWMutex
	verify map[string]*x509.Certificate // key_id → CA-verified certificate
}

// LoadAuditKeyring loads the host's signing identity from pkiDir. The returned
// keyring can both sign and verify. hostName must match the certificate's CN:
// a row's signature is only meaningful if the certificate that validates it
// names the host the row claims to come from.
func LoadAuditKeyring(pkiDir, hostName string) (*AuditKeyring, error) {
	certPath, keyPath := auditSigningPaths(pkiDir)
	return LoadAuditKeyringFromPaths(pkiDir, certPath, keyPath, hostName)
}

// LoadAuditKeyringFromPaths is LoadAuditKeyring with the identity read from an
// explicit pair rather than the host's installed one.
//
// `lv host retire-audit-key` uses it to sign one assertion with a certificate
// minted into a temp dir and destroyed immediately afterwards — the key is never
// installed, because a second live copy of a host's signing identity is the
// thing this whole feature exists to avoid.
func LoadAuditKeyringFromPaths(pkiDir, certPath, keyPath, hostName string) (*AuditKeyring, error) {
	k, err := loadAuditRoots(pkiDir)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read audit signing cert: %w", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if cert.Subject.CommonName != hostName {
		return nil, fmt.Errorf("audit signing certificate CN is %q but this host is %q; signatures "+
			"would be attributed to the wrong host", cert.Subject.CommonName, hostName)
	}
	if err := tightenKeyMode(keyPath); err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read audit signing key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", keyPath)
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse audit signing key: %w", err)
	}
	id, err := AuditKeyID(cert)
	if err != nil {
		return nil, err
	}
	k.hostName, k.keyID, k.certPEM, k.key = hostName, id, string(certPEM), priv
	return k, nil
}

// auditSigningPaths picks the identity this host signs audit rows with: a
// DEDICATED audit signing pair if one has been installed, otherwise the host's
// TLS identity.
//
// The fallback is what makes the feature work at all on an existing cluster.
// Minting anything new needs the CA private key, which lives only on the node
// that ran `lv host init`, so a node cannot give itself a dedicated key —
// every node already has host.key, and that is enough to start signing today.
//
// Rotation, which needs the CA anyway, installs the dedicated pair and the node
// moves onto it. From then on the audit identity is independent of the TLS
// identity, so replacing it never touches the certificate the gRPC listener
// serves, the one the health checker dials peers with, or the libvirt symlinks
// that qemu+tls:// migration follows — none of which reload without a restart.
func auditSigningPaths(pkiDir string) (certPath, keyPath string) {
	certPath = filepath.Join(pkiDir, pki.AuditSigningCertName)
	keyPath = filepath.Join(pkiDir, pki.AuditSigningKeyName)
	if fileExists(certPath) && fileExists(keyPath) {
		return certPath, keyPath
	}
	return filepath.Join(pkiDir, "host.crt"), filepath.Join(pkiDir, "host.key")
}

// UsesDedicatedAuditKey reports whether pkiDir holds a dedicated audit signing
// pair, i.e. whether this host has been rotated off its TLS identity.
func UsesDedicatedAuditKey(pkiDir string) bool {
	return fileExists(filepath.Join(pkiDir, pki.AuditSigningCertName)) &&
		fileExists(filepath.Join(pkiDir, pki.AuditSigningKeyName))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// tightenKeyMode repairs the mode of the key about to be loaded.
//
// The primitive lives in internal/pki and runs unconditionally at daemon start
// (pki.TightenPrivateKeys) — reaching it only from here meant reaching it only
// when enforcement.audit_signature was on, a flag that defaults to false, so the
// world-readable host.key that `lv host init` shipped went unrepaired on exactly
// the clusters that had not opted in. This call stays because loading a key is
// the last moment before it is used.
func tightenKeyMode(keyPath string) error { return pki.TightenKeyMode(keyPath) }

// LoadAuditVerifier loads a verify-only keyring — the cluster CA and nothing
// else. Verification deliberately needs no private key: an auditor with a state
// dump and the CA certificate can check every host's chain offline.
func LoadAuditVerifier(pkiDir string) (*AuditKeyring, error) { return loadAuditRoots(pkiDir) }

// PublishSigningCertOnly records this host's verification certificate WITHOUT
// needing the private key to be loadable.
//
// The certificate is public, and publishing it is what puts the host under a
// signing contract — the declaration that its rows carry a signature from here
// on. That declaration must not be conditional on the key being readable,
// because "the key is unreadable" is exactly the state an attacker arranges and
// exactly the state that must not go unnoticed. A host that publishes and then
// cannot sign has every unsigned row reported on every node; a host that
// publishes nothing has, until now, been indistinguishable from one that was
// never meant to sign at all.
//
// Returns the key id it published.
func PublishSigningCertOnly(ctx context.Context, c *Client, pkiDir, hostName string) (string, error) {
	certPath, _ := auditSigningPaths(pkiDir)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read audit signing cert: %w", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return "", err
	}
	if cert.Subject.CommonName != hostName {
		return "", fmt.Errorf("audit signing certificate CN is %q but this host is %q", cert.Subject.CommonName, hostName)
	}
	id, err := AuditKeyID(cert)
	if err != nil {
		return "", err
	}
	k := &AuditKeyring{hostName: hostName, keyID: id, certPEM: string(certPEM)}
	return id, k.publishCert(ctx, c)
}

func loadAuditRoots(pkiDir string) (*AuditKeyring, error) {
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("cluster CA at %s contains no usable certificate", pkiDir)
	}
	return &AuditKeyring{roots: roots, verify: map[string]*x509.Certificate{}}, nil
}

// AuditKeyID is the stable identifier of a signing certificate: the SHA-256 of
// its SubjectPublicKeyInfo. Derived from the key rather than assigned, so two
// nodes can never disagree about what a key id refers to, and a rotated
// certificate gets a new id automatically while the old one stays resolvable
// for rows already signed with it.
func AuditKeyID(cert *x509.Certificate) (string, error) {
	if len(cert.RawSubjectPublicKeyInfo) == 0 {
		return "", fmt.Errorf("certificate carries no public key info")
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:16]), nil
}

// KeyID reports the id of the key this keyring signs with ("" if verify-only).
func (k *AuditKeyring) KeyID() string {
	if k == nil {
		return ""
	}
	return k.keyID
}

// CanSign reports whether this keyring holds a private key.
func (k *AuditKeyring) CanSign() bool { return k != nil && k.key != nil }

// auditRowDigest is what a row signature actually covers.
//
// content_hash already binds prev_hash and all eight content fields, so signing
// it transitively signs the row AND its position in the chain. key_id and seq
// are added explicitly because content_hash does NOT cover them: without
// key_id, a signature made by one key could be presented as another's; without
// seq, rows could be renumbered to hide a gap.
func auditRowDigest(contentHash, keyID string, seq int64) []byte {
	h := sha256.New()
	writeField(h, auditSigDomain)
	writeField(h, contentHash)
	writeField(h, keyID)
	writeField(h, strconv.FormatInt(seq, 10))
	return h.Sum(nil)
}

// auditHeadDigest is the same for a chain head: host, epoch, seq, tail hash.
//
// createdAt is included (v2). The verifier measures the settle window against
// it, so leaving it outside the signature let anyone edit the column and decide
// whether their own head counted — see headHasSettled.
func auditHeadDigest(hostName string, epoch, seq int64, headHash, keyID, createdAt string) []byte {
	h := sha256.New()
	writeField(h, auditHeadDomainV2)
	writeField(h, hostName)
	writeField(h, strconv.FormatInt(epoch, 10))
	writeField(h, strconv.FormatInt(seq, 10))
	writeField(h, headHash)
	writeField(h, keyID)
	writeField(h, createdAt)
	return h.Sum(nil)
}

// auditHeadDigestV1 is the pre-created_at payload, kept so heads already
// published stay verifiable through the upgrade.
func auditHeadDigestV1(hostName string, epoch, seq int64, headHash, keyID string) []byte {
	h := sha256.New()
	writeField(h, auditHeadDomain)
	writeField(h, hostName)
	writeField(h, strconv.FormatInt(epoch, 10))
	writeField(h, strconv.FormatInt(seq, 10))
	writeField(h, headHash)
	writeField(h, keyID)
	return h.Sum(nil)
}

// auditRetireDigest is what a retirement signature covers: which host's key is
// being retired, at what sequence, and who says so.
//
// retiredByKeyID is signed rather than merely recorded, so a signature made by
// one signer cannot be re-filed under another's name.
func auditRetireDigest(hostName, retiredKeyID string, seq int64, retiredByKeyID string) []byte {
	h := sha256.New()
	writeField(h, auditRetireDomain)
	writeField(h, hostName)
	writeField(h, retiredKeyID)
	writeField(h, strconv.FormatInt(seq, 10))
	writeField(h, retiredByKeyID)
	return h.Sum(nil)
}

// writeField appends a NUL-terminated field, so a value containing the
// separator cannot be split to forge a different field boundary.
func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	h.Write([]byte(s))
	h.Write([]byte{0})
}

// SignRow returns the hex ECDSA signature over a row's digest. Returns "" for
// a nil or verify-only keyring, which is how an unsigned cluster behaves.
func (k *AuditKeyring) SignRow(contentHash string, seq int64) (string, error) {
	if !k.CanSign() {
		return "", nil
	}
	return k.sign(auditRowDigest(contentHash, k.keyID, seq))
}

// SignHead returns the hex ECDSA signature over a chain head's digest.
func (k *AuditKeyring) SignHead(hostName string, epoch, seq int64, headHash, createdAt string) (string, error) {
	if !k.CanSign() {
		return "", nil
	}
	return k.sign(auditHeadDigest(hostName, epoch, seq, headHash, k.keyID, createdAt))
}

// SignRetirement asserts that hostName's key retiredKeyID signed nothing valid
// past seq. The assertion is attributed to THIS keyring.
func (k *AuditKeyring) SignRetirement(hostName, retiredKeyID string, seq int64) (string, error) {
	if !k.CanSign() {
		return "", nil
	}
	return k.sign(auditRetireDigest(hostName, retiredKeyID, seq, k.keyID))
}

// VerifyRetirement checks a retirement's signature against the published
// certificate for retiredByKeyID.
//
// One rule covers every legitimate signer: the signing certificate must chain
// to the cluster CA and its CN must be hostName. That admits exactly the parties
// entitled to speak for the host — the retired key itself (a voluntary stop), a
// successor key (a rotation), and a certificate the CA holder minted for that
// host in order to retire it on its behalf (a lost key, a decommission). The
// third needs no special case here: minting a certificate with a chosen CN is
// already what holding the CA means, so `lv host retire-audit-key` publishes one
// and signs with it, and the key never has to be installed anywhere.
//
// Someone who has merely broken into a node has none of these.
func (k *AuditKeyring) VerifyRetirement(ctx context.Context, c *Client, hostName, retiredKeyID string, seq int64, retiredByKeyID, sigHex string) error {
	if k == nil {
		return fmt.Errorf("no audit keyring loaded")
	}
	if retiredByKeyID == "" || sigHex == "" {
		return fmt.Errorf("retirement of key %s carries no signature", retiredKeyID)
	}
	return k.verifySig(ctx, c, hostName, retiredByKeyID, sigHex, func(id string) []byte {
		return auditRetireDigest(hostName, retiredKeyID, seq, id)
	})
}

func (k *AuditKeyring) sign(digest []byte) (string, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest)
	if err != nil {
		return "", fmt.Errorf("sign audit digest: %w", err)
	}
	return hex.EncodeToString(sig), nil
}

// VerifyRow checks a row's signature against the certificate published for
// keyID, requiring that certificate to chain to the cluster CA and to name
// hostName. Returns nil when the signature is good.
func (k *AuditKeyring) VerifyRow(ctx context.Context, c *Client, hostName, keyID, contentHash string, seq int64, sigHex string) error {
	return k.verifySig(ctx, c, hostName, keyID, sigHex, func(id string) []byte {
		return auditRowDigest(contentHash, id, seq)
	})
}

// VerifyHead checks a chain head's signature, accepting either payload version.
//
// A v1 head does not cover created_at, so headHasSettled treats one as
// unverified-timestamp and falls back to the conservative reading. Trying v2
// first means a head published today cannot be downgraded by stripping its
// created_at.
func (k *AuditKeyring) VerifyHead(ctx context.Context, c *Client, hostName string, epoch, seq int64, headHash, keyID, sigHex, createdAt string) error {
	err := k.verifySig(ctx, c, hostName, keyID, sigHex, func(id string) []byte {
		return auditHeadDigest(hostName, epoch, seq, headHash, id, createdAt)
	})
	if err == nil || isUnknownKeyErr(err) {
		return err
	}
	return k.verifySig(ctx, c, hostName, keyID, sigHex, func(id string) []byte {
		return auditHeadDigestV1(hostName, epoch, seq, headHash, id)
	})
}

// HeadTimestampIsSigned reports whether a head's created_at is covered by its
// signature — true for v2 heads, false for ones published before the column
// moved inside the payload.
func (k *AuditKeyring) HeadTimestampIsSigned(ctx context.Context, c *Client, hostName string, epoch, seq int64, headHash, keyID, sigHex, createdAt string) bool {
	return k.verifySig(ctx, c, hostName, keyID, sigHex, func(id string) []byte {
		return auditHeadDigest(hostName, epoch, seq, headHash, id, createdAt)
	}) == nil
}

func (k *AuditKeyring) verifySig(ctx context.Context, c *Client, hostName, keyID, sigHex string, digest func(string) []byte) error {
	if k == nil {
		return fmt.Errorf("no audit keyring loaded")
	}
	cert, err := k.certFor(ctx, c, keyID)
	if err != nil {
		return err
	}
	// The certificate names the host, so a signature can only ever attest to
	// rows for the host that owns the key. Without this a compromised node
	// could sign rows claiming to come from any other host in the cluster.
	if cert.Subject.CommonName != hostName {
		return fmt.Errorf("key %s belongs to host %q but signed a row for %q",
			keyID, cert.Subject.CommonName, hostName)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("key %s is not an ECDSA key", keyID)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("signature is not hex: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest(keyID), sig) {
		return fmt.Errorf("signature does not match")
	}
	return nil
}

// certFor resolves a key id to its CA-verified certificate, caching the result.
// The cache holds only certificates that already passed CA verification, so a
// hit cannot weaken the check.
func (k *AuditKeyring) certFor(ctx context.Context, c *Client, keyID string) (*x509.Certificate, error) {
	if keyID == "" {
		return nil, fmt.Errorf("row carries no key id")
	}
	k.mu.RLock()
	cert := k.verify[keyID]
	k.mu.RUnlock()
	if cert != nil {
		return cert, nil
	}
	// deleted_at is deliberately NOT filtered. A retired certificate must stay
	// resolvable for as long as any row it signed still exists, so tombstoning
	// one cannot be allowed to make that history unverifiable — which would read
	// as mass tampering rather than as the erasure it is. Ignoring the column
	// makes the move inert instead of needing a merge rule to refuse it.
	rows, err := c.Query(ctx,
		`SELECT cert_pem FROM audit_signing_keys WHERE key_id = ?`, keyID)
	if err != nil {
		return nil, fmt.Errorf("look up signing key %s: %w", keyID, err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no published certificate for key %s", keyID)
	}
	cert, err = parseCertPEM([]byte(rows[0].String("cert_pem")))
	if err != nil {
		return nil, fmt.Errorf("published certificate for key %s: %w", keyID, err)
	}
	// The published certificate is replicated data an attacker may also be able
	// to write, so it is trusted only insofar as the cluster CA vouches for it.
	// Publishing a self-minted key alongside forged rows fails here.
	if _, err := cert.Verify(x509.VerifyOptions{Roots: k.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("certificate for key %s does not chain to the cluster CA: %w", keyID, err)
	}
	// A published certificate must match the id it was filed under, or one
	// certificate could answer for another key's signatures.
	if got, err := AuditKeyID(cert); err != nil || got != keyID {
		return nil, fmt.Errorf("certificate filed under key %s actually has id %s", keyID, got)
	}
	k.mu.Lock()
	k.verify[keyID] = cert
	k.mu.Unlock()
	return cert, nil
}

func parseCertPEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// PublishSigningKey records this host's verification certificate so peers can
// check its chain. Idempotent; safe to call on every start.
func (k *AuditKeyring) PublishSigningKey(ctx context.Context, c *Client) error {
	if !k.CanSign() {
		return nil
	}
	return k.publishCert(ctx, c)
}

// publishCert writes the certificate row. Split out because publishing does not
// require the private key — see PublishSigningCertOnly.
func (k *AuditKeyring) publishCert(ctx context.Context, c *Client) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO audit_signing_keys (key_id, host_name, cert_pem, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(key_id) DO UPDATE SET
		   host_name = excluded.host_name,
		   cert_pem = excluded.cert_pem,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`,
		k.keyID, k.hostName, k.certPEM, now, now)
}

// auditEvidenceGuard decides whether one incoming anti-entropy row of audit
// tamper-evidence must be refused, plus a short, bounded reason used as a metric
// label and in the warning. It can only ever REFUSE — see auditEvidenceIsImmutable.
type auditEvidenceGuard func(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (bool, string, error)

// auditEvidenceGuards are the anti-entropy floors under the three tables the
// audit verifier derives its conclusions from.
//
// Every row in them is an immutable signed assertion, so ordinary LWW
// convergence is not merely unnecessary — it is the attack. The clock on an
// incoming row is written by whoever sent it, so "newest wins" means "the
// compromised node wins", and anti-entropy would carry the rewrite to every
// peer.
//
// audit_signing_keys is deliberately absent. Its rows are certificates, which
// certFor re-validates against the cluster CA and re-derives the key id from on
// every use, so a swapped one is rejected where it is read rather than where it
// arrives — and the retirement that used to live on it, the part that genuinely
// needed protecting, is now its own signed table.
var auditEvidenceGuards = map[string]auditEvidenceGuard{
	"audit_log":             signedAuditRowIsImmutable,
	"audit_chain_heads":     auditEvidenceIsImmutable,
	"audit_key_retirements": auditEvidenceIsImmutable,
}

// signedAuditRowIsImmutable reports whether an incoming anti-entropy copy of an
// audit row must be refused because the LOCAL row is signed and differs.
//
// Deliberately NOT a signature check. Verifying here would mean crypto and a
// certificate lookup inside the merge transaction, and it would answer the
// wrong question anyway: whichever copy verifies, a signed row is immutable, so
// the local one is what this node has already published a chain head over.
// Keeping it and raising the divergence leaves both versions discoverable — the
// peer still holds its own — where silently taking one erases the other.
func signedAuditRowIsImmutable(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (bool, string, error) {
	if indexOf(table.Columns, "signature") < 0 {
		// A dump from a pre-v45 peer carries no signature column at all. It can
		// only be describing unsigned rows, so there is nothing to protect.
		return false, "", nil
	}
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return false, "", err
	}
	if cellStr(localRow, columnIndexMap(table.Columns), "signature") == "" {
		return false, "", nil // legacy row: keep converging as before
	}
	if encodeRowCells(localRow) != encodeRowCells(row) {
		return true, "signed_audit_row", nil
	}
	return false, "", nil
}

// auditEvidenceIsImmutable refuses an anti-entropy row that would change a
// published chain head or a signed retirement.
//
// Both are fixed assertions about a fixed key — a head about (host, epoch, seq),
// a retirement about (host, retired key). Neither has a later revision, so a
// differing body is corruption or forgery either way, and taking it would
// overwrite the copy that disagrees with whoever sent it.
//
// Note what this does NOT do. It does not refuse tombstones, and it does not
// repair anything. Both of those are handled by the shape of the data instead:
// the verifier ignores deleted_at on these tables, so a tombstone accomplishes
// nothing; and both tables are append-only, so a row deleted outright has no
// local copy to conflict with and is simply re-inserted from a peer. Trying to
// solve either here is what produced a force-apply path that could carry an
// arbitrary column rewrite past LWW.
func auditEvidenceIsImmutable(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (bool, string, error) {
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return false, "", err
	}
	if encodeRowCells(localRow) != encodeRowCells(row) {
		return true, "audit_evidence_rewrite", nil
	}
	return false, "", nil
}


// columnIndexMap builds the name→offset map cellStr needs.
func columnIndexMap(cols []string) map[string]int {
	idx := make(map[string]int, len(cols))
	for i, c := range cols {
		idx[c] = i
	}
	return idx
}

// SetAuditKeyring wires the signing/verifying identity onto this client. Nil
// means unsigned, which is the pre-v45 behaviour and the default.
func (c *Client) SetAuditKeyring(k *AuditKeyring) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.auditKeyring = k
}

// AuditKeyringOf returns the client's keyring (possibly nil).
func (c *Client) AuditKeyringOf() *AuditKeyring {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.auditKeyring
}

// SetAuditSignatureRequired wires the cluster-wide enforcement predicate:
// `enforcement.audit_signature && audit_signature_v1 latched`.
//
// Signing itself needs no latch — a signed row is readable by any node, and an
// older peer simply ignores the columns — so emission starts on the flag alone.
// What the latch gates is REFUSAL: once the whole cluster is signing, a node
// that cannot sign must fail the audit write rather than quietly append an
// unsigned row. Without that step the protection is trivially removable, since
// making the key unreadable would silently return the log to the state this
// whole change exists to fix.
func (c *Client) SetAuditSignatureRequired(fn func() bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.auditSignatureRequired = fn
}

func (c *Client) auditSignatureRequiredNow() bool {
	c.mu.RLock()
	fn := c.auditSignatureRequired
	c.mu.RUnlock()
	return fn != nil && fn()
}
