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
const auditHeadDomain = "litevirt-audit-head-v1"

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
	k, err := loadAuditRoots(pkiDir)
	if err != nil {
		return nil, err
	}
	certPath, keyPath := auditSigningPaths(pkiDir)
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
func auditHeadDigest(hostName string, epoch, seq int64, headHash, keyID string) []byte {
	h := sha256.New()
	writeField(h, auditHeadDomain)
	writeField(h, hostName)
	writeField(h, strconv.FormatInt(epoch, 10))
	writeField(h, strconv.FormatInt(seq, 10))
	writeField(h, headHash)
	writeField(h, keyID)
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
func (k *AuditKeyring) SignHead(hostName string, epoch, seq int64, headHash string) (string, error) {
	if !k.CanSign() {
		return "", nil
	}
	return k.sign(auditHeadDigest(hostName, epoch, seq, headHash, k.keyID))
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

// VerifyHead checks a chain head's signature.
func (k *AuditKeyring) VerifyHead(ctx context.Context, c *Client, hostName string, epoch, seq int64, headHash, keyID, sigHex string) error {
	return k.verifySig(ctx, c, hostName, keyID, sigHex, func(id string) []byte {
		return auditHeadDigest(hostName, epoch, seq, headHash, id)
	})
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
	rows, err := c.Query(ctx,
		`SELECT cert_pem FROM audit_signing_keys WHERE key_id = ? AND deleted_at IS NULL`, keyID)
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

// auditEvidenceDecision is what the merge does with one incoming row of audit
// tamper-evidence.
type auditEvidenceDecision int

const (
	// auditEvidencePassThrough: nothing special about this row; let the normal
	// identity/LWW handling below decide.
	auditEvidencePassThrough auditEvidenceDecision = iota
	// auditEvidenceKeepLocal: the incoming row would destroy evidence. Refuse it
	// whatever clock it carries.
	auditEvidenceKeepLocal
	// auditEvidenceHeal: the LOCAL row is the damaged one and the incoming copy
	// is intact. Apply it, bypassing LWW.
	//
	// Refusing damage must not mean freezing it. Whoever tombstoned a head or a
	// certificate wrote the clock on their own row too, so under LWW the damaged
	// node would keep its own copy forever and never recover from a peer that
	// still holds the real one — the guard would have converted a spreading
	// problem into a permanent local one.
	auditEvidenceHeal
)

// auditEvidenceGuard decides what to do with one incoming anti-entropy row of
// audit tamper-evidence, plus a short, bounded reason used as a metric label and
// in the warning.
type auditEvidenceGuard func(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (auditEvidenceDecision, string, error)

// auditEvidenceGuards are the anti-entropy floors under the three tables the
// audit verifier derives its conclusions from.
//
// Everything in these tables is either an immutable signed assertion or a
// monotone marker, so ordinary LWW convergence is not merely unnecessary — it is
// the attack. The clock on an incoming row is written by whoever sent it, so
// "newest wins" means "the compromised node wins", and anti-entropy would then
// carry the erasure to every peer. These guards make the losing move
// unavailable regardless of clock.
var auditEvidenceGuards = map[string]auditEvidenceGuard{
	"audit_log":          signedAuditRowIsImmutable,
	"audit_chain_heads":  auditChainHeadIsImmutable,
	"audit_signing_keys": auditSigningKeyIsMonotone,
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
func signedAuditRowIsImmutable(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (auditEvidenceDecision, string, error) {
	if indexOf(table.Columns, "signature") < 0 {
		// A dump from a pre-v45 peer carries no signature column at all. It can
		// only be describing unsigned rows, so there is nothing to protect.
		return auditEvidencePassThrough, "", nil
	}
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return auditEvidencePassThrough, "", err
	}
	if cellStr(localRow, columnIndexMap(table.Columns), "signature") == "" {
		return auditEvidencePassThrough, "", nil // legacy row: keep converging as before
	}
	if encodeRowCells(localRow) != encodeRowCells(row) {
		return auditEvidenceKeepLocal, "signed_audit_row", nil
	}
	return auditEvidencePassThrough, "", nil
}

// auditChainHeadIsImmutable refuses any anti-entropy row that would change or
// remove a published chain head.
//
// A head is a signed statement about a fixed (host, epoch, seq). There is no
// such thing as a later revision of one, so a differing body for the same key is
// corruption or forgery either way — and a head is the ONLY construct that can
// detect a truncated tail, which makes deleting one the cheapest way to disable
// truncation detection cluster-wide. The table is documented append-only and the
// statement lane enforces that, but anti-entropy ships whole rows including
// deleted_at, so the same rule has to exist here.
func auditChainHeadIsImmutable(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (auditEvidenceDecision, string, error) {
	idx := columnIndexMap(table.Columns)
	// Refused whether or not this node already holds the head. Accepting a
	// tombstone for an unseen key would pre-poison the slot, so the genuine head
	// could never land afterwards — a truncation hidden before it happened.
	if cellStr(row, idx, "deleted_at") != "" {
		return auditEvidenceKeepLocal, "audit_head_tombstone", nil
	}
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return auditEvidencePassThrough, "", err
	}
	// The incoming copy is live, so a local tombstone is the damaged side and a
	// peer is offering the repair. Take it: nothing legitimately deletes a head,
	// and under LWW the node that tombstoned its own would keep that clock
	// forever.
	if cellStr(localRow, idx, "deleted_at") != "" {
		return auditEvidenceHeal, "audit_head_untombstone", nil
	}
	if encodeRowCells(localRow) != encodeRowCells(row) {
		return auditEvidenceKeepLocal, "audit_head_rewrite", nil
	}
	return auditEvidencePassThrough, "", nil
}

// auditSigningKeyIsMonotone keeps a key's retirement from being walked back.
//
// Retirement is the record that says "this key is loose; anything it signs past
// sequence N is somebody else". Clearing retired_at, or moving retired_at_seq
// forward, retroactively authorises exactly the rows the local copy already
// flagged — and under plain LWW that edit replicates from the compromised node
// to every peer, taking the finding with it. Deleting the row is worse still:
// the certificate must stay resolvable for as long as any row it signed exists,
// so a tombstone does not hide those rows, it makes them unverifiable, which
// reads as mass tampering rather than as the erasure it is.
func auditSigningKeyIsMonotone(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (auditEvidenceDecision, string, error) {
	idx := columnIndexMap(table.Columns)
	if cellStr(row, idx, "deleted_at") != "" {
		return auditEvidenceKeepLocal, "audit_key_tombstone", nil
	}
	if indexOf(table.Columns, "retired_at") < 0 {
		return auditEvidencePassThrough, "", nil // pre-v46 dump: no retirement to weaken
	}
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return auditEvidencePassThrough, "", err
	}
	// Retirement is monotone in BOTH directions of the merge, and it has to be.
	// Refusing a weakening only makes the local copy sticky; the node that
	// cleared its own retired_at wrote the clock on that row too, so under LWW it
	// would keep the un-retired version forever and go on accepting the leaked
	// key's signatures while every peer reported them. Strictly-more-retired
	// therefore WINS regardless of clock, in whichever direction it arrives. The
	// EARLIER boundary is the strict one, so a later one is a weakening even
	// though both rows look retired.
	localRetired, incomingRetired := cellStr(localRow, idx, "retired_at"), cellStr(row, idx, "retired_at")
	switch {
	case localRetired != "" && incomingRetired == "":
		return auditEvidenceKeepLocal, "audit_key_unretire", nil
	case localRetired == "" && incomingRetired != "":
		return auditEvidenceHeal, "audit_key_retirement_learned", nil
	case localRetired != "" && incomingRetired != "":
		switch li, ri := cellInt64(localRow, idx, "retired_at_seq"), cellInt64(row, idx, "retired_at_seq"); {
		case ri > li:
			return auditEvidenceKeepLocal, "audit_key_boundary_raised", nil
		case ri < li:
			return auditEvidenceHeal, "audit_key_boundary_tightened", nil
		}
	}
	// The incoming copy is live and does not weaken anything. If the LOCAL row is
	// tombstoned, this is the repair for a certificate somebody deleted — without
	// which every row that key signed stays unverifiable on this node forever.
	if cellStr(localRow, idx, "deleted_at") != "" {
		return auditEvidenceHeal, "audit_key_untombstone", nil
	}
	return auditEvidencePassThrough, "", nil
}

// cellInt64 reads a numeric cell. A dump round-trips through JSON, so the same
// column arrives as float64 from a peer and int64 from SQLite; both render
// through coerceString and parse back the same way.
func cellInt64(row []interface{}, idx map[string]int, col string) int64 {
	f, err := strconv.ParseFloat(cellStr(row, idx, col), 64)
	if err != nil {
		return 0
	}
	return int64(f)
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
