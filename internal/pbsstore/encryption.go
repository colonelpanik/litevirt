package pbsstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// EncryptionMode names a supported chunk-cipher. Stored in repo.json
// so a downgraded binary can refuse a repo it can't decrypt.
const EncryptionModeAESGCM = "aes256gcm"

// ErrKeyMissing is returned when an encrypted repo is opened without a key.
var ErrKeyMissing = errors.New("encrypted repository requires a key")

// ErrKeyMismatch is returned when GCM authentication fails — typically
// because the wrong key is in use.
var ErrKeyMismatch = errors.New("chunk auth failed; key mismatch or tampering")

// SetKey configures the repo for AES-256-GCM. Call after Init/Open.
// The key must be exactly 32 bytes. Subsequent PutChunk / GetChunk
// calls transparently encrypt / decrypt.
//
// Note: this does NOT change the on-disk repo.json — that's
// EncryptionMode metadata which Init/Open is responsible for. SetKey
// simply attaches the key in-memory to an already-encrypted repo.
func (r *Repo) SetKey(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes (got %d)", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm: %w", err)
	}
	r.aead = gcm
	return nil
}

// InitEncrypted is like Init but stamps the repo as encrypted in
// repo.json. Callers must SetKey before any chunk operation.
func InitEncrypted(root, mode string) (*Repo, error) {
	if mode != EncryptionModeAESGCM {
		return nil, fmt.Errorf("unsupported encryption mode %q", mode)
	}
	r, err := Init(root)
	if err != nil {
		return nil, err
	}
	r.meta.Encryption = mode
	if err := writeJSONAtomic(metaPath(root), r.meta); err != nil {
		return nil, err
	}
	return r, nil
}

func metaPath(root string) string { return root + "/repo.json" }

// IsEncrypted reports whether the repo is configured for encryption.
func (r *Repo) IsEncrypted() bool {
	return r.meta.Encryption != ""
}

// encryptForStorage seals plaintext for writing to chunks/<id>. The
// on-disk format is nonce(12) || ciphertext+tag.
//
// Fail closed: a repo marked encrypted in repo.json but opened WITHOUT a key must
// never write plaintext — that would silently corrupt the repo (its metadata says
// encrypted, so a later reader with the real key fails GCM auth). Return
// ErrKeyMissing instead.
func (r *Repo) encryptForStorage(plaintext []byte) ([]byte, error) {
	if r.aead == nil {
		if r.IsEncrypted() {
			return nil, ErrKeyMissing
		}
		return plaintext, nil
	}
	nonce := make([]byte, r.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	out := make([]byte, len(nonce), len(nonce)+len(plaintext)+r.aead.Overhead())
	copy(out, nonce)
	out = r.aead.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// decryptFromStorage reverses encryptForStorage. Fail closed when the repo is
// encrypted but no key is attached (otherwise it would hand back raw stored bytes
// as if they were plaintext).
func (r *Repo) decryptFromStorage(blob []byte) ([]byte, error) {
	if r.aead == nil {
		if r.IsEncrypted() {
			return nil, ErrKeyMissing
		}
		return blob, nil
	}
	if len(blob) < r.aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short for nonce")
	}
	nonce := blob[:r.aead.NonceSize()]
	ct := blob[r.aead.NonceSize():]
	pt, err := r.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyMismatch, err)
	}
	return pt, nil
}
