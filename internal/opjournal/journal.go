// Package opjournal is the HOST-LOCAL tier of the F1 operation journal: durable
// records of artifacts that only the ORIGINATING host can restore or clean up
// (old domain XML, prior driver bindings), which therefore do not belong in the
// replicated operations/operation_steps tables. An entry is written durably
// (atomic temp-write → fsync file AND directory → rename) BEFORE the external
// mutation it protects, so a crash after any stage recovers; a corrupt entry is
// reported, never silently discarded, so the daemon can fail closed.
package opjournal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	entryVersion  = 1
	maxEntryBytes = 1 << 20 // 1 MiB per operation entry — artifacts are small (XML/bindings)
	dirPerm       = 0o700
	filePerm      = 0o600
)

// ErrCorrupt is returned when an entry fails its checksum or won't parse. The
// caller marks the host degraded and blocks affected mutations rather than
// proceeding on unknown recovery state.
var ErrCorrupt = errors.New("opjournal: corrupt entry")

// Entry records the host-local artifacts for one operation. It is keyed by the
// operation id and carries the owner epoch + spec generation so a returning old
// owner cleans up ONLY when they still match (see Matches); otherwise the entry
// is superseded and archived, never blindly rolled back.
type Entry struct {
	Version        int               `json:"version"`
	OperationID    string            `json:"operation_id"`
	OwnerEpoch     int64             `json:"owner_epoch"`
	SpecGeneration int64             `json:"spec_generation"`
	ResourceID     string            `json:"resource_id"`
	Kind           string            `json:"kind"`
	Stage          string            `json:"stage"`
	Artifacts      map[string]string `json:"artifacts"` // e.g. "old_domain_xml", "prior_driver:<addr>"
	CreatedAt      string            `json:"created_at"`
	Checksum       string            `json:"checksum"`
}

// Matches reports whether this entry still describes the given operation
// identity — the precondition for the original host to clean up its artifacts.
func (e Entry) Matches(operationID string, ownerEpoch, specGeneration int64) bool {
	return e.OperationID == operationID && e.OwnerEpoch == ownerEpoch && e.SpecGeneration == specGeneration
}

func (e Entry) checksum() string {
	c := e
	c.Checksum = ""
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Journal is a directory of per-operation host-local entries.
type Journal struct {
	dir string
	mu  sync.Mutex

	// Test-only failure injection. When set, Write/Remove consult it FIRST and return
	// its error (nil ⇒ proceed), so a test can exercise a durable-record failure without
	// a real I/O fault. Production never sets these (mirrors seams like vfio.SetFS).
	FailWrite  func(opID string) error
	FailRemove func(opID string) error
}

// Open creates (0700) and returns a journal rooted at dir.
func Open(dir string) (*Journal, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("opjournal: mkdir %s: %w", dir, err)
	}
	return &Journal{dir: dir}, nil
}

// sanitize keeps a filename to a safe charset (operation ids are hex hashes, but
// be defensive against a path separator ever reaching here).
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
}

func (j *Journal) path(opID string) string { return filepath.Join(j.dir, sanitize(opID)+".json") }

// Write durably records e (atomic temp-write → fsync file → rename → fsync dir).
// It is fail-closed: any I/O error is returned so the caller does NOT begin the
// external mutation the entry was meant to protect.
func (j *Journal) Write(e Entry) error {
	if j.FailWrite != nil {
		if err := j.FailWrite(e.OperationID); err != nil {
			return err
		}
	}
	e.Version = entryVersion
	e.Checksum = e.checksum()
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("opjournal: marshal: %w", err)
	}
	if len(b) > maxEntryBytes {
		return fmt.Errorf("opjournal: entry %s too large (%d > %d bytes)", e.OperationID, len(b), maxEntryBytes)
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	final := j.path(e.OperationID)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return fmt.Errorf("opjournal: open temp: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("opjournal: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("opjournal: fsync file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("opjournal: close temp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("opjournal: rename: %w", err)
	}
	return j.syncDir()
}

func (j *Journal) syncDir() error {
	d, err := os.Open(j.dir)
	if err != nil {
		return fmt.Errorf("opjournal: open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("opjournal: fsync dir: %w", err)
	}
	return nil
}

// Read returns the entry for opID. found=false with no error means "no entry".
// A checksum/parse failure returns ErrCorrupt (the entry is not silently
// dropped) so the caller can fail closed.
func (j *Journal) Read(opID string) (e *Entry, found bool, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return readFile(j.path(opID))
}

func readFile(path string) (*Entry, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, true, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if e.checksum() != e.Checksum {
		return &e, true, ErrCorrupt
	}
	return &e, true, nil
}

// Remove deletes opID's entry (used after the operation completes or is
// superseded). A missing entry is not an error.
func (j *Journal) Remove(opID string) error {
	if j.FailRemove != nil {
		if err := j.FailRemove(opID); err != nil {
			return err
		}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := os.Remove(j.path(opID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return j.syncDir()
}

// List returns all valid entries (sorted by operation id) plus the filenames of
// any corrupt entries — the startup-recovery caller reduces the valid ones and
// marks the host degraded if any are corrupt.
func (j *Journal) List() (entries []Entry, corrupt []string, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	des, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, nil, err
	}
	for _, de := range des {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		e, _, rerr := readFile(filepath.Join(j.dir, de.Name()))
		if rerr != nil {
			corrupt = append(corrupt, de.Name())
			continue
		}
		if e != nil {
			entries = append(entries, *e)
		}
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].OperationID < entries[b].OperationID })
	return entries, corrupt, nil
}
