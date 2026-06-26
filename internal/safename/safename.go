// Package safename provides input validation and filesystem-containment helpers
// shared across litevirt's gRPC handlers, libvirt layer, image store, and
// pbsstore. It is zero-dependency (stdlib only) so any package can import it
// without risking an import cycle.
//
// The guiding principle: put each guard at the lowest reusable layer. A name
// that lands in a filesystem path is validated here; a path is joined under a
// root here; an untrusted archive is extracted here. Callers then can't
// reintroduce a traversal by hand-rolling string concatenation.
package safename

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// maxNameLen caps a single name component. Long enough for any real VM/disk/
// image/snapshot/container/pool/stack name, short enough to keep paths sane.
const maxNameLen = 200

// nameRe is the safe charset for a single name component. Slashes are excluded
// by the charset; "." and ".." pass the charset but are rejected separately
// because they traverse. This matches the historical safeNameRe in
// internal/grpcapi/backup.go, which this package consolidates.
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// ValidateName is the base check: a non-empty, non-traversing, safe-charset
// name no longer than maxNameLen. Every typed wrapper delegates here.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("name must not be empty")
	}
	if len(name) > maxNameLen {
		return fmt.Errorf("name %q too long (max %d chars)", name, maxNameLen)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("name %q is a path traversal", name)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("name %q contains disallowed characters (allowed: letters, digits, '_', '.', '-')", name)
	}
	return nil
}

// Typed wrappers — same rule, caller-readable errors, and a single place to
// tighten a specific kind later if it ever needs to diverge.
func ValidateVMName(s string) error        { return wrapName("vm", s) }
func ValidateDiskName(s string) error      { return wrapName("disk", s) }
func ValidateImageName(s string) error     { return wrapName("image", s) }
func ValidateSnapshotName(s string) error  { return wrapName("snapshot", s) }
func ValidateContainerName(s string) error { return wrapName("container", s) }
func ValidatePoolName(s string) error      { return wrapName("pool", s) }
func ValidateStackName(s string) error     { return wrapName("stack", s) }

func wrapName(kind, s string) error {
	if err := ValidateName(s); err != nil {
		return fmt.Errorf("invalid %s name: %w", kind, err)
	}
	return nil
}

// CanonicalProjectName validates a (possibly hierarchical) project name and
// returns its canonical stored form: a single leading slash followed by
// slash-separated safe segments. "acme/team" and "/acme/team" both canonicalize
// to "/acme/team"; an empty input canonicalizes to "/" (callers normalize "" to
// the default project before this where it matters).
//
// Projects are hierarchical (parent_name in the data model), so unlike a flat
// name the input is split on "/" and each segment validated. The segment
// charset stays [A-Za-z0-9_.-]+ (uppercase allowed) on purpose: released code
// accepted arbitrary project names and docs/tests use both leading-slash and
// bare forms, so narrowing to lowercase-only would orphan existing projects.
func CanonicalProjectName(in string) (string, error) {
	trimmed := strings.Trim(in, "/")
	if trimmed == "" {
		return "/", nil
	}
	segs := strings.Split(trimmed, "/")
	for _, seg := range segs {
		if seg == "" {
			return "", fmt.Errorf("project %q has an empty path segment", in)
		}
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("project %q has a traversal segment %q", in, seg)
		}
		if len(seg) > maxNameLen || !nameRe.MatchString(seg) {
			return "", fmt.Errorf("project %q has an invalid segment %q", in, seg)
		}
	}
	return "/" + strings.Join(segs, "/"), nil
}

// ProjectRBACPath maps a canonical project name (from CanonicalProjectName) to
// its RBAC path root: "/acme/team" -> "/projects/acme/team", "/" -> "/projects".
// Building RBAC paths only through this avoids the "acme" vs "/acme" mismatch
// and double-slash bugs that ad-hoc string concatenation produced.
func ProjectRBACPath(canonical string) string {
	if canonical == "" || canonical == "/" {
		return "/projects"
	}
	return "/projects" + canonical
}

// chunkIDRe matches a pbsstore chunk ID: 64 lowercase hex chars, the
// hex-encoded BLAKE3-256 of the chunk plaintext (internal/pbsstore/chunkstore.go).
var chunkIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidateChunkID checks a content-addressed chunk ID so a tampered manifest
// can't drive a chunk path outside the repo's chunk store.
func ValidateChunkID(id string) error {
	if !chunkIDRe.MatchString(id) {
		return fmt.Errorf("invalid chunk id %q (want 64 lowercase hex chars)", id)
	}
	return nil
}

// ValidateTimestamp checks that a backup timestamp is strict RFC3339 (the format
// pbsstore writes). This matters because filenameSafeTS only strips ':', so a
// '/'-bearing timestamp would still escape a manifest filename.
func ValidateTimestamp(ts string) error {
	if ts == "" {
		return errors.New("timestamp must not be empty")
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return fmt.Errorf("invalid timestamp %q (want RFC3339): %w", ts, err)
	}
	return nil
}
