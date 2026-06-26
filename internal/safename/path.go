package safename

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SafeJoin joins root with the given path parts and guarantees the result stays
// within root. It rejects any combination (absolute parts, ".." traversal) that
// would escape, and returns the cleaned path. This generalizes the per-package
// withinDir/safeJoin helpers (internal/grpcapi/vmimport.go, internal/vmimport).
func SafeJoin(root string, parts ...string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("safejoin: empty root")
	}
	rootClean := filepath.Clean(root)
	joined := filepath.Clean(filepath.Join(append([]string{rootClean}, parts...)...))
	if !Contains(rootClean, joined) {
		return "", fmt.Errorf("safejoin: %q escapes %q", filepath.Join(parts...), root)
	}
	return joined, nil
}

// Contains reports whether path is within dir (or is dir itself). Both are
// cleaned first. It is a pure path check — it does not resolve symlinks, so a
// caller that must defend against a symlinked component should also lstat.
func Contains(dir, path string) bool {
	dirClean := filepath.Clean(dir)
	rel, err := filepath.Rel(dirClean, filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}
