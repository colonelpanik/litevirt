package daemon

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// activationMarkerPrefix is the basename prefix of the durable per-token
// capability activation markers. It must match the base handed to
// Checker.SetActivationMarker, which appends "." + token to it.
const activationMarkerPrefix = "split_brain_activated"

// preflightCapabilityRollback reports the capability tokens this node has already
// latched that THIS BINARY has never heard of — that is, evidence that a newer
// binary ran here and this one is a rollback below it. An empty result means the
// node is clean.
//
// This is the only place in the codebase that reads the marker DIRECTORY instead
// of iterating the token list. Everywhere else does the opposite, and that
// asymmetry is the whole bug: Checker.SetActivationMarker loads markers by
// walking capabilities.All() and Stat'ing each expected path, so a binary
// predating token X has no "X" string to look for, never looks, and starts as if
// nothing were ever latched. There is no cluster-side record to fall back on
// either — capabilities are only ever carried in a live PingResponse and no
// schema column holds them.
//
// It deliberately does NOT key on schema version. A DB forward of the binary is
// explicitly tolerated (schema.go), because that tolerance is what keeps a schema
// bump reversible and a mixed-version rolling upgrade legal. Gating on it would
// break the upgrade path this is supposed to protect.
//
// Note the shape of the guarantee: this only fires on a rollback to a build that
// CONTAINS this check. It cannot retroactively catch a rollback to an already
// released binary. Shipping it is what makes the next rollback detectable, which
// is the OnFailure-auto-rollback path that motivated it.
func preflightCapabilityRollback(dataDir string) []string {
	if os.Getenv("LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK") == "1" {
		slog.Warn("preflight: capability-rollback detection disabled by " +
			"LITEVIRT_UNSAFE_SKIP_ROLLBACK_CHECK=1; this node will emit replicated writes " +
			"even if it is a rollback below a token it already latched")
		return nil
	}
	if dataDir == "" {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(dataDir, activationMarkerPrefix+".*"))
	if err != nil {
		// The only error Glob returns is a malformed pattern, which ours is not.
		// Log rather than fail: an unreadable data dir is its own problem and the
		// daemon will hit it again immediately.
		slog.Warn("preflight: could not scan capability activation markers", "error", err)
		return nil
	}
	known := make(map[string]bool, len(capabilities.All()))
	for _, tok := range capabilities.All() {
		known[tok] = true
	}
	var unknown []string
	for _, path := range matches {
		token := strings.TrimPrefix(filepath.Base(path), activationMarkerPrefix+".")
		if token == "" || known[token] {
			continue
		}
		unknown = append(unknown, token)
	}
	sort.Strings(unknown)
	return unknown
}
