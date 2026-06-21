package firewall

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// NftRunner is the shell-out boundary so tests can drive applier
// without a real `nft` binary. Production wires NftBinary{}.
type NftRunner interface {
	// Apply replaces the litevirt-fw table atomically by piping ruleset
	// through `nft -f -`. ruleset is the full Render() output.
	Apply(ctx context.Context, ruleset string) (string, error)
	// Flush deletes the litevirt-fw table — used on uninstall and as
	// a clean-slate before the first apply.
	Flush(ctx context.Context) (string, error)
}

// NftBinary is the production NftRunner. Calls /sbin/nft (or whatever's
// on PATH) and pipes the rendered ruleset on stdin.
type NftBinary struct {
	// Bin overrides the binary path; empty = "nft" on PATH.
	Bin string
}

func (n NftBinary) bin() string {
	if n.Bin != "" {
		return n.Bin
	}
	return "nft"
}

// Apply runs `nft -f -` with ruleset on stdin. A `table inet litevirt-fw {…}`
// block alone does NOT replace an existing table — nft MERGES it, so every
// re-apply would append the forward chain's rules again (rule duplication).
// To get a true atomic replace we prepend the standard idiom:
//
//	table inet litevirt-fw {}      # ensure it exists (no-op if already present)
//	delete table inet litevirt-fw  # remove it (safe now that it exists)
//	<ruleset>                      # recreate it fresh
//
// nft -f processes the whole input as ONE transaction, so the delete+recreate
// is atomic — traffic never sees a half-applied or empty table.
func (n NftBinary) Apply(ctx context.Context, ruleset string) (string, error) {
	preamble := fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", TableName, TableName)
	cmd := exec.CommandContext(ctx, n.bin(), "-f", "-")
	cmd.Stdin = strings.NewReader(preamble + ruleset)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Flush drops the entire table — operators only need this on
// uninstall (the typical path is Apply with an empty Plan).
func (n NftBinary) Flush(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, n.bin(), "delete", "table", "inet", TableName)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Applier serialises Apply calls and short-circuits when the rendered
// ruleset hasn't changed. Intended to be a long-lived process-wide
// instance — daemon construction wires it once.
type Applier struct {
	runner NftRunner

	mu       sync.Mutex
	lastSent string
}

// NewApplier wraps an NftRunner with the change-detection cache.
func NewApplier(runner NftRunner) *Applier {
	if runner == nil {
		runner = NftBinary{}
	}
	return &Applier{runner: runner}
}

// Apply renders and applies p. Returns (changed, error). When changed
// is false, the daemon can skip log/event emission. Apply is goroutine-
// safe; concurrent callers serialise on a per-Applier mutex so two
// reconcilers don't fight.
func (a *Applier) Apply(ctx context.Context, p Plan) (bool, error) {
	rs, err := Render(p)
	if err != nil {
		return false, fmt.Errorf("render: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if rs == a.lastSent {
		return false, nil
	}
	if out, err := a.runner.Apply(ctx, rs); err != nil {
		return false, fmt.Errorf("nft apply: %w: %s", err, strings.TrimSpace(out))
	}
	a.lastSent = rs
	return true, nil
}

// LastApplied returns the most recent ruleset bytes the applier
// successfully sent. Useful for `lv firewall show` — the operator
// sees exactly what's loaded into the kernel right now.
func (a *Applier) LastApplied() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastSent
}

// Reset clears the last-sent cache so the next Apply will re-send even
// if the bytes are identical. Use after a kernel reset / nft flush
// happened out-of-band.
func (a *Applier) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastSent = ""
}
