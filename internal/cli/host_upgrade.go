package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/tabwriter"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// binaryVersion runs `<path> --version` and returns the stamped version (the
// token after "version=" in the output), or "" if the binary can't be probed
// (e.g. a cross-arch binary that won't exec locally). Used so the upgrade
// "outdated" check compares each host to the version we're about to deploy —
// not to the connected daemon's running version, which would no-op on a
// version-uniform cluster.
func binaryVersion(ctx context.Context, path string) string {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, path, "--version").Output()
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(string(out)) {
		if v, ok := strings.CutPrefix(f, "version="); ok {
			return v
		}
	}
	return ""
}

// UpgradeOpts configures a rolling host upgrade.
type UpgradeOpts struct {
	BinaryPath string   // path to new litevirtd binary
	HostNames  []string // empty = all outdated hosts
	Yes        bool     // skip confirmation prompt
	Force      bool     // skip preflight blocks (warnings still printed)
	NoPreStage bool     // skip the cluster-wide schema pre-stage pass
}

// hostResult tracks the outcome of upgrading a single host.
type hostResult struct {
	Name       string
	Address    string
	OldVersion string
	NewVersion string
	Status     string // "ok", "skipped", "error"
	Error      string
}

// HostUpgrade performs a rolling upgrade of litevirtd across cluster hosts.
//
// The binary at opts.BinaryPath (local to the machine running `lv`) is pushed
// to every target host via SSH. This works whether `lv` runs on a dev laptop
// (remote mode via LV_HOST) or directly on a cluster node (local mode).
//
// When running in local mode the connected host is upgraded last, because
// restarting its daemon kills our gRPC connection. The SSH session for the
// self-upgrade still completes — only the post-upgrade gRPC Ping check is
// skipped (systemctl verification is sufficient).
func HostUpgrade(ctx context.Context, client pb.LiteVirtClient, opts UpgradeOpts) error {
	// Verify the binary exists and is executable.
	info, err := os.Stat(opts.BinaryPath)
	if err != nil {
		return fmt.Errorf("binary not found: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a binary", opts.BinaryPath)
	}

	// Identify the host we're connected to (so we can upgrade it last).
	pingResp, _ := client.Ping(ctx, &pb.PingRequest{})
	connectedHost := ""
	if pingResp != nil {
		connectedHost = pingResp.HostName
	}

	// The target is the version of the binary we're distributing — probe it
	// directly. Using the connected daemon's running version instead would
	// make no-arg `lv host upgrade --binary X` a no-op on a version-uniform
	// cluster (every host matches the connected daemon, so nothing looks
	// "outdated", even though X is newer). Fall back to the connected daemon's
	// version only if the binary can't be probed (e.g. cross-arch).
	targetVersion := binaryVersion(ctx, opts.BinaryPath)
	if targetVersion == "" && pingResp != nil {
		targetVersion = pingResp.Version
	}

	// List all hosts.
	resp, err := client.ListHosts(ctx, nil)
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	if len(resp.Hosts) == 0 {
		fmt.Println("No hosts in cluster.")
		return nil
	}

	// Filter to hosts that need upgrading.
	filterSet := make(map[string]bool)
	for _, n := range opts.HostNames {
		filterSet[n] = true
	}
	named := len(filterSet) > 0

	var remoteTargets []*pb.Host // other hosts — upgraded first
	var selfTarget *pb.Host      // the connected host — upgraded last

	for _, h := range resp.Hosts {
		if named && !filterSet[h.Name] {
			continue
		}
		// In "all" mode, skip hosts already on the target (the --binary's)
		// version. An explicitly-named host is ALWAYS (re)deployed: the
		// operator asked for it (e.g. re-seeding the same version after a
		// manual change), so a version match must not silently skip it — that
		// no-op once forced the unsafe bare-restart workaround. See
		// docs/upgrades.md.
		if !named && targetVersion != "" && h.Version == targetVersion {
			continue
		}
		if h.Name == connectedHost {
			selfTarget = h
		} else {
			remoteTargets = append(remoteTargets, h)
		}
	}

	// Build ordered list: remote hosts first, connected host last.
	targets := remoteTargets
	if selfTarget != nil {
		targets = append(targets, selfTarget)
	}

	if len(targets) == 0 {
		fmt.Println("All hosts are up-to-date.")
		return nil
	}

	// Print upgrade plan.
	fmt.Printf("Upgrade plan: %d host(s) → %s\n\n", len(targets), versionLabel(targetVersion))
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "  HOST\tADDRESS\tCURRENT\tNOTE\n")
	for _, h := range targets {
		note := ""
		if h.Name == connectedHost {
			note = "(connected — upgraded last)"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", h.Name, h.Address, versionLabel(h.Version), note)
	}
	tw.Flush()
	fmt.Println()

	// Confirm unless --yes.
	if !opts.Yes {
		fmt.Print("Proceed? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Phase 1 — pre-stage schema on every target BEFORE swapping any binary.
	// This streams the new binary to each host and runs its `schema-migrate`
	// against the live state.db (safe: WAL + busy-timeout, idempotent). After
	// this pass every node's DB has the new schema, so the rolling restart in
	// phase 2 never produces a peer that's missing columns — which is the only
	// thing that makes a multi-version rolling upgrade unsafe. Older daemons
	// without the PreStageUpgrade RPC report Unimplemented and are skipped (they
	// migrate themselves on restart; single-version skew self-heals).
	if !opts.NoPreStage {
		if err := preStageSchema(ctx, client, targets, opts.BinaryPath, opts.Force); err != nil {
			return err
		}
	}

	// Phase 2 — upgrade each host sequentially (swap + re-exec).
	results := make([]hostResult, 0, len(targets))
	for i, h := range targets {
		isSelf := h.Name == connectedHost
		label := ""
		if isSelf {
			label = " (self)"
		}
		fmt.Printf("[%d/%d] Upgrading %s (%s)%s...\n", i+1, len(targets), h.Name, h.Address, label)
		res := upgradeOneHost(ctx, client, h, opts.BinaryPath, targetVersion, opts.Force)
		results = append(results, res)
		if res.Status == "ok" {
			fmt.Printf("  done: %s upgraded to %s\n", h.Name, versionLabel(res.NewVersion))
		} else {
			fmt.Fprintf(os.Stderr, "  FAILED: %s: %s\n", h.Name, res.Error)
		}
	}

	// Print summary.
	fmt.Println("\n--- Upgrade Summary ---")
	tw = tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "HOST\tOLD\tNEW\tSTATUS\n")
	for _, r := range results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			r.Name, versionLabel(r.OldVersion), versionLabel(r.NewVersion), r.Status)
	}
	tw.Flush()

	// Check for failures.
	var failures int
	for _, r := range results {
		if r.Status == "error" {
			failures++
		}
	}
	if failures > 0 {
		return fmt.Errorf("%d host(s) failed to upgrade", failures)
	}
	return nil
}

func upgradeOneHost(ctx context.Context, client pb.LiteVirtClient, h *pb.Host, binaryPath, targetVersion string, force bool) hostResult {
	res := hostResult{
		Name:       h.Name,
		Address:    h.Address,
		OldVersion: h.Version,
	}

	// Read binary and compute checksum.
	fmt.Printf("  streaming binary via gRPC...\n")
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		res.Status = "error"
		res.Error = fmt.Sprintf("read binary: %v", err)
		return res
	}
	checksum := sha256sum(data)

	stream, err := client.UpgradeHost(ctx)
	if err != nil {
		res.Status = "error"
		res.Error = fmt.Sprintf("open upgrade stream: %v", err)
		return res
	}

	// Send first chunk with metadata.
	const chunkSize = 64 * 1024
	first := &pb.UpgradeHostRequest{
		Checksum:   checksum,
		TargetHost: h.Name,
		Force:      force, // server-side preflight blocks are only skippable when this is set
	}
	if len(data) > chunkSize {
		first.Chunk = data[:chunkSize]
		data = data[chunkSize:]
	} else {
		first.Chunk = data
		data = nil
	}
	if err := stream.Send(first); err != nil {
		res.Status = "error"
		res.Error = upgradeErrorHint(fmt.Sprintf("send first chunk: %v", err))
		return res
	}

	// Send remaining chunks.
	for len(data) > 0 {
		end := chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := stream.Send(&pb.UpgradeHostRequest{Chunk: data[:end]}); err != nil {
			res.Status = "error"
			res.Error = upgradeErrorHint(fmt.Sprintf("send chunk: %v", err))
			return res
		}
		data = data[end:]
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		res.Status = "error"
		res.Error = upgradeErrorHint(fmt.Sprintf("upgrade failed: %v", err))
		return res
	}

	res.Status = resp.Status
	res.NewVersion = resp.NewVersion
	if resp.Error != "" {
		res.Error = resp.Error
	}
	if res.NewVersion == "" {
		res.NewVersion = targetVersion
	}
	return res
}

// upgradeErrorHint appends a hint when the error looks like the remote daemon
// doesn't support the UpgradeHost RPC (e.g. first upgrade from an older build).
func upgradeErrorHint(msg string) string {
	if strings.Contains(msg, "EOF") || strings.Contains(msg, "Unimplemented") {
		return msg + " (host may be running an older daemon without gRPC upgrade support — deploy the new binary manually with scp + systemctl restart)"
	}
	return msg
}

func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func versionLabel(v string) string {
	if v == "" {
		return "(unknown)"
	}
	return v
}
