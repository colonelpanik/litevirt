package network

import (
	"fmt"
	"strings"
)

// NAT, SNAT, and host-isolation nftables rules are no longer applied here. They
// are recorded as per-host intent (corrosion.host_fw_intent) by provisioning and
// the LB path, and rendered by the single canonical nftables reconciler
// (internal/firewall) into the atomic `inet litevirt-fw` table.
//
// The Remove* helpers below remain: they tear down the OLD out-of-band rules —
// the `inet litevirt` iso-/snat- chains and the iptables masquerade — on
// deprovision, and drive the one-time upgrade migration that clears a prior
// binary's rules once the consolidated ruleset is live (RemoveLegacyBridgeFirewall).

// isolationChainName returns the (legacy) nftables chain name for a bridge's
// host-isolation rules.
func isolationChainName(bridge string) string {
	return fmt.Sprintf("iso-%s", bridge)
}

// snatChainName returns the (legacy) nftables chain name for a bridge's SNAT rules.
func snatChainName(bridge string) string {
	return fmt.Sprintf("snat-%s", bridge)
}

// EnableIPForwarding turns on IPv4 forwarding, needed for both masquerade and
// SNAT. Formerly a side effect of EnsureNAT/EnsureSNAT; now called explicitly
// where NAT/SNAT intent is recorded.
func EnableIPForwarding() error {
	if out, err := execCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable ip forwarding: %w: %s", err, out)
	}
	return nil
}

// RemoveHostIsolation removes the legacy host-isolation nftables chain for a
// bridge from the `inet litevirt` table. Idempotent: ignores errors if the chain
// does not exist.
func RemoveHostIsolation(bridge string) error {
	chain := isolationChainName(bridge)

	// Flush before delete (nft requires empty chain to delete).
	execCommand("nft", "flush", "chain", "inet", "litevirt", chain) //nolint:errcheck

	if out, err := execCommand("nft", "delete", "chain", "inet", "litevirt", chain); err != nil {
		s := string(out)
		// Ignore "No such" / "does not exist" errors.
		if !isAlreadyExists(out) && !isFileExists(out) &&
			!strings.Contains(s, "No such") && !strings.Contains(s, "does not exist") {
			return fmt.Errorf("nft delete chain %s: %w: %s", chain, err, out)
		}
	}
	return nil
}

// RemoveSNAT removes the legacy SNAT nftables chain for a bridge from the
// `inet litevirt` table. Idempotent: ignores errors if the chain does not exist.
func RemoveSNAT(bridge string) error {
	chain := snatChainName(bridge)

	execCommand("nft", "flush", "chain", "inet", "litevirt", chain) //nolint:errcheck

	if out, err := execCommand("nft", "delete", "chain", "inet", "litevirt", chain); err != nil {
		s := string(out)
		if !isAlreadyExists(out) && !isFileExists(out) &&
			!strings.Contains(s, "No such") && !strings.Contains(s, "does not exist") {
			return fmt.Errorf("nft delete chain %s: %w: %s", chain, err, out)
		}
	}
	return nil
}

// RemoveLegacyBridgeFirewall clears any pre-consolidation NAT/isolation/SNAT rules
// a prior binary left for bridge: the `inet litevirt` iso-/snat- chains and, when
// masqueradeSubnet is set, the iptables MASQUERADE + FORWARD rules. It is the
// upgrade-migration cleanup, driven by the firewall reconciler ONCE the equivalent
// rules are live in `inet litevirt-fw` — so there is never a window without NAT.
// All steps are idempotent (safe to call when nothing is present).
func RemoveLegacyBridgeFirewall(bridge, masqueradeSubnet string) {
	RemoveHostIsolation(bridge) //nolint:errcheck
	RemoveSNAT(bridge)          //nolint:errcheck
	if masqueradeSubnet != "" {
		RemoveNAT(masqueradeSubnet, bridge) //nolint:errcheck
	}
}
