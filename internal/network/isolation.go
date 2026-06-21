package network

import (
	"fmt"
	"strings"
)

// IsolationLBException describes VIP ports that should be allowed through
// host-isolation nftables rules so VMs can reach HAProxy.
type IsolationLBException struct {
	VIP   string // e.g. "10.100.0.50"
	Ports []int  // e.g. [80, 443]
}

// isolationChainName returns the nftables chain name for a bridge's host-isolation rules.
func isolationChainName(bridge string) string {
	return fmt.Sprintf("iso-%s", bridge)
}

// snatChainName returns the nftables chain name for a bridge's SNAT rules.
func snatChainName(bridge string) string {
	return fmt.Sprintf("snat-%s", bridge)
}

// EnsureHostIsolation creates/replaces an nftables INPUT chain that drops all
// traffic from the bridge to the host, except for optional LB exceptions.
// This makes the hypervisor invisible to VMs on the bridge.
//
// If lbExceptions is non-empty, VRRP (IP protocol 112) and the specified VIP
// ports are allowed through before the final drop rule.
//
// The chain is flushed and rebuilt on every call, making this idempotent.
func EnsureHostIsolation(bridge string, lbExceptions []IsolationLBException) error {
	chain := isolationChainName(bridge)

	// Ensure table exists.
	if out, err := execCommand("nft", "add", "table", "inet", "litevirt"); err != nil {
		if !isAlreadyExists(out) && !isFileExists(out) {
			return fmt.Errorf("nft add table: %w: %s", err, out)
		}
	}

	// Create chain on input hook.
	out, err := execCommand("nft", "add", "chain", "inet", "litevirt", chain,
		"{ type filter hook input priority 0; policy accept; }")
	if err != nil && !isAlreadyExists(out) && !isFileExists(out) {
		return fmt.Errorf("nft add chain %s: %w: %s", chain, err, out)
	}

	// Flush existing rules (idempotent re-apply).
	if _, err := execCommand("nft", "flush", "chain", "inet", "litevirt", chain); err != nil {
		// Ignore flush errors on new chains.
	}

	// Add LB exceptions before the drop rule.
	if len(lbExceptions) > 0 {
		// Allow VRRP (keepalived) — IP protocol 112.
		if out, err := execCommand("nft", "add", "rule", "inet", "litevirt", chain,
			"iifname", bridge, "ip", "protocol", "112", "accept"); err != nil {
			if !isAlreadyExists(out) {
				return fmt.Errorf("nft add vrrp rule: %w: %s", err, out)
			}
		}

		// Allow traffic to each VIP on its declared ports.
		for _, exc := range lbExceptions {
			for _, port := range exc.Ports {
				if out, err := execCommand("nft", "add", "rule", "inet", "litevirt", chain,
					"iifname", bridge, "ip", "daddr", exc.VIP,
					"tcp", "dport", fmt.Sprintf("%d", port), "accept"); err != nil {
					if !isAlreadyExists(out) {
						return fmt.Errorf("nft add lb rule %s:%d: %w: %s", exc.VIP, port, err, out)
					}
				}
			}
		}
	}

	// Final drop: block all remaining traffic from bridge to host.
	if out, err := execCommand("nft", "add", "rule", "inet", "litevirt", chain,
		"iifname", bridge, "drop"); err != nil {
		if !isAlreadyExists(out) {
			return fmt.Errorf("nft add drop rule: %w: %s", err, out)
		}
	}

	return nil
}

// RemoveHostIsolation removes the host-isolation nftables chain for a bridge.
// Idempotent: ignores errors if the chain does not exist.
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

// EnsureSNAT creates an nftables nat/postrouting chain that SNATs outbound
// traffic from the VM subnet to the LB VIP address.
//
// This allows VMs on host-isolated networks to reach the internet with the
// VIP as their source address.
func EnsureSNAT(bridge, subnet, vip, outIface string) error {
	chain := snatChainName(bridge)

	// Ensure table exists.
	if out, err := execCommand("nft", "add", "table", "inet", "litevirt"); err != nil {
		if !isAlreadyExists(out) && !isFileExists(out) {
			return fmt.Errorf("nft add table: %w: %s", err, out)
		}
	}

	// Create chain on nat postrouting hook.
	out, err := execCommand("nft", "add", "chain", "inet", "litevirt", chain,
		"{ type nat hook postrouting priority srcnat; policy accept; }")
	if err != nil && !isAlreadyExists(out) && !isFileExists(out) {
		return fmt.Errorf("nft add chain %s: %w: %s", chain, err, out)
	}

	// Flush existing rules.
	if _, err := execCommand("nft", "flush", "chain", "inet", "litevirt", chain); err != nil {
		// Ignore flush errors on new chains.
	}

	// Enable IP forwarding.
	if out, err := execCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enable ip forwarding: %w: %s", err, out)
	}

	// SNAT rule: traffic from subnet leaving via outIface gets source rewritten to VIP.
	if out, err := execCommand("nft", "add", "rule", "inet", "litevirt", chain,
		"oifname", outIface, "ip", "saddr", subnet, "snat", "to", vip); err != nil {
		if !isAlreadyExists(out) {
			return fmt.Errorf("nft add snat rule: %w: %s", err, out)
		}
	}

	return nil
}

// RemoveSNAT removes the SNAT nftables chain for a bridge.
// Idempotent: ignores errors if the chain does not exist.
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
