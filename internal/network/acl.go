package network

import (
	"fmt"
)

// ACLRule describes a single firewall rule.
type ACLRule struct {
	Direction string // "ingress" | "egress"
	Proto     string // "tcp" | "udp" | "icmp" | "all"
	PortRange string // "80" | "8000-9000" | ""
	CIDR      string // "" = any
	Action    string // "accept" | "drop"
}

// chainName returns the nftables chain name for tapDev and direction.
func chainName(tapDev, direction string) string {
	return fmt.Sprintf("tap-%s-%s", tapDev, direction)
}

// nftRuleArgs returns nft rule command args for one rule on tapDev. Pure function.
func nftRuleArgs(tapDev string, rule ACLRule) []string {
	// Direction: ingress uses iifname, egress uses oifname
	ifaceMatch := "iifname"
	if rule.Direction == "egress" {
		ifaceMatch = "oifname"
	}

	args := []string{"nft", "add", "rule", "inet", "litevirt"}

	// Chain name based on direction
	dirSuffix := "in"
	if rule.Direction == "egress" {
		dirSuffix = "out"
	}
	args = append(args, chainName(tapDev, dirSuffix))

	// Interface match
	args = append(args, ifaceMatch, tapDev)

	action := rule.Action
	if action == "" {
		action = "accept"
	}

	switch rule.Proto {
	case "tcp", "udp":
		args = append(args, rule.Proto)
		if rule.PortRange != "" {
			if rule.Direction == "egress" {
				args = append(args, "sport", rule.PortRange)
			} else {
				args = append(args, "dport", rule.PortRange)
			}
		}
		if rule.CIDR != "" {
			if rule.Direction == "egress" {
				args = append(args, "ip", "daddr", rule.CIDR)
			} else {
				args = append(args, "ip", "saddr", rule.CIDR)
			}
		}
	case "icmp":
		args = append(args, "ip", "protocol", "icmp")
		if rule.CIDR != "" {
			if rule.Direction == "egress" {
				args = append(args, "ip", "daddr", rule.CIDR)
			} else {
				args = append(args, "ip", "saddr", rule.CIDR)
			}
		}
	default:
		// "all" or empty: no proto match
		if rule.CIDR != "" {
			if rule.Direction == "egress" {
				args = append(args, "ip", "daddr", rule.CIDR)
			} else {
				args = append(args, "ip", "saddr", rule.CIDR)
			}
		}
	}

	args = append(args, action)
	return args
}

// EnsureChain creates/replaces nftables chains for tapDev.
// table: "inet litevirt"
// chains: "tap-<tapDev>-in", "tap-<tapDev>-out"
// If rules empty: policy accept. If rules non-empty: policy drop + explicit allow rules.
func EnsureChain(tapDev string, rules []ACLRule) error {
	table := "inet litevirt"
	chainIn := chainName(tapDev, "in")
	chainOut := chainName(tapDev, "out")

	// Ensure table exists
	if out, err := execCommand("nft", "add", "table", "inet", "litevirt"); err != nil {
		if !isAlreadyExists(out) && !isFileExists(out) {
			return fmt.Errorf("nft add table: %w: %s", err, out)
		}
	}

	policy := "accept"
	if len(rules) > 0 {
		policy = "drop"
	}

	// Create/flush input chain
	for _, chain := range []string{chainIn, chainOut} {
		out, err := execCommand("nft", "add", "chain", "inet", "litevirt", chain,
			fmt.Sprintf("{ type filter hook forward priority 0; policy %s; }", policy))
		if err != nil && !isAlreadyExists(out) && !isFileExists(out) {
			return fmt.Errorf("nft add chain %s: %w: %s", chain, err, out)
		}
		// Flush existing rules
		if _, err := execCommand("nft", "flush", "chain", table, chain); err != nil {
			// Ignore flush errors (chain may be new)
		}
	}

	// Add rules
	for _, rule := range rules {
		args := nftRuleArgs(tapDev, rule)
		// args[0] is "nft", rest are the sub-args
		if out, err := execCommand(args[0], args[1:]...); err != nil {
			if !isAlreadyExists(out) {
				return fmt.Errorf("nft add rule: %w: %s", err, out)
			}
		}
	}

	return nil
}

// DeleteChain removes chains for tapDev.
func DeleteChain(tapDev string) error {
	chainIn := chainName(tapDev, "in")
	chainOut := chainName(tapDev, "out")

	for _, chain := range []string{chainIn, chainOut} {
		if out, err := execCommand("nft", "delete", "chain", "inet", "litevirt", chain); err != nil {
			if !isAlreadyExists(out) && !isFileExists(out) {
				return fmt.Errorf("nft delete chain %s: %w: %s", chain, err, out)
			}
		}
	}
	return nil
}

// FlushChain removes all rules from chains for tapDev.
func FlushChain(tapDev string) error {
	chainIn := chainName(tapDev, "in")
	chainOut := chainName(tapDev, "out")

	for _, chain := range []string{chainIn, chainOut} {
		if out, err := execCommand("nft", "flush", "chain", "inet", "litevirt", chain); err != nil {
			if !isAlreadyExists(out) && !isFileExists(out) {
				return fmt.Errorf("nft flush chain %s: %w: %s", chain, err, out)
			}
		}
	}
	return nil
}
