// Package firewall is litevirt's distributed firewall. It compiles a
// cluster-wide rule model (security groups + cluster / host / VM tiers)
// into a single atomic nftables ruleset per host and applies it via
// `nft -f -`.
//
// The design choices:
//
//   - One nftables table per host: `inet litevirt-fw`. Replacing the
//     entire table at once keeps rule application atomic — partial
//     state is impossible, so a half-applied ruleset can never leak
//     traffic between tenants.
//   - Three policy tiers, evaluated in order:
//     cluster_default → host overrides → per-VM rules
//     Each tier is a chain attached to `forward`; later tiers can
//     short-circuit with `accept` / `drop`.
//   - Security groups are *named* rule sets. NICs reference them by
//     name; the renderer expands them into chain rules. The schema
//     already in Corrosion (security_groups + sg_rules) becomes the
//     authoritative source.
//   - Stateful conntrack: every chain starts with
//     ct state established,related accept
//     so reply traffic is automatic. Drop policy applies to *new*
//     connections only.
//   - IPsets (named address lists) become nftables `set` objects
//     rendered into the same table.
//
// The package is split:
//
//	firewall.go (this file): types + renderer (pure function).
//	applier.go: nft binary shell-out + atomic load.
//	reconciler.go: watches Corrosion sg/sg_rules tables and re-applies.
package firewall

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// TableName is the single nftables table litevirt owns. Every chain we
// emit lives here so `nft list table inet litevirt-fw` shows the entire
// litevirt-managed surface.
const TableName = "litevirt-fw"

// Direction selects which side of a NIC a rule applies to. The
// semantics match Proxmox / AWS / GCP / OpenStack:
//
//	Ingress = traffic ARRIVING at the VM. In netfilter's forward
//	          chain a packet headed "into" a libvirt tap is matched
//	          with oifname=tap. Restrict who can CONNECT TO this VM.
//	Egress  = traffic LEAVING the VM. iifname=tap. Restrict where
//	          the VM can CONNECT TO.
//
// Note: the legacy internal/network/acl.go inverted these mappings; the
// new firewall package follows the cloud-vendor convention so a user
// writing `direction: ingress, port: 22, action: accept` gets the
// behaviour they expect: SSH from outside is accepted.
type Direction string

const (
	Ingress Direction = "ingress" // matches oifname=<tap> in forward chain
	Egress  Direction = "egress"  // matches iifname=<tap> in forward chain
)

// Action is the verdict at the end of a matched rule.
type Action string

const (
	Accept Action = "accept"
	Drop   Action = "drop"
	Reject Action = "reject" // sends an ICMP unreachable; useful for friendlier UX
)

// Tier is which of the three policy planes a rule belongs to.
// Cluster rules apply to every NIC; host rules apply to every NIC on
// one host; VM rules apply to one NIC. Higher-priority tiers may
// short-circuit lower ones with explicit accept/drop.
type Tier string

const (
	TierCluster Tier = "cluster"
	TierHost    Tier = "host"
	TierVM      Tier = "vm"
)

// Rule is a single firewall rule, normalised across the three tiers.
// SGRule (corrosion) and ACLRule (network/acl.go) both convert to this.
type Rule struct {
	Direction Direction
	Proto     string // "tcp" | "udp" | "icmp" | "all"
	PortRange string // "80" | "8000-9000" | ""
	CIDR      string // "10.0.0.0/24" | "" (any) | "@<ipset-name>"
	Action    Action
	Comment   string // human-readable; emitted as `# …` on the rule line
}

// SecurityGroup is a named set of Rules. NICs reference SGs by name;
// the renderer expands references into rule chains. Same-name SGs
// from different stacks collide — operators get a deterministic error
// at deploy rather than a silent overwrite.
type SecurityGroup struct {
	Name  string
	Rules []Rule
}

// IPSet is a named CIDR list, rendered as an nftables `set` object.
// Rules can reference one with CIDR="@<set-name>" — typed-aliased
// CIDR lists make rule files dramatically smaller.
type IPSet struct {
	Name  string
	CIDRs []string
}

// NICBinding attaches one VM NIC to zero or more security groups, plus
// any per-NIC rules layered on top. The NICDev string is the host-side
// device name (tap-… or veth…); it's the iifname/oifname token the
// renderer matches on.
type NICBinding struct {
	NICDev         string
	VMName         string
	SecurityGroups []string // SG names, resolved via Plan.SecurityGroups
	ExtraRules     []Rule   // per-VM rules layered after SG rules
}

// Plan is the input to the renderer — the *complete* desired state
// for one host. Apply replaces the host's table atomically with the
// renderer's output, so anything missing from a Plan is removed.
//
// Three-tier rules show up here as three slices. Within each tier,
// rules apply in array order (the first match wins, except for
// accept-then-fall-through semantics enforced by the renderer).
type Plan struct {
	// DefaultDeny, when true, drops any packet that no rule matched.
	// When false the policy is accept (a "logging-only" mode useful
	// during rollout).
	DefaultDeny bool

	ClusterRules []Rule
	HostRules    []Rule

	SecurityGroups []SecurityGroup
	IPSets         []IPSet
	NICs           []NICBinding
}

// Render turns the Plan into an nftables ruleset that can be fed to
// `nft -f -`. The output is deterministic — identical Plan ⇒ identical
// bytes — so apply can short-circuit when nothing changed.
func Render(p Plan) (string, error) {
	if err := validate(p); err != nil {
		return "", err
	}
	sgByName := map[string]SecurityGroup{}
	for _, sg := range p.SecurityGroups {
		sgByName[sg.Name] = sg
	}
	for _, n := range p.NICs {
		for _, name := range n.SecurityGroups {
			if _, ok := sgByName[name]; !ok {
				return "", fmt.Errorf("NIC %q references unknown security group %q", n.NICDev, name)
			}
		}
	}

	var b strings.Builder
	b.WriteString("# Generated by litevirt firewall renderer — do not edit by hand.\n")
	b.WriteString("# `nft -f -` consumes this file as an atomic ruleset replace.\n\n")

	// We emit the table block as a self-contained unit. `nft -f -`
	// treats this as an atomic replace of the litevirt-fw table.
	//
	// IMPORTANT: do NOT close the brace via `defer` — strings.Builder.String()
	// snapshots the length at call time, and a deferred WriteString
	// happens *after* return value evaluation, so the brace would be
	// written into the underlying buffer but never appear in the
	// returned string. Always close before returning.
	fmt.Fprintf(&b, "table inet %s {\n", TableName)

	// IP sets first; chains may reference them.
	renderIPSets(&b, p.IPSets)

	// One forward chain hooks to the netfilter forward path. Everything
	// else is a regular chain we jump into.
	defaultPolicy := "accept"
	if p.DefaultDeny {
		defaultPolicy = "drop"
	}
	fmt.Fprintf(&b, "    chain forward {\n")
	fmt.Fprintf(&b, "        type filter hook forward priority filter; policy %s;\n", defaultPolicy)
	// Stateful conntrack — reply traffic is always allowed. Putting it
	// at the head of the forward chain means we never re-evaluate per-
	// connection-state for established flows.
	fmt.Fprintf(&b, "        ct state established,related accept\n")
	fmt.Fprintf(&b, "        ct state invalid drop\n")
	// Jump tier-by-tier. Cluster rules run first because they describe
	// blanket policy (e.g. "block egress to RFC1918 from public VLAN").
	fmt.Fprintf(&b, "        jump cluster_default\n")
	fmt.Fprintf(&b, "        jump host_overrides\n")
	// Each NIC gets a dispatch chain so a packet only evaluates the
	// rules for the NIC it's traversing.
	fmt.Fprintf(&b, "        jump nic_dispatch\n")
	fmt.Fprintf(&b, "    }\n\n")

	renderTierChain(&b, "cluster_default", p.ClusterRules, "" /* no per-NIC match */)
	renderTierChain(&b, "host_overrides", p.HostRules, "")
	renderNICDispatch(&b, p.NICs, sgByName)

	b.WriteString("}\n")
	return b.String(), nil
}

// renderIPSets writes one `set <name> { … }` block per IPSet.
// nftables sets are typed; we use ipv4_addr with the `interval` flag
// so CIDRs work natively.
func renderIPSets(b *strings.Builder, sets []IPSet) {
	if len(sets) == 0 {
		return
	}
	// Stable order so the rendered output is byte-deterministic.
	sortedSets := make([]IPSet, len(sets))
	copy(sortedSets, sets)
	sort.Slice(sortedSets, func(i, j int) bool { return sortedSets[i].Name < sortedSets[j].Name })

	for _, s := range sortedSets {
		fmt.Fprintf(b, "    set %s {\n", s.Name)
		fmt.Fprintf(b, "        type ipv4_addr\n")
		fmt.Fprintf(b, "        flags interval\n")
		if len(s.CIDRs) > 0 {
			cidrs := append([]string(nil), s.CIDRs...)
			sort.Strings(cidrs)
			fmt.Fprintf(b, "        elements = { %s }\n", strings.Join(cidrs, ", "))
		}
		fmt.Fprintf(b, "    }\n\n")
	}
}

// renderTierChain emits a chain whose rules apply to every packet
// entering it (cluster + host tiers don't filter by NIC). The chain
// name is the tier name.
func renderTierChain(b *strings.Builder, name string, rules []Rule, _ string) {
	fmt.Fprintf(b, "    chain %s {\n", name)
	for _, r := range rules {
		fmt.Fprintf(b, "        %s\n", renderRule(r, ""))
	}
	fmt.Fprintf(b, "    }\n\n")
}

// renderNICDispatch emits one chain per NIC plus a `nic_dispatch` chain
// that jumps into the right one based on iifname / oifname. SG
// expansion happens here.
func renderNICDispatch(b *strings.Builder, nics []NICBinding, sgs map[string]SecurityGroup) {
	fmt.Fprintf(b, "    chain nic_dispatch {\n")
	// Sort by NICDev so the dispatch order is deterministic — important
	// for byte-equality between two equivalent Plans.
	sortedNICs := make([]NICBinding, len(nics))
	copy(sortedNICs, nics)
	sort.Slice(sortedNICs, func(i, j int) bool { return sortedNICs[i].NICDev < sortedNICs[j].NICDev })

	for _, n := range sortedNICs {
		// Both directions land in the same per-NIC chain — the chain's
		// rules use iifname/oifname to filter inside.
		fmt.Fprintf(b, "        iifname %s jump nic_%s\n", n.NICDev, sanitiseChain(n.NICDev))
		fmt.Fprintf(b, "        oifname %s jump nic_%s\n", n.NICDev, sanitiseChain(n.NICDev))
	}
	fmt.Fprintf(b, "    }\n\n")

	for _, n := range sortedNICs {
		fmt.Fprintf(b, "    chain nic_%s {\n", sanitiseChain(n.NICDev))
		// Expand each referenced SG, then layer extra rules on top.
		for _, name := range n.SecurityGroups {
			sg := sgs[name]
			if sg.Name == "" {
				continue
			}
			fmt.Fprintf(b, "        # security group %q\n", sg.Name)
			for _, r := range sg.Rules {
				fmt.Fprintf(b, "        %s\n", renderRule(r, n.NICDev))
			}
		}
		for _, r := range n.ExtraRules {
			fmt.Fprintf(b, "        %s\n", renderRule(r, n.NICDev))
		}
		fmt.Fprintf(b, "    }\n\n")
	}
}

// renderRule builds one nftables rule line. iifname/oifname is added
// only when nicDev is non-empty (cluster/host tiers don't filter by NIC).
func renderRule(r Rule, nicDev string) string {
	var parts []string

	if nicDev != "" {
		// Proxmox / cloud-vendor convention:
		//   Ingress (traffic arriving at the VM) → packet is leaving the
		//     forward chain via the VM's tap → oifname.
		//   Egress  (traffic leaving the VM) → packet entered the forward
		//     chain via the VM's tap → iifname.
		if r.Direction == Egress {
			parts = append(parts, "iifname", nicDev)
		} else {
			parts = append(parts, "oifname", nicDev)
		}
	}

	switch strings.ToLower(r.Proto) {
	case "tcp", "udp":
		parts = append(parts, strings.ToLower(r.Proto))
		if r.PortRange != "" {
			// Port semantics flip with the direction the rule was
			// expressed in by the operator:
			//   Ingress: dport (the destination port on the VM)
			//   Egress:  dport too (the destination port at the remote)
			// Both are dport — sport is rarely what a security group
			// wants. nftables port-range syntax is N-M; pass through.
			parts = append(parts, "dport", r.PortRange)
		}
	case "icmp":
		// IPv4 ICMP only — ICMPv6 will land with the IPv6 expansion.
		parts = append(parts, "ip", "protocol", "icmp")
	case "", "all":
		// no proto filter
	default:
		parts = append(parts, "ip", "protocol", strings.ToLower(r.Proto))
	}

	if r.CIDR != "" {
		// CIDR direction:
		//   Ingress: saddr — restrict WHO can talk to the VM
		//   Egress:  daddr — restrict WHERE the VM can talk to
		addrWord := "saddr"
		if r.Direction == Egress {
			addrWord = "daddr"
		}
		// "@name" is the nftables set-reference syntax. Preserve verbatim.
		parts = append(parts, "ip", addrWord, r.CIDR)
	}

	action := r.Action
	if action == "" {
		action = Accept
	}
	parts = append(parts, string(action))

	out := strings.Join(parts, " ")
	if r.Comment != "" {
		out += fmt.Sprintf(" comment %q", r.Comment)
	}
	return out
}

// sanitiseChain produces a chain-name-safe variant of a NIC device
// name. nftables identifiers can be alphanumeric + underscore; tap
// names already meet that, but veth names with dashes need swapping.
func sanitiseChain(nicDev string) string {
	r := strings.NewReplacer("-", "_", ".", "_")
	return r.Replace(nicDev)
}

// validate catches the classes of misconfigurations the renderer can't
// safely round-trip.
func validate(p Plan) error {
	for i, r := range allRules(p) {
		switch r.Direction {
		case Ingress, Egress:
		default:
			return fmt.Errorf("rule %d: direction %q must be ingress or egress", i, r.Direction)
		}
		switch r.Action {
		case "", Accept, Drop, Reject:
		default:
			return fmt.Errorf("rule %d: action %q not supported (accept|drop|reject)", i, r.Action)
		}
		// F10: the renderer is IPv4-only (ip saddr/daddr + ipv4_addr sets). A
		// literal IPv6 CIDR would emit an invalid `ip saddr <v6>` line and poison
		// the whole atomic ruleset at apply time — so reject it here rather than
		// silently mis-rendering. (Set references "@name" carry no ":"; their
		// elements are checked via the IPSet loop below.)
		if r.CIDR != "" && !strings.HasPrefix(r.CIDR, "@") && strings.Contains(r.CIDR, ":") {
			return fmt.Errorf("rule %d: IPv6 CIDR %q is not supported by security-group rules yet (IPv4-only renderer)", i, r.CIDR)
		}
	}
	for _, sg := range p.SecurityGroups {
		if sg.Name == "" {
			return errors.New("security group with empty name")
		}
	}
	for _, ipset := range p.IPSets {
		if ipset.Name == "" {
			return errors.New("ipset with empty name")
		}
		// F10: sets render as ipv4_addr, so an IPv6 element can't be expressed.
		for _, cidr := range ipset.CIDRs {
			if strings.Contains(cidr, ":") {
				return fmt.Errorf("ipset %q: IPv6 element %q not supported yet (sets render as ipv4_addr)", ipset.Name, cidr)
			}
		}
	}
	return nil
}

// allRules walks every Rule the Plan contains so validate can sweep
// them in one place.
func allRules(p Plan) []Rule {
	var out []Rule
	out = append(out, p.ClusterRules...)
	out = append(out, p.HostRules...)
	for _, sg := range p.SecurityGroups {
		out = append(out, sg.Rules...)
	}
	for _, n := range p.NICs {
		out = append(out, n.ExtraRules...)
	}
	return out
}

// FromCorrosionRule converts the on-disk SGRule struct into the typed
// Rule the renderer consumes. Empty / default fields collapse to the
// most permissive option — same convention the corrosion helpers use
// when persisting.
func FromCorrosionRule(direction, proto, portRange, cidr, action string) Rule {
	dir := Direction(strings.ToLower(direction))
	if dir != Egress {
		dir = Ingress
	}
	if proto == "" {
		proto = "all"
	}
	act := Action(strings.ToLower(action))
	if act == "" {
		act = Accept
	}
	return Rule{
		Direction: dir,
		Proto:     proto,
		PortRange: portRange,
		CIDR:      cidr,
		Action:    act,
	}
}
