package corrosion

import (
	"context"
	"fmt"
)

// FirewallRule is a cluster- or host-tier firewall rule — the two policy
// planes that apply beyond a single NIC. The per-NIC tier lives in
// security_groups + sg_rules; this is the cluster_default / host_overrides
// chains the renderer emits. HostName is set only for host-tier rules.
type FirewallRule struct {
	ID        string
	HostName  string // host_firewall_rules only; empty for cluster rules
	Direction string
	Proto     string
	PortRange string
	CIDR      string
	Action    string
	Priority  int
	Comment   string
	StackName string // set when the rule came from a compose file
}

// IPSet is a named CIDR list, rendered as an nftables set object. Rules
// reference one with cidr = "@<name>".
type IPSet struct {
	ID        string
	Name      string
	CIDRs     []string
	StackName string
}

// FirewallDefault is the default-deny policy for one scope ('cluster' or a
// host name).
type FirewallDefault struct {
	Scope       string
	DefaultDeny bool
	StackName   string
}

// normRule applies the same field defaults the renderer/security-group path
// uses, and rejects IPv6 CIDRs (the renderer only emits ipv4_addr sets, so an
// IPv6 rule would be silently unenforced — same guard as InsertSGRule).
func normRule(r *FirewallRule) error {
	if isIPv6CIDR(r.CIDR) {
		return fmt.Errorf("IPv6 CIDR %q is not supported in firewall rules yet (only IPv4 is enforced); specify an IPv4 CIDR", r.CIDR)
	}
	if r.Proto == "" {
		r.Proto = "all"
	}
	if r.Action == "" {
		r.Action = "accept"
	}
	if r.Priority == 0 {
		r.Priority = 100
	}
	return nil
}

// ── IP sets ──────────────────────────────────────────────────────────────

// InsertIPSet creates a named CIDR list.
func InsertIPSet(ctx context.Context, c *Client, s IPSet) error {
	cidrs, err := encodeSGs(s.CIDRs) // reuse the []string→JSON helper
	if err != nil {
		return err
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO ip_sets (id, name, cidrs, stack_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		s.ID, s.Name, cidrs, s.StackName, now, now,
	)
}

// ListIPSets returns every live ip set (cluster-wide — the renderer scopes
// them by reference, not by host).
func ListIPSets(ctx context.Context, c *Client) ([]IPSet, error) {
	rows, err := c.Query(ctx,
		`SELECT id, name, COALESCE(cidrs, '[]') AS cidrs, stack_name
		 FROM ip_sets WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := make([]IPSet, len(rows))
	for i, r := range rows {
		out[i] = IPSet{
			ID:        r.String("id"),
			Name:      r.String("name"),
			CIDRs:     decodeSGs(r.String("cidrs")),
			StackName: r.String("stack_name"),
		}
	}
	return out, nil
}

// DeleteIPSet tombstones an ip set by id.
func DeleteIPSet(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE ip_sets SET deleted_at = ?, updated_at = ? WHERE id = ?`, now, now, id)
}

// ── Cluster-tier rules ─────────────────────────────────────────────────────

// InsertClusterFirewallRule adds a rule to the cluster_default chain.
func InsertClusterFirewallRule(ctx context.Context, c *Client, r FirewallRule) error {
	if err := normRule(&r); err != nil {
		return err
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO cluster_firewall_rules
		   (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Priority, r.Comment, r.StackName, now, now,
	)
}

// ListClusterFirewallRules returns every live cluster-tier rule, in priority
// order (the order the renderer emits them within the chain).
func ListClusterFirewallRules(ctx context.Context, c *Client) ([]FirewallRule, error) {
	rows, err := c.Query(ctx,
		`SELECT id, direction, proto, port_range, cidr, action, priority, COALESCE(comment,'') AS comment, stack_name
		 FROM cluster_firewall_rules WHERE deleted_at IS NULL ORDER BY priority, id`)
	if err != nil {
		return nil, err
	}
	return scanRules(rows, ""), nil
}

// DeleteClusterFirewallRule tombstones a cluster-tier rule by id.
func DeleteClusterFirewallRule(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE cluster_firewall_rules SET deleted_at = ?, updated_at = ? WHERE id = ?`, now, now, id)
}

// ── Host-tier rules ─────────────────────────────────────────────────────────

// InsertHostFirewallRule adds a rule to one host's host_overrides chain.
func InsertHostFirewallRule(ctx context.Context, c *Client, r FirewallRule) error {
	if r.HostName == "" {
		return fmt.Errorf("host firewall rule requires a host name")
	}
	if err := normRule(&r); err != nil {
		return err
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO host_firewall_rules
		   (id, host_name, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.HostName, r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Priority, r.Comment, r.StackName, now, now,
	)
}

// ListHostFirewallRules returns the live host-tier rules for one host. An
// empty host returns every host's rules (used by the management UI).
func ListHostFirewallRules(ctx context.Context, c *Client, host string) ([]FirewallRule, error) {
	sql := `SELECT id, host_name, direction, proto, port_range, cidr, action, priority, COALESCE(comment,'') AS comment, stack_name
		FROM host_firewall_rules WHERE deleted_at IS NULL`
	var params []interface{}
	if host != "" {
		sql += " AND host_name = ?"
		params = append(params, host)
	}
	sql += " ORDER BY host_name, priority, id"
	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}
	out := make([]FirewallRule, len(rows))
	for i, r := range rows {
		out[i] = FirewallRule{
			ID:        r.String("id"),
			HostName:  r.String("host_name"),
			Direction: r.String("direction"),
			Proto:     r.String("proto"),
			PortRange: r.String("port_range"),
			CIDR:      r.String("cidr"),
			Action:    r.String("action"),
			Priority:  r.Int("priority"),
			Comment:   r.String("comment"),
			StackName: r.String("stack_name"),
		}
	}
	return out, nil
}

// DeleteHostFirewallRule tombstones a host-tier rule by id.
func DeleteHostFirewallRule(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE host_firewall_rules SET deleted_at = ?, updated_at = ? WHERE id = ?`, now, now, id)
}

// scanRules maps cluster-rule rows (no host_name column) into FirewallRule.
func scanRules(rows []Row, host string) []FirewallRule {
	out := make([]FirewallRule, len(rows))
	for i, r := range rows {
		out[i] = FirewallRule{
			ID:        r.String("id"),
			HostName:  host,
			Direction: r.String("direction"),
			Proto:     r.String("proto"),
			PortRange: r.String("port_range"),
			CIDR:      r.String("cidr"),
			Action:    r.String("action"),
			Priority:  r.Int("priority"),
			Comment:   r.String("comment"),
			StackName: r.String("stack_name"),
		}
	}
	return out
}

// ── Default-deny policy ──────────────────────────────────────────────────────

// SetFirewallDefault upserts the default-deny policy for a scope ('cluster' or
// a host name). stack is recorded when the policy came from a compose file.
func SetFirewallDefault(ctx context.Context, c *Client, scope string, deny bool, stack string) error {
	now := c.NowTS()
	denyInt := 0
	if deny {
		denyInt = 1
	}
	// Upsert: a scope has at most one live row.
	return c.Execute(ctx,
		`INSERT INTO firewall_defaults (scope, default_deny, stack_name, created_at, updated_at, deleted_at)
		 VALUES (?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(scope) DO UPDATE SET default_deny = excluded.default_deny,
		   stack_name = excluded.stack_name, updated_at = excluded.updated_at, deleted_at = NULL`,
		scope, denyInt, stack, now, now,
	)
}

// GetFirewallDefault returns the policy for one scope, or nil if unset.
func GetFirewallDefault(ctx context.Context, c *Client, scope string) (*FirewallDefault, error) {
	rows, err := c.Query(ctx,
		`SELECT scope, default_deny, stack_name FROM firewall_defaults
		 WHERE scope = ? AND deleted_at IS NULL`, scope)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &FirewallDefault{
		Scope:       r.String("scope"),
		DefaultDeny: r.Int("default_deny") != 0,
		StackName:   r.String("stack_name"),
	}, nil
}

// ListFirewallDefaults returns every live per-scope default policy (cluster +
// any host overrides), for the management UI / CLI.
func ListFirewallDefaults(ctx context.Context, c *Client) ([]FirewallDefault, error) {
	rows, err := c.Query(ctx,
		`SELECT scope, default_deny, stack_name FROM firewall_defaults
		 WHERE deleted_at IS NULL ORDER BY scope`)
	if err != nil {
		return nil, err
	}
	out := make([]FirewallDefault, len(rows))
	for i, r := range rows {
		out[i] = FirewallDefault{
			Scope:       r.String("scope"),
			DefaultDeny: r.Int("default_deny") != 0,
			StackName:   r.String("stack_name"),
		}
	}
	return out, nil
}

// ResolveDefaultDeny computes the effective default-deny for one host: the
// host-scoped policy if set, else the cluster policy, else false (accept).
func ResolveDefaultDeny(ctx context.Context, c *Client, host string) (bool, error) {
	if host != "" {
		if d, err := GetFirewallDefault(ctx, c, host); err != nil {
			return false, err
		} else if d != nil {
			return d.DefaultDeny, nil
		}
	}
	d, err := GetFirewallDefault(ctx, c, "cluster")
	if err != nil {
		return false, err
	}
	if d != nil {
		return d.DefaultDeny, nil
	}
	return false, nil
}

// DeleteFirewallDefault tombstones a scope's policy (reverts to inherit/accept).
func DeleteFirewallDefault(ctx context.Context, c *Client, scope string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE firewall_defaults SET deleted_at = ?, updated_at = ? WHERE scope = ?`, now, now, scope)
}

// ── Stack teardown ───────────────────────────────────────────────────────────

// DeleteStackFirewall tombstones every firewall row a compose stack created:
// its security groups (+ their rules), ip sets, cluster/host tier rules, and
// any default-deny policy it set. Called from `compose down`.
func DeleteStackFirewall(ctx context.Context, c *Client, stack string) error {
	if stack == "" {
		return nil
	}
	// Security groups + their rules.
	sgs, err := ListSecurityGroups(ctx, c, stack)
	if err != nil {
		return err
	}
	for _, sg := range sgs {
		if err := DeleteSGRules(ctx, c, sg.ID); err != nil {
			return err
		}
		if err := DeleteSecurityGroup(ctx, c, sg.ID); err != nil {
			return err
		}
	}
	now := c.NowTS()
	for _, tbl := range []string{"ip_sets", "cluster_firewall_rules", "host_firewall_rules", "firewall_defaults"} {
		if err := c.Execute(ctx,
			fmt.Sprintf(`UPDATE %s SET deleted_at = ?, updated_at = ? WHERE stack_name = ? AND deleted_at IS NULL`, tbl),
			now, now, stack); err != nil {
			return err
		}
	}
	return nil
}
