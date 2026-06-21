package corrosion

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// SecurityGroup represents a security group.
type SecurityGroup struct {
	ID        string
	Name      string
	StackName string
	CreatedAt string
	UpdatedAt string
}

// SGRule represents a security group rule.
type SGRule struct {
	ID        string
	SGID      string
	Direction string
	Proto     string
	PortRange string
	CIDR      string
	Action    string
	Priority  int
}

// InsertSecurityGroup creates a new security group.
func InsertSecurityGroup(ctx context.Context, c *Client, sg SecurityGroup) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if sg.CreatedAt == "" {
		sg.CreatedAt = now
	}
	return c.Execute(ctx,
		`INSERT INTO security_groups (id, name, stack_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		sg.ID, sg.Name, sg.StackName, sg.CreatedAt, now,
	)
}

// GetSecurityGroup returns a security group by ID.
func GetSecurityGroup(ctx context.Context, c *Client, id string) (*SecurityGroup, error) {
	rows, err := c.Query(ctx,
		`SELECT id, name, stack_name, created_at, updated_at
		 FROM security_groups WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &SecurityGroup{
		ID:        r.String("id"),
		Name:      r.String("name"),
		StackName: r.String("stack_name"),
		CreatedAt: r.String("created_at"),
		UpdatedAt: r.String("updated_at"),
	}, nil
}

// ListSecurityGroups returns all security groups, optionally filtered by stack.
func ListSecurityGroups(ctx context.Context, c *Client, stackName string) ([]SecurityGroup, error) {
	sql := `SELECT id, name, stack_name, created_at, updated_at
		FROM security_groups WHERE deleted_at IS NULL`
	var params []interface{}
	if stackName != "" {
		sql += " AND stack_name = ?"
		params = append(params, stackName)
	}
	// Stable order so the firewall renderer produces byte-identical output for
	// unchanged state (the applier's cache short-circuit relies on this).
	sql += " ORDER BY name, id"

	rows, err := c.Query(ctx, sql, params...)
	if err != nil {
		return nil, err
	}

	sgs := make([]SecurityGroup, len(rows))
	for i, r := range rows {
		sgs[i] = SecurityGroup{
			ID:        r.String("id"),
			Name:      r.String("name"),
			StackName: r.String("stack_name"),
			CreatedAt: r.String("created_at"),
			UpdatedAt: r.String("updated_at"),
		}
	}
	return sgs, nil
}

// DeleteSecurityGroup tombstones a security group.
func DeleteSecurityGroup(ctx context.Context, c *Client, id string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE security_groups SET deleted_at = ?, updated_at = ? WHERE id = ?`,
		now, now, id,
	)
}

// InsertSGRule adds a rule to a security group.
func InsertSGRule(ctx context.Context, c *Client, rule SGRule) error {
	// F10: the firewall renderer only emits ipv4_addr sets, so an IPv6 CIDR
	// would be silently dropped — the operator would believe IPv6 is filtered
	// when it isn't. Reject it explicitly until ip6 rendering lands.
	if isIPv6CIDR(rule.CIDR) {
		return fmt.Errorf("IPv6 CIDR %q is not supported in security-group rules yet (only IPv4 is enforced); specify an IPv4 CIDR", rule.CIDR)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	proto := rule.Proto
	if proto == "" {
		proto = "all"
	}
	action := rule.Action
	if action == "" {
		action = "accept"
	}
	priority := rule.Priority
	if priority == 0 {
		priority = 100
	}
	return c.Execute(ctx,
		`INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, priority, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.SGID, rule.Direction, proto, rule.PortRange, rule.CIDR,
		action, priority, now, now,
	)
}

// isIPv6CIDR reports whether s is an IPv6 address or CIDR. An empty string
// (any-source) and IPv4 values return false.
func isIPv6CIDR(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip.To4() == nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() == nil
	}
	return false // not an IP/CIDR at all — leave other validation to the caller
}

// ListSGRules returns all rules for a security group.
func ListSGRules(ctx context.Context, c *Client, sgID string) ([]SGRule, error) {
	rows, err := c.Query(ctx,
		`SELECT id, sg_id, direction, proto, port_range, cidr, action, priority
		 FROM sg_rules WHERE sg_id = ? AND deleted_at IS NULL
		 ORDER BY priority, id`, sgID)
	if err != nil {
		return nil, err
	}

	rules := make([]SGRule, len(rows))
	for i, r := range rows {
		rules[i] = SGRule{
			ID:        r.String("id"),
			SGID:      r.String("sg_id"),
			Direction: r.String("direction"),
			Proto:     r.String("proto"),
			PortRange: r.String("port_range"),
			CIDR:      r.String("cidr"),
			Action:    r.String("action"),
			Priority:  r.Int("priority"),
		}
	}
	return rules, nil
}

// DeleteSGRules tombstones all rules for a security group.
func DeleteSGRules(ctx context.Context, c *Client, sgID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE sg_rules SET deleted_at = ?, updated_at = ? WHERE sg_id = ?`,
		now, now, sgID,
	)
}

// DeleteSGRule tombstones a single rule by its id.
func DeleteSGRule(ctx context.Context, c *Client, ruleID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE sg_rules SET deleted_at = ?, updated_at = ? WHERE id = ?`,
		now, now, ruleID,
	)
}
