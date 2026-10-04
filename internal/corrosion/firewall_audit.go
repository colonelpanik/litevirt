package corrosion

import (
	"context"
	"fmt"
	"strings"
)

// Audit renderings for security groups (colonelpanik/litevirt#182).
//
// This is the security-group subset of the firewall audit renderings on the
// fork's main, carried here so the security-group RPCs record the same rows
// main records. The cluster-, host-tier and ip-set renderings are not needed
// by anything on this branch and are left out.
//
// A security-group audit row records the policy a mutation replaced and the
// policy it left, as `before=<state> after=<state>`. The "before" is the half
// that matters: a removed rule is tombstoned, so once it is gone the audit log
// is the only place that can still say which port the removal opened.
//
// The states are:
//
//	{...}    a rule or group, every field that decides what it matches or does
//	none     a read that SUCCEEDED found no such row
//	unknown  the read failed, so nothing is claimed about what was there
//
// "none" and "unknown" are kept apart on purpose. A failed read must not be
// recorded as absence: that would turn a lookup error into a signed statement
// that nothing was removed.

// AuditStateNone is the state of a row a successful read did not find.
const AuditStateNone = "none"

// AuditChange formats the detail of a firewall audit row.
func AuditChange(before, after string) string {
	return "before=" + before + " after=" + after
}

// AuditUnknown is the state recorded when the read that should have produced
// it failed.
func AuditUnknown(err error) string {
	return "unknown(" + err.Error() + ")"
}

// AuditText renders a security-group rule for an audit row.
func (r SGRule) AuditText() string {
	return "{sg=" + r.SGID + " " + ruleCore(r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action, r.Priority) + "}"
}

// AuditText renders a security group, with the rules that go with it, for an
// audit row.
func (g SecurityGroup) AuditText(rules []SGRule) string {
	out := "{name=" + g.Name
	if g.StackName != "" {
		out += " stack=" + g.StackName
	}
	texts := make([]string, len(rules))
	for i, r := range rules {
		texts[i] = r.AuditText()
	}
	return out + " rules=[" + strings.Join(texts, ",") + "]}"
}

func ruleCore(direction, proto, port, cidr, action string, priority int) string {
	if port == "" {
		port = "any"
	}
	if cidr == "" {
		cidr = "any"
	}
	return fmt.Sprintf("%s %s port=%s cidr=%s %s priority=%d", direction, proto, port, cidr, action, priority)
}

// GetSGRule returns one live security-group rule, or nil if there is none with
// that id.
func GetSGRule(ctx context.Context, c *Client, id string) (*SGRule, error) {
	rows, err := c.Query(ctx,
		`SELECT id, sg_id, direction, proto, port_range, cidr, action, priority
		 FROM sg_rules WHERE id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &SGRule{
		ID:        r.String("id"),
		SGID:      r.String("sg_id"),
		Direction: r.String("direction"),
		Proto:     r.String("proto"),
		PortRange: r.String("port_range"),
		CIDR:      r.String("cidr"),
		Action:    r.String("action"),
		Priority:  r.Int("priority"),
	}, nil
}

// SGRuleAuditState is the audit state of one security-group rule, from the
// result of GetSGRule: the rule, none when a read that succeeded found no such
// rule, or unknown when the read failed. A failed read is never recorded as
// absence.
func SGRuleAuditState(rule *SGRule, err error) string {
	switch {
	case err != nil:
		return AuditUnknown(err)
	case rule == nil:
		return AuditStateNone
	}
	return rule.AuditText()
}

// SecurityGroupAuditState reads one security group, with its rules, and
// renders it as an audit state. DeleteSecurityGroup records it as the "before"
// of a removal.
func SecurityGroupAuditState(ctx context.Context, c *Client, id string) string {
	sg, err := GetSecurityGroup(ctx, c, id)
	if err != nil {
		return AuditUnknown(err)
	}
	if sg == nil {
		return AuditStateNone
	}
	rules, err := ListSGRules(ctx, c, id)
	if err != nil {
		return AuditUnknown(err)
	}
	return sg.AuditText(rules)
}
