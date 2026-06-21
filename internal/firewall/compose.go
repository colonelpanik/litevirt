package firewall

import (
	"fmt"
	"strings"
)

// ComposeRuleInput is the realm-agnostic shape compose-package types
// (or any other producer) hand to FromComposeRules. Keeping the input
// shape in this package — rather than reaching across to import
// internal/compose — avoids a cyclic dependency and keeps firewall a
// leaf package.
type ComposeRuleInput struct {
	Direction string
	Proto     string
	Port      string
	CIDR      string
	Action    string
	Comment   string
}

// FromComposeRules converts a slice of ComposeRuleInput into the typed
// Rules the renderer consumes. Empty fields collapse to the most
// permissive option, matching corrosion.SGRule's defaults.
func FromComposeRules(in []ComposeRuleInput) ([]Rule, error) {
	out := make([]Rule, 0, len(in))
	for i, r := range in {
		dir := Direction(strings.ToLower(r.Direction))
		switch dir {
		case Ingress, Egress:
		case "":
			return nil, fmt.Errorf("rule %d: direction required (ingress|egress)", i)
		default:
			return nil, fmt.Errorf("rule %d: unknown direction %q", i, r.Direction)
		}
		act := Action(strings.ToLower(r.Action))
		if act == "" {
			act = Accept
		}
		switch act {
		case Accept, Drop, Reject:
		default:
			return nil, fmt.Errorf("rule %d: unknown action %q", i, r.Action)
		}
		proto := r.Proto
		if proto == "" {
			proto = "all"
		}
		out = append(out, Rule{
			Direction: dir,
			Proto:     proto,
			PortRange: r.Port,
			CIDR:      r.CIDR,
			Action:    act,
			Comment:   r.Comment,
		})
	}
	return out, nil
}
