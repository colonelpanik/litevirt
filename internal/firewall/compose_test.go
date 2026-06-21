package firewall

import (
	"strings"
	"testing"
)

// TestFromComposeRules_HappyPath covers the common cases and the
// default-collapsing behaviour.
func TestFromComposeRules_HappyPath(t *testing.T) {
	got, err := FromComposeRules([]ComposeRuleInput{
		{Direction: "ingress", Proto: "tcp", Port: "443", CIDR: "0.0.0.0/0", Action: "accept", Comment: "https"},
		{Direction: "egress", Proto: "", Port: "", CIDR: "10.0.0.0/24"}, // defaults: proto=all, action=accept
	})
	if err != nil {
		t.Fatalf("FromComposeRules: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(got))
	}
	if got[0].Direction != Ingress || got[0].PortRange != "443" || got[0].Comment != "https" {
		t.Errorf("rule 0 = %+v", got[0])
	}
	if got[1].Proto != "all" || got[1].Action != Accept {
		t.Errorf("rule 1 defaults wrong: %+v", got[1])
	}
}

// TestFromComposeRules_RejectsEmptyDirection — direction is the one
// field with no safe default (defaulting to ingress would silently
// open holes in deny-by-default deployments).
func TestFromComposeRules_RejectsEmptyDirection(t *testing.T) {
	_, err := FromComposeRules([]ComposeRuleInput{{Action: "accept"}})
	if err == nil || !strings.Contains(err.Error(), "direction") {
		t.Fatalf("expected direction-required error, got %v", err)
	}
}

// TestFromComposeRules_RejectsBadAction guards against typos like "allow".
func TestFromComposeRules_RejectsBadAction(t *testing.T) {
	_, err := FromComposeRules([]ComposeRuleInput{{Direction: "ingress", Action: "allow"}})
	if err == nil || !strings.Contains(err.Error(), "action") {
		t.Fatalf("expected action error, got %v", err)
	}
}
