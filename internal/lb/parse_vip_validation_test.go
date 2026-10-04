package lb

import "testing"

// ParseVIP never called net.ParseIP. Anything without a "/" was returned
// verbatim with prefix 32, so `--vip '*'` was accepted as an address.
//
// It reaches two root-applied surfaces. keepalived gets an unparseable
// virtual_ipaddress and the error is only logged, so the VIP silently never
// comes up; and on an isolated bridge the same string is rendered into an
// nftables rule, where `nft -f` rejects the WHOLE ruleset — so every later
// firewall reconcile on that host fails too, long after anyone connects it to
// the VIP they typed.
func TestParseVIP_RejectsAnythingThatIsNotAnAddress(t *testing.T) {
	for _, vip := range []string{
		"*",
		"not-an-ip",
		"10.0.0.999",
		"10.0.0.1.5",
		"",
		"10.0.0.0/24/8",
	} {
		if ip, prefix, err := ParseVIP(vip); err == nil {
			t.Errorf("ParseVIP(%q) = %q/%d, want an error — this string reaches "+
				"keepalived and nftables as an address", vip, ip, prefix)
		}
	}
}

// A prefix outside its family's range is not a network.
func TestParseVIP_RejectsAnOutOfRangePrefix(t *testing.T) {
	for _, vip := range []string{"10.0.0.1/33", "10.0.0.1/-1"} {
		if _, _, err := ParseVIP(vip); err == nil {
			t.Errorf("ParseVIP(%q) was accepted, want an error", vip)
		}
	}
}

// The shapes that already worked must keep working.
func TestParseVIP_StillAcceptsRealAddresses(t *testing.T) {
	for _, tc := range []struct {
		vip    string
		ip     string
		prefix int
	}{
		{"0.0.0.0/0", "0.0.0.0", 0},
		{"172.16.0.1", "172.16.0.1", 32},
		{"10.0.0.1/24", "10.0.0.1", 24},
	} {
		ip, prefix, err := ParseVIP(tc.vip)
		if err != nil || ip != tc.ip || prefix != tc.prefix {
			t.Errorf("ParseVIP(%q) = %q/%d err=%v, want %q/%d", tc.vip, ip, prefix, err, tc.ip, tc.prefix)
		}
	}
}

// A VIP must be IPv4. Every consumer is: keepalived's virtual_ipaddress is
// rendered IPv4-shaped, and internal/firewall rejects any exception VIP
// containing ":" outright — `exc.VIP == "" || strings.Contains(exc.VIP, ":")`
// fails the whole Plan, which fails EVERY later firewall reconcile on that
// host. That is the same cluster-wide blast radius this validator was added to
// prevent, so accepting an address the rest of the stack cannot carry just
// moves the failure one layer down.
//
// It matches the rest of the tree: CLAUDE.md states cluster transport is
// IPv4-only, and advertise_address and resolveHost already refuse IPv6 at their
// entry points.
func TestParseVIP_RejectsIPv6BecauseNothingDownstreamCanCarryIt(t *testing.T) {
	for _, vip := range []string{"fd00::1/64", "fd00::1", "::1", "::ffff:10.0.0.1"} {
		if ip, prefix, err := ParseVIP(vip); err == nil {
			t.Errorf("ParseVIP(%q) = %q/%d, want an error — internal/firewall "+
				"refuses any VIP containing \":\" and fails the entire plan", vip, ip, prefix)
		}
	}
}

// ParseStoredVIP reads a VIP written by an EARLIER build, whose parser accepted
// things this one refuses.
//
// Tightening the parser without this turned an upgrade into a silent outage:
// reapplyExplicitLB bails on a parse error, so an LB stored as
// "10.0.0.1/24/extra" — which the old Sscanf-based parser accepted and stored —
// simply stopped being re-applied after any daemon restart or failover, with
// one Warn line as the only trace.
//
// A row that still names a real address is repaired and flagged; one that never
// did is refused, because there is nothing to recover.
func TestParseStoredVIP_RepairsWhatTheOldParserAccepted(t *testing.T) {
	for _, tc := range []struct {
		stored string
		ip     string
		prefix int
	}{
		{"10.0.0.1/24/extra", "10.0.0.1", 24},
		{"10.0.0.1/3.5", "10.0.0.1", 3},
		{"10.0.0.1", "10.0.0.1", 32},
	} {
		ip, prefix, repaired, err := ParseStoredVIP(tc.stored)
		if err != nil {
			t.Errorf("ParseStoredVIP(%q) refused a row naming a real address: %v", tc.stored, err)
			continue
		}
		if ip != tc.ip || prefix != tc.prefix {
			t.Errorf("ParseStoredVIP(%q) = %q/%d, want %q/%d", tc.stored, ip, prefix, tc.ip, tc.prefix)
		}
		if repaired == (tc.stored == tc.ip) {
			t.Errorf("ParseStoredVIP(%q) repaired=%v; it must be true exactly when the row needed fixing",
				tc.stored, repaired)
		}
	}
}

func TestParseStoredVIP_RefusesARowThatNeverNamedAnAddress(t *testing.T) {
	for _, stored := range []string{"*", "", "/24", "not-an-ip", "fd00::1/64"} {
		if ip, prefix, repaired, err := ParseStoredVIP(stored); err == nil {
			t.Errorf("ParseStoredVIP(%q) = %q/%d repaired=%v, want an error", stored, ip, prefix, repaired)
		}
	}
}
