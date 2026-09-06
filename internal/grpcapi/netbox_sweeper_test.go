package grpcapi

import (
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/netbox"
)

// TestSweeperParseIdentityRoundTrips pins parseIdentity as the exact inverse of
// netbox.Identity for a REAL MAC.
//
// The hazard is specific: a MAC contains colons, so a four-way split on ":"
// silently truncates "52:54:00:aa:bb:cc" to "52". Every proof would then ask
// about a MAC no NIC has, no host would ever report holding it, and the sweeper
// would delete live addresses with a complete, confident, entirely wrong proof.
func TestSweeperParseIdentityRoundTrips(t *testing.T) {
	const (
		fp   = "abcdef0123456789"
		uuid = "6f1b0c2e-0000-4000-8000-0000000000aa"
		mac  = "52:54:00:aa:bb:cc"
	)
	gotFP, gotUUID, gotMAC, ok := parseIdentity(netbox.Identity(fp, uuid, mac))
	if !ok {
		t.Fatal("a well-formed identity must parse")
	}
	if gotFP != fp || gotUUID != uuid || gotMAC != mac {
		t.Fatalf("parseIdentity = (%q, %q, %q), want (%q, %q, %q)",
			gotFP, gotUUID, gotMAC, fp, uuid, mac)
	}
}

// TestSweeperParseIdentityRejectsMalformed pins the refusals. Each rejected
// shape would otherwise be treated as a candidate under SOME fingerprint, and a
// candidate is the first step toward a delete.
func TestSweeperParseIdentityRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"",
		"lv",
		"lv:fp",
		"lv:fp:uuid",              // no MAC at all
		"lv:fp:uuid:",             // empty MAC
		"lv::uuid:52:54:00:a:b:c", // empty fingerprint
		"lv:fp::52:54:00:a:b:c",   // empty uuid
		"xx:fp:uuid:52:54:00",     // not ours
		"someone-else",
	} {
		if _, _, _, ok := parseIdentity(raw); ok {
			t.Errorf("parseIdentity(%q) accepted a malformed identity", raw)
		}
	}
}

// TestSweeperBareAddressForms covers the reduction from NetBox's prefixed form
// to the bare host address local rows store. An address that reduced wrongly
// would match no lease, and "no lease" is the sweeper's licence to delete.
func TestSweeperBareAddressForms(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"10.0.5.100/24", "10.0.5.100", true},
		{"10.0.5.100", "10.0.5.100", true},
		{"10.0.5.100/33", "10.0.5.100", true}, // nonsense length, real host half
		{"2001:db8::5/64", "2001:db8::5", true},
		{"not-an-address/24", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := bareAddress(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("bareAddress(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestSweeperGraceTreatsUnknownAgeAsTooYoung pins the fail-closed reading of a
// missing creation timestamp. "I do not know how old this is" must never become
// "old enough to delete".
func TestSweeperGraceTreatsUnknownAgeAsTooYoung(t *testing.T) {
	cutoff := time.Now().UTC().Add(-orphanGrace)
	if olderThan(time.Time{}, cutoff) {
		t.Fatal("an object of unknown age must never be treated as past the grace window")
	}
	if olderThan(cutoff.Add(time.Minute), cutoff) {
		t.Fatal("an object created after the cutoff is inside the grace window")
	}
	if !olderThan(cutoff.Add(-time.Minute), cutoff) {
		t.Fatal("an object created before the cutoff is past the grace window")
	}
}

// TestSweeperSameHostSetIsOrderSensitiveOnSortedInput pins the membership
// comparison. Both samples come out of eligibleProofHosts sorted, so a
// positional compare is exact — and a set that differs anywhere must not
// compare equal, because the difference is a host the proof never asked.
func TestSweeperSameHostSetDetectsEveryDifference(t *testing.T) {
	base := []string{"a", "b", "c"}
	if !sameHostSet(base, []string{"a", "b", "c"}) {
		t.Fatal("identical sets must compare equal")
	}
	for _, other := range [][]string{
		{"a", "b"},
		{"a", "b", "c", "d"},
		{"a", "b", "d"},
		nil,
	} {
		if sameHostSet(base, other) {
			t.Errorf("sameHostSet(%v, %v) = true, want false", base, other)
		}
	}
}

// TestSweeperSkipReasonIsBounded pins that the metric label comes from the
// closed set, never from the error text. The reason strings name addresses and
// hosts; a Prometheus label built from them is unbounded cardinality, which is
// a cluster-wide memory bug rather than a diagnostic.
func TestSweeperSkipReasonIsBounded(t *testing.T) {
	err := skipf(skipHostHolds, "host %s still claims the address", "node-7")
	if got := skipReason(err); got != skipHostHolds {
		t.Fatalf("skipReason = %q, want %q", got, skipHostHolds)
	}
	if msg := err.Error(); msg != "host node-7 still claims the address" {
		t.Fatalf("the full reason must survive for the log line, got %q", msg)
	}
	if got := skipReason(errors.New("something else")); got != "error" {
		t.Fatalf("skipReason of a plain error = %q, want \"error\"", got)
	}
}
