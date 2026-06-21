package network

import "testing"

func TestIsolatedBridgeName(t *testing.T) {
	cases := []struct {
		name    string
		network string
		want    string // "" means "don't care about exact value, just check length"
	}{
		{"short fits verbatim", "internal", "br-iso-internal"}, // 15 chars exactly
		{"e2e-net fits", "e2e-net", "br-iso-e2e-net"},
		{"9-char name is hashed", "e2e-rvnet", ""}, // br-iso-e2e-rvnet would be 16 → hashed
		{"long name is hashed", "a-very-long-isolated-network-name", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsolatedBridgeName(c.network)
			if len(got) > maxIfaceName {
				t.Fatalf("bridge name %q is %d chars, exceeds IFNAMSIZ limit %d", got, len(got), maxIfaceName)
			}
			if c.want != "" && got != c.want {
				t.Fatalf("IsolatedBridgeName(%q) = %q, want %q", c.network, got, c.want)
			}
			// Stable: same input → same output.
			if again := IsolatedBridgeName(c.network); again != got {
				t.Fatalf("not stable: %q then %q", got, again)
			}
		})
	}

	// Distinct long names must not collide on the 8-hex suffix.
	a := IsolatedBridgeName("tenant-alpha-isolated-net")
	b := IsolatedBridgeName("tenant-beta-isolated-net")
	if a == b {
		t.Fatalf("distinct long names collided: both %q", a)
	}
}
