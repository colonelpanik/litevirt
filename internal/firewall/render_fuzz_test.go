package firewall

import (
	"strings"
	"testing"
)

// FuzzFromCorrosionRule drives the string-typed rule constructor used
// when reading sg_rules out of Corrosion. Property: (1) never panics,
// (2) the returned Rule never references an unknown CIDR set token
// without the `@` sigil being preserved verbatim.
func FuzzFromCorrosionRule(f *testing.F) {
	type seed struct{ dir, proto, port, cidr, action string }
	seeds := []seed{
		{"ingress", "tcp", "22", "10.0.0.0/24", "accept"},
		{"egress", "udp", "53", "0.0.0.0/0", "drop"},
		{"INGRESS", "ICMP", "", "@trusted", "reject"},
		{"", "", "", "", ""},
		{"egress", "all", "8000-9000", "@web-trusted-set", "accept"},
	}
	for _, s := range seeds {
		f.Add(s.dir, s.proto, s.port, s.cidr, s.action)
	}
	f.Fuzz(func(t *testing.T, dir, proto, port, cidr, action string) {
		// Bound to keep the table renderer cheap.
		if len(dir)+len(proto)+len(port)+len(cidr)+len(action) > 256 {
			t.Skip()
		}
		r := FromCorrosionRule(dir, proto, port, cidr, action)
		// IPset reference sigil must round-trip.
		if strings.HasPrefix(cidr, "@") && r.CIDR != cidr {
			t.Fatalf("ipset cidr mangled: in=%q out=%q", cidr, r.CIDR)
		}
	})
}

// FuzzRender drives the renderer with structured but adversarial Plans
// built from fuzz bytes. Property: Render never panics; if it returns
// an error the output must be empty.
func FuzzRender(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint8(0))
	f.Add(uint8(3), uint8(2), uint8(1))
	f.Add(uint8(7), uint8(7), uint8(7))
	f.Fuzz(func(t *testing.T, ruleSeed, sgSeed, nicSeed uint8) {
		// Cap structural growth so the fuzzer can't OOM.
		nRules := int(ruleSeed%6) + 1
		nSGs := int(sgSeed % 4)
		nNICs := int(nicSeed % 4)

		mkRule := func(i int) Rule {
			r := Rule{
				Direction: Ingress,
				Proto:     "tcp",
				PortRange: "80",
				Action:    Accept,
			}
			if i&1 == 1 {
				r.Direction = Egress
			}
			if i&2 == 2 {
				r.Proto = "udp"
			}
			if i&4 == 4 {
				r.Action = Drop
			}
			return r
		}

		plan := Plan{DefaultDeny: ruleSeed&1 == 1}
		for i := 0; i < nRules; i++ {
			plan.ClusterRules = append(plan.ClusterRules, mkRule(i))
		}
		for i := 0; i < nSGs; i++ {
			plan.SecurityGroups = append(plan.SecurityGroups, SecurityGroup{
				Name:  "sg" + string(rune('a'+i)),
				Rules: []Rule{mkRule(i + 1)},
			})
		}
		for i := 0; i < nNICs; i++ {
			binding := NICBinding{
				NICDev: "tap" + string(rune('a'+i)),
				VMName: "vm" + string(rune('a'+i)),
			}
			if nSGs > 0 {
				binding.SecurityGroups = []string{"sg" + string(rune('a'+(i%nSGs)))}
			}
			plan.NICs = append(plan.NICs, binding)
		}

		out, err := Render(plan)
		if err != nil {
			if out != "" {
				t.Fatalf("Render returned error AND non-empty output: %q", out)
			}
			return
		}
		// Successful renders must contain the table header — sanity
		// check that Render didn't return an absurd partial.
		if !strings.Contains(out, "table inet "+TableName) {
			t.Fatalf("Render output missing table header:\n%s", out)
		}
	})
}
