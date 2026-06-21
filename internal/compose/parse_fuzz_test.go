package compose

import "testing"

// FuzzParseBytes confirms the YAML→File parser is panic-free on
// adversarial input. Validation errors are fine; panics or runaway
// goroutines are not. Run with `go test -run=^$ -fuzz=FuzzParseBytes
// ./internal/compose/`.
func FuzzParseBytes(f *testing.F) {
	seeds := []string{
		"",
		"vms: {}",
		"workloads:\n  a:\n    kind: vm\n",
		"vms:\n  vm1:\n    extends: vm0\n",
		"vms:\n  vm1: {cpu: -1}",
		"vms:\n  vm1:\n    network:\n      - {ipv6: '2001:db8::/64'}\n",
		"vms:\n  vm1:\n    depends_on: [self]\n",
		"vms: !!str invalid\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Bound size — the YAML parser allocates proportionally.
		if len(data) > 64*1024 {
			t.Skip()
		}
		_, _ = ParseBytes(data)
	})
}
