package lxc

import (
	"strings"
	"testing"
)

// parseResourceConfig inverts litevirt's own ResourceConfig emission — but the
// config file is root-editable, and cgroup2 accepts forms litevirt never
// writes. A hand-written raw-bytes memory.max was read as MiB (a 256 MiB cap
// became a 268435456 MiB charge — conservative, but absurd), and cgroup2's
// "max" (unlimited) failed the whole parse instead of reading as unlimited.
func TestParseResourceConfig_CgroupNativeForms(t *testing.T) {
	cases := []struct {
		name    string
		cfg     string
		wantCPU int
		wantMem int
		wantErr bool
	}{
		{"litevirt round-trip", ResourceConfig(2, 512), 2, 512, false},
		{"raw bytes are bytes", "lxc.cgroup2.memory.max = 268435456\n", 0, 256, false},
		{"bytes round up", "lxc.cgroup2.memory.max = 268435457\n", 0, 257, false},
		{"unlimited memory", "lxc.cgroup2.memory.max = max\n", 0, 0, false},
		{"unlimited cpu", "lxc.cgroup2.cpu.max = max 100000\n", 0, 0, false},
		{"bare unlimited cpu", "lxc.cgroup2.cpu.max = max\n", 0, 0, false},
		{"gigabyte suffix", "lxc.cgroup2.memory.max = 1G\n", 0, 1024, false},
		{"lowercase suffix", "lxc.cgroup2.memory.max = 512m\n", 0, 512, false},
		{"kilobyte suffix", "lxc.cgroup2.memory.max = 2048K\n", 0, 2, false},
		{"custom period same ratio", "lxc.cgroup2.cpu.max = 25000 50000\n", 50, 0, false},
		{"default period when absent", "lxc.cgroup2.cpu.max = 2000\n", 2, 0, false},
		{"garbage memory still errors", "lxc.cgroup2.memory.max = banana\n", 0, 0, true},
		{"garbage cpu still errors", "lxc.cgroup2.cpu.max = banana 100000\n", 0, 0, true},
	}
	for _, c := range cases {
		cpu, mem, err := parseResourceConfig(c.cfg)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: parsed (%d,%d), want error", c.name, cpu, mem)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if cpu != c.wantCPU || mem != c.wantMem {
			t.Errorf("%s: got cpu=%d mem=%d, want %d/%d", c.name, cpu, mem, c.wantCPU, c.wantMem)
		}
	}
}

// TestParseResourceConfig_RejectsAndGuardsBadInput pins the validation the
// review flagged: negatives, overflow, and a non-positive period must error
// loudly (the commit's stated contract) rather than silently yield a negative,
// zero, or falsely-unlimited cap; and a sub-1%-of-a-core CPU cap must round UP
// to a nonzero limit, never truncate to 0 (which reads as unlimited).
func TestParseResourceConfig_RejectsAndGuardsBadInput(t *testing.T) {
	errCases := []struct{ name, cfg string }{
		{"negative bare memory", "lxc.cgroup2.memory.max = -256\n"},
		{"negative suffixed memory", "lxc.cgroup2.memory.max = -256M\n"},
		{"memory suffix overflow", "lxc.cgroup2.memory.max = 9000000T\n"},
		{"memory bare overflow", "lxc.cgroup2.memory.max = 9223372036854775807\n"},
		{"negative cpu quota", "lxc.cgroup2.cpu.max = -1000 100000\n"},
		{"cpu quota overflow", "lxc.cgroup2.cpu.max = 92233720368547760 100000\n"},
		{"zero period", "lxc.cgroup2.cpu.max = 25000 0\n"},
		{"negative period", "lxc.cgroup2.cpu.max = 25000 -1\n"},
	}
	for _, c := range errCases {
		if _, _, err := parseResourceConfig(c.cfg); err == nil {
			t.Errorf("%s: parsed without error, want error — bad input must fail loudly, not yield a silent cap", c.name)
		}
	}

	// The zero/negative-period error message must name the real reason, not "<nil>".
	if _, _, err := parseResourceConfig("lxc.cgroup2.cpu.max = 25000 0\n"); err != nil {
		if strings.Contains(err.Error(), "<nil>") {
			t.Errorf("period error message leaks <nil>: %v", err)
		}
	}

	okCases := []struct {
		name    string
		cfg     string
		wantCPU int
	}{
		{"sub-1% CPU cap rounds up to 1, not 0/unlimited", "lxc.cgroup2.cpu.max = 500 100000\n", 1},
		{"tiny fractional CPU cap rounds up to 1", "lxc.cgroup2.cpu.max = 1 100000\n", 1},
		{"litevirt 2-core emission still round-trips", "lxc.cgroup2.cpu.max = 2000 100000\n", 2},
		{"custom-period ratio preserved", "lxc.cgroup2.cpu.max = 25000 50000\n", 50},
	}
	for _, c := range okCases {
		cpu, _, err := parseResourceConfig(c.cfg)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if cpu != c.wantCPU {
			t.Errorf("%s: cpu=%d, want %d", c.name, cpu, c.wantCPU)
		}
	}
}
