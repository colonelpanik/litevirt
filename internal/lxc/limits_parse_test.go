package lxc

import (
	"fmt"
	"math"
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

// TestParseResourceConfig_CeilingArithmeticCannotOverflow pins the arithmetic
// itself. The ceiling was computed as (quota*100 + period - 1) / period, and the
// only guard was on quota*100 — so a quota that passes the guard can still
// overflow int64 when the period is added, and the wrapped negative numerator
// divides back into a plausible-looking answer:
//
//	quota 92233720368547758, period MaxInt64 -> numerator wraps to -10 -> 0
//	quota 92233720368547758, period 9        -> numerator wraps      -> -1024819115206086200
//
// Zero is the codebase's UNLIMITED sentinel, so the first form turns a
// malformed root-written cap into "no cap at all"; the second yields a negative
// limit that is not a cap in any sense. Both must error instead. The guard is
// stated as a property, not a list: no (quota, period) pair may produce a
// non-positive or wrapped limit while reporting success.
func TestParseResourceConfig_CeilingArithmeticCannotOverflow(t *testing.T) {
	const nearMax = math.MaxInt64 / 100 // the largest quota the multiplication guard admits

	// Pairs whose true ratio exceeds what the limit can represent must error,
	// rather than wrap into a negative or divide down to the sentinel.
	overflowing := []struct{ name, cfg string }{
		{"add overflows to a negative limit", "lxc.cgroup2.cpu.max = 92233720368547758 9\n"},
		{"largest admitted quota, smallest period", "lxc.cgroup2.cpu.max = 92233720368547758 1\n"},
		{"ordinary period, quota just under the guard", "lxc.cgroup2.cpu.max = 92233720368547757 100000\n"},
	}
	for _, c := range overflowing {
		cpu, _, err := parseResourceConfig(c.cfg)
		if err == nil {
			t.Errorf("%s: parsed cpu=%d without error — an unrepresentable limit must fail loudly, "+
				"never land on 0 (which reads as UNLIMITED) or a negative", c.name, cpu)
		}
	}

	// The counterpart: a pair whose ratio IS representable must be computed,
	// not rejected. The old expression wrapped this one to a numerator of -10
	// and reported 0 (unlimited); the true ceiling of 9223372036854775800 over
	// MaxInt64 is 1, and 1 is what a correct ceiling returns.
	if cpu, _, err := parseResourceConfig("lxc.cgroup2.cpu.max = 92233720368547758 9223372036854775807\n"); err != nil || cpu != 1 {
		t.Errorf("largest admitted quota over the largest period: cpu=%d err=%v, want 1/nil", cpu, err)
	}

	// The property, swept over every period that divides the extremes plus a
	// spread of ordinary ones: success implies a strictly positive limit.
	periods := []int{1, 2, 9, 7919, 100000, 1 << 20, math.MaxInt32, math.MaxInt64}
	quotas := []int{1, 500, 2000, 25000, nearMax - 1, nearMax}
	for _, q := range quotas {
		for _, p := range periods {
			cfg := fmt.Sprintf("lxc.cgroup2.cpu.max = %d %d\n", q, p)
			cpu, _, err := parseResourceConfig(cfg)
			if err != nil {
				continue // rejecting an unrepresentable pair is the correct outcome
			}
			if cpu <= 0 {
				t.Errorf("quota=%d period=%d: parsed cpu=%d with no error — a positive quota must yield a "+
					"positive limit or an error, never the unlimited sentinel", q, p, cpu)
			}
		}
	}
}

// TestParseResourceConfig_ZeroQuotaAndMaxPeriodValidation covers the two ways a
// malformed cpu.max still read as unlimited:
//
//   - a zero quota passed the "negative" guard and divided down to 0, i.e. the
//     UNLIMITED sentinel, for a value the kernel itself rejects (it enforces a
//     minimum bandwidth);
//   - "max" returned before the period was ever parsed, so "max 0", "max -1"
//     and "max banana" were accepted as unlimited even though the commit's
//     stated contract is that a non-positive period is rejected. The period is
//     part of the line's validity whatever the quota says.
func TestParseResourceConfig_ZeroQuotaAndMaxPeriodValidation(t *testing.T) {
	errCases := []struct{ name, cfg string }{
		{"zero quota with explicit period", "lxc.cgroup2.cpu.max = 0 100000\n"},
		{"zero quota with default period", "lxc.cgroup2.cpu.max = 0\n"},
		{"max with zero period", "lxc.cgroup2.cpu.max = max 0\n"},
		{"max with negative period", "lxc.cgroup2.cpu.max = max -1\n"},
		{"max with unparseable period", "lxc.cgroup2.cpu.max = max banana\n"},
	}
	for _, c := range errCases {
		cpu, _, err := parseResourceConfig(c.cfg)
		if err == nil {
			t.Errorf("%s: parsed cpu=%d without error — a malformed cpu.max must fail loudly, "+
				"not read as unlimited", c.name, cpu)
		}
	}

	// "max" with a VALID period, and bare "max", remain unlimited.
	for _, cfg := range []string{"lxc.cgroup2.cpu.max = max\n", "lxc.cgroup2.cpu.max = max 100000\n"} {
		cpu, _, err := parseResourceConfig(cfg)
		if err != nil || cpu != 0 {
			t.Errorf("%q: cpu=%d err=%v, want 0/nil — a well-formed max is still unlimited", cfg, cpu, err)
		}
	}
}
