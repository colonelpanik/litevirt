package lb

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ClaimsVIP must detect a VRRP PARTICIPANT by its rendered keepalived config even when it
// holds NO kernel address — a backup. This is the by-VIP ownership signal a kernel-address
// check alone would miss (the recurring Phase-2 bug). A config match short-circuits true
// WITHOUT touching the kernel (so this stays deterministic without `ip`).
func TestClaimsVIP_ParticipantWithoutAddress(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{configDir: dir, runDir: t.TempDir()}
	cfg := Config{
		Name: "app", VIP: "10.0.100.100", VIPPrefix: 24, Interface: "eth0", VRID: 51, Priority: 100,
		Ports:    []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []Backend{{Name: "vm1", IP: "10.0.0.5", Port: 8080}},
	}
	rendered, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app-keepalived.conf"), []byte(rendered), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// A backup renders the config but has no address assigned; ClaimsVIP must still see it.
	if claims, err := m.ClaimsVIP("10.0.100.100"); err != nil || !claims {
		t.Fatalf("ClaimsVIP(participant) = %v,%v; want true,nil (a backup holds no kernel address)", claims, err)
	}
	if claims, err := m.ClaimsVIP("10.0.100.100/24"); err != nil || !claims {
		t.Fatalf("ClaimsVIP(CIDR-form participant) = %v,%v; want true,nil", claims, err)
	}
}

// ClaimsVIP must FAIL CLOSED when a keepalived config can't be parsed: its VIP is unknown,
// so it might render the queried one — returning "not claiming" would be a false negative
// that lets a fresh claim overlap it. (Parse failure is checked before the kernel probe,
// so this is deterministic without `ip`.)
func TestClaimsVIP_UnparseableConfigFailsClosed(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{configDir: dir, runDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(dir, "junk-keepalived.conf"), []byte("garbage { no vip here }\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := m.ClaimsVIP("10.0.100.200"); err == nil {
		t.Fatal("an unparseable keepalived config must make ClaimsVIP fail closed (error), not return not-claiming")
	}
}

// DemoteAll's fail-closed orphan sweep must NOT false-fire on a clean host: with no
// rendered configs AND no litevirt-owned keepalived, there was nothing to stand down, so
// it reports held=false with no error. Deterministic because a FRESH temp configDir can't
// appear in any running process's cmdline, so litevirtKeepalivedPids is empty — and,
// crucially, an UNRELATED system keepalived (a different config dir) is never matched.
func TestDemoteAll_NoConfigsNoOrphan(t *testing.T) {
	m := &Manager{configDir: t.TempDir(), runDir: t.TempDir()}
	if pids := litevirtKeepalivedPids(m.configDir); len(pids) != 0 {
		t.Fatalf("a fresh temp configDir must own no keepalived; got %v", pids)
	}
	held, err := m.DemoteAll(time.Second)
	if held || err != nil {
		t.Fatalf("no configs + no litevirt keepalived → want held=false,nil; got held=%v err=%v", held, err)
	}
}

// parseKeepalivedVIP must recover the EXACT tuple keepalived was rendered with — the
// interface directive and the virtual_ipaddress entry — so demotion deletes what was
// actually assigned (not a recomputed interface).
func TestParseKeepalivedVIP_RoundTrip(t *testing.T) {
	cfg := Config{
		Name: "app", VIP: "10.0.100.100", VIPPrefix: 24, Interface: "eth0",
		VRID: 51, Priority: 100,
		Ports:    []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []Backend{{Name: "vm1", IP: "10.0.0.5", Port: 8080}},
	}
	rendered, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}
	vip, prefix, iface, ok := parseKeepalivedVIP(rendered)
	if !ok || vip != "10.0.100.100" || prefix != 24 || iface != "eth0" {
		t.Fatalf("parse = %q/%d dev %q ok=%v; want 10.0.100.100/24 dev eth0", vip, prefix, iface, ok)
	}
}

func TestParseKeepalivedVIP_Malformed(t *testing.T) {
	if _, _, _, ok := parseKeepalivedVIP("something {\n no vip here \n}"); ok {
		t.Fatal("a config with no interface/VIP must return ok=false (fail closed)")
	}
}

// vipDelAddr must use the stored prefix, and default a zero/absent prefix to a host
// route (/32 IPv4, /128 IPv6) — never /0, which would delete the whole subnet.
func TestVIPDelAddr(t *testing.T) {
	cases := []struct {
		vip    string
		prefix int
		want   string
	}{
		{"10.0.100.5", 24, "10.0.100.5/24"},
		{"10.0.100.5", 0, "10.0.100.5/32"},  // v4 default
		{"10.0.100.5", -1, "10.0.100.5/32"}, // negative → default
		{"fd00::5", 0, "fd00::5/128"},       // v6 default
		{"fd00::5", 64, "fd00::5/64"},       // v6 explicit
	}
	for _, c := range cases {
		if got := vipDelAddr(c.vip, c.prefix); got != c.want {
			t.Errorf("vipDelAddr(%q,%d) = %q, want %q", c.vip, c.prefix, got, c.want)
		}
	}
}

// addrShowHasVIP parses `ip -o addr show` output and matches the bare VIP.
func TestAddrShowHasVIP(t *testing.T) {
	out := `2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.100.100/32 scope global eth0\       valid_lft forever preferred_lft forever
2: eth0    inet6 fe80::1/64 scope link \       valid_lft forever preferred_lft forever`
	if !addrShowHasVIP(out, "10.0.100.100") {
		t.Error("should find the assigned VIP 10.0.100.100")
	}
	// A CIDR-form query (lbSpec.Vip is usually "<ip>/<prefix>") must still match the
	// kernel's bare address — the High-1 review-3 bug.
	if !addrShowHasVIP(out, "10.0.100.100/24") {
		t.Error("CIDR-form VIP query must match the assigned bare address")
	}
	if addrShowHasVIP(out, "10.0.100.101") {
		t.Error("must not match an unassigned VIP")
	}
	// The base IP is present but not the VIP — must not false-match on a substring.
	if addrShowHasVIP(out, "10.0.0.55") {
		t.Error("must not substring-match")
	}
}
