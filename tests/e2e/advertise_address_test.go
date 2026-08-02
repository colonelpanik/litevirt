package e2e

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// advertise_address decides what every other node dials to reach this one.
//
// Before it existed, the address was auto-detected by two DIFFERENT heuristics —
// default-route source IP for the host record, first private IP by interface
// enumeration order for gossip — which can disagree with each other and with
// reality. The failure is silent and total: on a multi-homed or NAT'd host every
// node derives the same wrong address, each dials itself, gossip looks healthy,
// and the cluster never converges. Nothing about it looks like an addressing bug.
//
// The unit/fleet tiers can check that a configured value is plumbed through.
// What they cannot check is the property that actually matters — that the
// address a host PUBLISHES is one its peers can really reach. That needs real
// hosts on a real network, so it lives here.

// hostRecordAddress returns the address the cluster has recorded for a host.
func hostRecordAddress(t *testing.T, host string) string {
	t.Helper()
	for _, line := range strings.Split(lv(t, "host", "ls"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == host {
			return f[1]
		}
	}
	t.Fatalf("host %q not present in `lv host ls`", host)
	return ""
}

// TestCluster_AdvertisedAddressesAreReachable is the regression guard: every
// host's PUBLISHED address must actually accept a gRPC connection. A host
// advertising an address nobody can dial is the exact shape of the bug, and it
// is invisible to `lv host ls`, which happily prints the wrong one.
func TestCluster_AdvertisedAddressesAreReachable(t *testing.T) {
	requireHosts(t, 2)

	for _, h := range hostNames {
		addr := hostRecordAddress(t, h)
		if addr == "" {
			t.Errorf("host %s has no recorded address", h)
			continue
		}
		// 7443 is the gRPC port every peer dials. We only need the TCP handshake:
		// proving reachability, not doing an authenticated RPC.
		target := net.JoinHostPort(addr, "7443")
		conn, err := net.DialTimeout("tcp", target, 10*time.Second)
		if err != nil {
			t.Errorf("host %s advertises %s but it is not reachable from %s: %v — peers cannot dial this node, and gossip will still look healthy",
				h, target, localHost, err)
			continue
		}
		_ = conn.Close()
	}
}

// TestCluster_AdvertisedAddressesAreDistinct catches the specific way the bug
// manifests in a NAT'd lab: auto-detection returns the SAME address on every
// node, so each one dials itself, every node looks up, and the cluster silently
// never converges.
func TestCluster_AdvertisedAddressesAreDistinct(t *testing.T) {
	requireHosts(t, 2)

	seen := map[string]string{}
	for _, h := range hostNames {
		addr := hostRecordAddress(t, h)
		if prev, dup := seen[addr]; dup {
			t.Errorf("hosts %s and %s both advertise %s — each will dial itself and the cluster cannot converge",
				prev, h, addr)
			continue
		}
		seen[addr] = h
	}
}

// TestHost_AdvertiseAddressIsHonoured: where we can read the local daemon's
// config, an explicitly configured advertise_address must be exactly what the
// cluster records. Auto-detection overriding an explicit setting is how a
// multi-homed host ends up publishing the wrong interface.
func TestHost_AdvertiseAddressIsHonoured(t *testing.T) {
	requireHosts(t, 1)
	if !localMode {
		t.Skip("needs the local daemon config; run this suite on a cluster node")
	}
	cfg, err := os.ReadFile("/etc/litevirt/config.yaml")
	if err != nil {
		t.Skipf("cannot read the local daemon config: %v", err)
	}
	want := ""
	for _, line := range strings.Split(string(cfg), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == "advertise_address" {
			want = strings.Trim(strings.TrimSpace(v), `"'`)
			break
		}
	}
	if want == "" {
		t.Skip("no advertise_address configured on this node (auto-detection in use)")
	}
	if got := hostRecordAddress(t, localHost); got != want {
		t.Errorf("configured advertise_address=%s but the cluster records %s for %s — the explicit setting was overridden by auto-detection",
			want, got, localHost)
	}
	fmt.Fprintf(os.Stderr, "advertise_address honoured on %s: %s\n", localHost, want)
}
