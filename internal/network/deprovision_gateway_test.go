package network

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

// Deprovision removes the gateway address StartDHCP put on the bridge. It built
// that argument by appending the subnet's prefix to SubnetRange's gateway — but
// SubnetRange already returns the gateway WITH its prefix (dnsmasq.go documents
// "10.0.1.128/25" -> gateway "10.0.1.129/25"), so the command carried the prefix
// twice. iproute2 rejects it, the error is discarded by the //nolint:errcheck,
// and the address stays on the bridge for good — including through
// SafeProvision's rollback, which calls this same function.
//
// The assertion parses the argument rather than string-matching it, so it pins
// "this is a valid CIDR" instead of one particular spelling of the bug.
func TestDeprovision_RemovesAWellFormedGatewayAddress(t *testing.T) {
	var addrDel []string
	execCommand = func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) >= 2 && args[0] == "addr" && args[1] == "del" {
			addrDel = append([]string{name}, args...)
		}
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	err := Deprovision(context.Background(), nil, "app", compose.NetworkDef{
		Type:      "bridge",
		Interface: "br-app",
		Subnet:    "10.0.1.0/24",
	}, "host-a")
	if err != nil {
		t.Fatalf("Deprovision: %v", err)
	}

	if addrDel == nil {
		t.Fatal("Deprovision issued no `ip addr del` for the DHCP gateway address")
	}
	// argv: ip addr del <addr> dev <bridge>
	if len(addrDel) < 4 {
		t.Fatalf("unexpected argv %v", addrDel)
	}
	addr := addrDel[3]
	if _, _, perr := net.ParseCIDR(addr); perr != nil {
		t.Fatalf("`ip addr del %s` is not a valid CIDR (%v) — iproute2 rejects it and the "+
			"gateway address is never removed; full argv: %v", addr, perr, addrDel)
	}
	if strings.Count(addr, "/") != 1 {
		t.Errorf("address %q carries %d prefixes, want exactly 1", addr, strings.Count(addr, "/"))
	}
	if addr != "10.0.1.1/24" {
		t.Errorf("address = %q, want 10.0.1.1/24", addr)
	}
}
