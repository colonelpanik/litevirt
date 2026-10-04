package grpcapi

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The VIP a peer is sent must be the REPAIRED one.
//
// UpdateLoadBalancer repairs the stored VIP for its own apply (ParseStoredVIP,
// which accepts a form an older Sscanf-era build persisted) and then forwarded
// the RAW stored string. ApplyLB parses with the strict ParseVIP and answers
// InvalidArgument, and the fan-out only logged it — so the coordinating host
// applied the update and every other holder silently kept its previous config.
// Backends added or removed never reached the standby holders, and a later VRRP
// failover served the pre-update backend set. It read as a successful update.
func TestVipForWire(t *testing.T) {
	for _, tc := range []struct {
		name, stored, want string
	}{
		{"legacy trailing field is repaired", "10.0.0.1/24/extra", "10.0.0.1/24"},
		{"well-formed value round-trips", "10.0.0.1/24", "10.0.0.1/24"},
		{"ipv6 round-trips", "fd00::1/64", "fd00::1/64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := vipForWire(tc.stored); got != tc.want {
				t.Errorf("vipForWire(%q) = %q, want %q", tc.stored, got, tc.want)
			}
		})
	}

	// Unrecoverable input is passed through rather than replaced with a guess,
	// so the peer's rejection names the value actually stored.
	if got := vipForWire("not-an-address"); got != "not-an-address" {
		t.Errorf("vipForWire on unrecoverable input = %q, want it passed through", got)
	}
}

// The wiring, not just the helper.
//
// A correct vipForWire that nothing calls is the bug over again, and the
// behavioural path is a detached goroutine behind a real peer dial — awkward to
// reach from a unit test. This reads the source instead, the way this repo's
// writecheck and stmtshapecheck guards already do: no ApplyLBRequest may carry a
// raw stored VIP.
func TestApplyLBRequests_SendNoRawStoredVIP(t *testing.T) {
	src, err := os.ReadFile("lb.go")
	if err != nil {
		t.Fatalf("read lb.go: %v", err)
	}
	// Every `Vip:` field set inside an ApplyLBRequest literal.
	re := regexp.MustCompile(`(?s)ApplyLBRequest\{.*?\}`)
	vipRe := regexp.MustCompile(`Vip:\s*([^,\n]+)`)
	var checked int
	for _, lit := range re.FindAllString(string(src), -1) {
		m := vipRe.FindStringSubmatch(lit)
		if m == nil {
			continue
		}
		checked++
		expr := strings.TrimSpace(m[1])
		// req.Vip is ingress-validated by the strict parser before it is stored,
		// so it is already in the tightened form.
		if expr == "req.Vip" || strings.HasPrefix(expr, "vipForWire(") {
			continue
		}
		t.Errorf("ApplyLBRequest sends Vip: %s — a stored VIP must go through vipForWire(), "+
			"or a legacy value is applied locally and refused by every peer", expr)
	}
	if checked == 0 {
		t.Fatal("found no ApplyLBRequest literal with a Vip field; this guard is not looking " +
			"at what it thinks it is")
	}
}
