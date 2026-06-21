package lb

import (
	"testing"

	"github.com/litevirt/litevirt/internal/testkit/golden"
)

// Golden-file coverage for the four LB renderers (haproxy, keepalived,
// conntrackd, notify-script). Update with `go test./internal/lb/
// -run TestLBRenderGolden -update`.
func TestLBRenderGolden(t *testing.T) {
	tcp := Config{
		Name:      "app",
		VIP:       "10.0.100.100",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      42,
		Priority:  100,
		Algorithm: "roundrobin",
		Backends: []Backend{
			{Name: "vm-a", IP: "10.0.100.10", Port: 8080},
			{Name: "vm-b", IP: "10.0.100.11", Port: 8080},
		},
		Ports: []Port{
			{Listen: 80, Target: 8080, Protocol: "tcp"},
		},
	}
	tls := Config{
		Name:      "https",
		VIP:       "10.0.100.101",
		VIPPrefix: 24,
		Interface: "eth0",
		VRID:      43,
		Priority:  50,
		Algorithm: "leastconn",
		Health:    &HealthConfig{Type: "http", Path: "/healthz", IntervalMS: 1500},
		Backends: []Backend{
			{Name: "web1", IP: "10.0.100.20", Port: 8443},
		},
		Ports: []Port{
			{Listen: 443, Target: 8443, Protocol: "http", TLS: &TLSConfig{
				Cert: "/etc/litevirt/lb/https.crt",
				Key:  "/etc/litevirt/lb/https.key",
			}},
		},
	}
	snat := Config{
		Name:        "egress",
		VIP:         "10.0.100.1",
		VIPPrefix:   24,
		Interface:   "eth0",
		VRID:        44,
		Priority:    100,
		Algorithm:   "roundrobin",
		SNATEnabled: true,
		LocalIP:     "10.0.100.2",
		PeerIP:      "10.0.100.3",
		Subnet:      "10.99.0.0/24",
		Ports:       []Port{{Listen: 80, Target: 80, Protocol: "tcp"}},
		Backends:    []Backend{{Name: "vm-z", IP: "10.99.0.10", Port: 80}},
	}

	t.Run("haproxy_tcp", func(t *testing.T) {
		got, err := RenderHAProxy(tcp)
		if err != nil {
			t.Fatalf("RenderHAProxy: %v", err)
		}
		golden.Assert(t, "testdata/haproxy_tcp.golden", got)
	})
	t.Run("haproxy_https_tls", func(t *testing.T) {
		got, err := RenderHAProxy(tls)
		if err != nil {
			t.Fatalf("RenderHAProxy: %v", err)
		}
		golden.Assert(t, "testdata/haproxy_https_tls.golden", got)
	})
	t.Run("keepalived_master", func(t *testing.T) {
		got, err := RenderKeepalived(tcp)
		if err != nil {
			t.Fatalf("RenderKeepalived: %v", err)
		}
		golden.Assert(t, "testdata/keepalived_master.golden", got)
	})
	t.Run("keepalived_snat", func(t *testing.T) {
		got, err := RenderKeepalived(snat)
		if err != nil {
			t.Fatalf("RenderKeepalived: %v", err)
		}
		golden.Assert(t, "testdata/keepalived_snat.golden", got)
	})
	t.Run("conntrackd_snat", func(t *testing.T) {
		got, err := RenderConntrackd(snat)
		if err != nil {
			t.Fatalf("RenderConntrackd: %v", err)
		}
		golden.Assert(t, "testdata/conntrackd_snat.golden", got)
	})
	t.Run("notify_script", func(t *testing.T) {
		got, err := RenderNotifyScript(snat)
		if err != nil {
			t.Fatalf("RenderNotifyScript: %v", err)
		}
		golden.Assert(t, "testdata/notify_snat.golden", got)
	})
}
