package cli

import (
	"strings"
	"testing"
)

// The setup script writes the daemon config. If it does not carry
// advertise_address, the node self-registers with getOutboundIP() — the
// default-route source IP, which is the wrong interface on a multi-homed host.
//
// That first wrong value is not cosmetic and does not stay local. `lv host add`
// builds the next node's join_peers from the cluster's recorded addresses, so a
// node registering wrong once puts a wrong gossip peer into the configuration of
// every host added after it. Both commands already KNOW the right address — init
// resolves it for the certificate SAN, add resolves it for the same reason — so
// there is no reason for the node to have to guess and be corrected later.

func TestSetupScript_WritesAdvertiseAddress(t *testing.T) {
	script, err := getSetupScript()
	if err != nil {
		t.Fatalf("getSetupScript: %v", err)
	}
	if !strings.Contains(script, "advertise_address") {
		t.Fatal("the generated daemon config has no advertise_address\n" +
			"the node then registers with its default-route source IP, and that value is " +
			"copied into the join_peers of every host added afterwards")
	}
	// It must be omitted rather than written empty when unknown: an empty string
	// would override the daemon's auto-detection with nothing.
	if !strings.Contains(script, "ADVERTISE_ADDRESS") {
		t.Error("advertise_address is hardcoded rather than taken from the address the " +
			"command already resolved")
	}
}

// TestSetupScript_OmitsAdvertiseAddressWhenUnknown guards the fallback: with no
// address to give, the config must not contain an empty advertise_address, which
// would suppress auto-detection instead of deferring to it.
func TestSetupScript_OmitsAdvertiseAddressWhenUnknown(t *testing.T) {
	got := renderAdvertiseLine("")
	if got != "" {
		t.Fatalf("with no address the config line is %q, want it omitted entirely\n"+
			"an empty advertise_address overrides auto-detection with nothing", got)
	}
	if line := renderAdvertiseLine("10.77.0.11"); !strings.Contains(line, "10.77.0.11") {
		t.Fatalf("a supplied address is not rendered into the config: %q", line)
	}
}

// TestSetupScriptEnv_CarriesTheAddress.
//
// --address goes into the certificate SAN and must also reach the daemon config.
// Without it the node auto-detects, registers with the wrong interface, and the
// correction only lands on a genuine RESTART — `lv host init --local` leaves the
// daemon running, so the operator's `systemctl start` is a no-op and the address
// stays wrong until something restarts it. Writing it up front removes the trap.
func TestSetupScriptEnv_CarriesTheAddress(t *testing.T) {
	env := setupScriptEnv("node-1", "10.77.0.11", "[]")
	if !hasEnv(env, "ADVERTISE_ADDRESS=10.77.0.11") {
		t.Fatalf("the setup environment does not carry the address: %v\n"+
			"the daemon then auto-detects and registers with its default-route source IP",
			env)
	}
	if !hasEnv(env, "HOST_NAME=node-1") || !hasEnv(env, "JOIN_PEERS=[]") {
		t.Errorf("the setup environment lost an existing key: %v", env)
	}
}

// TestSetupScriptEnv_EmptyAddressStaysEmpty — with nothing to advertise the value
// is empty, which is what makes the script omit the key and leave auto-detection
// in charge rather than overriding it with a blank.
func TestSetupScriptEnv_EmptyAddressStaysEmpty(t *testing.T) {
	if !hasEnv(setupScriptEnv("node-1", "", "[]"), "ADVERTISE_ADDRESS=") {
		t.Fatal("an absent address should produce an empty ADVERTISE_ADDRESS, which the " +
			"script omits entirely")
	}
}

func hasEnv(env []string, want string) bool {
	for _, e := range env {
		if e == want {
			return true
		}
	}
	return false
}
