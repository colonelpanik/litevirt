package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// evalEnvPrefix runs the rendered prefix through a real /bin/sh the way sshd
// does, and reports what the named variable actually arrived as.
//
// Asserting on the rendered STRING cannot settle this: `$(...)` inside single
// quotes is inert, so a correct fix and a broken one differ only in quoting a
// textual check has to re-implement a shell to judge. Running the shell is the
// test.
func evalEnvPrefix(t *testing.T, env []string, name string) string {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", shellEnvPrefix(env)+" printenv "+name)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("sh rejected the rendered prefix (%q): %v", shellEnvPrefix(env), err)
	}
	return strings.TrimRight(string(out), "\n")
}

// TestShellEnvPrefix_NoCommandSubstitution is the root-shell injection in
// `lv host add`.
//
// The remote path joins setupScriptEnv into ONE command line and hands it to
// session.Run, an SSH exec request that sshd runs through the login shell.
// Assignment words undergo command substitution there, and JOIN_PEERS is built
// from hosts.address — a replicated, peer-writable column that nothing
// validates as an IP. A node writing `$(...)` into a peer's address therefore
// executed as root on every host added afterwards, before the daemon, PKI or
// systemd units existed.
func TestShellEnvPrefix_NoCommandSubstitution(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "pwned")
	payload := `["$(touch ` + canary + `):7946"]`

	got := evalEnvPrefix(t, []string{"JOIN_PEERS=" + payload}, "JOIN_PEERS")

	if _, err := os.Stat(canary); err == nil {
		t.Fatalf("the shell EXECUTED the payload: %s exists", canary)
	}
	if got != payload {
		t.Fatalf("JOIN_PEERS arrived as %q, want the literal %q", got, payload)
	}
}

// Backticks are the other substitution form.
func TestShellEnvPrefix_NoBacktickSubstitution(t *testing.T) {
	canary := filepath.Join(t.TempDir(), "pwned")
	payload := "10.0.0.1`touch " + canary + "`"

	got := evalEnvPrefix(t, []string{"ADVERTISE_ADDRESS=" + payload}, "ADVERTISE_ADDRESS")

	if _, err := os.Stat(canary); err == nil {
		t.Fatalf("the shell EXECUTED the backtick payload: %s exists", canary)
	}
	if got != payload {
		t.Fatalf("ADVERTISE_ADDRESS arrived as %q, want the literal %q", got, payload)
	}
}

// An embedded single quote must not break out of its own word.
func TestShellEnvPrefix_SurvivesEmbeddedQuote(t *testing.T) {
	payload := `a'b; touch /tmp/should-not-exist; echo '`
	if got := evalEnvPrefix(t, []string{"HOST_NAME=" + payload}, "HOST_NAME"); got != payload {
		t.Fatalf("HOST_NAME arrived as %q, want the literal %q", got, payload)
	}
}

// The ordinary values must still arrive intact — a fix that mangles them breaks
// every host add rather than only the malicious one.
func TestShellEnvPrefix_PreservesOrdinaryValues(t *testing.T) {
	env := setupScriptEnv("node-9", "10.0.0.9", `["10.0.0.1:7946"]`)
	if got := evalEnvPrefix(t, env, "ADVERTISE_ADDRESS"); got != "10.0.0.9" {
		t.Errorf("ADVERTISE_ADDRESS = %q, want 10.0.0.9", got)
	}
	if got := evalEnvPrefix(t, env, "JOIN_PEERS"); got != `["10.0.0.1:7946"]` {
		t.Errorf("JOIN_PEERS = %q, want the literal peer list", got)
	}
	if got := evalEnvPrefix(t, env, "HOST_NAME"); got != "node-9" {
		t.Errorf("HOST_NAME = %q, want node-9", got)
	}
}
