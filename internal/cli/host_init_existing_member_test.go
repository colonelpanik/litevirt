package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `lv host init` rewrites the target's whole /etc/litevirt/config.yaml from the
// setup-script template, and the template writes `join_peers: ${JOIN_PEERS:-[]}`
// while host init sets no JOIN_PEERS. Pointed at a node that is already a
// cluster member, it therefore erases that node's peer list.
//
// That is worse than a gossip inconvenience. join_peers is also what tells the
// daemon it is JOINING rather than FOUNDING: a node with peers configured
// declines to mint an admin credential. Erasing the field puts the node back on
// the mint path, so a later state.db rebuild overwrites the cluster's admin
// password hash on every peer.

func TestHostInitPreflight_RefusesANodeThatAlreadyListsJoinPeers(t *testing.T) {
	cfg := []byte("host_name: \"node-2\"\njoin_peers:\n  - \"10.0.50.10:7946\"\n")

	err := refuseIfAlreadyAMember("root@10.0.50.11", cfg, false)
	if err == nil {
		t.Fatal("host init was allowed against a node that already has join_peers\n" +
			"its peer list would be erased, and with it the signal that stops the " +
			"node minting a fresh admin credential")
	}
	if !strings.Contains(err.Error(), "join_peers") {
		t.Errorf("the refusal does not name the field it is protecting: %v", err)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("the refusal does not tell the operator how to proceed anyway: %v", err)
	}
}

func TestHostInitPreflight_AllowsAFreshNodeWithNoConfig(t *testing.T) {
	if err := refuseIfAlreadyAMember("root@10.0.50.11", nil, false); err != nil {
		t.Fatalf("host init was refused against a node with no config at all: %v", err)
	}
}

// The founder legitimately carries an empty list, and re-running init against a
// half-finished first node is the normal repair. Neither is a member.
func TestHostInitPreflight_AllowsANodeWhoseJoinPeersIsEmpty(t *testing.T) {
	for _, cfg := range []string{
		"host_name: \"node-1\"\njoin_peers: []\n",
		"host_name: \"node-1\"\n",
	} {
		if err := refuseIfAlreadyAMember("root@10.0.50.10", []byte(cfg), false); err != nil {
			t.Errorf("refused a node with no peers configured (%q): %v", cfg, err)
		}
	}
}

func TestHostInitPreflight_ForceOverridesTheRefusal(t *testing.T) {
	cfg := []byte("join_peers:\n  - \"10.0.50.10:7946\"\n")

	if err := refuseIfAlreadyAMember("root@10.0.50.11", cfg, true); err != nil {
		t.Fatalf("--force did not override the refusal: %v", err)
	}
}

// A config that will not parse is not evidence that the node is fresh. host
// init is about to overwrite it, so "I could not read what I am replacing" is
// the moment to stop rather than the moment to guess.
func TestHostInitPreflight_RefusesAConfigItCannotParse(t *testing.T) {
	cfg := []byte("host_name: \"node-2\"\njoin_peers: [oh dear: : :\n")

	if err := refuseIfAlreadyAMember("root@10.0.50.11", cfg, false); err == nil {
		t.Fatal("an unparseable config was treated as proof the node is fresh")
	}
}

// ensureLocalPeer back-fills the ADDING node's own join_peers after `lv host
// add`. It is best-effort because `lv` legitimately runs from a workstation
// that is not a cluster node — but that is the only case that is benign. When
// this machine IS a node and the update fails, its seed list is now wrong and
// a slog.Warn is not enough, so the two have to be distinguishable.

func TestEnsureLocalPeer_AMissingConfigIsNotAFailedUpdate(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")

	err := ensureLocalPeer(cfgPath, "10.0.50.11", 7946)
	if !errors.Is(err, errNotALocalNode) {
		t.Fatalf("err = %v, want errNotALocalNode — a workstation with no daemon "+
			"config has nothing to update and must not read as a failed update", err)
	}
}

// A config that exists but cannot be READ is not a workstation either. Only
// os.ErrNotExist means "no daemon here"; collapsing every read failure into the
// sentinel hands back the quiet path for a node whose seed list is wrong.
func TestEnsureLocalPeer_AnUnreadableConfigIsNotAMissingOne(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("join_peers: []\n"), 0644); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if os.Getuid() == 0 {
		t.Skip("root ignores the file mode this test relies on")
	}
	if err := os.Chmod(cfgPath, 0000); err != nil {
		t.Fatalf("chmod config: %v", err)
	}

	err := ensureLocalPeer(cfgPath, "10.0.50.11", 7946)
	if err == nil {
		t.Fatal("an unreadable config reported a successful update")
	}
	if errors.Is(err, errNotALocalNode) {
		t.Errorf("a node whose config exists but could not be read was reported as "+
			"'not a node', which is the one classification callers may ignore: %v", err)
	}
}

func TestEnsureLocalPeer_AnUnwritableConfigIsAFailedUpdate(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("host_name: \"node-1\"\njoin_peers: []\n"), 0644); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if os.Getuid() == 0 {
		t.Skip("root ignores the file mode this test relies on")
	}
	// Readable, so the config still parses and the update gets as far as
	// writing — which is the failure this test is about.
	if err := os.Chmod(cfgPath, 0400); err != nil {
		t.Fatalf("chmod config: %v", err)
	}

	err := ensureLocalPeer(cfgPath, "10.0.50.11", 7946)
	if err == nil {
		t.Fatal("a config that could not be written reported a successful update")
	}
	if errors.Is(err, errNotALocalNode) {
		t.Errorf("a node whose config exists but could not be updated was reported "+
			"as 'not a node', which is the one classification that is allowed to be "+
			"ignored: %v", err)
	}
}

func TestEnsureLocalPeer_AppendsThePeerToAnExistingList(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("host_name: \"node-1\"\njoin_peers:\n  - \"10.0.50.10:7946\"\n"), 0644); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	if err := ensureLocalPeer(cfgPath, "10.0.50.11", 7946); err != nil {
		t.Fatalf("ensureLocalPeer: %v", err)
	}

	out, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	for _, want := range []string{"10.0.50.10:7946", "10.0.50.11:7946"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("config lost or never gained %q:\n%s", want, out)
		}
	}
}
