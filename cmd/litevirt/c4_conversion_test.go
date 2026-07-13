package main

import (
	"path/filepath"
	"testing"
)

// TestE2E_BackupCreate exercises `backup create`, which streams BackupVM into a
// file. It needs a writable output path, so it can't live in the static table.
// The fake BackupVM stream yields EOF immediately → an empty file + a
// "Backup complete" summary, proving the withClient closure wrapping the
// file-create + stream-consume body preserved behavior.
func TestE2E_BackupCreate(t *testing.T) {
	mock := newMockClient()
	out := filepath.Join(t.TempDir(), "web-1.qcow2")
	stdout, stderr, err := runCmd(t, mock, "backup", "create", "web-1", "--out", out)
	if err != nil {
		t.Fatalf("backup create errored: %v (stderr=%s)", err, stderr)
	}
	assertContains(t, stdout, "Backup complete")
}

// C4 refactor verification: every command converted to the withClient helper
// must still run end-to-end through the real root command against the mock
// client (cli.Connect override) and produce its expected output. This proves
// the closure wrapping preserved behavior — the whole point of the refactor.
//
// runCmd (e2e_test.go) overrides cli.Connect, builds the real root command,
// executes, and captures stdout. A nil-deref or broken closure surfaces as a
// non-nil err or a panic here.
func TestC4_ConvertedCommandsRun(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string // substring expected in stdout ("" = just assert no error)
	}{
		// pool.go
		{"pool ls", []string{"pool", "ls"}, ""},
		{"pool create", []string{"pool", "create", "p1", "--driver", "dir", "--target", "/x"}, "created"},
		{"pool inspect", []string{"pool", "inspect", "p1"}, "Name:"},
		{"pool delete", []string{"pool", "delete", "p1"}, "deleted"},
		// project.go
		{"project ls", []string{"project", "ls"}, ""},
		{"project create", []string{"project", "create", "/acme"}, "created"},
		{"project rm", []string{"project", "rm", "/acme"}, "removed"},
		{"project quota", []string{"project", "quota", "/acme", "--vcpu", "4"}, "vCPU limit"},
		{"project usage", []string{"project", "usage", "/acme"}, "vCPU used"},
		// role.go
		{"role ls", []string{"role", "ls"}, ""},
		{"role grant", []string{"role", "grant", "Admin", "user:alice", "--path", "/"}, "granted"},
		{"role revoke", []string{"role", "revoke", "b1"}, "revoked"},
		// audit.go
		{"audit ls", []string{"audit", "ls"}, ""},
		{"audit verify", []string{"audit", "verify"}, "audit chain intact"},
		{"audit export", []string{"audit", "export"}, "rows"},
		// rebalance.go
		{"rebalance list", []string{"rebalance", "list"}, "no proposals"},
		{"rebalance run", []string{"rebalance", "run"}, "Emitted"},
		{"rebalance approve", []string{"rebalance", "approve", "p1"}, "approved"},
		{"rebalance reject", []string{"rebalance", "reject", "p1"}, "rejected"},
		// status.go
		{"status", []string{"status"}, ""},
		// cluster.go
		{"cluster digest", []string{"cluster", "digest"}, ""},
		{"cluster converge", []string{"cluster", "converge"}, "Anti-entropy pass"},
		{"cluster sync", []string{"cluster", "sync"}, "Anti-entropy pass"}, // deprecated alias of converge
		// firewall.go
		{"firewall reload", []string{"firewall", "reload"}, "Reloaded"},
		// rebuild.go
		{"rebuild", []string{"rebuild", "vm1"}, "rebuilt"},
		{"cutover", []string{"cutover", "vm1"}, "Cutover complete"},
		// uninstall.go
		{"uninstall", []string{"uninstall", "host1", "--confirmed"}, "removed from"},
		// spice.go
		{"spice", []string{"spice", "vm1"}, "URI:"},
		// vmconfig.go
		{"config boot", []string{"config", "vm1", "--boot", "disk"}, "boot order set"},
		// snapshot.go
		{"snapshot create", []string{"snapshot", "create", "vm1", "s1"}, "created"},
		{"snapshot ls", []string{"snapshot", "ls", "vm1"}, ""},
		// ── batch 2 ──
		{"sg bind", []string{"sg", "bind", "vm1", "--network", "default", "--sg", "web"}, "Bound"},
		{"health", []string{"health"}, ""},
		{"update", []string{"update", "vm1", "--cpu", "4"}, "updated"},
		{"ansible-inventory", []string{"ansible-inventory", "--list"}, ""},
		{"events", []string{"events"}, "TIME"},                                                    // streaming (fake stream → EOF)
		{"migrate", []string{"migrate", "vm1", "host-b"}, "migrated"},                             // streaming
		{"logs", []string{"logs", "vm1"}, ""},                                                     // streaming
		{"stack migrate-volumes", []string{"stack", "migrate-volumes", "s1", "--to", "fast"}, ""}, // streaming
		{"logout", []string{"logout"}, "Logged out"},
		{"whoami", []string{"whoami"}, ""},
		{"stats", []string{"stats", "vm1"}, "VM:"},
		{"region ls", []string{"region", "ls"}, ""},
		{"region status", []string{"region", "status"}, "REGION"},
		{"region migrate", []string{"region", "migrate", "vm1", "host-b"}, ""}, // streaming
		{"region anycast add", []string{"region", "anycast", "add", "--name", "api", "--ip", "10.0.0.1"}, "registered"},
		{"region anycast ls", []string{"region", "anycast", "ls"}, "SERVICE"},
		{"region anycast rm", []string{"region", "anycast", "rm", "--name", "api", "--ip", "10.0.0.1"}, "removed"},
		{"network ls", []string{"network", "ls"}, "NAME"},
		{"network inspect", []string{"network", "inspect", "br0"}, "Name:"},
		{"network create", []string{"network", "create", "n1", "--type", "bridge"}, "created"},
		{"network rm", []string{"network", "rm", "n1"}, "deleted"},
		{"session ls", []string{"session", "ls"}, "ID"},
		{"session revoke", []string{"session", "revoke", "s1"}, "revoked"},
		{"2fa ls", []string{"2fa", "ls"}, "METHOD"},
		{"2fa enroll-totp", []string{"2fa", "enroll-totp"}, ""},
		{"2fa disable", []string{"2fa", "disable", "--method", "totp"}, "disabled"},
		{"attach-disk", []string{"attach-disk", "vm1", "data"}, "attached"},
		{"detach-disk", []string{"detach-disk", "vm1", "data"}, "detached"},
		{"attach-nic", []string{"attach-nic", "vm1", "default"}, "attached"},
		{"detach-nic", []string{"detach-nic", "vm1", "52:54:00:aa:bb:cc"}, "detached"},
		{"attach-pci", []string{"attach-pci", "vm1", "--type", "gpu"}, "attached"},
		{"detach-pci", []string{"detach-pci", "vm1", "0000:41:00.0"}, "detached"},
		{"resize-disk", []string{"resize-disk", "vm1", "--size", "40G"}, "resized"},
		// ── batch 3 ──
		// vm.go (run/ls/inspect/start/stop/restart/rm/exec covered by TestE2E_VMLifecycle)
		{"vnc", []string{"vnc", "web-1"}, "VNC:"},
		// ct.go (exec skipped — calls os.Exit)
		{"ct ls", []string{"ct", "ls"}, "ct-1"},
		{"ct create", []string{"ct", "create", "c1"}, "Created"},
		{"ct start", []string{"ct", "start", "c1"}, ""},
		{"ct stop", []string{"ct", "stop", "c1"}, ""},
		{"ct rm", []string{"ct", "rm", "c1"}, ""},
		{"ct pull", []string{"ct", "pull", "docker.io/library/alpine", "--dest", "/tmp/rootfs-test"}, ""},
		// user.go (ls/delete/token-create/token-revoke covered by TestE2E_UserOperations)
		{"user create", []string{"user", "create", "newuser", "--role", "operator", "--password", "pw"}, "Created user"},
		// lb.go
		{"lb ls", []string{"lb", "ls"}, "NAME"},
		{"lb inspect", []string{"lb", "inspect", "mylb"}, "Name:"},
		{"lb create", []string{"lb", "create", "mylb", "--vip", "10.0.100.5/24", "--port", "80:8080", "--vm-backend", "web-1"}, "Created load balancer"},
		{"lb update", []string{"lb", "update", "mylb", "--algorithm", "leastconn"}, "Updated load balancer"},
		{"lb delete", []string{"lb", "delete", "mylb"}, "Deleted load balancer"},
		{"lb stats", []string{"lb", "stats", "mylb"}, "Load Balancer:"},
		{"lb drain", []string{"lb", "drain", "mylb", "--backend", "web-1"}, "Backend web-1"},
		{"lb disable", []string{"lb", "disable", "mylb", "--backend", "web-1"}, "disabled"},
		{"lb enable", []string{"lb", "enable", "mylb", "--backend", "web-1"}, "enabled"},
		// image.go (ls/rm/build covered by TestE2E_ImageOperations; import skipped — client-stream needs a file)
		{"image pull", []string{"image", "pull", "https://ex/img.qcow2", "--name", "myimg"}, "pulled successfully"}, // streaming
		{"image push", []string{"image", "push", "ubuntu-24.04", "--to", "host-b"}, "pushed to"},                    // streaming
		// compose.go (up/down/ps/diff skipped — they read a compose file from disk)
		{"compose ls", []string{"compose", "ls"}, "NAME"},
		{"compose export", []string{"compose", "export", "s1"}, "name: s1"},
		// backup.go (create covered by TestE2E_BackupCreate; restore skipped — client-stream needs a file)
		{"backup schedule ls", []string{"backup", "schedule", "ls"}, "no schedules"},
		{"backup schedule add", []string{"backup", "schedule", "add", "web-1", "--repo", "main", "--cron", "0 2 * * *"}, "added"},
		{"backup schedule rm", []string{"backup", "schedule", "rm", "web-1", "--repo", "main"}, "removed"},
		{"backup snapshot", []string{"backup", "snapshot", "web-1", "--repo", "/srv/backup"}, ""},                                                                                                     // streaming
		{"backup restore-from", []string{"backup", "restore-from", "--repo", "/srv/backup", "--vm", "web-1", "--disk", "root", "--timestamp", "2026-01-01T00:00:00Z", "--target-path", "/tmp/d"}, ""}, // streaming
		{"backup restore-live", []string{"backup", "restore-live", "--repo", "/srv/backup", "--vm", "web-1", "--disk", "root", "--timestamp", "2026-01-01T00:00:00Z", "--target-path", "/tmp/o"}, ""}, // streaming
		// host.go (ls/inspect/undrain/fence/rm/rescan/devices covered by TestE2E_HostOperations)
		{"host drain", []string{"host", "drain", "host-a"}, "drained"}, // streaming
		{"host config", []string{"host", "config", "host-a", "--region", "us-east"}, "configured"},
		{"host label ls", []string{"host", "label", "ls", "host-a"}, "no labels"},
		{"host label set", []string{"host", "label", "set", "host-a", "env=prod"}, "labels updated"},
		{"host label rm", []string{"host", "label", "rm", "host-a", "env"}, "labels updated"},
		{"host fence-confirm", []string{"host", "fence-confirm", "host-a"}, "host-a"},
		{"host preflight-upgrade", []string{"host", "preflight-upgrade", "host-a"}, "no findings"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := newMockClient()
			out, stderr, err := runCmd(t, mock, tc.args...)
			if err != nil {
				t.Fatalf("command %v errored: %v (stderr=%s)", tc.args, err, stderr)
			}
			if tc.want != "" {
				assertContains(t, out, tc.want)
			}
		})
	}
}
