package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestPrintJSON_ProtoVM(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	vm := &pb.VM{
		Name:     "test-vm",
		HostName: "node1",
		State:    pb.VMState_VM_RUNNING,
	}
	err := printJSON(vm)

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("printJSON error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)

	output := buf.String()
	if !strings.Contains(output, "test-vm") {
		t.Errorf("output missing 'test-vm': %s", output)
	}
	if !strings.Contains(output, "VM_RUNNING") {
		t.Errorf("output missing 'VM_RUNNING': %s", output)
	}
	if !strings.Contains(output, "node1") {
		t.Errorf("output missing 'node1': %s", output)
	}
}

func TestPrintJSON_EnumRenderedAsString(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	vm := &pb.VM{
		Name:  "state-check",
		State: pb.VMState_VM_STOPPED,
	}
	err := printJSON(vm)

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("printJSON error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)

	output := buf.String()
	if !strings.Contains(output, "VM_STOPPED") {
		t.Errorf("enum not rendered as string: %s", output)
	}
	// Must not contain the numeric value for STOPPED (4) as the state
	if strings.Contains(output, `"state": 4`) {
		t.Errorf("enum rendered as number instead of string: %s", output)
	}
}

func TestPrintJSON_ProtoHost(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	host := &pb.Host{
		Name:    "host-01",
		Address: "10.0.50.1",
		State:   pb.HostState_HOST_ACTIVE,
	}
	err := printJSON(host)

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("printJSON error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)

	output := buf.String()
	if !strings.Contains(output, "host-01") {
		t.Errorf("output missing 'host-01': %s", output)
	}
	if !strings.Contains(output, "10.0.50.1") {
		t.Errorf("output missing address: %s", output)
	}
}

func TestPrintJSON_Indented(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	vm := &pb.VM{Name: "indent-test", HostName: "h1"}
	err := printJSON(vm)

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("printJSON error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)

	output := buf.String()
	if !strings.Contains(output, "  ") {
		t.Error("output should contain indentation")
	}
}

func TestPrintJSON_EmptyVM(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printJSON(&pb.VM{})

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("printJSON error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)

	output := strings.TrimSpace(buf.String())
	if output != "{}" {
		t.Errorf("output = %q, want {}", output)
	}
}

func TestClusterConfig_Struct(t *testing.T) {
	cfg := &ClusterConfig{
		DefaultHost: "admin@10.0.0.1",
		GRPCPort:    7443,
	}
	if cfg.DefaultHost != "admin@10.0.0.1" {
		t.Errorf("DefaultHost = %q", cfg.DefaultHost)
	}
	if cfg.GRPCPort != 7443 {
		t.Errorf("GRPCPort = %d", cfg.GRPCPort)
	}
}

func TestLoadClusterConfig_WhitespaceHost(t *testing.T) {
	old := daemonConfigPath
	daemonConfigPath = "/nonexistent/config.yaml"
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "   ")
	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DefaultHost != "   " {
		t.Errorf("DefaultHost = %q, want '   '", cfg.DefaultHost)
	}
}

func TestParseSSHTarget_EmptyString(t *testing.T) {
	_, _, err := parseSSHTarget("")
	if err == nil {
		t.Error("expected error for empty target")
	}
	if err != nil && !strings.Contains(err.Error(), "invalid SSH target") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseSSHTarget_AtOnly(t *testing.T) {
	_, _, err := parseSSHTarget("@")
	if err == nil {
		t.Error("expected error for '@' target")
	}
}

func TestParseSSHTarget_AtHost(t *testing.T) {
	host, user, err := parseSSHTarget("@hostname")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "" {
		t.Errorf("user = %q, want empty", user)
	}
	if host != "hostname" {
		t.Errorf("host = %q, want hostname", host)
	}
}

func TestParseSSHTarget_HighPort(t *testing.T) {
	host, user, err := parseSSHTarget("deploy@192.168.1.1:65535")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "192.168.1.1" {
		t.Errorf("host = %q, want 192.168.1.1", host)
	}
	if user != "deploy" {
		t.Errorf("user = %q, want deploy", user)
	}
}

func TestSetupScriptContent_NotEmpty(t *testing.T) {
	if setupScriptContent == "" {
		t.Fatal("setupScriptContent is empty")
	}
}

func TestSetupScriptContent_HasPCISection(t *testing.T) {
	required := []string{
		"pci",
		"rescan_interval",
		"udev_hook",
		"sriov",
		"max_vfs_per_pf",
		"vfio-pci",
		"modprobe",
	}
	for _, s := range required {
		if !strings.Contains(setupScriptContent, s) {
			t.Errorf("setupScriptContent missing %q", s)
		}
	}
	// The deprecated udev rule is no longer installed by the setup script.
	if strings.Contains(setupScriptContent, "99-litevirt-pci.rules") {
		t.Error("setup script still installs the deprecated litevirt PCI udev rule")
	}
}

func TestSetupScriptContent_HasSEUO(t *testing.T) {
	if !strings.Contains(setupScriptContent, "set -euo pipefail") {
		t.Error("setup script missing 'set -euo pipefail'")
	}
}

func TestSetupScriptContent_SupportsBothPackageManagers(t *testing.T) {
	if !strings.Contains(setupScriptContent, "apt-get") {
		t.Error("setup script missing apt-get support")
	}
	if !strings.Contains(setupScriptContent, "dnf") {
		t.Error("setup script missing dnf support")
	}
}

func TestConfigDir_OverrideReturnsExact(t *testing.T) {
	paths := []string{
		"/tmp/test",
		"/var/lib/litevirt/config",
		"/home/user/.litevirt",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			t.Setenv("LV_CONFIG_DIR", p)
			if got := ConfigDir(); got != p {
				t.Errorf("ConfigDir() = %q, want %q", got, p)
			}
		})
	}
}

func TestPKIDir_AppendsPki(t *testing.T) {
	t.Setenv("LV_CONFIG_DIR", "/a/b/c")
	got := PKIDir()
	if got != "/a/b/c/pki" {
		t.Errorf("PKIDir() = %q, want /a/b/c/pki", got)
	}
}
