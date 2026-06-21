package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestParseSSHTarget_UserAtEmpty(t *testing.T) {
	// "user@" should produce empty host -> error
	_, _, err := parseSSHTarget("user@")
	if err == nil {
		t.Error("expected error for 'user@' (empty host)")
	}
}

func TestParseSSHTarget_PortOnly(t *testing.T) {
	// "user@:22" should split to empty host -> error
	_, _, err := parseSSHTarget("user@:22")
	if err == nil {
		t.Error("expected error for 'user@:22' (empty host)")
	}
}

func TestParseSSHTarget_LongHostname(t *testing.T) {
	long := "admin@" + strings.Repeat("a", 200) + ".example.com"
	host, user, err := parseSSHTarget(long)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "admin" {
		t.Errorf("user = %q, want admin", user)
	}
	if !strings.HasSuffix(host, ".example.com") {
		t.Errorf("host = %q, expected to end with .example.com", host)
	}
}

func TestParseSSHTarget_NoAtWithPort(t *testing.T) {
	// Host with port but no user@ prefix
	host, user, err := parseSSHTarget("10.0.0.1:2222")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
	if host != "10.0.0.1" {
		t.Errorf("host = %q, want 10.0.0.1", host)
	}
}

func TestLoadClusterConfig_VariousHosts(t *testing.T) {
	old := daemonConfigPath
	daemonConfigPath = "/nonexistent/config.yaml"
	t.Cleanup(func() { daemonConfigPath = old })
	hosts := []string{
		"root@192.168.1.1",
		"admin@node1.cluster.local",
		"deploy@10.0.0.1:2222",
	}
	for _, h := range hosts {
		t.Run(h, func(t *testing.T) {
			t.Setenv("LV_HOST", h)
			cfg, err := LoadClusterConfig()
			if err != nil {
				t.Fatalf("LoadClusterConfig(%q): %v", h, err)
			}
			if cfg.DefaultHost != h {
				t.Errorf("DefaultHost = %q, want %q", cfg.DefaultHost, h)
			}
			if cfg.GRPCPort != 7443 {
				t.Errorf("GRPCPort = %d, want 7443", cfg.GRPCPort)
			}
		})
	}
}

func TestLoadClusterConfig_ErrorMessage(t *testing.T) {
	old := daemonConfigPath
	daemonConfigPath = "/nonexistent/config.yaml"
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "")
	_, err := LoadClusterConfig()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "LV_HOST not set") {
		t.Errorf("error message = %q, expected to mention LV_HOST", err.Error())
	}
}

func TestClusterConfig_ZeroValue(t *testing.T) {
	cfg := ClusterConfig{}
	if cfg.DefaultHost != "" {
		t.Errorf("zero DefaultHost = %q", cfg.DefaultHost)
	}
	if cfg.GRPCPort != 0 {
		t.Errorf("zero GRPCPort = %d", cfg.GRPCPort)
	}
}

func TestPrintJSON_AllVMStates(t *testing.T) {
	states := []struct {
		state pb.VMState
		want  string
	}{
		{pb.VMState_VM_RUNNING, "VM_RUNNING"},
		{pb.VMState_VM_STOPPED, "VM_STOPPED"},
		{pb.VMState_VM_ERROR, "VM_ERROR"},
		{pb.VMState_VM_STARTING, "VM_STARTING"},
		{pb.VMState_VM_MIGRATING, "VM_MIGRATING"},
	}
	for _, tt := range states {
		t.Run(tt.want, func(t *testing.T) {
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := printJSON(&pb.VM{Name: "s", State: tt.state})

			w.Close()
			os.Stdout = old

			if err != nil {
				t.Fatalf("printJSON error: %v", err)
			}

			var buf bytes.Buffer
			io.Copy(&buf, r)

			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("output missing %q: %s", tt.want, buf.String())
			}
		})
	}
}

func TestPrintJSON_ValidProtojson(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := printJSON(&pb.VM{
		Name:        "json-vm",
		HostName:    "h1",
		State:       pb.VMState_VM_RUNNING,
		StateDetail: "line1\nline2",
	})

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("printJSON error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)

	// Verify it's valid protojson
	var parsed pb.VM
	if err := protojson.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Errorf("output is not valid protojson: %v", err)
	}
	if parsed.Name != "json-vm" {
		t.Errorf("parsed name = %q, want json-vm", parsed.Name)
	}
	if parsed.StateDetail != "line1\nline2" {
		t.Errorf("state_detail = %q", parsed.StateDetail)
	}
}

func TestPKIDir_DefaultPath(t *testing.T) {
	t.Setenv("LV_CONFIG_DIR", "")
	dir := PKIDir()
	home, _ := os.UserHomeDir()
	expected := home + "/.config/litevirt/pki"
	if dir != expected {
		t.Errorf("PKIDir() = %q, want %q", dir, expected)
	}
}

func TestConfigDir_EmptyString(t *testing.T) {
	// Empty LV_CONFIG_DIR should fall through to default
	t.Setenv("LV_CONFIG_DIR", "")
	dir := ConfigDir()
	if strings.Contains(dir, "LV_CONFIG_DIR") {
		t.Errorf("ConfigDir() = %q, should not contain env var name", dir)
	}
	if !strings.Contains(dir, ".config/litevirt") {
		t.Errorf("ConfigDir() = %q, should contain .config/litevirt", dir)
	}
}

func TestGetSetupScript_HasShebang(t *testing.T) {
	script, err := getSetupScript()
	if err != nil {
		t.Fatalf("getSetupScript: %v", err)
	}
	if !strings.HasPrefix(script, "#!/bin/bash") {
		t.Errorf("script should start with #!/bin/bash, got prefix: %q", script[:20])
	}
}

func TestGetSetupScript_HasConfigSection(t *testing.T) {
	script, err := getSetupScript()
	if err != nil {
		t.Fatalf("getSetupScript: %v", err)
	}
	configKeys := []string{
		"grpc_port: 7443",
		"metrics_port: 7444",
		"gossip_port: 7946",
		"pki_dir: /etc/litevirt/pki",
		"data_dir: /var/lib/litevirt",
	}
	for _, key := range configKeys {
		if !strings.Contains(script, key) {
			t.Errorf("setup script missing config key %q", key)
		}
	}
}

func TestGetSetupScript_HasDirectories(t *testing.T) {
	script, err := getSetupScript()
	if err != nil {
		t.Fatalf("getSetupScript: %v", err)
	}
	dirs := []string{
		"/var/lib/litevirt/{images,disks,cloudinit}",
		"/etc/litevirt",
	}
	for _, dir := range dirs {
		if !strings.Contains(script, dir) {
			t.Errorf("setup script missing directory %q", dir)
		}
	}
}

func TestSetupScriptContent_Length(t *testing.T) {
	if len(setupScriptContent) < 100 {
		t.Errorf("setupScriptContent too short: %d bytes", len(setupScriptContent))
	}
}

func TestSetupScriptContent_LineCount(t *testing.T) {
	lines := strings.Split(setupScriptContent, "\n")
	if len(lines) < 10 {
		t.Errorf("setupScriptContent has only %d lines, expected more", len(lines))
	}
}

func TestParseSSHTarget_IPv4(t *testing.T) {
	// Various valid IPv4 addresses
	ips := []string{"127.0.0.1", "0.0.0.0", "255.255.255.255", "10.0.50.1"}
	for _, ip := range ips {
		t.Run(ip, func(t *testing.T) {
			target := "root@" + ip
			host, user, err := parseSSHTarget(target)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if host != ip {
				t.Errorf("host = %q, want %q", host, ip)
			}
			if user != "root" {
				t.Errorf("user = %q, want root", user)
			}
		})
	}
}

func TestParseSSHTarget_Underscore(t *testing.T) {
	host, user, err := parseSSHTarget("deploy@my_host")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if host != "my_host" {
		t.Errorf("host = %q, want my_host", host)
	}
	if user != "deploy" {
		t.Errorf("user = %q, want deploy", user)
	}
}

func TestConnect_NoLVHost(t *testing.T) {
	old := daemonConfigPath
	daemonConfigPath = "/nonexistent/config.yaml"
	t.Cleanup(func() { daemonConfigPath = old })
	// Connect should fail early when LV_HOST is not set
	t.Setenv("LV_HOST", "")
	_, _, err := Connect(context.Background())
	if err == nil {
		t.Error("expected error when LV_HOST is not set")
	}
	if !strings.Contains(err.Error(), "LV_HOST not set") {
		t.Errorf("error = %q, expected to mention LV_HOST", err.Error())
	}
}

func TestConnect_MissingTLS(t *testing.T) {
	// Connect should fail when no CA cert exists for TLS
	t.Setenv("LV_HOST", "127.0.0.1:7443")
	t.Setenv("LV_CONFIG_DIR", t.TempDir()) // empty dir, no ca.crt
	_, _, err := Connect(context.Background())
	if err == nil {
		t.Error("expected error when TLS config is missing")
	}
}
