package lxc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mkRootfs creates a directory that looks like a root filesystem (has the
// marker subdirs resolveRootfs/looksLikeRootfs check for).
func mkRootfs(t *testing.T, dir string) string {
	t.Helper()
	for _, d := range []string{"bin", "etc", "usr"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestResolveRootfs(t *testing.T) {
	tmp := t.TempDir()

	// A plain rootfs directory.
	plain := mkRootfs(t, filepath.Join(tmp, "plain"))

	// An OCI/umoci bundle: the real fs is under rootfs/.
	bundle := filepath.Join(tmp, "bundle")
	mkRootfs(t, filepath.Join(bundle, "rootfs"))
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A directory that exists but isn't a rootfs.
	empty := filepath.Join(tmp, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		template string
		wantOK   bool
		wantPath string
		wantErr  bool
	}{
		{"bare name is a template, not a rootfs", "busybox", false, "", false},
		{"download is not a rootfs", "download", false, "", false},
		{"plain rootfs path", plain, true, plain, false},
		{"rootfs: prefix", "rootfs:" + plain, true, plain, false},
		{"bundle descends into rootfs/", bundle, true, filepath.Join(bundle, "rootfs"), false},
		{"nonexistent absolute path errors", filepath.Join(tmp, "nope"), false, "", true},
		{"existing non-rootfs dir errors", empty, false, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, ok, err := resolveRootfs(tc.template)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr=%v", err, tc.wantErr)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if tc.wantOK && path != tc.wantPath {
				t.Errorf("path = %q, want %q", path, tc.wantPath)
			}
		})
	}
}

func TestCreateFromRootfs_WritesConfig(t *testing.T) {
	tmp := t.TempDir()
	lxcpath := filepath.Join(tmp, "lxc")
	bundle := filepath.Join(tmp, "img")
	mkRootfs(t, filepath.Join(bundle, "rootfs"))

	r := &LxcRunner{Lxcpath: lxcpath}
	c, err := r.Create(context.Background(), CreateOpts{Name: "web", Template: bundle})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.State != StateStopped {
		t.Errorf("state = %q, want stopped", c.State)
	}

	cfgPath := filepath.Join(lxcpath, "web", "config")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	cfg := string(raw)
	wantRootfs := "lxc.rootfs.path = dir:" + filepath.Join(bundle, "rootfs")
	for _, want := range []string{
		wantRootfs,
		"lxc.uts.name = web",
		"lxc.net.0.type = veth",
		"lxc.net.0.link = lxcbr0",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q\n--- config ---\n%s", want, cfg)
		}
	}

	// Creating again must refuse rather than clobber an existing container.
	if _, err := r.Create(context.Background(), CreateOpts{Name: "web", Template: bundle}); err == nil {
		t.Error("expected error creating an already-existing container")
	}
}

func TestCreateFromRootfs_ExplicitNetworks(t *testing.T) {
	tmp := t.TempDir()
	lxcpath := filepath.Join(tmp, "lxc")
	rootfs := mkRootfs(t, filepath.Join(tmp, "rfs"))

	r := &LxcRunner{Lxcpath: lxcpath}
	_, err := r.Create(context.Background(), CreateOpts{
		Name:     "api",
		Template: "rootfs:" + rootfs,
		Network: []NetworkAttach{
			{Name: "eth0", Bridge: "br-prod", IP: "10.0.0.5/24", MAC: "aa:bb:cc:dd:ee:ff"},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(lxcpath, "api", "config"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(raw)
	for _, want := range []string{
		"lxc.net.0.link = br-prod",
		"lxc.net.0.name = eth0",
		"lxc.net.0.hwaddr = aa:bb:cc:dd:ee:ff",
		"lxc.net.0.ipv4.address = 10.0.0.5/24",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q\n--- config ---\n%s", want, cfg)
		}
	}
	// No default lxcbr0 NIC when explicit networks are given.
	if strings.Contains(cfg, "lxcbr0") {
		t.Errorf("unexpected default lxcbr0 NIC with explicit networks\n%s", cfg)
	}
}

func TestCmdErrIncludesStderr(t *testing.T) {
	base := errors.New("exit status 1")
	got := cmdErr("lxc-create", "web", []byte("  Couldn't find a matching image\n"), base)
	if !strings.Contains(got.Error(), "Couldn't find a matching image") {
		t.Errorf("stderr not surfaced: %v", got)
	}
	if !errors.Is(got, base) {
		t.Errorf("wrapped error should match base via errors.Is")
	}
	// No stderr → no trailing colon-noise.
	got2 := cmdErr("lxc-start", "web", nil, base)
	if strings.HasSuffix(got2.Error(), ": ") {
		t.Errorf("trailing separator with empty stderr: %q", got2.Error())
	}
}

func TestCreateFromRootfs_AppliesResourceLimits(t *testing.T) {
	tmp := t.TempDir()
	lxcpath := filepath.Join(tmp, "lxc")
	rootfs := mkRootfs(t, filepath.Join(tmp, "rfs"))

	r := &LxcRunner{Lxcpath: lxcpath}
	if _, err := r.Create(context.Background(), CreateOpts{
		Name: "lim", Template: rootfs, CPULimit: 2, MemoryMiB: 512,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(lxcpath, "lim", "config"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(raw)
	// cgroup limits must reach the live config — the bug was that they never did.
	for _, want := range []string{
		"lxc.cgroup2.cpu.max = 2000 100000",
		"lxc.cgroup.cpu.shares = 2048",
		"lxc.cgroup2.memory.max = 512M",
		"lxc.cgroup.memory.limit_in_bytes = 512M",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q\n--- config ---\n%s", want, cfg)
		}
	}
}

func TestSplitCIDR(t *testing.T) {
	if a, m := splitCIDR("10.0.3.78/24"); a != "10.0.3.78" || m != "255.255.255.0" {
		t.Errorf("CIDR: got %q %q", a, m)
	}
	if a, m := splitCIDR("10.0.3.78"); a != "10.0.3.78" || m != "" {
		t.Errorf("bare IP: got %q %q", a, m)
	}
}

// A static --network IP must also configure the guest's /etc/network/interfaces,
// or the image's boot-time DHCP client flushes the address LXC assigned.
func TestCreateFromRootfs_WritesGuestStaticIP(t *testing.T) {
	tmp := t.TempDir()
	lxcpath := filepath.Join(tmp, "lxc")
	rootfs := mkRootfs(t, filepath.Join(tmp, "rfs"))

	r := &LxcRunner{Lxcpath: lxcpath}
	if _, err := r.Create(context.Background(), CreateOpts{
		Name: "sip", Template: "rootfs:" + rootfs,
		Network: []NetworkAttach{{Name: "eth0", Bridge: "lxcbr0", IP: "10.0.3.78/24"}},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(rootfs, "etc", "network", "interfaces"))
	if err != nil {
		t.Fatalf("guest interfaces not written: %v", err)
	}
	s := string(raw)
	for _, want := range []string{"iface eth0 inet static", "address 10.0.3.78", "netmask 255.255.255.0"} {
		if !strings.Contains(s, want) {
			t.Errorf("interfaces missing %q\n%s", want, s)
		}
	}
}

func TestCreateFromRootfs_NoStaticIP_NoGuestConfig(t *testing.T) {
	tmp := t.TempDir()
	lxcpath := filepath.Join(tmp, "lxc")
	rootfs := mkRootfs(t, filepath.Join(tmp, "rfs"))

	r := &LxcRunner{Lxcpath: lxcpath}
	if _, err := r.Create(context.Background(), CreateOpts{
		Name: "nosip", Template: "rootfs:" + rootfs,
		Network: []NetworkAttach{{Name: "eth0", Bridge: "lxcbr0"}}, // no IP
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := os.Stat(filepath.Join(rootfs, "etc", "network", "interfaces")); err == nil {
		t.Error("guest interfaces must NOT be written when no static IP is requested")
	}
}

// finalizeContainerConfig is the shared step the download path also uses: it
// must strip the template's default lxcbr0 NIC and apply the requested network
// + limits, without duplicating NICs or clobbering the base config.
func TestFinalizeContainerConfig_ReplacesDefaultNet(t *testing.T) {
	tmp := t.TempDir()
	lxcpath := filepath.Join(tmp, "lxc")
	cdir := filepath.Join(lxcpath, "dl")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := "lxc.include = /usr/share/lxc/config/common.conf\n" +
		"lxc.uts.name = dl\n" +
		"lxc.net.0.type = veth\nlxc.net.0.link = lxcbr0\nlxc.net.0.flags = up\n"
	if err := os.WriteFile(filepath.Join(cdir, "config"), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &LxcRunner{Lxcpath: lxcpath}
	if err := r.finalizeContainerConfig(CreateOpts{
		Name:      "dl",
		Network:   []NetworkAttach{{Name: "eth0", Bridge: "br-prod", IP: "10.9.9.9/24"}},
		MemoryMiB: 256,
	}); err != nil {
		t.Fatalf("finalizeContainerConfig: %v", err)
	}
	raw, _ := os.ReadFile(filepath.Join(cdir, "config"))
	cfg := string(raw)
	if strings.Contains(cfg, "lxcbr0") {
		t.Errorf("default lxcbr0 NIC was not stripped:\n%s", cfg)
	}
	if strings.Count(cfg, "lxc.net.0.link") != 1 {
		t.Errorf("expected exactly one NIC link line:\n%s", cfg)
	}
	for _, want := range []string{
		"lxc.net.0.link = br-prod",
		"lxc.net.0.ipv4.address = 10.9.9.9/24",
		"lxc.cgroup2.memory.max = 256M",
		"lxc.uts.name = dl", // base preserved
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q\n%s", want, cfg)
		}
	}
}
