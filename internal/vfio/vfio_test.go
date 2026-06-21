package vfio

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// memFS is an in-memory SysFS implementation for testing.
type memFS struct {
	mu       sync.Mutex
	files    map[string][]byte
	links    map[string]string // path → symlink target
	dirs     map[string][]os.DirEntry
	writeErr map[string]error // inject write failures by path substring
	written  map[string][]byte
}

func newMemFS() *memFS {
	return &memFS{
		files:    map[string][]byte{},
		links:    map[string]string{},
		dirs:     map[string][]os.DirEntry{},
		writeErr: map[string]error{},
		written:  map[string][]byte{},
	}
}

func (m *memFS) ReadFile(path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, ok := m.files[path]
	if !ok {
		return nil, fmt.Errorf("memFS: file not found: %s", path)
	}
	return data, nil
}

func (m *memFS) WriteFile(path string, data []byte, _ os.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for substr, err := range m.writeErr {
		if strings.Contains(path, substr) {
			return err
		}
	}
	m.files[path] = data
	m.written[path] = data
	return nil
}

func (m *memFS) Readlink(path string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	target, ok := m.links[path]
	if !ok {
		return "", fmt.Errorf("memFS: link not found: %s", path)
	}
	return target, nil
}

func (m *memFS) ReadDir(path string) ([]os.DirEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, ok := m.dirs[path]
	if !ok {
		return nil, fmt.Errorf("memFS: dir not found: %s", path)
	}
	return entries, nil
}

// addDevice sets up a fake sysfs device.
func (m *memFS) addDevice(address, vendor, device, driver string) {
	devPath := "/sys/bus/pci/devices/" + address
	m.files[devPath+"/vendor"] = []byte(vendor + "\n")
	m.files[devPath+"/device"] = []byte(device + "\n")
	if driver != "" {
		m.links[devPath+"/driver"] = "/sys/bus/pci/drivers/" + driver
	}
}

// setDriver updates the driver symlink for a device.
func (m *memFS) setDriver(address, driver string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	devPath := "/sys/bus/pci/devices/" + address
	if driver == "" {
		delete(m.links, devPath+"/driver")
	} else {
		m.links[devPath+"/driver"] = "/sys/bus/pci/drivers/" + driver
	}
}

// fakeEntry implements os.DirEntry for test.
type fakeEntry struct{ name string }

func (f fakeEntry) Name() string               { return f.name }
func (f fakeEntry) IsDir() bool                 { return true }
func (f fakeEntry) Type() os.FileMode           { return os.ModeDir }
func (f fakeEntry) Info() (os.FileInfo, error)   { return nil, nil }

// ── Bind tests ──

func TestBind_Success(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "nvidia")
	// After bind writes, the driver should update to vfio-pci.
	// Simulate the kernel: on write to vfio-pci/bind, update the symlink.
	origWrite := fs.WriteFile
	_ = origWrite
	// We need the verification readlink to return vfio-pci after bind.
	// Set it after addDevice so the initial read returns nvidia.
	// The trick: override WriteFile to update the symlink when bind path is written.
	wrapper := &bindUpdateFS{memFS: fs, addr: addr}
	restore := SetFS(wrapper)
	defer restore()

	prev, err := Bind(addr)
	if err != nil {
		t.Fatalf("Bind() error: %v", err)
	}
	if prev != "nvidia" {
		t.Errorf("previousDriver = %q, want nvidia", prev)
	}
}

// bindUpdateFS wraps memFS and simulates kernel behavior: updates driver symlink on bind.
type bindUpdateFS struct {
	*memFS
	addr string
}

func (b *bindUpdateFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	err := b.memFS.WriteFile(path, data, perm)
	if err != nil {
		return err
	}
	// Simulate kernel: when vfio-pci/bind or drivers_probe is written, update driver symlink.
	if strings.Contains(path, "vfio-pci/bind") || strings.Contains(path, "drivers_probe") {
		b.memFS.setDriver(b.addr, "vfio-pci")
	}
	// Simulate kernel: when driver/unbind is written, clear driver symlink.
	if strings.Contains(path, "driver/unbind") {
		b.memFS.setDriver(b.addr, "")
	}
	return nil
}

func TestBind_AlreadyBound(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "vfio-pci")
	restore := SetFS(fs)
	defer restore()

	prev, err := Bind(addr)
	if err != nil {
		t.Fatalf("Bind() error: %v", err)
	}
	if prev != "vfio-pci" {
		t.Errorf("previousDriver = %q, want vfio-pci", prev)
	}
	// Should not have written anything.
	if len(fs.written) > 0 {
		t.Errorf("expected no writes for already-bound device, got %d", len(fs.written))
	}
}

func TestBind_NoCurrentDriver(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "") // no driver
	wrapper := &bindUpdateFS{memFS: fs, addr: addr}
	restore := SetFS(wrapper)
	defer restore()

	prev, err := Bind(addr)
	if err != nil {
		t.Fatalf("Bind() error: %v", err)
	}
	if prev != "" {
		t.Errorf("previousDriver = %q, want empty", prev)
	}
}

func TestBind_UnbindFails(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "nvidia")
	fs.writeErr["driver/unbind"] = fmt.Errorf("permission denied")
	restore := SetFS(fs)
	defer restore()

	_, err := Bind(addr)
	if err == nil {
		t.Fatal("expected error from Bind()")
	}
	if !strings.Contains(err.Error(), "unbind") {
		t.Errorf("error should mention unbind: %v", err)
	}
}

func TestBind_OverrideFails(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "") // no driver to unbind
	fs.writeErr["driver_override"] = fmt.Errorf("permission denied")
	restore := SetFS(fs)
	defer restore()

	_, err := Bind(addr)
	if err == nil {
		t.Fatal("expected error from Bind()")
	}
	if !strings.Contains(err.Error(), "driver_override") {
		t.Errorf("error should mention driver_override: %v", err)
	}
}

func TestBind_BindAndProbeFail(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "")
	fs.writeErr["vfio-pci/bind"] = fmt.Errorf("no such device")
	fs.writeErr["drivers_probe"] = fmt.Errorf("no such device")
	restore := SetFS(fs)
	defer restore()

	_, err := Bind(addr)
	if err == nil {
		t.Fatal("expected error from Bind()")
	}
	if !strings.Contains(err.Error(), "probe also failed") {
		t.Errorf("error should mention both failures: %v", err)
	}
}

func TestBind_VerificationFails(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "")
	// Don't update the driver on bind — simulates kernel not actually binding.
	restore := SetFS(fs)
	defer restore()

	_, err := Bind(addr)
	if err == nil {
		t.Fatal("expected verification error from Bind()")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("error should mention verification: %v", err)
	}
}

// ── Unbind tests ──

func TestUnbind_Success(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "vfio-pci")
	wrapper := &unbindUpdateFS{memFS: fs, addr: addr, restoreTo: "nvidia"}
	restore := SetFS(wrapper)
	defer restore()

	err := Unbind(addr, "nvidia")
	if err != nil {
		t.Fatalf("Unbind() error: %v", err)
	}
}

// unbindUpdateFS simulates kernel behavior during unbind.
type unbindUpdateFS struct {
	*memFS
	addr      string
	restoreTo string
}

func (u *unbindUpdateFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	err := u.memFS.WriteFile(path, data, perm)
	if err != nil {
		return err
	}
	if strings.Contains(path, "driver/unbind") {
		u.memFS.setDriver(u.addr, "")
	}
	if strings.Contains(path, u.restoreTo+"/bind") || strings.Contains(path, "drivers_probe") {
		if u.restoreTo != "" {
			u.memFS.setDriver(u.addr, u.restoreTo)
		}
	}
	return nil
}

func TestUnbind_WithRestoreFallback(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "vfio-pci")
	// Direct bind to nvidia fails, but drivers_probe works.
	fs.writeErr["nvidia/bind"] = fmt.Errorf("no such device")
	wrapper := &unbindUpdateFS{memFS: fs, addr: addr, restoreTo: "nvidia"}
	restore := SetFS(wrapper)
	defer restore()

	err := Unbind(addr, "nvidia")
	if err != nil {
		t.Fatalf("Unbind() error: %v", err)
	}
}

func TestUnbind_RestoreAndProbeFail(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "vfio-pci")
	fs.writeErr["nvidia/bind"] = fmt.Errorf("no such device")
	fs.writeErr["drivers_probe"] = fmt.Errorf("no such device")
	// Simulate unbind clearing the driver so we don't get verification errors.
	wrapper := &unbindUpdateFS{memFS: fs, addr: addr, restoreTo: ""}
	restore := SetFS(wrapper)
	defer restore()

	err := Unbind(addr, "nvidia")
	if err == nil {
		t.Fatal("expected error from Unbind()")
	}
	if !strings.Contains(err.Error(), "probe also failed") {
		t.Errorf("error should mention both failures: %v", err)
	}
}

func TestUnbind_ClearOverrideFails(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "vfio-pci")
	fs.writeErr["driver_override"] = fmt.Errorf("permission denied")
	// Unbind itself should work, but clearing override fails.
	wrapper := &unbindUpdateFS{memFS: fs, addr: addr, restoreTo: "nvidia"}
	restore := SetFS(wrapper)
	defer restore()

	err := Unbind(addr, "nvidia")
	if err == nil {
		t.Fatal("expected error from Unbind()")
	}
	if !strings.Contains(err.Error(), "driver_override") {
		t.Errorf("error should mention driver_override: %v", err)
	}
}

func TestUnbind_VerificationFails(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "vfio-pci")
	// Unbind and restore "succeed" but driver stays vfio-pci (kernel bug simulation).
	restore := SetFS(fs) // no wrapper to update symlinks
	defer restore()

	err := Unbind(addr, "nvidia")
	if err == nil {
		t.Fatal("expected verification error from Unbind()")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("error should mention verification: %v", err)
	}
}

func TestUnbind_EmptyRestore(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "vfio-pci")
	wrapper := &unbindUpdateFS{memFS: fs, addr: addr, restoreTo: "auto"}
	restore := SetFS(wrapper)
	defer restore()

	err := Unbind(addr, "")
	if err != nil {
		t.Fatalf("Unbind() error: %v", err)
	}
}

func TestUnbind_NotBoundToVFIO(t *testing.T) {
	fs := newMemFS()
	addr := "0000:01:00.0"
	fs.addDevice(addr, "0x10de", "0x2204", "nvidia")
	restore := SetFS(fs)
	defer restore()

	err := Unbind(addr, "")
	if err != nil {
		t.Fatalf("Unbind() error: %v", err)
	}
}

// ── IsVF / IsIOMMUEnabled tests ──

func TestIsVF_True(t *testing.T) {
	fs := newMemFS()
	fs.links["/sys/bus/pci/devices/0000:01:00.1/physfn"] = "/sys/bus/pci/devices/0000:01:00.0"
	restore := SetFS(fs)
	defer restore()

	if !IsVF("0000:01:00.1") {
		t.Error("IsVF should return true for device with physfn")
	}
}

func TestIsVF_False(t *testing.T) {
	fs := newMemFS()
	restore := SetFS(fs)
	defer restore()

	if IsVF("0000:01:00.0") {
		t.Error("IsVF should return false for device without physfn")
	}
}

func TestIsIOMMUEnabled_True(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/sys/kernel/iommu_groups"] = []os.DirEntry{fakeEntry{"0"}, fakeEntry{"1"}}
	restore := SetFS(fs)
	defer restore()

	if !IsIOMMUEnabled() {
		t.Error("IsIOMMUEnabled should return true when groups exist")
	}
}

func TestIsIOMMUEnabled_False(t *testing.T) {
	fs := newMemFS()
	fs.dirs["/sys/kernel/iommu_groups"] = []os.DirEntry{}
	restore := SetFS(fs)
	defer restore()

	if IsIOMMUEnabled() {
		t.Error("IsIOMMUEnabled should return false when no groups")
	}
}

func TestIsIOMMUEnabled_NoDir(t *testing.T) {
	fs := newMemFS()
	restore := SetFS(fs)
	defer restore()

	if IsIOMMUEnabled() {
		t.Error("IsIOMMUEnabled should return false when dir doesn't exist")
	}
}
