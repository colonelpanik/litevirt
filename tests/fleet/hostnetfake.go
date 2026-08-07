package fleet

import (
	"context"
	"sync"
	"time"
)

// HostNetFake is the fleet stand-in for hostnet.RealSystem: an in-memory
// netplan file per node and a togglable connectivity confirm, so the apply
// protocol (forwarding, journal, rollback, replication of outcomes) runs
// multi-node without root or a real netplan. Mirrors n.Virt / n.CT.
type HostNetFake struct {
	mu         sync.Mutex
	file       string
	fileExists bool
	foreign    map[string]string
	iface      string // reported cluster interface
	confirmErr error  // non-nil => every apply reverts
	applies    int
}

func NewHostNetFake() *HostNetFake { return &HostNetFake{iface: "net1"} }

// File returns the current managed-file content — assert on THIS, not on row
// state alone: an apply that moved rows but wrote nothing must not pass.
func (f *HostNetFake) File() (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.file, f.fileExists
}

// Applies counts ApplyWithRevert invocations (accepted or not).
func (f *HostNetFake) Applies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.applies
}

// FailConfirm makes every subsequent connectivity confirm fail with reason,
// or succeed again when err is nil.
func (f *HostNetFake) FailConfirm(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.confirmErr = err
}

func (f *HostNetFake) NetplanAvailable() error { return nil }
func (f *HostNetFake) ReadManagedFile() (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.file, f.fileExists, nil
}
func (f *HostNetFake) WriteManagedFile(content string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.file, f.fileExists = content, true
	return nil
}
func (f *HostNetFake) RemoveManagedFile() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.file, f.fileExists = "", false
	return nil
}
func (f *HostNetFake) ForeignFiles() (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.foreign, nil
}
func (f *HostNetFake) ClusterInterface(string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.iface, nil
}
func (f *HostNetFake) ApplyWithRevert(ctx context.Context, _ time.Duration, confirm func(context.Context) error) (bool, error) {
	f.mu.Lock()
	f.applies++
	f.mu.Unlock()
	if err := confirm(ctx); err != nil {
		return false, nil
	}
	return true, nil
}
func (f *HostNetFake) ConfirmConnectivity(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.confirmErr
}
