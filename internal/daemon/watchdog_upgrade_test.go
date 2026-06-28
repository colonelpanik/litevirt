package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/upgrade"
)

func TestDecideWatchdog(t *testing.T) {
	cases := []struct {
		name                            string
		pingOK, shuttingDown, oldExists bool
		attempt                         int
		want                            watchdogOutcome
	}{
		{"healthy", true, false, true, 0, wdConfirm},
		{"healthy even mid-shutdown", true, true, true, 0, wdConfirm},
		{"unhealthy during shutdown -> no rollback", false, true, true, 0, wdShutdown},
		{"unhealthy first time with .old -> rollback", false, false, true, 0, wdRollback},
		{"unhealthy but already rolled back -> giveup", false, false, true, 1, wdGiveUp},
		{"unhealthy but no .old -> giveup", false, false, false, 0, wdGiveUp},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideWatchdog(tc.pingOK, tc.shuttingDown, tc.oldExists, tc.attempt); got != tc.want {
				t.Fatalf("decideWatchdog(%v,%v,%v,%d) = %d, want %d",
					tc.pingOK, tc.shuttingDown, tc.oldExists, tc.attempt, got, tc.want)
			}
		})
	}
}

// TestRollbackToOld proves a rollback restores .old over the binary, bumps the
// sentinel attempt (so the restored binary won't roll back again), and exits
// non-zero.
func TestRollbackToOld(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "litevirt")
	if err := os.WriteFile(bin, []byte("NEW-broken"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin+".old", []byte("OLD-good"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := upgrade.Arm(bin, "v1.0.30"); err != nil {
		t.Fatal(err)
	}
	s, _ := upgrade.Read(bin)

	var exitCode = -1
	d := &Daemon{exitFunc: func(c int) { exitCode = c }}
	d.rollbackToOld(bin, s)

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	got, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read restored binary: %v", err)
	}
	if string(got) != "OLD-good" {
		t.Fatalf("binary content after rollback = %q, want OLD-good (.old not restored)", got)
	}
	if _, err := os.Stat(bin + ".old"); !os.IsNotExist(err) {
		t.Fatalf(".old should be consumed by the rename, stat err=%v", err)
	}
	s2, ok := upgrade.Read(bin)
	if !ok || s2.Attempt != 1 {
		t.Fatalf("sentinel after rollback: ok=%v attempt=%d, want true/1 (flap guard)", ok, s2.Attempt)
	}
}

// TestConfirmUpgradeHealthy proves the confirm path (Ping succeeded): the
// sentinel is cleared and the host flips upgrading→active.
func TestConfirmUpgradeHealthy(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h", Address: "127.0.0.1", SSHUser: "root", CertSerial: "s", State: "upgrading",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	bin := filepath.Join(t.TempDir(), "litevirt")
	if err := upgrade.Arm(bin, "v-old"); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	d := &Daemon{cfg: &Config{HostName: "h"}, db: db}
	d.confirmUpgradeHealthy(bin)

	if _, ok := upgrade.Read(bin); ok {
		t.Fatal("sentinel must be cleared after a healthy confirm")
	}
	h, err := corrosion.GetHost(ctx, db, "h")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.State != "active" {
		t.Fatalf("host state = %q after confirm, want active", h.State)
	}
}

// TestConfirmUpgradeHealthy_RetainsSentinelOnWriteFailure proves the sentinel is
// NOT cleared when the active-state write fails — so a transient DB error can't
// strand the host in 'upgrading' with no watchdog; the next boot re-confirms.
func TestConfirmUpgradeHealthy_RetainsSentinelOnWriteFailure(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// Force the state write to fail by removing the table it targets.
	if err := db.Execute(ctx, `DROP TABLE hosts`); err != nil {
		t.Fatalf("drop hosts: %v", err)
	}

	bin := filepath.Join(t.TempDir(), "litevirt")
	if err := upgrade.Arm(bin, "v-old"); err != nil {
		t.Fatalf("Arm: %v", err)
	}

	d := &Daemon{cfg: &Config{HostName: "h"}, db: db}
	d.confirmUpgradeHealthy(bin)

	if _, ok := upgrade.Read(bin); !ok {
		t.Fatal("sentinel must be RETAINED when the active-state write fails (so the next boot retries)")
	}
}

// TestStartUpgradeWatchdog_Disabled confirms the watchdog is inert when disabled
// and never sets upgradePending.
func TestStartUpgradeWatchdog_Disabled(t *testing.T) {
	d := &Daemon{cfg: &Config{UpgradeWatchdogEnabled: false}}
	d.startUpgradeWatchdog(t.Context())
	if d.upgradePending {
		t.Fatal("disabled watchdog must not set upgradePending")
	}
}

// fakePinger fails the first failN Pings, then succeeds.
type fakePinger struct {
	calls int
	failN int
}

func (f *fakePinger) Ping(ctx context.Context, _ *pb.PingRequest, _ ...grpc.CallOption) (*pb.PingResponse, error) {
	f.calls++
	if f.calls <= f.failN {
		return nil, errors.New("not serving yet")
	}
	return &pb.PingResponse{}, nil
}

func TestPingUntil_SucceedsAfterRetries(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()

	p := &fakePinger{failN: 3}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if !pingUntil(ctx, p) {
		t.Fatal("pingUntil should return true once Ping succeeds")
	}
	if p.calls != 4 {
		t.Fatalf("expected 4 ping attempts (3 fail + 1 ok), got %d", p.calls)
	}
}

func TestPingUntil_DeadlineReturnsFalse(t *testing.T) {
	old := pingPollInterval
	pingPollInterval = time.Millisecond
	defer func() { pingPollInterval = old }()

	p := &fakePinger{failN: 1 << 30} // never succeeds
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if pingUntil(ctx, p) {
		t.Fatal("pingUntil must return false when the deadline elapses without a successful Ping")
	}
}

// TestLocalGRPCClient_BadPKI: a missing PKI dir surfaces an error (no rollback —
// runUpgradeWatchdog treats this as environmental and skips).
func TestLocalGRPCClient_BadPKI(t *testing.T) {
	d := &Daemon{cfg: &Config{PKIDir: filepath.Join(t.TempDir(), "nonexistent"), GRPCPort: 7443}}
	if _, _, err := d.localGRPCClient(); err == nil {
		t.Fatal("expected an error building the local gRPC client with a bad PKI dir")
	}
}
