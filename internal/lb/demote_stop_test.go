package lb

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestHelperKeepalivedHang is a re-exec helper (not a real test): it stands in for a HUNG
// keepalived that IGNORES SIGTERM, so stopKeepalivedConfirmed must fall back to SIGKILL. It
// prints "ready\n" only AFTER the ignore is installed, so the parent never races the signal.
func TestHelperKeepalivedHang(t *testing.T) {
	if os.Getenv("LV_HELPER_HANG") != "1" {
		return
	}
	signal.Ignore(syscall.SIGTERM)
	fmt.Println("ready")
	time.Sleep(60 * time.Second)
	os.Exit(0)
}

// A keepalived that ignores SIGTERM (a hung/stuck instance) must still be CONFIRMED stopped
// via the SIGKILL hard fallback, within the ceiling + a short reap window — the demotion
// invariant a leftover keepalived can't defeat. Uses a real SIGTERM-ignoring child so the
// SIGTERM→timeout→SIGKILL→verify path is exercised end to end.
func TestStopKeepalivedConfirmed_HungKeepalivedSIGKILLFallback(t *testing.T) {
	m := &Manager{configDir: t.TempDir(), runDir: t.TempDir()}
	const name = "hung"

	helper := exec.Command(os.Args[0], "-test.run=^TestHelperKeepalivedHang$")
	helper.Env = append(os.Environ(), "LV_HELPER_HANG=1")
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	pid := helper.Process.Pid
	// Reap concurrently so a SIGKILLed child doesn't linger as a zombie (a zombie still
	// answers kill(pid,0), which would falsely read as "alive").
	waited := make(chan struct{})
	go func() { _, _ = helper.Process.Wait(); close(waited) }()
	t.Cleanup(func() { _ = helper.Process.Kill(); <-waited })

	// Block until the helper has installed its SIGTERM-ignore, so we can't race the signal.
	if line, _ := bufio.NewReader(stdout).ReadString('\n'); line != "ready\n" {
		t.Fatalf("helper did not report ready; got %q", line)
	}

	// Record its pid as this LB's keepalived.
	pidFile := filepath.Join(m.runDir, name+"-keepalived.pid")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	if !pidAlive(pidFile) {
		t.Fatal("precondition: helper must be alive before demotion")
	}

	const ceiling = 200 * time.Millisecond
	start := time.Now()
	err = m.stopKeepalivedConfirmed(name, ceiling)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("hung keepalived must be confirmed stopped via SIGKILL fallback; got %v", err)
	}
	// SIGTERM was ignored, so it can only be gone if the SIGKILL fallback fired. Bound the
	// time so this proves the fallback ran within the ceiling + the reap window, not a hang.
	if elapsed > 3*time.Second {
		t.Fatalf("confirm took %v; the SIGKILL fallback should complete just past the %v ceiling", elapsed, ceiling)
	}
	// Give the concurrent reap a beat, then the process must be gone.
	deadline := time.Now().Add(time.Second)
	for processAlive(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatal("helper still alive after confirmed stop — SIGKILL fallback did not kill it")
	}
	// The pidfile is reclaimed on a confirmed stop.
	if _, statErr := os.Stat(pidFile); !os.IsNotExist(statErr) {
		t.Errorf("keepalived pidfile must be removed on a confirmed stop; stat err=%v", statErr)
	}
}
