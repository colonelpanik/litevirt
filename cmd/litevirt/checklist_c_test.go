package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/obs"
)

// Checklist (c) — self-upgrade re-exec env contract, runnable on macOS.
//
// Proves the two halves of findings 1 & 2 without systemd or libvirt:
//  1. reExecSelf hands the pristine snapshot to execFn (not live os.Environ).
//  2. A real child process started with that pristine env still has the
//     collector credential after obs.Setup has scrubbed the parent's live env,
//     and does NOT see post-Setup pollution.
//
//	go test ./cmd/litevirt/ -count=1 -v -run TestChecklist_C
func TestChecklist_C_ReExecPristineEnv_ChildKeepsCredential(t *testing.T) {
	// Child mode: re-entered via exec of this test binary with the pristine env.
	if os.Getenv("CHECKLIST_C_CHILD") == "1" {
		runChecklistCChild(t)
		return
	}

	// Isolate from ambient operator env that would confuse the scrub check.
	for _, k := range []string{
		"LITEVIRT_OTEL_HEADERS", "OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_ENDPOINT", "LITEVIRT_OTEL_ENDPOINT",
		"OTEL_RESOURCE_ATTRIBUTES", "EXTRA_POLLUTION",
		"PROVIDE_LOG_OTLP_ENABLED", "PROVIDE_METRICS_ENABLED",
	} {
		t.Setenv(k, "")
		_ = os.Unsetenv(k)
	}

	// Operator/systemd-shaped env BEFORE any obs mutation — this is what
	// runDaemon snapshots as pristineEnv.
	const secret = "Authorization=Bearer secret-checklist-c"
	if err := os.Setenv("LITEVIRT_OTEL_HEADERS", secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("LITEVIRT_OTEL_ENDPOINT", "http://127.0.0.1:4318"); err != nil {
		t.Fatal(err)
	}
	pristine := os.Environ()

	// obs.Setup scrubs the credential from the live process env (finding 1
	// protection for QEMU/hooks) and may write OTEL_RESOURCE_ATTRIBUTES.
	shutdown, err := obs.Setup(context.Background(), obs.Config{
		ServiceName:  "checklist-c",
		HostName:     "mac-node",
		OTLPEndpoint: "http://127.0.0.1:4318",
	})
	if err != nil {
		t.Logf("Setup err (fail-open ok): %v", err)
	}
	if shutdown != nil {
		t.Cleanup(func() { _ = shutdown(context.Background()) })
	}

	if got := os.Getenv("LITEVIRT_OTEL_HEADERS"); got != "" {
		t.Fatalf("parent live env still has LITEVIRT_OTEL_HEADERS=%q after Setup; scrub failed", got)
	}
	// Simulate further post-Setup pollution that must not ride the re-exec.
	if err := os.Setenv("EXTRA_POLLUTION", "from-obs-after-setup"); err != nil {
		t.Fatal(err)
	}

	// Half 1: reExecSelf must pass pristine to execFn, not live os.Environ().
	var gotEnv []string
	orig := execFn
	execFn = func(argv0 string, argv, envv []string) error {
		gotEnv = append([]string(nil), envv...)
		return nil // do not replace this process
	}
	t.Cleanup(func() { execFn = orig })

	if err := reExecSelf(pristine); err != nil {
		t.Fatalf("reExecSelf: %v", err)
	}
	if len(gotEnv) == 0 {
		t.Fatal("execFn was not invoked")
	}
	joined := strings.Join(gotEnv, "\n")
	if !strings.Contains(joined, "LITEVIRT_OTEL_HEADERS="+secret) {
		t.Fatalf("reExecSelf env missing credential; got:\n%s", joined)
	}
	if strings.Contains(joined, "EXTRA_POLLUTION=from-obs-after-setup") {
		t.Fatalf("reExecSelf env contains live-env pollution; got:\n%s", joined)
	}
	// Live env must still be scrubbed (snapshot was a copy, not a live alias).
	if got := os.Getenv("LITEVIRT_OTEL_HEADERS"); got != "" {
		t.Fatalf("pristine slice aliasing live env? parent headers became %q", got)
	}

	// Half 2: a real child process with the same env reExecSelf would pass
	// still sees the credential (and not pollution). This is the closest
	// macOS stand-in for systemd Environment= + execve without libvirt.
	cmd := exec.Command(os.Args[0], "-test.run=^TestChecklist_C_ReExecPristineEnv_ChildKeepsCredential$", "-test.v=true")
	cmd.Env = append(append([]string{}, gotEnv...),
		"CHECKLIST_C_CHILD=1",
		// go test needs these to re-enter the same binary cleanly.
		"CHECKLIST_C_EXPECT_SECRET="+secret,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child process failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "CHECKLIST_C_CHILD_OK") {
		t.Fatalf("child did not report OK; output:\n%s", out)
	}
}

func runChecklistCChild(t *testing.T) {
	t.Helper()
	want := os.Getenv("CHECKLIST_C_EXPECT_SECRET")
	if want == "" {
		t.Fatal("child missing CHECKLIST_C_EXPECT_SECRET")
	}
	if got := os.Getenv("LITEVIRT_OTEL_HEADERS"); got != want {
		t.Fatalf("child LITEVIRT_OTEL_HEADERS=%q; want %q (pristine re-exec must carry credential)", got, want)
	}
	if got := os.Getenv("EXTRA_POLLUTION"); got != "" {
		t.Fatalf("child saw EXTRA_POLLUTION=%q; pristine re-exec must not carry post-Setup pollution", got)
	}
	// Scrubbed header names must not appear as empty survivors from live env —
	// they simply were never in pristine (pristine was taken before scrub, so
	// LITEVIRT_OTEL_HEADERS is present; OTEL_*_HEADERS may have been set by
	// Setup mapping then scrubbed only in the parent).
	fmt.Println("CHECKLIST_C_CHILD_OK")
}
