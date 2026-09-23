package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// ExecVM never populated ExitCode: it called ExecInGuest, which collapses a
// non-zero guest exit into an error, and returned
// &pb.ExecVMResponse{Stdout: ...} on the only path that reached the response.
//
// So `lv exec` could not report a guest's status no matter what the CLI did
// with resp.ExitCode — a failing command took the error path, the guest's
// stdout was discarded, and the process exited 1 for exit 2 and exit 127
// alike. A CLI-side test of the exit-code helper passes against all of that,
// which is exactly why this test drives the RPC instead.
//
// A command that ran and returned non-zero is a RESULT, not an RPC failure.
// The error return is reserved for failing to run it at all.
func TestExecVM_ReportsTheGuestsExitCodeRatherThanErroring(t *testing.T) {
	s := testServerR2(t)
	fake := libvirtfake.New()
	s.virt = fake
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "exec-code", "test-host", "running")

	fake.SetExecResult("stdout-here\n", "stderr-here\n", 3)

	resp, err := s.ExecVM(ctx, &pb.ExecVMRequest{
		Name:    "exec-code",
		Command: []string{"sh", "-c", "exit 3"},
	})
	if err != nil {
		t.Fatalf("a guest command that exited 3 came back as an RPC error: %v\n"+
			"the exit status is a result to report, not a transport failure", err)
	}
	if resp.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3 — the CLI cannot report what the daemon never sends", resp.ExitCode)
	}
	if got := string(resp.Stdout); got != "stdout-here\n" {
		t.Errorf("Stdout = %q, want %q — a failing command's output must survive", got, "stdout-here\n")
	}
	if got := string(resp.Stderr); got != "stderr-here\n" {
		t.Errorf("Stderr = %q, want %q", got, "stderr-here\n")
	}
}

// Exit 0 must stay an ordinary success.
func TestExecVM_ZeroExitIsStillSuccess(t *testing.T) {
	s := testServerR2(t)
	fake := libvirtfake.New()
	s.virt = fake
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "exec-ok", "test-host", "running")

	fake.SetExecResult("fine\n", "", 0)

	resp, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "exec-ok", Command: []string{"true"}})
	if err != nil {
		t.Fatalf("ExecVM: %v", err)
	}
	if resp.ExitCode != 0 || string(resp.Stdout) != "fine\n" {
		t.Errorf("ExitCode=%d Stdout=%q, want 0 / %q", resp.ExitCode, resp.Stdout, "fine\n")
	}
}
