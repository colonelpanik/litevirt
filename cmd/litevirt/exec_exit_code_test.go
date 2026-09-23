package main

import "testing"

// `lv exec` is how a script runs a command in a guest, so its exit status is
// the command's result. Discarding it makes every guest failure look like a
// success: `lv exec vm false && echo ok` prints ok.
//
// The container twin already does this (ct.go calls os.Exit(res.ExitCode)),
// so the two halves of the same verb disagreed.
func TestExecExitError_CarriesTheGuestStatus(t *testing.T) {
	if err := execExitError(0); err != nil {
		t.Errorf("exit 0 produced %v, want nil — a successful command is not an error", err)
	}

	for _, code := range []int32{1, 2, 42, 127} {
		err := execExitError(code)
		if err == nil {
			t.Errorf("exit %d produced nil; `lv exec vm false` would report success", code)
			continue
		}
		got, ok := exitCodeOf(err)
		if !ok {
			t.Errorf("exit %d produced %T, which the root command cannot turn into an exit status", code, err)
			continue
		}
		if got != int(code) {
			t.Errorf("exit %d surfaced as %d", code, got)
		}
	}
}
