package main

import "testing"

// TestReExecSelfUsesPristineEnv pins the fix for findings 1 & 2: the
// self-upgrade re-exec must carry the env snapshot taken before obs mutated
// it (scrubbed credentials, setEnvDefault edits, accumulated
// OTEL_RESOURCE_ATTRIBUTES), not the live, obs-mutated os.Environ().
func TestReExecSelfUsesPristineEnv(t *testing.T) {
	pristine := []string{"LITEVIRT_OTEL_HEADERS=secret", "FOO=bar"}

	// Simulate obs mutating the live env after the snapshot was taken.
	t.Setenv("FOO", "mutated-by-obs")
	t.Setenv("EXTRA_JUNK", "added-by-obs")

	var gotEnv []string
	origExecFn := execFn
	execFn = func(argv0 string, argv, envv []string) error {
		gotEnv = envv
		return nil
	}
	t.Cleanup(func() { execFn = origExecFn })

	if err := reExecSelf(pristine); err != nil {
		t.Fatalf("reExecSelf returned error: %v", err)
	}

	if len(gotEnv) != len(pristine) {
		t.Fatalf("execFn got env %v, want exactly pristine snapshot %v", gotEnv, pristine)
	}
	for i, v := range pristine {
		if gotEnv[i] != v {
			t.Fatalf("execFn env[%d] = %q, want %q", i, gotEnv[i], v)
		}
	}
	for _, v := range gotEnv {
		if v == "EXTRA_JUNK=added-by-obs" || v == "FOO=mutated-by-obs" {
			t.Fatalf("execFn was passed live-env mutations, not the pristine snapshot: %v", gotEnv)
		}
	}
}
