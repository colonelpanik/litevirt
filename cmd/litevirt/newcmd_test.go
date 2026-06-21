package main

import "testing"

func TestNewStatsCmd(t *testing.T) {
	cmd := newStatsCmd()

	if cmd.Use != "stats <vm>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "stats <vm>")
	}
	if cmd.Args == nil {
		t.Error("Args should not be nil (expected ExactArgs(1))")
	}
	// Verify it rejects zero args.
	if err := cmd.Args(cmd, nil); err == nil {
		t.Error("expected error with zero args")
	}
	// Verify it accepts exactly one arg.
	if err := cmd.Args(cmd, []string{"myvm"}); err != nil {
		t.Errorf("expected no error with one arg, got %v", err)
	}
}

func TestNewHealthCmd(t *testing.T) {
	cmd := newHealthCmd()

	if cmd.Use != "health" {
		t.Errorf("Use = %q, want %q", cmd.Use, "health")
	}
}

func TestNewAuditCmd(t *testing.T) {
	cmd := newAuditCmd()

	if cmd.Use != "audit" {
		t.Errorf("Use = %q, want %q", cmd.Use, "audit")
	}

	// turned `audit` into a parent with ls/verify/export.
	// --limit moved to `ls`.
	lsCmd, _, err := cmd.Find([]string{"ls"})
	if err != nil || lsCmd == nil {
		t.Fatalf("audit ls subcommand missing: %v", err)
	}
	limitFlag := lsCmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatal("expected --limit flag on audit ls")
	}
	if limitFlag.DefValue != "50" {
		t.Errorf("--limit default = %q, want %q", limitFlag.DefValue, "50")
	}
}

func TestNewUpdateCmd(t *testing.T) {
	cmd := newUpdateCmd()

	if cmd.Use != "update <vm>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "update <vm>")
	}

	// Verify Args rejects zero args.
	if cmd.Args == nil {
		t.Fatal("Args should not be nil")
	}
	if err := cmd.Args(cmd, nil); err == nil {
		t.Error("expected error with zero args")
	}
	if err := cmd.Args(cmd, []string{"myvm"}); err != nil {
		t.Errorf("expected no error with one arg, got %v", err)
	}

	// Check flags exist.
	expectedFlags := []string{"cpu", "memory", "disable-vnc"}
	for _, name := range expectedFlags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag %q not found", name)
		}
	}
}
