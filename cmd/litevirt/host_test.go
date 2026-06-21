package main

import "testing"

func TestNewHostConfigCmd(t *testing.T) {
	cmd := newHostConfigCmd()

	if cmd.Use != "config <host>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "config <host>")
	}
	if cmd.Short == "" {
		t.Error("Short should not be empty")
	}

	expectedFlags := []string{
		"fence-strategy",
		"ipmi-address",
		"ipmi-user",
		"ipmi-pass",
		"watchdog-dev",
	}
	for _, name := range expectedFlags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag %q not found", name)
		}
	}
}
