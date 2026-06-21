package main

import "testing"

// TestRootHasDaemonAndSchemaMigrate guards the unified-binary wiring: the
// single `litevirt` binary must expose `daemon` (the server) and
// `schema-migrate` (the folded-in pre-stage tool) alongside the CLI commands.
func TestRootHasDaemonAndSchemaMigrate(t *testing.T) {
	root := newRootCmd()
	want := map[string]bool{"daemon": false, "schema-migrate": false}
	for _, c := range root.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("root command missing %q subcommand", name)
		}
	}
}
