package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/mcpserver"
)

func TestMCPCmdInRootTree(t *testing.T) {
	cmd, _, err := newRootCmd().Find([]string{"mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd == nil || cmd.Name() != "mcp" {
		t.Fatalf("root mcp command = %#v", cmd)
	}
}

func TestMCPCmdFlagsAndEnv(t *testing.T) {
	oldRun := runMCPServer
	defer func() { runMCPServer = oldRun }()
	t.Setenv("LV_MCP_ALLOW_WRITE", "1")

	var got mcpserver.Options
	runMCPServer = func(_ context.Context, opts mcpserver.Options) error {
		got = opts
		return nil
	}

	cmd := newRootCmd()
	cmd.SetArgs([]string{"mcp", "--timeout", "2s", "--max-list-items", "7", "--tool-prefix", "lv_"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !got.AllowWrite {
		t.Fatal("AllowWrite = false, want true from LV_MCP_ALLOW_WRITE")
	}
	if got.Timeout != 2*time.Second {
		t.Fatalf("Timeout = %s, want 2s", got.Timeout)
	}
	if got.MaxListItems != 7 {
		t.Fatalf("MaxListItems = %d, want 7", got.MaxListItems)
	}
	if got.ToolPrefix != "lv_" {
		t.Fatalf("ToolPrefix = %q, want lv_", got.ToolPrefix)
	}
}

func TestMCPCmdWritesNoStdoutBeforeServerRun(t *testing.T) {
	oldRun := runMCPServer
	defer func() { runMCPServer = oldRun }()
	runMCPServer = func(_ context.Context, _ mcpserver.Options) error { return nil }

	var stdout bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{"mcp"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("mcp command wrote stdout before JSON-RPC server run: %q", stdout.String())
	}
}
