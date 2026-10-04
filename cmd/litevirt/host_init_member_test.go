package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// `lv host init` asks the configured cluster before touching the target
// (colonelpanik/litevirt#229): a founder re-initialised from a workstation is
// refused before any SSH connection is made.
func TestHostInitCmd_RefusesAFounderTheClusterLists(t *testing.T) {
	orig := cli.Connect
	t.Cleanup(func() { cli.Connect = orig })
	cli.Connect = func(context.Context) (pb.LiteVirtClient, func(), error) {
		return &mockClient{hosts: []*pb.Host{
			{Name: "node-1", Address: "192.0.2.10"},
			{Name: "node-2", Address: "192.0.2.11"},
		}}, func() {}, nil
	}

	cmd := newHostInitCmd()
	cmd.SetArgs([]string{"root@192.0.2.10", "--name", "node-1"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err := cmd.ExecuteContext(context.Background())
	if err == nil || !strings.Contains(err.Error(), "lv host rm node-1") {
		t.Fatalf("init against a listed founder: err = %v, want the cluster-member refusal", err)
	}
}
