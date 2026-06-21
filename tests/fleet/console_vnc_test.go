// Fleet scenario: multi-host console/VNC forwarding + error diagnosability.
//
// The web UI's "VNC/terminal shows disconnected for many VMs" bug was rooted in
// the cross-host forward path (forwardVNC/forwardConsole → peerClient) collapsing
// every failure into an opaque error. These scenarios prove, across REAL nodes
// over loopback mTLS, that:
//   - a VM on a host missing from cluster state → codes.Unavailable (not Internal)
//   - a VM on a peer whose daemon is down → codes.Unavailable "unreachable"
//   - a stopped VM → codes.FailedPrecondition "not running"
// i.e. the daemon now hands the UI a specific, surface-able reason.
package fleet

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// vncErr opens a ProxyVNC stream for vmName via node n and returns the first
// error surfaced (the daemon's gRPC status flows back to this Recv).
func vncErr(c *Cluster, n *Node, vmName string) error {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-vm-name", vmName))
	stream, err := c.SelfClient(n).ProxyVNC(ctx)
	if err != nil {
		return err
	}
	_, err = stream.Recv()
	return err
}

func consoleErr(c *Cluster, n *Node, vmName string) error {
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-vm-name", vmName))
	stream, err := c.SelfClient(n).ConsoleVM(ctx)
	if err != nil {
		return err
	}
	_, err = stream.Recv()
	return err
}

func TestFleet_VNC_GhostHostUnavailable(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	ctx := context.Background()
	n0 := c.Nodes[0]

	// A "running" VM whose owning host isn't registered in cluster state.
	if err := corrosion.InsertVM(ctx, n0.DB, corrosion.VMRecord{
		Name: "ghost-vm", HostName: "ghost-host", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	err := vncErr(c, n0, "ghost-vm")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("ghost host: code = %v, want Unavailable; err = %v", status.Code(err), err)
	}
}

func TestFleet_VNC_PeerDownUnavailable(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	ctx := context.Background()
	n0, n1 := c.Nodes[0], c.Nodes[1]

	// VM owned by n1, present in n0's DB so n0 forwards to n1.
	if err := corrosion.InsertVM(ctx, n0.DB, corrosion.VMRecord{
		Name: "rv", HostName: n1.Name, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Take n1's daemon down — the forward dial now fails.
	n1.GRPCSrv.Stop()

	err := vncErr(c, n0, "rv")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("peer down: code = %v, want Unavailable; err = %v", status.Code(err), err)
	}
	if !strings.Contains(strings.ToLower(status.Convert(err).Message()), "unreachable") {
		t.Errorf("peer down: message = %q, want 'unreachable'", status.Convert(err).Message())
	}
}

func TestFleet_VNC_NotRunningFailedPrecondition(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	ctx := context.Background()
	n0 := c.Nodes[0]

	if err := corrosion.InsertVM(ctx, n0.DB, corrosion.VMRecord{
		Name: "stopped-vm", HostName: n0.Name, Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"vnc", vncErr(c, n0, "stopped-vm")},
		{"console", consoleErr(c, n0, "stopped-vm")},
	} {
		if status.Code(tc.err) != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition; err = %v", tc.name, status.Code(tc.err), tc.err)
		}
		if !strings.Contains(status.Convert(tc.err).Message(), "not running") {
			t.Errorf("%s: message = %q, want 'not running'", tc.name, status.Convert(tc.err).Message())
		}
	}
}

// TestFleet_VNC_VMNotFound proves a bogus VM name yields NotFound, not a
// generic disconnect.
func TestFleet_VNC_VMNotFound(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	defer c.Stop()
	err := vncErr(c, c.Nodes[0], "does-not-exist")
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound; err = %v", status.Code(err), err)
	}
}
