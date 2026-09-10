package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// enableVMReplace makes `lv cutover` runnable on s: the operator opted in AND
// vm_replace_v1 has latched cluster-wide. Both halves are required, so a test
// that drives a real cutover has to say so explicitly.
func enableVMReplace(s *Server) {
	s.SetVMReplaceEnforce(true)
	s.gate = fakeServerGate{enforcedTok: map[string]bool{capabilities.VMReplaceV1: true}}
}

// A cutover on a cluster that has not latched vm_replace_v1 must refuse, and must
// refuse having changed NOTHING — not the domain, not either VM's rows. The
// guarded replace batch carries a protocol an un-upgraded receiver cannot
// evaluate, so discovering this after the teardown would destroy the replaced VM
// for a transition that can never be emitted.
func TestCutoverRefusedWithoutVMReplaceCapability(t *testing.T) {
	ctx := adminCtx()

	for _, tc := range []struct {
		name    string
		prepare func(s *Server)
	}{
		{"neither flag nor latch", func(*Server) {}},
		{"flag on, not latched", func(s *Server) {
			s.SetVMReplaceEnforce(true)
			s.gate = fakeServerGate{enforcedTok: map[string]bool{}}
		}},
		{"latched, flag off", func(s *Server) {
			s.gate = fakeServerGate{enforcedTok: map[string]bool{capabilities.VMReplaceV1: true}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			tc.prepare(s)
			if err := corrosion.InsertVM(ctx, s.db,
				corrosion.VMRecord{Name: "app", HostName: s.hostName, Spec: `{"cpu":2}`, State: "running"},
				nil, nil); err != nil {
				t.Fatalf("InsertVM replaced: %v", err)
			}
			if err := corrosion.InsertVM(ctx, s.db,
				corrosion.VMRecord{Name: "app-next", HostName: s.hostName, Spec: `{"cpu":4}`, State: "running"},
				nil, nil); err != nil {
				t.Fatalf("InsertVM replacement: %v", err)
			}

			_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"})
			if c := status.Code(err); c != codes.FailedPrecondition {
				t.Fatalf("code = %v (%v), want FailedPrecondition", c, err)
			}

			// Both VMs untouched: still live, still under their own names, still
			// carrying their own specs.
			replaced, gErr := corrosion.GetVM(ctx, s.db, "app")
			if gErr != nil || replaced == nil {
				t.Fatalf(`replaced VM after a refused cutover: %+v err=%v`, replaced, gErr)
			}
			if replaced.Spec != `{"cpu":2}` {
				t.Errorf("replaced VM spec = %q, want its own", replaced.Spec)
			}
			replacement, gErr := corrosion.GetVM(ctx, s.db, "app-next")
			if gErr != nil || replacement == nil {
				t.Fatalf("replacement after a refused cutover: %+v err=%v", replacement, gErr)
			}
		})
	}
}

// The refusal must name the flag an operator has to set — a bare
// FailedPrecondition on the most destructive VM operation is not actionable.
func TestCutoverRefusalNamesTheEnforcementFlag(t *testing.T) {
	s := testServer(t)
	_, err := s.CutoverVM(adminCtx(), &pb.CutoverVMRequest{VmName: "app"})
	if err == nil {
		t.Fatal("cutover did not refuse")
	}
	for _, want := range []string{"enforcement.vm_replace", "vm_replace_v1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not mention %q", err, want)
		}
	}
}

// The advertisement half: a node withholds vm_replace_v1 while its flag is off,
// so the cluster cannot latch — and therefore no node starts emitting a guard
// protocol its peers may not understand — until every operator has opted in.
func TestVMReplaceAdvertisedOnlyWithTheFlag(t *testing.T) {
	s := &Server{hostName: "h"}
	if capabilities.Has(s.advertisedCapabilities(), capabilities.VMReplaceV1) {
		t.Error("vm_replace_v1 advertised with enforcement.vm_replace off")
	}
	s.SetVMReplaceEnforce(true)
	if !capabilities.Has(s.advertisedCapabilities(), capabilities.VMReplaceV1) {
		t.Error("vm_replace_v1 not advertised with enforcement.vm_replace on")
	}
}
