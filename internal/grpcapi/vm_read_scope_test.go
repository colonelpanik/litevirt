package grpcapi

import (
	"context"
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ListVMs and InspectVM used to check only a cluster-wide viewer floor, while
// every write RPC authorizes against the VM's own path. A caller whose binding
// covered one project — or a token scoped to it — could therefore read every
// VM in the cluster, spec and cloud-init user-data included. These pin the
// read side to the same per-VM path the writes use.

// seedScopedVMs puts one VM in each of three projects, all on s's host so
// InspectVM answers locally.
func seedScopedVMs(t *testing.T, s *Server) {
	t.Helper()
	for _, v := range []struct{ name, project string }{
		{"a1", "acme"}, {"a2", "acme"}, {"b1", "beta"}, {"d1", ""},
	} {
		if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
			Name: v.name, HostName: s.hostName, State: "stopped", Project: v.project,
			Spec: `{"name":"` + v.name + `","user_data":"#cloud-config secret"}`,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", v.name, err)
		}
	}
}

func listedNames(t *testing.T, s *Server, ctx context.Context, pageSize int32) []string {
	t.Helper()
	var names []string
	token := ""
	for i := 0; i < 20; i++ {
		resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{PageSize: pageSize, PageToken: token})
		if err != nil {
			t.Fatalf("ListVMs(page_size=%d): %v", pageSize, err)
		}
		for _, vm := range resp.GetVms() {
			names = append(names, vm.GetName())
		}
		token = resp.GetNextPageToken()
		if token != "" {
			// The cursor is a plain encoding of a VM name, so it must never
			// carry one the caller is not allowed to see.
			parts, ok := decodePageToken(token)
			if !ok || len(parts) != 1 {
				t.Fatalf("undecodable page token %q", token)
			}
			if s.RequirePerm(ctx, vmRBACPathFor(vmProjectOf(t, s, parts[0]), parts[0]), "vm.read", "viewer") != nil {
				t.Errorf("page token names %q, a VM the caller cannot read", parts[0])
			}
		}
		if token == "" || pageSize == 0 {
			sort.Strings(names)
			return names
		}
	}
	t.Fatal("pagination did not terminate")
	return nil
}

func vmProjectOf(t *testing.T, s *Server, name string) string {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), s.db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): %v", name, err)
	}
	return vm.Project
}

func TestListVMs_AProjectScopedCallerSeesOnlyItsProject(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"binding": func(s *Server) context.Context {
			return grantUser(t, s, "carol", "/projects/acme", "Viewer")
		},
		// An admin user holding a token scoped to /projects/acme. RequireRole
		// used to refuse every scoped token outright; the per-VM check lets it
		// read exactly its scope.
		"scoped-token": func(*Server) context.Context {
			return context.WithValue(userCtx("tok-admin", "admin"), ctxKeyScopePaths, []string{"/projects/acme"})
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedScopedVMs(t, s)
			ctx := mk(s)
			for _, ps := range []int32{0, 1, 2} {
				if got := strings.Join(listedNames(t, s, ctx, ps), ","); got != "a1,a2" {
					t.Errorf("page_size=%d: listed %q, want only the acme VMs a1,a2", ps, got)
				}
			}
		})
	}
}

func TestListVMs_ClusterWideCallersSeeEveryVM(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		// Legacy role, no bindings anywhere: the role fallback is cluster-wide.
		"legacy-viewer": func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context {
			return grantUser(t, s, "rooty", "/", "Viewer")
		},
		// A peer daemon calling under its host certificate, on a cluster that
		// does have bindings (for someone else).
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedScopedVMs(t, s)
			ctx := mk(s)
			for _, ps := range []int32{0, 1} {
				if got := strings.Join(listedNames(t, s, ctx, ps), ","); got != "a1,a2,b1,d1" {
					t.Errorf("page_size=%d: listed %q, want every VM", ps, got)
				}
			}
		})
	}
}

func TestInspectVM_RefusesAVMOutsideTheCallersScope(t *testing.T) {
	s := testServer(t)
	seedScopedVMs(t, s)
	carol := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	if vm, err := s.InspectVM(carol, &pb.InspectVMRequest{Name: "a1"}); err != nil || vm.GetName() != "a1" {
		t.Fatalf("in-scope inspect: %v, %v", vm, err)
	}
	for _, name := range []string{"b1", "d1"} {
		_, err := s.InspectVM(carol, &pb.InspectVMRequest{Name: name})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("inspect %s (another project): %v, want PermissionDenied", name, err)
		}
	}
	tok := context.WithValue(userCtx("tok-admin", "admin"), ctxKeyScopePaths, []string{"/projects/acme"})
	if _, err := s.InspectVM(tok, &pb.InspectVMRequest{Name: "b1"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("scoped token inspecting b1: %v, want PermissionDenied", err)
	}
	if _, err := s.InspectVM(tok, &pb.InspectVMRequest{Name: "a1"}); err != nil {
		t.Errorf("scoped token inspecting a1 (in scope): %v", err)
	}
}

// The refusal must not be an existence oracle: a foreign VM and a name that
// exists nowhere answer alike, in code and message (same shape as
// TestClone_ABindingHolderCannotTellWhetherAForeignSourceExists).
func TestInspectVM_AScopedCallerCannotTellWhetherAForeignVMExists(t *testing.T) {
	holder := testServer(t)
	seedScopedVMs(t, holder)
	lacker := testServer(t)

	present := func() error {
		_, err := holder.InspectVM(grantUser(t, holder, "carol", "/projects/acme", "Viewer"), &pb.InspectVMRequest{Name: "b1"})
		return err
	}()
	absent := func() error {
		_, err := lacker.InspectVM(grantUser(t, lacker, "carol", "/projects/acme", "Viewer"), &pb.InspectVMRequest{Name: "b1"})
		return err
	}()
	if status.Code(present) != codes.PermissionDenied {
		t.Fatalf("foreign VM: %v, want PermissionDenied", present)
	}
	if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
		t.Errorf("a scoped caller can tell whether a foreign VM exists:\n  present: %v\n  absent:  %v", present, absent)
	}
}

func TestInspectVM_ClusterWideCallersUnchanged(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedScopedVMs(t, s)
			ctx := mk(s)
			for _, vm := range []string{"a1", "b1", "d1"} {
				if got, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: vm}); err != nil || got.GetName() != vm {
					t.Errorf("inspect %s: %v, %v", vm, got, err)
				}
			}
			if _, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "nope"}); status.Code(err) != codes.NotFound {
				t.Errorf("absent VM: %v, want NotFound", err)
			}
		})
	}
}
