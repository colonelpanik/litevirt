package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestResolveRegistryCredential_Precedence checks per-user beats global, global
// is the fallback, and a registry with no credential resolves to nil.
func TestResolveRegistryCredential_Precedence(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	mustUpsert(t, s.db, corrosion.RegistryCredential{
		ID: "1", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice-u", Secret: "alice-secret",
	})
	mustUpsert(t, s.db, corrosion.RegistryCredential{
		ID: "2", Scope: "global", Owner: "", Registry: "ghcr.io", Username: "global-u", Secret: "global-secret",
	})

	if rc, err := corrosion.ResolveRegistryCredential(ctx, s.db, "alice", "ghcr.io"); err != nil || rc == nil || rc.Username != "alice-u" {
		t.Fatalf("alice@ghcr.io = %+v, err=%v; want alice's row", rc, err)
	}
	if rc, err := corrosion.ResolveRegistryCredential(ctx, s.db, "bob", "ghcr.io"); err != nil || rc == nil || rc.Username != "global-u" {
		t.Fatalf("bob@ghcr.io = %+v, err=%v; want global row", rc, err)
	}
	if rc, err := corrosion.ResolveRegistryCredential(ctx, s.db, "alice", "docker.io"); err != nil || rc != nil {
		t.Fatalf("alice@docker.io = %+v, err=%v; want nil (anonymous)", rc, err)
	}
}

// TestSetRegistryCredential_Authz: global writes need operator; per-user writes
// are owned by the caller regardless of any client-supplied value.
func TestSetRegistryCredential_Authz(t *testing.T) {
	s := testServer(t)

	// A viewer cannot set a global credential.
	_, err := s.SetRegistryCredential(userCtx("vic", "viewer"), &pb.SetRegistryCredentialRequest{
		Global: true, Registry: "ghcr.io", Username: "u", Password: "p",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer global set: got %v, want PermissionDenied", err)
	}

	// An operator can.
	if _, err := s.SetRegistryCredential(userCtx("op", "operator"), &pb.SetRegistryCredentialRequest{
		Global: true, Registry: "ghcr.io", Username: "gu", Password: "gp",
	}); err != nil {
		t.Fatalf("operator global set: %v", err)
	}

	// A per-user set is owned by the caller (alice), even though there is no
	// owner field on the wire to spoof.
	rc, err := s.SetRegistryCredential(userCtx("alice", "operator"), &pb.SetRegistryCredentialRequest{
		Registry: "ghcr.io", Username: "au", Password: "ap",
	})
	if err != nil {
		t.Fatalf("alice per-user set: %v", err)
	}
	if rc.Scope != "user" || rc.Owner != "alice" {
		t.Fatalf("stored scope/owner = %s/%s, want user/alice", rc.Scope, rc.Owner)
	}
	// Resolution for alice now returns her personal row, not the global one.
	got, _ := corrosion.ResolveRegistryCredential(context.Background(), s.db, "alice", "ghcr.io")
	if got == nil || got.Username != "au" || got.Secret != "ap" {
		t.Fatalf("alice resolve = %+v, want her personal au/ap", got)
	}
}

// TestListRegistryCredentials_Redacts confirms the wire type carries the
// username but never the secret (the pb message has no secret field), and that
// per-user listing includes the caller's own + global rows.
func TestListRegistryCredentials_Redacts(t *testing.T) {
	s := testServer(t)
	mustUpsert(t, s.db, corrosion.RegistryCredential{ID: "1", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "au", Secret: "as"})
	mustUpsert(t, s.db, corrosion.RegistryCredential{ID: "2", Scope: "global", Registry: "docker.io", Username: "gu", Secret: "gs"})
	mustUpsert(t, s.db, corrosion.RegistryCredential{ID: "3", Scope: "user", Owner: "bob", Registry: "quay.io", Username: "bu", Secret: "bs"})

	resp, err := s.ListRegistryCredentials(userCtx("alice", "operator"), &pb.ListRegistryCredentialsRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.Credentials) != 2 { // alice's ghcr.io + the global docker.io; NOT bob's
		t.Fatalf("got %d creds, want 2 (own + global)", len(resp.Credentials))
	}
	for _, rc := range resp.Credentials {
		if rc.Username == "" {
			t.Errorf("username missing for %s", rc.Registry)
		}
		if rc.Owner == "bob" {
			t.Errorf("alice's list leaked bob's row: %+v", rc)
		}
	}

	// --all requires operator and surfaces every owner.
	all, err := s.ListRegistryCredentials(userCtx("op", "operator"), &pb.ListRegistryCredentialsRequest{All: true})
	if err != nil {
		t.Fatalf("list --all: %v", err)
	}
	if len(all.Credentials) != 3 {
		t.Fatalf("list --all got %d, want 3", len(all.Credentials))
	}
	if _, err := s.ListRegistryCredentials(userCtx("vic", "viewer"), &pb.ListRegistryCredentialsRequest{All: true}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer --all: got %v, want PermissionDenied", err)
	}
}

// TestDeleteRegistryCredential covers NotFound + soft-delete-then-re-add.
func TestDeleteRegistryCredential(t *testing.T) {
	s := testServer(t)
	if _, err := s.SetRegistryCredential(userCtx("alice", "operator"), &pb.SetRegistryCredentialRequest{
		Registry: "ghcr.io", Username: "au", Password: "ap",
	}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := s.DeleteRegistryCredential(userCtx("alice", "operator"), &pb.DeleteRegistryCredentialRequest{Registry: "ghcr.io"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Second delete → NotFound.
	if _, err := s.DeleteRegistryCredential(userCtx("alice", "operator"), &pb.DeleteRegistryCredentialRequest{Registry: "ghcr.io"}); status.Code(err) != codes.NotFound {
		t.Fatalf("double delete: got %v, want NotFound", err)
	}
	// Re-add must succeed (partial unique index excludes the tombstone).
	if _, err := s.SetRegistryCredential(userCtx("alice", "operator"), &pb.SetRegistryCredentialRequest{
		Registry: "ghcr.io", Username: "au2", Password: "ap2",
	}); err != nil {
		t.Fatalf("re-add after delete: %v", err)
	}
	got, _ := corrosion.ResolveRegistryCredential(context.Background(), s.db, "alice", "ghcr.io")
	if got == nil || got.Username != "au2" {
		t.Fatalf("after re-add resolve = %+v, want au2", got)
	}
}

// TestPullOCIImage_ResolvesStoredCredential threads the full pull path: a stored
// per-user credential is resolved on the entry node and passed to the runtime;
// inline creds short-circuit resolution; a local oci: ref gets none.
func TestPullOCIImage_ResolvesStoredCredential(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	rt := &fakeCTRuntime{}
	s.SetContainerRuntime(rt)
	mustUpsert(t, s.db, corrosion.RegistryCredential{
		ID: "1", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "au", Secret: "as",
	})
	// admin: an absolute --dest and a local oci: source both require it; this
	// test threads username-based credential resolution, which is role-agnostic.
	alice := userCtx("alice", "admin")

	// (a) stored credential resolved.
	if _, err := s.PullOCIImage(alice, &pb.PullOCIImageRequest{Image: "ghcr.io/org/x:v1", Dest: "/tmp/r"}); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if got := rt.pullCalls[0]; got.Username != "au" || got.Password != "as" {
		t.Fatalf("resolved creds = %q/%q, want au/as", got.Username, got.Password)
	}

	// (b) inline creds short-circuit resolution.
	if _, err := s.PullOCIImage(alice, &pb.PullOCIImageRequest{
		Image: "ghcr.io/org/x:v1", Dest: "/tmp/r", Username: "inline", Password: "pw",
	}); err != nil {
		t.Fatalf("pull inline: %v", err)
	}
	if got := rt.pullCalls[1]; got.Username != "inline" || got.Password != "pw" {
		t.Fatalf("inline creds = %q/%q, want inline/pw", got.Username, got.Password)
	}

	// (c) local oci: ref → no creds attached even with a matching stored row.
	if _, err := s.PullOCIImage(alice, &pb.PullOCIImageRequest{Image: "oci:/var/lib/litevirt/oci/x:v1", Dest: "/tmp/r"}); err != nil {
		t.Fatalf("pull oci-local: %v", err)
	}
	if got := rt.pullCalls[2]; got.Username != "" || got.Password != "" {
		t.Fatalf("oci-local creds = %q/%q, want empty", got.Username, got.Password)
	}
}

func mustUpsert(t *testing.T, db *corrosion.Client, rc corrosion.RegistryCredential) {
	t.Helper()
	if err := corrosion.UpsertRegistryCredential(context.Background(), db, rc); err != nil {
		t.Fatalf("upsert %+v: %v", rc, err)
	}
}
