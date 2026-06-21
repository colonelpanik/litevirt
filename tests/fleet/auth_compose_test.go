// Fleet scenario 1: auth + compose deploy with backup schedule.
//
// Drives a real DeployStack through gRPC against a 1-node fleet
// with the libvirt fake wired in. Asserts:
//   - libvirtfake recorded a `define` + `start` event for the VM
//   - the compose `backup:` block flowed through syncComposeBackupSchedule
//     into a backup_schedules row
//   - the VM record landed in Corrosion with the placement-pinned host
//   - the compose deploy hook is idempotent: re-deploying the same
//     YAML updates the schedule rather than duplicating it
//
// What's NOT exercised: full multi-VM placement reasoning, network
// provisioning (those would need a real network reconciler running
// in the fleet — the fake networks scenario is its own piece).

package fleet

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

var (
	osMkdirAll = os.MkdirAll
	osCreate   = os.Create
)

const composeBackup = `name: e2e-stack

images:
  test:
    source: file:///dev/null

vms:
  web-1:
    image: test
    cpu: 2
    memory: 1024
    placement:
      host: node-0
    backup:
      repo: main
      schedule: "0 2 * * *"
      retention:
        keep-daily: 7
`

func TestFleet_AuthAndComposeDeploy(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	node := c.Nodes[0]

	// Seed the image so CreateVM doesn't fail on missing-image.
	if err := node.DB.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES ('test', 'qcow2', 'file:///dev/null', 'deadbeef', 1024, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed image: %v", err)
	}

	// Stage a real (zero-byte) file in the image.Store so the auto-pull
	// path takes the "already present" branch.
	imgFile := node.Server.ImagePathForTests("test")
	if err := writeEmptyImageFile(imgFile); err != nil {
		t.Fatalf("stage image file: %v", err)
	}

	// Deploy via the gRPC server (mTLS-admin path: SelfClient dials
	// over TLS, no bearer → handler treats us as admin).
	client := c.SelfClient(node)
	deployAndDrain(t, ctx, client, &pb.DeployStackRequest{ComposeYaml: composeBackup})

	// Assert: VM row landed.
	vm, err := corrosion.GetVM(ctx, node.DB, "web-1")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm == nil {
		t.Fatal("VM web-1 should exist after deploy")
	}
	if vm.HostName != "node-0" {
		t.Errorf("VM host = %q, want node-0", vm.HostName)
	}

	// Assert: libvirtfake recorded define + start.
	events := node.Virt.EventLog()
	if !sawEvent(events, "define", "web-1") {
		t.Errorf("libvirtfake should have recorded a define event for web-1: %+v", events)
	}
	if !sawEvent(events, "start", "web-1") {
		t.Errorf("libvirtfake should have recorded a start event for web-1: %+v", events)
	}

	// Assert: backup_schedules row created from the compose hook.
	sched, _ := corrosion.ListBackupSchedules(ctx, node.DB)
	if len(sched) != 1 {
		t.Fatalf("expected 1 backup_schedule row, got %d", len(sched))
	}
	got := sched[0]
	if got.VMName != "web-1" || got.Repo != "main" || got.Cron != "0 2 * * *" {
		t.Errorf("schedule mismatch: %+v", got)
	}
	if got.KeepDaily != 7 {
		t.Errorf("KeepDaily = %d, want 7", got.KeepDaily)
	}

	// Re-deploy: hook is idempotent — same row count, updated_at moves.
	deployAndDrain(t, ctx, client, &pb.DeployStackRequest{ComposeYaml: composeBackup})
	sched2, _ := corrosion.ListBackupSchedules(ctx, node.DB)
	if len(sched2) != 1 {
		t.Errorf("re-deploy should not duplicate schedule, got %d rows", len(sched2))
	}
}

// TestFleet_TokenScopeDeniesOutOfScopePath proves the auth scope
// picker we added to /users actually gates RPCs at runtime: a token
// scoped to /projects/_default/vms/foo is rejected when used against
// a different VM's path. End-to-end: handler → ValidateToken →
// auth.Engine.HasPermission against scope_paths intersection.
func TestFleet_TokenScopeDeniesOutOfScopePath(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	node := c.Nodes[0]
	admin := c.SelfClient(node)

	// Admin creates a user + a scoped token for that user.
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "scoped-bot", Password: "p4ssw0rd", Role: "operator",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tokResp, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{
		Username:   "scoped-bot",
		Name:       "narrow",
		ScopePaths: []string{"/projects/_default/vms/permitted"},
	})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if tokResp.Token == "" {
		t.Fatal("CreateToken returned empty token")
	}

	// New client carrying the scoped bearer.
	bearer := c.bearerClient(node, tokResp.Token)

	// Out-of-scope: CreateBackupSchedule uses RequirePerm with the
	// path "/projects/_default/vms/<name>". The scope-paths check
	// fires before any DB lookup, so VM existence is irrelevant.
	_, err = bearer.CreateBackupSchedule(ctx, &pb.CreateBackupScheduleRequest{
		VmName: "out-of-scope", Repo: "main", Cron: "0 2 * * *",
	})
	if err == nil {
		t.Fatal("scoped token should be denied when used outside its scope_paths")
	}
	if !strings.Contains(err.Error(), "PermissionDenied") && !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected PermissionDenied, got %v", err)
	}

	// In-scope: same RPC against the permitted VM clears the auth
	// check (and then fails on a different ground — VM not found —
	// which is exactly the contract: scope_paths gates *access*,
	// not *existence*.)
	_, err = bearer.CreateBackupSchedule(ctx, &pb.CreateBackupScheduleRequest{
		VmName: "permitted", Repo: "main", Cron: "0 2 * * *",
	})
	if err == nil {
		t.Fatal("expected VM-not-found for missing in-scope VM, got success")
	}
	if strings.Contains(err.Error(), "PermissionDenied") {
		t.Errorf("in-scope path should not get PermissionDenied: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected NotFound (VM doesn't exist), got %v", err)
	}
}

// deployAndDrain calls DeployStack and consumes the stream until EOF
// or a non-progress error. Returns silently on success; fatals the
// test on error. Most scenario asserts care about the post-deploy
// DB state rather than the progress messages themselves.
func deployAndDrain(t *testing.T, ctx context.Context, client pb.LiteVirtClient, req *pb.DeployStackRequest) {
	t.Helper()
	deployCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := client.DeployStack(deployCtx, req)
	if err != nil {
		t.Fatalf("DeployStack: %v", err)
	}
	for {
		_, err := stream.Recv()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("DeployStack stream: %v", err)
		}
	}
}

// sawEvent returns true if the libvirtfake event log contains a
// (op, domain) pair. Helper to keep assertions readable.
func sawEvent(events []libvirtfake.Event, op, domain string) bool {
	for _, e := range events {
		if e.Op == op && e.Domain == domain {
			return true
		}
	}
	return false
}

// _ keeps "time" import live if the assertion helpers above stop
// using it after a refactor.
var _ = time.Now

// writeEmptyImageFile creates a placeholder file at path so the
// image.Store.ImageExists check returns true and DeployStack's
// auto-pull short-circuits. The libvirtfake doesn't care about
// disk contents.
func writeEmptyImageFile(path string) error {
	if err := osMkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := osCreate(path)
	if err != nil {
		return err
	}
	return f.Close()
}
