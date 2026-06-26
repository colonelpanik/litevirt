package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// TestHandleSecurityGroups_Empty renders the page with no SGs in the
// DB — the empty-state CTA should appear so brand-new clusters have a
// hint instead of a blank table.
func TestHandleSecurityGroups_Empty(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)

	r := withAuth(httptest.NewRequest(http.MethodGet, "/security-groups", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	mustContain(t, w.Body.String(), "No security groups defined", "Create group")
}

// TestHandleSecurityGroups_RendersRows seeds two SGs with rules and
// asserts both appear with their rule lines.
func TestHandleSecurityGroups_RendersRows(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)
	ctx := context.Background()
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg-web", Name: "web"}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}
	if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{
		ID: "r1", SGID: "sg-web", Direction: "ingress", Proto: "tcp", PortRange: "443", Action: "accept",
	}); err != nil {
		t.Fatalf("InsertSGRule: %v", err)
	}

	r := withAuth(httptest.NewRequest(http.MethodGet, "/security-groups", nil))
	w := serveRequest(s, r)
	mustContain(t, w.Body.String(), "web", "ingress", "tcp", "443", "accept")
}

// TestHandleContainers_Empty exercises the empty-state branch via the
// default mock returning no containers.
func TestHandleContainers_Empty(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/containers", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mustContain(t, w.Body.String(), "No containers yet", "lv ct create")
}

// TestHandleContainers_RendersRows wires the mock to return one entry
// and asserts the table renders it.
func TestHandleContainers_RendersRows(t *testing.T) {
	mock := newDefaultMock()
	mock.listContainersResp = &pb.ListContainersResponse{Containers: []*pb.Container{{
		HostName: "host-a", Name: "ct-1", State: "running",
		Image: "alpine:3.19", CpuLimit: 2, MemoryMib: 256,
	}}}
	s := newTestUIServer(t, mock)
	r := withAuth(httptest.NewRequest(http.MethodGet, "/containers", nil))
	w := serveRequest(s, r)
	mustContain(t, w.Body.String(), "host-a", "ct-1", "running", "alpine:3.19")
}

// TestHandleBackups_NoRepoQuery shows the prompt+hint when no repos
// have been configured.
func TestHandleBackups_NoRepoQuery(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/backups", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mustContain(t, w.Body.String(), "No repos configured", "Browse")
}

// TestHandleBackups_ConfiguredRepos init-s two real pbsstore repos,
// hands them to the UI server via SetBackupRepos, then renders /backups
// (no query string) and asserts BOTH appear in the configured-repos
// table with their snapshot counts.
func TestHandleBackups_ConfiguredRepos(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	mainDir := filepath.Join(t.TempDir(), "main")
	dr2Dir := filepath.Join(t.TempDir(), "dr")
	mainRepo, err := pbsstore.Init(mainDir)
	if err != nil {
		t.Fatalf("Init main: %v", err)
	}
	if _, err := pbsstore.Init(dr2Dir); err != nil {
		t.Fatalf("Init dr: %v", err)
	}
	if err := mainRepo.PutManifest(&pbsstore.Manifest{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-10T01:23:45Z",
		TotalSize: 4096,
	}); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	s.SetBackupRepos(map[string]string{"main": mainDir, "dr": dr2Dir})

	r := withAuth(httptest.NewRequest(http.MethodGet, "/backups", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	// Repos now render as cards (name + path + snapshot count) rather than a table.
	mustContain(t, body, "main", "dr", mainDir, dr2Dir, "Snapshots")
}

// TestHandleBackups_RealRepo init-s a real pbsstore, pushes one
// snapshot, then renders /backups?repo=… and asserts the manifest
// row appears.
func TestHandleBackups_RealRepo(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	repoDir := filepath.Join(t.TempDir(), "repo")
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}
	m := &pbsstore.Manifest{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-10T01:23:45Z",
		TotalSize: 4096, Chunks: []pbsstore.ChunkRef{{ID: strings.Repeat("a", 64), Size: 4096, Offset: 0}},
	}
	if err := repo.PutManifest(m); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	r := withAuth(httptest.NewRequest(http.MethodGet, "/backups?repo="+repoDir, nil))
	w := serveRequest(s, r)
	mustContain(t, w.Body.String(), "vm1", "root", "2026-05-10T01:23:45Z")
}

// newCorrosionForUITest spins up an in-memory Corrosion suitable for
// UI handlers that read directly from the DB.
func newCorrosionForUITest(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

func mustContain(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Errorf("expected %q in body; got:\n%s", n, body)
		}
	}
}
