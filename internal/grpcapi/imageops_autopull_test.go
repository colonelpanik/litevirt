package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
)

// The 2026-08-01 lab run wedged a failover in a transient-retry loop because
// autoPullImage (a) dialed the fenced host that owned the only other image
// copy and (b) never noticed the image was already present locally. These
// tests pin both fixes.

func autopullServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	s.hostName = "local-host"
	dir := t.TempDir()
	s.images = image.NewStore(dir)
	if err := s.images.Init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
	return s
}

func TestAutoPullImage_LocalFileShortCircuits(t *testing.T) {
	s := autopullServer(t)

	// The image file is already in the local store; no image_hosts row, no
	// peer, no network — the pull must succeed as a no-op.
	if err := os.WriteFile(s.images.ImagePath("ubuntu"), []byte("qcow2"), 0o644); err != nil {
		t.Fatalf("stage image: %v", err)
	}
	if err := s.AutoPullImage(adminCtx(), "ubuntu"); err != nil {
		t.Fatalf("local image present: want nil, got %v", err)
	}
}

func TestAutoPullImage_SkipsFencedAndOfflineSources(t *testing.T) {
	s := autopullServer(t)
	ctx := adminCtx()

	// Two ready copies, but both holders are known-dead. Selection must skip
	// them and fail with the no-peer error — NOT a dial error against a
	// fenced host (which the reconciler would retry forever).
	for _, h := range []struct{ name, state string }{
		{"fenced-host", "fenced"},
		{"offline-host", "offline"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: h.name, Address: "10.0.0.9", State: h.state,
		}); err != nil {
			t.Fatalf("insert host: %v", err)
		}
		if err := corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
			ImageName: "ubuntu", HostName: h.name,
			Path: "/images/ubuntu.qcow2", Status: "ready",
			PulledAt: "2026-01-01T00:00:00Z",
		}); err != nil {
			t.Fatalf("insert image host: %v", err)
		}
	}

	err := s.AutoPullImage(ctx, "ubuntu")
	if err == nil {
		t.Fatal("expected error when every ready holder is dead")
	}
	if got := err.Error(); !contains(got, "no peer host has image") {
		t.Errorf("want the no-peer error (dead holders skipped), got: %v", err)
	}
}

func TestAutoPullImage_PrefersLiveSourceOverDead(t *testing.T) {
	s := autopullServer(t)
	ctx := adminCtx()

	// A dead holder sorts before a live one; selection must pick the live
	// host. The dial then fails (no real peer in unit tests), and that error
	// must name the LIVE host — proving the dead one was skipped.
	for _, h := range []struct{ name, state string }{
		{"aaa-fenced", "fenced"},
		{"zzz-live", "active"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: h.name, Address: "127.0.0.1", State: h.state,
		}); err != nil {
			t.Fatalf("insert host: %v", err)
		}
		if err := corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
			ImageName: "ubuntu", HostName: h.name,
			Path: "/images/ubuntu.qcow2", Status: "ready",
			PulledAt: "2026-01-01T00:00:00Z",
		}); err != nil {
			t.Fatalf("insert image host: %v", err)
		}
	}

	err := s.AutoPullImage(ctx, "ubuntu")
	if err == nil {
		t.Fatal("expected dial failure against the live host")
	}
	if got := err.Error(); contains(got, "aaa-fenced") {
		t.Errorf("selection tried the fenced host: %v", err)
	}
	if got := err.Error(); !contains(got, "zzz-live") {
		t.Errorf("error should name the live host it attempted: %v", err)
	}
}

var _ = filepath.Join // keep import if unused on some build tags

func TestAutoPullImage_CorruptLocalFileDoesNotShortCircuit(t *testing.T) {
	// 2026-08-01 lab: a node killed mid-image-transfer rebooted with a
	// zero-byte cirros.qcow2 at the final path. The local short-circuit
	// trusted bare existence and blocked the re-pull that would have healed
	// it, wedging the failover start forever. Existence is not integrity.
	s := autopullServer(t)
	ctx := adminCtx()

	// Zero-byte local file + a live ready holder: the pull must proceed
	// (and here fail on the dial, naming the holder — proving no short-circuit).
	if err := os.WriteFile(s.images.ImagePath("ubuntu"), nil, 0o644); err != nil {
		t.Fatalf("stage empty image: %v", err)
	}
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "live-holder", Address: "127.0.0.1", State: "active",
	}); err != nil {
		t.Fatalf("insert host: %v", err)
	}
	if err := corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
		ImageName: "ubuntu", HostName: "live-holder",
		Path: "/images/ubuntu.qcow2", Status: "ready", PulledAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("insert image host: %v", err)
	}
	err := s.AutoPullImage(ctx, "ubuntu")
	if err == nil {
		t.Fatal("zero-byte local file short-circuited the pull")
	}
	if !contains(err.Error(), "live-holder") {
		t.Errorf("pull was not attempted against the live holder: %v", err)
	}

	// Truncated file (nonzero but wrong size vs the replicated images row):
	// also no short-circuit.
	if err := corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name: "ubuntu", Format: "qcow2", Checksum: "sha256:aa", SizeBytes: 4096,
	}); err != nil {
		t.Fatalf("insert image row: %v", err)
	}
	if err := os.WriteFile(s.images.ImagePath("ubuntu"), []byte("torn"), 0o644); err != nil {
		t.Fatalf("stage truncated image: %v", err)
	}
	err = s.AutoPullImage(ctx, "ubuntu")
	if err == nil {
		t.Fatal("size-mismatched local file short-circuited the pull")
	}

	// Full-size file: short-circuits (positive control for the validation).
	if err := os.WriteFile(s.images.ImagePath("ubuntu"), make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("stage full image: %v", err)
	}
	if err := s.AutoPullImage(ctx, "ubuntu"); err != nil {
		t.Fatalf("intact local file must short-circuit: %v", err)
	}
}
