package grpcapi

import (
	"sync"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
)

// TestServerOpts is the minimal set of fields the in-process fleet
// harness needs to build a Server. Anything not specified here gets
// the same zero-value treatment NewServer-via-daemon would give it,
// which is fine because no production daemon ever constructs a Server
// without libvirt + an image store. Tests that need those plumbing
// pieces inject them via the existing Set*() methods.
type TestServerOpts struct {
	HostName string
	DataDir  string
	PKIDir   string
	DB       *corrosion.Client
	// Virt is the libvirt backend. nil = scenarios that touch VM
	// lifecycle will NPE — set Virt to a *libvirtfake.Fake (or any
	// other LibvirtBackend impl) for those.
	Virt LibvirtBackend
}

// ImagePathForTests exposes the image store's path resolver for
// fleet-harness scenarios that need to stage a fake image file
// before driving DeployStack. Tests-only — production callers never
// need this because images come through real auto-pull.
func (s *Server) ImagePathForTests(imageName string) string {
	if s.images == nil {
		return ""
	}
	return s.images.ImagePath(imageName)
}

// NewServerForTests is the in-process-fleet construction entry point.
// Identical to NewServer except virt and images stay nil — VM
// lifecycle RPCs will NPE if called, which is intentional: scenarios
// either inject fakes via Set*() or operate at the Corrosion layer.
//
// Do not call this from production code paths — the missing pieces
// (libvirt, image store) are not optional in a real daemon. The
// build-tag-free location is deliberate; the harness lives in tests/
// and can import internal/grpcapi without a wrapping interface.
func NewServerForTests(opts TestServerOpts) *Server {
	// Always wire an image.Store so the autoPullImages path on
	// DeployStack has somewhere to ImagePath() and ImageExists().
	// Tests that need a fully-stocked image cache write files into
	// opts.DataDir/images before calling the relevant RPC.
	imgs := image.NewStore(opts.DataDir)
	_ = imgs.Init()
	return &Server{
		hostName:   opts.HostName,
		dataDir:    opts.DataDir,
		pkiDir:     opts.PKIDir,
		db:         opts.DB,
		virt:       opts.Virt,
		images:     imgs,
		events:     events.NewBus(),
		vmLocks:    make(map[string]*sync.Mutex),
		ReExecCh:   make(chan struct{}, 1),
		ShutdownCh: make(chan struct{}, 1),
	}
}
