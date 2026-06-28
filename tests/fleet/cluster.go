// Package fleet is an in-process integration harness: N litevirt
// daemons running inside one `go test` process, wired together over
// real gRPC + real mTLS + real CRDT replication. Everything is
// in-memory except for a few tmp-dir artefacts (PKI keys, pbsstore
// chunks, gRPC unix sockets are not used — we use loopback TCP on
// ephemeral ports so existing peerClient TLS dial paths work
// unchanged).
//
// This sits between unit tests (one package, all deps faked) and
// the real-host suite in tests/e2e/ (which shells out to `lv`
// against a live 4-node cluster). The fleet harness is where the
// integration spine — CLI → gRPC → permissions → corrosion →
// mutation_log → replicator → peer.PushMutations → applyStatementLWW
// → scheduler — actually runs end-to-end.
//
// What the fleet harness does NOT cover: real qemu / nftables / dnsmasq —
// those need a real host. An in-process libvirt fake (internal/libvirtfake)
// IS injected per node, so VM-lifecycle RPCs run against it; deeper scenarios
// operate at the Corrosion / replicator layer and observe behaviour through DB
// state changes.
package fleet

import (
	"context"

	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/hlc"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pki"
)

// Options control fleet bootstrap. Zero values are sane defaults.
type Options struct {
	// Nodes is how many daemons to spin up. Default 3.
	Nodes int
	// SharedCRDT, when true, gives every node a SQLite handle into
	// the SAME in-memory DB — useful for scenarios that don't care
	// about the replication path (the rebalancer scenario, for
	// example, already exercises shared state via NewSharedTestClient
	// in tests/cluster/). When false (default), each node has its
	// own DB and mutations must travel via the real Replicator.
	SharedCRDT bool
	// RegionByIndex assigns regions to nodes 0..N-1. Empty → all "default".
	RegionByIndex []string
}

// Cluster is the assembled fleet. Use Stop in a t.Cleanup; nothing
// shuts down on its own.
type Cluster struct {
	t       *testing.T
	Nodes   []*Node
	caCert  string
	caKey   string
	tmpRoot string
}

// Node wraps one daemon — its DB, gRPC server, replicator, and
// addressing info.
type Node struct {
	Name     string
	Region   string
	Address  string // 127.0.0.1
	Port     int    // ephemeral, allocated by net.Listen(":0")
	PKIDir   string
	DB       *corrosion.Client
	Server   *grpcapi.Server
	Virt     *libvirtfake.Fake // in-process libvirt fake; scenarios assert on its Events
	GRPCSrv  *grpc.Server
	Listener net.Listener
	// peerConn caches a self-loopback client for scenario assertions
	// that want to call this node's RPCs from the test thread.
	selfConn *grpc.ClientConn

	// repl is the node's Replicator (wired into the server for PushMutations;
	// background loop not started — see buildServer).
	repl *corrosion.Replicator

	// partition gate: replication/state-sync RPCs whose mTLS caller CN is in
	// blockedFrom are refused, modeling a network partition on the real
	// transport. Guarded by partMu (Partition/Heal mutate it concurrently with
	// in-flight RPCs).
	partMu      sync.Mutex
	blockedFrom map[string]bool
}

// New brings up a Cluster ready for scenarios. Each node has:
//   - A unique PKI cert signed by a single shared cluster CA.
//   - A separate in-memory Corrosion DB (or shared if Options.SharedCRDT).
//   - A real grpcapi.Server (with libvirt = nil — scenarios that need
//     VM lifecycle inject a fake or operate at the DB layer).
//   - A real corrosion.Replicator pulling from its DB and pushing to
//     peers over loopback TLS.
//   - host_records inserted in every node's DB so peerClient resolves
//     the right loopback port.
func New(t *testing.T, opts Options) *Cluster {
	t.Helper()
	if opts.Nodes <= 0 {
		opts.Nodes = 3
	}

	// Reset the global audit-chain pointer so a test running after
	// another in the same process doesn't inherit a tail hash from
	// a different (now-closed) DB. Cheap, idempotent.
	corrosion.ResetChainStateForTests()
	c := &Cluster{t: t, tmpRoot: t.TempDir()}
	c.mintCA()

	// Step 1 — mint pki for every node and pre-allocate ports so the
	// host records can carry the right addresses before any daemon
	// starts listening.
	for i := 0; i < opts.Nodes; i++ {
		name := fmt.Sprintf("node-%d", i)
		n := &Node{
			Name:        name,
			Region:      regionFor(opts.RegionByIndex, i),
			Address:     "127.0.0.1",
			PKIDir:      filepath.Join(c.tmpRoot, name, "pki"),
			blockedFrom: make(map[string]bool),
		}
		c.mintHostCert(n)
		// Reserve an ephemeral port — close the listener immediately
		// after; we re-bind once everything is wired. (gRPC servers
		// need the listener to come from outside their constructor.)
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve port for %s: %v", name, err)
		}
		n.Port = l.Addr().(*net.TCPAddr).Port
		n.Listener = l
		c.Nodes = append(c.Nodes, n)
	}

	// Step 2 — open DBs and seed schema. Each node's DB is independent.
	for _, n := range c.Nodes {
		c.openDB(n, opts.SharedCRDT)
	}

	// Step 3 — register every node in every node's DB so peerClient
	// can resolve host addresses. Same shape the daemon's normal
	// host-add path produces.
	c.crossRegisterHosts()

	// Step 4 — build grpcapi.Server per node, attach replicator,
	// start gRPC server on the pre-allocated listener.
	for _, n := range c.Nodes {
		c.buildServer(n)
	}

	t.Cleanup(c.Stop)
	return c
}

// Stop tears down every daemon in the fleet. Idempotent.
func (c *Cluster) Stop() {
	for _, n := range c.Nodes {
		if n.selfConn != nil {
			_ = n.selfConn.Close()
		}
		if n.GRPCSrv != nil {
			n.GRPCSrv.GracefulStop()
		}
		if n.Listener != nil {
			_ = n.Listener.Close()
		}
		if n.DB != nil {
			n.DB.Close()
		}
	}
}

// SelfClient returns a gRPC client dialed at node n's own address.
// Useful for scenarios that drive RPCs from the test thread as if
// they were the operator's `lv` invocation.
func (c *Cluster) SelfClient(n *Node) pb.LiteVirtClient {
	c.t.Helper()
	if n.selfConn == nil {
		tlsCfg, err := pki.PeerTLSConfig(n.PKIDir)
		if err != nil {
			c.t.Fatalf("client TLS for %s: %v", n.Name, err)
		}
		cc, err := grpc.NewClient(
			fmt.Sprintf("%s:%d", n.Address, n.Port),
			grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		)
		if err != nil {
			c.t.Fatalf("dial self %s: %v", n.Name, err)
		}
		n.selfConn = cc
	}
	return pb.NewLiteVirtClient(n.selfConn)
}

// PeerClient returns a gRPC client dialed at target while presenting source's
// host certificate. Use this for node-to-node RPC tests whose request sender
// must match the mTLS peer identity.
func (c *Cluster) PeerClient(source, target *Node) pb.LiteVirtClient {
	c.t.Helper()
	tlsCfg, err := pki.PeerTLSConfig(source.PKIDir)
	if err != nil {
		c.t.Fatalf("peer client TLS for %s: %v", source.Name, err)
	}
	cc, err := grpc.NewClient(
		fmt.Sprintf("%s:%d", target.Address, target.Port),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		c.t.Fatalf("dial %s from %s: %v", target.Name, source.Name, err)
	}
	c.t.Cleanup(func() { _ = cc.Close() })
	return pb.NewLiteVirtClient(cc)
}

// bearerClient dials node n's gRPC server with a bearer-token
// unary/stream interceptor so scoped-token scenarios can exercise
// the permission engine end-to-end.
func (c *Cluster) bearerClient(n *Node, token string) pb.LiteVirtClient {
	c.t.Helper()
	tlsCfg, err := pki.PeerTLSConfig(n.PKIDir)
	if err != nil {
		c.t.Fatalf("client TLS for %s: %v", n.Name, err)
	}
	cc, err := grpc.NewClient(
		fmt.Sprintf("%s:%d", n.Address, n.Port),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithPerRPCCredentials(staticBearer{token}),
	)
	if err != nil {
		c.t.Fatalf("dial %s as bearer: %v", n.Name, err)
	}
	c.t.Cleanup(func() { _ = cc.Close() })
	return pb.NewLiteVirtClient(cc)
}

// staticBearer is a credentials.PerRPCCredentials that injects
// `authorization: Bearer <token>` on every RPC.
type staticBearer struct{ token string }

func (s staticBearer) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + s.token}, nil
}
func (s staticBearer) RequireTransportSecurity() bool { return true }

// Node by name lookup; fatals if not found.
func (c *Cluster) Node(name string) *Node {
	c.t.Helper()
	for _, n := range c.Nodes {
		if n.Name == name {
			return n
		}
	}
	c.t.Fatalf("fleet: unknown node %q", name)
	return nil
}

// ── private bootstrap helpers ───────────────────────────────────────────

func (c *Cluster) mintCA() {
	caDir := filepath.Join(c.tmpRoot, "ca")
	if err := mkdirAll(caDir); err != nil {
		c.t.Fatalf("mkdir ca: %v", err)
	}
	c.caCert = filepath.Join(caDir, "ca.crt")
	c.caKey = filepath.Join(caDir, "ca.key")
	if err := pki.GenerateCA(c.caCert, c.caKey); err != nil {
		c.t.Fatalf("GenerateCA: %v", err)
	}
}

func (c *Cluster) mintHostCert(n *Node) {
	if err := mkdirAll(n.PKIDir); err != nil {
		c.t.Fatalf("mkdir %s: %v", n.PKIDir, err)
	}
	// Drop the cluster CA into every node's PKI dir — production
	// daemons expect ca.crt local for trust-store anchoring.
	if err := copyFile(c.caCert, filepath.Join(n.PKIDir, "ca.crt")); err != nil {
		c.t.Fatalf("seed ca for %s: %v", n.Name, err)
	}
	if err := copyFile(c.caKey, filepath.Join(n.PKIDir, "ca.key")); err != nil {
		c.t.Fatalf("seed ca key for %s: %v", n.Name, err)
	}
	certPath := filepath.Join(n.PKIDir, "host.crt")
	keyPath := filepath.Join(n.PKIDir, "host.key")
	if err := pki.GenerateHostCert(
		c.caCert, c.caKey, certPath, keyPath, n.Name, net.ParseIP("127.0.0.1"),
	); err != nil {
		c.t.Fatalf("GenerateHostCert %s: %v", n.Name, err)
	}
}

func (c *Cluster) openDB(n *Node, shared bool) {
	var (
		db  *corrosion.Client
		err error
	)
	if shared {
		db, err = corrosion.NewSharedTestClient("fleet-shared", n.Name)
	} else {
		db, err = corrosion.NewSharedTestClient("fleet-"+n.Name, n.Name)
	}
	if err != nil {
		c.t.Fatalf("open DB for %s: %v", n.Name, err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		c.t.Fatalf("InitSchema for %s: %v", n.Name, err)
	}
	n.DB = db
}

func (c *Cluster) crossRegisterHosts() {
	ctx := context.Background()
	for _, target := range c.Nodes {
		for _, hostNode := range c.Nodes {
			rec := corrosion.HostRecord{
				Name:          hostNode.Name,
				Address:       hostNode.Address,
				GRPCPort:      hostNode.Port,
				SSHUser:       "root",
				SSHPort:       22,
				CertSerial:    "fleet",
				State:         "active",
				FenceStrategy: "best-effort",
			}
			if err := corrosion.InsertHost(ctx, target.DB, rec); err != nil {
				// "UNIQUE constraint" is fine — already registered.
				continue
			}
			// InsertHost doesn't take region (the production path
			// uses ConfigureHost post-hoc). Apply it as a separate
			// UPDATE so the host_record carries the harness-assigned
			// region label.
			if hostNode.Region != "" {
				if err := corrosion.UpdateHostRegion(ctx, target.DB, hostNode.Name, hostNode.Region); err != nil {
					c.t.Fatalf("UpdateHostRegion for %s on %s: %v", hostNode.Name, target.Name, err)
				}
			}
		}
	}
}

func (c *Cluster) buildServer(n *Node) {
	dataDir := filepath.Join(c.tmpRoot, n.Name, "data")
	if err := mkdirAll(dataDir); err != nil {
		c.t.Fatalf("mkdir data for %s: %v", n.Name, err)
	}
	// NewServer demands a *libvirt.Client; for the fleet harness we construct
	// the Server directly and inject an in-process libvirt fake (n.Virt) so
	// VM-lifecycle RPCs run without a real libvirtd.
	n.Virt = libvirtfake.New()
	n.Server = grpcapi.NewServerForTests(grpcapi.TestServerOpts{
		HostName: n.Name,
		DataDir:  dataDir,
		PKIDir:   n.PKIDir,
		DB:       n.DB,
		Virt:     n.Virt,
	})

	// Wire a real Replicator so the server's PushMutations handler + write-notify
	// path are exercised. Its background push loop is deliberately NOT started: it
	// discovers peers via memberlist (corrosion.Client.Members()), and the
	// in-process fleet doesn't join a gossip mesh, so Members() is empty here and a
	// started loop would be a no-op. Cross-node convergence is instead driven
	// deterministically over the REAL anti-entropy repair RPC (StreamStateDump →
	// MergeStateBytesLWW — the exact production path; see partition_test.go),
	// rather than the gossip-timed ticker.
	n.repl = corrosion.NewReplicator(n.DB, n.PKIDir, corrosion.RelayConfig{})
	n.Server.SetReplicator(n.repl)

	// Start the gRPC server on n.Listener.
	tlsCfg, err := pki.ServerTLSConfig(n.PKIDir)
	if err != nil {
		c.t.Fatalf("server TLS for %s: %v", n.Name, err)
	}
	// Auth interceptors mirror the daemon's wiring — without them
	// authenticate() never runs and every RPC fails RequireRole.
	// With no bearer token in metadata the auth path treats the
	// caller as mTLS-authenticated admin, which is what SelfClient
	// produces.
	// The partition interceptors run BEFORE auth: a partitioned peer's
	// replication RPC is dropped (codes.Unavailable) regardless of identity, as
	// if the link were severed. Both a unary and a stream interceptor are needed
	// — the streaming dump RPCs (StreamStateDump / StreamSensitiveStateDump)
	// never hit a unary interceptor.
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.ChainUnaryInterceptor(n.partitionUnaryInterceptor, n.Server.UnaryAuthInterceptor),
		grpc.ChainStreamInterceptor(n.partitionStreamInterceptor, n.Server.StreamAuthInterceptor),
	)
	pb.RegisterLiteVirtServer(srv, n.Server)
	n.GRPCSrv = srv
	go func() {
		// Errors here usually mean the listener was closed during
		// teardown — that's fine.
		_ = srv.Serve(n.Listener)
	}()

	// Spin briefly so the listener is accepting before scenarios dial.
	if err := waitTCP(n.Address, n.Port, 2*time.Second); err != nil {
		c.t.Fatalf("%s did not start gRPC: %v", n.Name, err)
	}
}

// replicationMethods are the gRPC method names (final path segment) the
// partition gate drops. It covers BOTH lanes — public and sensitive — and both
// the digest and the dump/push/ack steps; omitting the sensitive lane would let
// it converge during a "partition".
var replicationMethods = map[string]bool{
	"PushMutations":            true,
	"AckMutations":             true,
	"GetStateDigest":           true,
	"GetStateDump":             true,
	"StreamStateDump":          true,
	"GetSensitiveStateDigest":  true,
	"StreamSensitiveStateDump": true,
}

// methodName returns the final segment of a gRPC full-method string
// ("/litevirt.v1.LiteVirt/PushMutations" → "PushMutations").
func methodName(full string) string {
	if i := strings.LastIndex(full, "/"); i >= 0 {
		return full[i+1:]
	}
	return full
}

// peerCertCN extracts the caller's mTLS certificate CommonName (== node name in
// the harness), mirroring grpcapi.peerCommonName.
func peerCertCN(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return ""
	}
	return tlsInfo.State.PeerCertificates[0].Subject.CommonName
}

// blocked reports whether a replication RPC from the given caller is currently
// partitioned away from this node.
func (n *Node) blocked(fullMethod string, ctx context.Context) bool {
	if !replicationMethods[methodName(fullMethod)] {
		return false
	}
	caller := peerCertCN(ctx)
	if caller == "" {
		return false
	}
	n.partMu.Lock()
	defer n.partMu.Unlock()
	return n.blockedFrom[caller]
}

func (n *Node) partitionUnaryInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if n.blocked(info.FullMethod, ctx) {
		return nil, status.Errorf(codes.Unavailable, "fleet partition: %s refused by %s", methodName(info.FullMethod), n.Name)
	}
	return handler(ctx, req)
}

func (n *Node) partitionStreamInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if n.blocked(info.FullMethod, ss.Context()) {
		return status.Errorf(codes.Unavailable, "fleet partition: %s refused by %s", methodName(info.FullMethod), n.Name)
	}
	return handler(srv, ss)
}

func (n *Node) setBlocked(peer string, blocked bool) {
	n.partMu.Lock()
	defer n.partMu.Unlock()
	if blocked {
		n.blockedFrom[peer] = true
	} else {
		delete(n.blockedFrom, peer)
	}
}

// Partition severs replication/state-sync RPCs between a and b in BOTH
// directions (each refuses the other's replication calls), modeling a network
// partition on the real loopback transport. Non-replication RPCs are unaffected.
func (c *Cluster) Partition(a, b *Node) {
	a.setBlocked(b.Name, true)
	b.setBlocked(a.Name, true)
}

// Heal removes a partition between a and b so replication can flow again.
func (c *Cluster) Heal(a, b *Node) {
	a.setBlocked(b.Name, false)
	b.setBlocked(a.Name, false)
}

// regionFor reads the region label for index i, defaulting to "default".
func regionFor(by []string, i int) string {
	if i < len(by) && by[i] != "" {
		return by[i]
	}
	return "default"
}

// HLCClock returns a node's HLC. Used by scenarios that need to
// fabricate mutation entries with deterministic timestamps.
func (n *Node) HLCClock() *hlc.Clock { return n.DB.Clock() }
