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
	"os"
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
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hlc"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/opjournal"
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
	// NetBoxURL points every node's NetBox client at an external IPAM — in
	// practice a *NetBoxFake started by the scenario. Empty (the default)
	// leaves the client nil and netbox_ipam_v1 unadvertised, so every existing
	// scenario is untouched.
	NetBoxURL string
	// NamePrefix names the nodes ("node-" by default, giving node-0, node-1…).
	//
	// It is REQUIRED for a second cluster in the same test, and the reason is a
	// trap: each node's in-memory SQLite DB is a shared-cache database NAMED
	// after the node ("file:fleet-node-0?mode=memory&cache=shared"). Two
	// clusters whose nodes share a name therefore share one database — every
	// row, including the `cluster` row every identity is derived from — and a
	// scenario meaning "two independent installations" would silently be
	// testing one.
	NamePrefix string
	// NetBoxClusterName sets config `netbox.cluster_name` on every node, giving
	// this cluster a NetBox cluster object of its own.
	//
	// It is what a second installation sharing one NetBox needs: a NetBox
	// cluster is the scope in which NetBox enforces one VM name per cluster, so
	// two installations under one cluster name cannot both mirror a same-named
	// VM. Empty (the default) leaves every existing scenario resolving the
	// `cluster` row's name, exactly as before.
	NetBoxClusterName string
}

// Cluster is the assembled fleet. Use Stop in a t.Cleanup; nothing
// shuts down on its own.
type Cluster struct {
	t       *testing.T
	Nodes   []*Node
	caCert  string
	caKey   string
	tmpRoot string
	// opts is the bootstrap request, kept so per-node wiring (buildServer) can
	// read options the harness applies after the nodes exist.
	opts Options
	// ctx bounds every background loop the harness starts on a node's behalf
	// (the NetBox maintenance loop today). Cancelled by Stop, so a scenario's
	// goroutines never outlive the cluster that owns them.
	ctx    context.Context
	cancel context.CancelFunc
	// reach is the cluster-wide "this peer is up again" overlay every node's
	// gate unions into HealthyPeers. Nothing populates the real health
	// checker's peer table in-process (no probe loop runs), so without this a
	// fleet scenario has no way to model a host REJOINING — see Node.Rejoin.
	reach *reachSet
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
	CT       *CTFake           // in-process container runtime; real on-disk rootfs + tar export/import
	HostNet  *HostNetFake      // in-memory netplan System for the host-network apply protocol
	GRPCSrv  *grpc.Server
	Listener net.Listener
	// peerConn caches a self-loopback client for scenario assertions
	// that want to call this node's RPCs from the test thread.
	selfConn *grpc.ClientConn

	// cluster is the fleet this node belongs to, so a node-scoped helper can
	// reach cluster-wide state (the self client, the reachability overlay).
	cluster *Cluster

	// repl is the node's Replicator (wired into the server for PushMutations;
	// background loop not started — see buildServer).
	repl *corrosion.Replicator

	// netboxMaintenance records what StartNetBoxMaintenance ANSWERED for this
	// node. The harness does not decide for itself whether the loop runs — the
	// server does, from whether it has a NetBox client — so a scenario asserting
	// "no config, no goroutine" asserts on production code.
	netboxMaintenance bool

	// netboxMirror records what StartNetBoxMirror ANSWERED for this node, for
	// the same reason as netboxMaintenance above.
	netboxMirror bool

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

	// The audit-chain tail used to be process-global, so this had to reset it
	// between tests — and, worse, every node in a cluster shared one tail, so
	// node B's first audit row linked to node A's. The state now hangs off each
	// Client and is keyed by host_name, which is correct by construction here.
	c := &Cluster{t: t, tmpRoot: t.TempDir(), opts: opts, reach: newReachSet()}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.mintCA()

	// Step 1 — mint pki for every node and pre-allocate ports so the
	// host records can carry the right addresses before any daemon
	// starts listening.
	namePrefix := opts.NamePrefix
	if namePrefix == "" {
		namePrefix = "node-"
	}
	for i := 0; i < opts.Nodes; i++ {
		name := fmt.Sprintf("%s%d", namePrefix, i)
		n := &Node{
			Name:        name,
			Region:      regionFor(opts.RegionByIndex, i),
			Address:     "127.0.0.1",
			PKIDir:      filepath.Join(c.tmpRoot, name, "pki"),
			blockedFrom: make(map[string]bool),
			cluster:     c,
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

	// Step 3b — gossip membership, which every node in a real cluster has and
	// this harness did not.
	c.seedGossipMembership()

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
	if c.cancel != nil {
		c.cancel()
	}
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

// seedGossipMembership gives every node the memberlist view a real node has:
// each of its PEERS, by name and address, with itself excluded exactly as
// corrosion.Client.Members() excludes it.
//
// It is a fidelity fix, not a convenience. The in-process fleet joins no gossip
// mesh, so Members() answered empty on every node — and every production path
// that consults it as a SECOND, non-CRDT source of membership was therefore
// untestable here, silently. That is not a hypothetical gap: the two proofs in
// netbox_adopt.go and netbox_sweeper.go both union gossip into their participant
// universe precisely because the replicated `hosts` table can be missing a peer,
// and with Members() empty a scenario that deleted a `hosts` row proved nothing
// about the union at all.
//
// WHAT A GOSSIP-ONLY PEER CAN AND CANNOT DO HERE. It is NAMED, so it lands in
// every participant universe. It is not DIALABLE: corrosion's resolver takes the
// host from the membership address and defaults the port to 7443 — right for a
// real cluster, wrong for a harness whose daemons listen on ephemeral ports — so
// a peer known only to gossip answers as unreachable. Both outcomes are
// fail-closed and the proofs treat them the same way, which is why a scenario
// can rely on either; a scenario that needs the peer to ANSWER has to leave its
// `hosts` row in place.
func (c *Cluster) seedGossipMembership() {
	for _, target := range c.Nodes {
		self := target.Name
		nodes := c.Nodes
		target.DB.SetMembersForTests(func() []corrosion.PeerInfo {
			var peers []corrosion.PeerInfo
			for _, n := range nodes {
				if n.Name == self {
					continue
				}
				// The gossip port, not the gRPC one: memberlist advertises where
				// it gossips, and the resolver discards that port anyway.
				peers = append(peers, corrosion.PeerInfo{
					Name: n.Name,
					Addr: net.JoinHostPort(n.Address, "7946"),
				})
			}
			return peers
		})
	}
}

func (c *Cluster) crossRegisterHosts() {
	ctx := context.Background()
	for _, target := range c.Nodes {
		for _, hostNode := range c.Nodes {
			serial, err := pki.CertSerial(filepath.Join(hostNode.PKIDir, "host.crt"))
			if err != nil {
				c.t.Fatalf("read certificate serial for %s: %v", hostNode.Name, err)
			}
			rec := corrosion.HostRecord{
				Name:          hostNode.Name,
				Address:       hostNode.Address,
				GRPCPort:      hostNode.Port,
				SSHUser:       "root",
				SSHPort:       22,
				CertSerial:    serial,
				State:         "active",
				FenceStrategy: "best-effort",
				// Real capacity. Host admission now runs on CREATE as well as resize,
				// and a host record with zero CPU/memory reads as "full" — every
				// scenario that places a workload would be refused. Generous on
				// purpose: capacity is not what these scenarios are testing.
				CPUTotal: 64,
				MemTotal: 262144,
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

	// Domain lifecycle events: the daemon registers this same handler on its
	// libvirt client (internal/daemon.Run). Wiring it here lets a scenario call
	// n.Virt.FireEvent(...) and observe the daemon's real reaction rather than a
	// copy of its logic. Inert for every other scenario — the fake dispatches
	// nothing unless a test fires an event. context.Background() because the
	// harness has no daemon-lifetime ctx and the handler's corrosion calls are
	// synchronous, completing inside FireEvent.
	n.Virt.RegisterDomainEventCallback(
		health.NewDomainEventHandler(n.Name, n.DB).Callback(context.Background()))

	// Container runtime: the LXC analogue of n.Virt. Wired unconditionally so
	// container RPCs run on every node instead of returning "container runtime
	// not wired on this host"; scenarios that don't touch containers never
	// observe it. Rooted per-node so a migrate's export/import moves bytes
	// between two genuinely separate directories.
	n.CT = NewCTFake(filepath.Join(c.tmpRoot, n.Name, "lxc"))
	n.Server.SetContainerRuntime(n.CT)

	// Host network apply protocol: a per-node in-memory netplan System plus a
	// REAL host-local operation journal, so host-network RPCs — forwarding,
	// journaled apply, rollback, replicated outcomes — run multi-node without
	// root. The advertise address matches what the cluster harness registers.
	n.HostNet = NewHostNetFake()
	if j, err := opjournal.Open(filepath.Join(c.tmpRoot, n.Name, "opjournal")); err != nil {
		c.t.Fatalf("opjournal for %s: %v", n.Name, err)
	} else {
		n.Server.SetOpJournal(j)
	}
	n.Server.SetHostNetworkEnv(n.HostNet, "127.0.0.1")

	// External IPAM: a REAL netbox.Client (token file and all) pointed at the
	// scenario's fake server, plus the config kill-switch that lets this node
	// ADVERTISE netbox_ipam_v1. Both together are what the daemon does from
	// config, so a scenario exercises the same wiring production uses rather
	// than reaching past it.
	if c.opts.NetBoxURL != "" {
		c.wireNetBox(n)
	}
	// The maintenance loop, started exactly as the daemon starts it — through
	// the server's own guard, on EVERY node, so an unconfigured cluster
	// exercises the refusal rather than a harness branch that skipped the call.
	// The interval is the production default (15 minutes), which is far longer
	// than any scenario: nothing ticks under a test, and scenarios drive a pass
	// explicitly through RunNetBoxMaintenanceOnce.
	n.netboxMaintenance = n.Server.StartNetBoxMaintenance(c.ctx, 0)
	// The inventory mirror, started exactly as the daemon starts it and on every
	// node, so a scenario exercises the server's own "is this node configured"
	// guard rather than a harness branch. Same production default cadences, and
	// scenarios drive a pass explicitly through SyncNetBoxMirror. The 15-minute
	// sweep tick cannot fire under a test; the mirror's faster QUEUE POLL can, at
	// one minute — two orders of magnitude beyond the slowest scenario here, but
	// the reason a scenario that both queues work and counts NetBox writes must
	// not be made to run for minutes.
	n.netboxMirror = n.Server.StartNetBoxMirror(c.ctx, 0)

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

// partitionedMethods are the gRPC method names (final path segment) the partition
// gate drops — the peer-to-peer traffic a severed link would actually take out.
//
// Replication covers BOTH lanes, public and sensitive, and both the digest and the
// dump/push/ack steps; omitting the sensitive lane would let a "partition" converge.
// Delegated project admission is peer traffic over the same link, so a partition must
// drop it too — otherwise a scenario that partitions the authority holder would still
// reach it and prove nothing about the unreachable-holder path.
var partitionedMethods = map[string]bool{
	"PushMutations":            true,
	"AckMutations":             true,
	"GetStateDigest":           true,
	"GetStateDump":             true,
	"StreamStateDump":          true,
	"GetSensitiveStateDigest":  true,
	"StreamSensitiveStateDump": true,
	"ReserveProjectCapacity":   true,
	"ReleaseProjectCapacity":   true,
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

// blocked reports whether a peer RPC from the given caller is currently
// partitioned away from this node.
func (n *Node) blocked(fullMethod string, ctx context.Context) bool {
	if !partitionedMethods[methodName(fullMethod)] {
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

// NetBoxMaintenanceRunning reports whether this node started the NetBox
// maintenance loop (binding revalidation + the orphan sweep).
func (n *Node) NetBoxMaintenanceRunning() bool { return n.netboxMaintenance }

// NetBoxMirrorRunning reports whether this node started the inventory mirror.
func (n *Node) NetBoxMirrorRunning() bool { return n.netboxMirror }

// SyncNetBoxMirror runs ONE leader-gated mirror pass on this node.
//
// It goes through the same gate the loop does, so a node that loses the lease
// race does nothing and returns nil — which is the point: every configured node
// runs a pass, and only one of them writes.
func (n *Node) SyncNetBoxMirror() error {
	return n.Server.RunNetBoxMirrorOnce(context.Background())
}

// ExpireLeaderLeaseAfter makes this node's mirror hold the `netbox` leader
// lease for exactly `batches` per-batch re-validations and lose it thereafter.
//
// It models a leadership handover that lands MID-SWEEP. A real lease can be
// stolen between passes, which a scenario can already do with stealNetBoxLease
// — but not between two write batches of ONE pass without racing the test, and
// mid-sweep is the only window the per-batch re-validation exists for.
//
// The ACQUIRE is untouched: this node still genuinely takes the lease, so the
// pass starts for the real reason and only the re-validation is steered.
func (n *Node) ExpireLeaderLeaseAfter(batches int) {
	var mu sync.Mutex
	seen := 0
	n.Server.SetNetBoxLeaseProbe(func(context.Context) bool {
		mu.Lock()
		defer mu.Unlock()
		seen++
		return seen <= batches
	})
}

// ClearSyncQueue tombstones every netbox_sync_queue row on this node — the
// state a node that died before enqueueing, or a peer that drained an item and
// then died, leaves behind. The mirror's correctness may not depend on it.
func (n *Node) ClearSyncQueue() {
	if err := n.DB.Execute(context.Background(),
		`UPDATE netbox_sync_queue SET deleted_at = ?, updated_at = ? WHERE deleted_at IS NULL`,
		n.DB.NowWall(), n.DB.NowTS()); err != nil {
		n.cluster.t.Fatalf("clear sync queue on %s: %v", n.Name, err)
	}
}

// ── external IPAM wiring ────────────────────────────────────────────────────

// NewClusterWithNetBox brings up a fleet whose every node talks to nb. It is the
// entry point for scenarios that assert on NetBox-backed addressing: the fake
// hands out addresses from a band the builtin allocator never produces, so an
// assertion on the address genuinely distinguishes "NetBox supplied it" from
// "the wiring is missing and the builtin allocator answered".
func NewClusterWithNetBox(t *testing.T, nodes int, nb *NetBoxFake) *Cluster {
	t.Helper()
	return New(t, Options{Nodes: nodes, NetBoxURL: nb.URL()})
}

// NewClusterWithNetBoxNamed is NewClusterWithNetBox for a SECOND cluster in the
// same test — two installations sharing one NetBox.
//
// The distinct name prefix is load-bearing, not cosmetic: node names are the
// in-memory database names (see Options.NamePrefix), so two clusters both
// calling their node "node-0" would share one DB and one cluster row, and a
// scenario about two installations would quietly be about one.
func NewClusterWithNetBoxNamed(t *testing.T, nodes int, nb *NetBoxFake, namePrefix string) *Cluster {
	t.Helper()
	return New(t, Options{Nodes: nodes, NetBoxURL: nb.URL(), NamePrefix: namePrefix})
}

// wireNetBox gives one node the two things the daemon derives from
// config.netbox: a real *netbox.Client built from a token FILE (the production
// constructor, not a hand-assembled struct) and the advertise kill-switch.
//
// It also brings up the `cluster` row every node needs to derive a cluster
// fingerprint — through the PRODUCTION heal, corrosion.EnsureClusterRecord,
// reading this node's own pki/ca.crt exactly as the daemon does at startup.
//
// Deliberately not a hand-written INSERT any more. It used to be, and that hid a
// blocker for the whole feature: nothing in production ever wrote the row, so on
// a real cluster no fingerprint could be derived and every bind, claim, mirror
// pass and re-key refused — while the fleet stayed green because this harness
// created what the daemon never did. Driving the daemon's own heal means a heal
// that stops working takes the NetBox fleet suite down with it.
//
// Every node's pki/ca.crt is a copy of the one fleet CA, so every node derives
// the SAME fingerprint, which is the property a real cluster has.
//
// The NAME is the one thing still set by hand. The heal deliberately leaves it
// empty (nothing in litevirt takes a cluster name), and scenarios that assert
// which NetBox cluster object the mirror wrote into need a stable one.
func (c *Cluster) wireNetBox(n *Node) {
	c.t.Helper()

	if err := corrosion.EnsureClusterRecord(context.Background(), n.DB, n.PKIDir); err != nil {
		c.t.Fatalf("derive cluster record for %s: %v", n.Name, err)
	}
	rows, err := n.DB.ExecuteRows(context.Background(),
		`UPDATE cluster SET name = ?, domain = ?, updated_at = ? WHERE id = 'default'`,
		"fleet", "fleet.local", n.DB.NowTS())
	if err != nil {
		c.t.Fatalf("name the cluster row for %s: %v", n.Name, err)
	}
	if rows == 0 {
		c.t.Fatalf("no cluster row for %s after the startup heal — the daemon's "+
			"EnsureClusterRecord wrote nothing, so no NetBox identity can be minted", n.Name)
	}

	tokenDir := filepath.Join(c.tmpRoot, n.Name, "netbox")
	if err := mkdirAll(tokenDir); err != nil {
		c.t.Fatalf("mkdir netbox dir for %s: %v", n.Name, err)
	}
	tokenPath := filepath.Join(tokenDir, "token")
	// PER NODE, not one shared token. The token is what every request carries in
	// its Authorization header, so it is the only thing that tells the fake
	// WHICH node issued a write — and "exactly one of N masterless nodes writes
	// the inventory" is otherwise unobservable from outside the cluster.
	if err := os.WriteFile(tokenPath, []byte("fleet-netbox-token-"+n.Name+"\n"), 0o600); err != nil {
		c.t.Fatalf("write netbox token for %s: %v", n.Name, err)
	}
	client, err := netbox.New(netbox.Config{
		BaseURL:   c.opts.NetBoxURL,
		TokenPath: tokenPath,
		Timeout:   5 * time.Second,
	})
	if err != nil {
		c.t.Fatalf("netbox client for %s: %v", n.Name, err)
	}
	n.Server.SetNetBoxClient(client)
	n.Server.SetNetBoxClusterName(c.opts.NetBoxClusterName)
	n.Server.SetNetBoxIPAM(true)
	// The INVENTORY MIRROR's own opt-in (`netbox.mirror_inventory`), which drives
	// netbox_mirror_v1 the same conditional-advertisement way. Set alongside the
	// client because the mirror scenarios are the reason this wiring exists: a
	// fixture that left it off would model a pure-IPAM cluster and every mirror
	// assertion would pass by declining. A scenario whose subject IS the opt-in
	// turns it off on the node it wants to model.
	n.Server.SetNetBoxMirrorInventory(true)

	// Host bridges: CreateVM preflights every non-macvtap NIC with ensureBridge,
	// which runs `ip link add … type bridge` when the interface is missing. The
	// harness is unprivileged, so a VM on ANY network would fail there for want
	// of root — a property of the test process, not of the code under test.
	// Stubbing the seam lets NetBox scenarios reach the addressing logic; the
	// bridge itself is not what they assert on.
	//
	// Scoped to NetBox clusters (like the `cluster` row above) so every existing
	// scenario keeps the real validation path byte-for-byte.
	n.Server.SetBridgeEnsure(func(string) error { return nil })
}

// MoveClusterFingerprint rewrites cluster.ca_cert on EVERY node, which is the
// ONLY thing that moves the cluster identity fingerprint.
//
// It is deliberately NOT named after a CA replacement.
// corrosion.EnsureClusterRecord mints the fingerprint once and never rewrites
// the row, so replacing `ca.crt` on disk does not reach it; the producible cause
// is exactly what this helper does — an out-of-band rewrite of the replicated
// row (an operator edit, or a restore carrying another installation's CA).
//
// No real TLS re-issue happens, and none is needed: corrosion.ClusterFingerprint
// is a SHA-256 of that column, so ANY different string is a different cluster
// identity. Re-minting the PKI would additionally invalidate every node
// certificate the harness dials with — a second, unrelated failure that would
// stop these scenarios reaching the binding logic at all. Every node is written
// so the fleet stays uniform, exactly as a replicated row would be.
func (c *Cluster) MoveClusterFingerprint() {
	c.t.Helper()
	replacement := fmt.Sprintf("-----BEGIN CERTIFICATE-----\nreplacement-ca-%d\n-----END CERTIFICATE-----\n",
		time.Now().UnixNano())
	for _, n := range c.Nodes {
		if err := n.DB.Execute(context.Background(),
			`UPDATE cluster SET ca_cert = ?, updated_at = ? WHERE id = 'default'`,
			replacement, n.DB.NowWall()); err != nil {
			c.t.Fatalf("move the cluster fingerprint on %s: %v", n.Name, err)
		}
	}
}

// ── induced write failures ──────────────────────────────────────────────────
//
// Both seams install a SQLite trigger that aborts one specific write. A trigger
// is the only way to reach these windows from the fleet: the failure has to
// happen INSIDE the daemon's own transaction, after every earlier step has
// really run, which no stub above the corrosion client can produce. Reads stay
// unaffected, so the operation under test proceeds normally right up to the
// write that must fail.
//
// Each returns a drop function so a scenario can restore normal writes partway
// through, and each also registers that drop with t.Cleanup so a trigger can
// never leak into another test sharing the process.

// FailVMRowWrites aborts every INSERT into `vms` on this node. It is how a
// scenario reaches the window between a started domain and its durable row.
func (n *Node) FailVMRowWrites(t *testing.T) func() {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`CREATE TRIGGER test_fail_vm_insert BEFORE INSERT ON vms
		 BEGIN SELECT RAISE(ABORT, 'induced vm persist failure'); END`); err != nil {
		t.Fatalf("install vm-insert failure trigger on %s: %v", n.Name, err)
	}
	drop := func() {
		if err := n.DB.Execute(context.Background(),
			`DROP TRIGGER IF EXISTS test_fail_vm_insert`); err != nil {
			t.Fatalf("drop vm-insert failure trigger on %s: %v", n.Name, err)
		}
	}
	t.Cleanup(drop)
	return drop
}

// FailNICRowWrites aborts every INSERT into `vm_interfaces` on this node — the
// pre-latch dual-write half of a NIC attach, which runs AFTER the live hotplug
// and after the authoritative vm_nics row has landed. It is how a scenario
// reaches an attach that has to be rolled back with real forward progress
// already on the ground.
func (n *Node) FailNICRowWrites(t *testing.T) func() {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`CREATE TRIGGER test_fail_legacy_nic_insert BEFORE INSERT ON vm_interfaces
		 BEGIN SELECT RAISE(ABORT, 'induced legacy interface persist failure'); END`); err != nil {
		t.Fatalf("install legacy-interface-insert failure trigger on %s: %v", n.Name, err)
	}
	drop := func() {
		if err := n.DB.Execute(context.Background(),
			`DROP TRIGGER IF EXISTS test_fail_legacy_nic_insert`); err != nil {
			t.Fatalf("drop legacy-interface-insert failure trigger on %s: %v", n.Name, err)
		}
	}
	t.Cleanup(drop)
	return drop
}

// FailNICRowDelete aborts every vm_nics TOMBSTONE on this node (an UPDATE that
// sets deleted_at on a live row). The attach path writes its row with INSERT OR
// REPLACE, so that write is untouched and only the UNDO fails — which is how a
// scenario reaches a rollback that could not put the rows back, and therefore
// must NOT give the claimed address away.
func (n *Node) FailNICRowDelete(t *testing.T) func() {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`CREATE TRIGGER test_fail_nic_tombstone BEFORE UPDATE ON vm_nics
		 WHEN NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL
		 BEGIN SELECT RAISE(ABORT, 'induced nic tombstone failure'); END`); err != nil {
		t.Fatalf("install nic-tombstone failure trigger on %s: %v", n.Name, err)
	}
	drop := func() {
		if err := n.DB.Execute(context.Background(),
			`DROP TRIGGER IF EXISTS test_fail_nic_tombstone`); err != nil {
			t.Fatalf("drop nic-tombstone failure trigger on %s: %v", n.Name, err)
		}
	}
	t.Cleanup(drop)
	return drop
}

// FailLeaseTombstones aborts every ip_allocations TOMBSTONE on this node
// (an UPDATE that sets deleted_at on a live row), leaving inserts and every
// other update alone. It is how a scenario reaches a release whose LOCAL half
// failed while the remote IPAM object still exists.
func (n *Node) FailLeaseTombstones(t *testing.T) func() {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`CREATE TRIGGER test_fail_lease_tombstone BEFORE UPDATE ON ip_allocations
		 WHEN NEW.deleted_at IS NOT NULL AND OLD.deleted_at IS NULL
		 BEGIN SELECT RAISE(ABORT, 'induced tombstone failure'); END`); err != nil {
		t.Fatalf("install lease-tombstone failure trigger on %s: %v", n.Name, err)
	}
	drop := func() {
		if err := n.DB.Execute(context.Background(),
			`DROP TRIGGER IF EXISTS test_fail_lease_tombstone`); err != nil {
			t.Fatalf("drop lease-tombstone failure trigger on %s: %v", n.Name, err)
		}
	}
	t.Cleanup(drop)
	return drop
}
