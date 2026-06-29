package grpcapi

import (
	"context"
	"crypto/rand"
	"io"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// divergenceResampleDelay is the gap between the two scan samples. A real
// divergence persists across both with unchanged per-node hashes; an in-flight
// replication delta changes between samples and is dropped. Overridable in tests.
var divergenceResampleDelay = 1500 * time.Millisecond

// DiagnoseDivergence (lv doctor divergence) fans out to every active host, builds
// per-node row snapshots for the requested tables, and reports rows that diverge
// across nodes plus cluster-wide semantic-invariant violations. Read-only: it
// never writes or merges. Admin-gated — it exposes cross-node row metadata and,
// when include_sensitive is set, drives the peer-mTLS HMAC lane.
func (s *Server) DiagnoseDivergence(ctx context.Context, req *pb.DiagnoseDivergenceRequest) (*pb.DivergenceReport, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}

	opTables := intersect(corrosion.OperatorTableNames(), req.GetTables())
	var sensTables []string
	var scanKey []byte
	if req.GetIncludeSensitive() {
		sensTables = intersect(corrosion.SensitiveTableNames(), req.GetTables())
		var err error
		if scanKey, err = randomScanKey(); err != nil {
			return nil, status.Errorf(codes.Internal, "scan key: %v", err)
		}
	}

	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list hosts: %v", err)
	}
	var active []corrosion.HostRecord
	for _, h := range hosts {
		if h.State == "active" {
			active = append(active, h)
		}
	}
	nodeNames := make([]string, 0, len(active))
	for _, h := range active {
		nodeNames = append(nodeNames, h.Name)
	}
	sort.Strings(nodeNames)

	// Fewer than two reachable nodes ⇒ nothing to compare.
	s1, owned, unreachable := s.sampleCluster(ctx, active, opTables, sensTables, scanKey)
	report := &pb.DivergenceReport{Samples: 1, NodesUnreachable: unreachable}
	report.NodesScanned = reachableNames(nodeNames, unreachable)
	if len(report.NodesScanned) < 2 {
		// Still run semantic invariants — a single node can hold jointly-illegal rows.
		report.Violations = semanticViolationsPB(owned)
		return report, nil
	}

	// Second sample after a brief settle; only divergences stable across both are
	// real (the plan's "stable repeated divergence after catch-up").
	if divergenceResampleDelay > 0 {
		select {
		case <-time.After(divergenceResampleDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s2, owned2, _ := s.sampleCluster(ctx, active, opTables, sensTables, scanKey)
	report.Samples = 2

	d1 := classifyAll(append(opTables, sensTables...), report.NodesScanned, s1)
	d2 := classifyAll(append(opTables, sensTables...), report.NodesScanned, s2)
	report.Rows = reconcileSamples(d1, d2)
	report.Stable = true
	report.Violations = semanticViolationsPB(append(owned, owned2...))
	return report, nil
}

// sampleCluster gathers one snapshot per active host (self locally, peers via
// StreamStateDump + the sensitive HMAC RPC), returning the per-node snapshots,
// the union of semantic owned-rows, and the hosts that were unreachable.
func (s *Server) sampleCluster(ctx context.Context, active []corrosion.HostRecord, opTables, sensTables []string, scanKey []byte) (map[string]corrosion.NodeSnapshot, []corrosion.OwnedRow, []string) {
	snaps := make(map[string]corrosion.NodeSnapshot, len(active))
	var owned []corrosion.OwnedRow
	var unreachable []string

	for _, h := range active {
		if h.Name == s.hostName {
			tables, o, err := s.db.ScanLocalTables(ctx, opTables)
			if err != nil {
				unreachable = append(unreachable, h.Name)
				continue
			}
			owned = append(owned, o...)
			if len(sensTables) > 0 {
				if srows, serr := s.db.ScanLocalSensitive(ctx, scanKey, sensTables); serr == nil {
					mergeSnapshot(tables, corrosion.SensitiveRowsToSnapshot(srows))
				}
			}
			snaps[h.Name] = corrosion.NodeSnapshot{Host: h.Name, Tables: tables}
			continue
		}
		// Peer.
		tables, o, ok := s.fetchPeerSnapshot(ctx, h.Name, opTables, sensTables, scanKey)
		if !ok {
			unreachable = append(unreachable, h.Name)
			continue
		}
		owned = append(owned, o...)
		snaps[h.Name] = corrosion.NodeSnapshot{Host: h.Name, Tables: tables}
	}
	sort.Strings(unreachable)
	return snaps, owned, unreachable
}

// fetchPeerSnapshot pulls a peer's operator-safe dump (+ sensitive HMACs) and
// builds its snapshot. ok=false on any unreachable/RPC failure.
func (s *Server) fetchPeerSnapshot(ctx context.Context, host string, opTables, sensTables []string, scanKey []byte) (map[string]corrosion.TableSnapshot, []corrosion.OwnedRow, bool) {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return nil, nil, false
	}
	defer conn.Close()

	buf, err := fetchPeerStateDump(ctx, client)
	if err != nil {
		return nil, nil, false
	}
	want := make(map[string]bool, len(opTables))
	for _, t := range opTables {
		want[t] = true
	}
	tables, owned, err := corrosion.SnapshotFromDumpBytes(buf, want)
	if err != nil {
		return nil, nil, false
	}
	if len(sensTables) > 0 {
		resp, serr := client.ScanSensitiveDivergence(ctx, &pb.ScanSensitiveRequest{
			Sender: s.hostName, ScanKey: scanKey, Tables: sensTables,
		})
		if serr == nil {
			mergeSnapshot(tables, sensitivePBToSnapshot(resp.GetRows()))
		}
	}
	return tables, owned, true
}

// ScanSensitiveDivergence is the peer-only lane: it returns ONLY domain-separated
// keyed HMACs of this node's secret-bearing rows (never raw PKs or content). The
// scan key arrives over the peer-mTLS channel and is never logged.
func (s *Server) ScanSensitiveDivergence(ctx context.Context, req *pb.ScanSensitiveRequest) (*pb.ScanSensitiveResponse, error) {
	if err := requireReplicationPeer(ctx, req.GetSender()); err != nil {
		return nil, err
	}
	if len(req.GetScanKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "scan_key required")
	}
	// Only ever scan the sensitive allowlist via this lane.
	tables := intersect(corrosion.SensitiveTableNames(), req.GetTables())
	rows, err := s.db.ScanLocalSensitive(ctx, req.GetScanKey(), tables)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sensitive scan: %v", err)
	}
	out := &pb.ScanSensitiveResponse{HostName: s.hostName, Rows: make([]*pb.SensitiveRowMetaPB, 0, len(rows))}
	for _, r := range rows {
		out.Rows = append(out.Rows, &pb.SensitiveRowMetaPB{
			Table: r.Table, PkLabel: r.PKLabel, RowHash: r.RowHash, UpdatedAt: r.UpdatedAt, Deleted: r.Deleted,
		})
	}
	return out, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func randomScanKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// fetchPeerStateDump reassembles a peer's chunked StreamStateDump (operator-safe).
func fetchPeerStateDump(ctx context.Context, client pb.LiteVirtClient) ([]byte, error) {
	stream, err := client.StreamStateDump(ctx, &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	var buf []byte
	for {
		chunk, rerr := stream.Recv()
		if rerr == io.EOF {
			return buf, nil
		}
		if rerr != nil {
			return nil, rerr
		}
		buf = append(buf, chunk.GetData()...)
	}
}

// intersect returns base filtered to filter (case-exact); empty filter = all base.
func intersect(base, filter []string) []string {
	if len(filter) == 0 {
		return base
	}
	want := make(map[string]bool, len(filter))
	for _, f := range filter {
		want[f] = true
	}
	var out []string
	for _, b := range base {
		if want[b] {
			out = append(out, b)
		}
	}
	return out
}

func reachableNames(all, unreachable []string) []string {
	bad := make(map[string]bool, len(unreachable))
	for _, u := range unreachable {
		bad[u] = true
	}
	var out []string
	for _, n := range all {
		if !bad[n] {
			out = append(out, n)
		}
	}
	return out
}

// mergeSnapshot folds src table snapshots into dst (used to add the sensitive
// lane's HMAC-keyed rows alongside the operator-safe rows for one node).
func mergeSnapshot(dst, src map[string]corrosion.TableSnapshot) {
	for table, ts := range src {
		dst[table] = ts
	}
}

func sensitivePBToSnapshot(rows []*pb.SensitiveRowMetaPB) map[string]corrosion.TableSnapshot {
	conv := make([]corrosion.SensitiveRow, 0, len(rows))
	for _, r := range rows {
		conv = append(conv, corrosion.SensitiveRow{
			Table: r.GetTable(), PKLabel: r.GetPkLabel(), RowHash: r.GetRowHash(),
			UpdatedAt: r.GetUpdatedAt(), Deleted: r.GetDeleted(),
		})
	}
	return corrosion.SensitiveRowsToSnapshot(conv)
}

// classifyAll runs ClassifyTable across every table and keys the results by
// "table\x00pk" for cross-sample reconciliation.
func classifyAll(tables, nodes []string, snaps map[string]corrosion.NodeSnapshot) map[string]corrosion.RowDivergence {
	out := map[string]corrosion.RowDivergence{}
	for _, table := range tables {
		for _, d := range corrosion.ClassifyTable(table, nodes, snaps) {
			out[table+"\x00"+d.PKLabel] = d
		}
	}
	return out
}

// reconcileSamples keeps only divergences present in BOTH samples with unchanged
// per-node hashes (a real, settled split — not in-flight replication). A stable
// different_updated_at is promoted to stuck_different.
func reconcileSamples(d1, d2 map[string]corrosion.RowDivergence) []*pb.DivergenceRow {
	var out []*pb.DivergenceRow
	keys := make([]string, 0, len(d2))
	for k := range d2 {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r2 := d2[k]
		r1, ok := d1[k]
		if !ok || !samePerNodeHashes(r1.PerNode, r2.PerNode) {
			continue // only-in-one-sample or changed between samples → in-flight
		}
		class := r2.Class
		if class == corrosion.ClassDifferentUpdatedAt {
			class = corrosion.ClassStuckDifferent
		}
		out = append(out, rowDivergenceToPB(r2, class))
	}
	return out
}

func samePerNodeHashes(a, b map[string]corrosion.RowMeta) bool {
	if len(a) != len(b) {
		return false
	}
	for host, ma := range a {
		mb, ok := b[host]
		if !ok || ma.RowHash != mb.RowHash {
			return false
		}
	}
	return true
}

func rowDivergenceToPB(d corrosion.RowDivergence, class corrosion.DivergenceClass) *pb.DivergenceRow {
	hosts := make([]string, 0, len(d.PerNode))
	for h := range d.PerNode {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	per := make([]*pb.NodeRowMeta, 0, len(hosts))
	for _, h := range hosts {
		m := d.PerNode[h]
		per = append(per, &pb.NodeRowMeta{
			Host: h, UpdatedAt: m.UpdatedAt, RowHash: m.RowHash, Deleted: m.Deleted, State: m.State,
		})
	}
	return &pb.DivergenceRow{Table: d.Table, Pk: d.PKLabel, Class: string(class), PerNode: per}
}

func semanticViolationsPB(owned []corrosion.OwnedRow) []*pb.SemanticViolationPB {
	var containers, ips []corrosion.OwnedRow
	for _, o := range owned {
		if o.Host != "" && o.Name != "" && o.IP == "" {
			containers = append(containers, o)
		}
		if o.IP != "" {
			ips = append(ips, o)
		}
	}
	var vs []corrosion.SemanticViolation
	vs = append(vs, corrosion.CheckLiveContainerNames(containers)...)
	vs = append(vs, corrosion.CheckDuplicateIPOwners(ips)...)
	out := make([]*pb.SemanticViolationPB, 0, len(vs))
	for _, v := range vs {
		out = append(out, &pb.SemanticViolationPB{Kind: v.Kind, Key: v.Key, Detail: v.Detail, Hosts: v.Hosts})
	}
	return out
}
