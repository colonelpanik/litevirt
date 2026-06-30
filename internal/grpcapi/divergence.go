package grpcapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"strings"
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
	// Reject unknown --table values, and a sensitive table named without
	// --include-sensitive (it would otherwise silently scan nothing and read as
	// "clean") — the same false-reassurance class as an unknown table.
	if err := validateTableFilter(req.GetTables(), req.GetIncludeSensitive()); err != nil {
		return nil, err
	}

	opTables := intersect(corrosion.OperatorTableNames(), req.GetTables())
	var sensTables []string
	if req.GetIncludeSensitive() {
		sensTables = intersect(corrosion.SensitiveTableNames(), req.GetTables())
	}
	// Drive the sensitive lane (key, scan, reporting) only when a sensitive table
	// is actually in scope — e.g. `--include-sensitive --table vms` has no
	// sensitive table, so it must not mint a key or mark every host partial.
	var scanKey []byte
	if len(sensTables) > 0 {
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

	s1 := s.sampleCluster(ctx, active, opTables, sensTables, scanKey)
	report := &pb.DivergenceReport{Samples: 1}

	// A second sample after a brief settle. A divergence is real only when it
	// persists across both samples with unchanged content; an in-flight delta
	// changes between samples and is dropped. Per-lane reachability is tracked
	// separately so a host whose sensitive lane failed isn't treated as "missing"
	// the sensitive rows (a false divergence) and is surfaced as partial.
	if divergenceResampleDelay > 0 {
		select {
		case <-time.After(divergenceResampleDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s2 := s.sampleCluster(ctx, active, opTables, sensTables, scanKey)
	report.Samples = 2

	// Compare only over nodes reachable (per lane) in BOTH samples — a node that
	// flapped is excluded from classification (so its absence in one sample can't
	// fabricate a divergence) and surfaced as unreachable.
	commonOp := intersectStrSets(s1.opReachable, s2.opReachable)
	commonSens := intersectStrSets(s1.sensReachable, s2.sensReachable)
	report.NodesScanned = commonOp
	report.NodesUnreachable = subtract(activeNames(active), commonOp)
	if len(sensTables) > 0 {
		report.SensitiveUnreachable = subtract(activeNames(active), commonSens)
	}

	// Semantic invariants run regardless of node count — a single node can hold a
	// jointly-illegal state. Reconcile across BOTH samples (like row divergence):
	// report a violation only if it appears in both, so an in-flight migration
	// (web on host-a in s1, host-b in s2 — never both live at once) isn't faked
	// into a duplicate, and one fixed before s2 isn't preserved.
	report.Violations = reconcileViolations(
		semanticViolations(s1.owned), semanticViolations(s2.owned))

	if len(commonOp) >= 2 || len(commonSens) >= 2 {
		d1 := classifyLanes(opTables, sensTables, commonOp, commonSens, s1.snaps)
		d2 := classifyLanes(opTables, sensTables, commonOp, commonSens, s2.snaps)
		report.Rows = reconcileSamples(d1, d2)
	}

	// stable: the cluster was QUIESCENT across the scan — identical per-lane node
	// sets in both samples AND no scanned table's content changed between them.
	// When false, a stuck_different may be lagging backlog, not a true split.
	nodeSetsStable := equalStrSet(s1.opReachable, s2.opReachable) &&
		(len(sensTables) == 0 || equalStrSet(s1.sensReachable, s2.sensReachable))
	report.Stable = nodeSetsStable &&
		sampleFingerprint(commonOp, commonSens, opTables, sensTables, s1.snaps) ==
			sampleFingerprint(commonOp, commonSens, opTables, sensTables, s2.snaps)
	return report, nil
}

// clusterSample is one fan-out pass: per-node snapshots plus, per lane, the set
// of hosts that answered successfully (so a failed lane is partial, not silently
// clean — and not a fabricated divergence).
type clusterSample struct {
	snaps         map[string]corrosion.NodeSnapshot
	owned         []corrosion.OwnedRow
	opReachable   map[string]bool // host → op-safe lane succeeded
	sensReachable map[string]bool // host → sensitive lane succeeded
}

// sampleCluster gathers one snapshot per active host (self locally, peers via
// StreamStateDump + the sensitive HMAC RPC).
func (s *Server) sampleCluster(ctx context.Context, active []corrosion.HostRecord, opTables, sensTables []string, scanKey []byte) clusterSample {
	cs := clusterSample{
		snaps:         make(map[string]corrosion.NodeSnapshot, len(active)),
		opReachable:   map[string]bool{},
		sensReachable: map[string]bool{},
	}
	for _, h := range active {
		var tables map[string]corrosion.TableSnapshot
		var owned []corrosion.OwnedRow
		var sensOK bool

		if h.Name == s.hostName {
			t, o, err := s.db.ScanLocalTables(ctx, opTables)
			if err != nil {
				continue // op lane failed for self → not opReachable
			}
			tables, owned = t, o
			if len(sensTables) > 0 {
				if srows, serr := s.db.ScanLocalSensitive(ctx, scanKey, sensTables); serr == nil {
					mergeSnapshot(tables, corrosion.SensitiveRowsToSnapshot(srows))
					sensOK = true
				}
			}
		} else {
			t, o, ok, sok := s.fetchPeerSnapshot(ctx, h.Name, opTables, sensTables, scanKey)
			if !ok {
				continue // op lane failed for peer
			}
			tables, owned, sensOK = t, o, sok
		}

		cs.opReachable[h.Name] = true
		if len(sensTables) > 0 && sensOK {
			cs.sensReachable[h.Name] = true
		}
		cs.owned = append(cs.owned, owned...)
		cs.snaps[h.Name] = corrosion.NodeSnapshot{Host: h.Name, Tables: tables}
	}
	return cs
}

// fetchPeerSnapshot pulls a peer's operator-safe dump (+ sensitive HMACs). ok is
// the op-safe lane; sensOK is the sensitive lane (false when not requested OR the
// sensitive RPC failed — the caller marks that host's sensitive lane partial).
func (s *Server) fetchPeerSnapshot(ctx context.Context, host string, opTables, sensTables []string, scanKey []byte) (tables map[string]corrosion.TableSnapshot, owned []corrosion.OwnedRow, ok, sensOK bool) {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return nil, nil, false, false
	}
	defer conn.Close()

	buf, err := fetchPeerStateDump(ctx, client)
	if err != nil {
		return nil, nil, false, false
	}
	want := make(map[string]bool, len(opTables))
	for _, t := range opTables {
		want[t] = true
	}
	tables, owned, err = corrosion.SnapshotFromDumpBytes(buf, want)
	if err != nil {
		return nil, nil, false, false
	}
	if len(sensTables) > 0 {
		if resp, serr := client.ScanSensitiveDivergence(ctx, &pb.ScanSensitiveRequest{
			Sender: s.hostName, ScanKey: scanKey, Tables: sensTables,
		}); serr == nil {
			mergeSnapshot(tables, sensitivePBToSnapshot(resp.GetRows()))
			sensOK = true
		}
	}
	return tables, owned, true, sensOK
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

// validateTableFilter rejects any --table value that isn't a known replicated
// table (a typo must error, not silently scan nothing and read as "clean"), and a
// SENSITIVE table named without --include-sensitive (it would otherwise resolve to
// no scanned table — the same false-reassurance class).
func validateTableFilter(tables []string, includeSensitive bool) error {
	if len(tables) == 0 {
		return nil
	}
	op := map[string]bool{}
	for _, t := range corrosion.OperatorTableNames() {
		op[t] = true
	}
	sens := map[string]bool{}
	for _, t := range corrosion.SensitiveTableNames() {
		sens[t] = true
	}
	var unknown, sensWithoutFlag []string
	for _, t := range tables {
		switch {
		case op[t]:
		case sens[t]:
			if !includeSensitive {
				sensWithoutFlag = append(sensWithoutFlag, t)
			}
		default:
			unknown = append(unknown, t)
		}
	}
	if len(unknown) > 0 {
		return status.Errorf(codes.InvalidArgument, "unknown table(s): %s", strings.Join(unknown, ", "))
	}
	if len(sensWithoutFlag) > 0 {
		return status.Errorf(codes.InvalidArgument,
			"table(s) %s are secret-bearing; pass --include-sensitive to scan them", strings.Join(sensWithoutFlag, ", "))
	}
	return nil
}

func activeNames(active []corrosion.HostRecord) []string {
	out := make([]string, 0, len(active))
	for _, h := range active {
		out = append(out, h.Name)
	}
	return out
}

// intersectStrSets returns the sorted hosts present in both sets.
func intersectStrSets(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// subtract returns the sorted names in all that are not in keep.
func subtract(all, keep []string) []string {
	k := make(map[string]bool, len(keep))
	for _, n := range keep {
		k[n] = true
	}
	var out []string
	for _, n := range all {
		if !k[n] {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func equalStrSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
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

// classifyLanes classifies the operator-safe tables over the op-reachable node
// set and the sensitive tables over the sensitive-reachable set (a host whose
// sensitive lane failed isn't in the sensitive set, so its absence can't fabricate
// a missing_row for a sensitive table). Keyed by "table\x00pk" for reconciliation.
func classifyLanes(opTables, sensTables, opNodes, sensNodes []string, snaps map[string]corrosion.NodeSnapshot) map[string]corrosion.RowDivergence {
	out := map[string]corrosion.RowDivergence{}
	classify := func(tables, nodes []string) {
		if len(nodes) < 2 {
			return
		}
		for _, table := range tables {
			for _, d := range corrosion.ClassifyTable(table, nodes, snaps) {
				out[table+"\x00"+d.PKLabel] = d
			}
		}
	}
	classify(opTables, opNodes)
	classify(sensTables, sensNodes)
	return out
}

// sampleFingerprint hashes every (host, table, pk, rowHash) over the in-scope
// per-lane node sets, so two samples can be compared for quiescence: identical
// fingerprints ⇒ no table content changed between samples.
func sampleFingerprint(opNodes, sensNodes, opTables, sensTables []string, snaps map[string]corrosion.NodeSnapshot) string {
	var lines []string
	collect := func(tables, nodes []string) {
		for _, host := range nodes {
			ns := snaps[host]
			for _, table := range tables {
				for pk, m := range ns.Tables[table].Rows {
					lines = append(lines, host+"\x00"+table+"\x00"+pk+"\x00"+m.RowHash)
				}
			}
		}
	}
	collect(opTables, opNodes)
	collect(sensTables, sensNodes)
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
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

// semanticViolations runs the cluster-wide invariant checks over ONE sample's
// owned rows.
func semanticViolations(owned []corrosion.OwnedRow) []corrosion.SemanticViolation {
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
	return vs
}

// reconcileViolations reports a semantic violation only when it appears in BOTH
// samples with the SAME identity (kind + key + hosts) — so a violation that was
// transient (an in-flight migration that never had both rows live at once) or
// fixed before the second sample is not reported, matching the row-divergence
// persistence policy.
func reconcileViolations(v1, v2 []corrosion.SemanticViolation) []*pb.SemanticViolationPB {
	key := func(v corrosion.SemanticViolation) string {
		return v.Kind + "\x00" + v.Key + "\x00" + strings.Join(v.Hosts, ",")
	}
	in1 := make(map[string]bool, len(v1))
	for _, v := range v1 {
		in1[key(v)] = true
	}
	var out []*pb.SemanticViolationPB
	for _, v := range v2 {
		if in1[key(v)] {
			out = append(out, &pb.SemanticViolationPB{Kind: v.Kind, Key: v.Key, Detail: v.Detail, Hosts: v.Hosts})
		}
	}
	return out
}
