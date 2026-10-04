package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The convergence rule is what earns an epoch clear, so it is pinned directly:
// only a reseed that actually converged on shared-authority tables may end a
// quarantine, and per-node evidence tables must never block one.
func TestReseedDigestsConverged(t *testing.T) {
	local := []corrosion.TableDigest{
		{Name: "vms", Hash: "aaa"},
		{Name: "containers", Hash: "bbb"},
		{Name: "audit_log", Hash: "local-only"},
		{Name: "host_health", Hash: "local-only"},
	}

	// Converged: shared authority matches; per-node evidence differs and is
	// NOT counted — requiring it to match would make every reseed fail.
	n, mismatch := reseedDigestsConverged(local, map[string]string{
		"vms": "aaa", "containers": "bbb",
		"audit_log": "source-only", "host_health": "source-only",
	})
	if mismatch != "" || n != 2 {
		t.Fatalf("converged case: n=%d mismatch=%q", n, mismatch)
	}

	// NOT converged: a shared-authority table still differs → no clear, and the
	// message names the table so an operator knows what to look at.
	if _, mismatch := reseedDigestsConverged(local, map[string]string{
		"vms": "aaa", "containers": "DIFFERENT",
	}); mismatch == "" {
		t.Fatal("a differing shared-authority table must block the epoch clear")
	} else if mismatch != "table containers still differs" {
		t.Fatalf("mismatch should name the table: %q", mismatch)
	}

	// The invariant that failed on the lab: every table a reseed KEEPS must
	// also be skipped by the verifier. A kept table was never replaced, so it
	// cannot be expected to match the source — comparing one makes every
	// reseed fail verification and leaves the node permanently quarantined.
	for _, kept := range []string{"audit_log", "audit_signing_keys", "audit_chain_heads", "audit_key_lifecycle", "hosts"} {
		if !corrosion.ReseedKeepsTable(kept) {
			t.Fatalf("%s is expected to be kept by a reseed", kept)
		}
		// The fixture carries a real converging table alongside the kept one. A
		// kept table on its OWN compares nothing, and "nothing was compared" is
		// now itself a refusal — a different rule from the one under test here,
		// which is that a kept table whose hash DIFFERS must not block a reseed
		// that otherwise converged.
		if _, mismatch := reseedDigestsConverged(
			[]corrosion.TableDigest{{Name: kept, Hash: "local"}, {Name: "vms", Hash: "aaa"}},
			map[string]string{kept: "source-differs", "vms": "aaa"},
		); mismatch != "" {
			t.Fatalf("a KEPT table must never block a reseed, but %s did: %q", kept, mismatch)
		}
	}

	// A table the source doesn't report at all (older build) is skipped, not
	// treated as a mismatch — a benign version difference must not block a
	// reseed the node genuinely needs.
	if _, mismatch := reseedDigestsConverged(local, map[string]string{"vms": "aaa"}); mismatch != "" {
		t.Fatalf("a table absent on the source must not block: %q", mismatch)
	}
}

// TestReseedLocalDigests_IncludesSensitiveTables is part of the #199
// regression.
//
// reseedDigestsConverged compares whatever digests it is handed, and it was
// handed the OPERATOR set only. The sensitive tables were neither cleared, nor
// refetched, nor compared — so a reseed reported itself verified, cleared the
// isolation epoch, and a healthy peer then pulled the quarantined secrets
// fleet-wide. A reseed that cannot show the sensitive tables match its source
// has not converged with it, so they have to be in the set that gets compared.
func TestReseedLocalDigests_IncludesSensitiveTables(t *testing.T) {
	s := testServer(t)
	digests, err := s.reseedLocalDigests(context.Background())
	if err != nil {
		t.Fatalf("reseedLocalDigests: %v", err)
	}
	have := map[string]bool{}
	for _, d := range digests {
		have[d.Name] = true
	}
	for _, tbl := range corrosion.SensitiveTableNames() {
		if !have[tbl] {
			t.Errorf("%s is absent from the digests a reseed compares; a quarantined "+
				"secret in it would clear the epoch unnoticed", tbl)
		}
	}
	if !have["vms"] {
		t.Error("the operator tables dropped out of the comparison")
	}
}

// fakeReseedSource answers the three RPCs a reseed's verification asks of its
// source and nothing else. The embedded nil interface satisfies the rest of
// pb.LiteVirtClient, which is this package's convention for peer doubles.
type fakeReseedSource struct {
	pb.LiteVirtClient
	tables          map[string]string // operator-lane digests
	sensitive       map[string]string // sensitive-lane digests
	sensitiveUnimpl bool              // answer GetSensitiveStateDigest with Unimplemented
	ping            *pb.PingResponse
	pingErr         error
}

func (f *fakeReseedSource) GetStateDigest(context.Context, *emptypb.Empty, ...grpc.CallOption) (*pb.StateDigestResponse, error) {
	return &pb.StateDigestResponse{Tables: digestList(f.tables)}, nil
}

func (f *fakeReseedSource) GetSensitiveStateDigest(context.Context, *pb.SensitiveStateRequest, ...grpc.CallOption) (*pb.StateDigestResponse, error) {
	if f.sensitiveUnimpl {
		return nil, status.Error(codes.Unimplemented, "older build")
	}
	return &pb.StateDigestResponse{Tables: digestList(f.sensitive)}, nil
}

// StreamStateDump refuses rather than being left nil. A nil embedded interface
// panics, and a panic is a poor mutation signal: when a test here is checking
// that ReseedHost STOPS before the transfer, the interesting failure is the
// clean error from proceeding, not a crash inside the double.
func (f *fakeReseedSource) StreamStateDump(context.Context, *emptypb.Empty, ...grpc.CallOption) (grpc.ServerStreamingClient[pb.StateDumpChunk], error) {
	return nil, status.Error(codes.Unavailable, "this double serves no state dump")
}

func (f *fakeReseedSource) Ping(context.Context, *pb.PingRequest, ...grpc.CallOption) (*pb.PingResponse, error) {
	if f.pingErr != nil {
		return nil, f.pingErr
	}
	return f.ping, nil
}

func digestList(m map[string]string) []*pb.TableDigest {
	var out []*pb.TableDigest
	for n, h := range m {
		out = append(out, &pb.TableDigest{Name: n, Hash: h})
	}
	return out
}

// A reseed that COMPARED NOTHING is not a reseed that converged.
//
// Every table the source does not report is skipped as a benign version
// difference. That rule is right on its own, but it had no floor: a source that
// reported no table this node replaced produced verified=0 with an empty
// mismatch, which the caller reads as success — and an epoch clear on the
// strength of a comparison that never happened. The count was computed, sent
// over the wire and printed by `lv`, and never gated.
func TestReseedDigestsConverged_RefusesWhenNothingWasCompared(t *testing.T) {
	local := []corrosion.TableDigest{
		{Name: "vms", Hash: "aaa"},
		{Name: "containers", Hash: "bbb"},
	}
	// The source reports only tables this reseed deliberately KEPT, so every
	// shared-authority table is skipped and nothing is actually compared.
	n, mismatch := reseedDigestsConverged(local, map[string]string{"audit_log": "x"})
	if mismatch == "" {
		t.Fatalf("a comparison that verified %d tables must not read as converged: "+
			"it would clear the quarantine having proved nothing", n)
	}
	if n != 0 {
		t.Errorf("verified = %d, want 0", n)
	}
}

// The honest axes a reseed's source must satisfy, split from the RPC so the
// rule guarding an epoch clear is directly testable.
func TestReseedSourceCompatible(t *testing.T) {
	const local = 54

	t.Run("same schema and healthy is compatible", func(t *testing.T) {
		if m := reseedSourceCompatible(local, "peer1", &pb.PingResponse{SchemaVersion: local}); m != "" {
			t.Fatalf("a matching source must be accepted, got %q", m)
		}
	})

	// The hazard the digest comparison structurally cannot see: an older source
	// has fewer tables, every missing one is skipped as a benign difference, and
	// the reseed verifies against a partial comparison.
	t.Run("a source behind this binary is refused", func(t *testing.T) {
		m := reseedSourceCompatible(local, "peer1", &pb.PingResponse{SchemaVersion: local - 1})
		if m == "" {
			t.Fatal("a source on an older schema must not be able to clear a quarantine")
		}
		if !strings.Contains(m, "53") || !strings.Contains(m, "54") {
			t.Errorf("the refusal must name both versions so an operator can act: %q", m)
		}
	})

	t.Run("a source ahead of this binary is refused", func(t *testing.T) {
		if m := reseedSourceCompatible(local, "peer1", &pb.PingResponse{SchemaVersion: local + 1}); m == "" {
			t.Fatal("a source on a newer schema holds state this node cannot store; refuse")
		}
	})

	// pickReseedSource reads the RECORDED isolation row. A node that has just
	// detected its own rollback is quarantined before any peer has written that
	// row, and its self-report is the only thing that says so.
	t.Run("a WAL-quarantined source is refused", func(t *testing.T) {
		m := reseedSourceCompatible(local, "peer1", &pb.PingResponse{SchemaVersion: local, WalQuarantined: true})
		if m == "" {
			t.Fatal("reseeding from a quarantined source copies the state the regime exists to contain")
		}
	})
}

// The two halves of one condition must agree.
//
// fetchPeerSensitiveDump refuses a source with no sensitive lane outright —
// reseeding from it would empty this node's secret-bearing tables with nothing
// to restore them. The digest path treated the SAME capability gap as a benign
// version difference and merely logged it, so a source that got past the dump
// fetch could still skip the sensitive half of the verification and clear the
// epoch on the operator lane alone. That is the #199 hole, reachable through
// the other door.
func TestReseedRemoteDigests_RefusesASourceWithNoSensitiveDigest(t *testing.T) {
	s := testServer(t)
	peer := &fakeReseedSource{
		tables:          map[string]string{"vms": "aaa"},
		sensitiveUnimpl: true,
	}
	if _, err := s.reseedRemoteDigests(context.Background(), peer); err == nil {
		t.Fatal("a source that cannot report its sensitive digests must not be able to " +
			"verify a reseed: the secret-bearing half would go uncompared and the epoch " +
			"would clear anyway")
	}
}

// The barrier's cache TTL is justified by a threshold that can step BACKWARDS,
// and both of its comments used to name a reseed as the cause. That cause is
// wrong — leader_lease_terms is kept by a reseed, so the ledger's maximum cannot
// regress through one — and the reasoning is worth pinning rather than just
// correcting, because the premise is plausible enough to be re-derived.
//
// If this ever fails, the barrier's real window changed: a reseed would then
// genuinely drop the high water, and leaseBarrierCacheTTL would be bounding a
// second, different event.
func TestLeaseBarrier_AReseedCannotRegressTheHighWater(t *testing.T) {
	if !corrosion.ReseedKeepsTable("leader_lease_terms") {
		t.Fatal("leader_lease_terms is no longer kept by a reseed: the ledger's maximum " +
			"can now regress through one, which is the premise leaseBarrierCacheTTL's " +
			"comment was corrected for asserting")
	}
}

// The source check has to be WIRED, not merely present.
//
// reseedSourceCompatible is covered directly above, but removing its call from
// verifyReseedConvergence broke no test — the same shape of gap that let a
// defect sit behind a correct-looking helper before. This closes it.
//
// The fixture makes the digests converge EXACTLY, by answering with this node's
// own local digests. That matters: with a fake that reports nothing, the
// zero-verified floor would produce a mismatch all by itself and the test would
// pass with the source check deleted — vacuous, and testing the wrong guard.
// Here the state comparison has no complaint to make, so a non-empty mismatch
// can only have come from the source check.
func TestVerifyReseedConvergence_RefusesAnUnfitSourceWhoseStateMatches(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	local, err := s.reseedLocalDigests(ctx)
	if err != nil {
		t.Fatalf("reseedLocalDigests: %v", err)
	}
	sensitiveLane := map[string]bool{}
	for _, n := range corrosion.SensitiveTableNames() {
		sensitiveLane[n] = true
	}
	operator, sensitive := map[string]string{}, map[string]string{}
	for _, d := range local {
		if sensitiveLane[d.Name] {
			sensitive[d.Name] = d.Hash
		} else {
			operator[d.Name] = d.Hash
		}
	}

	newPeer := func(ping *pb.PingResponse) *fakeReseedSource {
		return &fakeReseedSource{tables: operator, sensitive: sensitive, ping: ping}
	}

	// Control: an identical, healthy source converges. Without this the test
	// could pass by refusing everything.
	fit := newPeer(&pb.PingResponse{SchemaVersion: int32(corrosion.CurrentSchemaVersion)})
	n, mismatch, err := s.verifyReseedConvergence(ctx, "peer1", fit)
	if err != nil {
		t.Fatalf("fit source: %v", err)
	}
	if mismatch != "" {
		t.Fatalf("a source with identical state must converge, got %q", mismatch)
	}
	if n == 0 {
		t.Fatal("the control verified no tables, so the refusals below prove nothing")
	}

	// Same identical state, older build. The digests agree; the source does not.
	behind := newPeer(&pb.PingResponse{SchemaVersion: int32(corrosion.CurrentSchemaVersion) - 1})
	if _, mismatch, err := s.verifyReseedConvergence(ctx, "peer1", behind); err != nil {
		t.Fatalf("behind source: %v", err)
	} else if mismatch == "" {
		t.Error("a source on an older schema cleared the quarantine because its digests " +
			"happened to match: the compatibility check is not wired in")
	}

	// Same again for the self-reported quarantine.
	quarantined := newPeer(&pb.PingResponse{
		SchemaVersion: int32(corrosion.CurrentSchemaVersion), WalQuarantined: true,
	})
	if _, mismatch, err := s.verifyReseedConvergence(ctx, "peer1", quarantined); err != nil {
		t.Fatalf("quarantined source: %v", err)
	} else if mismatch == "" {
		t.Error("a WAL-quarantined source cleared the quarantine: the self-report is not wired in")
	}
}

// An unfit source must be refused BEFORE the discard, not after it.
//
// The order used to be: pull, discard, merge, then check. A source on an older
// build therefore got to replace this node's entire replicated state before
// anything noticed, and the reseed then declined to clear the epoch — leaving
// the node strictly worse off than when it asked, and needing a repeat reseed
// from a source that might not exist. The check now runs while the local rows
// are still intact, and this asserts they survive.
func TestReseedHost_RefusesAnUnfitSourceWithoutDiscarding(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	for _, h := range []corrosion.HostRecord{
		{Name: "test-host", Address: "10.0.0.1", State: "active"},
		{Name: "peer1", Address: "10.0.0.2", State: "active"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	// A row that must still be here afterwards: the discard would take it.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "keepme", HostName: "test-host", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.IsolateHost(ctx, s.db, "peer1", "test-host", "schema_forward"); err != nil {
		t.Fatalf("IsolateHost: %v", err)
	}

	// A source that is reachable and would serve state quite happily — it is
	// simply a build behind.
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &fakeReseedSource{
			ping: &pb.PingResponse{SchemaVersion: int32(corrosion.CurrentSchemaVersion) - 1},
		}, func() {}, nil
	}

	_, err := s.ReseedHost(ctx, &pb.ReseedHostRequest{
		Name: "test-host", Source: "peer1", DrivenByPeer: "peer1",
	})
	if err == nil {
		t.Fatal("a reseed from a source on an older schema must be refused")
	}
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Errorf("code = %s, want FailedPrecondition: this is a refusal the operator can act on, "+
			"not a transport failure", got)
	}
	if !strings.Contains(err.Error(), "Nothing was discarded") {
		t.Errorf("the refusal must tell the operator their state is intact: %v", err)
	}

	// The local state is still there. With a double that serves no state dump
	// this cannot distinguish "stopped at the preflight" from "stopped at the
	// transfer" on its own — the assertions above do that. Its job is to catch a
	// future reordering that moves the discard ahead of the source check, which
	// is exactly the bug this test was written for.
	vm, verr := corrosion.GetVM(ctx, s.db, "keepme")
	if verr != nil {
		t.Fatalf("GetVM after the refused reseed: %v", verr)
	}
	if vm == nil {
		t.Fatal("the reseed discarded this node's state before finding out its source was " +
			"unfit — the node is now worse off than before it asked")
	}
}
