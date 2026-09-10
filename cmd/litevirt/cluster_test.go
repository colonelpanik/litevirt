package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func td(name, hash, hashV2 string, count int32, ties int32) *pb.TableDigest {
	return &pb.TableDigest{Name: name, Hash: hash, HashV2: hashV2, Count: count, UnresolvedTies: ties}
}

func host(name string, tables ...*pb.TableDigest) *pb.StateDigestResponse {
	return &pb.StateDigestResponse{HostName: name, Tables: tables}
}

// TestDigestVersions_AllEnabledPicksV2: when every host reporting a table supplies hash_v2,
// the comparison/display version is v2 for that table.
func TestDigestVersions_AllEnabledPicksV2(t *testing.T) {
	dig := &pb.ClusterStateDigestResponse{Hosts: []*pb.StateDigestResponse{
		host("a", td("vms", "v1a", "v2same", 3, 0)),
		host("b", td("vms", "v1b", "v2same", 3, 0)),
	}}
	ver := digestVersions(dig)
	if ver.label("vms") != "v2" {
		t.Fatalf("expected v2, got %s", ver.label("vms"))
	}
	if got := ver.hash("vms", dig.Hosts[0].Tables[0]); got != "v2same" {
		t.Fatalf("expected v2 hash for display, got %q", got)
	}
}

// TestDigestVersions_MixedFallsBackToV1: if any reporting host omits hash_v2 (pre-v2 or
// flag-off), the table is compared/displayed on v1 for the whole group.
func TestDigestVersions_MixedFallsBackToV1(t *testing.T) {
	dig := &pb.ClusterStateDigestResponse{Hosts: []*pb.StateDigestResponse{
		host("a", td("vms", "v1a", "v2a", 3, 0)),
		host("b", td("vms", "v1b", "", 3, 0)), // flag-off / pre-v2 peer
	}}
	ver := digestVersions(dig)
	if ver.label("vms") != "v1" {
		t.Fatalf("expected v1 fallback, got %s", ver.label("vms"))
	}
	if got := ver.hash("vms", dig.Hosts[0].Tables[0]); got != "v1a" {
		t.Fatalf("expected v1 hash for display, got %q", got)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy: %v", err)
	}
	return buf.String()
}

// TestPrintConvergence_V2ClearsColumnOrderDivergence: two hosts whose v1 hashes differ
// (column-order artifact) but whose v2 hashes match converge under v2.
func TestPrintConvergence_V2ClearsColumnOrderDivergence(t *testing.T) {
	dig := &pb.ClusterStateDigestResponse{Hosts: []*pb.StateDigestResponse{
		host("a", td("networks", "v1a", "v2same", 5, 0)),
		host("b", td("networks", "v1b", "v2same", 5, 0)),
	}}
	out := captureStdout(t, func() { printConvergence(dig) })
	if !strings.Contains(out, "1/1 table(s) converged") {
		t.Fatalf("expected converged summary, got:\n%s", out)
	}
	if strings.Contains(out, "DIVERGENT") {
		t.Fatalf("expected no DIVERGENT row under v2, got:\n%s", out)
	}
}

// TestPrintConvergence_SafetyFaultRemediation: a non-vms safety-fault table must NOT be
// told to run repair-owner (which only restamps VM ownership) — it gets the generic
// divergence-scan guidance; the vms table does get repair-owner.
func TestPrintConvergence_SafetyFaultRemediation(t *testing.T) {
	dig := &pb.ClusterStateDigestResponse{Hosts: []*pb.StateDigestResponse{
		host("a", td("lb_configs", "v1a", "", 2, 1), td("vms", "vh_a", "", 4, 1)),
		host("b", td("lb_configs", "v1b", "", 2, 0), td("vms", "vh_b", "", 4, 0)),
	}}
	out := captureStdout(t, func() { printConvergence(dig) })
	lines := strings.Split(out, "\n")
	var lbLine, vmLine string
	for _, l := range lines {
		if strings.HasPrefix(l, "lb_configs") {
			lbLine = l
		}
		if strings.HasPrefix(l, "vms") {
			vmLine = l
		}
	}
	if lbLine == "" || vmLine == "" {
		t.Fatalf("missing safety-fault rows:\n%s", out)
	}
	if strings.Contains(lbLine, "repair-owner") {
		t.Fatalf("lb_configs should NOT suggest repair-owner: %q", lbLine)
	}
	if !strings.Contains(lbLine, "lv doctor divergence") {
		t.Fatalf("lb_configs should suggest divergence scan: %q", lbLine)
	}
	if !strings.Contains(vmLine, "repair-owner") {
		t.Fatalf("vms should suggest repair-owner: %q", vmLine)
	}
}

// captureAckLeaseTerm records the AcknowledgeLeaseTermTie request the CLI put on
// the wire and returns a canned answer. The assertion that matters is that --key
// and --term REACH the request: a parsed-but-unwired flag would silently
// acknowledge term 0 for the empty key, which the server rejects as
// InvalidArgument and an operator would read as "the tie is not real".
type captureAckLeaseTerm struct {
	pb.LiteVirtClient
	req  *pb.AcknowledgeLeaseTermTieRequest
	resp bool
}

func (c *captureAckLeaseTerm) AcknowledgeLeaseTermTie(_ context.Context, in *pb.AcknowledgeLeaseTermTieRequest, _ ...grpc.CallOption) (*pb.AcknowledgeLeaseTermTieResponse, error) {
	c.req = in
	return &pb.AcknowledgeLeaseTermTieResponse{Acknowledged: c.resp}, nil
}

func runAckLeaseTermCLI(t *testing.T, spy *captureAckLeaseTerm, args ...string) (string, error) {
	t.Helper()
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(ctx, spy)
	}
	t.Cleanup(func() { withClient = orig })

	cmd := newClusterAckLeaseTermCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage = true
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	return out, err
}

// TestClusterAckLeaseTerm_FlagsReachTheRequest.
func TestClusterAckLeaseTerm_FlagsReachTheRequest(t *testing.T) {
	spy := &captureAckLeaseTerm{resp: true}
	out, err := runAckLeaseTermCLI(t, spy, "--key", "rebalancer", "--term", "7")
	if err != nil {
		t.Fatalf("acknowledge-lease-term: %v", err)
	}
	if spy.req.GetKey() != "rebalancer" {
		t.Errorf("key = %q, want rebalancer", spy.req.GetKey())
	}
	if spy.req.GetTerm() != 7 {
		t.Errorf("term = %d, want 7", spy.req.GetTerm())
	}
	if !strings.Contains(out, "Acknowledged rebalancer term 7") {
		t.Errorf("output does not confirm the acknowledgement:\n%s", out)
	}
}

// TestClusterAckLeaseTerm_UntrackedTieIsNotReportedAsDone: acknowledged=false is
// a legitimate answer (already acknowledged, or this host never contested), and
// must not print the same line as a real clear — the operator uses that
// distinction to decide whether the remaining hosts still need visiting.
func TestClusterAckLeaseTerm_UntrackedTieIsNotReportedAsDone(t *testing.T) {
	spy := &captureAckLeaseTerm{resp: false}
	out, err := runAckLeaseTermCLI(t, spy, "--key", "failover", "--term", "3")
	if err != nil {
		t.Fatalf("acknowledge-lease-term: %v", err)
	}
	if strings.Contains(out, "Acknowledged failover term 3") {
		t.Errorf("an untracked tie was reported as acknowledged:\n%s", out)
	}
	if !strings.Contains(out, "No tracked tie") {
		t.Errorf("output does not say the tie was untracked:\n%s", out)
	}
}

// TestClusterAckLeaseTerm_RefusesIncompleteInputWithoutDialling. A missing
// --term must not reach the wire as term 0: the server would answer
// InvalidArgument, and the operator would be debugging the wrong end.
func TestClusterAckLeaseTerm_RefusesIncompleteInputWithoutDialling(t *testing.T) {
	for _, args := range [][]string{
		{"--key", "failover"},
		{"--term", "1"},
		{"--key", "failover", "--term", "0"},
		{"--key", "failover", "--term", "-1"},
	} {
		spy := &captureAckLeaseTerm{resp: true}
		if _, err := runAckLeaseTermCLI(t, spy, args...); err == nil {
			t.Errorf("lv cluster acknowledge-lease-term %v was accepted", args)
		}
		if spy.req != nil {
			t.Errorf("lv cluster acknowledge-lease-term %v reached the wire as %+v", args, spy.req)
		}
	}
}
