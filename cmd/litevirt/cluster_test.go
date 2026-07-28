package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

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
