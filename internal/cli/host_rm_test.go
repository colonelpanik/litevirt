package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type hostRemoveTestClient struct {
	pb.LiteVirtClient
	publishErr error
	calls      []string
}

func (c *hostRemoveTestClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	return &pb.ListHostsResponse{Hosts: []*pb.Host{{Name: "node-9", CertSerial: "a1b2c3"}}}, nil
}

func (c *hostRemoveTestClient) PublishCRL(context.Context, *pb.PublishCRLRequest, ...grpc.CallOption) (*pb.PublishCRLResponse, error) {
	c.calls = append(c.calls, "publish")
	if c.publishErr != nil {
		return nil, c.publishErr
	}
	return &pb.PublishCRLResponse{Version: 47}, nil
}

func (c *hostRemoveTestClient) RetireAuditKey(context.Context, *pb.RetireAuditKeyRequest, ...grpc.CallOption) (*pb.RetireAuditKeyResponse, error) {
	c.calls = append(c.calls, "retire")
	return nil, errors.New(`rpc error: code = FailedPrecondition desc = host "node-9" has no live audit signing certificate: it either never published one or its key is already retired, so there is nothing to retire`)
}

func (c *hostRemoveTestClient) RemoveHost(context.Context, *pb.RemoveHostRequest, ...grpc.CallOption) (*emptypb.Empty, error) {
	c.calls = append(c.calls, "remove")
	return &emptypb.Empty{}, nil
}

// Removing a host tombstones its row and nothing else. The certificate it holds
// still chains to the cluster CA, so peer trust — which now falls back to the
// certificate for a host it has no row for — depends entirely on that tombstone
// reaching every node. A node that never receives it keeps accepting a peer the
// operator decommissioned, and nothing says so.
//
// The CRL is the second, independent mechanism, and every piece of it already
// existed: pki.AppendToCRL, a crl.pem the daemon re-reads on mtime change, and a
// health check that publishes each node's CRL version and warns on a mismatch.
// Nothing called them.

func TestRevokeHostCert_AddsTheSerialToTheCRL(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	if err := revokeHostCert(dir, "node-9", "a1b2c3"); err != nil {
		t.Fatalf("revokeHostCert: %v", err)
	}
	serials, err := pki.LoadCRL(filepath.Join(dir, "crl.pem"))
	if err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	found := false
	for _, s := range serials {
		if strings.EqualFold(s, "a1b2c3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the removed host's serial is not in the CRL (%v)\n"+
			"removal then rests solely on the tombstone reaching every node, and a node "+
			"that misses it keeps accepting a decommissioned peer", serials)
	}

	// Revoking again must not fail or duplicate — `lv host rm` is re-runnable.
	if err := revokeHostCert(dir, "node-9", "a1b2c3"); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if again, _ := pki.LoadCRL(filepath.Join(dir, "crl.pem")); len(again) != len(serials) {
		t.Errorf("re-revoking duplicated the entry: %v -> %v", serials, again)
	}
}

func TestHostRemove_DoesNotTombstoneBeforeRevocationPublishes(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("LV_CONFIG_DIR", configDir)
	pkiDir := filepath.Join(configDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatalf("mkdir pki: %v", err)
	}
	if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	client := &hostRemoveTestClient{publishErr: errors.New("cluster unavailable")}
	if err := HostRemove(context.Background(), client, "node-9", false); err == nil {
		t.Fatal("publish failure reported a successful removal")
	}
	if got := strings.Join(client.calls, ","); got != "publish" {
		t.Fatalf("calls = %q, want publish only; RemoveHost ran before revocation was durable", got)
	}
}

func TestHostRemove_PublishesBeforeTombstoning(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("LV_CONFIG_DIR", configDir)
	pkiDir := filepath.Join(configDir, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		t.Fatalf("mkdir pki: %v", err)
	}
	if err := pki.GenerateCA(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	client := &hostRemoveTestClient{}
	if err := HostRemove(context.Background(), client, "node-9", false); err != nil {
		t.Fatalf("HostRemove: %v", err)
	}
	if got := strings.Join(client.calls, ","); got != "publish,retire,remove" {
		t.Fatalf("calls = %q, want publish,retire,remove", got)
	}
}

// TestRevokeHostCert_WithoutTheCAKeySaysSo — `lv host rm` may be run from a node
// that holds no CA private key. That cannot silently skip revocation.
func TestRevokeHostCert_WithoutTheCAKeySaysSo(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("remove ca.key: %v", err)
	}
	err := revokeHostCert(dir, "node-9", "a1b2c3")
	if err == nil {
		t.Fatal("revocation without the CA private key reported success")
	}
	// The bare signing failure already errors, so the explicit check only earns its
	// place by saying WHICH machine can do this — otherwise the operator is told a
	// file is missing without being told where the one that matters lives.
	if !strings.Contains(err.Error(), "lv host init") {
		t.Errorf("the error does not point at the machine holding the CA: %v", err)
	}
}

func TestRevokeHostCert_NoSerialRefusesAnUnrevokableRemoval(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	for _, serial := range []string{"", "unknown"} {
		if err := revokeHostCert(dir, "node-9", serial); err == nil {
			t.Errorf("serial %q allowed a removal whose certificate cannot be revoked", serial)
		}
	}
}

// ── audit signing contract on removal ───────────────────────────────────────
//
// The 2026-08-01 lab found node-4 re-admitted with its OLD audit signing
// certificate still published and unretired: its fresh daemon would not sign
// (new key, closed-out world) and every row it wrote was reported as
// tampering on every node. `lv host rm` runs where the cluster CA lives — the
// only place a retirement can be signed — so removal must close the contract.

type hostRemoveAuditTestClient struct {
	hostRemoveTestClient
	retireErr error
}

func (c *hostRemoveAuditTestClient) RetireAuditKey(context.Context, *pb.RetireAuditKeyRequest, ...grpc.CallOption) (*pb.RetireAuditKeyResponse, error) {
	c.calls = append(c.calls, "retire")
	return nil, c.retireErr
}

func TestHostRemove_ClosesAuditContractBeforeRemoval(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	t.Setenv("LV_CONFIG_DIR", filepath.Dir(dir))
	if err := os.Rename(dir, filepath.Join(filepath.Dir(dir), "pki")); err != nil {
		t.Fatalf("stage pki dir: %v", err)
	}

	// The common case for a host that never signed: retirement reports there
	// is nothing to retire. Removal must attempt it and then proceed.
	c := &hostRemoveAuditTestClient{retireErr: errors.New(
		`rpc error: code = FailedPrecondition desc = host "node-9" has no live audit signing certificate: it either never published one or its key is already retired, so there is nothing to retire`)}
	if err := HostRemove(context.Background(), c, "node-9", false); err != nil {
		t.Fatalf("HostRemove with nothing to retire must succeed: %v", err)
	}
	retireIdx, removeIdx := -1, -1
	for i, call := range c.calls {
		switch call {
		case "retire":
			if retireIdx < 0 {
				retireIdx = i
			}
		case "remove":
			removeIdx = i
		}
	}
	if retireIdx < 0 {
		t.Fatal("HostRemove never attempted to close the audit signing contract")
	}
	if removeIdx < retireIdx {
		t.Fatal("audit contract must be probed before the host row is removed")
	}
}

func TestHostRemove_AuditRetirementFailureDoesNotBlockRemoval(t *testing.T) {
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	t.Setenv("LV_CONFIG_DIR", filepath.Dir(dir))
	if err := os.Rename(dir, filepath.Join(filepath.Dir(dir), "pki")); err != nil {
		t.Fatalf("stage pki dir: %v", err)
	}

	// A lagging replica (or any transient fault) must not wedge removal: the
	// CRL revocation above is the security boundary; the contract can still be
	// closed afterwards with `lv host retire-audit-key`.
	c := &hostRemoveAuditTestClient{retireErr: errors.New("rpc error: code = Unavailable desc = replica lags")}
	if err := HostRemove(context.Background(), c, "node-9", false); err != nil {
		t.Fatalf("HostRemove must warn, not fail, when retirement errs: %v", err)
	}
	found := false
	for _, call := range c.calls {
		if call == "remove" {
			found = true
		}
	}
	if !found {
		t.Fatal("removal did not proceed after a retirement failure")
	}
}
