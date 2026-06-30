package corrosion

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestAntiEntropy_BoundedResync: once an unresolved tie has been reconciled, a
// persistent digest mismatch caused ONLY by that intentional divergence is
// suppressed (no re-pull) — until a real new write changes a hash. This is the
// bound that removes the infinite no-op resync.
func TestAntiEntropy_BoundedResync(t *testing.T) {
	ctx := context.Background()
	dst := testClient(t)
	ae := &AntiEntropy{client: dst}
	const peer = "peer1"

	// Put dst into a known unresolved state for vms (a host_name split kept local).
	if err := InsertVM(ctx, dst, VMRecord{Name: "vm1", HostName: "host-a", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	dst.trackUnresolved("vms", "vm1", []interface{}{"host-a"}, []interface{}{"host-b"}, pathAE, "runtime_owned")

	local, err := dst.StateDigest(ctx)
	if err != nil {
		t.Fatalf("StateDigest: %v", err)
	}
	localMap := make(map[string]TableDigest, len(local))
	var vmsCount int
	var vmsLocalHash string
	for _, d := range local {
		localMap[d.Name] = d
		if d.Name == "vms" {
			vmsCount, vmsLocalHash = d.Count, d.Hash
		}
	}

	// Remote reports the same row count but a different vms hash (the divergence).
	remote := []*pb.TableDigest{{Name: "vms", Count: int32(vmsCount), Hash: "REMOTE_HASH"}}

	// First pass: a genuine, not-yet-reconciled mismatch → must sync.
	if got := ae.genuineMismatches(peer, remote, localMap); len(got) != 1 || got[0] != "vms" {
		t.Fatalf("first pass should report vms as a genuine mismatch, got %v", got)
	}
	// Simulate the post-merge memo update (vms still divergent, has an unresolved tie).
	ae.updateReconciledMemo(peer, remote, func() ([]TableDigest, error) { return dst.StateDigest(ctx) })

	// Second pass with the SAME hashes: now suppressed (intentional divergence).
	if got := ae.genuineMismatches(peer, remote, localMap); len(got) != 0 {
		t.Fatalf("a reconciled unresolved divergence must be suppressed, got %v", got)
	}

	// A real new write on the peer changes the hash → memo invalidated → re-sync.
	remoteChanged := []*pb.TableDigest{{Name: "vms", Count: int32(vmsCount), Hash: "REMOTE_HASH_2"}}
	if got := ae.genuineMismatches(peer, remoteChanged, localMap); len(got) != 1 {
		t.Fatalf("a changed remote hash must re-sync, got %v", got)
	}
	_ = vmsLocalHash
}
