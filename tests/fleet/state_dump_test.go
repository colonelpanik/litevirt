package fleet

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestStreamStateDump_EndToEndConverges exercises the P1-3 fix over the real
// gRPC/mTLS stack: StreamStateDump must carry a dump large enough to span
// multiple chunks (the unary GetStateDump silently failed past the ~4 MiB gRPC
// message limit) and merge into a lagging peer to convergence.
func TestStreamStateDump_EndToEndConverges(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	src := c.Node("node-0")
	dst := c.Node("node-1")
	ctx := context.Background()

	// Seed node-0 with > 1 MiB of state so the (gzipped) dump spans several
	// chunks over the wire. The spec blobs are seeded-random, base64-encoded
	// bytes — incompressible, so the dump stays large after gzip. dst has none
	// of these rows.
	rng := rand.New(rand.NewSource(42))
	mkSpec := func() string {
		raw := make([]byte, 160*1024)
		rng.Read(raw)
		return base64.StdEncoding.EncodeToString(raw)
	}
	const nVMs = 12
	if err := corrosion.InsertHost(ctx, src.DB, corrosion.HostRecord{
		Name: "wl-host", State: "active", CPUTotal: 8, MemTotal: 4096,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	for i := 0; i < nVMs; i++ {
		vm := corrosion.VMRecord{
			Name: fmt.Sprintf("wl-%02d", i), StackName: "s", HostName: "wl-host",
			Spec: mkSpec(), State: "running", CPUActual: 1, MemActual: 256,
		}
		if err := corrosion.InsertVM(ctx, src.DB, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM %d: %v", i, err)
		}
	}

	// Pull node-0's full state over the real streaming RPC.
	stream, err := c.SelfClient(src).StreamStateDump(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("StreamStateDump: %v", err)
	}
	var blob []byte
	chunks := 0
	for {
		chunk, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("Recv: %v", rerr)
		}
		blob = append(blob, chunk.Data...)
		chunks++
	}
	if chunks < 2 {
		t.Fatalf("expected a >1 MiB dump to span multiple chunks, got %d", chunks)
	}

	// Merge into the lagging node; it must now hold node-0's workload.
	dst.DB.MergeStateBytesLWW(blob)

	vms, err := corrosion.ListVMs(ctx, dst.DB, "", "wl-host")
	if err != nil {
		t.Fatalf("ListVMs on dst: %v", err)
	}
	if len(vms) != nVMs {
		t.Fatalf("dst has %d VMs after merge, want %d (state did not converge)", len(vms), nVMs)
	}
}
