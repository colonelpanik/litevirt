package grpcapi

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
)

type fanoutTestKey struct{}

// The point of the helper: survive the handler, keep everything else.
func TestDetachedFanout_SurvivesHandlerCancellationAndKeepsValues(t *testing.T) {
	parent := context.WithValue(context.Background(), fanoutTestKey{}, "caller-identity")
	parent, cancelParent := context.WithCancel(parent)

	fctx, cancel := detachedFanout(parent)
	defer cancel()

	// The handler returns: gRPC cancels its context here.
	cancelParent()

	if err := fctx.Err(); err != nil {
		t.Fatalf("fan-out context died with its handler (%v); the peer call would fail "+
			"with codes.Canceled and the failure would only be logged", err)
	}
	if got := fctx.Value(fanoutTestKey{}); got != "caller-identity" {
		t.Errorf("value = %v, want it carried through: dropping values re-authenticates the "+
			"peer call as somebody else", got)
	}
	if _, ok := fctx.Deadline(); !ok {
		t.Error("no deadline: an unreachable peer would hold the goroutine open indefinitely, " +
			"because the lazy dial returns immediately and the RPC is what blocks")
	}
}

// The wiring. A correct helper nothing calls leaves the bug in place, and these
// fan-outs are detached goroutines behind real peer dials — no unit test
// reaches them. This reads the source, as the repo's writecheck and
// stmtshapecheck guards already do.
func TestPeerFanouts_DoNotUseTheHandlerContext(t *testing.T) {
	// Opening brace of a fan-out goroutine through to its closing `}(`.
	block := regexp.MustCompile(`(?s)go func\(host string\) \{.*?\n\t\t\}\(`)
	for _, file := range []string{"lb.go", "networks.go", "fdb.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		blocks := block.FindAllString(string(src), -1)
		if len(blocks) == 0 {
			t.Errorf("%s: found no fan-out goroutine; this guard is not looking at what it "+
				"thinks it is", file)
			continue
		}
		for _, b := range blocks {
			// A block that detaches its own context, is handed one already
			// detached, or is waited on by the handler is fine.
			if strings.Contains(b, "detachedFanout(") ||
				strings.Contains(b, "context.Background()") ||
				strings.Contains(b, "wg.Done()") {
				continue
			}
			if strings.Contains(b, "peerClient(ctx") || strings.Contains(b, "(ctx,") {
				head := strings.SplitN(b, "\n", 3)
				t.Errorf("%s: a fan-out goroutine uses the handler's context — it is cancelled "+
					"the moment the handler returns, so the peer call fails with Canceled and "+
					"the failure is only logged. Use detachedFanout(ctx).\n\t%s",
					file, strings.TrimSpace(strings.Join(head[:2], " ")))
			}
		}
	}
}
