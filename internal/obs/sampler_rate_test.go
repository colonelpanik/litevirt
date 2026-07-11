package obs

import (
	"context"
	"testing"

	oteltrace "go.opentelemetry.io/otel/trace"
)

// Statistical smoke for sample_rate: 0.1 (not just the 0/1 endpoints).
// TraceIDRatioBased is deterministic per TraceID; the SDK assigns random
// TraceIDs to root spans, so over N roots the sampled fraction should land
// near the configured rate. A hollow/ignored rate (always 1 or always 0)
// fails the band hard.
func TestSetup_SamplerWired_RatePointOne_ApproximatelyTenPercent(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	setup(t, Config{ServiceName: "rate-dist", OTLPEndpoint: srv.URL, SampleRate: f64p(0.1)})

	const n = 2000
	var sampled int
	for i := 0; i < n; i++ {
		ctx, span := Span(context.Background(), "rate.dist")
		if oteltrace.SpanContextFromContext(ctx).IsSampled() {
			sampled++
		}
		span.End()
	}

	// Expect ~10%. Allow a wide band so this is a smoke test, not a flaky
	// chi-square: at N=2000, P(outside 5–15%) under a true 0.1 Bernoulli is
	// vanishingly small; always-on/always-off land at 100%/0% and fail.
	lo, hi := int(0.05*n), int(0.15*n)
	if sampled < lo || sampled > hi {
		t.Fatalf("sampled %d/%d (%.1f%%) at sample_rate=0.1; want ~10%% in [%d, %d] — sampler missing, double-applied, or ignored",
			sampled, n, 100*float64(sampled)/float64(n), lo, hi)
	}
	t.Logf("sample_rate=0.1: sampled %d/%d (%.1f%%)", sampled, n, 100*float64(sampled)/float64(n))
}
