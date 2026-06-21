package firewall

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingNft saves every applied ruleset for post-hoc inspection.
// Unlike fakeNft (in applier_test.go), it cares about every byte not
// just call count.
type recordingNft struct {
	mu      sync.Mutex
	applied [][]byte
	flushes int32
}

func (r *recordingNft) Apply(_ context.Context, ruleset string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applied = append(r.applied, []byte(ruleset))
	return "", nil
}

func (r *recordingNft) Flush(_ context.Context) (string, error) {
	atomic.AddInt32(&r.flushes, 1)
	return "", nil
}

func (r *recordingNft) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.applied))
	copy(out, r.applied)
	return out
}

// TestChaos_ConcurrentRuleMutationProducesValidRulesets — many writers
// churn the Plan that a reconciler hands to the applier; we assert
// every applied ruleset is well-formed (i.e. starts with the expected
// table preamble and contains a closing brace), and that no two
// successive applies were torn (a half-built Plan slipped through).
//
// This is the firewall analogue of the auth-engine atomic-pointer
// test from: the renderer must produce coherent output even
// under heavy concurrent state churn.
func TestChaos_ConcurrentRuleMutationProducesValidRulesets(t *testing.T) {
	if testing.Short() {
		t.Skip("chaos test")
	}

	// Shared state the loader reads from. Writers churn the slices;
	// the loader takes a snapshot so the renderer never sees a
	// half-mutated input.
	state := struct {
		mu  sync.RWMutex
		sgs []SecurityGroup
	}{
		sgs: []SecurityGroup{{Name: "base", Rules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "22", Action: Accept}}}},
	}

	loader := func(_ context.Context) (Plan, error) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		// Snapshot — Plan owns its slices so the writer can mutate
		// freely after we return.
		out := make([]SecurityGroup, len(state.sgs))
		for i, sg := range state.sgs {
			rules := make([]Rule, len(sg.Rules))
			copy(rules, sg.Rules)
			out[i] = SecurityGroup{Name: sg.Name, Rules: rules}
		}
		return Plan{SecurityGroups: out, DefaultDeny: true}, nil
	}

	rec := recordingNft{}
	a := NewApplier(&rec)

	// Writer goroutine: churns rule sets.
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			state.mu.Lock()
			i++
			port := 1024 + (i % 4096)
			state.sgs = []SecurityGroup{{
				Name: "base",
				Rules: []Rule{
					{Direction: Ingress, Proto: "tcp", PortRange: "22", Action: Accept},
					{Direction: Ingress, Proto: "tcp", PortRange: itoa(port), Action: Accept},
				},
			}}
			state.mu.Unlock()
		}
	}()

	// Reconciler goroutine: race-reads + applies.
	const reconciles = 200
	var rg sync.WaitGroup
	for i := 0; i < 4; i++ {
		rg.Add(1)
		go func() {
			defer rg.Done()
			for j := 0; j < reconciles/4; j++ {
				p, err := loader(context.Background())
				if err != nil {
					t.Errorf("loader: %v", err)
					return
				}
				if _, err := a.Apply(context.Background(), p); err != nil {
					t.Errorf("apply: %v", err)
					return
				}
			}
		}()
	}
	rg.Wait()
	close(stop)
	<-writerDone

	// Every applied ruleset must be a complete table — preamble +
	// closing brace. A torn render would chop one off.
	for i, blob := range rec.snapshot() {
		if !bytes.Contains(blob, []byte("table inet litevirt-fw {")) {
			t.Errorf("apply #%d missing table preamble", i)
		}
		if !bytes.HasSuffix(blob, []byte("}\n")) {
			t.Errorf("apply #%d missing closing brace", i)
		}
		if !bytes.Contains(blob, []byte("policy drop;")) {
			t.Errorf("apply #%d missing policy drop", i)
		}
	}

	// Sleep to allow any final writer iterations to flush.
	time.Sleep(10 * time.Millisecond)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
