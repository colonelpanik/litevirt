// Package chaos provides deterministic fault-injection primitives for
// testing litevirt's clustering, replication, and failover behavior under
// simulated network partitions, packet loss, clock skew, and disk failures.
//
// The harness is split into three layers:
//
//   - Clock: virtual time. Tests advance the clock explicitly via
//     [Clock.Advance], so timeouts/intervals fire at predictable points
//     instead of depending on wall time. Production code under test uses
//     a [TimeSource] supplied by tests in place of [time.Now].
//
//   - Net: a virtual peer-to-peer network. Each Node has an inbox; tests
//     route messages by calling [Net.Send] which respects per-edge policies
//     (drop, delay, partition). [Net.Partition] cleaves the graph into
//     groups; messages crossing a partition are dropped silently until the
//     partition heals. Designed to be deterministic given a seed.
//
//   - Disk: a virtual blockstore — a wrapper around an [io.Writer]/[io.Reader]
//     that can return ENOSPC, enforce per-op latency, or fail every Nth
//     write. Used to test the replicator's behavior under "disk fills" and
//     antientropy under slow storage.
//
// Determinism contract: every public method is deterministic given a Seed
// passed at construction. No goroutines. No real time. No real network. All
// scheduling is explicit via Clock.Advance and Net.Tick.
//
// This package is test-only. It must not be imported by production code.
package chaos

import (
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// ErrDropped is returned by Net.Send when a message is dropped by policy
// (loss, partition, or full inbox).
var ErrDropped = errors.New("chaos: message dropped")

// ───────────────────── Clock ─────────────────────

// TimeSource is the minimal time interface that production code under test
// can accept. The chaos harness implements it; production code wires
// time.Now via the same interface.
type TimeSource interface {
	Now() time.Time
}

// Clock is a virtual clock. Time advances only when tests call Advance.
// Safe for concurrent use; tests typically run single-threaded but the
// production code under test may have goroutines that read Now().
type Clock struct {
	mu   sync.Mutex
	now  time.Time
	tick chan struct{} // closed-and-replaced on every Advance
}

// NewClock returns a clock pinned at the given start time.
func NewClock(start time.Time) *Clock {
	return &Clock{now: start, tick: make(chan struct{})}
}

// Now returns the current virtual time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves virtual time forward by d. Any goroutines blocked on
// Tick() are woken once.
func (c *Clock) Advance(d time.Duration) {
	if d <= 0 {
		return
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	old := c.tick
	c.tick = make(chan struct{})
	c.mu.Unlock()
	close(old)
}

// Set jumps the clock to t. Useful for simulating NTP step-changes or
// reseeding a deterministic test mid-run.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	old := c.tick
	c.tick = make(chan struct{})
	c.mu.Unlock()
	close(old)
}

// Tick returns a channel closed on the next Advance/Set. Allows code under
// test to "sleep" without burning CPU: read Tick(), block, recheck.
func (c *Clock) Tick() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tick
}

// ───────────────────── Net ─────────────────────

// NodeID identifies a virtual node in the chaos network.
type NodeID string

// Message is a single unit of inter-node traffic. The harness does not
// interpret Payload; tests use whatever encoding suits the system under
// test (gRPC bytes, JSON, etc.).
type Message struct {
	From    NodeID
	To      NodeID
	Payload []byte
	// SentAt is set by Net.Send; DeliverAt is computed from edge policy.
	SentAt    time.Time
	DeliverAt time.Time
}

// EdgePolicy controls how a single directed edge (from→to) behaves.
//
// Zero value = perfect link: no drops, no delay, no partition.
type EdgePolicy struct {
	// DropProbability in [0, 1]. 0.1 means 10% of messages are dropped.
	DropProbability float64
	// MinDelay and MaxDelay bound the per-message delay. Each message gets
	// a uniformly-random delay in [MinDelay, MaxDelay].
	MinDelay time.Duration
	MaxDelay time.Duration
	// Partitioned: when true, the edge is severed; all messages are
	// dropped silently until set back to false.
	Partitioned bool
}

// Net is a virtual peer-to-peer network. Tests construct one Net per
// scenario, call Connect for each node, then Send/Recv to drive traffic.
//
// Internal state:
//   - inboxes: per-node delivered (post-delay) message queue
//   - inflight: per-node messages whose DeliverAt is still in the future
//   - policies: per-(from, to) policy; default is the zero EdgePolicy
type Net struct {
	mu       sync.Mutex
	clock    *Clock
	rng      *rand.Rand
	policies map[edge]*EdgePolicy
	defaults EdgePolicy
	inboxes  map[NodeID][]Message
	inflight map[NodeID][]Message // not yet deliverable; sorted by DeliverAt
	// inboxLimit is the max messages buffered per node. Sends that would
	// overflow return ErrDropped.
	inboxLimit int
}

type edge struct{ from, to NodeID }

// NewNet returns an empty network whose virtual time is driven by clock.
// Seed makes the random component (delay roll, drop roll) deterministic.
func NewNet(clock *Clock, seed int64) *Net {
	return &Net{
		clock:      clock,
		rng:        rand.New(rand.NewSource(seed)),
		policies:   map[edge]*EdgePolicy{},
		inboxes:    map[NodeID][]Message{},
		inflight:   map[NodeID][]Message{},
		inboxLimit: 1024,
	}
}

// Connect registers a node so it can receive messages. Idempotent.
func (n *Net) Connect(id NodeID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.inboxes[id]; !ok {
		n.inboxes[id] = nil
		n.inflight[id] = nil
	}
}

// Disconnect removes a node, dropping any pending messages. Useful for
// simulating a host crash mid-send.
func (n *Net) Disconnect(id NodeID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.inboxes, id)
	delete(n.inflight, id)
	// Also remove edges touching this node.
	for k := range n.policies {
		if k.from == id || k.to == id {
			delete(n.policies, k)
		}
	}
}

// SetEdge installs a policy for the (from→to) edge. Overwrites any
// existing policy. To remove, call ResetEdge.
func (n *Net) SetEdge(from, to NodeID, p EdgePolicy) {
	n.mu.Lock()
	defer n.mu.Unlock()
	cp := p
	n.policies[edge{from, to}] = &cp
}

// ResetEdge removes any per-edge policy; the edge falls back to defaults.
func (n *Net) ResetEdge(from, to NodeID) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.policies, edge{from, to})
}

// SetDefaults changes the policy applied to all unspecified edges.
func (n *Net) SetDefaults(p EdgePolicy) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.defaults = p
}

// Partition splits the connected nodes into the two given groups; all
// edges crossing the boundary are marked Partitioned=true. Edges within
// each group keep their existing policy (or default).
//
// Heal undoes a Partition. Pass the same two groups (order doesn't matter).
func (n *Net) Partition(a, b []NodeID) {
	n.setPartition(a, b, true)
}

// Heal lifts a Partition that previously cut a from b.
func (n *Net) Heal(a, b []NodeID) {
	n.setPartition(a, b, false)
}

func (n *Net) setPartition(a, b []NodeID, on bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, x := range a {
		for _, y := range b {
			if x == y {
				continue
			}
			n.ensurePolicy(x, y).Partitioned = on
			n.ensurePolicy(y, x).Partitioned = on
		}
	}
}

func (n *Net) ensurePolicy(from, to NodeID) *EdgePolicy {
	if p, ok := n.policies[edge{from, to}]; ok {
		return p
	}
	cp := n.defaults
	n.policies[edge{from, to}] = &cp
	return n.policies[edge{from, to}]
}

// Send transmits payload from→to. The message is buffered in flight; it
// only becomes deliverable after Tick advances time past DeliverAt.
//
// Returns ErrDropped if the edge is partitioned, the loss-roll fires, or
// the destination's inbox is full.
func (n *Net) Send(from, to NodeID, payload []byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.inboxes[to]; !ok {
		return fmt.Errorf("chaos: unknown destination %q", to)
	}
	p := n.policyOf(from, to)
	if p.Partitioned {
		return ErrDropped
	}
	if p.DropProbability > 0 && n.rng.Float64() < p.DropProbability {
		return ErrDropped
	}
	delay := p.MinDelay
	if p.MaxDelay > p.MinDelay {
		span := int64(p.MaxDelay - p.MinDelay)
		delay = p.MinDelay + time.Duration(n.rng.Int63n(span+1))
	}
	now := n.clock.Now()
	msg := Message{
		From: from, To: to, Payload: payload,
		SentAt: now, DeliverAt: now.Add(delay),
	}
	if len(n.inflight[to])+len(n.inboxes[to]) >= n.inboxLimit {
		return ErrDropped
	}
	// Insert keeping inflight sorted by DeliverAt.
	q := n.inflight[to]
	idx := sort.Search(len(q), func(i int) bool {
		return q[i].DeliverAt.After(msg.DeliverAt)
	})
	q = append(q, Message{})
	copy(q[idx+1:], q[idx:])
	q[idx] = msg
	n.inflight[to] = q
	return nil
}

func (n *Net) policyOf(from, to NodeID) EdgePolicy {
	if p, ok := n.policies[edge{from, to}]; ok {
		return *p
	}
	return n.defaults
}

// Tick promotes any in-flight messages whose DeliverAt has passed into
// the destination's inbox. Tests should call this after each Clock.Advance.
//
// Returns the number of messages promoted across all nodes.
func (n *Net) Tick() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.clock.Now()
	promoted := 0
	for to, q := range n.inflight {
		i := 0
		for ; i < len(q); i++ {
			if q[i].DeliverAt.After(now) {
				break
			}
		}
		if i == 0 {
			continue
		}
		n.inboxes[to] = append(n.inboxes[to], q[:i]...)
		n.inflight[to] = q[i:]
		promoted += i
	}
	return promoted
}

// Recv pops the oldest delivered message for id, or returns false if the
// inbox is empty. Tests typically call Tick first to promote due messages.
func (n *Net) Recv(id NodeID) (Message, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	q := n.inboxes[id]
	if len(q) == 0 {
		return Message{}, false
	}
	msg := q[0]
	n.inboxes[id] = q[1:]
	return msg, true
}

// Pending returns the number of messages still in flight (not yet
// promoted) plus any sitting in inbox. Useful for assertions like
// "drain everything: assert net.Pending() == 0".
func (n *Net) Pending() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	total := 0
	for _, q := range n.inflight {
		total += len(q)
	}
	for _, q := range n.inboxes {
		total += len(q)
	}
	return total
}

// Drain advances the clock until all in-flight messages are delivered.
// Returns the number of ticks needed (each tick moves past the next
// DeliverAt boundary). Useful at the end of scenarios to flush.
func (n *Net) Drain() int {
	steps := 0
	for {
		n.mu.Lock()
		var next time.Time
		found := false
		for _, q := range n.inflight {
			for _, m := range q {
				if !found || m.DeliverAt.Before(next) {
					next = m.DeliverAt
					found = true
				}
			}
		}
		n.mu.Unlock()
		if !found {
			return steps
		}
		gap := next.Sub(n.clock.Now())
		if gap <= 0 {
			gap = time.Nanosecond
		}
		n.clock.Advance(gap)
		n.Tick()
		steps++
	}
}
