package hlc

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

// Timestamp is a Hybrid Logical Clock timestamp consisting of physical
// milliseconds, a logical counter, and a node identifier. It serializes
// as "1710633600000-0003-node1" which is lexicographically sortable.
type Timestamp struct {
	PhysicalMS int64
	Logical    uint16
	NodeID     string
}

// String returns the canonical wire format: "<physical_ms>-<logical_04d>-<node_id>".
func (t Timestamp) String() string {
	return fmt.Sprintf("%013d-%04d-%s", t.PhysicalMS, t.Logical, t.NodeID)
}

// After reports whether t is strictly after other.
func (t Timestamp) After(other Timestamp) bool {
	if t.PhysicalMS != other.PhysicalMS {
		return t.PhysicalMS > other.PhysicalMS
	}
	if t.Logical != other.Logical {
		return t.Logical > other.Logical
	}
	return t.NodeID > other.NodeID
}

// IsZero reports whether the timestamp is the zero value.
func (t Timestamp) IsZero() bool {
	return t.PhysicalMS == 0 && t.Logical == 0 && t.NodeID == ""
}

// Parse parses a serialized HLC timestamp. Returns the zero Timestamp
// and false if the string is not valid HLC format.
func Parse(s string) (Timestamp, bool) {
	// Format: "0000000000000-0000-nodeid"
	// Physical is exactly 13 digits, logical is exactly 4 digits.
	if len(s) < 20 { // 13 + 1 + 4 + 1 + 1 minimum
		return Timestamp{}, false
	}
	if s[13] != '-' || s[18] != '-' {
		return Timestamp{}, false
	}
	phys, err := strconv.ParseInt(s[:13], 10, 64)
	if err != nil {
		return Timestamp{}, false
	}
	logical, err := strconv.ParseUint(s[14:18], 10, 16)
	if err != nil {
		return Timestamp{}, false
	}
	nodeID := s[19:]
	if nodeID == "" {
		return Timestamp{}, false
	}
	return Timestamp{
		PhysicalMS: phys,
		Logical:    uint16(logical),
		NodeID:     nodeID,
	}, true
}

// MaxSkew is the maximum forward skew, in milliseconds, that Clock.Update will
// accept from a remote timestamp. Beyond this, the remote is treated as
// clock-corrupted and its physical time is *not* adopted. The local clock
// still advances its logical counter so the returned timestamp orders after
// the local view, but cluster-wide HLC ordering is preserved.
//
// 5 minutes is the typical NTP-outlier tolerance; ops should fix the skew or
// fence the misconfigured peer well before this triggers.
const MaxSkewMS int64 = 5 * 60 * 1000

// Clock is a Hybrid Logical Clock bound to a specific node.
// It is safe for concurrent use.
type Clock struct {
	mu       sync.Mutex
	nodeID   string
	lastPhys int64
	lastLog  uint16
	nowFn    func() time.Time // injectable for testing
	rejected uint64           // count of timestamps rejected for skew

	// ceilMS is the last durably-persisted physical-ms ceiling; persist commits a
	// new one ahead of lastPhys so a restart-after-clock-rollback can't regress the
	// physical high-water (the HLC side of the backward-clock fix). nil persist ⇒
	// in-memory only (default; unchanged behavior). persistFatal is invoked when the
	// ceiling can't be durably advanced (see persistAheadLocked) — production exits.
	ceilMS       int64
	persist      func(ms int64) error
	persistFatal func()
}

const (
	// hlcPersistAheadMS is how far ahead of the current physical the durable ceiling
	// is committed, so persistence happens ~once per this interval, not per timestamp.
	hlcPersistAheadMS int64 = 2000
	// hlcPersistRetries bounds the in-line retry before failing closed.
	hlcPersistRetries = 3
	// hlcMaxLogical is the largest logical value the fixed-width %04d String()/Parse
	// format can represent. Beyond it a value is unparsable AND sorts wrong, so the
	// counter spills into physical (see normalizeLogicalLocked).
	hlcMaxLogical uint16 = 9999
)

// SetPersistence wires durable persistence of the physical high-water. floorMS raises
// the clock so it never emits below a previously-persisted physical ms (call at load).
// persist commits a ceiling AHEAD of the current physical; if it keeps failing, fatal
// is called (production exits) rather than emit a value beyond the durable ceiling
// (which would regress on restart) or a clamped duplicate. Nil persist ⇒ in-memory only.
func (c *Clock) SetPersistence(floorMS int64, persist func(ms int64) error, fatal func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if floorMS > c.lastPhys {
		c.lastPhys = floorMS
		c.lastLog = 0
	}
	c.ceilMS = floorMS
	c.persist = persist
	c.persistFatal = fatal
}

// PhysicalMS returns the clock's current physical high-water in epoch-ms. Used to
// bridge the RFC3339 emission path so it never emits below the HLC physical (a safe
// hlc_lww rollback — see corrosion.Client.NowTS).
func (c *Clock) PhysicalMS() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPhys
}

// normalizeLogicalLocked spills a logical counter that overflowed the 4-digit format
// into the physical ms, keeping every emitted value parsable and strictly ordered.
func (c *Clock) normalizeLogicalLocked() {
	for c.lastLog > hlcMaxLogical {
		c.lastPhys++
		c.lastLog -= (hlcMaxLogical + 1)
	}
}

// afterAdvanceLocked runs after every Now/Update mutation: normalize a logical overflow
// (so the value stays parsable + ordered) BEFORE committing the physical ceiling.
func (c *Clock) afterAdvanceLocked() {
	c.normalizeLogicalLocked()
	c.persistAheadLocked()
}

// persistAheadLocked commits a physical ceiling ahead of lastPhys once it advances past
// the last committed one. On a persist error it FAILS CLOSED: it retries, then calls
// persistFatal (production exits) rather than return a value beyond the durable ceiling
// (a crash would then regress) or a clamped duplicate. Called with c.mu held.
func (c *Clock) persistAheadLocked() {
	if c.persist == nil || c.lastPhys <= c.ceilMS {
		return
	}
	newCeil := c.lastPhys + hlcPersistAheadMS
	for i := 0; i < hlcPersistRetries; i++ {
		if err := c.persist(newCeil); err == nil {
			c.ceilMS = newCeil
			return
		}
	}
	// Fail closed: the ceiling can't be durably advanced.
	if c.persistFatal != nil {
		c.persistFatal()
	}
	// Only reached in tests (production persistFatal exits): clamp to the durable
	// ceiling so a returned value isn't beyond what's persisted.
	if c.lastPhys > c.ceilMS {
		c.lastPhys = c.ceilMS
	}
}

// Rejected returns the cumulative count of remote timestamps rejected for
// exceeding MaxSkewMS. Exposed so the metrics layer can publish it.
func (c *Clock) Rejected() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rejected
}

// NewClock creates an HLC bound to the given node ID.
func NewClock(nodeID string) *Clock {
	return &Clock{
		nodeID: nodeID,
		nowFn:  time.Now,
	}
}

// Now generates a new timestamp guaranteed to be greater than any
// previously returned by this clock.
func (c *Clock) Now() Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()

	phys := c.nowFn().UnixMilli()
	if phys > c.lastPhys {
		c.lastPhys = phys
		c.lastLog = 0
	} else {
		c.lastLog++
	}

	c.afterAdvanceLocked()
	return Timestamp{
		PhysicalMS: c.lastPhys,
		Logical:    c.lastLog,
		NodeID:     c.nodeID,
	}
}

// Update advances the clock given a remote timestamp. The returned
// timestamp is guaranteed to be after both the local clock and remote.
//
// If the remote timestamp is more than MaxSkewMS ahead of the local wall
// clock, the remote physical time is *not* adopted (preventing one
// misconfigured peer from corrupting the entire cluster's HLC). The local
// clock still advances its logical counter so the returned value still
// orders after our last-observed state. The caller can detect this via
// Rejected().
func (c *Clock) Update(remote Timestamp) Timestamp {
	c.mu.Lock()
	defer c.mu.Unlock()

	phys := c.nowFn().UnixMilli()

	// Reject remotes that are too far in the future. We never reject
	// remotes in the past — they're already covered by the "we're ahead"
	// branch and may simply be stale anti-entropy data.
	if remote.PhysicalMS-phys > MaxSkewMS {
		c.rejected++
		// Treat as if we never saw the remote, but still advance locally.
		if phys > c.lastPhys {
			c.lastPhys = phys
			c.lastLog = 0
		} else {
			c.lastLog++
		}
		c.afterAdvanceLocked()
		return Timestamp{
			PhysicalMS: c.lastPhys,
			Logical:    c.lastLog,
			NodeID:     c.nodeID,
		}
	}

	if phys > c.lastPhys && phys > remote.PhysicalMS {
		// Wall clock is ahead of both — use it.
		c.lastPhys = phys
		c.lastLog = 0
	} else if remote.PhysicalMS > c.lastPhys {
		// Remote is ahead — adopt remote physical, bump logical.
		c.lastPhys = remote.PhysicalMS
		c.lastLog = remote.Logical + 1
	} else if c.lastPhys > remote.PhysicalMS {
		// We're ahead — just bump our logical.
		c.lastLog++
	} else {
		// Same physical — take max logical + 1.
		if remote.Logical > c.lastLog {
			c.lastLog = remote.Logical + 1
		} else {
			c.lastLog++
		}
	}

	c.afterAdvanceLocked()
	return Timestamp{
		PhysicalMS: c.lastPhys,
		Logical:    c.lastLog,
		NodeID:     c.nodeID,
	}
}

// NodeID returns the node identifier for this clock.
func (c *Clock) NodeID() string {
	return c.nodeID
}

// IsHLC reports whether s looks like an HLC timestamp (starts with digits
// and contains the expected format). Old RFC3339 timestamps will return false.
func IsHLC(s string) bool {
	_, ok := Parse(s)
	return ok
}
