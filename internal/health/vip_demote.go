package health

import (
	"context"
	"log/slog"
	"time"
)

// VIP self-demotion monitor (Phase 2).
//
// keepalived otherwise keeps answering a VIP on the ISOLATED side of a partition, so
// a worker that has lost quorum must stand its own VIPs down. This monitor watches
// QuorumProof on the local monotonic clock and, on a SUSTAINED loss, demotes local
// VIPs (stop keepalived + remove the address). Self-demotion runs WITHOUT a hardware
// watchdog — the minority stops answering its own VIP regardless. A watchdog is an
// OPTIONAL backstop for the one corner a software demote can't cover: if the demote
// can't be CONFIRMED (e.g. a hung keepalived that might still dual-answer) and a
// VERIFIED watchdog is armed, the node self-fences so the majority can safely reclaim.
// If demotion fails and there is NO verified self-fence, the node must NOT pretend to
// be down: it keeps retrying and raises HA-degraded, and the majority stays in the safe
// gap (it won't reclaim without a release/fence proof — a VIP outage, not a takeover).
// Warmup (Unknown) never demotes; a sub-threshold blip never demotes.
//
// Layering: this lives in internal/health (it needs QuorumProof) but the actual
// demote + self-fence are INJECTED by the daemon (which owns the LB manager + the
// watchdog), so health imports neither internal/lb nor internal/grpcapi.

// demoterGate is the slice of *Checker the VIP monitor needs (injectable for tests).
type demoterGate interface {
	QuorumProof(ctx context.Context) (QuorumState, int, int)
}

// VIPDemoter drives isolated-side VIP self-demotion. All collaborators are injected.
type VIPDemoter struct {
	gate demoterGate

	// demoteLocalVIPs stops keepalived + removes the address for every VIP this host
	// currently holds. Returns (held, err): held=false when this host runs no VIPs
	// (nothing to do, never self-fence); err != nil when a demotion couldn't be
	// confirmed (→ self-fence). Injected by the daemon.
	demoteLocalVIPs func(ctx context.Context) (held bool, err error)
	// selfFence trips the hardware watchdog so this host reboots — the fail-closed
	// response to an unconfirmable demotion on a node that HAS a verified watchdog.
	// Only invoked when armed() reports true. Injected (nil-safe).
	selfFence func()
	// armed reports whether this node has a VERIFIED hardware watchdog (armed + timer
	// confirmed counting). It is the ONLY thing the watchdog now gates: self-demotion
	// itself runs without one. When armed() is true an unconfirmable demotion self-fences;
	// when false (or nil) the node stays up, keeps retrying, and raises HA-degraded so the
	// majority holds in the safe gap. Injected (nil → treated as no watchdog).
	armed func() bool
	// enabled reports whether Phase-2 self-demotion is active on THIS node: vip_demote_v1
	// is ENFORCED cluster-wide (the durable Enforced() latch, not merely built locally).
	// NO hardware watchdog is required — a minority node stands its own VIP down
	// regardless; the watchdog only governs whether a demotion FAILURE can self-fence
	// (see armed). Takes a ctx because the latch check may fresh-Ping peers. nil → inert.
	enabled func(context.Context) bool
	// onRefused observes gate/demote outcomes for the metric (nil-safe).
	onRefused func(action, reason string)
	// onDemotionUnfenced surfaces the "demotion failed and this node has no verified
	// self-fence" state as a persistent, alertable HA-degraded condition: true when a
	// demote can't be confirmed and no watchdog can self-fence (the majority stays in the
	// safe gap → VIP outage until repaired), cleared (false) once a demote succeeds or
	// quorum returns. Injected by the daemon; nil-safe.
	onDemotionUnfenced func(bool)
	// onQuorumRestored re-applies this host's LBs after quorum returns FOLLOWING a
	// self-demotion — DemoteAll stopped keepalived + removed the VIP, and nothing else
	// brings it back on heal. Injected by the daemon (nil-safe).
	onQuorumRestored func(context.Context)

	demoteAfter time.Duration
	tick        time.Duration
	now         func() time.Time

	// monotonic state (reset on restart — a restart must re-earn its timing).
	quorumLostAt time.Time // zero while quorum held / Unknown
	demoted      bool      // latched after a successful demote until quorum returns
}

// NewVIPDemoter builds the monitor. demoteAfter is quorum_loss_demote_after. The
// gate is the health.Checker (or a fake in tests).
func NewVIPDemoter(gate demoterGate, demoteAfter time.Duration) *VIPDemoter {
	return &VIPDemoter{
		gate:        gate,
		demoteAfter: demoteAfter,
		tick:        2 * time.Second,
		now:         time.Now,
	}
}

// SetDemoteLocalVIPs injects the local-VIP demote action (from the daemon).
func (d *VIPDemoter) SetDemoteLocalVIPs(fn func(ctx context.Context) (bool, error)) {
	d.demoteLocalVIPs = fn
}

// SetSelfFence injects the watchdog self-fence trigger (nil-safe). Only fired when
// SetArmed's predicate reports a verified watchdog.
func (d *VIPDemoter) SetSelfFence(fn func()) { d.selfFence = fn }

// SetArmed injects the verified-watchdog predicate. When it reports true a demotion
// failure self-fences; when false (or unset) the node stays up + raises HA-degraded.
func (d *VIPDemoter) SetArmed(fn func() bool) { d.armed = fn }

// SetEnabled injects the activation predicate (vip_demote_v1 ENFORCED cluster-wide — NO
// watchdog required). Takes a ctx so it can consult the cluster-wide latch. Without it
// the monitor is inert.
func (d *VIPDemoter) SetEnabled(fn func(context.Context) bool) { d.enabled = fn }

// SetRefusedObserver wires the metric hook (nil-safe).
func (d *VIPDemoter) SetRefusedObserver(fn func(action, reason string)) { d.onRefused = fn }

// SetDemotionUnfencedObserver wires the persistent HA-degraded surface for an unfenced
// demotion failure (nil-safe).
func (d *VIPDemoter) SetDemotionUnfencedObserver(fn func(bool)) { d.onDemotionUnfenced = fn }

func (d *VIPDemoter) setDemotionUnfenced(on bool) {
	if d.onDemotionUnfenced != nil {
		d.onDemotionUnfenced(on)
	}
}

// SetOnQuorumRestored injects the post-heal LB re-apply (recovers a VIP dropped by a
// prior self-demotion once quorum returns). Nil-safe.
func (d *VIPDemoter) SetOnQuorumRestored(fn func(context.Context)) { d.onQuorumRestored = fn }

func (d *VIPDemoter) noteRefused(reason string) {
	if d.onRefused != nil {
		d.onRefused(corrosionActionVIPDemote, reason)
	}
}

// corrosionActionVIPDemote is the metric action label for VIP self-demotion. Kept
// local (a plain string) so health needn't import corrosion just for a constant.
const corrosionActionVIPDemote = "vip_demote"

// Start runs the monitor loop until ctx is cancelled.
func (d *VIPDemoter) Start(ctx context.Context) {
	t := time.NewTicker(d.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.evaluate(ctx)
		}
	}
}

// evaluate is one monitor pass (exported-ish for tests via the same package).
func (d *VIPDemoter) evaluate(ctx context.Context) {
	// Inert unless vip_demote_v1 is ENFORCED cluster-wide (built + flipped + latched). A
	// hardware watchdog is NOT required — self-demotion runs without one; the watchdog
	// only decides whether a demotion FAILURE self-fences (see the err path below). Ships
	// dark (token de-advertised) so it's validated on an ephemeral partition first.
	if d.gate == nil || d.enabled == nil || !d.enabled(ctx) {
		return
	}

	state, _, _ := d.gate.QuorumProof(ctx)
	switch state {
	case QuorumUnknown:
		// Warmup / no confirmed loss: never demote (a restart mustn't drop a healthy VIP).
		// Unknown is "neither proof nor loss" (see Checker.QuorumProof) → CLEAR the loss
		// clock, so demotion requires a full quorum_loss_demote_after of CONTIGUOUS confirmed
		// No. Keeping the clock through an Unknown blip would let a No→Unknown→No sequence
		// demote after less than the threshold of real loss — an avoidable VIP outage. (We do
		// NOT clear `demoted`: recovery happens only on a positive QuorumYes.)
		d.quorumLostAt = time.Time{}
		return
	case QuorumYes:
		// Quorum (re)gained. If we had self-demoted, DemoteAll stopped keepalived and
		// removed the VIP — nothing brings it back on its own (the LB reconcile is
		// startup/event-driven, not heal-driven), so a demoted VIP would stay down
		// forever. Trigger a local LB re-apply to recover, THEN clear the loss latch.
		if d.demoted && d.onQuorumRestored != nil {
			d.onQuorumRestored(ctx)
		}
		d.quorumLostAt = time.Time{}
		d.demoted = false
		d.setDemotionUnfenced(false) // quorum back → any prior unfenced-failure clears
		return
	}

	// QuorumNo — track the loss on the local monotonic clock (hysteresis).
	if d.quorumLostAt.IsZero() {
		d.quorumLostAt = d.now()
		return // just started losing — wait out the debounce
	}
	if d.now().Sub(d.quorumLostAt) < d.demoteAfter {
		return // sub-threshold blip — no action
	}
	if d.demoted {
		return // already demoted this loss episode
	}

	// Sustained quorum loss → demote local VIPs.
	if d.demoteLocalVIPs == nil {
		return
	}
	held, err := d.demoteLocalVIPs(ctx)
	if err != nil {
		// Demotion couldn't be confirmed (e.g. keepalived stuck): the VIP may still be
		// assigned and we can't prove otherwise.
		d.noteRefused(ReasonDemotionFailed)
		if d.armed != nil && d.armed() {
			// A VERIFIED self-fence is available — trip it so this host goes down and
			// the majority can safely reclaim the VIP.
			slog.Error("VIP self-demote FAILED under quorum loss — self-fencing (verified watchdog) so the majority can safely reclaim",
				"error", err)
			if d.selfFence != nil {
				d.selfFence()
			}
			return
		}
		// No verified self-fence on this node. We must NOT pretend to be down: the
		// majority stays in the safe gap (it won't reclaim without a release/fence proof
		// — a VIP outage, not a takeover). Keep retrying the local demote each tick
		// (demoted stays false) and raise a persistent HA-degraded surface so an operator
		// can intervene / provide a fence for automatic recovery.
		slog.Error("VIP self-demote FAILED under quorum loss and no verified self-fence available — retrying; the majority will NOT reclaim without proof (VIP stays down until this heals). Provide a fence (watchdog / IPMI STONITH) for automatic recovery.",
			"error", err)
		d.setDemotionUnfenced(true)
		return
	}
	// err == nil: demote succeeded (or this host held nothing) → clear any prior
	// unfenced-failure surface.
	d.setDemotionUnfenced(false)
	if held {
		d.demoted = true
		slog.Warn("VIP self-demote complete under sustained quorum loss")
		d.noteRefused(ReasonNoQuorum) // observed as a demotion event (reason=no_quorum)
	}
}
