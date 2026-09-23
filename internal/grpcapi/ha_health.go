package grpcapi

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/notify"
)

// HA-degraded reasons (closed vocabulary for litevirt_ha_degraded{reason}).
const (
	haUnsupportedMember = "unsupported_member"         // a flipped capability can't be confirmed cluster-wide
	haRolloutPending    = "capability_rollout_pending" // a MANDATORY token has not latched yet — mid-upgrade, not a fault
	haDemotionUnfenced  = "demotion_unfenced"          // a minority node's VIP demote FAILED and it has no verified self-fence — the majority holds in the safe gap (VIP outage until repaired / a fence is provided)
	haVIPNoHolder       = "vip_no_holder"              // a configured VIP is served by nobody
	haStrandedPending   = "legacy_pending_stranded"    // a markerless pending VM refused proof_missing forever
	haRolledBackLatch   = "rolled_back_latch"          // this binary is below a capability token this node already latched — WAL-quarantined, needs an operator reseed
)

var haReasons = []string{haUnsupportedMember, haRolloutPending, haDemotionUnfenced, haVIPNoHolder, haStrandedPending, haRolledBackLatch}

// capabilityDegradedReason maps a configured-to-enforce token's latch state (ok = latched)
// to an HA-degraded reason, or "" if it's fine. vip_demote_v1 is a software capability (no
// watchdog gate), so a reachable member that doesn't advertise it is simply on an older
// binary mid-roll — an unsupported member that holds back enforcement. (The dangerous
// "demoted but can't self-fence" state is a per-node RUNTIME condition surfaced separately
// via haDemotionUnfenced, not a capability-advertisement gap.)
//
// Every cause maps to the same reason, deliberately, and ha_health_test.go pins
// it from both sides. litevirt_ha_degraded's reason vocabulary is CLOSED and
// alerting subscribes to it, so splitting "a peer does not advertise it" from
// "the sweep could not tell" HERE would add a series to a contract other systems
// read. That distinction is real and an operator needs it, so it is carried in
// the event detail instead — see degradedCause — where nothing depends on the
// exact strings. `reason` therefore stays in the signature unread: it is what
// makes the collapse visible at the call site rather than implicit.
func capabilityDegradedReason(token string, ok bool, reason string) string {
	if ok {
		return ""
	}
	return haUnsupportedMember
}

// degradedSetGrew reports whether an ALREADY-degraded unsupported_member should
// be published again because a NEW token joined the ones behind it.
//
// Every configured token collapses into that one reason, so its on/off edge is
// not its full identity: with operation_protocol_v1 already degraded, a second
// token going degraded moves nothing an operator can see. The gauge is 1 either
// way and no event fires, so the second incident arrives silently during the
// first — which is when someone is already looking at the wrong thing.
//
// It is deliberately scoped to unsupported_member. The other reasons are each a
// single condition, so their on/off edge IS their identity and republishing them
// would be noise.
//
// A token that flaps still republishes each time it comes BACK, which is one
// event per two cycles at worst and is bounded by the monitor interval.
// pageHADegraded does not route this reason, so that cost is an event-bus and
// webhook line, never a notification page.
func degradedSetGrew(reason string, on, was bool, cur, prev []degradedCapability) bool {
	if reason != haUnsupportedMember || !on || !was {
		return false
	}
	// ADDITIONS only, and not any change. A shrinking set is what ordinary
	// progress looks like: a fresh node with a dozen configured tokens starts
	// with all of them pending and latches ONE PER CYCLE, so republishing on
	// every change would emit a dozen events walking down a staircase during
	// every startup. Recovery of one token while others remain is not news worth
	// an event — the reason is still on, and the next event or the recovery edge
	// will carry the current set. A token APPEARING is news: it is a second
	// incident starting underneath the first, and it is the case that was
	// invisible before.
	for _, c := range cur {
		if !slices.ContainsFunc(prev, func(p degradedCapability) bool { return p.Token == c.Token }) {
			return true
		}
	}
	return false
}

// haDegradedDetail names the capabilities behind unsupported_member.
//
// The reason string is a closed vocabulary shared by every configured token, so
// on its own it tells an operator that something is unconfirmed cluster-wide and
// nothing about what to do. The remedy differs completely by token — finish a
// rollout, re-enable a flag, reseed a rolled-back peer — so the token names are
// the actionable part and belong in the event that wakes someone up.
// The host is named because `publish` does not carry it: it fills only Event and
// Detail on the webhook payload, dropping even the reason, unlike the sibling
// pageHADegraded which sets Subject. A token name with no node is not actionable
// on a fleet — "lww_skew_guard_v1 is unconfirmed" is a different investigation
// depending on which of twenty nodes said it.
//
// The reason guard is load-bearing, not defensive tidiness: the call site hands
// the live list to EVERY reason, so without it a vip_no_holder event — one of
// the two reasons that also raises a notify page at SevError — would blame a VIP
// outage on unrelated capability tokens.
func haDegradedDetail(reason, host string, unsupported []degradedCapability) string {
	base := "HA degraded: " + reason
	if host != "" {
		base += " on " + host
	}
	if reason != haUnsupportedMember || len(unsupported) == 0 {
		return base
	}
	parts := make([]string, 0, len(unsupported))
	for _, c := range unsupported {
		parts = append(parts, c.Token+": "+c.Cause)
	}
	return base + " (" + strings.Join(parts, ", ") + ")"
}

// RunHAHealthMonitor periodically evaluates the persistent HA-degraded conditions,
// updates the litevirt_ha_degraded gauge, and emits an event on each set→clear /
// clear→set transition — plus, for unsupported_member only, when a NEW capability
// joins the ones already degraded (see degradedSetGrew), since that reason is one
// boolean shared by every token. A durable, alertable surface, not just a
// per-refusal counter. Quiet by
// default: a token contributes only when this node is configured to enforce it
// (tokenEnabled) — advertising a token (Supported()) does not by itself raise degraded —
// and the VIP axis only when vip_self_demote / vip_proof_reclaim is enabled.
// HA notification Kinds (stable — notification routes subscribe to these; see
// docs/notifications.md). Keep these strings stable across releases.
const (
	kindVIPNoHolder         = "ha.vip.no_holder"
	kindVIPDemotionUnfenced = "ha.vip.demotion_unfenced"
)

// pageHADegraded routes the alertable VIP HA-degraded reasons to notify (a durable
// page, not just the event bus + gauge). Other reasons stay gauge+event only.
func (s *Server) pageHADegraded(ctx context.Context, reason string) {
	var kind string
	switch reason {
	case haVIPNoHolder:
		kind = kindVIPNoHolder
	case haDemotionUnfenced:
		kind = kindVIPDemotionUnfenced
	default:
		return
	}
	s.notify(ctx, notify.Notification{
		Kind:     kind,
		Severity: notify.SevError,
		Subject:  s.hostName,
		Detail:   "HA degraded (" + reason + "): a VIP is unheld or a minority demote is unconfirmed — operator action may be required.",
	})
}

func (s *Server) RunHAHealthMonitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	prev := map[string]bool{}
	// The token list behind unsupported_member, from the last cycle. Tracked
	// separately from `prev` because the reason is a single boolean shared by
	// every capability: without this, a second token going degraded while the
	// first still is changes nothing an operator can observe — the gauge is
	// already 1 and no event fires. The set changing IS the news.
	var prevUnsupported []degradedCapability
	eval := func() {
		// One peer op per cycle, split between the two axes so neither starves the
		// other: mostly spent latching an unlatched token (round-robin, so one
		// that cannot confirm does not absorb every cycle), with a reserved share
		// spent on the round-robin FRESHNESS check so a post-latch regression (a
		// peer that rolled back / stopped advertising) still surfaces — the
		// durable latch alone never flips back.
		//
		// This supersedes spendOnePeerOp's strict alternation, which solved the
		// same starvation problem from the other direction. Two differences
		// decided it: retryLatchedMarkers runs EVERY cycle here (alternation
		// skipped marker-persistence retries on the check's turn), and the
		// reserve is 1-in-4 rather than 1-in-2, so a pending activation is not
		// halved. spendOnePeerOp is left in place because a test still drives it
		// directly; retiring it belongs with whichever of these lands second.
		s.spendCapabilityPeerOp(ctx)
		// §A: act on a peer's SELF-REPORTED quarantine by recording its
		// isolation. One peer per cycle, so this adds no fan-out.
		s.recordSelfReportedIsolation(ctx)
		cur, unsupported := s.evaluateHADegraded(ctx)
		// Rollout observability: per-feature config intent, latch state, and
		// whether the feature is degraded. Written AFTER the evaluation because
		// the degraded set comes from it, and for EVERY supported token rather
		// than only the configured ones — a token that was degraded and is then
		// switched off must fall to 0 rather than keep its last value forever.
		if s.gate != nil {
			degraded := make(map[string]bool, len(unsupported))
			for _, c := range unsupported {
				degraded[c.Token] = true
			}
			for _, tok := range capabilities.Supported() {
				s.haMetrics.SetEnforcement(tok, s.tokenEnabled(tok), s.gate.Latched(tok))
				s.haMetrics.SetDegraded(tok, degraded[tok])
			}
		}
		for _, r := range haReasons {
			on := cur[r]
			s.haMetrics.Set(r, on)
			switch {
			case on && !prev[r], degradedSetGrew(r, on, prev[r], unsupported, prevUnsupported):
				s.publish("ha.degraded", r, haDegradedDetail(r, s.hostName, unsupported))
				s.pageHADegraded(ctx, r) // route the alertable VIP reasons to notify
			case !on && prev[r]:
				s.publish("ha.recovered", r, "")
			}
		}
		prev = cur
		prevUnsupported = unsupported
	}
	eval()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			eval()
		}
	}
}

// spendOnePeerOp spends this cycle's single peer operation on one of the two
// duties that need one, and returns whether the NEXT cycle is the freshness
// check's turn.
//
// The two duties are not interchangeable. Driving activation closes a latch that
// is pending; the freshness check finds a token that latched and has since
// REGRESSED, which the one-way durable marker can never show. Giving activation
// unconditional priority — `if !drive() { check() }` — silently makes the second
// unreachable, because driveCapabilityActivation reports that it SPENT the
// budget, not that it succeeded. A capability enabled against a peer that will
// not support it for hours is not an error state and not a bug; it simply never
// latches, and for that whole window no freshness check runs, so a regression on
// any OTHER token is undetectable. That is the failure this alternation removes:
// the check whose entire purpose is catching what the latch cannot is switched
// off by an ordinary mid-rollout condition.
//
// Alternating costs activation half its attempts while a token is pending — a
// retry every other cycle instead of every cycle — which is the cheaper side of
// the trade by a wide margin. When nothing is pending, activation spends nothing
// and the freshness check gets every cycle, exactly as before.
func (s *Server) spendOnePeerOp(ctx context.Context, freshnessTurn bool) bool {
	if freshnessTurn {
		s.checkOneCapabilityHealth(ctx)
		return false
	}
	if s.driveCapabilityActivation(ctx) {
		return true // activation took this cycle; the next one is the check's
	}
	// Nothing to drive, so the budget is free for the check and stays free.
	s.checkOneCapabilityHealth(ctx)
	return false
}

// driveCapabilityActivation flips the durable enforcement latch for every SUPPORTED
// token by calling Enforced — the ONLY path that latches (CapabilityActive/…ForHealth
// only compute). Most tokens are latched by their consumers calling Enforced at a
// decision point (the coordinator for split_brain_gate_v1 / safe_fence_default_v1, the
// VIP paths for the vip_* tokens). A token whose sole consumer reads the cheap Latched()
// on a hot path — lww_skew_guard_v1's per-merge skew guard — has NO such caller, so without
// this periodic drive its latch would never flip even after it is added to `supported`,
// and the guard would stay off forever. This runs at the HA-monitor cadence (off the hot
// path) and is idempotent for already-latched tokens (cheap `already` path in Enforced).
func (s *Server) driveCapabilityActivation(ctx context.Context) bool {
	if s.gate == nil {
		return false
	}
	// Drive the latch for the tokens this node is configured to enforce (mandatory
	// split_brain_gate_v1 ∪ config-on optional tokens) — establishing the durable
	// marker WHILE HEALTHY, so a token whose only decision-site caller is rare/
	// incident-time (safe_fence, only during a failover) is already latched before a
	// partition, not first attempted mid-partition when CapabilityActive fails closed.
	// A config-off token is deliberately NOT driven (advertised ≠ latched ≠
	// enforcing). Bound the cost: an unlatched token pays a fresh-Ping sweep, so drive
	// at most ONE unlatched token per cycle (already-latched Enforced() is a cheap
	// map read); the rest latch over subsequent cycles.
	s.retryLatchedMarkers(ctx)
	return s.activateOneUnlatched(ctx)
}

// retryLatchedMarkers re-drives every ALREADY-latched token. This costs no peer
// op — Enforced's already-path is a map read — so it is unconditional and runs
// on every cycle, including the ones reserved for the freshness check.
//
// A latched token is driven regardless of its config flag: the already-path
// RETRIES a marker write that hasn't yet persisted, and that retry must not stop
// just because the operator disabled the flag after the token latched.
// Otherwise a token latched in memory but not on disk would never become
// DurablyLatched, and a durable-gated contract (canonical registry acceptance,
// the lease-term mint) would fail closed forever.
func (s *Server) retryLatchedMarkers(ctx context.Context) {
	for _, tok := range capabilities.Supported() {
		if s.gate.Latched(tok) {
			s.gate.Enforced(ctx, tok)
		}
	}
}

// activateOneUnlatched spends this cycle's ONE peer op driving a single
// unlatched, config-enabled token's latch, and reports whether it spent it.
//
// An unlatched token pays a fresh-Ping sweep, which is why only one is driven
// per cycle. The starting point ROTATES, and that is the load-bearing part: the
// drive used to restart at index 0 every cycle and take the first unlatched
// enabled token it found, so a token that cannot currently latch absorbed every
// cycle forever and no token after it in Supported() was ever driven. The
// blocking token needs no fault to do this — a config-uniformity flag switched
// on here but not yet on one peer is enough, which is the ordinary state during
// any staged config rollout. Everything later then sat inert with nothing in the
// logs, including the tokens whose latch is the precondition for a durable-gated
// write.
//
// UNLATCHED activation still depends on the config flag: advertised ≠ enforcing,
// so a config-off token is not driven and never latches.
func (s *Server) activateOneUnlatched(ctx context.Context) bool {
	toks := capabilities.Supported()
	if len(toks) == 0 {
		return false
	}

	s.capHealthMu.Lock()
	start := s.capDriveCursor % len(toks)
	s.capHealthMu.Unlock()

	for i := 0; i < len(toks); i++ {
		idx := (start + i) % len(toks)
		tok := toks[idx]
		if s.gate.Latched(tok) || !s.tokenEnabled(tok) {
			continue
		}
		// Resume AFTER this token next cycle, so one that never confirms is
		// retried once per rotation instead of on every cycle.
		s.capHealthMu.Lock()
		s.capDriveCursor = (idx + 1) % len(toks)
		s.capHealthMu.Unlock()

		s.gate.Enforced(ctx, tok) // one CapabilityActive fresh-Ping sweep this cycle
		return true
	}
	return false
}

// capFreshnessReserveEvery is how often the HA monitor spends its cycle on the
// freshness axis even though activation is still incomplete.
//
// checkOneCapabilityHealth used to run ONLY when activation had nothing to
// drive, on the reasoning that a cycle spends at most one peer op. That held
// only while every flag-less token could latch on a homogeneous fleet. A
// mandatory token that cannot latch until the last host is upgraded makes the
// drive claim every cycle for the whole roll — and permanently on a cluster
// deliberately held with one host back — so the only post-latch regression
// detector never ran, capHealthLast stayed empty, and evaluateHADegraded's
// `latched && (!checked || lastOK)` quietly degenerated to `latched`.
//
// One cycle in four keeps the one-peer-op-per-cycle bound and still re-checks
// every configured token within a bounded number of cycles.
const capFreshnessReserveEvery = 4

// spendCapabilityPeerOp spends this cycle's single capability peer op, splitting
// it between driving activation and re-checking freshness so neither axis can
// starve the other.
func (s *Server) spendCapabilityPeerOp(ctx context.Context) {
	if s.gate == nil {
		return
	}
	s.retryLatchedMarkers(ctx)

	s.capHealthMu.Lock()
	s.capPeerOpCycle++
	reserved := s.capPeerOpCycle%capFreshnessReserveEvery == 0
	s.capHealthMu.Unlock()

	if reserved {
		s.checkOneCapabilityHealth(ctx)
		return
	}
	if !s.activateOneUnlatched(ctx) {
		s.checkOneCapabilityHealth(ctx)
	}
}

// checkOneCapabilityHealth does ONE bounded freshness check per cycle: it round-robins
// over the configured-on tokens and re-queries CapabilityActiveForHealth for the next
// one, recording the result in capHealthLast. This is how a POST-latch regression is
// detected (a latched token whose peer support later disappears) without the multi-token
// fan-out — each token is re-checked every ~N cycles. Called only when
// driveCapabilityActivation had no unlatched token to drive, so the cycle spends at most
// one peer op total.
func (s *Server) checkOneCapabilityHealth(ctx context.Context) {
	if s.gate == nil {
		return
	}
	var toks []string
	for _, tok := range capabilities.Supported() {
		if s.tokenEnabled(tok) {
			toks = append(toks, tok)
		}
	}
	if len(toks) == 0 {
		return
	}
	s.capHealthMu.Lock()
	if s.capHealthLast == nil {
		s.capHealthLast = map[string]bool{}
	}
	tok := toks[s.capHealthCursor%len(toks)]
	s.capHealthCursor++
	s.capHealthMu.Unlock()

	// The reason is kept, not discarded. It comes from an existing closed
	// vocabulary and separates the two answers an operator must not confuse:
	// health/capability.go returns ReasonUnsupportedCapability at exactly one
	// site (a peer genuinely not advertising the token) and
	// ReasonActivationUnconfirm at three (a hosts-table read failing, any
	// voting-eligible peer's Ping erroring). Collapsing them means one host
	// rebooting is reported as a capability a peer does not support.
	ok, why := s.gate.CapabilityActiveForHealth(ctx, tok)
	s.capHealthMu.Lock()
	if s.capHealthCause == nil {
		s.capHealthCause = map[string]string{}
	}
	s.capHealthLast[tok] = ok
	if ok {
		delete(s.capHealthCause, tok)
	} else {
		s.capHealthCause[tok] = why
	}
	s.capHealthMu.Unlock()
}

// evaluateHADegraded computes the currently-degraded reasons. A configured-to-enforce
// token that has not latched is degraded (enforcement not yet confirmed cluster-wide);
// when VIP HA is active, a configured VIP no reachable participant holds is a zero-holder
// outage.
// It also returns the capabilities behind haUnsupportedMember, sorted by token,
// each with the CAUSE that applies to it. The reason alone is not actionable:
// every configured-to-enforce token collapses into the same string, so an
// operator reading `unsupported_member` learns that SOMETHING is unconfirmed and
// has to go find out what — and a second token joining the first is silent,
// because the reason was already on.
//
// The cause travels with the token because a name on its own can be worse than
// no name. "This peer does not advertise it" and "the sweep could not tell"
// arrive through the same boolean and want opposite responses.
func (s *Server) evaluateHADegraded(ctx context.Context) (map[string]bool, []degradedCapability) {
	out := map[string]bool{}
	var unsupported []degradedCapability
	// A WAL-quarantined node advertises NOTHING, and the capability sweep asks
	// itself through a self short-circuit (PeerCapabilities returns
	// advertisedCapabilities for host == self). So every configured token reads
	// unconfirmed, and without this the node would emit `unsupported_member`
	// naming its entire capability set — "a peer is on an old binary, finish
	// your rollout" — in the same cycle as the rolled_back_latch that says the
	// true thing and names the real fix (reseed this node). haReasons puts
	// unsupported_member first, so the wrong alert would arrive first and
	// louder. The tokens it would name are precisely the ones no member is
	// failing to support: they are the ones THIS node stopped advertising.
	// wal_quarantine_test.go's own comment says rolled_back_latch exists to stop
	// an operator reading a quarantine as version skew; naming tokens here would
	// make the node itself commit that error.
	quarantined := s.walQuarantinedNow()
	if s.gate != nil && !quarantined {
		for _, tok := range capabilities.Supported() {
			// Only a token this node is configured to ENFORCE can be "degraded" —
			// an advertised-but-disabled token (or one still mid-rollout on old
			// peers) must not generate haUnsupportedMember noise.
			if !s.tokenEnabled(tok) {
				continue
			}
			// Degraded when either the token has NOT latched yet (activation pending),
			// OR a bounded round-robin freshness check (checkOneCapabilityHealth) most
			// recently found it unsupported/unreachable (a POST-latch regression the
			// durable marker can't reflect). No fan-out here — we only read cheap
			// in-memory state; the freshness Ping is the bounded one-per-cycle check.
			latched := s.gate.Latched(tok)
			s.capHealthMu.Lock()
			lastOK, checked := s.capHealthLast[tok]
			cause := s.capHealthCause[tok]
			s.capHealthMu.Unlock()
			healthy := latched && (!checked || lastOK)
			if healthy {
				continue
			}
			// A MANDATORY token that has NEVER latched is separated out, because
			// it is the ordinary state of every cluster part-way through an
			// upgrade rather than a fault. It has no config flag, so there is no
			// operator intent behind it to have been let down and nothing to turn
			// off in response: the only remedy is to finish the roll. Reporting it
			// as unsupported_member raised a hard degraded alarm — with an
			// ha.degraded event and a page-shaped gauge — on every node for the
			// whole of every upgrade, and permanently on a cluster deliberately
			// held with one host back, which docs/operating-model.md blesses as
			// by-design and describes as "visible as an empty ledger rather than
			// as an error".
			//
			// Not simply skipped: waiting-on-a-rollout is real, actionable state
			// and an operator watching a stalled upgrade wants it. It gets its own
			// reason so alerting can treat a planned rollout differently from a
			// member that cannot support what this node was told to enforce.
			//
			// A mandatory token that latched and LATER regressed still reports
			// unsupported_member — it reaches here with latched=true, so it falls
			// through — which is the case that genuinely warrants the alarm.
			if !latched && capabilities.Mandatory(tok) {
				out[haRolloutPending] = true
				continue
			}
			if r := capabilityDegradedReason(tok, healthy, cause); r != "" {
				out[r] = true
				unsupported = append(unsupported, degradedCapability{
					Token: tok, Cause: degradedCause(latched, cause),
				})
			}
		}
	}
	sort.Slice(unsupported, func(i, j int) bool { return unsupported[i].Token < unsupported[j].Token })
	// vip_no_holder is a real outage whenever VIP HA is active in EITHER direction
	// (demote-only can leave a VIP holderless), so it keys off vipHAHealthEnabled,
	// NOT vipGateActive (which is only the proof-reclaim gate).
	if s.vipHAHealthEnabled() && s.anyVIPUnheld(ctx) {
		out[haVIPNoHolder] = true
	}
	// A minority node whose VIP self-demote FAILED and that has no verified self-fence
	// (set by the VIPDemoter via SetDemotionUnfenced). The majority deliberately does NOT
	// reclaim without a release/fence proof, so the VIP stays down — surface it as a
	// durable, alertable condition so an operator can provide a fence / intervene.
	if s.demotionUnfenced.Load() {
		out[haDemotionUnfenced] = true
	}
	// A markerless state=pending VM row assigned here under enforcement (written by a
	// not-yet-latched coordinator just before the flip) is refused proof_missing forever
	// by startPendingVM — a stranded ownership transfer. The refusal is correct (no proof,
	// no transfer), so surface it persistently for operator repair rather than leave it a
	// silent per-tick warn. (Repair is operator-driven / a future coordinator re-mint; the
	// row no longer carries the source host, so an automatic safe re-mint isn't derivable.)
	if s.gate != nil && s.gate.Enforced(ctx, capabilities.SplitBrainGateV1) && s.anyStrandedPending(ctx) {
		out[haStrandedPending] = true
	}
	// This binary is a rollback below a token this node already latched, so it is
	// WAL-quarantined: up and reachable, but emitting no replicated writes and
	// advertising nothing. Peers raise haUnsupportedMember about it; this is the
	// node's own report, which is what tells an operator that the fix is a reseed
	// (or an upgrade back) rather than a network problem at the other end.
	if quarantined {
		out[haRolledBackLatch] = true
	}
	return out, unsupported
}

// degradedCapability is one capability behind haUnsupportedMember, with the
// cause that applies to it. Comparable, so a set of them can be compared
// directly.
type degradedCapability struct {
	Token string
	Cause string
}

// degradedCause names why one token is unconfirmed, in the operator's terms.
//
// Three states arrive here and they call for three different actions, which is
// the whole reason the cause is carried at all:
//
//	activation_pending      the latch has not formed yet — normal mid-rollout
//	unsupported_capability  a peer really does not advertise it — finish the roll
//	activation_unconfirmed  the sweep could not tell (a Ping failed, a read
//	                        failed) — usually a host that is down, and not a
//	                        capability problem
//
// An unlatched token is reported as pending regardless of any recorded cause:
// the freshness check only runs once everything has latched, so a cause left
// over from an earlier cycle would describe a question nobody is asking yet.
func degradedCause(latched bool, recorded string) string {
	if !latched {
		return "activation_pending"
	}
	if recorded == "" {
		return health.ReasonActivationUnconfirm
	}
	return recorded
}

// anyStrandedPending reports whether any VM assigned to THIS host is state=pending with no
// pending_action_id (proof marker) — the enforcement-flip legacy-pending stranding.
func (s *Server) anyStrandedPending(ctx context.Context) bool {
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		return false
	}
	for _, vm := range vms {
		if vm.State == "pending" && vm.PendingActionID == "" {
			return true
		}
	}
	return false
}

// anyVIPUnheld reports whether any enabled LB's VIP is DEFINITIVELY served by nobody —
// every configured participant reachable and none claiming it. It deliberately does NOT
// alarm when a participant is unreachable (can't tell mid-partition; that surfaces via the
// capability axis instead), so this catches the actionable post-heal "no holder" state.
func (s *Server) anyVIPUnheld(ctx context.Context) bool {
	cfgs, err := corrosion.ListLBConfigs(ctx, s.db)
	if err != nil {
		return false
	}
	for _, cfg := range cfgs {
		if cfg.Enabled && s.vipUnheld(ctx, cfg) {
			return true
		}
	}
	return false
}

func (s *Server) vipUnheld(ctx context.Context, cfg corrosion.LBConfigRecord) bool {
	hosts, ok := parseHostsJSON(cfg.Hosts)
	if !ok {
		return false
	}
	if len(hosts) == 0 {
		p, pok := s.actualLBParticipants(ctx, cfg.Name)
		if !pok {
			return false // can't resolve membership → don't alarm
		}
		hosts = p
	}
	if len(hosts) == 0 {
		return false // no participants configured → nothing that should be serving
	}
	for _, h := range hosts {
		if !s.participantReachable(ctx, h) {
			return false // a participant we can't reach → indeterminate, don't false-alarm
		}
	}
	for _, h := range hosts {
		if s.hostClaimsVIP(ctx, h, cfg.VIP) {
			return false // someone holds it
		}
	}
	return true // all participants reachable, none holds the VIP → unheld
}

// hostClaimsVIP reports whether host holds/could-master the VIP (by-VIP participant). Self
// is a local kernel/config check (fail-closed on error → treated as claimed, so we never
// false-alarm on an unreadable local state); peers via CheckVIPParticipant (probeHolder
// seam in tests).
func (s *Server) hostClaimsVIP(ctx context.Context, host, vip string) bool {
	if host == s.hostName {
		c, err := lb.NewManager().ClaimsVIP(vip)
		return err != nil || c
	}
	if s.probeHolder != nil {
		return s.probeHolder(ctx, host, vip).assigned
	}
	return s.peerVIPClaims(ctx, host, vip)
}

// recordSelfReportedIsolation closes the §A loop: the shipped detector makes a
// rolled-back node WAL-quarantine ITSELF, but nothing else refused it, and a
// self-muting node cannot record its own quarantine (the epoch is peer-written
// by design). Here a HEALTHY peer pings one voting-eligible host per cycle and,
// if that host reports itself quarantined, records the isolation — after which
// every peer refuses its replication until a verified reseed.
//
// Acting on a SELF-REPORT rather than inferring from "advertises nothing" is
// deliberate. Inference cannot distinguish a rollback from a self-fence or a
// pre-latch old build, and a false isolation stops a healthy node's replication
// until an operator reseeds it — an expensive mistake. A node claiming to be
// quarantined is self-incriminating, which is the one direction worth trusting:
// a node lying about its state claims health, not degradation.
func (s *Server) recordSelfReportedIsolation(ctx context.Context) {
	if !s.tokenEnabled(capabilities.IsolationEpochV1) || s.gate == nil {
		return
	}
	// Quorum-gated: a partitioned minority must not be able to quarantine the
	// majority it simply cannot see.
	if r := s.gate.DecisionGate(ctx); !r.OK {
		return
	}
	s.observeOneSelfReportedQuarantine(ctx)
}

// observeOneSelfReportedQuarantine is the observation itself, split from the
// quorum gate above so a fleet scenario can drive it directly — the harness's
// checker never probes peers, so DecisionGate can't be satisfied there. The
// gate is therefore NOT fleet-covered; it is one call at the single entry point.
func (s *Server) observeOneSelfReportedQuarantine(ctx context.Context) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return
	}
	var peers []string
	for _, h := range hosts {
		// Deliberately NOT filtered to active hosts. Draining/maintenance is
		// exactly the state an operator puts a node into BEFORE downgrading it,
		// so an active-only filter would miss the most common way a rollback
		// actually happens (the lab caught precisely that: a rolled-back node
		// sat HOST_DRAINING and was never observed). Isolation is about whether
		// a node's STATE is valid, not whether it is eligible for workloads.
		// An unreachable or decommissioned host simply fails the ping below.
		if h.Name != s.hostName && h.State != "decommissioned" {
			peers = append(peers, h.Name)
		}
	}
	if len(peers) == 0 {
		return
	}
	s.capHealthMu.Lock()
	peer := peers[s.isolationCursor%len(peers)]
	s.isolationCursor++
	s.capHealthMu.Unlock()

	if epoch, _, err := corrosion.HostIsolation(ctx, s.db, peer); err != nil || epoch > 0 {
		return // already recorded (or unreadable) — IsolateHost is idempotent anyway
	}
	c, conn, err := s.peerClient(ctx, peer)
	if err != nil {
		return // unreachable is NOT isolated: that is a peer being down, not out-of-regime
	}
	defer conn.Close()
	resp, err := c.Ping(ctx, &pb.PingRequest{})
	if err != nil || !resp.GetWalQuarantined() {
		return
	}
	if err := corrosion.IsolateHost(ctx, s.db, s.hostName, peer, corrosion.IsolationRolledBackLatch); err != nil {
		slog.Warn("could not record a self-reported quarantine as an isolation",
			"peer", peer, "error", err)
		return
	}
	s.audit(ctx, "host.isolate", peer, "reason=rolled_back_latch (self-reported quarantine)", "ok")
	slog.Warn("recorded a peer's self-reported quarantine as an isolation — its replication is now refused",
		"peer", peer, "observer", s.hostName, "fix", "lv host reseed "+peer)
}
