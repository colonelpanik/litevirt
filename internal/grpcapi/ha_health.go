package grpcapi

import (
	"context"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
)

// HA-degraded reasons (closed vocabulary for litevirt_ha_degraded{reason}).
const (
	haUnsupportedMember = "unsupported_member"      // a flipped capability can't be confirmed cluster-wide
	haDemotionUnfenced  = "demotion_unfenced"       // a minority node's VIP demote FAILED and it has no verified self-fence — the majority holds in the safe gap (VIP outage until repaired / a fence is provided)
	haVIPNoHolder       = "vip_no_holder"           // a configured VIP is served by nobody
	haStrandedPending   = "legacy_pending_stranded" // a markerless pending VM refused proof_missing forever
)

var haReasons = []string{haUnsupportedMember, haDemotionUnfenced, haVIPNoHolder, haStrandedPending}

// capabilityDegradedReason maps a SUPPORTED (flipped) token's CapabilityActive result to
// an HA-degraded reason, or "" if it's fine. vip_demote_v1 is a software capability (no
// watchdog gate), so a reachable member that doesn't advertise it is simply on an older
// binary mid-roll — an unsupported member that holds back enforcement. (The dangerous
// "demoted but can't self-fence" state is a per-node RUNTIME condition surfaced separately
// via haDemotionUnfenced, not a capability-advertisement gap.)
func capabilityDegradedReason(token string, ok bool, reason string) string {
	if ok {
		return ""
	}
	return haUnsupportedMember
}

// RunHAHealthMonitor periodically evaluates the persistent HA-degraded conditions,
// updates the litevirt_ha_degraded gauge, and emits an event on each set→clear / clear→set
// transition (a durable, alertable surface — not just a per-refusal counter). Inert on the
// capability axis until a token is actually flipped (Supported() is empty pre-flip), and on
// the VIP axis until vip_demote_v1 is enforced.
func (s *Server) RunHAHealthMonitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	prev := map[string]bool{}
	eval := func() {
		s.driveCapabilityActivation(ctx)
		cur := s.evaluateHADegraded(ctx)
		for _, r := range haReasons {
			on := cur[r]
			s.haMetrics.Set(r, on)
			switch {
			case on && !prev[r]:
				s.publish("ha.degraded", r, "HA degraded: "+r)
			case !on && prev[r]:
				s.publish("ha.recovered", r, "")
			}
		}
		prev = cur
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

// driveCapabilityActivation flips the durable enforcement latch for every SUPPORTED
// token by calling Enforced — the ONLY path that latches (CapabilityActive/…ForHealth
// only compute). Most tokens are latched by their consumers calling Enforced at a
// decision point (the coordinator for split_brain_gate_v1 / safe_fence_default_v1, the
// VIP paths for the vip_* tokens). A token whose sole consumer reads the cheap Latched()
// on a hot path — lww_skew_guard_v1's per-merge skew guard — has NO such caller, so without
// this periodic drive its latch would never flip even after it is added to `supported`,
// and the guard would stay off forever. This runs at the HA-monitor cadence (off the hot
// path) and is idempotent for already-latched tokens (cheap `already` path in Enforced).
func (s *Server) driveCapabilityActivation(ctx context.Context) {
	if s.gate == nil {
		return
	}
	for _, tok := range capabilities.Supported() {
		s.gate.Enforced(ctx, tok)
	}
}

// evaluateHADegraded computes the currently-degraded reasons. For every SUPPORTED token,
// an unconfirmed CapabilityActive is a degraded status; when the VIP gate is enforced, a
// configured VIP that no reachable participant holds is a zero-holder outage.
func (s *Server) evaluateHADegraded(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	if s.gate != nil {
		for _, tok := range capabilities.Supported() {
			ok, reason := s.gate.CapabilityActiveForHealth(ctx, tok)
			if r := capabilityDegradedReason(tok, ok, reason); r != "" {
				out[r] = true
			}
		}
	}
	if s.vipGateActive(ctx) && s.anyVIPUnheld(ctx) {
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
	return out
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
