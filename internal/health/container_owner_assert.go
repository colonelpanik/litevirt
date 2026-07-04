package health

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// SetPeerContainerRuntimeChecker injects the peer CheckContainerRuntime client.
// Without it, runtime re-key is disabled.
func (c *ContainerChecker) SetPeerContainerRuntimeChecker(fn func(ctx context.Context, host, name string) (string, error)) {
	c.checkPeerRuntime = fn
}

// SetContainerRekeyObserver registers a nil-safe observer of re-key outcomes.
func (c *ContainerChecker) SetContainerRekeyObserver(fn func(name, result string)) { c.onRekey = fn }

func (c *ContainerChecker) observeRekey(name, result string) {
	if c.onRekey != nil {
		c.onRekey(name, result)
	}
}

func (c *ContainerChecker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// assertContainerOwnership reclaims a container that runs LOCALLY but whose only
// live DB row points at another host — the container analogue of the VM
// owner-assert, but a PK re-key (ownership is part of the PK). It acts only on
// positive, decision-complete proof that no other host runs it, and never
// touches a container under an in-flight relocation/restore/migration (PR #57).
func (c *ContainerChecker) assertContainerOwnership(ctx context.Context) {
	if c.runtime == nil || c.checkPeerRuntime == nil {
		return
	}
	localCTs, err := c.runtime.List(ctx)
	if err != nil {
		return
	}
	hosts, err := corrosion.ListHosts(ctx, c.db)
	if err != nil {
		return
	}
	if !localHostIsActiveWorker(hosts, c.hostName) {
		return
	}
	// Split-brain gate (Phase 1): once enforced, a container re-key (a
	// runtime-ownership write) additionally requires local quorum. ExecutionGate-
	// only (per-host reclaim; no lease/proof). Fail-open until cluster-wide.
	if c.gate != nil && c.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
		if g := c.gate.ExecutionGate(ctx); !g.OK {
			slog.Info("container owner-assert: execution gate refused re-key (no quorum)", "reason", g.Reason)
			c.noteGateRefused(corrosion.ActionOwnerAssert, g.Reason)
			return
		}
	}
	others := workloadCapablePeers(hosts, c.hostName)

	// All live container rows indexed by name (cross-host) — we must reason over
	// every host's row, not just our own, to find the single remote owner.
	allRows, err := corrosion.ListContainers(ctx, c.db, "")
	if err != nil {
		return
	}
	rowsByName := make(map[string][]corrosion.ContainerRecord, len(allRows))
	for _, r := range allRows {
		rowsByName[r.Name] = append(rowsByName[r.Name], r)
	}

	seen := make(map[string]bool, len(localCTs))
	for _, name := range localCTs {
		// Must be RUNNING locally (a stopped local leftover is not a claim).
		st, serr := c.runtime.State(ctx, name)
		if serr != nil || st != lxc.StateRunning {
			continue
		}
		rows := rowsByName[name]
		var selfRow *corrosion.ContainerRecord
		var remotes []corrosion.ContainerRecord
		for i := range rows {
			if rows[i].HostName == c.hostName {
				selfRow = &rows[i]
			} else {
				remotes = append(remotes, rows[i])
			}
		}
		switch {
		case selfRow != nil:
			continue // already ours — the normal sweep handles it
		case len(remotes) != 1:
			continue // 0 = missing row (nothing to re-key); >1 = ambiguous duplicate
		case remotes[0].IsTemplate:
			continue // never re-key a template
		case containerUnderRelocation(rows):
			continue // an in-flight relocation/restore/migration owns the transition
		}

		seen[name] = true
		if !c.ownershipDebounceElapsed(name) {
			continue
		}
		c.tryRekey(ctx, name, remotes[0], others)
	}
	c.pruneOwnershipDebounce(seen)
}

// containerUnderRelocation reports whether ANY live row for the name is part of
// an active relocation/restore/migration the failover coordinator (PR #57) owns,
// so the runtime re-key must stand clear.
func containerUnderRelocation(rows []corrosion.ContainerRecord) bool {
	for _, r := range rows {
		if r.State == "migrating" || r.RelocateToken != "" {
			return true
		}
		if r.State == "pending" && r.StateDetail == corrosion.ContainerRelocateRecreateDetail {
			return true
		}
		if _, _, ok := corrosion.RelocateRestoreMarker(r.State, r.StateDetail); ok {
			return true
		}
	}
	return false
}

// tryRekey corroborates against every workload-capable peer and re-keys only
// when all answer and none reports the container running. (A peer reporting
// defined_stopped is just a stale leftover, not a live writer, so it does not
// block — unlike the VM path; an unreachable/unknown peer does block.)
func (c *ContainerChecker) tryRekey(ctx context.Context, name string, remote corrosion.ContainerRecord, others []string) {
	anyRunning := false
	allAnswered := true
	for _, h := range others {
		pctx, cancel := context.WithTimeout(ctx, peerRuntimeProbeTimeout)
		st, err := c.checkPeerRuntime(pctx, h, name)
		cancel()
		if err != nil {
			allAnswered = false
			slog.Info("ct-rekey: peer unreachable, deferring", "container", name, "peer", h, "error", err)
			continue
		}
		switch st {
		case RuntimeRunning:
			anyRunning = true
		case RuntimeUnknown:
			allAnswered = false
		}
		// RuntimeAbsent / RuntimeDefinedStopped → not a live writer; fine.
	}

	switch {
	case anyRunning:
		// True split-brain: the container runs here AND on another host. No
		// destructive cross-host re-key without fencing proof — alert only.
		slog.Error("ct-rekey: SPLIT-BRAIN — container runs locally AND on another host; refusing to re-key, manual intervention required",
			"container", name, "local_host", c.hostName, "db_host", remote.HostName)
		c.observeRekey(name, "split_brain")
	case !allAnswered:
		slog.Info("ct-rekey: inconclusive (a peer is unreachable or returned unknown); will retry",
			"container", name, "db_host", remote.HostName)
		c.observeRekey(name, "inconclusive")
	default:
		// Decision-complete: runs here, exactly one remote owner row, no other
		// host runs it. Re-key ownership to us (guarded atomic PK change across the
		// row, its interface rows, and its IPAM leases).
		applied, err := corrosion.RekeyContainerOwner(ctx, c.db, remote, c.hostName)
		if err != nil {
			slog.Warn("ct-rekey: RekeyContainerOwner failed", "container", name, "error", err)
			c.observeRekey(name, "error")
			return
		}
		if !applied {
			// The guard declined: between our read/probe and the write the source
			// changed (deleted / entered relocation / updated), a live local row
			// appeared, or a managed NIC IP isn't lease-backed on the source. Skip
			// and retry next sweep — never write a partial/clobbering state.
			slog.Info("ct-rekey: preconditions no longer hold (raced) — deferring", "container", name, "db_host", remote.HostName)
			c.observeRekey(name, "inconclusive")
			return
		}
		slog.Warn("ct-rekey: reclaimed container ownership — runs locally and no other host runs it",
			"container", name, "from_host", remote.HostName, "to_host", c.hostName)
		c.auditRekey(ctx, name, remote.HostName)
		c.publish("ct.runtime-owner-rekey", name, "reclaimed from "+remote.HostName)
		c.observeRekey(name, "rekeyed")
		c.clearOwnershipDebounce(name)
	}
}

// ── debounce (mirrors the VM reconciler's, on the container clock) ──

func (c *ContainerChecker) ownershipDebounceElapsed(name string) bool {
	c.ownerMu.Lock()
	defer c.ownerMu.Unlock()
	if c.ownershipFirstSeen == nil {
		c.ownershipFirstSeen = make(map[string]time.Time)
	}
	first, ok := c.ownershipFirstSeen[name]
	if !ok {
		c.ownershipFirstSeen[name] = c.now()
		return false
	}
	return c.now().Sub(first) >= ownershipAssertDebounce
}

func (c *ContainerChecker) clearOwnershipDebounce(name string) {
	c.ownerMu.Lock()
	delete(c.ownershipFirstSeen, name)
	c.ownerMu.Unlock()
}

func (c *ContainerChecker) pruneOwnershipDebounce(stillCandidate map[string]bool) {
	c.ownerMu.Lock()
	for name := range c.ownershipFirstSeen {
		if !stillCandidate[name] {
			delete(c.ownershipFirstSeen, name)
		}
	}
	c.ownerMu.Unlock()
}

func (c *ContainerChecker) auditRekey(ctx context.Context, name, fromHost string) {
	_ = corrosion.InsertAuditLog(ctx, c.db, corrosion.AuditRecord{
		ID:       ownerAssertID(),
		Username: "system",
		HostName: c.hostName,
		Action:   "ct.runtime-owner-rekey",
		Target:   name,
		Detail:   "reclaimed from " + fromHost + " (runs locally; no other host runs it)",
		Result:   "ok",
	})
}
