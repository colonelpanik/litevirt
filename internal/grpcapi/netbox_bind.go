package grpcapi

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// validateAndBindPrefix runs every bind-time precondition and records the
// binding. Each check fails closed with an operator-actionable message.
func (s *Server) validateAndBindPrefix(ctx context.Context, netName string, prefixID int) error {
	if s.netbox == nil {
		return fmt.Errorf("binding a NetBox prefix requires netbox configuration on this node")
	}

	// 1. The latch, DURABLY. A latch that is only in-memory would not survive a
	//    restart — this node could come back up, momentarily believe the fleet
	//    doesn't support netbox_ipam_v1 yet, and an older peer that never parses
	//    NetBoxPrefixID would then allocate from the builtin allocator across an
	//    already-bound prefix. DurablyLatched requires the persisted marker, not
	//    just the in-memory flag.
	if s.gate == nil || !s.gate.DurablyLatched(capabilities.NetBoxIPAMV1) {
		return fmt.Errorf("netbox_ipam_v1 is not durably latched cluster-wide — enable netbox on every node first")
	}

	// 2. The prefix exists, and we record its CIDR as the drift baseline.
	p, err := s.netbox.GetPrefix(ctx, prefixID)
	if err != nil {
		return fmt.Errorf("read NetBox prefix %d: %w", prefixID, err)
	}

	// 3. It must live in a VRF. NetBox does not expose the global
	//    ENFORCE_GLOBAL_UNIQUE setting through a supported API, so a global-table
	//    prefix cannot be validated — and without uniqueness enforcement every
	//    conflict guarantee in the claim path evaporates.
	if p.VRFID == 0 {
		return fmt.Errorf("NetBox prefix %d is in the global table; bind requires a prefix in a VRF with enforce_unique set, because the global uniqueness setting is not readable through the API", prefixID)
	}
	unique, err := s.netbox.VRFEnforcesUnique(ctx, p.VRFID)
	if err != nil {
		return fmt.Errorf("read NetBox VRF %d: %w", p.VRFID, err)
	}
	if !unique {
		return fmt.Errorf("NetBox VRF %d does not set enforce_unique; litevirt cannot guarantee address uniqueness without it", p.VRFID)
	}

	// 4. One litevirt network per prefix. ip_allocations is keyed on the LITEVIRT
	//    network name, so two networks sharing a prefix allocate independently.
	existing, err := corrosion.GetBindingByPrefix(ctx, s.db, prefixID)
	if err != nil {
		return fmt.Errorf("check existing binding: %w", err)
	}
	if existing != nil && existing.Network != netName {
		return fmt.Errorf("NetBox prefix %d is already bound to network %q", prefixID, existing.Network)
	}

	// 5. Pin the fingerprint. Pinned, not recomputed: a CA replacement must
	//    SUSPEND the binding rather than silently re-identify every object.
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return fmt.Errorf("derive cluster fingerprint: %w", err)
	}

	won, err := corrosion.ClaimBinding(ctx, s.db, corrosion.BindingRecord{
		Network:            netName,
		PrefixID:           prefixID,
		ObservedCIDR:       p.Prefix,
		VRFID:              p.VRFID,
		ClusterFingerprint: fp,
	})
	if err != nil {
		return err
	}
	if !won {
		// Another bind won the race between our check above and this insert.
		return fmt.Errorf("NetBox prefix %d was bound to another network concurrently", prefixID)
	}
	return nil
}
