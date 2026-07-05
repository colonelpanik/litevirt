package corrosion

import (
	"context"
	"encoding/json"
)

// HostFWIntent is one host's resolved firewall-infra decision for a single
// source (a managed network, or a load balancer). The canonical nftables
// reconciler reads every row for the host and renders the NAT (masquerade),
// SNAT, and host-isolation chains from them.
//
// A row contributes whatever it sets:
//   - MasqueradeSubnet != ""            → masquerade for that subnet's egress
//   - Isolate                            → the bridge is host-isolated (input drop)
//   - Exceptions                         → LB VIP:port holes in the bridge's isolation
//   - SNATVIP != ""                      → SNAT SNATSubnet→SNATVIP out SNATOutIface
//
// The table is LOCAL-only (execLocal, never replicated): nft rules are per-host
// state, so there is no cross-node last-writer-wins to arbitrate.
type HostFWIntent struct {
	ScopeKey         string // "net:<network>" | "lb:<name>" — the upsert/delete unit
	Bridge           string
	MasqueradeSubnet string
	Isolate          bool
	Exceptions       []HostFWException
	SNATSubnet       string
	SNATVIP          string
	SNATOutIface     string
}

// HostFWException is an LB VIP + its listen ports, punched through host isolation.
type HostFWException struct {
	VIP   string `json:"vip"`
	Ports []int  `json:"ports"`
}

// UpsertHostFWIntent writes (or replaces) one intent row for this host+scope.
func UpsertHostFWIntent(ctx context.Context, c *Client, hostName string, in HostFWIntent) error {
	exc := ""
	if len(in.Exceptions) > 0 {
		b, err := json.Marshal(in.Exceptions)
		if err != nil {
			return err
		}
		exc = string(b)
	}
	isolate := 0
	if in.Isolate {
		isolate = 1
	}
	return c.execLocal(ctx,
		`INSERT INTO host_fw_intent
		   (host_name, scope_key, bridge, masquerade_subnet, isolate, exceptions,
		    snat_subnet, snat_vip, snat_out_iface, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(host_name, scope_key) DO UPDATE SET
		   bridge = excluded.bridge,
		   masquerade_subnet = excluded.masquerade_subnet,
		   isolate = excluded.isolate,
		   exceptions = excluded.exceptions,
		   snat_subnet = excluded.snat_subnet,
		   snat_vip = excluded.snat_vip,
		   snat_out_iface = excluded.snat_out_iface,
		   updated_at = excluded.updated_at`,
		hostName, in.ScopeKey, in.Bridge, in.MasqueradeSubnet, isolate, exc,
		in.SNATSubnet, in.SNATVIP, in.SNATOutIface, c.NowTS())
}

// DeleteHostFWIntent removes one intent row (a network/LB was deprovisioned).
func DeleteHostFWIntent(ctx context.Context, c *Client, hostName, scopeKey string) error {
	return c.execLocal(ctx,
		`DELETE FROM host_fw_intent WHERE host_name = ? AND scope_key = ?`,
		hostName, scopeKey)
}

// ListHostFWIntent returns every intent row for hostName.
func ListHostFWIntent(ctx context.Context, c *Client, hostName string) ([]HostFWIntent, error) {
	rows, err := c.Query(ctx,
		`SELECT scope_key, bridge, masquerade_subnet, isolate, exceptions,
		        snat_subnet, snat_vip, snat_out_iface
		 FROM host_fw_intent WHERE host_name = ?`, hostName)
	if err != nil {
		return nil, err
	}
	out := make([]HostFWIntent, 0, len(rows))
	for _, r := range rows {
		in := HostFWIntent{
			ScopeKey:         r.String("scope_key"),
			Bridge:           r.String("bridge"),
			MasqueradeSubnet: r.String("masquerade_subnet"),
			Isolate:          r.Int("isolate") != 0,
			SNATSubnet:       r.String("snat_subnet"),
			SNATVIP:          r.String("snat_vip"),
			SNATOutIface:     r.String("snat_out_iface"),
		}
		if raw := r.String("exceptions"); raw != "" {
			// Best-effort: a malformed blob just drops the exceptions (isolation
			// stays fail-closed — the bridge is still dropped, just without holes).
			_ = json.Unmarshal([]byte(raw), &in.Exceptions)
		}
		out = append(out, in)
	}
	return out, nil
}
