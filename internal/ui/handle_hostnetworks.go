package ui

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Host network configuration panel (§O Tier 1). The UI is a form over the
// replicated intent plus a PLAN-THEN-CONFIRM flow: nothing ever applies
// straight from a form — the plan modal shows the exact rendered diff, any
// self-cutoff risk, and any foreign-file conflict before the apply button
// exists to press. The server-side refusals (grpcapi → hostnet) hold
// regardless; this flow just puts them in front of the click.

func (s *Server) handleHostNetworkModal(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("name")
	data := map[string]any{"Host": host}
	if iface := r.URL.Query().Get("iface"); iface != "" {
		resp, err := s.grpc.ListHostNetworks(s.uiBearerCtx(r), &pb.ListHostNetworksRequest{HostName: host})
		if err != nil {
			sendToast(w, "Load intent failed: "+err.Error(), "error")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		for _, n := range resp.GetNetworks() {
			if n.Name == iface {
				data["Edit"] = n
				data["Addr"] = parseAddressing(n.Addressing)
				break
			}
		}
	}
	s.renderFragment(w, "host_network_modal.html", data)
}

// uiAddressing mirrors corrosion.HostNetworkAddressing for form round-trips
// (the UI package deliberately talks proto, not corrosion).
type uiAddressing struct {
	DHCP4       bool     `json:"dhcp4,omitempty"`
	DHCP6       bool     `json:"dhcp6,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
	Gateway     string   `json:"gateway,omitempty"`
	Gateway6    string   `json:"gateway6,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
}

func parseAddressing(blob string) uiAddressing {
	var a uiAddressing
	if blob != "" {
		_ = json.Unmarshal([]byte(blob), &a)
	}
	return a
}

func (s *Server) handleHostNetworkSave(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	addr := uiAddressing{
		DHCP4:       r.FormValue("dhcp4") == "on",
		DHCP6:       r.FormValue("dhcp6") == "on",
		Addresses:   splitList(r.FormValue("addresses")),
		Gateway:     strings.TrimSpace(r.FormValue("gateway")),
		Gateway6:    strings.TrimSpace(r.FormValue("gateway6")),
		Nameservers: splitList(r.FormValue("nameservers")),
	}
	addressing := ""
	if addr.DHCP4 || addr.DHCP6 || len(addr.Addresses) > 0 || addr.Gateway != "" ||
		addr.Gateway6 != "" || len(addr.Nameservers) > 0 {
		b, err := json.Marshal(addr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		addressing = string(b)
	}
	vlanID, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("vlan_id")))
	mtu, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("mtu")))
	iface := strings.TrimSpace(r.FormValue("iface"))
	_, err := s.grpc.UpsertHostNetwork(s.uiBearerCtx(r), &pb.UpsertHostNetworkRequest{
		Network: &pb.HostNetwork{
			HostName: host, Name: iface, Kind: r.FormValue("kind"),
			Members: splitList(r.FormValue("members")),
			VlanId:  int32(vlanID), VlanLink: strings.TrimSpace(r.FormValue("vlan_link")),
			Addressing: addressing, Mtu: int32(mtu),
			BondMode:   strings.TrimSpace(r.FormValue("bond_mode")),
			LacpRate:   strings.TrimSpace(r.FormValue("lacp_rate")),
			HashPolicy: strings.TrimSpace(r.FormValue("hash_policy")),
		},
	})
	if err != nil {
		sendToast(w, "Record intent failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	sendToast(w, "Recorded "+iface+" — review with Plan & Apply", "success")
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleHostNetworkDelete(w http.ResponseWriter, r *http.Request) {
	host, iface := r.PathValue("name"), r.PathValue("iface")
	_, err := s.grpc.DeleteHostNetwork(s.uiBearerCtx(r), &pb.DeleteHostNetworkRequest{
		HostName: host, Name: iface,
	})
	if err != nil {
		sendToast(w, "Remove intent failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Removed "+iface+" — takes effect on the next apply", "success")
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleHostNetworkPlanModal(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("name")
	plan, err := s.grpc.PlanHostNetwork(s.uiBearerCtx(r), &pb.PlanHostNetworkRequest{HostName: host})
	if err != nil {
		sendToast(w, "Plan failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.renderFragment(w, "host_network_plan_modal.html", map[string]any{
		"Host": host, "Plan": plan,
	})
}

func (s *Server) handleHostNetworkApply(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err := s.grpc.ApplyHostNetwork(s.uiBearerCtx(r), &pb.ApplyHostNetworkRequest{
		HostName:       host,
		ForceInterface: strings.TrimSpace(r.FormValue("force_interface")),
	})
	if err != nil {
		// The refusal/rollback text is the product here — surface it verbatim
		// (cutoff names the interface to force; a rollback names its cause).
		sendToast(w, "Apply: "+err.Error(), "error")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	sendToast(w, "Applied and confirmed on "+host, "success")
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
