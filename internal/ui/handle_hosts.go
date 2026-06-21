package ui

import (
	"encoding/json"
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

// hostDiskActual is the statfs-based (df) disk usage for one host, shown in the
// hosts list alongside the allocated figure.
type hostDiskActual struct{ UsedBytes, TotalBytes int64 }

// sumPoolActual sums statfs used/total bytes across a host's storage pools,
// deduped by target so two pools on one filesystem aren't double-counted.
// Shared by the hosts list and the host detail page.
func sumPoolActual(pools []*pb.StoragePool) (used, total int64) {
	seen := map[string]bool{}
	for _, p := range pools {
		if t := p.GetTarget(); t != "" {
			if seen[t] {
				continue
			}
			seen[t] = true
		}
		used += p.GetUsedBytes()
		total += p.GetTotalBytes()
	}
	return used, total
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})
	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{})

	// Count VMs per host.
	vmsByHost := make(map[string][]*pb.VM)
	for _, vm := range vms.GetVms() {
		vmsByHost[vm.HostName] = append(vmsByHost[vm.HostName], vm)
	}

	// Actual (statfs/df) disk usage per host, shown next to the allocated
	// figure. The list previously showed allocation only, which doesn't move
	// on a same-host pool change and didn't match df.
	diskActual := make(map[string]*hostDiskActual)
	for _, h := range hosts.GetHosts() {
		u, t := sumPoolActual(h.GetStoragePools())
		diskActual[h.GetName()] = &hostDiskActual{UsedBytes: u, TotalBytes: t}
	}

	data := s.pageData("Hosts", "hosts")
	data["Hosts"] = hosts.GetHosts()
	data["VMsByHost"] = vmsByHost
	data["DiskActual"] = diskActual
	s.renderPage(w, "hosts.html", data)
}

func (s *Server) handleHostDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := s.uiBearerCtx(r)

	host, err := s.grpc.InspectHost(ctx, &pb.InspectHostRequest{Name: name})
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{HostName: name})
	devices, _ := s.grpc.ListHostDevices(ctx, &pb.ListHostDevicesRequest{Name: name})
	allNets, _ := s.grpc.ListNetworks(ctx, &emptypb.Empty{})

	// Filter networks to those used by VMs on this host.
	usedNets := map[string]bool{}
	for _, vm := range vms.GetVms() {
		for _, iface := range vm.Interfaces {
			usedNets[iface.NetworkName] = true
		}
	}
	var hostNets []*pb.NetworkInfo
	for _, n := range allNets.GetNetworks() {
		if usedNets[n.Name] || usedNets[n.Iface] {
			hostNets = append(hostNets, n)
		}
	}

	var cpuPct, memPct float64
	if host.CpuTotal > 0 {
		cpuPct = float64(host.CpuUsed) / float64(host.CpuTotal) * 100
	}
	if host.MemTotalMib > 0 {
		memPct = float64(host.MemUsedMib) / float64(host.MemTotalMib) * 100
	}
	// Actual on-disk usage (statfs, matches `df`) summed across the host's
	// storage pools. Distinct from host.DiskUsedGib (sum of VMs' allocated
	// virtual sizes) — both are shown so a same-host pool move (which doesn't
	// change allocation) is still visible as freed real space.
	diskActualUsed, diskActualTotal := sumPoolActual(host.GetStoragePools())
	var diskActualPct float64
	if diskActualTotal > 0 {
		diskActualPct = float64(diskActualUsed) / float64(diskActualTotal) * 100
	}

	data := s.pageData(name, "hosts")
	data["Host"] = host
	data["VMs"] = vms.GetVms()
	data["Devices"] = devices.GetDevices()
	data["Networks"] = hostNets
	data["CPUPct"] = cpuPct
	data["MemPct"] = memPct
	data["DiskActualUsed"] = diskActualUsed
	data["DiskActualTotal"] = diskActualTotal
	data["DiskActualPct"] = diskActualPct
	s.renderPage(w, "host_detail.html", data)
}

func (s *Server) handleDrainHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_, err := s.grpc.DrainHost(s.uiBearerCtx(r), &pb.DrainHostRequest{Name: name})
	if err != nil {
		sendToast(w, "Drain failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Drain started for "+name, "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleUndrainHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_, err := s.grpc.UndrainHost(s.uiBearerCtx(r), &pb.UndrainHostRequest{Name: name})
	if err != nil {
		sendToast(w, "Undrain failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, name+" returned to active", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleFenceHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	result, err := s.grpc.FenceHost(s.uiBearerCtx(r), &pb.FenceHostRequest{Name: name, Confirmed: true})
	if err != nil {
		sendToast(w, "Fence failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, name+" fenced via "+result.Method+": "+result.Result, "warning")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRemoveHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_, err := s.grpc.RemoveHost(s.uiBearerCtx(r), &pb.RemoveHostRequest{Name: name, Force: false})
	if err != nil {
		sendToast(w, "Remove failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, name+" removed from cluster", "success")
	w.Header().Set("HX-Redirect", "/hosts")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleHostLabelsUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_ = r.ParseForm()

	// Parse key=value pairs from form.
	labels := map[string]string{}
	var remove []string
	for _, kv := range r.Form["label"] {
		if kv == "" {
			continue
		}
		var k, v string
		for i, c := range kv {
			if c == '=' {
				k = kv[:i]
				v = kv[i+1:]
				break
			}
		}
		if k != "" {
			labels[k] = v
		}
	}
	for _, k := range r.Form["remove_label"] {
		if k != "" {
			remove = append(remove, k)
		}
	}

	_, err := s.grpc.SetHostLabels(s.uiBearerCtx(r), &pb.SetHostLabelsRequest{
		Name:   name,
		Labels: labels,
		Remove: remove,
	})
	if err != nil {
		sendToast(w, "Label update failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Labels updated for "+name, "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleHostHealthMatrix(w http.ResponseWriter, r *http.Request) {
	matrix, err := s.grpc.GetHostHealth(s.uiBearerCtx(r), &emptypb.Empty{})
	if err != nil {
		sendToast(w, "Health check failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(matrix.Entries)
}

func (s *Server) handleConfigureHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_ = r.ParseForm()

	_, err := s.grpc.ConfigureHost(s.uiBearerCtx(r), &pb.ConfigureHostRequest{
		Name:          name,
		FenceStrategy: r.FormValue("fence_strategy"),
		IpmiAddress:   r.FormValue("ipmi_address"),
		IpmiUser:      r.FormValue("ipmi_user"),
		IpmiPass:      r.FormValue("ipmi_pass"),
		WatchdogDev:   r.FormValue("watchdog_dev"),
	})
	if err != nil {
		sendToast(w, "Configure failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, name+" configured", "success")
	w.WriteHeader(http.StatusOK)
}
