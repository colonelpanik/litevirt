package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleVMs(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{HostName: r.URL.Query().Get("host")})
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})
	data := s.pageData("VMs", "vms")
	data["VMs"] = vms.GetVms()
	data["Hosts"] = hosts.GetHosts()
	s.renderPage(w, "vms.html", data)
}

func (s *Server) handleVMDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	vm, err := s.grpc.InspectVM(s.uiBearerCtx(r), &pb.InspectVMRequest{Name: name})
	if err != nil {
		http.Error(w, "VM not found", http.StatusNotFound)
		return
	}
	hosts, _ := s.grpc.ListHosts(s.uiBearerCtx(r), &pb.ListHostsRequest{})
	snapshots, _ := s.grpc.ListSnapshots(s.uiBearerCtx(r), &pb.ListSnapshotsRequest{VmName: name})
	data := s.pageData(name, "vms")
	data["VM"] = vm
	data["Hosts"] = hosts.GetHosts()
	data["Snapshots"] = snapshots.GetSnapshots()
	data["Backups"] = s.vmBackupManifests(name)
	data["Activity"] = s.vmActivity(r, name)
	s.renderPage(w, "vm_detail.html", data)
}

func (s *Server) handleVMsTable(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{HostName: r.URL.Query().Get("host")})
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})
	s.renderPartial(w, "vms.html", "vms-table", map[string]any{
		"VMs":         vms.GetVms(),
		"Hosts":       hosts.GetHosts(),
		"ClusterName": s.cluster,
	})
}

func (s *Server) handleNewVMModal(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	images, _ := s.grpc.ListImages(ctx, &emptypb.Empty{})
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})
	s.renderFragment(w, "vm_new_modal.html", map[string]any{
		"Images": images.GetImages(),
		"Hosts":  hosts.GetHosts(),
	})
}

// handleVMDetailPartial renders just the static inner detail (cards, network,
// disks, snapshots, PCI). No longer auto-polled — the VM-detail page keeps this
// region static and only the live-stats strip + charts self-refresh. Retained
// for explicit refreshes and action responses that target the inner region.
func (s *Server) handleVMDetailPartial(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	vm, err := s.grpc.InspectVM(s.uiBearerCtx(r), &pb.InspectVMRequest{Name: name})
	if err != nil {
		http.Error(w, "VM not found", 404)
		return
	}
	snapshots, _ := s.grpc.ListSnapshots(s.uiBearerCtx(r), &pb.ListSnapshotsRequest{VmName: name})
	s.renderPartial(w, "vm_detail.html", "vm_detail_inner", map[string]any{
		"VM": vm, "Snapshots": snapshots.GetSnapshots(), "Backups": s.vmBackupManifests(name),
		"Activity": s.vmActivity(r, name), "ClusterName": s.cluster,
	})
}

// handleVMPagePartial renders header + detail (for action button responses).
func (s *Server) handleVMPagePartial(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	vm, err := s.grpc.InspectVM(s.uiBearerCtx(r), &pb.InspectVMRequest{Name: name})
	if err != nil {
		http.Error(w, "VM not found", 404)
		return
	}
	snapshots, _ := s.grpc.ListSnapshots(s.uiBearerCtx(r), &pb.ListSnapshotsRequest{VmName: name})
	s.renderPartial(w, "vm_detail.html", "vm_page", map[string]any{
		"VM": vm, "Snapshots": snapshots.GetSnapshots(), "Backups": s.vmBackupManifests(name),
		"Activity": s.vmActivity(r, name), "ClusterName": s.cluster,
	})
}

// vmActivity fetches a VM's recent operational events (lifecycle + backup
// outcomes) for the detail-page Activity timeline. Best-effort: errors render
// an empty timeline rather than failing the page.
func (s *Server) vmActivity(r *http.Request, name string) []*pb.VMEvent {
	resp, err := s.grpc.ListVMEvents(s.uiBearerCtx(r), &pb.ListVMEventsRequest{VmName: name, Limit: 50})
	if err != nil {
		return nil
	}
	return resp.GetEvents()
}

func (s *Server) handleCreateVM(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	cpu, _ := strconv.Atoi(r.FormValue("cpu"))
	mem, _ := strconv.Atoi(r.FormValue("memory"))
	minMem, _ := strconv.Atoi(r.FormValue("min_memory"))
	maxMem, _ := strconv.Atoi(r.FormValue("max_memory"))
	startupOrder, _ := strconv.Atoi(r.FormValue("startup_order"))
	startDelay, _ := strconv.Atoi(r.FormValue("start_delay"))
	stopDelay, _ := strconv.Atoi(r.FormValue("stop_delay"))
	spec := &pb.VMSpec{
		Name:          r.FormValue("name"),
		Image:         r.FormValue("image"),
		Cpu:           int32(cpu),
		MemoryMib:     int32(mem),
		MinMemoryMib:  int32(minMem),
		MaxMemoryMib:  int32(maxMem),
		GuestAgent:    true,
		Machine:       "q35",
		Firmware:      "uefi",
		Onboot:        r.FormValue("onboot") == "true",
		StartupOrder:  int32(startupOrder),
		StartDelaySec: int32(startDelay),
		StopDelaySec:  int32(stopDelay),
	}
	if disk := r.FormValue("disk"); disk != "" {
		spec.Disks = []*pb.DiskSpec{{Name: "root", Size: disk, Bus: "virtio"}}
	}
	if r.FormValue("disable_vnc") == "true" {
		spec.DisableVnc = true
	}
	if r.FormValue("enable_spice") == "true" {
		spec.EnableSpice = true
	}
	if iso := strings.TrimSpace(r.FormValue("iso")); iso != "" {
		spec.Iso = iso
	}
	if boot := r.FormValue("boot"); boot != "" {
		spec.Boot = boot
	}
	if tags := parseTags(r.FormValue("tags")); tags != nil {
		spec.Labels = tags
	}
	if host := r.FormValue("host"); host != "" {
		spec.Placement = &pb.PlacementSpec{Host: host}
	}
	// Auto-restart policy (none | on-failure | always). Only set when chosen, so
	// the default stays "no policy" (never auto-restart).
	if rc := r.FormValue("restart_condition"); rc != "" && rc != "none" {
		max, _ := strconv.Atoi(r.FormValue("restart_max_attempts"))
		spec.Restart = &pb.RestartPolicy{
			Condition:   rc,
			MaxAttempts: int32(max),
			Delay:       r.FormValue("restart_delay"),
			Window:      r.FormValue("restart_window"),
		}
	}

	// Cloud-init: friendly fields (user/password/SSH keys/packages) assembled
	// into a #cloud-config doc, or a raw override. Nil if nothing was supplied.
	if ci := buildCloudInitUserdata(r); ci != "" {
		spec.CloudInit = &pb.CloudInitSpec{Userdata: ci}
	}

	// Networks — parallel arrays net_bridge[] and net_model[].
	bridges := r.Form["net_bridge[]"]
	models := r.Form["net_model[]"]
	for i, br := range bridges {
		if br == "" {
			continue
		}
		model := "virtio"
		if i < len(models) && models[i] != "" {
			model = models[i]
		}
		spec.Network = append(spec.Network, &pb.NetworkAttachment{
			Name:  br,
			Model: model,
		})
	}

	// Resource tuning from control knobs.
	ioThreads, _ := strconv.Atoi(r.FormValue("io_threads"))
	hugepages := r.FormValue("hugepages") == "true"
	numaStrict := r.FormValue("numa_strict") == "true"
	cpuPinStr := r.FormValue("cpu_pinning")
	if hugepages || ioThreads > 0 || numaStrict || cpuPinStr != "" {
		res := &pb.ResourceTuning{
			Hugepages: hugepages,
			IoThreads: int32(ioThreads),
		}
		if numaStrict {
			res.NumaPolicy = &pb.NUMAPolicy{
				PreferredNode: -1,
				Strict:        true,
			}
		}
		if cpuPinStr != "" {
			for _, s := range strings.Split(cpuPinStr, ",") {
				if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
					res.CpuPinning = append(res.CpuPinning, int32(v))
				}
			}
		}
		spec.Resources = res
	}

	// PCI devices — parallel arrays dev_type[], dev_address[], dev_mapping[].
	// A non-empty mapping makes the device cluster-portable (resolved per host).
	devTypes := r.Form["dev_type[]"]
	devAddresses := r.Form["dev_address[]"]
	devMappings := r.Form["dev_mapping[]"]
	for i, dt := range devTypes {
		mapping := ""
		if i < len(devMappings) {
			mapping = devMappings[i]
		}
		if dt == "" && mapping == "" {
			continue
		}
		addr := ""
		if i < len(devAddresses) {
			addr = devAddresses[i]
		}
		spec.Devices = append(spec.Devices, &pb.DeviceSpec{
			Type:    dt,
			Address: addr,
			Mapping: mapping,
		})
	}

	slog.Info("UI: creating VM", "name", spec.Name, "image", spec.Image, "host", r.FormValue("host"), "networks", len(spec.Network), "devices", len(spec.Devices))
	_, err := s.grpc.CreateVM(s.uiBearerCtx(r), &pb.CreateVMRequest{Spec: spec})
	if err != nil {
		slog.Error("UI: create VM failed", "name", spec.Name, "error", err)
		sendToast(w, "Create VM failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "VM '"+spec.Name+"' created", "success")
	w.Header().Set("HX-Redirect", "/vms")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStartVM(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.grpc.StartVM(s.uiBearerCtx(r), &pb.StartVMRequest{Name: name}); err != nil {
		slog.Error("UI: start VM failed", "name", name, "error", err)
		sendToast(w, "Start failed: "+err.Error(), "error")
		s.handleVMPagePartial(w, r)
		return
	}
	w.Header().Set("HX-Redirect", "/vms/"+name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStopVM(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.grpc.StopVM(s.uiBearerCtx(r), &pb.StopVMRequest{Name: name}); err != nil {
		slog.Error("UI: stop VM failed", "name", name, "error", err)
		sendToast(w, "Stop failed: "+err.Error(), "error")
		s.handleVMPagePartial(w, r)
		return
	}
	w.Header().Set("HX-Redirect", "/vms/"+name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRestartVM(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.grpc.RestartVM(s.uiBearerCtx(r), &pb.RestartVMRequest{Name: name}); err != nil {
		slog.Error("UI: restart VM failed", "name", name, "error", err)
		sendToast(w, "Restart failed: "+err.Error(), "error")
		s.handleVMPagePartial(w, r)
		return
	}
	w.Header().Set("HX-Redirect", "/vms/"+name)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteVM(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.grpc.DeleteVM(s.uiBearerCtx(r), &pb.DeleteVMRequest{Name: name}); err != nil {
		// e.g. the linked-clone refcount guard or an RBAC denial — surface it
		// instead of falsely reporting success and redirecting away.
		slog.Error("UI: delete VM failed", "name", name, "error", err)
		sendToast(w, "Delete failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusOK)
		return
	}
	sendToast(w, "VM '"+name+"' deleted", "success")
	w.Header().Set("HX-Redirect", "/vms")
	w.WriteHeader(http.StatusOK)
}

// handleSetVMMemoryUI sets a VM's live balloon target (#4). Mirrors `lv set-memory`.
func (s *Server) handleSetVMMemoryUI(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	target, _ := strconv.Atoi(r.FormValue("target_mib"))
	if _, err := s.grpc.SetVMMemory(s.uiBearerCtx(r), &pb.SetVMMemoryRequest{Name: name, TargetMib: int32(target)}); err != nil {
		sendToast(w, "Set memory failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Memory balloon target set to "+strconv.Itoa(target)+" MiB", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleSnapshotModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	s.renderFragment(w, "snapshot_modal.html", map[string]any{"VMName": name})
}

func (s *Server) handleCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	vmName := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	snapName := r.FormValue("snapshot_name")
	if snapName == "" {
		snapName = "snap"
	}
	_, err := s.grpc.CreateSnapshot(s.uiBearerCtx(r), &pb.CreateSnapshotRequest{
		VmName:     vmName,
		Name:       snapName,
		WithMemory: r.FormValue("with_memory") == "true",
	})
	if err != nil {
		sendToast(w, "Snapshot failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Snapshot '"+snapName+"' created", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleMigrateModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := s.uiBearerCtx(r)

	vm, _ := s.grpc.InspectVM(ctx, &pb.InspectVMRequest{Name: name})
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})

	// Filter out the host the VM is currently on.
	var eligible []*pb.Host
	for _, h := range hosts.GetHosts() {
		if vm != nil && h.Name == vm.HostName {
			continue
		}
		eligible = append(eligible, h)
	}

	s.renderFragment(w, "migrate_modal.html", map[string]any{
		"VMName": name,
		"Hosts":  eligible,
	})
}

func (s *Server) handleRestoreSnapshot(w http.ResponseWriter, r *http.Request) {
	vmName := r.PathValue("name")
	snapName := r.PathValue("snap")
	_, err := s.grpc.RestoreSnapshot(s.uiBearerCtx(r), &pb.RestoreSnapshotRequest{
		VmName: vmName, SnapshotName: snapName,
	})
	if err != nil {
		sendToast(w, "Restore failed: "+err.Error(), "error")
		s.handleVMPagePartial(w, r)
		return
	}
	sendToast(w, "Snapshot '"+snapName+"' restored", "success")
	w.Header().Set("HX-Redirect", "/vms/"+vmName)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	vmName := r.PathValue("name")
	snapName := r.PathValue("snap")
	_, err := s.grpc.DeleteSnapshot(s.uiBearerCtx(r), &pb.DeleteSnapshotRequest{
		VmName: vmName, SnapshotName: snapName,
	})
	if err != nil {
		sendToast(w, "Delete snapshot failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Snapshot '"+snapName+"' deleted", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleMigrateVM(w http.ResponseWriter, r *http.Request) {
	vmName := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	targetHost := r.FormValue("target_host")
	if targetHost == "" {
		http.Error(w, "target host required", 400)
		return
	}

	withStorage := r.FormValue("with_storage") == "true"

	// Initialize progress tracking.
	ms := &migrateState{
		Phase:      "MIGRATE_VALIDATING",
		Status:     "Starting migration...",
		TargetHost: targetHost,
	}
	s.migrations.Store(vmName, ms)

	// Run migration in background so we can respond immediately. Detached from
	// the request (survives the handler returning) but carrying the operator's
	// session bearer for daemon-side authz.
	opCtx := context.WithoutCancel(s.uiBearerCtx(r))
	go func() {
		defer func() {
			ms.Done = true
		}()

		grpcCtx := opCtx
		stream, err := s.grpc.MigrateVM(grpcCtx, &pb.MigrateVMRequest{
			VmName:      vmName,
			TargetHost:  targetHost,
			WithStorage: withStorage,
		})
		if err != nil {
			slog.Warn("UI migrate: stream open failed", "vm", vmName, "error", err)
			ms.Error = err.Error()
			ms.Status = "Migration failed"
			return
		}

		for {
			prog, recvErr := stream.Recv()
			if recvErr != nil {
				if recvErr.Error() != "EOF" {
					slog.Warn("UI migrate: stream error", "vm", vmName, "error", recvErr)
					ms.Error = recvErr.Error()
					ms.Status = "Migration failed"
				} else {
					ms.Status = "Migration complete"
				}
				break
			}
			slog.Info("UI migrate: progress", "vm", vmName, "phase", prog.Phase, "status", prog.Status)
			ms.Phase = prog.Phase.String()
			ms.Status = prog.Status
			ms.DiskPct = prog.DiskPct
			ms.MemoryPct = prog.MemoryPct
			if prog.Error != "" {
				ms.Error = prog.Error
				ms.Status = "Migration failed"
			}
		}
	}()

	// Immediately return the progress panel inside the modal.
	s.renderMigrateProgress(w, vmName, ms)
}

// handleMigrateProgress returns the current migration progress for HTMX polling.
func (s *Server) handleMigrateProgress(w http.ResponseWriter, r *http.Request) {
	vmName := r.PathValue("name")
	val, ok := s.migrations.Load(vmName)
	if !ok {
		// No migration in progress — return a redirect to the VM page.
		w.Header().Set("HX-Redirect", "/vms/"+vmName)
		w.WriteHeader(http.StatusOK)
		return
	}
	ms := val.(*migrateState)

	s.renderMigrateProgress(w, vmName, ms)

	// Clean up completed migrations after returning final state.
	if ms.Done {
		s.migrations.Delete(vmName)
		if ms.Error == "" {
			sendToast(w, "Migrated "+vmName+" → "+ms.TargetHost, "success")
			w.Header().Set("HX-Redirect", "/vms/"+vmName)
		}
	}
}

// phaseInfo is used to render the phase badges in the progress template.
type phaseInfo struct {
	Label      string
	BadgeClass string
}

// migratePhaseOrder is the display order and labels for migration phases.
var migratePhaseLabels = []struct {
	Key   string
	Label string
}{
	{"MIGRATE_VALIDATING", "Validating"},
	{"MIGRATE_PREPARING", "Preparing"},
	{"MIGRATE_COPYING", "Copying"},
	{"MIGRATE_CONVERGING", "Converging"},
	{"MIGRATE_CUTOVER", "Cutover"},
	{"MIGRATE_COMPLETING", "Completing"},
}

func buildPhaseList(current string) []phaseInfo {
	// Find the index of the current phase.
	currentIdx := -1
	for i, p := range migratePhaseLabels {
		if p.Key == current {
			currentIdx = i
			break
		}
	}
	phases := make([]phaseInfo, len(migratePhaseLabels))
	for i, p := range migratePhaseLabels {
		cls := "badge-gray"
		if i < currentIdx {
			cls = "badge-green"
		} else if i == currentIdx {
			cls = "badge-blue"
		}
		phases[i] = phaseInfo{Label: p.Label, BadgeClass: cls}
	}
	return phases
}

func migrateOverallPct(phase string, diskPct, memPct float32) float64 {
	// Weight: validating=5, preparing=10, copying=50, converging=20, cutover=10, completing=5
	switch phase {
	case "MIGRATE_VALIDATING":
		return 2
	case "MIGRATE_PREPARING":
		return 5 + float64(diskPct)*0.05
	case "MIGRATE_COPYING":
		return 10 + float64(diskPct)*0.50
	case "MIGRATE_CONVERGING":
		return 60 + float64(memPct)*0.20
	case "MIGRATE_CUTOVER":
		return 85
	case "MIGRATE_COMPLETING":
		return 95
	case "MIGRATE_DONE":
		return 100
	case "MIGRATE_FAILED":
		return 0
	}
	return 0
}

func (s *Server) renderMigrateProgress(w http.ResponseWriter, vmName string, ms *migrateState) {
	data := map[string]any{
		"VMName":     vmName,
		"TargetHost": ms.TargetHost,
		"Phase":      ms.Phase,
		"Status":     ms.Status,
		"DiskPct":    ms.DiskPct,
		"MemoryPct":  ms.MemoryPct,
		"Error":      ms.Error,
		"Done":       ms.Done,
		"OverallPct": migrateOverallPct(ms.Phase, ms.DiskPct, ms.MemoryPct),
		"Phases":     buildPhaseList(ms.Phase),
	}
	s.renderFragment(w, "migrate_progress.html", data)
}

// ── Edit VM ──────────────────────────────────────────────────────────────────

func (s *Server) handleEditVMModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := s.uiBearerCtx(r)
	vm, err := s.grpc.InspectVM(ctx, &pb.InspectVMRequest{Name: name})
	if err != nil {
		http.Error(w, "VM not found", 404)
		return
	}
	networks, _ := s.grpc.ListNetworks(ctx, &emptypb.Empty{})
	s.renderFragment(w, "vm_edit_modal.html", map[string]any{
		"VM":         vm,
		"Disks":      vm.GetDisks(),
		"Interfaces": vm.GetInterfaces(),
		"Networks":   networks.GetNetworks(),
	})
}

func (s *Server) handleUpdateVMSpec(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	cpu, _ := strconv.Atoi(r.FormValue("cpu"))
	mem, _ := strconv.Atoi(r.FormValue("memory_mib"))
	cpuMode := r.FormValue("cpu_mode")
	disableVNC := r.FormValue("disable_vnc") == "true"

	req := &pb.UpdateVMRequest{
		Name:       name,
		Cpu:        int32(cpu),
		MemoryMib:  int32(mem),
		CpuMode:    cpuMode,
		DisableVnc: disableVNC,
		Machine:    r.FormValue("machine"),
		Firmware:   r.FormValue("firmware"),
	}
	// Optional redefine-class fields: only send when the form supplied them.
	if v := r.FormValue("min_memory_mib"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			n32 := int32(n)
			req.MinMemoryMib = &n32
		}
	}
	if v := r.FormValue("max_memory_mib"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			n32 := int32(n)
			req.MaxMemoryMib = &n32
		}
	}
	if v := r.FormValue("guest_agent"); v != "" {
		b := v == "true"
		req.GuestAgent = &b
	}

	_, err := s.grpc.UpdateVM(s.uiBearerCtx(r), req)
	if err != nil {
		sendToast(w, "Update failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "VM '"+name+"' updated", "success")
	w.WriteHeader(http.StatusOK)
}

// handleUpdateVMLifecycle applies the LIVE-metadata fields (restart policy,
// onboot, startup ordering) — these take effect without stopping the VM, so this
// is a dedicated endpoint separate from the stopped-only resources form. A
// dedicated handler also avoids checkbox-presence ambiguity (an unchecked onboot
// box submits nothing; here we always set it from this form's control).
func (s *Server) handleUpdateVMLifecycle(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	onboot := r.FormValue("onboot") == "true"
	startupOrder, _ := strconv.Atoi(r.FormValue("startup_order"))
	startDelay, _ := strconv.Atoi(r.FormValue("start_delay_sec"))
	stopDelay, _ := strconv.Atoi(r.FormValue("stop_delay_sec"))
	so, sd, td := int32(startupOrder), int32(startDelay), int32(stopDelay)

	req := &pb.UpdateVMRequest{
		Name:          name,
		Onboot:        &onboot,
		StartupOrder:  &so,
		StartDelaySec: &sd,
		StopDelaySec:  &td,
	}
	// Restart policy: condition "none"/"" clears it server-side.
	cond := r.FormValue("restart_condition")
	maxAtt, _ := strconv.Atoi(r.FormValue("restart_max_attempts"))
	req.Restart = &pb.RestartPolicy{
		Condition:   cond,
		MaxAttempts: int32(maxAtt),
		Delay:       r.FormValue("restart_delay"),
	}

	if _, err := s.grpc.UpdateVM(s.uiBearerCtx(r), req); err != nil {
		sendToast(w, "Update failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "VM '"+name+"' lifecycle updated", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleSetBootOrder(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	bootOrder := r.FormValue("boot_order")
	if bootOrder == "" {
		bootOrder = "disk"
	}
	_, err := s.grpc.SetBootOrder(s.uiBearerCtx(r), &pb.SetBootOrderRequest{
		Name:      name,
		BootOrder: bootOrder,
	})
	if err != nil {
		sendToast(w, "Set boot order failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Boot order set to '"+bootOrder+"'", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAttachDisk(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	sizeGiB, _ := strconv.Atoi(r.FormValue("size_gib"))
	_, err := s.grpc.AttachDevice(s.uiBearerCtx(r), &pb.AttachDeviceRequest{
		VmName: name,
		Disk: &pb.DiskSpec{
			Name: r.FormValue("name"),
			Size: fmt.Sprintf("%dG", sizeGiB),
			Bus:  r.FormValue("bus"),
		},
	})
	if err != nil {
		sendToast(w, "Attach disk failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Disk attached", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleResizeDiskModal(w http.ResponseWriter, r *http.Request) {
	vmName := r.PathValue("name")
	diskName := r.URL.Query().Get("disk")
	currentBytes, _ := strconv.ParseInt(r.URL.Query().Get("current"), 10, 64)
	s.renderFragment(w, "resize_disk_modal.html", map[string]any{
		"VMName":      vmName,
		"DiskName":    diskName,
		"CurrentSize": formatBytes(currentBytes),
	})
}

// handleMoveVolumeModal renders the per-disk "move to pool" form: a dropdown of
// other file-based pools on the VM's host (excluding the disk's current pool).
func (s *Server) handleMoveVolumeModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	diskName := r.URL.Query().Get("disk")
	ctx := s.uiBearerCtx(r)
	vm, _ := s.grpc.InspectVM(ctx, &pb.InspectVMRequest{Name: name})
	host, current := "", ""
	if vm != nil {
		host = vm.HostName
		for _, d := range vm.Disks {
			if d.Name == diskName {
				current = d.StorageVolume
			}
		}
	}
	var pools []string
	resp, _ := s.grpc.ListStoragePools(ctx, &pb.ListStoragePoolsRequest{})
	for _, p := range resp.GetPools() {
		if p.Host == host && p.Name != current {
			pools = append(pools, p.Name)
		}
	}
	s.renderFragment(w, "move_volume_modal.html", map[string]any{
		"VMName": name, "DiskName": diskName, "CurrentPool": current, "Pools": pools,
	})
}

// handleMoveVolume drives a single-disk pool move via the MoveVolume RPC (which
// forwards to the VM's owning host) and renders the result. The disk-pool change
// propagates to the stack's compose YAML automatically (server-side).
func (s *Server) handleMoveVolume(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	disk := r.FormValue("disk")
	pool := r.FormValue("target_pool")
	if disk == "" || pool == "" {
		sendToast(w, "disk and target pool are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	deleteSource := r.FormValue("delete_source") == "on"

	render := func(status, cleanup, errMsg string) {
		s.renderFragment(w, "move_volume_result.html", map[string]any{
			"VMName": name, "DiskName": disk, "Pool": pool,
			"Status": status, "Cleanup": cleanup, "Error": errMsg,
		})
	}

	stream, err := s.grpc.MoveVolume(s.uiBearerCtx(r), &pb.MoveVolumeRequest{
		VmName: name, DiskName: disk, TargetPool: pool, DeleteSource: deleteSource,
	})
	if err != nil {
		render("", "", err.Error())
		return
	}
	var lastStatus, cleanupStatus, streamErr string
	for {
		p, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			streamErr = rerr.Error()
			break
		}
		if p.Error != "" {
			streamErr = p.Error
		}
		// The CLEANUP frame reports the source-delete outcome; capture it
		// separately so the terminal DONE frame's status doesn't bury it.
		if p.Phase == pb.MoveVolumeProgress_CLEANUP && p.Status != "" {
			cleanupStatus = p.Status
		}
		if p.Status != "" {
			lastStatus = p.Status
		}
	}
	render(lastStatus, cleanupStatus, streamErr)
}

// movePhaseLabel maps a MoveVolumeProgress phase to a human label for the bar.
func movePhaseLabel(p pb.MoveVolumeProgress_Phase) string {
	switch p {
	case pb.MoveVolumeProgress_COPY:
		return "Copying"
	case pb.MoveVolumeProgress_MIRROR:
		return "Mirroring"
	case pb.MoveVolumeProgress_CUTOVER:
		return "Switching over"
	case pb.MoveVolumeProgress_CLEANUP:
		return "Cleaning up source"
	case pb.MoveVolumeProgress_DONE:
		return "Done"
	default:
		return "Working"
	}
}

// handleMoveVolumeStream drives a single-disk pool move and streams live
// progress to the browser as Server-Sent Events so the UI can show a progress
// bar (the gRPC stream already reports per-frame copy percent + bytes). Frames
// become `progress` events; completion is a `done` event; any failure is an
// `error` event. POST (it mutates) with form fields disk/target_pool/delete_source.
func (s *Server) handleMoveVolumeStream(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// Use FormValue (not an explicit ParseForm) so both url-encoded and
	// multipart bodies are parsed — a pre-emptive ParseForm leaves r.Form
	// non-nil and stops FormValue from parsing a multipart body.
	disk := r.FormValue("disk")
	pool := r.FormValue("target_pool")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// A live move runs for minutes; without this the 30s WriteTimeout would tear
	// the SSE connection down mid-copy and abort the block-copy. See helper.
	disableStreamWriteTimeout(w)

	sendEvent := func(event string, payload any) {
		data, _ := json.Marshal(payload)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
		flusher.Flush()
	}
	if disk == "" || pool == "" {
		sendEvent("error", "disk and target pool are required")
		return
	}

	stream, err := s.grpc.MoveVolume(s.uiBearerCtx(r), &pb.MoveVolumeRequest{
		VmName: name, DiskName: disk, TargetPool: pool,
		DeleteSource: r.FormValue("delete_source") == "on",
	})
	if err != nil {
		sendEvent("error", grpcMsg(err))
		return
	}

	var cleanupStatus string
	for {
		p, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			sendEvent("done", map[string]any{"vm": name, "disk": disk, "pool": pool, "cleanup": cleanupStatus})
			return
		}
		if rerr != nil {
			sendEvent("error", grpcMsg(rerr))
			return
		}
		if p.Error != "" {
			sendEvent("error", p.Error)
			return
		}
		if p.Phase == pb.MoveVolumeProgress_CLEANUP && p.Status != "" {
			cleanupStatus = p.Status
		}
		sendEvent("progress", map[string]any{
			"phase":  movePhaseLabel(p.Phase),
			"pct":    p.CopyPct,
			"copied": p.BytesCopied,
			"total":  p.BytesTotal,
			"status": p.Status,
		})
	}
}

// handleReplicateVolumeModal renders the per-disk "replicate to pool" form. Like
// Move, the target dropdown lists other pools on the VM's host; unlike Move the
// VM keeps using its source disk (a point-in-time copy is made for DR/off-site).
func (s *Server) handleReplicateVolumeModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	diskName := r.URL.Query().Get("disk")
	ctx := s.uiBearerCtx(r)
	vm, _ := s.grpc.InspectVM(ctx, &pb.InspectVMRequest{Name: name})
	host, current := "", ""
	if vm != nil {
		host = vm.HostName
		for _, d := range vm.Disks {
			if d.Name == diskName {
				current = d.StorageVolume
			}
		}
	}
	var pools []string
	resp, _ := s.grpc.ListStoragePools(ctx, &pb.ListStoragePoolsRequest{})
	for _, p := range resp.GetPools() {
		if p.Host == host && p.Name != current {
			pools = append(pools, p.Name)
		}
	}
	s.renderFragment(w, "replicate_volume_modal.html", map[string]any{
		"VMName": name, "DiskName": diskName, "CurrentPool": current, "Pools": pools,
	})
}

// handleReplicateVolume drives a single-disk replication via the ReplicateVolume
// RPC and renders the result. Mirrors `lv replicate-volume <vm> <disk> <pool>
// [--target-path]`.
func (s *Server) handleReplicateVolume(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	disk := r.FormValue("disk")
	pool := r.FormValue("target_pool")
	if disk == "" || pool == "" {
		sendToast(w, "disk and target pool are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	render := func(status, targetPath, errMsg string) {
		s.renderFragment(w, "replicate_volume_result.html", map[string]any{
			"VMName": name, "DiskName": disk, "Pool": pool,
			"Status": status, "TargetPath": targetPath, "Error": errMsg,
		})
	}

	stream, err := s.grpc.ReplicateVolume(s.uiBearerCtx(r), &pb.ReplicateVolumeRequest{
		VmName: name, DiskName: disk, TargetPool: pool,
		TargetPath: strings.TrimSpace(r.FormValue("target_path")),
	})
	if err != nil {
		render("", "", err.Error())
		return
	}
	var lastStatus, targetPath, streamErr string
	for {
		p, rerr := stream.Recv()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			streamErr = rerr.Error()
			break
		}
		if p.Error != "" {
			streamErr = p.Error
		}
		if p.Status != "" {
			lastStatus = p.Status
		}
		if p.TargetPath != "" {
			targetPath = p.TargetPath
		}
	}
	render(lastStatus, targetPath, streamErr)
}

func (s *Server) handleResizeDisk(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	sizeGiB, _ := strconv.Atoi(r.FormValue("size_gib"))
	if sizeGiB <= 0 {
		sendToast(w, "Invalid size", "error")
		w.WriteHeader(400)
		return
	}
	_, err := s.grpc.ResizeDisk(s.uiBearerCtx(r), &pb.ResizeDiskRequest{
		VmName:   name,
		DiskName: r.FormValue("disk_name"),
		Size:     fmt.Sprintf("%dG", sizeGiB),
	})
	if err != nil {
		sendToast(w, "Resize disk failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Disk resized to "+fmt.Sprintf("%dG", sizeGiB), "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDetachDisk(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	_, err := s.grpc.DetachDevice(s.uiBearerCtx(r), &pb.DetachDeviceRequest{
		VmName:   name,
		DiskName: r.FormValue("disk_name"),
	})
	if err != nil {
		sendToast(w, "Detach disk failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Disk detached", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAttachNIC(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	_, err := s.grpc.AttachDevice(s.uiBearerCtx(r), &pb.AttachDeviceRequest{
		VmName: name,
		Nic: &pb.NetworkAttachment{
			Name:  r.FormValue("bridge"),
			Model: r.FormValue("model"),
		},
	})
	if err != nil {
		sendToast(w, "Attach NIC failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "NIC attached", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDetachNIC(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	_, err := s.grpc.DetachDevice(s.uiBearerCtx(r), &pb.DetachDeviceRequest{
		VmName: name,
		NicMac: r.FormValue("nic_mac"),
	})
	if err != nil {
		sendToast(w, "Detach NIC failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "NIC detached", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAttachPCI(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	_, err := s.grpc.AttachDevice(s.uiBearerCtx(r), &pb.AttachDeviceRequest{
		VmName: name,
		PciDevice: &pb.DeviceSpec{
			Type:    r.FormValue("type"),
			Address: r.FormValue("address"),
		},
	})
	if err != nil {
		sendToast(w, "Attach PCI failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "PCI device attached", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleDetachPCI(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	_, err := s.grpc.DetachDevice(s.uiBearerCtx(r), &pb.DetachDeviceRequest{
		VmName:     name,
		PciAddress: r.FormValue("pci_address"),
	})
	if err != nil {
		sendToast(w, "Detach PCI failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "PCI device detached", "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleAvailableDevices(w http.ResponseWriter, r *http.Request) {
	hostName := r.PathValue("name")
	typeFilter := r.URL.Query().Get("type")
	resp, err := s.grpc.ListHostDevices(s.uiBearerCtx(r), &pb.ListHostDevicesRequest{
		Name:       hostName,
		TypeFilter: typeFilter,
	})
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<option value="" disabled>Error loading devices</option>`)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	var free []*pb.PCIDevice
	for _, d := range resp.GetDevices() {
		if d.VmName == "" {
			free = append(free, d)
		}
	}
	if len(free) == 0 {
		fmt.Fprintf(w, `<option value="" disabled>No %s devices available</option>`, typeFilter)
		return
	}
	for _, d := range free {
		fmt.Fprintf(w, `<option value="%s">%s — %s %s</option>`, d.Address, d.Address, d.VendorName, d.DeviceName)
	}
}

func (s *Server) handleCompatibleHosts(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := s.uiBearerCtx(r)
	vm, err := s.grpc.InspectVM(ctx, &pb.InspectVMRequest{Name: name})
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<span style="color:var(--muted);font-size:13px">Could not load host compatibility info.</span>`)
		return
	}
	hosts, _ := s.grpc.ListHosts(ctx, &pb.ListHostsRequest{})

	type hostCompat struct {
		Name       string
		Compatible bool
		Reason     string
	}
	var results []hostCompat
	deviceSpecs := vm.GetSpec().GetDevices()

	for _, h := range hosts.GetHosts() {
		if h.Name == vm.HostName {
			continue
		}
		if h.State != pb.HostState_HOST_ACTIVE {
			results = append(results, hostCompat{h.Name, false, "host not active"})
			continue
		}
		if len(deviceSpecs) == 0 {
			results = append(results, hostCompat{h.Name, true, ""})
			continue
		}
		compatible := true
		reason := ""
		for _, ds := range deviceSpecs {
			devResp, err := s.grpc.ListHostDevices(ctx, &pb.ListHostDevicesRequest{
				Name: h.Name, TypeFilter: ds.Type,
			})
			if err != nil {
				compatible = false
				reason = "cannot query devices"
				break
			}
			freeCount := int32(0)
			for _, d := range devResp.GetDevices() {
				if d.VmName == "" {
					freeCount++
				}
			}
			if freeCount < ds.Count {
				compatible = false
				reason = fmt.Sprintf("need %d %s, only %d free", ds.Count, ds.Type, freeCount)
				break
			}
		}
		results = append(results, hostCompat{h.Name, compatible, reason})
	}

	w.Header().Set("Content-Type", "text/html")
	for _, r := range results {
		if r.Compatible {
			fmt.Fprintf(w, `<div style="margin:4px 0"><span class="badge badge-green">%s</span></div>`, r.Name)
		} else {
			fmt.Fprintf(w, `<div style="margin:4px 0"><span class="badge badge-red">%s</span> <span style="color:#888;font-size:12px">%s</span></div>`, r.Name, r.Reason)
		}
	}
	if len(results) == 0 {
		fmt.Fprint(w, `<span style="color:#888;font-size:13px">No other hosts available</span>`)
	}
}

func (s *Server) handleAvailableDevicesJSON(w http.ResponseWriter, r *http.Request) {
	hostName := r.PathValue("name")
	typeFilter := r.URL.Query().Get("type")
	resp, err := s.grpc.ListHostDevices(s.uiBearerCtx(r), &pb.ListHostDevicesRequest{
		Name:       hostName,
		TypeFilter: typeFilter,
	})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var free []*pb.PCIDevice
	for _, d := range resp.GetDevices() {
		if d.VmName == "" {
			free = append(free, d)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(free)
}
