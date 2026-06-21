package ui

import (
	"errors"
	"io"
	"log/slog"
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleStacks(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	stacks, _ := s.grpc.ListStacks(ctx, &emptypb.Empty{})
	data := s.pageData("Stacks", "stacks")
	data["Stacks"] = stacks.GetStacks()
	s.renderPage(w, "stacks.html", data)
}

func (s *Server) handleStackDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := s.uiBearerCtx(r)

	stacks, _ := s.grpc.ListStacks(ctx, &emptypb.Empty{})
	vms, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{})
	lbs, _ := s.grpc.ListLoadBalancers(ctx, &emptypb.Empty{})

	// Find the stack.
	var stack *pb.StackSummary
	for _, st := range stacks.GetStacks() {
		if st.Name == name {
			stack = st
			break
		}
	}
	if stack == nil {
		http.Error(w, "Stack not found", http.StatusNotFound)
		return
	}

	// Filter VMs by stack.
	var stackVMs []*pb.VM
	for _, vm := range vms.GetVms() {
		if vm.StackName == name {
			stackVMs = append(stackVMs, vm)
		}
	}

	// Find LB for this stack (convention: <stack>-lb).
	lbName := name + "-lb"
	var stackLB *pb.LoadBalancer
	for _, l := range lbs.GetLbs() {
		if l.Name == lbName {
			stackLB = l
			break
		}
	}

	data := s.pageData(name, "stacks")
	data["Stack"] = stack
	data["VMs"] = stackVMs
	data["LB"] = stackLB
	s.renderPage(w, "stack_detail.html", data)
}

func (s *Server) handleStackExport(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	resp, err := s.grpc.ExportStack(s.uiBearerCtx(r), &pb.ExportStackRequest{Name: name})
	if err != nil {
		http.Error(w, "Export failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", "attachment; filename="+name+".yaml")
	w.Write([]byte(resp.ComposeYaml))
}

func (s *Server) handleDeployStackModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "deploy_stack_modal.html", nil)
}

func (s *Server) handleDeployStack(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	yaml := r.FormValue("compose_yaml")
	if yaml == "" {
		http.Error(w, "compose YAML required", 400)
		return
	}
	stream, err := s.grpc.DeployStack(s.uiBearerCtx(r), &pb.DeployStackRequest{
		ComposeYaml: yaml,
	})
	if err != nil {
		slog.Error("UI: deploy stack failed", "error", err)
		sendToast(w, "Deploy failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}

	// Consume the stream to completion so the deployment actually runs.
	var lastErr string
	for {
		p, err := stream.Recv()
		if err != nil {
			break
		}
		if p.Error != "" {
			lastErr = p.Error
		}
	}
	if lastErr != "" {
		slog.Error("UI: deploy stream error", "error", lastErr)
		sendToast(w, "Deploy error: "+lastErr, "error")
		w.WriteHeader(500)
		return
	}

	w.Header().Set("HX-Redirect", "/stacks")
	sendToast(w, "Stack deployed", "success")
	w.WriteHeader(http.StatusOK)
}

// handlePlanPreview calls DiffStack (which runs the full planner) and renders
// the plan preview fragment inside the deploy modal.
func (s *Server) handlePlanPreview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	yaml := r.FormValue("compose_yaml")
	if yaml == "" {
		http.Error(w, "compose YAML required", 400)
		return
	}

	resp, err := s.grpc.DiffStack(s.uiBearerCtx(r), &pb.DiffStackRequest{ComposeYaml: yaml})
	if err != nil {
		slog.Error("UI: plan preview failed", "error", err)
		http.Error(w, "Plan failed: "+err.Error(), 500)
		return
	}

	// Categorize entries by phase prefix for the template.
	type entry struct {
		Kind, Name, Detail string
	}
	var warnings, networks, vms, lbs, dns []entry
	for _, e := range resp.GetEntries() {
		kind := e.Operation.String()
		row := entry{Kind: kind, Name: e.VmName, Detail: e.Detail}

		switch {
		case len(e.Detail) > 1 && e.Detail[0] == 0xe2 && e.Detail[1] == 0x9a: // ⚠ warning
			warnings = append(warnings, row)
		case len(e.Detail) > 7 && e.Detail[:7] == "network":
			networks = append(networks, row)
		case len(e.Detail) > 2 && e.Detail[:2] == "lb":
			lbs = append(lbs, row)
		case len(e.Detail) > 3 && e.Detail[:3] == "dns":
			dns = append(dns, row)
		default:
			vms = append(vms, row)
		}
	}

	data := map[string]any{
		"Warnings": warnings,
		"Networks": networks,
		"VMs":      vms,
		"LBs":      lbs,
		"DNS":      dns,
	}
	s.renderFragment(w, "plan_preview.html", data)
}

func (s *Server) handleDestroyStack(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	stream, err := s.grpc.DeleteStack(s.uiBearerCtx(r), &pb.DeleteStackRequest{Name: name})
	if err != nil {
		slog.Error("UI: destroy stack failed", "error", err)
		sendToast(w, "Destroy failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}

	// Consume the stream to completion.
	for {
		if _, err := stream.Recv(); err != nil {
			break
		}
	}

	w.Header().Set("HX-Redirect", "/stacks")
	sendToast(w, "Stack '"+name+"' destroyed", "success")
	w.WriteHeader(http.StatusOK)
}

// handleMigrateVolumesModal renders the "migrate volumes" form for a stack:
// a default-pool picker plus a per-VM override table, populated from the
// configured storage pools.
func (s *Server) handleMigrateVolumesModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := s.uiBearerCtx(r)

	vmsResp, _ := s.grpc.ListVMs(ctx, &pb.ListVMsRequest{})
	var stackVMs []*pb.VM
	for _, vm := range vmsResp.GetVms() {
		if vm.StackName == name {
			stackVMs = append(stackVMs, vm)
		}
	}

	poolsResp, _ := s.grpc.ListStoragePools(ctx, &pb.ListStoragePoolsRequest{})
	seen := map[string]bool{}
	var pools []string
	for _, p := range poolsResp.GetPools() {
		if p.Name != "" && !seen[p.Name] {
			seen[p.Name] = true
			pools = append(pools, p.Name)
		}
	}

	s.renderFragment(w, "migrate_volumes_modal.html", map[string]any{
		"Stack": name,
		"VMs":   stackVMs,
		"Pools": pools,
	})
}

// migrateRow is one line in the migrate-volumes result table.
type migrateRow struct {
	VM, Disk, Stage, Status, Error string
	OK                             bool
}

// handleMigrateStackVolumes runs (or previews) a stack volume migration and
// renders a per-disk result table. It consumes the streaming RPC to
// completion so the migration actually executes.
func (s *Server) handleMigrateStackVolumes(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	defaultPool := r.FormValue("default_pool")
	deleteSource := r.FormValue("delete_source") == "on"
	dryRun := r.FormValue("dry_run") == "on"

	var placements []*pb.VolumePlacement
	vmsResp, _ := s.grpc.ListVMs(s.uiBearerCtx(r), &pb.ListVMsRequest{})
	for _, vm := range vmsResp.GetVms() {
		if vm.StackName != name {
			continue
		}
		if p := r.FormValue("pool_" + vm.Name); p != "" {
			placements = append(placements, &pb.VolumePlacement{VmName: vm.Name, TargetPool: p})
		}
	}
	if defaultPool == "" && len(placements) == 0 {
		sendToast(w, "Choose a default pool or at least one per-VM target", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	stream, err := s.grpc.MigrateStackVolumes(s.uiBearerCtx(r), &pb.MigrateStackVolumesRequest{
		StackName:    name,
		DefaultPool:  defaultPool,
		Placements:   placements,
		DeleteSource: deleteSource,
		DryRun:       dryRun,
	})
	if err != nil {
		slog.Error("UI: migrate stack volumes failed", "error", err)
		sendToast(w, "Migration failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var rows []migrateRow
	for {
		p, err := stream.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				rows = append(rows, migrateRow{Stage: "error", Error: err.Error()})
			}
			break
		}
		switch p.Stage {
		case pb.StackVolumeProgress_PLANNING:
			if p.VmName != "" {
				rows = append(rows, migrateRow{VM: p.VmName, Disk: p.DiskName, Stage: "plan", Status: p.Status, OK: true})
			} else {
				rows = append(rows, migrateRow{Stage: "plan", Status: p.Status, OK: true})
			}
		case pb.StackVolumeProgress_PER_DISK:
			if p.Phase == "DONE" {
				rows = append(rows, migrateRow{VM: p.VmName, Disk: p.DiskName, Stage: "moved", Status: p.Status, OK: true})
			}
		case pb.StackVolumeProgress_SKIPPED:
			rows = append(rows, migrateRow{VM: p.VmName, Disk: p.DiskName, Stage: "skipped", Status: p.Status, OK: true})
		case pb.StackVolumeProgress_VM_DONE:
			rows = append(rows, migrateRow{VM: p.VmName, Stage: "vm-done", Status: p.Status, OK: true})
		case pb.StackVolumeProgress_ERROR:
			rows = append(rows, migrateRow{VM: p.VmName, Disk: p.DiskName, Stage: "error", Status: p.Status, Error: p.Error, OK: false})
		case pb.StackVolumeProgress_COMPLETE:
			rows = append(rows, migrateRow{Stage: "complete", Status: p.Status, OK: true})
		}
	}

	s.renderFragment(w, "migrate_volumes_result.html", map[string]any{
		"Stack":  name,
		"Rows":   rows,
		"DryRun": dryRun,
	})
}
