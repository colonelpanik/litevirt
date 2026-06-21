package ui

import (
	"fmt"
	"net/http"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type poolRow struct {
	Pool   *pb.StoragePool
	UsePct int
}

func (s *Server) handleStorage(w http.ResponseWriter, r *http.Request) {
	resp, err := s.grpc.ListStoragePools(s.uiBearerCtx(r), &pb.ListStoragePoolsRequest{})
	data := s.pageData("Storage", "storage")
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Pools"] = buildPoolRows(resp.GetPools())
	}
	s.renderPage(w, "storage.html", data)
}

func (s *Server) handleStorageTable(w http.ResponseWriter, r *http.Request) {
	resp, err := s.grpc.ListStoragePools(s.uiBearerCtx(r), &pb.ListStoragePoolsRequest{})
	data := map[string]any{"ClusterName": s.cluster}
	if err != nil {
		data["Error"] = err.Error()
	} else {
		data["Pools"] = buildPoolRows(resp.GetPools())
	}
	s.renderPartial(w, "storage.html", "storage-table", data)
}

func buildPoolRows(pools []*pb.StoragePool) []poolRow {
	rows := make([]poolRow, 0, len(pools))
	for _, p := range pools {
		pct := 0
		if p.TotalBytes > 0 {
			pct = int(p.UsedBytes * 100 / p.TotalBytes)
		}
		rows = append(rows, poolRow{Pool: p, UsePct: pct})
	}
	return rows
}

// handleCreatePoolModal renders the "Create pool" form. Mirrors `lv pool create`:
// name, driver, source, target, per-host placement, and repeatable key=value
// driver options.
func (s *Server) handleCreatePoolModal(w http.ResponseWriter, r *http.Request) {
	var hosts []string
	resp, _ := s.grpc.ListHosts(s.uiBearerCtx(r), &pb.ListHostsRequest{})
	for _, h := range resp.GetHosts() {
		hosts = append(hosts, h.Name)
	}
	s.renderFragment(w, "storage_create_modal.html", map[string]any{
		"Drivers": []string{"local", "dir", "nfs", "iscsi", "ceph", "zfs", "btrfs", "lvm-thin"},
		"Hosts":   hosts,
	})
}

// handleCreatePool wires the modal to the CreateStoragePool RPC. The daemon runs
// the driver's Prepare() hook before persisting, so a mount failure surfaces here.
func (s *Server) handleCreatePool(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	driver := r.FormValue("driver")
	if name == "" || driver == "" {
		sendToast(w, "Pool name and driver are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	opts, err := parsePoolOptionLines(r.FormValue("options"))
	if err != nil {
		sendToast(w, err.Error(), "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	req := &pb.CreateStoragePoolRequest{
		Name:    name,
		Driver:  driver,
		Source:  strings.TrimSpace(r.FormValue("source")),
		Target:  strings.TrimSpace(r.FormValue("target")),
		Host:    r.FormValue("host"),
		Options: opts,
	}
	if _, err := s.grpc.CreateStoragePool(s.uiBearerCtx(r), req); err != nil {
		sendToast(w, "Create pool failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Pool '"+name+"' created", "success")
	w.Header().Set("HX-Redirect", "/storage")
	w.WriteHeader(http.StatusOK)
}

// handleDeletePool soft-deletes a pool (best-effort driver teardown), mirroring
// `lv pool delete`. The owning host is carried so the daemon forwards correctly.
func (s *Server) handleDeletePool(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	host := r.URL.Query().Get("host")
	if _, err := s.grpc.DeleteStoragePool(s.uiBearerCtx(r), &pb.DeleteStoragePoolRequest{Name: name, Host: host}); err != nil {
		sendToast(w, "Delete pool failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sendToast(w, "Pool '"+name+"' deleted", "success")
	w.Header().Set("HX-Redirect", "/storage")
	w.WriteHeader(http.StatusOK)
}

// parsePoolOptionLines turns a textarea of "key=value" lines into a map, the UI
// analogue of the CLI's repeatable --option flag. Blank lines are ignored; a
// malformed line fails loudly so a typo doesn't silently drop a driver flag.
func parsePoolOptionLines(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i <= 0 || i == len(line)-1 {
			return nil, fmt.Errorf("option %q: want key=value", line)
		}
		out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
