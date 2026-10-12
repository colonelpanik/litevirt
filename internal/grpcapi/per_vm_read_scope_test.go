package grpcapi

import (
	"context"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Follow-up to commit 4b7374af (ListVMs/InspectVM): several more per-VM and
// per-container read RPCs checked only a cluster-wide viewer floor
// (RequireRole), so a caller whose binding or token scope covered one
// project could read every VM/container in the cluster through them —
// GetVMStats, GetHostStats, ListSnapshots, ListVMEvents, ListVMHardware,
// ListContainerSnapshots, ListBackupSchedules, ListReplicationSchedules and
// GetVMLogs. These pin the read side to the same per-resource path the
// writes use (vm.read / ct.read / backup.read on the resource's own RBAC
// path), mirroring vm_read_scope_test.go's shape.

// seedPVRScopedVMs puts one VM in each of three projects, all on s's host,
// with s.virt (libvirtfake) wired so stats RPCs don't nil-dereference.
func seedPVRScopedVMs(t *testing.T, s *Server) {
	t.Helper()
	if s.virt == nil {
		s.virt = libvirtfake.New()
	}
	fake := s.virt.(*libvirtfake.Fake)
	for _, v := range []struct{ name, project string }{
		{"a1", "acme"}, {"a2", "acme"}, {"b1", "beta"}, {"d1", ""},
	} {
		if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
			Name: v.name, HostName: s.hostName, State: "running", Project: v.project,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", v.name, err)
		}
		fake.SetState(v.name, libvirtfake.StateRunning)
	}
}

// --- GetVMStats ---

func TestGetVMStats_ScopedCallerSeesOnlyItsProject(t *testing.T) {
	s := testServer(t)
	seedPVRScopedVMs(t, s)
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	if _, err := s.GetVMStats(acme, &pb.GetVMStatsRequest{Name: "a1"}); err != nil {
		t.Errorf("in-scope GetVMStats(a1): %v", err)
	}
	for _, name := range []string{"b1", "d1"} {
		_, err := s.GetVMStats(acme, &pb.GetVMStatsRequest{Name: name})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("GetVMStats(%s) (out of scope): %v, want PermissionDenied", name, err)
		}
	}
}

func TestGetVMStats_ClusterWideCallersUnchanged(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedPVRScopedVMs(t, s)
			ctx := mk(s)
			for _, vm := range []string{"a1", "b1", "d1"} {
				if _, err := s.GetVMStats(ctx, &pb.GetVMStatsRequest{Name: vm}); err != nil {
					t.Errorf("GetVMStats(%s): %v", vm, err)
				}
			}
		})
	}
}

// Foreign VM and a name that exists nowhere must answer alike (same shape as
// TestInspectVM_AScopedCallerCannotTellWhetherAForeignVMExists in 4b7374af).
func TestGetVMStats_ExistenceNotLeaked(t *testing.T) {
	holder := testServer(t)
	seedPVRScopedVMs(t, holder)
	lacker := testServer(t)
	lacker.virt = libvirtfake.New()

	_, present := holder.GetVMStats(grantUser(t, holder, "carol", "/projects/acme", "Viewer"), &pb.GetVMStatsRequest{Name: "b1"})
	_, absent := lacker.GetVMStats(grantUser(t, lacker, "carol", "/projects/acme", "Viewer"), &pb.GetVMStatsRequest{Name: "b1"})

	if status.Code(present) != codes.PermissionDenied {
		t.Fatalf("foreign VM: %v, want PermissionDenied", present)
	}
	if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
		t.Errorf("existence leaked:\n  present: %v\n  absent:  %v", present, absent)
	}
}

// --- GetHostStats ---

func TestGetHostStats_FiltersPerVMEntries(t *testing.T) {
	s := testServer(t)
	seedPVRScopedVMs(t, s)
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	resp, err := s.GetHostStats(acme, &pb.GetHostStatsRequest{})
	if err != nil {
		t.Fatalf("GetHostStats: %v", err)
	}
	var names []string
	for _, vs := range resp.VmStats {
		names = append(names, vs.Name)
	}
	if len(names) != 2 || !containsAll(names, "a1", "a2") {
		t.Errorf("VmStats names = %v, want exactly [a1 a2]", names)
	}
}

func TestGetHostStats_ClusterWideCallersSeeEveryVM(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedPVRScopedVMs(t, s)
			ctx := mk(s)
			resp, err := s.GetHostStats(ctx, &pb.GetHostStatsRequest{})
			if err != nil {
				t.Fatalf("GetHostStats: %v", err)
			}
			if len(resp.VmStats) != 4 {
				t.Errorf("VmStats = %d entries, want 4", len(resp.VmStats))
			}
		})
	}
}

func containsAll(got []string, want ...string) bool {
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

// --- ListSnapshots ---

func TestListSnapshots_ScopedCallerSeesOnlyItsProject(t *testing.T) {
	s := testServer(t)
	seedPVRScopedVMs(t, s)
	corrosion.InsertSnapshot(context.Background(), s.db, corrosion.SnapshotRecord{VMName: "a1", HostName: s.hostName, Name: "s1", State: "ok"})
	corrosion.InsertSnapshot(context.Background(), s.db, corrosion.SnapshotRecord{VMName: "b1", HostName: s.hostName, Name: "s1", State: "ok"})
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	resp, err := s.ListSnapshots(acme, &pb.ListSnapshotsRequest{VmName: "a1"})
	if err != nil || len(resp.Snapshots) != 1 {
		t.Fatalf("in-scope ListSnapshots(a1): resp=%v err=%v", resp, err)
	}
	if _, err := s.ListSnapshots(acme, &pb.ListSnapshotsRequest{VmName: "b1"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ListSnapshots(b1) (out of scope): %v, want PermissionDenied", err)
	}
}

func TestListSnapshots_ClusterWideCallersUnchanged(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedPVRScopedVMs(t, s)
			ctx := mk(s)
			for _, vm := range []string{"a1", "b1", "d1"} {
				if _, err := s.ListSnapshots(ctx, &pb.ListSnapshotsRequest{VmName: vm}); err != nil {
					t.Errorf("ListSnapshots(%s): %v", vm, err)
				}
			}
		})
	}
}

func TestListSnapshots_ExistenceNotLeaked(t *testing.T) {
	holder := testServer(t)
	seedPVRScopedVMs(t, holder)
	lacker := testServer(t)

	_, present := holder.ListSnapshots(grantUser(t, holder, "carol", "/projects/acme", "Viewer"), &pb.ListSnapshotsRequest{VmName: "b1"})
	_, absent := lacker.ListSnapshots(grantUser(t, lacker, "carol", "/projects/acme", "Viewer"), &pb.ListSnapshotsRequest{VmName: "b1"})

	if status.Code(present) != codes.PermissionDenied {
		t.Fatalf("foreign VM: %v, want PermissionDenied", present)
	}
	if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
		t.Errorf("existence leaked:\n  present: %v\n  absent:  %v", present, absent)
	}
}

// --- ListVMHardware ---

func TestListVMHardware_ScopedCallerSeesOnlyItsProject(t *testing.T) {
	s := testServer(t)
	seedPVRScopedVMs(t, s)
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	if _, err := s.ListVMHardware(acme, &pb.ListVMHardwareRequest{VmName: "a1"}); err != nil {
		t.Errorf("in-scope ListVMHardware(a1): %v", err)
	}
	if _, err := s.ListVMHardware(acme, &pb.ListVMHardwareRequest{VmName: "b1"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ListVMHardware(b1) (out of scope): %v, want PermissionDenied", err)
	}
}

func TestListVMHardware_ClusterWideCallersUnchanged(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedPVRScopedVMs(t, s)
			ctx := mk(s)
			for _, vm := range []string{"a1", "b1", "d1"} {
				if _, err := s.ListVMHardware(ctx, &pb.ListVMHardwareRequest{VmName: vm}); err != nil {
					t.Errorf("ListVMHardware(%s): %v", vm, err)
				}
			}
		})
	}
}

func TestListVMHardware_ExistenceNotLeaked(t *testing.T) {
	holder := testServer(t)
	seedPVRScopedVMs(t, holder)
	lacker := testServer(t)

	_, present := holder.ListVMHardware(grantUser(t, holder, "carol", "/projects/acme", "Viewer"), &pb.ListVMHardwareRequest{VmName: "b1"})
	_, absent := lacker.ListVMHardware(grantUser(t, lacker, "carol", "/projects/acme", "Viewer"), &pb.ListVMHardwareRequest{VmName: "b1"})

	if status.Code(present) != codes.PermissionDenied {
		t.Fatalf("foreign VM: %v, want PermissionDenied", present)
	}
	if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
		t.Errorf("existence leaked:\n  present: %v\n  absent:  %v", present, absent)
	}
}

// --- ListVMEvents ---

func seedPVREvents(t *testing.T, s *Server) {
	t.Helper()
	for _, v := range []string{"a1", "b1", "d1"} {
		if err := corrosion.InsertVMEvent(context.Background(), s.db, corrosion.VMEventRecord{
			VMName: v, HostName: s.hostName, Type: "vm.started", Result: "ok",
		}); err != nil {
			t.Fatalf("InsertVMEvent(%s): %v", v, err)
		}
	}
}

func TestListVMEvents_ScopedCallerSeesOnlyItsProject_SingleVM(t *testing.T) {
	s := testServer(t)
	seedPVRScopedVMs(t, s)
	seedPVREvents(t, s)
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	resp, err := s.ListVMEvents(acme, &pb.ListVMEventsRequest{VmName: "a1"})
	if err != nil || len(resp.Events) != 1 {
		t.Fatalf("in-scope ListVMEvents(a1): resp=%v err=%v", resp, err)
	}
	if _, err := s.ListVMEvents(acme, &pb.ListVMEventsRequest{VmName: "b1"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ListVMEvents(b1) (out of scope): %v, want PermissionDenied", err)
	}
}

// ListVMEvents with an empty vm_name is the cluster-wide activity mode
// (corrosion.ListVMEvents's doc comment) — each row must be filtered the same
// way the single-VM form is.
func TestListVMEvents_ScopedCallerSeesOnlyItsProject_ClusterWide(t *testing.T) {
	s := testServer(t)
	seedPVRScopedVMs(t, s)
	seedPVREvents(t, s)
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	resp, err := s.ListVMEvents(acme, &pb.ListVMEventsRequest{})
	if err != nil {
		t.Fatalf("ListVMEvents(cluster-wide): %v", err)
	}
	for _, ev := range resp.Events {
		if ev.VmName != "a1" {
			t.Errorf("cluster-wide events included %q, a VM outside the caller's scope", ev.VmName)
		}
	}
	if len(resp.Events) != 1 {
		t.Errorf("got %d events, want 1 (only a1's)", len(resp.Events))
	}
}

func TestListVMEvents_ClusterWideCallersUnchanged(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedPVRScopedVMs(t, s)
			seedPVREvents(t, s)
			ctx := mk(s)
			resp, err := s.ListVMEvents(ctx, &pb.ListVMEventsRequest{})
			if err != nil {
				t.Fatalf("ListVMEvents(cluster-wide): %v", err)
			}
			if len(resp.Events) != 3 {
				t.Errorf("got %d events, want 3 (every VM's)", len(resp.Events))
			}
		})
	}
}

// Foreign VM and a name that exists nowhere must answer alike (single-VM
// mode) — the same shape every other single-VM read RPC's existence-not-leaked
// test already pins.
func TestListVMEvents_ExistenceNotLeaked(t *testing.T) {
	holder := testServer(t)
	seedPVRScopedVMs(t, holder)
	seedPVREvents(t, holder)
	lacker := testServer(t)

	_, present := holder.ListVMEvents(grantUser(t, holder, "carol", "/projects/acme", "Viewer"), &pb.ListVMEventsRequest{VmName: "b1"})
	_, absent := lacker.ListVMEvents(grantUser(t, lacker, "carol", "/projects/acme", "Viewer"), &pb.ListVMEventsRequest{VmName: "b1"})

	if status.Code(present) != codes.PermissionDenied {
		t.Fatalf("foreign VM: %v, want PermissionDenied", present)
	}
	if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
		t.Errorf("existence leaked:\n  present: %v\n  absent:  %v", present, absent)
	}
}

// TestListVMEvents_ClusterWidePaginationDoesNotStarveInScopeRows is the
// review-round regression: the cluster-wide activity mode applied corrosion's
// `LIMIT` in SQL BEFORE the per-row RBAC filter, so if the newest rows in the
// whole table happened to be a foreign project's, a scoped caller's own
// (merely older) in-scope events never got read at all — an empty or
// short page even though plenty of in-scope rows exist further back.
// Five "beta" events are seeded strictly newer than three "acme" ones; a
// caller scoped to acme asking for limit=3 must still get all three of its
// own events, not zero.
func TestListVMEvents_ClusterWidePaginationDoesNotStarveInScopeRows(t *testing.T) {
	s := testServer(t)
	seedPVRScopedVMs(t, s)
	ctx := context.Background()
	// Newest-first ordering (ts DESC): beta's 5 rows sort entirely ahead of
	// acme's 3, so a naive `LIMIT 3` reads only beta's rows.
	for i, ts := range []string{
		"2026-01-01T00:00:15.000000000Z", "2026-01-01T00:00:14.000000000Z",
		"2026-01-01T00:00:13.000000000Z", "2026-01-01T00:00:12.000000000Z",
		"2026-01-01T00:00:11.000000000Z",
	} {
		if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{
			ID: "beta-" + string(rune('a'+i)), VMName: "b1", HostName: s.hostName,
			Type: "vm.started", Result: "ok", TS: ts,
		}); err != nil {
			t.Fatalf("InsertVMEvent(beta %d): %v", i, err)
		}
	}
	for i, ts := range []string{
		"2026-01-01T00:00:03.000000000Z", "2026-01-01T00:00:02.000000000Z",
		"2026-01-01T00:00:01.000000000Z",
	} {
		if err := corrosion.InsertVMEvent(ctx, s.db, corrosion.VMEventRecord{
			ID: "acme-" + string(rune('a'+i)), VMName: "a1", HostName: s.hostName,
			Type: "vm.started", Result: "ok", TS: ts,
		}); err != nil {
			t.Fatalf("InsertVMEvent(acme %d): %v", i, err)
		}
	}
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	resp, err := s.ListVMEvents(acme, &pb.ListVMEventsRequest{Limit: 3})
	if err != nil {
		t.Fatalf("ListVMEvents: %v", err)
	}
	if len(resp.Events) != 3 {
		t.Fatalf("got %d events, want 3 (acme's full page, not starved by beta's newer rows)", len(resp.Events))
	}
	for _, ev := range resp.Events {
		if ev.VmName != "a1" {
			t.Errorf("page included %q, outside the caller's scope", ev.VmName)
		}
	}
}

// --- ListContainerSnapshots ---

func seedPVRScopedContainers(t *testing.T, s *Server) {
	t.Helper()
	for _, v := range []struct{ name, project string }{
		{"ca1", "acme"}, {"cb1", "beta"},
	} {
		if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
			HostName: s.hostName, Name: v.name, State: "running", Image: "alpine:3.19", Project: v.project,
		}); err != nil {
			t.Fatalf("UpsertContainer(%s): %v", v.name, err)
		}
	}
}

func TestListContainerSnapshots_ScopedCallerSeesOnlyItsProject(t *testing.T) {
	s := testServer(t)
	seedPVRScopedContainers(t, s)
	corrosion.InsertContainerSnapshot(context.Background(), s.db, corrosion.ContainerSnapshotRecord{
		CtName: "ca1", HostName: s.hostName, Name: "s1", State: "ok", Type: "tar",
	})
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	resp, err := s.ListContainerSnapshots(acme, &pb.ListContainerSnapshotsRequest{Name: "ca1", HostName: s.hostName})
	if err != nil || len(resp.Snapshots) != 1 {
		t.Fatalf("in-scope ListContainerSnapshots(ca1): resp=%v err=%v", resp, err)
	}
	if _, err := s.ListContainerSnapshots(acme, &pb.ListContainerSnapshotsRequest{Name: "cb1", HostName: s.hostName}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ListContainerSnapshots(cb1) (out of scope): %v, want PermissionDenied", err)
	}
}

func TestListContainerSnapshots_ClusterWideCallersUnchanged(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedPVRScopedContainers(t, s)
			ctx := mk(s)
			for _, ct := range []string{"ca1", "cb1"} {
				if _, err := s.ListContainerSnapshots(ctx, &pb.ListContainerSnapshotsRequest{Name: ct, HostName: s.hostName}); err != nil {
					t.Errorf("ListContainerSnapshots(%s): %v", ct, err)
				}
			}
		})
	}
}

func TestListContainerSnapshots_ExistenceNotLeaked(t *testing.T) {
	holder := testServer(t)
	seedPVRScopedContainers(t, holder)
	lacker := testServer(t)

	_, present := holder.ListContainerSnapshots(grantUser(t, holder, "carol", "/projects/acme", "Viewer"), &pb.ListContainerSnapshotsRequest{Name: "cb1", HostName: holder.hostName})
	_, absent := lacker.ListContainerSnapshots(grantUser(t, lacker, "carol", "/projects/acme", "Viewer"), &pb.ListContainerSnapshotsRequest{Name: "cb1", HostName: lacker.hostName})

	if status.Code(present) != codes.PermissionDenied {
		t.Fatalf("foreign container: %v, want PermissionDenied", present)
	}
	if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
		t.Errorf("existence leaked:\n  present: %v\n  absent:  %v", present, absent)
	}
}

// TestListContainerSnapshots_BackupOperatorCanListInScope is the review-round
// ruling: BackupOperator (backup.*, snapshot.*, vm.read — no ct.read) can
// create, restore and delete container snapshots (SnapshotContainer /
// RevertContainerSnapshot / DeleteContainerSnapshot all check snapshot.create
// / snapshot.restore / snapshot.delete), but had lost the ability to LIST
// them, since ListContainerSnapshots admitted only ct.read. It now admits
// ct.read OR snapshot.read on the container's path — BackupOperator holds
// snapshot.* (matches snapshot.read), so it can list what it can otherwise
// fully manage.
func TestListContainerSnapshots_BackupOperatorCanListInScope(t *testing.T) {
	s := testServer(t)
	seedPVRScopedContainers(t, s)
	corrosion.InsertContainerSnapshot(context.Background(), s.db, corrosion.ContainerSnapshotRecord{
		CtName: "ca1", HostName: s.hostName, Name: "s1", State: "ok", Type: "tar",
	})
	backupOp := grantUser(t, s, "bob", "/projects/acme", "BackupOperator")

	resp, err := s.ListContainerSnapshots(backupOp, &pb.ListContainerSnapshotsRequest{Name: "ca1", HostName: s.hostName})
	if err != nil || len(resp.Snapshots) != 1 {
		t.Fatalf("BackupOperator in-scope ListContainerSnapshots(ca1): resp=%v err=%v", resp, err)
	}
}

// TestListContainerSnapshots_BackupOperatorStillScopedPerContainer: the OR
// above must not widen BackupOperator's reach past its own binding — a
// BackupOperator scoped to acme still cannot list a container in another
// project through the snapshot.read fallback.
func TestListContainerSnapshots_BackupOperatorStillScopedPerContainer(t *testing.T) {
	s := testServer(t)
	seedPVRScopedContainers(t, s)
	backupOp := grantUser(t, s, "bob", "/projects/acme", "BackupOperator")

	if _, err := s.ListContainerSnapshots(backupOp, &pb.ListContainerSnapshotsRequest{Name: "cb1", HostName: s.hostName}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("BackupOperator listing a foreign project's container (cb1): %v, want PermissionDenied", err)
	}
}

// --- ListBackupSchedules / ListReplicationSchedules ---

func seedPVRSchedules(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	// vm-scoped, one per project.
	for _, r := range []corrosion.BackupScheduleRecord{
		{VMName: "a1", Scope: "vm", Repo: "repo-a", Cron: "@daily", Type: "backup"},
		{VMName: "b1", Scope: "vm", Repo: "repo-b", Cron: "@daily", Type: "backup"},
		{VMName: "a1", Scope: "vm", Repo: "repl-a", Cron: "@daily", Type: "replication", TargetPool: "pool-x"},
		{VMName: "b1", Scope: "vm", Repo: "repl-b", Cron: "@daily", Type: "replication", TargetPool: "pool-x"},
		// cluster-scoped: visible only to a root/legacy caller.
		{VMName: corrosion.ScheduleKey("cluster", "", "", ""), Scope: "cluster", Repo: "repo-c", Cron: "@daily", Type: "backup"},
	} {
		if err := corrosion.UpsertBackupSchedule(ctx, s.db, r); err != nil {
			t.Fatalf("UpsertBackupSchedule(%+v): %v", r, err)
		}
	}
}

func TestListBackupSchedules_ScopedCallerSeesOnlyItsProject(t *testing.T) {
	s := testServer(t)
	seedPVRScopedVMs(t, s)
	seedPVRSchedules(t, s)
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	resp, err := s.ListBackupSchedules(acme, &pb.ListBackupSchedulesRequest{})
	if err != nil {
		t.Fatalf("ListBackupSchedules: %v", err)
	}
	if len(resp.Schedules) != 1 || resp.Schedules[0].VmName != "a1" {
		t.Errorf("schedules = %+v, want exactly a1's", resp.Schedules)
	}
}

func TestListBackupSchedules_ClusterWideCallersUnchanged(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedPVRScopedVMs(t, s)
			seedPVRSchedules(t, s)
			ctx := mk(s)
			resp, err := s.ListBackupSchedules(ctx, &pb.ListBackupSchedulesRequest{})
			if err != nil {
				t.Fatalf("ListBackupSchedules: %v", err)
			}
			if len(resp.Schedules) != 3 {
				t.Errorf("got %d schedules, want 3 (a1, b1, cluster)", len(resp.Schedules))
			}
		})
	}
}

func TestListReplicationSchedules_ScopedCallerSeesOnlyItsProject(t *testing.T) {
	s := testServer(t)
	seedPVRScopedVMs(t, s)
	seedPVRSchedules(t, s)
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	resp, err := s.ListReplicationSchedules(acme, &pb.ListReplicationSchedulesRequest{})
	if err != nil {
		t.Fatalf("ListReplicationSchedules: %v", err)
	}
	if len(resp.Schedules) != 1 || resp.Schedules[0].VmName != "a1" {
		t.Errorf("schedules = %+v, want exactly a1's", resp.Schedules)
	}
}

func TestListReplicationSchedules_ClusterWideCallersUnchanged(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			seedPVRScopedVMs(t, s)
			seedPVRSchedules(t, s)
			ctx := mk(s)
			resp, err := s.ListReplicationSchedules(ctx, &pb.ListReplicationSchedulesRequest{})
			if err != nil {
				t.Fatalf("ListReplicationSchedules: %v", err)
			}
			if len(resp.Schedules) != 2 {
				t.Errorf("got %d schedules, want 2 (a1, b1)", len(resp.Schedules))
			}
		})
	}
}

// --- GetVMLogs ---

func TestGetVMLogs_ScopedCallerSeesOnlyItsProject(t *testing.T) {
	s, logDir := logsTestServer(t)
	seedPVRScopedVMs(t, s)
	writeTestLog(t, logDir, "a1")
	writeTestLog(t, logDir, "b1")
	acme := grantUser(t, s, "carol", "/projects/acme", "Viewer")

	stream := &fakeLogStream{ctx: acme}
	if err := s.GetVMLogs(&pb.GetVMLogsRequest{Name: "a1", Lines: 1}, stream); err != nil {
		t.Errorf("in-scope GetVMLogs(a1): %v", err)
	}

	stream = &fakeLogStream{ctx: acme}
	err := s.GetVMLogs(&pb.GetVMLogsRequest{Name: "b1", Lines: 1}, stream)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("GetVMLogs(b1) (out of scope): %v, want PermissionDenied", err)
	}
}

func writeTestLog(t *testing.T, logDir, vmName string) {
	t.Helper()
	if err := os.WriteFile(logDir+"/"+vmName+".log", []byte("line1\nline2\n"), 0644); err != nil {
		t.Fatalf("write log for %s: %v", vmName, err)
	}
}

func TestGetVMLogs_ClusterWideCallersUnchanged(t *testing.T) {
	callers := map[string]func(s *Server) context.Context{
		"legacy-viewer":       func(*Server) context.Context { return viewerCtx() },
		"root-viewer-binding": func(s *Server) context.Context { return grantUser(t, s, "rooty", "/", "Viewer") },
		"host-mtls": func(s *Server) context.Context {
			grantUser(t, s, "carol", "/projects/acme", "Viewer")
			return mtlsAdminCtx("peer-host")
		},
	}
	for name, mk := range callers {
		t.Run(name, func(t *testing.T) {
			s, logDir := logsTestServer(t)
			seedPVRScopedVMs(t, s)
			writeTestLog(t, logDir, "a1")
			writeTestLog(t, logDir, "b1")
			writeTestLog(t, logDir, "d1")
			ctx := mk(s)
			for _, vm := range []string{"a1", "b1", "d1"} {
				stream := &fakeLogStream{ctx: ctx}
				if err := s.GetVMLogs(&pb.GetVMLogsRequest{Name: vm, Lines: 1}, stream); err != nil {
					t.Errorf("GetVMLogs(%s): %v", vm, err)
				}
			}
		})
	}
}

// --- backup.read role matrix ---

// TestBackupReadVerb_RoleMatrix confirms backup.read resolves through the
// real auth engine for exactly the built-in roles that should see a schedule:
// Admin ("*"), Viewer/Auditor ("*.read") and Operator/BackupOperator
// ("backup.*") all match; NetworkAdmin, VMOperator and NoAccess — which hold
// none of those grants — do not. canReadSchedule/canReadVM only ever call
// RequirePerm with a ".read"-suffixed verb, so this is the one place the verb
// string itself needs pinning against auth.BuiltinRoles (internal/auth/permissions.go).
func TestBackupReadVerb_RoleMatrix(t *testing.T) {
	want := map[string]bool{
		"Admin": true, "Viewer": true, "Auditor": true, "Operator": true, "BackupOperator": true,
		"NetworkAdmin": false, "VMOperator": false, "NoAccess": false,
	}
	for role, allowed := range want {
		t.Run(role, func(t *testing.T) {
			s := testServer(t)
			ctx := grantUser(t, s, "u-"+role, "/projects/acme", role)
			got := s.RequirePerm(ctx, "/projects/acme/vms/a1", "backup.read", "viewer") == nil
			if got != allowed {
				t.Errorf("role %s: backup.read allowed=%v, want %v", role, got, allowed)
			}
		})
	}
}

// TestBackupReadVerb_LegacyRoleFallbackUnaffected pins that a cluster with NO
// RBAC bindings at all (the pre-RBAC "role" column alone) resolves canReadSchedule
// identically to how RequireRole(ctx, "viewer") always did: a caller whose legacy
// role is at least viewer passes, full stop, regardless of the schedule's
// project — because with no bindings RequirePerm/requirePermResolved fall all
// the way through to the same requireRoleLevel(ctx, fallbackRole) comparison
// RequireRole itself used. This is also exercised end-to-end by every
// "legacy-viewer" case in the ClusterWideCallersUnchanged tests above; this test
// isolates just the verb-resolution step.
func TestBackupReadVerb_LegacyRoleFallbackUnaffected(t *testing.T) {
	s := testServer(t) // no authEngine wired at all — the legacy, no-bindings cluster
	ctx := viewerCtx()
	if err := s.RequirePerm(ctx, "/projects/someone-elses-project/vms/x", "backup.read", "viewer"); err != nil {
		t.Errorf("legacy viewer denied backup.read on a foreign path: %v, want nil (cluster-wide, as RequireRole always was)", err)
	}
}

func TestGetVMLogs_ExistenceNotLeaked(t *testing.T) {
	holder, holderLogDir := logsTestServer(t)
	seedPVRScopedVMs(t, holder)
	writeTestLog(t, holderLogDir, "b1")
	lacker, _ := logsTestServer(t)

	presentStream := &fakeLogStream{ctx: grantUser(t, holder, "carol", "/projects/acme", "Viewer")}
	present := holder.GetVMLogs(&pb.GetVMLogsRequest{Name: "b1"}, presentStream)

	absentStream := &fakeLogStream{ctx: grantUser(t, lacker, "carol", "/projects/acme", "Viewer")}
	absent := lacker.GetVMLogs(&pb.GetVMLogsRequest{Name: "b1"}, absentStream)

	if status.Code(present) != codes.PermissionDenied {
		t.Fatalf("foreign VM: %v, want PermissionDenied", present)
	}
	if status.Code(absent) != status.Code(present) || status.Convert(absent).Message() != status.Convert(present).Message() {
		t.Errorf("existence leaked:\n  present: %v\n  absent:  %v", present, absent)
	}
}
