package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

const backupChunkSize = 256 * 1024 // 256 KiB per gRPC message

// maxRestoreBytes is a sanity ceiling on a single restore stream so a client
// can't write until the disk fills. Generous for real disks; raise if needed.
const maxRestoreBytes int64 = 2 << 40 // 2 TiB

// safeNameRe constrains a restore VM name to characters that can't escape the
// disks directory. Slashes are excluded by the charset; "." / ".." are rejected
// separately by validRestoreName since they pass the charset but traverse.
var safeNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// validRestoreName rejects names that would let filepath.Join escape dataDir.
func validRestoreName(name string) bool {
	return name != "." && name != ".." && safeNameRe.MatchString(name)
}

// validResourceName enforces the same safe charset on user-supplied resource
// names that get rendered verbatim into shell/config templates run as root —
// notably load-balancer and backend names, which land in the HAProxy +
// keepalived configs (internal/lb/config.go). Without it a name containing
// newlines/quotes/spaces could inject arbitrary directives. Same rule as
// validRestoreName; named generically because it now guards more than restores.
func validResourceName(name string) bool {
	return validRestoreName(name)
}

// BackupVM streams a VM's root disk to the client for external backup.
func (s *Server) BackupVM(req *pb.BackupVMRequest, stream pb.LiteVirt_BackupVMServer) error {
	ctx := stream.Context()
	if err := RequireRole(ctx, "operator"); err != nil {
		return err
	}

	if req.VmName == "" {
		return status.Error(codes.InvalidArgument, "vm_name required")
	}

	// Acquire per-VM lock to prevent concurrent delete during backup (#30).
	unlock := s.lockVM(req.VmName)
	defer unlock()

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		remote, err := client.BackupVM(ctx, req)
		if err != nil {
			return err
		}
		for {
			msg, err := remote.Recv()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}

	// The raw-stream backup carries only the disk bytes — it can't carry a
	// Secure-Boot/vTPM VM's NVRAM + swtpm, so a restore would boot a fresh-TPM VM
	// and silently brick BitLocker. Refuse; snapshot backup carries firmware (G1).
	if usesFirmwareState(vm.Spec) {
		return status.Errorf(codes.Unimplemented,
			"VM %q uses Secure Boot / vTPM; the raw stream backup can't carry firmware state — use snapshot backup instead", req.VmName)
	}

	// Mark VM as backing-up to prevent deletion mid-stream. Track it in memory
	// so the reconciler can tell this live backup apart from a stuck row.
	prevState := vm.State
	s.markBackupActive(req.VmName)
	corrosion.UpdateVMState(ctx, s.db, req.VmName, "backing-up", "")
	s.recordVMEvent(ctx, req.VmName, "backup.started", "ok", "stream backup")
	defer func() {
		s.clearBackupActive(req.VmName)
		// Reset with a fresh context: if the client disconnected mid-stream
		// (e.g. a browser navigating away from a disk download), the request
		// ctx is already canceled and the reset write would silently fail —
		// stranding the VM in "backing-up". The reconciler also self-heals,
		// but resetting here is immediate. (#stuck-backing-up)
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		corrosion.UpdateVMState(rctx, s.db, req.VmName, prevState, "")
	}()

	// Find root disk.
	disks, err := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if err != nil || len(disks) == 0 {
		return status.Errorf(codes.Internal, "no disks found for VM %q", req.VmName)
	}
	var diskPath, diskType string
	for _, d := range disks {
		if d.DiskName == "root" {
			diskPath, diskType = d.Path, d.StorageType
			break
		}
	}
	if diskPath == "" {
		diskPath, diskType = disks[0].Path, disks[0].StorageType
	}
	// This RPC streams the raw disk file to the client via os.Open, so it only
	// works for file-based pools. A block/object backend (ceph/zfs/lvm-thin/
	// iscsi) has no openable container file — fail clearly rather than erroring
	// deep in os.Open or streaming a raw block device.
	if !isFileBasedDriver(diskType) {
		return status.Errorf(codes.Unimplemented,
			"disk is on %q storage: the stream-backup RPC supports file-based pools only — use snapshot backup with the VM running", diskType)
	}

	f, err := os.Open(diskPath)
	if err != nil {
		return status.Errorf(codes.Internal, "open disk %s: %v", diskPath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return status.Errorf(codes.Internal, "stat disk: %v", err)
	}

	hasher := sha256.New()
	buf := make([]byte, backupChunkSize)

	slog.Info("streaming backup", "vm", req.VmName, "disk", diskPath, "size", info.Size())
	for {
		n, err := f.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
			if sendErr := stream.Send(&pb.BackupChunk{
				Data:       buf[:n],
				TotalBytes: info.Size(),
			}); sendErr != nil {
				return sendErr
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Errorf(codes.Internal, "read disk: %v", err)
		}
	}

	// Send final chunk with checksum. Surface a send failure so a client that
	// dropped mid-stream doesn't silently lose the integrity confirmation.
	checksum := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if err := stream.Send(&pb.BackupChunk{
		TotalBytes: info.Size(),
		Checksum:   checksum,
	}); err != nil {
		return status.Errorf(codes.Internal, "send checksum: %v", err)
	}

	slog.Info("backup complete", "vm", req.VmName, "size", info.Size(), "checksum", checksum)
	s.recordVMEvent(ctx, req.VmName, "backup.succeeded", "ok",
		fmt.Sprintf("stream backup, size=%d", info.Size()))
	return nil
}

// RestoreVM receives a streamed disk image and creates a VM from it.
func (s *Server) RestoreVM(stream pb.LiteVirt_RestoreVMServer) error {
	ctx := stream.Context()
	if err := RequireRole(ctx, "operator"); err != nil {
		return err
	}

	var (
		name    string
		cpu     int32
		memMiB  int32
		network string
		tmpFile *os.File
		hasher  = sha256.New()
		total   int64
	)

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// First chunk carries metadata.
		if tmpFile == nil {
			name = req.Name
			cpu = req.Cpu
			memMiB = req.MemoryMib
			network = req.Network
			if name == "" {
				return status.Error(codes.InvalidArgument, "vm name required")
			}
			// Reject path-traversal / odd characters before `name` flows into
			// filepath.Join(dataDir, "disks", name) — a name like "../../etc"
			// would otherwise escape dataDir.
			if !validRestoreName(name) {
				return status.Errorf(codes.InvalidArgument,
					"invalid vm name %q: allowed [A-Za-z0-9_.-], and not '.' or '..'", name)
			}

			// Check name uniqueness before writing any disk data (#58).
			existing, _ := corrosion.GetVM(ctx, s.db, name)
			if existing != nil {
				return status.Errorf(codes.AlreadyExists,
					"VM %q already exists (on host %s) — choose a different --name or delete the existing VM first",
					name, existing.HostName)
			}

			diskDir := filepath.Join(s.dataDir, "disks", name)
			os.MkdirAll(diskDir, 0755)
			f, err := os.CreateTemp(diskDir, "restore-*.tmp")
			if err != nil {
				return status.Errorf(codes.Internal, "create temp file: %v", err)
			}
			tmpFile = f
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()
		}

		if len(req.Chunk) > 0 {
			n, err := tmpFile.Write(req.Chunk)
			if err != nil {
				return status.Errorf(codes.Internal, "write chunk: %v", err)
			}
			hasher.Write(req.Chunk)
			total += int64(n)
			if total > maxRestoreBytes {
				return status.Errorf(codes.ResourceExhausted,
					"restore stream exceeded the %d-byte ceiling", maxRestoreBytes)
			}
		}
	}

	if tmpFile == nil {
		return status.Error(codes.InvalidArgument, "no data received")
	}
	tmpFile.Close()

	// Move to final disk path.
	diskPath := filepath.Join(s.dataDir, "disks", name, "root.qcow2")
	if err := os.Rename(tmpFile.Name(), diskPath); err != nil {
		return status.Errorf(codes.Internal, "move disk: %v", err)
	}

	// Defaults.
	if cpu == 0 {
		cpu = 2
	}
	if memMiB == 0 {
		memMiB = 4096
	}
	// Build a minimal spec for the restored VM.
	spec := &pb.VMSpec{
		Name:      name,
		Cpu:       cpu,
		MemoryMib: memMiB,
		Machine:   "q35",
		Firmware:  "uefi",
		Boot:      "disk",
	}
	specJSON, _ := json.Marshal(spec)

	// Generate domain XML.
	vmCfg := lv.VMConfig{
		Name:      name,
		CPU:       int(cpu),
		MemoryMiB: int(memMiB),
		Machine:   "q35",
		Firmware:  "uefi",
		Disks: []lv.DiskConfig{{
			Name: "root",
			Path: diskPath,
			Bus:  "virtio",
		}},
		Boot: "disk",
	}

	// Only attach a network if explicitly specified — the bridge must exist
	// on this host or libvirt will reject the domain definition.
	if network != "" {
		bridge := resolveBridge(ctx, s.db, network)
		mac := lv.GenerateMAC()
		vmCfg.Networks = []lv.NetworkConfig{{
			Bridge: bridge,
			Model:  "virtio",
			MAC:    mac,
		}}
	}

	domXML, err := lv.GenerateDomainXML(vmCfg)
	if err != nil {
		return status.Errorf(codes.Internal, "generate XML: %v", err)
	}

	// Clean up any orphaned libvirt domain (e.g. from a prior failed restore).
	_ = s.virt.UndefineDomain(name, false)

	if err := s.virt.DefineDomain(domXML); err != nil {
		return status.Errorf(codes.Internal, "define domain: %v", err)
	}
	if err := s.virt.StartDomain(name); err != nil {
		return status.Errorf(codes.Internal, "start domain: %v", err)
	}

	// Record in DB.
	var ifaces []corrosion.InterfaceRecord
	if network != "" {
		ifaces = append(ifaces, corrosion.InterfaceRecord{
			VMName:      name,
			NetworkName: network,
			Ordinal:     0,
			MAC:         vmCfg.Networks[0].MAC,
		})
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      name,
		HostName:  s.hostName,
		Spec:      string(specJSON),
		State:     "running",
		CPUActual: int(cpu),
		MemActual: int(memMiB),
	}, ifaces, []corrosion.DiskRecord{{
		VMName:      name,
		DiskName:    "root",
		HostName:    s.hostName,
		Path:        diskPath,
		SizeBytes:   total,
		StorageType: "local",
	}}); err != nil {
		slog.Warn("failed to record restored VM", "vm", name, "error", err)
	}

	slog.Info("VM restored from backup", "name", name, "size", total)
	s.recordVMEvent(ctx, name, "vm.restored", "ok", fmt.Sprintf("size=%d", total))

	return stream.SendAndClose(&pb.VM{
		Name:     name,
		HostName: s.hostName,
		State:    pb.VMState_VM_RUNNING,
	})
}
