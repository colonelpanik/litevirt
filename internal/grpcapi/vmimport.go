package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/uuid"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/tenancy"
	"github.com/litevirt/litevirt/internal/vmimport"
	"log/slog"
)

// ImportVM ingests a foreign VM (VMware OVA/OVF, Proxmox .conf or vzdump/.vma),
// converts its disks to qcow2, and defines it as a STOPPED VM (optionally
// started). The RPC is wire-level bidi: the client streams the source artifact
// (first frame carries metadata); the server streams unpack/convert/define
// progress. See internal/vmimport for the source adapters.
func (s *Server) ImportVM(stream pb.LiteVirt_ImportVMServer) error {
	ctx := stream.Context()

	// First frame carries metadata (+ possibly the first upload chunk).
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "no import metadata received: %v", err)
	}

	// Forward to the destination host before consuming the stream, so bytes land
	// directly on the host that will own the VM (a concurrent stream proxy).
	if first.TargetHost != "" && first.TargetHost != s.hostName {
		return s.proxyImportVM(ctx, stream, first)
	}

	// ── RBAC + name-uniqueness early (before accepting any bytes) ──
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return err
	}
	name := first.Name
	if name == "" || !validRestoreName(name) {
		return status.Errorf(codes.InvalidArgument,
			"invalid vm name %q: allowed [A-Za-z0-9_.-], not '.' or '..'", name)
	}
	project := tenancy.NormalizeProject(first.Project)
	if err := s.RequirePerm(ctx, vmRBACPathFor(project, name), "vm.create", "operator"); err != nil {
		return err
	}
	if project != tenancy.Default {
		if p, perr := corrosion.GetProject(ctx, s.db, project); perr != nil || p == nil {
			return status.Errorf(codes.NotFound, "project %q not found", project)
		}
	}
	if existing, _ := corrosion.GetVM(ctx, s.db, name); existing != nil {
		return status.Errorf(codes.AlreadyExists,
			"VM %q already exists (on host %s) — choose a different --name or remove it first", name, existing.HostName)
	}

	// ── Stage the source into a temp import dir (always cleaned up) ──
	if err := os.MkdirAll(filepath.Join(s.dataDir, "imports"), 0o755); err != nil {
		return status.Errorf(codes.Internal, "prepare import dir: %v", err)
	}
	importDir, err := os.MkdirTemp(filepath.Join(s.dataDir, "imports"), name+"-*")
	if err != nil {
		return status.Errorf(codes.Internal, "create import dir: %v", err)
	}
	defer os.RemoveAll(importDir)

	srcPath, err := s.stageImportSource(ctx, stream, first, importDir)
	if err != nil {
		return err
	}

	// ── Parse via the source adapter → ForeignVM ──
	fv, err := s.parseImportSource(first.SourceFormat, srcPath, importDir)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "parse source: %v", err)
	}
	fv.Name = name

	// Resolve foreign networks → bridges + MAC policy (also surfaced by --inspect).
	if err := s.applyImportNetworks(fv, first); err != nil {
		return err
	}

	if first.Inspect {
		return s.sendImportInspect(stream, fv, project)
	}

	// Resolve disk files (Proxmox .conf disks need --disk-map) + safety checks.
	if err := s.applyImportDiskMap(ctx, fv, first); err != nil {
		return err
	}

	// Quota estimate from declared sizes (re-checked post-convert with real sizes).
	if err := s.admitImport(ctx, project, fv); err != nil {
		return err
	}

	// ── Convert each data disk → qcow2 in the target pool ──
	poolDir, err := s.importPoolDir(ctx, first.TargetPool)
	if err != nil {
		return err
	}
	var convertedPaths []string
	cleanupDisks := func() {
		for _, p := range convertedPaths {
			_ = os.Remove(p)
		}
	}
	for i := range fv.Disks {
		d := &fv.Disks[i]
		if d.IsCDROM {
			continue
		}
		if !fileExists(d.LocalPath) {
			cleanupDisks()
			return status.Errorf(codes.FailedPrecondition,
				"disk %q (source %q) has no staged file — pass --disk-map %s=/path", d.Name, d.SourceID, d.SourceID)
		}
		dst := lv.DiskPath(poolDir, name, d.Name) // poolDir/<vm>-<disk>.qcow2 (poolDir already the disks dir)
		dst = filepath.Join(poolDir, name+"-"+d.Name+".qcow2")
		curDisk := d.Name
		if err := convertForeignDisk(ctx, d.LocalPath, d.Format, dst, importDir, func(pct float32) {
			_ = stream.Send(&pb.ImportVMProgress{Phase: "convert", ConvertPct: pct, CurrentDisk: curDisk})
		}); err != nil {
			cleanupDisks()
			return status.Errorf(codes.Internal, "convert disk %q: %v", d.Name, err)
		}
		convertedPaths = append(convertedPaths, dst)
		d.LocalPath = dst
		// Authoritative size from the converted qcow2.
		if info, e := qcow2.Info(dst); e == nil && info.VirtualSize > 0 {
			if d.CapacityBytes != 0 && info.VirtualSize != d.CapacityBytes {
				fv.Warnf("disk %q declared %d bytes but converted image is %d bytes", d.Name, d.CapacityBytes, info.VirtualSize)
			}
			d.CapacityBytes = info.VirtualSize
		}
	}

	// Re-check quota against the real converted sizes before committing.
	if err := s.admitImport(ctx, project, fv); err != nil {
		cleanupDisks()
		return err
	}

	// ── Define → persist stopped → optional start, with full rollback ──
	cfg := fv.ToVMConfig()
	spec := fv.ToVMSpec(project)

	// Firmware (G1): a source that had Secure Boot / a vTPM is imported WITH them,
	// but under a FRESH identity — the source's TPM secret is NOT carried, so a
	// BitLocker guest will need its recovery key (the new TPM can't unseal the old
	// volume). applyFirmwareConfig resolves the host OVMF paths, mints the NVRAM
	// location, and preflights host capability (fails clearly on a non-capable host).
	fwImport := spec.SecureBoot || spec.Tpm
	if fwImport {
		spec.Uuid = uuid.NewString()
		if err := s.applyFirmwareConfig(&cfg, spec); err != nil {
			cleanupDisks()
			return err
		}
		cfg.UUID = spec.Uuid
		if spec.Tpm {
			fv.Warnf("imported with a FRESH vTPM — the source's TPM secret was not carried, so a BitLocker guest needs its recovery key (the new TPM cannot unseal the old volume)")
		}
	}

	domXML, err := lv.GenerateDomainXML(cfg)
	if err != nil {
		cleanupDisks()
		return status.Errorf(codes.Internal, "generate domain XML: %v", err)
	}

	// Conditional orphan guard: never undefine a RUNNING same-name domain that
	// has no DB row — fail clearly instead (cf. vm.go orphan handling).
	if s.virt.DomainExists(name) {
		if st, _ := s.virt.DomainState(name); st == "running" {
			cleanupDisks()
			return status.Errorf(codes.FailedPrecondition,
				"a running libvirt domain %q already exists with no cluster record; resolve it before importing", name)
		}
		_ = s.virt.UndefineDomain(name, false)
	}
	if err := s.virt.DefineDomain(domXML); err != nil {
		cleanupDisks()
		if fwImport {
			lv.WipeFirmwareState(s.dataDir, name, spec.Uuid)
		}
		return status.Errorf(codes.Internal, "define domain: %v", err)
	}

	specJSON, _ := json.Marshal(spec)
	diskRecords, ifaceRecords := importRecords(fv, name, s.hostName)

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      name,
		HostName:  s.hostName,
		Spec:      string(specJSON),
		State:     "stopped",
		CPUActual: fv.CPUs,
		MemActual: fv.MemoryMiB,
		Project:   project,
	}, ifaceRecords, diskRecords); err != nil {
		_ = s.virt.UndefineDomain(name, false)
		if fwImport {
			lv.WipeFirmwareState(s.dataDir, name, spec.Uuid)
		}
		cleanupDisks()
		return status.Errorf(codes.Internal, "record imported VM: %v", err)
	}

	stateMsg := "imported (stopped)"
	if first.Start {
		if err := s.virt.StartDomain(name); err != nil {
			// Roll back fully: remove DB row, undefine, delete disks.
			_ = corrosion.DeleteVM(ctx, s.db, name)
			_ = s.virt.UndefineDomain(name, false)
			if fwImport {
				lv.WipeFirmwareState(s.dataDir, name, spec.Uuid)
			}
			cleanupDisks()
			return status.Errorf(codes.Internal, "imported but failed to start: %v", err)
		}
		corrosion.UpdateVMState(ctx, s.db, name, "running", "imported+started")
		if vm, _ := corrosion.GetVM(ctx, s.db, name); vm != nil {
			s.reapplyVLANTaps(ctx, vm) // best-effort
		}
		stateMsg = "imported + started"
	}

	s.recordVMEvent(ctx, name, "vm.imported", "ok", fmt.Sprintf("format=%s disks=%d", first.SourceFormat, len(convertedPaths)))
	slog.Info("VM imported", "name", name, "host", s.hostName, "disks", len(convertedPaths), "started", first.Start, "warnings", len(fv.Warnings))

	return stream.Send(&pb.ImportVMProgress{
		Phase:          "done",
		MappedSpecJson: string(specJSON),
		Warnings:       append(fv.Warnings, stateMsg),
	})
}

// proxyImportVM relays the import stream to the destination host. It is a
// concurrent proxy (client→peer chunks in one goroutine, peer→client progress in
// this one) so bytes never buffer locally first. The forwarded first frame keeps
// TargetHost set to the peer's name, so the peer treats it as a local import.
func (s *Server) proxyImportVM(ctx context.Context, stream pb.LiteVirt_ImportVMServer, first *pb.ImportVMRequest) error {
	client, conn, err := s.peerClient(ctx, first.TargetHost)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", first.TargetHost, err)
	}
	defer conn.Close()

	up, err := client.ImportVM(ctx)
	if err != nil {
		return status.Errorf(codes.Unavailable, "open import on %s: %v", first.TargetHost, err)
	}
	if err := up.Send(first); err != nil {
		return err
	}

	relayErr := make(chan error, 1)
	go func() {
		for {
			req, rerr := stream.Recv()
			if rerr == io.EOF {
				relayErr <- up.CloseSend()
				return
			}
			if rerr != nil {
				relayErr <- rerr
				return
			}
			if serr := up.Send(req); serr != nil {
				relayErr <- serr
				return
			}
		}
	}()

	for {
		prog, rerr := up.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
		if serr := stream.Send(prog); serr != nil {
			return serr
		}
	}
	select {
	case e := <-relayErr:
		if e != nil && e != io.EOF {
			return e
		}
	default:
	}
	return nil
}

// stageImportSource lands the source artifact under importDir and returns its
// path. source_path (a file/dir already on THIS host) skips the upload; otherwise
// the streamed chunks are written to importDir/source.
func (s *Server) stageImportSource(ctx context.Context, stream pb.LiteVirt_ImportVMServer, first *pb.ImportVMRequest, importDir string) (string, error) {
	if first.SourcePath != "" {
		return s.resolveStagedPath(ctx, first.SourcePath)
	}

	path := filepath.Join(importDir, "source")
	f, err := os.Create(path)
	if err != nil {
		return "", status.Errorf(codes.Internal, "create upload file: %v", err)
	}
	defer f.Close()

	var total int64
	write := func(chunk []byte) error {
		if len(chunk) == 0 {
			return nil
		}
		n, werr := f.Write(chunk)
		if werr != nil {
			return status.Errorf(codes.Internal, "write upload: %v", werr)
		}
		total += int64(n)
		if total > maxRestoreBytes {
			return status.Errorf(codes.ResourceExhausted, "import upload exceeded the %d-byte ceiling", maxRestoreBytes)
		}
		return nil
	}
	if err := write(first.Chunk); err != nil {
		return "", err
	}
	for {
		req, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", rerr
		}
		if err := write(req.Chunk); err != nil {
			return "", err
		}
	}
	if total == 0 {
		return "", status.Error(codes.InvalidArgument, "no source data received (and no --server-path)")
	}
	if err := f.Sync(); err != nil {
		return "", status.Errorf(codes.Internal, "sync upload: %v", err)
	}
	return path, nil
}

// resolveStagedPath validates a destination-host path used for --server-path or
// --disk-map: it must resolve (symlinks included) under the import staging root,
// or the caller must be admin.
func (s *Server) resolveStagedPath(ctx context.Context, p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", status.Errorf(codes.InvalidArgument, "staged path %q must be absolute", p)
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "staged path %q: %v", p, err)
	}
	stagingRoot := filepath.Join(s.dataDir, "imports", "staging")
	if root, e := filepath.EvalSymlinks(stagingRoot); e == nil {
		stagingRoot = root
	}
	if !withinDir(stagingRoot, resolved) {
		// Outside the staging root → privileged, require admin.
		if err := RequireRole(ctx, "admin"); err != nil {
			return "", status.Errorf(codes.PermissionDenied,
				"path %q is outside the import staging root (%s); reading an arbitrary host path requires the admin role", p, stagingRoot)
		}
	}
	return resolved, nil
}

// parseImportSource dispatches to the right adapter. auto sniffs by content.
func (s *Server) parseImportSource(format, srcPath, importDir string) (*vmimport.ForeignVM, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" || format == "auto" {
		format = sniffImportFormat(srcPath)
	}
	switch format {
	case "ova", "ovf":
		// Directory (server-path OVF dir): find the .ovf inside.
		if fi, err := os.Stat(srcPath); err == nil && fi.IsDir() {
			ovf, e := findByExt(srcPath, ".ovf")
			if e != nil {
				return nil, e
			}
			return vmimport.ParseOVF(ovf)
		}
		// A bare .ovf file (server-path) → parse directly.
		if strings.EqualFold(filepath.Ext(srcPath), ".ovf") {
			return vmimport.ParseOVF(srcPath)
		}
		// Otherwise a tar (.ova or an OVF-dir tar) → unpack then parse.
		f, err := os.Open(srcPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		ovfPath, err := vmimport.UnpackOVA(f, importDir)
		if err != nil {
			return nil, err
		}
		return vmimport.ParseOVF(ovfPath)
	case "proxmox":
		// A .conf file (disks resolved via --disk-map), or a dir holding one.
		if fi, err := os.Stat(srcPath); err == nil && fi.IsDir() {
			conf, e := findByExt(srcPath, ".conf")
			if e != nil {
				return nil, e
			}
			return vmimport.ParseProxmoxConf(conf)
		}
		return vmimport.ParseProxmoxConf(srcPath)
	case "vma":
		f, err := os.Open(srcPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return vmimport.ParseVMA(f, importDir)
	default:
		return nil, fmt.Errorf("unrecognized source format (use --from ova|ovf|proxmox|vma)")
	}
}

// applyImportNetworks resolves each foreign network to a bridge (via --net-map,
// the "*" wildcard from --network, or the name as-is) and applies the MAC policy.
// Two NICs on the same resolved bridge collide on vm_interfaces (vm_name,
// network_name) — rejected here (v1 limitation).
func (s *Server) applyImportNetworks(fv *vmimport.ForeignVM, meta *pb.ImportVMRequest) error {
	seen := map[string]bool{}
	for i := range fv.NICs {
		n := &fv.NICs[i]
		bridge := meta.NetMap[n.Network]
		if bridge == "" {
			bridge = meta.NetMap["*"]
		}
		if bridge == "" {
			bridge = n.Network
			fv.Warnf("network %q not mapped (--net-map); attaching to a bridge named %q", n.Network, n.Network)
		}
		if bridge == "" {
			return status.Errorf(codes.InvalidArgument, "NIC %d has no network; pass --network <bridge> or --net-map", i)
		}
		if seen[bridge] {
			return status.Errorf(codes.InvalidArgument,
				"two NICs map to the same network/bridge %q — litevirt v1 allows one NIC per network per VM; use distinct bridges or --net-map", bridge)
		}
		seen[bridge] = true
		n.Network = bridge
		if !meta.PreserveMac || n.MAC == "" {
			n.MAC = lv.GenerateMAC()
		}
	}
	return nil
}

// applyImportDiskMap resolves disks that have no staged file yet (Proxmox .conf
// references a storage volume) via --disk-map, with the same path safety as
// --server-path.
func (s *Server) applyImportDiskMap(ctx context.Context, fv *vmimport.ForeignVM, meta *pb.ImportVMRequest) error {
	for i := range fv.Disks {
		d := &fv.Disks[i]
		if d.IsCDROM || fileExists(d.LocalPath) {
			continue
		}
		mapped := meta.DiskMap[d.SourceID]
		if mapped == "" {
			return status.Errorf(codes.FailedPrecondition,
				"disk %q (source %q, ref %q) is not a local file — pass --disk-map %s=/staged/path", d.Name, d.SourceID, d.LocalPath, d.SourceID)
		}
		resolved, err := s.resolveStagedPath(ctx, mapped)
		if err != nil {
			return err
		}
		d.LocalPath = resolved
	}
	return nil
}

func (s *Server) admitImport(ctx context.Context, project string, fv *vmimport.ForeignVM) error {
	diskGiB := 0
	for _, d := range fv.Disks {
		if !d.IsCDROM {
			diskGiB += int((d.CapacityBytes + (1 << 30) - 1) >> 30)
		}
	}
	qreq := tenancy.QuotaRequest{VCPU: fv.CPUs, MemMiB: fv.MemoryMiB, DiskGiB: diskGiB, NIC: len(fv.NICs)}
	if s.tenancy != nil {
		if err := s.tenancy.Admit(ctx, project, qreq); err != nil {
			return status.Errorf(codes.ResourceExhausted, "%v", err)
		}
		return nil
	}
	if err := corrosion.CheckProjectQuota(ctx, s.db, project, corrosion.QuotaCheck{
		VCPU: qreq.VCPU, MemMiB: qreq.MemMiB, DiskGiB: qreq.DiskGiB, NIC: qreq.NIC,
	}); err != nil {
		return status.Errorf(codes.ResourceExhausted, "%v", err)
	}
	return nil
}

// importPoolDir resolves the target pool to a file-based directory. Empty pool =
// local {dataDir}/disks. Block-backed pools (ceph/iscsi/lvm-thin/zfs) are
// rejected for import in v1 — the converted artifact is a qcow2 file.
func (s *Server) importPoolDir(ctx context.Context, pool string) (string, error) {
	if pool == "" {
		dir := filepath.Join(s.dataDir, "disks")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", status.Errorf(codes.Internal, "prepare disks dir: %v", err)
		}
		return dir, nil
	}
	ref, ok := s.resolvePool(ctx, pool)
	if !ok {
		return "", status.Errorf(codes.NotFound, "storage pool %q not found", pool)
	}
	dir, err := fileBasedPoolDir(s.dataDir, ref)
	if err != nil {
		return "", status.Errorf(codes.FailedPrecondition,
			"pool %q (driver %q) is not file-backed; VM import targets file pools (local/dir/nfs/btrfs) only", pool, ref.Driver)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", status.Errorf(codes.Internal, "prepare pool dir: %v", err)
	}
	return dir, nil
}

func (s *Server) sendImportInspect(stream pb.LiteVirt_ImportVMServer, fv *vmimport.ForeignVM, project string) error {
	spec := fv.ToVMSpec(project)
	j, _ := json.Marshal(spec)
	return stream.Send(&pb.ImportVMProgress{
		Phase:          "done",
		MappedSpecJson: string(j),
		Warnings:       fv.Warnings,
	})
}

func importRecords(fv *vmimport.ForeignVM, name, host string) ([]corrosion.DiskRecord, []corrosion.InterfaceRecord) {
	var disks []corrosion.DiskRecord
	di := 0
	for _, d := range fv.Disks {
		if d.IsCDROM {
			continue
		}
		disks = append(disks, corrosion.DiskRecord{
			VMName:      name,
			DiskName:    d.Name,
			HostName:    host,
			Path:        d.LocalPath,
			SizeBytes:   int64(d.CapacityBytes),
			StorageType: "local",
			TargetDev:   lv.DiskDevName(d.Bus, di),
		})
		di++
	}
	var ifaces []corrosion.InterfaceRecord
	for i, n := range fv.NICs {
		ifaces = append(ifaces, corrosion.InterfaceRecord{
			VMName:      name,
			NetworkName: n.Network,
			Ordinal:     i,
			MAC:         n.MAC,
		})
	}
	return disks, ifaces
}

// ── disk conversion ──

// convertForeignDisk converts a foreign-format disk to qcow2 at dst using
// qemu-img. It HARD-FAILS if qemu-img is absent (the byte-copy fallback used
// elsewhere would dump foreign bytes into a qcow2-named file and corrupt it) and
// rejects any external backing-file / out-of-dir extent reference BEFORE invoking
// qemu-img (a malicious descriptor would otherwise make qemu-img read host files).
func convertForeignDisk(ctx context.Context, src, srcFormat, dst, allowedDir string, emit func(pct float32)) error {
	if !qemuImgAvailable() {
		return fmt.Errorf("qemu-img not found on PATH (required to import/convert foreign disks)")
	}
	if err := assertNoExternalDiskRefs(ctx, src, allowedDir); err != nil {
		return err
	}

	tmp := dst + ".tmp"
	_ = os.Remove(tmp)
	args := []string{"convert", "-p", "-O", "qcow2"}
	if srcFormat != "" {
		args = append(args, "-f", srcFormat)
	}
	args = append(args, src, tmp)

	cmd := exec.CommandContext(ctx, "qemu-img", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	buf := make([]byte, 256)
	for {
		n, rerr := stdout.Read(buf)
		if n > 0 && emit != nil {
			if pct := parseQemuImgProgress(string(buf[:n])); pct >= 0 {
				emit(pct)
			}
		}
		if rerr != nil {
			break
		}
	}
	if err := cmd.Wait(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("qemu-img convert: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	// Defense-in-depth: the produced qcow2 must be standalone.
	if err := assertNoExternalDiskRefs(ctx, tmp, allowedDir); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finalize converted disk: %w", err)
	}
	return nil
}

type qemuImgInfo struct {
	BackingFilename     string `json:"backing-filename"`
	FullBackingFilename string `json:"full-backing-filename"`
}

// assertNoExternalDiskRefs rejects a disk whose backing file or VMDK extents
// point outside allowedDir (a host-file-read escape via a crafted descriptor).
func assertNoExternalDiskRefs(ctx context.Context, file, allowedDir string) error {
	// Text VMDK descriptor: scan extent lines for absolute/escaping paths.
	if head, err := readHead(file, 4096); err == nil && bytes.Contains(head, []byte("# Disk DescriptorFile")) {
		full, _ := readHead(file, 256<<10)
		for _, line := range strings.Split(string(full), "\n") {
			line = strings.TrimSpace(line)
			if !(strings.HasPrefix(line, "RW ") || strings.HasPrefix(line, "RDONLY ") || strings.HasPrefix(line, "NOACCESS ")) {
				continue
			}
			a := strings.IndexByte(line, '"')
			b := strings.LastIndexByte(line, '"')
			if a < 0 || b <= a {
				continue
			}
			ext := line[a+1 : b]
			if filepath.IsAbs(ext) || strings.Contains(ext, "..") || !withinDir(allowedDir, filepath.Join(allowedDir, ext)) {
				return fmt.Errorf("VMDK descriptor references an external/escaping extent %q", ext)
			}
		}
	}
	// qemu-img info: reject a backing file that escapes allowedDir.
	out, err := exec.CommandContext(ctx, "qemu-img", "info", "-U", "--output=json", file).Output()
	if err != nil {
		// info failure is not itself an escape; surface it as a convert-time error.
		return fmt.Errorf("inspect %s: %w", filepath.Base(file), err)
	}
	var info qemuImgInfo
	if json.Unmarshal(out, &info) == nil {
		for _, b := range []string{info.BackingFilename, info.FullBackingFilename} {
			if b == "" {
				continue
			}
			resolved := b
			if !filepath.IsAbs(b) {
				resolved = filepath.Join(filepath.Dir(file), b)
			}
			if !withinDir(allowedDir, resolved) {
				return fmt.Errorf("disk has an external backing file %q outside the import directory", b)
			}
		}
	}
	return nil
}

// ── small helpers ──

func withinDir(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func readHead(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	r, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:r], nil
}

func findByExt(dir, ext string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ext) {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", fmt.Errorf("no %s file found in %s", ext, dir)
}

// sniffImportFormat guesses the source format from the file's leading bytes.
func sniffImportFormat(path string) string {
	head, err := readHead(path, 512)
	if err != nil || len(head) == 0 {
		return ""
	}
	switch {
	case len(head) >= 4 && bytes.Equal(head[:4], []byte{'V', 'M', 'A', 0}):
		return "vma"
	case len(head) >= 4 && bytes.Equal(head[:4], []byte{0x28, 0xB5, 0x2F, 0xFD}): // zstd
		return "vma"
	case len(head) >= 2 && head[0] == 0x1F && head[1] == 0x8B: // gzip
		return "vma"
	case len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar")): // tar
		return "ova"
	case bytes.Contains(head, []byte("<Envelope")) || bytes.Contains(head, []byte("<?xml")):
		return "ovf"
	case bytes.Contains(head, []byte("scsihw:")) || bytes.Contains(head, []byte("bootdisk:")) ||
		bytes.Contains(head, []byte("boot:")) || bytes.Contains(head, []byte("ostype:")):
		return "proxmox"
	default:
		return ""
	}
}
