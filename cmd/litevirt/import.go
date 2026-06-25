package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func newImportCmd() *cobra.Command {
	var (
		from        string
		name        string
		host        string
		pool        string
		project     string
		network     string
		netMap      []string
		diskMap     []string
		serverPath  string
		preserveMAC bool
		start       bool
		inspect     bool
	)
	cmd := &cobra.Command{
		Use:   "import [file]",
		Short: "Import a VM from VMware (OVA/OVF) or Proxmox (.conf / vzdump .vma)",
		Long: `Import an existing VM into litevirt, converting its disks to qcow2 and
defining it as a STOPPED VM (use --start to boot it immediately).

Sources (--from auto detects):
  ova       VMware/VirtualBox .ova archive
  ovf       a .ovf descriptor or a directory/tar of .ovf + disks
  proxmox   a Proxmox qemu-server .conf (pass disks via --disk-map or --server-path)
  vma       a Proxmox vzdump backup (.vma, .vma.zst, .vma.gz)

The file is uploaded to the target host, or use --server-path for a file/dir
already staged there (recommended for large images and all Proxmox sources).

Examples:
  lv import win2022.ova --name win2022 --network br0 --start
  lv import --from proxmox --server-path /srv/stage/100.conf --name app \
            --disk-map scsi0=/srv/stage/vm-100-disk-0.qcow2 --network br0
  lv import vzdump-qemu-100.vma.zst --from vma --server-path /srv/stage/dump.vma.zst \
            --name app --net-map vmbr0=br0 --inspect`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			nm := map[string]string{}
			if network != "" {
				nm["*"] = network
			}
			for _, kv := range netMap {
				if k, v, ok := splitKV(kv); ok {
					nm[k] = v
				}
			}
			dm := map[string]string{}
			for _, kv := range diskMap {
				if k, v, ok := splitKV(kv); ok {
					dm[k] = v
				}
			}
			meta := &pb.ImportVMRequest{
				SourceFormat: from,
				Name:         name,
				TargetHost:   host,
				TargetPool:   pool,
				Project:      project,
				NetMap:       nm,
				DiskMap:      dm,
				PreserveMac:  preserveMAC,
				Start:        start,
				Inspect:      inspect,
				SourcePath:   serverPath,
			}
			if serverPath == "" && len(args) == 0 {
				return fmt.Errorf("provide a source file, or --server-path for a file already on the host")
			}

			return withClient(cmd.Context(), func(ctx context.Context, c pb.LiteVirtClient) error {
				stream, err := c.ImportVM(ctx)
				if err != nil {
					return fmt.Errorf("start import: %w", err)
				}
				if err := stream.Send(meta); err != nil {
					return fmt.Errorf("send metadata: %w", err)
				}
				if serverPath == "" {
					if err := uploadImportSource(stream, args[0]); err != nil {
						return err
					}
				}
				if err := stream.CloseSend(); err != nil {
					return err
				}

				var lastPhase string
				for {
					prog, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						fmt.Println()
						return err
					}
					if prog.Error != "" {
						fmt.Println()
						return fmt.Errorf("import failed: %s", prog.Error)
					}
					if prog.Phase == "convert" {
						fmt.Printf("\r  converting %s: %.0f%%   ", prog.CurrentDisk, prog.ConvertPct)
						lastPhase = prog.Phase
						continue
					}
					if prog.Phase == "done" {
						if lastPhase == "convert" {
							fmt.Println()
						}
						printImportResult(prog, inspect, name)
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&from, "from", "auto", "Source format: auto|ova|ovf|proxmox|vma")
	cmd.Flags().StringVar(&name, "name", "", "Name for the imported VM (required)")
	cmd.Flags().StringVar(&host, "host", "", "Target host (default: the connected host)")
	cmd.Flags().StringVar(&pool, "pool", "", "Target storage pool (default: local)")
	cmd.Flags().StringVar(&project, "project", "", "Tenancy project")
	cmd.Flags().StringVar(&network, "network", "", "Attach all NICs to this bridge")
	cmd.Flags().StringArrayVar(&netMap, "net-map", nil, "Map a foreign network to a bridge (repeatable): foreign=bridge")
	cmd.Flags().StringArrayVar(&diskMap, "disk-map", nil, "Map a source disk to a staged file (repeatable): scsi0=/path")
	cmd.Flags().StringVar(&serverPath, "server-path", "", "Path to a source file/dir already staged on the target host")
	cmd.Flags().BoolVar(&preserveMAC, "preserve-mac", false, "Keep the source MAC addresses (default: regenerate)")
	cmd.Flags().BoolVar(&start, "start", false, "Start the VM after import")
	cmd.Flags().BoolVar(&inspect, "inspect", false, "Parse + print the mapping and warnings without importing")
	cmd.MarkFlagRequired("name")
	return cmd
}

func splitKV(s string) (string, string, bool) {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// uploadImportSource streams a local file (or, for a directory, an on-the-fly tar
// of its contents) to the server in 256 KiB chunks.
func uploadImportSource(stream pb.LiteVirt_ImportVMClient, path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	if fi.IsDir() {
		return uploadDirAsTar(stream, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return streamChunks(stream, f)
}

func uploadDirAsTar(stream pb.LiteVirt_ImportVMClient, dir string) error {
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		entries, err := os.ReadDir(dir)
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			hdr := &tar.Header{Name: e.Name(), Mode: 0o600, Size: info.Size(), Typeflag: tar.TypeReg}
			if err := tw.WriteHeader(hdr); err != nil {
				pw.CloseWithError(err)
				return
			}
			f, err := os.Open(filepath.Join(dir, e.Name()))
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if _, err := io.Copy(tw, f); err != nil {
				f.Close()
				pw.CloseWithError(err)
				return
			}
			f.Close()
		}
		pw.CloseWithError(tw.Close())
	}()
	return streamChunks(stream, pr)
}

func streamChunks(stream pb.LiteVirt_ImportVMClient, r io.Reader) error {
	buf := make([]byte, 256*1024)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			if err := stream.Send(&pb.ImportVMRequest{Chunk: buf[:n]}); err != nil {
				return fmt.Errorf("send chunk: %w", err)
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func printImportResult(prog *pb.ImportVMProgress, inspect bool, name string) {
	if inspect {
		fmt.Printf("Import plan for %q:\n", name)
		if prog.MappedSpecJson != "" {
			var spec pb.VMSpec
			if json.Unmarshal([]byte(prog.MappedSpecJson), &spec) == nil {
				fmt.Printf("  cpu=%d memory=%dMiB machine=%s firmware=%s\n",
					spec.Cpu, spec.MemoryMib, spec.Machine, spec.Firmware)
				for _, d := range spec.Disks {
					ctrl := ""
					if d.ControllerModel != "" {
						ctrl = " controller=" + d.ControllerModel
					}
					fmt.Printf("  disk %-6s bus=%s%s size=%s\n", d.Name, d.Bus, ctrl, d.Size)
				}
				for _, n := range spec.Network {
					vlan := ""
					if len(n.Trunk) > 0 {
						vlan = fmt.Sprintf(" vlan=%d", n.Trunk[0])
					}
					fmt.Printf("  nic  bridge=%s model=%s mac=%s%s\n", n.Name, n.Model, n.Mac, vlan)
				}
			}
		}
	} else {
		fmt.Printf("Imported %q.\n", name)
	}
	for _, w := range prog.Warnings {
		fmt.Printf("  ⚠ %s\n", w)
	}
	if !inspect {
		fmt.Printf("Start it with: lv start %s\n", name)
	}
}
