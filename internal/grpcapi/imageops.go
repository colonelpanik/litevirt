package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
)

// ImportImage receives a client-streamed image file and writes it to the local store.
func (s *Server) ImportImage(stream pb.LiteVirt_ImportImageServer) error {
	ctx := stream.Context()
	if err := s.RequirePerm(ctx, "/", "image.import", "operator"); err != nil {
		return err
	}

	var (
		name     string
		format   string
		checksum string
		tmpFile  *os.File
		hasher   = sha256.New()
		total    int64
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
			format = req.Format
			checksum = req.Checksum
			if name == "" {
				return status.Error(codes.InvalidArgument, "image name required")
			}
			if err := safename.ValidateImageName(name); err != nil {
				return status.Errorf(codes.InvalidArgument, "%v", err)
			}
			if format == "" {
				format = "qcow2"
			}

			destDir := filepath.Join(s.dataDir, "images")
			os.MkdirAll(destDir, 0755)
			f, err := os.CreateTemp(destDir, "import-*.tmp")
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
			if total > s.maxImageBytes() {
				return status.Errorf(codes.InvalidArgument,
					"image import exceeds the %d-byte ceiling", s.maxImageBytes())
			}
		}
	}

	if tmpFile == nil {
		return status.Error(codes.InvalidArgument, "no data received")
	}
	tmpFile.Close()

	// Verify checksum if provided.
	got := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if checksum != "" {
		expected := checksum
		if len(expected) == 64 {
			expected = "sha256:" + expected
		}
		if got != expected {
			return status.Errorf(codes.InvalidArgument, "checksum mismatch: got %s, expected %s", got, expected)
		}
	}

	// Move to final location.
	destPath := s.images.ImagePath(name)
	if err := os.Rename(tmpFile.Name(), destPath); err != nil {
		return status.Errorf(codes.Internal, "move image: %v", err)
	}

	// Record in DB.
	now := time.Now().UTC().Format(time.RFC3339)
	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name:      name,
		Format:    format,
		Checksum:  got,
		SizeBytes: total,
		SourceURL: "import",
	})
	corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
		ImageName: name,
		HostName:  s.hostName,
		Path:      destPath,
		Status:    "ready",
		PulledAt:  now,
	})

	slog.Info("image imported", "name", name, "size", total)
	return stream.SendAndClose(&pb.ImportImageResponse{
		Name:      name,
		SizeBytes: total,
		Checksum:  got,
	})
}

// PushImage copies a local image to another host via gRPC streaming (ImportImage).
// This uses the existing mTLS peer connection — no SSH/rsync required.
func (s *Server) PushImage(req *pb.PushImageRequest, stream pb.LiteVirt_PushImageServer) error {
	ctx := stream.Context()
	if err := s.RequirePerm(ctx, "/", "image.push", "operator"); err != nil {
		return err
	}

	if req.Name == "" || req.TargetHost == "" {
		return status.Error(codes.InvalidArgument, "name and target_host required")
	}
	if err := safename.ValidateImageName(req.Name); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// Verify image exists locally.
	srcPath := s.images.ImagePath(req.Name)
	info, err := os.Stat(srcPath)
	if err != nil {
		return status.Errorf(codes.NotFound, "image %q not found locally", req.Name)
	}
	// Fail source-side before streaming if the local file already exceeds the
	// ceiling (the target enforces it again as defense-in-depth).
	if info.Size() > s.maxImageBytes() {
		return status.Errorf(codes.InvalidArgument,
			"image %q is %d bytes, over the %d-byte ceiling", req.Name, info.Size(), s.maxImageBytes())
	}

	// Look up image metadata for checksum.
	imgRows, _ := s.db.Query(ctx,
		`SELECT checksum, format FROM images WHERE name = ? AND deleted_at IS NULL`, req.Name)
	var checksum, format string
	if len(imgRows) > 0 {
		checksum = imgRows[0].String("checksum")
		format = imgRows[0].String("format")
	}
	if format == "" {
		format = "qcow2"
	}

	// Connect to the target host via mTLS gRPC.
	client, conn, err := s.peerClient(ctx, req.TargetHost)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.TargetHost, err)
	}
	defer conn.Close()

	stream.Send(&pb.PushImageProgress{Status: "copying", ProgressPct: 0})

	// Open ImportImage stream on the target.
	importStream, err := client.ImportImage(ctx)
	if err != nil {
		return status.Errorf(codes.Internal, "open ImportImage stream on %s: %v", req.TargetHost, err)
	}

	// Stream the file in chunks.
	f, err := os.Open(srcPath)
	if err != nil {
		return status.Errorf(codes.Internal, "open image file: %v", err)
	}
	defer f.Close()

	const chunkSize = 256 * 1024 // 256 KiB
	buf := make([]byte, chunkSize)
	var sent int64
	first := true

	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			chunk := &pb.ImportImageRequest{Chunk: buf[:n]}
			if first {
				chunk.Name = req.Name
				chunk.Format = format
				chunk.Checksum = checksum
				first = false
			}
			if err := importStream.Send(chunk); err != nil {
				return status.Errorf(codes.Internal, "stream chunk to %s: %v", req.TargetHost, err)
			}
			sent += int64(n)
			if info.Size() > 0 {
				pct := float32(sent) / float32(info.Size()) * 90 // 0-90% for transfer
				stream.Send(&pb.PushImageProgress{Status: "copying", ProgressPct: pct})
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return status.Errorf(codes.Internal, "read image file: %v", readErr)
		}
	}

	// Close and get response.
	resp, err := importStream.CloseAndRecv()
	if err != nil {
		return status.Errorf(codes.Internal, "ImportImage on %s failed: %v", req.TargetHost, err)
	}

	stream.Send(&pb.PushImageProgress{Status: "complete", ProgressPct: 100})
	slog.Info("image pushed via gRPC", "name", req.Name, "target", req.TargetHost,
		"size", resp.SizeBytes, "checksum", resp.Checksum)
	return nil
}

// AutoPullImage is the exported wrapper for autoPullImage.
func (s *Server) AutoPullImage(ctx context.Context, imageName string) error {
	return s.autoPullImage(ctx, imageName)
}

// autoPullImage finds a peer that has the image and asks it to push to this host.
// Blocks until the transfer completes. Used by CreateVM and reconciler auto-pull.
func (s *Server) autoPullImage(ctx context.Context, imageName string) error {
	// Find a peer host that has this image ready.
	hosts, err := corrosion.GetImageHosts(ctx, s.db, imageName)
	if err != nil {
		return fmt.Errorf("query image_hosts: %w", err)
	}
	var sourceHost string
	for _, ih := range hosts {
		if ih.Status == "ready" && ih.HostName != s.hostName {
			sourceHost = ih.HostName
			break
		}
	}
	if sourceHost == "" {
		return fmt.Errorf("no peer host has image %q with status=ready", imageName)
	}

	slog.Info("auto-pulling image from peer", "image", imageName, "source", sourceHost, "target", s.hostName)

	// Call PushImage on the source host, telling it to push to us.
	client, conn, err := s.peerClient(ctx, sourceHost)
	if err != nil {
		return fmt.Errorf("cannot reach source host %s: %w", sourceHost, err)
	}
	defer conn.Close()

	stream, err := client.PushImage(ctx, &pb.PushImageRequest{
		Name:       imageName,
		TargetHost: s.hostName,
	})
	if err != nil {
		return fmt.Errorf("PushImage RPC: %w", err)
	}

	// Drain the progress stream until completion.
	for {
		prog, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("PushImage stream: %w", err)
		}
		if prog.Error != "" {
			return fmt.Errorf("PushImage error: %s", prog.Error)
		}
		if prog.Status == "complete" {
			break
		}
	}

	slog.Info("auto-pull complete", "image", imageName, "source", sourceHost)
	return nil
}

// BuildImage snapshots a running VM's root disk to create a golden image.
func (s *Server) BuildImage(ctx context.Context, req *pb.BuildImageRequest) (*pb.BuildImageResponse, error) {
	if err := s.RequirePerm(ctx, "/", "image.build", "operator"); err != nil {
		return nil, err
	}
	if req.VmName == "" || req.ImageName == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name and image_name required")
	}
	if err := safename.ValidateImageName(req.ImageName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	// Building an image reads the source VM's root disk into a (global) image —
	// a cross-project data-exposure surface — so also require backup-level
	// access to the SOURCE VM, not just the global image.build perm.
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "backup.create", "operator"); err != nil {
		return nil, err
	}
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.BuildImage(ctx, req)
	}

	// Find the root disk.
	disks, err := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if err != nil || len(disks) == 0 {
		return nil, status.Errorf(codes.Internal, "no disks found for VM %q", req.VmName)
	}

	var srcDisk corrosion.DiskRecord
	for _, d := range disks {
		if d.DiskName == "root" {
			srcDisk = d
			break
		}
	}
	if srcDisk.Path == "" {
		srcDisk = disks[0]
	}

	// Create a flattened copy of the disk (no backing chain).
	destPath := s.images.ImagePath(req.ImageName)
	os.MkdirAll(filepath.Dir(destPath), 0755)

	slog.Info("building image from VM disk", "vm", req.VmName, "src", srcDisk.Path, "dest", destPath)
	if err := qcow2.Convert(ctx, srcDisk.Path, destPath, nil); err != nil {
		return nil, status.Errorf(codes.Internal, "convert image: %v", err)
	}

	// Get size and checksum.
	info, err := os.Stat(destPath)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "stat image: %v", err)
	}

	// Record in DB.
	now := time.Now().UTC().Format(time.RFC3339)
	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name:      req.ImageName,
		Format:    "qcow2",
		SourceURL: "build:" + req.VmName,
		SizeBytes: info.Size(),
	})
	corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
		ImageName: req.ImageName,
		HostName:  s.hostName,
		Path:      destPath,
		Status:    "ready",
		PulledAt:  now,
	})

	slog.Info("image built", "name", req.ImageName, "size", info.Size())
	s.publish("image.built", req.ImageName, "from="+req.VmName)
	return &pb.BuildImageResponse{
		Name:      req.ImageName,
		SizeBytes: info.Size(),
	}, nil
}
