package grpcapi

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/safename"
)

// SetImageLimits records the daemon's image pull/import bounds (disk-fill +
// SSRF guards). Zero values fall back to the image package defaults;
// blockedCIDRs nil → no URL-pull network deny policy.
func (s *Server) SetImageLimits(maxBytes int64, timeout time.Duration, blockedCIDRs []netip.Prefix) {
	s.imageMaxBytes = maxBytes
	s.imagePullTimeout = timeout
	s.imageBlockedCIDRs = blockedCIDRs
}

// imagePullOptions builds the configured PullOptions (defaults applied inside
// image.Pull when a field is zero). BlockedCIDRs is the opt-in URL-pull network
// deny policy; it does NOT apply to streamed Import/Push (byte-ceiling only).
func (s *Server) imagePullOptions() image.PullOptions {
	return image.PullOptions{Timeout: s.imagePullTimeout, MaxBytes: s.imageMaxBytes, BlockedCIDRs: s.imageBlockedCIDRs}
}

// maxImageBytes returns the effective image byte ceiling for streamed
// import/upload (source-side + target-side guards).
func (s *Server) maxImageBytes() int64 {
	if s.imageMaxBytes > 0 {
		return s.imageMaxBytes
	}
	return image.DefaultMaxImageBytes
}

func (s *Server) PullImage(req *pb.PullImageRequest, stream pb.LiteVirt_PullImageServer) error {
	// Images are a cluster-global library (matching PullOCIImage), so the check
	// is rooted; a project-scoped token can't pull into the shared store.
	if err := s.RequirePerm(stream.Context(), "/", "image.pull", "operator"); err != nil {
		return err
	}
	if err := safename.ValidateImageName(req.Name); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	slog.Info("pulling image", "name", req.Name, "url", req.SourceUrl)

	// Insert image + image_host records with "pulling" status so the image
	// is visible in ListImages immediately.
	bgCtx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	corrosion.InsertImage(bgCtx, s.db, corrosion.ImageRecord{
		Name:      req.Name,
		Format:    req.Format,
		SourceURL: req.SourceUrl,
	})
	corrosion.InsertImageHost(bgCtx, s.db, corrosion.ImageHostRecord{
		ImageName: req.Name,
		HostName:  s.hostName,
		Path:      s.images.ImagePath(req.Name),
		Status:    "pulling",
		PulledAt:  now,
	})

	// Create a progress channel
	progressCh := make(chan image.PullProgress, 10)

	// Start the download in a goroutine. Use a detached context so the
	// pull completes even if the client disconnects (#17).
	errCh := make(chan error, 1)
	go func() {
		pullErr := image.Pull(s.images, req.Name, req.SourceUrl, req.Checksum, s.imagePullOptions(), progressCh)
		errCh <- pullErr
		if pullErr != nil {
			slog.Error("image pull failed", "name", req.Name, "error", pullErr)
			corrosion.UpdateImageHostStatus(bgCtx, s.db, req.Name, s.hostName, "error")
			return
		}
		// Persist final result with a background context — stream ctx may be cancelled.
		s.persistImageRecord(req)
	}()

	// Stream progress to client and persist to DB for UI polling.
	// On client disconnect, keep draining the channel so the download
	// goroutine doesn't block on channel writes.
	var lastPersisted float32
	clientGone := false
	for p := range progressCh {
		// Persist progress every ~5% to avoid flooding the DB.
		if p.ProgressPct-lastPersisted >= 5 || p.Status == "complete" {
			corrosion.UpdateImageHostProgress(bgCtx, s.db, req.Name, s.hostName, p.ProgressPct)
			lastPersisted = p.ProgressPct
		}

		if !clientGone {
			if err := stream.Send(&pb.PullProgress{
				HostName:    s.hostName,
				ProgressPct: p.ProgressPct,
				Status:      p.Status,
				Error:       p.Error,
			}); err != nil {
				slog.Info("image pull: client disconnected, pull continues in background", "name", req.Name)
				clientGone = true
			}
		}
	}

	// Check for download error
	if err := <-errCh; err != nil {
		if clientGone {
			return nil // already logged, client won't see the error
		}
		return status.Errorf(codes.Internal, "pull image: %v", err)
	}

	slog.Info("image pulled successfully", "name", req.Name)
	return nil
}

// persistImageRecord writes the image and image_host records after a successful pull.
func (s *Server) persistImageRecord(req *pb.PullImageRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var sizeBytes int64
	if _, sz, err := s.images.DiskInfo(s.images.ImagePath(req.Name)); err == nil {
		sizeBytes = sz
	}

	now := time.Now().UTC().Format(time.RFC3339)
	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name:      req.Name,
		Format:    req.Format,
		SourceURL: req.SourceUrl,
		Checksum:  req.Checksum,
		SizeBytes: sizeBytes,
	})

	corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
		ImageName: req.Name,
		HostName:  s.hostName,
		Path:      s.images.ImagePath(req.Name),
		Status:    "ready",
		PulledAt:  now,
	})

	slog.Info("image record persisted", "name", req.Name)
}

func (s *Server) ListImages(ctx context.Context, _ *emptypb.Empty) (*pb.ListImagesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	images, err := corrosion.ListImages(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list images: %v", err)
	}

	resp := &pb.ListImagesResponse{}
	for _, img := range images {
		// Get hosts that have this image
		hosts, _ := corrosion.GetImageHosts(ctx, s.db, img.Name)
		var hostNames []string
		imgStatus := "ready"
		var progressPct float32
		for _, h := range hosts {
			hostNames = append(hostNames, h.HostName)
			if h.Status == "pulling" {
				imgStatus = "pulling"
				progressPct = h.ProgressPct
			} else if h.Status == "error" && imgStatus != "pulling" {
				imgStatus = "error"
			}
		}
		if len(hosts) == 0 {
			imgStatus = "ready"
		}

		resp.Images = append(resp.Images, &pb.Image{
			Name:        img.Name,
			Format:      img.Format,
			SourceUrl:   img.SourceURL,
			Checksum:    img.Checksum,
			SizeBytes:   img.SizeBytes,
			Hosts:       hostNames,
			Status:      imgStatus,
			ProgressPct: progressPct,
		})
	}

	return resp, nil
}

func (s *Server) DeleteImage(ctx context.Context, req *pb.DeleteImageRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteImage(ctx, s.db, req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete image: %v", err)
	}
	return &emptypb.Empty{}, nil
}
