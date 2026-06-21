package ui

import (
	"log/slog"
	"net/http"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	images, _ := s.grpc.ListImages(ctx, &emptypb.Empty{})
	data := s.pageData("Images", "images")
	data["Images"] = images.GetImages()
	data["HasPulling"] = hasImagePulling(images.GetImages())
	s.renderPage(w, "images.html", data)
}

func (s *Server) handleImagesTable(w http.ResponseWriter, r *http.Request) {
	ctx := s.uiBearerCtx(r)
	images, _ := s.grpc.ListImages(ctx, &emptypb.Empty{})
	data := map[string]any{
		"Images":     images.GetImages(),
		"HasPulling": hasImagePulling(images.GetImages()),
	}
	s.renderFragment(w, "images_table.html", data)
}

func hasImagePulling(images []*pb.Image) bool {
	for _, img := range images {
		if img.GetStatus() == "pulling" {
			return true
		}
	}
	return false
}

func (s *Server) handlePullImageModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "pull_image_modal.html", nil)
}

func (s *Server) handleDeleteImage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.grpc.DeleteImage(s.uiBearerCtx(r), &pb.DeleteImageRequest{Name: name}); err != nil {
		sendToast(w, "Delete image failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Image '"+name+"' deleted", "success")
	w.Header().Set("HX-Redirect", "/images")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handlePullImage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	name := r.FormValue("name")
	url := r.FormValue("source_url")
	if name == "" || url == "" {
		http.Error(w, "name and source_url required", 400)
		return
	}
	stream, err := s.grpc.PullImage(s.uiBearerCtx(r), &pb.PullImageRequest{
		Name:      name,
		SourceUrl: url,
	})
	if err != nil {
		sendToast(w, "Pull failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	// Read first progress message to confirm pull started, then let it
	// continue in the background (server detaches on client disconnect).
	stream.Recv()
	sendToast(w, "Pulling image '"+name+"'", "success")
	w.Header().Set("HX-Redirect", "/images")
	w.WriteHeader(http.StatusOK)
}

// ── Build Image from VM ─────────────────────────────────────────────────────

func (s *Server) handleBuildImageModal(w http.ResponseWriter, r *http.Request) {
	vms, _ := s.grpc.ListVMs(s.uiBearerCtx(r), &pb.ListVMsRequest{})
	s.renderFragment(w, "build_image_modal.html", map[string]any{
		"VMs": vms.GetVms(),
	})
}

func (s *Server) handleBuildImage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	vmName := r.FormValue("vm_name")
	imageName := r.FormValue("image_name")
	if vmName == "" || imageName == "" {
		http.Error(w, "vm_name and image_name required", 400)
		return
	}
	_, err := s.grpc.BuildImage(s.uiBearerCtx(r), &pb.BuildImageRequest{
		VmName:    vmName,
		ImageName: imageName,
	})
	if err != nil {
		slog.Error("UI: build image failed", "error", err)
		sendToast(w, "Build image failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Image '"+imageName+"' built from VM '"+vmName+"'", "success")
	w.Header().Set("HX-Redirect", "/images")
	w.WriteHeader(http.StatusOK)
}

// ── Push Image ──────────────────────────────────────────────────────────────

func (s *Server) handlePushImageModal(w http.ResponseWriter, r *http.Request) {
	images, _ := s.grpc.ListImages(s.uiBearerCtx(r), &emptypb.Empty{})
	hosts, _ := s.grpc.ListHosts(s.uiBearerCtx(r), &pb.ListHostsRequest{})
	s.renderFragment(w, "push_image_modal.html", map[string]any{
		"Images": images.GetImages(),
		"Hosts":  hosts.GetHosts(),
	})
}

func (s *Server) handlePushImage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	imageName := r.FormValue("image_name")
	targetHost := r.FormValue("target_host")
	if imageName == "" || targetHost == "" {
		http.Error(w, "image_name and target_host required", 400)
		return
	}
	stream, err := s.grpc.PushImage(s.uiBearerCtx(r), &pb.PushImageRequest{
		Name:       imageName,
		TargetHost: targetHost,
	})
	if err != nil {
		slog.Error("UI: push image failed", "error", err)
		sendToast(w, "Push failed: "+err.Error(), "error")
		w.WriteHeader(500)
		return
	}
	// Consume progress stream to completion.
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
		sendToast(w, "Push error: "+lastErr, "error")
		w.WriteHeader(500)
		return
	}
	sendToast(w, "Image '"+imageName+"' pushed to '"+targetHost+"'", "success")
	w.Header().Set("HX-Redirect", "/images")
	w.WriteHeader(http.StatusOK)
}
