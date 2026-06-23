package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/tenancy"
)

// ConvertContainerToTemplate marks a stopped container as a template (a
// clone source that can't start), or with revert turns it back into a normal
// container. Mirrors ConvertToTemplate for VMs. Container clones are always
// full copies (no qcow2 backing), so a template has no linked-clone
// dependencies — revert is always safe.
func (s *Server) ConvertContainerToTemplate(ctx context.Context, req *pb.ConvertContainerToTemplateRequest) (*pb.Container, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	project := s.containerProject(ctx, req.HostName, req.Name)
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Name), "ct.update", "operator"); err != nil {
		return nil, err
	}
	host, rec, err := s.resolveContainerHost(ctx, req.HostName, req.Name)
	if err != nil {
		return nil, err
	}
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward convert-template: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.ConvertContainerToTemplate(ctx, req)
	}

	if req.Revert {
		if !rec.IsTemplate {
			return nil, status.Errorf(codes.FailedPrecondition, "%q is not a template", req.Name)
		}
		if err := corrosion.SetContainerTemplate(ctx, s.db, host, req.Name, false); err != nil {
			return nil, status.Errorf(codes.Internal, "revert template: %v", err)
		}
		s.audit(ctx, "ct.template.revert", req.Name, "project="+project, "ok")
	} else {
		if rec.IsTemplate {
			return nil, status.Errorf(codes.FailedPrecondition, "%q is already a template", req.Name)
		}
		if rec.State != "stopped" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"container %q must be stopped to convert to a template (current: %s)", req.Name, rec.State)
		}
		if err := corrosion.SetContainerTemplate(ctx, s.db, host, req.Name, true); err != nil {
			return nil, status.Errorf(codes.Internal, "convert to template: %v", err)
		}
		s.audit(ctx, "ct.template.convert", req.Name, "project="+project, "ok")
	}
	rec.IsTemplate = !req.Revert
	return toPbContainer(*rec), nil
}

// CloneContainer creates a new container as a full copy of a template or
// stopped source, with a fresh identity (new hostname/MAC/machine-id). The
// clone is created on the source's host (its rootfs lives there) and admitted
// against the project quota. Mirrors CloneVM (full-copy only — no linked
// clones for containers).
func (s *Server) CloneContainer(ctx context.Context, req *pb.CloneContainerRequest) (*pb.Container, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.Source == "" || req.Target == "" {
		return nil, status.Error(codes.InvalidArgument, "source and target required")
	}
	if !validResourceName(req.Target) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid target name %q", req.Target)
	}
	host, src, err := s.resolveContainerHost(ctx, req.HostName, req.Source)
	if err != nil {
		return nil, err
	}
	project := tenancy.NormalizeProject(req.Project)
	if req.Project == "" {
		project = tenancy.NormalizeProject(src.Project)
	}
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, req.Target), "ct.create", "operator"); err != nil {
		s.audit(ctx, "ct.clone", req.Target, "project="+project, "denied")
		return nil, err
	}
	// The clone is created where the source's rootfs lives.
	if host != s.hostName {
		c, conn, derr := s.peerClient(ctx, host)
		if derr != nil {
			return nil, status.Errorf(codes.Unavailable, "forward clone: %v", derr)
		}
		defer conn.Close()
		req.HostName = host
		return c.CloneContainer(ctx, req)
	}
	if s.containerRuntime == nil {
		return nil, status.Error(codes.Unavailable, "container runtime not wired on this host")
	}
	// Consistent rootfs: clone a template or a stopped container (a running
	// container's rootfs isn't quiescent). Mirrors CloneVM.
	if !src.IsTemplate && src.State != "stopped" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"source %q must be a template or stopped to clone (current: %s)", req.Source, src.State)
	}
	if existing, _ := corrosion.GetContainer(ctx, s.db, s.hostName, req.Target); existing != nil {
		return nil, status.Errorf(codes.AlreadyExists, "container %q already exists on host %q", req.Target, s.hostName)
	}

	unlock := s.lockVM("ct/" + req.Target)
	defer unlock()

	// Quota: the clone draws down the project's vCPU/Mem budget (like CreateContainer).
	if s.tenancy != nil {
		if err := s.tenancy.Admit(ctx, project, tenancy.QuotaRequest{VCPU: src.CPULimit, MemMiB: src.MemMiB}); err != nil {
			return nil, status.Errorf(codes.ResourceExhausted, "%v", err)
		}
	}

	if err := s.containerRuntime.CloneContainer(ctx, req.Source, req.Target); err != nil {
		s.audit(ctx, "ct.clone", req.Target, "project="+project+" source="+req.Source, "error")
		return nil, status.Errorf(codes.Internal, "clone: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	rec := corrosion.ContainerRecord{
		HostName: s.hostName, Name: req.Target, State: "stopped",
		Image: src.Image, CPULimit: src.CPULimit, MemMiB: src.MemMiB,
		Labels: src.Labels, RestartPolicy: src.RestartPolicy,
		Project: project, CreatedAt: now,
		// A clone is a normal container, never a template.
	}
	if err := corrosion.UpsertContainer(ctx, s.db, rec); err != nil {
		return nil, status.Errorf(codes.Internal, "persist clone: %v", err)
	}

	if req.Start {
		if err := s.containerRuntime.StartContainer(ctx, req.Target); err != nil {
			s.audit(ctx, "ct.clone", req.Target, "project="+project+" (start failed)", "error")
			return nil, status.Errorf(codes.Internal, "cloned but start failed: %v", err)
		}
		_ = corrosion.SetContainerStateDetail(ctx, s.db, s.hostName, req.Target, "running", "")
		rec.State = "running"
	}
	s.audit(ctx, "ct.clone", req.Target, fmt.Sprintf("project=%s source=%s", project, req.Source), "ok")
	slog.Info("container cloned", "source", req.Source, "target", req.Target, "host", s.hostName)
	return toPbContainer(rec), nil
}
