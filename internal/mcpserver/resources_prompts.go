package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) registerResources(m *mcp.Server) {
	s.addResource(m, "litevirt://cluster/status", "cluster status", "Safe live cluster status summary.", s.resourceClusterStatus)
	s.addResource(m, "litevirt://cluster/hosts", "cluster hosts", "Safe live host inventory.", s.resourceHosts)
	s.addResource(m, "litevirt://cluster/vms", "cluster vms", "Safe live VM inventory capped by --max-list-items.", s.resourceVMs)
	s.addResource(m, "litevirt://cluster/projects", "cluster projects", "Safe live project inventory capped by --max-list-items.", s.resourceProjects)
}

func (s *Server) addResource(m *mcp.Server, uri, name, description string, h func(context.Context) (any, error)) {
	m.AddResource(&mcp.Resource{
		URI:         uri,
		Name:        name,
		Title:       name,
		Description: description,
		MIMEType:    jsonMIME,
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		out, err := h(ctx)
		if err != nil {
			return nil, err
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return nil, err
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI:      uri,
			MIMEType: jsonMIME,
			Text:     string(b),
		}}}, nil
	})
}

func (s *Server) resourceClusterStatus(ctx context.Context) (any, error) {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.GetClusterStatus(ctx, &emptypb.Empty{})
	})
	if err != nil {
		return nil, err
	}
	return clusterDTO(out.(*pb.ClusterStatus), s.opts.MaxListItems), nil
}

func (s *Server) resourceHosts(ctx context.Context) (any, error) {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListHosts(ctx, &pb.ListHostsRequest{})
	})
	if err != nil {
		return nil, err
	}
	items := out.(*pb.ListHostsResponse).GetHosts()
	return map[string]any{"hosts": mapHosts(truncate(items, s.opts.MaxListItems)), "truncated": len(items) > s.opts.MaxListItems}, nil
}

func (s *Server) resourceVMs(ctx context.Context) (any, error) {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListVMs(ctx, &pb.ListVMsRequest{})
	})
	if err != nil {
		return nil, err
	}
	items := out.(*pb.ListVMsResponse).GetVms()
	return map[string]any{"vms": mapVMs(truncate(items, s.opts.MaxListItems)), "truncated": len(items) > s.opts.MaxListItems}, nil
}

func (s *Server) resourceProjects(ctx context.Context) (any, error) {
	out, err := s.rpc(ctx, true, func(ctx context.Context, c pb.LiteVirtClient) (any, error) {
		return c.ListProjects(ctx, &emptypb.Empty{})
	})
	if err != nil {
		return nil, err
	}
	items := out.(*pb.ListProjectsResponse).GetProjects()
	return map[string]any{"projects": s.mapProjects(ctx, truncate(items, s.opts.MaxListItems), false, false), "truncated": len(items) > s.opts.MaxListItems}, nil
}

func (s *Server) registerPrompts(m *mcp.Server) {
	s.addPrompt(m, "incident_triage", "Incident triage", "Gather safe cluster context and guide incident triage.", s.promptIncidentTriage)
	s.addPrompt(m, "capacity_review", "Capacity review", "Gather capacity context and guide host/project capacity review.", s.promptCapacityReview)
	s.addPrompt(m, "tenant_isolation_review", "Tenant isolation review", "Gather project, network, pool, VM, and container context for tenant-isolation review.", s.promptTenantIsolationReview)
}

func (s *Server) addPrompt(m *mcp.Server, name, title, description string, h func(context.Context) string) {
	m.AddPrompt(&mcp.Prompt{Name: name, Title: title, Description: description}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return &mcp.GetPromptResult{
			Description: description,
			Messages: []*mcp.PromptMessage{{
				Role:    mcp.Role("user"),
				Content: &mcp.TextContent{Text: h(ctx)},
			}},
		}, nil
	})
}

func (s *Server) promptIncidentTriage(ctx context.Context) string {
	return strings.TrimSpace(fmt.Sprintf(`
Use the safe litevirt MCP read tools to triage the incident. Do not call mutation tools unless the operator explicitly asks and the MCP server was started with --allow-write.

Start with:
- %scluster_status
- %slist_hosts
- %slist_vms
- %slist_audit_log with a narrow limit and filters when possible

Current safe cluster snapshot:
%s
`, s.opts.ToolPrefix, s.opts.ToolPrefix, s.opts.ToolPrefix, s.opts.ToolPrefix, promptSnapshot(ctx, s)))
}

func (s *Server) promptCapacityReview(ctx context.Context) string {
	return strings.TrimSpace(fmt.Sprintf(`
Review litevirt capacity using only safe read tools. Compare host CPU, memory, disk usage, VM placement, storage-pool utilization, and project quota/usage.

Suggested tools:
- %scluster_status
- %slist_hosts
- %slist_storage_pools
- %slist_projects with include_quota=true and include_usage=true
- %slist_rebalance_proposals

Current safe cluster snapshot:
%s
`, s.opts.ToolPrefix, s.opts.ToolPrefix, s.opts.ToolPrefix, s.opts.ToolPrefix, s.opts.ToolPrefix, promptSnapshot(ctx, s)))
}

func (s *Server) promptTenantIsolationReview(ctx context.Context) string {
	return strings.TrimSpace(fmt.Sprintf(`
Review tenant isolation with safe read tools. Focus on project-owned versus global networks and storage pools, project quota/usage, and workloads attached to shared resources.

Suggested tools:
- %slist_projects with include_quota=true and include_usage=true
- %slist_networks
- %slist_storage_pools
- %slist_vms
- %slist_containers

Remember: global project-empty resources are intentionally shared administrative resources; project-owned resources should not be usable across projects.

Current safe cluster snapshot:
%s
`, s.opts.ToolPrefix, s.opts.ToolPrefix, s.opts.ToolPrefix, s.opts.ToolPrefix, s.opts.ToolPrefix, promptSnapshot(ctx, s)))
}
