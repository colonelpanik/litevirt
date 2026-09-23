package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const composeCloudInit = `name: ci-stack

images:
  test:
    source: file:///dev/null

networks:
  lan:
    external: true

vms:
  box-1:
    image: test
    cpu: 2
    memory: 1024
    disks:
      root: 10G
    labels:
      owner: fleet-test
    network:
      - name: lan
    placement:
      host: node-0
    cloud-init:
      userdata: |
        #cloud-config
        users:
          - name: ubuntu
            ssh_authorized_keys:
              - ssh-ed25519 AAAAexample someone@laptop
`

// Re-applying an UNCHANGED compose file to a stack whose VMs carry cloud-init
// must be a no-op. The regression: the planner compared the file's cloud-init
// against a `cloud_init_hash` spec field nothing ever wrote, so every existing
// VM planned as "cloud-init added" → update → delete + recreate under the
// default strategy, wiping its root disk. This drives the REAL DeployStack RPC
// (plan + execute) rather than the planner in isolation, so the stored-spec
// shape the planner reads is the one CreateVM actually writes.
func TestFleet_ComposeReapplyWithCloudInitDoesNotRecreate(t *testing.T) {
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 1})
	ctx := context.Background()
	node := c.Nodes[0]

	if err := node.DB.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES ('test', 'qcow2', 'file:///dev/null', 'deadbeef', 1024, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	if err := writeEmptyImageFile(node.Server.ImagePathForTests("test")); err != nil {
		t.Fatalf("stage image file: %v", err)
	}
	// The external network the VM attaches to must already exist. A direct
	// (macvtap) network is the family an unprivileged harness can attach a VM
	// NIC to: it resolves to "direct:<iface>" and never runs `ip link add`.
	if err := corrosion.UpsertNetwork(ctx, node.DB, corrosion.NetworkRecord{
		Name: "lan", Type: "direct", Config: `{"type":"direct","interface":"lo"}`,
	}); err != nil {
		t.Fatalf("seed external network: %v", err)
	}
	client := c.SelfClient(node)

	deployAndDrain(t, ctx, client, &pb.DeployStackRequest{ComposeYaml: composeCloudInit})
	first, err := corrosion.GetVM(ctx, node.DB, "box-1")
	if err != nil || first == nil {
		t.Fatalf("GetVM after first deploy: vm=%v err=%v", first, err)
	}
	firstUUID := specUUID(t, first.Spec)
	if firstUUID == "" {
		t.Fatal("first deploy stored a spec without a uuid")
	}
	eventsBefore := len(node.Virt.EventLog())

	// Every daemon start runs the legacy network-name migration over the
	// stored specs. It used to prefix EVERY attachment name with the stack,
	// including an external network attached under its plain name — so after
	// the first restart the blob pointed at "<stack>_lan", and the unchanged
	// compose attachment read as a network-topology change (a recreate).
	if err := corrosion.MigrateLegacyNetworkNames(ctx, node.DB); err != nil {
		t.Fatalf("MigrateLegacyNetworkNames: %v", err)
	}
	afterRestart, err := corrosion.GetVM(ctx, node.DB, "box-1")
	if err != nil || afterRestart == nil {
		t.Fatalf("GetVM after migration: vm=%v err=%v", afterRestart, err)
	}
	if !strings.Contains(afterRestart.Spec, `"network":[{"name":"lan"}]`) {
		t.Errorf("startup migration rewrote the external network attachment in the stored spec: %s", afterRestart.Spec)
	}

	// The server's own plan for the same file must be a no-op for the VM.
	for _, op := range dryRunPlan(t, ctx, client, composeCloudInit) {
		if op.VmName == "box-1" && op.Phase != string(compose.OpNoChange) {
			t.Fatalf("dry-run re-apply planned %q for box-1 (%s); want %s",
				op.Phase, op.Detail, compose.OpNoChange)
		}
	}

	// And executing it must not touch the domain.
	deployAndDrain(t, ctx, client, &pb.DeployStackRequest{ComposeYaml: composeCloudInit})
	for _, e := range node.Virt.EventLog()[eventsBefore:] {
		if e.Domain == "box-1" && (e.Op == "undefine" || e.Op == "destroy" || e.Op == "define") {
			t.Errorf("re-apply of an unchanged stack recorded a %q on box-1 — the VM was recreated", e.Op)
		}
	}
	second, err := corrosion.GetVM(ctx, node.DB, "box-1")
	if err != nil || second == nil {
		t.Fatalf("GetVM after second deploy: vm=%v err=%v", second, err)
	}
	if got := specUUID(t, second.Spec); got != firstUUID {
		t.Errorf("VM identity changed across re-apply: uuid %s → %s", firstUUID, got)
	}

	// An edit outside the coarse cpu/memory/image/cloud-init fields is still a
	// change: the planner compares the whole stored spec before calling a VM
	// unchanged, so a cpu-mode edit plans an update and says why.
	edited := strings.Replace(composeCloudInit, "    cpu: 2\n", "    cpu: 2\n    cpu-mode: host-passthrough\n", 1)
	if edited == composeCloudInit {
		t.Fatal("fixture edit did not apply")
	}
	planned := false
	for _, op := range dryRunPlan(t, ctx, client, edited) {
		if op.VmName == "box-1" && op.Phase == string(compose.OpUpdate) {
			planned = true
			if !strings.Contains(op.Detail, "cpu-mode") {
				t.Errorf("update detail should name the cpu-mode change, got %q", op.Detail)
			}
		}
	}
	if !planned {
		t.Error("cpu-mode edit with everything else unchanged was not planned as an update")
	}
}

// stageFakeGenisoimage puts a stand-in `genisoimage` first on PATH for the
// test. A VM with an explicit cloud-init block has its NoCloud ISO generated at
// create time by shelling out to genisoimage, and a failure there is fatal to
// the create (unlike the auto-generated minimal ISO, which is best-effort). CI
// runners do not ship the binary; the libvirt fake never reads the ISO, so an
// empty file at the -output path is all the create needs.
func stageFakeGenisoimage(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n# test stand-in: create the -output file, ignore everything else\n" +
		"while [ $# -gt 0 ]; do\n  if [ \"$1\" = \"-output\" ]; then : > \"$2\"; shift; fi\n  shift\ndone\n"
	if err := os.WriteFile(filepath.Join(dir, "genisoimage"), []byte(script), 0o755); err != nil {
		t.Fatalf("stage fake genisoimage: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// dryRunPlan runs DeployStack with DryRun and returns every progress message.
func dryRunPlan(t *testing.T, ctx context.Context, client pb.LiteVirtClient, yaml string) []*pb.DeployProgress {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: yaml, DryRun: true})
	if err != nil {
		t.Fatalf("DeployStack dry-run: %v", err)
	}
	var out []*pb.DeployProgress
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("dry-run stream: %v", err)
		}
		out = append(out, p)
	}
}

func specUUID(t *testing.T, specJSON string) string {
	t.Helper()
	var s struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal([]byte(specJSON), &s); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	return s.UUID
}
