package fleet

import (
	"context"
	"io"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestContainerMigrate_CancelDuringArchiveRestartsSource: a client that goes
// away mid-archive cancels the source daemon's request context, which kills the
// runtime's tar. That is a pre-handoff failure — the target was never contacted
// — so the source must be rolled back exactly as for any other archive failure:
// restarted, and the migration's operator-stop marker cleared.
//
// The rollback used to run on the same cancelled request context, so the
// restart and every state write failed with it and the source stayed stopped
// under operator-stop indefinitely: the reconciler honours that marker, so not
// even a restart policy brought it back.
func TestContainerMigrate_CancelDuringArchiveRestartsSource(t *testing.T) {
	c := ctMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	bg := context.Background()
	const name = "ct-cancel-archive"

	createContainer(t, c, src, name)
	if _, err := c.SelfClient(src).StartContainer(bg, &pb.StartContainerRequest{
		HostName: src.Name, Name: name,
	}); err != nil {
		t.Fatalf("start container: %v", err)
	}

	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	reachedSource := make(chan struct{})
	src.CT.OnExportCtx(func(serverCtx context.Context) {
		cancel()
		select {
		case <-serverCtx.Done():
			close(reachedSource)
		case <-time.After(10 * time.Second):
			t.Error("the client's cancellation never reached the source daemon's export")
		}
	})

	st, err := c.SelfClient(src).MigrateContainer(ctx, &pb.MigrateContainerRequest{
		Name: name, SourceHost: src.Name, TargetHost: dst.Name, RepoPath: stagingRepo(t),
	})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
	}
	if err == nil || err == io.EOF {
		t.Fatal("migrate completed although the client cancelled it mid-archive")
	}
	select {
	case <-reachedSource:
	case <-time.After(15 * time.Second):
		t.Fatal("the migrate never reached the archive with a cancelled context — this scenario proves nothing")
	}
	if got := len(src.CT.StopCalls()); got != 1 {
		t.Fatalf("source stopped %d times, want 1 — the migrate never reached the cold-transfer stop", got)
	}

	// The handler finishes its rollback after the client has already seen the
	// cancellation, so wait for the outcome rather than reading it once.
	var (
		state string
		rec   *corrosion.ContainerRecord
	)
	deadline := time.Now().Add(10 * time.Second)
	for {
		state = src.CT.State(name)
		rec, err = corrosion.GetContainer(bg, src.DB, src.Name, name)
		if err != nil {
			t.Fatalf("read source row: %v", err)
		}
		if state == "running" && rec != nil && rec.State == "running" && rec.StateDetail != "operator-stop" {
			break
		}
		if time.Now().After(deadline) {
			if rec == nil {
				t.Fatalf("source row is gone after a cancelled migrate (runtime state %q)", state)
			}
			t.Fatalf("after a cancelled migrate the source is runtime=%q row=(%q,%q), want it running with the "+
				"operator-stop marker cleared — the rollback ran on the cancelled request context",
				state, rec.State, rec.StateDetail)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if dst.CT.Exists(name) {
		t.Error("target holds a container copy after a cancelled migrate")
	}
}
