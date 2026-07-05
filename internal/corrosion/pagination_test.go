package corrosion

import (
	"context"
	"fmt"
	"testing"
)

// TestListContainersPage_CompositeKeyset verifies the (host_name, name) composite
// keyset pages through all containers in order with no overlap — name alone is not
// unique across hosts, so the cursor must be the pair.
func TestListContainersPage_CompositeKeyset(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	// Same container name on two hosts + others, inserted out of order.
	seed := []struct{ host, name string }{
		{"host-b", "ct-1"}, {"host-a", "ct-2"}, {"host-a", "ct-1"}, {"host-b", "ct-2"}, {"host-a", "ct-3"},
	}
	for _, s := range seed {
		if err := UpsertContainer(ctx, c, ContainerRecord{HostName: s.host, Name: s.name, State: "running"}); err != nil {
			t.Fatalf("UpsertContainer %s/%s: %v", s.host, s.name, err)
		}
	}

	var seen []string
	afterHost, afterName := "", ""
	pages := 0
	for {
		page, err := ListContainersPage(ctx, c, "", afterHost, afterName, 2)
		if err != nil {
			t.Fatalf("ListContainersPage: %v", err)
		}
		if len(page) == 0 {
			break
		}
		pages++
		for _, r := range page {
			seen = append(seen, r.HostName+"/"+r.Name)
		}
		if len(page) < 2 {
			break
		}
		last := page[len(page)-1]
		afterHost, afterName = last.HostName, last.Name
		if pages > 10 {
			t.Fatal("did not terminate")
		}
	}
	// Ordered by (host_name, name).
	want := []string{"host-a/ct-1", "host-a/ct-2", "host-a/ct-3", "host-b/ct-1", "host-b/ct-2"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("composite-keyset order = %v, want %v", seen, want)
	}
}
