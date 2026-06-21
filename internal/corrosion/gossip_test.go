package corrosion

import (
	"context"
	"testing"
)

func TestDelegate_NodeMeta(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	d := &delegate{client: c}
	meta := d.NodeMeta(512)
	if string(meta) != "test-node" {
		t.Errorf("NodeMeta = %q, want test-node", meta)
	}
}

func TestDelegate_NotifyMsg_NoOp(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	InitSchema(context.Background(), c)

	d := &delegate{client: c}

	// All messages are ignored — memberlist is used for membership only.
	d.NotifyMsg(nil)
	d.NotifyMsg([]byte{})
	d.NotifyMsg([]byte("some data message"))

	// Verify no data was applied.
	hosts, _ := ListHosts(context.Background(), c)
	if len(hosts) != 0 {
		t.Errorf("NotifyMsg should be no-op, got %d hosts", len(hosts))
	}
}

func TestDelegate_GetBroadcasts_ReturnsNil(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	d := &delegate{client: c}
	msgs := d.GetBroadcasts(0, 100)
	if msgs != nil {
		t.Errorf("GetBroadcasts should return nil, got %d", len(msgs))
	}
}

func TestDelegate_LocalState_ReturnsNil(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	d := &delegate{client: c}
	// Both join and non-join should return nil — replicator handles state sync.
	if state := d.LocalState(false); state != nil {
		t.Errorf("LocalState(false) should return nil")
	}
	if state := d.LocalState(true); state != nil {
		t.Errorf("LocalState(true) should return nil")
	}
}

func TestDelegate_MergeRemoteState_NoOp(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	d := &delegate{client: c}
	// Should not panic.
	d.MergeRemoteState(nil, false)
	d.MergeRemoteState([]byte("data"), true)
}

func TestSlogWriter(t *testing.T) {
	w := &slogWriter{}
	n, err := w.Write([]byte("test log message"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 16 {
		t.Errorf("Write returned %d, want 16", n)
	}
}
