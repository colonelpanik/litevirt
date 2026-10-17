package network

import (
	"os"
	"testing"
)

// TestMain points the created-bridge records at a temp dir, so a test that
// reaches EnsureBridge's create path never writes into the host's /run.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lv-network-test-bridges-")
	if err != nil {
		panic(err)
	}
	createdBridgeDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
