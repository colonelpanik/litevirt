package health

import (
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func testDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNewChecker(t *testing.T) {
	db := testDB(t)
	c := NewChecker("host-a", "/etc/litevirt/pki", db)

	if c.hostName != "host-a" {
		t.Errorf("hostName = %s, want host-a", c.hostName)
	}
	if c.pkiDir != "/etc/litevirt/pki" {
		t.Errorf("pkiDir = %s", c.pkiDir)
	}
	if c.db == nil {
		t.Error("db should not be nil")
	}
	if c.tlsCfg != nil {
		t.Error("tlsCfg should be nil before Start")
	}
}

func TestConstants(t *testing.T) {
	if checkInterval != 2*time.Second {
		t.Errorf("checkInterval = %v, want 2s", checkInterval)
	}
	if checkTimeout != 3*time.Second {
		t.Errorf("checkTimeout = %v, want 3s", checkTimeout)
	}
	if suspectThreshold != 3 {
		t.Errorf("suspectThreshold = %d, want 3", suspectThreshold)
	}
}

func TestProbe_UnreachableHost(t *testing.T) {
	db := testDB(t)
	c := NewChecker("host-a", "/etc/litevirt/pki", db)

	// Probe a non-existent address — should return false quickly
	result := c.probe("127.0.0.1:1") // port 1 should be unreachable
	if result {
		t.Error("probe to unreachable host should return false")
	}
}
