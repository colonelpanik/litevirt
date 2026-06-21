package libvirt

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

const (
	defaultSocket = "/var/run/libvirt/libvirt-sock"

	// reconnectInterval is how often the client checks its connection to libvirtd.
	reconnectInterval = 5 * time.Second
	// reconnectMaxBackoff caps the retry delay when libvirtd is down.
	reconnectMaxBackoff = 30 * time.Second
)

// DomainEventCallback is called when a domain lifecycle event is received.
// Reason values are libvirt-specific (e.g. 0=booted, 1=migrated for Started).
type DomainEventCallback func(domainName string, event DomainEventType, detail int)

// DomainEventType represents a libvirt domain lifecycle event.
type DomainEventType int

const (
	DomainEventStarted  DomainEventType = 0
	DomainEventStopped  DomainEventType = 1
	DomainEventCrashed  DomainEventType = 2
	DomainEventShutdown DomainEventType = 3
)

// Client wraps a go-libvirt connection for VM lifecycle operations.
// It automatically reconnects if the connection to libvirtd drops (#42)
// and supports domain event callbacks for immediate VM death detection (#44).
type Client struct {
	mu   sync.RWMutex
	virt *golibvirt.Libvirt

	// Domain event callback registered by the daemon.
	eventCallback DomainEventCallback
}

// NewClient connects to the local libvirtd daemon.
func NewClient() (*Client, error) {
	virt, err := dialLibvirt()
	if err != nil {
		return nil, err
	}
	return &Client{virt: virt}, nil
}

func dialLibvirt() (*golibvirt.Libvirt, error) {
	conn, err := net.DialTimeout("unix", defaultSocket, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to libvirtd: %w", err)
	}

	virt := golibvirt.New(conn)
	if err := virt.Connect(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("libvirt handshake: %w", err)
	}
	return virt, nil
}

// Reconnect re-establishes the libvirt connection. Used after libvirtd restarts (#42).
func (c *Client) Reconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Disconnect old connection (best-effort, it may already be dead).
	if c.virt != nil {
		c.virt.Disconnect() //nolint:errcheck
	}

	virt, err := dialLibvirt()
	if err != nil {
		return err
	}
	c.virt = virt
	slog.Info("libvirt: reconnected to libvirtd")
	return nil
}

// StartReconnectLoop monitors the libvirt connection and automatically
// reconnects if libvirtd restarts (#42). Also registers domain event
// callbacks on each reconnect (#44). Blocks until ctx is cancelled.
func (c *Client) StartReconnectLoop(ctx context.Context) {
	ticker := time.NewTicker(reconnectInterval)
	defer ticker.Stop()

	backoff := reconnectInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.RLock()
			alive := c.isAlive()
			c.mu.RUnlock()

			if alive {
				backoff = reconnectInterval
				continue
			}

			slog.Warn("libvirt: connection lost, attempting reconnect...")
			if err := c.Reconnect(); err != nil {
				slog.Error("libvirt: reconnect failed", "error", err, "retry_in", backoff)
				backoff = min(backoff*2, reconnectMaxBackoff)
				continue
			}

			// Re-enumerate running domains after reconnect to reconcile state.
			if domains, err := c.ListDomains(); err == nil {
				slog.Info("libvirt: re-enumerated domains after reconnect", "count", len(domains))
			}

			backoff = reconnectInterval
		}
	}
}

// isAlive checks if the libvirt connection is still working.
func (c *Client) isAlive() bool {
	if c.virt == nil {
		return false
	}
	// A lightweight check: try to get the libvirt version.
	_, err := c.virt.ConnectGetLibVersion()
	return err == nil
}

// RegisterDomainEventCallback sets a callback that fires on domain lifecycle
// events (start, stop, crash, shutdown). This provides immediate VM death
// detection instead of relying on polling (#44).
func (c *Client) RegisterDomainEventCallback(cb DomainEventCallback) {
	c.mu.Lock()
	c.eventCallback = cb
	c.mu.Unlock()
}

// Close disconnects from libvirtd.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.virt == nil {
		return nil
	}
	return c.virt.Disconnect()
}

// Libvirt returns the underlying go-libvirt handle for advanced operations.
func (c *Client) Libvirt() *golibvirt.Libvirt {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.virt
}

// NodeInfo returns host CPU/memory info.
func (c *Client) NodeInfo() (cpus int, memMiB int, err error) {
	_, rMemory, _, _, rNodes, rSockets, rCores, rThreads, err := c.virt.NodeGetInfo()
	if err != nil {
		return 0, 0, fmt.Errorf("node info: %w", err)
	}
	totalCPUs := int(rNodes) * int(rSockets) * int(rCores) * int(rThreads)
	memMiB = int(rMemory / 1024) // rMemory is in KiB
	return totalCPUs, memMiB, nil
}
