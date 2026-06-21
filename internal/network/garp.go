package network

import (
	"fmt"
	"log/slog"
)

// SendGARP sends a gratuitous ARP on the given bridge for the specified IP.
// This updates switch MAC tables after a VM migration. Uses arping(8).
func SendGARP(bridge, ip string) error {
	if bridge == "" || ip == "" {
		return nil
	}
	// arping -A: ARP reply mode (gratuitous)
	// -c 3: send 3 packets
	// -I <bridge>: send on this interface
	out, err := execCommand("arping", "-A", "-c", "3", "-I", bridge, ip)
	if err != nil {
		return fmt.Errorf("arping on %s for %s: %w: %s", bridge, ip, err, out)
	}
	slog.Debug("sent gratuitous ARP", "bridge", bridge, "ip", ip)
	return nil
}

// SendGARPBestEffort sends GARP but only logs on failure (non-fatal).
func SendGARPBestEffort(bridge, ip string) {
	if err := SendGARP(bridge, ip); err != nil {
		slog.Warn("gratuitous ARP failed (non-fatal)", "bridge", bridge, "ip", ip, "error", err)
	}
}
