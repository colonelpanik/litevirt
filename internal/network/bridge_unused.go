package network

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"unicode"
)

// sysClassNet is the sysfs root RemoveBridgeIfUnused reads; a test points it
// at a temp tree.
var sysClassNet = "/sys/class/net"

// interfaceAddrs lists an interface's addresses; a seam for the same reason.
var interfaceAddrs = func(name string) ([]net.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return iface.Addrs()
}

// bridgeHasAddress reports whether an interface carries an address someone
// gave it: any IPv4 address, or any IPv6 address other than an fe80::/10
// link-local one. The kernel assigns that link-local address itself the first
// time a port brings the bridge's carrier up, and keeps it after the last port
// leaves, so it is no sign of use; counting it would keep every such bridge
// forever. An interface whose addresses cannot be read is an error: its state
// is unknown, so the caller must not treat it as unused.
func bridgeHasAddress(name string) (bool, error) {
	addrs, err := interfaceAddrs(name)
	if err != nil {
		return false, fmt.Errorf("read addresses of %s: %w", name, err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP == nil {
			return true, nil // an address of a shape not parsed here is still an address
		}
		if ipn.IP.To4() == nil && ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		return true, nil
	}
	return false, nil
}

// validLinkName applies the kernel's interface-name rules (dev_valid_name):
// 1..IFNAMSIZ-1 bytes, not "." or "..", no '/', ':' or whitespace. It also
// refuses a leading '-', which ip(8) would read as an option. A name that
// fails can name no interface, and must never reach a sysfs path or a command.
func validLinkName(name string) error {
	if name == "" || len(name) > maxIfaceName {
		return fmt.Errorf("interface name %q: must be 1..%d bytes", name, maxIfaceName)
	}
	if name == "." || name == ".." || name[0] == '-' {
		return fmt.Errorf("interface name %q is not valid", name)
	}
	for _, c := range name {
		if c == '/' || c == ':' || c == 0 || unicode.IsSpace(c) {
			return fmt.Errorf("interface name %q: contains %q", name, c)
		}
	}
	return nil
}

// RemoveBridgeIfUnused deletes bridge name from this host when it exists, is
// a bridge, has no ports and carries no address (IPv4, or IPv6 other than the
// kernel's fe80:: link-local one) — the shape of a bridge litevirt created
// that nothing uses any more. It
// reports whether it deleted it; an absent bridge is (false, nil). A name that
// is not a valid interface name, or a bridge whose addresses cannot be read,
// is refused with an error.
//
// It reads sysfs and the interface table; the only command it runs is the
// `ip link del` itself.
func RemoveBridgeIfUnused(name string) (bool, error) {
	if err := validLinkName(name); err != nil {
		return false, err
	}
	if _, err := os.Stat(filepath.Join(sysClassNet, name, "bridge")); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil // absent, or not a bridge
		}
		return false, err
	}
	hasAddr, err := bridgeHasAddress(name)
	if err != nil {
		return false, err
	}
	if hasAddr {
		return false, nil
	}
	// The ports are read last, right before the delete: a guest plugged in
	// between this read and the delete would be detached by it, so the window
	// is kept as short as one sysfs read. Nothing here can close it outright
	// (the kernel deletes a bridge with ports).
	ports, err := os.ReadDir(filepath.Join(sysClassNet, name, "brif"))
	if err != nil {
		return false, err
	}
	if len(ports) > 0 {
		return false, nil
	}
	if out, err := execCommand("ip", "link", "del", name); err != nil && !isNoSuchDevice(out) {
		return false, fmt.Errorf("ip link del %s: %w: %s", name, err, out)
	}
	// Whatever deleted it, a record that litevirt created this bridge no
	// longer describes anything; a bridge made later under the name is new.
	forgetCreatedBridge(name)
	return true, nil
}
