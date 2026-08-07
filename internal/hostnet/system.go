package hostnet

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// RealSystem is the production System: netplan exec, /etc/netplan IO, live
// interface state. The apply PROTOCOL is proven by the fake-backed unit tests;
// everything here is deliberately thin glue whose behavior only the lab can
// really prove (a wrong netplan interaction fails on real hardware, not in CI).
type RealSystem struct {
	// NetplanDir is /etc/netplan in production; a test/lab override elsewhere.
	NetplanDir string
	// AdvertiseIP and GRPCPort locate this daemon's own cluster listener for
	// the connectivity confirm.
	AdvertiseIP string
	GRPCPort    int

	// baselineGateway is captured just before an apply mutates runtime state:
	// "the gateway must still answer" is only meaningful if there was one.
	baselineGateway string
}

// settleDelay is how long ApplyWithRevert lets `netplan try` settle the new
// configuration before running the connectivity confirm. Too short and the
// confirm races DAD/route installation; the revert window bounds the total.
const settleDelay = 2 * time.Second

func (s *RealSystem) managedPath() string {
	dir := s.NetplanDir
	if dir == "" {
		dir = filepath.Dir(ManagedFile)
	}
	return filepath.Join(dir, filepath.Base(ManagedFile))
}

func (s *RealSystem) NetplanAvailable() error {
	dir := s.NetplanDir
	if dir == "" {
		dir = filepath.Dir(ManagedFile)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("%s is not present — this host is not netplan-managed", dir)
	}
	if _, err := exec.LookPath("netplan"); err != nil {
		return fmt.Errorf("the netplan binary is not installed")
	}
	return nil
}

func (s *RealSystem) ReadManagedFile() (string, bool, error) {
	b, err := os.ReadFile(s.managedPath())
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return string(b), true, nil
}

// WriteManagedFile writes atomically (temp + fsync + rename) with 0600 —
// newer netplan refuses world-readable files, and a torn write of a network
// config is exactly the half-state the journal exists to prevent.
func (s *RealSystem) WriteManagedFile(content string) error {
	path := s.managedPath()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".lv-netplan-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (s *RealSystem) RemoveManagedFile() error {
	err := os.Remove(s.managedPath())
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func (s *RealSystem) ForeignFiles() (map[string]string, error) {
	dir := s.NetplanDir
	if dir == "" {
		dir = filepath.Dir(ManagedFile)
	}
	out := map[string]string{}
	for _, pattern := range []string{"*.yaml", "*.yml"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			if filepath.Base(m) == filepath.Base(ManagedFile) {
				continue
			}
			b, err := os.ReadFile(m)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", m, err)
			}
			out[m] = string(b)
		}
	}
	return out, nil
}

func (s *RealSystem) ClusterInterface(ip string) (string, error) {
	want := net.ParseIP(ip)
	if want == nil {
		return "", nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(want) {
				return ifc.Name, nil
			}
		}
	}
	return "", nil
}

// ApplyWithRevert runs `netplan try --timeout=<window>`: netplan applies the
// written config and reverts it — kernel-side, surviving a daemon death —
// unless it is confirmed on stdin within the window. This daemon is its own
// confirmer over that LOCAL pipe, so it can accept or decline even when the
// new config broke every network path: the decision comes from confirm(), and
// a daemon that dies mid-window equals a decline.
func (s *RealSystem) ApplyWithRevert(ctx context.Context, window time.Duration, confirm func(context.Context) error) (bool, error) {
	s.baselineGateway = defaultGateway()

	if window <= 0 {
		// Recovery path: plain apply of an already-known-good restore config.
		out, err := exec.CommandContext(ctx, "netplan", "apply").CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("netplan apply: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return true, nil
	}

	secs := int(window / time.Second)
	if secs < 5 {
		secs = 5
	}
	cmd := exec.CommandContext(ctx, "netplan", "try", "--timeout", strconv.Itoa(secs))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("netplan try: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	// Let the new config settle before judging it; an early exit means netplan
	// itself rejected the config (parse/emit error) — that is a decline.
	select {
	case werr := <-done:
		stdin.Close()
		return false, fmt.Errorf("netplan try exited before confirmation: %v", werr)
	case <-time.After(settleDelay):
	case <-ctx.Done():
		stdin.Close()
		_ = cmd.Process.Signal(syscall.SIGINT) // revert now
		<-done
		return false, ctx.Err()
	}

	if cerr := confirm(ctx); cerr != nil {
		// Decline: SIGINT tells netplan try to revert immediately rather than
		// leaving the broken config live until the window expires.
		_ = cmd.Process.Signal(syscall.SIGINT)
		stdin.Close()
		<-done
		return false, nil
	}
	// Accept: ENTER on the local pipe.
	if _, err := stdin.Write([]byte("\n")); err != nil {
		_ = cmd.Process.Signal(syscall.SIGINT)
		stdin.Close()
		<-done
		return false, fmt.Errorf("confirm netplan try: %w", err)
	}
	stdin.Close()
	if werr := <-done; werr != nil {
		return false, fmt.Errorf("netplan try after confirmation: %w", werr)
	}
	return true, nil
}

// ConfirmConnectivity is the mechanical post-apply check from the design:
// the advertise address is still assigned, this daemon's own cluster listener
// answers a local dial, and — when there was one before the apply — the
// default gateway still answers a ping.
func (s *RealSystem) ConfirmConnectivity(ctx context.Context) error {
	if iface, err := s.ClusterInterface(s.AdvertiseIP); err != nil {
		return fmt.Errorf("enumerate interfaces: %w", err)
	} else if iface == "" {
		return fmt.Errorf("the advertise address %s is no longer assigned to any interface", s.AdvertiseIP)
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(s.AdvertiseIP, strconv.Itoa(s.GRPCPort)))
	if err != nil {
		return fmt.Errorf("this daemon's own gRPC listener no longer answers on %s:%d: %w", s.AdvertiseIP, s.GRPCPort, err)
	}
	conn.Close()
	if gw := s.baselineGateway; gw != "" {
		out, err := exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", gw).CombinedOutput()
		if err != nil {
			return fmt.Errorf("the default gateway %s stopped answering: %v (%s)", gw, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// defaultGateway parses the IPv4 default route's gateway from /proc/net/route
// ('' when there is none — a host without one is not judged by it).
func defaultGateway() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		// Iface Destination Gateway Flags ... — default route has dest 00000000.
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		gw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || gw == 0 {
			continue
		}
		// /proc/net/route is little-endian hex.
		return net.IPv4(byte(gw), byte(gw>>8), byte(gw>>16), byte(gw>>24)).String()
	}
	return ""
}
