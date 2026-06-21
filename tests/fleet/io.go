// Tiny stdlib-only helpers — kept out of cluster.go so the bootstrap
// flow there stays readable.

package fleet

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func mkdirAll(p string) error { return os.MkdirAll(p, 0o700) }

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// waitTCP polls a host:port until something accepts or the deadline
// expires. We use this to bridge the gap between go srv.Serve() and
// the first scenario dial — without it tests race the listener.
func waitTCP(host string, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("waiting for %s: deadline", addr)
}
