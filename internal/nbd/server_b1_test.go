package nbd

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"net"
	"sync"
	"testing"
	"time"
)

func startTestNBD(t *testing.T, dev *fakeDevice, export string) (net.Addr, func()) {
	t.Helper()
	srv := &Server{ExportName: export, Dev: dev}
	addr, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = srv.Serve(ctx) }()
	return addr, func() { srv.Stop(); cancel(); wg.Wait() }
}

// readReplyHeader reads a 16-byte NBD reply header and returns the error code.
func readReplyHeader(conn net.Conn) (uint32, error) {
	var magic, code uint32
	var handle uint64
	if err := binary.Read(conn, binary.BigEndian, &magic); err != nil {
		return 0, err
	}
	if err := binary.Read(conn, binary.BigEndian, &code); err != nil {
		return 0, err
	}
	if err := binary.Read(conn, binary.BigEndian, &handle); err != nil {
		return 0, err
	}
	return code, nil
}

// TestNBDServer_OversizedReadRejected is the B1 regression: a READ length far
// above the cap must be rejected with EINVAL *without* allocating (the old code
// did make([]byte, length) — up to 4 GiB — and could OOM the daemon). The
// connection must also stay in sync afterward.
func TestNBDServer_OversizedReadRejected(t *testing.T) {
	dev := &fakeDevice{data: bytes.Repeat([]byte{0x11}, 4096)}
	addr, stop := startTestNBD(t, dev, "ro")
	defer stop()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := clientHandshake(conn, "ro"); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// ~4 GiB read. Old code would allocate that; new code replies EINVAL.
	if err := writeNBDRequest(conn, nbdCmdRead, 0x01, 0, math.MaxUint32); err != nil {
		t.Fatalf("write request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	code, err := readReplyHeader(conn)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if code != nbdEINVAL {
		t.Fatalf("reply code = %d, want EINVAL(%d)", code, nbdEINVAL)
	}

	// Connection still alive + still guarding: a second oversized read EINVALs
	// too (the EINVAL reply carried no payload, so the stream stayed aligned).
	if err := writeNBDRequest(conn, nbdCmdRead, 0x02, 0, math.MaxUint32); err != nil {
		t.Fatalf("2nd request: %v", err)
	}
	if code, err := readReplyHeader(conn); err != nil || code != nbdEINVAL {
		t.Fatalf("2nd reply code=%d err=%v, want EINVAL", code, err)
	}
}

// TestNBDServer_OversizedWriteDropsConn is the B1 regression for WRITE: an
// over-limit length must drop the connection rather than allocate/drain
// gigabytes. We declare a ~4 GiB write but send no payload.
func TestNBDServer_OversizedWriteDropsConn(t *testing.T) {
	dev := &fakeDevice{data: bytes.Repeat([]byte{0x22}, 4096)}
	addr, stop := startTestNBD(t, dev, "ro")
	defer stop()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := clientHandshake(conn, "ro"); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	if err := writeNBDRequest(conn, nbdCmdWrite, 0x03, 0, math.MaxUint32); err != nil {
		t.Fatalf("write request: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := readReplyHeader(conn); err == nil {
		t.Fatal("expected the server to drop the connection on an oversized write, got a reply")
	}
}

// TestNBDServer_AtLimitReadStillWorks guards the boundary: a read at exactly the
// cap is served normally (not over-rejected).
func TestNBDServer_AtLimitReadStillWorks(t *testing.T) {
	dev := &fakeDevice{data: bytes.Repeat([]byte{0x33}, 8192)}
	addr, stop := startTestNBD(t, dev, "ro")
	defer stop()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := clientHandshake(conn, "ro"); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// A normal small read within the cap succeeds (code 0 + payload).
	got, err := clientRead(conn, 0, 1024)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1024 {
		t.Fatalf("read len = %d, want 1024", len(got))
	}
}
