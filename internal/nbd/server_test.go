package nbd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeDevice is a BlockDevice backed by a bytes.Reader for tests.
type fakeDevice struct {
	data []byte
}

func (f *fakeDevice) Size() int64                          { return int64(len(f.data)) }
func (f *fakeDevice) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	return bytes.NewReader(f.data).ReadAt(p, off)
}

// TestNBDServer_OPTGoAndRead drives a real-bytes-on-the-wire round
// trip: spin up the server, do the newstyle handshake + OPT_GO, then
// issue NBD_CMD_READ and assert the response payload matches the
// backing device.
func TestNBDServer_OPTGoAndRead(t *testing.T) {
	dev := &fakeDevice{data: bytes.Repeat([]byte{0xAB}, 1024*128)}
	srv := &Server{ExportName: "vm1-root", Dev: dev}
	addr, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(ctx)
	}()
	defer func() {
		srv.Stop()
		wg.Wait()
	}()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	size, err := clientHandshake(conn, "vm1-root")
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if size != int64(len(dev.data)) {
		t.Fatalf("size = %d, want %d", size, len(dev.data))
	}

	got, err := clientRead(conn, 0, 4096)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, dev.data[:4096]) {
		t.Fatalf("read payload mismatch")
	}
}

// TestNBDServer_WriteReturnsEPERM proves the export is read-only: a
// client write returns EPERM rather than silently succeeding.
func TestNBDServer_WriteReturnsEPERM(t *testing.T) {
	dev := &fakeDevice{data: bytes.Repeat([]byte{0xCD}, 1024)}
	srv := &Server{ExportName: "ro", Dev: dev}
	addr, err := srv.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = srv.Serve(ctx)
	}()
	defer func() {
		srv.Stop()
		wg.Wait()
	}()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := clientHandshake(conn, "ro"); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if code, err := clientWrite(conn, 0, []byte("nope")); err != nil {
		t.Fatalf("write: %v", err)
	} else if code != nbdEPerm {
		t.Fatalf("write reply code = %d, want %d (EPERM)", code, nbdEPerm)
	}
}

// ── tiny in-test NBD client (just enough to exercise the server) ──

func clientHandshake(conn net.Conn, export string) (int64, error) {
	// Read greeting: NBDMAGIC + IHAVEOPT + 2-byte handshake flags.
	var magic1, magic2 uint64
	var srvFlags uint16
	if err := binary.Read(conn, binary.BigEndian, &magic1); err != nil {
		return 0, err
	}
	if err := binary.Read(conn, binary.BigEndian, &magic2); err != nil {
		return 0, err
	}
	if err := binary.Read(conn, binary.BigEndian, &srvFlags); err != nil {
		return 0, err
	}
	if magic1 != nbdInitMagic || magic2 != nbdIHaveOpt {
		return 0, errors.New("bad greeting")
	}
	// Send client flags.
	var clientFlags uint32 = 1 // NBD_FLAG_C_FIXED_NEWSTYLE
	if err := binary.Write(conn, binary.BigEndian, clientFlags); err != nil {
		return 0, err
	}

	// Send NBD_OPT_GO with name + 0 info requests.
	data := make([]byte, 0)
	data = binary.BigEndian.AppendUint32(data, uint32(len(export)))
	data = append(data, []byte(export)...)
	data = binary.BigEndian.AppendUint16(data, 0)

	if err := binary.Write(conn, binary.BigEndian, nbdIHaveOpt); err != nil {
		return 0, err
	}
	if err := binary.Write(conn, binary.BigEndian, nbdOptGo); err != nil {
		return 0, err
	}
	if err := binary.Write(conn, binary.BigEndian, uint32(len(data))); err != nil {
		return 0, err
	}
	if _, err := conn.Write(data); err != nil {
		return 0, err
	}

	// Loop replies until NBD_REP_ACK.
	var size int64
	for {
		var replyMagic uint64
		var opt, code, replyLen uint32
		if err := binary.Read(conn, binary.BigEndian, &replyMagic); err != nil {
			return 0, err
		}
		if err := binary.Read(conn, binary.BigEndian, &opt); err != nil {
			return 0, err
		}
		if err := binary.Read(conn, binary.BigEndian, &code); err != nil {
			return 0, err
		}
		if err := binary.Read(conn, binary.BigEndian, &replyLen); err != nil {
			return 0, err
		}
		payload := make([]byte, replyLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return 0, err
		}
		switch code {
		case nbdRepAck:
			return size, nil
		case nbdRepInfo:
			if len(payload) >= 10 {
				size = int64(binary.BigEndian.Uint64(payload[2:10]))
			}
		default:
			return 0, errors.New("bad rep code")
		}
	}
}

func clientRead(conn net.Conn, off uint64, length uint32) ([]byte, error) {
	if err := writeNBDRequest(conn, nbdCmdRead, 0xAA, off, length); err != nil {
		return nil, err
	}
	return readNBDReply(conn, length)
}

func clientWrite(conn net.Conn, off uint64, data []byte) (uint32, error) {
	if err := writeNBDRequest(conn, nbdCmdWrite, 0xBB, off, uint32(len(data))); err != nil {
		return 0, err
	}
	if _, err := conn.Write(data); err != nil {
		return 0, err
	}
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

func writeNBDRequest(conn net.Conn, cmd uint16, handle, off uint64, length uint32) error {
	if err := binary.Write(conn, binary.BigEndian, nbdRequestMagic); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, uint16(0)); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, cmd); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, handle); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, off); err != nil {
		return err
	}
	return binary.Write(conn, binary.BigEndian, length)
}

func readNBDReply(conn net.Conn, length uint32) ([]byte, error) {
	var magic, code uint32
	var handle uint64
	if err := binary.Read(conn, binary.BigEndian, &magic); err != nil {
		return nil, err
	}
	if err := binary.Read(conn, binary.BigEndian, &code); err != nil {
		return nil, err
	}
	if err := binary.Read(conn, binary.BigEndian, &handle); err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, errors.New("nbd reply error")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}
