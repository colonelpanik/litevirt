package grpcapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// restoreLiveStream is a server-streaming double that buffers Send'd
// frames and lets the test trigger a cancel by closing cancelCh.
type restoreLiveStream struct {
	ctx context.Context
	mu  sync.Mutex
	out []*pb.RestoreLiveProgress
}

func (s *restoreLiveStream) Send(m *pb.RestoreLiveProgress) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.out = append(s.out, m)
	return nil
}
func (s *restoreLiveStream) Context() context.Context     { return s.ctx }
func (s *restoreLiveStream) SetHeader(metadata.MD) error  { return nil }
func (s *restoreLiveStream) SendHeader(metadata.MD) error { return nil }
func (s *restoreLiveStream) SetTrailer(metadata.MD)       {}
func (s *restoreLiveStream) SendMsg(any) error            { return nil }
func (s *restoreLiveStream) RecvMsg(any) error            { return io.EOF }

var _ grpc.ServerStreamingServer[pb.RestoreLiveProgress] = (*restoreLiveStream)(nil)

// TestRestoreLive_EndToEnd seeds a real backup repo, kicks the RPC,
// connects an NBD client to the advertised URL, and reads bytes back
// that match the original disk content. Proves the entire chain
// (manifest reader → NBD server → wire protocol) works without real
// libvirt or qemu.
func TestRestoreLive_EndToEnd(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"

	// 1. Seed a repo with a single manifest of pseudo-random bytes.
	repoDir := t.TempDir()
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}
	disk := make([]byte, 4*1024*1024) // exactly one chunk
	if _, err := rand.Read(disk); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	manifest, err := pbsstore.PushDisk(context.Background(), repo, bytes.NewReader(disk),
		pbsstore.PushOptions{VMName: "vm1", DiskName: "root", Timestamp: "2026-05-11T00:00:00Z"})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}

	// 2. Kick the RPC. Cancel after the READY frame so the test
	// doesn't block forever — the handler waits on ctx.Done.
	target := filepath.Join(t.TempDir(), "live.qcow2")
	ctx, cancel := context.WithCancel(adminCtx())
	stream := &restoreLiveStream{ctx: ctx}

	rpcDone := make(chan error, 1)
	go func() {
		rpcDone <- s.RestoreLive(&pb.RestoreLiveRequest{
			RepoPath: repoDir, VmName: "vm1", DiskName: "root",
			Timestamp: manifest.Timestamp, TargetPath: target,
		}, stream)
	}()

	// 3. Poll until the READY frame arrives.
	var nbdURL string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stream.mu.Lock()
		for _, p := range stream.out {
			if p.Phase == pb.RestoreLiveProgress_READY {
				nbdURL = p.NbdUrl
			}
		}
		stream.mu.Unlock()
		if nbdURL != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if nbdURL == "" {
		t.Fatalf("never received READY; got %d frames", len(stream.out))
	}

	// 4. Confirm the overlay qcow2 exists with the expected size.
	info, err := qcow2.Info(target)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if int64(info.VirtualSize) != int64(len(disk)) {
		t.Errorf("overlay size = %d, want %d", info.VirtualSize, len(disk))
	}

	// 5. Talk NBD to the server. The handshake / read pair lives in
	// the nbd package's test file; we duplicate the tiny client here
	// so we don't reach into another package's *_test.go.
	addr := strings.TrimPrefix(strings.TrimPrefix(nbdURL, "nbd://"), "")
	addr = strings.Split(addr, "/")[0]
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial NBD: %v", err)
	}
	defer conn.Close()
	if err := nbdHandshake(conn, "vm1-root"); err != nil {
		t.Fatalf("NBD handshake: %v", err)
	}
	got, err := nbdRead(conn, 0, 4096)
	if err != nil {
		t.Fatalf("NBD read: %v", err)
	}
	if !bytes.Equal(got, disk[:4096]) {
		t.Fatalf("NBD read returned mismatched bytes (got %d, want %d, prefix=%x... vs %x...)",
			len(got), 4096, got[:8], disk[:8])
	}

	// 6. Close the operator stream — handler should unwind cleanly.
	cancel()
	select {
	case err := <-rpcDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("RestoreLive returned %v after cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RestoreLive did not unwind within 2s of cancel")
	}
}

// TestRestoreLive_RejectsMissingFields covers the operator fat-finger
// case — every required field is checked up front.
func TestRestoreLive_RejectsMissingFields(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	stream := &restoreLiveStream{ctx: adminCtx()}
	err := s.RestoreLive(&pb.RestoreLiveRequest{RepoPath: "/tmp"}, stream)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}

// ── tiny inline NBD client (duplicate of the one in nbd/server_test.go
//    so this test stays self-contained) ───────────────────────────────

func nbdHandshake(conn net.Conn, export string) error {
	var magic1, magic2 uint64
	var srvFlags uint16
	if err := binary.Read(conn, binary.BigEndian, &magic1); err != nil {
		return err
	}
	if err := binary.Read(conn, binary.BigEndian, &magic2); err != nil {
		return err
	}
	if err := binary.Read(conn, binary.BigEndian, &srvFlags); err != nil {
		return err
	}
	var clientFlags uint32 = 1
	if err := binary.Write(conn, binary.BigEndian, clientFlags); err != nil {
		return err
	}
	// OPT_GO
	data := binary.BigEndian.AppendUint32(nil, uint32(len(export)))
	data = append(data, []byte(export)...)
	data = binary.BigEndian.AppendUint16(data, 0)
	if err := binary.Write(conn, binary.BigEndian, uint64(0x49484156454F5054)); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, uint32(7)); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	if _, err := conn.Write(data); err != nil {
		return err
	}
	for {
		var replyMagic uint64
		var opt, code, replyLen uint32
		if err := binary.Read(conn, binary.BigEndian, &replyMagic); err != nil {
			return err
		}
		if err := binary.Read(conn, binary.BigEndian, &opt); err != nil {
			return err
		}
		if err := binary.Read(conn, binary.BigEndian, &code); err != nil {
			return err
		}
		if err := binary.Read(conn, binary.BigEndian, &replyLen); err != nil {
			return err
		}
		payload := make([]byte, replyLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return err
		}
		if code == 1 { // NBD_REP_ACK
			return nil
		}
		if code == 3 { // NBD_REP_INFO — payload contains size; we ignore here
			continue
		}
		return errors.New("nbd reply error")
	}
}

func nbdRead(conn net.Conn, off uint64, length uint32) ([]byte, error) {
	if err := binary.Write(conn, binary.BigEndian, uint32(0x25609513)); err != nil {
		return nil, err
	}
	if err := binary.Write(conn, binary.BigEndian, uint16(0)); err != nil {
		return nil, err
	}
	if err := binary.Write(conn, binary.BigEndian, uint16(0)); err != nil { // NBD_CMD_READ
		return nil, err
	}
	if err := binary.Write(conn, binary.BigEndian, uint64(0xAA)); err != nil {
		return nil, err
	}
	if err := binary.Write(conn, binary.BigEndian, off); err != nil {
		return nil, err
	}
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return nil, err
	}
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
		return nil, errors.New("nbd read error")
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	return data, nil
}
