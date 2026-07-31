package nbd

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
)

func TestHandshakeRejectsOversizedOptionBeforeReadingPayload(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	s := &Server{ExportName: "x", Dev: &fakeDevice{}}
	done := make(chan error, 1)
	go func() {
		done <- s.handshake(server)
		_ = server.Close()
	}()

	var greeting [18]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil {
		t.Fatalf("read greeting: %v", err)
	}
	if err := binary.Write(client, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{nbdIHaveOpt, nbdOptGo, maxOptionLen + 1} {
		if err := binary.Write(client, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}

	if err := <-done; err == nil || !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("handshake error = %v, want size-limit error", err)
	}
}
