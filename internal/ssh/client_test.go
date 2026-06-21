package ssh

import (
	"io"
	"testing"
)

func TestParseTarget_UserAndHost(t *testing.T) {
	tests := []struct {
		input    string
		wantUser string
		wantHost string
		wantPort string
	}{
		{"root@10.0.50.10", "root", "10.0.50.10", "22"},
		{"admin@myhost", "admin", "myhost", "22"},
		{"deploy@10.0.50.10:2222", "deploy", "10.0.50.10", "2222"},
		{"10.0.50.10", "root", "10.0.50.10", "22"},
		{"myhost", "root", "myhost", "22"},
		{"user@host:22", "user", "host", "22"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			user, host, port := parseTarget(tt.input)
			if user != tt.wantUser {
				t.Errorf("user = %s, want %s", user, tt.wantUser)
			}
			if host != tt.wantHost {
				t.Errorf("host = %s, want %s", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %s, want %s", port, tt.wantPort)
			}
		})
	}
}

func TestBytesReader_ReadAll(t *testing.T) {
	data := []byte("hello world")
	r := bytesReader(data)

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if string(out) != "hello world" {
		t.Errorf("got %q, want %q", string(out), "hello world")
	}
}

func TestBytesReader_ReadInChunks(t *testing.T) {
	data := []byte("abcdefghij") // 10 bytes
	r := bytesReader(data)

	buf := make([]byte, 3)
	var result []byte

	for {
		n, err := r.Read(buf)
		result = append(result, buf[:n]...)
		if err != nil {
			break
		}
	}

	if string(result) != "abcdefghij" {
		t.Errorf("got %q, want %q", string(result), "abcdefghij")
	}
}

func TestBytesReader_Empty(t *testing.T) {
	r := bytesReader([]byte{})

	buf := make([]byte, 10)
	n, err := r.Read(buf)
	if n != 0 {
		t.Errorf("expected 0 bytes, got %d", n)
	}
	if err == nil {
		t.Error("expected EOF error for empty reader")
	}
}

func TestBytesReader_DoubleRead(t *testing.T) {
	r := bytesReader([]byte("abc"))

	buf := make([]byte, 10)
	n, _ := r.Read(buf)
	if string(buf[:n]) != "abc" {
		t.Errorf("first read: got %q", string(buf[:n]))
	}

	// Second read should return EOF
	n, err := r.Read(buf)
	if n != 0 || err == nil {
		t.Errorf("second read: n=%d, err=%v, expected 0 and EOF", n, err)
	}
}
