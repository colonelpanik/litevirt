package ssh

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTarget_DefaultsNoAt(t *testing.T) {
	user, host, port := parseTarget("myserver")
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
	if host != "myserver" {
		t.Errorf("host = %q, want myserver", host)
	}
	if port != "22" {
		t.Errorf("port = %q, want 22", port)
	}
}

func TestParseTarget_IPv6WithPort(t *testing.T) {
	user, host, port := parseTarget("admin@[::1]:2222")
	if user != "admin" {
		t.Errorf("user = %q, want admin", user)
	}
	if host != "::1" {
		t.Errorf("host = %q, want ::1", host)
	}
	if port != "2222" {
		t.Errorf("port = %q, want 2222", port)
	}
}

func TestParseTarget_IPv6NoPort(t *testing.T) {
	// Without brackets, net.SplitHostPort will fail, so the whole thing stays as host
	user, host, port := parseTarget("admin@::1")
	if user != "admin" {
		t.Errorf("user = %q, want admin", user)
	}
	// Without proper bracket notation, "::1" stays as-is
	if host != "::1" {
		t.Errorf("host = %q, want ::1", host)
	}
	if port != "22" {
		t.Errorf("port = %q, want 22 (default)", port)
	}
}

func TestParseTarget_EmptyString(t *testing.T) {
	user, host, port := parseTarget("")
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
	if host != "" {
		t.Errorf("host = %q, want empty", host)
	}
	if port != "22" {
		t.Errorf("port = %q, want 22", port)
	}
}

func TestParseTarget_AtSign(t *testing.T) {
	user, host, port := parseTarget("@")
	if user != "" {
		t.Errorf("user = %q, want empty", user)
	}
	if host != "" {
		t.Errorf("host = %q, want empty", host)
	}
	if port != "22" {
		t.Errorf("port = %q, want 22", port)
	}
}

func TestParseTarget_MultipleAt(t *testing.T) {
	user, host, port := parseTarget("user@host@extra")
	if user != "user" {
		t.Errorf("user = %q, want user", user)
	}
	// Everything after first @ is host (including second @)
	if host != "host@extra" {
		t.Errorf("host = %q, want host@extra", host)
	}
	if port != "22" {
		t.Errorf("port = %q, want 22", port)
	}
}

func TestParseTarget_HighPort(t *testing.T) {
	user, host, port := parseTarget("deploy@10.0.0.1:65535")
	if user != "deploy" {
		t.Errorf("user = %q, want deploy", user)
	}
	if host != "10.0.0.1" {
		t.Errorf("host = %q, want 10.0.0.1", host)
	}
	if port != "65535" {
		t.Errorf("port = %q, want 65535", port)
	}
}

func TestParseTarget_HostnameWithDashes(t *testing.T) {
	user, host, port := parseTarget("root@my-host-01.dc1.example.com")
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
	if host != "my-host-01.dc1.example.com" {
		t.Errorf("host = %q, want my-host-01.dc1.example.com", host)
	}
	if port != "22" {
		t.Errorf("port = %q, want 22", port)
	}
}

func TestParseTarget_LongHostname(t *testing.T) {
	long := strings.Repeat("a", 200) + ".example.com"
	user, host, port := parseTarget("admin@" + long)
	if user != "admin" {
		t.Errorf("user = %q, want admin", user)
	}
	if host != long {
		t.Errorf("host length = %d, want %d", len(host), len(long))
	}
	if port != "22" {
		t.Errorf("port = %q, want 22", port)
	}
}

func TestParseTarget_PortZero(t *testing.T) {
	user, host, port := parseTarget("root@host:0")
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
	if host != "host" {
		t.Errorf("host = %q, want host", host)
	}
	if port != "0" {
		t.Errorf("port = %q, want 0", port)
	}
}

func TestParseTarget_UserWithDot(t *testing.T) {
	user, host, port := parseTarget("john.doe@server")
	if user != "john.doe" {
		t.Errorf("user = %q, want john.doe", user)
	}
	if host != "server" {
		t.Errorf("host = %q, want server", host)
	}
	if port != "22" {
		t.Errorf("port = %q, want 22", port)
	}
}

func TestParseTarget_UserWithHyphen(t *testing.T) {
	user, host, port := parseTarget("deploy-user@server")
	if user != "deploy-user" {
		t.Errorf("user = %q, want deploy-user", user)
	}
	if host != "server" {
		t.Errorf("host = %q, want server", host)
	}
	if port != "22" {
		t.Errorf("port = %q, want 22", port)
	}
}

func TestParseTarget_NoAtWithPort(t *testing.T) {
	// "10.0.0.1:2222" -- no user, should default to root
	user, host, port := parseTarget("10.0.0.1:2222")
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
	if host != "10.0.0.1" {
		t.Errorf("host = %q, want 10.0.0.1", host)
	}
	if port != "2222" {
		t.Errorf("port = %q, want 2222", port)
	}
}

func TestBytesReader_SingleByte(t *testing.T) {
	r := bytesReader([]byte{0x42})

	buf := make([]byte, 10)
	n, err := r.Read(buf)
	if n != 1 {
		t.Errorf("n = %d, want 1", n)
	}
	if buf[0] != 0x42 {
		t.Errorf("byte = %x, want 42", buf[0])
	}
	// err may be nil (not yet EOF since we read exactly one call)
	if err != nil && err != io.EOF {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestBytesReader_NilData(t *testing.T) {
	r := bytesReader(nil)

	buf := make([]byte, 10)
	n, err := r.Read(buf)
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
	if err != io.EOF {
		t.Errorf("err = %v, want io.EOF", err)
	}
}

func TestBytesReader_ExactFit(t *testing.T) {
	data := []byte("abc")
	r := bytesReader(data)

	buf := make([]byte, 3)
	n, err := r.Read(buf)
	if n != 3 {
		t.Errorf("n = %d, want 3", n)
	}
	if string(buf) != "abc" {
		t.Errorf("buf = %q, want abc", string(buf))
	}
	// First read may or may not return EOF
	if err != nil && err != io.EOF {
		t.Errorf("unexpected error: %v", err)
	}

	// Second read should definitely be EOF
	n2, err2 := r.Read(buf)
	if n2 != 0 {
		t.Errorf("second read n = %d, want 0", n2)
	}
	if err2 != io.EOF {
		t.Errorf("second read err = %v, want io.EOF", err2)
	}
}

func TestBytesReader_LargeData(t *testing.T) {
	data := make([]byte, 1024*1024) // 1 MB
	for i := range data {
		data[i] = byte(i % 256)
	}
	r := bytesReader(data)

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(out) != len(data) {
		t.Errorf("output length = %d, want %d", len(out), len(data))
	}
	// Spot check
	if out[0] != 0 {
		t.Errorf("out[0] = %d, want 0", out[0])
	}
	if out[255] != 255 {
		t.Errorf("out[255] = %d, want 255", out[255])
	}
}

func TestBytesReader_SmallBuffer(t *testing.T) {
	data := []byte("hello world!")
	r := bytesReader(data)

	// Read one byte at a time
	var result []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if string(result) != "hello world!" {
		t.Errorf("result = %q, want 'hello world!'", string(result))
	}
}

func TestBytesReader_BinaryData(t *testing.T) {
	data := []byte{0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD}
	r := bytesReader(data)

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(out) != 6 {
		t.Errorf("length = %d, want 6", len(out))
	}
	for i, b := range data {
		if out[i] != b {
			t.Errorf("out[%d] = %x, want %x", i, out[i], b)
		}
	}
}

func TestBytesReaderWrapper_FieldAccess(t *testing.T) {
	r := &bytesReaderWrapper{data: []byte("test"), pos: 0}
	if len(r.data) != 4 {
		t.Errorf("data length = %d, want 4", len(r.data))
	}
	if r.pos != 0 {
		t.Errorf("pos = %d, want 0", r.pos)
	}
}

func TestBytesReader_MultipleSmallReads(t *testing.T) {
	data := []byte("abcdefghij") // 10 bytes
	r := bytesReader(data)

	// Read in chunks of 4
	buf := make([]byte, 4)
	var result []byte

	// First read: 4 bytes
	n, err := r.Read(buf)
	result = append(result, buf[:n]...)
	if n != 4 {
		t.Errorf("first read n = %d, want 4", n)
	}
	if err != nil {
		t.Errorf("first read err = %v", err)
	}

	// Second read: 4 bytes
	n, err = r.Read(buf)
	result = append(result, buf[:n]...)
	if n != 4 {
		t.Errorf("second read n = %d, want 4", n)
	}
	if err != nil {
		t.Errorf("second read err = %v", err)
	}

	// Third read: 2 bytes remaining
	n, err = r.Read(buf)
	result = append(result, buf[:n]...)
	if n != 2 {
		t.Errorf("third read n = %d, want 2", n)
	}

	if string(result) != "abcdefghij" {
		t.Errorf("result = %q, want abcdefghij", string(result))
	}
}

func TestClient_Struct(t *testing.T) {
	// Verify Client struct fields exist
	c := &Client{
		addr: "10.0.0.1:22",
	}
	if c.addr != "10.0.0.1:22" {
		t.Errorf("addr = %q", c.addr)
	}
}

func TestLoadPrivateKey_NonexistentFile(t *testing.T) {
	_, err := loadPrivateKey("/nonexistent/path/id_rsa")
	if err == nil {
		t.Error("expected error for nonexistent key file")
	}
}

func TestLoadPrivateKey_InvalidKeyData(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad_key")
	if err := os.WriteFile(keyPath, []byte("not a valid private key"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadPrivateKey(keyPath)
	if err == nil {
		t.Error("expected error for invalid key data")
	}
}

func TestLoadPrivateKey_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "empty_key")
	if err := os.WriteFile(keyPath, []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadPrivateKey(keyPath)
	if err == nil {
		t.Error("expected error for empty key file")
	}
}

func TestAuthMethods_NoAgentNoKeys(t *testing.T) {
	// Unset SSH_AUTH_SOCK and set HOME to a temp dir with no.ssh
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", t.TempDir())
	_, err := authMethods()
	if err == nil {
		t.Error("expected error when no auth methods are available")
	}
	if err != nil && !strings.Contains(err.Error(), "no SSH auth methods") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAuthMethods_InvalidAgentSocket(t *testing.T) {
	// Set SSH_AUTH_SOCK to a nonexistent path; should fall through to key files
	t.Setenv("SSH_AUTH_SOCK", "/nonexistent/agent.sock")
	t.Setenv("HOME", t.TempDir())
	_, err := authMethods()
	if err == nil {
		t.Error("expected error when agent socket is invalid and no keys exist")
	}
}

func TestDefaultHostKeyCallback_ReturnsCallbackOrError(t *testing.T) {
	// defaultHostKeyCallback uses user.Current().HomeDir, so we can't easily
	// redirect it. Just verify it returns either a valid callback or an error.
	cb, err := defaultHostKeyCallback()
	if err != nil {
		// No known_hosts file -- this is expected in many test environments
		if cb != nil {
			t.Error("callback should be nil when error is returned")
		}
	} else {
		if cb == nil {
			t.Error("callback should not be nil when no error")
		}
	}
}

func TestDefaultHostKeyCallback_EmptyKnownHosts(t *testing.T) {
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte{}, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	cb, err := defaultHostKeyCallback()
	if err != nil {
		t.Fatalf("unexpected error with empty known_hosts: %v", err)
	}
	if cb == nil {
		t.Error("callback should not be nil")
	}
}
