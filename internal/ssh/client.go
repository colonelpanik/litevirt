package ssh

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// Client wraps an SSH connection for remote operations.
type Client struct {
	conn *ssh.Client
	addr string
}

// NewClient connects to a remote host via SSH.
// target format: "user@host" or "user@host:port"
func NewClient(target string) (*Client, error) {
	sshUser, host, port := parseTarget(target)

	auth, err := authMethods()
	if err != nil {
		return nil, fmt.Errorf("SSH auth: %w", err)
	}

	hostKeyCallback, err := defaultHostKeyCallback()
	if err != nil {
		// No usable known_hosts (no HOME, unreadable file). Accept-new still
		// applies -- there is nothing to compare against, and refusing here
		// would make provisioning impossible on a fresh workstation -- but say
		// so, because this connection carries the cluster CA-signed host key
		// and nothing is pinning the far end.
		fmt.Fprintf(os.Stderr,
			"warning: no usable known_hosts (%v); %s's host key cannot be checked "+
				"against a previous one. This connection carries the cluster CA-signed "+
				"host key.\n", err, host)
		hostKeyCallback = firstContactOnlyCallback(host)
	}

	config := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
	}

	addr := net.JoinHostPort(host, port)
	conn, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("SSH dial %s: %w", addr, err)
	}

	return &Client{conn: conn, addr: addr}, nil
}

// Close closes the SSH connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Run executes a command on the remote host.
func (c *Client) Run(cmd string) error {
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	return session.Run(cmd)
}

// RunWithInput runs a command with data on its stdin.
//
// This is how a provisioning script should reach a remote host: `bash -s` with
// the script on stdin never creates a file, so there is no path for a local
// user on the target to pre-create, no window between writing and executing,
// and nothing to clean up if the process dies in between.
func (c *Client) RunWithInput(cmd string, input []byte) error {
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytesReader(input)
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	return session.Run(cmd)
}

// RunOutput executes a command and returns stdout.
func (c *Client) RunOutput(cmd string) ([]byte, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	return session.Output(cmd)
}

// CopyFile copies a local file to a remote path using SCP-like semantics.
func (c *Client) CopyFile(localPath, remotePath string) error {
	return c.CopyFileMode(localPath, remotePath, 0644)
}

// CopyFileMode copies a local file to the remote host with an explicit mode.
//
// It exists because CopyFile's 0644 default is wrong for private keys, and
// nothing about the call site made that visible: `lv host init root@<host>` —
// the form the docs tell you to use for anything multi-node — pushed
// /etc/litevirt/pki/host.key world-readable on every node it provisioned. That
// key is the host's whole cluster identity: any local user who can read it can
// impersonate the host over peer mTLS and sign audit rows in its name. Callers
// pushing key material MUST pass 0600.
func (c *Client) CopyFileMode(localPath, remotePath string, mode os.FileMode) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read local file: %w", err)
	}
	return c.WriteFile(remotePath, data, mode)
}

// ShellQuote renders s as a single-quoted POSIX shell word.
//
// Exported because every caller that builds a remote command line from data
// needs it, not only this package: an SSH exec request is run by the login
// shell, so anything interpolated into one is shell input.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// writeFileCmd builds the remote shell command that materialises a file.
//
// The content is staged in a mktemp file beside the destination, chmod'd there,
// and only then moved into place. The obvious `cat > path && chmod mode path`
// leaves the file complete and world-readable at the remote umask for the whole
// transfer — and permanently if the connection drops between the two commands.
// The payload here is host.key.
//
// Staging also fixes the case a leading chmod would not: redirecting into an
// EXISTING file truncates it but keeps its old mode, so re-provisioning over a
// loose file would write the new key at the old permissions. mv replaces the
// destination wholesale, mode included, and does so atomically.
//
// mktemp in the destination's own directory keeps the rename on one filesystem.
//
// -T is load-bearing, not tidiness. Without it, `mv src dest` where dest is a
// DIRECTORY moves src INSIDE it — so a local user who can see the destination
// path (process command lines are world-readable on a default Linux) can
// mkdir it first, let the staged file land inside, then rename their directory
// away and leave their own file at the path root is about to read. -T makes
// that case an error instead. -- stops a path that begins with "-" being read
// as options.
func writeFileCmd(remotePath string, mode os.FileMode) string {
	q := ShellQuote(remotePath)
	return fmt.Sprintf(
		"set -e; d=$(dirname %s); t=$(mktemp \"$d/.litevirt.XXXXXX\"); "+
			"trap 'rm -f \"$t\"' EXIT; cat > \"$t\"; chmod %o \"$t\"; "+
			"mv -fT -- \"$t\" %s; trap - EXIT",
		q, mode.Perm(), q)
}

// WriteFile writes data to a remote file.
func (c *Client) WriteFile(remotePath string, data []byte, mode os.FileMode) error {
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	session.Stdin = bytesReader(data)
	return session.Run(writeFileCmd(remotePath, mode))
}

// Interactive runs a command on the remote host with a PTY attached,
// connecting local stdin/stdout/stderr. Used for lv console.
func (c *Client) Interactive(cmd string) error {
	session, err := c.conn.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("make raw terminal: %w", err)
	}
	defer term.Restore(fd, oldState)

	w, h, _ := term.GetSize(fd)
	if err := session.RequestPty("xterm-256color", h, w, ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return fmt.Errorf("request PTY: %w", err)
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	// Forward SIGWINCH (terminal resize) to remote session.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			w, h, _ := term.GetSize(fd)
			session.WindowChange(h, w)
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
	}()

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("start command: %w", err)
	}
	return session.Wait()
}

// Conn returns the underlying SSH client connection (used for tunneling).
func (c *Client) Conn() *ssh.Client {
	return c.conn
}

func parseTarget(target string) (user, host, port string) {
	user = "root"
	host = target
	port = "22"

	for i, c := range target {
		if c == '@' {
			user = target[:i]
			host = target[i+1:]
			break
		}
	}

	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port = p
	}

	return
}

func authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	var tried []string

	// Try SSH agent first
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		tried = append(tried, "agent: SSH_AUTH_SOCK not set")
	} else {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			tried = append(tried, fmt.Sprintf("agent: dial %s: %v", sock, err))
		} else {
			ac := agent.NewClient(conn)
			// Verify agent actually has keys before adding
			keys, err := ac.List()
			if err != nil {
				conn.Close()
				tried = append(tried, fmt.Sprintf("agent: list keys: %v", err))
			} else if len(keys) == 0 {
				conn.Close()
				tried = append(tried, "agent: connected but no keys loaded")
			} else {
				tried = append(tried, fmt.Sprintf("agent: %d key(s) available", len(keys)))
				methods = append(methods, ssh.PublicKeysCallback(ac.Signers))
			}
		}
	}

	// Try default key files
	home, _ := os.UserHomeDir()
	keyFiles := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}
	for _, kf := range keyFiles {
		key, err := loadPrivateKey(kf)
		if err != nil {
			if !os.IsNotExist(err) {
				tried = append(tried, fmt.Sprintf("key %s: %v", filepath.Base(kf), err))
			}
			continue
		}
		tried = append(tried, fmt.Sprintf("key %s: loaded", filepath.Base(kf)))
		methods = append(methods, ssh.PublicKeys(key))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH auth methods available:\n  %s", joinLines(tried))
	}

	return methods, nil
}

func joinLines(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += "\n  "
		}
		result += s
	}
	return result
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// hostKeyVerdict decides what to do with the knownhosts callback's answer.
//
// The old policy accepted unknown hosts AND key mismatches, on the stated
// grounds that "litevirt manages its own trust via mTLS -- SSH is just a
// transport for setup/upgrade operations". That is exactly backwards for the
// operation it is used by: `lv host init` and `lv host add` use SSH to carry
// the cluster CA-signed HOST PRIVATE KEY to a machine that has no mTLS
// identity yet. There is no other anchor at that moment, so accepting a
// changed key hands that key to whoever answered.
//
// knownhosts.KeyError distinguishes the two cases by Want:
//
//   - empty  -- the host is UNKNOWN. Unavoidable: provisioning a new machine
//     is always first contact. Accepted (the documented
//     StrictHostKeyChecking=accept-new behaviour).
//   - non-empty -- the host is KNOWN and the key CHANGED. Refused. Nothing
//     about provisioning requires this, and it is the whole MITM.
func hostKeyVerdict(hostname string, err error) error {
	if keyErr := (*knownhosts.KeyError)(nil); errors.As(err, &keyErr) {
		if len(keyErr.Want) == 0 {
			return nil // unknown host: accept-new
		}
		return fmt.Errorf("host key for %s CHANGED (known key at %s:%d) -- refusing: "+
			"this connection would carry the cluster CA-signed host key, and a changed "+
			"key means something other than the host we trusted is answering. If the "+
			"host was genuinely rebuilt, remove its known_hosts entry first",
			hostname, keyErr.Want[0].Filename, keyErr.Want[0].Line)
	}
	return err
}

// firstContactOnlyCallback is used when no known_hosts is usable at all.
//
// It accepts, because with no store there is no previous key to contradict and
// refusing would make `lv host init` impossible on a fresh workstation. It is a
// named function rather than ssh.InsecureIgnoreHostKey so the two cases cannot
// be confused: this one has been reported to the operator, and it is reached
// only when the store itself is missing -- never to paper over a MISMATCH,
// which hostKeyVerdict refuses even here.
func firstContactOnlyCallback(host string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		slog.Warn("ssh: host key not verified (no known_hosts store)",
			"host", host, "remote", remote.String(), "key_type", key.Type())
		return nil
	}
}

func defaultHostKeyCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	knownHostsFile := filepath.Join(home, ".ssh", "known_hosts")
	cb, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, err
	}
	// accept-new, not accept-anything: see hostKeyVerdict for why a CHANGED
	// key is refused even though an unknown one is not.
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return hostKeyVerdict(hostname, cb(hostname, remote, key))
	}, nil
}

type bytesReaderWrapper struct {
	data []byte
	pos  int
}

func bytesReader(data []byte) *bytesReaderWrapper {
	return &bytesReaderWrapper{data: data}
}

func (r *bytesReaderWrapper) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return
}
